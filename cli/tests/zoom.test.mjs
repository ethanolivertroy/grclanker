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
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

import {
  ZOOM_FRAMEWORKS,
  ZOOM_SPEC_CONTROLS,
  ZoomApiClient,
  ZoomApiError,
  assessZoomCollaborationGovernance,
  assessZoomIdentity,
  assessZoomMeetingSecurity,
  checkZoomAccess,
  collectZoomSnapshot,
  exportZoomAuditBundle,
  resolveSecureOutputPath,
  resolveZoomConfiguration,
} from "../dist/extensions/grc-tools/zoom.js";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function sampleConfig(overrides = {}) {
  return {
    accountId: "acct-123",
    token: "zoom-token",
    baseUrl: "https://api.zoom.us/v2",
    oauthBaseUrl: "https://zoom.us",
    timeoutMs: 30000,
    sourceChain: ["tests"],
    ...overrides,
  };
}

function jsonResponse(value, options = {}) {
  return new Response(JSON.stringify(value), {
    status: options.status ?? 200,
    headers: {
      "content-type": "application/json",
      ...(options.headers ?? {}),
    },
  });
}

function headerValue(headers, name) {
  if (!headers) return undefined;
  if (headers instanceof Headers) return headers.get(name) ?? undefined;
  if (typeof headers.get === "function") return headers.get(name) ?? undefined;
  return headers[name] ?? headers[name.toLowerCase()];
}

function list(items, overrides = {}) {
  return { items, truncated: false, pages: 1, totalRecords: items.length, ...overrides };
}

function findingById(result, id) {
  const item = result.findings.find((finding) => finding.id === id);
  assert.ok(item, `missing finding ${id}`);
  return item;
}

function statuses(result) {
  return Object.fromEntries(result.findings.map((item) => [item.id, item.status]));
}

const NOW = new Date("2026-09-21T12:00:00.000Z");

/**
 * Fixture (d): a fully compliant account built strictly from documented field
 * names and shapes (see ZOOM_DOCS in zoom.ts for the reference page per endpoint).
 */
function compliantSettings(option) {
  switch (option) {
    case "security":
      return {
        security: {
          sign_in_with_two_factor_auth: "all",
          sign_again_period_for_inactivity_on_client: 30,
          sign_again_period_for_inactivity_on_web: 15,
          automatic_sign_out: { enable_separated_sign_out_settings: false },
        },
      };
    case "meeting_security":
      return {
        meeting_security: {
          waiting_room: true,
          meeting_password: true,
          end_to_end_encrypted_meetings: true,
          encryption_type: "e2ee",
          embed_password_in_join_link: false,
        },
      };
    case "meeting_authentication":
      return {
        meeting_authentication: true,
        authentication_options: [{ id: "auth-1", name: "Signed-in users", type: "enforce_login", default_option: true, visible: true }],
      };
    default:
      return {
        schedule_meeting: {
          require_password_for_scheduling_new_meetings: true,
          embed_password_in_join_link: false,
          use_pmi_for_scheduled_meetings: false,
          use_pmi_for_instant_meetings: false,
          personal_meeting: true,
          require_password_for_pmi_meetings: "all",
        },
        in_meeting: {
          screen_sharing: true,
          who_can_share_screen: "host",
          who_can_share_screen_when_someone_is_sharing: "host",
          file_transfer: false,
          custom_data_center_regions: true,
          data_center_regions: ["US"],
        },
        recording: {
          cloud_recording: true,
          local_recording: false,
          auto_delete_cmr: true,
          auto_delete_cmr_days: 90,
          recording_notification_for_zoom_client: {
            disclaimer_to_participants: "All participants",
            play_voice_prompt: "All participants",
            ask_host_to_confirm: true,
          },
          recording_notifications_phone_users: { require_press_one_consent_to_record: true },
        },
        chat: {
          allow_users_to_add_contacts: { enable: true, selected_option: 2 },
          allow_users_to_chat_with_others: { enable: true, selected_option: 2 },
          external_user_control: { enable: true, selected_option: 3 },
          share_files: { enable: true, share_option: "account", view_option: "account" },
        },
      };
  }
}

function compliantLocks(option) {
  if (option === "meeting_security") {
    return { meeting_security: { waiting_room: true, end_to_end_encrypted_meetings: true, embed_password_in_join_link: true } };
  }
  return {
    schedule_meeting: {
      require_password_for_scheduling_new_meetings: true,
      embed_password_in_join_link: true,
      use_pmi_for_scheduled_meetings: true,
      use_pmi_for_instant_meetings: true,
      meeting_authentication: true,
    },
    in_meeting: { screen_sharing: true, file_transfer: true, custom_data_center_regions: true },
    recording: { local_recording: true, auto_delete_cmr: true },
    chat: { allow_users_to_add_contacts: true, allow_users_to_chat_with_others: true },
  };
}

function compliantClient(overrides = {}) {
  return {
    getResolvedConfig: () => sampleConfig(),
    async getCurrentUser() {
      return { id: "user-1", email: "auditor@example.com" };
    },
    async getAccountSettings(option) {
      return compliantSettings(option);
    },
    async getAccountLockSettings(option) {
      return compliantLocks(option);
    },
    async listUsers() {
      return list([
        { id: "admin-1", email: "admin-1@example.com", status: "active", type: 2, login_types: [101] },
        { id: "user-2", email: "user-2@example.com", status: "active", type: 2, login_types: [101] },
      ]);
    },
    async listRoles() {
      return list([
        { id: "0", name: "Owner", total_members: 1 },
        { id: "1", name: "Admin", total_members: 1 },
        { id: "2", name: "Member", total_members: 1 },
      ]);
    },
    async listRoleMembers(roleId) {
      return roleId === "0" ? list([{ id: "admin-1", email: "admin-1@example.com" }]) : list([{ id: "admin-1", email: "admin-1@example.com" }]);
    },
    async listGroups() {
      return list([{ id: "group-1", name: "Finance", total_members: 4 }]);
    },
    async getGroupSettings(_groupId, option) {
      return compliantSettings(option);
    },
    async getGroupLockSettings(_groupId, option) {
      return compliantLocks(option);
    },
    async listOperationLogs() {
      return list([
        { action: "Update", category_type: "account", operation_detail: "Changed setting", operator: "admin-1@example.com", time: "2026-09-20T10:00:00Z" },
      ]);
    },
    async listImGroups() {
      return list([{ id: "im-1", name: "Engineering", type: "restricted", total_members: 10, search_by_account: true, search_by_domain: false, search_by_ma_account: false }]);
    },
    async getManagedDomains() {
      return list([{ domain: "example.com", status: "verified" }]);
    },
    async listTrustedDomains() {
      return { items: ["partners.example.com"], truncated: false, pages: 1 };
    },
    async getPhoneAccountSettings() {
      return {
        auto_call_recording: { enable: true, locked: true, locked_by: "account", recording_calls: "both" },
        ad_hoc_call_recording: { enable: false, locked: true, locked_by: "account" },
      };
    },
    ...overrides,
  };
}

/** Fixture (a): every endpoint returns 403. */
function deniedClient() {
  const denied = async () => {
    throw new ZoomApiError("Zoom request failed (403 Forbidden): Invalid access token, does not contain scopes", 403);
  };
  return {
    getResolvedConfig: () => sampleConfig(),
    getCurrentUser: denied,
    getAccountSettings: denied,
    getAccountLockSettings: denied,
    listUsers: denied,
    listRoles: denied,
    listRoleMembers: denied,
    listGroups: denied,
    getGroupSettings: denied,
    getGroupLockSettings: denied,
    listOperationLogs: denied,
    listImGroups: denied,
    getManagedDomains: denied,
    listTrustedDomains: denied,
    getPhoneAccountSettings: denied,
  };
}

/** Fixture (b): every list is empty and every settings object is {}. */
function emptyClient() {
  const emptyList = async () => list([]);
  const emptyObject = async () => ({});
  return {
    getResolvedConfig: () => sampleConfig(),
    getCurrentUser: emptyObject,
    getAccountSettings: emptyObject,
    getAccountLockSettings: emptyObject,
    listUsers: emptyList,
    listRoles: emptyList,
    listRoleMembers: emptyList,
    listGroups: emptyList,
    getGroupSettings: emptyObject,
    getGroupLockSettings: emptyObject,
    listOperationLogs: emptyList,
    listImGroups: emptyList,
    getManagedDomains: emptyList,
    listTrustedDomains: async () => ({ items: [], truncated: false, pages: 1 }),
    getPhoneAccountSettings: emptyObject,
  };
}

/**
 * Fixture (c): compliant values, but every inventory is partial (user cap hit,
 * truncated pages, total_records above the returned list) and the surfaces a
 * sub-account credential cannot read are denied (lock_settings, the security
 * option view, Zoom Phone, and the master-only trusted_domains list).
 */
function partialClient() {
  return compliantClient({
    async listTrustedDomains() {
      throw new ZoomApiError("Zoom request failed (403 Forbidden): Invalid access token, does not contain scopes: [account:read:trusted_domains:master]", 403);
    },
    async getAccountSettings(option) {
      if (option === "security") {
        throw new ZoomApiError("Zoom request failed (403 Forbidden): Invalid access token, does not contain scopes", 403);
      }
      return compliantSettings(option);
    },
    async listUsers() {
      return list([{ id: "admin-1", email: "admin-1@example.com", login_types: [101] }], { truncated: true, totalRecords: 250 });
    },
    async listRoleMembers() {
      return list([{ id: "admin-1" }], { truncated: true, totalRecords: 12 });
    },
    async listGroups() {
      return list([{ id: "group-1", name: "Finance" }], { truncated: true, totalRecords: 40 });
    },
    async listOperationLogs() {
      return list([{ action: "Update", time: "2026-09-20T10:00:00Z" }], { truncated: true });
    },
    async listImGroups() {
      return list([{ id: "im-1", name: "Engineering", type: "restricted" }], { truncated: true, totalRecords: 9 });
    },
    async getManagedDomains() {
      return list([{ domain: "example.com", status: "verified" }], { truncated: true, totalRecords: 3 });
    },
    async getPhoneAccountSettings() {
      throw new ZoomApiError("Zoom request failed (403 Forbidden): This account does not have Zoom Phone", 403);
    },
    async getAccountLockSettings() {
      throw new ZoomApiError("Zoom request failed (403 Forbidden): Invalid access token, does not contain scopes", 403);
    },
  });
}

async function runAllAssessments(client) {
  return {
    identity: await assessZoomIdentity(client, { now: NOW }),
    collaboration: await assessZoomCollaborationGovernance(client, { now: NOW }),
    meeting: await assessZoomMeetingSecurity(client, { now: NOW }),
  };
}

test("resolveZoomConfiguration prefers explicit args over environment values", () => {
  const resolved = resolveZoomConfiguration(
    {
      account_id: "acct-explicit",
      token: "arg-token",
      client_id: "arg-client",
      client_secret: "arg-secret",
      base_url: "https://api.zoomgov.com/v2",
      oauth_base_url: "https://zoomgov.com",
      timeout_seconds: 9,
    },
    {
      ZOOM_ACCOUNT_ID: "acct-env",
      ZOOM_TOKEN: "env-token",
      ZOOM_CLIENT_ID: "env-client",
      ZOOM_CLIENT_SECRET: "env-secret",
    },
  );

  assert.equal(resolved.accountId, "acct-explicit");
  assert.equal(resolved.token, "arg-token");
  assert.equal(resolved.baseUrl, "https://api.zoomgov.com/v2");
  assert.equal(resolved.oauthBaseUrl, "https://zoomgov.com");
  assert.equal(resolved.timeoutMs, 9000);
  assert.ok(resolved.sourceChain.includes("arguments-account-id"));
  assert.ok(resolved.sourceChain.includes("arguments-token"));
});

test("resolveZoomConfiguration discovers a JSON config file after arguments and environment", () => {
  const base = createTempBase("grclanker-zoom-config-");
  const configPath = join(base, "zoom.json");
  writeFileSync(configPath, JSON.stringify({
    account_id: "acct-file",
    client_id: "file-client",
    client_secret: "file-secret",
    base_url: "https://api.zoomgov.com/v2",
  }));

  const resolved = resolveZoomConfiguration({}, { ZOOM_CONFIG_FILE: configPath, ZOOM_CLIENT_ID: "env-client" });
  assert.equal(resolved.accountId, "acct-file");
  assert.equal(resolved.clientId, "env-client");
  assert.equal(resolved.clientSecret, "file-secret");
  assert.equal(resolved.baseUrl, "https://api.zoomgov.com/v2");
  assert.equal(resolved.oauthBaseUrl, "https://zoomgov.com");
  assert.equal(resolved.configFile, configPath);
  assert.deepEqual(resolved.sourceChain, ["config-file-account-id", "environment-client-id", "config-file-client-secret"]);

  assert.throws(() => resolveZoomConfiguration({}, { ZOOM_CONFIG_FILE: join(base, "missing.json") }), /config file not found/);
});

test("ZoomApiClient exchanges Server-to-Server OAuth credentials, paginates with next_page_token, and sends documented query parameters", async () => {
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({
      pathname: url.pathname,
      search: url.search,
      params: Object.fromEntries(url.searchParams.entries()),
      method: init.method ?? "GET",
      auth: headerValue(init.headers, "authorization"),
    });

    if (url.pathname === "/oauth/token") {
      return jsonResponse({ access_token: "oauth-token", expires_in: 3600 });
    }

    if (!url.searchParams.get("next_page_token")) {
      return jsonResponse({ users: [{ id: "user-1" }], total_records: 2, next_page_token: "page-2" });
    }

    return jsonResponse({ users: [{ id: "user-2" }], total_records: 2 });
  };

  const client = new ZoomApiClient(resolveZoomConfiguration({
    account_id: "acct-123",
    client_id: "client-id",
    client_secret: "client-secret",
  }, {}), { fetchImpl });
  const users = await client.listUsers(10);

  assert.deepEqual(users.items.map((user) => user.id), ["user-1", "user-2"]);
  assert.equal(users.truncated, false);
  assert.equal(users.totalRecords, 2);
  assert.equal(users.pages, 2);
  assert.equal(seen[0].pathname, "/oauth/token");
  assert.equal(seen[0].params.grant_type, "account_credentials");
  assert.equal(seen[0].params.account_id, "acct-123");
  assert.match(seen[0].auth, /^Basic /);
  assert.equal(seen[1].pathname, "/v2/users");
  assert.equal(seen[1].auth, "Bearer oauth-token");
  assert.equal(seen[1].params.page_size, "300");
  assert.equal(seen[1].params.status, "active");
  assert.equal(seen[2].params.next_page_token, "page-2");
});

test("ZoomApiClient marks truncation when the caller limit stops pagination and honors 429 Retry-After", async () => {
  let attempts = 0;
  const sleeps = [];
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    attempts += 1;
    if (attempts === 1) {
      return jsonResponse({ code: 429, message: "rate limited" }, { status: 429, headers: { "retry-after": "2" } });
    }
    if (url.pathname.endsWith("/report/operationlogs")) {
      assert.equal(url.searchParams.get("from"), "2026-08-22");
      assert.equal(url.searchParams.get("to"), "2026-09-21");
      return jsonResponse({ operation_logs: [{ time: "2026-09-01" }, { time: "2026-09-02" }], next_page_token: "more" });
    }
    return jsonResponse({});
  };
  const client = new ZoomApiClient(sampleConfig(), { fetchImpl, sleep: async (ms) => { sleeps.push(ms); } });

  const logs = await client.listOperationLogs("2026-08-22", "2026-09-21", 1);
  assert.deepEqual(sleeps, [2000]);
  assert.equal(logs.items.length, 1);
  assert.equal(logs.truncated, true);
});

test("ZoomApiClient surfaces 403 as ZoomApiError with the status code and calls documented endpoints", async () => {
  const seen = [];
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push(`${url.pathname}${url.search}`);
    return jsonResponse({ code: 124, message: "Invalid access token, does not contain scopes:[account:read:admin]" }, { status: 403 });
  };
  const client = new ZoomApiClient(sampleConfig(), { fetchImpl });

  await assert.rejects(client.getAccountSettings("security"), (error) => error instanceof ZoomApiError && error.status === 403);
  await assert.rejects(client.getPhoneAccountSettings(), ZoomApiError);
  await assert.rejects(client.getAccountLockSettings("meeting_security"), ZoomApiError);
  assert.deepEqual(seen, [
    "/v2/accounts/acct-123/settings?option=security",
    "/v2/phone/account_settings?setting_types=auto_call_recording%2Cad_hoc_call_recording",
    "/v2/accounts/acct-123/lock_settings?option=meeting_security",
  ]);
});

test("collectZoomSnapshot fetches every documented settings option view and merges nested objects", async () => {
  const calls = [];
  const client = compliantClient({
    async getAccountSettings(option) {
      calls.push(option ?? "default");
      return compliantSettings(option);
    },
  });
  const snapshot = await collectZoomSnapshot(client, { now: NOW });
  assert.deepEqual(calls.sort(), ["default", "meeting_authentication", "meeting_security", "security"]);
  assert.equal(snapshot.settings.settings.security.sign_in_with_two_factor_auth, "all");
  assert.equal(snapshot.settings.settings.meeting_security.waiting_room, true);
  assert.equal(snapshot.settings.settings.meeting_authentication, true);
  assert.equal(snapshot.settings.settings.schedule_meeting.require_password_for_scheduling_new_meetings, true);
  assert.equal(snapshot.settings.locks.meeting_security.waiting_room, true);
  assert.equal(snapshot.operationLogs.from, "2026-08-22");
  assert.equal(snapshot.operationLogs.to, "2026-09-21");
});

test("schema fidelity: every verdict reads the exact documented key path", async () => {
  const keyPaths = {
    "security.sign_in_with_two_factor_auth": ["ZOOM-ID-02", "all"],
    "security.sign_again_period_for_inactivity_on_client": ["ZOOM-ID-06", 30],
    "security.sign_again_period_for_inactivity_on_web": ["ZOOM-ID-06", 15],
    "in_meeting.file_transfer": ["ZOOM-COLLAB-02", false],
    "recording.auto_delete_cmr": ["ZOOM-COLLAB-03", true],
    "recording.auto_delete_cmr_days": ["ZOOM-COLLAB-03", 90],
    "chat.allow_users_to_add_contacts.selected_option": ["ZOOM-COLLAB-07", 2],
    "chat.allow_users_to_chat_with_others.selected_option": ["ZOOM-COLLAB-07", 2],
    "schedule_meeting.require_password_for_scheduling_new_meetings": ["ZOOM-MTG-01", true],
    "meeting_security.waiting_room": ["ZOOM-MTG-02", true],
    "in_meeting.who_can_share_screen": ["ZOOM-MTG-03", "host"],
    "recording.local_recording": ["ZOOM-MTG-04", false],
    "meeting_security.end_to_end_encrypted_meetings": ["ZOOM-MTG-05", true],
    "meeting_security.encryption_type": ["ZOOM-MTG-05", "e2ee"],
    "schedule_meeting.embed_password_in_join_link": ["ZOOM-MTG-06", false],
    "schedule_meeting.use_pmi_for_scheduled_meetings": ["ZOOM-MTG-07", false],
    "schedule_meeting.use_pmi_for_instant_meetings": ["ZOOM-MTG-07", false],
    "meeting_authentication": ["ZOOM-MTG-08", true],
    "in_meeting.custom_data_center_regions": ["ZOOM-MTG-09", true],
    "in_meeting.data_center_regions": ["ZOOM-MTG-09", ["US"]],
    "recording.recording_notification_for_zoom_client.disclaimer_to_participants": ["ZOOM-MTG-10", "All participants"],
  };
  const snapshot = await collectZoomSnapshot(compliantClient(), { now: NOW });
  for (const [path, [findingId, expected]] of Object.entries(keyPaths)) {
    let value = snapshot.settings.settings;
    for (const segment of path.split(".")) value = value?.[segment];
    assert.deepEqual(value, expected, `${findingId} depends on ${path}`);
  }

  const { identity, collaboration, meeting } = await runAllAssessments(compliantClient());
  const all = [...identity.findings, ...collaboration.findings, ...meeting.findings];
  for (const [path, [findingId]] of Object.entries(keyPaths)) {
    const item = all.find((finding) => finding.id === findingId);
    assert.ok(item, findingId);
    assert.equal(item.status, "pass", `${findingId} (${path}) should pass on the documented compliant fixture: ${item.summary}`);
  }
});

test("self-check (d): the compliant fixture passes every automatable control and covers all 25 spec controls", async () => {
  const { identity, collaboration, meeting } = await runAllAssessments(compliantClient());
  const all = [...identity.findings, ...collaboration.findings, ...meeting.findings];
  const manualByDesign = new Set(["ZOOM-ID-07", "ZOOM-COLLAB-08"]);
  for (const item of all) {
    if (manualByDesign.has(item.id)) {
      assert.equal(item.status, "manual", item.id);
      assert.match(item.summary, /developers\.zoom\.us/);
    } else {
      assert.equal(item.status, "pass", `${item.id}: ${item.summary}`);
    }
  }
  const covered = new Set(all.flatMap((item) => item.controls));
  assert.equal(covered.size, 25);
  assert.deepEqual([...covered].sort((a, b) => a - b), ZOOM_SPEC_CONTROLS.map((item) => item.number));
  assert.equal(all.length, 25);
  for (const item of all) {
    assert.ok(item.mappings.some((mapping) => mapping.startsWith("FedRAMP ")), item.id);
    assert.equal(item.mappings.length >= ZOOM_FRAMEWORKS.length, true, item.id);
  }
});

test("self-check (a): every endpoint denied yields manual verdicts that name the endpoint and never pass", async () => {
  const { identity, collaboration, meeting } = await runAllAssessments(deniedClient());
  const all = [...identity.findings, ...collaboration.findings, ...meeting.findings];
  assert.equal(all.length, 25);
  for (const item of all) {
    assert.equal(item.status, "manual", `${item.id}: ${item.summary}`);
    assert.match(item.summary, /^Manual:/);
  }
  assert.match(findingById(identity, "ZOOM-ID-01").summary, /\/users was denied \(403/);
  assert.match(findingById(identity, "ZOOM-ID-02").summary, /settings\?option=security was denied/);
  assert.match(findingById(collaboration, "ZOOM-COLLAB-04").summary, /phone\/account_settings.*was denied/);
  assert.match(findingById(collaboration, "ZOOM-COLLAB-05").summary, /report\/operationlogs.*was denied/);
  assert.match(findingById(meeting, "ZOOM-MTG-02").summary, /settings\?option=meeting_security was denied/);
  assert.ok(identity.errors.length > 0);
});

test("self-check (b): empty inventories and {} settings never pass; emptiness renders manual or warn per control intent", async () => {
  const { identity, collaboration, meeting } = await runAllAssessments(emptyClient());
  const all = [...identity.findings, ...collaboration.findings, ...meeting.findings];
  assert.equal(all.length, 25);
  for (const item of all) {
    assert.notEqual(item.status, "pass", `${item.id}: ${item.summary}`);
  }
  assert.equal(findingById(identity, "ZOOM-ID-01").status, "manual");
  assert.match(findingById(identity, "ZOOM-ID-01").summary, /empty inventory is treated as manual/);
  assert.equal(findingById(identity, "ZOOM-ID-03").status, "manual");
  assert.equal(findingById(identity, "ZOOM-ID-04").status, "manual");
  assert.equal(findingById(collaboration, "ZOOM-COLLAB-01").status, "manual");
  assert.equal(findingById(collaboration, "ZOOM-COLLAB-05").status, "warn");
  assert.match(findingById(collaboration, "ZOOM-COLLAB-05").summary, /emptiness cannot prove retention/);
  assert.equal(findingById(collaboration, "ZOOM-COLLAB-06").status, "manual");
  assert.equal(findingById(meeting, "ZOOM-MTG-01").status, "manual");
  assert.match(findingById(meeting, "ZOOM-MTG-01").summary, /absent key is unknown, not compliant/);
  assert.equal(findingById(meeting, "ZOOM-MTG-10").status, "manual");
});

test("self-check (c): partial inventories and one denied surface never pass and report seen versus total counts", async () => {
  const { identity, collaboration, meeting } = await runAllAssessments(partialClient());
  const all = [...identity.findings, ...collaboration.findings, ...meeting.findings];
  assert.equal(all.length, 25);
  for (const item of all) {
    assert.notEqual(item.status, "pass", `${item.id}: ${item.summary}`);
  }
  const sso = findingById(identity, "ZOOM-ID-01");
  assert.equal(sso.status, "warn");
  assert.match(sso.summary, /Partial inventory: 1 seen of 250/);
  assert.equal(findingById(identity, "ZOOM-ID-04").status, "warn");
  assert.match(findingById(identity, "ZOOM-ID-04").summary, /Partial inventory/);
  assert.equal(findingById(identity, "ZOOM-ID-02").status, "manual");
  assert.match(findingById(identity, "ZOOM-ID-02").summary, /option=security was denied/);
  assert.equal(findingById(collaboration, "ZOOM-COLLAB-03").status, "warn");
  assert.match(findingById(collaboration, "ZOOM-COLLAB-03").summary, /lock state was not visible/);
  assert.equal(findingById(collaboration, "ZOOM-COLLAB-04").status, "manual");
  assert.match(findingById(collaboration, "ZOOM-COLLAB-04").summary, /Zoom Phone/);
  assert.equal(findingById(collaboration, "ZOOM-COLLAB-05").status, "warn");
  assert.equal(findingById(collaboration, "ZOOM-COLLAB-06").status, "warn");
  const password = findingById(meeting, "ZOOM-MTG-01");
  assert.equal(password.status, "warn");
  assert.match(password.summary, /lock state was not visible|truncated/);
  assert.match(findingById(meeting, "ZOOM-MTG-02").summary, /truncated/);
  assert.equal(findingById(meeting, "ZOOM-MTG-07").status, "warn");
  assert.equal(findingById(meeting, "ZOOM-MTG-10").status, "warn");
  assert.match(findingById(meeting, "ZOOM-MTG-10").summary, /truncated/);
});

test("verdict safety: a compliant setting that is not locked is warn, and a group override is reported", async () => {
  const client = compliantClient({
    async getAccountLockSettings() {
      return {};
    },
    async getGroupSettings(_groupId, option) {
      if (option) return compliantSettings(option);
      return { ...compliantSettings(), recording: { local_recording: true } };
    },
  });
  const result = await assessZoomMeetingSecurity(client, { now: NOW });
  const password = findingById(result, "ZOOM-MTG-01");
  assert.equal(password.status, "warn");
  assert.match(password.summary, /not visible in lock_settings/);
  const local = findingById(result, "ZOOM-MTG-04");
  assert.equal(local.status, "warn");
  assert.match(local.summary, /1 sampled groups override it: Finance/);
  assert.deepEqual(local.evidence.groups_relaxing, ["Finance"]);
});

test("verdict safety: non-compliant documented values fail with the documented field named", async () => {
  const client = compliantClient({
    async getAccountSettings(option) {
      if (option === "security") {
        return { security: { sign_in_with_two_factor_auth: "none", sign_again_period_for_inactivity_on_client: 0, sign_again_period_for_inactivity_on_web: 480 } };
      }
      if (option === "meeting_security") {
        return { meeting_security: { waiting_room: false, end_to_end_encrypted_meetings: false, encryption_type: "enhanced_encryption" } };
      }
      if (option === "meeting_authentication") {
        return { meeting_authentication: false };
      }
      return {
        schedule_meeting: { require_password_for_scheduling_new_meetings: false, embed_password_in_join_link: true, use_pmi_for_scheduled_meetings: true, use_pmi_for_instant_meetings: false, personal_meeting: true },
        in_meeting: { screen_sharing: true, who_can_share_screen: "all", file_transfer: true, custom_data_center_regions: false },
        recording: { cloud_recording: true, local_recording: true, auto_delete_cmr: false, recording_disclaimer: false },
        chat: { allow_users_to_add_contacts: { enable: true, selected_option: 1 }, allow_users_to_chat_with_others: { enable: true, selected_option: 2 } },
      };
    },
    async listUsers() {
      return list([
        { id: "u1", email: "u1@example.com", login_types: [101] },
        { id: "u2", email: "u2@example.com", login_types: [100] },
        { id: "u3", email: "u3@example.com", login_types: [1] },
      ]);
    },
    async getManagedDomains() {
      return list([{ domain: "example.com", status: "verified" }, { domain: "pending.example.com", status: "pending" }]);
    },
    async listTrustedDomains() {
      return { items: ["*"], truncated: false, pages: 1 };
    },
    async listImGroups() {
      return list([{ id: "im-1", name: "Everyone", type: "shared" }]);
    },
    async getPhoneAccountSettings() {
      return { auto_call_recording: { enable: true, locked: false }, ad_hoc_call_recording: { enable: true, locked: false } };
    },
  });
  const { identity, collaboration, meeting } = await runAllAssessments(client);

  assert.deepEqual(statuses(identity), {
    "ZOOM-ID-01": "fail",
    "ZOOM-ID-05": "fail",
    "ZOOM-ID-02": "fail",
    "ZOOM-ID-03": "fail",
    "ZOOM-ID-04": "pass",
    "ZOOM-ID-06": "fail",
    "ZOOM-ID-07": "manual",
  });
  assert.match(findingById(identity, "ZOOM-ID-01").summary, /2\/3 active users expose a login_types code other than 101/);
  assert.match(findingById(identity, "ZOOM-ID-03").summary, /pending\.example\.com=pending/);
  assert.match(findingById(identity, "ZOOM-ID-06").summary, /disabled .* for the Zoom client/);

  assert.deepEqual(statuses(collaboration), {
    "ZOOM-COLLAB-01": "fail",
    "ZOOM-COLLAB-02": "fail",
    "ZOOM-COLLAB-03": "fail",
    "ZOOM-COLLAB-04": "warn",
    "ZOOM-COLLAB-05": "pass",
    "ZOOM-COLLAB-06": "warn",
    "ZOOM-COLLAB-07": "fail",
    "ZOOM-COLLAB-08": "manual",
  });

  assert.deepEqual(statuses(meeting), {
    "ZOOM-MTG-01": "fail",
    "ZOOM-MTG-02": "fail",
    "ZOOM-MTG-03": "fail",
    "ZOOM-MTG-04": "fail",
    "ZOOM-MTG-05": "fail",
    "ZOOM-MTG-06": "fail",
    "ZOOM-MTG-07": "fail",
    "ZOOM-MTG-08": "fail",
    "ZOOM-MTG-09": "fail",
    "ZOOM-MTG-10": "fail",
  });
  assert.match(findingById(meeting, "ZOOM-MTG-03").summary, /who_can_share_screen is `all`/);
});

test("verdict safety: role-scoped 2FA passes only when every admin role is listed, and session timeout above policy warns", async () => {
  const roleScoped = (roles) => compliantClient({
    async getAccountSettings(option) {
      if (option === "security") {
        return { security: { sign_in_with_two_factor_auth: "role", sign_in_with_two_factor_auth_roles: roles, sign_again_period_for_inactivity_on_client: 600, sign_again_period_for_inactivity_on_web: 30 } };
      }
      return compliantSettings(option);
    },
  });
  const covered = await assessZoomIdentity(roleScoped(["0", "1"]), { now: NOW });
  assert.equal(findingById(covered, "ZOOM-ID-02").status, "pass");
  assert.equal(findingById(covered, "ZOOM-ID-06").status, "warn");
  assert.match(findingById(covered, "ZOOM-ID-06").summary, /exceeds the 120-minute policy threshold/);

  const uncovered = await assessZoomIdentity(roleScoped(["0"]), { now: NOW });
  assert.equal(findingById(uncovered, "ZOOM-ID-02").status, "fail");
  assert.deepEqual(findingById(uncovered, "ZOOM-ID-02").evidence.uncovered_admin_roles, ["Admin"]);
});

test("verdict safety: users without login_types and logs without time are bucketed separately and cap at warn", async () => {
  const client = compliantClient({
    async listUsers() {
      return list([{ id: "u1", email: "u1@example.com", login_types: [101] }, { id: "u2", email: "u2@example.com" }]);
    },
    async listOperationLogs() {
      return list([{ action: "Update", time: "2026-09-20T10:00:00Z" }, { action: "Delete" }]);
    },
  });
  const identity = await assessZoomIdentity(client, { now: NOW });
  assert.equal(findingById(identity, "ZOOM-ID-01").status, "warn");
  assert.equal(findingById(identity, "ZOOM-ID-01").evidence.unknown_login_users, 1);
  const collaboration = await assessZoomCollaborationGovernance(client, { now: NOW });
  const logs = findingById(collaboration, "ZOOM-COLLAB-05");
  assert.equal(logs.status, "warn");
  assert.equal(logs.evidence.undated_entries, 1);
});

test("verdict safety: recording disclaimer distinguishes documented option names and the deprecated boolean", async () => {
  const withDisclaimer = (recording) => compliantClient({
    async getAccountSettings(option) {
      if (option) return compliantSettings(option);
      return { ...compliantSettings(), recording: { ...compliantSettings().recording, ...recording } };
    },
  });
  const guestOnly = await assessZoomMeetingSecurity(withDisclaimer({ recording_notification_for_zoom_client: { disclaimer_to_participants: "Guest only" } }), { now: NOW });
  assert.equal(findingById(guestOnly, "ZOOM-MTG-10").status, "warn");
  const legacy = await assessZoomMeetingSecurity(withDisclaimer({ recording_notification_for_zoom_client: undefined, recording_disclaimer: true }), { now: NOW });
  assert.equal(findingById(legacy, "ZOOM-MTG-10").status, "pass");
  assert.match(findingById(legacy, "ZOOM-MTG-10").summary, /deprecated but documented/);
  const cloudOff = await assessZoomCollaborationGovernance(withDisclaimer({ cloud_recording: false }), { now: NOW });
  assert.equal(findingById(cloudOff, "ZOOM-COLLAB-03").status, "manual");
  assert.match(findingById(cloudOff, "ZOOM-COLLAB-03").summary, /disabled by configuration/);
});

test("checkZoomAccess reports readable Zoom audit surfaces per documented option view", async () => {
  const result = await checkZoomAccess(compliantClient());
  assert.equal(result.status, "healthy");
  assert.equal(result.surfaces.filter((surface) => surface.status === "readable").length, result.surfaces.length);
  assert.ok(result.surfaces.some((surface) => surface.name === "account_settings:security"));
  assert.ok(result.surfaces.some((surface) => surface.endpoint.includes("setting_types=auto_call_recording")));
  assert.match(result.recommendedNextStep, /zoom_assess_identity/);

  const phoneOnly = await checkZoomAccess(compliantClient({
    async getPhoneAccountSettings() {
      throw new ZoomApiError("Zoom request failed (403 Forbidden): This account does not have Zoom Phone", 403);
    },
  }));
  assert.equal(phoneOnly.status, "healthy");
  assert.ok(phoneOnly.surfaces.some((surface) => surface.name === "phone_account_settings" && surface.status === "not_readable" && /denied/.test(surface.error)));

  const limited = await checkZoomAccess(partialClient());
  assert.equal(limited.status, "limited");
  assert.ok(limited.surfaces.some((surface) => surface.name === "account_settings:security" && surface.status === "not_readable"));

  const denied = await checkZoomAccess(deniedClient());
  assert.equal(denied.status, "limited");
  assert.match(denied.recommendedNextStep, /account:read:admin/);
});

test("exportZoomAuditBundle writes the shared layout, one report per framework, and never overwrites a prior bundle", async () => {
  const base = createTempBase("grclanker-zoom-export-");
  const first = await exportZoomAuditBundle(compliantClient(), sampleConfig(), base, { now: NOW });
  assert.ok(existsSync(first.outputDir));
  assert.ok(existsSync(first.zipPath));
  assert.equal(basename(first.zipPath), `${basename(first.outputDir)}.zip`);
  assert.equal(first.findingCount, 25);
  assert.equal(first.errorCount, 0);
  assert.ok(first.fileCount >= 30);

  const expectedFiles = [
    "README.md",
    "QUICK_REFERENCE.md",
    "metadata.json",
    "summary.md",
    "core_data/access.json",
    "core_data/account_settings.json",
    "core_data/account_lock_settings.json",
    "core_data/users.json",
    "core_data/roles.json",
    "core_data/groups.json",
    "core_data/im_groups.json",
    "core_data/managed_domains.json",
    "core_data/trusted_domains.json",
    "core_data/operation_logs.json",
    "core_data/phone_account_settings.json",
    "analysis/findings.json",
    "analysis/identity.json",
    "analysis/collaboration-governance.json",
    "analysis/meeting-security.json",
    "analysis/summary.json",
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
  ];
  for (const file of expectedFiles) {
    assert.ok(existsSync(join(first.outputDir, file)), file);
  }
  assert.equal(existsSync(join(first.outputDir, "_errors.log")), false);
  assert.equal(readdirSync(join(first.outputDir, "compliance")).length, 2 + ZOOM_FRAMEWORKS.length);

  const metadata = JSON.parse(readFileSync(join(first.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.account_id, "acct-123");
  assert.equal(metadata.finding_count, 25);
  const bundleText = readFileSync(join(first.outputDir, "core_data", "account_settings.json"), "utf8");
  assert.doesNotMatch(bundleText, /zoom-token/);
  const matrix = readFileSync(join(first.outputDir, "compliance", "unified_compliance_matrix.md"), "utf8");
  assert.match(matrix, /25 .*Personal Meeting ID/);
  assert.match(matrix, /ZOOM-MTG-07/);

  const second = await exportZoomAuditBundle(partialClient(), sampleConfig(), base, { now: NOW });
  assert.notEqual(second.outputDir, first.outputDir);
  assert.match(basename(second.outputDir), /-audit-bundle-2$/);
  assert.equal(basename(second.zipPath), `${basename(second.outputDir)}.zip`);
  assert.ok(second.errorCount > 0);
  const errorLog = readFileSync(join(second.outputDir, "_errors.log"), "utf8");
  assert.match(errorLog, /phone_account_settings: .*denied/);
  assert.ok(existsSync(first.zipPath));
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-zoom-path-");
  const outside = createTempBase("grclanker-zoom-outside-");
  const linked = join(base, "linked");
  symlinkSync(outside, linked, "dir");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "linked/file.txt"), /symlinked parent directory/);

  const safe = resolveSecureOutputPath(base, join("reports", "safe.txt"));
  assert.match(safe, /reports\/safe\.txt$/);
});
