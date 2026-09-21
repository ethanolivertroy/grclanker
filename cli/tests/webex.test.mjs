import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { inflateRawSync } from "node:zlib";

import {
  WEBEX_DOCS,
  WEBEX_SURFACE_FIELDS,
  WebexApiClient,
  WebexApiError,
  assessWebexCollaborationGovernance,
  assessWebexIdentity,
  assessWebexMeetingHybridSecurity,
  checkWebexAccess,
  detectTokenType,
  exportWebexAuditBundle,
  parseLinkHeaderNext,
  projectSurface,
  redactSecrets,
  resolveSecureOutputPath,
  resolveWebexConfiguration,
  scrubErrorText,
  scrubValue,
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

/**
 * Rule 9 fixture: one distinctive fake secret per carrier. Documented carriers
 * (recording RCID, meeting MTID and hostKey, webhook secret and URL token, host
 * PIN, SIP ;pwd=) sit next to undocumented extras (guestIssuerKey,
 * bindCredential, activationCode) that a fail-open redactor would copy through.
 */
const FAKE_SECRETS = {
  access_token: "FAKE-ACCESS-TOKEN-a1b2c3",
  client_secret: "FAKE-CLIENT-SECRET-d4e5f6",
  refresh_token: "FAKE-REFRESH-TOKEN-g7h8i9",
  me_sip_pwd: "FAKE-ME-SIP-PWD-j1k2l3",
  me_avatar_token: "FAKE-AVATAR-TOKEN-m4n5o6",
  person_sip_pwd: "FAKE-PERSON-SIP-PWD-p7q8r9",
  person_guest_issuer_key: "FAKE-GUEST-ISSUER-KEY-s1t2u3",
  recording_download_rcid: "FAKE-RCID-DOWNLOAD-v4w5x6",
  recording_playback_rcid: "FAKE-RCID-PLAYBACK-y7z8a9",
  meeting_mtid: "FAKE-MTID-JOIN-b1c2d3",
  meeting_password: "FAKE-MEETING-PASSWORD-e4f5g6",
  meeting_pvs_password: "FAKE-PVS-PASSWORD-h7i8j9",
  meeting_host_key: "FAKE-HOST-KEY-k1l2m3",
  meeting_sip_pwd: "FAKE-MEETING-SIP-PWD-n4o5p6",
  meeting_number: "FAKE-MEETING-NUMBER-q7r8s9",
  pmr_host_pin: "FAKE-HOST-PIN-t1u2v3",
  pmr_link_token: "FAKE-PMR-LINK-TOKEN-w4x5y6",
  pmr_sip_pwd: "FAKE-PMR-SIP-PWD-z7a8b9",
  pmr_access_code: "FAKE-PMR-ACCESS-CODE-c1d2e3",
  webhook_secret: "FAKE-WEBHOOK-SECRET-f4g5h6",
  webhook_url_token: "FAKE-WEBHOOK-URL-TOKEN-i7j8k9",
  connector_bind_credential: "FAKE-BIND-CREDENTIAL-l1m2n3",
  device_activation_code: "FAKE-ACTIVATION-CODE-o4p5q6",
  device_sip_pwd: "FAKE-DEVICE-SIP-PWD-r7s8t9",
  workspace_sip_pwd: "FAKE-WORKSPACE-SIP-PWD-u1v2w3",
  room_sip_pwd: "FAKE-ROOM-SIP-PWD-x4y5z6",
  event_message_text: "FAKE-MESSAGE-TEXT-a7b8c9",
  event_content_token: "FAKE-CONTENT-TOKEN-d1e2f3",
};

function secretConfig() {
  return sampleConfig({
    token: FAKE_SECRETS.access_token,
    refresh: { clientId: "cid", clientSecret: FAKE_SECRETS.client_secret, refreshToken: FAKE_SECRETS.refresh_token },
    sourceChain: ["tests", "args:token", "args:refresh"],
  });
}

function secretClient() {
  return compliantClient({
    async getMe() {
      return {
        id: "me-1", displayName: "Auditor", emails: ["auditor@example.com"], type: "person", roles: ["role-full-admin"],
        sipAddresses: [{ type: "personal-room", value: `sip:auditor@example.webex.com;pwd=${FAKE_SECRETS.me_sip_pwd}`, primary: true }],
        avatar: `https://avatar.example.com/auditor.png?token=${FAKE_SECRETS.me_avatar_token}`,
      };
    },
    async listPeople() {
      return page([
        {
          id: "u1", displayName: "Full Admin", emails: ["admin@example.com"], type: "person", roles: ["role-full-admin"], created: "2021-01-01T00:00:00.000Z",
          sipAddresses: [{ type: "enterprise", value: `sip:admin@example.webex.com;pwd=${FAKE_SECRETS.person_sip_pwd}` }],
          guestIssuerKey: FAKE_SECRETS.person_guest_issuer_key,
        },
        { id: "u2", displayName: "Compliance", emails: ["co@example.com"], type: "person", roles: ["role-compliance"], created: "2021-01-01T00:00:00.000Z" },
        { id: "b1", displayName: "Approved Bot", emails: ["bot@webex.bot"], type: "bot", created: "2022-01-01T00:00:00.000Z" },
        { id: "g1", displayName: "Visitor", emails: ["visitor@example.net"], type: "appuser", created: "2026-09-01T00:00:00.000Z" },
      ]);
    },
    async listAdminRecordings() {
      return page([{
        id: "rec-1", meetingId: "m-1", topic: "Board", createTime: "2026-09-01T00:00:00.000Z", hostEmail: "admin@example.com", siteUrl: "example.webex.com",
        downloadUrl: `https://example.webex.com/example/lsr.php?RCID=${FAKE_SECRETS.recording_download_rcid}`,
        playbackUrl: `https://example.webex.com/example/ldr.php?RCID=${FAKE_SECRETS.recording_playback_rcid}`,
        format: "MP4", serviceType: "MeetingCenter", durationSeconds: 3600, sizeBytes: 1024, status: "available",
      }]);
    },
    async listMeetings() {
      return page([{
        id: "m-1", meetingNumber: FAKE_SECRETS.meeting_number, title: "Weekly", state: "scheduled", siteUrl: "example.webex.com", hostEmail: "admin@example.com",
        webLink: `https://example.webex.com/example/j.php?MTID=${FAKE_SECRETS.meeting_mtid}`,
        password: FAKE_SECRETS.meeting_password,
        phoneAndVideoSystemPassword: FAKE_SECRETS.meeting_pvs_password,
        hostKey: FAKE_SECRETS.meeting_host_key,
        sipAddress: `m-1@example.webex.com;pwd=${FAKE_SECRETS.meeting_sip_pwd}`,
        unlockedMeetingJoinSecurity: "allowJoinWithLobby",
      }]);
    },
    async getMeetingPreferences() {
      return {
        personalMeetingRoom: {
          enabledAutoLock: true, autoLockMinutes: 5, hostPin: FAKE_SECRETS.pmr_host_pin,
          personalMeetingRoomLink: `https://example.webex.com/meet/auditor?token=${FAKE_SECRETS.pmr_link_token}`,
          sipAddress: `auditor@example.webex.com;pwd=${FAKE_SECRETS.pmr_sip_pwd}`,
          telephony: { accessCode: FAKE_SECRETS.pmr_access_code, callInNumbers: [] },
        },
        audio: { defaultAudioType: "webexAudio", enabledGlobalCallIn: false },
        schedulingOptions: { enabledJoinBeforeHost: false },
        sites: [{ siteUrl: "example.webex.com", default: true }],
      };
    },
    async listWebhooks() {
      return page([{
        id: "hook-1", name: "Notifier", resource: "messages", event: "created", status: "active",
        targetUrl: `https://example.com/hook?token=${FAKE_SECRETS.webhook_url_token}`,
        secret: FAKE_SECRETS.webhook_secret,
      }]);
    },
    async listHybridConnectors() {
      return page([{
        id: "conn-1", orgId: "org-123", hybridClusterId: "cluster-1", hostname: "cal-1.example.com", type: "calendar", version: "1.0", status: "operational",
        created: "2026-01-01T00:00:00.000Z", bindCredential: FAKE_SECRETS.connector_bind_credential,
      }]);
    },
    async listDevices() {
      return page([{
        id: "dev-1", displayName: "Room Kit", workspaceId: "ws-1", software: "RoomOS 11.20", upgradeChannel: "stable", connectionStatus: "connected", managedBy: "CUSTOMER",
        activationCode: FAKE_SECRETS.device_activation_code,
        primarySipUrl: `sip:dev@example.webex.com;pwd=${FAKE_SECRETS.device_sip_pwd}`,
      }]);
    },
    async listWorkspaces() {
      return page([{ id: "ws-1", displayName: "Boardroom", type: "meetingRoom", sipAddress: `ws@example.webex.com;pwd=${FAKE_SECRETS.workspace_sip_pwd}` }]);
    },
    async listRooms() {
      return page([{ id: "room-1", title: "General", type: "group", classificationId: "class-1", sipAddress: `room@example.webex.com;pwd=${FAKE_SECRETS.room_sip_pwd}` }]);
    },
    async listEvents() {
      return page([{
        id: "ev-1", resource: "messages", type: "created", actorId: "u1", orgId: "org-123", created: "2026-09-01T00:00:00.000Z",
        data: { text: FAKE_SECRETS.event_message_text, files: [`https://webexapis.com/v1/contents/abc?token=${FAKE_SECRETS.event_content_token}`] },
      }]);
    },
  });
}

function walkFiles(dir) {
  const output = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const pathname = join(dir, entry.name);
    if (entry.isDirectory()) output.push(...walkFiles(pathname));
    else output.push(pathname);
  }
  return output.sort();
}

/** Minimal zip reader: central directory walk plus raw inflate, no external dependency. */
function readZipEntries(buffer) {
  let eocd = -1;
  for (let offset = buffer.length - 22; offset >= 0; offset -= 1) {
    if (buffer.readUInt32LE(offset) === 0x06054b50) {
      eocd = offset;
      break;
    }
  }
  assert.ok(eocd >= 0, "zip end-of-central-directory record not found");
  const entryCount = buffer.readUInt16LE(eocd + 10);
  let cursor = buffer.readUInt32LE(eocd + 16);
  const entries = [];
  for (let index = 0; index < entryCount; index += 1) {
    assert.equal(buffer.readUInt32LE(cursor), 0x02014b50, "central directory header signature");
    const method = buffer.readUInt16LE(cursor + 10);
    const compressedSize = buffer.readUInt32LE(cursor + 20);
    const nameLength = buffer.readUInt16LE(cursor + 28);
    const extraLength = buffer.readUInt16LE(cursor + 30);
    const commentLength = buffer.readUInt16LE(cursor + 32);
    const localOffset = buffer.readUInt32LE(cursor + 42);
    const name = buffer.subarray(cursor + 46, cursor + 46 + nameLength).toString("utf8");
    assert.equal(buffer.readUInt32LE(localOffset), 0x04034b50, "local file header signature");
    const dataStart = localOffset + 30 + buffer.readUInt16LE(localOffset + 26) + buffer.readUInt16LE(localOffset + 28);
    const data = buffer.subarray(dataStart, dataStart + compressedSize);
    const content = method === 8 ? inflateRawSync(data) : data;
    entries.push({ name, content: content.toString("utf8") });
    cursor += 46 + nameLength + extraLength + commentLength;
  }
  return entries.filter((entry) => !entry.name.endsWith("/"));
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
  assert.deepEqual([...passingControls].sort((a, b) => a - b), [3, 9, 10, 13, 14, 15, 16, 19, 20, 24, 25]);
  assert.ok(!passingControls.has(2), "control 2 (admin MFA) stays manual by coordinator ruling and must never roll up as pass");
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
  assert.equal(partialGuests.status, "warn", "rule 1 corollary: a denied /guests/count is a dependent inventory, so the people-based inventory cannot pass");
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

/** Endpoint each client method reads, for 403 fixtures that name the real path. */
const ENDPOINT_OF = {
  getMe: "/people/me",
  listOrganizations: "/organizations",
  getOrganization: "/organizations/org-123",
  listPeople: "/people",
  listRoles: "/roles",
  listLicenses: "/licenses",
  getGuestCount: "/guests/count",
  listEvents: "/events",
  listAdminAuditEvents: "/adminAudit/events",
  listAdminRecordings: "/admin/recordings",
  listMeetings: "/meetings",
  getMeetingPreferences: "/meetingPreferences",
  listMeetingSites: "/meetingPreferences/sites",
  getMeetingCommonSettings: "/admin/meeting/config/commonSettings",
  listHybridClusters: "/hybrid/clusters",
  listHybridConnectors: "/hybrid/connectors",
  listDevices: "/devices",
  listWorkspaces: "/workspaces",
  listRooms: "/rooms",
  listWebhooks: "/webhooks",
};

const TWO_SITES = [{ siteUrl: "a.webex.com", default: true }, { siteUrl: "b.webex.com", default: false }];

/** Rule 1 corollary baseline: fixture (d) with two sites so a per-site commonSettings denial is meaningful. */
function twoSiteClient(overrides = {}) {
  return compliantClient({
    async getMeetingPreferences() {
      return { personalMeetingRoom: { enabledAutoLock: true, autoLockMinutes: 5 }, schedulingOptions: { enabledJoinBeforeHost: false }, sites: TWO_SITES };
    },
    async listMeetingSites() {
      return page(TWO_SITES);
    },
    ...overrides,
  });
}

/** The two-site baseline with exactly the named inventories answering 403 and everything else compliant. */
function denying(methods, overrides = {}) {
  const denied = {};
  for (const method of methods) {
    denied[method] = async () => { throw forbidden(ENDPOINT_OF[method]); };
  }
  return twoSiteClient({ ...denied, ...overrides });
}

/** The two-site baseline with commonSettings denied for one site only. */
function denyingSite(siteUrl, overrides = {}) {
  return twoSiteClient({
    async getMeetingCommonSettings(requested) {
      if (requested === siteUrl) throw forbidden(ENDPOINT_OF.getMeetingCommonSettings);
      return compliantCommonSettings();
    },
    ...overrides,
  });
}

function unreadable(endpoint) {
  return { readable: false, status: 403, error: `Webex request failed (403 Forbidden) for ${endpoint}` };
}

test("corollary hit 1: WEBEX-ID-07 caps at warn when GET /guests/count is denied and renders the API count as null plus status", async () => {
  const identity = await assessWebexIdentity(denying(["getGuestCount"]));
  const guests = byId(identity.findings, "WEBEX-ID-07");
  assert.equal(guests.status, "warn");
  assert.match(
    guests.summary,
    /^1 guest accounts .* were inventoried among 5 people\. GET \/guests\/count was not readable \(403; scope guest-issuer:read\), so the guest-issuer count could not be reconciled with the people-based inventory\. Reconcile the list/,
    "the note follows the same <endpoint> was not readable (<status>; scope <scope>), so <consequence> template as every other finding",
  );
  assert.equal(guests.evidence.guest_count_api, null);
  assert.deepEqual(guests.evidence.guest_count_api_status, unreadable("/guests/count"));
  assert.equal(guests.evidence.guest_count_people, 1, "the people-derived count stays a real value because GET /people was readable");
  assert.equal(guests.evidence.people_seen, 5);
  assert.deepEqual(identity.summary.inventory_status.guest_count, unreadable("/guests/count"));
  assert.ok(identity.errors.some((item) => /^guest_count: .*403/.test(item)));
  for (const id of ["WEBEX-ID-03", "WEBEX-ID-04", "WEBEX-ID-05"]) {
    assert.equal(byId(identity.findings, id).status, "pass", `${id} does not read /guests/count`);
  }

  const denied = byId((await assessWebexIdentity(denying(["listPeople"]))).findings, "WEBEX-ID-07");
  assert.equal(denied.status, "manual");
  assert.equal(denied.evidence.guests, null, "a guest list derived from an unreadable /people is null, not []");
  assert.equal(denied.evidence.guest_count_people, null);
  assert.equal(denied.evidence.people_seen, null);
});

test("corollary hit 2: WEBEX-MTG-02 and WEBEX-MTG-06 cap at warn when GET /meetings is denied, with null sampled counts", async () => {
  const result = await assessWebexMeetingHybridSecurity(denying(["listMeetings"]));
  for (const id of ["WEBEX-MTG-02", "WEBEX-MTG-06"]) {
    const item = byId(result.findings, id);
    assert.equal(item.status, "warn", id);
    assert.match(item.summary, /^a\.webex\.com: .*; b\.webex\.com: .* \(GET \/admin\/meeting\/config\/commonSettings, 2 of 2 sites\)\. GET \/meetings was not readable \(403; scope meeting:schedules_read or meeting:admin_schedule_read\), so the sampled per-meeting lobby and password evidence is unavailable\.$/, id);
    assert.equal(item.evidence.meetings_seen, null, `${id}: meetings_seen must not be a fabricated 0`);
    assert.equal(item.evidence.sampled_allow_join_without_lobby, null);
    assert.equal(item.evidence.sampled_without_password, null);
    assert.equal(item.evidence.meetings_truncated, null);
    assert.deepEqual(item.evidence.meetings_status, unreadable("/meetings"));
    assert.equal(item.evidence.personal_meeting_room_auto_lock, true, "the preferences read stays a real value");
    assert.equal(item.evidence.site_coverage_complete, true);
    assert.equal(item.evidence.sites.length, 2);
  }
  assert.equal(byId(result.findings, "WEBEX-MTG-03").status, "pass", "guest access reads commonSettings only");
  assert.equal(byId(result.findings, "WEBEX-MTG-04").status, "pass");
  assert.equal(result.summary.meetings_seen, null);
  assert.deepEqual(result.summary.inventory_status.meetings, unreadable("/meetings"));
  assert.ok(result.errors.some((item) => /^meetings: .*403/.test(item)));
});

test("corollary hit 3: WEBEX-MTG-02 and WEBEX-MTG-06 cap at warn when GET /meetingPreferences is denied and name the endpoint", async () => {
  const result = await assessWebexMeetingHybridSecurity(denying(["getMeetingPreferences"]));
  for (const id of ["WEBEX-MTG-02", "WEBEX-MTG-06"]) {
    const item = byId(result.findings, id);
    assert.equal(item.status, "warn", id);
    assert.match(item.summary, /\(GET \/admin\/meeting\/config\/commonSettings, 2 of 2 sites\)\. GET \/meetingPreferences was not readable \(403; scope meeting:preferences_read or meeting:admin_preferences_read\), so the Personal Room auto-lock preference is unavailable\.$/, id);
    assert.doesNotMatch(item.summary, /GET \/meetings was not readable/);
    assert.equal(item.evidence.personal_meeting_room_auto_lock, null);
    assert.deepEqual(item.evidence.meeting_preferences_status, unreadable("/meetingPreferences"));
    assert.equal(item.evidence.meetings_seen, 1, "the meetings sample stays a real count because GET /meetings was readable");
    assert.equal(item.evidence.sampled_without_password, 0);
    assert.equal(item.evidence.site_coverage_complete, true, "the site list still came from GET /meetingPreferences/sites");
  }
  assert.equal(byId(result.findings, "WEBEX-MTG-03").status, "pass", "guest access takes its sites from GET /meetingPreferences/sites when it answers");
  assert.ok(result.errors.some((item) => /^meeting_preferences: .*403/.test(item)));
});

test("corollary hit 4: an unreadable GET /people/me caps every token-type-gated finding at warn and names the probe", async () => {
  const assessments = await allAssessments(denying(["getMe"]));
  const findings = findingsOf(assessments);
  const gated = ["WEBEX-COLLAB-04", "WEBEX-COLLAB-05", "WEBEX-MTG-02", "WEBEX-MTG-03", "WEBEX-MTG-06"];
  for (const id of gated) {
    const item = byId(findings, id);
    assert.equal(item.status, "warn", id);
    assert.match(item.summary, / GET \/people\/me was not readable \(403; scope spark:people_read\), so the token type could not be verified and a bot token's partial view cannot be excluded\.$/, id);
    assert.equal(item.evidence.token_type, "unknown", id);
    assert.deepEqual(item.evidence.token_probe_status, unreadable("/people/me"), id);
  }
  for (const id of AUTOMATABLE.filter((entry) => !gated.includes(entry))) {
    assert.equal(byId(findings, id).status, "pass", `${id} reads org-wide admin surfaces that do not depend on the token type`);
  }
  for (const assessment of assessments) {
    assert.equal(assessment.summary.token_type, "unknown");
    assert.ok(assessment.errors.some((item) => /^me: .*403/.test(item)), `${assessment.category} errors array carries the probe failure`);
  }

  const typeless = await assessWebexCollaborationGovernance(twoSiteClient({
    async getMe() {
      return { id: "me-1", displayName: "Auditor" };
    },
  }));
  const rooms = byId(typeless.findings, "WEBEX-COLLAB-04");
  assert.equal(rooms.status, "warn", "a probe that answers without Person.type leaves the same uncertainty");
  assert.match(rooms.summary, /GET \/people\/me was not readable \(the response carried no Person\.type\)/);
  assert.deepEqual(rooms.evidence.token_probe_status, { readable: false, status: null, error: "the response carried no Person.type" });
});

test("corollary wording (a): a denied GET /meetingPreferences/sites is named even when GET /meetingPreferences still lists the sites", async () => {
  const requested = [];
  const result = await assessWebexMeetingHybridSecurity(denying(["listMeetingSites"], {
    async getMeetingCommonSettings(siteUrl) {
      requested.push(siteUrl);
      return compliantCommonSettings();
    },
  }));
  assert.deepEqual(requested.sort(), ["a.webex.com", "b.webex.com"], "the fallback site list from GET /meetingPreferences is still evaluated per site");
  for (const id of ["WEBEX-MTG-02", "WEBEX-MTG-03", "WEBEX-MTG-06"]) {
    const item = byId(result.findings, id);
    assert.equal(item.status, "warn", id);
    assert.match(item.summary, /\(GET \/admin\/meeting\/config\/commonSettings, 2 of 2 sites\)\. The site list \(GET \/meetingPreferences\/sites\) was not readable \(Webex request failed \(403 Forbidden\) for \/meetingPreferences\/sites\), so the 2 sites came from the sites array of GET \/meetingPreferences and site coverage cannot be confirmed complete\./, id);
    assert.equal(item.evidence.site_coverage_complete, false);
    assert.deepEqual(item.evidence.site_list_status, unreadable("/meetingPreferences/sites"), `${id}: site_coverage_complete carries its reason`);
    assert.deepEqual(item.evidence.denied_sites, []);
  }
  assert.ok(result.errors.some((item) => /^meeting_sites: .*403/.test(item)));
  assert.deepEqual(result.summary.inventory_status.meeting_sites, unreadable("/meetingPreferences/sites"));
});

test("corollary wording (b): a commonSettings denial for one site is recorded in the errors array and _errors.log", async () => {
  const result = await assessWebexMeetingHybridSecurity(denyingSite("b.webex.com"));
  assert.deepEqual(result.errors, ["meeting_common_settings[b.webex.com]: Webex request failed (403 Forbidden) for /admin/meeting/config/commonSettings"]);
  for (const id of ["WEBEX-MTG-02", "WEBEX-MTG-03", "WEBEX-MTG-06"]) {
    const item = byId(result.findings, id);
    assert.equal(item.status, "warn", id);
    assert.match(item.summary, /1 of 2 sites could not be read \(b\.webex\.com: Webex request failed \(403 Forbidden\) for \/admin\/meeting\/config\/commonSettings\)/, id);
    assert.deepEqual(item.evidence.site_list_status, { readable: true, truncated: false });
  }
  assert.equal(result.summary.sites_evaluated, 1);
  assert.equal(result.summary.sites_denied, 1);
  assert.deepEqual(result.summary.inventory_status.meeting_common_settings, { readable: true, truncated: true });

  const everySite = await assessWebexMeetingHybridSecurity(denying(["getMeetingCommonSettings"]));
  assert.deepEqual(everySite.errors, [
    "meeting_common_settings[a.webex.com]: Webex request failed (403 Forbidden) for /admin/meeting/config/commonSettings",
    "meeting_common_settings[b.webex.com]: Webex request failed (403 Forbidden) for /admin/meeting/config/commonSettings",
  ], "an all-sites denial lists each site once instead of one anonymous surface entry");

  const base = createTempBase("grclanker-webex-site-errors-");
  const bundle = await exportWebexAuditBundle(denyingSite("b.webex.com"), sampleConfig(), base);
  assert.equal(bundle.errorCount, 1);
  assert.match(readFileSync(join(bundle.outputDir, "_errors.log"), "utf8"), /meeting-hybrid-security: meeting_common_settings\[b\.webex\.com\]: .*403/);
});

/**
 * Reviewer's per-inventory sweep: deny exactly one inventory (fully, or for one
 * site) against the two-site compliant baseline and check that exactly the
 * dependent findings drop below pass while every other baseline pass stays pass.
 */
const COROLLARY_SWEEP = [
  { inventory: "/people/me (token type)", deny: ["getMe"], demotes: ["WEBEX-COLLAB-04", "WEBEX-COLLAB-05", "WEBEX-MTG-02", "WEBEX-MTG-03", "WEBEX-MTG-06"], names: /GET \/people\/me was not readable/ },
  { inventory: "/organizations (orgId configured)", deny: ["listOrganizations"], demotes: [] },
  { inventory: "/organizations (orgId not configured)", deny: ["listOrganizations"], config: { orgId: undefined }, demotes: ["WEBEX-COLLAB-07"], names: /GET \/organizations was not readable/ },
  { inventory: "/organizations/{orgId}", deny: ["getOrganization"], demotes: [] },
  { inventory: "/people", deny: ["listPeople"], demotes: ["WEBEX-ID-03", "WEBEX-ID-04", "WEBEX-ID-05", "WEBEX-ID-07"], names: /\/people(?: and \/roles)? returned 403/ },
  { inventory: "/roles", deny: ["listRoles"], demotes: ["WEBEX-ID-03", "WEBEX-ID-04"], names: /\/roles returned 403/ },
  { inventory: "/guests/count", deny: ["getGuestCount"], demotes: ["WEBEX-ID-07"], names: /GET \/guests\/count was not readable/ },
  { inventory: "/licenses", deny: ["listLicenses"], demotes: ["WEBEX-COLLAB-06"], names: /\/licenses returned 403/ },
  { inventory: "/events", deny: ["listEvents"], demotes: [] },
  { inventory: "/adminAudit/events", deny: ["listAdminAuditEvents"], demotes: ["WEBEX-COLLAB-07"], names: /\/adminAudit\/events returned 403/ },
  { inventory: "/admin/recordings", deny: ["listAdminRecordings"], demotes: [] },
  { inventory: "/rooms", deny: ["listRooms"], demotes: ["WEBEX-COLLAB-04"], names: /\/rooms returned 403/ },
  { inventory: "/webhooks", deny: ["listWebhooks"], demotes: ["WEBEX-COLLAB-05"], names: /\/webhooks returned 403/ },
  { inventory: "/meetings", deny: ["listMeetings"], demotes: ["WEBEX-MTG-02", "WEBEX-MTG-06"], names: /GET \/meetings was not readable/ },
  { inventory: "/meetingPreferences", deny: ["getMeetingPreferences"], demotes: ["WEBEX-MTG-02", "WEBEX-MTG-06"], names: /GET \/meetingPreferences was not readable/ },
  { inventory: "/meetingPreferences/sites (preferences still list sites)", deny: ["listMeetingSites"], demotes: ["WEBEX-MTG-02", "WEBEX-MTG-03", "WEBEX-MTG-06"], names: /\(GET \/meetingPreferences\/sites\) was not readable/ },
  { inventory: "/meetingPreferences/sites and /meetingPreferences", deny: ["listMeetingSites", "getMeetingPreferences"], demotes: ["WEBEX-MTG-02", "WEBEX-MTG-03", "WEBEX-MTG-06"], names: /\(GET \/meetingPreferences\/sites\) was not readable/ },
  { inventory: "/admin/meeting/config/commonSettings (every site)", deny: ["getMeetingCommonSettings"], demotes: ["WEBEX-MTG-02", "WEBEX-MTG-03", "WEBEX-MTG-06"], names: /\/admin\/meeting\/config\/commonSettings returned 403/ },
  { inventory: "commonSettings for b.webex.com only", denySite: "b.webex.com", demotes: ["WEBEX-MTG-02", "WEBEX-MTG-03", "WEBEX-MTG-06"], names: /1 of 2 sites could not be read \(b\.webex\.com: .*403/ },
  { inventory: "/hybrid/clusters", deny: ["listHybridClusters"], demotes: ["WEBEX-MTG-04"], names: /\/hybrid\/clusters returned 403/ },
  { inventory: "/hybrid/connectors", deny: ["listHybridConnectors"], demotes: ["WEBEX-MTG-04"], names: /\/hybrid\/connectors returned 403/ },
  { inventory: "/devices", deny: ["listDevices"], demotes: [] },
  { inventory: "/workspaces", deny: ["listWorkspaces"], demotes: [] },
];

/** Every leaf of a JSON value as [dotted path, value]; an empty array is itself a leaf so a fabricated [] is visible. */
function leafEntries(value, path = []) {
  if (Array.isArray(value)) {
    return value.length === 0 ? [[path.join("."), value]] : value.flatMap((item, index) => leafEntries(item, [...path, String(index)]));
  }
  if (value && typeof value === "object") {
    return Object.entries(value).flatMap(([key, entry]) => leafEntries(entry, [...path, key]));
  }
  return [[path.join("."), value]];
}

/** Every summary and evidence leaf of a run, keyed so a baseline and a denied run line up. */
function renderedLeaves(assessments) {
  return [
    ...assessments.flatMap((assessment) => leafEntries(assessment.summary, [`SUMMARY(${assessment.category})`])),
    ...findingsOf(assessments).flatMap((item) => leafEntries(item.evidence, [item.id])),
  ];
}

/**
 * Keys the reviewer cleared as true counts under denial: the per-category finding tallies count
 * findings, not tenant data, and sites_evaluated counts successful reads beside sites_denied.
 */
const CLEARED_ZERO_KEYS = new Set(["pass", "warn", "fail", "manual", "sites_evaluated"]);

/**
 * Uniform null-rendering standard: a leaf that is 0 or [] in the denied run but was a different
 * value (or absent) in the baseline was derived from the denied inventory and must be null.
 */
function fabricatedZeros(baselineAssessments, deniedAssessments) {
  const baseline = new Map(renderedLeaves(baselineAssessments));
  return renderedLeaves(deniedAssessments)
    .filter(([, value]) => value === 0 || (Array.isArray(value) && value.length === 0))
    .filter(([path]) => !CLEARED_ZERO_KEYS.has(path.split(".").at(-1)))
    .filter(([path, value]) => {
      const before = baseline.get(path);
      return Array.isArray(value) ? !(Array.isArray(before) && before.length === 0) : before !== 0;
    })
    .map(([path, value]) => `${path}=${JSON.stringify(value)}`);
}

test("corollary sweep: denying one inventory demotes exactly its dependent findings and names it, every other pass stays pass, and no summary or evidence leaf renders a fabricated 0 or []", async () => {
  const swept = new Set(COROLLARY_SWEEP.flatMap((row) => row.deny ?? ["getMeetingCommonSettings"]));
  assert.deepEqual([...swept].sort(), [...CLIENT_METHODS].sort(), "every surface the collectors read is swept");
  let leavesChecked = 0;
  for (const row of COROLLARY_SWEEP) {
    const config = sampleConfig(row.config ?? {});
    const configured = { getResolvedConfig: () => config };
    const baselineAssessments = await allAssessments(twoSiteClient(configured));
    const baseline = findingsOf(baselineAssessments);
    const baselinePass = baseline.filter((item) => item.status === "pass").map((item) => item.id).sort();
    assert.deepEqual(baselinePass, [...AUTOMATABLE].sort(), `${row.inventory}: the baseline must pass every automatable finding`);

    const client = row.denySite ? denyingSite(row.denySite, configured) : denying(row.deny, configured);
    const deniedAssessments = await allAssessments(client);
    const findings = findingsOf(deniedAssessments);
    const demoted = baselinePass.filter((id) => byId(findings, id).status !== "pass");
    assert.deepEqual(demoted, [...row.demotes].sort(), `${row.inventory}: exactly the dependent findings drop below pass`);
    for (const id of row.demotes) {
      const item = byId(findings, id);
      assert.notEqual(item.status, "pass");
      assert.match(item.summary, row.names, `${row.inventory}: ${id} names the unreadable inventory`);
    }
    for (const item of findings) {
      assert.ok(["pass", "warn", "fail", "manual"].includes(item.status));
      if (item.status === "manual") assert.match(item.summary, /^Manual:/, `${row.inventory}: ${item.id}`);
      assert.doesNotMatch(item.summary, /\b(?:the |among |across |, )0 (?:administrators|admins|people|bots|guests|spaces|webhooks|meetings|recordings|events|licenses|clusters|connectors|devices|workspaces|sites)\b/, `${row.inventory}: ${item.id} asserts no digit-zero population in prose`);
    }
    const fabricated = fabricatedZeros(baselineAssessments, deniedAssessments);
    assert.deepEqual(fabricated, [], `${row.inventory}: every count or list derived from the denied inventory renders null, not 0 or []`);
    leavesChecked += renderedLeaves(deniedAssessments).length;
  }
  assert.ok(leavesChecked > 5000, `the generalized assertion walked ${leavesChecked} leaves`);
});

test("corollary item 6: WEBEX-ID-02 takes the denied path when GET /roles alone is denied, rendering the administrator fields null and asserting no count", async () => {
  const baseline = byId((await assessWebexIdentity(twoSiteClient())).findings, "WEBEX-ID-02");
  assert.deepEqual(baseline.evidence.admin_users, ["Full Admin"]);
  assert.equal(baseline.evidence.admin_count, 1);
  assert.match(baseline.summary, /the 1 administrators found are listed as evidence only/);

  const identity = await assessWebexIdentity(denying(["listRoles"]));
  const item = byId(identity.findings, "WEBEX-ID-02");
  assert.equal(item.status, "manual");
  assert.equal(item.evidence.admin_users, null, "admin_users derives from /people and /roles together, so a denied /roles renders null, not []");
  assert.equal(item.evidence.admin_count, null, "admin_count renders null, not 0");
  assert.equal(item.evidence.denied_endpoint, "GET /roles");
  assert.deepEqual(item.evidence.inventory_status.roles, unreadable("/roles"));
  assert.deepEqual(item.evidence.inventory_status.people, { readable: true, truncated: false });
  assert.match(item.summary, /^Manual: \/roles returned 403; the token lacks the scope or admin role for roles\. Collect the Control Hub admin list with MFA status for each administrator\. No administrator count is asserted because the list is derived from GET \/people and GET \/roles together\. mfaEnabled is documented/);
  assert.doesNotMatch(item.summary, /\b0\b/, "no digit-zero administrator count anywhere in the summary");
  assert.doesNotMatch(item.summary, /\d+ administrators/);
  assert.equal(identity.summary.admin_users, null, "the category summary and the finding now agree on null for the same quantity");
  for (const id of ["WEBEX-ID-03", "WEBEX-ID-04"]) {
    assert.equal(byId(identity.findings, id).status, "manual", `${id} already took the denied path for /roles`);
  }
  assert.equal(byId(identity.findings, "WEBEX-ID-05").status, "pass", "the bot inventory reads only /people");
  assert.equal(byId(identity.findings, "WEBEX-ID-07").status, "pass", "the guest inventory reads only /people and /guests/count");

  const peopleDenied = await assessWebexIdentity(denying(["listPeople"]));
  const mfa = byId(peopleDenied.findings, "WEBEX-ID-02");
  assert.equal(mfa.evidence.admin_users, null);
  assert.equal(mfa.evidence.admin_count, null);
  assert.equal(mfa.evidence.denied_endpoint, "GET /people");
  assert.match(mfa.summary, /^Manual: \/people returned 403/);
  const botApproval = byId(peopleDenied.findings, "WEBEX-ID-06");
  assert.equal(botApproval.evidence.bot_count, null);
  assert.deepEqual(botApproval.evidence.people_status, unreadable("/people"));
  assert.match(botApproval.summary, /reconcile it with the bot inventory in WEBEX-ID-05, which could not be built because GET \/people was not readable, so no bot count is asserted here\.$/);
  assert.doesNotMatch(botApproval.summary, /\b0 inventoried bots/);
  assert.match(byId((await assessWebexIdentity(twoSiteClient())).findings, "WEBEX-ID-06").summary, /reconcile it with the 1 inventoried bots\.$/);
});

test("corollary bundle check: findings.json never carries ID-07, MTG-02, or MTG-06 as pass when /meetings, /guests/count, and /meetingPreferences are denied", async () => {
  const base = createTempBase("grclanker-webex-corollary-");
  const result = await exportWebexAuditBundle(denying(["listMeetings", "getGuestCount", "getMeetingPreferences"]), sampleConfig(), base);
  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis/findings.json"), "utf8"));
  for (const id of ["WEBEX-ID-07", "WEBEX-MTG-02", "WEBEX-MTG-06"]) {
    const item = findings.find((entry) => entry.id === id);
    assert.equal(item.status, "warn", `${id} must not be pass in the exported bundle`);
  }
  assert.match(byId(findings, "WEBEX-ID-07").summary, /GET \/guests\/count was not readable/);
  assert.match(byId(findings, "WEBEX-MTG-02").summary, /GET \/meetings was not readable .* GET \/meetingPreferences was not readable/);
  assert.equal(byId(findings, "WEBEX-MTG-02").evidence.meetings_seen, null);
  assert.equal(byId(findings, "WEBEX-MTG-02").evidence.personal_meeting_room_auto_lock, null);
  for (const id of ["WEBEX-ID-03", "WEBEX-ID-04", "WEBEX-ID-05", "WEBEX-COLLAB-04", "WEBEX-COLLAB-05", "WEBEX-COLLAB-06", "WEBEX-COLLAB-07", "WEBEX-MTG-03", "WEBEX-MTG-04"]) {
    assert.equal(byId(findings, id).status, "pass", `${id} keeps its complete-inventory pass`);
  }
  assert.equal(result.errorCount, 3);
  const errors = readFileSync(join(result.outputDir, "_errors.log"), "utf8");
  assert.match(errors, /identity: guest_count: .*403/);
  assert.match(errors, /meeting-hybrid-security: meeting_preferences: .*403/);
  assert.match(errors, /meeting-hybrid-security: meetings: .*403/);
  const meeting = JSON.parse(readFileSync(join(result.outputDir, "analysis/meeting-hybrid-security.json"), "utf8"));
  assert.equal(meeting.summary.meetings_seen, null);
  assert.equal(meeting.summary.inventory_status.meetings.readable, false);
  const rawMeetings = JSON.parse(readFileSync(join(result.outputDir, "core_data/meeting-hybrid-security/meetings.json"), "utf8"));
  assert.equal(rawMeetings.status, 403);
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

  const taggedControl2 = identity.findings.filter((item) => item.control.includes(2));
  assert.deepEqual(taggedControl2.map((item) => item.id), ["WEBEX-ID-02"], "only the MFA finding carries control 2");
  assert.ok(taggedControl2.every((item) => item.status === "manual"));
  assert.deepEqual(byId(identity.findings, "WEBEX-ID-04").control, [25], "admin concentration is evidence for control 25, not an MFA verdict");
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

test("rule 9: no fake secret from any carrier reaches any bundle file or any zip entry", async () => {
  const base = createTempBase("grclanker-webex-secrets-");
  const result = await exportWebexAuditBundle(secretClient(), secretConfig(), base);
  assert.equal(result.findingCount, FINDING_COUNT);
  assert.equal(result.errorCount, 0);

  const files = walkFiles(result.outputDir);
  assert.equal(files.length, result.fileCount);
  assert.ok(files.length >= 35, `expected a full bundle, saw ${files.length} files`);
  const secretEntries = Object.entries(FAKE_SECRETS);
  assert.ok(secretEntries.length >= 28);
  const leaks = [];
  for (const file of files) {
    const content = readFileSync(file, "utf8");
    for (const [carrier, value] of secretEntries) {
      if (content.includes(value)) leaks.push(`${carrier} in ${relative(result.outputDir, file)}`);
    }
  }
  assert.deepEqual(leaks, [], `secrets leaked into the bundle directory: ${leaks.join("; ")}`);

  const entries = readZipEntries(readFileSync(result.zipPath));
  assert.equal(entries.length, files.length, "every written file appears exactly once in the zip");
  assert.deepEqual(entries.map((entry) => entry.name).sort(), files.map((file) => relative(result.outputDir, file)).sort());
  const zipLeaks = [];
  for (const entry of entries) {
    for (const [carrier, value] of secretEntries) {
      if (entry.content.includes(value)) zipLeaks.push(`${carrier} in zip:${entry.name}`);
    }
  }
  assert.deepEqual(zipLeaks, [], `secrets leaked into the zip: ${zipLeaks.join("; ")}`);

  const read = (relativePath) => readFileSync(join(result.outputDir, relativePath), "utf8");
  const recordings = JSON.parse(read("core_data/collaboration-governance/admin_recordings.json"));
  assert.equal(recordings[0].downloadUrl, "https://example.webex.com/example/lsr.php");
  assert.equal(recordings[0].playbackUrl, "https://example.webex.com/example/ldr.php");
  assert.equal(recordings[0].status, "available");
  const meetings = JSON.parse(read("core_data/meeting-hybrid-security/meetings.json"));
  assert.equal(meetings[0].webLink, "https://example.webex.com/example/j.php");
  assert.equal(meetings[0].password, "[REDACTED]");
  assert.equal(meetings[0].unlockedMeetingJoinSecurity, "allowJoinWithLobby");
  assert.deepEqual(Object.keys(meetings[0]).filter((key) => ["hostKey", "meetingNumber", "phoneAndVideoSystemPassword", "sipAddress"].includes(key)), []);
  const webhooks = JSON.parse(read("core_data/collaboration-governance/webhooks.json"));
  assert.equal(webhooks[0].targetUrl, "https://example.com/hook");
  assert.equal(webhooks[0].secret, "[REDACTED]");
  const people = JSON.parse(read("core_data/identity/people.json"));
  assert.deepEqual(Object.keys(people[0]).sort(), ["created", "displayName", "emails", "id", "roles", "type"]);
  const preferences = JSON.parse(read("core_data/meeting-hybrid-security/meeting_preferences.json"));
  assert.deepEqual(Object.keys(preferences.personalMeetingRoom).sort(), ["autoLockMinutes", "enabledAutoLock"]);
  assert.equal(preferences.sites[0].siteUrl, "example.webex.com");
  assert.ok(!("activationCode" in JSON.parse(read("core_data/meeting-hybrid-security/devices.json"))[0]));
  assert.ok(!("bindCredential" in JSON.parse(read("core_data/meeting-hybrid-security/hybrid_connectors.json"))[0]));
  assert.ok(!("data" in JSON.parse(read("core_data/collaboration-governance/events.json"))[0]));
  const findings = JSON.parse(read("analysis/findings.json"));
  assert.equal(findings.find((item) => item.id === "WEBEX-COLLAB-05").status, "pass", "scrubbing the webhook URL query must not change the https verdict");
  assert.equal(findings.find((item) => item.id === "WEBEX-MTG-02").status, "pass");
});

/** Rule 9 error path: one canary per carrier that only an error response can bring into the bundle. */
const ERROR_CANARIES = {
  json_message_url_token: "FAKE-ERROR-URL-TOKEN-c1a2n3",
  json_description_url_token: "FAKE-ERROR-DESC-TOKEN-d4e5f6",
  html_bearer: "FAKE-ERROR-BEARER-a4r5y6",
  html_session: "FAKE-ERROR-SESSION-s7e8s9",
  html_api_key: "FAKE-ERROR-API-KEY-k1e2y3",
  refresh_html_bearer: "FAKE-REFRESH-BEARER-r1e2f3",
  network_url_token: "FAKE-NETWORK-URL-TOKEN-n4e5t6",
  network_bearer: "FAKE-NETWORK-BEARER-b7e8a9",
};

function deniedJsonBody() {
  return {
    message: `Access denied; sign in at https://idbroker.webex.com/idb/oauth2/v1/authorize?token=${ERROR_CANARIES.json_message_url_token}&state=1 to continue`,
    errors: [{ description: `Forbidden: see https://idbroker.webex.com/idb/oauth2/v1/authorize?token=${ERROR_CANARIES.json_description_url_token}` }],
    trackingId: "ROUTER_12345",
  };
}

function gatewayHtmlBody() {
  return [
    "<html><head><title>502 Bad Gateway</title></head><body><pre>",
    `upstream request: bearer=${ERROR_CANARIES.html_bearer}; Authorization: Bearer ${ERROR_CANARIES.html_bearer}`,
    `Set-Cookie: session=${ERROR_CANARIES.html_session}; Path=/`,
    `X-Api-Key: ${ERROR_CANARIES.html_api_key}`,
    "</pre></body></html>",
  ].join("\n");
}

/** Routes /rooms to a 403 JSON error with tokenised URLs and /webhooks to a 502 HTML gateway page. */
async function errorPathRouter(input) {
  const pathname = new URL(typeof input === "string" ? input : input.toString()).pathname;
  if (pathname.endsWith("/rooms")) return jsonResponse(deniedJsonBody(), { status: 403, statusText: "Forbidden" });
  if (pathname.endsWith("/webhooks")) return textResponse(gatewayHtmlBody(), { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html; charset=utf-8" } });
  throw new Error(`unexpected fetch ${pathname}`);
}

/** The secret-carrying fixture with two surfaces served through the real client and its real error path. */
function errorPathClient() {
  const real = new WebexApiClient(secretConfig(), { fetchImpl: errorPathRouter });
  return {
    ...secretClient(),
    listRooms: (limit) => real.listRooms(limit),
    listWebhooks: (limit) => real.listWebhooks(limit),
  };
}

test("scrubErrorText is the one scrub for error strings: unanchored URL queries, credential-shaped fragments, idempotent, and applied by the WebexApiError constructor", () => {
  assert.equal(scrubValue("see https://idbroker.webex.com/authorize?token=abc&x=1 to continue"), "see https://idbroker.webex.com/authorize to continue", "scrubValue strips the query of a URL embedded mid-string");
  assert.equal(scrubValue("a https://h/x?q=1#f and b https://h/y#frag."), "a https://h/x and b https://h/y.", "every embedded URL is scrubbed and sentence punctuation survives");
  assert.equal(scrubValue("see https://h/x?token=abc; then https://h/y?token=def, done"), "see https://h/x; then https://h/y, done");
  assert.equal(scrubValue("prefix https://h/x?q=1 sip:u@h;pwd=9;transport=tls"), "prefix https://h/x sip:u@h;transport=tls");

  assert.equal(scrubErrorText("Authorization: Bearer abc123def456ghi"), "Authorization=[REDACTED]");
  assert.equal(scrubErrorText("upstream bearer=FAKE-1234 failed"), "upstream bearer=[REDACTED] failed");
  assert.equal(scrubErrorText("Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig expired"), "Bearer [REDACTED] expired");
  assert.equal(scrubErrorText("Set-Cookie: session=s7e8s9; Path=/"), "Set-Cookie=[REDACTED]; Path=/", "a credential-named header takes its whole value");
  assert.equal(scrubErrorText("cookie session=s7e8s9; Path=/"), "cookie session=[REDACTED]; Path=/");
  assert.equal(scrubErrorText("JSESSIONID=abc123; sid: 42"), "JSESSIONID=[REDACTED]; sid=[REDACTED]");
  assert.equal(scrubErrorText("X-Api-Key: k1e2y3 rejected"), "X-Api-Key=[REDACTED] rejected");
  assert.equal(scrubErrorText('body {"access_token":"tok123","expires_in":3600}'), 'body {"access_token=[REDACTED]","expires_in":3600}');
  assert.equal(scrubErrorText("client_secret=s3cr3t&grant_type=refresh_token&refresh_token=r7"), "client_secret=[REDACTED]&grant_type=refresh_token&refresh_token=[REDACTED]");
  assert.equal(scrubErrorText("password: hunter2, pwd=x1, passcode=9, api_key=k, apikey=k2, credential=c, signature=s"), "password=[REDACTED], pwd=[REDACTED], passcode=[REDACTED], api_key=[REDACTED], apikey=[REDACTED], credential=[REDACTED], signature=[REDACTED]");
  assert.equal(scrubErrorText("Webex request failed (403 Forbidden) for /people: see https://idbroker.webex.com/authorize?token=abc to continue"), "Webex request failed (403 Forbidden) for /people: see https://idbroker.webex.com/authorize to continue");

  const plain = [
    "Webex request failed (403 Forbidden) for /admin/meeting/config/commonSettings",
    "GET /guests/count was not readable (403; scope guest-issuer:read), so the guest-issuer count could not be reconciled with the people-based inventory.",
    "Webex request failed (502 Bad Gateway) for /webhooks: non-JSON error body (text/html; charset=utf-8; 291 bytes)",
    "the token lacks the scope or admin role for people; scope spark-admin:people_read or meeting:admin_schedule_read",
    "Bot tokens cannot read admin surfaces; use an admin, integration, or Service App token.",
  ];
  for (const message of plain) assert.equal(scrubErrorText(message), message, `plain operational text is left alone: ${message}`);
  for (const message of ["Authorization: Bearer abc123def456ghi", "session=abc; bearer=FAKE-1234", "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"]) {
    assert.equal(scrubErrorText(scrubErrorText(message)), scrubErrorText(message), `idempotent: ${message}`);
  }

  const error = new WebexApiError("Webex request failed (401 Unauthorized) for /people: Authorization: Bearer abc123def456ghi at https://h/x?token=t", 401, "/people");
  assert.equal(error.message, "Webex request failed (401 Unauthorized) for /people: Authorization=[REDACTED] at https://h/x", "the constructor scrubs, so no consumer can receive an unscrubbed API error");
  assert.equal(error.status, 401);
  assert.equal(error.endpoint, "/people");
});

test("fetchJson never places a response body in an error string: non-JSON bodies become status, endpoint, content type and length; JSON messages are scrubbed", async () => {
  const gateway = new WebexApiClient(sampleConfig(), { fetchImpl: errorPathRouter });
  const htmlBytes = Buffer.byteLength(gatewayHtmlBody(), "utf8");
  await assert.rejects(() => gateway.listWebhooks(), (error) => {
    assert.ok(error instanceof WebexApiError);
    assert.equal(error.status, 502);
    assert.equal(error.endpoint, "/v1/webhooks");
    assert.equal(error.message, `Webex request failed (502 Bad Gateway) for /v1/webhooks: non-JSON error body (text/html; charset=utf-8; ${htmlBytes} bytes)`);
    for (const canary of Object.values(ERROR_CANARIES)) assert.ok(!error.message.includes(canary));
    assert.ok(!error.message.includes("<html>"));
    return true;
  });
  await assert.rejects(() => gateway.listRooms(), (error) => {
    assert.ok(error instanceof WebexApiError);
    assert.equal(error.status, 403);
    assert.equal(
      error.message,
      "Webex request failed (403 Forbidden) for /v1/rooms: Forbidden: see https://idbroker.webex.com/idb/oauth2/v1/authorize; Access denied; sign in at https://idbroker.webex.com/idb/oauth2/v1/authorize to continue",
      "the documented message fields are kept with their URL queries stripped",
    );
    return true;
  });

  const bareJson = new WebexApiClient(sampleConfig(), { fetchImpl: async () => jsonResponse({ access_token: "leaked-if-copied", trackingId: "T1" }, { status: 500, statusText: "Internal Server Error" }) });
  await assert.rejects(() => bareJson.listRoles(), (error) => {
    assert.equal(error.message, `Webex request failed (500 Internal Server Error) for /v1/roles: JSON error body without a message field (${Buffer.byteLength(JSON.stringify({ access_token: "leaked-if-copied", trackingId: "T1" }))} bytes)`);
    return true;
  });
  const emptyBody = new WebexApiClient(sampleConfig(), { fetchImpl: async () => new Response(null, { status: 404, statusText: "Not Found" }) });
  await assert.rejects(() => emptyBody.listRoles(), (error) => error instanceof WebexApiError && error.message === "Webex request failed (404 Not Found) for /v1/roles");
  const unknownType = new WebexApiClient(sampleConfig(), { fetchImpl: async () => new Response("<b>nope</b>", { status: 503, statusText: "Service Unavailable" }) });
  await assert.rejects(() => unknownType.listRoles(), (error) => /non-JSON error body \(text\/plain;charset=UTF-8; 11 bytes\)$/.test(error.message) || /non-JSON error body \(.*; 11 bytes\)$/.test(error.message));

  const refreshConfig = sampleConfig({ token: undefined, refresh: { clientId: "cid", clientSecret: "csecret", refreshToken: "rtoken" } });
  const refreshBody = `<html>Bearer ${ERROR_CANARIES.refresh_html_bearer}</html>`;
  const refreshHtml = new WebexApiClient(refreshConfig, {
    fetchImpl: async () => textResponse(refreshBody, { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html" } }),
  });
  await assert.rejects(() => refreshHtml.listRoles(), (error) => {
    assert.ok(error instanceof WebexApiError);
    assert.equal(error.endpoint, "/access_token");
    assert.equal(error.message, `Webex token refresh failed (502): non-JSON error body (text/html; ${Buffer.byteLength(refreshBody, "utf8")} bytes)`);
    assert.ok(!error.message.includes(ERROR_CANARIES.refresh_html_bearer));
    return true;
  });
  const refreshOkHtml = new WebexApiClient(refreshConfig, { fetchImpl: async () => textResponse("<html>not json</html>", { headers: { "content-type": "text/html" } }) });
  await assert.rejects(() => refreshOkHtml.listRoles(), (error) => error instanceof WebexApiError && error.message === "Webex token refresh returned non-JSON error body (text/html; 21 bytes) with status 200");
  const refreshDenied = new WebexApiClient(refreshConfig, {
    fetchImpl: async () => jsonResponse({ error: "invalid_grant", error_description: `refresh_token=${FAKE_SECRETS.refresh_token} is expired; sign in at https://idbroker.webex.com/x?token=abc` }, { status: 400, statusText: "Bad Request" }),
  });
  await assert.rejects(() => refreshDenied.listRoles(), (error) => error.message === "Webex token refresh failed (400): refresh_token=[REDACTED] is expired; sign in at https://idbroker.webex.com/x; invalid_grant");

  const networkFailure = compliantClient({
    async listRoles() {
      throw new Error(`connect ECONNREFUSED https://webexapis.com/v1/roles?token=${ERROR_CANARIES.network_url_token} with Authorization: Bearer ${ERROR_CANARIES.network_bearer}`);
    },
  });
  const identity = await assessWebexIdentity(networkFailure);
  const rolesError = identity.errors.find((item) => item.startsWith("roles: "));
  assert.equal(rolesError, "roles: connect ECONNREFUSED https://webexapis.com/v1/roles with Authorization=[REDACTED]", "non-API errors are scrubbed where they become surface errors");
  assert.deepEqual(identity.summary.inventory_status.roles, { readable: false, status: null, error: "connect ECONNREFUSED https://webexapis.com/v1/roles with Authorization=[REDACTED]" });
  assert.equal(byId(identity.findings, "WEBEX-ID-02").evidence.admin_count, null);
  const rendered = JSON.stringify(identity);
  for (const canary of [ERROR_CANARIES.network_url_token, ERROR_CANARIES.network_bearer]) assert.ok(!rendered.includes(canary), `${canary} must not reach any assessment field`);
});

test("rule 9 error path: a JSON error with tokenised URLs and a 502 HTML page with bearer, session, and API key canaries reach no bundle file and no zip entry", async () => {
  const rawJson = JSON.stringify(deniedJsonBody());
  const rawHtml = gatewayHtmlBody();
  const errorCanaries = Object.entries(ERROR_CANARIES).filter(([carrier]) => carrier.startsWith("json_") || carrier.startsWith("html_"));
  assert.equal(errorCanaries.length, 5);
  for (const [carrier, value] of errorCanaries) {
    assert.ok((carrier.startsWith("json_") ? rawJson : rawHtml).includes(value), `negative control: the raw response really carries ${carrier}`);
  }

  const base = createTempBase("grclanker-webex-error-canaries-");
  const result = await exportWebexAuditBundle(errorPathClient(), secretConfig(), base);
  assert.equal(result.findingCount, FINDING_COUNT);
  assert.equal(result.errorCount, 2, "rooms and webhooks failed and nothing else");

  const files = walkFiles(result.outputDir);
  assert.equal(files.length, result.fileCount);
  const entries = readZipEntries(readFileSync(result.zipPath));
  assert.equal(entries.length, files.length);
  const secretEntries = [...Object.entries(FAKE_SECRETS), ...Object.entries(ERROR_CANARIES)];
  const leaks = [];
  for (const file of files) {
    const content = readFileSync(file, "utf8");
    for (const [carrier, value] of secretEntries) if (content.includes(value)) leaks.push(`${carrier} in ${relative(result.outputDir, file)}`);
  }
  for (const entry of entries) {
    for (const [carrier, value] of secretEntries) if (entry.content.includes(value)) leaks.push(`${carrier} in zip:${entry.name}`);
  }
  assert.deepEqual(leaks, []);

  const read = (relativePath) => readFileSync(join(result.outputDir, relativePath), "utf8");
  const errors = read("_errors.log");
  const htmlBytes = Buffer.byteLength(rawHtml, "utf8");
  assert.match(errors, /collaboration-governance: rooms: Webex request failed \(403 Forbidden\) for \/v1\/rooms: Forbidden: see https:\/\/idbroker\.webex\.com\/idb\/oauth2\/v1\/authorize; Access denied; sign in at https:\/\/idbroker\.webex\.com\/idb\/oauth2\/v1\/authorize to continue/, "negative control: the scrubbed error did travel to _errors.log");
  assert.match(errors, new RegExp(`collaboration-governance: webhooks: Webex request failed \\(502 Bad Gateway\\) for /v1/webhooks: non-JSON error body \\(text/html; charset=utf-8; ${htmlBytes} bytes\\)`));
  assert.ok(!errors.includes("<html>") && !errors.includes("Set-Cookie"));
  const access = JSON.parse(read("core_data/access.json"));
  const roomsSurface = access.surfaces.find((item) => item.name === "rooms");
  const webhooksSurface = access.surfaces.find((item) => item.name === "webhooks");
  assert.equal(roomsSurface.status, "not_readable");
  assert.match(roomsSurface.error, /^Webex request failed \(403 Forbidden\) for \/v1\/rooms: Forbidden: see https:\/\/idbroker\.webex\.com\/idb\/oauth2\/v1\/authorize; /);
  assert.equal(webhooksSurface.error, `Webex request failed (502 Bad Gateway) for /v1/webhooks: non-JSON error body (text/html; charset=utf-8; ${htmlBytes} bytes)`);
  const rooms = JSON.parse(read("core_data/collaboration-governance/rooms.json"));
  assert.equal(rooms.status, 403);
  assert.match(rooms.error, /^Webex request failed \(403 Forbidden\) for \/v1\/rooms: /);
  const findings = JSON.parse(read("analysis/findings.json"));
  assert.equal(byId(findings, "WEBEX-COLLAB-04").status, "manual");
  assert.match(byId(findings, "WEBEX-COLLAB-04").summary, /^Manual: \/rooms returned 403/);
  assert.equal(byId(findings, "WEBEX-COLLAB-05").status, "manual");
  assert.match(byId(findings, "WEBEX-COLLAB-05").summary, /^Manual: \/webhooks could not be read \(Webex request failed \(502 Bad Gateway\) for \/v1\/webhooks: non-JSON error body/);
  assert.equal(byId(findings, "WEBEX-MTG-02").status, "pass", "the unrelated surfaces keep their complete-inventory verdicts");
});

test("projectSurface fails closed: unlisted keys are dropped, nested objects need a nested allowlist, values are scrubbed", async () => {
  assert.equal(scrubValue("https://a.webex.com/x/lsr.php?RCID=abc123#frag"), "https://a.webex.com/x/lsr.php");
  assert.equal(scrubValue("https://example.com/hook?token=t&x=1"), "https://example.com/hook");
  assert.equal(scrubValue("sip:u@h.example.com;pwd=1234;transport=tls"), "sip:u@h.example.com;transport=tls");
  assert.equal(scrubValue("room@example.webex.com;pwd=9999"), "room@example.webex.com");
  assert.equal(scrubValue("example.webex.com"), "example.webex.com");
  assert.equal(scrubValue("Is the lobby on?"), "Is the lobby on?");
  assert.deepEqual(
    redactSecrets({ webLink: "https://x.webex.com/j.php?MTID=m1", hostKey: "123456", nested: [{ sipAddress: "sip:a@b;pwd=9" }], count: 2 }),
    { webLink: "https://x.webex.com/j.php", hostKey: "[REDACTED]", nested: [{ sipAddress: "sip:a@b" }], count: 2 },
  );

  const projectedPeople = projectSurface("people", [{
    id: "u1", displayName: "A", emails: ["a@example.com"], type: "person", roles: ["r1"], created: "2021-01-01T00:00:00.000Z",
    guestIssuerKey: "k", sipAddresses: [{ value: "sip:a@b;pwd=1" }], phoneNumbers: [{ value: "+1" }], nickName: "A",
  }]);
  assert.deepEqual(projectedPeople, [{ id: "u1", displayName: "A", emails: ["a@example.com"], type: "person", roles: ["r1"], created: "2021-01-01T00:00:00.000Z" }]);
  assert.deepEqual(projectSurface("roles", [{ id: "r1", name: "Full Administrator", extra: { deep: "x" } }]), [{ id: "r1", name: "Full Administrator" }]);
  assert.deepEqual(
    projectSurface("meeting_common_settings", [{
      siteUrl: "a.webex.com",
      siteOptions: { allowCustomPersonalRoomURL: true },
      securityOptions: { joinBeforeHost: false, requireStrongPassword: true, passwordCriteria: { minLength: 8, disallowValues: ["password"], extra: 1 }, unknownFlag: true },
    }]),
    [{ siteUrl: "a.webex.com", securityOptions: { joinBeforeHost: false, requireStrongPassword: true, passwordCriteria: { minLength: 8, disallowValues: ["password"] } } }],
  );
  assert.deepEqual(projectSurface("guest_count", { count: 3, raw: { body: "3" } }), { count: 3 });
  assert.deepEqual(projectSurface("organization", "not-an-object"), undefined);

  for (const assessment of await allAssessments(compliantClient())) {
    for (const name of Object.keys(assessment.rawData)) {
      assert.ok(name in WEBEX_SURFACE_FIELDS, `${assessment.category} stores surface ${name} without an allowlist`);
    }
  }
  const identity = await assessWebexIdentity(secretClient());
  assert.ok(!JSON.stringify(identity).includes(FAKE_SECRETS.person_guest_issuer_key));
  assert.deepEqual(Object.keys(byId(identity.findings, "WEBEX-ID-01").evidence.organization).sort(), ["created", "displayName", "id"]);
});

test("WebexApiClient stops an endless rel=next chain at the page ceiling and reports truncated: true", async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return jsonResponse({ items: [] }, { headers: { link: `<https://webexapis.com/v1/people?after=page${calls}>; rel="next"` } });
  };
  const capped = await new WebexApiClient(sampleConfig(), { fetchImpl, maxPages: 5 }).listPeople();
  assert.deepEqual(capped, { items: [], truncated: true, pageCount: 5 });
  assert.equal(calls, 5);

  calls = 0;
  const defaulted = await new WebexApiClient(sampleConfig(), { fetchImpl }).listRoles();
  assert.equal(defaulted.truncated, true);
  assert.equal(defaulted.pageCount, 1000);
  assert.equal(calls, 1000);

  calls = 0;
  const finished = await new WebexApiClient(sampleConfig(), { fetchImpl: async () => jsonResponse({ items: [{ id: "a" }] }), maxPages: 1 }).listRoles();
  assert.deepEqual(finished, { items: [{ id: "a" }], truncated: false, pageCount: 1 });
});

test("evidence slices capped at 25 entries carry the matching total and scrubbed URLs", async () => {
  const many = (count, build) => Array.from({ length: count }, (_, index) => build(index + 1));
  const collaboration = await assessWebexCollaborationGovernance(compliantClient({
    async listRooms() {
      return page(many(30, (index) => ({ id: `room-${index}`, title: `Space ${index}`, type: "group" })));
    },
    async listWebhooks() {
      return page(many(30, (index) => ({ id: `hook-${index}`, name: `Hook ${index}`, targetUrl: `http://example.com/hook${index}?token=FAKE-URL-TOKEN-${index}`, status: "active" })));
    },
  }));
  const classification = byId(collaboration.findings, "WEBEX-COLLAB-04");
  assert.equal(classification.status, "fail");
  assert.equal(classification.evidence.rooms_without_classification.length, 25);
  assert.equal(classification.evidence.rooms_without_classification_count, 30);
  const webhooks = byId(collaboration.findings, "WEBEX-COLLAB-05");
  assert.equal(webhooks.status, "fail");
  assert.equal(webhooks.evidence.insecure_webhooks.length, 25);
  assert.equal(webhooks.evidence.insecure_webhooks_count, 30);
  assert.equal(webhooks.evidence.insecure_webhooks[0].target_url, "http://example.com/hook1");
  assert.ok(!JSON.stringify(collaboration).includes("FAKE-URL-TOKEN"));

  const meeting = await assessWebexMeetingHybridSecurity(compliantClient({
    async listHybridConnectors() {
      return page(many(30, (index) => ({ id: `conn-${index}`, type: "calendar", status: "impaired", created: "2026-01-01T00:00:00.000Z" })));
    },
  }));
  const hybrid = byId(meeting.findings, "WEBEX-MTG-04");
  assert.equal(hybrid.status, "fail");
  assert.equal(hybrid.evidence.non_operational.length, 25);
  assert.equal(hybrid.evidence.non_operational_count, 30);
  const devices = byId(meeting.findings, "WEBEX-MTG-05");
  assert.equal(devices.evidence.software_version_count, devices.evidence.software_versions.length);
  assert.equal(devices.evidence.upgrade_channel_count, devices.evidence.upgrade_channels.length);
  const identity = await assessWebexIdentity(compliantClient());
  assert.equal(byId(identity.findings, "WEBEX-ID-03").evidence.compliance_officer_count, 1);
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
