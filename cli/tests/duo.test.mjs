import test from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  DuoAuditorClient,
  assessDuoAdminAccess,
  assessDuoAuthentication,
  assessDuoIntegrations,
  assessDuoMonitoring,
  collectDuoAuthenticationData,
  exportDuoAuditBundle,
  collectDuoAdminAccessData,
  collectDuoIntegrationData,
  collectDuoMonitoringData,
  duoFixedTexts,
  projectCollectionStatus,
  redactBypassCodeRecords,
  redactCarrierText,
  redactErrorText,
  redactFields,
  redactIntegrationRecords,
  resolveDuoConfiguration,
  resolveSecureOutputPath,
  runDuoAccessCheck,
  scrubSnapshotValue,
} from "../dist/extensions/grc-tools/duo.js";
import { readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";
import {
  CANARY,
  CANARY_VALUES,
  ENCODED_FORM_SECRET,
  HTML_BODY_NOTE,
  PARSER_SNIPPET_CANARY,
  PARSER_WORDING,
  REDACTED_CANARY_URL,
  SHORT_BODY_CANARY,
  SHORT_BODY_CONTENT_TYPE,
  assertCanaryFixture,
  assertNoCanaryWindows,
  assertNoCanaryWindowsInFiles,
  assertNoShortBodyFragments,
  assertRedactionCases,
  assertScrubBoundary,
  assertShortBodyRecordedAsNote,
  encodedFormsOf,
  htmlCanaryBody,
  jsonCanaryMessage,
  parserMessageFor,
  parserSnippetBody,
  shortBodyResponse,
} from "./helpers/error-canaries.mjs";
import {
  BEARER_ID_CARRIER_CONTROL_ROWS,
  BEARER_ID_VALUES,
  DEPTH_CONTROL,
  ESCAPED_HEADER_LINES,
  JSON_ESCAPES,
  QUOTED_NON_CREDENTIAL_GROUP,
  assertAuthorizationParameterRows,
  assertBearerIdKeyRows,
  assertBearerIdSnapshotKeys,
  assertCarrierTextScrub,
  assertCredentialPairValuesRemoved,
  assertDepthControl,
  assertDepthControlOutputs,
  assertEscapedHeaderCarriers,
  assertFixedTextsSurvive,
  assertIdentifierKeyRows,
  assertFlagAndPathPairRows,
  assertUrlUserinfoBoundaryRows,
  assertMustKeepRows,
  assertMustRedactRowsBesideMustKeep,
  withPlantedRoutes,
} from "./helpers/redaction-table.mjs";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function dataset(data, error) {
  return error ? { data, error } : { data };
}

/**
 * The configured Duo credentials, alphanumeric and random-looking so no 6-character window of them occurs in the
 * fixture's legitimate values (see the fixture self-check); both are kept out of every output.
 */
const DUO_IKEY_CANARY = "DI3QW3S5UJCSFJFV7VMU";
const DUO_SKEY_CANARY = "H3kzAfks4jCg3VzH9uLuQdH38trqd9uqyzAvJZjd";

function createSampleConfig() {
  return {
    apiHost: "api-example.duosecurity.com",
    ikey: DUO_IKEY_CANARY,
    skey: DUO_SKEY_CANARY,
    lookbackDays: 30,
    sourceChain: ["tests"],
  };
}

function createSampleAuthenticationData() {
  return {
    settings: dataset({
      helpdesk_bypass: "limit",
      helpdesk_bypass_expiration: 60,
    }),
    policies: dataset([
      {
        policy_key: "global",
        policy_name: "Global Policy",
        is_global_policy: true,
        sections: {
          authentication_methods: {
            allowed_auth_list: "webauthn-roaming,duo-push",
            blocked_auth_list: "desktop,duo-passcode,phonecall,sms",
            require_verified_push: true,
            verified_push_digits: 6,
          },
          new_user: {
            new_user_behavior: "enroll",
          },
          remembered_devices: {
            browser_apps: {
              enabled: true,
              user_based: {
                max_time_value: 7,
                max_time_units: "days",
              },
            },
          },
          trusted_endpoints: {
            trusted_endpoint_checking: "require-trusted",
            trusted_endpoint_checking_mobile: "require-trusted",
          },
          duo_desktop: {
            requires_duo_desktop: "macos,windows",
          },
          screen_lock: {
            require_screen_lock: true,
          },
        },
      },
    ]),
    globalPolicy: dataset({
      policy_key: "global",
      policy_name: "Global Policy",
      is_global_policy: true,
      sections: {
        authentication_methods: {
          allowed_auth_list: "webauthn-roaming,duo-push",
          blocked_auth_list: "desktop,duo-passcode,phonecall,sms",
          require_verified_push: true,
          verified_push_digits: 6,
        },
        new_user: {
          new_user_behavior: "enroll",
        },
        remembered_devices: {
          browser_apps: {
            enabled: true,
            user_based: {
              max_time_value: 7,
              max_time_units: "days",
            },
          },
        },
        trusted_endpoints: {
          trusted_endpoint_checking: "require-trusted",
          trusted_endpoint_checking_mobile: "require-trusted",
        },
        duo_desktop: {
          requires_duo_desktop: "macos,windows",
        },
      },
    }),
    users: dataset([{ user_id: "DU123", username: "person@example.gov" }]),
    bypassCodes: dataset([]),
    webauthnCredentials: dataset([{ webauthnkey: "WK123" }]),
    allowedAdminAuthMethods: dataset({
      verified_push_enabled: true,
      verified_push_length: 6,
      webauthn_enabled: true,
      sms_enabled: false,
      voice_enabled: false,
    }),
    authenticationLogs: dataset([
      { txid: "tx-1", factor: "verified_duo_push", result: "success" },
      { txid: "tx-2", factor: "webauthn", result: "success" },
    ]),
  };
}

function createSampleAdminData() {
  return {
    settings: dataset({
      helpdesk_bypass: "limit",
      helpdesk_bypass_expiration: 60,
    }),
    admins: dataset([
      {
        admin_id: "A1",
        email: "owner@example.gov",
        role: "Owner",
        last_login: new Date().toISOString(),
      },
      {
        admin_id: "A2",
        email: "security@example.gov",
        role: "Help Desk",
        last_login: new Date().toISOString(),
      },
    ]),
    allowedAdminAuthMethods: dataset({
      verified_push_enabled: true,
      verified_push_length: 6,
      webauthn_enabled: true,
      sms_enabled: false,
      voice_enabled: false,
    }),
    activityLogs: dataset([{ eventtype: "admin.login", username: "owner@example.gov" }]),
  };
}

function createSampleIntegrationData() {
  return {
    settings: dataset({
      global_ssp_policy_enforced: true,
    }),
    policies: dataset([{ policy_key: "PO1", policy_name: "Global Policy", is_global_policy: true }]),
    globalPolicy: dataset({ policy_key: "global", is_global_policy: true, sections: {} }),
    integrations: dataset([
      {
        integration_key: "DIWEB1",
        name: "VPN",
        type: "websdk",
        user_access: "ALL_USERS",
        policy_key: "PO-VPN",
        prompt_v4_enabled: 1,
        frameless_auth_prompt_enabled: 1,
        self_service_allowed: false,
      },
      {
        integration_key: "DIADMIN1",
        name: "Read-only Admin API",
        type: "adminapi",
        user_access: "NO_USERS",
        adminapi_read_log: 1,
        adminapi_read_resource: 1,
        adminapi_admins_read: 1,
      },
    ]),
  };
}

function createSampleMonitoringData() {
  return {
    settings: dataset({
      fraud_email_enabled: true,
      push_activity_notification_enabled: true,
      email_activity_notification_enabled: false,
    }),
    infoSummary: dataset({
      telephony_credits_remaining: 400,
    }),
    authenticationLogs: dataset([
      { txid: "tx-1", factor: "verified_duo_push", result: "success" },
      { txid: "tx-2", factor: "webauthn", result: "success" },
    ]),
    activityLogs: dataset([{ eventtype: "admin.login" }]),
    telephonyLogs: dataset([]),
    trustMonitorEvents: dataset([{ sekey: "SE1", priority_event: true, state: "new" }]),
  };
}

const NOW_SECONDS = Math.floor(Date.now() / 1000);
const DAY_SECONDS = 24 * 60 * 60;

function forbidden(path) {
  return `Duo API request failed for ${path} (403 Forbidden): Received 403 Forbidden`;
}

function forbiddenDataset(path, fallback) {
  return { data: fallback, error: forbidden(path) };
}

function compliantGlobalPolicy() {
  return {
    policy_key: "POGLOBAL",
    policy_name: "Global Policy",
    is_global_policy: true,
    sections: {
      authentication_policy: { user_auth_behavior: "enforce" },
      authentication_methods: {
        // Admin API documents both lists as comma-separated strings.
        allowed_auth_list: "duo-push,webauthn-platform,webauthn-roaming,hardware-token",
        blocked_auth_list: "desktop,duo-passcode,phonecall,sms",
        require_verified_push: true,
        verified_push_digits: 6,
      },
      new_user: { new_user_behavior: "enroll" },
      remembered_devices: { browser_apps: { enabled: false } },
      trusted_endpoints: {
        trusted_endpoint_checking: "require-trusted",
        trusted_endpoint_checking_mobile: "require-trusted",
      },
      health_checks: {
        requires_duo_desktop: ["macos", "windows", "linux"],
        enforce_encryption: ["macos", "windows", "linux"],
        enforce_firewall: ["macos", "windows", "linux"],
        enforce_system_password: ["macos", "windows", "linux"],
      },
      operating_systems: {
        os_restrictions: {
          macos: { block_policy: "block" },
          windows: { block_policy: "block" },
        },
      },
      full_disk_encryption: { require_encryption: true },
      screen_lock: { require_screen_lock: true },
    },
  };
}

function compliantUser(id, extra = {}) {
  return {
    user_id: id,
    username: `${id}@example.gov`,
    status: "active",
    is_enrolled: true,
    created: NOW_SECONDS - 400 * DAY_SECONDS,
    last_login: NOW_SECONDS - 3 * DAY_SECONDS,
    phones: [{ phone_id: `P-${id}`, activated: true }],
    tokens: [],
    u2f_tokens: [],
    webauthncredentials: [{ webauthnkey: `WK-${id}`, credential_name: "Security key" }],
    ...extra,
  };
}

function compliantSettings() {
  return {
    helpdesk_bypass: "deny",
    helpdesk_bypass_expiration: 0,
    global_ssp_policy_enforced: true,
    fraud_email_enabled: true,
    push_activity_notification_enabled: true,
    email_activity_notification_enabled: true,
    lockout_threshold: 10,
    lockout_expire_duration: 30,
    unenrolled_user_lockout_threshold: 0,
  };
}

function compliantAuthenticationData() {
  const policy = compliantGlobalPolicy();
  return {
    settings: dataset(compliantSettings()),
    policies: dataset([policy], undefined),
    globalPolicy: dataset(policy),
    users: { data: [compliantUser("DU1"), compliantUser("DU2")], total: 2, complete: true },
    bypassCodes: { data: [], total: 0, complete: true },
    webauthnCredentials: {
      data: [
        { webauthnkey: "WK-DU1", uv_capable: true, user: { user_id: "DU1" } },
        { webauthnkey: "WK-DU2", uv_capable: true, user: { user_id: "DU2" } },
      ],
      total: 2,
      complete: true,
    },
    allowedAdminAuthMethods: dataset({
      verified_push_enabled: true,
      verified_push_length: 6,
      webauthn_enabled: true,
      sms_enabled: false,
      voice_enabled: false,
    }),
    authenticationLogs: { data: [{ txid: "tx-1", factor: "webauthn", result: "success" }], complete: true },
    offlineEnrollmentLogs: { data: [], complete: true },
  };
}

function forbiddenAuthenticationData() {
  return {
    settings: forbiddenDataset("/admin/v1/settings", null),
    policies: forbiddenDataset("/admin/v2/policies", []),
    globalPolicy: forbiddenDataset("/admin/v2/policies/global", null),
    users: forbiddenDataset("/admin/v1/users", []),
    bypassCodes: forbiddenDataset("/admin/v1/bypass_codes", []),
    webauthnCredentials: forbiddenDataset("/admin/v1/webauthncredentials", []),
    allowedAdminAuthMethods: forbiddenDataset("/admin/v1/admins/allowed_auth_methods", null),
    authenticationLogs: forbiddenDataset("/admin/v2/logs/authentication", []),
    offlineEnrollmentLogs: forbiddenDataset("/admin/v1/logs/offline_enrollment", []),
  };
}

function emptyAuthenticationData() {
  return {
    settings: dataset({}),
    policies: dataset([]),
    globalPolicy: dataset(null),
    users: dataset([]),
    bypassCodes: dataset([]),
    webauthnCredentials: dataset([]),
    allowedAdminAuthMethods: dataset({}),
    authenticationLogs: dataset([]),
    offlineEnrollmentLogs: dataset([]),
  };
}

function compliantAdminData() {
  return {
    settings: dataset(compliantSettings()),
    admins: {
      data: [
        { admin_id: "A1", email: "owner@example.gov", role: "Owner", status: "Active", last_login: NOW_SECONDS - DAY_SECONDS },
        { admin_id: "A2", email: "helpdesk@example.gov", role: "Help Desk", status: "Active", last_login: NOW_SECONDS - 2 * DAY_SECONDS },
      ],
      total: 2,
      complete: true,
    },
    allowedAdminAuthMethods: dataset({
      verified_push_enabled: true,
      verified_push_length: 6,
      webauthn_enabled: true,
      sms_enabled: false,
      voice_enabled: false,
    }),
    activityLogs: { data: [{ txid: "a-1", action: "admin_login" }], complete: true },
  };
}

function forbiddenAdminData() {
  return {
    settings: forbiddenDataset("/admin/v1/settings", null),
    admins: forbiddenDataset("/admin/v1/admins", []),
    allowedAdminAuthMethods: forbiddenDataset("/admin/v1/admins/allowed_auth_methods", null),
    activityLogs: forbiddenDataset("/admin/v2/logs/activity", []),
  };
}

function findingById(result, id) {
  const finding = result.findings.find((item) => item.id === id);
  assert.ok(finding, `expected finding ${id}`);
  return finding;
}

function assertNoPass(result, label) {
  const passed = result.findings.filter((finding) => finding.status === "Pass").map((finding) => finding.id);
  assert.deepEqual(passed, [], `${label} must not produce Pass findings`);
}

function assertManualContext(finding) {
  assert.equal(finding.status, "Manual", `${finding.id} should be Manual`);
  assert.ok(finding.evidence.some((line) => line.startsWith("endpoint=/admin/")), `${finding.id} names the endpoint`);
  assert.ok(finding.evidence.some((line) => line.startsWith("required_permission=Grant")), `${finding.id} names the permission`);
  assert.ok(finding.evidence.some((line) => line.startsWith("manual_evidence=")), `${finding.id} names the evidence to collect`);
}

function assertEveryManualHasContext(result, label) {
  for (const finding of result.findings.filter((item) => item.status === "Manual")) {
    assertManualContext(finding);
  }
  return result.findings.filter((item) => item.status === "Manual").length;
}

test("DuoAuditorClient sends documented paths and second-based windows for info and offline endpoints", async () => {
  const requests = [];
  const fetchImpl = async (input) => {
    const requestUrl = new URL(typeof input === "string" ? input : input.toString());
    requests.push(requestUrl);
    if (requestUrl.pathname === "/admin/v1/info/authentication_attempts") {
      return new Response(
        JSON.stringify({
          stat: "OK",
          response: { authentication_attempts: { ERROR: 0, FAILURE: 1, FRAUD: 0, SUCCESS: 50 }, mintime: 1, maxtime: 2 },
        }),
        { status: 200 },
      );
    }
    if (requestUrl.pathname === "/admin/v1/logs/offline_enrollment") {
      return new Response(
        JSON.stringify({ stat: "OK", response: [{ action: "o2fa_user_provisioned", username: "jsmith" }] }),
        { status: 200 },
      );
    }
    throw new Error(`Unexpected request: ${requestUrl.pathname}`);
  };

  const client = new DuoAuditorClient(createSampleConfig(), { fetchImpl });
  const attempts = await client.getAuthenticationAttempts(30);
  const offline = await client.listOfflineEnrollmentLogs(30);

  assert.equal(attempts.authentication_attempts.SUCCESS, 50);
  assert.equal(offline.length, 1);

  const attemptsRequest = requests.find((url) => url.pathname === "/admin/v1/info/authentication_attempts");
  const mintime = Number(attemptsRequest.searchParams.get("mintime"));
  const maxtime = Number(attemptsRequest.searchParams.get("maxtime"));
  assert.equal(String(mintime).length, 10, "mintime must be Unix seconds, not milliseconds");
  assert.equal(String(maxtime).length, 10, "maxtime must be Unix seconds, not milliseconds");
  assert.equal(maxtime - mintime, 30 * DAY_SECONDS);
  assert.deepEqual([...attemptsRequest.searchParams.keys()].sort(), ["maxtime", "mintime"]);

  const offlineRequest = requests.find((url) => url.pathname === "/admin/v1/logs/offline_enrollment");
  assert.deepEqual([...offlineRequest.searchParams.keys()], ["mintime"]);
  assert.equal(String(offlineRequest.searchParams.get("mintime")).length, 10);
});

test("DuoAuditorClient pages offline enrollment logs by advancing mintime and marks capped reads incomplete", async () => {
  const requests = [];
  const firstPageStart = NOW_SECONDS - 20 * DAY_SECONDS;
  const fetchImpl = async (input) => {
    const requestUrl = new URL(typeof input === "string" ? input : input.toString());
    assert.equal(requestUrl.pathname, "/admin/v1/logs/offline_enrollment");
    const mintime = Number(requestUrl.searchParams.get("mintime"));
    requests.push(mintime);
    if (requests.length === 1) {
      // Exactly 1000 events: the documented page size, so more may exist.
      const events = Array.from({ length: 1000 }, (_, index) => ({
        action: "o2fa_user_provisioned",
        username: `user${index}`,
        timestamp: firstPageStart + index,
      }));
      return new Response(JSON.stringify({ stat: "OK", response: events }), { status: 200 });
    }
    return new Response(
      JSON.stringify({
        stat: "OK",
        response: [
          { action: "o2fa_user_reenrolled", username: "late", timestamp: mintime + 5 },
          { action: "o2fa_user_deprovisioned", username: "later", timestamp: mintime + 9 },
        ],
      }),
      { status: 200 },
    );
  };

  const client = new DuoAuditorClient(createSampleConfig(), { fetchImpl });
  const events = await client.listOfflineEnrollmentLogs(30);
  assert.equal(events.length, 1002);
  assert.equal(requests.length, 2);
  assert.equal(requests[1], firstPageStart + 999 + 1, "the second call starts at the newest timestamp plus one");
  assert.deepEqual(client.collectionStatus("/admin/v1/logs/offline_enrollment"), { complete: true, totalObjects: 1002 });

  const cappedClient = new DuoAuditorClient(createSampleConfig(), { fetchImpl });
  requests.length = 0;
  const capped = await cappedClient.listOfflineEnrollmentLogs(30, 1000);
  assert.equal(capped.length, 1000);
  assert.equal(requests.length, 1, "the cap stops paging after the full first page");
  assert.deepEqual(cappedClient.collectionStatus("/admin/v1/logs/offline_enrollment"), { complete: false, totalObjects: undefined });
});

test("DuoAuditorClient follows the Trust Monitor next_offset cursor and never reports a truncated read complete", async () => {
  const requests = [];
  const fetchImpl = async (input) => {
    const requestUrl = new URL(typeof input === "string" ? input : input.toString());
    assert.equal(requestUrl.pathname, "/admin/v1/trust_monitor/events");
    requests.push(Object.fromEntries(requestUrl.searchParams.entries()));
    const offset = requestUrl.searchParams.get("offset");
    if (offset === null) {
      return new Response(
        JSON.stringify({
          stat: "OK",
          response: { events: [{ sekey: "SE1", state: "new" }, { sekey: "SE2", state: "new" }], metadata: { next_offset: "31229" } },
        }),
        { status: 200 },
      );
    }
    assert.equal(offset, "31229", "the documented opaque cursor is sent back verbatim as offset");
    return new Response(
      JSON.stringify({ stat: "OK", response: { events: [{ sekey: "SE3", state: "closed" }], metadata: {} } }),
      { status: 200 },
    );
  };

  const client = new DuoAuditorClient(createSampleConfig(), { fetchImpl });
  const events = await client.listTrustMonitorEvents(30);
  assert.equal(events.length, 3);
  assert.equal(requests.length, 2);
  assert.equal("offset" in requests[0], false, "the first request carries no offset");
  assert.equal("next_offset" in requests[1], false, "the cursor is passed as offset, not next_offset");
  assert.equal(requests[0].limit, "200");
  assert.equal(String(requests[0].mintime).length, 13, "Trust Monitor mintime is a 13-digit millisecond timestamp");
  assert.equal(String(requests[0].maxtime).length, 13);
  assert.deepEqual(client.collectionStatus("/admin/v1/trust_monitor/events"), { totalObjects: undefined, complete: true });

  const cappedClient = new DuoAuditorClient(createSampleConfig(), { fetchImpl });
  const capped = await cappedClient.listTrustMonitorEvents(30, 2);
  assert.equal(capped.length, 2);
  assert.deepEqual(cappedClient.collectionStatus("/admin/v1/trust_monitor/events"), { totalObjects: undefined, complete: false });
});

test("DuoAuditorClient records incomplete inventories when total_objects exceeds the collected records", async () => {
  const fetchImpl = async (input) => {
    const requestUrl = new URL(typeof input === "string" ? input : input.toString());
    if (requestUrl.pathname === "/admin/v1/users") {
      assert.equal(requestUrl.searchParams.get("limit"), "100");
      return new Response(
        JSON.stringify({
          stat: "OK",
          response: [{ user_id: "DU-1" }],
          metadata: { total_objects: 5 },
        }),
        { status: 200 },
      );
    }
    throw new Error(`Unexpected request: ${requestUrl.pathname}`);
  };
  const client = new DuoAuditorClient(createSampleConfig(), { fetchImpl });
  const users = await client.listUsers();
  assert.equal(users.length, 1);
  assert.deepEqual(client.collectionStatus("/admin/v1/users"), { totalObjects: 5, complete: false });

  const data = await collectDuoAuthenticationData(
    {
      getSettings: async () => compliantSettings(),
      listPolicies: async () => [compliantGlobalPolicy()],
      getGlobalPolicy: async () => compliantGlobalPolicy(),
      listUsers: () => client.listUsers(),
      listBypassCodes: async () => [],
      listWebauthnCredentials: async () => [],
      getAdminAllowedAuthMethods: async () => ({ webauthn_enabled: true }),
      listAuthenticationLogs: async () => [],
      collectionStatus: (path) => client.collectionStatus(path),
    },
    30,
  );
  assert.equal(data.users.complete, false);
  assert.equal(data.users.total, 5);
  assert.match(data.offlineEnrollmentLogs.error, /offline_enrollment/);
});

test("assessDuoAuthentication passes a fully compliant tenant on every automatable control", () => {
  const result = assessDuoAuthentication(compliantAuthenticationData(), createSampleConfig());
  const statuses = Object.fromEntries(result.findings.map((finding) => [finding.id, finding.status]));
  assert.equal(statuses["DUO-AUTH-001"], "Pass");
  assert.equal(statuses["DUO-AUTH-002"], "Pass");
  assert.equal(statuses["DUO-AUTH-003"], "Pass");
  assert.equal(statuses["DUO-AUTH-004"], "Pass");
  assert.equal(statuses["DUO-AUTH-005"], "Pass");
  assert.equal(statuses["DUO-AUTH-006"], "Pass");
  assert.equal(statuses["DUO-AUTH-007"], "Pass");
  assert.equal(statuses["DUO-AUTH-008"], "Pass");
  assert.equal(statuses["DUO-AUTH-009"], "Pass");
  assert.equal(statuses["DUO-AUTH-010"], "Pass");
  assert.equal(statuses["DUO-AUTH-011"], "Manual", "offline access has no documented policy section and stays Manual");
  assert.match(findingById(result, "DUO-AUTH-011").summary, /Policy Section Data/);
});

test("assessDuoAuthentication never passes when every call is forbidden", () => {
  const result = assessDuoAuthentication(forbiddenAuthenticationData(), createSampleConfig());
  assertNoPass(result, "forbidden authentication data");
  assert.equal(result.findings.length, 11);
  for (const finding of result.findings) {
    assertManualContext(finding);
  }
});

test("assessDuoAuthentication treats empty inventories as Manual except compliant-by-intent bypass codes", () => {
  const result = assessDuoAuthentication(emptyAuthenticationData(), createSampleConfig());
  const passed = result.findings.filter((finding) => finding.status === "Pass").map((finding) => finding.id);
  assert.deepEqual(passed, ["DUO-AUTH-006"], "only the empty bypass-code inventory is compliant by intent");
  assert.match(findingById(result, "DUO-AUTH-006").evidence.join(" "), /compliant by intent/);
  assert.equal(findingById(result, "DUO-AUTH-008").status, "Manual");
  assert.equal(findingById(result, "DUO-AUTH-009").status, "Manual");
  assert.equal(findingById(result, "DUO-AUTH-010").status, "Manual");
  assert.equal(findingById(result, "DUO-AUTH-007").status, "Manual");
});

test("assessDuoAuthentication fails on bypass, unenrolled, inactive, and undated users", () => {
  const data = compliantAuthenticationData();
  data.users = dataset([
    compliantUser("DU1"),
    compliantUser("DU2", { status: "bypass" }),
    compliantUser("DU3", { is_enrolled: false, phones: [], webauthncredentials: [] }),
    compliantUser("DU4", { last_login: NOW_SECONDS - 120 * DAY_SECONDS, webauthncredentials: [] }),
    compliantUser("DU5", { last_login: null, webauthncredentials: [] }),
    compliantUser("DU6", { status: "disabled", last_login: null }),
  ]);
  const result = assessDuoAuthentication(data, createSampleConfig());

  const enrollment = findingById(result, "DUO-AUTH-008");
  assert.equal(enrollment.status, "Fail");
  assert.ok(enrollment.evidence.includes("status_bypass=1"));
  assert.ok(enrollment.evidence.includes("not_enrolled=1"));
  assert.ok(enrollment.evidence.includes("bypass_user=DU2@example.gov"));

  const inactive = findingById(result, "DUO-AUTH-009");
  assert.equal(inactive.status, "Fail");
  assert.ok(inactive.evidence.includes("inactive_over_90_days=1"));
  assert.ok(inactive.evidence.includes("never_logged_in_or_undated=1"), "disabled users are excluded from the undated bucket");

  const adoption = findingById(result, "DUO-AUTH-010");
  assert.equal(adoption.status, "Partial");
});

test("assessDuoAuthentication caps undated-only populations at Partial and fails bypass enforcement", () => {
  const data = compliantAuthenticationData();
  data.users = dataset([compliantUser("DU1"), compliantUser("DU2", { last_login: null })]);
  data.globalPolicy.data.sections.authentication_policy.user_auth_behavior = "bypass";
  data.policies.data[0].sections.authentication_policy.user_auth_behavior = "bypass";
  const result = assessDuoAuthentication(data, createSampleConfig());
  assert.equal(findingById(result, "DUO-AUTH-009").status, "Partial");
  assert.equal(findingById(result, "DUO-AUTH-007").status, "Fail");

  const noWebauthn = compliantAuthenticationData();
  noWebauthn.users = dataset([compliantUser("DU1", { webauthncredentials: [] })]);
  assert.equal(findingById(assessDuoAuthentication(noWebauthn, createSampleConfig()), "DUO-AUTH-010").status, "Fail");
});

test("assessDuoAuthentication downgrades incomplete user inventories to Partial with seen and total counts", () => {
  const data = compliantAuthenticationData();
  data.users = { data: [compliantUser("DU1")], total: 40, complete: false };
  const result = assessDuoAuthentication(data, createSampleConfig());
  for (const id of ["DUO-AUTH-008", "DUO-AUTH-009", "DUO-AUTH-010"]) {
    const finding = findingById(result, id);
    assert.equal(finding.status, "Partial", `${id} must not pass on a partial inventory`);
    assert.ok(finding.evidence.some((line) => line.includes("inventory_seen=1 inventory_total=40")), `${id} reports seen and total`);
  }
});

function withAuthMethods(authenticationMethods) {
  const data = compliantAuthenticationData();
  data.globalPolicy.data.sections.authentication_methods = authenticationMethods;
  data.policies.data[0].sections.authentication_methods = authenticationMethods;
  return data;
}

test("assessDuoAuthentication treats telephony as permitted unless blocked_auth_list blocks it", () => {
  const config = createSampleConfig();

  // Documented defaults: the allow-list includes sms and the block-list omits it.
  const defaults = withAuthMethods({
    allowed_auth_list: "bypass,bypass-pwl,duo-push,duo-push-pwl,hardware-token,sms,webauthn-platform,webauthn-platform-pwl,webauthn-roaming,webauthn-roaming-pwl",
    blocked_auth_list: "desktop,duo-passcode,phonecall",
    require_verified_push: true,
    verified_push_digits: 6,
  });
  const defaultFinding = findingById(assessDuoAuthentication(defaults, config), "DUO-AUTH-002");
  assert.equal(defaultFinding.status, "Partial", "sms is explicitly allowed while phonecall is blocked");
  assert.ok(defaultFinding.evidence.includes("permitted_telephony_methods=sms"));
  assert.equal(findingById(assessDuoAuthentication(defaults, config), "DUO-AUTH-001").status, "Pass", "string allow-lists still feed the phishing-resistant check");

  // sms is absent from the allow-list but not blocked, so it is still permitted.
  const notBlocked = withAuthMethods({
    allowed_auth_list: "duo-push,webauthn-roaming",
    blocked_auth_list: "desktop,duo-passcode,phonecall",
    require_verified_push: true,
  });
  const notBlockedFinding = findingById(assessDuoAuthentication(notBlocked, config), "DUO-AUTH-002");
  assert.equal(notBlockedFinding.status, "Partial");
  assert.match(notBlockedFinding.summary, /not in blocked_auth_list: sms/);
  assert.ok(notBlockedFinding.evidence.includes("blocked_telephony_methods=phonecall"));

  // Neither telephony method blocked.
  const neither = withAuthMethods({ allowed_auth_list: "duo-push,webauthn-roaming", blocked_auth_list: "desktop", require_verified_push: true });
  assert.equal(findingById(assessDuoAuthentication(neither, config), "DUO-AUTH-002").status, "Fail");

  // Both blocked, allow-list provided in the JSON array shape.
  const arrays = withAuthMethods({
    allowed_auth_list: ["duo-push", "webauthn-roaming"],
    blocked_auth_list: ["desktop", "duo-passcode", "phonecall", "sms"],
    require_verified_push: true,
  });
  const arraysFinding = findingById(assessDuoAuthentication(arrays, config), "DUO-AUTH-002");
  assert.equal(arraysFinding.status, "Pass");
  assert.ok(arraysFinding.evidence.includes("blocked_telephony_methods=sms,phonecall"));

  // Without blocked_auth_list nothing can be confirmed blocked.
  const noBlockList = withAuthMethods({ allowed_auth_list: "duo-push,webauthn-roaming", require_verified_push: true });
  const noBlockListFinding = findingById(assessDuoAuthentication(noBlockList, config), "DUO-AUTH-002");
  assert.equal(noBlockListFinding.status, "Manual");
  assert.ok(noBlockListFinding.evidence.includes("authentication_methods.blocked_auth_list=absent"));

  const noLists = withAuthMethods({ require_verified_push: true });
  assert.equal(findingById(assessDuoAuthentication(noLists, config), "DUO-AUTH-002").status, "Manual");
});

function bypassCode(id, extra = {}) {
  // Documented Retrieve Bypass Codes response shape.
  return {
    admin_email: "janesmith@example.gov",
    bypass_code_id: id,
    created: NOW_SECONDS - 2 * 60 * 60,
    expiration: NOW_SECONDS + 60 * 60,
    reuse_count: 1,
    user: { user_id: `DU-${id}`, username: `${id.toLowerCase()}@example.gov`, status: "active" },
    ...extra,
  };
}

test("assessDuoAuthentication audits bypass codes with the documented created, expiration, and reuse_count fields", () => {
  const config = createSampleConfig();

  const fresh = compliantAuthenticationData();
  fresh.bypassCodes = { data: [bypassCode("DB1")], total: 1, complete: true };
  const freshFinding = findingById(assessDuoAuthentication(fresh, config), "DUO-AUTH-006");
  assert.equal(freshFinding.status, "Partial", "active but fresh, limited codes are Partial rather than Pass");
  assert.ok(freshFinding.evidence.includes("codes_older_than_24_hours=0"));
  assert.ok(freshFinding.evidence.includes("codes_with_unlimited_uses=0"));

  const stale = compliantAuthenticationData();
  stale.bypassCodes = dataset([bypassCode("DB2", { created: NOW_SECONDS - 30 * 60 * 60, expiration: NOW_SECONDS + 10 * 60 * 60 })]);
  const staleFinding = findingById(assessDuoAuthentication(stale, config), "DUO-AUTH-006");
  assert.equal(staleFinding.status, "Fail");
  assert.ok(staleFinding.evidence.includes("codes_older_than_24_hours=1"));
  assert.ok(staleFinding.evidence.some((line) => line.startsWith("stale_bypass_code=DB2 user=db2@example.gov")));

  const unlimitedUses = compliantAuthenticationData();
  unlimitedUses.bypassCodes = dataset([bypassCode("DB3", { reuse_count: null })]);
  const unlimitedFinding = findingById(assessDuoAuthentication(unlimitedUses, config), "DUO-AUTH-006");
  assert.equal(unlimitedFinding.status, "Fail");
  assert.ok(unlimitedFinding.evidence.includes("codes_with_unlimited_uses=1"));
  assert.ok(unlimitedFinding.evidence.some((line) => line.startsWith("unlimited_bypass_code=DB3") && line.includes("reuse_count=null")));

  const neverExpires = compliantAuthenticationData();
  neverExpires.bypassCodes = dataset([bypassCode("DB4", { expiration: null })]);
  const neverExpiresFinding = findingById(assessDuoAuthentication(neverExpires, config), "DUO-AUTH-006");
  assert.equal(neverExpiresFinding.status, "Fail");
  assert.ok(neverExpiresFinding.evidence.includes("codes_without_expiration=1"));

  const undated = compliantAuthenticationData();
  undated.bypassCodes = dataset([bypassCode("DB5", { created: null })]);
  const undatedFinding = findingById(assessDuoAuthentication(undated, config), "DUO-AUTH-006");
  assert.equal(undatedFinding.status, "Partial");
  assert.ok(undatedFinding.evidence.includes("codes_undated=1"));

  const expired = compliantAuthenticationData();
  expired.bypassCodes = dataset([bypassCode("DB6", { created: NOW_SECONDS - 3 * DAY_SECONDS, expiration: NOW_SECONDS - DAY_SECONDS })]);
  const expiredFinding = findingById(assessDuoAuthentication(expired, config), "DUO-AUTH-006");
  assert.equal(expiredFinding.status, "Partial", "codes already expired by date are reported but not flagged as stale");
  assert.ok(expiredFinding.evidence.includes("codes_expired=1"));

  const partialInventory = compliantAuthenticationData();
  partialInventory.bypassCodes = { data: [], total: 12, complete: false };
  const partialFinding = findingById(assessDuoAuthentication(partialInventory, config), "DUO-AUTH-006");
  assert.equal(partialFinding.status, "Partial", "an empty page of an incomplete inventory cannot pass");
  assert.ok(partialFinding.evidence.some((line) => line.includes("inventory_seen=0 inventory_total=12")));

  const forbiddenResult = findingById(assessDuoAuthentication(forbiddenAuthenticationData(), config), "DUO-AUTH-006");
  assert.equal(forbiddenResult.status, "Manual");
  assert.ok(forbiddenResult.evidence.includes("endpoint=/admin/v1/bypass_codes"));
});

test("assessDuoAuthentication reports trusted endpoint evidence with the documented device health keys", () => {
  const config = createSampleConfig();
  const compliant = findingById(assessDuoAuthentication(compliantAuthenticationData(), config), "DUO-AUTH-005");
  assert.equal(compliant.status, "Pass");
  assert.ok(compliant.evidence.includes("requires_duo_desktop=macos,windows,linux"), "requires_duo_desktop is an operating system list");
  assert.ok(compliant.evidence.includes("full_disk_encryption.require_encryption=true"));
  assert.ok(compliant.evidence.includes("screen_lock.require_screen_lock=true"));

  const legacy = compliantAuthenticationData();
  for (const policy of [legacy.globalPolicy.data, legacy.policies.data[0]]) {
    delete policy.sections.health_checks;
    policy.sections.duo_desktop = { requires_duo_desktop: "windows" };
    policy.sections.full_disk_encryption = { require_disk_encryption: true };
  }
  const legacyFinding = findingById(assessDuoAuthentication(legacy, config), "DUO-AUTH-005");
  assert.ok(legacyFinding.evidence.includes("requires_duo_desktop=windows"), "the deprecated duo_desktop section uses the same OS list shape");
  assert.equal(
    legacyFinding.evidence.some((line) => line.startsWith("full_disk_encryption")),
    false,
    "an undocumented require_disk_encryption key never counts as encryption evidence",
  );
});

test("assessDuoAdminAccess evaluates lockout policy and undated administrators", () => {
  const compliant = assessDuoAdminAccess(compliantAdminData(), createSampleConfig());
  for (const id of ["DUO-ADMIN-001", "DUO-ADMIN-002", "DUO-ADMIN-003", "DUO-ADMIN-004", "DUO-ADMIN-005"]) {
    assert.equal(findingById(compliant, id).status, "Pass", `${id} passes on the compliant tenant`);
  }

  const forbiddenResult = assessDuoAdminAccess(forbiddenAdminData(), createSampleConfig());
  assertNoPass(forbiddenResult, "forbidden admin data");
  assert.equal(forbiddenResult.findings.length, 5);
  for (const finding of forbiddenResult.findings) {
    assertManualContext(finding);
  }
  assert.equal(
    forbiddenResult.findings.some((finding) => finding.id.startsWith("DUO-MON-")),
    false,
    "the admin-access assessment no longer emits a monitoring finding id",
  );

  const emptyResult = assessDuoAdminAccess(
    { settings: dataset({}), admins: dataset([]), allowedAdminAuthMethods: dataset({}), activityLogs: dataset([]) },
    createSampleConfig(),
  );
  assertNoPass(emptyResult, "empty admin data");
  assert.equal(emptyResult.snapshotSummary.activity_logs_readable, "yes", "activity log readability is reported as evidence, not as a finding");

  const weak = compliantAdminData();
  weak.settings = dataset({ ...compliantSettings(), lockout_threshold: 25 });
  assert.equal(findingById(assessDuoAdminAccess(weak, createSampleConfig()), "DUO-ADMIN-005").status, "Partial");
  weak.settings = dataset({ ...compliantSettings(), lockout_threshold: 0 });
  assert.equal(findingById(assessDuoAdminAccess(weak, createSampleConfig()), "DUO-ADMIN-005").status, "Fail");
  weak.settings = dataset({ ...compliantSettings(), lockout_threshold: "unknown" });
  assert.equal(findingById(assessDuoAdminAccess(weak, createSampleConfig()), "DUO-ADMIN-005").status, "Manual");

  const undated = compliantAdminData();
  undated.admins = dataset([
    { admin_id: "A1", email: "owner@example.gov", role: "Owner", status: "Active", last_login: null },
  ]);
  const undatedResult = findingById(assessDuoAdminAccess(undated, createSampleConfig()), "DUO-ADMIN-004");
  assert.equal(undatedResult.status, "Partial");
  assert.ok(undatedResult.evidence.includes("undated_admins=1"));

  const partial = compliantAdminData();
  partial.admins = { data: partial.admins.data, total: 9, complete: false };
  assert.equal(findingById(assessDuoAdminAccess(partial, createSampleConfig()), "DUO-ADMIN-001").status, "Partial");
});

function compliantIntegrationData() {
  const policy = compliantGlobalPolicy();
  return {
    settings: dataset(compliantSettings()),
    policies: dataset([policy]),
    globalPolicy: dataset(policy),
    infoSummary: dataset({ edition: "Duo Premier", integration_count: 2, user_count: 2, admin_count: 2 }),
    integrations: {
      data: [
        {
          integration_key: "DIVPN",
          name: "VPN",
          type: "websdk",
          user_access: "ALL_USERS",
          policy_key: "PO-VPN",
          sensitivity_level: "Critical",
          compliance_requirements: ["FedRAMP"],
          prompt_v4_enabled: 1,
          frameless_auth_prompt_enabled: 1,
          self_service_allowed: false,
        },
        {
          integration_key: "DIAUDIT",
          name: "grclanker audit",
          type: "adminapi",
          user_access: "NO_USERS",
          adminapi_read_log: 1,
          adminapi_read_resource: 1,
          adminapi_admins_read: 1,
          adminapi_info: 1,
          adminapi_settings: 0,
          adminapi_write_resource: 0,
          adminapi_integrations: 0,
          adminapi_allow_to_set_permissions: 0,
        },
      ],
      total: 2,
      complete: true,
    },
  };
}

function forbiddenIntegrationData() {
  return {
    settings: forbiddenDataset("/admin/v1/settings", null),
    policies: forbiddenDataset("/admin/v2/policies", []),
    globalPolicy: forbiddenDataset("/admin/v2/policies/global", null),
    infoSummary: forbiddenDataset("/admin/v1/info/summary", null),
    integrations: forbiddenDataset("/admin/v3/integrations", []),
  };
}

function locatedAuthEvent(txid, userKey, country, minutesAgo) {
  return {
    txid,
    result: "success",
    factor: "webauthn",
    timestamp: NOW_SECONDS - minutesAgo * 60,
    user: { key: userKey, name: `${userKey}@example.gov` },
    access_device: { location: { city: "Springfield", state: "VA", country } },
  };
}

function compliantMonitoringData() {
  return {
    settings: dataset(compliantSettings()),
    infoSummary: dataset({ edition: "Duo Premier", telephony_credits_remaining: 900 }),
    authenticationAttempts: dataset({ authentication_attempts: { ERROR: 0, FAILURE: 2, FRAUD: 0, SUCCESS: 98 } }),
    authenticationLogs: {
      data: [locatedAuthEvent("tx-1", "DU1", "United States", 30), locatedAuthEvent("tx-2", "DU1", "United States", 10)],
      complete: true,
    },
    activityLogs: { data: [{ txid: "a-1" }], complete: true },
    telephonyLogs: { data: [], complete: true },
    trustMonitorEvents: { data: [{ sekey: "SE1", priority_event: false, state: "closed" }], complete: true },
  };
}

function forbiddenMonitoringData() {
  return {
    settings: forbiddenDataset("/admin/v1/settings", null),
    infoSummary: forbiddenDataset("/admin/v1/info/summary", null),
    authenticationAttempts: forbiddenDataset("/admin/v1/info/authentication_attempts", null),
    authenticationLogs: forbiddenDataset("/admin/v2/logs/authentication", []),
    activityLogs: forbiddenDataset("/admin/v2/logs/activity", []),
    telephonyLogs: forbiddenDataset("/admin/v2/logs/telephony", []),
    trustMonitorEvents: forbiddenDataset("/admin/v1/trust_monitor/events", []),
  };
}

test("assessDuoIntegrations covers critical applications and device health depth", () => {
  const compliant = assessDuoIntegrations(compliantIntegrationData(), createSampleConfig());
  for (const id of ["DUO-INTEGRATIONS-001", "DUO-INTEGRATIONS-002", "DUO-INTEGRATIONS-003", "DUO-INTEGRATIONS-004", "DUO-INTEGRATIONS-005", "DUO-INTEGRATIONS-006"]) {
    assert.equal(findingById(compliant, id).status, "Pass", `${id} passes on the compliant tenant`);
  }

  const forbiddenResult = assessDuoIntegrations(forbiddenIntegrationData(), createSampleConfig());
  assertNoPass(forbiddenResult, "forbidden integration data");
  assert.equal(forbiddenResult.findings.length, 6);
  for (const finding of forbiddenResult.findings) {
    assertManualContext(finding);
    assert.ok(finding.evidence.some((line) => line.startsWith("collection_error=")), `${finding.id} carries the 403 error`);
  }

  const emptyResult = assessDuoIntegrations(
    { settings: dataset({}), policies: dataset([]), globalPolicy: dataset(null), infoSummary: dataset({}), integrations: dataset([]) },
    createSampleConfig(),
  );
  assertNoPass(emptyResult, "empty integration data");
  assert.equal(findingById(emptyResult, "DUO-INTEGRATIONS-004").status, "Partial");
  assert.equal(findingById(emptyResult, "DUO-INTEGRATIONS-005").status, "Manual");

  const untagged = compliantIntegrationData();
  untagged.integrations.data[0].sensitivity_level = null;
  untagged.integrations.data[0].compliance_requirements = [];
  assert.equal(findingById(assessDuoIntegrations(untagged, createSampleConfig()), "DUO-INTEGRATIONS-005").status, "Manual");

  const unprotected = compliantIntegrationData();
  delete unprotected.integrations.data[0].policy_key;
  const unprotectedFinding = findingById(assessDuoIntegrations(unprotected, createSampleConfig()), "DUO-INTEGRATIONS-005");
  assert.equal(unprotectedFinding.status, "Fail");
  assert.ok(unprotectedFinding.evidence.some((line) => line.startsWith("unprotected_critical_app=VPN type=websdk")));

  const partial = compliantIntegrationData();
  partial.integrations = { data: partial.integrations.data, total: 30, complete: false };
  const partialResult = assessDuoIntegrations(partial, createSampleConfig());
  for (const id of ["DUO-INTEGRATIONS-001", "DUO-INTEGRATIONS-002", "DUO-INTEGRATIONS-003", "DUO-INTEGRATIONS-004", "DUO-INTEGRATIONS-005"]) {
    const finding = findingById(partialResult, id);
    assert.equal(finding.status, "Partial", `${id} must not pass on a partial inventory`);
    assert.ok(
      finding.evidence.some((line) => line.startsWith("inventory_seen=2 inventory_total=30")),
      `${id} reports seen and total counts when paging is incomplete`,
    );
  }
  assert.equal(findingById(partialResult, "DUO-INTEGRATIONS-006").status, "Pass", "policy-backed device health depth does not depend on the integrations page");

  const essentials = compliantIntegrationData();
  essentials.infoSummary = dataset({ edition: "Duo Essentials" });
  for (const section of ["health_checks", "operating_systems", "full_disk_encryption", "screen_lock"]) {
    delete essentials.globalPolicy.data.sections[section];
  }
  const editionFinding = findingById(assessDuoIntegrations(essentials, createSampleConfig()), "DUO-INTEGRATIONS-006");
  assert.equal(editionFinding.status, "Manual");
  assert.match(editionFinding.summary, /Duo Essentials/);

  const weakHealth = compliantIntegrationData();
  weakHealth.globalPolicy.data.sections.health_checks = { requires_duo_desktop: "windows", enforce_encryption: "", enforce_firewall: "", enforce_system_password: "" };
  weakHealth.globalPolicy.data.sections.operating_systems = { os_restrictions: {} };
  weakHealth.globalPolicy.data.sections.full_disk_encryption = { require_encryption: false };
  weakHealth.globalPolicy.data.sections.screen_lock = { require_screen_lock: false };
  assert.equal(findingById(assessDuoIntegrations(weakHealth, createSampleConfig()), "DUO-INTEGRATIONS-006").status, "Partial");
});

test("assessDuoIntegrations judges self-service device management per integration, not the legacy settings flag", () => {
  const config = createSampleConfig();

  const compliant = findingById(assessDuoIntegrations(compliantIntegrationData(), config), "DUO-INTEGRATIONS-003");
  assert.equal(compliant.status, "Pass");
  assert.ok(compliant.evidence.includes("self_service_allowed=0"));
  assert.ok(compliant.evidence.some((line) => line.startsWith("global_ssp_policy_enforced=true (legacy")));

  // The legacy flag is true (its documented default) but the only user-facing application allows self-service.
  const enabled = compliantIntegrationData();
  enabled.integrations.data[0].self_service_allowed = 1;
  const enabledFinding = findingById(assessDuoIntegrations(enabled, config), "DUO-INTEGRATIONS-003");
  assert.equal(enabledFinding.status, "Fail");
  assert.ok(enabledFinding.evidence.includes("self_service_integration=VPN type=websdk"));

  const mixed = compliantIntegrationData();
  mixed.integrations.data.push({
    integration_key: "DIWIKI",
    name: "Wiki",
    type: "websdk",
    user_access: "ALL_USERS",
    policy_key: "PO-WIKI",
    self_service_allowed: 1,
  });
  const mixedFinding = findingById(assessDuoIntegrations(mixed, config), "DUO-INTEGRATIONS-003");
  assert.equal(mixedFinding.status, "Partial");
  assert.ok(mixedFinding.evidence.includes("self_service_allowed=1"));
  assert.ok(mixedFinding.evidence.includes("self_service_disabled=1"));

  const absent = compliantIntegrationData();
  delete absent.integrations.data[0].self_service_allowed;
  const absentFinding = findingById(assessDuoIntegrations(absent, config), "DUO-INTEGRATIONS-003");
  assert.equal(absentFinding.status, "Manual");
  assert.ok(absentFinding.evidence.includes("endpoint=/admin/v3/integrations"));
  assert.ok(absentFinding.evidence.includes("required_permission=Grant resource - Read"));
  assert.ok(absentFinding.evidence.some((line) => line.startsWith("manual_evidence=")));

  const partial = compliantIntegrationData();
  partial.integrations = { data: partial.integrations.data, total: 40, complete: false };
  assert.equal(findingById(assessDuoIntegrations(partial, config), "DUO-INTEGRATIONS-003").status, "Partial");

  const forbiddenFinding = findingById(assessDuoIntegrations(forbiddenIntegrationData(), config), "DUO-INTEGRATIONS-003");
  assert.equal(forbiddenFinding.status, "Manual");
  assert.ok(forbiddenFinding.evidence.includes("required_permission=Grant resource - Read"));
});

test("assessDuoMonitoring evaluates authentication attempts and impossible travel", () => {
  const compliant = assessDuoMonitoring(compliantMonitoringData(), createSampleConfig());
  for (const id of ["DUO-MON-001", "DUO-MON-002", "DUO-MON-003", "DUO-MON-004", "DUO-MON-005"]) {
    assert.equal(findingById(compliant, id).status, "Pass", `${id} passes on the compliant tenant`);
  }

  const forbiddenResult = assessDuoMonitoring(forbiddenMonitoringData(), createSampleConfig());
  assertNoPass(forbiddenResult, "forbidden monitoring data");
  assert.equal(forbiddenResult.findings.length, 5);
  for (const finding of forbiddenResult.findings) {
    assertManualContext(finding);
    assert.ok(finding.evidence.some((line) => line.startsWith("collection_error=")), `${finding.id} carries the 403 error`);
  }
  assert.ok(findingById(forbiddenResult, "DUO-MON-005").evidence.includes("required_permission=Grant read information"));
  const telephonyForbidden = findingById(forbiddenResult, "DUO-MON-003");
  assert.ok(telephonyForbidden.evidence.includes("endpoint=/admin/v1/info/summary"));
  assert.ok(telephonyForbidden.evidence.includes("endpoint=/admin/v2/logs/telephony"));

  const emptyResult = assessDuoMonitoring(
    {
      settings: dataset({}),
      infoSummary: dataset({}),
      authenticationAttempts: dataset({ authentication_attempts: { ERROR: 0, FAILURE: 0, FRAUD: 0, SUCCESS: 0 } }),
      authenticationLogs: dataset([]),
      activityLogs: dataset([]),
      telephonyLogs: dataset([]),
      trustMonitorEvents: dataset([]),
    },
    createSampleConfig(),
  );
  assertNoPass(emptyResult, "empty monitoring data");
  const unknownCredits = findingById(emptyResult, "DUO-MON-003");
  assert.equal(unknownCredits.status, "Manual", "unknown telephony credits never support Pass");
  assert.ok(unknownCredits.evidence.some((line) => line.startsWith("telephony_credits_remaining=unknown")));
  assertManualContext(unknownCredits);
  assert.equal(findingById(emptyResult, "DUO-MON-005").status, "Partial");

  const travel = compliantMonitoringData();
  travel.authenticationLogs = dataset([
    locatedAuthEvent("tx-1", "DU1", "United States", 40),
    locatedAuthEvent("tx-2", "DU1", "Brazil", 15),
    locatedAuthEvent("tx-3", "DU2", "United States", 30),
  ]);
  const travelFinding = findingById(assessDuoMonitoring(travel, createSampleConfig()), "DUO-MON-005");
  assert.equal(travelFinding.status, "Fail");
  assert.ok(travelFinding.evidence.some((line) => line.includes("user=DU1 United States -> Brazil within 25 minutes")));

  const fraud = compliantMonitoringData();
  fraud.authenticationAttempts = dataset({ authentication_attempts: { ERROR: 0, FAILURE: 0, FRAUD: 1, SUCCESS: 50 } });
  assert.equal(findingById(assessDuoMonitoring(fraud, createSampleConfig()), "DUO-MON-005").status, "Partial");

  const noLocation = compliantMonitoringData();
  noLocation.infoSummary = dataset({ edition: "Duo Essentials", telephony_credits_remaining: 900 });
  noLocation.authenticationLogs = dataset([{ txid: "tx-1", result: "success", factor: "webauthn", timestamp: NOW_SECONDS - 60 }]);
  const noLocationFinding = findingById(assessDuoMonitoring(noLocation, createSampleConfig()), "DUO-MON-005");
  assert.equal(noLocationFinding.status, "Manual");
  assert.match(noLocationFinding.summary, /Duo Essentials/);
});

test("every Manual Duo finding names endpoint, permission, and evidence, and finding ids are unique across tools", () => {
  const config = createSampleConfig();

  // Manual paths that are not 403s: undocumented offline access, edition gating, untagged apps,
  // missing policy sections, unknown lockout threshold, unknown telephony credits, missing location.
  const essentials = compliantIntegrationData();
  essentials.infoSummary = dataset({ edition: "Duo Essentials" });
  for (const section of ["health_checks", "operating_systems", "full_disk_encryption", "screen_lock"]) {
    delete essentials.globalPolicy.data.sections[section];
  }
  essentials.integrations.data[0].sensitivity_level = null;
  essentials.integrations.data[0].compliance_requirements = [];
  delete essentials.integrations.data[0].self_service_allowed;
  delete essentials.integrations.data[0].prompt_v4_enabled;
  delete essentials.integrations.data[0].frameless_auth_prompt_enabled;

  const unknownLockout = compliantAdminData();
  unknownLockout.settings = dataset({ ...compliantSettings(), lockout_threshold: "unknown" });

  const noLocation = compliantMonitoringData();
  noLocation.infoSummary = dataset({ edition: "Duo Essentials" });
  noLocation.authenticationLogs = dataset([{ txid: "tx-1", result: "success", factor: "webauthn", timestamp: NOW_SECONDS - 60 }]);

  const results = [
    assessDuoAuthentication(compliantAuthenticationData(), config),
    assessDuoAuthentication(emptyAuthenticationData(), config),
    assessDuoAuthentication(withAuthMethods({ require_verified_push: true }), config),
    assessDuoAdminAccess(unknownLockout, config),
    assessDuoIntegrations(essentials, config),
    assessDuoIntegrations({ settings: dataset({}), policies: dataset([]), globalPolicy: dataset(null), infoSummary: dataset({}), integrations: dataset([]) }, config),
    assessDuoMonitoring(noLocation, config),
  ];
  const manualCount = results.reduce((count, result) => count + assertEveryManualHasContext(result, "non-403 manual paths"), 0);
  assert.ok(manualCount >= 12, `expected the fixtures to exercise many Manual paths, saw ${manualCount}`);
  assertManualContext(findingById(results[0], "DUO-AUTH-011"));
  assertManualContext(findingById(results[4], "DUO-INTEGRATIONS-006"));
  assertManualContext(findingById(results[4], "DUO-INTEGRATIONS-005"));
  assertManualContext(findingById(results[4], "DUO-INTEGRATIONS-002"));
  assertManualContext(findingById(results[6], "DUO-MON-005"));
  assertManualContext(findingById(results[6], "DUO-MON-003"));

  const allIds = [
    assessDuoAuthentication(compliantAuthenticationData(), config),
    assessDuoAdminAccess(compliantAdminData(), config),
    assessDuoIntegrations(compliantIntegrationData(), config),
    assessDuoMonitoring(compliantMonitoringData(), config),
  ].flatMap((result) => result.findings.map((finding) => finding.id));
  assert.equal(new Set(allIds).size, allIds.length, "no finding id is emitted by more than one tool");
  assert.equal(allIds.length, 27, "11 authentication, 5 admin-access, 6 integration, and 5 monitoring findings");
});

test("assessDuoMonitoring caps log-backed findings at Partial when the log sample is incomplete", () => {
  const config = createSampleConfig();
  const capped = compliantMonitoringData();
  capped.authenticationLogs = { data: capped.authenticationLogs.data, total: 5000, complete: false };
  capped.telephonyLogs = { data: [], complete: false };
  const result = assessDuoMonitoring(capped, config);
  for (const id of ["DUO-MON-001", "DUO-MON-005"]) {
    const finding = findingById(result, id);
    assert.equal(finding.status, "Partial", `${id} must not pass on a capped authentication log sample`);
    assert.ok(
      finding.evidence.some((line) => line.includes("inventory_seen=2 inventory_total=5000 collection_cap=400")),
      `${id} reports seen, total, and the cap size`,
    );
    assert.match(finding.manualNote, /next_offset/);
  }
  const telephony = findingById(result, "DUO-MON-003");
  assert.equal(telephony.status, "Partial", "telephony capacity cannot pass on an incomplete telephony log");
  assert.ok(telephony.evidence.some((line) => line.includes("inventory_seen=0 inventory_total=unknown collection_cap=400")));

  const truncatedTrustMonitor = compliantMonitoringData();
  truncatedTrustMonitor.trustMonitorEvents = { data: truncatedTrustMonitor.trustMonitorEvents.data, complete: false };
  assert.equal(findingById(assessDuoMonitoring(truncatedTrustMonitor, config), "DUO-MON-002").status, "Partial");

  const complete = assessDuoMonitoring(compliantMonitoringData(), config);
  for (const id of ["DUO-MON-001", "DUO-MON-003", "DUO-MON-005"]) {
    assert.equal(findingById(complete, id).status, "Pass", `${id} still passes on a complete sample`);
  }
});

test("config resolution: credentials set through the environment survive an argument overlay that carries every credential key as undefined and names only an unrelated argument, and the source chain names the environment", () => {
  const env = { DUO_API_HOST: "api-env.duosecurity.com", DUO_IKEY: "DIENV7KQ2XW9MP4ZR6LC", DUO_SKEY: "Rk7Xq2Vw9Mt4Zp8Lc3Nb6Hd5Fs1Gy0Jv" };
  // Every documented credential key present as undefined (the shape an argument overlay emits), one unrelated argument set.
  const overlay = { api_host: undefined, ikey: undefined, skey: undefined, output_dir: "bundles" };

  const resolved = resolveDuoConfiguration(overlay, env);
  assert.deepEqual({ apiHost: resolved.apiHost, ikey: resolved.ikey, skey: resolved.skey }, { apiHost: env.DUO_API_HOST, ikey: env.DUO_IKEY, skey: env.DUO_SKEY }, "the environment credentials resolve");
  assert.deepEqual(resolved.sourceChain, ["environment"], "the source chain names the environment and not the overlay of undefined keys");

  const withLookback = resolveDuoConfiguration({ ...overlay, lookback_days: 30 }, env);
  assert.equal(withLookback.skey, env.DUO_SKEY, "a non-credential argument does not erase the environment secret");
  assert.equal(withLookback.lookbackDays, 30);
  assert.deepEqual(withLookback.sourceChain, ["environment", "arguments"], "the source chain names both layers when the arguments carry a value");

  // A blank string argument is "not provided" as well: it never shadows the environment value, including when it
  // rides along with a set argument (the case where the overlay is applied and a blank could overwrite the layer below).
  const blank = resolveDuoConfiguration({ ...overlay, skey: "", ikey: "  ", api_host: "" }, env);
  assert.deepEqual({ apiHost: blank.apiHost, ikey: blank.ikey, skey: blank.skey }, { apiHost: env.DUO_API_HOST, ikey: env.DUO_IKEY, skey: env.DUO_SKEY }, "blank arguments do not erase the environment credentials");
  assert.deepEqual(blank.sourceChain, ["environment"]);
  const blankBesideSet = resolveDuoConfiguration({ ...overlay, skey: "", ikey: "  ", api_host: "", lookback_days: 30 }, env);
  assert.deepEqual({ apiHost: blankBesideSet.apiHost, ikey: blankBesideSet.ikey, skey: blankBesideSet.skey }, { apiHost: env.DUO_API_HOST, ikey: env.DUO_IKEY, skey: env.DUO_SKEY }, "blank credentials beside a set argument do not erase the environment credentials");
  assert.equal(blankBesideSet.lookbackDays, 30);
  assert.deepEqual(blankBesideSet.sourceChain, ["environment", "arguments"]);
});

test("resolveDuoConfiguration prefers explicit args over environment values", () => {
  const base = resolveDuoConfiguration(
    {},
    {
      DUO_API_HOST: "api-home.duosecurity.com",
      DUO_IKEY: "home-ikey",
      DUO_SKEY: "home-skey",
      DUO_LOOKBACK_DAYS: "14",
    },
  );
  assert.equal(base.apiHost, "api-home.duosecurity.com");
  assert.equal(base.ikey, "home-ikey");
  assert.equal(base.lookbackDays, 14);
  assert.deepEqual(base.sourceChain, ["environment"]);

  const overridden = resolveDuoConfiguration(
    {
      api_host: "https://api-override.duosecurity.com",
      ikey: "arg-ikey",
      skey: "arg-skey",
      lookback_days: 45,
    },
    {
      DUO_API_HOST: "api-home.duosecurity.com",
      DUO_IKEY: "home-ikey",
      DUO_SKEY: "home-skey",
      DUO_LOOKBACK_DAYS: "14",
    },
  );
  assert.equal(overridden.apiHost, "api-override.duosecurity.com");
  assert.equal(overridden.ikey, "arg-ikey");
  assert.equal(overridden.skey, "arg-skey");
  assert.equal(overridden.lookbackDays, 45);
  assert.deepEqual(overridden.sourceChain, ["environment", "arguments"]);
});

function sha512Hex(value) {
  return createHash("sha512").update(value).digest("hex");
}

function expectedAuthorization(config, canonicalLines) {
  const signature = createHmac("sha512", config.skey).update(canonicalLines.join("\n")).digest("hex");
  return `Basic ${Buffer.from(`${config.ikey}:${signature}`).toString("base64")}`;
}

test("DuoAuditorClient signs the Policies v2 API with the documented v5 canonical string", async () => {
  const config = createSampleConfig();
  const captured = [];
  const fetchImpl = async (input, init = {}) => {
    const requestUrl = new URL(typeof input === "string" ? input : input.toString());
    captured.push({
      path: requestUrl.pathname,
      query: requestUrl.search.replace(/^\?/, ""),
      method: init.method,
      date: init.headers.Date,
      authorization: init.headers.Authorization,
      contentType: init.headers["Content-Type"],
    });
    if (requestUrl.pathname === "/admin/v2/policies/global") {
      return new Response(JSON.stringify({ stat: "OK", response: compliantGlobalPolicy() }), { status: 200 });
    }
    if (requestUrl.pathname === "/admin/v2/policies") {
      return new Response(
        JSON.stringify({ stat: "OK", response: [compliantGlobalPolicy()], metadata: { total_objects: 1 } }),
        { status: 200 },
      );
    }
    if (requestUrl.pathname === "/admin/v1/settings") {
      return new Response(JSON.stringify({ stat: "OK", response: compliantSettings() }), { status: 200 });
    }
    throw new Error(`Unexpected request: ${requestUrl.pathname}`);
  };

  const client = new DuoAuditorClient(config, { fetchImpl });
  await client.getGlobalPolicy();
  await client.listPolicies();
  await client.getSettings();

  const emptyHash = sha512Hex("");
  const globalPolicyRequest = captured.find((request) => request.path === "/admin/v2/policies/global");
  assert.equal(globalPolicyRequest.method, "GET");
  assert.equal(globalPolicyRequest.query, "", "the global policy read sends no query parameters");
  assert.equal(globalPolicyRequest.contentType, undefined, "GET requests carry no body and no Content-Type");
  assert.equal(
    globalPolicyRequest.authorization,
    expectedAuthorization(config, [
      globalPolicyRequest.date,
      "GET",
      config.apiHost,
      "/admin/v2/policies/global",
      "",
      emptyHash,
      emptyHash,
    ]),
    "v5: date, method, host, path, blank query line, SHA-512 of the empty body, SHA-512 of no X-Duo headers",
  );
  assert.notEqual(
    globalPolicyRequest.authorization,
    expectedAuthorization(config, [globalPolicyRequest.date, "GET", config.apiHost, "/admin/v2/policies/global", ""]),
    "the legacy five-line v2 canonical string must not be used for the Policies v2 API",
  );

  const policiesRequest = captured.find((request) => request.path === "/admin/v2/policies");
  assert.equal(policiesRequest.query, "limit=100&offset=0");
  assert.equal(
    policiesRequest.authorization,
    expectedAuthorization(config, [
      policiesRequest.date,
      "GET",
      config.apiHost,
      "/admin/v2/policies",
      "limit=100&offset=0",
      emptyHash,
      emptyHash,
    ]),
    "paged policy reads keep the sorted query string on line five of the v5 canonical string",
  );

  const settingsRequest = captured.find((request) => request.path === "/admin/v1/settings");
  assert.equal(
    settingsRequest.authorization,
    expectedAuthorization(config, [settingsRequest.date, "GET", config.apiHost, "/admin/v1/settings", ""]),
    "endpoints without a v5-only note keep the v2 canonical string",
  );
});

test("DuoAuditorClient handles v2/v5 signing, retries, and pagination", async () => {
  const state = {
    userRetries: 0,
    capturedAuthHeaders: [],
  };

  const fetchImpl = async (input, init = {}) => {
    const requestUrl = new URL(typeof input === "string" ? input : input.toString());
    const authHeader = init.headers?.Authorization ?? init.headers?.authorization;
    if (authHeader) {
      state.capturedAuthHeaders.push(String(authHeader));
    }

    if (requestUrl.pathname === "/admin/v1/users") {
      const offset = requestUrl.searchParams.get("offset") ?? "0";
      if (offset === "0" && state.userRetries === 0) {
        state.userRetries += 1;
        return new Response(JSON.stringify({ stat: "FAIL", code: 42901, message: "Rate limited" }), {
          status: 429,
          statusText: "Too Many Requests",
        });
      }
      if (offset === "0") {
        return new Response(
          JSON.stringify({
            stat: "OK",
            response: [{ user_id: "DU-1" }],
            metadata: { next_offset: 1, total_objects: 2 },
          }),
          { status: 200 },
        );
      }
      return new Response(
        JSON.stringify({
          stat: "OK",
          response: [{ user_id: "DU-2" }],
          metadata: { total_objects: 2 },
        }),
        { status: 200 },
      );
    }

    if (requestUrl.pathname === "/admin/v3/integrations") {
      return new Response(
        JSON.stringify({
          stat: "OK",
          response: [{ integration_key: "DI-1", name: "VPN", type: "websdk" }],
          metadata: { total_objects: 1 },
        }),
        { status: 200 },
      );
    }

    if (requestUrl.pathname === "/admin/v2/logs/authentication") {
      const nextOffset = requestUrl.searchParams.get("next_offset");
      if (!nextOffset) {
        return new Response(
          JSON.stringify({
            stat: "OK",
            response: {
              items: [{ txid: "tx-1", factor: "verified_duo_push" }],
              metadata: { next_offset: ["1234567890000", "tx-1"], total_objects: 2 },
            },
          }),
          { status: 200 },
        );
      }
      return new Response(
        JSON.stringify({
          stat: "OK",
          response: {
            items: [{ txid: "tx-2", factor: "webauthn" }],
            metadata: { total_objects: 2 },
          },
        }),
        { status: 200 },
      );
    }

    throw new Error(`Unexpected request: ${requestUrl.pathname}`);
  };

  const client = new DuoAuditorClient(createSampleConfig(), { fetchImpl });
  const users = await client.listUsers();
  const integrations = await client.listIntegrations();
  const logs = await client.listAuthenticationLogs(2, 10);

  assert.equal(users.length, 2);
  assert.equal(integrations.length, 1);
  assert.equal(logs.length, 2);
  assert.equal(state.userRetries, 1);
  assert.equal(state.capturedAuthHeaders.length >= 4, true);
  assert.match(state.capturedAuthHeaders[0], /^Basic /);
  assert.notEqual(state.capturedAuthHeaders[0], state.capturedAuthHeaders[state.capturedAuthHeaders.length - 1]);
});

test("Duo assessments generate mapped findings across all focus areas", async () => {
  const config = createSampleConfig();
  const access = await runDuoAccessCheck(
    {
      getSettings: async () => ({ key: "value" }),
      listUsers: async () => [{ user_id: "DU-1" }],
      listPolicies: async () => [{ policy_key: "global" }],
      listAdmins: async () => [{ admin_id: "A1" }],
      listAuthenticationLogs: async () => [{ txid: "tx-1" }],
      listIntegrations: async () => {
        throw new Error("Duo API request failed for /admin/v3/integrations (403 Forbidden)");
      },
    },
    config,
  );
  assert.equal(access.status, "limited");
  assert.equal(access.probes.some((probe) => probe.key === "integrations" && probe.status === "forbidden"), true);

  const authentication = assessDuoAuthentication(createSampleAuthenticationData(), config);
  const admin = assessDuoAdminAccess(createSampleAdminData(), config);
  const integrations = assessDuoIntegrations(createSampleIntegrationData(), config);
  const monitoring = assessDuoMonitoring(createSampleMonitoringData(), config);

  assert.equal(authentication.findings.length >= 6, true);
  assert.equal(admin.findings.length >= 4, true);
  assert.equal(integrations.findings.length >= 4, true);
  assert.equal(monitoring.findings.length >= 4, true);
  assert.equal(authentication.findings.some((finding) => finding.frameworks.fedramp.length > 0), true);
  assert.equal(integrations.summary.Pass >= 1, true);
});

test("exportDuoAuditBundle writes the expected package and secure paths stay rooted", async () => {
  const outputRoot = createTempBase("grclanker-duo-export-");
  const config = createSampleConfig();

  const client = {
    getSettings: async () => ({
      helpdesk_bypass: "limit",
      helpdesk_bypass_expiration: 60,
      global_ssp_policy_enforced: true,
      fraud_email_enabled: true,
      push_activity_notification_enabled: true,
      email_activity_notification_enabled: false,
    }),
    listPolicies: async () => createSampleAuthenticationData().policies.data,
    getGlobalPolicy: async () => createSampleAuthenticationData().globalPolicy.data,
    listUsers: async () => createSampleAuthenticationData().users.data,
    listBypassCodes: async () => [],
    listWebauthnCredentials: async () => createSampleAuthenticationData().webauthnCredentials.data,
    getAdminAllowedAuthMethods: async () => createSampleAuthenticationData().allowedAdminAuthMethods.data,
    listAuthenticationLogs: async () => createSampleMonitoringData().authenticationLogs.data,
    listAdmins: async () => createSampleAdminData().admins.data,
    listActivityLogs: async () => createSampleAdminData().activityLogs.data,
    listIntegrations: async () => createSampleIntegrationData().integrations.data,
    getInfoSummary: async () => createSampleMonitoringData().infoSummary.data,
    listTelephonyLogs: async () => [],
    listTrustMonitorEvents: async () => createSampleMonitoringData().trustMonitorEvents.data,
  };

  const result = await exportDuoAuditBundle(client, config, outputRoot);

  // The bundle moved from assessments/, frameworks/, summary.md, and README.md to the
  // shared grclanker layout (core_data/, analysis/, compliance/, QUICK_REFERENCE.md).
  assert.equal(existsSync(result.outputDir), true);
  assert.equal(existsSync(result.zipPath), true);
  assert.equal(result.zipPath, `${result.outputDir}.zip`, "zip is named after the allocated directory");
  for (const relativePath of [
    "QUICK_REFERENCE.md",
    "config.json",
    "core_data/users.json",
    "core_data/global_policy.json",
    "core_data/integrations.json",
    "core_data/collection_status.json",
    "analysis/authentication.json",
    "analysis/admin_access.json",
    "analysis/integrations.json",
    "analysis/monitoring.json",
    "analysis/findings.json",
    "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md",
    "compliance/fedramp/fedramp_compliance_report.md",
    "compliance/cmmc/cmmc_compliance_report.md",
    "compliance/soc2/soc2_compliance_report.md",
    "compliance/cis/cis_compliance_report.md",
    "compliance/pci_dss/pci_dss_compliance_report.md",
    "compliance/disa_stig/stig_compliance_checklist.md",
    "compliance/irap/irap_compliance_report.md",
    "compliance/ismap/ismap_compliance_report.md",
  ]) {
    assert.equal(existsSync(join(result.outputDir, relativePath)), true, `${relativePath} is written`);
  }
  assert.equal(existsSync(join(result.outputDir, "_errors.log")), true, "offline enrollment logs are missing from this client, so _errors.log is written");
  assert.match(readFileSync(join(result.outputDir, "_errors.log"), "utf8"), /offline_enrollment/);
  assert.match(readFileSync(join(result.outputDir, "compliance", "executive_summary.md"), "utf8"), /Duo authentication assessment/);
  assert.equal(result.findingCount > 0, true);
  assert.equal(result.errorCount >= 1, true);
  assert.equal(result.fileCount > 20, true);

  const rerun = await exportDuoAuditBundle(client, config, outputRoot);
  assert.notEqual(rerun.outputDir, result.outputDir, "re-running never overwrites the prior bundle directory");
  assert.notEqual(rerun.zipPath, result.zipPath, "re-running never overwrites the prior zip");
  assert.equal(existsSync(result.zipPath), true);

  assert.throws(
    () => resolveSecureOutputPath(outputRoot, "../escape"),
    /outside output root|symlinked output path/,
  );
});

test("exportDuoAuditBundle omits _errors.log when every read succeeds", async () => {
  const outputRoot = createTempBase("grclanker-duo-export-clean-");
  const config = createSampleConfig();
  const authentication = compliantAuthenticationData();
  const client = {
    getSettings: async () => compliantSettings(),
    listPolicies: async () => authentication.policies.data,
    getGlobalPolicy: async () => authentication.globalPolicy.data,
    listUsers: async () => authentication.users.data,
    listBypassCodes: async () => [],
    listWebauthnCredentials: async () => authentication.webauthnCredentials.data,
    getAdminAllowedAuthMethods: async () => authentication.allowedAdminAuthMethods.data,
    listAuthenticationLogs: async () => compliantMonitoringData().authenticationLogs.data,
    listOfflineEnrollmentLogs: async () => [],
    listAdmins: async () => compliantAdminData().admins.data,
    listActivityLogs: async () => [{ txid: "a-1" }],
    listIntegrations: async () => compliantIntegrationData().integrations.data,
    getInfoSummary: async () => ({ edition: "Duo Premier", telephony_credits_remaining: 900 }),
    getAuthenticationAttempts: async () => ({ authentication_attempts: { ERROR: 0, FAILURE: 0, FRAUD: 0, SUCCESS: 10 } }),
    listTelephonyLogs: async () => [],
    listTrustMonitorEvents: async () => [{ sekey: "SE1", state: "closed" }],
  };

  const result = await exportDuoAuditBundle(client, config, outputRoot);
  assert.equal(result.errorCount, 0);
  assert.equal(existsSync(join(result.outputDir, "_errors.log")), false);
  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  const failed = findings.filter((finding) => finding.status === "Fail" || finding.status === "Partial").map((finding) => finding.id);
  assert.deepEqual(failed, [], "the fully compliant fixture produces no Fail or Partial findings");
  assert.equal(findings.filter((finding) => finding.status === "Manual").map((finding) => finding.id).join(","), "DUO-AUTH-011");
});

function okEnvelope(response, metadata) {
  return new Response(JSON.stringify({ stat: "OK", response, ...(metadata ? { metadata } : {}) }), { status: 200 });
}

function forbiddenResponse() {
  return new Response(JSON.stringify({ stat: "FAIL", code: 40301, message: "Access denied", message_detail: "Insufficient permissions" }), {
    status: 403,
    statusText: "Forbidden",
  });
}

test("rule 10: offset paging exits as incomplete on a repeated, unusable, or empty-page next_offset and accepts a numeric string", async () => {
  const scenario = async (pages) => {
    let calls = 0;
    const fetchImpl = async (input) => {
      const requestUrl = new URL(typeof input === "string" ? input : input.toString());
      assert.equal(requestUrl.pathname, "/admin/v1/users");
      calls += 1;
      if (calls > 10) throw new Error("offset pager looped");
      const page = pages[requestUrl.searchParams.get("offset") ?? "0"] ?? { response: [], metadata: {} };
      return okEnvelope(page.response, page.metadata);
    };
    const client = new DuoAuditorClient(createSampleConfig(), { fetchImpl });
    const users = await client.listUsers();
    return { users, calls, status: client.collectionStatus("/admin/v1/users") };
  };

  const repeated = await scenario({ 0: { response: [{ user_id: "DU-1" }], metadata: { next_offset: 0, total_objects: 3 } } });
  assert.equal(repeated.calls, 1, "a next_offset equal to the offset just fetched is not followed");
  assert.deepEqual(repeated.status, { totalObjects: 3, complete: false });

  const backwards = await scenario({
    0: { response: [{ user_id: "DU-1" }, { user_id: "DU-2" }], metadata: { next_offset: 2, total_objects: 4 } },
    2: { response: [{ user_id: "DU-3" }], metadata: { next_offset: 1, total_objects: 4 } },
  });
  assert.equal(backwards.calls, 2, "a next_offset behind the current offset is not followed");
  assert.deepEqual(backwards.status, { totalObjects: 4, complete: false });

  const numericString = await scenario({
    0: { response: [{ user_id: "DU-1" }], metadata: { next_offset: "1", total_objects: 2 } },
    1: { response: [{ user_id: "DU-2" }], metadata: { total_objects: 2 } },
  });
  assert.equal(numericString.users.length, 2, "a numeric string next_offset pages like the documented integer");
  assert.deepEqual(numericString.status, { totalObjects: 2, complete: true });

  const opaque = await scenario({ 0: { response: [{ user_id: "DU-1" }], metadata: { next_offset: "opaque-cursor", total_objects: 1 } } });
  assert.equal(opaque.calls, 1);
  assert.equal(opaque.status.complete, false, "a next_offset the offset pager cannot send back is reported as an incomplete walk");

  const emptyPage = await scenario({ 0: { response: [], metadata: { next_offset: 100 } } });
  assert.equal(emptyPage.calls, 1);
  assert.equal(emptyPage.status.complete, false, "an empty page that still carries next_offset is reported as incomplete");
});

test("rule 10: cursor paging exits as incomplete when next_offset repeats or arrives with an empty page", async () => {
  const run = async (path, list, responder) => {
    let calls = 0;
    const fetchImpl = async (input) => {
      const requestUrl = new URL(typeof input === "string" ? input : input.toString());
      assert.equal(requestUrl.pathname, path);
      calls += 1;
      if (calls > 10) throw new Error(`${path} pager looped`);
      return new Response(JSON.stringify({ stat: "OK", ...responder(requestUrl, calls) }), { status: 200 });
    };
    const client = new DuoAuditorClient(createSampleConfig(), { fetchImpl });
    const items = await list(client);
    return { items, calls, status: client.collectionStatus(path) };
  };

  const repeatedLogCursor = await run(
    "/admin/v2/logs/authentication",
    (client) => client.listAuthenticationLogs(1, 50),
    (_url, call) => ({ response: { items: [{ txid: `tx-${call}` }], metadata: { next_offset: ["1700000000000", "tx-1"] } } }),
  );
  assert.equal(repeatedLogCursor.calls, 2, "the repeated cursor is sent once and then abandoned");
  assert.equal(repeatedLogCursor.items.length, 2);
  assert.equal(repeatedLogCursor.status.complete, false);

  const emptyLogPage = await run(
    "/admin/v2/logs/authentication",
    (client) => client.listAuthenticationLogs(1, 50),
    (url) => (url.searchParams.get("next_offset")
      ? { response: { items: [], metadata: { next_offset: ["1700000000001", "tx-2"] } } }
      : { response: { items: [{ txid: "tx-1" }], metadata: { next_offset: ["1700000000000", "tx-1"] } } }),
  );
  assert.equal(emptyLogPage.calls, 2);
  assert.equal(emptyLogPage.items.length, 1);
  assert.equal(emptyLogPage.status.complete, false);

  const repeatedTrustCursor = await run(
    "/admin/v1/trust_monitor/events",
    (client) => client.listTrustMonitorEvents(1, 50),
    (_url, call) => ({ response: { events: [{ sekey: `SE${call}` }], metadata: { next_offset: "cursor-1" } } }),
  );
  assert.equal(repeatedTrustCursor.calls, 2);
  assert.deepEqual(repeatedTrustCursor.status, { totalObjects: undefined, complete: false });
});

test("rule 10: a client that tracks paging but recorded nothing for a list never lets that list read as complete", async () => {
  const methods = {
    getSettings: async () => compliantSettings(),
    listPolicies: async () => [compliantGlobalPolicy()],
    getGlobalPolicy: async () => compliantGlobalPolicy(),
    listUsers: async () => [compliantUser("DU1"), compliantUser("DU2")],
    listBypassCodes: async () => [],
    listWebauthnCredentials: async () => [],
    getAdminAllowedAuthMethods: async () => ({ webauthn_enabled: true }),
    listAuthenticationLogs: async () => [],
    listOfflineEnrollmentLogs: async () => [],
  };

  const tracked = await collectDuoAuthenticationData({ ...methods, collectionStatus: () => undefined }, 30);
  assert.equal(tracked.users.complete, false);
  assert.equal(tracked.users.total, undefined);
  const result = assessDuoAuthentication(tracked, createSampleConfig());
  for (const id of ["DUO-AUTH-008", "DUO-AUTH-009", "DUO-AUTH-010"]) {
    const finding = findingById(result, id);
    assert.equal(finding.status, "Partial", `${id} cannot pass on a walk with no recorded paging outcome`);
    assert.ok(finding.evidence.some((line) => line.includes("inventory_seen=2 inventory_total=unknown")), `${id} reports the unknown total`);
  }

  const untracked = await collectDuoAuthenticationData(methods, 30);
  assert.equal(untracked.users.complete, undefined, "a client without collectionStatus records nothing about paging");
  assert.equal(findingById(assessDuoAuthentication(untracked, createSampleConfig()), "DUO-AUTH-008").status, "Pass");
});

test("rule 9: integration secret_key and bypass code values are redacted at collection time", async () => {
  const fetchImpl = async (input) => {
    const requestUrl = new URL(typeof input === "string" ? input : input.toString());
    if (requestUrl.pathname === "/admin/v3/integrations") {
      return okEnvelope(
        [{ integration_key: "DIVPN", name: "VPN", type: "websdk", secret_key: "sk-live-plaintext-1234", nested: { skey: "sk-nested-5678" } }],
        { total_objects: 1 },
      );
    }
    if (requestUrl.pathname === "/admin/v1/bypass_codes") {
      return okEnvelope(
        [{ bypass_code_id: "B1", code: "123456789", bypass_code: "987654321", user: { username: "break-glass@example.gov" } }],
        { total_objects: 1 },
      );
    }
    throw new Error(`Unexpected request: ${requestUrl.pathname}`);
  };
  const client = new DuoAuditorClient(createSampleConfig(), { fetchImpl });

  const [integration] = await client.listIntegrations();
  assert.equal(integration.secret_key, "[REDACTED]");
  assert.equal(integration.nested.skey, "[REDACTED]");
  assert.equal(integration.integration_key, "DIVPN");
  assert.equal(integration.name, "VPN");

  const [code] = await client.listBypassCodes();
  assert.equal(code.code, "[REDACTED]");
  assert.equal(code.bypass_code, "[REDACTED]");
  assert.equal(code.bypass_code_id, "B1");
  assert.equal(code.user.username, "break-glass@example.gov");

  assert.deepEqual(redactIntegrationRecords([{ secret_key: "x", name: "n" }]), [{ secret_key: "[REDACTED]", name: "n" }]);
  assert.deepEqual(redactBypassCodeRecords([{ code: "1", bypass_code_id: "B" }]), [{ code: "[REDACTED]", bypass_code_id: "B" }]);
});

test("rule 9: projectCollectionStatus keeps counts, totals, paging outcome, and errors but no records", () => {
  const projected = projectCollectionStatus({
    users: { data: [{ username: "alice@example.gov" }], total: 40, complete: false },
    settings: { data: { lockout_threshold: 10 } },
    infoSummary: { data: null, error: forbidden("/admin/v1/info/summary"), endpoint: "/admin/v1/info/summary", status: 403 },
    telephonyLogs: { data: [], error: forbidden("/admin/v2/logs/telephony") },
    authenticationAttempts: undefined,
  });
  assert.deepEqual(projected, {
    users: { readable: true, records: 1, total: 40, complete: false },
    settings: { readable: true },
    infoSummary: { readable: false, error: forbidden("/admin/v1/info/summary"), status: 403, endpoint: "/admin/v1/info/summary" },
    // A failure without an observed HTTP response (duck-typed client, transport error) keeps status and endpoint null.
    telephonyLogs: { readable: false, error: forbidden("/admin/v2/logs/telephony"), status: null, endpoint: null, records: null, total: null, complete: null },
    authenticationAttempts: {
      readable: false,
      records: null,
      total: null,
      complete: null,
      status: null,
      endpoint: null,
      error: "not collected: this client does not expose the endpoint, so no request was attempted",
    },
  });
  assert.equal(JSON.stringify(projected).includes("alice@example.gov"), false);
});

const INTEGRATION_SECRET = "Z8NuV9GgLCQwL2THRTgLkmzsLgf6bbScBFMZ9NWd";
const BYPASS_CODE_VALUE = "837488763496";

/** Every planted canary a Duo output is swept for, window by window. */
const DUO_PLANTED_CANARIES = Object.freeze([
  ...CANARY_VALUES,
  SHORT_BODY_CANARY,
  PARSER_SNIPPET_CANARY,
  DUO_IKEY_CANARY,
  DUO_SKEY_CANARY,
  INTEGRATION_SECRET,
  BYPASS_CODE_VALUE,
]);

/** Every documented endpoint the client reads, answered healthily; each key is one surface. */
function healthyDuoRoutes() {
  const policy = compliantGlobalPolicy();
  return {
    "/admin/v1/settings": () => okEnvelope(compliantSettings()),
    "/admin/v2/policies": () => okEnvelope([policy], { total_objects: 1 }),
    "/admin/v2/policies/global": () => okEnvelope(policy),
    "/admin/v1/users": () => okEnvelope([compliantUser("DU1", { username: "bundle-user@example.gov" })], { total_objects: 1 }),
    "/admin/v1/bypass_codes": () =>
      okEnvelope(
        [{ bypass_code_id: "B1", code: BYPASS_CODE_VALUE, created: NOW_SECONDS - 3600, expiration: NOW_SECONDS + 3600, reuse_count: 1, user: { user_id: "DU1" } }],
        { total_objects: 1 },
      ),
    "/admin/v1/webauthncredentials": () => okEnvelope([{ webauthnkey: "WK-DU1", uv_capable: true, user: { user_id: "DU1" } }], { total_objects: 1 }),
    "/admin/v1/admins/allowed_auth_methods": () => okEnvelope({ webauthn_enabled: true, verified_push_enabled: true, sms_enabled: false, voice_enabled: false }),
    "/admin/v2/logs/authentication": () => okEnvelope({ items: [locatedAuthEvent("tx-1", "DU1", "United States", 30)], metadata: {} }),
    "/admin/v1/logs/offline_enrollment": () => okEnvelope([]),
    "/admin/v1/admins": () => okEnvelope(compliantAdminData().admins.data, { total_objects: 2 }),
    "/admin/v2/logs/activity": () => okEnvelope({ items: [{ txid: "a-1", action: "admin_login" }], metadata: {} }),
    "/admin/v3/integrations": () =>
      okEnvelope(
        compliantIntegrationData().integrations.data.map((integration) => ({ ...integration, secret_key: INTEGRATION_SECRET })),
        { total_objects: 2 },
      ),
    "/admin/v1/info/summary": () => okEnvelope({ edition: "Duo Premier", telephony_credits_remaining: 900 }),
    "/admin/v2/logs/telephony": () => okEnvelope({ items: [], metadata: {} }),
    "/admin/v1/trust_monitor/events": () => okEnvelope({ events: [{ sekey: "SE1", priority_event: false, state: "closed" }], metadata: {} }),
    "/admin/v1/info/authentication_attempts": () => okEnvelope({ authentication_attempts: { ERROR: 0, FAILURE: 2, FRAUD: 0, SUCCESS: 98 } }),
  };
}

function routedFetch(routes) {
  return async (input) => {
    const requestUrl = new URL(typeof input === "string" ? input : input.toString());
    const route = routes[requestUrl.pathname];
    if (!route) throw new Error(`Unexpected request: ${requestUrl.pathname}`);
    return route();
  };
}

test("rule 9: the exported bundle and its zip never contain the skey, integration secrets, or bypass code values, and collection_status.json is a projection", async () => {
  const outputRoot = createTempBase("grclanker-duo-redaction-");
  const config = createSampleConfig();
  const fetchImpl = routedFetch({ ...healthyDuoRoutes(), "/admin/v2/logs/telephony": () => forbiddenResponse() });
  const client = new DuoAuditorClient(config, { fetchImpl });

  const result = await exportDuoAuditBundle(client, config, outputRoot);
  const files = readBundleFiles(result.outputDir);
  const zipEntries = readZipEntries(result.zipPath);
  const secrets = [config.skey, config.ikey, INTEGRATION_SECRET, BYPASS_CODE_VALUE];
  assertNoCanaryWindowsInFiles(assert, files, secrets, "bundle directory");
  assertNoCanaryWindowsInFiles(assert, zipEntries, secrets, "bundle zip");
  assert.ok(zipEntries.size >= files.size, "every bundle file is inside the zip");

  const integrations = JSON.parse(files.get("core_data/integrations.json"));
  assert.ok(integrations.every((integration) => integration.secret_key === "[REDACTED]"), "secret_key is redacted in core_data");
  const bypassCodes = JSON.parse(files.get("core_data/bypass_codes.json"));
  assert.equal(bypassCodes[0].code, "[REDACTED]");
  assert.equal(bypassCodes[0].bypass_code_id, "B1", "non-secret bypass code fields are kept for the hygiene review");

  const status = JSON.parse(files.get("core_data/collection_status.json"));
  assert.deepEqual(status.authentication.users, { readable: true, records: 1, total: 1, complete: true });
  assert.deepEqual(status.authentication.settings, { readable: true });
  assert.equal(status.monitoring.telephonyLogs.readable, false);
  assert.match(status.monitoring.telephonyLogs.error, /\/admin\/v2\/logs\/telephony \(403 Forbidden\): Access denied: Insufficient permissions/);
  assert.equal(JSON.stringify(status).includes("bundle-user@example.gov"), false, "collection_status.json carries no records");
  assert.equal(status.monitoring.telephonyLogs.records, null, "an unread list never reports a record count");
  assert.equal(status.monitoring.telephonyLogs.total, null, "an unread list never reports a total");
  assert.equal(status.monitoring.telephonyLogs.complete, null, "an unread list never reports a paging outcome");
  assert.equal(status.monitoring.telephonyLogs.status, 403, "the observed HTTP status is recorded");
  assert.equal(status.monitoring.telephonyLogs.endpoint, "/admin/v2/logs/telephony", "the observed request path is recorded");
  const telephonyMarker = JSON.parse(files.get("core_data/telephony_logs.json"));
  assert.equal(telephonyMarker.collected, false, "an unread dataset is written as a not-collected marker, not its empty fallback");
  assert.equal(telephonyMarker.status, 403);
  assert.equal(telephonyMarker.endpoint, "/admin/v2/logs/telephony");
  assert.match(telephonyMarker.error, /403 Forbidden/);
  assert.equal(result.errorCount, 1);
  assert.match(files.get("_errors.log"), /\/admin\/v2\/logs\/telephony/);
});

test("rule 9: redactErrorText scrubs every credential shape anywhere in an error string and leaves prose alone", () => {
  assertRedactionCases(assert, redactErrorText);
  assert.equal(redactErrorText(`skey ${createSampleConfig().skey} echoed`), "skey [REDACTED] echoed", "the configured skey is scrubbed wherever it appears");
});

test("rule 9 scrub boundary: name-shaped values stay bare, any value in a carrier is removed, token-shaped values are removed bare, the configured secret is removed in every encoded form, and the integration's fixed texts survive", () => {
  new DuoAuditorClient({ ...createSampleConfig(), skey: ENCODED_FORM_SECRET }, { fetchImpl: async () => new Response("{}") });
  assertScrubBoundary(assert, redactErrorText, {
    configuredSecret: ENCODED_FORM_SECRET,
    mustKeep: [
      "GET /admin/v1/settings (403 Forbidden): Access denied (Insufficient permissions)",
      "GET /admin/v2/logs/telephony (502 Bad Gateway): non-JSON body (text/html, 5120 bytes)",
      "SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body",
      "bypass code inventory is empty but GET /admin/v1/settings could not be read (403 Forbidden)",
      "allowed_auth_methods could not be read from GET /admin/v1/settings",
      "policy Global-Policy-2026 allows sms_passcodes",
      ...duoFixedTexts(),
    ],
  });
  for (const form of encodedFormsOf(DUO_IKEY_CANARY)) {
    const output = redactErrorText(`Duo rejected integration ${form} for this host`);
    assert.equal(output, "Duo rejected integration [REDACTED] for this host", `the integration key is a configured secret removed whatever its shape: ${form}`);
    assertNoCanaryWindows(assert, output, [DUO_IKEY_CANARY], `integration key form ${form}`);
  }
});

test("rule 9 fixed texts (GWS note 1): every fixed-text message the integration emits survives redactErrorText unchanged, from the SyntaxError and non-JSON notes through the was not attempted and not collected wordings to the unread evidence lines and the capped-verdict prose", () => {
  const texts = duoFixedTexts();
  assertFixedTextsSurvive(assert, redactErrorText, texts, { minimum: 30 });
  for (const required of [
    "SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body",
    "/admin/v1/logs/offline_enrollment was not attempted: this client does not expose it.",
    "/admin/v1/info/summary was not attempted: this client does not expose it.",
    "not collected: this client does not expose the endpoint, so no request was attempted",
    "Access forbidden: Insufficient permissions",
    "Duo API request failed for /admin/v1/settings (403 Forbidden): Access forbidden: Insufficient permissions",
    "Duo API request failed for /admin/v1/settings (network error: fetch failed)",
    "Duo API request returned an unexpected payload for /admin/v1/settings",
    "Duo API request exceeded retry budget for /admin/v1/settings (429 Too Many Requests).",
    "/admin/v1/settings (403 Forbidden): Access forbidden: Insufficient permissions",
    "users: unread",
    "bypass codes: unread",
    "helpdesk_bypass_expiration=unread",
    "Remaining telephony credits could not be read, so telephony capacity cannot be confirmed (unknown credits never support Pass).",
  ]) {
    assert.ok(texts.includes(required), `the fixed-text list carries: ${required}`);
  }
  assert.ok(texts.some((text) => HTML_BODY_NOTE.test(text)), "the fixed-text list carries the non-JSON body note");
  assert.ok(texts.some((text) => /^No active bypass codes were returned, but help desk issuance limits could not be read: \/admin\/v1\/settings \(403 Forbidden\): .* The zero-code verdict is capped at Partial\.$/.test(text)), "the capped zero-code verdict wording is in the list");
  assert.ok(texts.some((text) => /^admin_allowed_auth_methods=unread \(\/admin\/v1\/admins\/allowed_auth_methods \(403 Forbidden\): .*; requires Grant administrators - Read\); administrator WebAuthn posture was not confirmed\.$/.test(text)), "the unread admin auth-methods evidence line is in the list");

  // The renderings the client throws, built the way requestJson and parseDetailFromBody build them, survive too.
  const thrown = [
    "Duo API request failed for /admin/v1/settings (403 Forbidden): Access forbidden: Insufficient permissions",
    "Duo API request failed for /admin/v2/logs/telephony (502 Bad Gateway): non-JSON body (text/html, 5120 bytes)",
    "Duo API request returned an unexpected payload for /admin/v1/settings: non-JSON body (text/plain, 21 bytes)",
    "Duo API request failed for /admin/v1/users (401 Unauthorized): Invalid signature in request credentials",
  ];
  for (const message of thrown) {
    assert.equal(redactErrorText(message), message, `the thrown rendering survives the scrub: ${message}`);
  }
});

test("rule 9 must-keep and must-redact table (addendum 7): every endpoint path, name, principal, status text, finding id, and fixed text the summaries, markers, probes, and evidence rely on survives redactErrorText alone and inside a realistic summary sentence, and every canary planted in every carrier beside one of them is removed while the row survives (extends the rule 9 scrub boundary fixed texts)", () => {
  const groups = [
    {
      label: "endpoint paths",
      values: [
        "/admin/v1/settings",
        "/admin/v1/info/summary",
        "/admin/v1/info/authentication_attempts",
        "/admin/v1/admins/allowed_auth_methods",
        "/admin/v1/admins",
        "/admin/v1/users",
        "/admin/v1/bypass_codes",
        "/admin/v1/webauthncredentials",
        "/admin/v1/logs/offline_enrollment",
        "/admin/v1/trust_monitor/events",
        "/admin/v2/policies/global",
        "/admin/v2/policies",
        "/admin/v2/logs/authentication",
        "/admin/v2/logs/activity",
        "/admin/v2/logs/telephony",
        "/admin/v3/integrations",
        "GET /admin/v1/admins/allowed_auth_methods",
        "https://api-example.duosecurity.com/admin/v1/settings",
      ],
      sentence: (value) => `Duo API request failed for ${value} (403 Forbidden): Access forbidden: Insufficient permissions`,
    },
    {
      label: "names",
      values: [
        "api-example.duosecurity.com",
        "Global Policy",
        "Global-Policy-2026",
        "prod-us-east-2026",
        "Read-only Admin API",
        "grclanker audit",
        "Security key",
        "VPN",
        "helpdesk_bypass",
        "helpdesk_bypass_expiration",
        "allowed_auth_methods",
        "sms_passcodes",
        "Grant administrators - Read",
        "Grant resource - Read",
        "Grant settings",
      ],
      sentence: (value) => `${value} could not be read (403 Forbidden); it is rendered unread, its count is null, and the verdict is capped at Partial.`,
    },
    {
      label: "principals",
      values: ["owner@example.gov", "helpdesk@example.gov", "break-glass@example.gov", "jsmith", "svc-deploy", "Owner", "Help Desk"],
      sentence: (value) => `Administrator ${value} could not be checked because /admin/v1/admins/allowed_auth_methods returned 403 Forbidden; the WebAuthn posture is unread.`,
    },
    {
      label: "status text",
      values: [
        "401 Unauthorized",
        "403 Forbidden",
        "429 Too Many Requests",
        "502 Bad Gateway",
        "200 OK",
        "network error: fetch failed",
        "Access forbidden: Insufficient permissions",
        "Invalid signature in request credentials",
        "non-JSON body (text/html, 5120 bytes)",
      ],
      sentence: (value) => `GET /admin/v1/settings returned ${value}, so help desk issuance limits must be collected manually.`,
    },
    {
      label: "finding ids",
      values: ["DUO-AUTH-001", "DUO-AUTH-006", "DUO-AUTH-010", "DUO-ADMIN-002", "DUO-INTEGRATIONS-003", "DUO-MON-005"],
      sentence: (value) => `${value} /admin/v1/settings: 403 Forbidden`,
    },
    {
      label: "fixed texts",
      values: duoFixedTexts(),
      sentence: (value) => `DUO-AUTH-006 ${value}`,
    },
    QUOTED_NON_CREDENTIAL_GROUP,
  ];
  assertMustKeepRows(assert, redactErrorText, groups);
  assertMustRedactRowsBesideMustKeep(assert, redactErrorText, groups);
});

test("rule 9 escapes (reviewer D round 5 escapes): a header carrier after a two-character or six-character JSON escape is removed exactly as at a line start, for the nineteen header lines the integrations send, the six escapes, and five forms, at 6-to-24 windows, direct and through the client's JSON error path", async () => {
  const judged = assertEscapedHeaderCarriers(assert, redactErrorText);
  assert.equal(judged, ESCAPED_HEADER_LINES.length * JSON_ESCAPES.length * 5);
  assert.equal(ESCAPED_HEADER_LINES.length, 19);

  // The two classes reviewer D found leaking, carried by an error message on a probed surface: a later cookie
  // pair whose name has no credential word, and X-Auth-Key with an alphabetic value, each after a two-character
  // and a six-character escape.
  const tracker = "Rk7mVq2Zt9Xw4Ly6Pn8Hc3Jb";
  const globalKey = "prodkeyQz8Nv3Tm5Rk2Wy7";
  const message = `request failed\\nCookie: theme=dark; my.tracker=${tracker}\\u000aX-Auth-Key: ${globalKey}`;
  assert.ok(message.includes("\\n") && message.includes("\\u000a"), "the message carries the escapes as backslash text");
  const expectedTail = "\\nCookie: [REDACTED]\\u000aX-Auth-Key: [REDACTED]";
  const config = createSampleConfig();
  const surface = [...DUO_ACCESS_PROBE_PATHS][0];
  const respond = () => new Response(JSON.stringify({ stat: "FAIL", code: 40301, message, message_detail: "" }), { status: 403, statusText: "Forbidden", headers: { "content-type": "application/json" } });
  const client = new DuoAuditorClient(config, { fetchImpl: routedFetch({ ...healthyDuoRoutes(), [surface]: respond }) });
  const access = await runDuoAccessCheck(client, config);
  const probe = access.probes.find((entry) => entry.path === surface);
  assert.ok(probe && probe.status !== "ok", `the probe for ${surface} is not ok`);
  assert.ok(probe.detail.includes(expectedTail), `both carriers are removed whole after their escapes: ${probe.detail}`);
  assertNoCanaryWindows(assert, access, [tracker, globalKey], "check_access after escaped headers");
});

test("rule 9 depth control (reviewer D round 5 depth control): every string a snapshot keeps passes the data-side carrier scrub at every depth in place, a credential-keyed value is the marker in place with its benign sibling kept, and a container nested past the cap of 32 is the marker, on redactFields, redactIntegrationRecords, and scrubSnapshotValue and end to end through every healthy route into the bundle, the zip, and every tool payload", async () => {
  assert.equal(DEPTH_CONTROL.cap, 32);
  // The exported walkers: level k of the tree handed to the walker sits at depth k, so levels 1 to 32 are in place and level 33 is the marker.
  assertDepthControl(assert, (tree) => redactFields(tree, /^(secret_key|secretkey|skey)$/i), { label: "duo.redactFields (integration pattern)" });
  assertDepthControl(assert, (tree) => redactIntegrationRecords([tree])[0], { label: "duo.redactIntegrationRecords", rootDepth: 2 });
  assertDepthControl(assert, scrubSnapshotValue, { label: "duo.scrubSnapshotValue" });
  assertDepthControl(assert, (tree) => scrubSnapshotValue({ response: [tree] }).response[0], { label: "duo.scrubSnapshotValue under an envelope", rootDepth: 3 });
  // redactBypassCodeRecords keys on `code`, not `secret_key`, so only the string half and the cap apply to it.
  const bypassWalked = redactBypassCodeRecords([{ code: "123456", note: `Authorization: Bearer ${DEPTH_CONTROL.carrierCanary}` }])[0];
  assert.deepEqual(bypassWalked, { code: "[REDACTED]", note: "Authorization: Bearer [REDACTED]" });
  // The string half on its own: carriers go, identifiers stay, the configured skey goes in every form.
  const config = createSampleConfig();
  new DuoAuditorClient(config, { fetchImpl: routedFetch(healthyDuoRoutes()) });
  assertCarrierTextScrub(assert, redactCarrierText, { label: "duo.redactCarrierText", configuredSecret: config.skey });

  // End to end: the tree planted on every envelope and in every record and nested record of every healthy route.
  // Duo keeps its core_data records whole (the Admin API returns arbitrary nested values in policies and logs), so
  // the files carry the tree as data with the cap counted from the file's root: in a record list the tree's level 1
  // sits at depth 3 (list, record, member) and level 30 is the last in place; in an object file at depth 2 and level
  // 31 is. The datasets a collector returns are the same snapshots, so no function result carries a canary either.
  const planted = { count: 0 };
  const client = new DuoAuditorClient(config, { fetchImpl: routedFetch(withPlantedRoutes(healthyDuoRoutes(), { planted })) });
  const access = await runDuoAccessCheck(client, config);
  const datasets = [
    await collectDuoAuthenticationData(client, config.lookbackDays),
    await collectDuoAdminAccessData(client, config.lookbackDays),
    await collectDuoIntegrationData(client),
    await collectDuoMonitoringData(client, config.lookbackDays),
  ];
  const assessments = [
    assessDuoAuthentication(datasets[0], config),
    assessDuoAdminAccess(datasets[1], config),
    assessDuoIntegrations(datasets[2], config),
    assessDuoMonitoring(datasets[3], config),
  ];
  const exported = await exportDuoAuditBundle(client, config, createTempBase("grclanker-duo-depth-"));
  assert.ok(planted.count >= Object.keys(healthyDuoRoutes()).length, `the fixture planted the tree into ${planted.count} objects`);
  assert.equal(exported.errorCount, 0, "the planted tree causes no read to fail");
  assert.ok(access.probes.every((probe) => probe.status === "ok"), "every probe reads the planted fixture");
  const files = readBundleFiles(exported.outputDir);
  const carrying = assertDepthControlOutputs(
    assert,
    { files, zipEntries: readZipEntries(exported.zipPath), outputs: [access, ...datasets, ...assessments] },
    { label: "duo", treeExpected: true },
  );
  for (const [name, levelAtCap] of [["core_data/users.json", DEPTH_CONTROL.cap - 2], ["core_data/settings.json", DEPTH_CONTROL.cap - 1]]) {
    assert.ok(carrying.includes(`file ${name}`), `${name} carries the tree with the cap applied`);
    assert.ok(carrying.some((entry) => entry.startsWith("zip ") && entry.endsWith(name)), `the zip entry for ${name} carries it too`);
    const text = files.get(name);
    assert.ok(text.includes(`"benign-note-${levelAtCap}"`) && !text.includes(`"benign-note-${levelAtCap + 1}"`), `${name}: level ${levelAtCap} is the last in place`);
  }
  assert.ok(!JSON.stringify(assessments).includes("benign-note-"), "no assessment copies a record tree into its evidence");
  // The dataset a collector returns is already the snapshot: the same tree, capped, with no canary.
  const settingsDataset = datasets[0].settings.data;
  assert.equal(settingsDataset.x_deep_probe.secret_key, "[REDACTED]");
  assert.equal(settingsDataset.x_deep_probe.detail, "Authorization: Bearer [REDACTED]");
});

test("rule 9 credential-named pairs (reviewer D round 5 baseline): a value under a credential-named key is removed whatever its shape and length, unquoted as well as quoted, in every form the pair takes, while identifier-named keys keep their values unless the value's own shape removes it", () => {
  assertCredentialPairValuesRemoved(assert, redactErrorText);
  assertIdentifierKeyRows(assert, redactErrorText);
  assertFlagAndPathPairRows(assert, redactErrorText);
  // The retired value-shape test would have kept every one of these; the pair rule no longer asks.
  for (const [text, expected] of [
    ["password=letmein", "password=[REDACTED]"],
    ["DB_PASSWORD=Sunshine", "DB_PASSWORD=[REDACTED]"],
    ["AZURE_CLIENT_SECRET: abc12", "AZURE_CLIENT_SECRET: [REDACTED]"],
    ["DUO_SKEY=p@ss", "DUO_SKEY=[REDACTED]"],
    ["DUO_IKEY=DIXXXXXXXXXXXXXXXXXX", "DUO_IKEY=[REDACTED]"],
    ["DUO_IKEY=letmein", "DUO_IKEY=[REDACTED]"],
    ["ikey: monkey", "ikey: [REDACTED]"],
    ['{"DUO_IKEY":"Sunshine"}', '{"DUO_IKEY":"[REDACTED]"}'],
    ['"ikey": "abc12"', '"ikey": "[REDACTED]"'],
    ["Authorization: Basic letmein", "Authorization: Basic [REDACTED]"],
    ["token: value shape", "token: [REDACTED] shape"],
  ]) {
    assert.equal(redactErrorText(text), expected, `credential-named pair: ${text}`);
  }
  // A PascalCase error code that ends in a credential word is prose, and a bare scheme word is not a pair; a path segment
  // ending in a credential word is one (assertFlagAndPathPairRows).
  for (const text of [
    "InvalidAuthenticationToken: Access token has expired. Basic authentication is disabled for this tenant.",
    "ExpiredToken: The security token included in the request is expired",
    "sent as Authorization: Bearer) or as X-Auth-Key",
    "oauth: invalid_grant was returned",
  ]) {
    assert.equal(redactErrorText(text), text, `prose beside a credential word survives: ${text}`);
  }
});

test("rule 9 URL userinfo boundary (CodeRabbit on #76 at b0ef16f): an `@` inside a query or a fragment is not a userinfo boundary, so the real host stays, a query becomes the marker whole, and a fragment is kept, on the error sink, the data-string sink, and a snapshot string", () => {
  assertUrlUserinfoBoundaryRows(assert, redactErrorText, { label: "duo.redactErrorText" });
  assertUrlUserinfoBoundaryRows(assert, redactCarrierText, { label: "duo.redactCarrierText" });
  assertUrlUserinfoBoundaryRows(assert, (text) => scrubSnapshotValue(text), { label: "duo.scrubSnapshotValue" });
});
test("rule 9 Authorization parameter lists (CodeRabbit on #81, discussion_r4081238237): under an Authorization or Proxy-Authorization scheme every parameter value that is a proof is removed whatever its name, quoted or bare (Snowflake Token=\"...\", Bearer value=\"...\", Digest response, nonce, cnonce, and opaque, OAuth 1.0 oauth_token, oauth_signature, and oauth_nonce), while realm, username, uri, qop, nc, the SigV4 scope and signed headers, a WWW-Authenticate challenge, and Bearer realm=\"api\" in prose stay, on the error sink, the data-string sink, and a snapshot string, bare, inside a sentence, after a JSON escape, and inside a JSON string", () => {
  assertAuthorizationParameterRows(assert, redactErrorText, { label: "duo.redactErrorText" });
  assertAuthorizationParameterRows(assert, redactCarrierText, { label: "duo.redactCarrierText" });
  assertAuthorizationParameterRows(assert, (text) => scrubSnapshotValue(text), { label: "duo.scrubSnapshotValue" });
});
test("rule 9 bearer-id override (CodeRabbit r4077259415 on #78): a key ending in secret_id or naming a session id is a credential key despite its id suffix, so a Vault AppRole secret id goes whatever its shape, a UUID included, through the error sink, the data-string sink, the snapshot walker, and the thrown error, while AZURE_TENANT_ID=<uuid> and the other identifier keys keep their values", async () => {
  assertBearerIdKeyRows(assert, redactErrorText);
  assertBearerIdKeyRows(assert, redactCarrierText, { controls: BEARER_ID_CARRIER_CONTROL_ROWS });
  assertBearerIdSnapshotKeys(assert, scrubSnapshotValue);
  const [uuid, random] = BEARER_ID_VALUES;
  const tenant = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
  const echoed = `VAULT_SECRET_ID=${uuid} and role_secret_id: ${random} were rejected; AZURE_TENANT_ID=${tenant} was accepted`;
  const expected = `VAULT_SECRET_ID=[REDACTED] and role_secret_id: [REDACTED] were rejected; AZURE_TENANT_ID=${tenant} was accepted`;
  const client = new DuoAuditorClient(createSampleConfig(), {
    fetchImpl: async () => new Response(JSON.stringify({ stat: "FAIL", code: 40301, message: "Access forbidden", message_detail: echoed }), { status: 403, statusText: "Forbidden", headers: { "content-type": "application/json" } }),
  });
  await assert.rejects(() => client.getSettings(), (error) => {
    assert.equal(error.message, `Duo API request failed for /admin/v1/settings (403 Forbidden): Access forbidden: ${expected}`);
    assertNoCanaryWindows(assert, error.message, [uuid, random], "DuoApiError message");
    return true;
  });
});

const DUO_ACCESS_PROBE_PATHS = new Set([
  "/admin/v1/settings",
  "/admin/v1/users",
  "/admin/v2/policies",
  "/admin/v1/admins",
  "/admin/v2/logs/authentication",
  "/admin/v3/integrations",
]);

function canaryHtmlResponse() {
  return new Response(htmlCanaryBody(), { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html; charset=utf-8" } });
}

function canaryJsonResponse() {
  return new Response(
    JSON.stringify({ stat: "FAIL", code: 40301, message: jsonCanaryMessage(), message_detail: `token=${CANARY.urlToken}` }),
    { status: 403, statusText: "Forbidden", headers: { "content-type": "application/json" } },
  );
}

test("fixture self-check: every planted canary is alphanumeric and random-looking, and no 6-to-24-character window of any canary occurs in the healthy fixture's legitimate values, so a windowed leak assertion can fail only on a real echo", async () => {
  const config = createSampleConfig();
  const legitimate = new Map();
  // The healthy routes carry the two bundle secrets by design (the bundle test proves they are redacted); everything else in them is legitimate.
  const plantedInRoutes = [INTEGRATION_SECRET, BYPASS_CODE_VALUE];
  for (const [path, route] of Object.entries(healthyDuoRoutes())) {
    const body = await route().text();
    legitimate.set(`route ${path}`, plantedInRoutes.reduce((text, planted) => text.replaceAll(planted, ""), body));
  }
  const client = new DuoAuditorClient(config, { fetchImpl: routedFetch(healthyDuoRoutes()) });
  legitimate.set("check_access", await runDuoAccessCheck(client, config));
  const datasets = [
    await collectDuoAuthenticationData(client, config.lookbackDays),
    await collectDuoAdminAccessData(client, config.lookbackDays),
    await collectDuoIntegrationData(client),
    await collectDuoMonitoringData(client, config.lookbackDays),
  ];
  legitimate.set("authentication assessment", assessDuoAuthentication(datasets[0], config));
  legitimate.set("admin access assessment", assessDuoAdminAccess(datasets[1], config));
  legitimate.set("integrations assessment", assessDuoIntegrations(datasets[2], config));
  legitimate.set("monitoring assessment", assessDuoMonitoring(datasets[3], config));
  const exported = await exportDuoAuditBundle(client, config, createTempBase("grclanker-duo-self-check-"));
  for (const [name, text] of readBundleFiles(exported.outputDir)) legitimate.set(`bundle ${name}`, text);
  for (const [name, text] of readZipEntries(exported.zipPath)) legitimate.set(`zip ${name}`, text);
  legitimate.set("api host and lookback", { apiHost: config.apiHost, lookbackDays: config.lookbackDays });
  assertCanaryFixture(assert, DUO_PLANTED_CANARIES, legitimate, "duo fixture");
});

test("rule 9: a 502 HTML page or a JSON error message carrying credentials on any surface never reaches a probe, finding, summary, or bundle file", async () => {
  const config = createSampleConfig();
  const outputRoot = createTempBase("grclanker-duo-canary-");
  const surfaces = Object.keys(healthyDuoRoutes());
  assert.ok(surfaces.length >= 16, "every documented endpoint is a surface");

  for (const surface of surfaces) {
    for (const [variant, response, expectedNote] of [
      ["html", canaryHtmlResponse, HTML_BODY_NOTE],
      ["json", canaryJsonResponse, REDACTED_CANARY_URL],
    ]) {
      const label = `${surface} (${variant})`;
      const client = new DuoAuditorClient(config, { fetchImpl: routedFetch({ ...healthyDuoRoutes(), [surface]: response }) });

      const access = await runDuoAccessCheck(client, config);
      assertNoCanaryWindows(assert, access, DUO_PLANTED_CANARIES, `${label} check_access`);
      if (DUO_ACCESS_PROBE_PATHS.has(surface)) {
        const probe = access.probes.find((entry) => entry.path === surface);
        assert.ok(probe && probe.status !== "ok", `${label}: the probe for the failing surface is not ok`);
        assert.match(probe.detail, expectedNote, `${label}: probe detail carries the expected note`);
      }

      const datasets = [
        await collectDuoAuthenticationData(client, config.lookbackDays),
        await collectDuoAdminAccessData(client, config.lookbackDays),
        await collectDuoIntegrationData(client),
        await collectDuoMonitoringData(client, config.lookbackDays),
      ];
      const assessments = [
        assessDuoAuthentication(datasets[0], config),
        assessDuoAdminAccess(datasets[1], config),
        assessDuoIntegrations(datasets[2], config),
        assessDuoMonitoring(datasets[3], config),
      ];
      const recordedErrors = datasets.flatMap((data) => Object.values(data).flatMap((dataset) => (dataset?.error ? [dataset.error] : [])));
      assert.ok(recordedErrors.length > 0, `${label}: the failing surface records an error`);
      for (const error of recordedErrors) {
        assertNoCanaryWindows(assert, error, DUO_PLANTED_CANARIES, `${label} dataset error`);
        assert.match(error, expectedNote, `${label}: dataset error carries the expected note`);
      }
      for (const assessment of assessments) {
        assertNoCanaryWindows(assert, assessment, DUO_PLANTED_CANARIES, `${label} ${assessment.category} assessment`);
      }

      const exported = await exportDuoAuditBundle(client, config, outputRoot);
      const files = readBundleFiles(exported.outputDir);
      assertNoCanaryWindowsInFiles(assert, files, DUO_PLANTED_CANARIES, `${label} bundle`);
      assertNoCanaryWindowsInFiles(assert, readZipEntries(exported.zipPath), DUO_PLANTED_CANARIES, `${label} zip`);
      assert.ok(exported.errorCount > 0, `${label}: the export records the failed read`);
      assert.match(files.get("_errors.log"), expectedNote, `${label}: _errors.log carries the expected note`);
      if (variant === "html") assert.match(files.get("_errors.log"), /502 Bad Gateway\): non-JSON body \(text\/html/);
    }
  }
});

function statusesOf(result) {
  return Object.fromEntries(result.findings.map((finding) => [finding.id, finding.status]));
}

/**
 * One secondary dataset denied at a time while the finding's primary read stays healthy. Each row
 * names the findings that depend on that secondary and what they must report; every other finding
 * must be identical to the fully compliant baseline.
 */
const SECONDARY_DENIALS = [
  {
    assess: assessDuoAuthentication,
    fixture: compliantAuthenticationData,
    key: "settings",
    path: "/admin/v1/settings",
    fallback: null,
    expect: {
      "DUO-AUTH-006": (finding) => {
        assert.equal(finding.status, "Partial", "an empty bypass inventory cannot pass while help desk issuance limits are unread");
        assert.match(finding.summary, /help desk issuance limits could not be read: \/admin\/v1\/settings \(403 Forbidden\)/);
        assert.equal(finding.summary.includes("Duo API request failed for"), false, "the endpoint is named once, not through the raw client prefix");
        assert.ok(finding.evidence.some((line) => line.startsWith("helpdesk_bypass=unread (/admin/v1/settings (403 Forbidden)") && line.includes("requires Grant settings")));
        assert.ok(finding.evidence.includes("helpdesk_bypass_expiration=unread"));
        assert.match(finding.recommendation, /Grant settings/);
      },
    },
  },
  {
    assess: assessDuoAuthentication,
    fixture: compliantAuthenticationData,
    key: "allowedAdminAuthMethods",
    path: "/admin/v1/admins/allowed_auth_methods",
    fallback: null,
    expect: {
      "DUO-AUTH-001": (finding) => {
        assert.equal(finding.status, "Pass", "the verdict rests on the readable global policy");
        const line = finding.evidence.find((item) => item.startsWith("admin_allowed_auth_methods=unread"));
        assert.ok(line, "the unread supporting read is named in evidence");
        assert.match(line, /^admin_allowed_auth_methods=unread \(\/admin\/v1\/admins\/allowed_auth_methods \(403 Forbidden\)/);
        assert.match(line, /requires Grant administrators - Read/);
        assert.match(line, /not confirmed/);
        assert.equal(finding.evidence.includes("Admin auth methods allow WebAuthn."), false);
      },
    },
  },
  {
    assess: assessDuoAuthentication,
    fixture: compliantAuthenticationData,
    key: "webauthnCredentials",
    path: "/admin/v1/webauthncredentials",
    fallback: [],
    expect: {
      "DUO-AUTH-010": (finding) => {
        assert.equal(finding.status, "Pass", "adoption is measured from the readable user inventory");
        assert.ok(finding.evidence.some((line) => line.startsWith("webauthn_inventory_error=") && line.includes("/admin/v1/webauthncredentials")));
        assert.equal(finding.evidence.some((line) => line.startsWith("webauthn_credentials_total=")), false, "no phantom credential count");
      },
    },
  },
  {
    assess: assessDuoAuthentication,
    fixture: compliantAuthenticationData,
    key: "offlineEnrollmentLogs",
    path: "/admin/v1/logs/offline_enrollment",
    fallback: [],
    expect: {
      "DUO-AUTH-011": (finding) => {
        assert.equal(finding.status, "Manual");
        assert.ok(finding.evidence.includes("endpoint=/admin/v1/logs/offline_enrollment"));
        assert.ok(finding.evidence.some((line) => line.startsWith("collection_error=") && line.includes("403 Forbidden")));
      },
    },
  },
  {
    assess: assessDuoAuthentication,
    fixture: compliantAuthenticationData,
    key: "policies",
    path: "/admin/v2/policies",
    fallback: [],
    expect: {},
  },
  {
    assess: assessDuoAdminAccess,
    fixture: compliantAdminData,
    key: "settings",
    path: "/admin/v1/settings",
    fallback: null,
    expect: {
      "DUO-ADMIN-003": (finding) => {
        assert.equal(finding.status, "Manual");
        assert.ok(finding.evidence.includes("endpoint=/admin/v1/settings"));
      },
      "DUO-ADMIN-005": (finding) => {
        assert.equal(finding.status, "Manual");
        assert.ok(finding.evidence.includes("endpoint=/admin/v1/settings"));
      },
    },
  },
  {
    assess: assessDuoAdminAccess,
    fixture: compliantAdminData,
    key: "allowedAdminAuthMethods",
    path: "/admin/v1/admins/allowed_auth_methods",
    fallback: null,
    expect: {
      "DUO-ADMIN-002": (finding) => {
        assert.equal(finding.status, "Manual");
        assert.ok(finding.evidence.includes("endpoint=/admin/v1/admins/allowed_auth_methods"));
      },
    },
  },
  {
    assess: assessDuoAdminAccess,
    fixture: compliantAdminData,
    key: "activityLogs",
    path: "/admin/v2/logs/activity",
    fallback: [],
    expect: {},
    snapshot: (result) => assert.match(String(result.snapshotSummary.activity_logs_readable), /^no \(.*403 Forbidden/),
  },
  {
    assess: assessDuoIntegrations,
    fixture: compliantIntegrationData,
    key: "settings",
    path: "/admin/v1/settings",
    fallback: null,
    expect: {
      "DUO-INTEGRATIONS-003": (finding) => {
        assert.equal(finding.status, "Pass", "self-service is judged per integration; the legacy settings flag is evidence only");
        assert.ok(finding.evidence.some((line) => line.startsWith("global_ssp_policy_enforced=unknown")));
      },
    },
  },
  {
    assess: assessDuoIntegrations,
    fixture: compliantIntegrationData,
    key: "infoSummary",
    path: "/admin/v1/info/summary",
    fallback: null,
    expect: {
      "DUO-INTEGRATIONS-006": (finding) => {
        assert.equal(finding.status, "Pass", "device health is judged from the readable global policy sections");
        assert.ok(finding.evidence.includes("edition=unknown"));
      },
    },
  },
  {
    assess: assessDuoIntegrations,
    fixture: compliantIntegrationData,
    key: "policies",
    path: "/admin/v2/policies",
    fallback: [],
    expect: {},
  },
  {
    assess: assessDuoMonitoring,
    fixture: compliantMonitoringData,
    key: "settings",
    path: "/admin/v1/settings",
    fallback: null,
    expect: {
      "DUO-MON-004": (finding) => {
        assert.equal(finding.status, "Manual");
        assert.ok(finding.evidence.includes("endpoint=/admin/v1/settings"));
      },
    },
  },
  {
    assess: assessDuoMonitoring,
    fixture: compliantMonitoringData,
    key: "infoSummary",
    path: "/admin/v1/info/summary",
    fallback: null,
    expect: {
      "DUO-MON-003": (finding) => {
        assert.equal(finding.status, "Manual");
        assert.ok(finding.evidence.includes("endpoint=/admin/v1/info/summary"));
        assert.ok(finding.evidence.includes("telephony_logs=0"), "the readable telephony log is still reported");
      },
    },
  },
  {
    assess: assessDuoMonitoring,
    fixture: compliantMonitoringData,
    key: "telephonyLogs",
    path: "/admin/v2/logs/telephony",
    fallback: [],
    expect: {
      "DUO-MON-003": (finding) => {
        assert.equal(finding.status, "Manual");
        assert.ok(finding.evidence.includes("endpoint=/admin/v2/logs/telephony"));
        assert.ok(finding.evidence.includes("telephony_credits_remaining=900"), "the readable credit balance is still reported");
      },
    },
  },
  {
    assess: assessDuoMonitoring,
    fixture: compliantMonitoringData,
    key: "authenticationAttempts",
    path: "/admin/v1/info/authentication_attempts",
    fallback: null,
    expect: {
      "DUO-MON-005": (finding) => {
        assert.equal(finding.status, "Manual");
        assert.ok(finding.evidence.includes("endpoint=/admin/v1/info/authentication_attempts"));
      },
    },
  },
  {
    assess: assessDuoMonitoring,
    fixture: compliantMonitoringData,
    key: "trustMonitorEvents",
    path: "/admin/v1/trust_monitor/events",
    fallback: [],
    expect: {
      "DUO-MON-002": (finding) => {
        assert.equal(finding.status, "Manual");
        assert.ok(finding.evidence.includes("endpoint=/admin/v1/trust_monitor/events"));
      },
    },
  },
  {
    assess: assessDuoMonitoring,
    fixture: compliantMonitoringData,
    key: "activityLogs",
    path: "/admin/v2/logs/activity",
    fallback: [],
    expect: {},
  },
];

/** Snapshot summary fields that are derived from each list dataset; all must read as unread when that list is denied. */
const SNAPSHOT_FIELDS_BY_DATASET = {
  users: ["users"],
  bypassCodes: ["active_bypass_codes"],
  webauthnCredentials: ["webauthn_credentials"],
  authenticationLogs: ["auth_logs_collected"],
  offlineEnrollmentLogs: ["offline_enrollment_events"],
  admins: ["admins", "owners", "stale_admins", "undated_admins"],
  activityLogs: ["activity_logs_collected"],
  integrations: ["protected_integrations", "adminapi_integrations", "overprivileged_adminapi_integrations"],
  policies: ["policies"],
  trustMonitorEvents: ["trust_monitor_events"],
  telephonyLogs: ["telephony_logs"],
};

test("rule 1 corollary: denying one secondary read at a time never passes a dependent finding silently and never moves unrelated findings", () => {
  const config = createSampleConfig();
  for (const denial of SECONDARY_DENIALS) {
    const baseline = statusesOf(denial.assess(denial.fixture(), config));
    const data = { ...denial.fixture(), [denial.key]: forbiddenDataset(denial.path, denial.fallback) };
    const result = denial.assess(data, config);
    const label = `${denial.assess.name} with ${denial.path} denied`;

    for (const [id, check] of Object.entries(denial.expect)) {
      check(findingById(result, id));
    }
    for (const finding of result.findings) {
      if (denial.expect[finding.id]) continue;
      assert.equal(finding.status, baseline[finding.id], `${label}: ${finding.id} must not move from ${baseline[finding.id]}`);
    }
    for (const finding of result.findings.filter((item) => item.status === "Manual")) {
      assertManualContext(finding);
    }
    for (const field of SNAPSHOT_FIELDS_BY_DATASET[denial.key] ?? []) {
      if (!(field in result.snapshotSummary)) continue;
      assert.equal(result.snapshotSummary[field], null, `${label}: snapshot ${field} must be null, not a count derived from the empty fallback`);
      assert.match(result.text, new RegExp(`${field.replace(/_/g, " ")}: unread`), `${label}: the text summary renders ${field} as unread`);
    }
    denial.snapshot?.(result);
  }
});

test("rule 1 corollary: every list dataset renders null in the snapshot summary and null in core_data when it is denied", async () => {
  const config = createSampleConfig();
  const assessors = {
    authentication: [collectDuoAuthenticationData, assessDuoAuthentication],
    admin_access: [collectDuoAdminAccessData, assessDuoAdminAccess],
    integrations: [collectDuoIntegrationData, assessDuoIntegrations],
    monitoring: [collectDuoMonitoringData, assessDuoMonitoring],
  };
  const listSurfaces = {
    "/admin/v1/users": ["authentication", "users"],
    "/admin/v1/bypass_codes": ["authentication", "active_bypass_codes"],
    "/admin/v1/webauthncredentials": ["authentication", "webauthn_credentials"],
    "/admin/v2/logs/authentication": ["authentication", "auth_logs_collected"],
    "/admin/v1/logs/offline_enrollment": ["authentication", "offline_enrollment_events"],
    "/admin/v1/admins": ["admin_access", "admins"],
    "/admin/v2/logs/activity": ["admin_access", "activity_logs_collected"],
    "/admin/v3/integrations": ["integrations", "protected_integrations"],
    "/admin/v2/policies": ["integrations", "policies"],
    "/admin/v1/trust_monitor/events": ["monitoring", "trust_monitor_events"],
    "/admin/v2/logs/telephony": ["monitoring", "telephony_logs"],
  };
  for (const [surface, [category, field]] of Object.entries(listSurfaces)) {
    const client = new DuoAuditorClient(config, { fetchImpl: routedFetch({ ...healthyDuoRoutes(), [surface]: () => forbiddenResponse() }) });
    const [collect, assess] = assessors[category];
    const result = assess(await collect(client, config.lookbackDays), config);
    assert.equal(result.snapshotSummary[field], null, `${surface} denied: ${category} snapshot ${field} is null`);
    assert.match(result.text, new RegExp(`${field.replace(/_/g, " ")}: unread`), `${surface} denied: text renders ${field} as unread`);
  }
});

/** core_data file written for each list endpoint, used to check denied-list markers one inventory at a time. */
const LIST_CORE_DATA_FILES = {
  "/admin/v1/users": "core_data/users.json",
  "/admin/v1/bypass_codes": "core_data/bypass_codes.json",
  "/admin/v1/webauthncredentials": "core_data/webauthn_credentials.json",
  "/admin/v2/logs/authentication": "core_data/authentication_logs.json",
  "/admin/v1/logs/offline_enrollment": "core_data/offline_enrollment_logs.json",
  "/admin/v1/admins": "core_data/admins.json",
  "/admin/v2/logs/activity": "core_data/activity_logs.json",
  "/admin/v3/integrations": "core_data/integrations.json",
  "/admin/v2/policies": "core_data/policies.json",
  "/admin/v1/trust_monitor/events": "core_data/trust_monitor_events.json",
  "/admin/v2/logs/telephony": "core_data/telephony_logs.json",
};

function collectionStatusEntries(status) {
  return Object.values(status).flatMap((category) => Object.values(category));
}

test("denied-list markers: a denied list writes a not-collected marker in core_data with the observed status and path while a readable-but-empty list stays []", async () => {
  const config = createSampleConfig();
  const outputRoot = createTempBase("grclanker-duo-markers-");

  for (const [surface, file] of Object.entries(LIST_CORE_DATA_FILES)) {
    const client = new DuoAuditorClient(config, { fetchImpl: routedFetch({ ...healthyDuoRoutes(), [surface]: () => forbiddenResponse() }) });
    const exported = await exportDuoAuditBundle(client, config, outputRoot);
    const files = readBundleFiles(exported.outputDir);

    const marker = JSON.parse(files.get(file));
    assert.deepEqual(Object.keys(marker).sort(), ["collected", "endpoint", "error", "status"], `${surface}: the denied list is a marker object, not []`);
    assert.equal(marker.collected, false);
    assert.equal(marker.status, 403, `${surface}: the marker carries the status the request observed`);
    assert.equal(marker.endpoint, surface, `${surface}: the marker names the path the request actually used`);
    assert.match(marker.error, /\(403 Forbidden\): Access denied: Insufficient permissions/);

    // The healthy fixture serves offline enrollment and telephony logs as readable-but-empty lists.
    const control = surface === "/admin/v2/logs/telephony" ? "core_data/offline_enrollment_logs.json" : "core_data/telephony_logs.json";
    assert.deepEqual(JSON.parse(files.get(control)), [], `${surface} denied: a readable-but-empty list is still []`);

    const entry = collectionStatusEntries(JSON.parse(files.get("core_data/collection_status.json"))).find((candidate) => candidate.endpoint === surface);
    assert.ok(entry, `${surface}: collection_status.json names the denied endpoint`);
    assert.deepEqual(
      { readable: entry.readable, records: entry.records, total: entry.total, complete: entry.complete, status: entry.status },
      { readable: false, records: null, total: null, complete: null, status: 403 },
      `${surface}: count, total, and paging flags stay null for a read that never ran`,
    );
  }

  const client = new DuoAuditorClient(config, {
    fetchImpl: routedFetch({ ...healthyDuoRoutes(), "/admin/v1/info/authentication_attempts": () => forbiddenResponse() }),
  });
  const exported = await exportDuoAuditBundle(client, config, outputRoot);
  const files = readBundleFiles(exported.outputDir);
  const attemptsMarker = JSON.parse(files.get("core_data/authentication_attempts.json"));
  assert.equal(attemptsMarker.collected, false, "a denied object dataset is also written as a marker");
  assert.equal(attemptsMarker.status, 403);
  assert.equal(attemptsMarker.endpoint, "/admin/v1/info/authentication_attempts");
  const attemptsStatus = collectionStatusEntries(JSON.parse(files.get("core_data/collection_status.json"))).find(
    (candidate) => candidate.endpoint === "/admin/v1/info/authentication_attempts",
  );
  assert.deepEqual(attemptsStatus, {
    readable: false,
    error: attemptsMarker.error,
    status: 403,
    endpoint: "/admin/v1/info/authentication_attempts",
  });
});

function recordingFetch(routes, log) {
  return async (input, init) => {
    const requestUrl = new URL(typeof input === "string" ? input : input.toString());
    const route = routes[requestUrl.pathname];
    if (!route) throw new Error(`Unexpected request: ${requestUrl.pathname}`);
    const response = await route();
    log.push({ method: init?.method ?? "GET", path: requestUrl.pathname, status: response.status });
    return response;
  };
}

function namedEndpoints(text) {
  return new Set(text.match(/\/admin\/v\d\/[A-Za-z0-9_/-]+/g) ?? []);
}

function namedStatusCodes(text) {
  const codes = new Set();
  for (const match of text.matchAll(/\((\d{3}) (?:[A-Z][A-Za-z]*(?: |\)))/g)) codes.add(Number(match[1]));
  for (const match of text.matchAll(/"status": ?(\d{3})\b/g)) codes.add(Number(match[1]));
  return codes;
}

test("request matching: every endpoint path and HTTP status named in any output corresponds to a request the run made and observed", async () => {
  const config = createSampleConfig();
  const outputRoot = createTempBase("grclanker-duo-request-log-");
  const log = [];
  const routes = {
    ...healthyDuoRoutes(),
    "/admin/v1/bypass_codes": () => forbiddenResponse(),
    "/admin/v2/logs/telephony": () => canaryHtmlResponse(),
    "/admin/v1/admins/allowed_auth_methods": () => new Response("", { status: 404, statusText: "Not Found" }),
  };
  const client = new DuoAuditorClient(config, { fetchImpl: recordingFetch(routes, log) });

  const outputs = [JSON.stringify(await runDuoAccessCheck(client, config))];
  outputs.push(JSON.stringify(assessDuoAuthentication(await collectDuoAuthenticationData(client, config.lookbackDays), config)));
  outputs.push(JSON.stringify(assessDuoAdminAccess(await collectDuoAdminAccessData(client, config.lookbackDays), config)));
  outputs.push(JSON.stringify(assessDuoIntegrations(await collectDuoIntegrationData(client), config)));
  outputs.push(JSON.stringify(assessDuoMonitoring(await collectDuoMonitoringData(client, config.lookbackDays), config)));
  const exported = await exportDuoAuditBundle(client, config, outputRoot);
  outputs.push(...readBundleFiles(exported.outputDir).values());

  const requestedPaths = new Set(log.map((entry) => entry.path));
  const observedStatuses = new Set(log.map((entry) => entry.status));
  assert.ok(observedStatuses.has(403) && observedStatuses.has(502) && observedStatuses.has(404), "the fixture served every failure status under test");

  const text = outputs.join("\n");
  const endpoints = namedEndpoints(text);
  const statuses = namedStatusCodes(text);
  assert.ok(endpoints.size >= 3, "the outputs name the failing endpoints");
  assert.ok(statuses.has(403) && statuses.has(502) && statuses.has(404), "the outputs name the observed failure statuses");
  for (const endpoint of endpoints) {
    assert.ok(requestedPaths.has(endpoint), `endpoint ${endpoint} is named in output but the run never requested it`);
  }
  for (const status of statuses) {
    assert.ok(observedStatuses.has(status), `status ${status} is named in output but no request observed it`);
  }
});

test("rule 1 corollary: DUO-AUTH-006 keeps reading bypass codes when settings are unread and DUO-AUTH-001 never invents administrator WebAuthn", () => {
  const config = createSampleConfig();

  const staleWithSettingsUnread = compliantAuthenticationData();
  staleWithSettingsUnread.settings = forbiddenDataset("/admin/v1/settings", null);
  staleWithSettingsUnread.bypassCodes = dataset([bypassCode("B1", { created: NOW_SECONDS - 3 * DAY_SECONDS })]);
  const stale = findingById(assessDuoAuthentication(staleWithSettingsUnread, config), "DUO-AUTH-006");
  assert.equal(stale.status, "Fail", "a stale code still fails on the readable inventory");
  assert.ok(stale.evidence.some((line) => line.startsWith("helpdesk_bypass=unread (/admin/v1/settings (403 Forbidden)")));

  const settingsWithoutKeys = compliantAuthenticationData();
  settingsWithoutKeys.settings = dataset({});
  const unknown = findingById(assessDuoAuthentication(settingsWithoutKeys, config), "DUO-AUTH-006");
  assert.equal(unknown.status, "Pass", "a readable settings payload without helpdesk keys is reported as unknown, not unread");
  assert.ok(unknown.evidence.includes("helpdesk_bypass=unknown"));

  const weakPolicy = compliantAuthenticationData();
  weakPolicy.globalPolicy.data.sections.authentication_methods = { allowed_auth_list: "duo-passcode", blocked_auth_list: "" };
  weakPolicy.policies.data[0].sections.authentication_methods = { allowed_auth_list: "duo-passcode", blocked_auth_list: "" };
  weakPolicy.allowedAdminAuthMethods = forbiddenDataset("/admin/v1/admins/allowed_auth_methods", null);
  const fail = findingById(assessDuoAuthentication(weakPolicy, config), "DUO-AUTH-001");
  assert.equal(fail.status, "Fail", "an unread admin methods payload never softens a Fail into Partial");
  assert.ok(fail.evidence.some((line) => line.startsWith("admin_allowed_auth_methods=unread (/admin/v1/admins/allowed_auth_methods (403 Forbidden)")));

  const emptyAdminMethods = compliantAuthenticationData();
  emptyAdminMethods.allowedAdminAuthMethods = dataset({});
  const noPayload = findingById(assessDuoAuthentication(emptyAdminMethods, config), "DUO-AUTH-001");
  assert.ok(noPayload.evidence.some((line) => line.startsWith("admin_allowed_auth_methods=unread (/admin/v1/admins/allowed_auth_methods returned no usable payload")));

  const readable = findingById(assessDuoAuthentication(compliantAuthenticationData(), config), "DUO-AUTH-001");
  assert.ok(readable.evidence.includes("Admin auth methods allow WebAuthn."));
  assert.ok(readable.evidence.includes("admin_allowed_auth_methods.webauthn_enabled=true"));
});

test("config loader errors: a SyntaxError raised by the transport is recorded by name only, never by the parser's message that quotes the body", async () => {
  const snippet = parserSnippetBody();
  const fetchImpl = async () => {
    throw new SyntaxError(`Unexpected token '<', "${snippet}"... is not valid JSON`);
  };
  const note = "SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body";
  const config = createSampleConfig();
  const client = new DuoAuditorClient(config, { fetchImpl });

  await assert.rejects(() => client.getSettings(), (error) => {
    assert.equal(error.name, "DuoApiError");
    assertNoCanaryWindows(assert, error.message, [PARSER_SNIPPET_CANARY], "thrown client error");
    assert.doesNotMatch(error.message, PARSER_WORDING, `the parser's message was interpolated: ${error.message}`);
    assert.equal(error.message, `Duo API request failed for /admin/v1/settings (network error: ${note})`);
    return true;
  });

  const outputs = [
    await runDuoAccessCheck(client, config).then((result) => JSON.stringify(result), (error) => error.message),
    JSON.stringify(assessDuoAuthentication(await collectDuoAuthenticationData(client, config.lookbackDays), config)),
  ];
  for (const text of outputs) {
    assertNoCanaryWindows(assert, text, [PARSER_SNIPPET_CANARY], "tool output");
    assert.doesNotMatch(text, PARSER_WORDING, `a slice of the parser's message reached an output: ${text.slice(0, 400)}`);
    assert.ok(text.includes(note), `the output records the parse failure by name: ${text.slice(0, 400)}`);
  }
});

test("config loader errors: a 200 answer whose body is short non-JSON text is recorded as the non-JSON note only; no 6-to-24-character window of the body and no parser wording reaches the thrown client error, the access check, an assessment, or the bundle", async () => {
  // Positive control for the class: V8 quotes the whole source when it is 21 characters or shorter.
  assert.ok(SHORT_BODY_CANARY.length <= 21 && parserMessageFor(SHORT_BODY_CANARY).includes(SHORT_BODY_CANARY), "the parser's message carries the whole short body");

  const config = createSampleConfig();
  const surface = "/admin/v1/settings";
  const log = [];
  const client = new DuoAuditorClient(config, { fetchImpl: recordingFetch({ ...healthyDuoRoutes(), [surface]: () => shortBodyResponse() }, log) });

  // The thrown client error is fixed text: a scrub at the tool boundary would not protect a caller that logs it.
  await assert.rejects(() => client.getSettings(), (error) => {
    assert.equal(error.name, "DuoApiError");
    assert.equal(error.status, 200);
    assert.equal(error.path, surface);
    assertShortBodyRecordedAsNote(assert, error.message, "thrown client error");
    assert.equal(error.message, `Duo API request returned an unexpected payload for ${surface}: non-JSON body (${SHORT_BODY_CONTENT_TYPE}, 18 bytes)`);
    return true;
  });

  const access = await runDuoAccessCheck(client, config);
  assertShortBodyRecordedAsNote(assert, access, "check_access");
  const probe = access.probes.find((entry) => entry.path === surface);
  assert.ok(probe && probe.status === "error", "the settings probe is not ok and is not mislabelled as a 401 or 403");
  assertShortBodyRecordedAsNote(assert, probe.detail, "settings probe detail");

  const authentication = await collectDuoAuthenticationData(client, config.lookbackDays);
  assertShortBodyRecordedAsNote(assert, authentication.settings.error, "settings dataset error");
  assert.equal(authentication.settings.status, 200, "the dataset records the observed status");
  assertShortBodyRecordedAsNote(assert, assessDuoAuthentication(authentication, config), "authentication assessment");

  const exported = await exportDuoAuditBundle(client, config, createTempBase("grclanker-duo-short-body-"));
  const files = readBundleFiles(exported.outputDir);
  for (const [name, text] of files) assertNoShortBodyFragments(assert, text, `bundle ${name}`);
  for (const [name, text] of readZipEntries(exported.zipPath)) assertNoShortBodyFragments(assert, text, `zip ${name}`);
  assertShortBodyRecordedAsNote(assert, files.get("_errors.log"), "_errors.log");
  assert.ok(log.some((entry) => entry.path === surface && entry.status === 200), "the 200 answer named in the note was observed");
});
