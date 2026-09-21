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
  resolveDuoConfiguration,
  resolveSecureOutputPath,
  runDuoAccessCheck,
} from "../dist/extensions/grc-tools/duo.js";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function dataset(data, error) {
  return error ? { data, error } : { data };
}

function createSampleConfig() {
  return {
    apiHost: "api-example.duosecurity.com",
    ikey: "DIXXXXXXXXXXXXXXXXXX",
    skey: "super-secret-key",
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
            allowed_auth_list: ["webauthn", "duo-push"],
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
            requires_duo_desktop: true,
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
          allowed_auth_list: ["webauthn", "duo-push"],
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
          requires_duo_desktop: true,
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
        allowed_auth_list: ["webauthn", "duo-push"],
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
    assert.equal(finding.status, "Manual", `${finding.id} should be Manual on 403`);
    assert.ok(finding.evidence.some((line) => line.startsWith("endpoint=/admin/")), `${finding.id} names the endpoint`);
    assert.ok(finding.evidence.some((line) => line.startsWith("required_permission=Grant")), `${finding.id} names the permission`);
    assert.ok(finding.evidence.some((line) => line.startsWith("manual_evidence=")), `${finding.id} names the evidence to collect`);
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

test("assessDuoAdminAccess evaluates lockout policy and undated administrators", () => {
  const compliant = assessDuoAdminAccess(compliantAdminData(), createSampleConfig());
  for (const id of ["DUO-ADMIN-001", "DUO-ADMIN-002", "DUO-ADMIN-003", "DUO-ADMIN-004", "DUO-ADMIN-005"]) {
    assert.equal(findingById(compliant, id).status, "Pass", `${id} passes on the compliant tenant`);
  }

  const forbiddenResult = assessDuoAdminAccess(forbiddenAdminData(), createSampleConfig());
  assertNoPass(forbiddenResult, "forbidden admin data");
  for (const finding of forbiddenResult.findings) {
    assert.equal(finding.status, "Manual", `${finding.id} should be Manual on 403`);
    assert.ok(finding.evidence.some((line) => line.startsWith("required_permission=Grant")), `${finding.id} names the permission`);
  }

  const emptyResult = assessDuoAdminAccess(
    { settings: dataset({}), admins: dataset([]), allowedAdminAuthMethods: dataset({}), activityLogs: dataset([]) },
    createSampleConfig(),
  );
  assert.deepEqual(
    emptyResult.findings.filter((finding) => finding.status === "Pass").map((finding) => finding.id),
    ["DUO-MON-004"],
    "readable-but-empty activity logs remain the only Pass because the control only asserts readability",
  );

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
  for (const finding of forbiddenResult.findings) {
    assert.equal(finding.status, "Manual", `${finding.id} should be Manual on 403`);
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
  for (const id of ["DUO-INTEGRATIONS-001", "DUO-INTEGRATIONS-004", "DUO-INTEGRATIONS-005"]) {
    assert.equal(findingById(partialResult, id).status, "Partial", `${id} must not pass on a partial inventory`);
  }

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

test("assessDuoMonitoring evaluates authentication attempts and impossible travel", () => {
  const compliant = assessDuoMonitoring(compliantMonitoringData(), createSampleConfig());
  for (const id of ["DUO-MON-001", "DUO-MON-002", "DUO-MON-003", "DUO-MON-004", "DUO-MON-005"]) {
    assert.equal(findingById(compliant, id).status, "Pass", `${id} passes on the compliant tenant`);
  }

  const forbiddenResult = assessDuoMonitoring(forbiddenMonitoringData(), createSampleConfig());
  assertNoPass(forbiddenResult, "forbidden monitoring data");
  for (const finding of forbiddenResult.findings) {
    assert.equal(finding.status, "Manual", `${finding.id} should be Manual on 403`);
  }
  assert.ok(findingById(forbiddenResult, "DUO-MON-005").evidence.includes("required_permission=Grant read information"));

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
  assert.deepEqual(
    emptyResult.findings.filter((finding) => finding.status === "Pass").map((finding) => finding.id),
    ["DUO-MON-003"],
    "zero telephony usage with unknown credits is the only compliant-by-intent empty result",
  );
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
