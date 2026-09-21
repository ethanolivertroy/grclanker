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
import { join } from "node:path";

import {
  CROWDSTRIKE_CLOUDS,
  CROWDSTRIKE_CONTROLS,
  CROWDSTRIKE_FRAMEWORKS,
  CrowdstrikeApiClient,
  CrowdstrikeHttpError,
  assessCrowdstrikeAccessGovernance,
  assessCrowdstrikeDeviceFirewall,
  assessCrowdstrikePreventionPolicies,
  assessCrowdstrikeResponseReadiness,
  assessCrowdstrikeSensorCoverage,
  checkCrowdstrikeAccess,
  exportCrowdstrikeAuditBundle,
  resolveCrowdstrikeConfiguration,
  resolveSecureOutputPath,
  runAllCrowdstrikeAssessments,
} from "../dist/extensions/grc-tools/crowdstrike.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";
import { assertSecretsAbsent, readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";

const ALL_CONTROL_IDS = Array.from({ length: 25 }, (_, index) => `CS-${String(index + 1).padStart(2, "0")}`);
const EXPECTED_TOOLS = [
  "crowdstrike_check_access",
  "crowdstrike_assess_prevention_policies",
  "crowdstrike_assess_response_readiness",
  "crowdstrike_assess_device_firewall",
  "crowdstrike_assess_sensor_coverage",
  "crowdstrike_assess_access_governance",
  "crowdstrike_export_audit_bundle",
];

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function sampleConfig(overrides = {}) {
  return {
    clientId: "client-id",
    clientSecret: "client-secret-value",
    baseUrl: "https://api.crowdstrike.com",
    cloud: "us-1",
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

function isoDaysAgo(days) {
  return new Date(Date.now() - days * 86_400_000).toISOString();
}

function isoHoursAgo(hours) {
  return new Date(Date.now() - hours * 3_600_000).toISOString();
}

function findingById(result, id) {
  const item = result.findings.find((entry) => entry.id === id);
  assert.ok(item, `expected finding ${id}`);
  return item;
}

function page(items, overrides = {}) {
  return { items, total: items.length, truncated: false, ...overrides };
}

function truncatedPage(items, total = items.length * 10) {
  return { items, total, truncated: true };
}

function forbidden(path) {
  return async () => {
    throw new CrowdstrikeHttpError(`CrowdStrike request failed for ${path} (403): access denied`, 403, path);
  };
}

const SCOPE_GROUP_NAMES = {
  "prevention-policies": "Prevention Policies",
  hosts: "Hosts",
  "user-management": "User Management",
  "sensor-update-policies": "Sensor Update Policies",
  detects: "Detections",
};

function apiScope(id, action) {
  return { id, group: SCOPE_GROUP_NAMES[id] ?? id, action };
}

const PAGED_METHODS = [
  "listPreventionPolicies",
  "listResponsePolicies",
  "listRtrSessions",
  "listAlerts",
  "listHosts",
  "listDeviceControlPolicies",
  "listFirewallPolicies",
  "listFirewallRuleGroups",
  "listFirewallRules",
  "listSensorUpdatePolicies",
  "listHostGroups",
  "listUserUuids",
  "listUserRoles",
  "listRoles",
  "listApiClients",
  "listDiscoverHosts",
  "listZtaAssessments",
  "listIoaExclusions",
  "listMlExclusions",
  "listSensorVisibilityExclusions",
  "listIdentityProtectionRules",
];

function autoPaged(fn) {
  return async (...args) => {
    const result = await fn(...args);
    return Array.isArray(result) ? page(result) : result;
  };
}

function statusMap(assessments) {
  return Object.fromEntries(assessments.flatMap((assessment) => assessment.findings.map((item) => [item.id, item.status])));
}

function toggleSettings(ids, enabled) {
  return ids.map((id) => ({ id, type: "toggle", value: { enabled } }));
}

function preventionPolicy(overrides = {}) {
  const {
    id = "prev-win",
    name = "Windows Hardened",
    platform = "Windows",
    enabled = true,
    detection = "AGGRESSIVE",
    prevention = "AGGRESSIVE",
    exploitEnabled = true,
    includeExploit = true,
    scriptEnabled = true,
    includeScript = true,
    tamperEnabled = true,
    detectOnWrite = true,
    quarantineOnWrite = true,
    groups = [{ id: "hg-1", name: "Workstations" }],
    sliders,
  } = overrides;
  const categories = [
    {
      name: "Machine Learning",
      settings: sliders ?? [
        { id: "CloudAntiMalware", type: "mlslider", value: { detection, prevention } },
        { id: "OnSensorMLSlider", type: "mlslider", value: { detection, prevention } },
        { id: "AdwarePUP", type: "mlslider", value: { detection: "MODERATE", prevention: "MODERATE" } },
      ],
    },
    { name: "Sensor Tampering", settings: toggleSettings(["SensorTamperingProtection"], tamperEnabled) },
    {
      name: "On-Write",
      settings: [
        ...toggleSettings(["DetectOnWrite"], detectOnWrite),
        ...toggleSettings(["QuarantineOnWrite"], quarantineOnWrite),
      ],
    },
  ];
  if (includeExploit) {
    categories.push({
      name: "Exploit Mitigation",
      settings: toggleSettings(
        ["ForceASLR", "ForceDEP", "HeapSprayPreallocation", "NullPageAllocation", "SEHOverwriteProtection", "ProcessHollowing"],
        exploitEnabled,
      ),
    });
  }
  if (includeScript) {
    categories.push({
      name: "Script Control",
      settings: toggleSettings(["ScriptBasedExecutionMonitoring", "InterpreterProtection", "EngineProtectionV2"], scriptEnabled),
    });
  }
  return { id, name, platform_name: platform, enabled, groups, prevention_settings: categories };
}

function passingPreventionPolicies() {
  return [
    preventionPolicy(),
    preventionPolicy({ id: "prev-mac", name: "Mac Hardened", platform: "Mac", includeExploit: false, includeScript: false }),
    preventionPolicy({ id: "prev-linux", name: "Linux Hardened", platform: "Linux", includeExploit: false, includeScript: false }),
  ];
}

function responsePolicy(overrides = {}) {
  const { rtr = true, customScripts = false, enabled = true, groups = [{ id: "hg-1" }] } = overrides;
  return {
    id: "resp-1",
    name: "Default Response",
    platform_name: "Windows",
    enabled,
    groups,
    settings: [
      {
        name: "Real Time Response",
        settings: [
          { id: "RealTimeFunctionality", type: "toggle", value: { enabled: rtr } },
          { id: "CustomScripts", type: "toggle", value: { enabled: customScripts } },
          { id: "GetCommand", type: "toggle", value: { enabled: true } },
        ],
      },
    ],
  };
}

function passingDeviceControl() {
  return {
    policies: [{ id: "dc-1", name: "USB Lockdown", platform_name: "Windows", enabled: true, groups: [{ id: "hg-1" }] }],
    details: [
      {
        id: "dc-1",
        usb_settings: {
          enforcement_mode: "MONITOR_ENFORCE",
          pcie_enforcement_mode: "MONITOR_ENFORCE",
          classes: [
            { id: "MASS_STORAGE", action: "BLOCK_ALL", exceptions: [{ id: "exc-1" }] },
            { id: "PRINTER", action: "FULL_ACCESS", exceptions: [] },
          ],
        },
        bluetooth_settings: {
          enforcement_mode: "MONITOR_ENFORCE",
          classes: [{ id: "AUDIO_VIDEO", action: "BLOCK_ALL" }],
        },
      },
    ],
  };
}

function passingFirewall() {
  return {
    policies: [{ id: "fw-1", name: "Workstation Firewall", platform_name: "Windows", enabled: true, groups: [{ id: "hg-1" }] }],
    containers: [{
      policy_id: "fw-1",
      platform_id: "0",
      enforce: true,
      test_mode: false,
      default_inbound: "DENY",
      default_outbound: "ALLOW",
      rule_group_ids: ["rg-1"],
    }],
    ruleGroups: [{ id: "rg-1", name: "Core", enabled: true, rule_ids: ["rule-1"] }],
    rules: [{ id: "rule-1", name: "Allow RDP from jump hosts", action: "ALLOW", direction: "IN", enabled: true, description: "Change CHG-1234" }],
  };
}

function host(overrides = {}) {
  return {
    device_id: "aid-1",
    hostname: "ws-01",
    platform_name: "Windows",
    agent_version: "7.22.17407.0",
    last_seen: isoHoursAgo(2),
    status: "normal",
    groups: ["hg-1"],
    reduced_functionality_mode: "no",
    modified_timestamp: isoHoursAgo(2),
    ...overrides,
  };
}

function passingUsers() {
  return {
    users: [
      { uuid: "u-admin", uid: "alice@example.com", status: "active", last_login_at: isoDaysAgo(3) },
      { uuid: "u-analyst", uid: "bob@example.com", status: "active", last_login_at: isoDaysAgo(1) },
    ],
    roles: {
      "u-admin": [{ role_id: "falcon_administrator", role_name: "Falcon Administrator" }],
      "u-analyst": [{ role_id: "falcon_analyst", role_name: "Falcon Analyst" }],
    },
  };
}

function sensorUpdatePolicy(overrides = {}) {
  return {
    id: "su-1",
    name: "Auto N-1",
    platform_name: "Windows",
    enabled: true,
    groups: [{ id: "hg-1" }],
    settings: { build: "17306|n-1|tagged", uninstall_protection: "ENABLED", stage: "prod" },
    ...overrides,
  };
}

function createFakeClient(overrides = {}) {
  const prevention = passingPreventionPolicies();
  const deviceControl = passingDeviceControl();
  const firewall = passingFirewall();
  const users = passingUsers();
  const hosts = [host(), host({ device_id: "aid-2", hostname: "ws-02" }), host({ device_id: "aid-3", hostname: "srv-01", platform_name: "Linux" })];

  const client = {
    getResolvedConfig: () => sampleConfig(),
    getJson: async () => ({ resources: ["x"], meta: { pagination: { total: 1 } } }),
    postJson: async () => ({ resources: ["x"], meta: { pagination: { total: 1 } } }),
    listPreventionPolicies: async () => prevention,
    listResponsePolicies: async () => [responsePolicy()],
    listRtrSessions: async () => [
      { id: "s-1", user_id: "alice@example.com", hostname: "ws-01", created_at: isoHoursAgo(5), deleted_at: isoHoursAgo(4.8), duration: 600 },
      { id: "s-2", user_id: "bob@example.com", hostname: "ws-02", created_at: isoHoursAgo(3), deleted_at: isoHoursAgo(2.9) },
    ],
    listAlerts: async () => [
      { composite_id: "a-1", severity: 90, severity_name: "Critical", status: "closed", created_timestamp: isoHoursAgo(30), updated_timestamp: isoHoursAgo(26), seconds_to_resolved: 7200 },
      { composite_id: "a-2", severity: 70, severity_name: "High", status: "new", created_timestamp: isoHoursAgo(10) },
    ],
    listHosts: async (_limit, filter) => (filter ? [] : hosts),
    listDeviceControlPolicies: async () => deviceControl.policies,
    getDeviceControlPoliciesV2: async () => deviceControl.details,
    listFirewallPolicies: async () => firewall.policies,
    getFirewallPolicyContainers: async () => firewall.containers,
    listFirewallRuleGroups: async () => firewall.ruleGroups,
    listFirewallRules: async () => firewall.rules,
    listSensorUpdatePolicies: async () => [sensorUpdatePolicy()],
    listSensorUpdateBuilds: async () => [
      { build: "17407|n|tagged", sensor_version: "7.22.17407", platform: "windows", stage: "prod" },
      { build: "17306|n-1|tagged", sensor_version: "7.21.17306", platform: "windows", stage: "prod" },
      { build: "17206|n-2|tagged", sensor_version: "7.20.17206", platform: "windows", stage: "prod" },
    ],
    listHostGroups: async () => [{ id: "hg-1", name: "Workstations", group_type: "dynamic" }],
    countDiscoverHosts: async (filter) => (filter.includes("unmanaged") ? 0 : 3),
    listDiscoverHosts: async () => [],
    countZtaAssessments: async (filter) => (filter.startsWith("score:<") ? 0 : 3),
    listZtaAssessments: async () => [],
    listUserUuids: async () => users.users.map((user) => user.uuid),
    getUsers: async () => users.users,
    listUserRoles: async (uuid) => users.roles[uuid] ?? [],
    listRoles: async () => [{ id: "falcon_administrator", display_name: "Falcon Administrator" }, { id: "falcon_analyst", display_name: "Falcon Analyst" }],
    listApiClients: async () => [{ id: "api-1", name: "grclanker audit", scopes: [apiScope("prevention-policies", "read"), apiScope("hosts", "read"), apiScope("user-management", "read")] }],
    listIoaExclusions: async () => [{ id: "ioa-1", name: "Backup agent", ifn_regex: "C:\\\\Program Files\\\\Backup\\\\agent\\.exe", cl_regex: ".*--quiet.*", applied_globally: false, groups: [{ id: "hg-1" }] }],
    listMlExclusions: async () => [{ id: "ml-1", value: "D:\\Builds\\artifacts\\*.pdb", excluded_from: ["blocking"], applied_globally: false, groups: [{ id: "hg-1" }] }],
    listSensorVisibilityExclusions: async () => [{ id: "sv-1", value: "/opt/vendor/agent/collector", applied_globally: false, groups: [{ id: "hg-1" }] }],
    listIdentityProtectionRules: async () => [{ id: "idp-1", name: "Block stale accounts", enabled: true, simulationMode: false, action: "BLOCK", trigger: "AUTHENTICATION" }],
    ...overrides,
  };
  for (const name of PAGED_METHODS) {
    client[name] = autoPaged(client[name]);
  }
  return client;
}

function createForbiddenClient() {
  const client = { getResolvedConfig: () => sampleConfig() };
  for (const name of Object.keys(createFakeClient())) {
    if (name === "getResolvedConfig") continue;
    client[name] = forbidden(`/${name}`);
  }
  return client;
}

function createEmptyClient() {
  return createFakeClient({
    listPreventionPolicies: async () => [],
    listResponsePolicies: async () => [],
    listRtrSessions: async () => [],
    listAlerts: async () => [],
    listHosts: async () => [],
    listDeviceControlPolicies: async () => [],
    getDeviceControlPoliciesV2: async () => [],
    listFirewallPolicies: async () => [],
    getFirewallPolicyContainers: async () => [],
    listFirewallRuleGroups: async () => [],
    listFirewallRules: async () => [],
    listSensorUpdatePolicies: async () => [],
    listSensorUpdateBuilds: async () => [],
    listHostGroups: async () => [],
    countDiscoverHosts: async () => 0,
    listDiscoverHosts: async () => [],
    countZtaAssessments: async () => 0,
    listZtaAssessments: async () => [],
    listUserUuids: async () => [],
    getUsers: async () => [],
    listUserRoles: async () => [],
    listRoles: async () => [],
    listApiClients: async () => [],
    listIoaExclusions: async () => [],
    listMlExclusions: async () => [],
    listSensorVisibilityExclusions: async () => [],
    listIdentityProtectionRules: async () => [],
  });
}

function createPartialClient() {
  const complete = createFakeClient();
  const overrides = {};
  for (const name of PAGED_METHODS) {
    overrides[name] = async (...args) => {
      const result = await complete[name](...args);
      return truncatedPage(result.items, result.items.length + 40);
    };
  }
  return createFakeClient({
    ...overrides,
    listUserRoles: async (uuid) => {
      if (uuid === "u-analyst") throw new CrowdstrikeHttpError("CrowdStrike request failed for /user-management/combined/user-roles/v2 (403)", 403, "/user-management/combined/user-roles/v2");
      return complete.listUserRoles(uuid);
    },
    countDiscoverHosts: async (filter) => (filter.includes("unmanaged") ? 1 : 99),
    countZtaAssessments: async (filter) => (filter.startsWith("score:<") ? 1 : 100),
  });
}

test("resolveCrowdstrikeConfiguration prefers explicit args over environment and config file values", () => {
  const home = createTempBase("grclanker-cs-home-");
  mkdirSync(join(home, ".crowdstrike"), { recursive: true });
  writeFileSync(join(home, ".crowdstrike", "config.json"), JSON.stringify({
    client_id: "file-client",
    client_secret: "file-secret",
    cloud: "eu-1",
    member_cid: "file-cid",
  }));

  const fromFile = resolveCrowdstrikeConfiguration({}, {}, home);
  assert.equal(fromFile.clientId, "file-client");
  assert.equal(fromFile.clientSecret, "file-secret");
  assert.equal(fromFile.baseUrl, CROWDSTRIKE_CLOUDS["eu-1"]);
  assert.equal(fromFile.cloud, "eu-1");
  assert.equal(fromFile.memberCid, "file-cid");
  assert.ok(fromFile.sourceChain.some((entry) => entry.startsWith("config:")));

  const fromEnv = resolveCrowdstrikeConfiguration({}, {
    CS_CLIENT_ID: "env-client",
    CS_CLIENT_SECRET: "env-secret",
    CS_BASE_URL: "https://api.us-2.crowdstrike.com/",
  }, home);
  assert.equal(fromEnv.clientId, "env-client");
  assert.equal(fromEnv.clientSecret, "env-secret");
  assert.equal(fromEnv.baseUrl, "https://api.us-2.crowdstrike.com");
  assert.equal(fromEnv.cloud, "us-2");
  assert.ok(fromEnv.sourceChain.includes("environment-client-id"));

  const fromArgs = resolveCrowdstrikeConfiguration({
    client_id: "arg-client",
    client_secret: "arg-secret",
    cloud: "us-gov-1",
    member_cid: "arg-cid",
    timeout_seconds: 9,
  }, {
    CS_CLIENT_ID: "env-client",
    CS_CLIENT_SECRET: "env-secret",
    CS_CLOUD: "us-2",
  }, home);
  assert.equal(fromArgs.clientId, "arg-client");
  assert.equal(fromArgs.clientSecret, "arg-secret");
  assert.equal(fromArgs.baseUrl, "https://api.laggar.gcw.crowdstrike.com");
  assert.equal(fromArgs.cloud, "us-gov-1");
  assert.equal(fromArgs.memberCid, "arg-cid");
  assert.equal(fromArgs.timeoutMs, 9000);
  assert.ok(fromArgs.sourceChain.includes("arguments-client-id"));
});

test("resolveCrowdstrikeConfiguration defaults to us-1, accepts FalconPy env names, and rejects bad input", () => {
  const home = createTempBase("grclanker-cs-home-empty-");
  const resolved = resolveCrowdstrikeConfiguration({}, { FALCON_CLIENT_ID: "falcon-id", FALCON_CLIENT_SECRET: "falcon-secret" }, home);
  assert.equal(resolved.baseUrl, "https://api.crowdstrike.com");
  assert.equal(resolved.cloud, "us-1");
  assert.equal(resolved.timeoutMs, 30000);
  assert.ok(resolved.sourceChain.includes("default-base-url"));

  assert.throws(() => resolveCrowdstrikeConfiguration({}, {}, home), /CS_CLIENT_ID and CS_CLIENT_SECRET/);
  assert.throws(
    () => resolveCrowdstrikeConfiguration({ client_id: "a", client_secret: "b", cloud: "mars-1" }, {}, home),
    /Unknown CrowdStrike cloud/,
  );
  assert.throws(
    () => resolveCrowdstrikeConfiguration({ client_id: "a", client_secret: "b", base_url: "http://api.crowdstrike.com" }, {}, home),
    /must use https/,
  );
});

test("CrowdstrikeApiClient exchanges OAuth2 client credentials and paginates offset endpoints", async () => {
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({
      pathname: url.pathname,
      search: url.search,
      method: init.method ?? "GET",
      auth: headerValue(init.headers, "authorization"),
      body: init.body,
    });

    if (url.pathname === "/oauth2/token") {
      return jsonResponse({ access_token: "token-1", expires_in: 1799, token_type: "bearer" });
    }

    const offset = Number(url.searchParams.get("offset") ?? "0");
    if (offset === 0) {
      return jsonResponse({ resources: [{ id: "p-1" }, { id: "p-2" }], meta: { pagination: { offset: 2, limit: 2, total: 3 } } });
    }
    return jsonResponse({ resources: [{ id: "p-3" }], meta: { pagination: { offset: 3, limit: 2, total: 3 } } });
  };

  const client = new CrowdstrikeApiClient(sampleConfig({ memberCid: "child-cid" }), { fetchImpl });
  const policies = await client.listOffset("/policy/combined/prevention/v1", {}, { limit: 10, pageSize: 2 });

  assert.deepEqual(policies.items.map((policy) => policy.id), ["p-1", "p-2", "p-3"]);
  assert.equal(policies.total, 3);
  assert.equal(policies.truncated, false);
  assert.equal(seen[0].pathname, "/oauth2/token");
  assert.equal(seen[0].method, "POST");
  const tokenBody = new URLSearchParams(seen[0].body);
  assert.equal(tokenBody.get("client_id"), "client-id");
  assert.equal(tokenBody.get("client_secret"), "client-secret-value");
  assert.equal(tokenBody.get("member_cid"), "child-cid");
  assert.equal(seen[1].auth, "Bearer token-1");
  assert.equal(seen[1].pathname, "/policy/combined/prevention/v1");
  assert.match(seen[1].search, /limit=2/);
  assert.match(seen[2].search, /offset=2/);
  assert.equal(seen.filter((entry) => entry.pathname === "/oauth2/token").length, 1);
});

test("CrowdstrikeApiClient follows after cursors, opaque offset tokens, and POST alert pagination", async () => {
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.pathname === "/oauth2/token") {
      return jsonResponse({ access_token: "token-1", expires_in: 1799 });
    }
    if (url.pathname === "/discover/combined/hosts/v1") {
      const after = url.searchParams.get("after");
      if (!after) return jsonResponse({ resources: [{ id: "d-1" }], meta: { pagination: { after: "cursor-2", total: 2 } } });
      return jsonResponse({ resources: [{ id: "d-2" }], meta: { pagination: { total: 2 } } });
    }
    if (url.pathname === "/devices/combined/devices/v1") {
      const offset = url.searchParams.get("offset");
      if (!offset) return jsonResponse({ resources: [{ device_id: "h-1" }], meta: { pagination: { offset: "opaque-token", total: 2 } } });
      assert.equal(offset, "opaque-token");
      return jsonResponse({ resources: [{ device_id: "h-2" }], meta: { pagination: { total: 2 } } });
    }
    if (url.pathname === "/alerts/combined/alerts/v1") {
      const body = JSON.parse(init.body);
      assert.equal(init.method, "POST");
      if (!body.after) return jsonResponse({ resources: [{ composite_id: "a-1" }], meta: { pagination: { after: "alert-cursor" } } });
      return jsonResponse({ resources: [{ composite_id: "a-2" }], meta: { pagination: {} } });
    }
    throw new Error(`unexpected path ${url.pathname}`);
  };

  const client = new CrowdstrikeApiClient(sampleConfig(), { fetchImpl });
  const discovered = await client.listDiscoverHosts("entity_type:'unmanaged'", 10);
  assert.deepEqual(discovered.items.map((item) => item.id), ["d-1", "d-2"]);
  assert.equal(discovered.truncated, false);

  const hosts = await client.listHosts(10);
  assert.deepEqual(hosts.items.map((item) => item.device_id), ["h-1", "h-2"]);
  assert.equal(hosts.truncated, false);

  const alerts = await client.listAlerts("severity:>=70", 10);
  assert.deepEqual(alerts.items.map((item) => item.composite_id), ["a-1", "a-2"]);
  assert.equal(alerts.truncated, false);
});

test("CrowdstrikeApiClient records truncation instead of treating a first page as the whole population", async () => {
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.pathname === "/oauth2/token") {
      return jsonResponse({ access_token: "token-1", expires_in: 1799 });
    }
    if (url.pathname === "/policy/combined/prevention/v1") {
      const offset = Number(url.searchParams.get("offset") ?? "0");
      const limit = Number(url.searchParams.get("limit"));
      const ids = Array.from({ length: 7 }, (_, index) => ({ id: `p-${index + 1}` })).slice(offset, offset + limit);
      return jsonResponse({ resources: ids, meta: { pagination: { offset: offset + ids.length, limit, total: 7 } } });
    }
    if (url.pathname === "/discover/combined/hosts/v1") {
      const after = url.searchParams.get("after");
      const index = after ? Number(after.replace("cursor-", "")) : 0;
      const nextAfter = index + 1 < 3 ? `cursor-${index + 1}` : undefined;
      return jsonResponse({ resources: [{ id: `d-${index + 1}` }], meta: { pagination: { after: nextAfter, total: 3 } } });
    }
    if (url.pathname === "/alerts/combined/alerts/v1") {
      const body = JSON.parse(init.body);
      const index = body.after ? Number(body.after.replace("alert-", "")) : 0;
      return jsonResponse({ resources: [{ composite_id: `a-${index + 1}` }], meta: { pagination: { after: `alert-${index + 1}` } } });
    }
    throw new Error(`unexpected path ${url.pathname}`);
  };
  const client = new CrowdstrikeApiClient(sampleConfig(), { fetchImpl });

  const truncatedOffset = await client.listOffset("/policy/combined/prevention/v1", {}, { limit: 4, pageSize: 2 });
  assert.equal(truncatedOffset.items.length, 4);
  assert.equal(truncatedOffset.total, 7);
  assert.equal(truncatedOffset.truncated, true);

  const completeOffset = await client.listOffset("/policy/combined/prevention/v1", {}, { limit: 50, pageSize: 2 });
  assert.equal(completeOffset.items.length, 7);
  assert.equal(completeOffset.truncated, false);

  const truncatedAfter = await client.listDiscoverHosts("entity_type:'unmanaged'", 2);
  assert.equal(truncatedAfter.items.length, 2);
  assert.equal(truncatedAfter.total, 3);
  assert.equal(truncatedAfter.truncated, true);

  const completeAfter = await client.listDiscoverHosts("entity_type:'unmanaged'", 10);
  assert.equal(completeAfter.items.length, 3);
  assert.equal(completeAfter.truncated, false);

  const truncatedAlerts = await client.listAlerts("severity:>=70", 2);
  assert.equal(truncatedAlerts.items.length, 2);
  assert.equal(truncatedAlerts.truncated, true);
});

test("CrowdstrikeApiClient retries 429 and 5xx responses honoring X-RateLimit-RetryAfter and refreshes expired tokens", async () => {
  const sleeps = [];
  let tokenCount = 0;
  let policyCalls = 0;
  const auths = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.pathname === "/oauth2/token") {
      tokenCount += 1;
      return jsonResponse({ access_token: `token-${tokenCount}`, expires_in: 1799 });
    }
    auths.push(headerValue(init.headers, "authorization"));
    policyCalls += 1;
    if (policyCalls === 1) {
      return jsonResponse({ errors: [{ code: 429, message: "Rate limit exceeded" }] }, {
        status: 429,
        headers: { "X-RateLimit-RetryAfter": String(Math.floor(Date.now() / 1000) + 2) },
      });
    }
    if (policyCalls === 2) {
      return jsonResponse({ errors: [{ code: 502, message: "bad gateway" }] }, { status: 502 });
    }
    if (policyCalls === 3) {
      return jsonResponse({ errors: [{ code: 401, message: "access denied, invalid bearer token" }] }, { status: 401 });
    }
    return jsonResponse({ resources: [{ id: "p-1" }], meta: { pagination: { total: 1 } } });
  };

  const client = new CrowdstrikeApiClient(sampleConfig(), {
    fetchImpl,
    sleep: async (ms) => { sleeps.push(ms); },
  });
  const policies = await client.listPreventionPolicies();

  assert.deepEqual(policies.items.map((policy) => policy.id), ["p-1"]);
  assert.equal(sleeps.length, 2);
  assert.ok(sleeps[0] >= 1000 && sleeps[0] <= 2500, `expected retry-after delay near 2s, saw ${sleeps[0]}`);
  assert.equal(sleeps[1], 500);
  assert.equal(tokenCount, 2);
  assert.equal(auths[0], "Bearer token-1");
  assert.equal(auths[auths.length - 1], "Bearer token-2");
});

test("CrowdstrikeApiClient redacts secrets in errors and gives up after the retry budget", async () => {
  const leakyFetch = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.pathname === "/oauth2/token") {
      return jsonResponse({ errors: [{ code: 403, message: "invalid client client-secret-value" }] }, { status: 403 });
    }
    return jsonResponse({});
  };
  const client = new CrowdstrikeApiClient(sampleConfig(), { fetchImpl: leakyFetch });
  await assert.rejects(client.listPreventionPolicies(), (error) => {
    assert.ok(error instanceof CrowdstrikeHttpError);
    assert.equal(error.status, 403);
    assert.doesNotMatch(error.message, /client-secret-value/);
    assert.match(error.message, /\[REDACTED\]/);
    return true;
  });

  let attempts = 0;
  const failingFetch = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.pathname === "/oauth2/token") return jsonResponse({ access_token: "token", expires_in: 1799 });
    attempts += 1;
    return jsonResponse({ errors: [{ code: 503, message: "unavailable" }] }, { status: 503 });
  };
  const retryingClient = new CrowdstrikeApiClient(sampleConfig(), { fetchImpl: failingFetch, sleep: async () => {}, retryLimit: 2 });
  await assert.rejects(retryingClient.listHostGroups(), /\(503\)/);
  assert.equal(attempts, 3);

  const opaqueBodyFetch = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.pathname === "/oauth2/token") return jsonResponse({ access_token: "token", expires_in: 1799 });
    return new Response("<html>gateway error: x-api-key FAKE_PROXY_ECHOED_SECRET</html>", { status: 502, headers: { "content-type": "text/html; charset=utf-8" } });
  };
  const opaqueClient = new CrowdstrikeApiClient(sampleConfig(), { fetchImpl: opaqueBodyFetch, sleep: async () => {}, retryLimit: 0 });
  await assert.rejects(opaqueClient.listHostGroups(), (error) => {
    assert.match(error.message, /\(502\): response body omitted \(text\/html, 62 characters\)/);
    assert.doesNotMatch(error.message, /FAKE_PROXY_ECHOED_SECRET/, "a non-JSON error body is never copied into the error string");
    return true;
  });
});

test("checkCrowdstrikeAccess reports healthy when every read surface responds", async () => {
  const result = await checkCrowdstrikeAccess(createFakeClient());
  assert.equal(result.status, "healthy");
  assert.equal(result.surfaces.length, 19);
  assert.ok(result.surfaces.every((surface) => surface.status === "readable"));
  assert.deepEqual(result.missingScopes, []);
  assert.match(result.recommendedNextStep, /crowdstrike_export_audit_bundle/);
});

test("checkCrowdstrikeAccess reports limited access and missing scopes on 403 responses", async () => {
  const forbidden = new Set([
    "/user-management/queries/users/v1",
    "/user-management/queries/roles/v1",
    "/api-clients/queries/api-clients/v1",
    "/identity-protection/queries/policy-rules/v1",
    "/zero-trust-assessment/queries/assessments/v1",
  ]);
  const client = createFakeClient({
    getJson: async (path) => {
      if (forbidden.has(path)) throw new CrowdstrikeHttpError(`CrowdStrike request failed for ${path} (403): access denied`, 403, path);
      if (path === "/discover/queries/hosts/v1") throw new Error("socket hang up");
      return { resources: ["x"], meta: { pagination: { total: 4 } } };
    },
  });
  const result = await checkCrowdstrikeAccess(client);
  assert.equal(result.status, "limited");
  assert.equal(result.surfaces.filter((surface) => surface.status === "forbidden").length, 5);
  assert.equal(result.surfaces.find((surface) => surface.name === "discover_hosts").status, "not_readable");
  assert.ok(result.missingScopes.includes("User management: Read"));
  assert.ok(result.missingScopes.includes("Zero Trust Assessment: Read"));
  assert.match(result.recommendedNextStep, /Grant the missing read scopes/);
});

test("assessCrowdstrikePreventionPolicies passes hardened policies across platforms", async () => {
  const result = await assessCrowdstrikePreventionPolicies(createFakeClient());
  assert.equal(result.category, "prevention_policies");
  assert.deepEqual(result.findings.map((item) => item.id), ["CS-01", "CS-02", "CS-03", "CS-04", "CS-05"]);
  assert.ok(result.findings.every((item) => item.status === "pass"), JSON.stringify(result.findings.map((item) => [item.id, item.status, item.summary])));
  assert.equal(result.summary.enabled_policies, 3);
  assert.ok(findingById(result, "CS-01").mappings.includes("FedRAMP SI-3"));
  assert.ok(findingById(result, "CS-04").mappings.includes("DISA STIG V-256377"));
  assert.equal(findingById(result, "CS-04").severity, "critical");
});

test("assessCrowdstrikePreventionPolicies fails weak sliders, disabled mitigations, and disabled tamper protection", async () => {
  const client = createFakeClient({
    listPreventionPolicies: async () => [
      preventionPolicy({ detection: "CAUTIOUS", prevention: "DISABLED", exploitEnabled: false, scriptEnabled: false, tamperEnabled: false, detectOnWrite: false }),
      preventionPolicy({ id: "prev-disabled", name: "Disabled", platform: "Mac", enabled: false }),
    ],
  });
  const result = await assessCrowdstrikePreventionPolicies(client);
  for (const id of ["CS-01", "CS-02", "CS-03", "CS-04", "CS-05"]) {
    assert.equal(findingById(result, id).status, "fail", `${id} should fail`);
  }
  assert.match(findingById(result, "CS-01").summary, /Mac, Linux/);
  assert.equal(findingById(result, "CS-04").evidence.policies[0].disabled[0], "SensorTamperingProtection");

  const moderate = await assessCrowdstrikePreventionPolicies(createFakeClient({
    listPreventionPolicies: async () => [preventionPolicy({ detection: "MODERATE", prevention: "MODERATE", quarantineOnWrite: false })],
  }));
  assert.equal(findingById(moderate, "CS-01").status, "warn");
  assert.equal(findingById(moderate, "CS-05").status, "warn");

  const unreadable = await assessCrowdstrikePreventionPolicies(createFakeClient({
    listPreventionPolicies: async () => { throw new CrowdstrikeHttpError("CrowdStrike request failed for /policy/combined/prevention/v1 (403)", 403, "/policy/combined/prevention/v1"); },
  }));
  assert.ok(unreadable.findings.every((item) => item.status === "manual"));
  assert.equal(unreadable.errors.length, 1);
});

test("assessCrowdstrikeResponseReadiness passes RTR posture and flags session limits as manual", async () => {
  const result = await assessCrowdstrikeResponseReadiness(createFakeClient(), { lookbackDays: 14 });
  assert.deepEqual(result.findings.map((item) => item.id), ["CS-06", "CS-07", "CS-22", "CS-23"]);
  assert.equal(findingById(result, "CS-06").status, "pass");
  assert.equal(findingById(result, "CS-07").status, "manual");
  assert.match(findingById(result, "CS-07").summary, /Collect manually/);
  assert.equal(findingById(result, "CS-22").status, "pass");
  assert.equal(findingById(result, "CS-23").status, "pass");
  assert.equal(result.summary.lookback_days, 14);
  assert.deepEqual(Object.keys(result.snapshots), ["response_policies", "rtr_audit_sessions", "alerts", "contained_hosts"]);
});

test("assessCrowdstrikeResponseReadiness fails disabled RTR, SLA breaches, long sessions, and stale containment", async () => {
  const client = createFakeClient({
    listResponsePolicies: async () => [responsePolicy({ rtr: false })],
    listRtrSessions: async () => [
      { id: "s-long", user_id: "alice@example.com", hostname: "ws-01", created_at: isoHoursAgo(6), deleted_at: isoHoursAgo(4) },
    ],
    listAlerts: async () => [
      { composite_id: "a-1", severity: 90, severity_name: "Critical", status: "new", created_timestamp: isoHoursAgo(100) },
      { composite_id: "a-2", severity: 70, severity_name: "High", status: "closed", created_timestamp: isoHoursAgo(200), updated_timestamp: isoHoursAgo(20) },
    ],
    listHosts: async () => [host({ hostname: "contained-01", status: "contained", modified_timestamp: isoHoursAgo(200) })],
  });
  const result = await assessCrowdstrikeResponseReadiness(client);
  assert.equal(findingById(result, "CS-06").status, "fail");
  assert.equal(findingById(result, "CS-07").status, "warn");
  assert.equal(findingById(result, "CS-07").evidence.sessions_over_limit, 1);
  assert.equal(findingById(result, "CS-22").status, "fail");
  assert.equal(findingById(result, "CS-22").evidence.sla_breaches, 2);
  assert.equal(findingById(result, "CS-23").status, "warn");
  assert.match(findingById(result, "CS-23").summary, /1 hosts are network contained/);

  const scripts = await assessCrowdstrikeResponseReadiness(createFakeClient({
    listResponsePolicies: async () => [responsePolicy({ customScripts: true })],
  }));
  assert.equal(findingById(scripts, "CS-06").status, "warn");
});

test("assessCrowdstrikeDeviceFirewall passes enforced USB, peripheral, and default deny firewall posture", async () => {
  const result = await assessCrowdstrikeDeviceFirewall(createFakeClient());
  assert.deepEqual(result.findings.map((item) => item.id), ["CS-08", "CS-09", "CS-10", "CS-11"]);
  assert.ok(result.findings.every((item) => item.status === "pass"), JSON.stringify(result.findings.map((item) => [item.id, item.status, item.summary])));
  assert.equal(findingById(result, "CS-09").evidence.policies[0].sd_card_via_mass_storage_blocked, true);
  assert.equal(result.summary.firewall_rules_reviewed, 1);
});

test("assessCrowdstrikeDeviceFirewall fails monitor-only device control and permissive firewalls", async () => {
  const client = createFakeClient({
    getDeviceControlPoliciesV2: async () => [{
      id: "dc-1",
      usb_settings: {
        enforcement_mode: "MONITOR_ONLY",
        pcie_enforcement_mode: "MONITOR_ONLY",
        classes: [{ id: "MASS_STORAGE", action: "FULL_ACCESS", exceptions: [] }],
      },
    }],
    getFirewallPolicyContainers: async () => [{
      policy_id: "fw-1",
      enforce: false,
      test_mode: true,
      default_inbound: "ALLOW",
      default_outbound: "ALLOW",
      rule_group_ids: [],
    }],
    listFirewallRules: async () => [{ id: "rule-1", name: "Allow all", action: "ALLOW", direction: "IN", enabled: true }],
  });
  const result = await assessCrowdstrikeDeviceFirewall(client);
  for (const id of ["CS-08", "CS-09", "CS-10", "CS-11"]) {
    assert.equal(findingById(result, id).status, "fail", `${id} should fail`);
  }
  assert.match(findingById(result, "CS-11").summary, /1\/1 enabled allow rules have no description/);

  const exceptions = await assessCrowdstrikeDeviceFirewall(createFakeClient({
    getDeviceControlPoliciesV2: async () => [{
      id: "dc-1",
      usb_settings: {
        enforcement_mode: "MONITOR_ENFORCE",
        pcie_enforcement_mode: "MONITOR_ENFORCE",
        classes: [{ id: "MASS_STORAGE", action: "BLOCK_ALL", exceptions: Array.from({ length: 3 }, (_, index) => ({ id: `exc-${index}` })) }],
      },
      bluetooth_settings: { enforcement_mode: "MONITOR_ENFORCE", classes: [{ id: "AUDIO_VIDEO", action: "BLOCK_ALL" }] },
    }],
  }), { maxUsbExceptions: 2 });
  assert.equal(findingById(exceptions, "CS-08").status, "warn");

  const noPolicies = await assessCrowdstrikeDeviceFirewall(createFakeClient({
    listDeviceControlPolicies: async () => [],
    listFirewallPolicies: async () => [],
  }));
  assert.equal(findingById(noPolicies, "CS-08").status, "fail");
  assert.equal(findingById(noPolicies, "CS-10").status, "fail");
  assert.equal(findingById(noPolicies, "CS-11").status, "fail");
});

test("assessCrowdstrikeSensorCoverage passes auto-updating sensors with complete coverage", async () => {
  const result = await assessCrowdstrikeSensorCoverage(createFakeClient());
  assert.deepEqual(result.findings.map((item) => item.id), ["CS-12", "CS-13", "CS-14", "CS-15", "CS-25"]);
  assert.ok(result.findings.every((item) => item.status === "pass"), JSON.stringify(result.findings.map((item) => [item.id, item.status, item.summary])));
  assert.equal(findingById(result, "CS-12").evidence.policies[0].builds[0].tag, "n-1");
  assert.equal(result.summary.sampled_hosts, 3);
  assert.equal(result.summary.unmanaged_assets, 0);
});

test("assessCrowdstrikeSensorCoverage fails disabled updates, stale sensors, unmanaged assets, and low ZTA scores", async () => {
  const client = createFakeClient({
    listSensorUpdatePolicies: async () => [
      sensorUpdatePolicy({ id: "su-off", name: "Updates Off", settings: { build: "", uninstall_protection: "DISABLED" } }),
      sensorUpdatePolicy({ id: "su-old", name: "Pinned Old", settings: { build: "16000", uninstall_protection: "ENABLED" } }),
    ],
    listHosts: async () => [
      host({ last_seen: isoDaysAgo(30), groups: [] }),
      host({ device_id: "aid-2", hostname: "ws-02", last_seen: isoDaysAgo(45), groups: [], reduced_functionality_mode: "yes" }),
    ],
    countDiscoverHosts: async (filter) => (filter.includes("unmanaged") ? 5 : 3),
    listDiscoverHosts: async () => [{ hostname: "rogue-01", platform_name: "Linux", last_seen_timestamp: isoDaysAgo(1), local_ip_addresses: ["10.0.0.9"] }],
    countZtaAssessments: async (filter) => (filter.startsWith("score:<") ? 2 : 3),
    listZtaAssessments: async () => [{ aid: "aid-1", score: 22 }, { aid: "aid-2", score: 41 }],
  });
  const result = await assessCrowdstrikeSensorCoverage(client, { minZtaScore: 60 });
  for (const id of ["CS-12", "CS-13", "CS-14", "CS-15", "CS-25"]) {
    assert.equal(findingById(result, id).status, "fail", `${id} should fail`);
  }
  assert.equal(findingById(result, "CS-12").evidence.policies[0].builds[0].mode, "off");
  assert.equal(findingById(result, "CS-12").evidence.policies[1].builds[0].mode, "pinned");
  assert.equal(findingById(result, "CS-13").evidence.reduced_functionality_hosts, 1);
  assert.equal(findingById(result, "CS-15").evidence.unmanaged_samples[0].hostname, "rogue-01");
  assert.equal(findingById(result, "CS-25").evidence.hosts_below_threshold, 2);

  const unlicensed = await assessCrowdstrikeSensorCoverage(createFakeClient({
    countDiscoverHosts: async () => { throw new CrowdstrikeHttpError("CrowdStrike request failed for /discover/queries/hosts/v1 (403): access denied", 403, "/discover/queries/hosts/v1"); },
    countZtaAssessments: async () => { throw new CrowdstrikeHttpError("CrowdStrike request failed for /zero-trust-assessment/queries/assessments/v1 (404)", 404, "/zero-trust-assessment/queries/assessments/v1"); },
  }));
  assert.equal(findingById(unlicensed, "CS-15").status, "manual");
  assert.equal(findingById(unlicensed, "CS-25").status, "manual");
  assert.equal(unlicensed.errors.length, 2);
});

test("assessCrowdstrikeAccessGovernance passes least privilege, scoped API clients, and narrow exclusions", async () => {
  const result = await assessCrowdstrikeAccessGovernance(createFakeClient());
  assert.deepEqual(result.findings.map((item) => item.id), ["CS-16", "CS-17", "CS-18", "CS-19", "CS-20", "CS-21", "CS-24"]);
  assert.ok(result.findings.every((item) => item.status === "pass"), JSON.stringify(result.findings.map((item) => [item.id, item.status, item.summary])));
  assert.equal(result.summary.admin_users, 1);
  assert.equal(result.summary.api_clients, 1);
  assert.equal(findingById(result, "CS-24").evidence.enforcing_rules, 1);
});

test("assessCrowdstrikeAccessGovernance fails excessive admins, write-heavy API clients, broad exclusions, and missing identity rules", async () => {
  const admins = Array.from({ length: 11 }, (_, index) => ({ uuid: `u-${index}`, uid: `admin${index}@example.com`, status: "active", last_login_at: isoDaysAgo(200) }));
  const client = createFakeClient({
    listUserUuids: async () => [...admins.map((user) => user.uuid), "u-shared"],
    getUsers: async () => [...admins, { uuid: "u-shared", uid: "soc-shared@example.com", status: "active", last_login_at: isoDaysAgo(2) }],
    listUserRoles: async (uuid) => (uuid === "u-shared"
      ? [{ role_id: "falcon_administrator", role_name: "Falcon Administrator" }]
      : [
        { role_id: "falcon_administrator", role_name: "Falcon Administrator" },
        { role_id: "falcon_analyst", role_name: "Falcon Analyst" },
        { role_id: "rtr_admin", role_name: "Real Time Responder - Administrator" },
        { role_id: "image_admin", role_name: "Image Admin" },
        { role_id: "dashboard_admin", role_name: "Dashboard Admin" },
        { role_id: "fw_manager", role_name: "Firewall Manager" },
      ]),
    listApiClients: async () => Array.from({ length: 4 }, (_, index) => ({ id: `api-${index}`, name: `integration-${index}`, scopes: [apiScope("prevention-policies", "write"), apiScope("hosts", "write")] })),
    listIoaExclusions: async () => [{ id: "ioa-1", name: "Everything", ifn_regex: ".*", cl_regex: ".*", applied_globally: true, groups: [] }],
    listMlExclusions: async () => [{ id: "ml-1", value: "C:\\Windows\\Temp\\*", excluded_from: ["blocking", "extraction"], applied_globally: true, groups: [] }],
    listSensorVisibilityExclusions: async () => [{ id: "sv-1", value: "/usr/*", applied_globally: true, groups: [] }],
    listIdentityProtectionRules: async () => [],
  });
  const result = await assessCrowdstrikeAccessGovernance(client);
  for (const id of ["CS-16", "CS-17", "CS-18", "CS-19", "CS-20", "CS-21", "CS-24"]) {
    assert.equal(findingById(result, id).status, "fail", `${id} should fail: ${findingById(result, id).summary}`);
  }
  assert.equal(findingById(result, "CS-16").evidence.admin_users, 12);
  assert.ok(findingById(result, "CS-16").evidence.suspected_shared_accounts.includes("soc-shared@example.com"));
  assert.equal(findingById(result, "CS-17").evidence.stale_privileged.length, 11);
  assert.equal(findingById(result, "CS-18").evidence.write_clients.length, 4);

  const simulation = await assessCrowdstrikeAccessGovernance(createFakeClient({
    listIdentityProtectionRules: async () => [{ id: "idp-1", name: "Simulated", enabled: true, simulationMode: true, action: "BLOCK" }],
    listMlExclusions: async () => [{ id: "ml-2", value: "/tmp/build", applied_globally: false, groups: [{ id: "hg-1" }] }],
  }));
  assert.equal(findingById(simulation, "CS-24").status, "fail");
  assert.equal(findingById(simulation, "CS-20").status, "warn");

  const unlicensed = await assessCrowdstrikeAccessGovernance(createFakeClient({
    listIdentityProtectionRules: async () => { throw new CrowdstrikeHttpError("CrowdStrike request failed for /identity-protection/queries/policy-rules/v1 (403)", 403, "/identity-protection/queries/policy-rules/v1"); },
    listUserUuids: async () => { throw new CrowdstrikeHttpError("CrowdStrike request failed for /user-management/queries/users/v1 (403)", 403, "/user-management/queries/users/v1"); },
  }));
  assert.equal(findingById(unlicensed, "CS-24").status, "manual");
  assert.equal(findingById(unlicensed, "CS-16").status, "manual");
  assert.equal(findingById(unlicensed, "CS-17").status, "manual");
});

test("verdict safety rule 1: unreadable dependencies yield manual with cause and console evidence, never pass", async () => {
  const deviceDetails = await assessCrowdstrikeDeviceFirewall(createFakeClient({
    getDeviceControlPoliciesV2: forbidden("/policy/entities/device-control/v2"),
    getFirewallPolicyContainers: async () => { throw new Error("socket hang up"); },
  }));
  for (const id of ["CS-08", "CS-09", "CS-10", "CS-11"]) {
    const item = findingById(deviceDetails, id);
    assert.equal(item.status, "manual", `${id} should be manual`);
    assert.match(item.summary, /Verdict: manual \(unknown\)/);
    assert.match(item.summary, /Collect manually:/);
  }
  assert.match(findingById(deviceDetails, "CS-08").summary, /device control policy details read failed \(.*403/);
  assert.match(findingById(deviceDetails, "CS-10").summary, /firewall policy containers read failed \(.*socket hang up/);

  const ruleGroupsOnly = await assessCrowdstrikeDeviceFirewall(createFakeClient({ listFirewallRuleGroups: forbidden("/fwmgr/queries/rule-groups/v1") }));
  assert.equal(findingById(ruleGroupsOnly, "CS-10").status, "manual");
  assert.equal(findingById(ruleGroupsOnly, "CS-11").status, "pass");
  const rulesOnly = await assessCrowdstrikeDeviceFirewall(createFakeClient({ listFirewallRules: forbidden("/fwmgr/queries/rules/v1") }));
  assert.equal(findingById(rulesOnly, "CS-10").status, "pass");
  assert.equal(findingById(rulesOnly, "CS-11").status, "manual");

  const coverage = await assessCrowdstrikeSensorCoverage(createFakeClient({
    listHostGroups: forbidden("/devices/combined/host-groups/v1"),
    countDiscoverHosts: async (filter) => {
      if (filter.includes("managed'") && !filter.includes("unmanaged")) throw new Error("gateway timeout");
      return 0;
    },
    countZtaAssessments: async (filter) => {
      if (filter.startsWith("score:<")) throw new CrowdstrikeHttpError("CrowdStrike request failed for /zero-trust-assessment/queries/assessments/v1 (500)", 500, "/zero-trust-assessment/queries/assessments/v1");
      return 25;
    },
  }));
  assert.equal(findingById(coverage, "CS-13").status, "pass");
  assert.equal(findingById(coverage, "CS-14").status, "manual");
  assert.match(findingById(coverage, "CS-14").summary, /host groups read failed/);
  assert.equal(findingById(coverage, "CS-15").status, "manual");
  assert.match(findingById(coverage, "CS-15").summary, /managed asset count read failed/);
  assert.equal(findingById(coverage, "CS-25").status, "manual");
  assert.match(findingById(coverage, "CS-25").summary, /below-threshold scores read failed/);

  const allRolesForbidden = await assessCrowdstrikeAccessGovernance(createFakeClient({ listUserRoles: forbidden("/user-management/combined/user-roles/v2") }));
  assert.equal(findingById(allRolesForbidden, "CS-16").status, "manual");
  assert.equal(findingById(allRolesForbidden, "CS-17").status, "manual");
  assert.match(findingById(allRolesForbidden, "CS-16").summary, /user role grants read failed/);

  const someRolesForbidden = await assessCrowdstrikeAccessGovernance(createFakeClient({
    listUserRoles: async (uuid) => {
      if (uuid === "u-analyst") throw new CrowdstrikeHttpError("CrowdStrike request failed for /user-management/combined/user-roles/v2 (403)", 403, "/user-management/combined/user-roles/v2");
      return passingUsers().roles[uuid];
    },
  }));
  assert.equal(findingById(someRolesForbidden, "CS-16").status, "warn");
  assert.equal(findingById(someRolesForbidden, "CS-17").status, "warn");
  assert.equal(findingById(someRolesForbidden, "CS-16").evidence.users_without_readable_roles, 1);
  assert.match(findingById(someRolesForbidden, "CS-16").summary, /lower bound/);
  assert.equal(someRolesForbidden.summary.role_lookups_failed, 1);

  const buildCatalogForbidden = await assessCrowdstrikeSensorCoverage(createFakeClient({
    listSensorUpdateBuilds: forbidden("/policy/combined/sensor-update-builds/v1"),
  }));
  const autoUpdate = findingById(buildCatalogForbidden, "CS-12");
  assert.equal(autoUpdate.status, "warn", `CS-12 must not pass on auto-update tags alone when the build catalog is unreadable: ${autoUpdate.summary}`);
  assert.match(autoUpdate.summary, /^All 1 enabled and host-assigned sensor update policies auto-update/);
  assert.match(autoUpdate.summary, /The sensor build catalog read failed \(sensor builds \(windows\): .*\(403\).*\), so build tags and pinned builds could not be verified against the catalog for that platform and this verdict cannot exceed warn\.$/);
  assert.deepEqual(autoUpdate.evidence.unreadable_secondary_reads.map((entry) => entry.dataset), ["sensor build catalog"]);
  assert.equal(autoUpdate.evidence.policies[0].supported_builds, undefined);
  assert.equal(findingById(buildCatalogForbidden, "CS-13").status, "pass");
  assert.equal(buildCatalogForbidden.errors.length, 1);

  const samplesForbidden = await assessCrowdstrikeSensorCoverage(createFakeClient({
    listDiscoverHosts: forbidden("/discover/combined/hosts/v1"),
  }));
  const unmanaged = findingById(samplesForbidden, "CS-15");
  assert.equal(unmanaged.status, "warn", `CS-15 must not pass when the unmanaged sample read is forbidden: ${unmanaged.summary}`);
  assert.match(unmanaged.summary, /^Falcon Discover reports no unmanaged assets against 3 managed assets \(server-side totals\)\. The Falcon Discover unmanaged asset samples read failed \(discover unmanaged samples: .*\(403\).*\), so the unmanaged asset sample list is unavailable and this verdict cannot exceed warn\.$/);
  assert.equal(findingById(samplesForbidden, "CS-13").status, "pass");
  assert.equal(findingById(samplesForbidden, "CS-25").status, "pass");

  const roleCatalogForbidden = await assessCrowdstrikeAccessGovernance(createFakeClient({
    listRoles: forbidden("/user-management/queries/roles/v1"),
  }));
  for (const id of ["CS-16", "CS-17"]) {
    const item = findingById(roleCatalogForbidden, id);
    assert.equal(item.status, "warn", `${id} must not pass when the role catalog is unreadable: ${item.summary}`);
    assert.match(item.summary, /The role catalog read failed \(role catalog: .*\(403\).*\), so the role inventory could not be checked for completeness against the catalog and this verdict cannot exceed warn\.$/);
    assert.deepEqual(item.evidence.unreadable_secondary_reads.map((entry) => entry.dataset), ["role catalog"]);
  }
  assert.equal(findingById(roleCatalogForbidden, "CS-18").status, "pass");
  assert.equal(roleCatalogForbidden.summary.roles_in_catalog, "unavailable");
  assert.equal(roleCatalogForbidden.summary.reported_total_roles, "unavailable");
  assert.equal(roleCatalogForbidden.summary.role_catalog_truncated, "unavailable");

  const ztaListForbidden = await assessCrowdstrikeSensorCoverage(createFakeClient({
    listZtaAssessments: forbidden("/zero-trust-assessment/queries/assessments/v1"),
  }));
  assert.equal(findingById(ztaListForbidden, "CS-25").status, "manual");
  assert.match(findingById(ztaListForbidden, "CS-25").summary, /Zero Trust Assessment below-threshold scores read failed \(zero trust assessments below threshold: .*\(403\)/);
  assert.equal(findingById(ztaListForbidden, "CS-15").status, "pass");
});

test("verdict safety rule 2: empty inventories pass only where emptiness is compliant and say so", async () => {
  const statuses = statusMap(await runAllCrowdstrikeAssessments(createEmptyClient()));
  const expected = {
    "CS-01": "fail", "CS-02": "fail", "CS-03": "fail", "CS-04": "fail", "CS-05": "fail",
    "CS-06": "fail", "CS-07": "manual", "CS-08": "fail", "CS-09": "fail", "CS-10": "fail",
    "CS-11": "fail", "CS-12": "fail", "CS-13": "fail", "CS-14": "fail", "CS-15": "manual",
    "CS-16": "manual", "CS-17": "manual", "CS-18": "manual", "CS-19": "pass", "CS-20": "pass",
    "CS-21": "pass", "CS-22": "pass", "CS-23": "pass", "CS-24": "fail", "CS-25": "manual",
  };
  assert.deepEqual(statuses, expected);

  const assessments = await runAllCrowdstrikeAssessments(createEmptyClient());
  const findings = assessments.flatMap((assessment) => assessment.findings);
  const byId = (id) => findings.find((item) => item.id === id);
  assert.match(byId("CS-01").summary, /returned zero policies; with no prevention policy defined this control fails/);
  assert.match(byId("CS-13").summary, /emptiness fails this control/);
  assert.match(byId("CS-16").summary, /returned zero users/);
  assert.match(byId("CS-18").summary, /returned zero clients/);
  assert.match(byId("CS-19").summary, /emptiness is compliant for this control/);
  assert.match(byId("CS-22").summary, /alerts endpoint was readable .* last 30 days \(window stated\)/);
  assert.match(byId("CS-23").summary, /Hosts API was readable .* emptiness is compliant/);
  assert.match(byId("CS-24").summary, /emptiness fails this control/);
  assert.match(byId("CS-15").summary, /zero managed and zero unmanaged assets/);
  assert.match(byId("CS-25").summary, /zero scored hosts/);
});

test("verdict safety rule 3: unlicensed Discover, Identity Protection, and ZTA render as manual not applicable", async () => {
  const coverage = await assessCrowdstrikeSensorCoverage(createFakeClient({
    countDiscoverHosts: forbidden("/discover/queries/hosts/v1"),
    countZtaAssessments: async () => { throw new CrowdstrikeHttpError("CrowdStrike request failed for /zero-trust-assessment/queries/assessments/v1 (404)", 404, "/zero-trust-assessment/queries/assessments/v1"); },
  }));
  const governance = await assessCrowdstrikeAccessGovernance(createFakeClient({
    listIdentityProtectionRules: forbidden("/identity-protection/queries/policy-rules/v1"),
  }));
  for (const item of [findingById(coverage, "CS-15"), findingById(coverage, "CS-25"), findingById(governance, "CS-24")]) {
    assert.equal(item.status, "manual", `${item.id} should be manual`);
    assert.match(item.summary, /unlicensed or not applicable/);
    assert.match(item.summary, /Collect manually:/);
    assert.equal(item.evidence.not_applicable, true);
  }
});

test("verdict safety rule 4: undated records are bucketed separately and cap the verdict at warn", async () => {
  const coverage = await assessCrowdstrikeSensorCoverage(createFakeClient({
    listHosts: async (_limit, filter) => (filter ? [] : [host(), host({ device_id: "aid-2", hostname: "ws-02", last_seen: null }), host({ device_id: "aid-3", hostname: "ws-03", last_seen: undefined })]),
  }));
  const deployment = findingById(coverage, "CS-13");
  assert.equal(deployment.status, "warn");
  assert.equal(deployment.evidence.hosts_without_last_seen, 2);
  assert.equal(deployment.evidence.active_hosts, 1);
  assert.equal(deployment.evidence.stale_hosts, 0);
  assert.deepEqual(deployment.evidence.undated_items, { label: "hosts", field: "last_seen", count: 2 });
  assert.match(deployment.summary, /2 hosts have no last_seen timestamp/);

  const governance = await assessCrowdstrikeAccessGovernance(createFakeClient({
    getUsers: async () => [
      { uuid: "u-admin", uid: "alice@example.com", status: "active" },
      { uuid: "u-analyst", uid: "bob@example.com", status: "active", last_login_at: isoDaysAgo(1) },
    ],
  }));
  const leastPrivilege = findingById(governance, "CS-17");
  assert.equal(leastPrivilege.status, "warn");
  assert.deepEqual(leastPrivilege.evidence.admins_without_login_date, ["alice@example.com"]);
  assert.equal(leastPrivilege.evidence.stale_privileged.length, 0);

  const response = await assessCrowdstrikeResponseReadiness(createFakeClient({
    listAlerts: async () => [
      { composite_id: "a-1", severity: 90, severity_name: "Critical", status: "closed", seconds_to_resolved: 600 },
      { composite_id: "a-2", severity: 70, severity_name: "High", status: "closed", created_timestamp: isoHoursAgo(30), updated_timestamp: isoHoursAgo(26) },
    ],
    listHosts: async () => [host({ hostname: "contained-01", status: "contained", modified_timestamp: null })],
  }));
  const sla = findingById(response, "CS-22");
  assert.equal(sla.status, "warn");
  assert.equal(sla.evidence.alerts_with_created_timestamp, 1);
  assert.equal(sla.evidence.undated_items.count, 1);
  const containment = findingById(response, "CS-23");
  assert.equal(containment.status, "warn");
  assert.equal(containment.evidence.undated_items.count, 1);
});

test("verdict safety rule 5: partial inventories never pass and report seen versus total counts", async () => {
  const assessments = await runAllCrowdstrikeAssessments(createPartialClient());
  const findings = assessments.flatMap((assessment) => assessment.findings);
  assert.equal(findings.length, 25);
  for (const item of findings) {
    assert.notEqual(item.status, "pass", `${item.id} passed on a partial inventory: ${item.summary}`);
  }
  const deployment = findings.find((item) => item.id === "CS-13");
  assert.equal(deployment.status, "warn");
  assert.deepEqual(deployment.evidence.partial_inventory, [{ dataset: "hosts", seen: 3, total: 43 }]);
  assert.match(deployment.summary, /Partial inventory: only 3 of 43 hosts were read/);
  const admins = findings.find((item) => item.id === "CS-16");
  assert.equal(admins.status, "warn");
  assert.equal(admins.evidence.users_without_readable_roles, 1);
  assert.deepEqual(admins.evidence.partial_inventory, [
    { dataset: "users", seen: 2, total: 42 },
    { dataset: "roles in the role catalog", seen: 2, total: 42 },
  ]);
  const alerts = findings.find((item) => item.id === "CS-22");
  assert.deepEqual(alerts.evidence.partial_inventory, [{ dataset: "critical/high alerts", seen: 2, total: 42 }]);
  const apiClients = findings.find((item) => item.id === "CS-18");
  assert.equal(apiClients.evidence.reported_total_api_clients, 41);
  const sensorCoverage = assessments.find((assessment) => assessment.category === "sensor_coverage");
  assert.equal(sensorCoverage.summary.hosts_truncated, true);
  assert.equal(sensorCoverage.summary.reported_total_hosts, 43);
});

test("verdict safety rule 6: disabled, unassigned, or incomplete enabling flags never support pass", async () => {
  const disabledOnly = await assessCrowdstrikePreventionPolicies(createFakeClient({
    listPreventionPolicies: async () => [preventionPolicy({ enabled: false })],
  }));
  assert.equal(findingById(disabledOnly, "CS-01").status, "fail");
  assert.match(findingById(disabledOnly, "CS-01").summary, /None of the 1 prevention policies is both enabled and assigned/);

  const unassigned = await assessCrowdstrikePreventionPolicies(createFakeClient({
    listPreventionPolicies: async () => [preventionPolicy({ groups: [] })],
  }));
  for (const id of ["CS-01", "CS-02", "CS-03", "CS-04", "CS-05"]) {
    assert.equal(findingById(unassigned, id).status, "fail", `${id} should fail without host group assignment`);
  }
  assert.match(findingById(unassigned, "CS-04").summary, /1 enabled but unassigned/);
  assert.deepEqual(findingById(unassigned, "CS-04").evidence.enabled_but_unassigned_policies, ["Windows Hardened (Windows)"]);

  const platformDefault = await assessCrowdstrikePreventionPolicies(createFakeClient({
    listPreventionPolicies: async () => [
      preventionPolicy({ name: "platform_default", groups: [] }),
      preventionPolicy({ id: "prev-mac", name: "platform_default", platform: "Mac", groups: [], includeExploit: false, includeScript: false }),
      preventionPolicy({ id: "prev-linux", name: "platform_default", platform: "Linux", groups: [], includeExploit: false, includeScript: false }),
    ],
  }));
  assert.equal(findingById(platformDefault, "CS-04").status, "pass");

  const mixed = await assessCrowdstrikePreventionPolicies(createFakeClient({
    listPreventionPolicies: async () => [
      preventionPolicy({ id: "strong-unassigned", name: "Strong but unassigned", groups: [] }),
      preventionPolicy({ id: "weak-assigned", name: "Weak assigned", detection: "CAUTIOUS", prevention: "CAUTIOUS" }),
    ],
  }));
  assert.equal(findingById(mixed, "CS-01").status, "fail");
  assert.equal(findingById(mixed, "CS-01").evidence.policies.length, 1);

  const incompleteSlider = await assessCrowdstrikePreventionPolicies(createFakeClient({
    listPreventionPolicies: async () => [preventionPolicy({
      sliders: [
        { id: "CloudAntiMalware", type: "mlslider", value: { detection: "AGGRESSIVE" } },
        { id: "OnSensorMLSlider", type: "mlslider", value: { detection: "AGGRESSIVE", prevention: "AGGRESSIVE" } },
      ],
    })],
  }));
  assert.equal(findingById(incompleteSlider, "CS-01").status, "warn");
  assert.equal(findingById(incompleteSlider, "CS-01").evidence.policies[0].sliders_complete, false);

  const missingSlider = await assessCrowdstrikePreventionPolicies(createFakeClient({
    listPreventionPolicies: async () => [preventionPolicy({
      sliders: [{ id: "OnSensorMLSlider", type: "mlslider", value: { detection: "EXTRA_AGGRESSIVE", prevention: "EXTRA_AGGRESSIVE" } }],
    })],
  }));
  assert.equal(findingById(missingSlider, "CS-01").status, "warn");

  const unknownGroups = await assessCrowdstrikeDeviceFirewall(createFakeClient({
    listFirewallRuleGroups: async () => [],
  }));
  assert.equal(findingById(unknownGroups, "CS-10").status, "warn");
  assert.equal(findingById(unknownGroups, "CS-10").evidence.policies[0].unknown_rule_groups, 1);
  assert.equal(findingById(unknownGroups, "CS-10").evidence.policies[0].active_rule_groups, 0);

  const unassignedResponse = await assessCrowdstrikeResponseReadiness(createFakeClient({
    listResponsePolicies: async () => [responsePolicy({ groups: [] })],
  }));
  assert.equal(findingById(unassignedResponse, "CS-06").status, "fail");
  const unassignedSensor = await assessCrowdstrikeSensorCoverage(createFakeClient({
    listSensorUpdatePolicies: async () => [sensorUpdatePolicy({ groups: [] })],
  }));
  assert.equal(findingById(unassignedSensor, "CS-12").status, "fail");
  const unassignedDevice = await assessCrowdstrikeDeviceFirewall(createFakeClient({
    listDeviceControlPolicies: async () => [{ id: "dc-1", name: "USB Lockdown", platform_name: "Windows", enabled: true, groups: [] }],
  }));
  assert.equal(findingById(unassignedDevice, "CS-08").status, "fail");
  assert.equal(findingById(unassignedDevice, "CS-09").status, "fail");
});

test("verdict safety rule 7: truncated pages downgrade the assessments that depend on them", async () => {
  const result = await assessCrowdstrikeAccessGovernance(createFakeClient({
    listIoaExclusions: async () => truncatedPage([{ id: "ioa-1", name: "Backup agent", ifn_regex: "C:\\\\Program Files\\\\Backup\\\\agent\\.exe", applied_globally: false, groups: [{ id: "hg-1" }] }], 600),
    listApiClients: async () => truncatedPage([{ id: "api-1", name: "grclanker audit", scopes: ["hosts:read"] }], 501),
  }));
  const ioa = findingById(result, "CS-19");
  assert.equal(ioa.status, "warn");
  assert.match(ioa.summary, /only 1 of 600 IOA exclusions were read/);
  assert.equal(findingById(result, "CS-18").status, "warn");
  assert.equal(findingById(result, "CS-20").status, "pass");

  const prevention = await assessCrowdstrikePreventionPolicies(createFakeClient({
    listPreventionPolicies: async () => ({ items: passingPreventionPolicies(), total: undefined, truncated: true }),
  }));
  for (const item of prevention.findings) {
    assert.equal(item.status, "warn", `${item.id} should be capped at warn on a truncated policy page`);
    assert.match(item.summary, /3 of an unknown total of prevention policies/);
  }
  assert.equal(prevention.summary.policies_truncated, true);
});

test("verdict safety rule 8: re-running an export pairs each bundle directory with its own zip", async () => {
  const base = createTempBase("grclanker-cs-rerun-");
  const first = await exportCrowdstrikeAuditBundle(createFakeClient(), sampleConfig(), base);
  const firstBytes = readFileSync(first.zipPath);
  const second = await exportCrowdstrikeAuditBundle(createFakeClient(), sampleConfig(), base);
  const third = await exportCrowdstrikeAuditBundle(createFakeClient(), sampleConfig(), base);

  assert.match(first.zipPath, /us-1-audit-bundle\.zip$/);
  assert.match(second.zipPath, /us-1-audit-bundle-2\.zip$/);
  assert.match(third.zipPath, /us-1-audit-bundle-3\.zip$/);
  assert.equal(second.zipPath, `${second.outputDir}.zip`);
  assert.equal(third.zipPath, `${third.outputDir}.zip`);
  assert.ok(existsSync(first.zipPath) && existsSync(second.zipPath) && existsSync(third.zipPath));
  assert.ok(firstBytes.length > 0);
  assert.deepEqual(readFileSync(first.zipPath), firstBytes);
  const zips = readdirSync(base).filter((entry) => entry.endsWith(".zip")).sort();
  assert.deepEqual(zips, ["us-1-audit-bundle-2.zip", "us-1-audit-bundle-3.zip", "us-1-audit-bundle.zip"]);
});

test("review fix 1: API client write scopes are read from the action and group fields, never from the id alone", async () => {
  const writeClients = await assessCrowdstrikeAccessGovernance(createFakeClient({
    listApiClients: async () => [
      { id: "api-hosts", name: "host-writer", scopes: [apiScope("hosts", "write")] },
      { id: "api-prev", name: "policy-writer", scopes: [apiScope("prevention-policies", "write")] },
      { id: "api-users", name: "user-writer", scopes: [apiScope("user-management", "write")] },
    ],
  }));
  const finding = findingById(writeClients, "CS-18");
  assert.notEqual(finding.status, "pass");
  assert.equal(finding.status, "warn");
  assert.equal(finding.evidence.write_clients.length, 3);
  assert.deepEqual(
    finding.evidence.write_clients.map((client) => client.sensitive_write_scopes).flat().sort(),
    ["Hosts:write", "Prevention Policies:write", "User Management:write"],
  );
  assert.match(finding.summary, /3 of 3 API clients hold write-action scopes/);

  const fourWriters = await assessCrowdstrikeAccessGovernance(createFakeClient({
    listApiClients: async () => Array.from({ length: 4 }, (_, index) => ({ id: `api-${index}`, name: `writer-${index}`, scopes: [apiScope("hosts", "write")] })),
  }));
  assert.equal(findingById(fourWriters, "CS-18").status, "fail");

  const readOnly = await assessCrowdstrikeAccessGovernance(createFakeClient({
    listApiClients: async () => [
      { id: "api-1", name: "reader", scopes: [apiScope("hosts", "read"), apiScope("prevention-policies", "read"), { id: "hosts", group: "Hosts", action: "READ" }] },
    ],
  }));
  assert.equal(findingById(readOnly, "CS-18").status, "pass");
  assert.match(findingById(readOnly, "CS-18").summary, /action and group fields was read for every client/);
  assert.match(findingById(readOnly, "CS-18").summary, /documents no last-used field for API clients and none was returned, so unused-client staleness was not evaluated from API data/);
  assert.equal(findingById(readOnly, "CS-18").evidence.last_used_evaluated_from_api, false);

  const upperCaseAction = await assessCrowdstrikeAccessGovernance(createFakeClient({
    listApiClients: async () => [{ id: "api-1", name: "writer", scopes: [{ id: "user-management", group: "User Management", action: "WRITE" }] }],
  }));
  assert.equal(findingById(upperCaseAction, "CS-18").status, "warn");
  assert.equal(findingById(upperCaseAction, "CS-18").evidence.write_clients.length, 1);

  const legacyStrings = await assessCrowdstrikeAccessGovernance(createFakeClient({
    listApiClients: async () => [{ id: "api-1", name: "legacy", scopes: ["hosts:write", "prevention-policies:read"] }],
  }));
  assert.equal(findingById(legacyStrings, "CS-18").status, "warn");
  assert.deepEqual(findingById(legacyStrings, "CS-18").evidence.write_clients[0].sensitive_write_scopes, ["hosts:write"]);

  const missingAction = await assessCrowdstrikeAccessGovernance(createFakeClient({
    listApiClients: async () => [{ id: "api-1", name: "opaque", scopes: [{ id: "hosts", group: "Hosts" }] }],
  }));
  assert.equal(findingById(missingAction, "CS-18").status, "warn");
  assert.equal(findingById(missingAction, "CS-18").evidence.clients_without_scope_action_data, 1);
  assert.match(findingById(missingAction, "CS-18").summary, /without an action field, so their read or write level is unknown/);

  const withLastUsed = await assessCrowdstrikeAccessGovernance(createFakeClient({
    listApiClients: async () => [
      { id: "api-1", name: "recent", scopes: [apiScope("hosts", "read")], last_used_at: new Date().toISOString() },
      { id: "api-2", name: "stale-writer", scopes: [apiScope("hosts", "write")], last_used_at: "2020-01-01T00:00:00Z" },
    ],
  }));
  assert.match(findingById(withLastUsed, "CS-18").summary, /Last-used timestamps were returned for 2 of 2 clients; 1 write clients were unused/);
  assert.equal(findingById(withLastUsed, "CS-18").evidence.last_used_evaluated_from_api, true);
  assert.deepEqual(findingById(withLastUsed, "CS-18").evidence.stale_write_clients, ["stale-writer"]);
});

test("review fix 2: missing Discover and ZTA pagination totals yield manual or warn, never pass", async () => {
  const unmanagedMissing = await assessCrowdstrikeSensorCoverage(createFakeClient({
    countDiscoverHosts: async (filter) => (filter.includes("unmanaged") ? undefined : 3),
  }));
  const cs15 = findingById(unmanagedMissing, "CS-15");
  assert.equal(cs15.status, "manual");
  assert.match(cs15.summary, /did not report a server-side total \(meta\.pagination\.total\) for unmanaged assets/);
  assert.match(cs15.summary, /Collect manually:/);
  assert.deepEqual(cs15.evidence.totals_missing, ["unmanaged"]);
  assert.equal(cs15.evidence.managed_assets, 3);

  const managedMissing = await assessCrowdstrikeSensorCoverage(createFakeClient({
    countDiscoverHosts: async (filter) => (filter.includes("unmanaged") ? 5 : undefined),
    listDiscoverHosts: async () => [{ hostname: "printer-01", platform_name: "Other" }],
  }));
  assert.equal(findingById(managedMissing, "CS-15").status, "manual");
  assert.match(findingById(managedMissing, "CS-15").summary, /for managed assets/);
  assert.match(findingById(managedMissing, "CS-15").summary, /1 unmanaged assets were sampled as a lower bound only/);

  const bothMissing = await assessCrowdstrikeSensorCoverage(createFakeClient({ countDiscoverHosts: async () => undefined }));
  assert.equal(findingById(bothMissing, "CS-15").status, "manual");
  assert.deepEqual(findingById(bothMissing, "CS-15").evidence.totals_missing, ["unmanaged", "managed"]);

  const scoredMissing = await assessCrowdstrikeSensorCoverage(createFakeClient({
    countZtaAssessments: async (filter) => (filter.startsWith("score:<") ? 0 : undefined),
  }));
  const cs25 = findingById(scoredMissing, "CS-25");
  assert.equal(cs25.status, "manual");
  assert.match(cs25.summary, /did not report a server-side total \(meta\.pagination\.total\) for scored hosts/);
  assert.deepEqual(cs25.evidence.totals_missing, ["scored"]);

  const belowMissing = await assessCrowdstrikeSensorCoverage(createFakeClient({
    countZtaAssessments: async (filter) => (filter.startsWith("score:<") ? undefined : 100),
    listZtaAssessments: async () => [],
  }));
  assert.equal(findingById(belowMissing, "CS-25").status, "warn");
  assert.match(findingById(belowMissing, "CS-25").summary, /At least 0 of 100 scored hosts/);
  assert.match(findingById(belowMissing, "CS-25").summary, /sampled count is a lower bound and this verdict cannot exceed warn/);
  assert.equal(findingById(belowMissing, "CS-25").evidence.below_threshold_total_reported, false);

  const belowMissingWithSamples = await assessCrowdstrikeSensorCoverage(createFakeClient({
    countZtaAssessments: async (filter) => (filter.startsWith("score:<") ? undefined : 10),
    listZtaAssessments: async () => [{ aid: "aid-1", score: 20 }, { aid: "aid-2", score: 30 }],
  }));
  assert.equal(findingById(belowMissingWithSamples, "CS-25").status, "fail");
  assert.equal(findingById(belowMissingWithSamples, "CS-25").evidence.hosts_below_threshold, 2);
});

test("review fix 3: role and Identity Protection rule queries compare returned ids against meta.pagination.total", async () => {
  const entityCalls = [];
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.pathname === "/oauth2/token") {
      return jsonResponse({ access_token: "token-1", expires_in: 1799 });
    }
    if (url.pathname === "/user-management/queries/roles/v1") {
      assert.equal(url.searchParams.get("limit"), null, "roles query documents no pagination parameters");
      return jsonResponse({ resources: ["falcon_administrator", "falcon_analyst"], meta: { pagination: { limit: 2, offset: 0, total: 5 } } });
    }
    if (url.pathname === "/user-management/entities/roles/v1") {
      entityCalls.push(url.searchParams.getAll("ids"));
      return jsonResponse({ resources: url.searchParams.getAll("ids").map((id) => ({ id, display_name: id })) });
    }
    if (url.pathname === "/identity-protection/queries/policy-rules/v1") {
      return jsonResponse({ resources: ["idp-1"], meta: { pagination: { limit: 1, offset: 0, total: 3 } } });
    }
    if (url.pathname === "/identity-protection/entities/policy-rules/v1") {
      return jsonResponse({ resources: url.searchParams.getAll("ids").map((id) => ({ id, name: `Rule ${id}`, enabled: true })) });
    }
    if (url.pathname === "/zero-trust-assessment/queries/assessments/v1") {
      return jsonResponse({ resources: [], meta: { pagination: { limit: 1, offset: 0 } } });
    }
    throw new Error(`unexpected path ${url.pathname}`);
  };
  const client = new CrowdstrikeApiClient(sampleConfig(), { fetchImpl });

  const roles = await client.listRoles();
  assert.equal(roles.items.length, 2);
  assert.equal(roles.total, 5);
  assert.equal(roles.truncated, true);
  assert.deepEqual(entityCalls, [["falcon_administrator", "falcon_analyst"]]);

  const rules = await client.listIdentityProtectionRules();
  assert.equal(rules.items.length, 1);
  assert.equal(rules.total, 3);
  assert.equal(rules.truncated, true);

  assert.equal(await client.countZtaAssessments("score:>=0"), undefined, "a missing total must surface as undefined, not zero");

  const truncatedCatalog = await assessCrowdstrikeAccessGovernance(createFakeClient({
    listRoles: async () => truncatedPage([{ id: "falcon_administrator", display_name: "Falcon Administrator" }], 5),
  }));
  for (const id of ["CS-16", "CS-17"]) {
    const item = findingById(truncatedCatalog, id);
    assert.equal(item.status, "warn", `${id} should warn on a truncated role catalog: ${item.summary}`);
    assert.match(item.summary, /only 1 of 5 roles in the role catalog were read/);
    assert.ok(item.evidence.partial_inventory.some((partial) => partial.dataset === "roles in the role catalog"));
  }
  assert.equal(truncatedCatalog.summary.role_catalog_truncated, true);
  assert.equal(truncatedCatalog.summary.reported_total_roles, 5);

  const truncatedGrants = await assessCrowdstrikeAccessGovernance(createFakeClient({
    listUserRoles: async (uuid) => (uuid === "u-analyst" ? truncatedPage(passingUsers().roles[uuid], 12) : passingUsers().roles[uuid]),
  }));
  for (const id of ["CS-16", "CS-17"]) {
    const item = findingById(truncatedGrants, id);
    assert.equal(item.status, "warn", `${id} should warn on truncated role grant pages: ${item.summary}`);
    assert.match(item.summary, /role grant pages were truncated for 1 of \d+ users/);
    assert.equal(item.evidence.users_with_truncated_role_pages, 1);
  }
  assert.equal(truncatedGrants.summary.role_pages_truncated, 1);

  const truncatedRules = await assessCrowdstrikeAccessGovernance(createFakeClient({
    listIdentityProtectionRules: async () => truncatedPage([{ id: "idp-1", name: "Block stale accounts", enabled: true, simulationMode: false, action: "BLOCK" }], 3),
  }));
  assert.equal(findingById(truncatedRules, "CS-24").status, "warn");
  assert.match(findingById(truncatedRules, "CS-24").summary, /only 1 of 3 Identity Protection policy rules were read/);
  assert.equal(truncatedRules.summary.identity_protection_rules_truncated, true);
});

test("review fix 4: supplemental ML sliders are limited to identifiers verified in the Terraform provider", async () => {
  const slider = (id, detection = "MODERATE", prevention = "MODERATE") => ({ id, type: "mlslider", value: { detection, prevention } });
  const result = await assessCrowdstrikePreventionPolicies(createFakeClient({
    listPreventionPolicies: async () => [
      preventionPolicy({
        sliders: [
          slider("CloudAntiMalware", "AGGRESSIVE", "AGGRESSIVE"),
          slider("OnSensorMLSlider", "AGGRESSIVE", "AGGRESSIVE"),
          slider("AdwarePUP"),
          slider("CloudAntiMalwareForMicrosoftOfficeFiles"),
          slider("CloudMLSliderForPupAdwareCloudEndUserScans"),
          slider("OnSensorMLAdwarePUPSlider"),
          slider("OnSensorMLSliderForSensorEndUserScans"),
          slider("OnSensorMLSliderForCloudEndUserScans"),
          slider("CloudAntiMalwareUserInitiated"),
        ],
      }),
      preventionPolicy({ id: "prev-mac", name: "Mac Hardened", platform: "Mac" }),
      preventionPolicy({ id: "prev-linux", name: "Linux Hardened", platform: "Linux" }),
    ],
  }));
  const cs01 = findingById(result, "CS-01");
  assert.equal(cs01.status, "pass");
  const reported = Object.keys(cs01.evidence.policies[0].sliders).sort();
  assert.deepEqual(reported, [
    "AdwarePUP",
    "CloudAntiMalware",
    "CloudAntiMalwareForMicrosoftOfficeFiles",
    "CloudMLSliderForPupAdwareCloudEndUserScans",
    "OnSensorMLAdwarePUPSlider",
    "OnSensorMLSlider",
    "OnSensorMLSliderForCloudEndUserScans",
    "OnSensorMLSliderForSensorEndUserScans",
  ]);
  assert.ok(!reported.includes("CloudAntiMalwareUserInitiated"));
});

test("false-pass self-check (a): every endpoint forbidden yields 25 manual findings and zero passes", async () => {
  const assessments = await runAllCrowdstrikeAssessments(createForbiddenClient());
  const findings = assessments.flatMap((assessment) => assessment.findings);
  assert.deepEqual(findings.map((item) => item.id).sort(), ALL_CONTROL_IDS);
  for (const item of findings) {
    assert.equal(item.status, "manual", `${item.id} should be manual when its endpoints are forbidden: ${item.summary}`);
    assert.match(item.summary, /Collect manually:/);
  }
  assert.ok(assessments.every((assessment) => assessment.errors.length > 0));
});

test("false-pass self-check (b): empty inventories pass only for exclusion hygiene, alert response, and containment", async () => {
  const statuses = statusMap(await runAllCrowdstrikeAssessments(createEmptyClient()));
  const passing = Object.entries(statuses).filter(([, status]) => status === "pass").map(([id]) => id).sort();
  assert.deepEqual(passing, ["CS-19", "CS-20", "CS-21", "CS-22", "CS-23"]);
});

test("false-pass self-check (c): partial inventories never produce a pass", async () => {
  const statuses = statusMap(await runAllCrowdstrikeAssessments(createPartialClient()));
  assert.equal(Object.keys(statuses).length, 25);
  assert.deepEqual(Object.values(statuses).filter((status) => status === "pass"), []);
});

test("the five assessments cover every spec control exactly once with framework mappings", async () => {
  const assessments = await runAllCrowdstrikeAssessments(createFakeClient());
  const findings = assessments.flatMap((assessment) => assessment.findings);
  assert.deepEqual(findings.map((item) => item.id).sort(), ALL_CONTROL_IDS);
  assert.equal(CROWDSTRIKE_CONTROLS.length, 25);
  for (const item of findings) {
    for (const framework of CROWDSTRIKE_FRAMEWORKS) {
      assert.ok(
        item.mappings.some((mapping) => mapping.startsWith(`${framework.label} `)),
        `${item.id} is missing a ${framework.label} mapping`,
      );
    }
    assert.ok(["critical", "high", "medium", "low", "info"].includes(item.severity));
    assert.ok(["pass", "warn", "fail", "manual"].includes(item.status));
    assert.ok(item.summary.length > 0);
  }
});

test("exportCrowdstrikeAuditBundle writes the audit layout, framework reports, and zip archive", async () => {
  const base = createTempBase("grclanker-cs-bundle-");
  const result = await exportCrowdstrikeAuditBundle(createFakeClient(), sampleConfig(), base);

  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.match(result.zipPath, /us-1-audit-bundle\.zip$/);
  assert.equal(result.findingCount, 25);
  assert.equal(result.errorCount, 0);
  assert.ok(result.fileCount >= 30);

  const expectedFiles = [
    "QUICK_REFERENCE.md",
    "metadata.json",
    join("analysis", "findings.json"),
    join("analysis", "access_check.json"),
    join("analysis", "prevention_policies.json"),
    join("analysis", "response_readiness.json"),
    join("analysis", "device_firewall.json"),
    join("analysis", "sensor_coverage.json"),
    join("analysis", "access_governance.json"),
    join("core_data", "prevention_policies", "prevention_policies.json"),
    join("core_data", "response_readiness", "alerts.json"),
    join("core_data", "device_firewall", "firewall_rules.json"),
    join("core_data", "sensor_coverage", "hosts.json"),
    join("core_data", "access_governance", "api_clients.json"),
    join("compliance", "executive_summary.md"),
    join("compliance", "unified_compliance_matrix.md"),
    ...CROWDSTRIKE_FRAMEWORKS.map((framework) => join("compliance", "frameworks", `${framework.key}.md`)),
  ];
  for (const relativePath of expectedFiles) {
    assert.ok(existsSync(join(result.outputDir, relativePath)), `missing ${relativePath}`);
  }
  assert.ok(!existsSync(join(result.outputDir, "_errors.log")));

  const metadata = JSON.parse(readFileSync(join(result.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.base_url, "https://api.crowdstrike.com");
  assert.equal(metadata.controls_evaluated, 25);
  assert.ok(!JSON.stringify(metadata).includes("client-secret-value"));

  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  assert.equal(findings.length, 25);
  const fedramp = readFileSync(join(result.outputDir, "compliance", "frameworks", "fedramp.md"), "utf8");
  assert.match(fedramp, /FedRAMP \(NIST SP 800-53\) Compliance Report/);
  assert.match(fedramp, /CS-04 \| Prevention Policy - Sensor Tamper Protection \| pass/);
  const matrix = readFileSync(join(result.outputDir, "compliance", "unified_compliance_matrix.md"), "utf8");
  assert.equal((matrix.match(/^\| CS-/gm) ?? []).length, 25);
  assert.ok(readdirSync(join(result.outputDir, "compliance", "frameworks")).length === CROWDSTRIKE_FRAMEWORKS.length);
});

test("exportCrowdstrikeAuditBundle records partial collection failures in _errors.log", async () => {
  const base = createTempBase("grclanker-cs-bundle-errors-");
  const client = createFakeClient({
    listApiClients: async () => { throw new CrowdstrikeHttpError("CrowdStrike request failed for /api-clients/queries/api-clients/v1 (403): access denied", 403, "/api-clients/queries/api-clients/v1"); },
    listFirewallRules: async () => { throw new Error("socket hang up"); },
  });
  const result = await exportCrowdstrikeAuditBundle(client, sampleConfig({ memberCid: "child-cid" }), base);

  assert.equal(result.findingCount, 25);
  assert.equal(result.errorCount, 2);
  assert.match(result.zipPath, /us-1-child-cid-audit-bundle\.zip$/);
  const errorLog = readFileSync(join(result.outputDir, "_errors.log"), "utf8");
  assert.match(errorLog, /\[access_governance\] api clients: .*403/);
  assert.match(errorLog, /\[device_firewall\] firewall rules: socket hang up/);
  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  assert.equal(findings.find((item) => item.id === "CS-18").status, "manual");
  const summary = readFileSync(join(result.outputDir, "compliance", "executive_summary.md"), "utf8");
  assert.match(summary, /## Collection Warnings/);

  const second = await exportCrowdstrikeAuditBundle(client, sampleConfig({ memberCid: "child-cid" }), base);
  assert.notEqual(second.outputDir, result.outputDir);
  assert.match(second.outputDir, /-audit-bundle-2$/);
});

// Verdict safety rules 9 and 10: export credential hygiene and pagination truncation.

const FAKE_CROWDSTRIKE_SECRETS = {
  alertCmdlinePassword: "Hunter2-Backup-Pass-4471",
  alertParentEncodedCommand: "RW5jb2RlZFBhcmVudFNlY3JldC05OTEy",
  alertGrandparentToken: "grandparent-api-token-0f9e8d",
  alertDescriptionToken: "ghp_alertDescriptionToken0000000000001",
  alertIocValue: "ioc-secret-blob-7f3a9c",
  alertBearer: "eyJhbGciOiJIUzI1NiJ9.fake-alert-bearer.c2VjcmV0",
  rtrRunscriptSecret: "RtrInlineSecret-2026-Q3",
  rtrPutCommand: "put creds-export-9a8b7c.txt",
  rtrStdoutSecret: "rtr-stdout-secret-5561",
};

function secretBearingCrowdstrikeClient() {
  const fake = FAKE_CROWDSTRIKE_SECRETS;
  return createFakeClient({
    listAlerts: async () => [
      {
        id: "a-1",
        composite_id: "cid-1:ind:a-1",
        aggregate_id: "agg-1",
        cid: "cid-1",
        agent_id: "aid-1",
        product: "epp",
        type: "ldt",
        name: "SuspiciousCredentialUse",
        display_name: "Suspicious credential use",
        tactic: "Credential Access",
        technique: "Credentials In Files",
        pattern_id: 10101,
        severity: 90,
        severity_name: "Critical",
        confidence: 80,
        status: "closed",
        assigned_to_name: "Alice Analyst",
        resolution: "true_positive",
        created_timestamp: isoHoursAgo(30),
        updated_timestamp: isoHoursAgo(26),
        seconds_to_resolved: 7200,
        tags: ["reviewed"],
        cmdline: `net use \\\\fs01\\share /user:corp\\svc-backup ${fake.alertCmdlinePassword}`,
        filepath: "\\Device\\HarddiskVolume3\\Windows\\System32\\net.exe",
        filename: "net.exe",
        parent_details: { filename: "powershell.exe", cmdline: `powershell -EncodedCommand ${fake.alertParentEncodedCommand}` },
        grandparent_details: { filename: "cmd.exe", cmdline: `cmd.exe /c set API_TOKEN=${fake.alertGrandparentToken}` },
        description: `A process used the token ${fake.alertDescriptionToken} to access an internal API.`,
        ioc_value: fake.alertIocValue,
        user_name: "svc-backup",
        device: { device_id: "aid-1", hostname: "ws-01", platform_name: "Windows", external_ip: "203.0.113.10", local_ip: "10.0.0.5", mac_address: "00-11-22-33-44-55" },
      },
      {
        composite_id: "cid-1:ind:a-2",
        severity: 70,
        severity_name: "High",
        status: "new",
        created_timestamp: isoHoursAgo(10),
        cmdline: `curl -H "Authorization: Bearer ${fake.alertBearer}" https://internal.example.com/api`,
      },
    ],
    listRtrSessions: async () => [
      {
        id: "s-1",
        cid: "cid-1",
        device_id: "aid-1",
        hostname: "ws-01",
        platform_name: "Windows",
        user_id: "alice@example.com",
        user_uuid: "u-admin",
        created_at: isoHoursAgo(5),
        deleted_at: isoHoursAgo(4.8),
        duration: 600,
        commands: [
          { base_command: "runscript", command_string: `runscript -Raw=\`\`\`$cred = ConvertTo-SecureString '${fake.rtrRunscriptSecret}'\`\`\``, status: "complete" },
          { base_command: "put", command_string: fake.rtrPutCommand, status: "complete" },
          { base_command: "ls", command_string: "ls C:\\Users", status: "complete" },
        ],
        logs: [{ stdout: `PASSWORD=${fake.rtrStdoutSecret}`, stderr: "" }],
        device_details: { external_ip: "203.0.113.10" },
      },
      {
        id: "s-2",
        user_id: "bob@example.com",
        hostname: "ws-02",
        created_at: isoHoursAgo(3),
        deleted_at: isoHoursAgo(2.9),
        commands: [{ base_command: "ls", command_string: "ls" }],
      },
    ],
  });
}

test("verdict safety rule 9: exportCrowdstrikeAuditBundle never writes alert command lines, IOC values, or RTR command strings into the bundle, its zip, or the tool payloads", async () => {
  const base = createTempBase("grclanker-cs-export-secrets-");
  const secrets = Object.values(FAKE_CROWDSTRIKE_SECRETS);
  const client = secretBearingCrowdstrikeClient();
  const result = await exportCrowdstrikeAuditBundle(client, sampleConfig(), base);
  assert.equal(result.errorCount, 0);
  assert.equal(result.findingCount, 25);

  const files = readBundleFiles(result.outputDir);
  for (const file of [
    "core_data/response_readiness/alerts.json",
    "core_data/response_readiness/rtr_audit_sessions.json",
    "analysis/response_readiness.json",
    "analysis/findings.json",
    "compliance/executive_summary.md",
  ]) {
    assert.ok(files.has(file), `expected ${file} in ${[...files.keys()].join(", ")}`);
  }
  assertSecretsAbsent(assert, files, secrets, "bundle directory");
  const zipEntries = readZipEntries(result.zipPath);
  assert.equal(zipEntries.size, files.size, "the zip carries exactly the written files");
  assertSecretsAbsent(assert, zipEntries, secrets, "zip archive");

  const payloads = JSON.stringify([await checkCrowdstrikeAccess(client), ...(await runAllCrowdstrikeAssessments(client))]);
  for (const secret of secrets) {
    assert.ok(!payloads.includes(secret), `tool payloads must not carry ${secret}`);
  }

  const alerts = JSON.parse(files.get("core_data/response_readiness/alerts.json"));
  assert.equal(alerts.length, 2);
  assert.deepEqual(Object.keys(alerts[0]).sort(), [
    "agent_id", "aggregate_id", "assigned_to_name", "cid", "composite_id", "confidence", "created_timestamp", "device", "display_name",
    "id", "name", "pattern_id", "product", "resolution", "seconds_to_resolved", "severity", "severity_name", "status", "tactic", "tags",
    "technique", "type", "updated_timestamp",
  ]);
  assert.deepEqual(alerts[0].device, { device_id: "aid-1", hostname: "ws-01", platform_name: "Windows" });
  assert.equal(alerts[0].severity_name, "Critical");
  assert.deepEqual(Object.keys(alerts[1]).sort(), ["composite_id", "created_timestamp", "severity", "severity_name", "status"]);
  const sessions = JSON.parse(files.get("core_data/response_readiness/rtr_audit_sessions.json"));
  assert.equal(sessions.length, 2);
  assert.deepEqual(Object.keys(sessions[0]).sort(), [
    "base_commands", "cid", "command_count", "created_at", "deleted_at", "device_id", "duration", "hostname", "id", "platform_name", "user_id", "user_uuid",
  ]);
  assert.equal(sessions[0].command_count, 3);
  assert.deepEqual(sessions[0].base_commands, ["runscript", "put", "ls"]);
  assert.deepEqual(sessions[1].base_commands, ["ls"]);

  const response = JSON.parse(files.get("analysis/response_readiness.json"));
  assert.equal(findingById(response, "CS-22").status, "pass");
  assert.equal(findingById(response, "CS-22").evidence.alerts_reviewed, 2);
  assert.equal(findingById(response, "CS-07").status, "manual");
  assert.equal(findingById(response, "CS-07").evidence.sessions_reviewed, 2);
  assert.equal(response.summary.rtr_sessions_reviewed, 2);
});

test("verdict safety rule 10: stuck cursors, empty cursor pages, and absent totals are reported as truncated instead of complete", async () => {
  let deviceCalls = 0;
  let alertCalls = 0;
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.pathname === "/oauth2/token") return jsonResponse({ access_token: "token-1", expires_in: 1799 });
    if (url.pathname === "/devices/combined/devices/v1") {
      deviceCalls += 1;
      return jsonResponse({ resources: [{ device_id: `h-${deviceCalls}` }], meta: { pagination: { offset: "stuck-token", limit: 1 } } });
    }
    if (url.pathname === "/discover/combined/hosts/v1") {
      return jsonResponse({ resources: [{ id: "d-1" }], meta: { pagination: { after: "same-cursor" } } });
    }
    if (url.pathname === "/zero-trust-assessment/queries/assessments/v1") {
      if (!url.searchParams.get("after")) return jsonResponse({ resources: [{ aid: "z-1", score: 10 }], meta: { pagination: { after: "zta-2" } } });
      return jsonResponse({ resources: [], meta: { pagination: { after: "zta-3" } } });
    }
    if (url.pathname === "/alerts/combined/alerts/v1") {
      alertCalls += 1;
      assert.equal(init.method, "POST");
      return jsonResponse({ resources: [{ composite_id: `a-${alertCalls}` }], meta: { pagination: { after: "alert-stuck" } } });
    }
    if (url.pathname === "/user-management/queries/roles/v1") {
      return jsonResponse({ resources: ["falcon_administrator", "falcon_analyst"], meta: { pagination: { limit: 2, offset: 0 } } });
    }
    if (url.pathname === "/user-management/entities/roles/v1") {
      return jsonResponse({ resources: url.searchParams.getAll("ids").map((id) => ({ id, display_name: id })) });
    }
    if (url.pathname === "/identity-protection/queries/policy-rules/v1") return jsonResponse({ resources: ["idp-1"] });
    if (url.pathname === "/identity-protection/entities/policy-rules/v1") {
      return jsonResponse({ resources: [{ id: "idp-1", name: "Block stale accounts", enabled: true, simulationMode: false, action: "BLOCK" }] });
    }
    throw new Error(`unexpected path ${url.pathname}`);
  };
  const client = new CrowdstrikeApiClient(sampleConfig(), { fetchImpl });

  const stuckOffset = await client.listHosts(10);
  assert.deepEqual(stuckOffset.items.map((item) => item.device_id), ["h-1", "h-2"]);
  assert.equal(stuckOffset.total, undefined);
  assert.equal(stuckOffset.truncated, true, "a repeated opaque offset token with no total must not read as complete");
  assert.equal(deviceCalls, 2, "the repeated token stops the loop instead of spinning");

  const stuckAfter = await client.listDiscoverHosts("entity_type:'unmanaged'", 10);
  assert.equal(stuckAfter.items.length, 2);
  assert.equal(stuckAfter.total, undefined);
  assert.equal(stuckAfter.truncated, true, "a repeated after cursor with no total must not read as complete");

  const emptyCursorPage = await client.listZtaAssessments("score:<60", 10);
  assert.equal(emptyCursorPage.items.length, 1);
  assert.equal(emptyCursorPage.truncated, true, "an empty page that still carries a fresh cursor cannot be confirmed complete");

  const stuckAlerts = await client.listAlerts("severity:>=70", 10);
  assert.deepEqual(stuckAlerts.items.map((item) => item.composite_id), ["a-1", "a-2"]);
  assert.equal(stuckAlerts.truncated, true, "a repeated alert cursor with no total must not read as complete");

  const roles = await client.listRoles();
  assert.equal(roles.items.length, 2);
  assert.equal(roles.total, undefined);
  assert.equal(roles.truncated, true, "a single-page query without meta.pagination.total cannot be confirmed complete");
  const rules = await client.listIdentityProtectionRules();
  assert.equal(rules.items.length, 1);
  assert.equal(rules.truncated, true);
});

test("verdict safety rule 10: a stuck alert cursor and a role catalog without a total demote the dependent findings and state total unknown", async () => {
  let alertCalls = 0;
  const users = passingUsers();
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const ids = url.searchParams.getAll("ids");
    switch (url.pathname) {
      case "/oauth2/token":
        return jsonResponse({ access_token: "token-1", expires_in: 1799 });
      case "/policy/combined/response/v1":
        return jsonResponse({ resources: [responsePolicy()], meta: { pagination: { total: 1 } } });
      case "/real-time-response-audit/combined/sessions/v1":
      case "/devices/combined/devices/v1":
      case "/policy/queries/ioa-exclusions/v1":
      case "/policy/queries/ml-exclusions/v1":
      case "/policy/queries/sv-exclusions/v1":
        return jsonResponse({ resources: [], meta: { pagination: { total: 0 } } });
      case "/alerts/combined/alerts/v1":
        alertCalls += 1;
        return jsonResponse({
          resources: [{ composite_id: `a-${alertCalls}`, severity: 90, severity_name: "Critical", status: "closed", created_timestamp: isoHoursAgo(30), seconds_to_resolved: 3600 }],
          meta: { pagination: { after: "alert-stuck" } },
        });
      case "/user-management/queries/users/v1":
        return jsonResponse({ resources: users.users.map((user) => user.uuid), meta: { pagination: { total: 2 } } });
      case "/user-management/entities/users/GET/v1":
        return jsonResponse({ resources: users.users.filter((user) => JSON.parse(init.body).ids.includes(user.uuid)) });
      case "/user-management/combined/user-roles/v2":
        return jsonResponse({ resources: users.roles[url.searchParams.get("user_uuid")] ?? [], meta: { pagination: { total: 1 } } });
      case "/user-management/queries/roles/v1":
        return jsonResponse({ resources: ["falcon_administrator", "falcon_analyst"], meta: { pagination: { limit: 2, offset: 0 } } });
      case "/user-management/entities/roles/v1":
        return jsonResponse({ resources: ids.map((id) => ({ id, display_name: id })) });
      case "/api-clients/queries/api-clients/v1":
        return jsonResponse({ resources: ["api-1"], meta: { pagination: { total: 1 } } });
      case "/api-clients/entities/api-clients/v1":
        return jsonResponse({ resources: [{ id: "api-1", name: "grclanker audit", scopes: [apiScope("hosts", "read")] }] });
      case "/identity-protection/queries/policy-rules/v1":
        return jsonResponse({ resources: ["idp-1"], meta: { pagination: { total: 1 } } });
      case "/identity-protection/entities/policy-rules/v1":
        return jsonResponse({ resources: [{ id: "idp-1", name: "Block stale accounts", enabled: true, simulationMode: false, action: "BLOCK" }] });
      default:
        throw new Error(`unexpected path ${url.pathname}`);
    }
  };
  const client = new CrowdstrikeApiClient(sampleConfig(), { fetchImpl });

  const response = await assessCrowdstrikeResponseReadiness(client, { alertLimit: 10 });
  const sla = findingById(response, "CS-22");
  assert.equal(sla.status, "warn", `CS-22 must not pass on a stuck alert cursor: ${sla.summary}`);
  assert.match(sla.summary, /Partial inventory: only 2 of an unknown total of critical\/high alerts were read/);
  assert.deepEqual(sla.evidence.partial_inventory, [{ dataset: "critical/high alerts", seen: 2, total: undefined }]);
  assert.equal(response.summary.alerts_truncated, true);
  assert.equal(findingById(response, "CS-06").status, "pass");

  const governance = await assessCrowdstrikeAccessGovernance(client);
  for (const id of ["CS-16", "CS-17"]) {
    const item = findingById(governance, id);
    assert.equal(item.status, "warn", `${id} must not pass when the role catalog total is unknown: ${item.summary}`);
    assert.match(item.summary, /only 2 of an unknown total of roles in the role catalog were read/);
  }
  assert.equal(governance.summary.role_catalog_truncated, true);
  assert.equal(governance.summary.reported_total_roles, "unknown");
  assert.equal(findingById(governance, "CS-18").status, "pass");
  assert.equal(findingById(governance, "CS-24").status, "pass");
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-cs-path-");
  const outside = createTempBase("grclanker-cs-outside-");
  const linked = join(base, "linked");
  symlinkSync(outside, linked, "dir");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "linked/file.txt"), /symlinked parent directory/);

  const safe = resolveSecureOutputPath(base, join("reports", "safe.txt"));
  assert.match(safe, /reports\/safe\.txt$/);
});

test("CrowdStrike tools are registered in the tool catalog under the CrowdStrike group", () => {
  const tools = getRegisteredToolSummaries();
  for (const name of EXPECTED_TOOLS) {
    const tool = tools.find((entry) => entry.name === name);
    assert.ok(tool, `expected ${name} in the tool catalog`);
    assert.equal(tool.group, "CrowdStrike");
    assert.equal(tool.kind, "domain");
    assert.ok(tool.parameterSummaries.some((parameter) => parameter.name === "client_id"));
  }
  const exportTool = tools.find((entry) => entry.name === "crowdstrike_export_audit_bundle");
  assert.ok(exportTool.parameterSummaries.some((parameter) => parameter.name === "output_dir"));
});
