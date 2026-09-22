import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
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
  registerCrowdstrikeTools,
  resolveCrowdstrikeConfiguration,
  resolveSecureOutputPath,
  runAllCrowdstrikeAssessments,
} from "../dist/extensions/grc-tools/crowdstrike.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";
import { assertSecretFragmentsAbsent, readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";
import { CONFIG_CANARIES, assertConfigLoaderMatrix, configLoaderCases } from "./helpers/config-loader-matrix.mjs";
import { assertFixedTextsSurvive, collectFixedTexts, collectThrownMessage, collectToolTexts, logLines } from "./helpers/fixed-text-survival.mjs";
import { assertFragmentsAbsent, assertPlantedValuesWellFormed } from "./helpers/planted-values.mjs";
import { CONFIGURED_SECRET_CANARIES, assertTextFieldCarriers, carrierSuffix, injectingFetch } from "./helpers/text-field-carriers.mjs";
import { assertDeepCanariesWellFormed, assertDeepNesting, deepFields, plantingFetch } from "./helpers/deep-nesting.mjs";
import { assertScrubBoundary } from "./helpers/scrub-boundary-matrix.mjs";

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

/** The configured API client secret: a planted credential, so random-looking (see the planted-values self-check). */
const SAMPLE_CLIENT_SECRET = "845kpNMHDNTcWGMC2A";

function sampleConfig(overrides = {}) {
  return {
    clientId: "client-id",
    clientSecret: SAMPLE_CLIENT_SECRET,
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

test("addendum 6b: the JSON config loader reports read and parse failures with fixed text and never quotes the file, JSON.parse, or the fs error", async () => {
  const home = createTempBase("grclanker-cs-home-loader-");
  const cases = configLoaderCases({ format: "json", displayName: "CrowdStrike", fileNoun: "config file", extension: ".json" });
  assert.deepEqual(cases.map((item) => item.name), [
    "json unquoted value",
    "json short source",
    "json trailing comma with position",
    "EISDIR",
    "EACCES",
    "ENOENT on an explicit path",
  ]);
  const registered = [];
  registerCrowdstrikeTools({ registerTool: (tool) => registered.push(tool) });
  const checkAccess = registered.find((tool) => tool.name === "crowdstrike_check_access");
  await assertConfigLoaderMatrix(cases, {
    resolve: (path) => resolveCrowdstrikeConfiguration({ config_file: path }, {}, home),
    checkAccess: (path) => checkAccess.execute("call-config", checkAccess.prepareArguments({ config_file: path })),
  });
  // The same defect at the default location (~/.crowdstrike/config.json) is a parse failure too.
  mkdirSync(join(home, ".crowdstrike"), { recursive: true });
  const defaultPath = join(home, ".crowdstrike", "config.json");
  writeFileSync(defaultPath, "{\n  \"client_secret\": KVRPWLXTHBQNZMY\n}\n");
  assert.throws(() => resolveCrowdstrikeConfiguration({}, {}, home), (error) => {
    assert.equal(error.message, `Unable to parse CrowdStrike config file: invalid JSON in ${defaultPath}`);
    assert.equal(error.code, "INVALID_JSON");
    return true;
  });
  // The env-pointed path is explicit as well: a missing file is a read error, not a silent skip.
  assert.throws(() => resolveCrowdstrikeConfiguration({}, { CS_CONFIG_FILE: join(home, "absent.json") }, home), (error) => {
    assert.equal(error.message, `Unable to read CrowdStrike config file ${join(home, "absent.json")} (ENOENT)`);
    return true;
  });
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
  assert.equal(tokenBody.get("client_secret"), SAMPLE_CLIENT_SECRET);
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
      return jsonResponse({ errors: [{ code: 403, message: `invalid client ${SAMPLE_CLIENT_SECRET}` }] }, { status: 403 });
    }
    return jsonResponse({});
  };
  const client = new CrowdstrikeApiClient(sampleConfig(), { fetchImpl: leakyFetch });
  await assert.rejects(client.listPreventionPolicies(), (error) => {
    assert.ok(error instanceof CrowdstrikeHttpError);
    assert.equal(error.status, 403);
    assertFragmentsAbsent(assert, error.message, [SAMPLE_CLIENT_SECRET], "error message echoing the client secret");
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
    assert.match(error.message, /\(502\): non-JSON body \(text\/html, 62 bytes\)/);
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
  assertFragmentsAbsent(assert, JSON.stringify(metadata), [SAMPLE_CLIENT_SECRET], "metadata.json");

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

/**
 * Random-looking alphanumeric planted secrets; the bundle and zip scans check every substring of them at
 * lengths 6 through 24. Each is planted inside the field or carrier named by its key (an alert command line,
 * an RTR command string, an exclusion regex or path, a comment URL query).
 */
const FAKE_CROWDSTRIKE_SECRETS = {
  alertCmdlinePassword: "cN4rGYkQv4MsftpRf4",
  alertParentEncodedCommand: "KUS9kRX89Vepjnxd6G",
  alertGrandparentToken: "Sx5T2uSUa7nwunm5AF",
  alertDescriptionToken: "QY5PHe53gd9h8xy26c",
  alertIocValue: "Ecx39uZd3gTpKECnQh",
  alertBearer: "ve7dGCwYPnpHkFKtNZ",
  rtrRunscriptSecret: "6hPpZYXUCsPxCUgGxP",
  rtrPutCommand: "dhgLG3kLCfvdtHtuLG",
  rtrStdoutSecret: "fanNHJPRQ8hTdrQe84",
  // Free-text exclusion carriers (review round item 6): command-line and image regexes, paths, and notes.
  ioaClRegexToken: "GnLNeK7BVWATB8vrSR",
  ioaIfnRegexKey: "BhdHYLvSUmsyvG5TQk",
  ioaDescriptionBearer: "MnKdD9NCNVyrvmBuWn",
  mlValuePassword: "Y9yWFGgBas8nujKGLs",
  svValueSecret: "y6RWbfHqmHfduL8VUr",
  svCommentUrlToken: "47xGMHC5Z8gJUckTyB",
};

function secretBearingCrowdstrikeClient() {
  const fake = FAKE_CROWDSTRIKE_SECRETS;
  return createFakeClient({
    listIoaExclusions: async () => [{
      id: "ioa-1",
      name: "Backup agent",
      pattern_name: "SuspiciousCommandLine",
      ifn_regex: `C:\\\\Tools\\\\uploader\\.exe api_key=${fake.ioaIfnRegexKey}`,
      cl_regex: `.*uploader\\.exe --token ${fake.ioaClRegexToken} --quiet.*`,
      description: `Allow the uploader; it authenticates with Authorization: Bearer ${fake.ioaDescriptionBearer}`,
      applied_globally: false,
      groups: [{ id: "hg-1" }],
    }],
    listMlExclusions: async () => [{ id: "ml-1", value: `D:\\Builds\\artifacts\\password=${fake.mlValuePassword}\\*.pdb`, excluded_from: ["blocking"], applied_globally: false, groups: [{ id: "hg-1" }] }],
    listSensorVisibilityExclusions: async () => [{
      id: "sv-1",
      value: `/opt/vendor/agent/collector --secret ${fake.svValueSecret}`,
      comment: `Registered at https://vendor.example.com/register?token=${fake.svCommentUrlToken} by ops`,
      applied_globally: false,
      groups: [{ id: "hg-1" }],
    }],
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
          { base_command: "put", command_string: `put ${fake.rtrPutCommand}.txt`, status: "complete" },
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
  assertSecretFragmentsAbsent(assert, files, secrets, "bundle directory");
  const zipEntries = readZipEntries(result.zipPath);
  assert.equal(zipEntries.size, files.size, "the zip carries exactly the written files");
  assertSecretFragmentsAbsent(assert, zipEntries, secrets, "zip archive");

  const payloads = JSON.stringify([await checkCrowdstrikeAccess(client), ...(await runAllCrowdstrikeAssessments(client))]);
  assertFragmentsAbsent(assert, payloads, secrets, "tool payloads");

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

  // Review round item 6: the exclusion records are kept, with the redaction marker where a credential shape was found.
  const ioa = JSON.parse(files.get("core_data/access_governance/ioa_exclusions.json"));
  assert.equal(ioa.length, 1);
  assert.equal(ioa[0].cl_regex, ".*uploader\\.exe --token [REDACTED] --quiet.*");
  assert.equal(ioa[0].ifn_regex, "C:\\\\Tools\\\\uploader\\.exe api_key=[REDACTED]");
  assert.match(ioa[0].description, /^Allow the uploader; it authenticates with Authorization: \[REDACTED\]/);
  assert.equal(ioa[0].name, "Backup agent");
  const ml = JSON.parse(files.get("core_data/access_governance/ml_exclusions.json"));
  // The credential value ends at the path separator, so the path skeleton after it stays.
  assert.equal(ml[0].value, "D:\\Builds\\artifacts\\password=[REDACTED]\\*.pdb");
  const sv = JSON.parse(files.get("core_data/access_governance/sensor_visibility_exclusions.json"));
  assert.equal(sv[0].value, "/opt/vendor/agent/collector --secret [REDACTED]");
  assert.equal(sv[0].comment, "Registered at https://vendor.example.com/register?[REDACTED] by ops");
  const governance = JSON.parse(files.get("analysis/access_governance.json"));
  assert.equal(findingById(governance, "CS-19").evidence.listing[0].cl_regex, ".*uploader\\.exe --token [REDACTED] --quiet.*");
  assert.equal(findingById(governance, "CS-19").evidence.listing[0].ifn_regex, "C:\\\\Tools\\\\uploader\\.exe api_key=[REDACTED]");
  assert.equal(findingById(governance, "CS-20").evidence.listing[0].value, "D:\\Builds\\artifacts\\password=[REDACTED]\\*.pdb");
  assert.equal(findingById(governance, "CS-21").evidence.listing[0].value, "/opt/vendor/agent/collector --secret [REDACTED]");
  assert.equal(findingById(governance, "CS-19").status, "pass", "redaction does not change the broad-regex verdict");
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
    if (url.pathname === "/api-clients/queries/api-clients/v1") {
      return jsonResponse({ resources: ["client-1", "client-2", "client-3"], meta: { pagination: { total: 3, limit: 500, offset: 3 } } });
    }
    if (url.pathname === "/api-clients/entities/api-clients/v1") {
      return jsonResponse({ resources: url.searchParams.getAll("ids").filter((id) => id !== "client-2").map((id) => ({ id, name: id })) });
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

  const apiClients = await client.listApiClients();
  assert.deepEqual(apiClients.items.map((item) => item.id), ["client-1", "client-3"]);
  assert.equal(apiClients.total, 3);
  assert.equal(apiClients.truncated, true, "an entity lookup that returns fewer records than the id query listed is a partial inventory");
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

// Review round items 3 and 4: every denied dataset is written as a not-collected marker, dependents skipped
// because their parent was denied name the parent, and every summary count or flag derived from an unread
// dataset renders null instead of 0, [] or false.

function assertNotCollected(marker, { dataset, endpoint, status = 403, context }) {
  assert.ok(marker && typeof marker === "object" && !Array.isArray(marker), `${context}: expected a marker object, got ${JSON.stringify(marker)}`);
  assert.equal(marker.collected, false, `${context}: collected`);
  assert.equal(marker.dataset, dataset, `${context}: dataset`);
  assert.equal(marker.status, status, `${context}: status`);
  assert.equal(marker.endpoint, endpoint, `${context}: endpoint`);
  assert.match(marker.error, new RegExp(`\\(${status}\\)`), `${context}: error names the status`);
}

function assertNotRequested(marker, { dataset, parent, context }) {
  assert.ok(marker && typeof marker === "object" && !Array.isArray(marker), `${context}: expected a marker object, got ${JSON.stringify(marker)}`);
  assert.equal(marker.collected, false, `${context}: collected`);
  assert.equal(marker.dataset, dataset, `${context}: dataset`);
  assert.equal(marker.status, null, `${context}: status`);
  assert.match(marker.error, /^not requested: /, `${context}: error`);
  assert.match(marker.error, parent, `${context}: names the parent read`);
}

const CROWDSTRIKE_DENIALS = [
  { method: "listPreventionPolicies", endpoint: "/policy/combined/prevention/v1", category: "prevention_policies", markers: { prevention_policies: "prevention policies" }, nulls: ["total_policies", "enabled_policies", "enabled_and_assigned_policies", "enabled_but_unassigned_policies", "policies_truncated", "platforms_covered"] },
  { method: "listResponsePolicies", endpoint: "/policy/combined/response/v1", category: "response_readiness", markers: { response_policies: "response policies" }, nulls: ["response_policies", "enabled_and_assigned_response_policies"] },
  { method: "listRtrSessions", endpoint: "/real-time-response-audit/combined/sessions/v1", category: "response_readiness", markers: { rtr_audit_sessions: "rtr audit sessions" }, nulls: ["rtr_sessions_reviewed"] },
  { method: "listAlerts", endpoint: "/alerts/combined/alerts/v1", category: "response_readiness", markers: { alerts: "alerts" }, nulls: ["critical_high_alerts", "alerts_truncated"] },
  { method: "listHosts", endpoint: "/devices/combined/devices/v1", category: "response_readiness", markers: { contained_hosts: "contained hosts" }, nulls: ["contained_hosts"] },
  { method: "listDeviceControlPolicies", endpoint: "/policy/combined/device-control/v1", category: "device_firewall", markers: { device_control_policies: "device control policies" }, skipped: { device_control_policy_details: { dataset: "device control policy details", parent: /device control policies list was not read/ } }, nulls: ["device_control_policies", "enabled_and_assigned_device_control_policies"] },
  { method: "getDeviceControlPoliciesV2", endpoint: "/policy/entities/device-control/v2", category: "device_firewall", markers: { device_control_policy_details: "device control policy details" }, nulls: [] },
  { method: "listFirewallPolicies", endpoint: "/policy/combined/firewall/v1", category: "device_firewall", markers: { firewall_policies: "firewall policies" }, skipped: { firewall_policy_containers: { dataset: "firewall policy containers", parent: /firewall policies list was not read/ } }, nulls: ["firewall_policies", "enabled_and_assigned_firewall_policies"] },
  { method: "getFirewallPolicyContainers", endpoint: "/fwmgr/entities/policies/v1", category: "device_firewall", markers: { firewall_policy_containers: "firewall policy containers" }, nulls: [] },
  { method: "listFirewallRuleGroups", endpoint: "/fwmgr/queries/rule-groups/v1", category: "device_firewall", markers: { firewall_rule_groups: "firewall rule groups" }, nulls: ["firewall_rule_groups"] },
  { method: "listFirewallRules", endpoint: "/fwmgr/queries/rules/v1", category: "device_firewall", markers: { firewall_rules: "firewall rules" }, nulls: ["firewall_rules_reviewed", "firewall_rules_truncated"] },
  { method: "listSensorUpdatePolicies", endpoint: "/policy/combined/sensor-update/v2", category: "sensor_coverage", markers: { sensor_update_policies: "sensor update policies" }, skipped: { sensor_update_builds: { dataset: "sensor update builds", parent: /sensor update policies list was not read/ } }, nulls: ["sensor_update_policies", "enabled_and_assigned_sensor_update_policies"] },
  { method: "listSensorUpdateBuilds", endpoint: "/policy/combined/sensor-update-builds/v1", category: "sensor_coverage", nested: { sensor_update_builds: { windows: "sensor builds (windows)" } }, nulls: [] },
  { method: "listHosts", endpoint: "/devices/combined/devices/v1", category: "sensor_coverage", markers: { hosts: "hosts" }, nulls: ["sampled_hosts", "reported_total_hosts", "hosts_truncated"] },
  { method: "listHostGroups", endpoint: "/devices/combined/host-groups/v1", category: "sensor_coverage", markers: { host_groups: "host groups" }, nulls: ["host_groups"] },
  { method: "countDiscoverHosts", endpoint: "/discover/queries/hosts/v1", category: "sensor_coverage", skipped: { discover_unmanaged_samples: { dataset: "discover unmanaged samples", parent: /discover unmanaged hosts count was not read/ } }, nulls: ["unmanaged_assets"] },
  { method: "listDiscoverHosts", endpoint: "/discover/combined/hosts/v1", category: "sensor_coverage", markers: { discover_unmanaged_samples: "discover unmanaged samples" }, nulls: [] },
  { method: "countZtaAssessments", endpoint: "/zero-trust-assessment/queries/assessments/v1", category: "sensor_coverage", skipped: { zero_trust_assessments_below_threshold: { dataset: "zero trust assessments below threshold", parent: /zero trust assessment totals count was not read/ } }, nulls: ["zta_scored_hosts"] },
  { method: "listZtaAssessments", endpoint: "/zero-trust-assessment/queries/assessments/v1", category: "sensor_coverage", markers: { zero_trust_assessments_below_threshold: "zero trust assessments below threshold" }, nulls: [] },
  { method: "listUserUuids", endpoint: "/user-management/queries/users/v1", category: "access_governance", skipped: { users: { dataset: "users", parent: /user uuid list was not read/ }, user_roles: { dataset: "user roles", parent: /user uuid list was not read/ } }, nulls: ["users_reviewed", "reported_total_users", "users_truncated", "role_lookups_failed", "role_pages_truncated", "admin_users"] },
  { method: "getUsers", endpoint: "/user-management/entities/users/GET/v1", category: "access_governance", markers: { users: "users" }, skipped: { user_roles: { dataset: "user roles", parent: /user details were not read/ } }, nulls: ["users_reviewed", "role_lookups_failed", "role_pages_truncated", "admin_users"] },
  { method: "listUserRoles", endpoint: "/user-management/combined/user-roles/v2", category: "access_governance", nested: { user_roles: { "u-admin": "user roles (u-admin)", "u-analyst": "user roles (u-analyst)" } }, nulls: ["admin_users"] },
  { method: "listRoles", endpoint: "/user-management/queries/roles/v1", category: "access_governance", markers: { roles: "role catalog" }, nulls: [], unavailable: ["roles_in_catalog", "reported_total_roles", "role_catalog_truncated"] },
  { method: "listApiClients", endpoint: "/api-clients/queries/api-clients/v1", category: "access_governance", markers: { api_clients: "api clients" }, nulls: ["api_clients"] },
  { method: "listIoaExclusions", endpoint: "/policy/queries/ioa-exclusions/v1", category: "access_governance", markers: { ioa_exclusions: "ioa exclusions" }, nulls: ["ioa_exclusions"] },
  { method: "listMlExclusions", endpoint: "/policy/queries/ml-exclusions/v1", category: "access_governance", markers: { ml_exclusions: "ml exclusions" }, nulls: ["ml_exclusions"] },
  { method: "listSensorVisibilityExclusions", endpoint: "/policy/queries/sv-exclusions/v1", category: "access_governance", markers: { sensor_visibility_exclusions: "sensor visibility exclusions" }, nulls: ["sensor_visibility_exclusions"] },
  { method: "listIdentityProtectionRules", endpoint: "/identity-protection/queries/policy-rules/v1", category: "access_governance", markers: { identity_protection_rules: "identity protection rules" }, nulls: [], unavailable: ["identity_protection_rules", "identity_protection_rules_truncated"] },
];

test("review round items 3 and 4: every denied Falcon dataset is a not-collected marker, skipped dependents name the parent, and derived summary counts and flags render null", async () => {
  const healthy = Object.fromEntries((await runAllCrowdstrikeAssessments(createFakeClient())).map((assessment) => [assessment.category, assessment]));
  for (const [category, assessment] of Object.entries(healthy)) {
    for (const [name, snapshot] of Object.entries(assessment.snapshots)) {
      assert.ok(!(snapshot && snapshot.collected === false), `${category}/${name} must not carry a marker when every read succeeded`);
    }
    for (const description of Object.values(assessment.summary.inventories)) {
      const states = typeof description === "string" ? [description] : Object.values(description);
      for (const state of states) assert.match(state, /^read/, `${category} inventories: ${state}`);
    }
  }

  for (const denial of CROWDSTRIKE_DENIALS) {
    const context = `${denial.method} denied`;
    const assessments = await runAllCrowdstrikeAssessments(createFakeClient({ [denial.method]: forbidden(denial.endpoint) }));
    const assessment = assessments.find((entry) => entry.category === denial.category);
    for (const [name, dataset] of Object.entries(denial.markers ?? {})) {
      assertNotCollected(assessment.snapshots[name], { dataset, endpoint: denial.endpoint, context: `${context}: snapshots.${name}` });
      assert.match(assessment.summary.inventories[name] ?? "", /^unread \(/, `${context}: inventories.${name}`);
    }
    for (const [name, expected] of Object.entries(denial.skipped ?? {})) {
      // The expected dataset label is declared in the table, so the marker's own label is never compared against itself.
      assertNotRequested(assessment.snapshots[name], { dataset: expected.dataset, parent: expected.parent, context: `${context}: snapshots.${name}` });
      assert.match(assessment.summary.inventories[name] ?? "", /^not requested \(/, `${context}: inventories.${name}`);
    }
    for (const [name, entries] of Object.entries(denial.nested ?? {})) {
      const snapshot = assessment.snapshots[name];
      for (const [key, dataset] of Object.entries(entries)) {
        assertNotCollected(snapshot[key], { dataset, endpoint: denial.endpoint, context: `${context}: snapshots.${name}.${key}` });
      }
    }
    for (const key of denial.nulls) {
      assert.ok(key in assessment.summary, `${context}: summary.${key} exists`);
      assert.equal(assessment.summary[key], null, `${context}: summary.${key} renders null, got ${JSON.stringify(assessment.summary[key])}`);
      assert.notEqual(healthy[denial.category].summary[key], null, `${context}: summary.${key} is populated on the healthy run`);
    }
    for (const key of denial.unavailable ?? []) {
      assert.equal(assessment.summary[key], "unavailable", `${context}: summary.${key}`);
    }
    // The denial must reach at least one verdict, every finding that names the unread dataset must not pass,
    // and a finding that still passes must have passed on the healthy run too (a denial never upgrades).
    const affected = assessment.findings.filter((item) => item.evidence?.unreadable_dataset || item.evidence?.unreadable_secondary_reads || item.evidence?.not_applicable);
    assert.ok(affected.length > 0, `${context}: at least one ${denial.category} finding must record the unread dataset`);
    for (const item of affected) {
      assert.notEqual(item.status, "pass", `${context}: ${item.id} names an unread dataset and must not pass`);
    }
    for (const item of assessment.findings.filter((entry) => entry.status === "pass")) {
      assert.equal(findingById(healthy[denial.category], item.id).status, "pass", `${context}: ${item.id} passes under denial but not on the healthy run`);
    }
  }
});

test("review round items 3 and 4: the exported bundle writes markers for denied datasets and skipped dependents instead of empty arrays", async () => {
  const base = createTempBase("grclanker-cs-markers-");
  const client = createFakeClient({
    listFirewallPolicies: forbidden("/policy/combined/firewall/v1"),
    listUserUuids: forbidden("/user-management/queries/users/v1"),
    listSensorUpdateBuilds: async () => { throw new Error("socket hang up"); },
  });
  const result = await exportCrowdstrikeAuditBundle(client, sampleConfig(), base);
  const files = readBundleFiles(result.outputDir);
  const zipEntries = readZipEntries(result.zipPath);

  for (const source of [files, zipEntries]) {
    const firewall = JSON.parse(source.get("core_data/device_firewall/firewall_policies.json"));
    assertNotCollected(firewall, { dataset: "firewall policies", endpoint: "/policy/combined/firewall/v1", context: "firewall_policies.json" });
    const containers = JSON.parse(source.get("core_data/device_firewall/firewall_policy_containers.json"));
    assertNotRequested(containers, { dataset: "firewall policy containers", parent: /firewall policies list was not read/, context: "firewall_policy_containers.json" });
    const users = JSON.parse(source.get("core_data/access_governance/users.json"));
    assertNotRequested(users, { dataset: "users", parent: /user uuid list was not read/, context: "users.json" });
    const userRoles = JSON.parse(source.get("core_data/access_governance/user_roles.json"));
    assertNotRequested(userRoles, { dataset: "user roles", parent: /user uuid list was not read/, context: "user_roles.json" });
    const builds = JSON.parse(source.get("core_data/sensor_coverage/sensor_update_builds.json"));
    assert.equal(builds.windows.collected, false);
    assert.equal(builds.windows.status, null, "a transport failure carries no HTTP status");
    assert.equal(builds.windows.endpoint, "/policy/combined/sensor-update-builds/v1");
    assert.match(builds.windows.error, /socket hang up/);
    // Readable datasets keep their array shape.
    assert.ok(Array.isArray(JSON.parse(source.get("core_data/device_firewall/firewall_rules.json"))));
    assert.ok(Array.isArray(JSON.parse(source.get("core_data/sensor_coverage/hosts.json"))));
  }

  const deviceFirewall = JSON.parse(files.get("analysis/device_firewall.json"));
  assert.equal(deviceFirewall.summary.firewall_policies, null);
  assert.equal(deviceFirewall.summary.enabled_and_assigned_firewall_policies, null);
  assert.equal(deviceFirewall.summary.firewall_rules_reviewed, 1, "an independent readable dataset keeps its count");
  assert.match(deviceFirewall.summary.inventories.firewall_policies, /^unread \(firewall policies: .*\(403\)/);
  assert.match(deviceFirewall.summary.inventories.firewall_policy_containers, /^not requested \(the firewall policies list was not read\)/);
  const governance = JSON.parse(files.get("analysis/access_governance.json"));
  assert.equal(governance.summary.users_reviewed, null);
  assert.equal(governance.summary.admin_users, null);
  assert.equal(governance.summary.users_truncated, null);
  assert.equal(governance.summary.role_pages_truncated, null);
  assert.equal(governance.summary.api_clients, 1);
  assert.equal(findingById(governance, "CS-16").status, "manual");
  assert.equal(findingById(governance, "CS-16").evidence.users_reviewed, undefined, "no user count is rendered beside the denial");
  const quickReference = files.get("QUICK_REFERENCE.md");
  assert.match(quickReference, /"collected": false/);
  assert.match(quickReference, /summary\.inventories/);
});

test("review round item 5: a capped prevention policy list never asserts platforms without a policy, and an absence-driven fail on a truncated list renders manual", async () => {
  const capped = await assessCrowdstrikePreventionPolicies(createFakeClient({
    listPreventionPolicies: async () => truncatedPage([preventionPolicy()], 43),
  }));
  const ml = findingById(capped, "CS-01");
  assert.equal(ml.status, "warn");
  assert.equal(ml.evidence.platforms_without_policy, null, "Mac and Linux are provable only against the 42 unread policies");
  assert.doesNotMatch(ml.summary, /no assigned policy covers/);
  assert.match(ml.summary, /Partial inventory: only 1 of 43 prevention policies were read/);
  assert.deepEqual(ml.evidence.partial_inventory, [{ dataset: "prevention policies", seen: 1, total: 43 }]);
  assert.equal(capped.summary.policies_truncated, true);
  assert.equal(capped.summary.platforms_covered, "Windows", "platforms covered by a visible policy remain a presence claim");

  const complete = await assessCrowdstrikePreventionPolicies(createFakeClient({ listPreventionPolicies: async () => [preventionPolicy()] }));
  assert.deepEqual(findingById(complete, "CS-01").evidence.platforms_without_policy, ["Mac", "Linux"], "a complete list still names the uncovered platforms");
  assert.match(findingById(complete, "CS-01").summary, /no assigned policy covers Mac, Linux/);

  const unassignedCapped = await assessCrowdstrikePreventionPolicies(createFakeClient({
    listPreventionPolicies: async () => truncatedPage([preventionPolicy({ groups: [] })], 43),
  }));
  for (const id of ["CS-01", "CS-02", "CS-03", "CS-04", "CS-05"]) {
    const item = findingById(unassignedCapped, id);
    assert.equal(item.status, "manual", `${id} must not fail on the absence of an assigned policy among 1 of 43 visible policies: ${item.summary}`);
    assert.match(item.summary, /None of the 1 prevention policies is both enabled and assigned/);
    assert.match(item.summary, /so the absence this verdict rests on cannot be asserted for the unread rows\. Verdict: manual \(unknown\)\.$/);
    assert.equal(item.evidence.absence_claim, true);
  }
  const unassignedComplete = await assessCrowdstrikePreventionPolicies(createFakeClient({ listPreventionPolicies: async () => [preventionPolicy({ groups: [] })] }));
  assert.equal(findingById(unassignedComplete, "CS-01").status, "fail", "a complete list with no assigned policy still fails");

  const firewall = passingFirewall();
  const cappedFirewall = await assessCrowdstrikeDeviceFirewall(createFakeClient({
    listFirewallPolicies: async () => truncatedPage(firewall.policies.map((policy) => ({ ...policy, groups: [] })), 40),
  }));
  assert.equal(findingById(cappedFirewall, "CS-10").status, "manual");
  assert.equal(findingById(cappedFirewall, "CS-11").status, "manual", "no containers among the visible unassigned policies is an absence claim over the unread rows");
  assert.equal(findingById(cappedFirewall, "CS-11").evidence.absence_claim, true);
});

/** Wording that asserts an absence across rows the finding did not read; a capped list must never carry it. */
const UNIVERSAL_ABSENCE = /\bNo user\b|\bevery dated admin login\b|\breturned no hosts\b|\bno active containment\b|\bemptiness is compliant\b|\bemptiness fails\b|\bnothing to\b|\breturned zero\b|\bzero rules exist\b|\bno detection logic\b|\bno machine learning coverage\b|\bnothing is hidden\b/;

test("round 2 SEND BACK 5: under a capped list CS-17 and CS-23 scope their sentences to the rows that were read and never assert a universal absence; a complete read keeps its counts and the emptiness sentence", async () => {
  // CS-17 under CAP listUserUuids: 1 of 43 user uuids visible, the visible user an admin with a fresh login.
  const users = passingUsers();
  const cappedUsers = await assessCrowdstrikeAccessGovernance(createFakeClient({
    listUserUuids: async () => truncatedPage(["u-admin"], 43),
    getUsers: async (uuids) => users.users.filter((user) => uuids.includes(user.uuid)),
  }));
  const leastPrivilege = findingById(cappedUsers, "CS-17");
  assert.equal(leastPrivilege.status, "warn");
  assert.equal(leastPrivilege.evidence.users_reviewed, 1);
  assert.deepEqual(leastPrivilege.evidence.partial_inventory, [{ dataset: "users", seen: 1, total: 43 }]);
  assert.equal(
    leastPrivilege.summary,
    "1 users reviewed; 0 carry more than 5 roles or redundant roles on top of an admin grant, and 0 of 1 admin accounts have a last login older than 90 days. Partial inventory: only 1 of 43 users were read (sampled or truncated), so this verdict cannot exceed warn.",
  );
  assert.doesNotMatch(leastPrivilege.summary, UNIVERSAL_ABSENCE);

  // Control: a complete read keeps the count-scoped sentence over the whole inventory and passes without a partial clause.
  const completeUsers = await assessCrowdstrikeAccessGovernance(createFakeClient());
  const completeLeastPrivilege = findingById(completeUsers, "CS-17");
  assert.equal(completeLeastPrivilege.status, "pass");
  assert.equal(completeLeastPrivilege.summary, "2 users reviewed; 0 carry more than 5 roles or redundant roles on top of an admin grant, and 0 of 1 admin accounts have a last login older than 90 days.");
  assert.equal(completeLeastPrivilege.evidence.partial_inventory, undefined);
  assert.doesNotMatch(completeLeastPrivilege.summary, UNIVERSAL_ABSENCE);

  // A stale admin observed on a visible row still fails under the cap, and the sentence stays count-scoped.
  const staleCapped = await assessCrowdstrikeAccessGovernance(createFakeClient({
    listUserUuids: async () => truncatedPage(["u-admin"], 43),
    getUsers: async () => [{ uuid: "u-admin", uid: "alice@example.com", status: "active", last_login_at: isoDaysAgo(120) }],
  }));
  const staleLeastPrivilege = findingById(staleCapped, "CS-17");
  assert.equal(staleLeastPrivilege.status, "fail", "a fail observed on a visible row stands under a cap");
  assert.match(staleLeastPrivilege.summary, /^1 users reviewed; 0 carry more than 5 roles or redundant roles on top of an admin grant, and 1 of 1 admin accounts have a last login older than 90 days\. Partial inventory: only 1 of 43 users were read/);

  // CS-23 under CAP listHosts: the containment status filter reports 40 hosts and none is visible.
  const cappedHosts = await assessCrowdstrikeResponseReadiness(createFakeClient({
    listHosts: async (_limit, filter) => (filter ? truncatedPage([], 40) : [host()]),
  }));
  const containment = findingById(cappedHosts, "CS-23");
  assert.equal(containment.status, "warn");
  assert.equal(containment.evidence.contained_hosts, 0);
  assert.deepEqual(containment.evidence.partial_inventory, [{ dataset: "contained hosts", seen: 0, total: 40 }]);
  assert.equal(
    containment.summary,
    "The containment status filter read was truncated before any matching host was visible, so active containment cannot be confirmed or ruled out from the visible rows; document each containment and its incident reference. Partial inventory: only 0 of 40 contained hosts were read (sampled or truncated), so this verdict cannot exceed warn.",
  );
  assert.doesNotMatch(containment.summary, UNIVERSAL_ABSENCE);

  // A visible contained host under the cap keeps the count-scoped sentence and the partial clause.
  const cappedContained = await assessCrowdstrikeResponseReadiness(createFakeClient({
    listHosts: async (_limit, filter) => (filter ? truncatedPage([host({ hostname: "contained-01", status: "contained" })], 40) : [host()]),
  }));
  assert.equal(findingById(cappedContained, "CS-23").status, "warn");
  assert.match(findingById(cappedContained, "CS-23").summary, /^1 hosts are network contained or pending containment changes; document each containment and its incident reference\. Partial inventory: only 1 of 40 contained hosts were read/);

  // Control: a complete read with no contained hosts keeps the emptiness sentence and passes.
  const completeHosts = await assessCrowdstrikeResponseReadiness(createFakeClient());
  const completeContainment = findingById(completeHosts, "CS-23");
  assert.equal(completeContainment.status, "pass");
  assert.equal(completeContainment.summary, "The Hosts API was readable and the containment status filter returned no hosts, so there is no active containment to document; emptiness is compliant for this control.");
  assert.equal(completeContainment.evidence.partial_inventory, undefined);

  // The full capped run (every paged read truncated) carries no universal absence sentence on either finding.
  const partialRun = await runAllCrowdstrikeAssessments(createPartialClient());
  for (const id of ["CS-17", "CS-23"]) {
    const item = partialRun.flatMap((assessment) => assessment.findings).find((entry) => entry.id === id);
    assert.ok(item, `expected finding ${id}`);
    assert.notEqual(item.status, "pass");
    assert.doesNotMatch(item.summary, UNIVERSAL_ABSENCE, `${id} under the partial client: ${item.summary}`);
    assert.match(item.summary, /Partial inventory: only \d+ of \d+ /);
  }
});

/** Every paged read reports rows it did not return: a truncated page with zero visible rows. */
function createTruncatedEmptyClient(total = 40) {
  const overrides = {};
  for (const name of PAGED_METHODS) overrides[name] = async () => truncatedPage([], total);
  return createFakeClient(overrides);
}

function truncatedBeforeVisibleSentence(read, row, property) {
  return `The ${read} read was truncated before any ${row} was visible, so ${property} cannot be confirmed or ruled out from the visible rows.`;
}

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
}

/** Ruling (a): emptiness is compliant only for a complete read, so a truncated page with no visible row renders warn. */
const EMPTINESS_RULE_CASES = [
  { id: "CS-19", read: "IOA exclusions", row: "exclusion", property: "suppression of detection logic", countLeaf: "exclusions", assess: assessCrowdstrikeAccessGovernance, method: "listIoaExclusions", emptiness: /returned zero exclusions; no detection logic is being suppressed, so emptiness is compliant/ },
  { id: "CS-20", read: "ML exclusions", row: "exclusion", property: "suppression of machine learning coverage", countLeaf: "exclusions", assess: assessCrowdstrikeAccessGovernance, method: "listMlExclusions", emptiness: /returned zero exclusions; no machine learning coverage is being suppressed, so emptiness is compliant/ },
  { id: "CS-21", read: "sensor visibility exclusions", row: "exclusion", property: "paths hidden from the sensor", countLeaf: "exclusions", assess: assessCrowdstrikeAccessGovernance, method: "listSensorVisibilityExclusions", emptiness: /returned zero exclusions; nothing is hidden from the sensor, so emptiness is compliant/ },
  { id: "CS-22", read: "critical/high alerts", row: "dated alert", property: "response within the SLA", countLeaf: "alerts_reviewed", assess: assessCrowdstrikeResponseReadiness, method: "listAlerts", emptiness: /returned no dated critical or high alerts created in the last 30 days \(window stated\), so there was nothing to respond to; emptiness is compliant/ },
];

/** Ruling (b): a fail asserted from zero visible rows of a truncated list is a claim about unread rows, so it renders manual. */
const EMPTY_FAIL_RULE_CASES = [
  { id: "CS-13", read: "hosts", row: "host", property: "sensor deployment coverage", countLeaf: "sampled_hosts", assess: assessCrowdstrikeSensorCoverage, method: "listHosts", emptiness: /returned zero hosts, so no sensor deployment coverage can be demonstrated; emptiness fails this control/ },
  { id: "CS-14", read: "host groups", row: "host group", property: "policy assignment coverage", countLeaf: "host_groups", assess: assessCrowdstrikeSensorCoverage, method: "listHostGroups", emptiness: /returned zero host groups, so no policy assignment coverage can be demonstrated; emptiness fails this control/ },
  { id: "CS-24", read: "Identity Protection policy rules", row: "rule", property: "identity-based lateral movement prevention", countLeaf: "rules", assess: assessCrowdstrikeAccessGovernance, method: "listIdentityProtectionRules", emptiness: /zero rules exist, so identity-based lateral movement is not being prevented; emptiness fails this control/ },
];

test("round 3 rulings (a) and (b): a truncated page with zero visible rows never passes CS-19, CS-20, CS-21, or CS-22 and never fails CS-13, CS-14, or CS-24; the sentence says the property cannot be confirmed or ruled out from the visible rows, and a complete empty read keeps its emptiness verdict", async () => {
  // Every paged read truncated at zero visible rows of 40.
  const truncatedEmpty = (await runAllCrowdstrikeAssessments(createTruncatedEmptyClient())).flatMap((assessment) => assessment.findings);
  const byId = (findings, id) => {
    const item = findings.find((entry) => entry.id === id);
    assert.ok(item, `expected finding ${id}`);
    return item;
  };

  // (a) The four emptiness findings render warn with the scoped sentence and the seen-versus-total clause.
  for (const item of EMPTINESS_RULE_CASES) {
    const found = byId(truncatedEmpty, item.id);
    assert.equal(found.status, "warn", `${item.id} on a truncated page with zero visible rows`);
    assert.equal(
      found.summary,
      `${truncatedBeforeVisibleSentence(item.read, item.row, item.property)} Partial inventory: only 0 of 40 ${item.read} were read (sampled or truncated), so this verdict cannot exceed warn.`,
    );
    assert.doesNotMatch(found.summary, UNIVERSAL_ABSENCE);
    assert.deepEqual(found.evidence.partial_inventory, [{ dataset: item.read, seen: 0, total: 40 }]);
    assert.equal(found.evidence[item.countLeaf], 0, `${item.id} counts the visible rows`);
    assert.equal(found.evidence.absence_claim, undefined, `${item.id} does not fail, so it carries no absence claim`);

    // The single-dataset cap: only this read truncated at zero rows, the rest of the fixture healthy.
    const single = byId((await item.assess(createFakeClient({ [item.method]: async () => truncatedPage([], 40) }))).findings, item.id);
    assert.equal(single.status, "warn", `${item.id} under a single truncated empty read`);
    assert.match(single.summary, new RegExp(`^${escapeRegExp(truncatedBeforeVisibleSentence(item.read, item.row, item.property))} Partial inventory: only 0 of 40 `));
    assert.doesNotMatch(single.summary, UNIVERSAL_ABSENCE);
  }

  // (b) The three empty-fail findings render manual through absence_claim, never fail.
  for (const item of EMPTY_FAIL_RULE_CASES) {
    const found = byId(truncatedEmpty, item.id);
    assert.equal(found.status, "manual", `${item.id} on a truncated page with zero visible rows`);
    assert.notEqual(found.status, "fail");
    assert.equal(found.evidence.absence_claim, true, `${item.id} marks the fail as an absence claim`);
    assert.match(found.summary, new RegExp(`^${escapeRegExp(truncatedBeforeVisibleSentence(item.read, item.row, item.property))} Partial inventory: only 0 of 40 `));
    assert.match(found.summary, /so the absence this verdict rests on cannot be asserted for the unread rows\. Verdict: manual \(unknown\)\.$/);
    assert.doesNotMatch(found.summary, UNIVERSAL_ABSENCE);
    assert.equal(found.evidence[item.countLeaf], 0, `${item.id} counts the visible rows`);
    assert.ok(found.evidence.partial_inventory.some((partial) => partial.dataset === item.read && partial.seen === 0 && partial.total === 40));

    const single = byId((await item.assess(createFakeClient({ [item.method]: async () => truncatedPage([], 40) }))).findings, item.id);
    assert.equal(single.status, "manual", `${item.id} under a single truncated empty read`);
    assert.equal(single.evidence.absence_claim, true);
    assert.equal(
      single.summary,
      `${truncatedBeforeVisibleSentence(item.read, item.row, item.property)} Partial inventory: only 0 of 40 ${item.read} were read (sampled or truncated), so the absence this verdict rests on cannot be asserted for the unread rows. Verdict: manual (unknown).`,
    );
  }
  assert.equal(byId(truncatedEmpty, "CS-14").summary, "The host groups read was truncated before any host group was visible, so policy assignment coverage cannot be confirmed or ruled out from the visible rows. Partial inventory: only 0 of 40 hosts; 0 of 40 host groups were read (sampled or truncated), so the absence this verdict rests on cannot be asserted for the unread rows. Verdict: manual (unknown).");

  // CS-14 rests on whichever list is empty: zero hosts of a truncated host list with a complete group list is the
  // absence claim (manual); a complete empty group list is a real fail even when the host list is partial.
  const emptyHosts = findingById(await assessCrowdstrikeSensorCoverage(createFakeClient({ listHosts: async () => truncatedPage([], 40) })), "CS-14");
  assert.equal(emptyHosts.status, "manual");
  assert.equal(emptyHosts.evidence.absence_claim, true);
  assert.equal(emptyHosts.summary, "The hosts read was truncated before any host was visible, so host group assignment coverage cannot be confirmed or ruled out from the visible rows. Partial inventory: only 0 of 40 hosts were read (sampled or truncated), so the absence this verdict rests on cannot be asserted for the unread rows. Verdict: manual (unknown).");
  const noGroups = findingById(await assessCrowdstrikeSensorCoverage(createFakeClient({ listHostGroups: async () => [], listHosts: async () => truncatedPage([host()], 41) })), "CS-14");
  assert.equal(noGroups.status, "fail", "zero host groups on a complete read is a fail whatever the host list did");
  assert.equal(noGroups.evidence.absence_claim, undefined);
  assert.equal(noGroups.summary, "The host groups endpoint was readable but returned zero host groups, so no policy assignment coverage can be demonstrated; emptiness fails this control. Partial inventory: only 1 of 41 hosts were read (sampled or truncated), so this verdict cannot exceed warn.");

  // CS-22 with one visible but undated alert of 40: no dated alert is visible, so the scoped sentence carries the
  // undated clause and the partial clause, and the verdict is warn.
  const undatedAlerts = findingById(await assessCrowdstrikeResponseReadiness(createFakeClient({ listAlerts: async () => truncatedPage([{ composite_id: "a-9", severity: 90, status: "new" }], 40) })), "CS-22");
  assert.equal(undatedAlerts.status, "warn");
  assert.equal(undatedAlerts.summary, "The critical/high alerts read was truncated before any dated alert was visible, so response within the SLA cannot be confirmed or ruled out from the visible rows. 1 alerts have no created_timestamp timestamp; they were excluded from freshness counts and cap this verdict at warn. Partial inventory: only 1 of 40 critical/high alerts were read (sampled or truncated), so this verdict cannot exceed warn.");
  assert.doesNotMatch(undatedAlerts.summary, UNIVERSAL_ABSENCE);

  // Control: a complete empty read keeps the emptiness verdict and sentence with no partial clause and no absence claim.
  const completeEmpty = (await runAllCrowdstrikeAssessments(createEmptyClient())).flatMap((assessment) => assessment.findings);
  for (const item of EMPTINESS_RULE_CASES) {
    const found = byId(completeEmpty, item.id);
    assert.equal(found.status, "pass", `${item.id} on a complete empty read`);
    assert.match(found.summary, item.emptiness);
    assert.doesNotMatch(found.summary, /Partial inventory:|cannot be confirmed or ruled out/);
    assert.equal(found.evidence.partial_inventory, undefined);
  }
  for (const item of EMPTY_FAIL_RULE_CASES) {
    const found = byId(completeEmpty, item.id);
    assert.equal(found.status, "fail", `${item.id} on a complete empty read`);
    assert.match(found.summary, item.emptiness);
    assert.doesNotMatch(found.summary, /Partial inventory:|cannot be confirmed or ruled out/);
    assert.equal(found.evidence.absence_claim, undefined, `${item.id} on a complete read carries no absence claim`);
    assert.equal(found.evidence.partial_inventory, undefined);
  }

  // Control: a complete healthy read carries neither the scoped sentence nor an absence claim on any of the seven.
  const healthy = (await runAllCrowdstrikeAssessments(createFakeClient())).flatMap((assessment) => assessment.findings);
  for (const item of [...EMPTINESS_RULE_CASES, ...EMPTY_FAIL_RULE_CASES]) {
    const found = byId(healthy, item.id);
    assert.doesNotMatch(found.summary, /cannot be confirmed or ruled out|Partial inventory:/);
    assert.equal(found.evidence.absence_claim, undefined);
    assert.equal(found.evidence.partial_inventory, undefined);
  }

  // Control: a truncated page with visible rows keeps the count-scoped sentence over the visible rows (warn, never pass).
  const truncatedVisible = (await runAllCrowdstrikeAssessments(createPartialClient())).flatMap((assessment) => assessment.findings);
  for (const item of [...EMPTINESS_RULE_CASES, ...EMPTY_FAIL_RULE_CASES]) {
    const found = byId(truncatedVisible, item.id);
    assert.notEqual(found.status, "pass", `${item.id} under a truncated page with visible rows`);
    assert.doesNotMatch(found.summary, /cannot be confirmed or ruled out|emptiness/);
    assert.match(found.summary, /Partial inventory: only \d+ of \d+ /);
  }

  // Invariant over the whole run: a finding whose partial inventory shows zero visible rows is neither pass nor fail.
  let zeroRowFindings = 0;
  for (const found of truncatedEmpty) {
    const partials = found.evidence?.partial_inventory;
    if (!Array.isArray(partials) || !partials.some((partial) => partial.seen === 0)) continue;
    zeroRowFindings += 1;
    assert.ok(found.status === "warn" || found.status === "manual", `${found.id} renders ${found.status} from a truncated page with zero visible rows: ${found.summary}`);
  }
  assert.ok(zeroRowFindings >= 7, `the truncated empty run exercised the zero-row shape on ${zeroRowFindings} findings`);
});

// Addendum 4: on every Falcon surface, a 502 HTML body or a JSON error embedding a credential URL never reaches
// tool results, findings, summaries, or the bundle; the recorded error carries a status-and-length note instead.

/** Random-looking alphanumeric canaries; the leak assertions check every substring of them at lengths 6 through 24. */
const CS_CANARY = {
  bearer: "wzqUxGCZDwhWFQjgJ2",
  session: "u2UxNASwxbcU4UVgq8",
  apiKey: "rh5SzQeu7bq3ypyZtP",
  urlToken: "k2va2LcNRQ8MpbvEZs",
  clientSecret: "8y6YfvKmNBqS3ynUq3",
  accessToken: "R7cQYACujPskMA2jJD",
};
const CS_CANARY_URL = `https://api.example.com/v1/x?token=${CS_CANARY.urlToken}`;

function csCanaryHtml() {
  return [
    "<html><head><title>502 Bad Gateway</title></head><body>",
    `<p>The upstream request carried Authorization: Bearer ${CS_CANARY.bearer} and Set-Cookie: session=${CS_CANARY.session}.</p>`,
    `<p>Retry with x-api-key: ${CS_CANARY.apiKey}; the incident is tracked at ${CS_CANARY_URL} until resolved.</p>`,
    "</body></html>",
  ].join("");
}

const CS_CANARY_SURFACES = [
  "/oauth2/token",
  "/policy/combined/prevention/v1",
  "/policy/combined/response/v1",
  "/policy/combined/device-control/v1",
  "/policy/entities/device-control/v2",
  "/policy/combined/firewall/v1",
  "/fwmgr/entities/policies/v1",
  "/fwmgr/queries/rule-groups/v1",
  "/fwmgr/entities/rule-groups/v1",
  "/fwmgr/queries/rules/v1",
  "/fwmgr/entities/rules/v1",
  "/policy/combined/sensor-update/v2",
  "/policy/combined/sensor-update-builds/v1",
  "/devices/combined/devices/v1",
  "/devices/combined/host-groups/v1",
  "/user-management/queries/users/v1",
  "/user-management/entities/users/GET/v1",
  "/user-management/combined/user-roles/v2",
  "/user-management/queries/roles/v1",
  "/user-management/entities/roles/v1",
  "/api-clients/queries/api-clients/v1",
  "/api-clients/entities/api-clients/v1",
  "/discover/queries/hosts/v1",
  "/discover/combined/hosts/v1",
  "/alerts/queries/alerts/v2",
  "/alerts/combined/alerts/v1",
  "/policy/queries/ioa-exclusions/v1",
  "/policy/entities/ioa-exclusions/v1",
  "/policy/queries/ml-exclusions/v1",
  "/policy/entities/ml-exclusions/v1",
  "/policy/queries/sv-exclusions/v1",
  "/policy/entities/sv-exclusions/v1",
  "/zero-trust-assessment/queries/assessments/v1",
  "/identity-protection/queries/policy-rules/v1",
  "/identity-protection/entities/policy-rules/v1",
  "/real-time-response-audit/combined/sessions/v1",
];

function csHealthyResponse(path) {
  if (path === "/oauth2/token") return jsonResponse({ access_token: CS_CANARY.accessToken, expires_in: 1799 });
  if (path === "/user-management/queries/users/v1") return jsonResponse({ resources: ["u-1"], meta: { pagination: { total: 1 } } });
  if (path === "/user-management/entities/users/GET/v1") return jsonResponse({ resources: [{ uuid: "u-1", uid: "alice@example.com", status: "active", last_login_at: isoDaysAgo(1) }] });
  if (path === "/user-management/combined/user-roles/v2") return jsonResponse({ resources: [{ role_id: "falcon_analyst", role_name: "Falcon Analyst" }], meta: { pagination: { total: 1 } } });
  if (path === "/alerts/combined/alerts/v1") return jsonResponse({ resources: [{ composite_id: "a-1", severity: 90, status: "closed", created_timestamp: isoHoursAgo(30), seconds_to_resolved: 3600 }], meta: { pagination: { total: 1 } } });
  if (path === "/policy/combined/sensor-update-builds/v1") return jsonResponse({ resources: [{ build: "17306|n-1|tagged", sensor_version: "7.21.17306", platform: "windows" }] });
  if (path.includes("/queries/")) return jsonResponse({ resources: ["id-1"], meta: { pagination: { total: 1 } } });
  if (path.includes("/entities/")) {
    return jsonResponse({ resources: [{ id: "id-1", policy_id: "id-1", name: "Entity", enabled: true, groups: [{ id: "hg-1" }], platform_name: "Windows", rule_ids: ["r-1"], rule_group_ids: ["id-1"], default_inbound: "DENY", enforce: true, action: "ALLOW", description: "documented", scopes: [apiScope("hosts", "read")] }] });
  }
  return jsonResponse({
    resources: [{
      id: "id-1", name: "Combined", enabled: true, groups: [{ id: "hg-1" }], platform_name: "Windows", device_id: "aid-1", hostname: "ws-01",
      last_seen: isoDaysAgo(1), created_at: isoHoursAgo(2), deleted_at: isoHoursAgo(1.9), settings: { build: "17306|n-1|tagged", uninstall_protection: "ENABLED" },
    }],
    meta: { pagination: { total: 1 } },
  });
}

function csCanaryFetch(failing) {
  return async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.pathname === failing.path) {
      if (failing.flavor === "html") {
        return new Response(csCanaryHtml(), { status: 502, headers: { "content-type": "text/html; charset=utf-8" } });
      }
      // Credential-free failure flavors for the fixed-text harvest: a plain proxy page, an unrecognized JSON shape, a documented error.
      if (failing.flavor === "plainHtml") return new Response("<html><head><title>502 Bad Gateway</title></head><body>upstream unavailable</body></html>", { status: 502, headers: { "content-type": "text/html; charset=utf-8" } });
      if (failing.flavor === "opaqueJson") return jsonResponse({ unexpected: { shape: true } }, { status: 403 });
      if (failing.flavor === "plainJson") return jsonResponse({ errors: [{ code: 403, message: "access denied, authorization failed" }] }, { status: 403 });
      return jsonResponse({ errors: [{ code: 403, message: `access denied for this API client; see ${CS_CANARY_URL} for the scope that is missing` }] }, { status: 403 });
    }
    return csHealthyResponse(url.pathname);
  };
}

/** No canary survives in any substring at lengths 6 through 24. */
function assertCsCanariesAbsent(text, context) {
  assertFragmentsAbsent(assert, text, Object.values(CS_CANARY), context);
}

test("addendum 4: on every Falcon surface a 502 HTML body or a JSON error embedding a credential URL never reaches results or the bundle, and the recorded error carries a status-and-length note", async () => {
  const runs = [];
  for (const path of CS_CANARY_SURFACES) {
    for (const flavor of ["html", "json"]) {
      const base = createTempBase("grclanker-cs-canary-");
      const config = sampleConfig({ clientSecret: CS_CANARY.clientSecret });
      const client = new CrowdstrikeApiClient(config, { fetchImpl: csCanaryFetch({ path, flavor }), sleep: async () => {}, retryLimit: 0 });
      const access = await checkCrowdstrikeAccess(client);
      const assessments = await runAllCrowdstrikeAssessments(client);
      const result = await exportCrowdstrikeAuditBundle(client, config, base);
      const files = readBundleFiles(result.outputDir);
      const zipEntries = readZipEntries(result.zipPath);
      const context = `${path} (${flavor})`;

      assertCsCanariesAbsent(JSON.stringify(access), `${context} check_access`);
      assertCsCanariesAbsent(JSON.stringify(assessments), `${context} assessments`);
      for (const [name, content] of files) assertCsCanariesAbsent(content, `${context} bundle ${name}`);
      for (const [name, content] of zipEntries) assertCsCanariesAbsent(content, `${context} zip ${name}`);

      const errorStrings = [
        ...access.surfaces.map((surface) => surface.error).filter(Boolean),
        ...assessments.flatMap((assessment) => assessment.errors),
        ...(files.get("_errors.log") ?? "").split("\n").filter(Boolean),
      ];
      assert.ok(errorStrings.length > 0, `${context}: the failing surface must be exercised by the access check, an assessment, or the export`);
      for (const errorString of errorStrings) {
        if (flavor === "html") {
          assert.match(errorString, /\(502\)[^\n]*: non-JSON body \(text\/html, \d+ bytes\)/, `${context}: ${errorString}`);
        } else {
          assert.match(errorString, /\(403\)[^\n]*https:\/\/api\.example\.com\/v1\/x\?\[REDACTED\]/, `${context}: ${errorString}`);
        }
      }
      runs.push(context);
    }
  }
  assert.equal(runs.length, CS_CANARY_SURFACES.length * 2);
});

/**
 * Round 4 item 2 (data-side carrier class): the healthy Falcon fixture with reviewer B's fifteen carrier
 * forms, the configured secrets bare in prose, and the must-survive controls appended to every text-like
 * field of every response. Nothing planted may survive in any 6-to-24-character window of the access
 * check, the assessments, the bundle files, or the zip entries; the controls (a hostname, a table name,
 * a UUID, a quoted non-credential header, prose using a scheme word) and the bare token must.
 */
test("rule 9 data side: a credential carried in any free-text field of any Falcon response never reaches a snapshot, evidence, summary, bundle file, or zip entry, while identifiers in the same fields stay", async () => {
  const configuredSecrets = [CONFIGURED_SECRET_CANARIES.crowdstrikeClientSecret];
  const suffix = carrierSuffix(configuredSecrets);
  const harvest = async (injected) => {
    const config = sampleConfig({ clientSecret: configuredSecrets[0] });
    const healthyFetch = csCanaryFetch({ path: null, flavor: null });
    const client = new CrowdstrikeApiClient(config, { fetchImpl: injected ? injectingFetch(healthyFetch, suffix) : healthyFetch, sleep: async () => {}, retryLimit: 0 });
    const access = await checkCrowdstrikeAccess(client);
    const assessments = await runAllCrowdstrikeAssessments(client);
    const base = createTempBase("grclanker-cs-text-fields-");
    try {
      const result = await exportCrowdstrikeAuditBundle(client, config, base);
      return [
        ["check_access", JSON.stringify(access)],
        ["assessments", JSON.stringify(assessments)],
        ...[...readBundleFiles(result.outputDir)].map(([name, content]) => [`bundle file ${name}`, content]),
        ...[...readZipEntries(result.zipPath)].map(([name, content]) => [`zip entry ${name}`, content]),
      ];
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  };
  const healthyTexts = await harvest(false);
  const texts = await harvest(true);
  assertTextFieldCarriers(assert, texts, { configuredSecrets, healthyTexts });
});

/**
 * CodeRabbit (#62, second review) items 2 and 3: a container nested past MAX_REDACTION_DEPTH in a Falcon
 * response is replaced by the marker, never passed through unscrubbed. The first prevention policy (kept whole
 * in core_data/prevention_policies/prevention_policies.json) carries the three planted fields; the walker's
 * root is the CrowdstrikePage, so items is depth 1, the policy depth 2, and the planted fields depth 3.
 */
test("CodeRabbit (#62, second review) items 2 and 3: a CrowdStrike record container nested past MAX_REDACTION_DEPTH is replaced whole, the leaf at the maximum depth is scrubbed in place, and no planted window reaches any output", async () => {
  const harvest = async (planted) => {
    const config = sampleConfig();
    const healthyFetch = csCanaryFetch({ path: null, flavor: null });
    const planting = plantingFetch(healthyFetch, (url) => url.pathname === "/policy/combined/prevention/v1", (payload) => {
      Object.assign(payload.resources[0], deepFields(3));
      return payload;
    });
    const client = new CrowdstrikeApiClient(config, { fetchImpl: planted ? planting : healthyFetch, sleep: async () => {}, retryLimit: 0 });
    const access = await checkCrowdstrikeAccess(client);
    const assessments = await runAllCrowdstrikeAssessments(client);
    const base = createTempBase("grclanker-cs-deep-nesting-");
    try {
      const result = await exportCrowdstrikeAuditBundle(client, config, base);
      return [
        ["check_access", JSON.stringify(access)],
        ["assessments", JSON.stringify(assessments)],
        ...[...readBundleFiles(result.outputDir)].map(([name, content]) => [`bundle file ${name}`, content]),
        ...[...readZipEntries(result.zipPath)].map(([name, content]) => [`zip entry ${name}`, content]),
      ];
    } finally {
      rmSync(base, { recursive: true, force: true });
    }
  };
  assertDeepCanariesWellFormed(assert, await harvest(false));
  assertDeepNesting(assert, await harvest(true));
});

test("planted values self-check: every canary and planted secret is alphanumeric, distinct in every 6-character window, and no window occurs in the healthy fixtures, the sample configuration, or a healthy bundle", async () => {
  const base = createTempBase("grclanker-cs-planted-self-check-");
  const client = new CrowdstrikeApiClient(sampleConfig(), { fetchImpl: csCanaryFetch({ path: "/no-surface-fails", flavor: "json" }), sleep: async () => {}, retryLimit: 0 });
  const payloads = [await checkCrowdstrikeAccess(client), ...(await runAllCrowdstrikeAssessments(client))];
  const result = await exportCrowdstrikeAuditBundle(client, sampleConfig(), base);
  assert.equal(result.errorCount, 0);
  const fakeBundle = await exportCrowdstrikeAuditBundle(createFakeClient(), sampleConfig(), createTempBase("grclanker-cs-planted-self-check-fake-"));
  assertPlantedValuesWellFormed(assert, {
    ...Object.fromEntries(Object.entries(CS_CANARY).map(([name, value]) => [`CS_CANARY.${name}`, value])),
    ...Object.fromEntries(Object.entries(FAKE_CROWDSTRIKE_SECRETS).map(([name, value]) => [`FAKE_CROWDSTRIKE_SECRETS.${name}`, value])),
    ...Object.fromEntries(Object.entries(CONFIG_CANARIES).map(([name, value]) => [`CONFIG_CANARIES.${name}`, value])),
    SAMPLE_CLIENT_SECRET,
  }, [
    ["sample configuration", JSON.stringify({ ...sampleConfig(), clientSecret: null })],
    ["healthy tool payloads", JSON.stringify(payloads)],
    ...[...readBundleFiles(result.outputDir)].map(([name, content]) => [`healthy bundle ${name}`, content]),
    ...[...readBundleFiles(fakeBundle.outputDir)].map(([name, content]) => [`fake-client bundle ${name}`, content]),
  ]);
});

/** Every Falcon dataset the collectors read, as the summaries' inventories and the not-collected markers name them. */
const CROWDSTRIKE_DATASETS = [...new Set([
  ...CROWDSTRIKE_DENIALS.flatMap((denial) => [
    ...Object.values(denial.markers ?? {}),
    ...Object.values(denial.nested ?? {}).flatMap((entries) => Object.values(entries)),
  ]),
  "discover managed hosts",
  "zero trust assessment below-threshold totals",
  "user roles",
  "sensor builds (linux)",
])];

const CS_SAMPLE_DENIAL = "CrowdStrike request failed for /policy/combined/prevention/v1 (403): access denied, authorization failed";

/**
 * The standing fixed texts CrowdStrike emits, rendered with sample paths and names: the config loader read
 * and parse messages, the non-JSON and opaque-body notes, the timeout, the inventory states (read, read
 * truncated, unread, not requested), the `not requested:` marker errors naming the parent read, the scope
 * notes, and the corollary summary templates. Each must come back from CrowdstrikeHttpError's pass unchanged.
 */
const CROWDSTRIKE_FIXED_TEXTS = [
  // The resolver's own messages, which reach check_access, assess, and export results live.
  "CrowdStrike API credentials are required. Set CS_CLIENT_ID and CS_CLIENT_SECRET, configure ~/.crowdstrike/config.json, or pass client_id and client_secret explicitly.",
  "Unknown CrowdStrike cloud \"mars-1\". Use one of: us-1, us-2, eu-1, us-gov-1, us-gov-2.",
  "Falcon API client secret. Defaults to CS_CLIENT_SECRET (or FALCON_CLIENT_SECRET), then the config file.",
  "Unable to read CrowdStrike config file /home/svc/.crowdstrike/config.json (ENOENT)",
  "Unable to read CrowdStrike config file /tmp/grclanker-crowdstrike-loader-Ab3dEf/directory.json (EISDIR)",
  "Unable to read CrowdStrike config file /tmp/grclanker-crowdstrike-loader-Ab3dEf/locked.json (EACCES)",
  "Unable to parse CrowdStrike config file: invalid JSON in /tmp/grclanker-crowdstrike-loader-Ab3dEf/short.json",
  "Unable to parse CrowdStrike config file: invalid JSON in /tmp/grclanker-crowdstrike-loader-Ab3dEf/trailing-comma.json at line 3",
  "Unable to parse CrowdStrike config file: /home/svc/.crowdstrike/config.json must contain a JSON object",
  "CrowdStrike OAuth2 token request failed (502): non-JSON body (text/html, 5120 bytes)",
  "CrowdStrike OAuth2 token request failed (401): access denied, invalid bearer token",
  "CrowdStrike request failed for /policy/combined/prevention/v1 (403): JSON body without a documented error field (application/json, 27 bytes)",
  "CrowdStrike request failed for /user-management/queries/users/v1 (429): non-JSON body (text/plain, 12 bytes)",
  "CrowdStrike request timed out after 30000ms: /devices/combined/devices/v1",
  CS_SAMPLE_DENIAL,
  `unread (${CS_SAMPLE_DENIAL})`,
  "not requested (the device control policies list was not read)",
  "not requested (the firewall policies list was not read)",
  "not requested (the sensor update policies list was not read)",
  "not requested (the user uuid list was not read)",
  "not requested (the user details were not read)",
  "not requested (the discover unmanaged hosts count was not read)",
  "not requested (the zero trust assessment totals count was not read)",
  "not requested: the user uuid list was not read",
  "not requested: the device control policies list returned no policy ids to look up",
  "not requested: no enabled and host-assigned sensor update policy named a platform to look up",
  "read (12 items)",
  "read, truncated (500 of 5000 items)",
  "read (3 records)",
  "read (total 3)",
  "read (no server-side total reported)",
  "read for 2 of 5 users (3 lookups failed, 0 truncated)",
  "Scope: results cover the CID that issued the API client; Flight Control child tenants need CS_MEMBER_CID runs.",
  "issuing CID only (Flight Control children need CS_MEMBER_CID runs)",
  "host group Workstations-US-East-2026 and sensor update policy platform_default on cloud us-1",
  "None of the enabled prevention policies expose ScriptBasedExecutionMonitoring, InterpreterProtection, EngineProtectionV2",
  "the prevention policies list was not read, so CS-01 is manual and the enabled policy count renders null",
  "1 of 3 sampled hosts (srv-01) run a sensor build older than n-2; the host list was truncated at 500 of 5000, so the unread hosts are not counted",
  "alice@example.com holds Falcon Administrator and has not logged in for 120 days; admin users from a partial read are not named",
  // The zero-visible-rows sentences of a truncated page (round 3 rulings a and b).
  "The hosts read was truncated before any host was visible, so sensor deployment coverage cannot be confirmed or ruled out from the visible rows.",
  "The host groups read was truncated before any host group was visible, so policy assignment coverage cannot be confirmed or ruled out from the visible rows.",
  "The IOA exclusions read was truncated before any exclusion was visible, so suppression of detection logic cannot be confirmed or ruled out from the visible rows.",
  "The ML exclusions read was truncated before any exclusion was visible, so suppression of machine learning coverage cannot be confirmed or ruled out from the visible rows.",
  "The sensor visibility exclusions read was truncated before any exclusion was visible, so paths hidden from the sensor cannot be confirmed or ruled out from the visible rows.",
  "The critical/high alerts read was truncated before any dated alert was visible, so response within the SLA cannot be confirmed or ruled out from the visible rows.",
  "The Identity Protection policy rules read was truncated before any rule was visible, so identity-based lateral movement prevention cannot be confirmed or ruled out from the visible rows.",
  "The containment status filter read was truncated before any matching host was visible, so active containment cannot be confirmed or ruled out from the visible rows; document each containment and its incident reference.",
];

/** Addendum 7 must-keep table for CrowdStrike: paths and datasets, clouds and tenants, principals, finding ids, and the standing fixed texts. */
function crowdstrikeKeepTable() {
  return {
    paths: CS_CANARY_SURFACES,
    tables: CROWDSTRIKE_DATASETS,
    tenants: [
      "api.crowdstrike.com",
      "https://api.crowdstrike.com",
      "api.us-2.crowdstrike.com",
      "api.eu-1.crowdstrike.com",
      "api.laggar.gcw.crowdstrike.com",
      "us-1",
      "us-gov-1",
      "prod-us-east-2026",
      "Acme_Production_Org",
    ],
    principals: [
      "alice@example.com",
      "bob.user@acme.example",
      // Falcon user uuids are canonical UUIDs.
      "3f2a1c4e-8b7d-4e6f-9a0b-1c2d3e4f5a6b",
      "falcon_administrator",
      "Falcon Administrator",
      "falcon_analyst",
      "grclanker audit",
      "Workstations-US-East-2026",
      "ws-01",
      "srv-01",
      "platform_default",
    ],
    findingIds: ALL_CONTROL_IDS,
    fixedTexts: CROWDSTRIKE_FIXED_TEXTS,
  };
}

test("scrub boundary: bare name-shaped values stay, carriers and registered secrets (in every encoded form) and real token shapes go, in CrowdstrikeHttpError; the addendum 7 must-keep table survives in isolation and in sentences", () => {
  const fetchImpl = async () => jsonResponse({});
  const mustKeep = [
    "Falcon request failed (502) for /oauth2/token: non-JSON body (text/html, 5120 bytes)",
    "Falcon request failed (403) for /policy/combined/prevention/v1: JSON body without documented error fields (application/json, 42 bytes)",
    "Unable to read CrowdStrike config file /home/svc/.crowdstrike/config.json (ENOENT)",
    "Unable to parse CrowdStrike config file: invalid JSON in /tmp/grclanker-crowdstrike-loader-Ab3dEf/short.json",
    "host group Workstations-US-East-2026 and sensor update policy platform_default on cloud us-1",
  ];
  const keepTable = crowdstrikeKeepTable();
  assert.equal(keepTable.findingIds.length, 25, "every CrowdStrike finding id is in the table");
  assert.ok(keepTable.tables.includes("prevention policies") && keepTable.tables.includes("sensor builds (windows)") && keepTable.tables.includes("user roles (u-admin)"));
  // The client constructor is the registration path (rememberSecrets on the configured client secret); the error constructor is the pass.
  assertScrubBoundary({
    scrub: (text) => new CrowdstrikeHttpError(text, 502, "/x").message,
    registerSecret: (secret) => new CrowdstrikeApiClient(sampleConfig({ clientSecret: secret }), { fetchImpl }),
    mustKeep,
    keepTable,
  });
});

test("round 7 note 1: every fixed-text message CrowdStrike emits (loader, opaque body, timeout, inventory states, not requested markers, scope notes, corollary summaries) comes back from CrowdstrikeHttpError's pass unchanged", async () => {
  const texts = new Set(CROWDSTRIKE_FIXED_TEXTS);
  const scrub = (text) => new CrowdstrikeHttpError(text, 502, "/x").message;
  const assessAndExport = async (client, config, texts) => {
    collectFixedTexts(await checkCrowdstrikeAccess(client), texts);
    collectFixedTexts(await runAllCrowdstrikeAssessments(client), texts);
    const exported = await exportCrowdstrikeAuditBundle(client, config, createTempBase("grclanker-cs-fixed-text-bundle-"));
    const files = readBundleFiles(exported.outputDir);
    for (const line of logLines(files.get("_errors.log"))) texts.add(line);
    for (const [name, content] of files) {
      if ((name.startsWith("analysis/") || name.startsWith("core_data/")) && name.endsWith(".json")) collectFixedTexts(JSON.parse(content), texts);
    }
  };

  // The loader's own read and parse messages on real failing files, plus the shape guard.
  for (const item of configLoaderCases({ format: "json", displayName: "CrowdStrike", fileNoun: "config file", extension: ".json" })) {
    if (item.skip) continue;
    assert.throws(() => resolveCrowdstrikeConfiguration({ config_file: item.path }, {}), (error) => {
      texts.add(error.message);
      return true;
    });
  }
  const arrayPath = join(createTempBase("grclanker-cs-fixed-text-"), "config.json");
  writeFileSync(arrayPath, "[]\n");
  assert.throws(() => resolveCrowdstrikeConfiguration({ config_file: arrayPath }, {}), (error) => {
    texts.add(error.message);
    return true;
  });

  // The resolver's own messages on the real path with an empty environment and an empty home: no
  // credentials, and credentials with an unknown cloud alias.
  const emptyHome = createTempBase("grclanker-cs-fixed-text-home-");
  const resolverMessages = [
    collectThrownMessage(texts, () => resolveCrowdstrikeConfiguration({}, {}, emptyHome), "no credentials"),
    collectThrownMessage(texts, () => resolveCrowdstrikeConfiguration({ client_id: "falcon-client", client_secret: "falcon-client-secret", cloud: "mars-1" }, {}, emptyHome), "unknown cloud"),
  ];
  assert.ok(resolverMessages.some((message) => /^CrowdStrike API credentials are required\./.test(message)), "the resolver rendered its credentials-required message");
  assert.ok(resolverMessages.some((message) => /^Unknown CrowdStrike cloud "mars-1"\. Use one of: /.test(message)), "the resolver rendered its unknown-cloud message");

  // Every tool label, description, and argument description the integration registers.
  const registered = [];
  registerCrowdstrikeTools({ registerTool: (tool) => registered.push(tool) });
  const toolTexts = collectToolTexts(registered);
  assert.ok([...toolTexts].some((text) => /CS_CLIENT_SECRET/.test(text)), "the tool schemas carry the client secret argument description");
  for (const text of toolTexts) texts.add(text);

  // Every surface under three credential-free failure flavors (plain proxy page, unrecognized JSON shape, documented
  // error): the access check, every assessment, the analysis and core_data files, and the error log render the
  // opaque-body notes, the unread and not requested states, the markers naming the parent read, and the demotion
  // templates on real paths.
  for (const path of CS_CANARY_SURFACES) {
    for (const flavor of ["plainHtml", "opaqueJson", "plainJson"]) {
      const config = sampleConfig();
      const client = new CrowdstrikeApiClient(config, { fetchImpl: csCanaryFetch({ path, flavor }), sleep: async () => {}, retryLimit: 0 });
      await assessAndExport(client, config, texts);
    }
  }

  // The fake clients: healthy, every read forbidden, one dataset denied at a time, and every paged read truncated.
  await assessAndExport(createFakeClient(), sampleConfig(), texts);
  await assessAndExport(createForbiddenClient(), sampleConfig(), texts);
  for (const denial of CROWDSTRIKE_DENIALS) {
    collectFixedTexts(await runAllCrowdstrikeAssessments(createFakeClient({ [denial.method]: forbidden(denial.endpoint) })), texts);
  }
  const partial = createFakeClient();
  for (const name of PAGED_METHODS) {
    const inner = partial[name];
    partial[name] = async (...args) => {
      const result = await inner(...args);
      return { ...result, total: Math.max(result.items.length * 10, 10), truncated: true };
    };
  }
  await assessAndExport(partial, sampleConfig(), texts);
  // Every paged read truncated at zero visible rows renders the cannot-be-confirmed-or-ruled-out sentences live.
  await assessAndExport(createTruncatedEmptyClient(), sampleConfig(), texts);

  // The timeout wording through the real client.
  const timingOut = new CrowdstrikeApiClient(sampleConfig({ timeoutMs: 1000 }), {
    fetchImpl: async (_input, init) => new Promise((_resolve, reject) => init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")))),
    sleep: async () => {},
    retryLimit: 0,
  });
  await assert.rejects(timingOut.getJson("/devices/combined/devices/v1"), (error) => {
    texts.add(error.message);
    return true;
  });

  const checked = assertFixedTextsSurvive(scrub, texts, "CrowdStrike fixed texts");
  assert.ok(checked >= CROWDSTRIKE_FIXED_TEXTS.length + 40, `the harvest rendered texts beyond the standing list (${checked})`);
  assert.ok([...texts].some((text) => /^unread \(/.test(text)), "the harvest rendered an unread inventory state");
  assert.ok([...texts].some((text) => /^not requested \(/.test(text)), "the harvest rendered a not requested inventory state");
  assert.ok([...texts].some((text) => /^not requested: /.test(text)), "the harvest rendered a not requested marker error");
  assert.ok([...texts].some((text) => /^read, truncated \(/.test(text)), "the harvest rendered a truncated inventory state");
  assert.ok([...texts].some((text) => /non-JSON body \(text\/html, \d+ bytes\)/.test(text)), "the harvest rendered a status-and-length note");
  assert.ok([...texts].some((text) => /JSON body without a documented error field \(application\/json, \d+ bytes\)/.test(text)), "the harvest rendered an opaque JSON note");
  assert.ok([...texts].some((text) => /timed out after \d+ms/.test(text)), "the harvest rendered the timeout wording");
  assert.ok([...texts].some((text) => /^The hosts read was truncated before any host was visible, so sensor deployment coverage cannot be confirmed or ruled out from the visible rows\. Partial inventory: only 0 of 40 hosts/.test(text)), "the harvest rendered a zero-visible-rows sentence live");
});

test("round 7 note 2: credentials and the config file path set through the environment survive an unrelated argument, and the source chain names the environment", () => {
  const base = createTempBase("grclanker-cs-env-survives-");
  const configPath = join(base, "falcon.json");
  writeFileSync(configPath, JSON.stringify({ client_id: "file-client-id", client_secret: "file-client-secret", cloud: "eu-1", member_cid: "file-member-cid" }));
  for (const env of [
    { CS_CONFIG_FILE: configPath, CS_CLIENT_ID: "env-client-id", CS_CLIENT_SECRET: "env-client-secret-value" },
    { CS_CONFIG_FILE: configPath, FALCON_CLIENT_ID: "env-client-id", FALCON_CLIENT_SECRET: "env-client-secret-value" },
  ]) {
    for (const [label, unrelated] of [
      ["cloud", { cloud: "us-2" }],
      ["timeout_seconds", { timeout_seconds: 45 }],
      ["member_cid", { member_cid: "arg-member-cid" }],
    ]) {
      const resolved = resolveCrowdstrikeConfiguration(unrelated, env, base);
      const context = `${Object.keys(env).join(",")} with ${label}`;
      assert.equal(resolved.clientId, "env-client-id", `${context}: the environment client id resolves over the file`);
      assert.equal(resolved.clientSecret, "env-client-secret-value", `${context}: the environment client secret resolves over the file`);
      assert.ok(resolved.sourceChain.includes("environment-client-id"), `${context}: the source chain names the environment: ${JSON.stringify(resolved.sourceChain)}`);
      assert.ok(resolved.sourceChain.includes("environment-client-secret"), context);
      assert.ok(resolved.sourceChain.includes(`config:${configPath}`), `${context}: the source chain names the config file from the environment`);
      assert.ok(!resolved.sourceChain.includes("arguments-client-id"), `${context}: the unrelated argument does not claim the client id`);
      if (label === "cloud") assert.equal(resolved.baseUrl, "https://api.us-2.crowdstrike.com", context);
      else assert.equal(resolved.baseUrl, "https://api.eu-1.crowdstrike.com", `${context}: the file value not set elsewhere still applies`);
      if (label === "timeout_seconds") assert.equal(resolved.timeoutMs, 45000, context);
      assert.equal(resolved.memberCid, label === "member_cid" ? "arg-member-cid" : "file-member-cid", context);
    }
  }
  // An argument object whose credential keys are present but undefined must not shadow the environment.
  const env = { CS_CONFIG_FILE: configPath, CS_CLIENT_ID: "env-client-id", CS_CLIENT_SECRET: "env-client-secret-value" };
  const shadowed = resolveCrowdstrikeConfiguration({ client_id: undefined, client_secret: undefined, cloud: "us-2" }, env, base);
  assert.equal(shadowed.clientId, "env-client-id");
  assert.equal(shadowed.clientSecret, "env-client-secret-value");
  assert.deepEqual(shadowed.sourceChain, [`config:${configPath}`, "environment-client-id", "environment-client-secret", "arguments-cloud", "config-member-cid"]);
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
