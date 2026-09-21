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
  } = overrides;
  const categories = [
    {
      name: "Machine Learning",
      settings: [
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
  return { id, name, platform_name: platform, enabled, prevention_settings: categories };
}

function passingPreventionPolicies() {
  return [
    preventionPolicy(),
    preventionPolicy({ id: "prev-mac", name: "Mac Hardened", platform: "Mac", includeExploit: false, includeScript: false }),
    preventionPolicy({ id: "prev-linux", name: "Linux Hardened", platform: "Linux", includeExploit: false, includeScript: false }),
  ];
}

function responsePolicy(overrides = {}) {
  const { rtr = true, customScripts = false, enabled = true } = overrides;
  return {
    id: "resp-1",
    name: "Default Response",
    platform_name: "Windows",
    enabled,
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
    policies: [{ id: "dc-1", name: "USB Lockdown", platform_name: "Windows", enabled: true }],
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

function createFakeClient(overrides = {}) {
  const prevention = passingPreventionPolicies();
  const deviceControl = passingDeviceControl();
  const firewall = passingFirewall();
  const users = passingUsers();
  const hosts = [host(), host({ device_id: "aid-2", hostname: "ws-02" }), host({ device_id: "aid-3", hostname: "srv-01", platform_name: "Linux" })];

  return {
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
    listSensorUpdatePolicies: async () => [
      { id: "su-1", name: "Auto N-1", platform_name: "Windows", enabled: true, settings: { build: "17306|n-1|tagged", uninstall_protection: "ENABLED", stage: "prod" } },
    ],
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
    listApiClients: async () => [{ id: "api-1", name: "grclanker audit", scopes: ["prevention-policies:read", "hosts:read", "user-management:read"] }],
    listIoaExclusions: async () => [{ id: "ioa-1", name: "Backup agent", ifn_regex: "C:\\\\Program Files\\\\Backup\\\\agent\\.exe", cl_regex: ".*--quiet.*", applied_globally: false, groups: [{ id: "hg-1" }] }],
    listMlExclusions: async () => [{ id: "ml-1", value: "D:\\Builds\\artifacts\\*.pdb", excluded_from: ["blocking"], applied_globally: false, groups: [{ id: "hg-1" }] }],
    listSensorVisibilityExclusions: async () => [{ id: "sv-1", value: "/opt/vendor/agent/collector", applied_globally: false, groups: [{ id: "hg-1" }] }],
    listIdentityProtectionRules: async () => [{ id: "idp-1", name: "Block stale accounts", enabled: true, simulationMode: false, action: "BLOCK", trigger: "AUTHENTICATION" }],
    ...overrides,
  };
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

  assert.deepEqual(policies.map((policy) => policy.id), ["p-1", "p-2", "p-3"]);
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
  assert.deepEqual(discovered.map((item) => item.id), ["d-1", "d-2"]);

  const hosts = await client.listHosts(10);
  assert.deepEqual(hosts.map((item) => item.device_id), ["h-1", "h-2"]);

  const alerts = await client.listAlerts("severity:>=70", 10);
  assert.deepEqual(alerts.map((item) => item.composite_id), ["a-1", "a-2"]);
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

  assert.deepEqual(policies.map((policy) => policy.id), ["p-1"]);
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
      { id: "su-off", name: "Updates Off", platform_name: "Windows", enabled: true, settings: { build: "", uninstall_protection: "DISABLED" } },
      { id: "su-old", name: "Pinned Old", platform_name: "Windows", enabled: true, settings: { build: "16000", uninstall_protection: "ENABLED" } },
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
    listApiClients: async () => Array.from({ length: 4 }, (_, index) => ({ id: `api-${index}`, name: `integration-${index}`, scopes: ["prevention-policies:write", "hosts:write"] })),
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
