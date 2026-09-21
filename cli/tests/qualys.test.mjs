import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  QUALYS_PLATFORMS,
  QualysApiClient,
  assessQualysAdministration,
  assessQualysAssetInventory,
  assessQualysScanCoverage,
  assessQualysVulnerabilityManagement,
  checkQualysAccess,
  exportQualysAuditBundle,
  parseCsv,
  parseXml,
  resolveQualysConfiguration,
  resolveQualysPlatform,
  resolveSecureOutputPath,
  xmlToRecord,
} from "../dist/extensions/grc-tools/qualys.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";

const NOW = new Date();
const daysAgo = (days) => new Date(NOW.getTime() - days * 86_400_000).toISOString().replace(/\.\d{3}Z$/, "Z");

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function sampleConfig(overrides = {}) {
  return {
    username: "acme_api",
    password: "s3cret-value",
    authMode: "basic",
    platform: "US1",
    baseUrl: "https://qualysapi.qualys.com",
    gatewayUrl: "https://gateway.qg1.apps.qualys.com",
    timeoutMs: 30_000,
    maxRetries: 2,
    lookbackDays: 30,
    sourceChain: ["tests"],
    ...overrides,
  };
}

function xmlResponse(body, options = {}) {
  return new Response(body, {
    status: options.status ?? 200,
    headers: { "content-type": "application/xml", ...(options.headers ?? {}) },
  });
}

function jsonResponse(value, options = {}) {
  return new Response(JSON.stringify(value), {
    status: options.status ?? 200,
    headers: { "content-type": "application/json", ...(options.headers ?? {}) },
  });
}

function qpsResponse(entity, items, extra = {}) {
  return {
    ServiceResponse: {
      responseCode: "SUCCESS",
      count: items.length,
      hasMoreRecords: "false",
      data: items.map((item) => ({ [entity]: item })),
      ...extra,
    },
  };
}

function createFakeClient(overrides = {}, config = sampleConfig()) {
  const base = {
    getResolvedConfig: () => config,
    listScheduledScans: async () => [],
    listScans: async () => [],
    listHosts: async () => [],
    listOptionProfiles: async () => [],
    listExcludedIps: async () => [],
    listAssetGroups: async () => [],
    listAppliances: async () => [],
    listAuthRecordSummary: async () => [],
    listCompliancePolicies: async () => [],
    listDetections: async () => [],
    listKnowledgeBase: async () => [],
    listScheduledReports: async () => [],
    listReports: async () => [],
    listActivityLog: async () => [],
    searchUsers: async () => [],
    searchCloudAgents: async () => [],
    searchConnectors: async () => [],
    searchTags: async () => [],
    searchWebApps: async () => [],
    searchWasScans: async () => [],
    searchWasAuthRecords: async () => [],
    searchWasSchedules: async () => [],
    lastRateLimit: {},
  };
  return { ...base, ...overrides };
}

const failing = (message) => async () => {
  throw new Error(message);
};

function findingById(result, id) {
  const found = result.findings.find((item) => item.id === id);
  assert.ok(found, `expected finding ${id}`);
  return found;
}

const healthyFixtures = {
  listScheduledScans: async () => [
    { ID: "1", ACTIVE: "1", TITLE: "Internal weekly", TARGET: "10.0.0.0/24", ISCANNER_NAME: "dmz-scanner", ASSET_GROUP_TITLE_LIST: { ASSET_GROUP_TITLE: "Internal" }, SCHEDULE: { NEXTLAUNCH_UTC: daysAgo(-2) } },
    { ID: "2", ACTIVE: "1", TITLE: "Perimeter", TARGET: "203.0.113.0/28", ASSET_GROUP_TITLE_LIST: { ASSET_GROUP_TITLE: "DMZ" }, SCHEDULE: { NEXTLAUNCH_UTC: daysAgo(-1) } },
  ],
  listScans: async () => [{ REF: "scan/1", STATUS: { STATE: "Finished" } }],
  listHosts: async () => [
    { ID: "100", IP: "10.0.0.5", OS: "Windows Server 2022", TRACKING_METHOD: "Cloud Agent", LAST_VULN_SCAN_DATETIME: daysAgo(2), LAST_VM_AUTH_SCANNED_DATE: daysAgo(2), TAGS: { TAG: [{ TAG_ID: "1", NAME: "PCI" }] } },
    { ID: "101", IP: "10.0.0.6", OS: "Ubuntu Linux 22.04", TRACKING_METHOD: "Cloud Agent", LAST_VULN_SCAN_DATETIME: daysAgo(3), LAST_VM_AUTH_SCANNED_DATE: daysAgo(3), TAGS: { TAG: { TAG_ID: "2", NAME: "Prod" } } },
  ],
  listOptionProfiles: async () => [{ BASIC_INFO: { ID: "7", GROUP_NAME: "Authenticated Full" }, SCAN: { AUTHENTICATION: "Windows, Unix" } }],
  listExcludedIps: async () => [],
  listAssetGroups: async () => [
    { ID: "10", TITLE: "Internal", IP_SET: { IP_RANGE: "10.0.0.1-10.0.0.254" } },
    { ID: "11", TITLE: "DMZ", IP_SET: { IP: "203.0.113.5" } },
  ],
  listAppliances: async () => [{ ID: "1", NAME: "dmz-scanner", STATUS: "Online", SOFTWARE_VERSION: "12.7", ML_LATEST: "12.7", HEARTBEATS_MISSED: "0" }],
  listAuthRecordSummary: async () => [{ type: "windows", count: 2 }, { type: "unix", count: 3 }],
  listCompliancePolicies: async () => [{ ID: "5", TITLE: "CIS Baseline", IS_ACTIVE: "1", ASSET_GROUP_IDS: "10,11" }],
  listDetections: async () => [
    { host_id: "100", QID: "91000", SEVERITY: "5", STATUS: "Active", FIRST_FOUND_DATETIME: daysAgo(3), QDS: { "@severity": "HIGH", "#text": "72" } },
    { host_id: "101", QID: "38000", SEVERITY: "4", STATUS: "New", FIRST_FOUND_DATETIME: daysAgo(5), QDS: { "@severity": "MEDIUM", "#text": "50" } },
  ],
  listKnowledgeBase: async () => [{ QID: "91000", PATCHABLE: "1" }, { QID: "38000", PATCHABLE: "0" }],
  listScheduledReports: async () => [{ ID: "3", ACTIVE: "1", TITLE: "Weekly executive report" }],
  listReports: async () => [{ ID: "9", TITLE: "Weekly executive report", LAUNCH_DATETIME: daysAgo(1) }],
  listActivityLog: async () => [{ date: daysAgo(1), action: "login", module: "auth", details: "ok", user_name: "acme_api" }],
  searchUsers: async () => [
    { id: 1, username: "acme_mgr", emailAddress: "mgr@example.com", roleList: { list: [{ RoleData: { id: 1, name: "Manager" } }] } },
    { id: 2, username: "acme_rd", emailAddress: "reader@example.com", roleList: { list: [{ RoleData: { id: 2, name: "Reader" } }] } },
  ],
  searchCloudAgents: async () => [
    { id: 100, agentInfo: { status: "STATUS_ACTIVE", lastCheckedIn: daysAgo(0), agentVersion: "6.1" } },
    { id: 101, agentInfo: { status: "STATUS_ACTIVE", lastCheckedIn: daysAgo(1), agentVersion: "6.1" } },
  ],
  searchConnectors: async () => [{ id: 1, name: "prod-aws", type: "AWS", connectorState: "FINISHED_SUCCESS", lastSync: daysAgo(0), disabled: false }],
  searchTags: async () => [{ id: 1, name: "PCI", ruleType: "NAME_CONTAINS" }, { id: 2, name: "Prod" }],
  searchWebApps: async () => [{ id: 500, name: "Portal", url: "https://portal.example.com" }],
  searchWasScans: async () => [{ id: 1, status: "FINISHED", launchedDate: daysAgo(4), target: { webApp: { id: 500 } } }],
  searchWasAuthRecords: async () => [{ id: 1, name: "portal-login", updatedDate: daysAgo(10) }],
  searchWasSchedules: async () => [{ id: 1, active: true }],
};

const failingFixtures = {
  listScheduledScans: async () => [{ ID: "1", ACTIVE: "0", TITLE: "Disabled", TARGET: "10.0.0.0/24" }],
  listScans: async () => [],
  listHosts: async () => [
    { ID: "100", IP: "10.0.0.5", OS: "Windows Server 2019", TRACKING_METHOD: "IP", LAST_VULN_SCAN_DATETIME: daysAgo(120) },
    { ID: "101", IP: "10.0.0.6", OS: "Red Hat Enterprise Linux 8", TRACKING_METHOD: "IP", LAST_VULN_SCAN_DATETIME: daysAgo(90) },
    { ID: "102", IP: "10.0.0.7", OS: "Windows 10", TRACKING_METHOD: "IP" },
  ],
  listOptionProfiles: async () => [{ BASIC_INFO: { ID: "7", GROUP_NAME: "Unauthenticated" }, SCAN: { PORTS: { TCP_PORTS: { TCP_PORTS_TYPE: "standard" } } } }],
  listExcludedIps: async () => [{ type: "range", value: "10.0.0.0-10.0.255.255" }],
  listAssetGroups: async () => [{ ID: "10", TITLE: "Everything", IP_SET: {} }],
  listAppliances: async () => [{ ID: "1", NAME: "old-scanner", STATUS: "Offline", SOFTWARE_VERSION: "11.0", ML_LATEST: "12.7", HEARTBEATS_MISSED: "12" }],
  listAuthRecordSummary: async () => [{ type: "windows", count: 0 }],
  listCompliancePolicies: async () => [{ ID: "5", TITLE: "Draft policy", IS_ACTIVE: "1" }],
  listDetections: async () => [
    { host_id: "100", QID: "91000", SEVERITY: "5", STATUS: "Active", FIRST_FOUND_DATETIME: daysAgo(60) },
    { host_id: "101", QID: "38000", SEVERITY: "4", STATUS: "Active", FIRST_FOUND_DATETIME: daysAgo(90) },
    { host_id: "102", QID: "11000", SEVERITY: "3", STATUS: "Active", FIRST_FOUND_DATETIME: daysAgo(200) },
  ],
  listKnowledgeBase: async () => [{ QID: "91000", PATCHABLE: "1" }, { QID: "38000", PATCHABLE: "1" }, { QID: "11000", PATCHABLE: "1" }],
  listScheduledReports: async () => [],
  listReports: async () => [],
  listActivityLog: async () => [{ date: daysAgo(1), action: "delete", module: "user", details: "User removed", user_name: "acme_mgr" }],
  searchUsers: async () => [
    { id: 1, username: "shared_admin", emailAddress: "ops@example.com", roleList: { list: [{ RoleData: { name: "Manager" } }] } },
    { id: 2, username: "svc_scan", emailAddress: "ops@example.com", roleList: { list: [{ RoleData: { name: "Manager" } }] } },
  ],
  searchCloudAgents: async () => [{ id: 100, agentInfo: { status: "STATUS_INACTIVE", lastCheckedIn: daysAgo(40) } }],
  searchConnectors: async () => [{ id: 1, name: "prod-aws", type: "AWS", connectorState: "ERROR", lastError: "Invalid role", lastSync: daysAgo(30) }],
  searchTags: async () => [],
  searchWebApps: async () => [{ id: 500, name: "Legacy portal", url: "https://legacy.example.com" }],
  searchWasScans: async () => [],
  searchWasAuthRecords: async () => [{ id: 1, name: "old-login", updatedDate: daysAgo(400) }],
  searchWasSchedules: async () => [],
};

test("resolveQualysConfiguration prefers arguments, then environment, then config file", () => {
  const dir = createTempBase("qualys-config-");
  const configFile = join(dir, "qcrc");
  writeFileSync(configFile, "[info]\nusername = file_user\npassword = file_pass\nplatform = EU2\n");

  const fromFile = resolveQualysConfiguration({ config_file: configFile }, {});
  assert.equal(fromFile.username, "file_user");
  assert.equal(fromFile.platform, "EU2");
  assert.equal(fromFile.baseUrl, "https://qualysapi.qg2.apps.qualys.eu");
  assert.ok(fromFile.sourceChain.includes("config-file-username"));

  const fromEnv = resolveQualysConfiguration(
    { config_file: configFile },
    { QUALYS_USERNAME: "env_user", QUALYS_PASSWORD: "env_pass", QUALYS_PLATFORM: "qualysapi.qg1.apps.qualys.ca", QUALYS_TIMEOUT: "15" },
  );
  assert.equal(fromEnv.username, "env_user");
  assert.equal(fromEnv.platform, "CA1");
  assert.equal(fromEnv.baseUrl, "https://qualysapi.qg1.apps.qualys.ca");
  assert.equal(fromEnv.timeoutMs, 15_000);
  assert.ok(fromEnv.sourceChain.includes("environment-username"));

  const fromArgs = resolveQualysConfiguration(
    { config_file: configFile, username: "arg_user", password: "arg_pass", platform: "https://qualysapi.example.internal/" },
    { QUALYS_USERNAME: "env_user", QUALYS_PASSWORD: "env_pass", QUALYS_PLATFORM: "US2" },
  );
  assert.equal(fromArgs.username, "arg_user");
  assert.equal(fromArgs.platform, "custom");
  assert.equal(fromArgs.baseUrl, "https://qualysapi.example.internal");
  assert.equal(fromArgs.gatewayUrl, "https://qualysgateway.example.internal");
  assert.equal(fromArgs.authMode, "basic");
});

test("resolveQualysConfiguration supports bearer tokens, OAuth mode, and rejects missing credentials", () => {
  const bearer = resolveQualysConfiguration({ config_file: "/nonexistent/qcrc" }, { QUALYS_TOKEN: "jwt-token", QUALYS_PLATFORM: "GOV1" });
  assert.equal(bearer.authMode, "bearer");
  assert.equal(bearer.baseUrl, "https://qualysapi.gov1.qualys.us");

  const oauth = resolveQualysConfiguration({ config_file: "/nonexistent/qcrc" }, { QUALYS_USERNAME: "u", QUALYS_PASSWORD: "p", QUALYS_USE_OAUTH: "true" });
  assert.equal(oauth.authMode, "oauth");
  assert.equal(oauth.gatewayUrl, "https://gateway.qg1.apps.qualys.com");

  assert.throws(() => resolveQualysConfiguration({ config_file: "/nonexistent/qcrc" }, {}), /QUALYS_USERNAME/);
  assert.throws(() => resolveQualysPlatform("MARS9"), /Unknown Qualys platform/);
});

test("resolveQualysPlatform maps every documented platform ID to its API server", () => {
  assert.equal(QUALYS_PLATFORMS.length, 14);
  for (const platform of QUALYS_PLATFORMS) {
    const resolved = resolveQualysPlatform(platform.id.toLowerCase());
    assert.equal(resolved.baseUrl, platform.apiServer);
    assert.equal(resolveQualysPlatform(platform.apiServer).platform, platform.id);
  }
  assert.equal(resolveQualysPlatform("US2").baseUrl, "https://qualysapi.qg2.apps.qualys.com");
  assert.equal(resolveQualysPlatform("AU1").baseUrl, "https://qualysapi.qg1.apps.qualys.com.au");
});

test("parseXml handles declarations, DOCTYPE, CDATA, entities, attributes, and repeated elements", () => {
  const document = parseXml(`<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE HOST_LIST_OUTPUT SYSTEM "https://qualysapi.qualys.com/api/2.0/fo/asset/host/host_list_output.dtd">
<HOST_LIST_OUTPUT><RESPONSE><HOST_LIST>
  <HOST><ID>1</ID><DNS><![CDATA[web&01.example.com]]></DNS><OS>Windows &amp; Server</OS>
    <TAGS><TAG><NAME>A</NAME></TAG><TAG><NAME>B</NAME></TAG></TAGS>
    <QDS severity="HIGH">72</QDS><EMPTY/>
  </HOST>
</HOST_LIST></RESPONSE></HOST_LIST_OUTPUT>`);
  const record = xmlToRecord(document);
  const host = record.HOST_LIST_OUTPUT.RESPONSE.HOST_LIST.HOST;
  assert.equal(host.ID, "1");
  assert.equal(host.DNS, "web&01.example.com");
  assert.equal(host.OS, "Windows & Server");
  assert.deepEqual(host.TAGS.TAG.map((tag) => tag.NAME), ["A", "B"]);
  assert.equal(host.QDS["@severity"], "HIGH");
  assert.equal(host.QDS["#text"], "72");
  assert.equal(host.EMPTY, "");
  assert.throws(() => parseXml("<A><B></A>"), /Malformed XML/);
});

test("parseCsv handles quoted fields with embedded commas and quotes", () => {
  const rows = parseCsv('Date,Action,Details\n"2026-01-01T00:00:00Z","delete","Removed ""svc"" user, by admin"\n');
  assert.deepEqual(rows[1], ["2026-01-01T00:00:00Z", "delete", 'Removed "svc" user, by admin']);
});

test("QualysApiClient sends basic auth and X-Requested-With headers and surfaces SIMPLE_RETURN errors", async () => {
  const calls = [];
  const client = new QualysApiClient(sampleConfig(), {
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), headers: init.headers });
      return xmlResponse('<?xml version="1.0"?><SCHEDULE_SCAN_LIST_OUTPUT><RESPONSE><SCHEDULE_SCAN_LIST><SCHEDULE_SCAN><ID>1</ID><ACTIVE>1</ACTIVE></SCHEDULE_SCAN></SCHEDULE_SCAN_LIST></RESPONSE></SCHEDULE_SCAN_LIST_OUTPUT>');
    },
    sleepImpl: async () => {},
  });

  const schedules = await client.listScheduledScans();
  assert.equal(schedules.length, 1);
  assert.equal(schedules[0].ID, "1");
  assert.ok(calls[0].url.startsWith("https://qualysapi.qualys.com/api/2.0/fo/schedule/scan/?action=list"));
  assert.equal(calls[0].headers.get("X-Requested-With"), "grclanker");
  assert.equal(calls[0].headers.get("Authorization"), `Basic ${Buffer.from("acme_api:s3cret-value").toString("base64")}`);

  const erroring = new QualysApiClient(sampleConfig(), {
    fetchImpl: async () => xmlResponse('<SIMPLE_RETURN><RESPONSE><CODE>2000</CODE><TEXT>Bad Login/Password s3cret-value</TEXT></RESPONSE></SIMPLE_RETURN>', { status: 401 }),
    sleepImpl: async () => {},
  });
  await assert.rejects(() => erroring.listAppliances(), (error) => {
    assert.match(error.message, /code 2000/);
    assert.doesNotMatch(error.message, /s3cret-value/);
    return true;
  });
});

test("QualysApiClient follows WARNING/URL continuation, retries 409 with X-RateLimit-ToWait-Sec, and pages QPS results", async () => {
  const waits = [];
  let hostCalls = 0;
  const client = new QualysApiClient(sampleConfig(), {
    fetchImpl: async (url, init) => {
      const target = String(url);
      if (target.includes("/api/2.0/fo/asset/host/")) {
        hostCalls += 1;
        if (hostCalls === 1) {
          return xmlResponse("<SIMPLE_RETURN><RESPONSE><TEXT>concurrency</TEXT></RESPONSE></SIMPLE_RETURN>", {
            status: 409,
            headers: { "X-RateLimit-ToWait-Sec": "2", "X-Concurrency-Limit-Limit": "2", "X-Concurrency-Limit-Running": "2" },
          });
        }
        if (!target.includes("id_min")) {
          return xmlResponse('<HOST_LIST_OUTPUT><RESPONSE><HOST_LIST><HOST><ID>1</ID></HOST></HOST_LIST><WARNING><CODE>1980</CODE><TEXT>truncated</TEXT><URL><![CDATA[https://qualysapi.qualys.com/api/2.0/fo/asset/host/?action=list&id_min=2]]></URL></WARNING></RESPONSE></HOST_LIST_OUTPUT>');
        }
        return xmlResponse("<HOST_LIST_OUTPUT><RESPONSE><HOST_LIST><HOST><ID>2</ID></HOST></HOST_LIST></RESPONSE></HOST_LIST_OUTPUT>");
      }
      if (target.includes("/qps/rest/2.0/search/am/tag")) {
        assert.equal(init.headers.get("Accept"), "application/json");
        assert.equal(init.headers.get("Content-Type"), "application/json");
        const body = JSON.parse(init.body);
        const criteria = body.ServiceRequest.filters?.Criteria ?? [];
        const afterId = criteria.find((item) => item.field === "id" && item.operator === "GREATER");
        if (!afterId) {
          return jsonResponse(qpsResponse("Tag", [{ id: 1, name: "one" }], { hasMoreRecords: "true", lastId: 1 }));
        }
        assert.equal(afterId.value, "1");
        return jsonResponse(qpsResponse("Tag", [{ id: 2, name: "two" }]));
      }
      throw new Error(`unexpected url ${target}`);
    },
    sleepImpl: async (ms) => {
      waits.push(ms);
    },
  });

  const hosts = await client.listHosts(50);
  assert.deepEqual(hosts.map((host) => host.ID), ["1", "2"]);
  assert.deepEqual(waits, [2000]);
  assert.equal(client.lastRateLimit["X-Concurrency-Limit-Limit"], "2");

  const tags = await client.searchTags(10);
  assert.deepEqual(tags.map((tag) => tag.name), ["one", "two"]);

  const qpsError = new QualysApiClient(sampleConfig(), {
    fetchImpl: async () => jsonResponse({ ServiceResponse: { responseCode: "INVALID_REQUEST", responseErrorDetails: { errorMessage: "WAS module is not enabled" } } }, { status: 400 }),
    sleepImpl: async () => {},
  });
  await assert.rejects(() => qpsError.searchWebApps(), /WAS module is not enabled/);
});

test("checkQualysAccess reports healthy, degraded with a missing module, and limited states", async () => {
  const healthy = await checkQualysAccess(createFakeClient(healthyFixtures));
  assert.equal(healthy.status, "healthy");
  assert.equal(healthy.surfaces.length, 14);
  assert.ok(healthy.surfaces.every((surface) => surface.status === "readable"));
  assert.deepEqual(healthy.unavailableModules, []);

  const degraded = await checkQualysAccess(createFakeClient({
    ...healthyFixtures,
    searchWebApps: failing("Qualys QPS request failed (403) for /qps/rest/3.0/search/was/webapp: WAS module is not enabled"),
    listCompliancePolicies: failing("Qualys request failed (403) for /api/2.0/fo/compliance/policy/: code 2010: Policy Compliance not subscribed"),
  }));
  assert.equal(degraded.status, "degraded");
  assert.deepEqual(degraded.unavailableModules.sort(), ["PC", "WAS"]);
  assert.equal(degraded.surfaces.find((surface) => surface.name === "was_webapps").status, "module_unavailable");
  assert.match(degraded.notes.join("\n"), /PC, WAS|WAS, PC/);

  const limited = await checkQualysAccess(createFakeClient({
    ...healthyFixtures,
    listHosts: failing("Qualys request failed (500) for /api/2.0/fo/asset/host/: boom"),
  }));
  assert.equal(limited.status, "limited");
  assert.equal(limited.surfaces.find((surface) => surface.name === "hosts").status, "not_readable");
  assert.match(limited.recommendedNextStep, /Manager or Unit Manager/);
});

test("assessQualysScanCoverage passes on healthy fixtures and fails on weak fixtures", async () => {
  const healthy = await assessQualysScanCoverage(createFakeClient(healthyFixtures));
  assert.deepEqual(healthy.findings.map((item) => item.control), [1, 2, 3, 14, 16, 20]);
  assert.equal(findingById(healthy, "QUALYS-C01").status, "pass");
  assert.equal(findingById(healthy, "QUALYS-C02").status, "pass");
  assert.equal(findingById(healthy, "QUALYS-C02").evidence.authenticated_percent, 100);
  assert.equal(findingById(healthy, "QUALYS-C03").status, "pass");
  assert.equal(findingById(healthy, "QUALYS-C14").status, "pass");
  assert.equal(findingById(healthy, "QUALYS-C16").status, "pass");
  assert.equal(findingById(healthy, "QUALYS-C20").status, "pass");
  assert.ok(findingById(healthy, "QUALYS-C01").mappings.includes("FedRAMP RA-5"));
  assert.ok(findingById(healthy, "QUALYS-C02").mappings.includes("PCI-DSS 11.3.2"));
  assert.equal(healthy.errors.length, 0);

  const weak = await assessQualysScanCoverage(createFakeClient(failingFixtures));
  assert.equal(findingById(weak, "QUALYS-C01").status, "fail");
  assert.equal(findingById(weak, "QUALYS-C02").status, "fail");
  assert.equal(findingById(weak, "QUALYS-C03").status, "warn");
  assert.equal(findingById(weak, "QUALYS-C14").status, "fail");
  assert.equal(findingById(weak, "QUALYS-C16").status, "fail");
  assert.equal(findingById(weak, "QUALYS-C20").status, "fail");

  const unreadable = await assessQualysScanCoverage(createFakeClient({ ...healthyFixtures, listScheduledScans: failing("Qualys request failed (403)") }));
  assert.equal(findingById(unreadable, "QUALYS-C01").status, "manual");
  assert.match(findingById(unreadable, "QUALYS-C01").summary, /Collect manually/);
  assert.equal(unreadable.errors.length, 1);
});

test("assessQualysAssetInventory grades connectors, appliances, agents, and tags", async () => {
  const healthy = await assessQualysAssetInventory(createFakeClient(healthyFixtures));
  assert.deepEqual(healthy.findings.map((item) => item.control), [4, 5, 6, 7, 18]);
  assert.equal(findingById(healthy, "QUALYS-C04").status, "manual");
  assert.match(findingById(healthy, "QUALYS-C04").summary, /CMDB/);
  assert.equal(findingById(healthy, "QUALYS-C05").status, "pass");
  assert.equal(findingById(healthy, "QUALYS-C06").status, "pass");
  assert.equal(findingById(healthy, "QUALYS-C07").status, "pass");
  assert.equal(findingById(healthy, "QUALYS-C07").evidence.agent_coverage_percent, 100);
  assert.equal(findingById(healthy, "QUALYS-C18").status, "pass");
  assert.ok(findingById(healthy, "QUALYS-C05").mappings.includes("FedRAMP CM-8(2)"));

  const weak = await assessQualysAssetInventory(createFakeClient(failingFixtures));
  assert.equal(findingById(weak, "QUALYS-C05").status, "fail");
  assert.equal(findingById(weak, "QUALYS-C06").status, "fail");
  assert.equal(findingById(weak, "QUALYS-C07").status, "fail");
  assert.equal(findingById(weak, "QUALYS-C18").status, "fail");

  const noConnectors = await assessQualysAssetInventory(createFakeClient({ ...healthyFixtures, searchConnectors: async () => [] }));
  assert.equal(findingById(noConnectors, "QUALYS-C05").status, "warn");
});

test("assessQualysVulnerabilityManagement computes SLA, patch, and QDS posture", async () => {
  const healthy = await assessQualysVulnerabilityManagement(createFakeClient(healthyFixtures));
  assert.deepEqual(healthy.findings.map((item) => item.control), [8, 9, 10, 11, 17]);
  assert.equal(findingById(healthy, "QUALYS-C08").status, "pass");
  assert.equal(findingById(healthy, "QUALYS-C09").status, "pass");
  assert.equal(findingById(healthy, "QUALYS-C10").status, "pass");
  assert.equal(findingById(healthy, "QUALYS-C10").evidence.sla_compliance_percent, 100);
  assert.equal(findingById(healthy, "QUALYS-C11").status, "pass");
  assert.equal(findingById(healthy, "QUALYS-C17").status, "pass");
  assert.ok(findingById(healthy, "QUALYS-C10").mappings.includes("CIS 7.4"));

  const weak = await assessQualysVulnerabilityManagement(createFakeClient(failingFixtures));
  assert.equal(findingById(weak, "QUALYS-C08").status, "fail");
  assert.equal(findingById(weak, "QUALYS-C09").status, "fail");
  assert.equal(findingById(weak, "QUALYS-C10").status, "fail");
  assert.equal(findingById(weak, "QUALYS-C10").evidence.sla_breaches, 3);
  assert.deepEqual(findingById(weak, "QUALYS-C10").evidence.breaches_by_severity, { critical: 1, high: 1, medium: 1 });
  assert.equal(findingById(weak, "QUALYS-C11").status, "fail");
  assert.equal(findingById(weak, "QUALYS-C17").status, "fail");

  const noPc = await assessQualysVulnerabilityManagement(createFakeClient({ ...healthyFixtures, listCompliancePolicies: failing("Qualys request failed (403): PC module not subscribed") }));
  assert.equal(findingById(noPc, "QUALYS-C09").status, "manual");
});

test("assessQualysAdministration grades reporting, users, WAS inventory, and activity log", async () => {
  const healthy = await assessQualysAdministration(createFakeClient(healthyFixtures));
  assert.deepEqual(healthy.findings.map((item) => item.control), [12, 13, 15, 19]);
  assert.equal(findingById(healthy, "QUALYS-C12").status, "pass");
  assert.equal(findingById(healthy, "QUALYS-C13").status, "pass");
  assert.equal(findingById(healthy, "QUALYS-C15").status, "pass");
  assert.equal(findingById(healthy, "QUALYS-C19").status, "pass");
  assert.ok(findingById(healthy, "QUALYS-C13").mappings.includes("SOC 2 CC6.3"));

  const weak = await assessQualysAdministration(createFakeClient(failingFixtures));
  assert.equal(findingById(weak, "QUALYS-C12").status, "fail");
  assert.equal(findingById(weak, "QUALYS-C13").status, "fail");
  assert.deepEqual(findingById(weak, "QUALYS-C13").evidence.shared_emails, ["ops@example.com"]);
  assert.equal(findingById(weak, "QUALYS-C15").status, "fail");
  assert.equal(findingById(weak, "QUALYS-C19").status, "warn");
  assert.equal(findingById(weak, "QUALYS-C19").evidence.sensitive_actions.length, 1);

  const noWas = await assessQualysAdministration(createFakeClient({ ...healthyFixtures, searchWebApps: failing("Qualys QPS request failed (403): WAS module is not enabled") }));
  assert.equal(findingById(noWas, "QUALYS-C15").status, "manual");
  assert.match(findingById(noWas, "QUALYS-C15").summary, /WAS module is not enabled/);
});

test("all four assessments together cover every one of the 20 spec controls with framework mappings", async () => {
  const client = createFakeClient(healthyFixtures);
  const results = await Promise.all([
    assessQualysScanCoverage(client),
    assessQualysAssetInventory(client),
    assessQualysVulnerabilityManagement(client),
    assessQualysAdministration(client),
  ]);
  const findings = results.flatMap((result) => result.findings);
  const controls = findings.map((item) => item.control).sort((a, b) => a - b);
  assert.deepEqual(controls, Array.from({ length: 20 }, (_, index) => index + 1));
  for (const item of findings) {
    assert.ok(["critical", "high", "medium", "low", "info"].includes(item.severity));
    assert.ok(["pass", "warn", "fail", "manual"].includes(item.status));
    assert.ok(item.mappings.length >= 7, `${item.id} should carry framework mappings`);
    assert.ok(item.mappings.some((mapping) => mapping.startsWith("FedRAMP ")));
    assert.ok(item.mappings.some((mapping) => mapping.startsWith("ISMAP ")));
    assert.equal(typeof item.summary, "string");
    assert.equal(typeof item.evidence, "object");
  }
});

test("exportQualysAuditBundle writes the bundle layout, zip, and error log on partial failure", async () => {
  const outputRoot = createTempBase("qualys-bundle-");
  const config = sampleConfig();
  const client = createFakeClient({
    ...healthyFixtures,
    listCompliancePolicies: failing("Qualys request failed (403) for /api/2.0/fo/compliance/policy/: PC module not subscribed"),
  }, config);

  const result = await exportQualysAuditBundle(client, config, outputRoot);
  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.equal(result.findingCount, 20);
  assert.equal(result.errorCount, 1);
  for (const file of [
    "QUICK_REFERENCE.md",
    "metadata.json",
    "_errors.log",
    "core_data/access.json",
    "core_data/scan_coverage/scheduled_scans.json",
    "core_data/asset_inventory/appliances.json",
    "core_data/vulnerability_management/detections.json",
    "core_data/administration/users.json",
    "analysis/findings.json",
    "analysis/scan_coverage.json",
    "analysis/asset_inventory.json",
    "analysis/vulnerability_management.json",
    "analysis/administration.json",
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
    assert.ok(existsSync(join(result.outputDir, file)), `expected ${file}`);
  }
  assert.match(readFileSync(join(result.outputDir, "_errors.log"), "utf8"), /PC module not subscribed/);
  assert.match(readFileSync(join(result.outputDir, "compliance/executive_summary.md"), "utf8"), /Manual controls: 2/);
  assert.match(readFileSync(join(result.outputDir, "compliance/fedramp/fedramp_compliance_report.md"), "utf8"), /RA-5\(3\)/);
  const metadata = JSON.parse(readFileSync(join(result.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.platform, "US1");
  assert.equal(JSON.stringify(metadata).includes(config.password), false);

  const clean = await exportQualysAuditBundle(createFakeClient(healthyFixtures, config), config, outputRoot);
  assert.equal(clean.errorCount, 0);
  assert.equal(existsSync(join(clean.outputDir, "_errors.log")), false);
  assert.notEqual(clean.outputDir, result.outputDir);
});

test("resolveSecureOutputPath rejects traversal and symlinked parents", () => {
  const base = createTempBase("qualys-secure-");
  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  const outside = createTempBase("qualys-outside-");
  symlinkSync(outside, join(base, "linked"));
  assert.throws(() => resolveSecureOutputPath(base, "linked/nested"), /symlinked parent/);
  const safe = resolveSecureOutputPath(base, "nested/report");
  assert.ok(safe.startsWith(base) || safe.includes("qualys-secure-"));
});

test("Qualys tools are registered in the tool catalog under the Qualys group", () => {
  const tools = getRegisteredToolSummaries().filter((tool) => tool.name.startsWith("qualys_"));
  assert.deepEqual(
    tools.map((tool) => tool.name).sort(),
    [
      "qualys_assess_administration",
      "qualys_assess_asset_inventory",
      "qualys_assess_scan_coverage",
      "qualys_assess_vulnerability_management",
      "qualys_check_access",
      "qualys_export_audit_bundle",
    ],
  );
  assert.ok(tools.every((tool) => tool.group === "Qualys"));
  assert.ok(tools.every((tool) => tool.kind === "domain"));
  assert.ok(tools.every((tool) => typeof tool.description === "string" && tool.description.length > 40));
});
