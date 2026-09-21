import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  QUALYS_PLATFORMS,
  QualysApiClient,
  assessQualysAdministration,
  assessQualysAssetInventory,
  assessQualysScanCoverage,
  assessQualysVulnerabilityManagement,
  bundleZipPath,
  checkQualysAccess,
  exportQualysAuditBundle,
  normalizeList,
  parseCsv,
  parseXml,
  resolveQualysConfiguration,
  resolveQualysPlatform,
  resolveSecureOutputPath,
  resolveViewScope,
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

function csvResponse(body) {
  return new Response(body, { status: 200, headers: { "content-type": "text/csv" } });
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

const LIST_METHODS = [
  "listScheduledScans",
  "listScans",
  "listHosts",
  "listOptionProfiles",
  "listExcludedIps",
  "listAssetGroups",
  "listAppliances",
  "listAuthRecordSummary",
  "listCompliancePolicies",
  "listDetections",
  "listKnowledgeBase",
  "listScheduledReports",
  "listReports",
  "listActivityLog",
  "searchUsers",
  "searchCloudAgents",
  "searchConnectors",
  "searchTags",
  "searchWebApps",
  "searchWasScans",
  "searchWasAuthRecords",
  "searchWasSchedules",
];

const failing = (message) => async () => {
  throw new Error(message);
};

function forbiddenFixtures() {
  return Object.fromEntries(LIST_METHODS.map((name) => [
    name,
    failing(`Qualys request failed (403) for ${name}: code 2010: Forbidden, module not subscribed for this user`),
  ]));
}

function truncated(items, truncationReason) {
  return { items, truncated: true, truncationReason, pages: 25 };
}

function partialFixtures(base) {
  return Object.fromEntries(LIST_METHODS.map((name) => [
    name,
    async (...args) => truncated(normalizeList(await base[name](...args)).items, name.startsWith("search")
      ? "page cap 25 reached with hasMoreRecords true"
      : "page cap 25 reached with a WARNING/URL continuation not followed"),
  ]));
}

function findingById(result, id) {
  const found = result.findings.find((item) => item.id === id);
  assert.ok(found, `expected finding ${id}`);
  return found;
}

function statusMap(result) {
  return Object.fromEntries(result.findings.map((item) => [item.id, item.status]));
}

async function runAllAssessments(client, options = {}) {
  return Promise.all([
    assessQualysScanCoverage(client, options),
    assessQualysAssetInventory(client, options),
    assessQualysVulnerabilityManagement(client, options),
    assessQualysAdministration(client, options),
  ]);
}

function allFindings(results) {
  return results.flatMap((result) => result.findings);
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
  listCompliancePolicies: async () => [{ ID: "5", TITLE: "CIS Baseline", STATUS: "active", ASSET_GROUP_IDS: "10,11" }],
  listDetections: async () => [
    { host_id: "100", QID: "91000", TYPE: "Confirmed", SEVERITY: "5", STATUS: "Active", FIRST_FOUND_DATETIME: daysAgo(3), QDS: { "@severity": "HIGH", "#text": "72" } },
    { host_id: "101", QID: "38000", TYPE: "Confirmed", SEVERITY: "4", STATUS: "New", FIRST_FOUND_DATETIME: daysAgo(5), QDS: { "@severity": "MEDIUM", "#text": "50" } },
  ],
  listKnowledgeBase: async () => [{ QID: "91000", PATCHABLE: "1" }, { QID: "38000", PATCHABLE: "0" }],
  listScheduledReports: async () => [{ ID: "3", ACTIVE: "1", TITLE: "Weekly executive report" }],
  listReports: async () => [{ ID: "9", TITLE: "Weekly executive report", LAUNCH_DATETIME: daysAgo(1) }],
  listActivityLog: async () => [{ date: daysAgo(1), action: "login", module: "auth", details: "ok", user_name: "acme_api", user_role: "Manager" }],
  searchUsers: async () => [
    { id: 0, username: "acme_api", emailAddress: "api@example.com", roleList: { list: [{ RoleData: { id: 1, name: "MANAGER" } }] } },
    { id: 1, username: "acme_mgr", emailAddress: "mgr@example.com", roleList: { list: [{ RoleData: { id: 1, name: "Manager" } }] } },
    { id: 2, username: "acme_rd", emailAddress: "reader@example.com", roleList: { list: [{ RoleData: { id: 2, name: "Reader" } }] } },
  ],
  searchCloudAgents: async () => [
    { id: 100, agentInfo: { status: "STATUS_ACTIVE", lastCheckedIn: daysAgo(0), agentVersion: "6.1", activationKey: { activationId: "key-1", title: "prod-key" } } },
    { id: 101, agentInfo: { status: "STATUS_ACTIVE", lastCheckedIn: { date: daysAgo(1) }, agentVersion: "6.1", activationKey: { activationId: "key-1", title: "prod-key" } } },
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
  listCompliancePolicies: async () => [{ ID: "5", TITLE: "Unassigned policy", STATUS: "active" }],
  listDetections: async () => [
    { host_id: "100", QID: "91000", TYPE: "Confirmed", SEVERITY: "5", STATUS: "Active", FIRST_FOUND_DATETIME: daysAgo(60) },
    { host_id: "101", QID: "38000", TYPE: "Confirmed", SEVERITY: "4", STATUS: "Active", FIRST_FOUND_DATETIME: daysAgo(90) },
    { host_id: "102", QID: "11000", TYPE: "Confirmed", SEVERITY: "3", STATUS: "Active", FIRST_FOUND_DATETIME: daysAgo(200) },
  ],
  listKnowledgeBase: async () => [{ QID: "91000", PATCHABLE: "1" }, { QID: "38000", PATCHABLE: "1" }, { QID: "11000", PATCHABLE: "1" }],
  listScheduledReports: async () => [],
  listReports: async () => [],
  listActivityLog: async () => [{ date: daysAgo(1), action: "delete", module: "user", details: "User removed", user_name: "acme_mgr", user_role: "Manager" }],
  searchUsers: async () => [
    { id: 1, username: "shared_admin", emailAddress: "ops@example.com", roleList: { list: [{ RoleData: { name: "Manager" } }] } },
    { id: 2, username: "svc_scan", emailAddress: "ops@example.com", roleList: { list: [{ RoleData: { name: "Manager" } }] } },
  ],
  searchCloudAgents: async () => [{ id: 100, agentInfo: { status: "STATUS_INACTIVE", lastCheckedIn: daysAgo(40), activationKey: { title: "old-key" } } }],
  searchConnectors: async () => [{ id: 1, name: "prod-aws", type: "AWS", connectorState: "ERROR", lastError: "Invalid role", lastSync: daysAgo(30) }],
  searchTags: async () => [],
  searchWebApps: async () => [{ id: 500, name: "Legacy portal", url: "https://legacy.example.com" }],
  searchWasScans: async () => [],
  searchWasAuthRecords: async () => [{ id: 1, name: "old-login", updatedDate: daysAgo(400) }],
  searchWasSchedules: async () => [],
};

const EMPTY_LIST_XML = '<?xml version="1.0" encoding="UTF-8"?><LIST_OUTPUT><RESPONSE><DATETIME>2026-09-21T00:00:00Z</DATETIME></RESPONSE></LIST_OUTPUT>';
const CSV_HEADER = '"Date","Action","Module","Details","User Name","User Role","User IP"\n';

function routedClient(handler, configOverrides = {}) {
  return new QualysApiClient(sampleConfig(configOverrides), {
    fetchImpl: async (url, init) => handler(String(url), init ?? {}),
    sleepImpl: async () => {},
  });
}

const forbiddenRouter = async (url) => {
  if (url.includes("/qps/rest/")) {
    return jsonResponse({ ServiceResponse: { responseCode: "UNAUTHORIZED", responseErrorDetails: { errorMessage: "User is not authorized to access this module" } } }, { status: 403 });
  }
  return xmlResponse("<SIMPLE_RETURN><RESPONSE><CODE>2010</CODE><TEXT>Forbidden: module not subscribed</TEXT></RESPONSE></SIMPLE_RETURN>", { status: 403 });
};

const emptyRouter = async (url) => {
  if (url.includes("/qps/rest/")) return jsonResponse({ ServiceResponse: { responseCode: "SUCCESS", count: 0, hasMoreRecords: "false" } });
  if (url.includes("/activity_log/")) return csvResponse(CSV_HEADER);
  return xmlResponse(EMPTY_LIST_XML);
};

function xmlPage(recordXml, url) {
  const nextId = Number(new URL(url).searchParams.get("id_min") ?? "0") + 1;
  const nextUrl = new URL(url);
  nextUrl.searchParams.set("id_min", String(nextId));
  return xmlResponse(`<?xml version="1.0"?><LIST_OUTPUT><RESPONSE><DATETIME>2026-09-21T00:00:00Z</DATETIME>${recordXml(nextId)}<WARNING><CODE>1980</CODE><TEXT>truncated</TEXT><URL><![CDATA[${nextUrl.toString()}]]></URL></WARNING></RESPONSE></LIST_OUTPUT>`);
}

function partialXmlRecord(url, id) {
  if (url.includes("/schedule/scan/")) return `<SCHEDULE_SCAN_LIST><SCHEDULE_SCAN><ID>${id}</ID><ACTIVE>1</ACTIVE><TITLE>Sched ${id}</TITLE><TARGET>10.0.${id}.0/24</TARGET></SCHEDULE_SCAN></SCHEDULE_SCAN_LIST>`;
  if (url.includes("/scan/?")) return `<SCAN_LIST><SCAN><REF>scan/${id}</REF><STATUS><STATE>Finished</STATE></STATUS></SCAN></SCAN_LIST>`;
  if (url.includes("/vm/detection/")) return `<HOST_LIST><HOST><ID>${id}</ID><IP>10.0.0.${id}</IP><DETECTION_LIST><DETECTION><QID>9${id}</QID><TYPE>Confirmed</TYPE><SEVERITY>4</SEVERITY><STATUS>Active</STATUS><FIRST_FOUND_DATETIME>${daysAgo(2)}</FIRST_FOUND_DATETIME><QDS severity="HIGH">70</QDS></DETECTION></DETECTION_LIST></HOST></HOST_LIST>`;
  if (url.includes("/asset/host/")) return `<HOST_LIST><HOST><ID>${id}</ID><IP>10.0.0.${id}</IP><OS>Windows Server 2022</OS><TRACKING_METHOD>Cloud Agent</TRACKING_METHOD><LAST_VULN_SCAN_DATETIME>${daysAgo(1)}</LAST_VULN_SCAN_DATETIME><LAST_VM_AUTH_SCANNED_DATE>${daysAgo(1)}</LAST_VM_AUTH_SCANNED_DATE><TAGS><TAG><NAME>Prod</NAME></TAG></TAGS></HOST></HOST_LIST>`;
  if (url.includes("/option_profile/")) return `<OPTION_PROFILES><OPTION_PROFILE><BASIC_INFO><ID>${id}</ID><GROUP_NAME>Profile ${id}</GROUP_NAME></BASIC_INFO><SCAN><AUTHENTICATION>Windows, Unix</AUTHENTICATION></SCAN></OPTION_PROFILE></OPTION_PROFILES>`;
  if (url.includes("/excluded_ip/")) return `<IP_SET><IP>10.0.0.${id}</IP></IP_SET>`;
  if (url.includes("/asset/group/")) return `<ASSET_GROUP_LIST><ASSET_GROUP><ID>${id}</ID><TITLE>Sched ${id}</TITLE><IP_SET><IP>10.0.${id}.5</IP></IP_SET></ASSET_GROUP></ASSET_GROUP_LIST>`;
  if (url.includes("/appliance/")) return `<APPLIANCE_LIST><APPLIANCE><ID>${id}</ID><NAME>scanner-${id}</NAME><STATUS>Online</STATUS><SOFTWARE_VERSION>12.7</SOFTWARE_VERSION><ML_LATEST>12.7</ML_LATEST><HEARTBEATS_MISSED>0</HEARTBEATS_MISSED></APPLIANCE></APPLIANCE_LIST>`;
  if (url.includes("/auth/")) return "<AUTH_RECORDS><AUTH_WINDOWS_RECORDS><ID_SET><ID>1</ID></ID_SET></AUTH_WINDOWS_RECORDS><AUTH_UNIX_RECORDS><ID_SET><ID>2</ID></ID_SET></AUTH_UNIX_RECORDS></AUTH_RECORDS>";
  if (url.includes("/compliance/policy/")) return `<POLICY_LIST><POLICY><ID>${id}</ID><TITLE>Policy ${id}</TITLE><STATUS>active</STATUS><ASSET_GROUP_IDS>${id}</ASSET_GROUP_IDS></POLICY></POLICY_LIST>`;
  if (url.includes("/knowledge_base/")) return `<VULN_LIST><VULN><QID>9${id}</QID><PATCHABLE>0</PATCHABLE></VULN></VULN_LIST>`;
  if (url.includes("/schedule/report/")) return `<SCHEDULE_REPORT_LIST><REPORT><ID>${id}</ID><ACTIVE>1</ACTIVE><TITLE>Report ${id}</TITLE></REPORT></SCHEDULE_REPORT_LIST>`;
  if (url.includes("/report/")) return `<REPORT_LIST><REPORT><ID>${id}</ID><TITLE>Report ${id}</TITLE><LAUNCH_DATETIME>${daysAgo(1)}</LAUNCH_DATETIME></REPORT></REPORT_LIST>`;
  throw new Error(`unexpected XML url ${url}`);
}

function qpsEntity(url) {
  if (url.includes("/am/user")) return ["User", (id) => ({ id, username: `user${id}`, emailAddress: `user${id}@example.com`, roleList: { list: [{ RoleData: { name: "Reader" } }] } })];
  if (url.includes("/am/hostasset")) return ["HostAsset", (id) => ({ id, agentInfo: { status: "STATUS_ACTIVE", lastCheckedIn: daysAgo(0), activationKey: { title: "k" } } })];
  if (url.includes("/am/assetdataconnector")) return ["AwsAssetDataConnector", (id) => ({ id, name: `aws-${id}`, connectorState: "FINISHED_SUCCESS", lastSync: daysAgo(0) })];
  if (url.includes("/am/tag")) return ["Tag", (id) => ({ id, name: `Tag ${id}` })];
  if (url.includes("/was/webapp")) return ["WebApp", (id) => ({ id, name: `App ${id}`, lastScan: { date: daysAgo(2) } })];
  if (url.includes("/was/wasscan")) return ["WasScan", (id) => ({ id, status: "FINISHED", launchedDate: daysAgo(2), target: { webApp: { id } } })];
  if (url.includes("/was/webappauthrecord")) return ["WebAppAuthRecord", (id) => ({ id, name: `auth-${id}`, updatedDate: daysAgo(3) })];
  if (url.includes("/was/wasscanschedule")) return ["WasScanSchedule", (id) => ({ id, active: true })];
  throw new Error(`unexpected QPS url ${url}`);
}

const partialRouter = async (url, init) => {
  if (url.includes("/qps/rest/")) {
    const body = JSON.parse(init.body);
    const after = (body.ServiceRequest.filters?.Criteria ?? []).find((item) => item.field === "id" && item.operator === "GREATER");
    const id = after ? Number(after.value) + 1 : 1;
    const [entity, build] = qpsEntity(url);
    return jsonResponse(qpsResponse(entity, [build(id)], { hasMoreRecords: "true", lastId: id }));
  }
  if (url.includes("/activity_log/")) {
    const rows = Array.from({ length: 5000 }, (_, index) => `"${daysAgo(1)}","request","auth","API: /api/2.0/fo/activity_log/","acme_api","Reader","10.0.0.${index % 250}"`);
    return csvResponse(`${CSV_HEADER}${rows.join("\n")}\n`);
  }
  return xmlPage((id) => partialXmlRecord(url, id), url);
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
  assert.equal(schedules.items.length, 1);
  assert.equal(schedules.items[0].ID, "1");
  assert.equal(schedules.truncated, false);
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
  assert.deepEqual(hosts.items.map((host) => host.ID), ["1", "2"]);
  assert.equal(hosts.truncated, false);
  assert.equal(hosts.pages, 2);
  assert.deepEqual(waits, [2000]);
  assert.equal(client.lastRateLimit["X-Concurrency-Limit-Limit"], "2");

  const tags = await client.searchTags(10);
  assert.deepEqual(tags.items.map((tag) => tag.name), ["one", "two"]);
  assert.equal(tags.truncated, false);

  const qpsError = new QualysApiClient(sampleConfig(), {
    fetchImpl: async () => jsonResponse({ ServiceResponse: { responseCode: "INVALID_REQUEST", responseErrorDetails: { errorMessage: "WAS module is not enabled" } } }, { status: 400 }),
    sleepImpl: async () => {},
  });
  await assert.rejects(() => qpsError.searchWebApps(), /WAS module is not enabled/);
});

test("rule 7: QualysApiClient runs pagination to completion or records truncation instead of trusting the first page", async () => {
  const client = routedClient(partialRouter);

  const schedules = await client.listScheduledScans();
  assert.equal(schedules.pages, 25, "single-page endpoints now follow WARNING/URL continuations");
  assert.equal(schedules.items.length, 25);
  assert.equal(schedules.truncated, true);
  assert.match(schedules.truncationReason, /page cap 25 reached with a WARNING\/URL continuation not followed/);

  const cappedHosts = await client.listHosts(3);
  assert.equal(cappedHosts.items.length, 3);
  assert.equal(cappedHosts.truncated, true);
  assert.match(cappedHosts.truncationReason, /item cap 3 reached with more records available/);

  const detections = await client.listDetections(2);
  assert.equal(detections.items.length, 2);
  assert.equal(detections.truncated, true);

  const excluded = await client.listExcludedIps();
  assert.equal(excluded.truncated, true);
  assert.match(excluded.truncationReason, /WARNING\/URL continuation present and not followed/);

  const users = await client.searchUsers();
  assert.equal(users.items.length, 25);
  assert.equal(users.truncated, true);
  assert.match(users.truncationReason, /page cap 25 reached with hasMoreRecords true/);

  const cappedTags = await client.searchTags(4);
  assert.equal(cappedTags.items.length, 4);
  assert.match(cappedTags.truncationReason, /item cap 4 reached with hasMoreRecords true/);

  const noLastId = routedClient(async () => jsonResponse(qpsResponse("Tag", [{ id: 1, name: "one" }], { hasMoreRecords: "true" })));
  const orphan = await noLastId.searchTags(10);
  assert.equal(orphan.items.length, 1);
  assert.equal(orphan.truncated, true);
  assert.match(orphan.truncationReason, /no lastId/);

  const complete = routedClient(async (url) => {
    if (url.includes("/qps/rest/")) return jsonResponse(qpsResponse("Tag", [{ id: 1, name: "one" }]));
    return xmlResponse("<APPLIANCE_LIST_OUTPUT><RESPONSE><APPLIANCE_LIST><APPLIANCE><ID>1</ID></APPLIANCE></APPLIANCE_LIST></RESPONSE></APPLIANCE_LIST_OUTPUT>");
  });
  assert.equal((await complete.listAppliances()).truncated, false);
  assert.equal((await complete.searchTags()).truncated, false);

  const activity = await client.listActivityLog(7);
  assert.equal(activity.items.length, 5000);
  assert.equal(activity.truncated, true);
  assert.match(activity.truncationReason, /truncation_limit 5000/);
});

test("normalizeList accepts plain arrays and list results", () => {
  assert.deepEqual(normalizeList([{ a: 1 }]), { items: [{ a: 1 }], truncated: false, truncationReason: undefined, pages: 1 });
  const list = normalizeList({ items: [{ a: 1 }], truncationReason: "item cap 1 reached", pages: 3 });
  assert.equal(list.truncated, true);
  assert.equal(list.pages, 3);
  assert.deepEqual(normalizeList(undefined).items, []);
});

test("resolveViewScope verifies the API user role from the user search, falls back to the activity log, and reports unverified", () => {
  const config = sampleConfig();
  const readable = (name, data) => ({ name, data, moduleUnavailable: false, truncated: false });
  const unreadable = (name) => ({ name, data: [], error: "Qualys request failed (403)", moduleUnavailable: true, truncated: false });

  const manager = resolveViewScope(config, readable("users", [{ username: "ACME_API", roleList: { list: [{ RoleData: { name: "Manager" } }] } }]));
  assert.equal(manager.verified, true);
  assert.equal(manager.partial, false);
  assert.equal(manager.source, "user_search");

  const reader = resolveViewScope(config, readable("users", [{ username: "acme_api", roleList: { list: [{ RoleData: { name: "Reader" } }] } }]));
  assert.equal(reader.partial, true);
  assert.match(reader.note, /Reader/);

  const scoped = resolveViewScope(config, readable("users", [{ username: "acme_api", roleList: { list: [{ RoleData: { name: "Manager" } }] }, scopeTags: { list: [{ TagData: { name: "BU-East" } }] } }]));
  assert.equal(scoped.partial, true);
  assert.deepEqual(scoped.scopeTags, ["BU-East"]);

  const fromActivity = resolveViewScope(config, readable("users", []), readable("activity_log", [{ user_name: "acme_api", user_role: "Manager" }]));
  assert.equal(fromActivity.verified, true);
  assert.equal(fromActivity.partial, false);
  assert.equal(fromActivity.source, "activity_log");

  const hidden = resolveViewScope(config, readable("users", [{ username: "someone_else" }]));
  assert.equal(hidden.verified, false);
  assert.equal(hidden.partial, false);
  assert.match(hidden.note, /hidden/);

  const failed = resolveViewScope(config, unreadable("users"));
  assert.equal(failed.verified, false);
  assert.match(failed.note, /user search failed/);

  const bearer = resolveViewScope(sampleConfig({ username: undefined, authMode: "bearer" }), readable("users", []));
  assert.match(bearer.note, /bearer token/);
});

test("checkQualysAccess reports healthy, degraded with a missing module or partial role, and limited states", async () => {
  const healthy = await checkQualysAccess(createFakeClient(healthyFixtures));
  assert.equal(healthy.status, "healthy");
  assert.equal(healthy.surfaces.length, 14);
  assert.ok(healthy.surfaces.every((surface) => surface.status === "readable"));
  assert.deepEqual(healthy.unavailableModules, []);
  assert.equal(healthy.viewScope.verified, true);
  assert.equal(healthy.viewScope.partial, false);
  assert.match(healthy.notes.join("\n"), /Manager role/);

  const degraded = await checkQualysAccess(createFakeClient({
    ...healthyFixtures,
    searchWebApps: failing("Qualys QPS request failed (403) for /qps/rest/3.0/search/was/webapp: WAS module is not enabled"),
    listCompliancePolicies: failing("Qualys request failed (403) for /api/2.0/fo/compliance/policy/: code 2010: Policy Compliance not subscribed"),
  }));
  assert.equal(degraded.status, "degraded");
  assert.deepEqual(degraded.unavailableModules.sort(), ["PC", "WAS"]);
  assert.equal(degraded.surfaces.find((surface) => surface.name === "was_webapps").status, "module_unavailable");
  assert.match(degraded.notes.join("\n"), /PC, WAS|WAS, PC/);

  const reader = await checkQualysAccess(createFakeClient({
    ...healthyFixtures,
    searchUsers: async () => [{ id: 0, username: "acme_api", roleList: { list: [{ RoleData: { name: "Reader" } }] } }],
  }));
  assert.equal(reader.status, "degraded");
  assert.equal(reader.viewScope.partial, true);
  assert.match(reader.notes.join("\n"), /Reader/);

  const limited = await checkQualysAccess(createFakeClient({
    ...healthyFixtures,
    listHosts: failing("Qualys request failed (500) for /api/2.0/fo/asset/host/: boom"),
  }));
  assert.equal(limited.status, "limited");
  assert.equal(limited.surfaces.find((surface) => surface.name === "hosts").status, "not_readable");
  assert.match(limited.recommendedNextStep, /Manager or Unit Manager/);

  const truncatedProbe = await checkQualysAccess(createFakeClient({
    ...healthyFixtures,
    listHosts: async () => truncated([{ ID: "1" }], "item cap 100 reached with more records available"),
  }));
  assert.match(truncatedProbe.surfaces.find((surface) => surface.name === "hosts").truncation, /item cap 100/);
});

test("assessQualysScanCoverage: passing fixture passes only the machine-verifiable controls", async () => {
  const healthy = await assessQualysScanCoverage(createFakeClient(healthyFixtures));
  assert.deepEqual(healthy.findings.map((item) => item.control), [1, 2, 3, 14, 16, 20]);
  assert.deepEqual(statusMap(healthy), {
    "QUALYS-C01": "pass",
    "QUALYS-C02": "pass",
    "QUALYS-C03": "warn",
    "QUALYS-C14": "pass",
    "QUALYS-C16": "pass",
    "QUALYS-C20": "warn",
  });
  assert.equal(findingById(healthy, "QUALYS-C02").evidence.authenticated_percent, 100);
  assert.match(findingById(healthy, "QUALYS-C03").summary, /capped at warn/);
  assert.match(findingById(healthy, "QUALYS-C16").summary, /read completely, so emptiness is compliant/);
  assert.match(findingById(healthy, "QUALYS-C20").summary, /capped at warn/);
  assert.ok(findingById(healthy, "QUALYS-C01").mappings.includes("FedRAMP RA-5"));
  assert.ok(findingById(healthy, "QUALYS-C02").mappings.includes("PCI-DSS 11.3.2"));
  assert.equal(healthy.errors.length, 0);
  for (const item of healthy.findings) {
    assert.equal(item.evidence.collection.view_scope.partial, false);
    assert.ok(item.evidence.collection.sources.every((source) => source.status === "readable"));
  }
});

test("assessQualysScanCoverage: failing fixture fails", async () => {
  const weak = await assessQualysScanCoverage(createFakeClient(failingFixtures));
  assert.deepEqual(statusMap(weak), {
    "QUALYS-C01": "fail",
    "QUALYS-C02": "fail",
    "QUALYS-C03": "warn",
    "QUALYS-C14": "fail",
    "QUALYS-C16": "fail",
    "QUALYS-C20": "fail",
  });
  assert.deepEqual(findingById(weak, "QUALYS-C03").evidence.profiles_without_authentication, ["Unauthenticated"]);
  assert.equal(findingById(weak, "QUALYS-C02").evidence.authenticated_percent, 0);
});

test("assessQualysScanCoverage: unreadable fixture is manual everywhere and names the cause", async () => {
  const unreadable = await assessQualysScanCoverage(createFakeClient(forbiddenFixtures()));
  assert.ok(unreadable.findings.every((item) => item.status === "manual"));
  for (const item of unreadable.findings) {
    assert.match(item.summary, /not readable/);
    assert.match(item.summary, /code 2010/);
    assert.match(item.summary, /Collect manually:/);
  }
  assert.equal(unreadable.errors.length, 6);

  const oneSource = await assessQualysScanCoverage(createFakeClient({ ...healthyFixtures, listHosts: failing("Qualys request failed (403) for /api/2.0/fo/asset/host/: code 2010: Forbidden") }));
  assert.equal(findingById(oneSource, "QUALYS-C01").status, "manual", "a healthy schedule list must not pass when hosts are unreadable");
  assert.equal(findingById(oneSource, "QUALYS-C02").status, "manual");
  assert.equal(findingById(oneSource, "QUALYS-C14").status, "pass", "controls that do not depend on hosts keep their verdict");
});

test("assessQualysScanCoverage: empty fixture never passes and states the emptiness decision", async () => {
  const empty = await assessQualysScanCoverage(createFakeClient());
  assert.deepEqual(statusMap(empty), {
    "QUALYS-C01": "fail",
    "QUALYS-C02": "manual",
    "QUALYS-C03": "fail",
    "QUALYS-C14": "fail",
    "QUALYS-C16": "manual",
    "QUALYS-C20": "fail",
  });
  assert.match(findingById(empty, "QUALYS-C01").summary, /emptiness is a failure/i);
  assert.match(findingById(empty, "QUALYS-C02").summary, /treated as unknown, not compliant/);
  assert.match(findingById(empty, "QUALYS-C16").summary, /QID exclusions could not be evaluated/);

  const noHosts = await assessQualysScanCoverage(createFakeClient({ ...healthyFixtures, listHosts: async () => [] }));
  assert.equal(findingById(noHosts, "QUALYS-C01").status, "manual");
  assert.equal(findingById(noHosts, "QUALYS-C02").status, "manual");
  const noGroups = await assessQualysScanCoverage(createFakeClient({ ...healthyFixtures, listAssetGroups: async () => [] }));
  assert.equal(findingById(noGroups, "QUALYS-C01").status, "manual");
});

test("assessQualysScanCoverage: partial fixture never passes and reports seen versus cap", async () => {
  const partial = await assessQualysScanCoverage(createFakeClient(partialFixtures(healthyFixtures)));
  assert.ok(partial.findings.every((item) => item.status !== "pass"));
  assert.equal(findingById(partial, "QUALYS-C01").status, "warn");
  assert.match(findingById(partial, "QUALYS-C01").summary, /Partial view: scheduled_scans page cap 25/);
  assert.equal(findingById(partial, "QUALYS-C01").evidence.verdict_basis, "pass");

  const capped = await assessQualysScanCoverage(createFakeClient(healthyFixtures), { hostLimit: 2 });
  assert.equal(findingById(capped, "QUALYS-C02").status, "warn");
  assert.match(findingById(capped, "QUALYS-C02").summary, /Partial view: hosts returned 2 records, reaching the 2 record cap \(2 seen of cap 2\)/);
  assert.equal(findingById(capped, "QUALYS-C14").status, "pass", "schedules were complete so the external scanner control is unaffected");
});

test("assessQualysAssetInventory: passing fixture", async () => {
  const healthy = await assessQualysAssetInventory(createFakeClient(healthyFixtures));
  assert.deepEqual(healthy.findings.map((item) => item.control), [4, 5, 6, 7, 18]);
  assert.deepEqual(statusMap(healthy), {
    "QUALYS-C04": "manual",
    "QUALYS-C05": "pass",
    "QUALYS-C06": "pass",
    "QUALYS-C07": "pass",
    "QUALYS-C18": "pass",
  });
  assert.match(findingById(healthy, "QUALYS-C04").summary, /CMDB/);
  assert.equal(findingById(healthy, "QUALYS-C07").evidence.agent_coverage_percent, 100);
  assert.equal(findingById(healthy, "QUALYS-C07").evidence.agents_without_activation_key, 0);
  assert.ok(findingById(healthy, "QUALYS-C05").mappings.includes("FedRAMP CM-8(2)"));
});

test("assessQualysAssetInventory: failing fixture", async () => {
  const weak = await assessQualysAssetInventory(createFakeClient(failingFixtures));
  assert.deepEqual(statusMap(weak), {
    "QUALYS-C04": "manual",
    "QUALYS-C05": "fail",
    "QUALYS-C06": "fail",
    "QUALYS-C07": "fail",
    "QUALYS-C18": "fail",
  });
});

test("assessQualysAssetInventory: unreadable fixture is manual everywhere", async () => {
  const unreadable = await assessQualysAssetInventory(createFakeClient(forbiddenFixtures()));
  assert.ok(unreadable.findings.every((item) => item.status === "manual"));
  assert.ok(unreadable.findings.every((item) => /Collect manually:/.test(item.summary)));
  assert.match(findingById(unreadable, "QUALYS-C07").summary, /hosts, cloud_agents were not readable/);

  const agentsOnly = await assessQualysAssetInventory(createFakeClient({ ...healthyFixtures, searchCloudAgents: failing("Qualys QPS request failed (403): Cloud Agent module is not enabled") }));
  assert.equal(findingById(agentsOnly, "QUALYS-C07").status, "manual", "host tracking data alone must not pass when the agent list is unreadable");
});

test("assessQualysAssetInventory: empty fixture never passes", async () => {
  const empty = await assessQualysAssetInventory(createFakeClient());
  assert.deepEqual(statusMap(empty), {
    "QUALYS-C04": "manual",
    "QUALYS-C05": "manual",
    "QUALYS-C06": "manual",
    "QUALYS-C07": "manual",
    "QUALYS-C18": "fail",
  });
  assert.match(findingById(empty, "QUALYS-C05").summary, /not applicable if no AWS, Azure, or GCP accounts/);
  assert.match(findingById(empty, "QUALYS-C06").summary, /not applicable/);
  assert.match(findingById(empty, "QUALYS-C18").summary, /emptiness is a failure/i);

  const noHosts = await assessQualysAssetInventory(createFakeClient({ ...healthyFixtures, listHosts: async () => [] }));
  assert.equal(findingById(noHosts, "QUALYS-C18").status, "manual", "tags with zero hosts must not compute a 0% untagged pass");
  assert.equal(findingById(noHosts, "QUALYS-C07").status, "manual");
});

test("assessQualysAssetInventory: partial fixture never passes", async () => {
  const partial = await assessQualysAssetInventory(createFakeClient(partialFixtures(healthyFixtures)));
  assert.ok(partial.findings.every((item) => item.status !== "pass"));
  assert.match(findingById(partial, "QUALYS-C05").summary, /Partial view: connectors page cap 25 reached with hasMoreRecords true/);

  const capped = await assessQualysAssetInventory(createFakeClient(healthyFixtures), { hostLimit: 2 });
  assert.equal(findingById(capped, "QUALYS-C07").status, "warn");
  assert.equal(findingById(capped, "QUALYS-C18").status, "warn");
  assert.equal(findingById(capped, "QUALYS-C06").status, "pass", "appliances were complete");
});

test("assessQualysVulnerabilityManagement: passing fixture", async () => {
  const healthy = await assessQualysVulnerabilityManagement(createFakeClient(healthyFixtures));
  assert.deepEqual(healthy.findings.map((item) => item.control), [8, 9, 10, 11, 17]);
  assert.deepEqual(statusMap(healthy), {
    "QUALYS-C08": "pass",
    "QUALYS-C09": "pass",
    "QUALYS-C10": "pass",
    "QUALYS-C11": "pass",
    "QUALYS-C17": "warn",
  });
  assert.equal(findingById(healthy, "QUALYS-C10").evidence.sla_compliance_percent, 100);
  assert.equal(findingById(healthy, "QUALYS-C08").evidence.authenticated_scan_percent, 100);
  assert.match(findingById(healthy, "QUALYS-C17").summary, /capped at warn/);
  assert.ok(findingById(healthy, "QUALYS-C10").mappings.includes("CIS 7.4"));
});

test("assessQualysVulnerabilityManagement: failing fixture", async () => {
  const weak = await assessQualysVulnerabilityManagement(createFakeClient(failingFixtures));
  assert.deepEqual(statusMap(weak), {
    "QUALYS-C08": "fail",
    "QUALYS-C09": "fail",
    "QUALYS-C10": "fail",
    "QUALYS-C11": "fail",
    "QUALYS-C17": "fail",
  });
  assert.equal(findingById(weak, "QUALYS-C10").evidence.sla_breaches, 3);
  assert.deepEqual(findingById(weak, "QUALYS-C10").evidence.breaches_by_severity, { critical: 1, high: 1, medium: 1 });
  assert.deepEqual(findingById(weak, "QUALYS-C09").evidence.unassigned_policies, ["Unassigned policy"]);
});

test("assessQualysVulnerabilityManagement: unreadable fixture is manual everywhere", async () => {
  const unreadable = await assessQualysVulnerabilityManagement(createFakeClient(forbiddenFixtures()));
  assert.ok(unreadable.findings.every((item) => item.status === "manual"));
  assert.ok(unreadable.findings.every((item) => /Collect manually:/.test(item.summary)));

  const noPc = await assessQualysVulnerabilityManagement(createFakeClient({ ...healthyFixtures, listCompliancePolicies: failing("Qualys request failed (403): PC module not subscribed") }));
  assert.equal(findingById(noPc, "QUALYS-C09").status, "manual");
  assert.match(findingById(noPc, "QUALYS-C09").summary, /unlicensed, not applicable, or role not permitted/);

  const noKb = await assessQualysVulnerabilityManagement(createFakeClient({ ...healthyFixtures, listKnowledgeBase: async () => [] }));
  assert.equal(findingById(noKb, "QUALYS-C11").status, "manual");
  assert.match(findingById(noKb, "QUALYS-C11").summary, /knowledge base lookup returned no entries/);
});

test("assessQualysVulnerabilityManagement: empty fixture never passes, and zero detections pass only with a complete read and a non-zero host population", async () => {
  const empty = await assessQualysVulnerabilityManagement(createFakeClient());
  assert.deepEqual(statusMap(empty), {
    "QUALYS-C08": "fail",
    "QUALYS-C09": "manual",
    "QUALYS-C10": "manual",
    "QUALYS-C11": "manual",
    "QUALYS-C17": "manual",
  });
  assert.match(findingById(empty, "QUALYS-C10").summary, /No host assets were returned/);
  assert.match(findingById(empty, "QUALYS-C09").summary, /not applicable if Policy Compliance is not in use/);

  const cleanHosts = await assessQualysVulnerabilityManagement(createFakeClient({ ...healthyFixtures, listDetections: async () => [] }));
  assert.equal(findingById(cleanHosts, "QUALYS-C10").status, "pass");
  assert.match(findingById(cleanHosts, "QUALYS-C10").summary, /Zero open severity 3 to 5 detections across 2 hosts with the detection list read completely; emptiness is compliant/);
  assert.equal(findingById(cleanHosts, "QUALYS-C11").status, "pass");
  assert.equal(findingById(cleanHosts, "QUALYS-C17").status, "manual");

  const cleanTruncated = await assessQualysVulnerabilityManagement(createFakeClient({
    ...healthyFixtures,
    listDetections: async () => truncated([], "page cap 25 reached with a WARNING/URL continuation not followed"),
  }));
  assert.equal(findingById(cleanTruncated, "QUALYS-C10").status, "manual");
  assert.match(findingById(cleanTruncated, "QUALYS-C10").summary, /emptiness cannot be trusted/);
  assert.equal(findingById(cleanTruncated, "QUALYS-C11").status, "manual");

  const noHosts = await assessQualysVulnerabilityManagement(createFakeClient({ ...healthyFixtures, listDetections: async () => [], listHosts: async () => [] }));
  assert.equal(findingById(noHosts, "QUALYS-C10").status, "manual");
  assert.equal(findingById(noHosts, "QUALYS-C08").status, "manual");
});

test("assessQualysVulnerabilityManagement: partial fixture never passes", async () => {
  const partial = await assessQualysVulnerabilityManagement(createFakeClient(partialFixtures(healthyFixtures)));
  assert.ok(partial.findings.every((item) => item.status !== "pass"));
  assert.match(findingById(partial, "QUALYS-C10").summary, /Partial view: detections page cap 25/);

  const capped = await assessQualysVulnerabilityManagement(createFakeClient(healthyFixtures), { detectionLimit: 2 });
  assert.equal(findingById(capped, "QUALYS-C10").status, "warn");
  assert.match(findingById(capped, "QUALYS-C10").summary, /reaching the 2 record cap \(2 seen of cap 2\)/);
  assert.equal(findingById(capped, "QUALYS-C11").status, "warn");
  assert.equal(findingById(capped, "QUALYS-C09").status, "pass", "policies were complete");
});

test("assessQualysAdministration: passing fixture caps the partly manual controls", async () => {
  const healthy = await assessQualysAdministration(createFakeClient(healthyFixtures));
  assert.deepEqual(healthy.findings.map((item) => item.control), [12, 13, 15, 19]);
  assert.deepEqual(statusMap(healthy), {
    "QUALYS-C12": "warn",
    "QUALYS-C13": "manual",
    "QUALYS-C15": "pass",
    "QUALYS-C19": "warn",
  });
  assert.match(findingById(healthy, "QUALYS-C12").summary, /Distribution recipients are not exposed/);
  assert.match(findingById(healthy, "QUALYS-C13").summary, /hides other Manager and Super User accounts/);
  assert.match(findingById(healthy, "QUALYS-C19").summary, /capped at warn/);
  assert.ok(findingById(healthy, "QUALYS-C13").mappings.includes("SOC 2 CC6.3"));
});

test("assessQualysAdministration: failing fixture", async () => {
  const weak = await assessQualysAdministration(createFakeClient(failingFixtures));
  assert.deepEqual(statusMap(weak), {
    "QUALYS-C12": "fail",
    "QUALYS-C13": "fail",
    "QUALYS-C15": "fail",
    "QUALYS-C19": "warn",
  });
  assert.deepEqual(findingById(weak, "QUALYS-C13").evidence.shared_emails, ["ops@example.com"]);
  assert.deepEqual(findingById(weak, "QUALYS-C15").evidence.never_scanned_web_apps, ["Legacy portal"]);
  assert.equal(findingById(weak, "QUALYS-C19").evidence.sensitive_actions.length, 1);
});

test("assessQualysAdministration: unreadable fixture is manual everywhere and marks WAS unlicensed as not applicable", async () => {
  const unreadable = await assessQualysAdministration(createFakeClient(forbiddenFixtures()));
  assert.ok(unreadable.findings.every((item) => item.status === "manual"));
  assert.ok(unreadable.findings.every((item) => /Collect manually:/.test(item.summary)));

  const noWas = await assessQualysAdministration(createFakeClient({ ...healthyFixtures, searchWebApps: failing("Qualys QPS request failed (403): WAS module is not enabled") }));
  assert.equal(findingById(noWas, "QUALYS-C15").status, "manual");
  assert.match(findingById(noWas, "QUALYS-C15").summary, /WAS module is not licensed or not enabled for this API user, so this control is not applicable/);
  assert.equal(findingById(noWas, "QUALYS-C12").status, "warn", "other controls are unaffected");
});

test("assessQualysAdministration: empty fixture never passes", async () => {
  const empty = await assessQualysAdministration(createFakeClient());
  assert.deepEqual(statusMap(empty), {
    "QUALYS-C12": "fail",
    "QUALYS-C13": "manual",
    "QUALYS-C15": "manual",
    "QUALYS-C19": "manual",
  });
  assert.match(findingById(empty, "QUALYS-C13").summary, /cannot see the user list/);
  assert.match(findingById(empty, "QUALYS-C15").summary, /not applicable if no web applications are in scope/);
  assert.match(findingById(empty, "QUALYS-C19").summary, /cannot read the log/);
});

test("assessQualysAdministration: partial fixture never passes", async () => {
  const partial = await assessQualysAdministration(createFakeClient(partialFixtures(healthyFixtures)));
  assert.ok(partial.findings.every((item) => item.status !== "pass"));
  assert.equal(findingById(partial, "QUALYS-C15").status, "warn");
  assert.match(findingById(partial, "QUALYS-C15").summary, /Partial view: was_webapps page cap 25/);
});

test("rule 1: a SIMPLE_RETURN or 403 response through the real client yields manual, never pass, and names the cause", async () => {
  const client = routedClient(forbiddenRouter);
  const results = await runAllAssessments(client);
  const findings = allFindings(results);
  assert.equal(findings.length, 20);
  for (const item of findings) {
    assert.equal(item.status, "manual", `${item.id} must be manual when its evidence is forbidden`);
    assert.match(item.summary, /Collect manually:/);
    assert.match(item.summary, /code 2010|not authorized/);
    assert.ok(item.evidence.collection.sources.some((source) => source.status === "unreadable"));
  }
  assert.ok(results.every((result) => result.errors.length > 0));
});

test("rule 2: empty inventories through the real client never pass and each summary states fail, unknown, or not applicable", async () => {
  const client = routedClient(emptyRouter);
  const findings = allFindings(await runAllAssessments(client));
  assert.equal(findings.length, 20);
  assert.ok(findings.every((item) => item.status !== "pass"));
  for (const item of findings) {
    assert.match(item.summary, /emptiness is a failure|treated as unknown|not applicable|could not be evaluated|always manual|cannot see|cannot read/i, `${item.id}: ${item.summary}`);
  }
  const byId = Object.fromEntries(findings.map((item) => [item.id, item.status]));
  assert.equal(byId["QUALYS-C01"], "fail");
  assert.equal(byId["QUALYS-C03"], "fail");
  assert.equal(byId["QUALYS-C08"], "fail");
  assert.equal(byId["QUALYS-C12"], "fail");
  assert.equal(byId["QUALYS-C18"], "fail");
  assert.equal(byId["QUALYS-C10"], "manual");
  assert.equal(byId["QUALYS-C13"], "manual");
});

test("rule 3: unlicensed PC, WAS, Asset Management, and Cloud Agent modules render as manual with an unlicensed or not applicable summary", async () => {
  const unlicensed = createFakeClient({
    ...healthyFixtures,
    listCompliancePolicies: failing("Qualys request failed (403) for /api/2.0/fo/compliance/policy/: code 2010: Policy Compliance not subscribed"),
    searchWebApps: failing("Qualys QPS request failed (403) for /qps/rest/3.0/search/was/webapp: WAS module is not enabled"),
    searchTags: failing("Qualys QPS request failed (403) for /qps/rest/2.0/search/am/tag: Asset Management module is not enabled"),
    searchConnectors: failing("Qualys QPS request failed (403) for /qps/rest/2.0/search/am/assetdataconnector: Asset Management module is not enabled"),
    searchCloudAgents: failing("Qualys QPS request failed (403) for /qps/rest/2.0/search/am/hostasset: Cloud Agent module is not enabled"),
  });
  const findings = allFindings(await runAllAssessments(unlicensed));
  const byId = Object.fromEntries(findings.map((item) => [item.id, item]));
  for (const id of ["QUALYS-C05", "QUALYS-C07", "QUALYS-C09", "QUALYS-C15", "QUALYS-C18"]) {
    assert.equal(byId[id].status, "manual", `${id} must be manual when its module is unlicensed`);
    assert.match(byId[id].summary, /unlicensed|not applicable/);
  }
  assert.equal(byId["QUALYS-C01"].status, "pass", "VM controls with complete evidence still pass");
  assert.equal(byId["QUALYS-C10"].status, "pass");
});

test("rule 4: records without a date are bucketed, reported, and cap the verdict at warn", async () => {
  const undated = createFakeClient({
    ...healthyFixtures,
    listHosts: async () => [
      ...(await healthyFixtures.listHosts()),
      { ID: "102", IP: "10.0.0.7", OS: "Windows Server 2022", TRACKING_METHOD: "Cloud Agent", TAGS: { TAG: { NAME: "Prod" } } },
    ],
    searchCloudAgents: async () => [
      ...(await healthyFixtures.searchCloudAgents()),
      { id: 102, agentInfo: { status: "STATUS_ACTIVE", activationKey: { title: "prod-key" } } },
    ],
    searchConnectors: async () => [{ id: 1, name: "prod-aws", type: "AWS", connectorState: "FINISHED_SUCCESS" }],
    listDetections: async () => [
      ...(await healthyFixtures.listDetections()),
      { host_id: "102", QID: "91000", TYPE: "Confirmed", SEVERITY: "5", STATUS: "Active", QDS: { "#text": "80" } },
    ],
    searchWasAuthRecords: async () => [{ id: 1, name: "portal-login" }],
    searchUsers: async () => [{ id: 0, username: "acme_api", emailAddress: "api@example.com", roleList: { list: [{ RoleData: { name: "Manager" } }] } }],
  });
  const [scan, inventory, vuln, admin] = await runAllAssessments(undated);

  const auth = findingById(scan, "QUALYS-C02");
  assert.equal(auth.status, "warn");
  assert.equal(auth.evidence.authenticated_percent, 100, "the undated host is excluded from the ratio rather than counted as authenticated");
  assert.equal(auth.evidence.unknown_buckets.hosts_without_scan_date, 1);
  assert.equal(findingById(scan, "QUALYS-C01").status, "warn");

  const agents = findingById(inventory, "QUALYS-C07");
  assert.equal(agents.status, "warn");
  assert.equal(agents.evidence.stale_agents, 0, "an agent without a check-in date is never counted as stale or as fresh");
  assert.equal(agents.evidence.unknown_buckets.agents_without_checkin_date, 1);
  const connectors = findingById(inventory, "QUALYS-C05");
  assert.equal(connectors.status, "warn");
  assert.equal(connectors.evidence.unknown_buckets.connectors_without_sync_date, 1);

  const sla = findingById(vuln, "QUALYS-C10");
  assert.equal(sla.status, "warn");
  assert.equal(sla.evidence.sla_dated_detections, 2);
  assert.equal(sla.evidence.sla_compliance_percent, 100);
  assert.equal(sla.evidence.unknown_buckets.detections_without_first_found, 1);
  assert.match(sla.summary, /1 detections without a first-found date were excluded from the compliant count/);
  const patch = findingById(vuln, "QUALYS-C11");
  assert.equal(patch.status, "warn");
  assert.equal(patch.evidence.unknown_buckets.patchable_detections_without_first_found, 1);

  const was = findingById(admin, "QUALYS-C15");
  assert.equal(was.status, "warn");
  assert.equal(was.evidence.unknown_buckets.was_auth_records_without_date, 1);
  assert.equal(findingById(admin, "QUALYS-C13").evidence.unknown_buckets.users_without_last_login, 1);

  const onlyUndated = await assessQualysVulnerabilityManagement(createFakeClient({
    ...healthyFixtures,
    listDetections: async () => [{ host_id: "100", QID: "91000", TYPE: "Confirmed", SEVERITY: "5", STATUS: "Active" }],
  }));
  assert.equal(findingById(onlyUndated, "QUALYS-C10").status, "warn");
  assert.match(findingById(onlyUndated, "QUALYS-C10").summary, /none carries FIRST_FOUND_DATETIME/);
});

test("rule 5: sampling caps and a scoped API role flag a partial view instead of passing", async () => {
  const capped = await runAllAssessments(createFakeClient(healthyFixtures), { hostLimit: 2, detectionLimit: 2 });
  const cappedIds = ["QUALYS-C01", "QUALYS-C02", "QUALYS-C07", "QUALYS-C08", "QUALYS-C10", "QUALYS-C11", "QUALYS-C18"];
  for (const item of allFindings(capped)) {
    if (cappedIds.includes(item.id)) {
      assert.equal(item.status, "warn", `${item.id} must downgrade when a capped list reached its cap`);
      assert.match(item.summary, /Partial view: .*reaching the 2 record cap \(2 seen of cap 2\)/);
      assert.ok(item.evidence.collection.sources.some((source) => source.status === "truncated" && source.cap === 2));
    }
    assert.notEqual(item.status, "pass" && cappedIds.includes(item.id) ? "pass" : "never");
  }

  const reader = createFakeClient({
    ...healthyFixtures,
    searchUsers: async () => [{ id: 0, username: "acme_api", emailAddress: "api@example.com", roleList: { list: [{ RoleData: { name: "Reader" } }] } }],
  });
  const readerFindings = allFindings(await runAllAssessments(reader));
  assert.ok(readerFindings.every((item) => item.status !== "pass"), "a Reader role can only see its own asset groups, so nothing may pass");
  const wouldPass = readerFindings.filter((item) => item.evidence.verdict_basis === "pass");
  assert.ok(wouldPass.length >= 10);
  for (const item of wouldPass) {
    assert.equal(item.status, "warn");
    assert.match(item.summary, /Partial view: API user acme_api holds role Reader/);
    assert.equal(item.evidence.collection.view_scope.partial, true);
  }

  const scopedManager = await assessQualysScanCoverage(createFakeClient({
    ...healthyFixtures,
    searchUsers: async () => [{ id: 0, username: "acme_api", roleList: { list: [{ RoleData: { name: "Manager" } }] }, scopeTags: { list: [{ TagData: { name: "BU-East" } }] } }],
  }));
  assert.equal(findingById(scopedManager, "QUALYS-C01").status, "warn");
  assert.match(findingById(scopedManager, "QUALYS-C01").summary, /scoped to tags BU-East/);

  const hasMore = await assessQualysAdministration(createFakeClient({
    ...healthyFixtures,
    searchWebApps: async () => truncated(await healthyFixtures.searchWebApps(), "item cap 5000 reached with hasMoreRecords true"),
  }));
  assert.equal(findingById(hasMore, "QUALYS-C15").status, "warn");
  assert.match(findingById(hasMore, "QUALYS-C15").summary, /hasMoreRecords true \(1 seen of cap 5000\)/);
});

test("rule 6: a value whose enabling flag is false or absent never supports pass", async () => {
  const flagless = createFakeClient({
    ...healthyFixtures,
    listScheduledScans: async () => [
      { ID: "1", TITLE: "No flag", TARGET: "10.0.0.0/24" },
      { ID: "2", ACTIVE: "", TITLE: "Empty flag", TARGET: "203.0.113.0/28" },
    ],
    listCompliancePolicies: async () => [
      { ID: "5", TITLE: "CIS Baseline", STATUS: "active", ASSET_GROUP_IDS: "10" },
      { ID: "6", TITLE: "No status", ASSET_GROUP_IDS: "10" },
      { ID: "7", TITLE: "Hidden groups", STATUS: "active", ASSET_GROUP_IDS: { "@has_hidden_data": "1", "#text": "" } },
    ],
    listDetections: async () => [
      ...(await healthyFixtures.listDetections()),
      { host_id: "100", QID: "77000", TYPE: "Confirmed", SEVERITY: "5", STATUS: "Fixed", FIRST_FOUND_DATETIME: daysAgo(400) },
      { host_id: "100", QID: "78000", TYPE: "Info", STATUS: "Active", FIRST_FOUND_DATETIME: daysAgo(400) },
      { host_id: "100", QID: "79000", TYPE: "Confirmed", STATUS: "Active", FIRST_FOUND_DATETIME: daysAgo(2) },
    ],
    listKnowledgeBase: async () => [{ QID: "91000", PATCHABLE: "1" }, { QID: "38000", PATCHABLE: "0" }, { QID: "79000", PATCHABLE: "0" }],
    searchCloudAgents: async () => [
      ...(await healthyFixtures.searchCloudAgents()),
      { id: 102, agentInfo: { lastCheckedIn: daysAgo(0), activationKey: { title: "prod-key" } } },
    ],
    listHosts: async () => [
      ...(await healthyFixtures.listHosts()),
      { ID: "102", IP: "10.0.0.7", OS: "Windows Server 2022", LAST_VULN_SCAN_DATETIME: daysAgo(1), LAST_VM_AUTH_SCANNED_DATE: daysAgo(1), TAGS: { TAG: { NAME: "Prod" } } },
    ],
    searchWasSchedules: async () => [{ id: 1 }],
    searchUsers: async () => [
      { id: 0, username: "acme_api", emailAddress: "api@example.com", roleList: { list: [{ RoleData: { name: "Manager" } }] } },
      { id: 3, username: "no_role", emailAddress: "norole@example.com" },
    ],
  });
  const [scan, inventory, vuln, admin] = await runAllAssessments(flagless);

  const schedules = findingById(scan, "QUALYS-C01");
  assert.equal(schedules.status, "fail", "schedules without an ACTIVE=1 flag are not active");
  assert.equal(schedules.evidence.active_schedules, 0);
  assert.equal(schedules.evidence.schedules_without_active_flag, 2);
  assert.equal(findingById(scan, "QUALYS-C14").status, "fail");

  const policies = findingById(vuln, "QUALYS-C09");
  assert.equal(policies.status, "warn");
  assert.equal(policies.evidence.unknown_buckets.policies_without_status, 1);
  assert.equal(policies.evidence.unknown_buckets.policies_with_hidden_asset_groups, 1);
  assert.deepEqual(policies.evidence.unassigned_policies, []);

  const sla = findingById(vuln, "QUALYS-C10");
  assert.equal(sla.evidence.fixed_or_info_excluded, 2, "Fixed and Info detections are read and excluded");
  assert.equal(sla.evidence.sla_breaches, 0);
  assert.equal(sla.evidence.unknown_buckets.detections_without_severity, 1);
  assert.equal(sla.status, "warn");

  const agents = findingById(inventory, "QUALYS-C07");
  assert.equal(agents.status, "warn");
  assert.equal(agents.evidence.unknown_buckets.agents_without_status, 1);
  assert.equal(agents.evidence.unknown_buckets.hosts_without_tracking_method, 1);
  assert.equal(agents.evidence.inactive_agents, 0);

  const was = findingById(admin, "QUALYS-C15");
  assert.equal(was.status, "warn");
  assert.equal(was.evidence.active_schedules, 0);
  assert.equal(was.evidence.unknown_buckets.was_schedules_without_active_flag, 1);
  assert.equal(findingById(admin, "QUALYS-C13").evidence.unknown_buckets.users_without_role, 1);

  const noAuthProfile = await assessQualysScanCoverage(createFakeClient({
    ...healthyFixtures,
    listOptionProfiles: async () => [{ BASIC_INFO: { ID: "7", GROUP_NAME: "Silent" }, SCAN: {} }],
  }));
  assert.deepEqual(findingById(noAuthProfile, "QUALYS-C03").evidence.profiles_without_authentication, ["Silent"]);

  const unknownAppliance = await assessQualysAssetInventory(createFakeClient({
    ...healthyFixtures,
    listAppliances: async () => [{ ID: "2", NAME: "mystery" }],
  }));
  assert.equal(findingById(unknownAppliance, "QUALYS-C06").status, "warn");
  assert.equal(findingById(unknownAppliance, "QUALYS-C06").evidence.unknown_buckets.appliances_without_status, 1);
});

test("rule 7: a truncated collection through the real client downgrades the verdict", async () => {
  const client = routedClient(partialRouter);
  const result = await assessQualysScanCoverage(client, { hostLimit: 3 });
  const auth = findingById(result, "QUALYS-C02");
  assert.equal(auth.status, "warn");
  assert.equal(auth.evidence.verdict_basis, "pass");
  assert.match(auth.summary, /Partial view: hosts item cap 3 reached with more records available \(3 seen of cap 3\)/);
  assert.ok(result.findings.every((item) => item.status !== "pass"));
});

test("rule 8: re-running an export never overwrites a prior bundle and the zip name follows the allocated directory", async () => {
  const outputRoot = createTempBase("qualys-rerun-");
  const config = sampleConfig();
  const client = createFakeClient(healthyFixtures, config);

  const first = await exportQualysAuditBundle(client, config, outputRoot);
  const second = await exportQualysAuditBundle(client, config, outputRoot);
  assert.notEqual(first.outputDir, second.outputDir);
  assert.notEqual(first.zipPath, second.zipPath);
  assert.equal(first.zipPath, bundleZipPath(first.outputDir));
  assert.equal(second.zipPath, bundleZipPath(second.outputDir));
  assert.equal(second.outputDir, `${first.outputDir}-2`);
  assert.ok(existsSync(first.zipPath));
  assert.ok(existsSync(second.zipPath));

  const firstZipSize = statSync(first.zipPath).size;
  rmSync(first.outputDir, { recursive: true, force: true });
  const third = await exportQualysAuditBundle(client, config, outputRoot);
  assert.notEqual(third.outputDir, first.outputDir, "a leftover zip must block reuse of its directory name");
  assert.equal(third.outputDir, `${first.outputDir}-3`);
  assert.equal(statSync(first.zipPath).size, firstZipSize, "the prior archive is untouched");
});

test("false-pass self-check (a): every endpoint forbidden yields zero pass across all four tools", async () => {
  const findings = allFindings(await runAllAssessments(routedClient(forbiddenRouter)));
  assert.equal(findings.length, 20);
  assert.deepEqual(findings.filter((item) => item.status === "pass").map((item) => item.id), []);
  assert.equal(findings.filter((item) => item.status === "manual").length, 20);
});

test("false-pass self-check (b): every list empty yields zero pass because no control treats an unread or context-free emptiness as compliant", async () => {
  const findings = allFindings(await runAllAssessments(routedClient(emptyRouter)));
  assert.equal(findings.length, 20);
  assert.deepEqual(findings.filter((item) => item.status === "pass").map((item) => item.id), []);
  const counts = findings.reduce((total, item) => ({ ...total, [item.status]: (total[item.status] ?? 0) + 1 }), {});
  assert.deepEqual(counts, { fail: 7, manual: 13 });
  const failing = findings.filter((item) => item.status === "fail").map((item) => item.id).sort();
  assert.deepEqual(failing, ["QUALYS-C01", "QUALYS-C03", "QUALYS-C08", "QUALYS-C12", "QUALYS-C14", "QUALYS-C18", "QUALYS-C20"]);
});

test("false-pass self-check (c): a partial inventory with caps, unfollowed continuations, and hasMoreRecords yields zero pass", async () => {
  const findings = allFindings(await runAllAssessments(routedClient(partialRouter), { hostLimit: 3, detectionLimit: 3 }));
  assert.equal(findings.length, 20);
  assert.deepEqual(findings.filter((item) => item.status === "pass").map((item) => item.id), []);
  const downgraded = findings.filter((item) => item.evidence.verdict_basis === "pass");
  assert.ok(downgraded.length >= 8, `expected several would-be passes to be downgraded, got ${downgraded.length}`);
  for (const item of downgraded) {
    assert.equal(item.status, "warn");
    assert.match(item.summary, /Partial view/);
  }
  for (const item of findings) {
    assert.ok(item.evidence.collection.sources.some((source) => source.status === "truncated" || source.status === "unreadable"), `${item.id} should record a truncated source`);
  }
});

test("all four assessments together cover every one of the 20 spec controls with framework mappings and collection evidence", async () => {
  const results = await runAllAssessments(createFakeClient(healthyFixtures));
  const findings = allFindings(results);
  const controls = findings.map((item) => item.control).sort((a, b) => a - b);
  assert.deepEqual(controls, Array.from({ length: 20 }, (_, index) => index + 1));
  for (const item of findings) {
    assert.ok(["critical", "high", "medium", "low", "info"].includes(item.severity));
    assert.ok(["pass", "warn", "fail", "manual"].includes(item.status));
    assert.ok(item.mappings.length >= 7, `${item.id} should carry framework mappings`);
    assert.ok(item.mappings.some((mapping) => mapping.startsWith("FedRAMP ")));
    assert.ok(item.mappings.some((mapping) => mapping.startsWith("ISMAP ")));
    assert.equal(typeof item.summary, "string");
    assert.equal(typeof item.manual_evidence === "undefined" ? item.evidence.manual_evidence : item.manual_evidence, item.evidence.manual_evidence);
    assert.ok(Array.isArray(item.evidence.collection.sources) && item.evidence.collection.sources.length > 0);
    assert.ok(["pass", "warn", "fail", "manual"].includes(item.evidence.verdict_basis));
  }
  assert.deepEqual(
    findings.filter((item) => item.status === "pass").map((item) => item.id).sort(),
    ["QUALYS-C01", "QUALYS-C02", "QUALYS-C05", "QUALYS-C06", "QUALYS-C07", "QUALYS-C08", "QUALYS-C09", "QUALYS-C10", "QUALYS-C11", "QUALYS-C14", "QUALYS-C15", "QUALYS-C16", "QUALYS-C18"],
  );
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
  assert.equal(result.zipPath, `${result.outputDir}.zip`);
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
  const executive = readFileSync(join(result.outputDir, "compliance/executive_summary.md"), "utf8");
  assert.match(executive, /Manual controls: 3/);
  assert.match(executive, /Passing controls: 12/);
  assert.match(readFileSync(join(result.outputDir, "compliance/fedramp/fedramp_compliance_report.md"), "utf8"), /RA-5\(3\)/);
  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis/findings.json"), "utf8"));
  assert.equal(findings.find((item) => item.id === "QUALYS-C09").status, "manual");
  const metadata = JSON.parse(readFileSync(join(result.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.platform, "US1");
  assert.equal(JSON.stringify(metadata).includes(config.password), false);
  assert.equal(readFileSync(join(result.outputDir, "core_data/access.json"), "utf8").includes(config.password), false);

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
