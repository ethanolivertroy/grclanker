import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { inflateRawSync } from "node:zlib";

import {
  QUALYS_PLATFORMS,
  QualysApiClient,
  QualysApiError,
  SURFACE_ENDPOINTS,
  assessQualysAdministration,
  assessQualysAssetInventory,
  assessQualysScanCoverage,
  assessQualysVulnerabilityManagement,
  bundleZipPath,
  checkQualysAccess,
  credentialValues,
  exportQualysAuditBundle,
  exportableRecords,
  normalizeList,
  parseCsv,
  parseXml,
  rawDataSurfaceNames,
  registerQualysTools,
  resolveQualysConfiguration,
  resolveQualysPlatform,
  resolveSecureOutputPath,
  resolveViewScope,
  scrubErrorText,
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

// ---------------------------------------------------------------------------------------------
// Documented-shape builders. Every record below follows the published DTD or XSD for its endpoint
// (schedule_scan_list_output.dtd, host_list_output.dtd, option_profile_info.dtd,
// appliance_list_output.dtd, asset_group_list_output.dtd, policy_list_output.dtd,
// schedule_report_list_output.dtd, report_list_output.dtd, user_list_output.dtd, user.xsd,
// hostasset.xsd with agent_source.xsd, asset_data_connector.xsd, tag.xsd, webapp.xsd, wasscan.xsd,
// webappauthrecord.xsd, wasscanschedule.xsd). Objects mirror what xmlToRecord produces: attributes
// as "@name", element text as "#text" when attributes are present, repeated elements as arrays.
// ---------------------------------------------------------------------------------------------

function escapeXml(value) {
  return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function xmlFromRecord(name, value) {
  if (value === undefined) return "";
  if (Array.isArray(value)) return value.map((item) => xmlFromRecord(name, item)).join("");
  if (value === null || typeof value !== "object") return `<${name}>${escapeXml(value)}</${name}>`;
  const attributes = Object.entries(value)
    .filter(([key]) => key.startsWith("@"))
    .map(([key, item]) => ` ${key.slice(1)}="${escapeXml(item)}"`)
    .join("");
  const text = value["#text"] === undefined ? "" : escapeXml(value["#text"]);
  const children = Object.entries(value)
    .filter(([key]) => !key.startsWith("@") && key !== "#text")
    .map(([key, item]) => xmlFromRecord(key, item))
    .join("");
  return `<${name}${attributes}>${text}${children}</${name}>`;
}

function listOutputXml(root, listName, itemName, items) {
  return `<?xml version="1.0" encoding="UTF-8" ?><${root}><RESPONSE><DATETIME>${daysAgo(0)}</DATETIME><${listName}>${xmlFromRecord(itemName, items)}</${listName}></RESPONSE></${root}>`;
}

function userListXml(users) {
  return `<?xml version="1.0" encoding="UTF-8" ?><!DOCTYPE USER_LIST_OUTPUT SYSTEM "https://qualysapi.qualys.com/user_list_output.dtd"><USER_LIST_OUTPUT><USER_LIST>${xmlFromRecord("USER", users)}</USER_LIST></USER_LIST_OUTPUT>`;
}

const SCHEDULE_TIME_ZONE = { TIME_ZONE_CODE: "US-CA", TIME_ZONE_DETAILS: "(GMT-0800) United States: America/Los_Angeles" };

// schedule_scan_list_output.dtd: SCAN (ID, SCAN_TYPE?, ACTIVE, TITLE?, CLIENT?, USER_LOGIN, TARGET, NETWORK_ID?,
// ISCANNER_NAME?, ..., ASSET_GROUP_TITLE_LIST?, ASSET_TAGS?, ..., USER_ENTERED_IPS?, ..., OPTION_PROFILE?,
// PROCESSING_PRIORITY?, SCHEDULE, NOTIFICATIONS?)
function documentedSchedule(overrides = {}) {
  return {
    ID: "160642",
    ACTIVE: "1",
    TITLE: "My Daily Scan",
    USER_LOGIN: "acme_api",
    TARGET: "10.10.10.10-10.10.10.20",
    NETWORK_ID: "0",
    ISCANNER_NAME: "dmz-scanner",
    USER_ENTERED_IPS: { RANGE: { START: "10.10.10.10", END: "10.10.10.20" } },
    OPTION_PROFILE: { TITLE: "Initial Options", DEFAULT_FLAG: "1" },
    PROCESSING_PRIORITY: "0 - No Priority",
    SCHEDULE: {
      DAILY: { "@frequency_days": "1" },
      START_DATE_UTC: "2017-11-30T00:30:00Z",
      START_HOUR: "16",
      START_MINUTE: "30",
      NEXTLAUNCH_UTC: daysAgo(-1),
      TIME_ZONE: SCHEDULE_TIME_ZONE,
      DST_SELECTED: "1",
    },
    ...overrides,
  };
}

// schedule_scan_list_output.dtd: ASSET_TAGS (TAG_INCLUDE_SELECTOR, TAG_SET_INCLUDE (#PCDATA), TAG_EXCLUDE_SELECTOR?,
// TAG_SET_EXCLUDE?, USE_IP_NT_RANGE_TAGS?, USE_IP_NT_RANGE_TAGS_INCLUDE, USE_IP_NT_RANGE_TAGS_EXCLUDE?)
function documentedAssetTags(tagSetInclude) {
  return { TAG_INCLUDE_SELECTOR: "any", TAG_SET_INCLUDE: tagSetInclude, USE_IP_NT_RANGE_TAGS: "0", USE_IP_NT_RANGE_TAGS_INCLUDE: "0" };
}

// scan_list_output.dtd: SCAN (ID?, REF, SCAN_TYPE?, TYPE, TITLE, CLIENT?, USER_LOGIN, LAUNCH_DATETIME, DURATION,
// PROCESSING_PRIORITY?, PROCESSED, STATUS?, TARGET?, ...) with STATUS (STATE, SUB_STATE?)
function documentedScan(overrides = {}) {
  return {
    REF: "scan/1758000000.12345",
    TYPE: "Scheduled",
    TITLE: "Internal weekly",
    USER_LOGIN: "acme_api",
    LAUNCH_DATETIME: daysAgo(2),
    DURATION: "00:42:10",
    PROCESSING_PRIORITY: "0 - No Priority",
    PROCESSED: "1",
    STATUS: { STATE: "Finished" },
    TARGET: "10.0.0.1-10.0.0.254",
    ...overrides,
  };
}

// host_list_output.dtd (details=All, show_tags=1): HOST with ID, IP, TRACKING_METHOD, DNS, OS, LAST_VULN_SCAN_DATETIME,
// LAST_VM_SCANNED_DATE, LAST_VM_AUTH_SCANNED_DATE, TAGS (TAG (TAG_ID, NAME))
function documentedHost(overrides = {}) {
  return {
    ID: "100",
    IP: "10.0.0.5",
    TRACKING_METHOD: "Cloud Agent",
    DNS: "web-01.example.com",
    OS: "Windows Server 2022",
    LAST_VULN_SCAN_DATETIME: daysAgo(2),
    LAST_VM_SCANNED_DATE: daysAgo(2),
    LAST_VM_SCANNED_DURATION: "600",
    LAST_VM_AUTH_SCANNED_DATE: daysAgo(2),
    LAST_VM_AUTH_SCANNED_DURATION: "600",
    TAGS: { TAG: [{ TAG_ID: "1", NAME: "PCI" }, { TAG_ID: "2", NAME: "Prod" }] },
    ...overrides,
  };
}

// option_profile_info.dtd, values from the guide "Sample - List VM Option Profile" (option_profile/vm/?action=list)
function documentedOptionProfile(overrides = {}) {
  return {
    BASIC_INFO: {
      ID: "51451401",
      GROUP_NAME: "Authenticated Full",
      GROUP_TYPE: "user",
      USER_ID: "John smith (jsmith_ap)",
      UNIT_ID: "0",
      SUBSCRIPTION_ID: "10421401",
      IS_DEFAULT: "0",
      IS_GLOBAL: "1",
      IS_OFFLINE_SYNCABLE: "1",
      UPDATE_DATE: "2018-04-10T13:39:41Z",
    },
    SCAN: {
      PORTS: { TCP_PORTS: { TCP_PORTS_TYPE: "standard", THREE_WAY_HANDSHAKE: "1" }, UDP_PORTS: { UDP_PORTS_TYPE: "light" }, AUTHORITATIVE_OPTION: "1" },
      SCAN_DEAD_HOSTS: "1",
      PERFORMANCE: { PARALLEL_SCALING: "1", OVERALL_PERFORMANCE: "Normal" },
      VULNERABILITY_DETECTION: { COMPLETE: "complete", DETECTION_INCLUDE: { BASIC_HOST_INFO_CHECKS: "0", OVAL_CHECKS: "1" } },
      AUTHENTICATION: "Windows,Unix",
    },
    ...overrides,
  };
}

// appliance_list_output.dtd: APPLIANCE (ID, UUID, NAME, ..., SOFTWARE_VERSION, RUNNING_SLICES_COUNT, RUNNING_SCAN_COUNT,
// STATUS, ..., ML_LATEST?, ML_VERSION?, VULNSIGS_LATEST?, VULNSIGS_VERSION?, ..., LAST_UPDATED_DATE?, ..., HEARTBEATS_MISSED?)
function documentedAppliance(overrides = {}) {
  return {
    ID: "1",
    UUID: "f0e2b1c4-6d1a-4d1e-9a8c-1f2e3d4c5b6a",
    NAME: "dmz-scanner",
    SOFTWARE_VERSION: "12.7.50-1",
    RUNNING_SLICES_COUNT: "0",
    RUNNING_SCAN_COUNT: "0",
    STATUS: "Online",
    ML_LATEST: "12.7.50-1",
    ML_VERSION: { "@updated": "yes", "#text": "12.7.50-1" },
    VULNSIGS_LATEST: "2.6.212-3",
    VULNSIGS_VERSION: { "@updated": "yes", "#text": "2.6.212-3" },
    LAST_UPDATED_DATE: daysAgo(0),
    HEARTBEATS_MISSED: "0",
    ...overrides,
  };
}

// asset_group_list_output.dtd: ASSET_GROUP (ID, TITLE, OWNER_USER_ID?, UNIT_ID?, LAST_UPDATE?, IP_SET?, ...)
function documentedAssetGroup(overrides = {}) {
  return { ID: "10", TITLE: "Internal", OWNER_USER_ID: "1001", UNIT_ID: "0", LAST_UPDATE: daysAgo(20), IP_SET: { IP_RANGE: "10.0.0.1-10.0.0.254" }, ...overrides };
}

// policy_list_output.dtd: POLICY (ID, TITLE, CREATED?, LAST_MODIFIED?, STATUS?, ASSET_GROUP_IDS?, TAG_SET_INCLUDE?, ...)
function documentedPolicy(overrides = {}) {
  return {
    ID: "5",
    TITLE: "CIS Baseline",
    CREATED: { DATETIME: "2024-02-01T10:00:00Z", BY: "acme_mgr" },
    LAST_MODIFIED: { DATETIME: daysAgo(40), BY: "acme_mgr" },
    STATUS: "active",
    ASSET_GROUP_IDS: "10,11",
    ...overrides,
  };
}

// host_list_vm_detection_output.dtd: DETECTION (QID, TYPE, SEVERITY?, PORT?, PROTOCOL?, SSL?, RESULTS?, STATUS?,
// FIRST_FOUND_DATETIME?, LAST_FOUND_DATETIME?, QDS?, TIMES_FOUND?, LAST_TEST_DATETIME?, LAST_UPDATE_DATETIME?, IS_IGNORED?, IS_DISABLED?)
function documentedDetection(overrides = {}) {
  return {
    QID: "91000",
    TYPE: "Confirmed",
    SEVERITY: "5",
    SSL: "0",
    RESULTS: "Vulnerable version detected",
    STATUS: "Active",
    FIRST_FOUND_DATETIME: daysAgo(3),
    LAST_FOUND_DATETIME: daysAgo(1),
    QDS: { "@severity": "HIGH", "#text": "72" },
    TIMES_FOUND: "3",
    LAST_TEST_DATETIME: daysAgo(1),
    LAST_UPDATE_DATETIME: daysAgo(1),
    IS_IGNORED: "0",
    IS_DISABLED: "0",
    ...overrides,
  };
}

// knowledge_base_vuln_list_output.dtd: VULN (QID, VULN_TYPE, SEVERITY_LEVEL, TITLE, ..., PATCHABLE, ...)
function documentedVuln(overrides = {}) {
  return { QID: "91000", VULN_TYPE: "Vulnerability", SEVERITY_LEVEL: "5", TITLE: "Remote code execution", PATCHABLE: "1", ...overrides };
}

// schedule_report_list_output.dtd: REPORT (ID, TITLE?, OUTPUT_FORMAT, TEMPLATE_TITLE?, ACTIVE, SCHEDULE)
function documentedScheduledReport(overrides = {}) {
  return {
    ID: "3",
    TITLE: "Weekly executive report",
    OUTPUT_FORMAT: "pdf",
    TEMPLATE_TITLE: "Executive Report",
    ACTIVE: "1",
    SCHEDULE: {
      WEEKLY: { "@frequency_weeks": "1", "@weekdays": "1" },
      START_DATE_UTC: "2024-03-04T06:00:00Z",
      START_HOUR: "6",
      START_MINUTE: "0",
      TIME_ZONE: SCHEDULE_TIME_ZONE,
      DST_SELECTED: "0",
    },
    ...overrides,
  };
}

// report_list_output.dtd: REPORT (ID, TITLE?, CLIENT?, TYPE, USER_LOGIN, LAUNCH_DATETIME, OUTPUT_FORMAT, SIZE, STATUS, EXPIRATION_DATETIME)
function documentedReport(overrides = {}) {
  return {
    ID: "9",
    TITLE: "Weekly executive report",
    TYPE: "Scan",
    USER_LOGIN: "acme_api",
    LAUNCH_DATETIME: daysAgo(1),
    OUTPUT_FORMAT: "PDF",
    SIZE: "1.2 MB",
    STATUS: { STATE: "Finished" },
    EXPIRATION_DATETIME: daysAgo(-6),
    ...overrides,
  };
}

// user_list_output.dtd: USER (USER_LOGIN?, USER_ID?, EXTERNAL_ID?, CONTACT_INFO, ASSIGNED_ASSET_GROUPS?, USER_STATUS,
// CREATION_DATE, LAST_LOGIN_DATE?, USER_ROLE?, BUSINESS_UNIT?, ...) with CONTACT_INFO (FIRSTNAME, LASTNAME, TITLE, PHONE, FAX,
// EMAIL, COMPANY, ADDRESS1, ADDRESS2, CITY, COUNTRY, STATE, ZIP_CODE, TIME_ZONE_CODE)
function legacyUser(options = {}) {
  const login = options.login ?? "acme_api";
  const user = {
    USER_LOGIN: login,
    USER_ID: options.id ?? "1001",
    CONTACT_INFO: {
      FIRSTNAME: options.firstName ?? "Api",
      LASTNAME: options.lastName ?? "Account",
      TITLE: "",
      PHONE: "",
      FAX: "",
      EMAIL: options.email ?? `${login}@example.com`,
      COMPANY: "Acme",
      ADDRESS1: "",
      ADDRESS2: "",
      CITY: "",
      COUNTRY: "United States of America",
      STATE: "",
      ZIP_CODE: "",
      TIME_ZONE_CODE: "",
    },
    USER_STATUS: options.status ?? "Active",
    CREATION_DATE: "2024-01-05T10:00:00Z",
  };
  if (options.lastLogin !== null) user.LAST_LOGIN_DATE = options.lastLogin ?? daysAgo(1);
  if (options.role !== null) user.USER_ROLE = options.role ?? "Reader";
  user.BUSINESS_UNIT = options.businessUnit ?? "Unassigned";
  if (options.hideLogin) {
    // Restricted view (guide "Sub-user Permissions"): user login, user ID, and external ID are not visible.
    delete user.USER_LOGIN;
    delete user.USER_ID;
  }
  return user;
}

// user.xsd (Administration API search/am/user): id, username, firstName, lastName, title, emailAddress, roleList, scopeTags
function adminUser(id, username, role, overrides = {}) {
  return {
    id,
    username,
    firstName: username.split("_")[0],
    lastName: "Account",
    title: "",
    emailAddress: `${username}@example.com`,
    roleList: { count: 1, list: [{ RoleData: { id: /manager/i.test(role) ? 1 : 2, name: role } }] },
    ...overrides,
  };
}

// hostasset.xsd with agent_source.xsd: agentInfo (agentVersion, agentId, status, lastCheckedIn, platform, activationKey (activationId, title), manifestVersion)
function documentedAgent(overrides = {}) {
  return {
    id: 100,
    name: "web-01.example.com",
    created: daysAgo(200),
    modified: daysAgo(0),
    trackingMethod: "QAGENT",
    agentInfo: {
      agentVersion: "6.1.0.36",
      agentId: "4d7f2c0a-1b2c-4d5e-8f90-1a2b3c4d5e6f",
      status: "STATUS_ACTIVE",
      lastCheckedIn: { date: daysAgo(0) },
      platform: "WINDOWS",
      activationKey: { activationId: "0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b", title: "prod-key" },
      manifestVersion: { vm: "2.6.212-3", pc: "2.6.212-3" },
    },
    ...overrides,
  };
}

// asset_data_connector.xsd: id, name, awsAccountId, description, lastSync, lastError, connectorState, type, disabled; the
// AWS connector documentation adds arn and externalId (credential material).
function documentedConnector(overrides = {}) {
  return {
    id: 1,
    name: "prod-aws",
    awsAccountId: "123456789012",
    description: "Production account",
    lastSync: daysAgo(0),
    connectorState: "FINISHED_SUCCESS",
    type: "AWS",
    disabled: false,
    arn: "arn:aws:iam::123456789012:role/qualys-connector",
    externalId: "connector-external-id-1",
    ...overrides,
  };
}

// tag.xsd: id, name, created, modified, ruleType (TagRuleType, STATIC among the values)
function documentedTag(overrides = {}) {
  return { id: 1, name: "PCI", created: daysAgo(300), modified: daysAgo(30), ruleType: "NAME_CONTAINS", ...overrides };
}

// webapp.xsd: WebApp (id, name, url, ..., lastScan (WasScan reference: id and name only), createdDate, updatedDate)
function documentedWebApp(overrides = {}) {
  return {
    id: 500,
    name: "Portal",
    url: "https://portal.example.com",
    createdDate: daysAgo(300),
    updatedDate: daysAgo(4),
    lastScan: { id: 1, name: "Portal weekly" },
    ...overrides,
  };
}

// wasscan.xsd: WasScan (id, name, type (VULNERABILITY|DISCOVERY), target (webApp (id, name, url)), launchedDate, status)
function documentedWasScan(overrides = {}) {
  return {
    id: 1,
    name: "Portal weekly",
    type: "VULNERABILITY",
    target: { webApp: { id: 500, name: "Portal", url: "https://portal.example.com" } },
    launchedDate: daysAgo(4),
    status: "FINISHED",
    ...overrides,
  };
}

// webappauthrecord.xsd: WebAppAuthRecord (id, name, owner, formRecord (type, sslOnly, fields (count, list (WebAppAuthFormRecordField
// (id, name, secured, value)))), createdDate, updatedDate)
function documentedWasAuthRecord(overrides = {}) {
  return {
    id: 1,
    name: "portal-login",
    owner: { id: 1001, username: "acme_api" },
    formRecord: {
      type: "STANDARD",
      sslOnly: false,
      fields: {
        count: 2,
        list: [
          { WebAppAuthFormRecordField: { id: 1, name: "username", secured: false, value: "portal_user" } },
          { WebAppAuthFormRecordField: { id: 2, name: "password", secured: true, value: "portal-form-password" } },
        ],
      },
    },
    createdDate: daysAgo(30),
    updatedDate: daysAgo(10),
    ...overrides,
  };
}

// wasscanschedule.xsd: WasScanSchedule (id, name, type, active (xs:boolean), target)
function documentedWasSchedule(overrides = {}) {
  return { id: 1, name: "Portal weekly", type: "VULNERABILITY", active: true, target: { webApp: { id: 500, name: "Portal" } }, ...overrides };
}

// A fully compliant tenant built only from the documented shapes above. The fake-client fixtures and the routed
// compliant fixture (d) both read from it, so the assessors see the same tenant through the real parser and directly.
const tenant = {
  schedules: [
    documentedSchedule({
      ID: "1",
      TITLE: "Internal weekly",
      TARGET: "10.0.0.1-10.0.0.254",
      ISCANNER_NAME: "dmz-scanner",
      ASSET_GROUP_TITLE_LIST: { ASSET_GROUP_TITLE: "Internal" },
      USER_ENTERED_IPS: { RANGE: { START: "10.0.0.1", END: "10.0.0.254" } },
      SCHEDULE: { WEEKLY: { "@frequency_weeks": "1", "@weekdays": "1" }, START_DATE_UTC: "2024-03-04T02:00:00Z", START_HOUR: "2", START_MINUTE: "0", NEXTLAUNCH_UTC: daysAgo(-2), TIME_ZONE: SCHEDULE_TIME_ZONE, DST_SELECTED: "0" },
    }),
    documentedSchedule({
      ID: "2",
      TITLE: "Perimeter",
      TARGET: "Asset Tags Included",
      ISCANNER_NAME: "External Scanner",
      USER_ENTERED_IPS: undefined,
      ASSET_TAGS: documentedAssetTags("DMZ"),
    }),
  ],
  scans: [documentedScan()],
  hosts: [
    documentedHost(),
    documentedHost({ ID: "101", IP: "10.0.0.6", DNS: "app-01.example.com", OS: "Ubuntu Linux 22.04", LAST_VULN_SCAN_DATETIME: daysAgo(3), LAST_VM_SCANNED_DATE: daysAgo(3), LAST_VM_AUTH_SCANNED_DATE: daysAgo(3), TAGS: { TAG: { TAG_ID: "2", NAME: "Prod" } } }),
  ],
  profiles: [documentedOptionProfile()],
  groups: [documentedAssetGroup(), documentedAssetGroup({ ID: "11", TITLE: "DMZ", IP_SET: { IP: "203.0.113.5" } })],
  appliances: [documentedAppliance()],
  policies: [documentedPolicy()],
  detectionHosts: [
    { ID: "100", IP: "10.0.0.5", TRACKING_METHOD: "Cloud Agent", OS: "Windows Server 2022", LAST_SCAN_DATETIME: daysAgo(1), DETECTION_LIST: { DETECTION: [documentedDetection()] } },
    { ID: "101", IP: "10.0.0.6", TRACKING_METHOD: "Cloud Agent", OS: "Ubuntu Linux 22.04", LAST_SCAN_DATETIME: daysAgo(1), DETECTION_LIST: { DETECTION: [documentedDetection({ QID: "38000", SEVERITY: "4", STATUS: "New", FIRST_FOUND_DATETIME: daysAgo(5), QDS: { "@severity": "MEDIUM", "#text": "50" } })] } },
  ],
  knowledgeBase: [documentedVuln(), documentedVuln({ QID: "38000", SEVERITY_LEVEL: "4", TITLE: "Information disclosure", PATCHABLE: "0" })],
  scheduledReports: [documentedScheduledReport()],
  reports: [documentedReport()],
  activityRows: [{ date: daysAgo(1), action: "login", module: "auth", details: "ok", user_name: "acme_api", user_role: "Manager", user_ip: "10.0.0.9" }],
  legacyUsers: [
    legacyUser({ login: "acme_api", id: "1001", role: "Manager", email: "api@example.com" }),
    legacyUser({ login: "acme_mgr", id: "1002", role: "Manager", email: "mgr@example.com", firstName: "Morgan", lastName: "Manager" }),
    legacyUser({ login: "acme_rd", id: "1003", role: "Reader", email: "reader@example.com", firstName: "Riley", lastName: "Reader" }),
  ],
  adminUsers: [
    adminUser(0, "acme_api", "MANAGER", { emailAddress: "api@example.com" }),
    adminUser(1, "acme_mgr", "Manager", { emailAddress: "mgr@example.com" }),
    adminUser(2, "acme_rd", "Reader", { emailAddress: "reader@example.com" }),
  ],
  agents: [
    documentedAgent(),
    documentedAgent({ id: 101, name: "app-01.example.com", agentInfo: { ...documentedAgent().agentInfo, agentId: "5e8a3d1b-2c3d-4e6f-9a01-2b3c4d5e6f70", lastCheckedIn: { date: daysAgo(1) }, platform: "LINUX" } }),
  ],
  connectors: [documentedConnector()],
  tags: [documentedTag(), documentedTag({ id: 2, name: "Prod", ruleType: "STATIC" })],
  webApps: [documentedWebApp()],
  wasScans: [documentedWasScan()],
  wasAuthRecords: [documentedWasAuthRecord()],
  wasSchedules: [documentedWasSchedule()],
};

function flattenDetections(hosts) {
  return hosts.flatMap((host) => [].concat(host.DETECTION_LIST.DETECTION).map((detection) => ({ host_id: host.ID, ip: host.IP, ...detection })));
}

function activityCsv(rows) {
  return `${CSV_HEADER}${rows.map((row) => `"${row.date}","${row.action}","${row.module}","${row.details}","${row.user_name}","${row.user_role}","${row.user_ip}"`).join("\n")}\n`;
}

// auth_records.dtd: RESPONSE > AUTH_RECORDS > AUTH_<TECHNOLOGY>_IDS > ID_SET > (ID|ID_RANGE)+. The guide writes ranges as
// first-last, so 3010-3260 spans 251 records.
const AUTH_RECORDS_SAMPLE = `<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE AUTH_RECORDS_OUTPUT SYSTEM "https://qualysapi.qualys.com/api/2.0/fo/auth/auth_records.dtd">
<AUTH_RECORDS_OUTPUT>
  <RESPONSE>
    <DATETIME>2026-09-21T00:00:00Z</DATETIME>
    <AUTH_RECORDS>
      <AUTH_UNIX_IDS>
        <ID_SET>
          <ID>3000</ID>
          <ID_RANGE>3010-3260</ID_RANGE>
          <ID>3300</ID>
        </ID_SET>
      </AUTH_UNIX_IDS>
      <AUTH_WINDOWS_IDS>
        <ID_SET>
          <ID>4000</ID>
          <ID>4001</ID>
        </ID_SET>
      </AUTH_WINDOWS_IDS>
    </AUTH_RECORDS>
  </RESPONSE>
</AUTH_RECORDS_OUTPUT>`;

// VM/PC API user guide, "VM Scan Schedules" list samples, reproduced verbatim: SCAN nested in SCHEDULE_SCAN_LIST, the
// line-wrapped ISCANNER_NAME CDATA of the first sample, an empty ACTIVE on the cloud perimeter sample, TARGET
// "Asset Tags Included", and TAG_SET_INCLUDE as PCDATA.
const GUIDE_SCHEDULE_SCAN_LIST_SAMPLE = `<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE SCHEDULE_SCAN_LIST_OUTPUT SYSTEM "https://qualysapi.qualys.com/api/2.0/fo/schedule/scan/schedule_scan_list_output.dtd">
<SCHEDULE_SCAN_LIST_OUTPUT>
  <RESPONSE>
    <DATETIME>2017-12-01T19:26:50Z</DATETIME>
    <SCHEDULE_SCAN_LIST>
      <SCAN>
        <ID>160642</ID>
        <ACTIVE>1</ACTIVE>
        <TITLE><![CDATA[My Daily Scan]]></TITLE>
        <USER_LOGIN>qualys_ps</USER_LOGIN>
        <TARGET><![CDATA[10.10.10.10-10.10.10.20]]></TARGET>
        <NETWORK_ID><![CDATA[0]]></NETWORK_ID>
        <ISCANNER_NAME><![CDATA[External 
Scanner]]></ISCANNER_NAME>
        <USER_ENTERED_IPS>
          <RANGE>
            <START>10.10.10.10</START>
            <END>10.10.10.20</END>
          </RANGE>
        </USER_ENTERED_IPS>
        <OPTION_PROFILE>
          <TITLE><![CDATA[Initial Options]]></TITLE>
          <DEFAULT_FLAG>1</DEFAULT_FLAG>
        </OPTION_PROFILE>
        <PROCESSING_PRIORITY>0 - No Priority</PROCESSING_PRIORITY>
        <SCHEDULE>
          <DAILY frequency_days="1" />
          <START_DATE_UTC>2017-11-30T00:30:00Z</START_DATE_UTC>
          <START_HOUR>16</START_HOUR>
          <START_MINUTE>30</START_MINUTE>
          <NEXTLAUNCH_UTC>2017-12-02T00:30:00</NEXTLAUNCH_UTC>
          <TIME_ZONE>
            <TIME_ZONE_CODE>US-CA</TIME_ZONE_CODE>
            <TIME_ZONE_DETAILS>(GMT-0800) United States: America/Los_Angeles</TIME_ZONE_DETAILS>
          </TIME_ZONE>
          <DST_SELECTED>1</DST_SELECTED>
        </SCHEDULE>
        <NOTIFICATIONS>
          <BEFORE_LAUNCH>
            <TIME>30</TIME>
            <UNIT><![CDATA[minutes]]></UNIT>
            <MESSAGE><![CDATA[This is my custom before scan email message.]]></MESSAGE>
          </BEFORE_LAUNCH>
          <AFTER_COMPLETE>
            <MESSAGE><![CDATA[This is my custom after scan email message.]]></MESSAGE>
          </AFTER_COMPLETE>
        </NOTIFICATIONS>
      </SCAN>
      <SCAN>
        <ID>1340788</ID>
        <ACTIVE></ACTIVE>
        <TITLE><![CDATA[My_External_Scan]]></TITLE>
        <USER_LOGIN>utwrx_mp</USER_LOGIN>
        <TARGET><![CDATA[Asset Tags Included]]></TARGET>
        <ISCANNER_NAME><![CDATA[External Scanner]]></ISCANNER_NAME>
        <EC2_INSTANCE>
          <CONNECTOR_UUID><![CDATA[8047abce-c3ac-42e0-ad49-be4181d22c84]]></CONNECTOR_UUID>
          <EC2_ENDPOINT><![CDATA[1507b6c1-07a7-4d88-acf2-8c6b63e749c4]]></EC2_ENDPOINT>
          <EC2_ONLY_CLASSIC><![CDATA[1]]></EC2_ONLY_CLASSIC>
        </EC2_INSTANCE>
        <CLOUD_DETAILS>
          <PROVIDER>AWS</PROVIDER>
          <CONNECTOR>
            <ID>37361</ID>
            <UUID>8047abce-c3ac-42e0-ad49-be4181d22c84</UUID>
            <NAME><![CDATA[EC2 Connector]]></NAME>
          </CONNECTOR>
          <SCAN_TYPE>Cloud Perimeter</SCAN_TYPE>
          <CLOUD_TARGET>
            <PLATFORM>Classic</PLATFORM>
            <REGION>
              <UUID>1507b6c1-07a7-4d88-acf2-8c6b63e749c4</UUID>
              <CODE>us-east-1</CODE>
              <NAME><![CDATA[US East (N. Virginia)]]></NAME>
            </REGION>
            <VPC_SCOPE>None</VPC_SCOPE>
          </CLOUD_TARGET>
        </CLOUD_DETAILS>
        <ASSET_TAGS>
          <TAG_INCLUDE_SELECTOR>any</TAG_INCLUDE_SELECTOR>
          <TAG_SET_INCLUDE><![CDATA[EC2_Targets]]></TAG_SET_INCLUDE>
          <TAG_EXCLUDE_SELECTOR>any</TAG_EXCLUDE_SELECTOR>
          <TAG_SET_EXCLUDE><![CDATA[EC2_Test]]></TAG_SET_EXCLUDE>
          <USE_IP_NT_RANGE_TAGS>0</USE_IP_NT_RANGE_TAGS>
        </ASSET_TAGS>
        <ELB_DNS>
          <DNS><![CDATA[abc.com]]></DNS>
          <DNS><![CDATA[abc123.com]]></DNS>
        </ELB_DNS>
        <OPTION_PROFILE>
          <TITLE><![CDATA[Initial Options]]></TITLE>
          <DEFAULT_FLAG>1</DEFAULT_FLAG>
        </OPTION_PROFILE>
        <PROCESSING_PRIORITY>0 - No Priority</PROCESSING_PRIORITY>
        <SCHEDULE>
          <DAILY frequency_days="364" />
          <START_DATE_UTC>2018-04-02T05:00:00Z</START_DATE_UTC>
          <START_HOUR>10</START_HOUR>
          <START_MINUTE>30</START_MINUTE>
          <TIME_ZONE>
            <TIME_ZONE_CODE>IN</TIME_ZONE_CODE>
            <TIME_ZONE_DETAILS>(GMT+0530) India: Asia/Calcutta</TIME_ZONE_DETAILS>
          </TIME_ZONE>
          <DST_SELECTED>0</DST_SELECTED>
        </SCHEDULE>
      </SCAN>
    </SCHEDULE_SCAN_LIST>
  </RESPONSE>
</SCHEDULE_SCAN_LIST_OUTPUT>`;

// VM/PC API user guide, "Sample - List VM Option Profile" (/api/2.0/fo/subscription/option_profile/vm/?action=list),
// reproduced verbatim apart from the MAP and ADDITIONAL sections. It carries brute-force LOGIN_PASSWORD entries, which
// is why option profile configuration is never written verbatim into an audit bundle.
const GUIDE_OPTION_PROFILE_LIST_SAMPLE = `<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE OPTION_PROFILES SYSTEM "https://qualysapi.qualys.com/api/2.0/fo/subscription/option_profile/option_profile_info.dtd">
<OPTION_PROFILES>
<OPTION_PROFILE>
    <BASIC_INFO>
      <ID>51451401</ID>
      <GROUP_NAME><![CDATA[user op - 1]]></GROUP_NAME>
      <GROUP_TYPE>user</GROUP_TYPE>
      <USER_ID><![CDATA[John smith (jsmith_ap)]]></USER_ID>
      <UNIT_ID>0</UNIT_ID>
      <SUBSCRIPTION_ID>10421401</SUBSCRIPTION_ID>
      <IS_DEFAULT>0</IS_DEFAULT>
      <IS_GLOBAL>1</IS_GLOBAL>
      <IS_OFFLINE_SYNCABLE>1</IS_OFFLINE_SYNCABLE>
      <UPDATE_DATE>2018-04-10T13:39:41Z</UPDATE_DATE>
    </BASIC_INFO>
    <SCAN>
      <PORTS>
        <TCP_PORTS>
          <TCP_PORTS_TYPE>standard</TCP_PORTS_TYPE>
          <TCP_PORTS_ADDITIONAL>
            <HAS_ADDITIONAL>1</HAS_ADDITIONAL>
            <ADDITIONAL_PORTS>1024</ADDITIONAL_PORTS>
          </TCP_PORTS_ADDITIONAL>
          <THREE_WAY_HANDSHAKE>1</THREE_WAY_HANDSHAKE>
        </TCP_PORTS>
        <UDP_PORTS>
          <UDP_PORTS_TYPE>light</UDP_PORTS_TYPE>
          <UDP_PORTS_ADDITIONAL>
            <HAS_ADDITIONAL>1</HAS_ADDITIONAL>
            <ADDITIONAL_PORTS>8080</ADDITIONAL_PORTS>
          </UDP_PORTS_ADDITIONAL>
        </UDP_PORTS>
        <AUTHORITATIVE_OPTION>1</AUTHORITATIVE_OPTION>
      </PORTS>
      <SCAN_DEAD_HOSTS>1</SCAN_DEAD_HOSTS>
      <CLOSE_VULNERABILITIES>
        <HAS_CLOSE_VULNERABILITIES>1</HAS_CLOSE_VULNERABILITIES>
        <HOST_NOT_FOUND_ALIVE>10</HOST_NOT_FOUND_ALIVE>
      </CLOSE_VULNERABILITIES>
      <PURGE_OLD_HOST_OS_CHANGED>1</PURGE_OLD_HOST_OS_CHANGED>
      <PERFORMANCE>
        <PARALLEL_SCALING>1</PARALLEL_SCALING>
        <OVERALL_PERFORMANCE>Normal</OVERALL_PERFORMANCE>
        <HOSTS_TO_SCAN>
          <EXTERNAL_SCANNERS>10</EXTERNAL_SCANNERS>
          <SCANNER_APPLIANCES>30</SCANNER_APPLIANCES>
        </HOSTS_TO_SCAN>
        <PROCESSES_TO_RUN>
          <TOTAL_PROCESSES>10</TOTAL_PROCESSES>
          <HTTP_PROCESSES>10</HTTP_PROCESSES>
        </PROCESSES_TO_RUN>
        <PACKET_DELAY>Medium</PACKET_DELAY>
        <PORT_SCANNING_AND_HOST_DISCOVERY>Normal</PORT_SCANNING_AND_HOST_DISCOVERY>
      </PERFORMANCE>
      <LOAD_BALANCER_DETECTION>1</LOAD_BALANCER_DETECTION>
      <PASSWORD_BRUTE_FORCING>
        <SYSTEM>
          <HAS_SYSTEM>1</HAS_SYSTEM>
          <SYSTEM_LEVEL>Standard</SYSTEM_LEVEL>
        </SYSTEM>
        <CUSTOM_LIST>
          <CUSTOM>
            <ID>1001</ID>
            <TITLE><![CDATA[ftp - 1]]></TITLE>
            <TYPE>FTP</TYPE>
            <LOGIN_PASSWORD><![CDATA[L:Guest,P:temp]]></LOGIN_PASSWORD>
          </CUSTOM>
          <CUSTOM>
            <ID>1002</ID>
            <TITLE><![CDATA[ssh - 1]]></TITLE>
            <TYPE>SSH</TYPE>
            <LOGIN_PASSWORD><![CDATA[L:Guest,P:temp]]></LOGIN_PASSWORD>
          </CUSTOM>
          <CUSTOM>
            <ID>1003</ID>
            <TITLE><![CDATA[window - 1]]></TITLE>
            <TYPE>Windows</TYPE>
            <LOGIN_PASSWORD><![CDATA[L:Guest,P:temp]]></LOGIN_PASSWORD>
          </CUSTOM>
        </CUSTOM_LIST>
      </PASSWORD_BRUTE_FORCING>
      <VULNERABILITY_DETECTION>
        <COMPLETE><![CDATA[complete]]></COMPLETE>
        <DETECTION_INCLUDE>
          <BASIC_HOST_INFO_CHECKS>0</BASIC_HOST_INFO_CHECKS>
          <OVAL_CHECKS>1</OVAL_CHECKS>
        </DETECTION_INCLUDE>
      </VULNERABILITY_DETECTION>
      <AUTHENTICATION><![CDATA[Windows,Unix,Oracle,Oracle Listener,SNMP,VMware,DB2,HTTP,MySQL,Sybase]]></AUTHENTICATION>
      <AUTHENTICATION_LEAST_PRIVILEGE><![CDATA[Unix]]></AUTHENTICATION_LEAST_PRIVILEGE>
      <ADDL_CERT_DETECTION>1</ADDL_CERT_DETECTION>
      <DISSOLVABLE_AGENT>
        <DISSOLVABLE_AGENT_ENABLE>1</DISSOLVABLE_AGENT_ENABLE>
        <WINDOWS_SHARE_ENUMERATION_ENABLE>1</WINDOWS_SHARE_ENUMERATION_ENABLE>
      </DISSOLVABLE_AGENT>
      <LITE_OS_SCAN>1</LITE_OS_SCAN>
      <CUSTOM_HTTP_HEADER>
        <VALUE>sdfdsf</VALUE>
        <DEFINITION_KEY>abc</DEFINITION_KEY>
        <DEFINITION_VALUE>xyz</DEFINITION_VALUE>
      </CUSTOM_HTTP_HEADER>
      <SYSTEM_AUTH_RECORD>
          <INCLUDE_SYSTEM_AUTH>
            <ON_DUPLICATE_USE_USER_AUTH>1</ON_DUPLICATE_USE_USER_AUTH>
          </INCLUDE_SYSTEM_AUTH>
      </SYSTEM_AUTH_RECORD>
    </SCAN>
  </OPTION_PROFILE>
</OPTION_PROFILES>`;

// ---------------------------------------------------------------------------------------------
// Fake client and fixture sets
// ---------------------------------------------------------------------------------------------

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
    listUsers: async () => [],
    searchUsers: async () => [],
    searchCloudAgents: async () => [],
    searchConnectors: async () => [],
    searchTags: async () => [],
    searchWebApps: async () => [],
    searchWasScans: async () => [],
    searchWasScanHistory: async () => [],
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
  "listUsers",
  "searchUsers",
  "searchCloudAgents",
  "searchConnectors",
  "searchTags",
  "searchWebApps",
  "searchWasScans",
  "searchWasScanHistory",
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

function statusCounts(findings) {
  return findings.reduce((total, item) => ({ ...total, [item.status]: (total[item.status] ?? 0) + 1 }), {});
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
  listScheduledScans: async () => tenant.schedules,
  listScans: async () => tenant.scans,
  listHosts: async () => tenant.hosts,
  listOptionProfiles: async () => tenant.profiles,
  listExcludedIps: async () => [],
  listAssetGroups: async () => tenant.groups,
  listAppliances: async () => tenant.appliances,
  listAuthRecordSummary: async () => [{ type: "unix", count: 253 }, { type: "windows", count: 2 }],
  listCompliancePolicies: async () => tenant.policies,
  listDetections: async () => flattenDetections(tenant.detectionHosts),
  listKnowledgeBase: async () => tenant.knowledgeBase,
  listScheduledReports: async () => tenant.scheduledReports,
  listReports: async () => tenant.reports,
  listActivityLog: async () => tenant.activityRows,
  listUsers: async () => tenant.legacyUsers,
  searchUsers: async () => tenant.adminUsers,
  searchCloudAgents: async () => tenant.agents,
  searchConnectors: async () => tenant.connectors,
  searchTags: async () => tenant.tags,
  searchWebApps: async () => tenant.webApps,
  searchWasScans: async () => tenant.wasScans,
  searchWasScanHistory: async () => [],
  searchWasAuthRecords: async () => tenant.wasAuthRecords,
  searchWasSchedules: async () => tenant.wasSchedules,
};

const failingFixtures = {
  listScheduledScans: async () => [documentedSchedule({ ID: "1", ACTIVE: "0", TITLE: "Disabled", TARGET: "10.0.0.0/24", USER_ENTERED_IPS: undefined })],
  listScans: async () => [],
  listHosts: async () => [
    { ID: "100", IP: "10.0.0.5", TRACKING_METHOD: "IP", OS: "Windows Server 2019", LAST_VULN_SCAN_DATETIME: daysAgo(120), LAST_VM_SCANNED_DATE: daysAgo(120) },
    { ID: "101", IP: "10.0.0.6", TRACKING_METHOD: "IP", OS: "Red Hat Enterprise Linux 8", LAST_VULN_SCAN_DATETIME: daysAgo(90), LAST_VM_SCANNED_DATE: daysAgo(90) },
    { ID: "102", IP: "10.0.0.7", TRACKING_METHOD: "IP", OS: "Windows 10" },
  ],
  listOptionProfiles: async () => [documentedOptionProfile({ BASIC_INFO: { ID: "7", GROUP_NAME: "Unauthenticated" }, SCAN: { PORTS: { TCP_PORTS: { TCP_PORTS_TYPE: "standard" } } } })],
  listExcludedIps: async () => [{ type: "range", value: "10.0.0.0-10.0.255.255" }],
  listAssetGroups: async () => [documentedAssetGroup({ ID: "10", TITLE: "Everything", IP_SET: undefined })],
  listAppliances: async () => [documentedAppliance({ NAME: "old-scanner", STATUS: "Offline", SOFTWARE_VERSION: "11.0.10-1", ML_VERSION: { "@updated": "no", "#text": "" }, VULNSIGS_VERSION: { "@updated": "no", "#text": "" }, HEARTBEATS_MISSED: "12" })],
  listAuthRecordSummary: async () => [{ type: "windows", count: 0 }],
  listCompliancePolicies: async () => [documentedPolicy({ TITLE: "Unassigned policy", ASSET_GROUP_IDS: undefined })],
  listDetections: async () => [
    { host_id: "100", ...documentedDetection({ FIRST_FOUND_DATETIME: daysAgo(60), QDS: undefined }) },
    { host_id: "101", ...documentedDetection({ QID: "38000", SEVERITY: "4", FIRST_FOUND_DATETIME: daysAgo(90), QDS: undefined }) },
    { host_id: "102", ...documentedDetection({ QID: "11000", SEVERITY: "3", FIRST_FOUND_DATETIME: daysAgo(200), QDS: undefined }) },
  ],
  listKnowledgeBase: async () => [documentedVuln(), documentedVuln({ QID: "38000" }), documentedVuln({ QID: "11000", SEVERITY_LEVEL: "3" })],
  listScheduledReports: async () => [],
  listReports: async () => [],
  listActivityLog: async () => [{ date: daysAgo(1), action: "delete", module: "user", details: "User removed", user_name: "acme_mgr", user_role: "Manager", user_ip: "10.0.0.9" }],
  listUsers: async () => [
    legacyUser({ login: "shared_admin", id: "2001", role: "Manager", email: "ops@example.com" }),
    legacyUser({ login: "svc_scan", id: "2002", role: "Manager", email: "ops@example.com" }),
  ],
  searchUsers: async () => [
    adminUser(1, "shared_admin", "Manager", { emailAddress: "ops@example.com" }),
    adminUser(2, "svc_scan", "Manager", { emailAddress: "ops@example.com" }),
  ],
  searchCloudAgents: async () => [documentedAgent({ agentInfo: { status: "STATUS_INACTIVE", lastCheckedIn: { date: daysAgo(40) }, activationKey: { activationId: "old-activation-id", title: "old-key" } } })],
  searchConnectors: async () => [documentedConnector({ connectorState: "ERROR", lastError: "Invalid role", lastSync: daysAgo(30) })],
  searchTags: async () => [],
  searchWebApps: async () => [documentedWebApp({ name: "Legacy portal", url: "https://legacy.example.com", lastScan: undefined })],
  searchWasScans: async () => [],
  searchWasScanHistory: async () => [],
  searchWasAuthRecords: async () => [documentedWasAuthRecord({ name: "old-login", updatedDate: daysAgo(400) })],
  searchWasSchedules: async () => [],
};

const EMPTY_LIST_XML = '<?xml version="1.0" encoding="UTF-8"?><LIST_OUTPUT><RESPONSE><DATETIME>2026-09-21T00:00:00Z</DATETIME></RESPONSE></LIST_OUTPUT>';
const EMPTY_USER_LIST_XML = '<?xml version="1.0" encoding="UTF-8"?><USER_LIST_OUTPUT><USER_LIST></USER_LIST></USER_LIST_OUTPUT>';
const CSV_HEADER = '"Date","Action","Module","Details","User Name","User Role","User IP"\n';

function routedClient(handler, configOverrides = {}) {
  return new QualysApiClient(sampleConfig(configOverrides), {
    fetchImpl: async (url, init) => handler(String(url), init ?? {}),
    sleepImpl: async () => {},
  });
}

// ---------------------------------------------------------------------------------------------
// Routers driving the real QualysApiClient: (a) forbidden, (b) empty, (c) partial, (d) compliant
// ---------------------------------------------------------------------------------------------

const forbiddenRouter = async (url) => {
  if (url.includes("/qps/rest/")) {
    return jsonResponse({ ServiceResponse: { responseCode: "UNAUTHORIZED", responseErrorDetails: { errorMessage: "User is not authorized to access this module" } } }, { status: 403 });
  }
  if (url.includes("/msp/user_list.php")) {
    // user_list_output.dtd: USER_LIST_OUTPUT (ERROR | USER_LIST) with ATTLIST ERROR number
    return xmlResponse('<?xml version="1.0" encoding="UTF-8"?><USER_LIST_OUTPUT><ERROR number="999">Forbidden: this account is not authorized to list users</ERROR></USER_LIST_OUTPUT>');
  }
  return xmlResponse("<SIMPLE_RETURN><RESPONSE><CODE>2010</CODE><TEXT>Forbidden: module not subscribed</TEXT></RESPONSE></SIMPLE_RETURN>", { status: 403 });
};

const emptyRouter = async (url) => {
  if (url.includes("/qps/rest/")) return jsonResponse({ ServiceResponse: { responseCode: "SUCCESS", count: 0, hasMoreRecords: "false" } });
  if (url.includes("/activity_log/")) return csvResponse(CSV_HEADER);
  if (url.includes("/msp/user_list.php")) return xmlResponse(EMPTY_USER_LIST_XML);
  return xmlResponse(EMPTY_LIST_XML);
};

function xmlPage(recordXml, url) {
  const nextId = Number(new URL(url).searchParams.get("id_min") ?? "0") + 1;
  const nextUrl = new URL(url);
  nextUrl.searchParams.set("id_min", String(nextId));
  return xmlResponse(`<?xml version="1.0"?><LIST_OUTPUT><RESPONSE><DATETIME>2026-09-21T00:00:00Z</DATETIME>${recordXml(nextId)}<WARNING><CODE>1980</CODE><TEXT>truncated</TEXT><URL><![CDATA[${nextUrl.toString()}]]></URL></WARNING></RESPONSE></LIST_OUTPUT>`);
}

function partialXmlRecord(url, id) {
  if (url.includes("/schedule/scan/")) {
    return `<SCHEDULE_SCAN_LIST>${xmlFromRecord("SCAN", documentedSchedule({ ID: String(id), TITLE: `Sched ${id}`, TARGET: "Asset Tags Included", ISCANNER_NAME: "External Scanner", USER_ENTERED_IPS: undefined, ASSET_TAGS: documentedAssetTags(`Segment ${id}`) }))}</SCHEDULE_SCAN_LIST>`;
  }
  if (url.includes("/fo/scan/")) return `<SCAN_LIST>${xmlFromRecord("SCAN", documentedScan({ REF: `scan/${id}`, TITLE: `Sched ${id}` }))}</SCAN_LIST>`;
  if (url.includes("/vm/detection/")) {
    return `<HOST_LIST>${xmlFromRecord("HOST", { ID: String(id), IP: `10.0.0.${id}`, DETECTION_LIST: { DETECTION: documentedDetection({ QID: `9${id}`, SEVERITY: "4", FIRST_FOUND_DATETIME: daysAgo(2), QDS: { "@severity": "HIGH", "#text": "70" } }) } })}</HOST_LIST>`;
  }
  if (url.includes("/asset/host/")) return `<HOST_LIST>${xmlFromRecord("HOST", documentedHost({ ID: String(id), IP: `10.0.0.${id}`, LAST_VULN_SCAN_DATETIME: daysAgo(1), LAST_VM_SCANNED_DATE: daysAgo(1), LAST_VM_AUTH_SCANNED_DATE: daysAgo(1), TAGS: { TAG: { TAG_ID: "2", NAME: "Prod" } } }))}</HOST_LIST>`;
  if (url.includes("/option_profile/vm/")) return `<OPTION_PROFILES>${xmlFromRecord("OPTION_PROFILE", documentedOptionProfile({ BASIC_INFO: { ID: String(id), GROUP_NAME: `Profile ${id}` } }))}</OPTION_PROFILES>`;
  if (url.includes("/excluded_ip/")) return `<IP_SET><IP>10.0.0.${id}</IP></IP_SET>`;
  if (url.includes("/asset/group/")) return `<ASSET_GROUP_LIST>${xmlFromRecord("ASSET_GROUP", documentedAssetGroup({ ID: String(id), TITLE: `Segment ${id}`, IP_SET: { IP: `10.0.${id}.5` } }))}</ASSET_GROUP_LIST>`;
  if (url.includes("/appliance/")) return `<APPLIANCE_LIST>${xmlFromRecord("APPLIANCE", documentedAppliance({ ID: String(id), NAME: `scanner-${id}` }))}</APPLIANCE_LIST>`;
  if (url.includes("/fo/auth/")) return "<AUTH_RECORDS><AUTH_WINDOWS_IDS><ID_SET><ID>1</ID></ID_SET></AUTH_WINDOWS_IDS><AUTH_UNIX_IDS><ID_SET><ID>2</ID></ID_SET></AUTH_UNIX_IDS></AUTH_RECORDS>";
  if (url.includes("/compliance/policy/")) return `<POLICY_LIST>${xmlFromRecord("POLICY", documentedPolicy({ ID: String(id), TITLE: `Policy ${id}`, ASSET_GROUP_IDS: String(id) }))}</POLICY_LIST>`;
  if (url.includes("/knowledge_base/")) return `<VULN_LIST>${xmlFromRecord("VULN", documentedVuln({ QID: `9${id}`, PATCHABLE: "0" }))}</VULN_LIST>`;
  if (url.includes("/schedule/report/")) return `<SCHEDULE_REPORT_LIST>${xmlFromRecord("REPORT", documentedScheduledReport({ ID: String(id), TITLE: `Report ${id}` }))}</SCHEDULE_REPORT_LIST>`;
  if (url.includes("/fo/report/")) return `<REPORT_LIST>${xmlFromRecord("REPORT", documentedReport({ ID: String(id), TITLE: `Report ${id}` }))}</REPORT_LIST>`;
  throw new Error(`unexpected XML url ${url}`);
}

function qpsEntity(url) {
  if (url.includes("/am/user")) return ["User", (id) => adminUser(id, `user${id}`, "Reader")];
  if (url.includes("/am/hostasset")) return ["HostAsset", (id) => documentedAgent({ id, name: `host-${id}` })];
  if (url.includes("/am/assetdataconnector")) return ["AwsAssetDataConnector", (id) => documentedConnector({ id, name: `aws-${id}` })];
  if (url.includes("/am/tag")) return ["Tag", (id) => documentedTag({ id, name: `Tag ${id}` })];
  if (url.includes("/was/webappauthrecord")) return ["WebAppAuthRecord", (id) => documentedWasAuthRecord({ id, name: `auth-${id}`, updatedDate: daysAgo(3) })];
  if (url.includes("/was/wasscanschedule")) return ["WasScanSchedule", (id) => documentedWasSchedule({ id, name: `Schedule ${id}` })];
  if (url.includes("/was/wasscan")) return ["WasScan", (id) => documentedWasScan({ id, name: `Scan ${id}`, launchedDate: daysAgo(2), target: { webApp: { id, name: `App ${id}` } } })];
  if (url.includes("/was/webapp")) return ["WebApp", (id) => documentedWebApp({ id, name: `App ${id}`, lastScan: { id, name: `Scan ${id}` } })];
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
  if (url.includes("/msp/user_list.php")) {
    // A Reader caller: the User List API is read completely, but the role only sees its own business unit.
    return xmlResponse(userListXml([legacyUser({ login: "acme_api", role: "Reader" })]));
  }
  return xmlPage((id) => partialXmlRecord(url, id), url);
};

const compliantRouter = async (url) => {
  if (url.includes("/qps/rest/")) {
    if (url.includes("/am/user")) return jsonResponse(qpsResponse("User", tenant.adminUsers));
    if (url.includes("/am/hostasset")) return jsonResponse(qpsResponse("HostAsset", tenant.agents));
    if (url.includes("/am/assetdataconnector")) return jsonResponse(qpsResponse("AwsAssetDataConnector", tenant.connectors));
    if (url.includes("/am/tag")) return jsonResponse(qpsResponse("Tag", tenant.tags));
    if (url.includes("/was/webappauthrecord")) return jsonResponse(qpsResponse("WebAppAuthRecord", tenant.wasAuthRecords));
    if (url.includes("/was/wasscanschedule")) return jsonResponse(qpsResponse("WasScanSchedule", tenant.wasSchedules));
    if (url.includes("/was/wasscan")) return jsonResponse(qpsResponse("WasScan", tenant.wasScans));
    if (url.includes("/was/webapp")) return jsonResponse(qpsResponse("WebApp", tenant.webApps));
    throw new Error(`unexpected QPS url ${url}`);
  }
  if (url.includes("/activity_log/")) return csvResponse(activityCsv(tenant.activityRows));
  if (url.includes("/msp/user_list.php")) return xmlResponse(userListXml(tenant.legacyUsers));
  if (url.includes("/schedule/scan/")) return xmlResponse(listOutputXml("SCHEDULE_SCAN_LIST_OUTPUT", "SCHEDULE_SCAN_LIST", "SCAN", tenant.schedules));
  if (url.includes("/fo/scan/")) return xmlResponse(listOutputXml("SCAN_LIST_OUTPUT", "SCAN_LIST", "SCAN", tenant.scans));
  if (url.includes("/vm/detection/")) return xmlResponse(listOutputXml("HOST_LIST_VM_DETECTION_OUTPUT", "HOST_LIST", "HOST", tenant.detectionHosts));
  if (url.includes("/asset/host/")) return xmlResponse(listOutputXml("HOST_LIST_OUTPUT", "HOST_LIST", "HOST", tenant.hosts));
  if (url.includes("/option_profile/vm/")) return xmlResponse(`<?xml version="1.0" encoding="UTF-8" ?><OPTION_PROFILES>${xmlFromRecord("OPTION_PROFILE", tenant.profiles)}</OPTION_PROFILES>`);
  if (url.includes("/excluded_ip/")) return xmlResponse(`<?xml version="1.0" encoding="UTF-8" ?><IP_LIST_OUTPUT><RESPONSE><DATETIME>${daysAgo(0)}</DATETIME></RESPONSE></IP_LIST_OUTPUT>`);
  if (url.includes("/asset/group/")) return xmlResponse(listOutputXml("ASSET_GROUP_LIST_OUTPUT", "ASSET_GROUP_LIST", "ASSET_GROUP", tenant.groups));
  if (url.includes("/appliance/")) return xmlResponse(listOutputXml("APPLIANCE_LIST_OUTPUT", "APPLIANCE_LIST", "APPLIANCE", tenant.appliances));
  if (url.includes("/fo/auth/")) return xmlResponse(AUTH_RECORDS_SAMPLE);
  if (url.includes("/compliance/policy/")) return xmlResponse(listOutputXml("POLICY_LIST_OUTPUT", "POLICY_LIST", "POLICY", tenant.policies));
  if (url.includes("/knowledge_base/")) return xmlResponse(listOutputXml("KNOWLEDGE_BASE_VULN_LIST_OUTPUT", "VULN_LIST", "VULN", tenant.knowledgeBase));
  if (url.includes("/schedule/report/")) return xmlResponse(listOutputXml("SCHEDULE_REPORT_LIST_OUTPUT", "SCHEDULE_REPORT_LIST", "REPORT", tenant.scheduledReports));
  if (url.includes("/fo/report/")) return xmlResponse(listOutputXml("REPORT_LIST_OUTPUT", "REPORT_LIST", "REPORT", tenant.reports));
  throw new Error(`unexpected url ${url}`);
};

const COMPLIANT_PASS_IDS = ["QUALYS-C01", "QUALYS-C02", "QUALYS-C05", "QUALYS-C06", "QUALYS-C07", "QUALYS-C08", "QUALYS-C09", "QUALYS-C10", "QUALYS-C11", "QUALYS-C13", "QUALYS-C14", "QUALYS-C15", "QUALYS-C16", "QUALYS-C18"];
const CAPPED_BY_DESIGN_IDS = ["QUALYS-C03", "QUALYS-C12", "QUALYS-C17", "QUALYS-C19", "QUALYS-C20"];

// ---------------------------------------------------------------------------------------------
// Configuration, platform, and parser tests
// ---------------------------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------------------------
// Config loader: the read error, the tool catches, and the platform value are never echoed
// ---------------------------------------------------------------------------------------------

// Captures the six tool handlers so a test can drive execute() the way the pi runtime does.
function registeredQualysTools() {
  const tools = new Map();
  registerQualysTools({
    registerTool(tool) {
      tools.set(tool.name, tool);
    },
  });
  return tools;
}

// Replaces one node:fs function while `run` executes. syncBuiltinESMExports makes the dist module's named import see
// the stub, and the original is restored (and synced back) whether or not `run` throws.
async function withFsStub(name, stub, run) {
  const original = fs[name];
  fs[name] = (...args) => stub(original, ...args);
  syncBuiltinESMExports();
  try {
    return await run();
  } finally {
    fs[name] = original;
    syncBuiltinESMExports();
  }
}

function thrownBy(fn) {
  try {
    fn();
    return undefined;
  } catch (error) {
    return error;
  }
}

const TOOL_FAILURE_PREFIXES = {
  qualys_assess_scan_coverage: "Assess Qualys scan coverage failed",
  qualys_assess_asset_inventory: "Assess Qualys asset inventory failed",
  qualys_assess_vulnerability_management: "Assess Qualys vulnerability management failed",
  qualys_assess_administration: "Assess Qualys administration hygiene failed",
  qualys_check_access: "Qualys access check failed",
  qualys_export_audit_bundle: "Qualys audit bundle export failed",
};

test("config loader: a directory as the config file reports the system error code through config_file and QUALYS_CONFIG_FILE, never the fs message", () => {
  const dir = createTempBase("qualys-config-loader-");
  const directoryPath = join(dir, "config-as-directory.qcrc");
  mkdirSync(directoryPath);

  // Positive control: the fs error the loader used to rethrow unwrapped carries the operation wording.
  const fsError = thrownBy(() => readFileSync(directoryPath, "utf8"));
  assert.ok(fsError instanceof Error);
  assert.equal(fsError.code, "EISDIR");
  assert.match(fsError.message, /^EISDIR: illegal operation on a directory, read/);

  for (const [label, input, env] of [
    ["config_file", { config_file: directoryPath }, {}],
    ["QUALYS_CONFIG_FILE", {}, { QUALYS_CONFIG_FILE: directoryPath }],
  ]) {
    const thrown = thrownBy(() => resolveQualysConfiguration(input, env));
    assert.ok(thrown instanceof Error, `${label}: a directory throws`);
    assert.match(thrown.message, /^Unable to read Qualys config file .* \(EISDIR\)$/, label);
    assert.ok(thrown.message.endsWith("/config-as-directory.qcrc (EISDIR)"), `${label}: the path is named: ${thrown.message}`);
    for (const forbidden of ["illegal operation", "EISDIR:", "on a directory", ", read", fsError.message]) {
      assert.ok(!thrown.message.includes(forbidden), `${label}: no fs wording ${JSON.stringify(forbidden)} in ${thrown.message}`);
    }
  }

  // ENOENT is unreachable: a missing file is simply an empty config.
  assert.deepEqual(thrownBy(() => resolveQualysConfiguration({ config_file: join(dir, "missing.qcrc"), username: "u", password: "p" }, {})), undefined);
});

test("config loader: a non-standard value thrown by the config read reaches neither the thrown error nor the qualys_check_access result", async () => {
  const dir = createTempBase("qualys-config-loader-");
  const configPath = join(dir, "stubbed.qcrc");
  writeFileSync(configPath, "username = u\npassword = p\n");
  const tools = registeredQualysTools();
  const fields = ["NONSTD-CODE-CANARY", "NONSTD-MSG-CANARY", "NONSTD-FIELD-CANARY", "NONSTD-TOSTRING-CANARY"];
  const nonStandard = {
    code: "NONSTD-CODE-CANARY",
    message: "NONSTD-MSG-CANARY",
    field: "NONSTD-FIELD-CANARY",
    toString() {
      return "NONSTD-TOSTRING-CANARY";
    },
  };
  class ReadFailure extends Error {
    constructor() {
      super(`EACCES: permission denied, open '${configPath}' NONSTD-MSG-CANARY`);
      this.code = "EACCES";
      this.field = "NONSTD-FIELD-CANARY";
    }
  }

  let failure = "non-standard object";
  const [objectResult, subclassResult] = await withFsStub(
    "readFileSync",
    (original, pathname, ...rest) => {
      if (pathname !== configPath) return original(pathname, ...rest);
      throw failure === "non-standard object" ? nonStandard : new ReadFailure();
    },
    async () => {
      // Positive control: without the loader the object's toString() is what String(error) would have rendered.
      assert.equal(String(nonStandard), "NONSTD-TOSTRING-CANARY");
      assert.equal(thrownBy(() => readFileSync(configPath, "utf8")), nonStandard);

      // The code is outside the E[A-Z0-9_] grammar, so the thrown text is the fixed description with no code at all.
      const direct = thrownBy(() => resolveQualysConfiguration({ config_file: configPath }, {}));
      assert.ok(direct instanceof Error);
      assert.match(direct.message, /^Unable to read Qualys config file .*\/stubbed\.qcrc$/);
      const viaTool = await tools.get("qualys_check_access").execute("call-1", { config_file: configPath });

      failure = "Error subclass";
      const subclass = await tools.get("qualys_check_access").execute("call-2", { config_file: configPath });
      return [viaTool, subclass];
    },
  );

  assert.equal(objectResult.isError, true);
  assert.match(objectResult.content[0].text, /^Qualys access check failed: Unable to read Qualys config file .*\/stubbed\.qcrc$/);
  assert.deepEqual(objectResult.details, { tool: "qualys_check_access" });
  for (const field of fields) {
    assert.ok(!JSON.stringify(objectResult).includes(field), `${field} reached the tool result: ${JSON.stringify(objectResult)}`);
  }

  // An Error subclass with a valid system code contributes exactly that code, never its message or extra fields.
  assert.equal(subclassResult.isError, true);
  assert.match(subclassResult.content[0].text, /^Qualys access check failed: Unable to read Qualys config file .*\/stubbed\.qcrc \(EACCES\)$/);
  for (const forbidden of [...fields, "permission denied", "open '"]) {
    assert.ok(!JSON.stringify(subclassResult).includes(forbidden), `${forbidden} reached the tool result: ${JSON.stringify(subclassResult)}`);
  }

  // The stub is gone: the same file reads normally again.
  assert.equal(resolveQualysConfiguration({ config_file: configPath }, {}).username, "u");
});

test("config loader: an unrecognised platform or base_url names its source and the documented platforms, never the value", async () => {
  const dir = createTempBase("qualys-config-loader-");
  const platformCanary = "qk_live_LEAKPLATFORMCANARY7f3a9c1d";
  const baseUrlCanary = `https://LEAKPLATFORMCANARY:${platformCanary}@bad host/path`;
  const platformFile = join(dir, "platform.qcrc");
  writeFileSync(platformFile, `username = u\npassword = p\nplatform = ${platformCanary}\n`);
  const baseUrlFile = join(dir, "base-url.qcrc");
  writeFileSync(baseUrlFile, `username = u\npassword = p\nbase_url = ${baseUrlCanary}\n`);
  const tools = registeredQualysTools();
  const allowed = QUALYS_PLATFORMS.map((platform) => platform.id).join(", ");
  const expected = (source) =>
    `Unknown Qualys platform in ${source} (the value is not repeated here). Use one of ${allowed}, an API server hostname, or a full https URL.`;
  const parts = ["qk_live", "LEAKPLATFORMCANARY", "7f3a9c1d", "LEAK", "bad host", "@bad", "Invalid URL", platformCanary, baseUrlCanary];

  // Positive control: the URL parser rejects the base_url value, and its error carries the value as `input`.
  const urlError = thrownBy(() => new URL(baseUrlCanary));
  assert.ok(urlError instanceof TypeError);
  assert.equal(urlError.input, baseUrlCanary);

  const direct = [
    ["the config file key platform", () => resolveQualysConfiguration({ config_file: platformFile }, {})],
    ["the config file key base_url", () => resolveQualysConfiguration({ config_file: baseUrlFile }, {})],
    ["QUALYS_PLATFORM", () => resolveQualysConfiguration({ config_file: join(dir, "missing.qcrc") }, { QUALYS_USERNAME: "u", QUALYS_PASSWORD: "p", QUALYS_PLATFORM: platformCanary })],
    ["QUALYS_BASE_URL", () => resolveQualysConfiguration({ config_file: join(dir, "missing.qcrc") }, { QUALYS_USERNAME: "u", QUALYS_PASSWORD: "p", QUALYS_BASE_URL: baseUrlCanary })],
    ["the platform argument", () => resolveQualysConfiguration({ config_file: join(dir, "missing.qcrc"), username: "u", password: "p", platform: platformCanary }, {})],
    ["the base_url argument", () => resolveQualysConfiguration({ config_file: join(dir, "missing.qcrc"), username: "u", password: "p", base_url: baseUrlCanary }, {})],
    ["the platform value", () => resolveQualysPlatform(platformCanary)],
    ["the platform value", () => resolveQualysPlatform(baseUrlCanary)],
  ];
  for (const [source, run] of direct) {
    const thrown = thrownBy(run);
    assert.ok(thrown instanceof Error, source);
    assert.equal(thrown.message, expected(source));
    for (const part of parts) assert.ok(!thrown.message.includes(part), `${source}: ${JSON.stringify(part)} reached the thrown message`);
  }

  // Through the tool the same message is rendered, prefixed and scrubbed, with the source named.
  for (const [name, args, source] of [
    ["qualys_check_access", { config_file: platformFile }, "the config file key platform"],
    ["qualys_check_access", { config_file: baseUrlFile }, "the config file key base_url"],
    ["qualys_assess_administration", { config_file: join(dir, "missing.qcrc"), username: "u", password: "p", platform: platformCanary }, "the platform argument"],
  ]) {
    const result = await tools.get(name).execute("call", args);
    assert.equal(result.isError, true, name);
    assert.equal(result.content[0].text, `${TOOL_FAILURE_PREFIXES[name]}: ${expected(source)}`);
    for (const part of parts) assert.ok(!JSON.stringify(result).includes(part), `${name}: ${JSON.stringify(part)} reached the tool result`);
  }

  // A documented shape from the same file is still accepted, so the guard only bites on the undocumented grammar.
  writeFileSync(platformFile, "username = u\npassword = p\nplatform = qualysapi.qg2.apps.qualys.eu\n");
  assert.equal(resolveQualysConfiguration({ config_file: platformFile }, {}).platform, "EU2");
});

test("tool handlers: an error raised inside each try block renders through the scrub, so a planted bearer reads [REDACTED] in the assess, check_access, and export results", async () => {
  const dir = createTempBase("qualys-config-loader-");
  const configPath = join(dir, "probe.qcrc");
  writeFileSync(configPath, "username = u\npassword = p\n");
  const bearer = "LEAKBEARERCANARY7f3a9c1d2e4b";
  const outputRoot = join(dir, "export");
  const tools = registeredQualysTools();
  assert.deepEqual([...tools.keys()].sort(), Object.keys(TOOL_FAILURE_PREFIXES).sort());

  await withFsStub(
    "existsSync",
    (original, pathname) => {
      // existsSync is the first call inside every handler's try block that is not already guarded, so an error thrown
      // here reaches the catch with its message intact.
      if (pathname === configPath) throw new Error(`config probe failed: Authorization: Bearer ${bearer}`);
      return original(pathname);
    },
    async () => {
      // Positive control: the error reaches the handlers' catch blocks with the bearer verbatim.
      const raw = thrownBy(() => resolveQualysConfiguration({ config_file: configPath }, {}));
      assert.ok(raw instanceof Error);
      assert.equal(raw.message, `config probe failed: Authorization: Bearer ${bearer}`);

      for (const [name, prefix] of Object.entries(TOOL_FAILURE_PREFIXES)) {
        const result = await tools.get(name).execute("call", { config_file: configPath, output_dir: outputRoot });
        assert.equal(result.isError, true, name);
        assert.equal(result.content[0].text, `${prefix}: config probe failed: Authorization: Bearer [REDACTED]`, name);
        assert.deepEqual(result.details, { tool: name });
        assert.ok(!JSON.stringify(result).includes(bearer), `${name}: the bearer reached the tool result`);
        assert.ok(!JSON.stringify(result).includes("LEAKBEARER"), name);
      }
    },
  );
  assert.ok(!existsSync(outputRoot), "the export handler wrote nothing before failing");
  assert.equal(resolveQualysConfiguration({ config_file: configPath }, {}).username, "u", "the stub is gone");
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
      return xmlResponse(listOutputXml("SCHEDULE_SCAN_LIST_OUTPUT", "SCHEDULE_SCAN_LIST", "SCAN", [documentedSchedule({ ID: "1" })]));
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

test("rule 7: listKnowledgeBase follows the documented WARNING/URL continuation and records the cap when it cannot, so C11 never passes on partial patch data", async () => {
  // knowledge_base_vuln_list_output.dtd: RESPONSE (DATETIME, (VULN_LIST|ID_SET)?, WARNING?), WARNING (CODE?, TEXT, URL?)
  const kbPage = (vulns, nextUrl) => xmlResponse(`<?xml version="1.0"?><KNOWLEDGE_BASE_VULN_LIST_OUTPUT><RESPONSE><DATETIME>${daysAgo(0)}</DATETIME><VULN_LIST>${xmlFromRecord("VULN", vulns)}</VULN_LIST>${nextUrl ? `<WARNING><CODE>1980</CODE><TEXT>truncated</TEXT><URL><![CDATA[${nextUrl}]]></URL></WARNING>` : ""}</RESPONSE></KNOWLEDGE_BASE_VULN_LIST_OUTPUT>`);
  const calls = [];
  const followed = routedClient(async (url) => {
    calls.push(url);
    if (url.includes("id_min=2")) return kbPage([documentedVuln({ QID: "91002", PATCHABLE: "1" })]);
    return kbPage([documentedVuln({ QID: "91001", PATCHABLE: "1" })], "https://qualysapi.qualys.com/api/2.0/fo/knowledge_base/vuln/?action=list&details=Basic&id_min=2");
  });
  const complete = await followed.listKnowledgeBase(["91001", "91002"]);
  assert.deepEqual(complete.items.map((vuln) => vuln.QID), ["91001", "91002"]);
  assert.equal(complete.pages, 2);
  assert.equal(complete.truncated, false, "a followed continuation is a complete read");
  assert.equal(calls.length, 2);

  // Every page carries a WARNING/URL to the next id_min, so the continuation can never be exhausted.
  const endlessKbPages = async (url) => {
    const nextUrl = new URL(url);
    nextUrl.searchParams.set("id_min", String(Number(nextUrl.searchParams.get("id_min") ?? "0") + 1));
    return kbPage(tenant.knowledgeBase, nextUrl.toString());
  };
  const capped = await routedClient(endlessKbPages).listKnowledgeBase(["91001"]);
  assert.equal(capped.truncated, true, "an unfollowed WARNING/URL continuation is a partial read (pre-fix: truncated false)");
  assert.match(capped.truncationReason, /page cap 25 reached with a WARNING\/URL continuation not followed/);
  assert.equal(capped.pages, 25);

  const partialPatchData = await assessQualysVulnerabilityManagement(routedClient(async (url, init) => {
    if (url.includes("/knowledge_base/")) return endlessKbPages(url);
    return compliantRouter(url, init);
  }));
  const patchTracking = partialPatchData.findings.find((item) => item.id === "QUALYS-C11");
  assert.notEqual(patchTracking.status, "pass", "C11 must not pass when the knowledge base read is partial");
  assert.equal(patchTracking.status, "warn");
  assert.match(patchTracking.summary, /Partial view: knowledge_base page cap 25 reached with a WARNING\/URL continuation not followed/);
  assert.equal(patchTracking.evidence.collection.sources.find((source) => source.name === "knowledge_base").status, "truncated");
});

test("rule 7: searchQps treats a page that fills limitResults without hasMoreRecords as a possible continuation instead of the whole population", async () => {
  const connectors = (start, count) => Array.from({ length: count }, (_, index) => documentedConnector({ id: start + index, name: `aws-${start + index}` }));
  const withoutFlag = (items, extra = {}) => {
    const body = qpsResponse("AwsAssetDataConnector", items, extra);
    delete body.ServiceResponse.hasMoreRecords;
    return jsonResponse(body);
  };

  let orphanCalls = 0;
  const orphan = routedClient(async () => {
    orphanCalls += 1;
    return withoutFlag(connectors(1, 100));
  });
  const orphanResult = await orphan.searchConnectors();
  assert.equal(orphanCalls, 1);
  assert.equal(orphanResult.items.length, 100);
  assert.equal(orphanResult.truncated, true, "exactly limitResults records with neither hasMoreRecords nor lastId cannot be the proven whole population (pre-fix: truncated false)");
  assert.match(orphanResult.truncationReason, /full page was returned without hasMoreRecords or lastId/);

  const continued = routedClient(async (url, init) => {
    const body = JSON.parse(init.body);
    assert.equal(body.ServiceRequest.preferences.limitResults, 100);
    const after = (body.ServiceRequest.filters?.Criteria ?? []).find((item) => item.field === "id" && item.operator === "GREATER");
    if (!after) return withoutFlag(connectors(1, 100), { lastId: 100 });
    assert.equal(after.value, "100");
    return withoutFlag(connectors(101, 7));
  });
  const continuedResult = await continued.searchConnectors();
  assert.equal(continuedResult.items.length, 107);
  assert.equal(continuedResult.pages, 2, "a full page with a lastId continues paging even without the flag");
  assert.equal(continuedResult.truncated, false);

  let explicitCalls = 0;
  const explicitEnd = routedClient(async () => {
    explicitCalls += 1;
    return jsonResponse(qpsResponse("AwsAssetDataConnector", connectors(1, 100)));
  });
  const explicitResult = await explicitEnd.searchConnectors();
  assert.equal(explicitCalls, 1);
  assert.equal(explicitResult.truncated, false, "an explicit hasMoreRecords false ends a full page");

  const shortPage = await routedClient(async () => withoutFlag(connectors(1, 3))).searchConnectors();
  assert.equal(shortPage.truncated, false, "a page below limitResults without the flag is complete");

  const inventory = await assessQualysAssetInventory(routedClient(async (url, init) => {
    if (url.includes("/am/assetdataconnector")) return withoutFlag(connectors(1, 100));
    return compliantRouter(url, init);
  }));
  const connectorHealth = inventory.findings.find((item) => item.id === "QUALYS-C05");
  assert.notEqual(connectorHealth.status, "pass");
  assert.match(connectorHealth.summary, /Partial view: connectors a full page was returned without hasMoreRecords or lastId/);
});

test("normalizeList accepts plain arrays and list results", () => {
  assert.deepEqual(normalizeList([{ a: 1 }]), { items: [{ a: 1 }], truncated: false, truncationReason: undefined, pages: 1 });
  const list = normalizeList({ items: [{ a: 1 }], truncationReason: "item cap 1 reached", pages: 3 });
  assert.equal(list.truncated, true);
  assert.equal(list.pages, 3);
  assert.deepEqual(normalizeList(undefined).items, []);
});

// ---------------------------------------------------------------------------------------------
// Docs fidelity pins: each of these fails on the pre-fix build (5792ce3) and passes on the fixed parsers.
// ---------------------------------------------------------------------------------------------

test("docs fidelity 1: listScheduledScans reads SCAN nested in SCHEDULE_SCAN_LIST from the guide sample verbatim", async () => {
  const client = routedClient(async () => xmlResponse(GUIDE_SCHEDULE_SCAN_LIST_SAMPLE));
  const schedules = await client.listScheduledScans();
  assert.equal(schedules.items.length, 2, "schedule_scan_list_output.dtd nests SCAN, not SCHEDULE_SCAN, inside SCHEDULE_SCAN_LIST");
  assert.deepEqual(schedules.items.map((schedule) => schedule.ID), ["160642", "1340788"]);
  assert.equal(schedules.items[0].ACTIVE, "1");
  assert.equal(schedules.items[0].SCHEDULE.NEXTLAUNCH_UTC, "2017-12-02T00:30:00");
  assert.equal(schedules.items[1].ACTIVE, "");
  assert.equal(schedules.items[1].TARGET, "Asset Tags Included");
  assert.equal(schedules.items[1].ASSET_TAGS.TAG_SET_INCLUDE, "EC2_Targets");

  const result = await assessQualysScanCoverage(createFakeClient({ ...healthyFixtures, listScheduledScans: async () => schedules.items }));
  const coverage = findingById(result, "QUALYS-C01");
  assert.equal(coverage.evidence.total_schedules, 2);
  assert.equal(coverage.evidence.active_schedules, 1);
  assert.equal(coverage.evidence.schedules_without_active_flag, 1, "an empty ACTIVE element is unknown, never active");
  assert.deepEqual(coverage.evidence.next_launches, ["2017-12-02T00:30:00"]);
  assert.notEqual(coverage.status, "fail", "a documented schedule list must not read as zero schedules");
});

test("docs fidelity 2: C14 matches only the documented ISCANNER_NAME literal External Scanner and never assumes a missing name is external", async () => {
  const withSchedules = (schedules) => assessQualysScanCoverage(createFakeClient({ ...healthyFixtures, listScheduledScans: async () => schedules }));

  const guideSample = await withSchedules((await routedClient(async () => xmlResponse(GUIDE_SCHEDULE_SCAN_LIST_SAMPLE)).listScheduledScans()).items);
  const literal = findingById(guideSample, "QUALYS-C14");
  assert.equal(literal.status, "pass");
  assert.deepEqual(literal.evidence.external_schedules, ["My Daily Scan"], "the line-wrapped CDATA External Scanner in the guide sample is recognized");
  assert.deepEqual(literal.evidence.scanners_in_use, ["External Scanner"]);
  assert.match(literal.summary, /ISCANNER_NAME "External Scanner"/);

  const bareWord = await withSchedules([documentedSchedule({ ID: "3", TITLE: "Bare word", ISCANNER_NAME: "External" })]);
  assert.notEqual(findingById(bareWord, "QUALYS-C14").status, "pass", "External alone is an appliance name, not the documented literal");
  assert.deepEqual(findingById(bareWord, "QUALYS-C14").evidence.external_schedules, []);

  const missing = await withSchedules([documentedSchedule({ ID: "4", TITLE: "No scanner element", ISCANNER_NAME: undefined })]);
  const unverified = findingById(missing, "QUALYS-C14");
  assert.notEqual(unverified.status, "pass", "a missing ISCANNER_NAME is unverifiable and must never pass as external");
  assert.deepEqual(unverified.evidence.external_schedules, []);
  assert.deepEqual(unverified.evidence.schedules_without_scanner_name, ["No scanner element"]);
  assert.equal(unverified.evidence.unknown_buckets.schedules_without_scanner_name, 1);
  assert.match(unverified.summary, /no ISCANNER_NAME, so their scanner is unverifiable and was never assumed to be external/);
});

test("docs fidelity 3: schedule ASSET_TAGS/TAG_SET_INCLUDE is PCDATA, so tag-targeted schedules contribute their tags as targets", async () => {
  const tagged = documentedSchedule({ ID: "5", TITLE: "Tagged", TARGET: "Asset Tags Included", ISCANNER_NAME: "External Scanner", USER_ENTERED_IPS: undefined, ASSET_TAGS: documentedAssetTags("Internal,DMZ") });
  const result = await assessQualysScanCoverage(createFakeClient({ ...healthyFixtures, listScheduledScans: async () => [tagged] }));

  const segmentation = findingById(result, "QUALYS-C20");
  assert.deepEqual(segmentation.evidence.distinct_targets, ["Internal", "DMZ"], "tags are read from the PCDATA and the TARGET placeholder Asset Tags Included is not a target");

  const coverage = findingById(result, "QUALYS-C01");
  assert.deepEqual(coverage.evidence.asset_groups_without_schedule, [], "asset groups named by the tag set count as scheduled");
  assert.equal(coverage.status, "pass");

  const client = routedClient(async () => xmlResponse(GUIDE_SCHEDULE_SCAN_LIST_SAMPLE));
  const fromGuide = await assessQualysScanCoverage(createFakeClient({ ...healthyFixtures, listScheduledScans: async () => (await client.listScheduledScans()).items }));
  assert.ok(findingById(fromGuide, "QUALYS-C20").evidence.distinct_targets.includes("10.10.10.10-10.10.10.20"));
  assert.ok(!findingById(fromGuide, "QUALYS-C20").evidence.distinct_targets.includes("Asset Tags Included"));
});

test("docs fidelity 4: option profiles are listed from /api/2.0/fo/subscription/option_profile/vm/ and parsed from the guide sample verbatim", async () => {
  const urls = [];
  const client = routedClient(async (url) => {
    urls.push(url);
    return xmlResponse(GUIDE_OPTION_PROFILE_LIST_SAMPLE);
  });
  const profiles = await client.listOptionProfiles();
  assert.equal(urls.length, 1);
  assert.ok(urls[0].startsWith("https://qualysapi.qualys.com/api/2.0/fo/subscription/option_profile/vm/?action=list"), `action=list is documented under /option_profile/vm/, got ${urls[0]}`);
  assert.equal(profiles.items.length, 1);
  assert.equal(profiles.items[0].BASIC_INFO.GROUP_NAME, "user op - 1");

  const result = await assessQualysScanCoverage(createFakeClient({ ...healthyFixtures, listOptionProfiles: async () => profiles.items }));
  const review = findingById(result, "QUALYS-C03");
  assert.deepEqual(review.evidence.option_profiles, ["user op - 1"]);
  assert.deepEqual(review.evidence.profiles_without_authentication, []);
  assert.deepEqual(review.evidence.authentication_types, { "user op - 1": ["Windows", "Unix", "Oracle", "Oracle Listener", "SNMP", "VMware", "DB2", "HTTP", "MySQL", "Sybase"] });
  assert.equal(findingById(result, "QUALYS-C16").evidence.option_profile_detection_exclusions, 0, "PASSWORD_BRUTE_FORCING custom lists are not detection exclusions");

  const access = await checkQualysAccess(createFakeClient(healthyFixtures));
  assert.equal(access.surfaces.find((surface) => surface.name === "option_profiles").endpoint, "/api/2.0/fo/subscription/option_profile/vm/");
});

test("docs fidelity 5: user status, role, and last login come from /msp/user_list.php (user_list_output.dtd); search/am/user carries no status", async () => {
  const legacyUsers = [
    legacyUser({ login: "acme_api", id: "1001", role: "Manager" }),
    legacyUser({ login: "dormant_user", id: "1002", role: "Reader", lastLogin: daysAgo(120) }),
    legacyUser({ login: "old_user", id: "1003", role: "Scanner", status: "Inactive", lastLogin: daysAgo(400) }),
    legacyUser({ login: "new_user", id: "1004", role: "Reader", status: "Pending Activation", lastLogin: null }),
  ];
  const urls = [];
  const client = routedClient(async (url, init) => {
    urls.push(url);
    if (url.includes("/msp/user_list.php")) return xmlResponse(userListXml(legacyUsers));
    if (url.includes("/am/user")) return jsonResponse(qpsResponse("User", [adminUser(0, "acme_api", "MANAGER"), adminUser(2, "dormant_user", "Reader")]));
    return emptyRouter(url, init);
  });

  const users = await client.listUsers();
  assert.ok(urls.some((url) => url.startsWith("https://qualysapi.qualys.com/msp/user_list.php")));
  assert.deepEqual(users.items.map((user) => user.USER_STATUS), ["Active", "Active", "Inactive", "Pending Activation"]);
  assert.equal(users.items[0].CONTACT_INFO.EMAIL, "acme_api@example.com");

  const result = await assessQualysAdministration(client);
  const audit = findingById(result, "QUALYS-C13");
  assert.equal(audit.evidence.user_list_users, 4);
  assert.equal(audit.evidence.active_users, 2);
  assert.equal(audit.evidence.inactive_status_users, 1);
  assert.equal(audit.evidence.pending_activation_users, 1);
  assert.deepEqual(audit.evidence.stale_login_users, ["dormant_user"]);
  assert.deepEqual(audit.evidence.managers, ["acme_api"]);
  assert.match(audit.evidence.status_source, /\/msp\/user_list\.php USER_STATUS, USER_ROLE, LAST_LOGIN_DATE/);
  assert.match(audit.evidence.api_contract, /search\/am\/user returns Active users only/);
  assert.match(audit.summary, /1 Active users whose LAST_LOGIN_DATE is older than 90 days/);
  assert.equal(audit.status, "warn");

  const erroring = routedClient(async () => xmlResponse('<?xml version="1.0" encoding="UTF-8"?><USER_LIST_OUTPUT><ERROR number="999">Internal error. Please contact customer support.</ERROR></USER_LIST_OUTPUT>'));
  await assert.rejects(() => erroring.listUsers(), /\/msp\/user_list\.php: error 999: Internal error/);

  const undocumented = await assessQualysAdministration(createFakeClient({
    ...healthyFixtures,
    listUsers: failing("Qualys request failed (403) for /msp/user_list.php: error 999: not permitted"),
    searchUsers: async () => [adminUser(0, "acme_api", "MANAGER", { userStatus: "INACTIVE", lastLoginDate: daysAgo(400) })],
  }));
  const fallback = findingById(undocumented, "QUALYS-C13");
  assert.notEqual(fallback.status, "pass");
  assert.equal(fallback.evidence.status_source, "not available");
  assert.equal(fallback.evidence.inactive_status_users, null, "userStatus and lastLoginDate are not documented on search/am/user and are never read, so the count is unknown without the User List API");
  assert.equal(fallback.evidence.users_with_last_login, null);
  assert.equal(fallback.evidence.administration_api_users, 1);
  assert.equal(fallback.evidence.stale_login_users, null, "LAST_LOGIN_DATE exists only on /msp/user_list.php, so the stale list is unknown without it");
  assert.match(fallback.evidence.stale_login_users_status, /^unreadable: user_list \(\/msp\/user_list\.php\) was not readable/);
  assert.match(fallback.summary, /documents no status or last-login field, so inactive-user detection is manual/);
});

test("docs fidelity 6: web app scan dates come from the WAS scan search launchedDate; a web app scanned before the window is stale, not never scanned", async () => {
  const historyCalls = [];
  const beforeWindow = await assessQualysAdministration(createFakeClient({
    ...healthyFixtures,
    searchWebApps: async () => [documentedWebApp({ lastScan: { id: 77, name: "Portal quarterly" } })],
    searchWasScans: async () => [],
    searchWasScanHistory: async (ids) => {
      historyCalls.push(ids);
      return [documentedWasScan({ id: 77, name: "Portal quarterly", launchedDate: daysAgo(60) })];
    },
  }));
  const stale = findingById(beforeWindow, "QUALYS-C15");
  assert.deepEqual(historyCalls, [["500"]], "unresolved web apps are looked up in the unbounded scan history by webApp.id");
  assert.deepEqual(stale.evidence.stale_web_apps, ["Portal"]);
  assert.deepEqual(stale.evidence.never_scanned_web_apps, []);
  assert.equal(stale.evidence.scan_history_scans, 1);
  assert.equal(stale.status, "fail");
  assert.match(stale.evidence.last_scan_source, /launchedDate/);
  assert.match(stale.summary, /1 were last scanned before the window per the unbounded scan history/);

  const fresh = findingById(await assessQualysAdministration(createFakeClient(healthyFixtures)), "QUALYS-C15");
  assert.equal(fresh.evidence.recently_scanned_web_apps, 1, "a FINISHED VULNERABILITY scan 4 days old is fresh against a 30 day lookback");
  assert.deepEqual(fresh.evidence.stale_web_apps, []);
  assert.equal(fresh.status, "pass");

  const undocumentedDate = await assessQualysAdministration(createFakeClient({
    ...healthyFixtures,
    searchWebApps: async () => [{ ...documentedWebApp(), lastScan: { id: 1, name: "Portal weekly", date: daysAgo(1) }, lastScanDate: daysAgo(1) }],
    searchWasScans: async () => [],
    searchWasScanHistory: async () => [],
  }));
  assert.deepEqual(findingById(undocumentedDate, "QUALYS-C15").evidence.never_scanned_web_apps, ["Portal"], "lastScan.date is not on a WAS 3.0 webapp and is never read");

  const discoveryOnly = await assessQualysAdministration(createFakeClient({
    ...healthyFixtures,
    searchWasScans: async () => [documentedWasScan({ type: "DISCOVERY" })],
    searchWasScanHistory: async () => [],
  }));
  assert.deepEqual(findingById(discoveryOnly, "QUALYS-C15").evidence.never_scanned_web_apps, ["Portal"], "only FINISHED VULNERABILITY scans count");

  const unreadableHistory = await assessQualysAdministration(createFakeClient({
    ...healthyFixtures,
    searchWasScans: async () => [],
    searchWasScanHistory: failing("Qualys QPS request failed (500) for /qps/rest/3.0/search/was/wasscan: timeout"),
  }));
  const unresolved = findingById(unreadableHistory, "QUALYS-C15");
  assert.deepEqual(unresolved.evidence.unresolved_web_apps, ["Portal"]);
  assert.equal(unresolved.evidence.never_scanned_web_apps, null, "without the history the never-scanned set is unknown, not empty");
  assert.match(unresolved.evidence.never_scanned_web_apps_status, /^unreadable: was_scan_history \(\/qps\/rest\/3\.0\/search\/was\/wasscan\) was not readable/);
  assert.equal(unresolved.status, "manual");
});

test("docs fidelity: auth record wrappers follow auth_records.dtd (AUTH_<TECHNOLOGY>_IDS with ID_SET ID and ID_RANGE spans)", async () => {
  const client = routedClient(async () => xmlResponse(AUTH_RECORDS_SAMPLE));
  const summary = await client.listAuthRecordSummary();
  assert.deepEqual(summary.items, [{ type: "unix", count: 253 }, { type: "windows", count: 2 }]);
  assert.equal(summary.truncated, false);

  const result = await assessQualysVulnerabilityManagement(createFakeClient({ ...healthyFixtures, listAuthRecordSummary: async () => summary.items }));
  assert.deepEqual(findingById(result, "QUALYS-C08").evidence.missing_auth_types, []);
  assert.equal(findingById(result, "QUALYS-C08").status, "pass");
});

test("docs fidelity: appliance versions compare ML_VERSION with ML_LATEST and VULNSIGS_VERSION with VULNSIGS_LATEST, never SOFTWARE_VERSION", async () => {
  const outdated = await assessQualysAssetInventory(createFakeClient({
    ...healthyFixtures,
    listAppliances: async () => [documentedAppliance({ ML_VERSION: { "@updated": "no", "#text": "12.7.49-1" } })],
  }));
  assert.equal(findingById(outdated, "QUALYS-C06").status, "warn");
  assert.equal(findingById(outdated, "QUALYS-C06").evidence.appliances[0].version_state, "outdated");

  const offlineGuideShape = await assessQualysAssetInventory(createFakeClient({
    ...healthyFixtures,
    listAppliances: async () => [documentedAppliance({ ML_VERSION: { "@updated": "no", "#text": "" }, VULNSIGS_VERSION: { "@updated": "no", "#text": "" } })],
  }));
  assert.equal(findingById(offlineGuideShape, "QUALYS-C06").evidence.appliances[0].version_state, "outdated", "the guide shows <ML_VERSION updated=\"no\"></ML_VERSION>, so the attribute decides");

  const noLatest = await assessQualysAssetInventory(createFakeClient({
    ...healthyFixtures,
    listAppliances: async () => [documentedAppliance({ ML_LATEST: undefined, ML_VERSION: "12.7.50-1", VULNSIGS_LATEST: undefined, VULNSIGS_VERSION: "2.6.212-3" })],
  }));
  assert.equal(findingById(noLatest, "QUALYS-C06").status, "warn");
  assert.equal(findingById(noLatest, "QUALYS-C06").evidence.unknown_buckets.appliances_without_version_data, 1);
});

// ---------------------------------------------------------------------------------------------
// View scope and access check
// ---------------------------------------------------------------------------------------------

test("resolveViewScope verifies the API user role from the user search, then the User List API, then the activity log, and reports unverified", () => {
  const config = sampleConfig();
  const readable = (name, data) => ({ name, data, moduleUnavailable: false, truncated: false });
  const unreadable = (name) => ({ name, data: [], error: "Qualys request failed (403)", moduleUnavailable: true, truncated: false });

  const manager = resolveViewScope(config, readable("users", [adminUser(0, "ACME_API", "Manager")]));
  assert.equal(manager.verified, true);
  assert.equal(manager.partial, false);
  assert.equal(manager.source, "user_search");

  const reader = resolveViewScope(config, readable("users", [adminUser(0, "acme_api", "Reader")]));
  assert.equal(reader.partial, true);
  assert.match(reader.note, /Reader/);

  const scoped = resolveViewScope(config, readable("users", [adminUser(0, "acme_api", "Manager", { scopeTags: { list: [{ TagData: { name: "BU-East" } }] } })]));
  assert.equal(scoped.partial, true);
  assert.deepEqual(scoped.scopeTags, ["BU-East"]);

  const fromUserList = resolveViewScope(config, readable("users", []), undefined, readable("user_list", [legacyUser({ login: "acme_api", role: "Unit Manager" })]));
  assert.equal(fromUserList.verified, true);
  assert.equal(fromUserList.partial, true);
  assert.equal(fromUserList.source, "user_list");
  assert.match(fromUserList.note, /User List API records API user acme_api with role Unit Manager/);

  const managerFromUserList = resolveViewScope(config, readable("users", []), undefined, readable("user_list", [legacyUser({ login: "acme_api", role: "Manager" })]));
  assert.equal(managerFromUserList.partial, false);

  const fromActivity = resolveViewScope(config, readable("users", []), readable("activity_log", [{ user_name: "acme_api", user_role: "Manager" }]));
  assert.equal(fromActivity.verified, true);
  assert.equal(fromActivity.partial, false);
  assert.equal(fromActivity.source, "activity_log");

  const hidden = resolveViewScope(config, readable("users", [adminUser(9, "someone_else", "Reader")]));
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
  assert.equal(healthy.surfaces.length, 15);
  assert.ok(healthy.surfaces.every((surface) => surface.status === "readable"));
  assert.deepEqual(healthy.unavailableModules, []);
  assert.equal(healthy.viewScope.verified, true);
  assert.equal(healthy.viewScope.partial, false);
  assert.match(healthy.notes.join("\n"), /Manager role/);
  const userList = healthy.surfaces.find((surface) => surface.name === "user_list");
  assert.equal(userList.endpoint, "/msp/user_list.php");
  assert.equal(userList.count, 3);

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
    searchUsers: async () => [adminUser(0, "acme_api", "Reader")],
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
    listHosts: async () => truncated([documentedHost()], "item cap 100 reached with more records available"),
  }));
  assert.match(truncatedProbe.surfaces.find((surface) => surface.name === "hosts").truncation, /item cap 100/);
});

// ---------------------------------------------------------------------------------------------
// Per-tool fixtures: passing, failing, unreadable, empty, partial
// ---------------------------------------------------------------------------------------------

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
  assert.deepEqual(findingById(healthy, "QUALYS-C01").evidence.asset_groups_without_schedule, []);
  assert.deepEqual(findingById(healthy, "QUALYS-C14").evidence.external_schedules, ["Perimeter"]);
  assert.deepEqual(findingById(healthy, "QUALYS-C20").evidence.distinct_targets, ["Internal", "10.0.0.1-10.0.0.254", "DMZ"]);
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
  assert.match(findingById(empty, "QUALYS-C16").summary, /detection exclusion search lists could not be evaluated/);

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
  assert.equal(findingById(healthy, "QUALYS-C06").evidence.appliances[0].version_state, "current");
  assert.equal(findingById(healthy, "QUALYS-C07").evidence.agent_coverage_percent, 100);
  assert.equal(findingById(healthy, "QUALYS-C07").evidence.agents_without_activation_key, 0);
  assert.equal(findingById(healthy, "QUALYS-C18").evidence.dynamic_tags, 1, "STATIC tags are not rule based");
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
    "QUALYS-C13": "pass",
    "QUALYS-C15": "pass",
    "QUALYS-C19": "warn",
  });
  assert.match(findingById(healthy, "QUALYS-C12").summary, /Distribution recipients are not exposed/);
  const audit = findingById(healthy, "QUALYS-C13");
  assert.match(audit.summary, /3 Active users \(USER_STATUS\) of 3 returned by the User List API/);
  assert.match(audit.summary, /0 Active users without a LAST_LOGIN_DATE/);
  assert.deepEqual(audit.evidence.managers, ["acme_api", "acme_mgr"]);
  assert.equal(audit.evidence.users_with_last_login, 3);
  assert.match(findingById(healthy, "QUALYS-C19").summary, /capped at warn/);
  assert.ok(audit.mappings.includes("SOC 2 CC6.3"));
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
  assert.deepEqual(findingById(weak, "QUALYS-C13").evidence.generic_accounts, ["shared_admin", "svc_scan"]);
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

  const noUserList = await assessQualysAdministration(createFakeClient({ ...healthyFixtures, listUsers: failing("Qualys request failed for /msp/user_list.php: error 999: not permitted") }));
  assert.equal(findingById(noUserList, "QUALYS-C13").status, "manual", "the Administration API search alone cannot establish status or last login");
  assert.match(findingById(noUserList, "QUALYS-C13").summary, /User List API \(\/msp\/user_list\.php, user_list_output\.dtd\), which was not readable/);
});

test("assessQualysAdministration: empty fixture never passes", async () => {
  const empty = await assessQualysAdministration(createFakeClient());
  assert.deepEqual(statusMap(empty), {
    "QUALYS-C12": "fail",
    "QUALYS-C13": "manual",
    "QUALYS-C15": "manual",
    "QUALYS-C19": "manual",
  });
  assert.match(findingById(empty, "QUALYS-C13").summary, /cannot see the user population/);
  assert.match(findingById(empty, "QUALYS-C15").summary, /not applicable if no web applications are in scope/);
  assert.match(findingById(empty, "QUALYS-C19").summary, /cannot read the log/);
});

test("assessQualysAdministration: partial fixture never passes", async () => {
  const partial = await assessQualysAdministration(createFakeClient(partialFixtures(healthyFixtures)));
  assert.ok(partial.findings.every((item) => item.status !== "pass"));
  assert.equal(findingById(partial, "QUALYS-C15").status, "warn");
  assert.match(findingById(partial, "QUALYS-C15").summary, /Partial view: was_webapps page cap 25/);
  assert.equal(findingById(partial, "QUALYS-C13").status, "warn");
  assert.match(findingById(partial, "QUALYS-C13").summary, /Partial view: user_list page cap 25/);
});

// ---------------------------------------------------------------------------------------------
// Verdict safety rules through the real client and the fake client
// ---------------------------------------------------------------------------------------------

test("rule 1: a SIMPLE_RETURN or 403 response through the real client yields manual, never pass, and names the cause", async () => {
  const client = routedClient(forbiddenRouter);
  const results = await runAllAssessments(client);
  const findings = allFindings(results);
  assert.equal(findings.length, 20);
  for (const item of findings) {
    assert.equal(item.status, "manual", `${item.id} must be manual when its evidence is forbidden`);
    assert.match(item.summary, /Collect manually:/);
    assert.match(item.summary, /code 2010|responseCode UNAUTHORIZED/, "the parsed SIMPLE_RETURN code or QPS responseCode names the cause");
    assert.ok(item.evidence.collection.sources.some((source) => source.status === "unreadable"));
  }
  assert.ok(results.every((result) => result.errors.length > 0));
  assert.match(findingById(results[3], "QUALYS-C13").summary, /\/msp\/user_list\.php: error 999: Forbidden/, "the documented USER_LIST_OUTPUT/ERROR element is surfaced with its number");
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
      { ID: "102", IP: "10.0.0.7", TRACKING_METHOD: "Cloud Agent", OS: "Windows Server 2022", TAGS: { TAG: { TAG_ID: "2", NAME: "Prod" } } },
    ],
    searchCloudAgents: async () => [
      ...(await healthyFixtures.searchCloudAgents()),
      documentedAgent({ id: 102, agentInfo: { status: "STATUS_ACTIVE", activationKey: { activationId: "0f1e2d3c", title: "prod-key" } } }),
    ],
    searchConnectors: async () => [documentedConnector({ lastSync: undefined })],
    listDetections: async () => [
      ...(await healthyFixtures.listDetections()),
      { host_id: "102", ...documentedDetection({ FIRST_FOUND_DATETIME: undefined, LAST_FOUND_DATETIME: undefined, QDS: { "#text": "80" } }) },
    ],
    searchWasAuthRecords: async () => [documentedWasAuthRecord({ createdDate: undefined, updatedDate: undefined })],
    listUsers: async () => [
      ...(await healthyFixtures.listUsers()),
      legacyUser({ login: "acme_new", id: "1004", role: "Reader", email: "new@example.com", lastLogin: null }),
    ],
    searchUsers: async () => [adminUser(0, "acme_api", "Manager", { emailAddress: "api@example.com" })],
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
  const users = findingById(admin, "QUALYS-C13");
  assert.equal(users.status, "warn");
  assert.equal(users.evidence.unknown_buckets.users_without_last_login, 1);
  assert.deepEqual(users.evidence.stale_login_users, [], "a user without LAST_LOGIN_DATE is never counted as stale or as recently active");

  const onlyUndated = await assessQualysVulnerabilityManagement(createFakeClient({
    ...healthyFixtures,
    listDetections: async () => [{ host_id: "100", ...documentedDetection({ FIRST_FOUND_DATETIME: undefined, LAST_FOUND_DATETIME: undefined }) }],
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
  }

  const reader = createFakeClient({
    ...healthyFixtures,
    searchUsers: async () => [adminUser(0, "acme_api", "Reader", { emailAddress: "api@example.com" })],
  });
  const readerFindings = allFindings(await runAllAssessments(reader));
  assert.ok(readerFindings.every((item) => item.status !== "pass"), "a Reader role can only see its own asset groups, so nothing may pass");
  const wouldPass = readerFindings.filter((item) => item.evidence.verdict_basis === "pass");
  assert.equal(wouldPass.length, COMPLIANT_PASS_IDS.length);
  for (const item of wouldPass) {
    assert.equal(item.status, "warn");
    assert.match(item.summary, /Partial view: API user acme_api holds role Reader/);
    assert.equal(item.evidence.collection.view_scope.partial, true);
  }

  const scopedManager = await assessQualysScanCoverage(createFakeClient({
    ...healthyFixtures,
    searchUsers: async () => [adminUser(0, "acme_api", "Manager", { scopeTags: { list: [{ TagData: { name: "BU-East" } }] } })],
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
      documentedSchedule({ ID: "1", ACTIVE: undefined, TITLE: "No flag", TARGET: "10.0.0.0/24" }),
      documentedSchedule({ ID: "2", ACTIVE: "", TITLE: "Empty flag", TARGET: "203.0.113.0/28" }),
    ],
    listCompliancePolicies: async () => [
      documentedPolicy({ ASSET_GROUP_IDS: "10" }),
      documentedPolicy({ ID: "6", TITLE: "No status", STATUS: undefined, ASSET_GROUP_IDS: "10" }),
      documentedPolicy({ ID: "7", TITLE: "Hidden groups", ASSET_GROUP_IDS: { "@has_hidden_data": "1", "#text": "" } }),
    ],
    listDetections: async () => [
      ...(await healthyFixtures.listDetections()),
      { host_id: "100", ...documentedDetection({ QID: "77000", STATUS: "Fixed", FIRST_FOUND_DATETIME: daysAgo(400) }) },
      { host_id: "100", ...documentedDetection({ QID: "78000", TYPE: "Info", SEVERITY: undefined, FIRST_FOUND_DATETIME: daysAgo(400) }) },
      { host_id: "100", ...documentedDetection({ QID: "79000", SEVERITY: undefined, FIRST_FOUND_DATETIME: daysAgo(2) }) },
    ],
    listKnowledgeBase: async () => [...tenant.knowledgeBase, documentedVuln({ QID: "79000", PATCHABLE: "0" })],
    searchCloudAgents: async () => [
      ...(await healthyFixtures.searchCloudAgents()),
      documentedAgent({ id: 102, agentInfo: { lastCheckedIn: { date: daysAgo(0) }, activationKey: { activationId: "0f1e2d3c", title: "prod-key" } } }),
    ],
    listHosts: async () => [
      ...(await healthyFixtures.listHosts()),
      documentedHost({ ID: "102", IP: "10.0.0.7", TRACKING_METHOD: undefined, LAST_VULN_SCAN_DATETIME: daysAgo(1), LAST_VM_SCANNED_DATE: daysAgo(1), LAST_VM_AUTH_SCANNED_DATE: daysAgo(1) }),
    ],
    searchWasSchedules: async () => [documentedWasSchedule({ active: undefined })],
    listUsers: async () => [
      ...(await healthyFixtures.listUsers()),
      legacyUser({ login: "no_role", id: "1005", role: null, email: "norole@example.com" }),
    ],
  });
  const [scan, inventory, vuln, admin] = await runAllAssessments(flagless);

  const schedules = findingById(scan, "QUALYS-C01");
  assert.equal(schedules.status, "fail", "schedules without an ACTIVE flag of 1, 2, or 3 are not active");
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
    listOptionProfiles: async () => [documentedOptionProfile({ BASIC_INFO: { ID: "7", GROUP_NAME: "Silent" }, SCAN: {} })],
  }));
  assert.deepEqual(findingById(noAuthProfile, "QUALYS-C03").evidence.profiles_without_authentication, ["Silent"]);

  const unknownAppliance = await assessQualysAssetInventory(createFakeClient({
    ...healthyFixtures,
    listAppliances: async () => [{ ID: "2", NAME: "mystery" }],
  }));
  assert.equal(findingById(unknownAppliance, "QUALYS-C06").status, "warn");
  assert.equal(findingById(unknownAppliance, "QUALYS-C06").evidence.unknown_buckets.appliances_without_status, 1);

  const inactiveReport = await assessQualysAdministration(createFakeClient({
    ...healthyFixtures,
    listScheduledReports: async () => [documentedScheduledReport({ ACTIVE: "0" }), documentedScheduledReport({ ID: "4", ACTIVE: undefined })],
  }));
  assert.equal(findingById(inactiveReport, "QUALYS-C12").status, "fail");
  assert.equal(findingById(inactiveReport, "QUALYS-C12").evidence.scheduled_reports_without_active_flag, 1);
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

// ---------------------------------------------------------------------------------------------
// Rule 9: rawData is a per-record allowlist projection, never the verbatim API response
// ---------------------------------------------------------------------------------------------

// One distinct fake secret per surface that can carry credential or distribution material, each planted in the
// documented field that holds it (option_profile_info.dtd LOGIN_PASSWORD and CUSTOM_HTTP_HEADER, agent_source.xsd
// activationId, the AWS connector arn and externalId, webappauthrecord.xsd field values and clientSecret,
// appliance_list_output.dtd ACTIVATION_CODE and PROXY USER, webapp.xsd headers, host METADATA, user_list_output.dtd
// PHONE, tag.xsd ruleText, detection RESULTS, schedule NOTIFICATIONS, wasscanschedule.xsd recipients, wasscan.xsd
// sensitiveContents) plus an undocumented recipients element on a scheduled report.
const PLANTED_SECRETS = {
  option_profile_password: "L:svc_scan,P:OPTIONPROFILE-BRUTEFORCE-SECRET-7f3a",
  option_profile_header: "Authorization: Bearer OPTIONPROFILE-HEADER-SECRET-9c1d",
  agent_activation_id: "AGENT-ACTIVATION-ID-SECRET-4b2e",
  connector_external_id: "CONNECTOR-EXTERNAL-ID-SECRET-6d8f",
  connector_arn: "arn:aws:iam::123456789012:role/CONNECTOR-ROLE-ARN-SECRET-1a2b",
  was_form_password: "WAS-FORM-PASSWORD-SECRET-3c4d",
  was_server_password: "WAS-SERVER-PASSWORD-SECRET-5e6f",
  was_oauth_client_secret: "WAS-OAUTH-CLIENT-SECRET-7a8b",
  report_recipient: "REPORT-RECIPIENT-SECRET-9c0d@example.com",
  appliance_activation_code: "APPLIANCE-ACTIVATION-CODE-SECRET-1e2f",
  appliance_proxy_user: "APPLIANCE-PROXY-USER-SECRET-3a4b",
  webapp_header: "Authorization: Bearer WEBAPP-HEADER-SECRET-5c6d",
  host_metadata_value: "HOST-METADATA-VALUE-SECRET-7e8f",
  user_phone: "USER-PHONE-SECRET-9a0b",
  tag_rule_text: "TAG-RULETEXT-SECRET-1c2d",
  detection_results: "DETECTION-RESULTS-SECRET-3e4f",
  schedule_notification: "SCHEDULE-NOTIFICATION-SECRET-5a6b",
  was_schedule_recipient: "WAS-SCHEDULE-RECIPIENT-SECRET-7c8d@example.com",
  was_scan_sensitive_content: "WAS-SCAN-SENSITIVE-CONTENT-SECRET-9e0f",
};

const secretFixtures = {
  ...healthyFixtures,
  listScheduledScans: async () => tenant.schedules.map((schedule) => ({
    ...schedule,
    NOTIFICATIONS: { BEFORE_LAUNCH: { TIME: "30", UNIT: "minutes", MESSAGE: PLANTED_SECRETS.schedule_notification } },
  })),
  listHosts: async () => tenant.hosts.map((host) => ({
    ...host,
    METADATA: { EC2: { ATTRIBUTE: { NAME: "latest/dynamic/instance-identity/document/accountId", LAST_STATUS: "Success", VALUE: PLANTED_SECRETS.host_metadata_value } } },
  })),
  listOptionProfiles: async () => tenant.profiles.map((profile) => ({
    ...profile,
    SCAN: {
      ...profile.SCAN,
      PASSWORD_BRUTE_FORCING: { SYSTEM: { HAS_SYSTEM: "1", SYSTEM_LEVEL: "Standard" }, CUSTOM_LIST: { CUSTOM: { ID: "1001", TITLE: "ssh - 1", TYPE: "SSH", LOGIN_PASSWORD: PLANTED_SECRETS.option_profile_password } } },
      CUSTOM_HTTP_HEADER: { VALUE: PLANTED_SECRETS.option_profile_header, DEFINITION_KEY: "Authorization", DEFINITION_VALUE: PLANTED_SECRETS.option_profile_header },
    },
  })),
  listAppliances: async () => tenant.appliances.map((appliance) => ({
    ...appliance,
    ACTIVATION_CODE: PLANTED_SECRETS.appliance_activation_code,
    PROXY_SETTINGS: { SETTING: "Enabled", PROXY: { PROTOCOL: "https", HOSTNAME: "proxy.example.com", PORT: "3128", USER: PLANTED_SECRETS.appliance_proxy_user } },
  })),
  listDetections: async () => flattenDetections(tenant.detectionHosts).map((detection) => ({ ...detection, RESULTS: PLANTED_SECRETS.detection_results })),
  listScheduledReports: async () => tenant.scheduledReports.map((report) => ({
    ...report,
    DISTRIBUTION_GROUPS: { DISTRIBUTION_GROUP: { TITLE: "Executives", RECIPIENTS: { EMAIL: PLANTED_SECRETS.report_recipient } } },
  })),
  listUsers: async () => tenant.legacyUsers.map((user) => ({ ...user, CONTACT_INFO: { ...user.CONTACT_INFO, PHONE: PLANTED_SECRETS.user_phone } })),
  searchCloudAgents: async () => tenant.agents.map((agent) => ({
    ...agent,
    agentInfo: { ...agent.agentInfo, activationKey: { activationId: PLANTED_SECRETS.agent_activation_id, title: "prod-key" } },
  })),
  searchConnectors: async () => tenant.connectors.map((connector) => ({
    ...connector,
    arn: PLANTED_SECRETS.connector_arn,
    externalId: PLANTED_SECRETS.connector_external_id,
  })),
  searchTags: async () => tenant.tags.map((tag) => ({ ...tag, ruleText: PLANTED_SECRETS.tag_rule_text })),
  searchWebApps: async () => tenant.webApps.map((webApp) => ({
    ...webApp,
    headers: { count: 1, list: [{ WebAppHeader: PLANTED_SECRETS.webapp_header }] },
  })),
  searchWasScans: async () => tenant.wasScans.map((scan) => ({
    ...scan,
    sensitiveContents: { count: 1, list: [{ SensitiveContent: PLANTED_SECRETS.was_scan_sensitive_content }] },
  })),
  searchWasAuthRecords: async () => tenant.wasAuthRecords.map((record) => ({
    ...record,
    formRecord: {
      ...record.formRecord,
      fields: {
        count: 2,
        list: [
          { WebAppAuthFormRecordField: { id: 1, name: "username", secured: false, value: "portal_user" } },
          { WebAppAuthFormRecordField: { id: 2, name: "password", secured: true, value: PLANTED_SECRETS.was_form_password } },
        ],
      },
    },
    serverRecord: {
      type: "BASIC",
      sslOnly: true,
      fields: { count: 1, list: [{ WebAppAuthServerRecordField: { id: 3, type: "BASIC", domain: "portal.example.com", username: "portal_admin", password: PLANTED_SECRETS.was_server_password } }] },
    },
    oauth2Record: { grantType: "CLIENT_CREDS", clientId: "portal-client", clientSecret: PLANTED_SECRETS.was_oauth_client_secret, accessTokenUrl: "https://portal.example.com/oauth/token" },
  })),
  searchWasSchedules: async () => tenant.wasSchedules.map((schedule) => ({
    ...schedule,
    notification: { sendMail: true, recipients: { count: 1, list: [{ EmailAddress: PLANTED_SECRETS.was_schedule_recipient }] } },
  })),
};

function walkFiles(root, dir = root) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const pathname = join(dir, entry.name);
    if (entry.isDirectory()) return walkFiles(root, pathname);
    return [{ name: relative(root, pathname), content: readFileSync(pathname, "utf8") }];
  });
}

// Minimal reader for the archives written by archiver: end of central directory, central directory entries, and
// each local header, inflating deflate members with zlib.
function readZipMembers(zipPath) {
  const buffer = readFileSync(zipPath);
  let eocd = buffer.length - 22;
  while (eocd >= 0 && buffer.readUInt32LE(eocd) !== 0x06054b50) eocd -= 1;
  assert.ok(eocd >= 0, "end of central directory record not found");
  const entryCount = buffer.readUInt16LE(eocd + 10);
  let offset = buffer.readUInt32LE(eocd + 16);
  const members = [];
  for (let index = 0; index < entryCount; index += 1) {
    assert.equal(buffer.readUInt32LE(offset), 0x02014b50, "central directory file header signature");
    const method = buffer.readUInt16LE(offset + 10);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const localOffset = buffer.readUInt32LE(offset + 42);
    const name = buffer.toString("utf8", offset + 46, offset + 46 + nameLength);
    assert.equal(buffer.readUInt32LE(localOffset), 0x04034b50, `local file header signature for ${name}`);
    const dataStart = localOffset + 30 + buffer.readUInt16LE(localOffset + 26) + buffer.readUInt16LE(localOffset + 28);
    const data = buffer.subarray(dataStart, dataStart + compressedSize);
    assert.ok(method === 8 || method === 0, `unsupported compression method ${method} for ${name}`);
    members.push({ name, content: (method === 8 ? inflateRawSync(data) : data).toString("utf8") });
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return members;
}

test("rule 9: the audit bundle never carries a planted secret in any file or zip member while the allowlisted fields survive", async () => {
  const outputRoot = createTempBase("qualys-secrets-");
  const config = sampleConfig();
  const client = createFakeClient(secretFixtures, config);
  const result = await exportQualysAuditBundle(client, config, outputRoot);
  assert.equal(result.errorCount, 0);

  const files = walkFiles(result.outputDir);
  const members = readZipMembers(result.zipPath).filter((member) => !member.name.endsWith("/"));
  assert.ok(files.length >= 30, `expected a full bundle, got ${files.length} files`);
  assert.deepEqual(members.map((member) => member.name).sort(), files.map((file) => file.name).sort(), "every written file is a zip member");
  for (const [label, secret] of Object.entries(PLANTED_SECRETS)) {
    for (const file of files) {
      assert.equal(file.content.includes(secret), false, `${label} leaked into ${file.name}`);
    }
    for (const member of members) {
      assert.equal(member.content.includes(secret), false, `${label} leaked into zip member ${member.name}`);
    }
  }
  for (const file of files) {
    assert.equal(file.content.includes(config.password), false, `credential leaked into ${file.name}`);
  }

  const read = (name) => {
    const surface = JSON.parse(readFileSync(join(result.outputDir, "core_data", name), "utf8"));
    assert.equal(surface.status, "readable", `${name} was read completely`);
    assert.equal(surface.count, surface.records.length, `${name} count matches its records`);
    return surface.records;
  };
  const profiles = read("scan_coverage/option_profiles.json");
  assert.equal(profiles[0].BASIC_INFO.GROUP_NAME, "Authenticated Full");
  assert.equal(profiles[0].SCAN.AUTHENTICATION, "Windows,Unix");
  assert.equal(profiles[0].SCAN.PASSWORD_BRUTE_FORCING, undefined);
  assert.equal(profiles[0].SCAN.CUSTOM_HTTP_HEADER, undefined);
  assert.equal(profiles[0].SCAN.PORTS, undefined, "option profile configuration is not exported verbatim");

  const agents = read("asset_inventory/cloud_agents.json");
  assert.equal(agents[0].agentInfo.status, "STATUS_ACTIVE");
  assert.deepEqual(agents[0].agentInfo.lastCheckedIn, { date: tenant.agents[0].agentInfo.lastCheckedIn.date });
  assert.deepEqual(agents[0].agentInfo.activationKey, { title: "prod-key" });

  const connectors = read("asset_inventory/connectors.json");
  assert.equal(connectors[0].name, "prod-aws");
  assert.equal(connectors[0].connectorState, "FINISHED_SUCCESS");
  assert.equal(connectors[0].awsAccountId, "123456789012");
  assert.equal(connectors[0].lastSync, tenant.connectors[0].lastSync);
  assert.equal(connectors[0].arn, undefined);
  assert.equal(connectors[0].externalId, undefined);

  const appliances = read("asset_inventory/appliances.json");
  assert.deepEqual(appliances[0].ML_VERSION, { "@updated": "yes", "#text": "12.7.50-1" }, "DTD text nodes keep their attributes");
  assert.equal(appliances[0].STATUS, "Online");
  assert.equal(appliances[0].ACTIVATION_CODE, undefined);
  assert.equal(appliances[0].PROXY_SETTINGS, undefined);

  const hosts = read("scan_coverage/hosts.json");
  assert.deepEqual(hosts[0].TAGS.TAG.map((tag) => tag.NAME), ["PCI", "Prod"]);
  assert.equal(hosts[0].LAST_VM_AUTH_SCANNED_DATE, tenant.hosts[0].LAST_VM_AUTH_SCANNED_DATE);
  assert.equal(hosts[0].METADATA, undefined);

  const authRecords = read("administration/was_auth_records.json");
  assert.equal(authRecords[0].name, "portal-login");
  assert.equal(authRecords[0].updatedDate, tenant.wasAuthRecords[0].updatedDate);
  assert.deepEqual(authRecords[0].formRecord.fields.list.map((entry) => entry.WebAppAuthFormRecordField), [
    { id: 1, name: "username", secured: false },
    { id: 2, name: "password", secured: true },
  ]);
  assert.deepEqual(authRecords[0].serverRecord.fields.list, [{ WebAppAuthServerRecordField: { id: 3, type: "BASIC", domain: "portal.example.com" } }]);
  assert.deepEqual(authRecords[0].oauth2Record, { grantType: "CLIENT_CREDS" });

  const scheduledReports = read("administration/scheduled_reports.json");
  assert.equal(scheduledReports[0].TITLE, "Weekly executive report");
  assert.equal(scheduledReports[0].ACTIVE, "1");
  assert.deepEqual(scheduledReports[0].SCHEDULE.WEEKLY, { "@frequency_weeks": "1", "@weekdays": "1" });
  assert.equal(scheduledReports[0].DISTRIBUTION_GROUPS, undefined);

  const schedules = read("scan_coverage/scheduled_scans.json");
  assert.equal(schedules[1].ISCANNER_NAME, "External Scanner");
  assert.equal(schedules[1].ASSET_TAGS.TAG_SET_INCLUDE, "DMZ");
  assert.equal(schedules[0].NOTIFICATIONS, undefined);

  const userList = read("administration/user_list.json");
  assert.equal(userList.length, 3);
  assert.equal(userList[0].USER_STATUS, "Active");
  assert.equal(userList[0].USER_ROLE, "Manager");
  assert.equal(userList[0].CONTACT_INFO.EMAIL, "api@example.com");
  assert.equal(userList[0].CONTACT_INFO.PHONE, undefined);

  const detections = read("vulnerability_management/detections.json");
  assert.equal(detections[0].QID, "91000");
  assert.equal(detections[0].host_id, "100");
  assert.deepEqual(detections[0].QDS, { "@severity": "HIGH", "#text": "72" });
  assert.equal(detections[0].RESULTS, undefined);

  const webApps = read("administration/was_webapps.json");
  assert.deepEqual(webApps[0].lastScan, { id: 1, name: "Portal weekly" });
  assert.equal(webApps[0].headers, undefined);
  const wasScans = read("administration/was_scans.json");
  assert.equal(wasScans[0].launchedDate, tenant.wasScans[0].launchedDate);
  assert.deepEqual(wasScans[0].target.webApp, { id: 500, name: "Portal", url: "https://portal.example.com" });
  assert.equal(wasScans[0].sensitiveContents, undefined);
  const wasSchedules = read("administration/was_schedules.json");
  assert.equal(wasSchedules[0].active, true);
  assert.equal(wasSchedules[0].notification, undefined);
  const tags = read("asset_inventory/tags.json");
  assert.equal(tags[0].ruleType, "NAME_CONTAINS");
  assert.equal(tags[0].ruleText, undefined);
});

test("rule 9: every rawData surface has an allowlist and an unknown surface is refused rather than exported verbatim", async () => {
  const results = await runAllAssessments(createFakeClient(healthyFixtures));
  const surfaces = rawDataSurfaceNames();
  for (const result of results) {
    for (const [name, surface] of Object.entries(result.rawData)) {
      assert.ok(surfaces.includes(name), `${result.category}/${name} has no allowlist`);
      assert.equal(surface.name, name);
      assert.match(surface.endpoint, /^\/(api|qps|msp)\//, `${name} names its endpoint`);
      if (surface.status === "readable" || surface.status === "truncated") {
        assert.ok(Array.isArray(surface.records), `${name} carries projected records`);
        assert.equal(surface.count, surface.records.length);
      } else {
        assert.equal(surface.records, null, `${name} was ${surface.status}, so it carries no records array`);
        assert.equal(surface.count, null);
      }
    }
  }
  assert.throws(() => exportableRecords("verbatim_surface", [{ password: "x" }]), /No rawData allowlist is defined for surface verbatim_surface/);
  assert.deepEqual(exportableRecords("auth_records", [{ type: "unix", count: 3, password: "nope" }]), [{ type: "unix", count: 3 }]);
  assert.deepEqual(
    exportableRecords("cloud_agents", [{ id: 1, agentInfo: { lastCheckedIn: "2026-09-01T00:00:00Z", activationKey: { activationId: "secret", title: "key" } } }]),
    [{ id: 1, agentInfo: { lastCheckedIn: "2026-09-01T00:00:00Z", activationKey: { title: "key" } } }],
    "a plain dateTime survives the date rule and the activation ID never does",
  );
  assert.deepEqual(exportableRecords("connectors", [{ id: 1, lastSync: { date: "2026-09-01T00:00:00Z", zone: "UTC" } }]), [{ id: 1, lastSync: { date: "2026-09-01T00:00:00Z" } }]);
});

// ---------------------------------------------------------------------------------------------
// Rule 9, error-body class: a secret a Qualys server echoes in an error body (not the configured credential) must
// never reach a finding, summary, errors array, collection.sources reason, bundle file, zip entry, or thrown error.
// ---------------------------------------------------------------------------------------------

const ERROR_CANARIES = {
  bearer: "CANARY-BEARER-7f3a9c1d",
  session: "CANARY-SESSION-7f3a9c1d",
  apiKey: "CANARY-APIKEY-7f3a9c1d",
  urlToken: "CANARY-URLTOKEN-7f3a9c1d",
  // 64 characters, the shape of a QPS or gateway token, with no header, name, or scheme around it.
  longToken: `C4NARYL0NGT0KEN${"7f3a9c1d".repeat(6)}0`,
  // The caller's own password (sampleConfig), which a SIMPLE_RETURN TEXT may echo.
  password: "s3cret-value",
  // Plain lowercase letters: no header, no name, no token shape. Only the rule that never echoes a body keeps them out.
  bareHtml: "canaryhtmlbodyzqxwvutsrp",
  bareCsv: "canarycsvrowzqxwvutsrp",
};

function canaryHtmlPage() {
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>502 Bad Gateway</title></head><body><h1>502 Bad Gateway ${ERROR_CANARIES.bareHtml}</h1><p>Authorization: Bearer ${ERROR_CANARIES.bearer}</p><p>Set-Cookie: QualysSession=${ERROR_CANARIES.session}; Path=/; HttpOnly</p><p>X-Api-Key: qk_live_${ERROR_CANARIES.apiKey}</p><br></body></html>`;
}

function canarySimpleReturn() {
  return `<?xml version="1.0" encoding="UTF-8" ?><!DOCTYPE SIMPLE_RETURN SYSTEM "https://qualysapi.qualys.com/api/2.0/simple_return.dtd"><SIMPLE_RETURN><RESPONSE><DATETIME>${daysAgo(0)}</DATETIME><CODE>1903</CODE><TEXT>Login failed for acme_api with password ${ERROR_CANARIES.password}; retry at https://qualysapi.qualys.com/api/2.0/fo/report/?action=fetch&amp;token=${ERROR_CANARIES.urlToken}</TEXT></RESPONSE></SIMPLE_RETURN>`;
}

function canaryQpsError() {
  return { ServiceResponse: { responseCode: "INVALID_REQUEST", responseErrorDetails: { errorMessage: `Upstream rejected token ${ERROR_CANARIES.longToken} for QualysSession=${ERROR_CANARIES.session}` } } };
}

function canaryCsvBody() {
  return `${CSV_HEADER}"${daysAgo(0)}","login","auth","password=${ERROR_CANARIES.password} X-Api-Key: ${ERROR_CANARIES.apiKey} ${ERROR_CANARIES.bareCsv}","acme_api","Manager","10.0.0.9"\n`;
}

function assertNoCanary(text, label) {
  for (const [name, canary] of Object.entries(ERROR_CANARIES)) {
    assert.ok(!text.includes(canary), `${label}: ${name} canary leaked`);
  }
}

test("scrubErrorText redacts every credential shape in free text and leaves benign Qualys operator text untouched", () => {
  const basic = Buffer.from("acme_api:s3cret-value").toString("base64");
  const cases = [
    { name: "tokenised URL query", input: `retry at https://qualysapi.qualys.com/api/2.0/fo/report/?action=fetch&token=${ERROR_CANARIES.urlToken}`, expect: /^retry at https:\/\/qualysapi\.qualys\.com\/api\/2\.0\/fo\/report\/\?\[REDACTED\]$/ },
    { name: "tokenised URL fragment", input: `see https://qualysguard.qg1.apps.qualys.com/portal/#access_token=${ERROR_CANARIES.urlToken}&token_type=bearer`, expect: /^see https:\/\/qualysguard\.qg1\.apps\.qualys\.com\/portal\/#\[REDACTED\]$/ },
    { name: "Bearer", input: `Authorization: Bearer ${ERROR_CANARIES.bearer}`, expect: /^Authorization: Bearer \[REDACTED\]$/ },
    { name: "Basic", input: `Authorization: Basic ${basic}`, expect: /^Authorization: Basic \[REDACTED\]$/ },
    { name: "Cookie", input: `Cookie: QualysSession=${ERROR_CANARIES.session}; theme=dark`, expect: /^Cookie: \[REDACTED\]$/ },
    { name: "Set-Cookie", input: `Set-Cookie: QualysSession=${ERROR_CANARIES.session}; Path=/; HttpOnly`, expect: /^Set-Cookie: \[REDACTED\]$/ },
    { name: "session assignment", input: `QualysSession=${ERROR_CANARIES.session}`, expect: /^QualysSession=\[REDACTED\]$/ },
    { name: "session id quoted", input: `"session_id": "${ERROR_CANARIES.session}"`, expect: /^"session_id": "\[REDACTED\]"$/ },
    { name: "API key header", input: `X-Api-Key: qk_live_${ERROR_CANARIES.apiKey}`, expect: /^X-Api-Key: \[REDACTED\]$/ },
    { name: "API key quoted", input: `api_key="${ERROR_CANARIES.apiKey}"`, expect: /^api_key="\[REDACTED\]"$/ },
    { name: "client secret", input: `client_secret=${ERROR_CANARIES.apiKey}`, expect: /^client_secret=\[REDACTED\]$/ },
    { name: "client secret JSON", input: `{"client_secret": "${ERROR_CANARIES.apiKey}"}`, expect: /^\{"client_secret": "\[REDACTED\]"\}$/ },
    { name: "password unquoted", input: "password: hunter22seven", expect: /^password: \[REDACTED\]$/ },
    { name: "password quoted", input: "password='hunter22seven'", expect: /^password='\[REDACTED\]'$/ },
    { name: "access, refresh, and id tokens", input: "access_token=abcdef123456 refresh_token=abcdef123456 id_token=abcdef123456", expect: /^access_token=\[REDACTED\] refresh_token=\[REDACTED\] id_token=\[REDACTED\]$/ },
    { name: "HTML page headers", input: canaryHtmlPage(), expect: /<p>Authorization: Bearer \[REDACTED\]<\/p><p>Set-Cookie: \[REDACTED\]<\/p><p>X-Api-Key: \[REDACTED\]<\/p>/ },
    { name: "long token in free text", input: `Upstream rejected token ${ERROR_CANARIES.longToken} for tenant 9f8e7d6c5b4a39281706f5e4d3c2b1a0`, expect: /^Upstream rejected token \[REDACTED\] for tenant \[REDACTED\]$/ },
    { name: "JWT segments", input: "token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhY21lIn0.s3cr3tS1gnatur3Valu3", expect: /^token \[REDACTED\]\.\[REDACTED\]\.\[REDACTED\]$/ },
  ];
  for (const item of cases) {
    const scrubbed = scrubErrorText(item.input);
    assert.match(scrubbed, item.expect, item.name);
    for (const name of ["bearer", "session", "apiKey", "urlToken", "longToken"]) {
      assert.ok(!scrubbed.includes(ERROR_CANARIES[name]), `${item.name}: ${name} canary survived the scrub`);
    }
    assert.doesNotMatch(scrubbed, /hunter22seven|abcdef123456|9f8e7d6c5b4a39281706f5e4d3c2b1a0|YWNtZV9hcGk|eyJhbGci/, item.name);
    assert.equal(scrubErrorText(scrubbed), scrubbed, `${item.name}: idempotent`);
  }

  const secrets = credentialValues(sampleConfig());
  assert.deepEqual(secrets, ["s3cret-value", basic], "the configured password and the derived basic string are exact secrets");
  assert.equal(scrubErrorText(`Bad Login/Password ${ERROR_CANARIES.password} for acme_api`, secrets), "Bad Login/Password [REDACTED] for acme_api", "the configured password is removed wherever it appears");
  assert.equal(scrubErrorText(`header ${basic} echoed`, secrets), "header [REDACTED] echoed");
  assert.equal(scrubErrorText("Bearer pre-issued-token-value-1234", credentialValues(sampleConfig({ password: undefined, username: undefined, token: "pre-issued-token-value-1234" }))), "Bearer [REDACTED]");

  const benign = [
    "Qualys request failed (403) for /api/2.0/fo/asset/host/vm/detection/: code 2010: Forbidden, module not subscribed for this user",
    "Qualys QPS request failed (403) for /qps/rest/2.0/search/am/assetdataconnector: responseCode UNAUTHORIZED: User is not authorized to access this module",
    "Qualys request failed (502) for /api/2.0/fo/asset/host/: non-XML error body (text/html; 236 bytes)",
    "Qualys QPS request failed (500) for /qps/rest/3.0/search/was/wasscanschedule: non-JSON error body (text/csv; 180 bytes)",
    "Qualys request failed (200) for /msp/user_list.php: error 999: Forbidden: this account is not authorized to list users",
    "Qualys request to /api/2.0/fo/schedule/scan/ failed: fetch failed",
    "X-Requested-With: grclanker",
    "token: user",
    "SCHEDULE_SCAN_LIST_OUTPUT, HOST_LIST_VM_DETECTION_OUTPUT, LAST_VM_AUTH_SCANNED_DATE, KNOWLEDGE_BASE_VULN_LIST_OUTPUT",
    "ISCANNER_NAME External Scanner, TAG_SET_INCLUDE, AUTH_UNIX_IDS, ML_VERSION versus ML_LATEST",
    "QID 90001, 105191, 38170 open on host 12345678 tagged 7654321 since 2026-09-21T12:17:03Z",
    "activity log truncation_limit 5000 reached; item cap 5000 reached with hasMoreRecords true; page cap 25 reached with a WARNING/URL continuation not followed",
    "a full page was returned without hasMoreRecords or lastId, so the population may continue beyond it",
    "Using Qualys platform US1 at https://qualysapi.qualys.com with basic authentication.",
    "Using Qualys platform GOV1 at https://qualysapi.qg1.apps.qualysgov.com with bearer authentication.",
    "was not called because detections (/api/2.0/fo/asset/host/vm/detection/) was not readable (module unlicensed or role not permitted)",
    "Authentication record types windows, unix cover the host OS mix and 3/3 scanned hosts (100%) had a recent authenticated scan",
    "authStatus SUCCESSFUL, AUTHENTICATION Windows, Unix, oauth2Record grantType, activationKey title",
  ];
  for (const text of benign) {
    assert.equal(scrubErrorText(text), text, `benign text must survive: ${text}`);
    assert.equal(scrubErrorText(text, secrets), text, `benign text must survive the configured secrets: ${text}`);
  }

  // The heuristic cannot recognise arbitrary words, which is exactly why no response body is ever echoed.
  assert.equal(scrubErrorText(ERROR_CANARIES.bareHtml), ERROR_CANARIES.bareHtml);
  const agentId = "agentId 3f2a9c1d-7b4e-4c8a-9d2e-1f0a8b7c6d5e on tag 7654321";
  assert.equal(scrubErrorText(agentId, [], { longTokens: false }), agentId, "data mode keeps opaque identifiers as evidence");
  assert.equal(scrubErrorText(agentId), "agentId [REDACTED] on tag 7654321", "error mode treats the same run as a token");
});

const ERROR_BODY_SHAPES = {
  "502 text/html": {
    status: 502,
    respond: () => new Response(canaryHtmlPage(), { status: 502, headers: { "content-type": "text/html; charset=utf-8" } }),
    disclosure: /non-(?:XML|JSON) error body \(text\/html; \d+ bytes\)/,
  },
  "SIMPLE_RETURN TEXT with a tokenised URL and the caller's password": {
    status: 401,
    respond: () => xmlResponse(canarySimpleReturn(), { status: 401 }),
    // XML and CSV surfaces parse the envelope and echo CODE plus the scrubbed TEXT; QPS surfaces never echo a non-JSON body.
    disclosure: /code 1903: Login failed for acme_api with password \[REDACTED\]; retry at https:\/\/qualysapi\.qualys\.com\/api\/2\.0\/fo\/report\/\?\[REDACTED\]|non-JSON error body \(application\/xml; \d+ bytes\)/,
  },
  "QPS errorMessage with a 64-character token": {
    status: 400,
    respond: () => jsonResponse(canaryQpsError(), { status: 400 }),
    disclosure: /responseCode INVALID_REQUEST: Upstream rejected token \[REDACTED\] for QualysSession=\[REDACTED\]|non-XML error body \(application\/json; \d+ bytes\)/,
  },
  "CSV path failure": {
    status: 500,
    respond: () => new Response(canaryCsvBody(), { status: 500, headers: { "content-type": "text/csv" } }),
    disclosure: /non-(?:XML|JSON) error body \(text\/csv; \d+ bytes\)/,
  },
};

// The direct client call that reads each surface endpoint, so the thrown error itself can be inspected.
const SURFACE_CLIENT_CALLS = {
  "/api/2.0/fo/schedule/scan/": (client) => client.listScheduledScans(),
  "/api/2.0/fo/scan/": (client) => client.listScans(),
  "/api/2.0/fo/asset/host/": (client) => client.listHosts(100),
  "/api/2.0/fo/subscription/option_profile/vm/": (client) => client.listOptionProfiles(),
  "/api/2.0/fo/asset/excluded_ip/": (client) => client.listExcludedIps(),
  "/api/2.0/fo/asset/group/": (client) => client.listAssetGroups(),
  "/qps/rest/2.0/search/am/assetdataconnector": (client) => client.searchConnectors(),
  "/api/2.0/fo/appliance/": (client) => client.listAppliances(),
  "/qps/rest/2.0/search/am/hostasset": (client) => client.searchCloudAgents(100),
  "/qps/rest/2.0/search/am/tag": (client) => client.searchTags(100),
  "/api/2.0/fo/auth/": (client) => client.listAuthRecordSummary(),
  "/api/2.0/fo/compliance/policy/": (client) => client.listCompliancePolicies(),
  "/api/2.0/fo/asset/host/vm/detection/": (client) => client.listDetections(100),
  "/api/2.0/fo/knowledge_base/vuln/": (client) => client.listKnowledgeBase(["90001"]),
  "/api/2.0/fo/schedule/report/": (client) => client.listScheduledReports(),
  "/api/2.0/fo/report/": (client) => client.listReports(),
  "/qps/rest/2.0/search/am/user/": (client) => client.searchUsers(),
  "/msp/user_list.php": (client) => client.listUsers(),
  "/api/2.0/fo/activity_log/": (client) => client.listActivityLog(7),
  "/qps/rest/3.0/search/was/webapp": (client) => client.searchWebApps(),
  "/qps/rest/3.0/search/was/wasscan": (client) => client.searchWasScans(),
  "/qps/rest/3.0/search/was/webappauthrecord": (client) => client.searchWasAuthRecords(),
  "/qps/rest/3.0/search/was/wasscanschedule": (client) => client.searchWasSchedules(),
};

function failingEndpointRouter(endpoint, shape) {
  return async (url, init) => (new URL(url).pathname === endpoint ? shape.respond() : compliantRouter(url, init));
}

test("error-body walk: every surface the collectors call, failing in four body shapes, leaks no canary and is disclosed with status, endpoint, and content type and length or the parsed code", async () => {
  const outputRoot = createTempBase("qualys-error-body-walk-");
  const endpoints = [...new Set(Object.values(SURFACE_ENDPOINTS))].sort();
  assert.ok(endpoints.length >= 22, `expected every surface endpoint, saw ${endpoints.length}`);
  assert.deepEqual(Object.keys(SURFACE_CLIENT_CALLS).sort(), endpoints, "every SURFACE_ENDPOINTS entry has a direct client call in the walk");

  const baseline = recordingClient(compliantRouter);
  await runAllAssessments(baseline.client);
  await checkQualysAccess(baseline.client);
  for (const endpoint of endpoints) {
    assert.ok(baseline.requested.has(endpoint), `the compliant baseline reads ${endpoint}, so the walk exercises a real call`);
  }

  const walked = [];
  for (const endpoint of endpoints) {
    for (const [shapeName, shape] of Object.entries(ERROR_BODY_SHAPES)) {
      const label = `${endpoint} [${shapeName}]`;
      const client = routedClient(failingEndpointRouter(endpoint, shape));

      const thrown = await SURFACE_CLIENT_CALLS[endpoint](client).then(() => null, (error) => error);
      assert.ok(thrown instanceof QualysApiError, `${label}: the direct client call throws a QualysApiError`);
      assert.equal(thrown.status, shape.status, `${label}: the error carries the HTTP status`);
      assert.equal(thrown.endpoint, endpoint, `${label}: the error carries the endpoint`);
      assertNoCanary(thrown.message, `${label} thrown message`);
      assert.match(thrown.message, new RegExp(`^Qualys (?:QPS )?request failed \\(${shape.status}\\) for ${endpoint.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")}: `), label);
      assert.match(thrown.message, shape.disclosure, `${label}: the failure is described by content type and length or by the parsed code`);
      assert.doesNotMatch(thrown.message, /<html|<p>|Bad Gateway|"Date","Action"/, `${label}: no body text is echoed`);

      const results = await runAllAssessments(client);
      const access = await checkQualysAccess(client);
      assertNoCanary(JSON.stringify(results), `${label} findings, summaries, evidence, sources, and errors arrays`);
      assertNoCanary(JSON.stringify(access), `${label} access check`);
      const errors = results.flatMap((result) => result.errors);
      assert.ok(errors.length > 0, `${label}: an assessment errors array records the failure`);
      assert.ok(errors.some((entry) => entry.includes(endpoint) && entry.includes(`(${shape.status})`) && shape.disclosure.test(entry)), `${label}: the errors array names the endpoint, status, and body description (${errors.join(" | ")})`);
      const reasons = allFindings(results).flatMap((item) => item.evidence.collection.sources.filter((source) => source.status === "unreadable").map((source) => source.reason));
      assert.ok(reasons.length > 0, `${label}: a finding lists the surface as unreadable`);

      const exported = await exportQualysAuditBundle(client, client.getResolvedConfig(), outputRoot);
      assert.ok(exported.errorCount > 0, `${label}: the bundle records the failure`);
      for (const file of walkFiles(exported.outputDir)) {
        assertNoCanary(file.content, `${label} bundle file ${file.name}`);
      }
      for (const member of readZipMembers(exported.zipPath)) {
        assertNoCanary(member.content, `${label} zip member ${member.name}`);
      }
      const errorsLog = readFileSync(join(exported.outputDir, "_errors.log"), "utf8");
      assert.ok(errorsLog.includes(endpoint), `${label}: _errors.log names the endpoint`);
      assert.ok(errorsLog.includes(`(${shape.status})`), `${label}: _errors.log carries the HTTP status`);
      assert.match(errorsLog, shape.disclosure, `${label}: _errors.log carries the content type and length or the parsed code`);
      rmSync(exported.outputDir, { recursive: true, force: true });
      rmSync(exported.zipPath, { force: true });
      walked.push(label);
    }
  }
  assert.equal(walked.length, endpoints.length * Object.keys(ERROR_BODY_SHAPES).length);
});

test("rule 9: the activity log's XML error envelope on the CSV path goes through the same scrubbed constructor as every other site", async () => {
  const client = routedClient(async (url, init) => (url.includes("/activity_log/") ? xmlResponse(canarySimpleReturn(), { status: 401 }) : compliantRouter(url, init)));
  const thrown = await client.listActivityLog(7).then(() => null, (error) => error);
  assert.ok(thrown instanceof QualysApiError);
  assert.equal(thrown.message, "Qualys request failed (401) for /api/2.0/fo/activity_log/: code 1903: Login failed for acme_api with password [REDACTED]; retry at https://qualysapi.qualys.com/api/2.0/fo/report/?[REDACTED]");

  const result = await assessQualysAdministration(client);
  const activity = findingById(result, "QUALYS-C19");
  assert.equal(activity.status, "manual");
  assert.doesNotMatch(activity.summary, /s3cret-value|CANARY/);
  assert.match(activity.summary, /code 1903/);
  const source = activity.evidence.collection.sources.find((item) => item.name === "activity_log");
  assert.equal(source.status, "unreadable");
  assert.match(source.reason, /password \[REDACTED\]/);
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /^activity_log: Qualys request failed \(401\) for \/api\/2\.0\/fo\/activity_log\/: code 1903/);
  assertNoCanary(JSON.stringify(result), "administration assessment, including the caller's password");
});

// ---------------------------------------------------------------------------------------------
// False-pass self-check fixtures (a) forbidden, (b) empty, (c) partial, (d) compliant
// ---------------------------------------------------------------------------------------------

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
  assert.deepEqual(statusCounts(findings), { fail: 7, manual: 13 });
  const failingIds = findings.filter((item) => item.status === "fail").map((item) => item.id).sort();
  assert.deepEqual(failingIds, ["QUALYS-C01", "QUALYS-C03", "QUALYS-C08", "QUALYS-C12", "QUALYS-C14", "QUALYS-C18", "QUALYS-C20"]);
});

test("false-pass self-check (c): a partial inventory with caps, unfollowed continuations, hasMoreRecords, and a Reader role yields zero pass", async () => {
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
    const partialSource = item.evidence.collection.sources.some((source) => source.status === "truncated" || source.status === "unreadable");
    // The User List API has no continuation, so C13 records the Reader view scope instead of a truncated source.
    assert.ok(partialSource || (item.id === "QUALYS-C13" && item.evidence.collection.view_scope.partial), `${item.id} should record a truncated source or a partial view scope`);
  }
});

test("false-pass self-check (d): a fully compliant tenant built strictly from documented shapes passes every automatable control through the real client", async () => {
  const results = await runAllAssessments(routedClient(compliantRouter));
  const findings = allFindings(results);
  assert.equal(findings.length, 20);
  assert.ok(results.every((result) => result.errors.length === 0), results.flatMap((result) => result.errors).join("\n"));
  assert.deepEqual(statusCounts(findings), { pass: 14, warn: 5, manual: 1 });
  assert.deepEqual(findings.filter((item) => item.status === "pass").map((item) => item.id).sort(), COMPLIANT_PASS_IDS);
  assert.deepEqual(findings.filter((item) => item.status === "warn").map((item) => item.id).sort(), CAPPED_BY_DESIGN_IDS);
  assert.deepEqual(findings.filter((item) => item.status === "manual").map((item) => item.id), ["QUALYS-C04"]);
  for (const item of findings) {
    for (const source of item.evidence.collection.sources) {
      if (source.name === "was_scan_history") {
        // Every web app resolved through the bounded scan search, so the unbounded history read was never issued
        // and must not be described as readable.
        assert.equal(source.status, "not_collected", `${item.id}: ${JSON.stringify(source)}`);
        assert.equal(source.count, null);
        assert.match(source.reason, /was not issued because every web application returned by was_webapps \(\/qps\/rest\/3\.0\/search\/was\/webapp\) resolved a finished vulnerability scan inside the 30 day window/);
      } else {
        assert.equal(source.status, "readable", `${item.id}: ${JSON.stringify(source)}`);
        assert.equal(source.count_status, "complete");
        assert.equal(typeof source.count, "number");
        assert.match(source.endpoint, /^\/(api|qps|msp)\//);
      }
    }
    assert.equal(item.evidence.collection.view_scope.partial, false);
    assert.equal(item.evidence.collection.view_scope.source, "user_search");
  }
  for (const item of findings.filter((entry) => entry.status === "pass")) {
    assert.deepEqual(item.evidence.unknown_buckets, {}, `${item.id} passes with no unknown records`);
    assert.equal(item.evidence.verdict_basis, "pass");
  }
  for (const item of findings.filter((entry) => entry.status === "warn")) {
    assert.match(item.summary, /capped at warn/, `${item.id} warns only because the control is capped by design`);
  }

  const [scan, inventory, vuln, admin] = results;
  assert.equal(findingById(scan, "QUALYS-C01").evidence.finished_scans_in_lookback, 1);
  assert.deepEqual(findingById(scan, "QUALYS-C14").evidence.external_schedules, ["Perimeter"]);
  assert.equal(findingById(inventory, "QUALYS-C07").evidence.agent_coverage_percent, 100);
  assert.deepEqual(findingById(vuln, "QUALYS-C08").evidence.auth_record_types, [{ type: "unix", count: 253 }, { type: "windows", count: 2 }]);
  assert.equal(findingById(vuln, "QUALYS-C10").evidence.sla_compliance_percent, 100);
  assert.equal(findingById(admin, "QUALYS-C13").evidence.active_users, 3);
  assert.match(findingById(admin, "QUALYS-C13").evidence.active_users_status, /^readable: USER_STATUS Active users from user_list \(\/msp\/user_list\.php\)$/);
  assert.equal(findingById(admin, "QUALYS-C13").evidence.administration_api_users, 3);
  const was = findingById(admin, "QUALYS-C15");
  assert.equal(was.evidence.recently_scanned_web_apps, 1);
  assert.deepEqual(was.evidence.stale_web_apps, [], "known empty: every web app resolved without the history read");
  assert.equal(was.evidence.scan_history_scans, null);
  assert.match(was.evidence.scan_history_scans_status, /^not_collected: was_scan_history \(\/qps\/rest\/3\.0\/search\/was\/wasscan\) the unbounded WAS scan history search/);
  assert.match(was.summary, /1\/1 web applications have a finished vulnerability scan \(WAS scan search launchedDate\) within 30 days; the unbounded WAS scan history search \(webApp\.id filtered, no launchedDate bound\) was not issued because every web application resolved a finished scan inside the window; /);
  assert.doesNotMatch(was.summary, /fully read scan history|per the unbounded scan history/, "no completeness claim for a read that never happened");
});

// ---------------------------------------------------------------------------------------------
// Rule 1 corollary: a finding that reads more than one inventory demotes when any of them is unreadable,
// names the dataset and endpoint in its summary, and renders counts taken from it as null, never 0.
// ---------------------------------------------------------------------------------------------

function forbiddenHandler(matches) {
  return async (url, init) => (matches(url) ? forbiddenRouter(url) : compliantRouter(url, init));
}

function withForbidden(matches) {
  return routedClient(forbiddenHandler(matches));
}

// Records the pathname of every request the real client issues, so a status that claims a read happened can be
// checked against the reads that actually did.
function recordingClient(handler) {
  const requested = new Set();
  const client = routedClient(async (url, init) => {
    requested.add(new URL(url).pathname);
    return handler(url, init);
  });
  return { client, requested };
}

const UNAVAILABLE_STATUS = /^(unreadable|not_readable|module_unavailable|not_collected|unknown)\b/;
const COLLECTED_STATUS = /^(readable|truncated|complete|partial)\b/;
const ENDPOINT_MENTION = /\/(?:api\/2\.0\/fo\/[a-z_/]+\/|qps\/rest\/[23]\.0\/search\/(?:am|was)\/[a-z]+\/?|msp\/user_list\.php)/g;

function rendersEmpty(value) {
  if (value === 0) return true;
  if (Array.isArray(value)) return value.length === 0;
  return value !== null && typeof value === "object" && Object.keys(value).length === 0;
}

/** A core_data wrapper's records are API values: a null inside one is the API's own field, not a rendering. */
function isSurfaceWrapper(value) {
  return typeof value.endpoint === "string" && typeof value.status === "string" && "records" in value;
}

/**
 * Any status reading unreadable, not_collected, or unknown needs a null companion, a status item carrying one never
 * renders 0, [], or {} beside it, and conversely every null rendered value needs a status sibling (<field>_status or
 * a status on the same item) explaining why it is unknown.
 */
function assertNoFabricatedValues(value, label, path = "", apiRecords = false) {
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoFabricatedValues(item, label, `${path}[${index}]`, apiRecords));
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry === "string" && UNAVAILABLE_STATUS.test(entry)) {
      if (key.endsWith("_status")) {
        const base = key.slice(0, -"_status".length);
        assert.ok(base in value, `${label}: ${path}.${key} has no companion field ${base}`);
        assert.equal(value[base], null, `${label}: ${path}.${base} must be null beside status "${entry}", got ${JSON.stringify(value[base])}`);
      }
      if (key === "status") {
        for (const [sibling, siblingValue] of Object.entries(value)) {
          assert.ok(!rendersEmpty(siblingValue), `${label}: ${path}.${sibling} renders ${JSON.stringify(siblingValue)} beside status "${entry}"`);
        }
      }
    }
    if (entry === null && !apiRecords) {
      const explained = typeof value[`${key}_status`] === "string" || typeof value.status === "string";
      assert.ok(explained, `${label}: ${path}.${key} is null without a ${key}_status or status sibling`);
    }
    assertNoFabricatedValues(entry, label, `${path}.${key}`, apiRecords || (key === "records" && isSurfaceWrapper(value)));
  }
}

/** A status that says a read happened (readable, truncated, complete, partial) may only name endpoints that were actually requested. */
function assertStatusesMatchRequests(value, requested, label, path = "") {
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertStatusesMatchRequests(item, requested, label, `${path}[${index}]`));
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry === "string" && (key === "status" || key.endsWith("_status")) && COLLECTED_STATUS.test(entry)) {
      if (key === "status" && typeof value.endpoint === "string") {
        assert.ok(requested.has(value.endpoint), `${label}: ${path} says "${entry}" but ${value.endpoint} was never requested`);
      }
      for (const mention of entry.match(ENDPOINT_MENTION) ?? []) {
        assert.ok(requested.has(mention), `${label}: ${path}.${key} says "${entry}" but ${mention} was never requested`);
      }
    }
    assertStatusesMatchRequests(entry, requested, label, `${path}.${key}`);
  }
}

function readBundleJson(outputDir, directory) {
  return walkFiles(join(outputDir, directory))
    .filter((file) => file.name.endsWith(".json"))
    .map((file) => ({ name: `${directory}/${file.name}`, value: JSON.parse(file.content) }));
}

// Runs every assessment and a bundle export through one recording client, then applies both generic assertions to
// each finding's evidence (including collection.sources), each assessment summary, and every core_data and
// analysis file in the bundle.
async function assertRenderingStandard(handler, label, outputRoot) {
  const recorder = recordingClient(handler);
  const results = await runAllAssessments(recorder.client);
  const findings = allFindings(results);
  assertNoFabricatedValues(results.map((result) => result.summary), `${label}: summaries`);
  assertNoFabricatedValues(findings.map((item) => item.evidence), `${label}: evidence`);
  assertStatusesMatchRequests(results.map((result) => result.summary), recorder.requested, `${label}: summaries`);
  assertStatusesMatchRequests(findings.map((item) => item.evidence), recorder.requested, `${label}: evidence`);

  const config = recorder.client.getResolvedConfig();
  const bundle = await exportQualysAuditBundle(recorder.client, config, outputRoot);
  const files = [...readBundleJson(bundle.outputDir, "core_data"), ...readBundleJson(bundle.outputDir, "analysis")];
  assert.ok(files.length >= 28, `${label}: expected core_data and analysis files, got ${files.length}`);
  for (const file of files) {
    assertNoFabricatedValues(file.value, `${label}: ${file.name}`);
    assertStatusesMatchRequests(file.value, recorder.requested, `${label}: ${file.name}`);
    if (file.name.startsWith("core_data/") && file.name !== "core_data/access.json") {
      assert.equal(Array.isArray(file.value), false, `${label}: ${file.name} is a status wrapper, never a bare array`);
      assert.match(file.value.endpoint, /^\/(api|qps|msp)\//, `${label}: ${file.name} names its endpoint`);
    }
  }
  return { findings, results, requested: recorder.requested, files };
}

test("rule 1 corollary: C01 demotes and names /api/2.0/fo/scan/ when the scan list is forbidden instead of passing with finished_scans_in_lookback 0", async () => {
  const result = await assessQualysScanCoverage(withForbidden((url) => url.includes("/fo/scan/")));
  const coverage = findingById(result, "QUALYS-C01");
  assert.notEqual(coverage.status, "pass", "pre-fix: pass with finished_scans_in_lookback 0 and scans absent from sources");
  assert.equal(coverage.status, "manual");
  assert.match(coverage.summary, /Required evidence was not readable: scans[^:]*: .*\/api\/2\.0\/fo\/scan\//);
  assert.equal(coverage.evidence.finished_scans_in_lookback, null, "a count from an unreadable inventory renders as null");
  assert.equal(coverage.evidence.active_schedules, 2, "counts from readable inventories keep their values");
  const scans = coverage.evidence.collection.sources.find((source) => source.name === "scans");
  assert.equal(scans.status, "unreadable");
  assert.match(scans.reason, /\/api\/2\.0\/fo\/scan\//);
  assert.equal(result.summary.finished_scans_in_lookback, null);
  assert.equal(result.errors.length, 1);
  for (const item of result.findings.filter((entry) => entry.id !== "QUALYS-C01")) {
    assert.equal(item.evidence.collection.sources.some((source) => source.name === "scans"), false, `${item.id} does not read the scan list`);
  }
});

test("rule 1 corollary: C13 demotes and names /qps/rest/2.0/search/am/user/ when the Administration API search is forbidden even though the User List API answered", async () => {
  const result = await assessQualysAdministration(withForbidden((url) => url.includes("/am/user")));
  const users = findingById(result, "QUALYS-C13");
  assert.notEqual(users.status, "pass", "pre-fix: pass because sources dropped users whenever the User List API was readable");
  assert.equal(users.status, "manual");
  assert.match(users.summary, /Administration API user search \(\/qps\/rest\/2\.0\/search\/am\/user\/\) was not readable/);
  assert.match(users.summary, /Required evidence was not readable: users[^:]*: .*\/qps\/rest\/2\.0\/search\/am\/user\//);
  assert.equal(users.evidence.administration_api_users, null);
  assert.equal(users.evidence.user_list_users, 3);
  assert.equal(users.evidence.active_users, 3, "status, role, and last login still come from the readable User List API");
  assert.deepEqual(users.evidence.collection.sources.map((source) => [source.name, source.status]), [["user_list", "readable"], ["users", "unreadable"]]);
  assert.equal(users.evidence.collection.view_scope.source, "user_list", "the role scope falls back to the User List API without becoming partial");
  assert.equal(users.evidence.collection.view_scope.partial, false);

  const reversed = findingById(await assessQualysAdministration(withForbidden((url) => url.includes("/msp/user_list.php"))), "QUALYS-C13");
  assert.equal(reversed.status, "manual");
  assert.match(reversed.summary, /\/msp\/user_list\.php/);
  assert.equal(reversed.evidence.user_list_users, null);
  assert.equal(reversed.evidence.administration_api_users, 3);
  assert.equal(reversed.evidence.status_source, "not available");
});

test("C13 discloses User List rows returned without USER_LOGIN under the documented Restricted view instead of naming them user", async () => {
  // user_list_output.dtd: USER_LOGIN? and USER_ID? are optional; the guide's Restricted view hides both for users
  // outside the caller's business unit while CONTACT_INFO stays required.
  const hidden = legacyUser({ login: "hidden_manager", id: "1009", role: "Manager", email: "ops-shared@example.com" });
  delete hidden.USER_LOGIN;
  delete hidden.USER_ID;
  const result = await assessQualysAdministration(routedClient(async (url, init) => {
    if (url.includes("/msp/user_list.php")) return xmlResponse(userListXml([...tenant.legacyUsers, hidden]));
    return compliantRouter(url, init);
  }));
  const users = findingById(result, "QUALYS-C13");
  assert.equal(users.status, "warn");
  assert.match(users.summary, /1 users were returned without a USER_LOGIN \(the Restricted view hides logins outside the caller's business unit\), so generic_accounts and shared_emails under-report for them/);
  assert.equal(users.evidence.restricted_view_users_without_login, 1);
  assert.deepEqual(users.evidence.unknown_buckets, { users_without_login_in_restricted_view: 1 });
  assert.ok(users.evidence.managers.includes("ops-shared@example.com"), "the documented CONTACT_INFO/EMAIL labels the row before any placeholder");
  assert.equal(users.evidence.managers.includes("user"), false);
});

// Each surface a finding reads, the endpoint that serves it, and every finding that lists it in sources.
const SWEEP_SURFACES = [
  { surface: "scheduled_scans", endpoint: "/api/2.0/fo/schedule/scan/", matches: (url) => url.includes("/schedule/scan/"), dependents: ["QUALYS-C01", "QUALYS-C14", "QUALYS-C20"] },
  { surface: "scans", endpoint: "/api/2.0/fo/scan/", matches: (url) => url.includes("/fo/scan/"), dependents: ["QUALYS-C01"] },
  { surface: "hosts", endpoint: "/api/2.0/fo/asset/host/", matches: (url) => url.includes("/asset/host/?"), dependents: ["QUALYS-C01", "QUALYS-C02", "QUALYS-C04", "QUALYS-C07", "QUALYS-C08", "QUALYS-C10", "QUALYS-C11", "QUALYS-C18"] },
  { surface: "option_profiles", endpoint: "/api/2.0/fo/subscription/option_profile/vm/", matches: (url) => url.includes("/option_profile/vm/"), dependents: ["QUALYS-C03", "QUALYS-C16"] },
  { surface: "excluded_ips", endpoint: "/api/2.0/fo/asset/excluded_ip/", matches: (url) => url.includes("/excluded_ip/"), dependents: ["QUALYS-C16"] },
  { surface: "asset_groups", endpoint: "/api/2.0/fo/asset/group/", matches: (url) => url.includes("/asset/group/"), dependents: ["QUALYS-C01", "QUALYS-C04"] },
  { surface: "connectors", endpoint: "/qps/rest/2.0/search/am/assetdataconnector", matches: (url) => url.includes("/am/assetdataconnector"), dependents: ["QUALYS-C05"] },
  { surface: "appliances", endpoint: "/api/2.0/fo/appliance/", matches: (url) => url.includes("/appliance/"), dependents: ["QUALYS-C06"] },
  { surface: "cloud_agents", endpoint: "/qps/rest/2.0/search/am/hostasset", matches: (url) => url.includes("/am/hostasset"), dependents: ["QUALYS-C07"] },
  { surface: "tags", endpoint: "/qps/rest/2.0/search/am/tag", matches: (url) => url.includes("/am/tag"), dependents: ["QUALYS-C18"] },
  { surface: "auth_records", endpoint: "/api/2.0/fo/auth/", matches: (url) => url.includes("/fo/auth/"), dependents: ["QUALYS-C08"] },
  { surface: "compliance_policies", endpoint: "/api/2.0/fo/compliance/policy/", matches: (url) => url.includes("/compliance/policy/"), dependents: ["QUALYS-C09"] },
  { surface: "detections", endpoint: "/api/2.0/fo/asset/host/vm/detection/", matches: (url) => url.includes("/vm/detection/"), dependents: ["QUALYS-C10", "QUALYS-C11", "QUALYS-C17"] },
  { surface: "knowledge_base", endpoint: "/api/2.0/fo/knowledge_base/vuln/", matches: (url) => url.includes("/knowledge_base/"), dependents: ["QUALYS-C11"] },
  { surface: "scheduled_reports", endpoint: "/api/2.0/fo/schedule/report/", matches: (url) => url.includes("/schedule/report/"), dependents: ["QUALYS-C12"] },
  { surface: "reports", endpoint: "/api/2.0/fo/report/", matches: (url) => url.includes("/fo/report/"), dependents: ["QUALYS-C12"] },
  { surface: "users", endpoint: "/qps/rest/2.0/search/am/user/", matches: (url) => url.includes("/am/user"), dependents: ["QUALYS-C13"] },
  { surface: "user_list", endpoint: "/msp/user_list.php", matches: (url) => url.includes("/msp/user_list.php"), dependents: ["QUALYS-C13"] },
  { surface: "activity_log", endpoint: "/api/2.0/fo/activity_log/", matches: (url) => url.includes("/activity_log/"), dependents: ["QUALYS-C19"] },
  { surface: "was_webapps", endpoint: "/qps/rest/3.0/search/was/webapp", matches: (url) => /\/was\/webapp(\?|$)/.test(url), dependents: ["QUALYS-C15"] },
  { surface: "was_scans", endpoint: "/qps/rest/3.0/search/was/wasscan", matches: (url) => /\/was\/wasscan(\?|$)/.test(url), dependents: ["QUALYS-C15"] },
  { surface: "was_auth_records", endpoint: "/qps/rest/3.0/search/was/webappauthrecord", matches: (url) => url.includes("/was/webappauthrecord"), dependents: ["QUALYS-C15"] },
  { surface: "was_schedules", endpoint: "/qps/rest/3.0/search/was/wasscanschedule", matches: (url) => url.includes("/was/wasscanschedule"), dependents: ["QUALYS-C15"] },
];

test("rule 1 corollary sweep: each surface made unreadable in turn demotes exactly its dependents below pass and names the endpoint", async () => {
  const outputRoot = createTempBase("qualys-sweep-");
  const compliant = await assertRenderingStandard(compliantRouter, "baseline", outputRoot);
  const baseline = new Map(compliant.findings.map((item) => [item.id, item.status]));
  assert.equal(baseline.size, 20);
  assert.ok(compliant.requested.has("/api/2.0/fo/knowledge_base/vuln/"), "the compliant tenant has open QIDs, so the knowledge base is read");
  const table = [];
  for (const { surface, endpoint, matches, dependents } of SWEEP_SURFACES) {
    const { findings, requested } = await assertRenderingStandard(forbiddenHandler(matches), surface, outputRoot);
    assert.equal(findings.length, 20, surface);
    assert.ok(requested.has(endpoint), `${surface}: the denied endpoint ${endpoint} was requested`);
    const demoted = findings.filter((item) => item.evidence.collection.sources.some((source) => source.status === "unreadable")).map((item) => item.id).sort();
    assert.deepEqual(demoted, [...dependents].sort(), `${surface}: exactly the dependents record the unreadable source`);
    for (const item of findings) {
      if (dependents.includes(item.id)) {
        assert.notEqual(item.status, "pass", `${surface}: ${item.id} must not pass while ${endpoint} is unreadable`);
        assert.ok(item.summary.includes(endpoint), `${surface}: ${item.id} summary must name ${endpoint}: ${item.summary}`);
        assert.ok(item.summary.includes("not readable"), `${surface}: ${item.id} summary must disclose the unreadable dataset`);
        const unreadable = item.evidence.collection.sources.filter((source) => source.status === "unreadable");
        assert.ok(unreadable.some((source) => source.reason.includes(endpoint)), `${surface}: ${item.id} collection.sources must carry the endpoint`);
        for (const source of unreadable) {
          assert.equal(source.count, null, `${surface}: ${item.id} sources.${source.name}.count must be null, never 0`);
          assert.equal(source.endpoint, SWEEP_SURFACES.find((entry) => entry.surface === source.name)?.endpoint ?? endpoint);
          assert.equal("count_status" in source, false, "an unreadable source carries no completeness marker");
        }
        // Every plain count of the unreadable surface renders as null, never as 0 (list-valued evidence such as
        // C03 option_profiles names is not a count).
        // C13 users_returned is the population from whichever user surface answered, so the two user surfaces
        // are judged on their own count keys.
        const countKeys = surface === "users"
          ? ["administration_api_users"]
          : surface === "user_list"
            ? ["user_list_users", "inactive_status_users", "pending_activation_users", "users_with_last_login"]
            : [surface, `${surface}_returned`, ...(surface === "scans" ? ["finished_scans_in_lookback"] : [])];
        for (const key of countKeys) {
          if (!(key in item.evidence) || Array.isArray(item.evidence[key])) continue;
          assert.equal(item.evidence[key], null, `${surface}: ${item.id} evidence.${key} must be null, got ${JSON.stringify(item.evidence[key])}`);
        }
      } else {
        assert.equal(item.status, baseline.get(item.id), `${surface}: ${item.id} does not read ${endpoint} and must keep its compliant verdict`);
        assert.equal(item.evidence.collection.view_scope.partial, false, `${surface}: ${item.id} view scope stays full`);
      }
    }
    const statuses = findings.filter((item) => dependents.includes(item.id)).map((item) => `${item.id}=${item.status}`).join(", ");
    table.push(`| ${surface} | ${endpoint} | ${statuses} |`);
  }
  assert.equal(table.length, SWEEP_SURFACES.length);
  if (process.env.QUALYS_SWEEP_TABLE) {
    console.log(["| surface | endpoint | dependents after 403 |", "| --- | --- | --- |", ...table].join("\n"));
  }
});

// ---------------------------------------------------------------------------------------------
// Uniform null standard: unreadable or never-collected data renders null beside a status that names the denied
// read, never 0, [], or {}, even where no verdict depends on it; a readable or complete status only ever
// describes a call that happened.
// ---------------------------------------------------------------------------------------------

const DETECTIONS_UNREADABLE = /^unreadable: detections \(\/api\/2\.0\/fo\/asset\/host\/vm\/detection\/\) was not readable \(/;
const OPTION_PROFILES_UNREADABLE = /^unreadable: option_profiles \(\/api\/2\.0\/fo\/subscription\/option_profile\/vm\/\) was not readable \(/;
const USER_LIST_UNREADABLE = /^unreadable: user_list \(\/msp\/user_list\.php\) was not readable \(/;
const KNOWLEDGE_BASE_NOT_CALLED = /^was not called because detections \(\/api\/2\.0\/fo\/asset\/host\/vm\/detection\/\) was not readable \(/;
const WAS_HISTORY_SEARCH_TEXT = "the unbounded WAS scan history search (webApp.id filtered, no launchedDate bound)";

// Keys whose value is legitimately a list of names even under a full denial: they describe the collection run
// itself (which sources were truncated), not an inventory.
const COLLECTION_METADATA_KEYS = new Set(["collection", "truncated_sources"]);

function sourcesOf(findings) {
  return findings.flatMap((item) => item.evidence.collection.sources);
}

test("uniform null standard 1: describeSource renders count null without a completeness marker for a denied read, partial when truncated, and complete when fully read", async () => {
  const denied = findingById(await assessQualysScanCoverage(withForbidden((url) => url.includes("/option_profile/vm/"))), "QUALYS-C03");
  const profiles = denied.evidence.collection.sources.find((source) => source.name === "option_profiles");
  assert.deepEqual(profiles, {
    name: "option_profiles",
    endpoint: "/api/2.0/fo/subscription/option_profile/vm/",
    status: "unreadable",
    count: null,
    reason: profiles.reason,
  }, "pre-fix: {status: unreadable, count: 0}");
  assert.match(profiles.reason, /403/);

  const forbidden = sourcesOf(allFindings(await runAllAssessments(routedClient(forbiddenRouter))));
  assert.ok(forbidden.length >= 30, `every finding lists its sources, saw ${forbidden.length}`);
  for (const source of forbidden) {
    assert.ok(source.status === "unreadable" || source.status === "not_collected", JSON.stringify(source));
    assert.equal(source.count, null, `${source.name}.count must be null, never 0`);
    assert.equal("count_status" in source, false, `${source.name} carries no completeness marker`);
    assert.match(source.reason, /403|forbidden|not readable/i, `${source.name} names the cause`);
    assert.match(source.endpoint, /^\/(api|qps|msp)\//);
  }

  const truncatedSources = sourcesOf(allFindings(await runAllAssessments(routedClient(partialRouter)))).filter((source) => source.status === "truncated");
  assert.ok(truncatedSources.length >= 20, `the partial tenant truncates most reads, saw ${truncatedSources.length}`);
  for (const source of truncatedSources) {
    assert.equal(source.count_status, "partial", source.name);
    assert.equal(typeof source.count, "number", source.name);
    assert.ok(source.count > 0, `${source.name} reports the records it did see`);
    assert.equal(typeof source.reason, "string", `${source.name} names why the read is partial`);
  }

  const compliantSources = sourcesOf(allFindings(await runAllAssessments(routedClient(compliantRouter))));
  const readableSources = compliantSources.filter((source) => source.status === "readable");
  assert.equal(compliantSources.length - readableSources.length, 1, "only the never-needed WAS history search is not readable on the compliant tenant");
  for (const source of readableSources) {
    assert.equal(source.count_status, "complete", source.name);
    assert.equal(typeof source.count, "number", source.name);
    assert.equal(source.reason, undefined, `${source.name} carries no reason when fully read`);
  }
});

test("uniform null standard 2: a call that never happened renders not_collected with count null naming the denied upstream read and the skipped call, never readable 0", async () => {
  const recorder = recordingClient(forbiddenHandler((url) => url.includes("/vm/detection/")));
  const vuln = await assessQualysVulnerabilityManagement(recorder.client);
  assert.ok(recorder.requested.has("/api/2.0/fo/asset/host/vm/detection/"));
  assert.equal(recorder.requested.has("/api/2.0/fo/knowledge_base/vuln/"), false, "the knowledge base is looked up for open QIDs only, so it was never called");
  const patch = findingById(vuln, "QUALYS-C11");
  const knowledgeBase = patch.evidence.collection.sources.find((source) => source.name === "knowledge_base");
  assert.equal(knowledgeBase.status, "not_collected", "pre-fix: readable with count 0 for a call that never happened");
  assert.equal(knowledgeBase.count, null);
  assert.equal(knowledgeBase.endpoint, "/api/2.0/fo/knowledge_base/vuln/");
  assert.match(knowledgeBase.reason, KNOWLEDGE_BASE_NOT_CALLED);
  assert.equal("count_status" in knowledgeBase, false);
  assert.equal(patch.status, "manual");
  assert.match(patch.summary, /Not collected: knowledge_base \(\/api\/2\.0\/fo\/knowledge_base\/vuln\/\) was not called because detections \(\/api\/2\.0\/fo\/asset\/host\/vm\/detection\/\) was not readable/);
  assert.equal(patch.evidence.knowledge_base_qids, null);
  assert.match(patch.evidence.knowledge_base_qids_status, /^not_collected: knowledge_base \(\/api\/2\.0\/fo\/knowledge_base\/vuln\/\) was not called because detections/);
  assert.equal(patch.evidence.patchable_qids, null);
  for (const key of ["unresolved_qids", "patchable_detections", "overdue_patchable_detections", "overdue_percent"]) {
    assert.equal(patch.evidence[key], null, key);
    assert.match(patch.evidence[`${key}_status`], /^unreadable: detections .*; not_collected: knowledge_base/, `${key} names both the denied read and the skipped call`);
  }
  assert.equal(patch.evidence.unknown_buckets, null, "bucket counts of records that were never read are unknown, not {}");
  assert.match(patch.evidence.unknown_buckets_status, DETECTIONS_UNREADABLE);

  // The compliant tenant has open QIDs, so the knowledge base is read and described as such.
  const compliant = recordingClient(compliantRouter);
  const read = findingById(await assessQualysVulnerabilityManagement(compliant.client), "QUALYS-C11").evidence.collection.sources.find((source) => source.name === "knowledge_base");
  assert.ok(compliant.requested.has("/api/2.0/fo/knowledge_base/vuln/"));
  assert.equal(read.status, "readable");
  assert.equal(read.count_status, "complete");

  // The unbounded WAS scan history search is never issued once the bounded scan search is denied.
  const criteria = [];
  const admin = await assessQualysAdministration(routedClient(async (url, init) => {
    if (/\/was\/wasscan(\?|$)/.test(url)) {
      criteria.push(JSON.parse(init.body).ServiceRequest.filters.Criteria.map((item) => item.field));
      return forbiddenRouter(url);
    }
    return compliantRouter(url, init);
  }));
  assert.deepEqual(criteria, [["launchedDate", "type"]], "only the bounded scan search was issued");
  const was = findingById(admin, "QUALYS-C15");
  const history = was.evidence.collection.sources.find((source) => source.name === "was_scan_history");
  assert.equal(history.status, "not_collected", "pre-fix: readable with count 0");
  assert.equal(history.count, null);
  assert.equal(history.endpoint, "/qps/rest/3.0/search/was/wasscan");
  assert.equal(history.reason.startsWith(`${WAS_HISTORY_SEARCH_TEXT} was not issued because was_scans (/qps/rest/3.0/search/was/wasscan) was not readable (`), true, history.reason);
  assert.equal(was.evidence.scan_history_scans, null);
  assert.match(was.evidence.scan_history_scans_status, /^not_collected: was_scan_history \(\/qps\/rest\/3\.0\/search\/was\/wasscan\) the unbounded WAS scan history search/);
  assert.match(was.summary, /Not collected: was_scan_history \(\/qps\/rest\/3\.0\/search\/was\/wasscan\) the unbounded WAS scan history search .* was not issued because was_scans/);
  assert.equal(was.status, "manual");
});

test("uniform null standard 3: derived lists and maps render null beside a status naming the denied read, never [] or {}", async () => {
  const scan = await assessQualysScanCoverage(withForbidden((url) => url.includes("/option_profile/vm/")));
  const profiles = findingById(scan, "QUALYS-C03");
  for (const key of ["option_profiles", "profiles_without_authentication", "authentication_types"]) {
    assert.equal(profiles.evidence[key], null, `pre-fix: C03 ${key} rendered ${key === "authentication_types" ? "{}" : "[]"}`);
    assert.match(profiles.evidence[`${key}_status`], OPTION_PROFILES_UNREADABLE);
  }
  const exclusions = findingById(scan, "QUALYS-C16");
  assert.equal(exclusions.evidence.option_profile_exclusion_lists, null);
  assert.match(exclusions.evidence.option_profile_exclusion_lists_status, OPTION_PROFILES_UNREADABLE);
  assert.equal(exclusions.evidence.option_profile_detection_exclusions, null);
  assert.deepEqual(exclusions.evidence.excluded_entries, [], "a list from the readable, empty excluded host inventory stays a known empty list");
  assert.equal("excluded_entries_status" in exclusions.evidence, false);

  const admin = await assessQualysAdministration(withForbidden((url) => url.includes("/msp/user_list.php")));
  const users = findingById(admin, "QUALYS-C13");
  assert.equal(users.evidence.stale_login_users, null, "pre-fix: [] although LAST_LOGIN_DATE exists only on the User List response");
  assert.match(users.evidence.stale_login_users_status, USER_LIST_UNREADABLE);
  for (const key of ["inactive_status_users", "pending_activation_users", "users_with_last_login", "restricted_view_users_without_login"]) {
    assert.equal(users.evidence[key], null, key);
    assert.match(users.evidence[`${key}_status`], USER_LIST_UNREADABLE);
  }

  // With every endpoint denied, no evidence or summary field of any tool renders 0, [], or {}, every null carries
  // a status naming the read, and the unverified API user scope renders null roles rather than [].
  const results = await runAllAssessments(routedClient(forbiddenRouter));
  const findings = allFindings(results);
  let withheld = 0;
  const records = [...results.map((result) => ({ label: result.category, record: result.summary })), ...findings.map((item) => ({ label: item.id, record: item.evidence }))];
  for (const { label, record } of records) {
    for (const [key, value] of Object.entries(record)) {
      if (COLLECTION_METADATA_KEYS.has(key)) continue;
      assert.equal(rendersEmpty(value), false, `${label}.${key} renders ${JSON.stringify(value)} under a full denial`);
      if (value === null) {
        withheld += 1;
        assert.match(record[`${key}_status`] ?? "", UNAVAILABLE_STATUS, `${label}.${key} is null without a status naming the read`);
      }
    }
  }
  assert.ok(withheld >= 120, `every derived list, map, count, and percentage is withheld with a status, saw ${withheld}`);
  for (const item of findings) {
    const scope = item.evidence.collection.view_scope;
    assert.equal(scope.verified, false);
    assert.equal(scope.roles, null, `${item.id}: unverified roles are unknown, not []`);
    assert.equal(scope.scope_tags, null);
    assert.match(scope.status, /^unknown: API user role not verified: user search failed/);
    assert.equal(item.evidence.unknown_buckets, null, item.id);
  }
});

test("uniform null standard 4: percentages and derived counts render null when an input is unreadable or the denominator is unknown, never 0 beside null siblings", async () => {
  const vuln = await assessQualysVulnerabilityManagement(withForbidden((url) => url.includes("/vm/detection/")));
  const sla = findingById(vuln, "QUALYS-C10");
  assert.equal(sla.evidence.open_detections, null);
  assert.equal(sla.evidence.sla_compliance_percent, null, "pre-fix: 0 beside open_detections null");
  assert.match(sla.evidence.sla_compliance_percent_status, DETECTIONS_UNREADABLE);
  assert.equal(sla.evidence.breaches_by_severity, null, "pre-fix: {critical: 0, high: 0, medium: 0}");
  assert.match(sla.evidence.breaches_by_severity_status, DETECTIONS_UNREADABLE);
  for (const key of ["detections_returned", "closed_detections_excluded", "fixed_or_info_excluded", "sla_scoped_detections", "sla_dated_detections", "sla_breaches"]) {
    assert.equal(sla.evidence[key], null, key);
    assert.match(sla.evidence[`${key}_status`], DETECTIONS_UNREADABLE);
  }
  assert.equal(sla.evidence.hosts, tenant.hosts.length, "counts of the readable host inventory keep their values");
  assert.deepEqual(sla.evidence.sla_days, { critical: 15, high: 30, medium: 90 }, "configured thresholds are not derived from any read");
  const patch = findingById(vuln, "QUALYS-C11");
  assert.equal(patch.evidence.overdue_percent, null);
  assert.equal(patch.evidence.open_qids, null);
  const qds = findingById(vuln, "QUALYS-C17");
  assert.equal(qds.evidence.qds_percent, null);
  assert.equal(qds.evidence.detections_with_qds, null);
  assert.match(qds.evidence.qds_percent_status, DETECTIONS_UNREADABLE);
  for (const key of ["open_detections", "sla_compliance_percent", "sla_breaches", "patchable_detections", "overdue_patchable_detections", "qds_percent"]) {
    assert.equal(vuln.summary[key], null, `summary.${key}`);
    assert.match(vuln.summary[`${key}_status`], /^unreadable: detections/, `summary.${key}`);
  }

  const agents = findingById(await assessQualysAssetInventory(withForbidden((url) => url.includes("/am/hostasset"))), "QUALYS-C07");
  assert.equal(agents.evidence.agent_coverage_percent, 100, "the coverage ratio reads host TRACKING_METHOD only, so it survives a denied agent search");
  assert.equal(agents.evidence.hosts, tenant.hosts.length);
  for (const key of ["cloud_agents", "inactive_agents", "stale_agents", "agents_without_activation_key"]) {
    assert.equal(agents.evidence[key], null, key);
    assert.match(agents.evidence[`${key}_status`], /^unreadable: cloud_agents \(\/qps\/rest\/2\.0\/search\/am\/hostasset\) was not readable \(/);
  }
  assert.equal(agents.status, "manual");
  const noHosts = findingById(await assessQualysAssetInventory(withForbidden((url) => url.includes("/asset/host/?"))), "QUALYS-C07");
  assert.equal(noHosts.evidence.agent_coverage_percent, null, "the ratio's numerator and denominator both come from the denied host inventory");
  assert.match(noHosts.evidence.agent_coverage_percent_status, /^unreadable: hosts \(\/api\/2\.0\/fo\/asset\/host\/\) was not readable \(/);
  assert.equal(noHosts.evidence.agent_tracked_hosts, null);
  assert.equal(noHosts.evidence.cloud_agents, tenant.agents.length, "the readable agent search keeps its count");

  // A ratio over a readable inventory with a zero denominator is undefined, not 0%.
  const emptyHosts = await assessQualysScanCoverage(routedClient(async (url, init) => (url.includes("/asset/host/?") ? emptyRouter(url) : compliantRouter(url, init))));
  const auth = findingById(emptyHosts, "QUALYS-C02");
  assert.equal(auth.evidence.hosts, 0, "the host inventory was read completely and is empty");
  assert.equal(auth.evidence.authenticated_percent, null, "pre-fix: percent() returned 0 for a zero denominator");
  assert.equal(auth.evidence.authenticated_percent_status, "unknown: ratio undefined because scanned_hosts is 0");
  assert.equal(auth.status, "manual");
  const emptyDetections = await assessQualysVulnerabilityManagement(routedClient(async (url, init) => (url.includes("/vm/detection/") ? emptyRouter(url) : compliantRouter(url, init))));
  const noDetections = findingById(emptyDetections, "QUALYS-C10");
  assert.equal(noDetections.status, "pass", "zero detections pass only with a complete read and a non-zero host population");
  assert.equal(noDetections.evidence.sla_compliance_percent, null);
  assert.equal(noDetections.evidence.sla_compliance_percent_status, "unknown: ratio undefined because sla_dated_detections is 0");
  assert.deepEqual(noDetections.evidence.breaches_by_severity, { critical: 0, high: 0, medium: 0 }, "known zeros from a complete, empty detection list");
  assert.equal(noDetections.evidence.open_detections, 0);
});

test("uniform null standard 5: C15 prose claims an unbounded or fully read scan history only when that read happened and finished", async () => {
  // The bounded scan search returns nothing inside the window, so the history search is issued for the web app;
  // the history variant decides what that second call on the same endpoint returns.
  const historyRouter = (history) => async (url, init) => {
    if (/\/was\/wasscan(\?|$)/.test(url)) {
      const isHistory = JSON.parse(init.body).ServiceRequest.filters.Criteria.some((item) => item.field === "webApp.id");
      return isHistory ? history(url, init) : jsonResponse(qpsResponse("WasScan", []));
    }
    return compliantRouter(url, init);
  };
  const oldScan = documentedWasScan({ id: 77, name: "Portal quarterly", launchedDate: daysAgo(60) });
  const completenessClaim = /per the unbounded scan history|in the fully read scan history/;

  const denied = findingById(await assessQualysAdministration(routedClient(historyRouter(forbiddenRouter))), "QUALYS-C15");
  assert.equal(denied.status, "manual");
  assert.match(denied.summary, /0\/1 web applications have a finished vulnerability scan \(WAS scan search launchedDate\) within 30 days; 1 could not be resolved because the unbounded WAS scan history search \(webApp\.id filtered, no launchedDate bound\) on \/qps\/rest\/3\.0\/search\/was\/wasscan was not readable, so the stale and never-scanned counts are unknown/);
  assert.doesNotMatch(denied.summary, completenessClaim, "pre-fix: the completeness claim and the unreadable clause in one sentence");
  assert.deepEqual(denied.evidence.unresolved_web_apps, ["Portal"]);
  assert.equal(denied.evidence.stale_web_apps, null);
  assert.equal(denied.evidence.never_scanned_web_apps, null);
  assert.match(denied.evidence.stale_web_apps_status, /^unreadable: was_scan_history \(\/qps\/rest\/3\.0\/search\/was\/wasscan\) was not readable \(/);
  assert.equal(denied.evidence.collection.sources.find((source) => source.name === "was_scan_history").status, "unreadable");

  const truncated = findingById(await assessQualysAdministration(routedClient(historyRouter(async () => jsonResponse(qpsResponse("WasScan", [oldScan], { hasMoreRecords: "true" }))))), "QUALYS-C15");
  assert.notEqual(truncated.status, "pass");
  assert.match(truncated.summary, /1 could not be resolved because the unbounded WAS scan history search \(webApp\.id filtered, no launchedDate bound\) was truncated \(hasMoreRecords was true but no lastId was returned to continue paging\), so the stale and never-scanned counts are unknown/);
  assert.doesNotMatch(truncated.summary, completenessClaim);
  assert.equal(truncated.evidence.stale_web_apps, null, "a web app whose only known scan came from a partial history is unresolved, not stale");
  assert.match(truncated.evidence.stale_web_apps_status, /^unknown: was_scan_history \(\/qps\/rest\/3\.0\/search\/was\/wasscan\) was read partially \(hasMoreRecords was true but no lastId/);
  assert.equal(truncated.evidence.collection.sources.find((source) => source.name === "was_scan_history").count_status, "partial");

  const complete = findingById(await assessQualysAdministration(routedClient(historyRouter(async () => jsonResponse(qpsResponse("WasScan", [oldScan]))))), "QUALYS-C15");
  assert.equal(complete.status, "fail");
  assert.match(complete.summary, /0\/1 web applications have a finished vulnerability scan \(WAS scan search launchedDate\) within 30 days, 1 were last scanned before the window per the unbounded scan history, and 0 have no finished vulnerability scan in the fully read scan history;/);
  assert.deepEqual(complete.evidence.stale_web_apps, ["Portal"]);
  assert.deepEqual(complete.evidence.never_scanned_web_apps, []);
  assert.equal(complete.evidence.scan_history_scans, 1);
  assert.equal(complete.evidence.collection.sources.find((source) => source.name === "was_scan_history").count_status, "complete");

  const notIssued = findingById(await assessQualysAdministration(routedClient(compliantRouter)), "QUALYS-C15");
  assert.equal(notIssued.status, "pass");
  assert.match(notIssued.summary, /within 30 days; the unbounded WAS scan history search \(webApp\.id filtered, no launchedDate bound\) was not issued because every web application resolved a finished scan inside the window; /);
  assert.doesNotMatch(notIssued.summary, completenessClaim);
});

test("uniform null standard 6: core_data writes a status marker with null records for a denied or never-collected inventory, never []", async () => {
  const recorder = recordingClient(forbiddenHandler((url) => url.includes("/vm/detection/") || url.includes("/option_profile/vm/")));
  const bundle = await exportQualysAuditBundle(recorder.client, recorder.client.getResolvedConfig(), createTempBase("qualys-marker-"));
  const readCore = (name) => JSON.parse(readFileSync(join(bundle.outputDir, "core_data", name), "utf8"));

  const detections = readCore("vulnerability_management/detections.json");
  assert.equal(Array.isArray(detections), false, "pre-fix: []");
  assert.deepEqual(detections, {
    name: "detections",
    endpoint: "/api/2.0/fo/asset/host/vm/detection/",
    status: "unreadable",
    count: null,
    reason: detections.reason,
    records: null,
  });
  assert.match(detections.reason, /403/);
  const knowledgeBase = readCore("vulnerability_management/knowledge_base.json");
  assert.equal(knowledgeBase.status, "not_collected", "pre-fix: [] for a call that never happened");
  assert.equal(knowledgeBase.count, null);
  assert.equal(knowledgeBase.records, null);
  assert.match(knowledgeBase.reason, KNOWLEDGE_BASE_NOT_CALLED);
  assert.equal(recorder.requested.has("/api/2.0/fo/knowledge_base/vuln/"), false);
  const profiles = readCore("scan_coverage/option_profiles.json");
  assert.equal(profiles.status, "unreadable");
  assert.equal(profiles.records, null);
  assert.equal(profiles.endpoint, "/api/2.0/fo/subscription/option_profile/vm/");
  const access = readCore("access.json");
  assert.equal(access.surfaces.find((surface) => surface.name === "detections").status, "module_unavailable");
  assert.equal(access.surfaces.find((surface) => surface.name === "option_profiles").status, "module_unavailable");

  const files = readBundleJson(bundle.outputDir, "core_data").filter((file) => file.name !== "core_data/access.json");
  assert.ok(files.length >= 27, `one file per collected surface, saw ${files.length}`);
  const statuses = {};
  for (const { name, value } of files) {
    assert.equal(Array.isArray(value), false, `${name} is never a bare array`);
    assert.match(value.endpoint, /^\/(api|qps|msp)\//, `${name} names its endpoint`);
    statuses[value.status] = (statuses[value.status] ?? 0) + 1;
    if (value.status === "readable" || value.status === "truncated") {
      assert.ok(Array.isArray(value.records), `${name} carries its projected records`);
      assert.equal(value.records.length, value.count, `${name} count matches its records`);
    } else {
      assert.equal(value.records, null, `${name} records are null, not []`);
      assert.equal(value.count, null, `${name} count is null, not 0`);
      assert.equal(typeof value.reason, "string", `${name} names the cause`);
    }
  }
  assert.equal(statuses.unreadable, 2, "detections and option_profiles");
  assert.ok(statuses.not_collected >= 2, "knowledge_base (blocked) and was_scan_history (nothing needed it)");

  const members = readZipMembers(bundle.zipPath);
  const zipped = JSON.parse(members.find((member) => member.name.endsWith("core_data/vulnerability_management/detections.json")).content);
  assert.deepEqual(zipped, detections, "the archive carries the same marker as the directory");
  const readableMember = JSON.parse(members.find((member) => member.name.endsWith("core_data/scan_coverage/scheduled_scans.json")).content);
  assert.equal(readableMember.status, "readable");
  assert.equal(readableMember.records.length, tenant.schedules.length);
});

test("C13 discloses which surface its user population came from: the User List API when readable, the Administration API fallback when /msp/user_list.php is denied, and neither when both are denied", async () => {
  const fallback = findingById(await assessQualysAdministration(withForbidden((url) => url.includes("/msp/user_list.php"))), "QUALYS-C13");
  assert.equal(fallback.evidence.active_users, tenant.adminUsers.length, "pre-fix: the Administration API population rendered with no indication of its source");
  assert.match(fallback.evidence.active_users_status, /^partial: user_list \(\/msp\/user_list\.php\) was not readable \(.*\), so the population is the Administration API user search \(\/qps\/rest\/2\.0\/search\/am\/user\/\), which returns Active users only and hides other Manager and Super User accounts$/);
  for (const key of ["users_returned", "managers"]) {
    assert.equal(fallback.evidence[`${key}_status`], fallback.evidence.active_users_status, `${key} discloses the same population source`);
  }
  for (const key of ["shared_emails", "generic_accounts"]) {
    assert.equal(fallback.evidence[key], null, `${key}: an empty match list over the partial population is withheld, never []`);
    assert.equal(fallback.evidence[`${key}_status`], `${fallback.evidence.active_users_status}, so matches are a lower bound and an empty match list cannot show there are none`);
  }
  assert.equal(fallback.status, "manual");
  assert.match(fallback.summary, /the Administration API search returns Active users only, hides other Manager and Super User accounts, and documents no status or last-login field, so inactive-user detection is manual and the manager count is a lower bound/);

  const both = findingById(await assessQualysAdministration(withForbidden((url) => url.includes("/msp/user_list.php") || url.includes("/am/user"))), "QUALYS-C13");
  assert.equal(both.status, "manual");
  assert.equal(both.evidence.active_users, null);
  assert.match(both.evidence.active_users_status, /^unreadable: user_list \(\/msp\/user_list\.php\) was not readable \(.*\); users \(\/qps\/rest\/2\.0\/search\/am\/user\/\) was not readable \(/);
  assert.equal(both.evidence.managers, null);
  assert.equal(both.evidence.users_returned, null);

  const primary = findingById(await assessQualysAdministration(routedClient(compliantRouter)), "QUALYS-C13");
  assert.equal(primary.evidence.active_users, 3);
  assert.equal(primary.evidence.active_users_status, "readable: USER_STATUS Active users from user_list (/msp/user_list.php)");
  assert.equal(primary.evidence.managers_status, primary.evidence.active_users_status);
  assert.deepEqual(primary.evidence.generic_accounts, [], "a complete User List read can show there are no generic accounts");
  assert.equal(primary.evidence.generic_accounts_status, primary.evidence.active_users_status);
});

test("C13 keeps a non-empty match list over the partial Administration API population as a lower bound and withholds only an empty one", async () => {
  const matching = [...tenant.adminUsers, adminUser(3, "svc_backup", "Reader", { emailAddress: "mgr@example.com" })];
  const result = await assessQualysAdministration(routedClient(async (url, init) => {
    if (url.includes("/msp/user_list.php")) return forbiddenRouter(url);
    if (url.includes("/am/user")) return jsonResponse(qpsResponse("User", matching));
    return compliantRouter(url, init);
  }));
  const users = findingById(result, "QUALYS-C13");
  assert.deepEqual(users.evidence.generic_accounts, ["svc_backup"], "a match found in the partial population is real evidence");
  assert.deepEqual(users.evidence.shared_emails, ["mgr@example.com"]);
  assert.match(users.evidence.generic_accounts_status, /^partial: user_list \(\/msp\/user_list\.php\) was not readable \(.*\), so the population is the Administration API user search \(\/qps\/rest\/2\.0\/search\/am\/user\/\), which returns Active users only and hides other Manager and Super User accounts, so matches are a lower bound and an empty match list cannot show there are none$/);
  assert.equal(users.evidence.shared_emails_status, users.evidence.generic_accounts_status);
  assert.equal(users.status, "fail", "a shared email in the lower bound still fails the control");
  assert.equal(result.summary.shared_emails, 1);
  assert.equal(result.summary.shared_emails_status, users.evidence.shared_emails_status);

  const none = await assessQualysAdministration(withForbidden((url) => url.includes("/msp/user_list.php")));
  assert.equal(none.summary.shared_emails, null, "the summary count is withheld with the list");
  assert.match(none.summary.shared_emails_status, /an empty match list cannot show there are none$/);
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
    assert.equal(typeof item.evidence.manual_evidence, "string");
    assert.ok(Array.isArray(item.evidence.collection.sources) && item.evidence.collection.sources.length > 0);
    assert.ok(["pass", "warn", "fail", "manual"].includes(item.evidence.verdict_basis));
  }
  assert.deepEqual(findings.filter((item) => item.status === "pass").map((item) => item.id).sort(), COMPLIANT_PASS_IDS);
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
  assert.match(executive, /Manual controls: 2/);
  assert.match(executive, /Passing controls: 13/);
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
