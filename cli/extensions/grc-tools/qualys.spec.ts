import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
  deriveDecisionRules,
  type BatchCheckDefinition,
  type BatchCompletenessDefinition,
  type BatchCriterionExample,
  type BatchPaginationDefinition,
  type BatchSurfaceDefinition,
} from "./batch-spec-builder.js";
import { QUALYS_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import type { PortableValue, RequestParameterContract, VerdictCondition, VerdictOperand, VerdictRule } from "./spec-model.js";

// true keeps a scalar or a DTD text node; "date" also keeps the QPS JSON date wrapper {"date": "..."}; a nested
// allowlist descends into an object (or into every element of an array) and keeps only the listed fields.
export type FieldRule = true | "date" | FieldAllowlist;
export type FieldAllowlist = { readonly [field: string]: FieldRule };

// schedule_scan_list_output.dtd and schedule_report_list_output.dtd: SCHEDULE
const SCHEDULE_PLAN_FIELDS: FieldAllowlist = {
  DAILY: true,
  WEEKLY: true,
  MONTHLY: true,
  START_DATE_UTC: true,
  START_HOUR: true,
  START_MINUTE: true,
  NEXTLAUNCH_UTC: true,
  TIME_ZONE: { TIME_ZONE_CODE: true, TIME_ZONE_DETAILS: true },
  DST_SELECTED: true,
  MAX_OCCURRENCE: true,
  END_AFTER: true,
  END_AFTER_MINS: true,
  PAUSE_AFTER_HOURS: true,
  RESUME_IN_DAYS: true,
  RESUME_IN_HOURS: true,
};

// host_list_output.dtd (details=All, show_tags=1). METADATA, CLOUD_PROVIDER_TAGS, USER_DEF, OWNER, and
// COMMENTS are free-form and are not exported.
const HOST_FIELDS: FieldAllowlist = {
  ID: true,
  ASSET_ID: true,
  IP: true,
  IPV6: true,
  TRACKING_METHOD: true,
  NETWORK_ID: true,
  DNS: true,
  DNS_DATA: { HOSTNAME: true, DOMAIN: true, FQDN: true },
  CLOUD_PROVIDER: true,
  CLOUD_SERVICE: true,
  CLOUD_RESOURCE_ID: true,
  EC2_INSTANCE_ID: true,
  NETBIOS: true,
  OS: true,
  QG_HOSTID: true,
  LAST_BOOT: true,
  FIRST_FOUND_DATE: true,
  LAST_ACTIVITY: true,
  AGENT_STATUS: true,
  CLOUD_AGENT_RUNNING_ON: true,
  TAGS: { TAG: { TAG_ID: true, NAME: true } },
  LAST_VULN_SCAN_DATETIME: true,
  LAST_VULN_SCAN_DURATION: true,
  LAST_VM_SCANNED_DATE: true,
  LAST_VM_SCANNED_DURATION: true,
  LAST_VM_AUTH_SCANNED_DATE: true,
  LAST_VM_AUTH_SCANNED_DURATION: true,
  LAST_COMPLIANCE_SCAN_DATETIME: true,
  LAST_SCAP_SCAN_DATETIME: true,
  ASSET_GROUP_IDS: true,
};

// asset_group_list_output.dtd; COMMENTS is not exported.
const ASSET_GROUP_FIELDS: FieldAllowlist = {
  ID: true,
  TITLE: true,
  OWNER_USER_ID: true,
  OWNER_UNIT_ID: true,
  OWNER_USER_NAME: true,
  NETWORK_ID: true,
  NETWORK_IDS: true,
  LAST_UPDATE: true,
  BUSINESS_IMPACT: true,
  DEFAULT_APPLIANCE_ID: true,
  APPLIANCE_IDS: true,
  IP_SET: { IP: true, IP_RANGE: true },
  DOMAIN_LIST: { DOMAIN: true },
  DNS_LIST: { DNS: true },
  NETBIOS_LIST: { NETBIOS: true },
  HOST_IDS: true,
  EC2_IDS: true,
  ASSIGNED_USER_IDS: true,
  ASSIGNED_UNIT_IDS: true,
};

// user.xsd (Administration API search/am/user)
const ADMIN_USER_FIELDS: FieldAllowlist = {
  id: true,
  username: true,
  firstName: true,
  lastName: true,
  title: true,
  emailAddress: true,
  roleList: { count: true, list: { RoleData: { id: true, name: true } } },
  scopeTags: { count: true, list: { TagData: { id: true, name: true } } },
};

const QPS_USER_REFERENCE: FieldAllowlist = { id: true, username: true, firstName: true, lastName: true };
const QPS_NAMED_REFERENCE: FieldAllowlist = { id: true, name: true };
const QPS_TAG_LIST: FieldAllowlist = { count: true, list: { Tag: QPS_NAMED_REFERENCE } };
const WAS_WEB_APP_REFERENCE: FieldAllowlist = { id: true, name: true, url: true };
const WAS_SCANNER_REFERENCE: FieldAllowlist = { type: true, friendlyName: true };

// wasscan.xsd: options, sensitiveContents, vulns, igs, and stats are not exported.
const WAS_SCAN_FIELDS: FieldAllowlist = {
  id: true,
  name: true,
  reference: true,
  type: true,
  mode: true,
  multi: true,
  progressiveScanning: true,
  target: {
    webApp: WAS_WEB_APP_REFERENCE,
    webApps: { count: true, list: { WebApp: WAS_WEB_APP_REFERENCE } },
    tags: QPS_TAG_LIST,
    scannerAppliance: WAS_SCANNER_REFERENCE,
    cancelOption: true,
    authRecord: QPS_NAMED_REFERENCE,
  },
  profile: QPS_NAMED_REFERENCE,
  launchedDate: "date",
  launchedBy: QPS_USER_REFERENCE,
  status: true,
  endScanDate: "date",
  scanDuration: true,
  summary: { crawlDuration: true, testDuration: true, linksCrawled: true, nbRequests: true, resultsStatus: true, authStatus: true, os: true },
};

export const QUALYS_RAW_DATA_ALLOWLISTS: Record<string, FieldAllowlist> = {
  // schedule_scan_list_output.dtd; NOTIFICATIONS (custom messages and distribution) is not exported.
  scheduled_scans: {
    ID: true,
    SCAN_TYPE: true,
    ACTIVE: true,
    TITLE: true,
    CLIENT: { ID: true, NAME: true },
    USER_LOGIN: true,
    TARGET: true,
    NETWORK_ID: true,
    ISCANNER_NAME: true,
    EC2_INSTANCE: { CONNECTOR_UUID: true, EC2_ENDPOINT: true, EC2_ONLY_CLASSIC: true },
    CLOUD_DETAILS: { PROVIDER: true, CONNECTOR: { ID: true, UUID: true, NAME: true }, SCAN_TYPE: true, CLOUD_TARGET: { PLATFORM: true, REGION: { UUID: true, CODE: true, NAME: true }, VPC_SCOPE: true } },
    ASSET_GROUP_TITLE_LIST: { ASSET_GROUP_TITLE: true },
    ASSET_TAGS: {
      TAG_INCLUDE_SELECTOR: true,
      TAG_SET_INCLUDE: true,
      TAG_EXCLUDE_SELECTOR: true,
      TAG_SET_EXCLUDE: true,
      USE_IP_NT_RANGE_TAGS: true,
      USE_IP_NT_RANGE_TAGS_INCLUDE: true,
      USE_IP_NT_RANGE_TAGS_EXCLUDE: true,
    },
    EXCLUDE_IP_PER_SCAN: true,
    DEFAULT_SCANNER: true,
    USER_ENTERED_IPS: { IP: true, RANGE: { START: true, END: true } },
    ELB_DNS: { DNS: true },
    OPTION_PROFILE: { TITLE: true, DEFAULT_FLAG: true },
    PROCESSING_PRIORITY: true,
    SCHEDULE: SCHEDULE_PLAN_FIELDS,
  },
  // scan_list_output.dtd
  scans: {
    ID: true,
    REF: true,
    SCAN_TYPE: true,
    TYPE: true,
    TITLE: true,
    CLIENT: { ID: true, NAME: true },
    USER_LOGIN: true,
    LAUNCH_DATETIME: true,
    DURATION: true,
    PROCESSING_PRIORITY: true,
    PROCESSED: true,
    STATUS: { STATE: true, SUB_STATE: true },
    TARGET: true,
    ASSET_GROUP_TITLE_LIST: { ASSET_GROUP_TITLE: true },
    OPTION_PROFILE: { TITLE: true, DEFAULT_FLAG: true },
  },
  hosts: HOST_FIELDS,
  // option_profile_info.dtd: only the identity block and the settings the verdicts read (authentication types
  // and detection exclusion search lists). PASSWORD_BRUTE_FORCING, CUSTOM_HTTP_HEADER, SYSTEM_AUTH_RECORD, and
  // the rest of the configuration are never exported.
  option_profiles: {
    BASIC_INFO: { ID: true, GROUP_NAME: true, GROUP_TYPE: true, USER_ID: true, UNIT_ID: true, SUBSCRIPTION_ID: true, IS_DEFAULT: true, IS_GLOBAL: true, IS_OFFLINE_SYNCABLE: true, UPDATE_DATE: true },
    SCAN: {
      AUTHENTICATION: true,
      AUTHENTICATION_LEAST_PRIVILEGE: true,
      VULNERABILITY_DETECTION: {
        COMPLETE: true,
        RUNTIME: true,
        CUSTOM_LIST: { CUSTOM: { ID: true, TITLE: true } },
        DETECTION_INCLUDE: { BASIC_HOST_INFO_CHECKS: true, OVAL_CHECKS: true, QRDI_CHECKS: true },
        DETECTION_EXCLUDE: { CUSTOM_LIST: { CUSTOM: { ID: true, TITLE: true } } },
      },
    },
  },
  // ip_list_output.dtd: IP and IP_RANGE text with network_id and expiration_date attributes.
  excluded_ips: { type: true, value: true, network_id: true, expiration_date: true },
  asset_groups: ASSET_GROUP_FIELDS,
  // asset_data_connector.xsd plus the documented cloud account identifiers; arn, externalId, authRecord, and
  // any other credential material are not exported.
  connectors: {
    id: true,
    name: true,
    awsAccountId: true,
    subscriptionId: true,
    projectId: true,
    lastSync: "date",
    lastError: true,
    connectorState: true,
    type: true,
    serviceType: true,
    disabled: true,
    isGovCloudConfigured: true,
    isChinaConfigured: true,
    isInstantAssessmentEnabled: true,
    isSnapshotAssessmentEnabled: true,
    isAttachedToOrganization: true,
    isDeleted: true,
  },
  // appliance_list_output.dtd; ACTIVATION_CODE, INTERFACE_SETTINGS, PROXY_SETTINGS, CLOUD_INFO, VLANS,
  // STATIC_ROUTES, and COMMENTS are not exported.
  appliances: {
    ID: true,
    UUID: true,
    NAME: true,
    NETWORK_ID: true,
    SOFTWARE_VERSION: true,
    RUNNING_SLICES_COUNT: true,
    RUNNING_SCAN_COUNT: true,
    STATUS: true,
    MODEL_NUMBER: true,
    TYPE: true,
    IS_CLOUD_DEPLOYED: true,
    ML_LATEST: true,
    ML_VERSION: true,
    VULNSIGS_LATEST: true,
    VULNSIGS_VERSION: true,
    ASSET_GROUP_COUNT: true,
    ASSET_GROUP_LIST: { ASSET_GROUP: { ID: true, NAME: true } },
    ASSET_TAGS_LIST: { ASSET_TAG: { UUID: true, NAME: true } },
    LAST_UPDATED_DATE: true,
    POLLING_INTERVAL: true,
    USER_LOGIN: true,
    HEARTBEATS_MISSED: true,
    SS_CONNECTION: true,
    SS_LAST_CONNECTED: true,
    UPDATED: true,
    MAX_CAPACITY_UNITS: true,
  },
  // hostasset.xsd with agent_source.xsd; activationKey keeps its title only, never the activationId.
  cloud_agents: {
    id: true,
    name: true,
    created: "date",
    modified: "date",
    type: true,
    qwebHostId: true,
    trackingMethod: true,
    fqdn: true,
    dnsHostName: true,
    netbiosName: true,
    os: true,
    address: true,
    lastVulnScan: "date",
    lastComplianceScan: "date",
    lastSystemBoot: "date",
    criticalityScore: true,
    agentInfo: {
      agentVersion: true,
      agentId: true,
      status: true,
      lastCheckedIn: "date",
      platform: true,
      activatedModule: true,
      chirpStatus: true,
      manifestVersion: { vm: true, pc: true, sca: true },
      agentConfiguration: QPS_NAMED_REFERENCE,
      activationKey: { title: true },
    },
    tags: QPS_TAG_LIST,
  },
  // tag.xsd; ruleText and description are free-form configuration and are not exported.
  tags: {
    id: true,
    name: true,
    created: "date",
    modified: "date",
    ruleType: true,
    color: true,
    parentTagId: true,
    criticalityScore: true,
    provider: true,
    srcAssetGroupId: true,
    srcBusinessUnitId: true,
    srcOperatingSystemName: true,
  },
  // Summary rows built from auth_records.dtd ID_SET counts.
  auth_records: { type: true, count: true },
  // policy_list_output.dtd (details=Basic)
  compliance_policies: {
    ID: true,
    TITLE: true,
    CREATED: { DATETIME: true, BY: true },
    LAST_MODIFIED: { DATETIME: true, BY: true },
    LAST_EVALUATED: { DATETIME: true },
    STATUS: true,
    IS_LOCKED: true,
    EVALUATE_NOW: true,
    ASSET_GROUP_IDS: true,
    TAG_SET_INCLUDE: { TAG_ID: true },
    TAG_INCLUDE_SELECTOR: true,
    TAG_SET_EXCLUDE: { TAG_ID: true },
    TAG_EXCLUDE_SELECTOR: true,
    INCLUDE_AGENT_IPS: true,
  },
  // host_list_vm_detection_output.dtd flattened with host_id and ip; RESULTS (scanner output) is not exported.
  detections: {
    host_id: true,
    ip: true,
    UNIQUE_VULN_ID: true,
    QID: true,
    TYPE: true,
    SEVERITY: true,
    PORT: true,
    PROTOCOL: true,
    FQDN: true,
    SSL: true,
    INSTANCE: true,
    STATUS: true,
    FIRST_FOUND_DATETIME: true,
    LAST_FOUND_DATETIME: true,
    QDS: true,
    TIMES_FOUND: true,
    LAST_TEST_DATETIME: true,
    LAST_UPDATE_DATETIME: true,
    LAST_FIXED_DATETIME: true,
    LAST_PROCESSED_DATETIME: true,
    IS_IGNORED: true,
    IS_DISABLED: true,
    AFFECT_RUNNING_KERNEL: true,
    AFFECT_RUNNING_SERVICE: true,
    AFFECT_EXPLOITABLE_CONFIG: true,
  },
  // knowledge_base_vuln_list_output.dtd (details=Basic); DIAGNOSIS, CONSEQUENCE, and SOLUTION text is not exported.
  knowledge_base: {
    QID: true,
    VULN_TYPE: true,
    SEVERITY_LEVEL: true,
    TITLE: true,
    CATEGORY: true,
    LAST_SERVICE_MODIFICATION_DATETIME: true,
    PUBLISHED_DATETIME: true,
    PATCHABLE: true,
    PCI_FLAG: true,
    IS_DISABLED: true,
    DISCOVERY: { REMOTE: true, AUTH_TYPE_LIST: { AUTH_TYPE: true } },
    CVE_LIST: { CVE: { ID: true, URL: true } },
    CVSS: { BASE: true, TEMPORAL: true, VECTOR_STRING: true },
    CVSS_V3: { BASE: true, TEMPORAL: true, VECTOR_STRING: true, CVSS3_VERSION: true },
    THREAT_INTELLIGENCE: { THREAT_INTEL: true },
  },
  // schedule_report_list_output.dtd; any distribution or recipient element is not exported.
  scheduled_reports: {
    ID: true,
    TITLE: true,
    OUTPUT_FORMAT: true,
    TEMPLATE_TITLE: true,
    ACTIVE: true,
    SCHEDULE: SCHEDULE_PLAN_FIELDS,
  },
  // report_list_output.dtd
  reports: {
    ID: true,
    TITLE: true,
    TYPE: true,
    USER_LOGIN: true,
    LAUNCH_DATETIME: true,
    OUTPUT_FORMAT: true,
    SIZE: true,
    STATUS: { STATE: true, MESSAGE: true, PERCENT: true },
    EXPIRATION_DATETIME: true,
  },
  users: ADMIN_USER_FIELDS,
  // user_list_output.dtd; postal address and phone contact details are not exported.
  user_list: {
    USER_LOGIN: true,
    USER_ID: true,
    EXTERNAL_ID: true,
    CONTACT_INFO: { FIRSTNAME: true, LASTNAME: true, TITLE: true, EMAIL: true, COMPANY: true, COUNTRY: true, TIME_ZONE_CODE: true },
    ASSIGNED_ASSET_GROUPS: { ASSET_GROUP_TITLE: true },
    USER_STATUS: true,
    CREATION_DATE: true,
    LAST_LOGIN_DATE: true,
    USER_ROLE: true,
    BUSINESS_UNIT: true,
    UNIT_MANAGER_POC: true,
    MANAGER_POC: true,
  },
  // Activity Log CSV columns.
  activity_log: { date: true, action: true, module: true, details: true, user_name: true, user_role: true, user_ip: true },
  // webapp.xsd; headers, proxy, config, crawlingScripts, authRecords values, and screenshot are not exported.
  was_webapps: {
    id: true,
    name: true,
    url: true,
    os: true,
    owner: QPS_USER_REFERENCE,
    scope: true,
    tags: QPS_TAG_LIST,
    defaultProfile: QPS_NAMED_REFERENCE,
    defaultScanner: WAS_SCANNER_REFERENCE,
    scannerLocked: true,
    progressiveScanning: true,
    authRecords: { count: true, list: { WebAppAuthRecord: QPS_NAMED_REFERENCE } },
    useRobots: true,
    useSitemap: true,
    malwareMonitoring: true,
    isScheduled: true,
    lastScan: QPS_NAMED_REFERENCE,
    lastScanStatus: true,
    riskScore: true,
    createdBy: QPS_USER_REFERENCE,
    createdDate: "date",
    updatedBy: QPS_USER_REFERENCE,
    updatedDate: "date",
  },
  was_scans: WAS_SCAN_FIELDS,
  was_scan_history: WAS_SCAN_FIELDS,
  // webappauthrecord.xsd: form field values, server record credentials, OAuth2 client secrets and tokens,
  // selenium scripts, certificates, and auth vault details are not exported.
  was_auth_records: {
    id: true,
    name: true,
    owner: QPS_USER_REFERENCE,
    formRecord: {
      type: true,
      sslOnly: true,
      fields: { count: true, list: { WebAppAuthFormRecordField: { id: true, name: true, secured: true } } },
    },
    serverRecord: {
      type: true,
      sslOnly: true,
      fields: { count: true, list: { WebAppAuthServerRecordField: { id: true, type: true, domain: true } } },
    },
    oauth2Record: { grantType: true },
    tags: QPS_TAG_LIST,
    createdBy: QPS_USER_REFERENCE,
    createdDate: "date",
    updatedBy: QPS_USER_REFERENCE,
    updatedDate: "date",
  },
  // wasscanschedule.xsd; notification recipients and proxy settings are not exported.
  was_schedules: {
    id: true,
    name: true,
    type: true,
    active: true,
    multi: true,
    progressiveScanning: true,
    target: {
      webApp: WAS_WEB_APP_REFERENCE,
      webApps: { count: true, list: { WebApp: WAS_WEB_APP_REFERENCE } },
      tags: QPS_TAG_LIST,
      scannerAppliance: WAS_SCANNER_REFERENCE,
      cancelOption: true,
      authRecord: QPS_NAMED_REFERENCE,
    },
    profile: QPS_NAMED_REFERENCE,
    schedule: { startDate: "date", timeZone: { code: true, offset: true }, occurrenceType: true, occurrenceCount: true },
    launchedCount: true,
    launchedDate: "date",
    nextLaunchDate: "date",
    owner: QPS_USER_REFERENCE,
    createdBy: QPS_USER_REFERENCE,
    createdDate: "date",
    updatedBy: QPS_USER_REFERENCE,
    updatedDate: "date",
  },
};

const VM_SERVICE = "Qualys VM/PC API";
const ADMIN_SERVICE = "Qualys Administration API";
const AM_SERVICE = "Qualys Asset Management and Tagging API";
const CA_SERVICE = "Qualys Cloud Agent API";
const WAS_SERVICE = "Qualys WAS API";
const VM_DOCS = "https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects";
const WAS_DOCS = "https://docs.qualys.com/en/was/api";
const API_SERVER = "Use the configured API server (base_url, else the selected platform's API server); never follow a continuation URL to another origin.";
const AUTH_HEADER = "Authorization: {Basic base64(username:password), or Bearer token}";
const XML_HEADERS = ["X-Requested-With: grclanker", "Accept: application/xml", AUTH_HEADER];
const QPS_HEADERS = ["X-Requested-With: grclanker", "Accept: application/json", "Content-Type: application/json", AUTH_HEADER];
const ACTIVITY_HEADERS = ["X-Requested-With: grclanker", "Accept: text/csv, application/xml", AUTH_HEADER];
const PROJECTION_STAGE = "The collector keeps only the listed fields, the allowlist projection written under core_data, and drops every other response member before evidence export; decision facts read a subset of these fields.";

const fieldsOf = (allowlist: FieldAllowlist, prefix = ""): string[] => Object.entries(allowlist).flatMap(([key, rule]) => {
  const name = prefix ? `${prefix}.${key}` : key;
  return rule === true || rule === "date" ? [name] : fieldsOf(rule, name);
});

const surfaceFields = (id: string): string[] => {
  const allowlist = QUALYS_RAW_DATA_ALLOWLISTS[id];
  if (!allowlist) throw new Error(`Qualys surface ${id} has no raw data allowlist`);
  return fieldsOf(allowlist);
};

const param = (
  name: string,
  location: RequestParameterContract["location"],
  value: string,
  required = true,
  when?: string,
): RequestParameterContract => ({ name, location, required, value, ...(when ? { when } : {}) });

const LIST_ACTION = param("action", "query", "list");
const LOOKBACK_START = "lookback_days before the assessment time, in UTC ISO 8601 without fractional seconds";
const ID_MIN = param(
  "id_min",
  "query",
  "The id_min carried by the previous page's WARNING/URL",
  false,
  "Only on a continuation, which requests the WARNING/URL exactly as returned",
);
const limitResults = (value: string) => param("ServiceRequest.preferences.limitResults", "json-body", value);
const CONTINUATION_CRITERIA = param(
  "ServiceRequest.filters.Criteria",
  "json-body",
  "One criterion with field id, operator GREATER, and the previous page's lastId as its value",
  false,
  "Only on a continuation page",
);

const xmlRecords = (element: string): string =>
  `XML in which every <${element}> element is one record and an optional WARNING carries a continuation URL; a SIMPLE_RETURN, GENERIC_RETURN, or root-level ERROR envelope, a non-XML body, or HTTP status 400 or above is a refusal.`;
const QPS_RESPONSE = "A JSON ServiceResponse with responseCode SUCCESS, a data array of single-key objects whose value is the record, hasMoreRecords, and lastId; any other responseCode or HTTP status 400 or above is a refusal.";

const vmSurface = (
  id: string,
  path: string,
  page: string,
  parameters: readonly RequestParameterContract[],
  responseShape: string,
  headers: readonly string[] = XML_HEADERS,
): BatchSurfaceDefinition => ({
  id,
  path,
  service: VM_SERVICE,
  documentationUrl: `${VM_DOCS}/${page}`,
  fields: surfaceFields(id),
  request: { clientRegion: API_SERVER, headers, parameters, responseShape },
  projectionStage: PROJECTION_STAGE,
});

const qpsSurface = (
  id: string,
  path: string,
  service: string,
  documentationUrl: string,
  parameters: readonly RequestParameterContract[],
  projectionStage = PROJECTION_STAGE,
): BatchSurfaceDefinition => ({
  id,
  method: "POST",
  path,
  service,
  documentationUrl,
  fields: surfaceFields(id),
  request: { clientRegion: API_SERVER, headers: QPS_HEADERS, parameters, responseShape: QPS_RESPONSE },
  projectionStage,
});

// Every assessment resolves the configured user's view scope from these two reads.
const SCOPE_SURFACES: readonly BatchSurfaceDefinition[] = [
  qpsSurface(
    "users",
    "/qps/rest/2.0/search/am/user/",
    ADMIN_SERVICE,
    "https://docs.qualys.com/en/admin/api/rbac_apis/search_user_list_based_on_id_name_and_rolename.htm",
    [limitResults("500, or the users left under the 5000-user cap when fewer"), CONTINUATION_CRITERIA],
  ),
  vmSurface(
    "user_list",
    "/msp/user_list.php",
    "qapi-user/users/list_users.htm",
    [],
    "XML whose USER_LIST_OUTPUT holds one USER element per user; a missing USER_LIST_OUTPUT, a USER_LIST_OUTPUT/ERROR, a non-XML body, or HTTP status 400 or above is a refusal.",
  ),
];

const SCAN_COVERAGE_SURFACES: readonly BatchSurfaceDefinition[] = [
  vmSurface(
    "scheduled_scans",
    "/api/2.0/fo/schedule/scan/",
    "qapi-scan/vm_schedules/list_scan_schedules.htm",
    [LIST_ACTION, param("show_notifications", "query", "0"), ID_MIN],
    xmlRecords("SCAN"),
  ),
  vmSurface("scans", "/api/2.0/fo/scan/", "qapi-scan/vm_scans/list_vm_scans.htm", [
    LIST_ACTION,
    param("launched_after_datetime", "query", LOOKBACK_START),
    param("show_ags", "query", "1"),
    param("show_op", "query", "1"),
    ID_MIN,
  ], xmlRecords("SCAN")),
  vmSurface("hosts", "/api/2.0/fo/asset/host/", "qapi-assets/host_lists/host_list.htm", [
    LIST_ACTION,
    param("details", "query", "All"),
    param("show_tags", "query", "1"),
    param("truncation_limit", "query", "The smaller of host_limit and 1000; the access check sends 100"),
    ID_MIN,
  ], xmlRecords("HOST")),
  vmSurface(
    "option_profiles",
    "/api/2.0/fo/subscription/option_profile/vm/",
    "qapi-scan/ops/ops_vm/list_vm_op.htm",
    [LIST_ACTION, ID_MIN],
    xmlRecords("OPTION_PROFILE"),
  ),
  vmSurface(
    "excluded_ips",
    "/api/2.0/fo/asset/excluded_ip/",
    "qapi-assets/asset_ips/excl_host_list.htm",
    [LIST_ACTION],
    "XML whose IP_SET holds IP and IP_RANGE entries, each kept as its text plus attributes; a WARNING/URL continuation is not followed and marks the read partial; a SIMPLE_RETURN, GENERIC_RETURN, or root-level ERROR envelope, a non-XML body, or HTTP status 400 or above is a refusal.",
  ),
  vmSurface("asset_groups", "/api/2.0/fo/asset/group/", "qapi-assets/asset_groups/list_asset_groups.htm", [
    LIST_ACTION,
    param("show_attributes", "query", "ALL"),
    param("truncation_limit", "query", "500"),
    ID_MIN,
  ], xmlRecords("ASSET_GROUP")),
];

const ASSET_INVENTORY_SURFACES: readonly BatchSurfaceDefinition[] = [
  qpsSurface(
    "connectors",
    "/qps/rest/2.0/search/am/assetdataconnector",
    AM_SERVICE,
    "https://docs.qualys.com/en/am/api/asset_data_connector/search_connectors.htm",
    [limitResults("100, or the connectors left under the 5000-connector cap when fewer"), CONTINUATION_CRITERIA],
  ),
  vmSurface(
    "appliances",
    "/api/2.0/fo/appliance/",
    "qapi-scan/appliances/list_appliances.htm",
    [LIST_ACTION, param("output_mode", "query", "full"), ID_MIN],
    xmlRecords("APPLIANCE"),
  ),
  qpsSurface(
    "cloud_agents",
    "/qps/rest/2.0/search/am/hostasset",
    CA_SERVICE,
    "https://docs.qualys.com/en/ca/api/agents/list_agents.htm",
    [
      limitResults("1000, or the agents left under host_limit when fewer"),
      param(
        "ServiceRequest.filters.Criteria",
        "json-body",
        "The criterion tagName EQUALS Cloud Agent, joined on a continuation by id GREATER than the previous page's lastId",
      ),
    ],
    `${PROJECTION_STAGE} QUALYS-C07 reads agentInfo.activationKey.activationId and agentInfo.activationKey.id only to tell whether an activation key is present; neither is exported.`,
  ),
  qpsSurface(
    "tags",
    "/qps/rest/2.0/search/am/tag",
    AM_SERVICE,
    "https://docs.qualys.com/en/am/api/tags/search_tags.htm",
    [limitResults("1000, or the tags left under the 2000-tag cap when fewer"), CONTINUATION_CRITERIA],
  ),
];

const VULNERABILITY_SURFACES: readonly BatchSurfaceDefinition[] = [
  vmSurface(
    "auth_records",
    "/api/2.0/fo/auth/",
    "qapi-auth/record_list/list_records.htm",
    [LIST_ACTION],
    "XML whose AUTH_RECORDS holds one AUTH_<TYPE>_IDS or AUTH_<TYPE>_RECORDS wrapper per technology, kept as the lowercased type and a count of its IDs plus every ID in each first-last ID_RANGE; a WARNING/URL continuation is not followed and marks the read partial; a SIMPLE_RETURN, GENERIC_RETURN, or root-level ERROR envelope, a non-XML body, or HTTP status 400 or above is a refusal.",
  ),
  vmSurface(
    "compliance_policies",
    "/api/2.0/fo/compliance/policy/",
    "qapi-pc/policies/list_policies.htm",
    [LIST_ACTION, param("details", "query", "Basic"), ID_MIN],
    xmlRecords("POLICY"),
  ),
  vmSurface("detections", "/api/2.0/fo/asset/host/vm/detection/", "qapi-assets/host_lists/host_detection.htm", [
    LIST_ACTION,
    param("status", "query", "Active,New,Re-Opened"),
    param("severities", "query", "3,4,5"),
    param("show_qds", "query", "1"),
    param("truncation_limit", "query", "The smaller of detection_limit and 1000"),
    param("output_format", "query", "XML"),
    ID_MIN,
  ], "XML in which every DETECTION under a <HOST> element's DETECTION_LIST becomes one record carrying that host's ID and IP, and an optional WARNING carries a continuation URL; a SIMPLE_RETURN, GENERIC_RETURN, or root-level ERROR envelope, a non-XML body, or HTTP status 400 or above is a refusal."),
  vmSurface("knowledge_base", "/api/2.0/fo/knowledge_base/vuln/", "qapi-scan/kbase/knowledgebase.htm", [
    LIST_ACTION,
    param("details", "query", "Basic"),
    param("ids", "query", "Up to 200 distinct QIDs of open detections, comma-separated"),
    ID_MIN,
  ], xmlRecords("VULN")),
];

const qpsContinuation = (records: string) => [limitResults(`100, or the ${records} left under the 5000-record cap when fewer`), CONTINUATION_CRITERIA];
const scanCriteria = (criteria: string) => param(
  "ServiceRequest.filters.Criteria",
  "json-body",
  `${criteria}, joined on a continuation by id GREATER than the previous page's lastId`,
);

// was_scans must stay ahead of was_scan_history: both POST the same WAS scan search.
const ADMINISTRATION_SURFACES: readonly BatchSurfaceDefinition[] = [
  vmSurface(
    "scheduled_reports",
    "/api/2.0/fo/schedule/report/",
    "qapi-rep/reports/list_sched_reports.htm",
    [LIST_ACTION, param("is_active", "query", "1"), ID_MIN],
    xmlRecords("REPORT"),
  ),
  vmSurface("reports", "/api/2.0/fo/report/", "qapi-rep/reports/list_reports.htm", [LIST_ACTION, ID_MIN], xmlRecords("REPORT")),
  vmSurface(
    "activity_log",
    "/api/2.0/fo/activity_log/",
    "qapi-user/activity/export_activity.htm",
    [LIST_ACTION, param("since_datetime", "query", LOOKBACK_START), param("truncation_limit", "query", "5000")],
    "CSV whose header row is the first row with a Date column; every later row is one record keyed by its lowercased, underscore-joined headers. A SIMPLE_RETURN, GENERIC_RETURN, or root-level ERROR XML envelope, or HTTP status 400 or above, is a refusal.",
    ACTIVITY_HEADERS,
  ),
  qpsSurface("was_webapps", "/qps/rest/3.0/search/was/webapp", WAS_SERVICE, `${WAS_DOCS}/web_apps/search_webapps.htm`, [
    ...qpsContinuation("web applications"),
    param("ServiceRequest.preferences.verbose", "json-body", "true"),
  ]),
  qpsSurface("was_scans", "/qps/rest/3.0/search/was/wasscan", WAS_SERVICE, `${WAS_DOCS}/scans/search_scan.htm`, [
    limitResults("100, or the scans left under the 5000-scan cap when fewer"),
    scanCriteria(`The criteria launchedDate GREATER ${LOOKBACK_START}, and type EQUALS VULNERABILITY`),
  ]),
  qpsSurface("was_scan_history", "/qps/rest/3.0/search/was/wasscan", WAS_SERVICE, `${WAS_DOCS}/scans/search_scan.htm`, [
    limitResults("100, or the scans left under the 5000-scan cap when fewer"),
    scanCriteria(
      "The criteria webApp.id IN up to 100 comma-separated IDs of web applications without a finished vulnerability scan in the lookback search, type EQUALS VULNERABILITY, and status EQUALS FINISHED",
    ),
  ]),
  qpsSurface(
    "was_auth_records",
    "/qps/rest/3.0/search/was/webappauthrecord",
    WAS_SERVICE,
    `${WAS_DOCS}/auth/search_auth.htm`,
    qpsContinuation("authentication records"),
  ),
  qpsSurface(
    "was_schedules",
    "/qps/rest/3.0/search/was/wasscanschedule",
    WAS_SERVICE,
    `${WAS_DOCS}/schedules/search_schedule.htm`,
    qpsContinuation("schedules"),
  ),
];

const QUALYS_SURFACES: readonly BatchSurfaceDefinition[] = [
  ...SCAN_COVERAGE_SURFACES,
  ...ASSET_INVENTORY_SURFACES,
  ...VULNERABILITY_SURFACES,
  ...ADMINISTRATION_SURFACES,
  ...SCOPE_SURFACES,
];

const value = (entry: PortableValue): VerdictOperand => ({ kind: "value", value: entry });
const path = (name: string): VerdictOperand => ({ kind: "path", path: name });
type Comparator = "eq" | "ne" | "gt" | "gte" | "lt" | "lte";
const cmp = (op: Comparator, left: string | VerdictOperand, right: PortableValue | VerdictOperand): VerdictCondition => ({
  op,
  left: typeof left === "string" ? path(left) : left,
  right: right !== null && typeof right === "object" && !Array.isArray(right) ? right as VerdictOperand : value(right as PortableValue),
});
const eq = (left: string | VerdictOperand, right: PortableValue | VerdictOperand) => cmp("eq", left, right);
const ne = (left: string | VerdictOperand, right: PortableValue | VerdictOperand) => cmp("ne", left, right);
const gt = (left: string | VerdictOperand, right: PortableValue | VerdictOperand) => cmp("gt", left, right);
const lt = (left: string | VerdictOperand, right: PortableValue | VerdictOperand) => cmp("lt", left, right);
const lte = (left: string | VerdictOperand, right: PortableValue | VerdictOperand) => cmp("lte", left, right);
const all = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "and", conditions });
const any = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "or", conditions });
const some = (name: string, condition: VerdictCondition): VerdictCondition => ({ op: "some", path: name, condition });
const always: VerdictCondition = { op: "always" };
const rule = (status: VerdictRule["status"], condition: VerdictCondition): VerdictRule => ({ status, condition });
const scopePartial = eq("view_scope_partial", true);

const QUALYS_INPUTS: Readonly<Record<string, string>> = {
  view_scope_partial: "True when the configured user is verified, by the QPS user search, by GET /msp/user_list.php, or in the administration assessment by the user's own activity log rows, to hold no Manager or Super User role or to carry scope tags, so lists may cover only part of the subscription; false when the user cannot be verified, as with a bearer token.",
  lookback_days: "The lookback_days assessment option, else the configured lookback, in whole days clamped to 1 through 365; default 30.",
  min_auth_scan_percent: "The min_auth_scan_percent assessment option, clamped to 0 through 100; default 80.",
  scheduled_scans_readable: "True when GET /api/2.0/fo/schedule/scan/ returned its scan schedule list without a refusal.",
  scheduled_scans_complete: "Scan schedule list coverage.",
  active_schedule_count: "Number of returned scan schedules whose ACTIVE flag is 1, 2, or 3.",
  schedules_without_active_flag_count: "Number of returned scan schedules whose ACTIVE flag is absent or is not one of 0, 1, 2, or 3.",
  external_scanner_schedule_count: "Number of active scan schedules whose ISCANNER_NAME, with whitespace collapsed and trimmed, is External Scanner, case-insensitively.",
  scans_readable: "True when GET /api/2.0/fo/scan/ returned its list of scans launched in the lookback window without a refusal.",
  scans_complete: "Coverage of the scans launched in the lookback window.",
  asset_groups_readable: "True when GET /api/2.0/fo/asset/group/ returned its asset group list without a refusal.",
  asset_groups_complete: "Asset group list coverage.",
  asset_group_count: "Number of asset group records returned.",
  unscheduled_asset_group_count: "Number of returned asset groups whose title, lowercased, is not among the lowercased targets of the active scan schedules (their ASSET_GROUP_TITLE entries, TAG_SET_INCLUDE names, and TARGET unless it reads asset tags included); 0 when an active schedule targets all.",
  hosts_readable: "True when GET /api/2.0/fo/asset/host/ returned its host list without a refusal.",
  hosts_complete: "Host list coverage up to host_limit.",
  host_count: "Number of host records returned, at most host_limit.",
  scanned_host_scan_age_days: "Whole days since each returned host's LAST_VULN_SCAN_DATETIME, else its LAST_VM_SCANNED_DATE, for every host carrying one of them as a parseable date.",
  scanned_host_count: "Number of returned hosts carrying a parseable LAST_VULN_SCAN_DATETIME or LAST_VM_SCANNED_DATE.",
  undated_host_count: "Number of returned hosts carrying neither a parseable LAST_VULN_SCAN_DATETIME nor a parseable LAST_VM_SCANNED_DATE.",
  authenticated_scan_percent: "Percentage of scanned hosts whose LAST_VM_AUTH_SCANNED_DATE is at most the larger of lookback_days and 30 whole days old, rounded to one decimal place with ties rounded up; recorded only when scanned_host_count is above 0.",
  option_profiles_readable: "True when GET /api/2.0/fo/subscription/option_profile/vm/ returned its option profile list without a refusal.",
  option_profiles_complete: "Option profile list coverage.",
  option_profile_count: "Number of option profile records returned.",
  detection_exclusion_list_count: "Total number of CUSTOM entries under SCAN/VULNERABILITY_DETECTION/DETECTION_EXCLUDE/CUSTOM_LIST across the returned option profiles.",
  excluded_ips_readable: "True when GET /api/2.0/fo/asset/excluded_ip/ returned its excluded IP list without a refusal.",
  excluded_ips_complete: "Excluded IP list coverage.",
  excluded_entry_count: "Number of IP and IP_RANGE entries in the excluded IP list.",
  excluded_range_address_counts: "Address count of each IP_RANGE entry: the end address minus the start address plus one, at least 1, for a start-end range; 2 raised to 32 minus the prefix length for CIDR notation; otherwise 1. Ranges whose addresses do not parse are omitted.",
  connectors_readable: "True when POST /qps/rest/2.0/search/am/assetdataconnector returned SUCCESS.",
  connectors_complete: "Asset data connector list coverage.",
  connector_count: "Number of asset data connector records returned.",
  unhealthy_connector_count: "Number of returned connectors whose connectorState, uppercased, contains ERROR, DISABLED, or INCOMPLETE, whose disabled flag is true, or that carry a non-empty lastError.",
  connector_sync_age_days: "Whole days since each returned connector's lastSync, for every connector carrying a parseable one.",
  unknown_state_connector_count: "Number of healthy connectors whose connectorState is UNKNOWN.",
  undated_connector_count: "Number of healthy connectors without a parseable lastSync.",
  appliances_readable: "True when GET /api/2.0/fo/appliance/ returned its scanner appliance list without a refusal.",
  appliances_complete: "Scanner appliance list coverage.",
  appliance_count: "Number of scanner appliance records returned.",
  offline_appliance_count: "Number of returned appliances whose STATUS, lowercased, contains offline, inactive, or disconnected.",
  outdated_appliance_count: "Number of appliances that are not offline and either report HEARTBEATS_MISSED above 0 or run an outdated version: ML_VERSION differs from ML_LATEST, or VULNSIGS_VERSION from VULNSIGS_LATEST, when both texts are present, or, when either text is empty, that VERSION element's updated attribute is no.",
  unknown_status_appliance_count: "Number of returned appliances whose STATUS is absent or unknown.",
  unknown_version_appliance_count: "Number of appliances that are neither offline nor outdated and have an ML or vulnerability signature version pair that cannot be compared, because a text is empty and the updated attribute is neither yes nor no.",
  cloud_agents_readable: "True when POST /qps/rest/2.0/search/am/hostasset with the tagName EQUALS Cloud Agent criterion returned SUCCESS.",
  cloud_agents_complete: "Cloud agent host asset coverage up to host_limit.",
  agent_coverage_percent: "Percentage of returned hosts whose TRACKING_METHOD, lowercased, contains agent, rounded to one decimal place with ties rounded up; recorded only when host_count is above 0.",
  min_agent_coverage_percent: "The min_agent_coverage_percent assessment option, clamped to 0 through 100; default 50.",
  inactive_agent_count: "Number of returned agents whose agentInfo.status, uppercased, contains INACTIVE or UNINSTALL.",
  agent_checkin_age_days: "Whole days since each returned agent's agentInfo.lastCheckedIn (its date member when it is an object), for every agent carrying a parseable one.",
  untracked_host_count: "Number of returned hosts without a TRACKING_METHOD.",
  unknown_status_agent_count: "Number of returned agents whose agentInfo.status is UNKNOWN.",
  undated_agent_count: "Number of returned agents without a parseable agentInfo.lastCheckedIn.",
  agents_without_activation_key_count: "Number of returned agents whose agentInfo.activationKey carries none of activationId, title, or id.",
  tags_readable: "True when POST /qps/rest/2.0/search/am/tag returned SUCCESS.",
  tags_complete: "Tag list coverage up to 2000 tags.",
  tag_count: "Number of tag records returned.",
  untagged_host_percent: "Percentage of returned hosts without a TAGS/TAG NAME, rounded to one decimal place with ties rounded up; recorded only when host_count is above 0.",
  auth_records_readable: "True when GET /api/2.0/fo/auth/ returned its authentication record summary without a refusal.",
  auth_records_complete: "Authentication record summary coverage.",
  auth_record_type_count: "Number of authentication record technologies whose ID count is above 0.",
  uncovered_os_family_count: "Number of operating system families, out of three, that some returned host runs while no authentication record technology with an ID count above 0 covers it: Windows (OS matching windows) needs a technology matching windows; Unix-like (OS matching linux, unix, bsd, solaris, aix, hp-ux, esx, mac os, or darwin) needs one matching unix or linux; network devices (OS matching cisco, nx-os, ios-xe, junos, juniper, palo alto, pan-os, fortinet, fortios, fortigate, arista, big-ip, f5, check point, gaia, router, switch, firewall, screenos, brocade, or huawei) need one matching snmp, cisco, checkpoint, check_point, palo, fortinet, juniper, arista, network, f5, huawei, or brocade. Matching is case-insensitive.",
  os_unknown_host_count: "Number of returned hosts whose OS is absent or empty after trimming.",
  compliance_policies_readable: "True when GET /api/2.0/fo/compliance/policy/ returned its compliance policy list without a refusal.",
  compliance_policies_complete: "Compliance policy list coverage.",
  policy_count: "Number of compliance policy records returned.",
  unassigned_active_policy_count: "Number of returned policies whose STATUS is active, case-insensitively, that list no ASSET_GROUP_IDS and no TAG_SET_INCLUDE/TAG_ID and whose ASSET_GROUP_IDS does not set has_hidden_data to true.",
  inactive_policy_count: "Number of returned policies whose STATUS, lowercased, contains inactive, draft, or disabled.",
  unknown_status_policy_count: "Number of returned policies whose STATUS is absent, or is neither active nor contains inactive, draft, or disabled.",
  hidden_asset_group_policy_count: "Number of returned policies whose ASSET_GROUP_IDS sets has_hidden_data to true, so some assigned asset groups are hidden from the configured user.",
  detections_readable: "True when GET /api/2.0/fo/asset/host/vm/detection/ returned its detection list without a refusal.",
  detections_complete: "Detection list coverage up to detection_limit.",
  sla_scoped_detection_count: "Number of open detections (TYPE not Info, STATUS absent or one of Active, New, Re-Opened, or Reopened, case-insensitively) with a SEVERITY of 3 or higher; each has a remediation SLA of sla_critical_days for severity 5, sla_high_days for 4, and sla_medium_days for 3 (defaults 15, 30, and 90).",
  sla_compliance_percent: "Percentage of SLA-scoped detections with a parseable FIRST_FOUND_DATETIME whose age in whole days is at most their severity's SLA, rounded to one decimal place with ties rounded up; recorded only when at least one SLA-scoped detection carries a parseable FIRST_FOUND_DATETIME.",
  undated_sla_detection_count: "Number of SLA-scoped detections without a parseable FIRST_FOUND_DATETIME.",
  unrated_open_detection_count: "Number of open detections without a SEVERITY.",
  statusless_open_detection_count: "Number of open detections without a STATUS.",
  knowledge_base_readable: "True when every GET /api/2.0/fo/knowledge_base/vuln/ batch for the open detections' QIDs returned without a refusal, or when the readable detection list holds no open QID to look up.",
  knowledge_base_complete: "Knowledge base lookup coverage of the open QIDs; true when no lookup was needed.",
  open_detection_count: "Number of returned detections whose TYPE is not Info and whose STATUS is absent or one of Active, New, Re-Opened, or Reopened, case-insensitively.",
  open_qid_count: "Number of distinct QIDs among the open detections.",
  knowledge_base_qid_count: "Number of distinct QIDs the knowledge base lookup returned; recorded only when the lookup ran.",
  unresolved_qid_count: "Number of distinct open QIDs the knowledge base lookup returned no entry for; recorded only when the lookup ran.",
  overdue_patchable_percent: "Percentage of dated patchable open detections (the QID's knowledge base entry sets PATCHABLE to true and FIRST_FOUND_DATETIME parses) first found more than sla_high_days whole days ago, rounded to one decimal place with ties rounded up; recorded only when at least one patchable open detection is dated.",
  overdue_patchable_detection_count: "Number of dated patchable open detections first found more than sla_high_days whole days ago.",
  undated_patchable_detection_count: "Number of patchable open detections without a parseable FIRST_FOUND_DATETIME.",
  qds_detection_percent: "Percentage of open detections carrying a non-empty QDS, rounded to one decimal place with ties rounded up; recorded only when open_detection_count is above 0.",
  scheduled_reports_readable: "True when GET /api/2.0/fo/schedule/report/ returned its active scheduled report list without a refusal.",
  reports_readable: "True when GET /api/2.0/fo/report/ returned its report list without a refusal.",
  active_scheduled_report_count: "Number of returned scheduled reports whose ACTIVE flag reads as true: true, 1, or yes, case-insensitively.",
  user_list_readable: "True when GET /msp/user_list.php returned its USER_LIST_OUTPUT without a refusal.",
  users_readable: "True when POST /qps/rest/2.0/search/am/user/ returned SUCCESS.",
  users_complete: "QPS user search coverage up to 5000 users.",
  active_user_count: "Number of active users: the user list rows whose USER_STATUS is active, case-insensitively, when GET /msp/user_list.php is readable, else the QPS user search rows, which list active users only.",
  max_managers: "The max_managers assessment option, clamped to 0 through 10000; default 5.",
  manager_count: "Number of active users holding a role (USER_ROLE in the user list, a roleList name in the QPS user search) that is exactly manager, or contains super user, superuser, or administrator, case-insensitively.",
  shared_email_count: "Number of distinct email addresses (CONTACT_INFO EMAIL in the user list, emailAddress in the QPS user search), compared case-insensitively, that more than one active user holds.",
  last_login_age_days: "Whole days since each active user's LAST_LOGIN_DATE, for every active user carrying a parseable one.",
  generic_account_count: "Number of active users whose login (USER_LOGIN in the user list, username in the QPS user search), lowercased, contains shared, generic, service, svc, or test, or ends with admin followed by optional digits.",
  pending_activation_user_count: "Number of user list rows whose USER_STATUS, lowercased, contains pending.",
  roleless_active_user_count: "Number of active users without a role: no USER_ROLE in the user list, or no roleList name in the QPS user search.",
  statusless_user_count: "Number of user list rows without a USER_STATUS.",
  undated_login_user_count: "Number of active users without a parseable LAST_LOGIN_DATE.",
  loginless_user_count: "Number of user list rows without a USER_LOGIN.",
  was_webapps_readable: "True when POST /qps/rest/3.0/search/was/webapp returned SUCCESS.",
  was_webapps_complete: "WAS web application list coverage up to 5000 web applications.",
  was_scans_readable: "True when POST /qps/rest/3.0/search/was/wasscan with the lookback criteria returned SUCCESS.",
  was_scans_complete: "Coverage of the WAS vulnerability scans launched in the lookback window, up to 5000 scans.",
  was_scan_history_readable: "True when every WAS scan history batch, for the web applications without a finished vulnerability scan in the lookback search, returned SUCCESS, or when no web application needed history.",
  was_scan_history_complete: "WAS scan history coverage of the web applications that needed it; true when no web application needed history.",
  was_auth_records_readable: "True when POST /qps/rest/3.0/search/was/webappauthrecord returned SUCCESS.",
  was_auth_records_complete: "WAS authentication record list coverage up to 5000 records.",
  was_schedules_readable: "True when POST /qps/rest/3.0/search/was/wasscanschedule returned SUCCESS.",
  was_schedules_complete: "WAS scan schedule list coverage up to 5000 schedules.",
  web_app_count: "Number of WAS web application records returned.",
  never_scanned_web_app_count: "Number of returned web applications with no finished vulnerability scan in the lookback search and none in a readable, complete scan history.",
  resolved_web_app_scan_age_days: "Whole days since the launchedDate of each returned web application's newest finished vulnerability scan, taken from the lookback search, else from the scan history, for every web application whose scan is at most lookback_days old or whose scan history was readable and complete.",
  unresolved_web_app_count: "Number of returned web applications without a finished vulnerability scan at most lookback_days old whose scan history was refused or stopped early.",
  was_auth_record_age_days: "Whole days since each returned WAS authentication record's updatedDate, else its createdDate, for every record carrying one of them as a parseable date.",
  undated_was_auth_record_count: "Number of returned WAS authentication records carrying neither a parseable updatedDate nor a parseable createdDate.",
  was_schedules_without_active_flag_count: "Number of returned WAS scan schedules whose active flag is absent or reads as neither true nor false.",
  activity_log_readable: "True when GET /api/2.0/fo/activity_log/ returned its rows since the lookback start without a refusal.",
  activity_entry_count: "Number of activity log rows returned, at most 5000.",
};

const inputs = (...names: string[]): Readonly<Record<string, string>> => Object.fromEntries(names.map((name) => {
  const definition = QUALYS_INPUTS[name];
  if (!definition) throw new Error(`Qualys decision input ${name} has no portable definition`);
  return [name, definition];
}));

const completeFrom = (
  semantics: string,
  sources: BatchCompletenessDefinition["sources"],
): BatchCompletenessDefinition => ({ semantics, sources });

const continuationComplete = (surfaceId: string, list: string, cap: string): BatchCompletenessDefinition => completeFrom(
  `false when the ${list} stopped with a WARNING/URL continuation left: at ${cap}, at the 25-page cap, at an empty page, or at a continuation URL on another origin.`,
  [{ surfaceId, falseWhen: ["truncated"] }],
);

const SCHEDULES_COMPLETE = continuationComplete("scheduled_scans", "scan schedule list", "5000 schedules");
const HOSTS_COMPLETE = continuationComplete("hosts", "host list", "host_limit hosts");
const OPTION_PROFILES_COMPLETE = continuationComplete("option_profiles", "option profile list", "5000 profiles");

type QualysCheck = {
  id: string;
  control: number;
  title: string;
  severity: BatchCheckDefinition["severity"];
  owner: string;
  surfaces: readonly string[];
  inputs: readonly string[];
  constants?: Readonly<Record<string, PortableValue>>;
  rules: readonly VerdictRule[];
  completeness?: Readonly<Record<string, BatchCompletenessDefinition>>;
  decision: string;
  examples: readonly BatchCriterionExample[];
};

const example = (
  kind: BatchCriterionExample["kind"],
  expected: BatchCriterionExample["expected"],
  reason: string,
  facts: Readonly<Record<string, unknown>>,
): BatchCriterionExample => ({ kind, expected, reason, facts });

const SCAN_COVERAGE = "qualys_assess_scan_coverage";

const SCAN_COVERAGE_CHECKS: readonly QualysCheck[] = [
  {
    id: "QUALYS-C01",
    control: 1,
    title: "Scan schedule coverage",
    severity: "high",
    owner: SCAN_COVERAGE,
    surfaces: ["scheduled_scans", "scans", "asset_groups", "hosts", "users", "user_list"],
    inputs: [
      "scheduled_scans_readable", "active_schedule_count", "scans_readable", "asset_groups_readable", "hosts_readable", "asset_group_count",
      "host_count", "unscheduled_asset_group_count", "scanned_host_scan_age_days", "lookback_days", "undated_host_count",
      "scheduled_scans_complete", "scans_complete", "asset_groups_complete", "hosts_complete", "schedules_without_active_flag_count",
      "view_scope_partial",
    ],
    rules: [
      rule("manual", ne("scheduled_scans_readable", true)),
      rule("fail", eq("active_schedule_count", 0)),
      rule("manual", any(ne("scans_readable", true), ne("asset_groups_readable", true), ne("hosts_readable", true))),
      rule("manual", any(eq("asset_group_count", 0), eq("host_count", 0))),
      rule("warn", any(
        gt("unscheduled_asset_group_count", 0),
        some("scanned_host_scan_age_days", gt("$", path("lookback_days"))),
        gt("undated_host_count", 0),
      )),
      rule("warn", any(
        ne("scheduled_scans_complete", true),
        ne("scans_complete", true),
        ne("asset_groups_complete", true),
        ne("hosts_complete", true),
        gt("schedules_without_active_flag_count", 0),
        scopePartial,
      )),
      rule("pass", always),
    ],
    completeness: {
      scheduled_scans_complete: SCHEDULES_COMPLETE,
      scans_complete: continuationComplete("scans", "list of scans launched in the lookback window", "5000 scans"),
      asset_groups_complete: continuationComplete("asset_groups", "asset group list", "5000 groups"),
      hosts_complete: HOSTS_COMPLETE,
    },
    decision: "Manual when the scan schedule list is unreadable. Fail when no scan schedule is active. Manual when the scan, asset group, or host list is unreadable, or when no asset group or no host is returned. Warn when an asset group is not targeted by any active schedule, when a scanned host's last scan is more than lookback_days old, or when a host carries no scan date. Warn instead of pass when any of the four lists stopped early, when a schedule's ACTIVE flag is missing or unrecognized, or when the configured user's view covers only part of the subscription. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Every asset group is scheduled and every scanned host was scanned inside the lookback window.", {
        scheduled_scans_readable: true, active_schedule_count: 2, scans_readable: true, asset_groups_readable: true, hosts_readable: true,
        asset_group_count: 3, host_count: 40, unscheduled_asset_group_count: 0, scanned_host_scan_age_days: [3, 30], lookback_days: 30,
        undated_host_count: 0, scheduled_scans_complete: true, scans_complete: true, asset_groups_complete: true, hosts_complete: true,
        schedules_without_active_flag_count: 0, view_scope_partial: false,
      }),
      example("noncompliant", "fail", "No schedule is active, which fails even though the scan list was refused.", {
        scheduled_scans_readable: true, active_schedule_count: 0, scans_readable: false,
      }),
      example("partial", "warn", "One scanned host was last scanned 31 days ago, past the 30-day lookback.", {
        scheduled_scans_readable: true, active_schedule_count: 2, scans_readable: true, asset_groups_readable: true, hosts_readable: true,
        asset_group_count: 3, host_count: 40, unscheduled_asset_group_count: 0, scanned_host_scan_age_days: [3, 31], lookback_days: 30,
        undated_host_count: 0, scheduled_scans_complete: true, scans_complete: true, asset_groups_complete: true, hosts_complete: true,
        schedules_without_active_flag_count: 0, view_scope_partial: false,
      }),
      example("unreadable", "manual", "The scan schedule list was refused.", { scheduled_scans_readable: false }),
    ],
  },
  {
    id: "QUALYS-C02",
    control: 2,
    title: "Authenticated scan ratio",
    severity: "high",
    owner: SCAN_COVERAGE,
    surfaces: ["hosts", "users", "user_list"],
    inputs: [
      "hosts_readable", "host_count", "scanned_host_count", "authenticated_scan_percent", "min_auth_scan_percent", "hosts_complete",
      "undated_host_count", "view_scope_partial",
    ],
    rules: [
      rule("manual", ne("hosts_readable", true)),
      rule("manual", eq("host_count", 0)),
      rule("fail", eq("scanned_host_count", 0)),
      rule("fail", lt("authenticated_scan_percent", path("min_auth_scan_percent"))),
      rule("warn", any(ne("hosts_complete", true), gt("undated_host_count", 0), scopePartial)),
      rule("pass", always),
    ],
    completeness: { hosts_complete: HOSTS_COMPLETE },
    decision: "Manual when the host list is unreadable or returns no host. Fail when no host carries a scan date, or when the share of scanned hosts with an authenticated scan no older than the larger of lookback_days and 30 days is below min_auth_scan_percent. Warn instead of pass when the host list stopped early, when a host carries no scan date, or when the configured user's view covers only part of the subscription. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Exactly the minimum share of scanned hosts had a recent authenticated scan.", {
        hosts_readable: true, host_count: 10, scanned_host_count: 10, authenticated_scan_percent: 80, min_auth_scan_percent: 80,
        hosts_complete: true, undated_host_count: 0, view_scope_partial: false,
      }),
      example("noncompliant", "fail", "Only 70 percent of scanned hosts had a recent authenticated scan.", {
        hosts_readable: true, host_count: 10, scanned_host_count: 10, authenticated_scan_percent: 70, min_auth_scan_percent: 80,
        hosts_complete: true, undated_host_count: 0, view_scope_partial: false,
      }),
      example("partial", "warn", "The ratio meets the minimum, but one host carries no scan date.", {
        hosts_readable: true, host_count: 10, scanned_host_count: 9, authenticated_scan_percent: 88.9, min_auth_scan_percent: 80,
        hosts_complete: true, undated_host_count: 1, view_scope_partial: false,
      }),
      example("unreadable", "manual", "The host list was refused.", { hosts_readable: false }),
    ],
  },
  {
    id: "QUALYS-C03",
    control: 3,
    title: "Scan option profile review",
    severity: "medium",
    owner: SCAN_COVERAGE,
    surfaces: ["option_profiles"],
    inputs: ["option_profiles_readable", "option_profile_count"],
    rules: [
      rule("manual", ne("option_profiles_readable", true)),
      rule("fail", eq("option_profile_count", 0)),
      rule("warn", always),
    ],
    decision: "Manual when the option profile list is unreadable. Fail when no option profile is returned. Otherwise warn, because the profiles' scan settings need a reviewer.",
    examples: [
      example("noncompliant", "fail", "No option profile is returned.", { option_profiles_readable: true, option_profile_count: 0 }),
      example("partial", "warn", "Option profiles exist and await review.", { option_profiles_readable: true, option_profile_count: 4 }),
      example("unreadable", "manual", "The option profile list was refused.", { option_profiles_readable: false }),
    ],
  },
  {
    id: "QUALYS-C14",
    control: 14,
    title: "External scanner configuration",
    severity: "medium",
    owner: SCAN_COVERAGE,
    surfaces: ["scheduled_scans", "users", "user_list"],
    inputs: [
      "scheduled_scans_readable", "active_schedule_count", "external_scanner_schedule_count", "scheduled_scans_complete", "view_scope_partial",
    ],
    rules: [
      rule("manual", ne("scheduled_scans_readable", true)),
      rule("fail", eq("active_schedule_count", 0)),
      rule("warn", eq("external_scanner_schedule_count", 0)),
      rule("warn", any(ne("scheduled_scans_complete", true), scopePartial)),
      rule("pass", always),
    ],
    completeness: { scheduled_scans_complete: SCHEDULES_COMPLETE },
    decision: "Manual when the scan schedule list is unreadable. Fail when no scan schedule is active. Warn when no active schedule runs on the External Scanner. Warn instead of pass when the schedule list stopped early or when the configured user's view covers only part of the subscription. Otherwise pass.",
    examples: [
      example("compliant", "pass", "An active schedule runs on the External Scanner.", {
        scheduled_scans_readable: true, active_schedule_count: 3, external_scanner_schedule_count: 1, scheduled_scans_complete: true,
        view_scope_partial: false,
      }),
      example("noncompliant", "fail", "No schedule is active.", { scheduled_scans_readable: true, active_schedule_count: 0 }),
      example("partial", "warn", "Active schedules exist, but none runs on the External Scanner.", {
        scheduled_scans_readable: true, active_schedule_count: 3, external_scanner_schedule_count: 0, scheduled_scans_complete: true,
        view_scope_partial: false,
      }),
      example("unreadable", "manual", "The scan schedule list was refused.", { scheduled_scans_readable: false }),
    ],
  },
  {
    id: "QUALYS-C16",
    control: 16,
    title: "Exclusion list review",
    severity: "medium",
    owner: SCAN_COVERAGE,
    surfaces: ["excluded_ips", "option_profiles", "users", "user_list"],
    inputs: [
      "excluded_ips_readable", "excluded_range_address_counts", "option_profiles_readable", "excluded_entry_count",
      "detection_exclusion_list_count", "option_profile_count", "excluded_ips_complete", "option_profiles_complete", "view_scope_partial",
    ],
    constants: { broad_exclusion_address_count: 256 },
    rules: [
      rule("manual", ne("excluded_ips_readable", true)),
      rule("fail", some("excluded_range_address_counts", gt("$", path("broad_exclusion_address_count")))),
      rule("manual", ne("option_profiles_readable", true)),
      rule("warn", any(gt("excluded_entry_count", 0), gt("detection_exclusion_list_count", 0))),
      rule("manual", eq("option_profile_count", 0)),
      rule("warn", any(ne("excluded_ips_complete", true), ne("option_profiles_complete", true), scopePartial)),
      rule("pass", always),
    ],
    completeness: {
      excluded_ips_complete: completeFrom(
        "false when the excluded IP list carried a WARNING/URL continuation, which is not followed.",
        [{ surfaceId: "excluded_ips", falseWhen: ["truncated"] }],
      ),
      option_profiles_complete: OPTION_PROFILES_COMPLETE,
    },
    decision: "Manual when the excluded IP list is unreadable. Fail when an excluded IP range covers more than broad_exclusion_address_count (256) addresses. Manual when the option profile list is unreadable. Warn when any IP is excluded or any option profile carries a custom detection exclusion list. Manual when no option profile is returned. Warn instead of pass when either list stopped early or when the configured user's view covers only part of the subscription. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Nothing is excluded from scanning or detection.", {
        excluded_ips_readable: true, excluded_range_address_counts: [], option_profiles_readable: true, excluded_entry_count: 0,
        detection_exclusion_list_count: 0, option_profile_count: 2, excluded_ips_complete: true, option_profiles_complete: true,
        view_scope_partial: false,
      }),
      example("noncompliant", "fail", "A 512-address range is excluded, which fails even though the option profiles were refused.", {
        excluded_ips_readable: true, excluded_range_address_counts: [512], option_profiles_readable: false,
      }),
      example("partial", "warn", "A 256-address range is excluded and needs review.", {
        excluded_ips_readable: true, excluded_range_address_counts: [256], option_profiles_readable: true, excluded_entry_count: 1,
        detection_exclusion_list_count: 0, option_profile_count: 2, excluded_ips_complete: true, option_profiles_complete: true,
        view_scope_partial: false,
      }),
      example("unreadable", "manual", "The excluded IP list was refused.", { excluded_ips_readable: false }),
    ],
  },
  {
    id: "QUALYS-C20",
    control: 20,
    title: "Network segmentation scanning",
    severity: "medium",
    owner: SCAN_COVERAGE,
    surfaces: ["scheduled_scans"],
    inputs: ["scheduled_scans_readable", "active_schedule_count"],
    rules: [
      rule("manual", ne("scheduled_scans_readable", true)),
      rule("fail", eq("active_schedule_count", 0)),
      rule("warn", always),
    ],
    decision: "Manual when the scan schedule list is unreadable. Fail when no scan schedule is active. Otherwise warn, because whether the active schedules reach every network segment needs a reviewer.",
    examples: [
      example("noncompliant", "fail", "No schedule is active.", { scheduled_scans_readable: true, active_schedule_count: 0 }),
      example("partial", "warn", "Active schedules exist and their segment coverage awaits review.", {
        scheduled_scans_readable: true, active_schedule_count: 2,
      }),
      example("unreadable", "manual", "The scan schedule list was refused.", { scheduled_scans_readable: false }),
    ],
  },
];

const ASSET_INVENTORY = "qualys_assess_asset_inventory";

const ASSET_INVENTORY_CHECKS: readonly QualysCheck[] = [
  {
    id: "QUALYS-C04",
    control: 4,
    title: "Asset group completeness",
    severity: "medium",
    owner: ASSET_INVENTORY,
    surfaces: ["asset_groups", "hosts"],
    inputs: [],
    rules: [rule("manual", always)],
    decision: "Always return manual, because whether the asset groups hold every host the organization owns needs a reviewer.",
    examples: [example("partial", "manual", "Group coverage is left to a reviewer whatever the lists hold.", {})],
  },
  {
    id: "QUALYS-C05",
    control: 5,
    title: "Cloud connector status",
    severity: "medium",
    owner: ASSET_INVENTORY,
    surfaces: ["connectors", "users", "user_list"],
    inputs: [
      "connectors_readable", "connector_count", "unhealthy_connector_count", "connector_sync_age_days", "unknown_state_connector_count",
      "undated_connector_count", "connectors_complete", "view_scope_partial",
    ],
    constants: { stale_connector_days: 7 },
    rules: [
      rule("manual", ne("connectors_readable", true)),
      rule("manual", eq("connector_count", 0)),
      rule("fail", gt("unhealthy_connector_count", 0)),
      rule("warn", some("connector_sync_age_days", gt("$", path("stale_connector_days")))),
      rule("warn", any(
        gt("unknown_state_connector_count", 0),
        gt("undated_connector_count", 0),
        ne("connectors_complete", true),
        scopePartial,
      )),
      rule("pass", always),
    ],
    completeness: {
      connectors_complete: completeFrom(
        "false when the connector search stopped with more records left: at 5000 connectors, at the 25-page cap, or on a page without lastId.",
        [{ surfaceId: "connectors", falseWhen: ["truncated"] }],
      ),
    },
    decision: "Manual when the connector search is unreadable or returns no connector. Fail when a connector's state contains ERROR, DISABLED, or INCOMPLETE, when it is disabled, or when it reports a last error. Warn when a connector last synced more than stale_connector_days (7) days ago. Warn instead of pass when a healthy connector's state is UNKNOWN or it carries no sync date, when the search stopped early, or when the configured user's view covers only part of the subscription. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Every connector is healthy and synced within 7 days.", {
        connectors_readable: true, connector_count: 2, unhealthy_connector_count: 0, connector_sync_age_days: [1, 7],
        unknown_state_connector_count: 0, undated_connector_count: 0, connectors_complete: true, view_scope_partial: false,
      }),
      example("noncompliant", "fail", "A connector reports an error state.", {
        connectors_readable: true, connector_count: 2, unhealthy_connector_count: 1, connector_sync_age_days: [1],
      }),
      example("partial", "warn", "A healthy connector last synced 8 days ago.", {
        connectors_readable: true, connector_count: 2, unhealthy_connector_count: 0, connector_sync_age_days: [1, 8],
        unknown_state_connector_count: 0, undated_connector_count: 0, connectors_complete: true, view_scope_partial: false,
      }),
      example("unreadable", "manual", "The connector search was refused.", { connectors_readable: false }),
    ],
  },
  {
    id: "QUALYS-C06",
    control: 6,
    title: "Scanner appliance health",
    severity: "high",
    owner: ASSET_INVENTORY,
    surfaces: ["appliances", "users", "user_list"],
    inputs: [
      "appliances_readable", "appliance_count", "offline_appliance_count", "outdated_appliance_count", "unknown_status_appliance_count",
      "unknown_version_appliance_count", "appliances_complete", "view_scope_partial",
    ],
    rules: [
      rule("manual", ne("appliances_readable", true)),
      rule("manual", eq("appliance_count", 0)),
      rule("fail", gt("offline_appliance_count", 0)),
      rule("warn", gt("outdated_appliance_count", 0)),
      rule("warn", any(
        gt("unknown_status_appliance_count", 0),
        gt("unknown_version_appliance_count", 0),
        ne("appliances_complete", true),
        scopePartial,
      )),
      rule("pass", always),
    ],
    completeness: { appliances_complete: continuationComplete("appliances", "scanner appliance list", "5000 appliances") },
    decision: "Manual when the scanner appliance list is unreadable or returns no appliance. Fail when an appliance is offline, inactive, or disconnected. Warn when an appliance that is not offline has missed heartbeats or runs an outdated ML or vulnerability signature version. Warn instead of pass when an appliance's status is missing or unknown, when its versions cannot be compared, when the list stopped early, or when the configured user's view covers only part of the subscription. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Every appliance is online and current.", {
        appliances_readable: true, appliance_count: 2, offline_appliance_count: 0, outdated_appliance_count: 0,
        unknown_status_appliance_count: 0, unknown_version_appliance_count: 0, appliances_complete: true, view_scope_partial: false,
      }),
      example("noncompliant", "fail", "An appliance is offline.", {
        appliances_readable: true, appliance_count: 2, offline_appliance_count: 1, outdated_appliance_count: 1,
      }),
      example("partial", "warn", "An online appliance runs an outdated vulnerability signature version.", {
        appliances_readable: true, appliance_count: 2, offline_appliance_count: 0, outdated_appliance_count: 1,
        unknown_status_appliance_count: 0, unknown_version_appliance_count: 0, appliances_complete: true, view_scope_partial: false,
      }),
      example("unreadable", "manual", "The appliance list was refused.", { appliances_readable: false }),
    ],
  },
  {
    id: "QUALYS-C07",
    control: 7,
    title: "Agent deployment coverage",
    severity: "medium",
    owner: ASSET_INVENTORY,
    surfaces: ["hosts", "cloud_agents", "users", "user_list"],
    inputs: [
      "hosts_readable", "cloud_agents_readable", "host_count", "agent_coverage_percent", "min_agent_coverage_percent", "inactive_agent_count",
      "agent_checkin_age_days", "untracked_host_count", "unknown_status_agent_count", "undated_agent_count",
      "agents_without_activation_key_count", "hosts_complete", "cloud_agents_complete", "view_scope_partial",
    ],
    constants: { stale_agent_days: 7 },
    rules: [
      rule("manual", any(ne("hosts_readable", true), ne("cloud_agents_readable", true))),
      rule("manual", eq("host_count", 0)),
      rule("fail", lt("agent_coverage_percent", path("min_agent_coverage_percent"))),
      rule("warn", any(gt("inactive_agent_count", 0), some("agent_checkin_age_days", gt("$", path("stale_agent_days"))))),
      rule("warn", any(
        gt("untracked_host_count", 0),
        gt("unknown_status_agent_count", 0),
        gt("undated_agent_count", 0),
        gt("agents_without_activation_key_count", 0),
        ne("hosts_complete", true),
        ne("cloud_agents_complete", true),
        scopePartial,
      )),
      rule("pass", always),
    ],
    completeness: {
      hosts_complete: HOSTS_COMPLETE,
      cloud_agents_complete: completeFrom(
        "false when the cloud agent search stopped with more records left: at host_limit agents, at the 25-page cap, or on a page without lastId.",
        [{ surfaceId: "cloud_agents", falseWhen: ["truncated"] }],
      ),
    },
    decision: "Manual when the host list or the cloud agent search is unreadable, or when no host is returned. Fail when the share of hosts tracked by agent is below min_agent_coverage_percent. Warn when an agent is inactive or uninstalled, or last checked in more than stale_agent_days (7) days ago. Warn instead of pass when a host has no tracking method, when an agent's status is unknown or it carries no check-in date or activation key, when either list stopped early, or when the configured user's view covers only part of the subscription. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Exactly the minimum share of hosts is agent-tracked and every agent checked in within 7 days.", {
        hosts_readable: true, cloud_agents_readable: true, host_count: 10, agent_coverage_percent: 50, min_agent_coverage_percent: 50,
        inactive_agent_count: 0, agent_checkin_age_days: [0, 7], untracked_host_count: 0, unknown_status_agent_count: 0,
        undated_agent_count: 0, agents_without_activation_key_count: 0, hosts_complete: true, cloud_agents_complete: true,
        view_scope_partial: false,
      }),
      example("noncompliant", "fail", "Only 40 percent of hosts are agent-tracked.", {
        hosts_readable: true, cloud_agents_readable: true, host_count: 10, agent_coverage_percent: 40, min_agent_coverage_percent: 50,
      }),
      example("partial", "warn", "Coverage meets the minimum, but one agent last checked in 8 days ago.", {
        hosts_readable: true, cloud_agents_readable: true, host_count: 10, agent_coverage_percent: 60, min_agent_coverage_percent: 50,
        inactive_agent_count: 0, agent_checkin_age_days: [0, 8], untracked_host_count: 0, unknown_status_agent_count: 0,
        undated_agent_count: 0, agents_without_activation_key_count: 0, hosts_complete: true, cloud_agents_complete: true,
        view_scope_partial: false,
      }),
      example("unreadable", "manual", "The cloud agent search was refused.", { hosts_readable: true, cloud_agents_readable: false }),
    ],
  },
  {
    id: "QUALYS-C18",
    control: 18,
    title: "Tag-based asset management",
    severity: "medium",
    owner: ASSET_INVENTORY,
    surfaces: ["tags", "hosts", "users", "user_list"],
    inputs: [
      "tags_readable", "hosts_readable", "tag_count", "host_count", "untagged_host_percent", "tags_complete", "hosts_complete",
      "view_scope_partial",
    ],
    constants: { max_untagged_host_percent: 20 },
    rules: [
      rule("manual", any(ne("tags_readable", true), ne("hosts_readable", true))),
      rule("fail", eq("tag_count", 0)),
      rule("manual", eq("host_count", 0)),
      rule("fail", gt("untagged_host_percent", path("max_untagged_host_percent"))),
      rule("warn", gt("untagged_host_percent", 0)),
      rule("warn", any(ne("tags_complete", true), ne("hosts_complete", true), scopePartial)),
      rule("pass", always),
    ],
    completeness: {
      tags_complete: completeFrom(
        "false when the tag search stopped with more records left: at 2000 tags, at the 25-page cap, or on a page without lastId.",
        [{ surfaceId: "tags", falseWhen: ["truncated"] }],
      ),
      hosts_complete: HOSTS_COMPLETE,
    },
    decision: "Manual when the tag search or the host list is unreadable. Fail when no tag is returned. Manual when no host is returned. Fail when more than max_untagged_host_percent (20) percent of hosts carry no tag. Warn when the rounded share of untagged hosts is above 0. Warn instead of pass when either list stopped early or when the configured user's view covers only part of the subscription. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Every host carries a tag.", {
        tags_readable: true, hosts_readable: true, tag_count: 12, host_count: 40, untagged_host_percent: 0, tags_complete: true,
        hosts_complete: true, view_scope_partial: false,
      }),
      example("noncompliant", "fail", "20.5 percent of hosts carry no tag.", {
        tags_readable: true, hosts_readable: true, tag_count: 12, host_count: 200, untagged_host_percent: 20.5,
      }),
      example("partial", "warn", "Exactly 20 percent of hosts carry no tag.", {
        tags_readable: true, hosts_readable: true, tag_count: 12, host_count: 40, untagged_host_percent: 20, tags_complete: true,
        hosts_complete: true, view_scope_partial: false,
      }),
      example("unreadable", "manual", "The tag search was refused.", { tags_readable: false, hosts_readable: true }),
    ],
  },
];

const VULNERABILITY_MANAGEMENT = "qualys_assess_vulnerability_management";

const DETECTIONS_COMPLETE = continuationComplete("detections", "detection list", "detection_limit detections");

const VULNERABILITY_CHECKS: readonly QualysCheck[] = [
  {
    id: "QUALYS-C08",
    control: 8,
    title: "Authentication record completeness",
    severity: "high",
    owner: VULNERABILITY_MANAGEMENT,
    surfaces: ["auth_records", "hosts", "users", "user_list"],
    inputs: [
      "auth_records_readable", "hosts_readable", "auth_record_type_count", "host_count", "uncovered_os_family_count", "scanned_host_count",
      "authenticated_scan_percent", "min_auth_scan_percent", "os_unknown_host_count", "auth_records_complete", "hosts_complete",
      "view_scope_partial",
    ],
    rules: [
      rule("manual", any(ne("auth_records_readable", true), ne("hosts_readable", true))),
      rule("fail", eq("auth_record_type_count", 0)),
      rule("manual", eq("host_count", 0)),
      rule("fail", gt("uncovered_os_family_count", 0)),
      rule("fail", eq("scanned_host_count", 0)),
      rule("warn", lt("authenticated_scan_percent", path("min_auth_scan_percent"))),
      rule("warn", any(gt("os_unknown_host_count", 0), ne("auth_records_complete", true), ne("hosts_complete", true), scopePartial)),
      rule("pass", always),
    ],
    completeness: {
      auth_records_complete: completeFrom(
        "false when the authentication record summary carried a WARNING/URL continuation, which is not followed.",
        [{ surfaceId: "auth_records", falseWhen: ["truncated"] }],
      ),
      hosts_complete: HOSTS_COMPLETE,
    },
    decision: "Manual when the authentication record summary or the host list is unreadable. Fail when no authentication record technology holds a record. Manual when no host is returned. Fail when hosts run an operating system family (Windows, Unix-like, or network device) that no authentication record technology covers, or when no host carries a scan date. Warn when the share of scanned hosts with an authenticated scan no older than the larger of lookback_days and 30 days is below min_auth_scan_percent. Warn instead of pass when a host reports no operating system, when either list stopped early, or when the configured user's view covers only part of the subscription. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Every host family is covered and exactly the minimum share of hosts had a recent authenticated scan.", {
        auth_records_readable: true, hosts_readable: true, auth_record_type_count: 2, host_count: 10, uncovered_os_family_count: 0,
        scanned_host_count: 10, authenticated_scan_percent: 80, min_auth_scan_percent: 80, os_unknown_host_count: 0,
        auth_records_complete: true, hosts_complete: true, view_scope_partial: false,
      }),
      example("noncompliant", "fail", "Windows hosts exist but no Windows authentication record does.", {
        auth_records_readable: true, hosts_readable: true, auth_record_type_count: 1, host_count: 10, uncovered_os_family_count: 1,
      }),
      example("partial", "warn", "Every family is covered, but only 79.9 percent of scanned hosts had a recent authenticated scan.", {
        auth_records_readable: true, hosts_readable: true, auth_record_type_count: 2, host_count: 10, uncovered_os_family_count: 0,
        scanned_host_count: 10, authenticated_scan_percent: 79.9, min_auth_scan_percent: 80, os_unknown_host_count: 0,
        auth_records_complete: true, hosts_complete: true, view_scope_partial: false,
      }),
      example("unreadable", "manual", "The authentication record summary was refused.", { auth_records_readable: false, hosts_readable: true }),
    ],
  },
  {
    id: "QUALYS-C09",
    control: 9,
    title: "Policy compliance profile assignment",
    severity: "medium",
    owner: VULNERABILITY_MANAGEMENT,
    surfaces: ["compliance_policies", "users", "user_list"],
    inputs: [
      "compliance_policies_readable", "policy_count", "unassigned_active_policy_count", "inactive_policy_count", "unknown_status_policy_count",
      "hidden_asset_group_policy_count", "compliance_policies_complete", "view_scope_partial",
    ],
    rules: [
      rule("manual", ne("compliance_policies_readable", true)),
      rule("manual", eq("policy_count", 0)),
      rule("fail", gt("unassigned_active_policy_count", 0)),
      rule("warn", gt("inactive_policy_count", 0)),
      rule("warn", any(
        gt("unknown_status_policy_count", 0),
        gt("hidden_asset_group_policy_count", 0),
        ne("compliance_policies_complete", true),
        scopePartial,
      )),
      rule("pass", always),
    ],
    completeness: {
      compliance_policies_complete: continuationComplete("compliance_policies", "compliance policy list", "5000 policies"),
    },
    decision: "Manual when the compliance policy list is unreadable or returns no policy. Fail when an active policy is assigned no asset group or tag. Warn when a policy is inactive, draft, or disabled. Warn instead of pass when a policy's status is missing or unrecognized, when a policy's asset groups include ones hidden from the configured user, when the list stopped early, or when the configured user's view covers only part of the subscription. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Every policy is active and assigned.", {
        compliance_policies_readable: true, policy_count: 3, unassigned_active_policy_count: 0, inactive_policy_count: 0,
        unknown_status_policy_count: 0, hidden_asset_group_policy_count: 0, compliance_policies_complete: true, view_scope_partial: false,
      }),
      example("noncompliant", "fail", "An active policy is assigned no asset group or tag.", {
        compliance_policies_readable: true, policy_count: 3, unassigned_active_policy_count: 1,
      }),
      example("partial", "warn", "A draft policy awaits review.", {
        compliance_policies_readable: true, policy_count: 3, unassigned_active_policy_count: 0, inactive_policy_count: 1,
      }),
      example("unreadable", "manual", "The compliance policy list was refused.", { compliance_policies_readable: false }),
    ],
  },
  {
    id: "QUALYS-C10",
    control: 10,
    title: "Vulnerability SLA adherence",
    severity: "critical",
    owner: VULNERABILITY_MANAGEMENT,
    surfaces: ["detections", "hosts", "users", "user_list"],
    inputs: [
      "detections_readable", "hosts_readable", "host_count", "sla_scoped_detection_count", "detections_complete", "sla_compliance_percent",
      "undated_sla_detection_count", "unrated_open_detection_count", "statusless_open_detection_count", "hosts_complete", "view_scope_partial",
    ],
    constants: { sla_fail_below_percent: 80, sla_warn_below_percent: 95 },
    rules: [
      rule("manual", any(ne("detections_readable", true), ne("hosts_readable", true))),
      rule("manual", eq("host_count", 0)),
      rule("manual", all(eq("sla_scoped_detection_count", 0), ne("detections_complete", true))),
      rule("fail", lt("sla_compliance_percent", path("sla_fail_below_percent"))),
      rule("warn", lt("sla_compliance_percent", path("sla_warn_below_percent"))),
      rule("warn", any(
        gt("undated_sla_detection_count", 0),
        gt("unrated_open_detection_count", 0),
        gt("statusless_open_detection_count", 0),
        ne("detections_complete", true),
        ne("hosts_complete", true),
        scopePartial,
      )),
      rule("pass", always),
    ],
    completeness: { detections_complete: DETECTIONS_COMPLETE, hosts_complete: HOSTS_COMPLETE },
    decision: "Manual when the detection or host list is unreadable, or when no host is returned. Manual when no open detection of severity 3 or higher is returned and the detection list stopped early. Fail when fewer than sla_fail_below_percent (80) percent of dated open detections of severity 3 or higher are within their remediation SLA (sla_critical_days for severity 5, sla_high_days for 4, sla_medium_days for 3). Warn when fewer than sla_warn_below_percent (95) percent are. Warn instead of pass when such a detection carries no first-found date, when an open detection has no severity or status, when either list stopped early, or when the configured user's view covers only part of the subscription. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Exactly 95 percent of dated detections are within their SLA.", {
        detections_readable: true, hosts_readable: true, host_count: 10, sla_scoped_detection_count: 20, detections_complete: true,
        sla_compliance_percent: 95, undated_sla_detection_count: 0, unrated_open_detection_count: 0, statusless_open_detection_count: 0,
        hosts_complete: true, view_scope_partial: false,
      }),
      example("noncompliant", "fail", "Only 75 percent of dated detections are within their SLA.", {
        detections_readable: true, hosts_readable: true, host_count: 10, sla_scoped_detection_count: 20, detections_complete: true,
        sla_compliance_percent: 75,
      }),
      example("partial", "warn", "Exactly 80 percent of dated detections are within their SLA.", {
        detections_readable: true, hosts_readable: true, host_count: 10, sla_scoped_detection_count: 20, detections_complete: true,
        sla_compliance_percent: 80,
      }),
      example("unreadable", "manual", "The detection list was refused.", { detections_readable: false, hosts_readable: true }),
    ],
  },
  {
    id: "QUALYS-C11",
    control: 11,
    title: "Patch management tracking",
    severity: "high",
    owner: VULNERABILITY_MANAGEMENT,
    surfaces: ["detections", "hosts", "knowledge_base", "users", "user_list"],
    inputs: [
      "detections_readable", "hosts_readable", "knowledge_base_readable", "open_qid_count", "knowledge_base_qid_count", "host_count",
      "open_detection_count", "detections_complete", "overdue_patchable_percent", "overdue_patchable_detection_count",
      "undated_patchable_detection_count", "unresolved_qid_count", "hosts_complete", "knowledge_base_complete", "view_scope_partial",
    ],
    constants: { max_overdue_patchable_percent: 25 },
    rules: [
      rule("manual", any(ne("detections_readable", true), ne("hosts_readable", true), ne("knowledge_base_readable", true))),
      rule("manual", all(gt("open_qid_count", 0), eq("knowledge_base_qid_count", 0))),
      rule("manual", eq("host_count", 0)),
      rule("manual", all(eq("open_detection_count", 0), ne("detections_complete", true))),
      rule("fail", gt("overdue_patchable_percent", path("max_overdue_patchable_percent"))),
      rule("warn", gt("overdue_patchable_detection_count", 0)),
      rule("warn", any(
        gt("undated_patchable_detection_count", 0),
        gt("unresolved_qid_count", 0),
        ne("detections_complete", true),
        ne("hosts_complete", true),
        ne("knowledge_base_complete", true),
        scopePartial,
      )),
      rule("pass", always),
    ],
    completeness: {
      detections_complete: DETECTIONS_COMPLETE,
      hosts_complete: HOSTS_COMPLETE,
      knowledge_base_complete: completeFrom(
        "false when more than 2000 distinct open QIDs left the rest unrequested, or when a 200-QID batch stopped with a WARNING/URL continuation left; true when no lookup was needed.",
        [{ surfaceId: "knowledge_base", falseWhen: ["truncated"] }],
      ),
    },
    decision: "Manual when the detection list, the host list, or the knowledge base lookup is unreadable, when the lookup returned none of the open QIDs, or when no host is returned. Manual when no open detection is returned and the detection list stopped early. Fail when more than max_overdue_patchable_percent (25) percent of dated patchable open detections were first found more than sla_high_days days ago. Warn when any was. Warn instead of pass when a patchable detection carries no first-found date, when an open QID has no knowledge base entry, when any of the three reads stopped early, or when the configured user's view covers only part of the subscription. Otherwise pass.",
    examples: [
      example("compliant", "pass", "No dated patchable detection is past the high-severity SLA.", {
        detections_readable: true, hosts_readable: true, knowledge_base_readable: true, open_qid_count: 5, knowledge_base_qid_count: 5,
        host_count: 10, open_detection_count: 12, detections_complete: true, overdue_patchable_percent: 0,
        overdue_patchable_detection_count: 0, undated_patchable_detection_count: 0, unresolved_qid_count: 0, hosts_complete: true,
        knowledge_base_complete: true, view_scope_partial: false,
      }),
      example("noncompliant", "fail", "30 percent of dated patchable detections are overdue.", {
        detections_readable: true, hosts_readable: true, knowledge_base_readable: true, open_qid_count: 5, knowledge_base_qid_count: 5,
        host_count: 10, open_detection_count: 12, detections_complete: true, overdue_patchable_percent: 30,
        overdue_patchable_detection_count: 3,
      }),
      example("partial", "warn", "Exactly 25 percent of dated patchable detections are overdue.", {
        detections_readable: true, hosts_readable: true, knowledge_base_readable: true, open_qid_count: 5, knowledge_base_qid_count: 5,
        host_count: 10, open_detection_count: 12, detections_complete: true, overdue_patchable_percent: 25,
        overdue_patchable_detection_count: 2,
      }),
      example("unreadable", "manual", "The knowledge base lookup returned none of the open QIDs.", {
        detections_readable: true, hosts_readable: true, knowledge_base_readable: true, open_qid_count: 5, knowledge_base_qid_count: 0,
      }),
    ],
  },
  {
    id: "QUALYS-C17",
    control: 17,
    title: "Vulnerability prioritization (QDS)",
    severity: "medium",
    owner: VULNERABILITY_MANAGEMENT,
    surfaces: ["detections"],
    inputs: ["detections_readable", "open_detection_count", "qds_detection_percent"],
    rules: [
      rule("manual", ne("detections_readable", true)),
      rule("manual", eq("open_detection_count", 0)),
      rule("fail", lte("qds_detection_percent", 0)),
      rule("warn", always),
    ],
    decision: "Manual when the detection list is unreadable or holds no open detection. Fail when the share of open detections carrying a QDS score rounds to 0 percent. Otherwise warn, because QDS-based prioritization needs a reviewer.",
    examples: [
      example("noncompliant", "fail", "No open detection carries a QDS score.", {
        detections_readable: true, open_detection_count: 10, qds_detection_percent: 0,
      }),
      example("partial", "warn", "Some open detections carry QDS scores.", {
        detections_readable: true, open_detection_count: 10, qds_detection_percent: 40,
      }),
      example("unreadable", "manual", "The detection list was refused.", { detections_readable: false }),
    ],
  },
];

const ADMINISTRATION = "qualys_assess_administration";

const qpsComplete = (surfaceId: string, search: string, cap: string): BatchCompletenessDefinition => completeFrom(
  `false when the ${search} stopped with more records left: at ${cap}, at the 25-page cap, or on a page without lastId.`,
  [{ surfaceId, falseWhen: ["truncated"] }],
);

const ADMINISTRATION_CHECKS: readonly QualysCheck[] = [
  {
    id: "QUALYS-C12",
    control: 12,
    title: "Report template and distribution",
    severity: "medium",
    owner: ADMINISTRATION,
    surfaces: ["scheduled_reports", "reports"],
    inputs: ["scheduled_reports_readable", "reports_readable", "active_scheduled_report_count"],
    rules: [
      rule("manual", any(ne("scheduled_reports_readable", true), ne("reports_readable", true))),
      rule("fail", eq("active_scheduled_report_count", 0)),
      rule("warn", always),
    ],
    decision: "Manual when the scheduled report list or the report list is unreadable. Fail when no returned scheduled report is active. Otherwise warn, because report templates and their distribution need a reviewer.",
    examples: [
      example("noncompliant", "fail", "No scheduled report is active.", {
        scheduled_reports_readable: true, reports_readable: true, active_scheduled_report_count: 0,
      }),
      example("partial", "warn", "Two scheduled reports are active.", {
        scheduled_reports_readable: true, reports_readable: true, active_scheduled_report_count: 2,
      }),
      example("unreadable", "manual", "The report list was refused.", { scheduled_reports_readable: true, reports_readable: false }),
    ],
  },
  {
    id: "QUALYS-C13",
    control: 13,
    title: "User role and permission audit",
    severity: "high",
    owner: ADMINISTRATION,
    surfaces: ["user_list", "users", "activity_log"],
    inputs: [
      "user_list_readable", "users_readable", "manager_count", "max_managers", "shared_email_count", "active_user_count",
      "last_login_age_days", "generic_account_count", "pending_activation_user_count", "roleless_active_user_count",
      "statusless_user_count", "undated_login_user_count", "loginless_user_count", "users_complete", "view_scope_partial",
    ],
    constants: { inactive_user_days: 90 },
    rules: [
      rule("manual", all(ne("user_list_readable", true), ne("users_readable", true))),
      rule("fail", gt("manager_count", path("max_managers"))),
      rule("fail", gt("shared_email_count", 0)),
      rule("manual", any(ne("user_list_readable", true), ne("users_readable", true))),
      rule("manual", eq("active_user_count", 0)),
      rule("warn", any(
        some("last_login_age_days", gt("$", path("inactive_user_days"))),
        gt("generic_account_count", 0),
        gt("pending_activation_user_count", 0),
      )),
      rule("warn", any(
        gt("roleless_active_user_count", 0),
        gt("statusless_user_count", 0),
        gt("undated_login_user_count", 0),
        gt("loginless_user_count", 0),
        ne("users_complete", true),
        scopePartial,
      )),
      rule("pass", always),
    ],
    completeness: { users_complete: qpsComplete("users", "QPS user search", "5000 users") },
    decision: "Manual when neither the user list nor the QPS user search is readable. Fail when more active users hold a manager, super user, or administrator role than max_managers, or when more than one active user holds the same email address. Manual when either user read is unreadable or no active user is returned. Warn when an active user last logged in more than inactive_user_days (90) days ago, when an active user's login names a shared, generic, service, admin, or test account, or when a user awaits activation. Warn instead of pass when an active user has no role or no parseable last login date, when a user list row has no status or no login, when the QPS user search stopped early, or when the configured user's view covers only part of the subscription. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Two managers, no shared email, and every active user logged in within 90 days.", {
        user_list_readable: true, users_readable: true, manager_count: 2, max_managers: 5, shared_email_count: 0, active_user_count: 10,
        last_login_age_days: [1, 30, 90], generic_account_count: 0, pending_activation_user_count: 0, roleless_active_user_count: 0,
        statusless_user_count: 0, undated_login_user_count: 0, loginless_user_count: 0, users_complete: true, view_scope_partial: false,
      }),
      example("noncompliant", "fail", "Six active users hold a manager role against a limit of five.", {
        user_list_readable: true, users_readable: true, manager_count: 6, max_managers: 5,
      }),
      example("partial", "warn", "Five managers meet the limit, but one active user last logged in 91 days ago.", {
        user_list_readable: true, users_readable: true, manager_count: 5, max_managers: 5, shared_email_count: 0, active_user_count: 10,
        last_login_age_days: [91, 4],
      }),
      example("unreadable", "manual", "Both user reads were refused.", { user_list_readable: false, users_readable: false }),
    ],
  },
  {
    id: "QUALYS-C15",
    control: 15,
    title: "Web application inventory",
    severity: "medium",
    owner: ADMINISTRATION,
    surfaces: ["was_webapps", "was_scans", "was_scan_history", "was_auth_records", "was_schedules", "users", "user_list", "activity_log"],
    inputs: [
      "was_webapps_readable", "was_scans_readable", "was_auth_records_readable", "web_app_count", "never_scanned_web_app_count",
      "resolved_web_app_scan_age_days", "lookback_days", "was_scan_history_readable", "was_schedules_readable",
      "was_auth_record_age_days", "unresolved_web_app_count", "undated_was_auth_record_count", "was_schedules_without_active_flag_count",
      "was_webapps_complete", "was_scans_complete", "was_scan_history_complete", "was_auth_records_complete", "was_schedules_complete",
      "view_scope_partial",
    ],
    constants: { stale_was_auth_days: 180 },
    rules: [
      rule("manual", any(ne("was_webapps_readable", true), ne("was_scans_readable", true), ne("was_auth_records_readable", true))),
      rule("manual", eq("web_app_count", 0)),
      rule("fail", any(
        gt("never_scanned_web_app_count", 0),
        some("resolved_web_app_scan_age_days", gt("$", path("lookback_days"))),
      )),
      rule("manual", any(ne("was_scan_history_readable", true), ne("was_schedules_readable", true))),
      rule("warn", some("was_auth_record_age_days", gt("$", path("stale_was_auth_days")))),
      rule("warn", any(
        gt("unresolved_web_app_count", 0),
        gt("undated_was_auth_record_count", 0),
        gt("was_schedules_without_active_flag_count", 0),
        ne("was_webapps_complete", true),
        ne("was_scans_complete", true),
        ne("was_scan_history_complete", true),
        ne("was_auth_records_complete", true),
        ne("was_schedules_complete", true),
        scopePartial,
      )),
      rule("pass", always),
    ],
    completeness: {
      was_webapps_complete: qpsComplete("was_webapps", "web application search", "5000 web applications"),
      was_scans_complete: qpsComplete("was_scans", "lookback scan search", "5000 scans"),
      was_scan_history_complete: completeFrom(
        "false when a history batch of up to 100 web applications stopped with more records left, or when web applications were left unrequested at 5000 scans; true when no web application needed history.",
        [{ surfaceId: "was_scan_history", falseWhen: ["truncated"] }],
      ),
      was_auth_records_complete: qpsComplete("was_auth_records", "WAS authentication record search", "5000 records"),
      was_schedules_complete: qpsComplete("was_schedules", "WAS schedule search", "5000 schedules"),
    },
    decision: "Manual when the web application search, the lookback scan search, or the WAS authentication record search is unreadable, or when no web application is returned. Fail when a web application has no finished vulnerability scan, or when its newest finished vulnerability scan is more than lookback_days days old. Manual when the scan history or the WAS schedule search is unreadable. Warn when a WAS authentication record was last updated more than stale_was_auth_days (180) days ago. Warn instead of pass when a web application's newest scan could not be resolved, when a WAS authentication record carries no date, when a WAS schedule carries no active flag, when any of the five searches stopped early, or when the configured user's view covers only part of the subscription. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Every web application had a finished vulnerability scan within 30 days.", {
        was_webapps_readable: true, was_scans_readable: true, was_auth_records_readable: true, web_app_count: 3,
        never_scanned_web_app_count: 0, resolved_web_app_scan_age_days: [2, 10, 30], lookback_days: 30, was_scan_history_readable: true,
        was_schedules_readable: true, was_auth_record_age_days: [180], unresolved_web_app_count: 0, undated_was_auth_record_count: 0,
        was_schedules_without_active_flag_count: 0, was_webapps_complete: true, was_scans_complete: true, was_scan_history_complete: true,
        was_auth_records_complete: true, was_schedules_complete: true, view_scope_partial: false,
      }),
      example("noncompliant", "fail", "One web application's newest finished scan is 31 days old.", {
        was_webapps_readable: true, was_scans_readable: true, was_auth_records_readable: true, web_app_count: 3,
        never_scanned_web_app_count: 0, resolved_web_app_scan_age_days: [31, 2], lookback_days: 30,
      }),
      example("partial", "warn", "A WAS authentication record was last updated 181 days ago.", {
        was_webapps_readable: true, was_scans_readable: true, was_auth_records_readable: true, web_app_count: 3,
        never_scanned_web_app_count: 0, resolved_web_app_scan_age_days: [2], lookback_days: 30, was_scan_history_readable: true,
        was_schedules_readable: true, was_auth_record_age_days: [181],
      }),
      example("unreadable", "manual", "The scan history for an unscanned web application was refused.", {
        was_webapps_readable: true, was_scans_readable: true, was_auth_records_readable: true, web_app_count: 3,
        never_scanned_web_app_count: 0, resolved_web_app_scan_age_days: [2], lookback_days: 30, was_scan_history_readable: false,
      }),
    ],
  },
  {
    id: "QUALYS-C19",
    control: 19,
    title: "Activity log monitoring",
    severity: "medium",
    owner: ADMINISTRATION,
    surfaces: ["activity_log"],
    inputs: ["activity_log_readable", "activity_entry_count"],
    rules: [
      rule("manual", ne("activity_log_readable", true)),
      rule("manual", eq("activity_entry_count", 0)),
      rule("warn", always),
    ],
    decision: "Manual when the activity log is unreadable or holds no row since the lookback start. Otherwise warn, because activity log monitoring needs a reviewer.",
    examples: [
      example("partial", "warn", "The activity log holds 120 rows in the lookback window.", { activity_log_readable: true, activity_entry_count: 120 }),
      example("unreadable", "manual", "The activity log was refused.", { activity_log_readable: false }),
    ],
  },
];

const toCheck = (check: QualysCheck): BatchCheckDefinition => {
  const executable = deriveDecisionRules(check.id, check.rules);
  return {
    id: check.id,
    control: check.control,
    title: check.title,
    severity: check.severity,
    owner: check.owner,
    surfaces: check.surfaces,
    evidenceFields: check.inputs,
    decisionInputs: inputs(...check.inputs),
    decisionConstants: check.constants ?? {},
    decisionRules: executable.rules,
    derivedFactRules: executable.derivedFactRules,
    ...(check.completeness ? { completeness: check.completeness } : {}),
    decision: check.decision,
    examples: check.examples,
  };
};

const checks: readonly BatchCheckDefinition[] = [
  ...SCAN_COVERAGE_CHECKS,
  ...ASSET_INVENTORY_CHECKS,
  ...VULNERABILITY_CHECKS,
  ...ADMINISTRATION_CHECKS,
].map(toCheck);
const idsFor = (owner: string): string[] => checks.filter((check) => check.owner === owner).map((check) => check.id);

const continuationStops = (cap: string): string[] => [
  "A page without a WARNING/URL continuation",
  cap,
  "The 25-page cap",
  "An empty page that still carries a continuation, which marks the list partial",
  "A continuation URL on another origin, which is not followed and marks the list partial",
];
const NO_TOTAL = "Qualys reports no total: a page without a WARNING/URL continuation ends the list, and a continuation left at the item cap or at the 25-page cap marks it partial.";
const qpsWalk = (surfaceIds: readonly string[], pages: string, itemCap: number | null, cap: string): BatchPaginationDefinition => ({
  surfaceIds,
  cursorFields: ["hasMoreRecords", "lastId"],
  pageSize: null,
  itemCap,
  pageCap: 25,
  totalSemantics: `${pages}; each continuation repeats the search with the criterion id GREATER than the previous page's lastId. hasMoreRecords, or a full page when it is absent, means more records follow; more records left at ${cap} or at the 25-page cap mark the list partial.`,
  stopConditions: [
    "hasMoreRecords false, or a page shorter than limitResults when hasMoreRecords is absent",
    "A page without lastId, which marks the list partial when more records follow",
    "An empty page",
    `${cap} collected`,
    "The 25-page cap",
  ],
});

const FRAMEWORK_REPORTS = [
  "fedramp/fedramp_compliance_report.md",
  "cmmc/cmmc_compliance_report.md",
  "soc2/soc2_compliance_report.md",
  "cis/cis_compliance_report.md",
  "pci_dss/pci_dss_compliance_report.md",
  "disa_stig/stig_compliance_checklist.md",
  "irap/irap_compliance_report.md",
  "ismap/ismap_compliance_report.md",
];

// The export runs every assessment and writes each one's raw data under its own category.
const RAW_DATA_FILES: Readonly<Record<string, readonly string[]>> = {
  scan_coverage: ["scheduled_scans", "scans", "hosts", "option_profiles", "excluded_ips", "asset_groups"],
  asset_inventory: ["asset_groups", "hosts", "connectors", "appliances", "cloud_agents", "tags"],
  vulnerability_management: ["auth_records", "hosts", "compliance_policies", "detections", "knowledge_base"],
  administration: [
    "scheduled_reports", "reports", "users", "user_list", "activity_log", "was_webapps", "was_scans", "was_scan_history", "was_auth_records",
    "was_schedules",
  ],
};

export const QUALYS_SPEC = buildBatchIntegrationSpec({
  slug: "qualys-sec-inspector",
  displayName: "Qualys Security Inspector",
  vendor: "Qualys",
  category: "vulnerability-application-security",
  summary: "Portable contract for the shipped Qualys scan coverage, asset inventory, vulnerability management, and administration assessments over the Qualys VM/PC, Administration, Asset Management, Cloud Agent, and WAS APIs.",
  sourceModule: "cli/extensions/grc-tools/qualys.ts",
  baseServices: [VM_SERVICE, ADMIN_SERVICE, AM_SERVICE, CA_SERVICE, WAS_SERVICE],
  authentication: QUALYS_AUTH_RESOLVER,
  permissions: [
    {
      id: "manager-api-access",
      kind: "role",
      value: "Qualys Manager or Super User with API access",
      unlocks: QUALYS_SURFACES.map((surface) => surface.id),
      notes: "Other roles see only the assets and objects in their scope; when the configured user is verified to hold such a role or scope tags, view_scope_partial caps otherwise passing findings at warn.",
    },
    {
      id: "cloud-agent-module",
      kind: "license",
      value: "Qualys Cloud Agent",
      unlocks: ["cloud_agents"],
    },
    {
      id: "policy-compliance-module",
      kind: "license",
      value: "Qualys Policy Compliance",
      unlocks: ["compliance_policies"],
    },
    {
      id: "web-application-scanning-module",
      kind: "license",
      value: "Qualys Web Application Scanning",
      unlocks: ["was_webapps", "was_scans", "was_scan_history", "was_auth_records", "was_schedules"],
    },
  ],
  surfaces: QUALYS_SURFACES,
  checks,
  tools: {
    qualys_check_access: [],
    qualys_assess_scan_coverage: idsFor(SCAN_COVERAGE),
    qualys_assess_asset_inventory: idsFor(ASSET_INVENTORY),
    qualys_assess_vulnerability_management: idsFor(VULNERABILITY_MANAGEMENT),
    qualys_assess_administration: idsFor(ADMINISTRATION),
    qualys_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [
    {
      surfaceIds: ["scheduled_scans", "scans", "option_profiles", "appliances", "compliance_policies", "scheduled_reports", "reports"],
      cursorFields: ["WARNING/URL"],
      pageSize: null,
      itemCap: 5000,
      pageCap: 25,
      totalSemantics: `Each page holds as many records as Qualys returns. ${NO_TOTAL}`,
      stopConditions: continuationStops("5000 records collected"),
    },
    {
      surfaceIds: ["hosts"],
      cursorFields: ["WARNING/URL"],
      pageSize: null,
      itemCap: null,
      pageCap: 25,
      totalSemantics: `Pages of the smaller of host_limit and 1000 hosts (truncation_limit), up to host_limit hosts (default 5000, set from 1 through 200000). ${NO_TOTAL}`,
      stopConditions: continuationStops("host_limit hosts collected"),
    },
    {
      surfaceIds: ["asset_groups"],
      cursorFields: ["WARNING/URL"],
      pageSize: 500,
      itemCap: 5000,
      pageCap: 25,
      totalSemantics: `Pages of 500 asset groups (truncation_limit). ${NO_TOTAL}`,
      stopConditions: continuationStops("5000 asset groups collected"),
    },
    {
      surfaceIds: ["detections"],
      cursorFields: ["WARNING/URL"],
      pageSize: null,
      itemCap: null,
      pageCap: 25,
      totalSemantics: `Pages of the smaller of detection_limit and 1000 hosts (truncation_limit), flattened to one record per detection, up to detection_limit detections (default 5000, set from 1 through 200000). ${NO_TOTAL}`,
      stopConditions: continuationStops("detection_limit detections collected"),
    },
    {
      surfaceIds: ["knowledge_base"],
      cursorFields: ["WARNING/URL", "ids"],
      pageSize: null,
      itemCap: 5000,
      pageCap: 25,
      totalSemantics: "The distinct QIDs of open detections are requested in batches of 200 (ids), at most 2000 QIDs; QIDs past 2000 are not requested and mark the lookup partial. Qualys reports no total: a page without a WARNING/URL continuation ends a batch, and a continuation left at 5000 records or at the 25-page cap marks the lookup partial.",
      stopConditions: [...continuationStops("5000 records collected in a batch"), "Every batch of up to 200 QIDs requested"],
    },
    {
      surfaceIds: ["excluded_ips", "auth_records"],
      cursorFields: ["WARNING/URL"],
      pageSize: null,
      itemCap: "none",
      pageCap: 1,
      totalSemantics: "One read; a WARNING/URL continuation is not followed and marks the list partial.",
      stopConditions: ["The first response"],
    },
    {
      surfaceIds: ["user_list"],
      cursorFields: [],
      pageSize: null,
      itemCap: "none",
      pageCap: 1,
      totalSemantics: "One read of the whole user list, which carries no continuation.",
      stopConditions: ["The first response"],
    },
    {
      surfaceIds: ["activity_log"],
      cursorFields: [],
      pageSize: 5000,
      itemCap: 5000,
      pageCap: 1,
      totalSemantics: "One read of up to 5000 rows since the lookback start (truncation_limit); 5000 rows mark the log partial, because older rows in the window may be left.",
      stopConditions: ["The first response"],
    },
    qpsWalk(["users"], "Pages of 500 users (limitResults)", 5000, "5000 users"),
    qpsWalk(
      ["connectors", "was_webapps", "was_scans", "was_auth_records", "was_schedules"],
      "Pages of 100 records (limitResults)",
      5000,
      "5000 records",
    ),
    {
      surfaceIds: ["was_scan_history"],
      cursorFields: ["webApp.id", "hasMoreRecords", "lastId"],
      pageSize: null,
      itemCap: 5000,
      pageCap: 25,
      totalSemantics: "The web applications without a finished vulnerability scan in the lookback search are requested in batches of 100 IDs (webApp.id IN), each walked in pages of 100 scans (limitResults) with the criterion id GREATER than the previous page's lastId. hasMoreRecords, or a full page when it is absent, means more records follow; a batch left with more records at the 25-page cap or on a page without lastId stops the history, and web applications left unrequested at 5000 scans mark it partial.",
      stopConditions: [
        "Every batch of up to 100 web application IDs requested",
        "A batch that stops with more records left, which marks the history partial",
        "5000 scans collected across batches, which marks the history partial when web applications are left unrequested",
      ],
    },
    qpsWalk(
      ["cloud_agents"],
      "Pages of 1000 agents (limitResults), up to host_limit agents (default 5000, set from 1 through 200000)",
      null,
      "host_limit agents",
    ),
    qpsWalk(["tags"], "Pages of 1000 tags (limitResults)", 2000, "2000 tags"),
  ],
  rateLimit: {
    documentedLimit: "Subscription-specific: responses report X-RateLimit-Limit calls per X-RateLimit-Window-Sec seconds and X-Concurrency-Limit-Limit concurrent calls.",
    retryHeaders: ["X-RateLimit-ToWait-Sec"],
    retryableStatuses: [409, 429],
    retryableStatusRanges: [{ from: 500, to: 599 }],
    backoffPolicy: "Retry 409, 429, every 5xx status, and network errors up to 3 times after the first attempt. Wait X-RateLimit-ToWait-Sec seconds when a retried response carries it as a number, otherwise 2, 4, then 8 seconds, capped at 30 seconds; Retry-After is ignored. Requests that time out (60 seconds by default) are not retried.",
  },
  runtimeBehavior: [],
  knownGaps: [
    "A WARNING/URL continuation that repeats the previous page's URL is requested again until the 25-page cap, so the list can collect duplicate records.",
    "Authentication records are summarized as a count per technology, so record status and expiry are never evaluated.",
  ],
  sensitiveFields: ["password", "token", "Authorization", "activationKey"],
  credentialFormats: ["Qualys username and password, sent as Basic authentication or exchanged at the platform gateway", "Qualys bearer token"],
  output: buildBatchOutputContract({
    files: [
      "QUICK_REFERENCE.md",
      "metadata.json",
      "core_data/access.json",
      ...Object.entries(RAW_DATA_FILES).flatMap(([category, names]) => names.map((name) => `core_data/${category}/${name}.json`)),
      ...Object.keys(RAW_DATA_FILES).map((category) => `analysis/${category}.json`),
      "analysis/findings.json",
      "compliance/executive_summary.md",
      "compliance/unified_compliance_matrix.md",
      ...FRAMEWORK_REPORTS.map((report) => `compliance/${report}`),
    ],
    conditionalFiles: ["_errors.log"],
    conditionalFileConditions: { "_errors.log": "Only when some reads fail but the bundle still completes." },
    overwritePolicy: "Allocate qualys-{platform}-audit-bundle, or the first of -2 through -99 whose directory and zip are both free, and fail rather than overwrite.",
    archivePairing: "Write a sibling zip named from the exact allocated bundle-directory path plus .zip.",
  }),
  lastUpdated: "2026-10-17",
  findingPreviewLimit: 100,
  redaction: {
    projectionStage: "Every surface keeps only its declared fields, the Qualys raw data allowlist, before evidence export, and every bundle file is scrubbed of the configured credential values.",
  },
});
