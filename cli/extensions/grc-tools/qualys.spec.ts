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
const VM_DOCS = "https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects";
const API_SERVER = "Use the configured API server (base_url, else the selected platform's API server); never follow a continuation URL to another origin.";
const AUTH_HEADER = "Authorization: {Basic base64(username:password), or Bearer token}";
const XML_HEADERS = ["X-Requested-With: grclanker", "Accept: application/xml", AUTH_HEADER];
const QPS_HEADERS = ["X-Requested-With: grclanker", "Accept: application/json", "Content-Type: application/json", AUTH_HEADER];
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
    param("launched_after_datetime", "query", "lookback_days before the assessment time, in UTC ISO 8601 without fractional seconds"),
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

const QUALYS_SURFACES: readonly BatchSurfaceDefinition[] = [
  ...SCAN_COVERAGE_SURFACES,
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
const qpsStops = (cap: string): string[] => [
  "hasMoreRecords false, or a page shorter than limitResults when hasMoreRecords is absent",
  "A page without lastId, which marks the list partial when more records follow",
  "An empty page",
  cap,
  "The 25-page cap",
];

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
  baseServices: [VM_SERVICE, ADMIN_SERVICE],
  authentication: QUALYS_AUTH_RESOLVER,
  permissions: [
    {
      id: "manager-api-access",
      kind: "role",
      value: "Qualys Manager or Super User with API access",
      unlocks: QUALYS_SURFACES.map((surface) => surface.id),
      notes: "Other roles see only the assets and objects in their scope; when the configured user is verified to hold such a role or scope tags, view_scope_partial caps otherwise passing findings at warn.",
    },
  ],
  surfaces: QUALYS_SURFACES,
  checks,
  tools: {
    qualys_check_access: [],
    qualys_assess_scan_coverage: idsFor(SCAN_COVERAGE),
    qualys_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [
    {
      surfaceIds: ["scheduled_scans", "scans", "option_profiles"],
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
      surfaceIds: ["excluded_ips"],
      cursorFields: ["WARNING/URL"],
      pageSize: null,
      itemCap: "none",
      pageCap: 1,
      totalSemantics: "One read; a WARNING/URL continuation is not followed and marks the list partial.",
      stopConditions: ["The first response"],
    },
    {
      surfaceIds: ["users"],
      cursorFields: ["hasMoreRecords", "lastId"],
      pageSize: null,
      itemCap: 5000,
      pageCap: 25,
      totalSemantics: "Pages of 500 users (limitResults); each continuation repeats the search with the criterion id GREATER than the previous page's lastId. hasMoreRecords, or a full page when it is absent, means more records follow; more records left at 5000 users or at the 25-page cap mark the list partial.",
      stopConditions: qpsStops("5000 users collected"),
    },
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
