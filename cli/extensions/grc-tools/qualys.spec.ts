import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
  restSurface,
} from "./batch-spec-builder.js";
import { QUALYS_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import { BATCH3_FRAMEWORK_FILES, batch3Checks, type Batch3CheckRow } from "./batch3-spec-helpers.js";

const DOCS = "https://docs.qualys.com/en/vm/api/";
const vm = (id: string, path: string, fields: readonly string[]) =>
  restSurface(id, path, path.startsWith("/qps/") ? "Qualys QPS REST API" : path.startsWith("/msp/") ? "Qualys Administration API" : "Qualys VM/PC API v2", DOCS, fields);

const surfaces = [
  vm("scheduled-scans", "/api/2.0/fo/schedule/scan/", ["ID", "TITLE", "ACTIVE", "SCHEDULE", "OPTION_PROFILE", "ASSET_GROUPS"]),
  vm("scans", "/api/2.0/fo/scan/", ["REF", "TITLE", "STATUS", "LAUNCH_DATETIME", "TARGET"]),
  vm("hosts", "/api/2.0/fo/asset/host/", ["ID", "IP", "LAST_SCAN_DATETIME", "TRACKING_METHOD"]),
  vm("option-profiles", "/api/2.0/fo/subscription/option_profile/vm/", ["OPTION_PROFILE.ID", "OPTION_PROFILE.TITLE", "OPTION_PROFILE.DEFAULT_FLAG", "OPTION_PROFILE.SCAN"]),
  vm("excluded-ips", "/api/2.0/fo/asset/excluded_ip/", ["IP", "COMMENT", "EXPIRATION_DATE"]),
  vm("asset-groups", "/api/2.0/fo/asset/group/", ["ID", "TITLE", "IP_SET", "APPLIANCE_IDS"]),
  vm("connectors", "/qps/rest/2.0/search/am/assetdataconnector", ["id", "name", "type", "state", "lastSync"]),
  vm("appliances", "/api/2.0/fo/appliance/", ["ID", "NAME", "STATUS", "SOFTWARE_VERSION", "LAST_CHECKIN_DATE"]),
  vm("cloud-agents", "/qps/rest/2.0/search/am/hostasset", ["id", "agentInfo", "lastUpdated", "tags"]),
  vm("tags", "/qps/rest/2.0/search/am/tag", ["id", "name", "ruleText", "assetCount"]),
  vm("auth-records", "/api/2.0/fo/auth/", ["ID", "TITLE", "TYPE", "STATUS", "LAST_SUCCESS"]),
  vm("compliance-policies", "/api/2.0/fo/compliance/policy/", ["ID", "TITLE", "STATUS", "ASSET_GROUP_IDS"]),
  vm("detections", "/api/2.0/fo/asset/host/vm/detection/", ["HOST_ID", "QID", "SEVERITY", "STATUS", "FIRST_FOUND_DATETIME", "LAST_FOUND_DATETIME", "QDS"]),
  vm("knowledge-base", "/api/2.0/fo/knowledge_base/vuln/", ["QID", "SEVERITY_LEVEL", "PATCHABLE", "SOLUTION"]),
  vm("scheduled-reports", "/api/2.0/fo/schedule/report/", ["ID", "TITLE", "ACTIVE", "SCHEDULE", "DISTRIBUTION"]),
  vm("reports", "/api/2.0/fo/report/", ["ID", "TITLE", "TYPE", "LAUNCH_DATETIME", "STATUS"]),
  vm("users", "/qps/rest/2.0/search/am/user/", ["id", "username", "role", "status", "lastLoginDate"]),
  vm("user-list", "/msp/user_list.php", ["USER_LOGIN", "USER_ROLE", "USER_STATUS", "LAST_LOGIN"]),
  vm("activity-log", "/api/2.0/fo/activity_log/", ["DATETIME", "ACTION", "USER", "DETAILS"]),
  vm("was-webapps", "/qps/rest/3.0/search/was/webapp", ["id", "name", "url", "lastScan", "authRecords"]),
  vm("was-scans", "/qps/rest/3.0/search/was/wasscan", ["id", "webApp", "status", "launchedDate", "type"]),
  vm("was-scan-history", "/qps/rest/3.0/search/was/wasscan", ["id", "webApp", "status", "launchedDate"]),
  vm("was-auth-records", "/qps/rest/3.0/search/was/webappauthrecord", ["id", "name", "type", "lastUpdated"]),
  vm("was-schedules", "/qps/rest/3.0/search/was/wasscanschedule", ["id", "name", "active", "webApp", "occurrence"]),
] as const;

const rows: readonly Batch3CheckRow[] = [
  { id: "QUALYS-C01", control: 1, title: "Scan schedule coverage", severity: "high", owner: "qualys_assess_scan_coverage", surfaces: ["scheduled-scans", "scans", "asset-groups"], predicate: "Count asset groups with no active recurring vulnerability scan and schedules whose most recent completed scan is older than lookback_days.", constants: { default_lookback_days: 30 } },
  { id: "QUALYS-C02", control: 2, title: "Authenticated scan ratio", severity: "high", owner: "qualys_assess_scan_coverage", surfaces: ["hosts", "auth-records"], predicate: "Compute hosts with successful authenticated-scan evidence divided by the complete host population; percentages below min_auth_scan_percent violate.", constants: { default_min_auth_scan_percent: 80 } },
  { id: "QUALYS-C03", control: 3, title: "Scan option profile review", severity: "medium", owner: "qualys_assess_scan_coverage", surfaces: ["option-profiles", "scheduled-scans"], predicate: "Count option profiles referenced by active schedules that omit safe checks, authenticated scanning, or documented port and performance settings." },
  { id: "QUALYS-C04", control: 4, title: "Asset group completeness", severity: "high", owner: "qualys_assess_asset_inventory", surfaces: ["hosts", "asset-groups"], predicate: "Count host assets assigned to no asset group, empty group IP sets, and group members absent from the complete host inventory." },
  { id: "QUALYS-C05", control: 5, title: "Cloud connector status", severity: "high", owner: "qualys_assess_asset_inventory", surfaces: ["connectors"], predicate: "Count cloud connectors not in an active or successful synchronization state or with no readable last-sync timestamp." },
  { id: "QUALYS-C06", control: 6, title: "Scanner appliance health", severity: "high", owner: "qualys_assess_asset_inventory", surfaces: ["appliances"], predicate: "Count scanner appliances that are offline, whose heartbeat is stale, or whose software version is absent." },
  { id: "QUALYS-C07", control: 7, title: "Agent deployment coverage", severity: "high", owner: "qualys_assess_asset_inventory", surfaces: ["hosts", "cloud-agents"], predicate: "Compute unique Cloud Agent host coverage over the complete host inventory; percentages below min_agent_coverage_percent violate.", constants: { default_min_agent_coverage_percent: 50 } },
  { id: "QUALYS-C08", control: 8, title: "Authentication record completeness", severity: "high", owner: "qualys_assess_vulnerability_management", surfaces: ["auth-records", "hosts"], predicate: "Count missing Windows, Unix/Linux, or network-device authentication record types and records whose latest status is failed or expired." },
  { id: "QUALYS-C09", control: 9, title: "Policy compliance profile assignment", severity: "high", owner: "qualys_assess_vulnerability_management", surfaces: ["compliance-policies", "asset-groups"], predicate: "Count draft or disabled compliance policies and policies with no readable asset-group assignment; no policy is a violation." },
  { id: "QUALYS-C10", control: 10, title: "Vulnerability SLA adherence", severity: "critical", owner: "qualys_assess_vulnerability_management", surfaces: ["detections", "knowledge-base"], predicate: "Count open detections older than the configurable critical, high, or medium SLA for their normalized severity.", constants: { default_sla_critical_days: 15, default_sla_high_days: 30, default_sla_medium_days: 90 } },
  { id: "QUALYS-C11", control: 11, title: "Patch management tracking", severity: "high", owner: "qualys_assess_vulnerability_management", surfaces: ["detections", "knowledge-base"], predicate: "Count open patchable detections with no solution metadata or whose first-found age exceeds the applicable remediation SLA." },
  { id: "QUALYS-C12", control: 12, title: "Report template and distribution", severity: "medium", owner: "qualys_assess_administration", surfaces: ["scheduled-reports", "reports"], predicate: "Count the absence of an active scheduled report and scheduled reports without a readable distribution target." },
  { id: "QUALYS-C13", control: 13, title: "User role and permission audit", severity: "high", owner: "qualys_assess_administration", surfaces: ["users", "user-list"], predicate: "Count active Manager or Unit Manager accounts above max_managers plus inactive or shared accounts.", constants: { default_max_managers: 5 } },
  { id: "QUALYS-C14", control: 14, title: "External scanner configuration", severity: "high", owner: "qualys_assess_scan_coverage", surfaces: ["scheduled-scans", "appliances"], predicate: "Count the absence of an active external scan schedule and schedules referencing no external scanner appliance." },
  { id: "QUALYS-C15", control: 15, title: "Web application inventory", severity: "high", owner: "qualys_assess_administration", surfaces: ["was-webapps", "was-scans", "was-scan-history", "was-auth-records", "was-schedules"], predicate: "Count web applications without an active schedule, a recent completed scan, or required authentication records." },
  { id: "QUALYS-C16", control: 16, title: "Exclusion list review", severity: "medium", owner: "qualys_assess_scan_coverage", surfaces: ["excluded-ips"], predicate: "Count exclusion entries with broad IP ranges, no expiration, or no readable comment." },
  { id: "QUALYS-C17", control: 17, title: "Vulnerability prioritization (QDS)", severity: "high", owner: "qualys_assess_vulnerability_management", surfaces: ["detections", "knowledge-base"], predicate: "Count open severe detections with no numeric QDS; an empty complete detection population passes only when the endpoint was readable." },
  { id: "QUALYS-C18", control: 18, title: "Tag-based asset management", severity: "medium", owner: "qualys_assess_asset_inventory", surfaces: ["hosts", "tags"], predicate: "Count hosts with no Qualys tag and the absence of tags identifying compliance scope, environment, or business ownership." },
  { id: "QUALYS-C19", control: 19, title: "Activity log monitoring", severity: "medium", owner: "qualys_assess_administration", surfaces: ["activity-log"], predicate: "Count sensitive user, policy, report, and scan administration actions inside lookback_days; empty activity is review evidence.", constants: { default_lookback_days: 30 } },
  { id: "QUALYS-C20", control: 20, title: "Network segmentation scanning", severity: "high", owner: "qualys_assess_scan_coverage", surfaces: ["scheduled-scans", "asset-groups"], predicate: "Count the absence of distinct active scan schedules covering separate DMZ, internal, and OT or ICS asset-group segments." },
] as const;

const checks = batch3Checks(rows);
const idsFor = (owner: string) => checks.filter((check) => check.owner === owner).map((check) => check.id);

export const QUALYS_RUNTIME_BEHAVIOR = [
  "Each collected dataset preserves endpoint, read error, not-collected dependency, module-unavailable state, truncation reason, configured cap, complete record count, and the projected records.",
  "A required module denial or absent subscription is not an empty inventory; the affected finding is manual unless another readable source already proves a violation.",
  "QPS pagination exhausts lastId and VM XML pagination exhausts WARNING next URLs before complete population counts are used.",
] as const;

const categoryFiles: Readonly<Record<string, readonly string[]>> = {
  scan_coverage: ["scheduled_scans", "scans", "hosts", "option_profiles", "excluded_ips", "asset_groups", "appliances"],
  asset_inventory: ["hosts", "asset_groups", "connectors", "appliances", "cloud_agents", "tags"],
  vulnerability_management: ["auth_records", "hosts", "compliance_policies", "asset_groups", "detections", "knowledge_base"],
  administration: ["scheduled_reports", "reports", "users", "user_list", "activity_log", "was_webapps", "was_scans", "was_scan_history", "was_auth_records", "was_schedules"],
};
const coreFiles = Object.entries(categoryFiles).flatMap(([category, names]) =>
  names.map((name) => `core_data/${category}/${name}.json`));

export const QUALYS_SPEC = buildBatchIntegrationSpec({
  slug: "qualys-sec-inspector",
  displayName: "Qualys Security Inspector",
  vendor: "Qualys",
  category: "vulnerability-management",
  summary: "Portable contract for Qualys scan coverage, asset inventory, vulnerability management, WAS, and administration assessments.",
  sourceModule: "cli/extensions/grc-tools/qualys.ts",
  baseServices: ["Qualys VM/PC API v2", "Qualys QPS REST API", "Qualys Administration API", "Qualys gateway OAuth"],
  authentication: QUALYS_AUTH_RESOLVER,
  permissions: [
    { id: "manager", kind: "role", value: "Manager", unlocks: surfaces.map((entry) => entry.id) },
    { id: "unit-manager", kind: "role", value: "Unit Manager with all assessed asset groups and subscribed modules", unlocks: surfaces.map((entry) => entry.id) },
    { id: "was-license", kind: "license", value: "Web Application Scanning subscription", unlocks: ["was-webapps", "was-scans", "was-scan-history", "was-auth-records", "was-schedules"] },
    { id: "pc-license", kind: "license", value: "Policy Compliance subscription", unlocks: ["compliance-policies"] },
  ],
  surfaces,
  checks,
  tools: {
    qualys_check_access: [],
    qualys_assess_scan_coverage: idsFor("qualys_assess_scan_coverage"),
    qualys_assess_asset_inventory: idsFor("qualys_assess_asset_inventory"),
    qualys_assess_vulnerability_management: idsFor("qualys_assess_vulnerability_management"),
    qualys_assess_administration: idsFor("qualys_assess_administration"),
    qualys_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [
    {
      surfaceIds: surfaces.filter((entry) => !["activity-log", "scheduled-reports", "reports", "user-list"].includes(entry.id)).map((entry) => entry.id),
      cursorFields: ["WARNING.URL", "lastId", "hasMoreRecords"],
      pageSize: 1000,
      itemCap: 5000,
      pageCap: 25,
      totalSemantics: "Completion requires the VM XML WARNING continuation URL or QPS lastId chain to end before the item and page caps.",
      stopConditions: ["No VM WARNING continuation URL", "QPS hasMoreRecords is false", "Repeated continuation", "25-page cap", "Dataset item cap"],
    },
    {
      surfaceIds: ["activity-log", "scheduled-reports", "reports", "user-list"],
      cursorFields: [],
      pageSize: null,
      itemCap: 5000,
      pageCap: 1,
      totalSemantics: "The API returns one documented list; reaching its explicit runtime cap marks the dataset truncated.",
      stopConditions: ["Single response", "5000-item cap"],
    },
  ],
  rateLimit: {
    documentedLimit: "Qualys publishes subscription-specific concurrency limits and returns rate-limit reset headers.",
    retryHeaders: ["X-RateLimit-Remaining", "X-RateLimit-ToWait-Sec", "Retry-After"],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "Retry three times; honor X-RateLimit-ToWait-Sec or Retry-After up to 30 seconds, otherwise use bounded exponential backoff.",
  },
  runtimeBehavior: QUALYS_RUNTIME_BEHAVIOR,
  knownGaps: ["CloudView connector APIs are not called; the shipped connector assessment uses the Asset Management asset-data-connector QPS resource."],
  sensitiveFields: ["username", "password", "token", "authorization", "cookie", "IP", "DNS", "NETBIOS", "email", "distribution"],
  credentialFormats: ["Qualys Basic credentials", "Qualys bearer tokens", "gateway OAuth tokens", "WAS authentication-record metadata"],
  output: buildBatchOutputContract({
    files: [
      "QUICK_REFERENCE.md", "metadata.json", "core_data/access.json", ...coreFiles,
      "analysis/findings.json", ...Object.keys(categoryFiles).map((name) => `analysis/${name}.json`),
      "compliance/executive_summary.md", "compliance/unified_compliance_matrix.md", ...BATCH3_FRAMEWORK_FILES,
    ],
    conditionalFiles: ["_errors.log"],
    conditionalFileConditions: { "_errors.log": "Written when any dataset, child WAS history read, assessment, or archive operation reports an error." },
    overwritePolicy: "Allocate qualys-audit-<UTC timestamp> and add a numeric suffix when the directory or archive exists.",
    archivePairing: "Create <allocated-directory>.zip beside the allocated Qualys audit directory.",
  }),
});
