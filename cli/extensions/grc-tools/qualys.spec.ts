import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
} from "./batch-spec-builder.js";
import {
  batch2All,
  batch2Any,
  batch2Defined,
  batch2Eq,
  batch2Gt,
  batch2Ne,
  batch2Not,
  batch2Path,
  batch2Rule,
  restSurface,
} from "./batch2-spec-helpers.js";
import { QUALYS_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import { BATCH3_FRAMEWORK_FILES, batch3Checks, batch3Source, type Batch3CheckRow } from "./batch3-spec-helpers.js";
import type { RequestParameterContract } from "./spec-model.js";

const DOCS = "https://docs.qualys.com/en/vm/api/";
const parameter = (
  name: string,
  value: string,
  required = true,
  location: RequestParameterContract["location"] = "query",
): RequestParameterContract => ({ name, location, required, value });
const VM_PARAMETERS: Readonly<Record<string, readonly RequestParameterContract[]>> = {
  "scheduled-scans": [parameter("action", "list"), parameter("show_notifications", "0")],
  scans: [parameter("action", "list"), parameter("launched_after_datetime", "ISO-8601 UTC now minus the resolved lookbackDays"), parameter("show_ags", "1"), parameter("show_op", "1")],
  hosts: [parameter("action", "list"), parameter("details", "All"), parameter("show_tags", "1"), parameter("truncation_limit", "min(resolved hostLimit, 1000)")],
  "option-profiles": [parameter("action", "list")],
  "excluded-ips": [parameter("action", "list")],
  "asset-groups": [parameter("action", "list"), parameter("show_attributes", "ALL"), parameter("truncation_limit", "500")],
  appliances: [parameter("action", "list"), parameter("output_mode", "full")],
  "auth-records": [parameter("action", "list")],
  "compliance-policies": [parameter("action", "list"), parameter("details", "Basic")],
  detections: [
    parameter("action", "list"),
    parameter("status", "Active,New,Re-Opened"),
    parameter("severities", "3,4,5"),
    parameter("show_qds", "1"),
    parameter("truncation_limit", "min(resolved detectionLimit, 1000)"),
    parameter("output_format", "XML"),
  ],
  "knowledge-base": [parameter("action", "list"), parameter("details", "Basic"), parameter("ids", "Comma-separated batch of at most 100 QIDs returned by the detection inventory")],
  "scheduled-reports": [parameter("action", "list"), parameter("is_active", "1")],
  reports: [parameter("action", "list")],
  "activity-log": [parameter("action", "list"), parameter("since_datetime", "ISO-8601 UTC now minus the resolved lookbackDays"), parameter("truncation_limit", "5000")],
  "user-list": [],
};
const QPS_FILTERS: Readonly<Record<string, readonly RequestParameterContract[]>> = {
  connectors: [],
  "cloud-agents": [parameter("ServiceRequest.filters.Criteria[tagName,EQUALS]", "Cloud Agent", true, "form-body")],
  tags: [],
  users: [],
  "was-webapps": [parameter("ServiceRequest.preferences.verbose", "true", true, "form-body")],
  "was-scans": [
    parameter("ServiceRequest.filters.Criteria[launchedDate,GREATER]", "ISO-8601 UTC now minus the resolved lookbackDays", true, "form-body"),
    parameter("ServiceRequest.filters.Criteria[type,EQUALS]", "VULNERABILITY", true, "form-body"),
  ],
  "was-scan-history": [
    parameter("ServiceRequest.filters.Criteria[webApp.id,IN]", "Comma-separated batch of at most 50 web-application IDs", true, "form-body"),
    parameter("ServiceRequest.filters.Criteria[type,EQUALS]", "VULNERABILITY", true, "form-body"),
    parameter("ServiceRequest.filters.Criteria[status,EQUALS]", "FINISHED", true, "form-body"),
  ],
  "was-auth-records": [],
  "was-schedules": [],
};
const vm = (id: string, path: string, fields: readonly string[]) => {
  const qps = path.startsWith("/qps/");
  const administration = path.startsWith("/msp/");
  return restSurface(
    id,
    path,
    qps ? "Qualys QPS REST API" : administration ? "Qualys Administration API" : "Qualys VM/PC API v2",
    DOCS,
    fields,
    qps ? "POST" : "GET",
    qps
      ? {
          headers: ["Authorization: Basic or Bearer according to the resolved mode", "X-Requested-With: grclanker", "Accept: application/json", "Content-Type: application/json"],
          parameters: [
            { name: "ServiceRequest.preferences.limitResults", location: "form-body", required: true, value: "100, 500, or the remaining configured cap selected by the concrete collector." },
            { name: "ServiceRequest.preferences.startFromId", location: "form-body", required: false, value: "Last returned object ID when hasMoreRecords is true." },
            ...(QPS_FILTERS[id] ?? []),
          ],
          responseShape: `JSON ServiceResponse containing data, hasMoreRecords, lastId, and projected ${fields.join(", ")} members.`,
        }
      : {
          headers: ["Authorization: Basic or Bearer according to the resolved mode", "X-Requested-With: grclanker", "Accept: application/xml"],
          parameters: administration
            ? VM_PARAMETERS[id] ?? []
            : VM_PARAMETERS[id] ?? [],
          responseShape: `Qualys VM/PC API v2 XML response parsed from the documented DTD; projected ${fields.join(", ")} members.`,
        },
  );
};

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
  {
    id: "QUALYS-C02",
    control: 2,
    title: "Authenticated scan ratio",
    severity: "high",
    owner: "qualys_assess_scan_coverage",
    surfaces: ["hosts"],
    predicate: "Compute hosts carrying LAST_VM_AUTH_SCANNED_DATE inside the resolved lookback divided by hosts carrying a vulnerability scan date; fail when the percentage is below configured_min_auth_scan_percent.",
    constants: { default_min_auth_scan_percent: 80 },
    runtimeFactNames: {
      readable: "qualys_c02_host_list_readable",
      complete: "qualys_c02_host_list_complete",
      population: "qualys_c02_scanned_host_count",
      failureMatches: "qualys_c02_authenticated_host_count",
      reviewMatches: "qualys_c02_hosts_without_scan_date_count",
    },
    decisionInputs: {
      qualys_c02_host_list_readable: "Boolean true only when the host XML list returns parseable LAST_VULN_SCAN_DATETIME and LAST_VM_AUTH_SCANNED_DATE fields.",
      qualys_c02_host_list_complete: "Boolean true only when host XML pagination exhausts without a cap, repeated continuation, request error, denial, or missing required fields.",
      qualys_c02_returned_host_count: "Uncapped host XML record count; zero means the subscription population is unknown rather than a zero-percent authenticated population.",
      qualys_c02_scanned_host_count: "Uncapped count of hosts carrying a parseable vulnerability scan date; this is the ratio denominator.",
      qualys_c02_authenticated_host_count: "Uncapped count of scanned hosts whose LAST_VM_AUTH_SCANNED_DATE falls inside max(configured lookbackDays, 30 days).",
      qualys_c02_hosts_without_scan_date_count: "Uncapped count of returned hosts without a parseable vulnerability scan date; these hosts never enter the denominator and require review only after the ratio branch.",
      qualys_c02_configured_min_auth_scan_percent: "Resolved minAuthScanPercent after clamping to the inclusive 0 through 100 configuration domain; null means configuration was not established and requires manual review.",
    },
    decisionRules: [
      batch2Rule("manual", batch2Ne("qualys_c02_host_list_readable", true)),
      batch2Rule("manual", batch2Not(batch2Defined("qualys_c02_configured_min_auth_scan_percent"))),
      batch2Rule("manual", batch2Eq("qualys_c02_returned_host_count", 0)),
      batch2Rule("fail", batch2Eq("qualys_c02_scanned_host_count", 0)),
      batch2Rule("fail", {
        op: "ratio",
        numerator: batch2Path("qualys_c02_authenticated_host_count"),
        denominator: batch2Path("qualys_c02_scanned_host_count"),
        comparator: "lt",
        threshold: batch2Path("qualys_c02_configured_min_auth_scan_percent"),
        scale: 100,
      }),
      batch2Rule("warn", batch2Any(
        batch2Ne("qualys_c02_host_list_complete", true),
        batch2Gt("qualys_c02_hosts_without_scan_date_count", 0),
      )),
      batch2Rule("pass", { op: "always" }),
    ],
  },
  { id: "QUALYS-C03", control: 3, title: "Scan option profile review", severity: "medium", owner: "qualys_assess_scan_coverage", surfaces: ["option-profiles", "scheduled-scans"], predicate: "Count option profiles referenced by active schedules that omit safe checks, authenticated scanning, or documented port and performance settings." },
  { id: "QUALYS-C04", control: 4, title: "Asset group completeness", severity: "high", owner: "qualys_assess_asset_inventory", surfaces: ["hosts", "asset-groups"], predicate: "Count host assets assigned to no asset group, empty group IP sets, and group members absent from the complete host inventory." },
  { id: "QUALYS-C05", control: 5, title: "Cloud connector status", severity: "high", owner: "qualys_assess_asset_inventory", surfaces: ["connectors"], predicate: "Count cloud connectors not in an active or successful synchronization state or with no readable last-sync timestamp." },
  { id: "QUALYS-C06", control: 6, title: "Scanner appliance health", severity: "high", owner: "qualys_assess_asset_inventory", surfaces: ["appliances"], predicate: "Count scanner appliances that are offline, whose heartbeat is stale, or whose software version is absent." },
  { id: "QUALYS-C07", control: 7, title: "Agent deployment coverage", severity: "high", owner: "qualys_assess_asset_inventory", surfaces: ["hosts", "cloud-agents"], predicate: "Compute unique Cloud Agent host coverage over the complete host inventory; percentages below min_agent_coverage_percent violate.", constants: { default_min_agent_coverage_percent: 50 } },
  { id: "QUALYS-C08", control: 8, title: "Authentication record completeness", severity: "high", owner: "qualys_assess_vulnerability_management", surfaces: ["auth-records", "hosts"], predicate: "Count missing Windows, Unix/Linux, or network-device authentication record types and records whose latest status is failed or expired." },
  { id: "QUALYS-C09", control: 9, title: "Policy compliance profile assignment", severity: "high", owner: "qualys_assess_vulnerability_management", surfaces: ["compliance-policies", "asset-groups"], predicate: "Count draft or disabled compliance policies and policies with no readable asset-group assignment; no policy is a violation." },
  {
    id: "QUALYS-C10",
    control: 10,
    title: "Vulnerability SLA adherence",
    severity: "critical",
    owner: "qualys_assess_vulnerability_management",
    surfaces: ["hosts", "detections"],
    predicate: "For open severity 3 through 5 detections, apply the configured 90-day medium, 30-day high, or 15-day critical first-found SLA. Fail when dated on-SLA percentage is below 80, warn from 80 through below 95 or for undated rows, and pass at 95 or above.",
    emptyOutcome: "pass",
    constants: {
      default_sla_critical_days: 15,
      default_sla_high_days: 30,
      default_sla_medium_days: 90,
      pass_sla_percent: 95,
      fail_below_sla_percent: 80,
    },
    runtimeFactNames: {
      readable: "qualys_c10_host_and_detection_reads_succeeded",
      complete: "qualys_c10_host_and_detection_lists_complete",
      population: "qualys_c10_sla_scoped_detection_count",
      failureMatches: "qualys_c10_on_sla_detection_count",
      reviewMatches: "qualys_c10_undated_detection_count",
    },
    decisionInputs: {
      qualys_c10_host_and_detection_reads_succeeded: "Boolean true only when a non-empty host inventory and the VM detection listing returned parseable status, severity, and first-found fields.",
      qualys_c10_host_and_detection_lists_complete: "Boolean true only when host and detection VM XML continuation chains exhausted before item and page caps.",
      qualys_c10_detection_list_complete: "Boolean true only when the VM detection XML continuation chain exhausted before item and page caps; host-list truncation does not change this fact.",
      qualys_c10_sla_scoped_detection_count: "Non-negative complete count of open normalized severity 3, 4, or 5 detections after fixed, closed, and informational records are excluded.",
      qualys_c10_dated_detection_count: "Non-negative count of SLA-scoped detections carrying a parseable FIRST_FOUND_DATETIME.",
      qualys_c10_on_sla_detection_count: "Non-negative count of dated detections whose first-found age is at most the configured 90-day medium, 30-day high, or 15-day critical SLA.",
      qualys_c10_undated_detection_count: "Non-negative count of SLA-scoped detections without a parseable FIRST_FOUND_DATETIME; these rows are excluded from the ratio and require review.",
    },
    completeness: {
      qualys_c10_host_and_detection_lists_complete: {
        sources: [batch3Source("hosts"), batch3Source("detections")],
        semantics: "qualys_c10_host_and_detection_lists_complete is true only when both host and detection pagination exhaust. Hosts and detections each set this named fact false on truncated, error, denied, not-collected, not-configured, or missing-required-field. Finding previews and exported samples never establish source cardinality.",
      },
      qualys_c10_detection_list_complete: {
        sources: [batch3Source("detections")],
        semantics: "qualys_c10_detection_list_complete is true when detection pagination exhausts regardless of host-list coverage. Detections sets this named fact false on truncated, error, denied, not-collected, not-configured, or missing-required-field. Finding previews and exported samples never establish source cardinality.",
      },
    },
    decisionRules: [
      batch2Rule("manual", batch2Ne("qualys_c10_host_and_detection_reads_succeeded", true)),
      batch2Rule("manual", batch2All(batch2Eq("qualys_c10_sla_scoped_detection_count", 0), batch2Ne("qualys_c10_detection_list_complete", true))),
      batch2Rule("pass", batch2All(batch2Eq("qualys_c10_sla_scoped_detection_count", 0), batch2Eq("qualys_c10_host_and_detection_lists_complete", true))),
      batch2Rule("warn", batch2Eq("qualys_c10_sla_scoped_detection_count", 0)),
      batch2Rule("warn", batch2Eq("qualys_c10_dated_detection_count", 0)),
      batch2Rule("fail", { op: "ratio", numerator: batch2Path("qualys_c10_on_sla_detection_count"), denominator: batch2Path("qualys_c10_dated_detection_count"), comparator: "lt", threshold: batch2Path("fail_below_sla_percent"), scale: 100 }),
      batch2Rule("warn", batch2Any(
        batch2Ne("qualys_c10_host_and_detection_lists_complete", true),
        batch2Gt("qualys_c10_undated_detection_count", 0),
        { op: "ratio", numerator: batch2Path("qualys_c10_on_sla_detection_count"), denominator: batch2Path("qualys_c10_dated_detection_count"), comparator: "lt", threshold: batch2Path("pass_sla_percent"), scale: 100 },
      )),
      batch2Rule("pass", { op: "always" }),
    ],
  },
  { id: "QUALYS-C11", control: 11, title: "Patch management tracking", severity: "high", owner: "qualys_assess_vulnerability_management", surfaces: ["detections", "knowledge-base"], predicate: "Count open patchable detections with no solution metadata or whose first-found age exceeds the applicable remediation SLA.", emptyOutcome: "pass" },
  { id: "QUALYS-C12", control: 12, title: "Report template and distribution", severity: "medium", owner: "qualys_assess_administration", surfaces: ["scheduled-reports", "reports"], predicate: "Count the absence of an active scheduled report and scheduled reports without a readable distribution target." },
  {
    id: "QUALYS-C13",
    control: 13,
    title: "User role and permission audit",
    severity: "high",
    owner: "qualys_assess_administration",
    surfaces: ["users", "user-list"],
    predicate: "Fail when the uncapped active Manager or super-user count exceeds configured_max_managers or any email address is shared by multiple accounts; otherwise review stale, generic, pending, or source-incomplete accounts.",
    constants: { default_max_managers: 5 },
    runtimeFactNames: {
      readable: "qualys_c13_user_sources_readable",
      complete: "qualys_c13_user_population_complete",
      population: "qualys_c13_active_user_count",
      failureMatches: "qualys_c13_manager_count",
      reviewMatches: "qualys_c13_review_account_count",
    },
    decisionInputs: {
      qualys_c13_user_sources_readable: "Boolean true only when both Administration user search and VM/PC User List return their required role, status, login, email, and last-login fields.",
      qualys_c13_user_population_complete: "Boolean true only when both user sources exhaust and no Restricted-view hidden login, source truncation, error, denial, or missing required field leaves the joined population incomplete.",
      qualys_c13_active_user_count: "Uncapped count of joined users whose VM/PC USER_STATUS is Active, or the lower-bound Administration population when that source alone proves a violation.",
      qualys_c13_manager_count: "Uncapped count of joined active users carrying Manager, Unit Manager, or super-user role evidence.",
      qualys_c13_shared_email_count: "Uncapped count of normalized email addresses used by more than one returned account.",
      qualys_c13_review_account_count: "Uncapped sum of stale-login, generic-identifier, Pending Activation, and required-field review records.",
      qualys_c13_configured_max_managers: "Resolved maxManagers after clamping to 0 through 10000; null means configuration was not established and requires manual review.",
    },
    decisionRules: [
      batch2Rule("manual", batch2Not(batch2Defined("qualys_c13_configured_max_managers"))),
      batch2Rule("fail", batch2Any(
        { op: "gt", left: batch2Path("qualys_c13_manager_count"), right: batch2Path("qualys_c13_configured_max_managers") },
        batch2Gt("qualys_c13_shared_email_count", 0),
      )),
      batch2Rule("manual", batch2Any(
        batch2Ne("qualys_c13_user_sources_readable", true),
        batch2Eq("qualys_c13_active_user_count", 0),
      )),
      batch2Rule("warn", batch2Any(
        batch2Ne("qualys_c13_user_population_complete", true),
        batch2Gt("qualys_c13_review_account_count", 0),
      )),
      batch2Rule("pass", { op: "always" }),
    ],
  },
  { id: "QUALYS-C14", control: 14, title: "External scanner configuration", severity: "high", owner: "qualys_assess_scan_coverage", surfaces: ["scheduled-scans", "appliances"], predicate: "Count the absence of an active external scan schedule and schedules referencing no external scanner appliance." },
  { id: "QUALYS-C15", control: 15, title: "Web application inventory", severity: "high", owner: "qualys_assess_administration", surfaces: ["was-webapps", "was-scans", "was-scan-history", "was-auth-records", "was-schedules"], predicate: "Count web applications without an active schedule, a recent completed scan, or required authentication records." },
  {
    id: "QUALYS-C16",
    control: 16,
    title: "Exclusion list review",
    severity: "medium",
    owner: "qualys_assess_scan_coverage",
    surfaces: ["excluded-ips", "option-profiles"],
    predicate: "Fail when the readable excluded-host list proves any IP range spans more than 256 addresses, even if option profiles are denied. Otherwise require both sources, warn when any excluded host or option-profile detection exclusion exists, and pass only when both complete sources prove no exclusions.",
    runtimeFactNames: {
      readable: "qualys_c16_required_exclusion_sources_readable",
      complete: "qualys_c16_exclusion_sources_complete",
      population: "qualys_c16_excluded_host_and_profile_count",
      failureMatches: "qualys_c16_broad_excluded_ip_range_count",
      reviewMatches: "qualys_c16_documented_exclusion_count",
    },
    decisionInputs: {
      qualys_c16_required_exclusion_sources_readable: "Boolean true only when both the excluded-host XML list and option-profile XML list returned parseable records; false when either request is denied, errors, is not collected, is not configured, or omits a required field.",
      qualys_c16_exclusion_sources_complete: "Boolean true only when both excluded-host and option-profile XML lists exhaust their continuation chains without truncation and the subscription view is complete.",
      qualys_c16_excluded_host_and_profile_count: "Uncapped sum of excluded-host entries and option profiles returned by the two XML list operations.",
      qualys_c16_broad_excluded_ip_range_count: "Uncapped count of excluded-host range entries whose inclusive address span is greater than 256; this primitive is owned solely by the excluded-host list and remains available when option profiles are denied.",
      qualys_c16_documented_exclusion_count: "Uncapped sum of excluded-host entries and VULNERABILITY_DETECTION or DETECTION_EXCLUDE search-list references found in option profiles.",
      qualys_c16_option_profile_count: "Uncapped option-profile count, or null when that source is denied, errors, is not collected, is not configured, truncated before a trustworthy count, or lacks required fields.",
    },
    completeness: {
      qualys_c16_exclusion_sources_complete: {
        sources: [batch3Source("excluded-ips"), batch3Source("option-profiles")],
        semantics: "QUALYS-C16 sets this fact true only after the excluded-host and option-profile XML lists both exhaust. Any truncated, error, denied, not-collected, not-configured, or missing-required-field state on either named source sets it false; a broad range already proved by excluded-ips still retains fail precedence. Finding previews and exported samples never establish source cardinality.",
      },
    },
    decisionRules: [
      batch2Rule("fail", batch2Gt("qualys_c16_broad_excluded_ip_range_count", 0)),
      batch2Rule("manual", batch2Ne("qualys_c16_required_exclusion_sources_readable", true)),
      batch2Rule("manual", batch2All(
        batch2Eq("qualys_c16_excluded_host_and_profile_count", 0),
        batch2Eq("qualys_c16_option_profile_count", 0),
      )),
      batch2Rule("warn", batch2Gt("qualys_c16_documented_exclusion_count", 0)),
      batch2Rule("warn", batch2Ne("qualys_c16_exclusion_sources_complete", true)),
      batch2Rule("pass", { op: "always" }),
    ],
  },
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
