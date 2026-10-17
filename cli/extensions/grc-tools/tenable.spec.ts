import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
  deriveDecisionRules,
  type BatchCheckDefinition,
  type BatchCompletenessDefinition,
  type BatchCompletenessSourceDefinition,
  type BatchCriterionExample,
  type BatchPaginationDefinition,
  type BatchSurfaceDefinition,
  type PortableInputType,
} from "./batch-spec-builder.js";
import { TENABLE_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import type { PortableValue, RequestParameterContract, VerdictCondition, VerdictOperand, VerdictRule } from "./spec-model.js";

const VM_SERVICE = "Tenable Vulnerability Management API";
const SC_SERVICE = "Tenable Security Center REST API";
const VM_AUTH_HEADER = "X-ApiKeys: accessKey={access_key};secretKey={secret_key}";
const SC_AUTH_HEADER = "x-apikey: accesskey={sc_access_key}; secretkey={sc_secret_key};";

type SurfaceRequestOptions = {
  method?: "GET" | "POST";
  parameters?: readonly RequestParameterContract[];
  responseShape: string;
};

const vmSurface = (
  id: string,
  path: string,
  slug: string,
  fields: readonly string[],
  { method, parameters = [], responseShape }: SurfaceRequestOptions,
): BatchSurfaceDefinition => ({
  id,
  ...(method ? { method } : {}),
  path,
  service: VM_SERVICE,
  documentationUrl: `https://developer.tenable.com/reference/${slug}`,
  fields,
  request: {
    headers: [
      "Accept: application/json",
      VM_AUTH_HEADER,
      ...(method === "POST" ? ["Content-Type: application/json"] : []),
    ],
    parameters,
    responseShape,
  },
});

const scSurface = (
  id: string,
  resource: string,
  page: string,
  fields: readonly string[],
  parameters: readonly RequestParameterContract[],
  responseShape: string,
): BatchSurfaceDefinition => ({
  id,
  path: `/rest/${resource}`,
  service: SC_SERVICE,
  documentationUrl: `https://docs.tenable.com/security-center/api/${page}`,
  fields,
  request: {
    clientRegion: "Use the configured Tenable Security Center origin (sc_url, or url when it names a Security Center host); never follow a server link to a different origin.",
    headers: ["Accept: application/json", SC_AUTH_HEADER],
    parameters,
    responseShape,
  },
});

const param = (
  name: string,
  location: RequestParameterContract["location"],
  value: string,
  required = true,
): RequestParameterContract => ({ name, location, required, value });

const SC_LIST_SHAPE = "A JSON object whose response is either an array of records or an object with usable and manageable arrays, merged by id; a nonzero error_code is a refusal.";

const TENABLE_SURFACES: readonly BatchSurfaceDefinition[] = [
  vmSurface("scans", "/scans", "scans-list", [
    "id", "name", "type", "status", "enabled", "rrules", "policy_id", "wizard_uuid", "template_uuid", "last_modification_date",
  ], { responseShape: "A JSON object with a scans array." }),
  vmSurface("policies", "/policies", "policies-list", ["id", "name", "template_uuid"], {
    responseShape: "A JSON object with a policies array.",
  }),
  vmSurface("policy-details", "/policies/{policy_id}", "policies-details", [
    "uuid", "name", "settings.safe_checks", "settings.portscan_range", "settings.max_hosts_per_scan", "settings.max_checks_per_host",
    "settings.thorough_tests", "settings.report_paranoia", "plugins.*.status",
  ], {
    parameters: [param("policy_id", "path", "Each distinct policy_id carried by a visible scan, for the first 100 such policies")],
    responseShape: "A JSON object carrying at least one of uuid, settings, plugins, or credentials; credential properties under settings are redacted before evidence export.",
  }),
  vmSurface("scan-templates", "/editor/scan/templates", "editor-list-templates", ["uuid", "name", "title"], {
    responseShape: "A JSON object with a templates array.",
  }),
  vmSurface("users", "/users", "users-list", [
    "username", "email", "enabled", "permissions", "lastlogin", "last_apikey_access", "ui_permitted", "ui_saml_only", "two_factor.sms_enabled",
    "lockout", "login_fail_count",
  ], {
    parameters: [param("withRoles", "query", "true")],
    responseShape: "A JSON object with a users array; only an Administrator key receives the numeric permissions attribute on each user.",
  }),
  vmSurface("target-groups", "/target-groups", "target-groups-list", ["name", "members", "last_modification_date"], {
    responseShape: "A JSON object with a target_groups array.",
  }),
  vmSurface("exclusions", "/exclusions", "exclusions-list", ["id", "name", "description", "members", "schedule.enabled"], {
    parameters: [
      param("limit", "query", "200"),
      param("offset", "query", "Number of exclusion records already received, starting at 0"),
    ],
    responseShape: "A JSON object with an exclusions array and pagination.total.",
  }),
  vmSurface("asset-export-request", "/assets/export", "exports-assets-request-export", ["export_uuid"], {
    method: "POST",
    parameters: [param("chunk_size", "json-body", "10000")],
    responseShape: "A JSON object with export_uuid.",
  }),
  vmSurface("asset-export-status", "/assets/export/{export_uuid}/status", "exports-assets-export-status", [
    "status", "reason", "chunks_available", "chunks_failed", "total_chunks",
  ], {
    parameters: [param("export_uuid", "path", "The export_uuid returned by POST /assets/export, polled every 2 seconds for up to 300 seconds")],
    responseShape: "A JSON object with a status string and the chunks_available, chunks_failed, and total_chunks members.",
  }),
  vmSurface("asset-export-chunks", "/assets/export/{export_uuid}/chunks/{chunk_id}", "exports-assets-download-chunk", [
    "id", "uuid", "has_agent", "last_seen", "network_id", "network_name", "tags", "last_authentication_scan_status",
  ], {
    parameters: [
      param("export_uuid", "path", "The export_uuid returned by POST /assets/export"),
      param("chunk_id", "path", "Each id in chunks_available, for the first max_chunks ids (default 50, clamped to 1 through 1000)"),
    ],
    responseShape: "A JSON array of asset records; a record carrying none of id, uuid, has_agent, last_seen, network_id, or tags is counted as unevaluable and kept out.",
  }),
  vmSurface("server-properties", "/server/properties", "server-properties", ["plugin_set", "loaded_plugin_set", "license.agents"], {
    responseShape: "A JSON object carrying at least one of plugin_set, loaded_plugin_set, server_version, nessus_type, nessus_ui_version, or license.",
  }),
  vmSurface("scanners", "/scanners", "scanners-list", [
    "id", "name", "type", "pool", "group", "linked", "status", "last_connect", "ui_version", "loaded_plugin_set",
  ], {
    responseShape: "A JSON object with a scanners array; each scanner's key, registration_code, and license values are replaced with a redaction marker before evaluation or export.",
  }),
  vmSurface("agents", "/scanners/null/agents", "agents-list", [
    "id", "uuid", "name", "status", "last_connect", "core_version", "groups", "plugin_feed_id",
  ], {
    parameters: [
      param("limit", "query", "1000"),
      param("offset", "query", "Number of agent records already received, starting at 0"),
    ],
    responseShape: "A JSON object with an agents array and pagination.total.",
  }),
  vmSurface("agent-groups", "/scanners/null/agent-groups", "agent-groups-list", ["name", "agents_count"], {
    responseShape: "A JSON object with a groups array.",
  }),
  vmSurface("networks", "/networks", "networks-list", ["uuid", "name", "scanner_count", "assets_ttl_days", "is_default"], {
    parameters: [
      param("limit", "query", "50"),
      param("offset", "query", "Number of network records already received, starting at 0"),
    ],
    responseShape: "A JSON object with a networks array and pagination.total.",
  }),
  vmSurface("tag-categories", "/tags/categories", "tags-list-tag-categories", ["uuid", "name"], {
    parameters: [
      param("limit", "query", "5000"),
      param("offset", "query", "Number of tag category records already received, starting at 0"),
    ],
    responseShape: "A JSON object with a categories array and pagination.total.",
  }),
  vmSurface("tag-values", "/tags/values", "tags-list-tag-values", ["uuid"], {
    parameters: [
      param("limit", "query", "5000"),
      param("offset", "query", "Number of tag value records already received, starting at 0"),
    ],
    responseShape: "A JSON object with a values array and pagination.total; only the number of values is evaluated.",
  }),
  vmSurface("groups", "/groups", "groups-list", [], {
    responseShape: "A JSON object with a groups array; only whether it was returned and how many groups it holds are evaluated.",
  }),
  vmSurface("roles", "/access-control/v1/roles", "access-control-roles-list", ["name", "type"], {
    responseShape: "A JSON array of role records; a non-empty array in which no record carries uuid, id, name, type, or privileges is a failed read.",
  }),
  vmSurface("permissions", "/api/v3/access-control/permissions", "io-v3-access-control-permissions-list", [
    "name", "actions", "subjects.*.type", "subjects.*.uuid", "subjects.*.name", "objects.*.type",
  ], { responseShape: "A JSON object with a permissions array." }),
  vmSurface("access-groups", "/v2/access-groups", "io-v2-access-groups-list", ["id", "name", "all_assets"], {
    parameters: [
      param("limit", "query", "200"),
      param("offset", "query", "Number of access group records already received, starting at 0"),
    ],
    responseShape: "A JSON object with an access_groups array and pagination.total.",
  }),
  vmSurface("credentials", "/credentials", "credentials-list", ["id", "name", "type.name", "type.id", "created_date", "last_used_by.id"], {
    parameters: [
      param("limit", "query", "200"),
      param("offset", "query", "Number of credential records already received, starting at 0"),
    ],
    responseShape: "A JSON object with a credentials array and pagination.total.",
  }),
  vmSurface("audit-log", "/audit-log/v1/events", "audit-log-events", [
    "id", "action", "crud", "is_failure", "received", "actor.name", "target.name",
  ], {
    parameters: [
      param("f", "query", "date.gte: followed by the ISO 8601 time audit_lookback_days days before the assessment time (clamped to 1 through 365; default 30)"),
      param("limit", "query", "5000"),
      param("offset", "query", "Number of event records already received, starting at 0"),
    ],
    responseShape: "A JSON object with an events array and pagination.total.",
  }),
  scSurface("sc-scans", "scan", "Scan.htm", ["id", "name", "schedule.type"], [
    param("fields", "query", "id,name,status,schedule,policy,repository,credentials,modifiedTime"),
  ], SC_LIST_SHAPE),
  scSurface("sc-scan-results", "scanResult", "Scan-Result.htm", ["id", "status", "finishTime"], [
    param("fields", "query", "id,name,status,startTime,finishTime,scannedIPs,totalIPs"),
    param("startTime", "query", "Unix seconds 30 days before the assessment time"),
  ], SC_LIST_SHAPE),
  scSurface("sc-scanners", "scanner", "Scanner.htm", ["id", "name", "status", "enabled", "pluginSet", "loadedPluginSet", "lastCheckinTime"], [
    param("fields", "query", "id,name,status,statusMessage,enabled,version,pluginSet,loadedPluginSet,lastCheckinTime,agentCapable"),
  ], SC_LIST_SHAPE),
  scSurface("sc-feed", "feed", "Feed.htm", ["active.stale", "active.updateTime"], [], "A JSON object whose response object describes each plugin feed; a nonzero error_code is a refusal."),
  scSurface("sc-users", "user", "User.htm", ["id", "username", "status", "role.id", "role.name", "lastLogin", "locked"], [
    param("fields", "query", "id,username,status,role,lastLogin,locked,failedLogins,authType"),
  ], SC_LIST_SHAPE),
];

const value = (entry: PortableValue): VerdictOperand => ({ kind: "value", value: entry });
const path = (name: string): VerdictOperand => ({ kind: "path", path: name });
const lengthOf = (name: string): VerdictOperand => ({ kind: "length", path: name });
type Comparator = "eq" | "ne" | "gt" | "gte" | "lt" | "lte";
const cmp = (op: Comparator, left: string | VerdictOperand, right: PortableValue | VerdictOperand): VerdictCondition => ({
  op,
  left: typeof left === "string" ? path(left) : left,
  right: right !== null && typeof right === "object" && !Array.isArray(right) ? right as VerdictOperand : value(right as PortableValue),
});
const eq = (left: string | VerdictOperand, right: PortableValue | VerdictOperand) => cmp("eq", left, right);
const ne = (left: string | VerdictOperand, right: PortableValue | VerdictOperand) => cmp("ne", left, right);
const gt = (left: string | VerdictOperand, right: PortableValue | VerdictOperand) => cmp("gt", left, right);
const gte = (left: string | VerdictOperand, right: PortableValue | VerdictOperand) => cmp("gte", left, right);
const lt = (left: string | VerdictOperand, right: PortableValue | VerdictOperand) => cmp("lt", left, right);
const lte = (left: string | VerdictOperand, right: PortableValue | VerdictOperand) => cmp("lte", left, right);
const isNull = (name: string): VerdictCondition => ({ op: "null", operand: path(name) });
const all = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "and", conditions });
const any = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "or", conditions });
const some = (name: string, condition: VerdictCondition): VerdictCondition => ({ op: "some", path: name, condition });
const always: VerdictCondition = { op: "always" };
const rule = (status: VerdictRule["status"], condition: VerdictCondition): VerdictRule => ({ status, condition });

const TENABLE_INPUTS: Readonly<Record<string, string>> = {
  caller_is_administrator: "True only when GET /users returned at least one user record carrying a numeric permissions attribute, which Tenable returns only to an Administrator key; false when the user list is unreadable, empty, or returned in the reduced shape.",
  stale_scan_days: "The stale_scan_days assessment option in days, clamped to 1 through 365; default 30.",
  credential_threshold: "The credential_threshold assessment option, clamped to 0 through 1; default 0.8.",
  scans_readable: "True when GET /scans returned its documented scans array.",
  scan_count: "Number of scan records GET /scans returned.",
  discovery_scan_count: "Number of scans whose wizard_uuid, or else template_uuid, resolves to a GET /editor/scan/templates record whose name or title contains discovery, case-insensitively; 0 when the template list is unreadable.",
  failing_policy_count: "Number of referenced policies whose GET /policies/{policy_id} detail was read and either sets settings.safe_checks to no or has a non-empty plugins family map in which no family status is enabled or mixed.",
  policy_details_readable: "False when the scan list was unreadable or every attempted GET /policies/{policy_id} read was refused or failed; true otherwise, including when no policy detail was requested.",
  evaluated_policy_count: "Number of GET /policies/{policy_id} reads attempted: one per distinct scan policy_id, for at most the first 100.",
  scans_without_policy_id_count: "Number of visible scans with no policy_id string.",
  unreadable_policy_count: "Number of attempted policy detail reads that were refused or failed.",
  unverified_policy_count: "Number of read policy details that are not failing and either omit settings.safe_checks or expose an empty plugins family map.",
  policy_details_complete: "Policy detail coverage of the referenced policies.",
  warning_policy_count: "Number of read policy details that are neither failing nor unverified and have a safe_checks value other than yes, a missing settings.portscan_range or one that is not default, all, or 1-65535, or more than half of their plugin families disabled.",
  templates_readable: "True when GET /editor/scan/templates returned its documented templates array.",
  policies_readable: "True when GET /policies returned its documented policies array.",
  enabled_recurring_scan_count: "Number of scans with enabled true and a non-empty rrules string that does not contain FREQ=ONETIME.",
  recurring_scan_age_days: "For each enabled recurring scan whose last_modification_date parses as epoch seconds, epoch milliseconds, or a date string, the days from that timestamp to the assessment time as a fraction, floored at 0.",
  never_run_or_undated_recurring_scan_count: "Number of enabled recurring scans whose status is the string empty, which Tenable reports for a scan that never ran, or whose last_modification_date does not parse as a timestamp.",
  active_compliance_scan_count: "Number of enabled recurring scans whose resolved template name or title contains compliance, pci, scap, audit, offline config, or stig, case-insensitively.",
  asset_export_readable: "True when the POST /assets/export job reached FINISHED and, when Tenable listed any available chunk, at least one chunk downloaded.",
  asset_count: "Number of exported asset records carrying at least one of id, uuid, has_agent, last_seen, network_id, or tags.",
  credentialed_coverage_ratio: "Exported assets whose last_authentication_scan_status is Success or whose has_agent is true, divided by the exported asset count and rounded to four decimal places with ties rounded up; 0 when no asset was exported.",
  asset_export_complete: "Asset export coverage.",
  exclusions_readable: "True when the GET /exclusions offset walk returned documented exclusions pages.",
  exclusions_complete: "Exclusion inventory coverage.",
  permanent_exclusion_count: "Number of exclusion records whose schedule.enabled is not true.",
  broad_exclusion_count: "Number of exclusions whose comma-separated members include a CIDR block with a prefix length of 16 or less, or an IPv4 range whose start and end differ in the second octet.",
  undocumented_exclusion_count: "Number of exclusions without a non-empty description string.",
  target_groups_readable: "True when GET /target-groups returned its documented target_groups array.",
  target_group_age_days: "For each target group whose last_modification_date parses as a timestamp, the days from that timestamp to the assessment time as a fraction, floored at 0.",
  undated_target_group_count: "Number of target groups whose last_modification_date does not parse as a timestamp.",
  overlapping_member_count: "Number of distinct trimmed member targets listed more than once across the comma-separated members strings of all target groups, including a target repeated within one group.",
  sc_scans_readable: "True when Tenable Security Center is configured and GET /rest/scan returned a scan list.",
  sc_scan_count: "Number of Security Center scan records, with the usable and manageable lists merged by id.",
  sc_recurring_scan_count: "Number of Security Center scans whose schedule.type is ical.",
  sc_scan_results_readable: "True when GET /rest/scanResult returned a result list.",
  sc_finished_result_age_days: "For each returned Security Center scan result whose status contains completed, case-insensitively, and whose finishTime parses as a timestamp, the days from finishTime to the assessment time as a fraction, floored at 0.",
  expected_asset_coverage_ratio: "Exported assets whose last_seen parses as a timestamp no more than stale_asset_days days (clamped to 1 through 365; default 30) before the assessment time, divided by the expected_asset_count assessment option and rounded to four decimal places with ties rounded up; null when expected_asset_count is not supplied or is not positive.",
  networks_complete: "False when the GET /networks read was refused, failed, or not configured, or its offset walk stopped before the end of the network list; true otherwise.",
  tag_categories_readable: "True when the GET /tags/categories offset walk returned documented categories pages.",
  tag_category_count: "Number of tag category records the GET /tags/categories walk delivered.",
  tag_categories_complete: "False when the GET /tags/categories read was refused, failed, or not configured, or its offset walk stopped before the end of the category list; true otherwise.",
  tagged_asset_ratio: "Exported assets whose tags array holds at least one object, divided by the exported asset count and rounded to four decimal places with ties rounded up; 0 when no asset was exported.",
  tagged_threshold: "The tagged_threshold assessment option, clamped to 0 through 1; default 0.9.",
  tag_values_complete: "False when the GET /tags/values read was refused, failed, or not configured, or its offset walk stopped before the end of the value list; true otherwise.",
  agents_readable: "True when the GET /scanners/null/agents offset walk returned documented agents pages.",
  agent_count: "Number of agent records the GET /scanners/null/agents walk delivered.",
  unhealthy_agent_ratio: "Distinct agents that are offline (status off) or stale (last_connect parses as a timestamp more than agent_offline_days days before the assessment time; agent_offline_days is clamped to 1 through 365, default 7), keyed by uuid, else id, else name, with agents carrying none of them sharing one key, divided by the agent count and rounded to four decimal places with ties rounded up.",
  undated_agent_count: "Number of agents whose last_connect does not parse as a timestamp.",
  outdated_agent_count: "Number of agents whose core_version is lower than the newest dotted core_version among the agents and differs from it in the major version or has a lower minor version; 0 when no agent reports a dotted version.",
  agents_complete: "False when the GET /scanners/null/agents read was refused, failed, or not configured, or its offset walk stopped before the end of the agent list; true otherwise.",
  server_properties_readable: "True when GET /server/properties returned its documented object.",
  agent_groups_readable: "True when GET /scanners/null/agent-groups returned its documented groups array.",
  agent_group_count: "Number of agent group records GET /scanners/null/agent-groups returned; null when that list is unreadable.",
  ungrouped_agent_count: "Number of agents whose groups array holds no object.",
  ungrouped_agent_ratio: "Agents whose groups array holds no object, divided by the agent count and rounded to four decimal places with ties rounded up.",
  scanners_readable: "True when GET /scanners returned its documented scanners array.",
  scanner_count: "Number of scanner entries GET /scanners returned, including Tenable-managed cloud scanners, scanner pools, and groups.",
  linked_scanner_count: "Number of scanner entries, the linked scanner appliances, whose type is not local and whose pool and group flags are not true (true, 1, or the strings true or 1).",
  unlinked_scanner_count: "Number of linked scanner appliances whose linked attribute is not 1, given as a number or a numeric string.",
  off_scanner_count: "Number of linked scanner appliances whose status is not on.",
  linked_scanner_connect_age_days: "For each linked scanner appliance whose last_connect parses as a timestamp, the days from that timestamp to the assessment time as a fraction, floored at 0.",
  undated_linked_scanner_count: "Number of linked scanner appliances whose last_connect does not parse as a timestamp.",
  outdated_linked_scanner_count: "Number of linked scanner appliances whose ui_version is lower than the newest dotted ui_version among the linked appliances.",
  plugin_stale_hours: "The plugin_stale_hours assessment option in hours, clamped to 1 through 720; default 24.",
  server_plugin_set_age_hours: "Hours from the plugin_set of GET /server/properties, else its loaded_plugin_set, read as a twelve-digit YYYYMMDDHHMM UTC stamp, to the assessment time; null when neither parses.",
  scanner_plugin_set_age_hours: "For each GET /scanners entry, including cloud scanners, pools, and groups, whose loaded_plugin_set parses as a twelve-digit YYYYMMDDHHMM UTC stamp, the hours from that stamp to the assessment time; empty when the scanner list is unreadable.",
  scanners_without_plugin_set_count: "Number of GET /scanners entries whose pool and group flags are not true and whose loaded_plugin_set does not parse as a twelve-digit YYYYMMDDHHMM stamp.",
  online_agent_plugin_set_age_hours: "For each agent whose status is on and whose plugin_feed_id parses as a twelve-digit YYYYMMDDHHMM UTC stamp, the hours from that stamp to the assessment time; empty when the agent list is unreadable.",
  networks_readable: "True when the GET /networks offset walk returned documented networks pages.",
  network_count: "Number of network records the GET /networks walk delivered.",
  zero_scanner_network_count: "Number of networks whose scanner_count is 0, given as a number or a numeric string.",
  unreported_scanner_network_count: "Number of networks whose scanner_count is neither a finite number nor a numeric string.",
  sc_scanners_readable: "True when Tenable Security Center is configured and GET /rest/scanner returned a scanner list.",
  sc_scanner_count: "Number of Security Center scanner records, with the usable and manageable lists merged by id.",
  sc_unhealthy_scanner_count: "Number of Security Center scanners whose enabled value is not false (false, 0, or the strings false or 0) and whose status is not 1.",
  sc_scanner_checkin_age_days: "For each Security Center scanner whose enabled value is not false and whose lastCheckinTime parses as a timestamp, the days from lastCheckinTime to the assessment time as a fraction, floored at 0.",
  sc_scanner_plugin_set_age_hours: "For each Security Center scanner whose enabled value is not false and whose loadedPluginSet, else pluginSet, parses as a twelve-digit YYYYMMDDHHMM UTC stamp, the hours from that stamp to the assessment time.",
  sc_feed_marked_stale: "True when GET /rest/feed was read and its active.stale value is true (true, 1, or the strings true or 1); false otherwise.",
  sc_undated_scanner_count: "Number of Security Center scanners whose enabled value is not false and whose lastCheckinTime does not parse as a timestamp.",
  sc_feed_readable: "True when GET /rest/feed returned its documented object.",
  inactive_user_days: "The inactive_user_days assessment option in days, clamped to 1 through 3650; default 90.",
  max_admins: "The max_admins assessment option, clamped to 0 through 10000; default 5.",
  users_readable: "True when GET /users returned its documented users array.",
  user_count: "Number of user records GET /users returned.",
  enabled_user_count: "Number of users whose enabled value is true (true, 1, or the strings true or 1).",
  enabled_administrator_count: "Number of enabled users whose permissions value is 64, the Administrator role, given as a number or numeric string.",
  administrators_without_strong_auth_count: "Number of enabled Administrators whose ui_permitted value is not false (false, 0, or the strings false or 0) and that have neither ui_saml_only true (true, 1, or the strings true or 1) nor two_factor.sms_enabled 1, given as a number or numeric string.",
  enabled_user_last_login_age_days: "For each enabled user whose lastlogin parses as epoch seconds, epoch milliseconds, or a date string, the days from that timestamp to the assessment time as a fraction, floored at 0.",
  never_logged_in_user_count: "Number of enabled users whose lastlogin does not parse as a timestamp.",
  enabled_user_api_key_age_days: "For each enabled user whose last_apikey_access parses as a timestamp, the days from that timestamp to the assessment time as a fraction, floored at 0.",
  locked_out_user_count: "Number of enabled users whose lockout value is 1, given as a number or numeric string.",
  enabled_user_login_failure_counts: "For each enabled user, its login_fail_count as a number or numeric string, or 0 when it is neither.",
  users_without_enabled_flag_count: "Number of users whose enabled value is neither true nor false (a boolean, 1 or 0, or the strings true, false, 1, or 0).",
  roles_readable: "True when GET /access-control/v1/roles returned its documented array of roles.",
  permissions_readable: "True when GET /api/v3/access-control/permissions returned its documented permissions array.",
  permission_count: "Number of permission records GET /api/v3/access-control/permissions returned.",
  broad_permission_count: "Number of permissions whose subjects include an AllUsers subject, or a UserGroup subject whose uuid is 00000000-0000-0000-0000-000000000000 or whose name is All Users; whose objects include an AllAssets, AllObjects, or AllTags object; and whose actions include one containing CanEdit, CanScan, or CanUse, case-insensitively.",
  legacy_access_group_count: "Number of GET /v2/access-groups records whose all_assets value is not true (true, 1, or the strings true or 1); 0 when that walk was not read.",
  access_groups_complete: "False when the GET /v2/access-groups read was refused, failed, or not configured, or its offset walk stopped before the end of the access group list; true otherwise.",
  groups_readable: "True when GET /groups returned its documented groups array.",
  credentials_readable: "True when the GET /credentials offset walk returned documented credentials pages.",
  credential_count: "Number of managed credential records the GET /credentials walk delivered.",
  unused_credential_count: "Number of managed credentials whose last_used_by.id is not a number or numeric string, meaning no scan has used them.",
  credential_age_days: "For each managed credential whose created_date parses as epoch seconds, epoch milliseconds, or a date string, the days from that timestamp to the assessment time as a fraction, floored at 0.",
  undated_credential_count: "Number of managed credentials whose created_date does not parse as a timestamp.",
  credentials_complete: "False when the GET /credentials read was refused, failed, or not configured, or its offset walk stopped before the end of the credential list; true otherwise.",
  audit_log_readable: "True when the GET /audit-log/v1/events offset walk returned documented events pages.",
  audit_event_count: "Number of activity log events the GET /audit-log/v1/events walk delivered for the audit_lookback_days window.",
  audit_events_complete: "False when the GET /audit-log/v1/events read was refused, failed, or not configured, or its offset walk stopped before the end of the event list, including at its 20-page cap; true otherwise.",
  sensitive_audit_event_count: "Number of distinct events, keyed by id or else by the whole event, whose crud is d, or whose crud is not r (a missing crud included) and whose action contains user, role, permission, key, exclusion, policy, or template, case-insensitively.",
  sc_users_readable: "True when Tenable Security Center is configured and GET /rest/user returned a user list.",
  sc_user_count: "Number of Security Center user records, with the usable and manageable lists merged by id.",
  sc_active_user_last_login_age_days: "For each Security Center user whose status is 0 and whose lastLogin parses as epoch seconds, epoch milliseconds, or a date string, the days from lastLogin to the assessment time as a fraction, floored at 0.",
  sc_never_logged_in_user_count: "Number of Security Center users whose status is 0 and whose lastLogin does not parse as a timestamp; a lastLogin of 0 counts as never.",
  sc_locked_user_count: "Number of Security Center users whose status is 0 and whose locked value is true (true, 1, or the strings true or 1).",
};

const inputs = (...names: string[]): Readonly<Record<string, string>> => Object.fromEntries(names.map((name) => {
  const definition = TENABLE_INPUTS[name];
  if (!definition) throw new Error(`Tenable decision input ${name} has no portable definition`);
  return [name, definition];
}));

const completeFrom = (
  semantics: string,
  sources: BatchCompletenessDefinition["sources"],
): BatchCompletenessDefinition => ({ semantics, sources });

const ASSET_EXPORT_COMPLETE = completeFrom(
  "true when the finished export listed no more than max_chunks available chunks, Tenable reported no failed chunk and no total_chunks beyond the available list, every requested chunk downloaded, and every downloaded record carried a documented asset member.",
  [
    { surfaceId: "asset-export-status", falseWhen: ["truncated"] },
    { surfaceId: "asset-export-chunks", falseWhen: ["truncated", "missing-required-field"] },
  ],
);

const UNREAD_OR_TRUNCATED: BatchCompletenessSourceDefinition["falseWhen"] = ["truncated", "denied", "error", "not-configured"];

const walkComplete = (surfaceId: string, request: string): BatchCompletenessDefinition => completeFrom(
  `false when the ${request} read was refused, failed, or not configured, or its offset walk stopped before the end of the list.`,
  [{ surfaceId, falseWhen: UNREAD_OR_TRUNCATED }],
);

type TenableCheck = {
  id: string;
  control: number;
  title: string;
  severity: BatchCheckDefinition["severity"];
  owner: string;
  surfaces: readonly string[];
  inputs: readonly string[];
  inputTypes?: Readonly<Record<string, readonly PortableInputType[]>>;
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

const SCAN_PROGRAM = "tenable_assess_scan_program";

const SCAN_PROGRAM_CHECKS: readonly TenableCheck[] = [
  {
    id: "TENABLE-01",
    control: 1,
    title: "Scan policy configuration",
    severity: "high",
    owner: SCAN_PROGRAM,
    surfaces: ["scans", "policies", "policy-details", "scan-templates", "users"],
    inputs: [
      "scans_readable", "scan_count", "discovery_scan_count", "failing_policy_count", "policy_details_readable", "evaluated_policy_count",
      "scans_without_policy_id_count", "unreadable_policy_count", "unverified_policy_count", "policy_details_complete", "warning_policy_count",
      "templates_readable", "policies_readable", "caller_is_administrator",
    ],
    rules: [
      rule("manual", ne("scans_readable", true)),
      rule("fail", eq("scan_count", 0)),
      rule("fail", eq("discovery_scan_count", path("scan_count"))),
      rule("fail", gt("failing_policy_count", 0)),
      rule("manual", any(
        ne("policy_details_readable", true),
        all(eq("evaluated_policy_count", 0), eq("scans_without_policy_id_count", path("scan_count"))),
      )),
      rule("manual", any(gt("unreadable_policy_count", 0), gt("unverified_policy_count", 0), ne("policy_details_complete", true))),
      rule("warn", gt("warning_policy_count", 0)),
      rule("warn", any(
        ne("templates_readable", true),
        ne("policies_readable", true),
        ne("caller_is_administrator", true),
        gt("scans_without_policy_id_count", 0),
      )),
      rule("pass", always),
    ],
    completeness: {
      policy_details_complete: completeFrom(
        "true unless more than 100 distinct policies are referenced by visible scans, so the policies past the first 100 were never requested; individually refused or failed reads are counted separately and do not change this fact.",
        [{ surfaceId: "policy-details", falseWhen: ["truncated"] }],
      ),
    },
    decision: "Manual when GET /scans is unreadable. Fail when no scan is visible, when every visible scan resolves to a discovery template, or when any referenced policy detail sets safe_checks to no or disables every plugin family. Manual when every policy detail read failed, when no visible scan carries a policy_id, when any referenced policy detail was unreadable or omits safe_checks or its plugin family map, or when more than 100 referenced policies left the rest unrequested. Warn when an evaluated policy has a safe_checks value other than yes, a missing or custom port range, or more than half of its plugin families disabled. Warn instead of pass when the template or policy list is unreadable, when the key is not confirmed as Administrator, or when any visible scan carries no policy_id. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Every referenced policy was read and verified safe, and the key is an Administrator.", {
        scans_readable: true, scan_count: 3, discovery_scan_count: 1, failing_policy_count: 0, policy_details_readable: true, evaluated_policy_count: 2,
        scans_without_policy_id_count: 0, unreadable_policy_count: 0, unverified_policy_count: 0, policy_details_complete: true, warning_policy_count: 0,
        templates_readable: true, policies_readable: true, caller_is_administrator: true,
      }),
      example("noncompliant", "fail", "A referenced policy turns safe checks off, which fails even though another policy detail was unreadable.", {
        scans_readable: true, scan_count: 3, discovery_scan_count: 0, failing_policy_count: 1, policy_details_readable: true, evaluated_policy_count: 2,
        scans_without_policy_id_count: 0, unreadable_policy_count: 1, unverified_policy_count: 0, policy_details_complete: true, warning_policy_count: 0,
        templates_readable: true, policies_readable: true, caller_is_administrator: true,
      }),
      example("partial", "warn", "Every policy is safe, but one visible scan carries no policy_id and was not evaluated.", {
        scans_readable: true, scan_count: 3, discovery_scan_count: 0, failing_policy_count: 0, policy_details_readable: true, evaluated_policy_count: 2,
        scans_without_policy_id_count: 1, unreadable_policy_count: 0, unverified_policy_count: 0, policy_details_complete: true, warning_policy_count: 0,
        templates_readable: true, policies_readable: true, caller_is_administrator: true,
      }),
      example("unreadable", "manual", "The scan list was refused, so no policy can be located.", { scans_readable: false }),
    ],
  },
  {
    id: "TENABLE-02-SC",
    control: 2,
    title: "Scan schedule discipline (Tenable Security Center)",
    severity: "high",
    owner: SCAN_PROGRAM,
    surfaces: ["sc-scans", "sc-scan-results"],
    inputs: ["sc_scans_readable", "sc_scan_count", "sc_recurring_scan_count", "sc_scan_results_readable", "sc_finished_result_age_days", "stale_scan_days"],
    rules: [
      rule("manual", ne("sc_scans_readable", true)),
      rule("fail", eq("sc_scan_count", 0)),
      rule("fail", eq("sc_recurring_scan_count", 0)),
      rule("manual", ne("sc_scan_results_readable", true)),
      rule("pass", some("sc_finished_result_age_days", lte("$", path("stale_scan_days")))),
      rule("fail", always),
    ],
    decision: "Manual when Security Center is not configured or GET /rest/scan is unreadable. Fail when Security Center returns no scan or no scan has an ical (recurring) schedule. Manual when GET /rest/scanResult is unreadable. Pass when at least one scan result whose status mentions completed finished within stale_scan_days; otherwise fail.",
    examples: [
      example("compliant", "pass", "A completed result finished exactly 30 days ago, inside the 30-day window.", {
        sc_scans_readable: true, sc_scan_count: 2, sc_recurring_scan_count: 1, sc_scan_results_readable: true, sc_finished_result_age_days: [30], stale_scan_days: 30,
      }),
      example("noncompliant", "fail", "Scans are visible, but none uses an ical schedule, which fails before the results are consulted.", {
        sc_scans_readable: true, sc_scan_count: 2, sc_recurring_scan_count: 0, sc_scan_results_readable: false,
      }),
      example("unreadable", "manual", "Security Center is not configured.", { sc_scans_readable: false }),
    ],
  },
  {
    id: "TENABLE-02",
    control: 2,
    title: "Scan schedule discipline",
    severity: "high",
    owner: SCAN_PROGRAM,
    surfaces: ["scans", "users"],
    inputs: [
      "scans_readable", "scan_count", "enabled_recurring_scan_count", "recurring_scan_age_days", "stale_scan_days",
      "never_run_or_undated_recurring_scan_count", "caller_is_administrator",
    ],
    rules: [
      rule("manual", ne("scans_readable", true)),
      rule("fail", eq("scan_count", 0)),
      rule("fail", eq("enabled_recurring_scan_count", 0)),
      rule("fail", some("recurring_scan_age_days", gt("$", path("stale_scan_days")))),
      rule("warn", gt("never_run_or_undated_recurring_scan_count", 0)),
      rule("warn", ne("caller_is_administrator", true)),
      rule("pass", always),
    ],
    decision: "Manual when GET /scans is unreadable. Fail when no scan is visible, when no scan is enabled with a recurring rrules schedule, or when any enabled recurring scan last launched more than stale_scan_days ago. Warn when an enabled recurring scan has never run or carries no parseable launch date. Warn instead of pass when the key is not confirmed as Administrator. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Both recurring scans launched within the window, and the key is an Administrator.", {
        scans_readable: true, scan_count: 4, enabled_recurring_scan_count: 2, recurring_scan_age_days: [2, 30], stale_scan_days: 30,
        never_run_or_undated_recurring_scan_count: 0, caller_is_administrator: true,
      }),
      example("noncompliant", "fail", "One recurring scan last launched 31 days ago, past the 30-day window.", {
        scans_readable: true, scan_count: 4, enabled_recurring_scan_count: 2, recurring_scan_age_days: [2, 31], stale_scan_days: 30,
        never_run_or_undated_recurring_scan_count: 0, caller_is_administrator: true,
      }),
      example("partial", "warn", "A third recurring scan has never run, so it is not counted as fresh.", {
        scans_readable: true, scan_count: 4, enabled_recurring_scan_count: 3, recurring_scan_age_days: [2, 30], stale_scan_days: 30,
        never_run_or_undated_recurring_scan_count: 1, caller_is_administrator: true,
      }),
      example("unreadable", "manual", "The scan list failed, so no schedule can be assessed.", { scans_readable: false }),
    ],
  },
  {
    id: "TENABLE-17",
    control: 17,
    title: "Compliance audit templates",
    severity: "medium",
    owner: SCAN_PROGRAM,
    surfaces: ["scans", "scan-templates", "users"],
    inputs: ["scans_readable", "templates_readable", "scan_count", "active_compliance_scan_count", "caller_is_administrator"],
    rules: [
      rule("manual", ne("scans_readable", true)),
      rule("manual", ne("templates_readable", true)),
      rule("fail", eq("scan_count", 0)),
      rule("fail", eq("active_compliance_scan_count", 0)),
      rule("warn", ne("caller_is_administrator", true)),
      rule("pass", always),
    ],
    decision: "Manual when GET /scans or GET /editor/scan/templates is unreadable. Fail when no scan is visible or when no enabled recurring scan resolves to a template whose name or title mentions compliance, PCI, SCAP, audit, offline config, or STIG. Warn instead of pass when the key is not confirmed as Administrator. Otherwise pass.",
    examples: [
      example("compliant", "pass", "An enabled recurring scan uses a compliance audit template, and the key is an Administrator.", {
        scans_readable: true, templates_readable: true, scan_count: 5, active_compliance_scan_count: 1, caller_is_administrator: true,
      }),
      example("noncompliant", "fail", "Scans exist, but none is an enabled recurring compliance scan.", {
        scans_readable: true, templates_readable: true, scan_count: 5, active_compliance_scan_count: 0, caller_is_administrator: true,
      }),
      example("partial", "warn", "A compliance scan runs, but the key is not confirmed as Administrator, so other scans may be hidden.", {
        scans_readable: true, templates_readable: true, scan_count: 5, active_compliance_scan_count: 1, caller_is_administrator: false,
      }),
      example("unreadable", "manual", "The template list was refused, so compliance templates cannot be recognized.", {
        scans_readable: true, templates_readable: false,
      }),
    ],
  },
  {
    id: "TENABLE-04",
    control: 4,
    title: "Credentialed scan ratio",
    severity: "high",
    owner: SCAN_PROGRAM,
    surfaces: ["asset-export-request", "asset-export-status", "asset-export-chunks"],
    inputs: ["asset_export_readable", "asset_count", "credentialed_coverage_ratio", "credential_threshold", "asset_export_complete"],
    rules: [
      rule("manual", ne("asset_export_readable", true)),
      rule("manual", eq("asset_count", 0)),
      rule("fail", lt("credentialed_coverage_ratio", path("credential_threshold"))),
      rule("warn", ne("asset_export_complete", true)),
      rule("pass", always),
    ],
    completeness: { asset_export_complete: ASSET_EXPORT_COMPLETE },
    decision: "Manual when the asset export did not finish or no available chunk could be downloaded, and manual when it finished with zero assets. Fail when the share of exported assets with a successful authenticated scan or an agent is below credential_threshold. Warn instead of pass when the export left chunks unread, reported failed chunks, or held records that could not be evaluated. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Nine of ten exported assets were scanned with credentials or by an agent, above the 0.8 threshold.", {
        asset_export_readable: true, asset_count: 10, credentialed_coverage_ratio: 0.9, credential_threshold: 0.8, asset_export_complete: true,
      }),
      example("noncompliant", "fail", "Seven of ten assets were credentialed, below the 0.8 threshold, even though the export was partial.", {
        asset_export_readable: true, asset_count: 10, credentialed_coverage_ratio: 0.7, credential_threshold: 0.8, asset_export_complete: false,
      }),
      example("partial", "warn", "Coverage meets the threshold exactly, but the export left chunks unread.", {
        asset_export_readable: true, asset_count: 10, credentialed_coverage_ratio: 0.8, credential_threshold: 0.8, asset_export_complete: false,
      }),
      example("unreadable", "manual", "The export finished with zero assets, so no ratio exists.", {
        asset_export_readable: true, asset_count: 0, credentialed_coverage_ratio: 0, credential_threshold: 0.8, asset_export_complete: true,
      }),
    ],
  },
  {
    id: "TENABLE-13",
    control: 13,
    title: "Scan exclusion audit",
    severity: "medium",
    owner: SCAN_PROGRAM,
    surfaces: ["exclusions"],
    inputs: ["exclusions_readable", "exclusions_complete", "permanent_exclusion_count", "broad_exclusion_count", "undocumented_exclusion_count"],
    rules: [
      rule("manual", ne("exclusions_readable", true)),
      rule("fail", any(gt("permanent_exclusion_count", 0), gt("broad_exclusion_count", 0))),
      rule("warn", gt("undocumented_exclusion_count", 0)),
      rule("warn", ne("exclusions_complete", true)),
      rule("pass", always),
    ],
    completeness: {
      exclusions_complete: completeFrom(
        "true when the offset walk ended on an empty or short page or reached pagination.total; false when it stopped at the 200-page cap, delivered fewer records than pagination.total, or the endpoint replayed a page.",
        [{ surfaceId: "exclusions", falseWhen: ["truncated"] }],
      ),
    },
    decision: "Manual when GET /exclusions is unreadable. Fail when any delivered exclusion is always on (schedule.enabled is not true) or covers a /16 or wider range. Warn when an exclusion has no description. Warn instead of pass when the exclusion walk stopped before the end of the list. Otherwise pass, including when no exclusion exists.",
    examples: [
      example("compliant", "pass", "The complete list holds no always-on, broad, or undocumented exclusion.", {
        exclusions_readable: true, exclusions_complete: true, permanent_exclusion_count: 0, broad_exclusion_count: 0, undocumented_exclusion_count: 0,
      }),
      example("noncompliant", "fail", "One delivered exclusion is always on; the partial walk does not soften the failure.", {
        exclusions_readable: true, exclusions_complete: false, permanent_exclusion_count: 1, broad_exclusion_count: 0, undocumented_exclusion_count: 0,
      }),
      example("partial", "warn", "Every delivered exclusion is clean, but the walk stopped short of pagination.total.", {
        exclusions_readable: true, exclusions_complete: false, permanent_exclusion_count: 0, broad_exclusion_count: 0, undocumented_exclusion_count: 0,
      }),
      example("unreadable", "manual", "GET /exclusions was refused.", { exclusions_readable: false }),
    ],
  },
  {
    id: "TENABLE-20",
    control: 20,
    title: "Target group management",
    severity: "low",
    owner: SCAN_PROGRAM,
    surfaces: ["target-groups", "users"],
    inputs: ["target_groups_readable", "target_group_age_days", "undated_target_group_count", "overlapping_member_count", "caller_is_administrator"],
    rules: [
      rule("manual", ne("target_groups_readable", true)),
      rule("warn", any(
        some("target_group_age_days", gt("$", 365)),
        gt("undated_target_group_count", 0),
        gt("overlapping_member_count", 0),
      )),
      rule("warn", ne("caller_is_administrator", true)),
      rule("pass", always),
    ],
    decision: "Manual when GET /target-groups is unreadable. Warn when any legacy target group was last modified more than 365 days ago or carries no parseable modification date, or when any member target appears more than once across target groups. Warn instead of pass when the key is not confirmed as Administrator. Otherwise pass, including when no target group exists.",
    examples: [
      example("compliant", "pass", "No legacy target group remains, and the key is an Administrator.", {
        target_groups_readable: true, target_group_age_days: [], undated_target_group_count: 0, overlapping_member_count: 0, caller_is_administrator: true,
      }),
      example("partial", "warn", "One target group was last modified 366 days ago.", {
        target_groups_readable: true, target_group_age_days: [10, 366], undated_target_group_count: 0, overlapping_member_count: 0, caller_is_administrator: true,
      }),
      example("unreadable", "manual", "GET /target-groups failed.", { target_groups_readable: false }),
    ],
  },
];

const SENSOR_COVERAGE = "tenable_assess_sensor_coverage";
const ASSET_EXPORT_SURFACES = ["asset-export-request", "asset-export-status", "asset-export-chunks"];

const SENSOR_COVERAGE_CHECKS: readonly TenableCheck[] = [
  {
    id: "TENABLE-03",
    control: 3,
    title: "Asset discovery coverage",
    severity: "high",
    owner: SENSOR_COVERAGE,
    surfaces: [...ASSET_EXPORT_SURFACES, "networks"],
    inputs: ["asset_export_readable", "asset_count", "expected_asset_coverage_ratio", "asset_export_complete", "networks_complete"],
    inputTypes: { expected_asset_coverage_ratio: ["null"] },
    rules: [
      rule("manual", ne("asset_export_readable", true)),
      rule("fail", eq("asset_count", 0)),
      rule("manual", isNull("expected_asset_coverage_ratio")),
      rule("fail", lt("expected_asset_coverage_ratio", 0.95)),
      rule("warn", any(ne("asset_export_complete", true), ne("networks_complete", true))),
      rule("pass", always),
    ],
    completeness: { asset_export_complete: ASSET_EXPORT_COMPLETE, networks_complete: walkComplete("networks", "GET /networks") },
    decision: "Manual when the asset export did not finish or no available chunk could be downloaded. Fail when the export finished with zero assets, since no inventory exists to compare. Manual when expected_asset_count is not supplied or not positive, since the API does not know the expected population. Fail when the assets seen within stale_asset_days cover less than 95% of expected_asset_count. Warn instead of pass when the export left chunks unread or held unevaluable records, or the network list was unreadable or truncated. Otherwise pass.",
    examples: [
      example("compliant", "pass", "97 of 100 expected assets were seen recently and every read was complete.", {
        asset_export_readable: true, asset_count: 110, expected_asset_coverage_ratio: 0.97, asset_export_complete: true, networks_complete: true,
      }),
      example("noncompliant", "fail", "Only 80% of the expected population was seen recently.", {
        asset_export_readable: true, asset_count: 90, expected_asset_coverage_ratio: 0.8, asset_export_complete: true, networks_complete: true,
      }),
      example("partial", "warn", "Coverage meets 95% exactly, but the network walk stopped early.", {
        asset_export_readable: true, asset_count: 100, expected_asset_coverage_ratio: 0.95, asset_export_complete: true, networks_complete: false,
      }),
      example("unreadable", "manual", "No expected_asset_count was supplied, so coverage has no denominator.", {
        asset_export_readable: true, asset_count: 100, expected_asset_coverage_ratio: null, asset_export_complete: true, networks_complete: true,
      }),
    ],
  },
  {
    id: "TENABLE-16",
    control: 16,
    title: "Asset tagging strategy",
    severity: "medium",
    owner: SENSOR_COVERAGE,
    surfaces: [...ASSET_EXPORT_SURFACES, "tag-categories", "tag-values"],
    inputs: [
      "asset_export_readable", "tag_categories_readable", "asset_count", "tag_category_count", "tag_categories_complete",
      "tagged_asset_ratio", "tagged_threshold", "asset_export_complete", "tag_values_complete",
    ],
    rules: [
      rule("manual", ne("asset_export_readable", true)),
      rule("manual", ne("tag_categories_readable", true)),
      rule("manual", eq("asset_count", 0)),
      rule("warn", all(eq("tag_category_count", 0), ne("tag_categories_complete", true))),
      rule("fail", eq("tag_category_count", 0)),
      rule("fail", lt("tagged_asset_ratio", path("tagged_threshold"))),
      rule("warn", any(ne("asset_export_complete", true), ne("tag_categories_complete", true), ne("tag_values_complete", true))),
      rule("pass", always),
    ],
    completeness: {
      asset_export_complete: ASSET_EXPORT_COMPLETE,
      tag_categories_complete: walkComplete("tag-categories", "GET /tags/categories"),
      tag_values_complete: walkComplete("tag-values", "GET /tags/values"),
    },
    decision: "Manual when the asset export did not finish or no available chunk could be downloaded, when the tag category list is unreadable, or when the export finished with zero assets. Warn when the category walk delivered no category but stopped early, since the taxonomy was not read. Fail when no tag category is defined, or when the share of exported assets carrying at least one tag is below tagged_threshold. Warn instead of pass when the export was partial, the category walk stopped early, or the tag value list was unreadable or truncated. Otherwise pass.",
    examples: [
      example("compliant", "pass", "95% of assets carry a tag across four categories, above the 0.9 threshold.", {
        asset_export_readable: true, tag_categories_readable: true, asset_count: 100, tag_category_count: 4, tag_categories_complete: true,
        tagged_asset_ratio: 0.95, tagged_threshold: 0.9, asset_export_complete: true, tag_values_complete: true,
      }),
      example("noncompliant", "fail", "Only 60% of assets carry a tag, below the 0.9 threshold.", {
        asset_export_readable: true, tag_categories_readable: true, asset_count: 100, tag_category_count: 4, tag_categories_complete: true,
        tagged_asset_ratio: 0.6, tagged_threshold: 0.9, asset_export_complete: true, tag_values_complete: true,
      }),
      example("partial", "warn", "Tag coverage meets the threshold, but the tag value walk stopped early.", {
        asset_export_readable: true, tag_categories_readable: true, asset_count: 100, tag_category_count: 4, tag_categories_complete: true,
        tagged_asset_ratio: 0.9, tagged_threshold: 0.9, asset_export_complete: true, tag_values_complete: false,
      }),
      example("unreadable", "manual", "The tag category list was refused, so the taxonomy is unknown.", {
        asset_export_readable: true, tag_categories_readable: false, asset_count: 100,
      }),
    ],
  },
  {
    id: "TENABLE-05",
    control: 5,
    title: "Agent deployment status",
    severity: "high",
    owner: SENSOR_COVERAGE,
    surfaces: ["agents", "server-properties"],
    inputs: [
      "agents_readable", "agent_count", "unhealthy_agent_ratio", "undated_agent_count", "outdated_agent_count", "agents_complete",
      "server_properties_readable",
    ],
    rules: [
      rule("manual", ne("agents_readable", true)),
      rule("manual", eq("agent_count", 0)),
      rule("fail", gt("unhealthy_agent_ratio", 0.1)),
      rule("warn", any(
        gt("undated_agent_count", 0),
        gt("outdated_agent_count", 0),
        ne("agents_complete", true),
        ne("server_properties_readable", true),
      )),
      rule("pass", always),
    ],
    completeness: { agents_complete: walkComplete("agents", "GET /scanners/null/agents") },
    decision: "Manual when the agent list is unreadable or empty; an unlicensed tenant with no agents is reported the same way. Fail when more than 10% of agents are offline or have not connected within agent_offline_days. Warn when any agent has no last_connect or runs a major or minor version behind the newest agent, when the agent walk stopped early, or when the server properties holding the licensed agent count were unreadable. Otherwise pass.",
    examples: [
      example("compliant", "pass", "One of fifty agents is offline and every agent runs the newest version.", {
        agents_readable: true, agent_count: 50, unhealthy_agent_ratio: 0.02, undated_agent_count: 0, outdated_agent_count: 0, agents_complete: true,
        server_properties_readable: true,
      }),
      example("noncompliant", "fail", "Ten of fifty agents are offline or stale, more than 10%.", {
        agents_readable: true, agent_count: 50, unhealthy_agent_ratio: 0.2, undated_agent_count: 0, outdated_agent_count: 0, agents_complete: true,
        server_properties_readable: true,
      }),
      example("partial", "warn", "Exactly 10% of agents are unhealthy, which does not fail, but two agents have no last_connect.", {
        agents_readable: true, agent_count: 50, unhealthy_agent_ratio: 0.1, undated_agent_count: 2, outdated_agent_count: 0, agents_complete: true,
        server_properties_readable: true,
      }),
      example("unreadable", "manual", "No agents are linked, so deployment cannot be confirmed.", {
        agents_readable: true, agent_count: 0, unhealthy_agent_ratio: 0, undated_agent_count: 0, outdated_agent_count: 0, agents_complete: true,
        server_properties_readable: true,
      }),
    ],
  },
  {
    id: "TENABLE-06",
    control: 6,
    title: "Agent group organization",
    severity: "medium",
    owner: SENSOR_COVERAGE,
    surfaces: ["agents", "agent-groups"],
    inputs: [
      "agents_readable", "agent_count", "agent_groups_readable", "agent_group_count", "ungrouped_agent_ratio", "ungrouped_agent_count",
      "agents_complete",
    ],
    inputTypes: { agent_group_count: ["null"] },
    rules: [
      rule("manual", ne("agents_readable", true)),
      rule("manual", eq("agent_count", 0)),
      rule("manual", ne("agent_groups_readable", true)),
      rule("fail", any(eq("agent_group_count", 0), gt("ungrouped_agent_ratio", 0.1))),
      rule("warn", any(gt("ungrouped_agent_count", 0), ne("agents_complete", true))),
      rule("pass", always),
    ],
    completeness: { agents_complete: walkComplete("agents", "GET /scanners/null/agents") },
    decision: "Manual when the agent list is unreadable or empty, or when the agent group list is unreadable. Fail when no agent group exists or more than 10% of agents belong to no group. Warn when any agent is ungrouped or the agent walk stopped early. Otherwise pass.",
    examples: [
      example("compliant", "pass", "All forty agents belong to one of three groups.", {
        agents_readable: true, agent_count: 40, agent_groups_readable: true, agent_group_count: 3, ungrouped_agent_ratio: 0, ungrouped_agent_count: 0,
        agents_complete: true,
      }),
      example("noncompliant", "fail", "No agent group exists, so every agent is ungrouped.", {
        agents_readable: true, agent_count: 40, agent_groups_readable: true, agent_group_count: 0, ungrouped_agent_ratio: 1, ungrouped_agent_count: 40,
        agents_complete: true,
      }),
      example("partial", "warn", "Two of forty agents are ungrouped, within the 10% tolerance.", {
        agents_readable: true, agent_count: 40, agent_groups_readable: true, agent_group_count: 3, ungrouped_agent_ratio: 0.05, ungrouped_agent_count: 2,
        agents_complete: true,
      }),
      example("unreadable", "manual", "The agent group list was refused.", {
        agents_readable: true, agent_count: 40, agent_groups_readable: false, agent_group_count: null, ungrouped_agent_ratio: 0.05, ungrouped_agent_count: 2,
        agents_complete: true,
      }),
    ],
  },
  {
    id: "TENABLE-07-SC",
    control: 7,
    title: "Scanner health and version (Tenable Security Center)",
    severity: "high",
    owner: SENSOR_COVERAGE,
    surfaces: ["sc-scanners", "sc-feed"],
    inputs: [
      "sc_scanners_readable", "sc_scanner_count", "sc_unhealthy_scanner_count", "sc_scanner_checkin_age_days", "sc_scanner_plugin_set_age_hours",
      "plugin_stale_hours", "sc_feed_marked_stale", "sc_undated_scanner_count", "sc_feed_readable",
    ],
    rules: [
      rule("manual", ne("sc_scanners_readable", true)),
      rule("manual", eq("sc_scanner_count", 0)),
      rule("fail", any(
        gt("sc_unhealthy_scanner_count", 0),
        some("sc_scanner_checkin_age_days", gt("$", 1)),
        some("sc_scanner_plugin_set_age_hours", gt("$", path("plugin_stale_hours"))),
        eq("sc_feed_marked_stale", true),
      )),
      rule("warn", any(gt("sc_undated_scanner_count", 0), ne("sc_feed_readable", true))),
      rule("pass", always),
    ],
    decision: "Manual when Security Center is not configured, its scanner list is unreadable, or it returned zero scanners. Fail when an enabled scanner reports a status other than 1, last checked in more than one day before the assessment, or loads a plugin set older than plugin_stale_hours, or when the active plugin feed is marked stale. Warn when an enabled scanner has no lastCheckinTime or the feed status is unreadable. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Both enabled scanners work, checked in today, and load a fresh plugin set.", {
        sc_scanners_readable: true, sc_scanner_count: 2, sc_unhealthy_scanner_count: 0, sc_scanner_checkin_age_days: [0.2, 0.4],
        sc_scanner_plugin_set_age_hours: [5, 6], plugin_stale_hours: 24, sc_feed_marked_stale: false, sc_undated_scanner_count: 0, sc_feed_readable: true,
      }),
      example("noncompliant", "fail", "The active plugin feed is marked stale.", {
        sc_scanners_readable: true, sc_scanner_count: 2, sc_unhealthy_scanner_count: 0, sc_scanner_checkin_age_days: [0.2, 0.4],
        sc_scanner_plugin_set_age_hours: [5, 6], plugin_stale_hours: 24, sc_feed_marked_stale: true, sc_undated_scanner_count: 0, sc_feed_readable: true,
      }),
      example("partial", "warn", "Every scanner is healthy, but the feed status could not be read.", {
        sc_scanners_readable: true, sc_scanner_count: 2, sc_unhealthy_scanner_count: 0, sc_scanner_checkin_age_days: [0.2, 0.4],
        sc_scanner_plugin_set_age_hours: [5, 6], plugin_stale_hours: 24, sc_feed_marked_stale: false, sc_undated_scanner_count: 0, sc_feed_readable: false,
      }),
      example("unreadable", "manual", "Security Center is not configured, so no scanner list exists.", { sc_scanners_readable: false }),
    ],
  },
  {
    id: "TENABLE-07",
    control: 7,
    title: "Scanner health and version",
    severity: "high",
    owner: SENSOR_COVERAGE,
    surfaces: ["scanners", "users"],
    inputs: [
      "scanners_readable", "scanner_count", "linked_scanner_count", "unlinked_scanner_count", "off_scanner_count", "linked_scanner_connect_age_days",
      "undated_linked_scanner_count", "outdated_linked_scanner_count", "caller_is_administrator",
    ],
    rules: [
      rule("manual", ne("scanners_readable", true)),
      rule("manual", eq("scanner_count", 0)),
      rule("manual", eq("linked_scanner_count", 0)),
      rule("fail", any(
        gt("unlinked_scanner_count", 0),
        gt("off_scanner_count", 0),
        some("linked_scanner_connect_age_days", gt("$", 1)),
      )),
      rule("warn", any(
        gt("undated_linked_scanner_count", 0),
        gt("outdated_linked_scanner_count", 0),
        ne("caller_is_administrator", true),
      )),
      rule("pass", always),
    ],
    decision: "Manual when the scanner list is unreadable, empty, or holds only Tenable-managed cloud scanners, pools, and groups. Fail when any linked scanner appliance is not linked, is not on, or last connected more than one day before the assessment. Warn when a linked appliance has no last_connect or runs an older ui_version than the newest linked appliance, or when the key is not confirmed as Administrator. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Both linked appliances are on, linked, connected today, and current, and the key is Administrator.", {
        scanners_readable: true, scanner_count: 3, linked_scanner_count: 2, unlinked_scanner_count: 0, off_scanner_count: 0,
        linked_scanner_connect_age_days: [0.1, 0.5], undated_linked_scanner_count: 0, outdated_linked_scanner_count: 0, caller_is_administrator: true,
      }),
      example("noncompliant", "fail", "One linked appliance is off.", {
        scanners_readable: true, scanner_count: 3, linked_scanner_count: 2, unlinked_scanner_count: 0, off_scanner_count: 1,
        linked_scanner_connect_age_days: [0.1, 0.5], undated_linked_scanner_count: 0, outdated_linked_scanner_count: 0, caller_is_administrator: true,
      }),
      example("partial", "warn", "Every appliance is healthy, but the key is not confirmed as Administrator.", {
        scanners_readable: true, scanner_count: 3, linked_scanner_count: 2, unlinked_scanner_count: 0, off_scanner_count: 0,
        linked_scanner_connect_age_days: [0.1, 0.5], undated_linked_scanner_count: 0, outdated_linked_scanner_count: 0, caller_is_administrator: false,
      }),
      example("unreadable", "manual", "Only cloud scanners are visible, so no linked appliance exists to evaluate.", {
        scanners_readable: true, scanner_count: 2, linked_scanner_count: 0,
      }),
    ],
  },
  {
    id: "TENABLE-08",
    control: 8,
    title: "Plugin update currency",
    severity: "high",
    owner: SENSOR_COVERAGE,
    surfaces: ["server-properties", "scanners", "agents"],
    inputs: [
      "server_properties_readable", "server_plugin_set_age_hours", "plugin_stale_hours", "scanner_plugin_set_age_hours", "scanners_readable",
      "scanners_without_plugin_set_count", "online_agent_plugin_set_age_hours", "agents_complete",
    ],
    inputTypes: { server_plugin_set_age_hours: ["null"] },
    rules: [
      rule("manual", ne("server_properties_readable", true)),
      rule("manual", isNull("server_plugin_set_age_hours")),
      rule("fail", any(
        gt("server_plugin_set_age_hours", path("plugin_stale_hours")),
        some("scanner_plugin_set_age_hours", gt("$", path("plugin_stale_hours"))),
      )),
      rule("manual", ne("scanners_readable", true)),
      rule("manual", eq(lengthOf("scanner_plugin_set_age_hours"), 0)),
      rule("warn", any(
        gt("scanners_without_plugin_set_count", 0),
        some("online_agent_plugin_set_age_hours", gt("$", path("plugin_stale_hours"))),
        ne("agents_complete", true),
      )),
      rule("pass", always),
    ],
    completeness: { agents_complete: walkComplete("agents", "GET /scanners/null/agents") },
    decision: "Manual when the server properties are unreadable or expose no parseable plugin set. Fail when the container plugin set, or the loaded plugin set of any scanner entry, is older than plugin_stale_hours. Manual when the scanner list is unreadable or no scanner entry exposes a parseable loaded plugin set. Warn when a scanner instance exposes no parseable plugin set, an online agent loads a plugin set older than plugin_stale_hours, or the agent list is unreadable or truncated. Otherwise pass.",
    examples: [
      example("compliant", "pass", "The container, both scanners, and every online agent load a plugin set under 24 hours old.", {
        server_properties_readable: true, server_plugin_set_age_hours: 6, plugin_stale_hours: 24, scanner_plugin_set_age_hours: [6, 7],
        scanners_readable: true, scanners_without_plugin_set_count: 0, online_agent_plugin_set_age_hours: [8], agents_complete: true,
      }),
      example("noncompliant", "fail", "One scanner loads a plugin set 40 hours old.", {
        server_properties_readable: true, server_plugin_set_age_hours: 6, plugin_stale_hours: 24, scanner_plugin_set_age_hours: [6, 40],
        scanners_readable: true, scanners_without_plugin_set_count: 0, online_agent_plugin_set_age_hours: [8], agents_complete: true,
      }),
      example("partial", "warn", "Every plugin set is current, but the agent walk stopped early.", {
        server_properties_readable: true, server_plugin_set_age_hours: 6, plugin_stale_hours: 24, scanner_plugin_set_age_hours: [6, 7],
        scanners_readable: true, scanners_without_plugin_set_count: 0, online_agent_plugin_set_age_hours: [8], agents_complete: false,
      }),
      example("unreadable", "manual", "The server properties expose no parseable plugin set.", {
        server_properties_readable: true, server_plugin_set_age_hours: null, plugin_stale_hours: 24,
      }),
    ],
  },
  {
    id: "TENABLE-09",
    control: 9,
    title: "Network zone configuration",
    severity: "medium",
    owner: SENSOR_COVERAGE,
    surfaces: ["networks"],
    inputs: ["networks_readable", "network_count", "zero_scanner_network_count", "unreported_scanner_network_count", "networks_complete"],
    rules: [
      rule("manual", ne("networks_readable", true)),
      rule("manual", eq("network_count", 0)),
      rule("fail", gt("zero_scanner_network_count", 0)),
      rule("warn", any(gt("unreported_scanner_network_count", 0), ne("networks_complete", true))),
      rule("pass", always),
    ],
    completeness: { networks_complete: walkComplete("networks", "GET /networks") },
    decision: "Manual when the network list is unreadable or empty, since the default network always exists. Fail when any network has scanner_count 0. Warn when a network does not report scanner_count or the network walk stopped early. Otherwise pass.",
    examples: [
      example("compliant", "pass", "All three networks have an assigned scanner.", {
        networks_readable: true, network_count: 3, zero_scanner_network_count: 0, unreported_scanner_network_count: 0, networks_complete: true,
      }),
      example("noncompliant", "fail", "One network has no assigned scanner.", {
        networks_readable: true, network_count: 3, zero_scanner_network_count: 1, unreported_scanner_network_count: 0, networks_complete: true,
      }),
      example("partial", "warn", "Every network read has a scanner, but the walk stopped early.", {
        networks_readable: true, network_count: 3, zero_scanner_network_count: 0, unreported_scanner_network_count: 0, networks_complete: false,
      }),
      example("unreadable", "manual", "Zero networks were returned, so the view is incomplete.", {
        networks_readable: true, network_count: 0, zero_scanner_network_count: 0, unreported_scanner_network_count: 0, networks_complete: true,
      }),
    ],
  },
];

const ACCESS_CONTROL = "tenable_assess_access_control";

const ACCESS_CONTROL_CHECKS: readonly TenableCheck[] = [
  {
    id: "TENABLE-10-SC",
    control: 10,
    title: "User role and permission audit (Tenable Security Center)",
    severity: "high",
    owner: ACCESS_CONTROL,
    surfaces: ["sc-users"],
    inputs: [
      "sc_users_readable", "sc_user_count", "sc_active_user_last_login_age_days", "inactive_user_days", "sc_never_logged_in_user_count",
      "sc_locked_user_count",
    ],
    rules: [
      rule("manual", ne("sc_users_readable", true)),
      rule("manual", eq("sc_user_count", 0)),
      rule("fail", some("sc_active_user_last_login_age_days", gt("$", path("inactive_user_days")))),
      rule("warn", any(gt("sc_never_logged_in_user_count", 0), gt("sc_locked_user_count", 0))),
      rule("pass", always),
    ],
    decision: "Manual when Security Center is not configured, its user list is unreadable, or it returned zero users, since the calling user must exist. Fail when an active user (status 0) last logged in more than inactive_user_days before the assessment. Warn when an active user never logged in or is locked. Otherwise pass.",
    examples: [
      example("compliant", "pass", "All three active users logged in within the last month.", {
        sc_users_readable: true, sc_user_count: 3, sc_active_user_last_login_age_days: [1, 4, 20], inactive_user_days: 90,
        sc_never_logged_in_user_count: 0, sc_locked_user_count: 0,
      }),
      example("noncompliant", "fail", "One active user last logged in 120 days ago, past the 90-day window.", {
        sc_users_readable: true, sc_user_count: 3, sc_active_user_last_login_age_days: [1, 4, 120], inactive_user_days: 90,
        sc_never_logged_in_user_count: 0, sc_locked_user_count: 0,
      }),
      example("partial", "warn", "Every login is recent, but one active user is locked.", {
        sc_users_readable: true, sc_user_count: 3, sc_active_user_last_login_age_days: [1, 4, 20], inactive_user_days: 90,
        sc_never_logged_in_user_count: 0, sc_locked_user_count: 1,
      }),
      example("unreadable", "manual", "Security Center is not configured, so no user list exists.", { sc_users_readable: false }),
    ],
  },
  {
    id: "TENABLE-10",
    control: 10,
    title: "User role and permission audit",
    severity: "high",
    owner: ACCESS_CONTROL,
    surfaces: ["users", "roles"],
    inputs: [
      "users_readable", "user_count", "caller_is_administrator", "administrators_without_strong_auth_count", "enabled_user_last_login_age_days",
      "inactive_user_days", "enabled_administrator_count", "max_admins", "enabled_user_count", "never_logged_in_user_count",
      "enabled_user_api_key_age_days", "locked_out_user_count", "enabled_user_login_failure_counts", "users_without_enabled_flag_count",
      "roles_readable",
    ],
    rules: [
      rule("manual", ne("users_readable", true)),
      rule("manual", eq("user_count", 0)),
      rule("manual", ne("caller_is_administrator", true)),
      rule("fail", any(
        gt("administrators_without_strong_auth_count", 0),
        some("enabled_user_last_login_age_days", gt("$", path("inactive_user_days"))),
        gt("enabled_administrator_count", path("max_admins")),
      )),
      rule("manual", eq("enabled_user_count", 0)),
      rule("warn", any(
        gt("never_logged_in_user_count", 0),
        some("enabled_user_api_key_age_days", gt("$", path("inactive_user_days"))),
        gt("locked_out_user_count", 0),
        some("enabled_user_login_failure_counts", gte("$", 5)),
        gt("users_without_enabled_flag_count", 0),
        ne("roles_readable", true),
      )),
      rule("pass", always),
    ],
    decision: "Manual when the user list is unreadable or empty, since the calling user must exist, or when users come back in the reduced shape because the key is not Administrator, which hides roles, logins, and two-factor settings. Fail when an enabled Administrator allowed into the UI has neither SAML-only login nor two-factor enabled, when an enabled user last logged in more than inactive_user_days before the assessment, or when enabled Administrators outnumber max_admins. Manual when no user is enabled, since the calling user is then unaccounted for. Warn when an enabled user never logged in, holds an API key unused for more than inactive_user_days, is locked out, or shows 5 or more failed logins, when any user exposes no enabled flag, or when the role list is unreadable. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Four enabled users logged in recently, and both Administrators enforce SAML-only login.", {
        users_readable: true, user_count: 5, caller_is_administrator: true, administrators_without_strong_auth_count: 0,
        enabled_user_last_login_age_days: [1, 3, 10, 30], inactive_user_days: 90, enabled_administrator_count: 2, max_admins: 5,
        enabled_user_count: 4, never_logged_in_user_count: 0, enabled_user_api_key_age_days: [2, 15], locked_out_user_count: 0,
        enabled_user_login_failure_counts: [0, 0, 1, 0], users_without_enabled_flag_count: 0, roles_readable: true,
      }),
      example("noncompliant", "fail", "One enabled user last logged in 120 days ago, past the 90-day window.", {
        users_readable: true, user_count: 5, caller_is_administrator: true, administrators_without_strong_auth_count: 0,
        enabled_user_last_login_age_days: [1, 3, 10, 120], inactive_user_days: 90, enabled_administrator_count: 2, max_admins: 5,
        enabled_user_count: 4, never_logged_in_user_count: 0, enabled_user_api_key_age_days: [2, 15], locked_out_user_count: 0,
        enabled_user_login_failure_counts: [0, 0, 1, 0], users_without_enabled_flag_count: 0, roles_readable: true,
      }),
      example("partial", "warn", "Every user is healthy, but the role list could not be read, so custom roles are unknown.", {
        users_readable: true, user_count: 5, caller_is_administrator: true, administrators_without_strong_auth_count: 0,
        enabled_user_last_login_age_days: [1, 3, 10, 30], inactive_user_days: 90, enabled_administrator_count: 2, max_admins: 5,
        enabled_user_count: 4, never_logged_in_user_count: 0, enabled_user_api_key_age_days: [2, 15], locked_out_user_count: 0,
        enabled_user_login_failure_counts: [0, 0, 1, 0], users_without_enabled_flag_count: 0, roles_readable: false,
      }),
      example("unreadable", "manual", "Users came back in the reduced shape, so roles, logins, and two-factor settings are hidden.", {
        users_readable: true, user_count: 5, caller_is_administrator: false,
      }),
    ],
  },
  {
    id: "TENABLE-11",
    control: 11,
    title: "Access group review",
    severity: "high",
    owner: ACCESS_CONTROL,
    surfaces: ["permissions", "access-groups", "groups", "users"],
    inputs: [
      "permissions_readable", "permission_count", "broad_permission_count", "legacy_access_group_count", "access_groups_complete", "groups_readable",
      "caller_is_administrator",
    ],
    rules: [
      rule("manual", ne("permissions_readable", true)),
      rule("manual", eq("permission_count", 0)),
      rule("fail", gt("broad_permission_count", 0)),
      rule("warn", any(
        gt("legacy_access_group_count", 0),
        ne("access_groups_complete", true),
        ne("groups_readable", true),
        ne("caller_is_administrator", true),
      )),
      rule("pass", always),
    ],
    completeness: { access_groups_complete: walkComplete("access-groups", "GET /v2/access-groups") },
    decision: "Manual when the permission list is unreadable or empty, since Tenable always generates administrator permissions. Fail when any permission grants all users write-style actions (CanEdit, CanScan, or CanUse) on all assets, objects, or tags. Warn when a deprecated access group other than an all-assets group remains, when the access group walk was unreadable or stopped early, when the user group list is unreadable, or when the key is not confirmed as Administrator. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Six scoped permissions, no legacy access group, and an Administrator key.", {
        permissions_readable: true, permission_count: 6, broad_permission_count: 0, legacy_access_group_count: 0, access_groups_complete: true,
        groups_readable: true, caller_is_administrator: true,
      }),
      example("noncompliant", "fail", "One permission lets All Users scan every asset.", {
        permissions_readable: true, permission_count: 6, broad_permission_count: 1, legacy_access_group_count: 0, access_groups_complete: true,
        groups_readable: true, caller_is_administrator: true,
      }),
      example("partial", "warn", "Permissions are scoped, but the access group walk stopped early.", {
        permissions_readable: true, permission_count: 6, broad_permission_count: 0, legacy_access_group_count: 0, access_groups_complete: false,
        groups_readable: true, caller_is_administrator: true,
      }),
      example("unreadable", "manual", "The permission list was refused.", { permissions_readable: false }),
    ],
  },
  {
    id: "TENABLE-12",
    control: 12,
    title: "Managed credential hygiene",
    severity: "medium",
    owner: ACCESS_CONTROL,
    surfaces: ["credentials"],
    inputs: ["credentials_readable", "credential_count", "unused_credential_count", "credential_age_days", "undated_credential_count", "credentials_complete"],
    rules: [
      rule("manual", ne("credentials_readable", true)),
      rule("manual", eq("credential_count", 0)),
      rule("warn", any(
        gt("unused_credential_count", 0),
        some("credential_age_days", gt("$", 365)),
        gt("undated_credential_count", 0),
        ne("credentials_complete", true),
      )),
      rule("pass", always),
    ],
    completeness: { credentials_complete: walkComplete("credentials", "GET /credentials") },
    decision: "Manual when the managed credential walk is unreadable or delivered no credential, since scan-embedded credentials are not listed by the API. Warn when any credential was never used by a scan, was created more than 365 days before the assessment, or has no created_date, since the API exposes no rotation date, or when the walk stopped early. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Three credentials are in use and were created within the last year.", {
        credentials_readable: true, credential_count: 3, unused_credential_count: 0, credential_age_days: [30, 200, 365], undated_credential_count: 0,
        credentials_complete: true,
      }),
      example("partial", "warn", "One credential was created 366 days ago.", {
        credentials_readable: true, credential_count: 3, unused_credential_count: 0, credential_age_days: [30, 200, 366], undated_credential_count: 0,
        credentials_complete: true,
      }),
      example("unreadable", "manual", "The credential walk delivered no credential, so scan credentials need a human review.", {
        credentials_readable: true, credential_count: 0,
      }),
    ],
  },
  {
    id: "TENABLE-18",
    control: 18,
    title: "Audit log review",
    severity: "medium",
    owner: ACCESS_CONTROL,
    surfaces: ["audit-log"],
    inputs: ["audit_log_readable", "audit_event_count", "audit_events_complete", "sensitive_audit_event_count"],
    rules: [
      rule("manual", ne("audit_log_readable", true)),
      rule("warn", any(eq("audit_event_count", 0), ne("audit_events_complete", true), gt("sensitive_audit_event_count", 0))),
      rule("pass", always),
    ],
    completeness: { audit_events_complete: walkComplete("audit-log", "GET /audit-log/v1/events") },
    decision: "Manual when the activity log walk was unreadable. Warn when it returned no event for the audit_lookback_days window, since an active tenant records logins and API calls, when it stopped before the end of the event list, or when it holds sensitive events needing sign-off: deletions, or changes to users, roles, permissions, keys, exclusions, policies, or templates. Otherwise pass.",
    examples: [
      example("compliant", "pass", "All 420 events were read and none is sensitive.", {
        audit_log_readable: true, audit_event_count: 420, audit_events_complete: true, sensitive_audit_event_count: 0,
      }),
      example("partial", "warn", "Two user changes in the window need reviewer sign-off.", {
        audit_log_readable: true, audit_event_count: 420, audit_events_complete: true, sensitive_audit_event_count: 2,
      }),
      example("unreadable", "manual", "The activity log was refused to a non-Administrator key.", { audit_log_readable: false }),
    ],
  },
];

const toCheck = (check: TenableCheck): BatchCheckDefinition => {
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
    ...(check.inputTypes ? { decisionInputTypes: check.inputTypes } : {}),
    decisionConstants: {},
    decisionRules: executable.rules,
    derivedFactRules: executable.derivedFactRules,
    ...(check.completeness ? { completeness: check.completeness } : {}),
    decision: check.decision,
    examples: check.examples,
  };
};

const checks: readonly BatchCheckDefinition[] = [...SCAN_PROGRAM_CHECKS, ...SENSOR_COVERAGE_CHECKS, ...ACCESS_CONTROL_CHECKS].map(toCheck);
const idsFor = (owner: string): string[] => checks.filter((check) => check.owner === owner).map((check) => check.id);
const surfaceIds = (predicate: (surface: BatchSurfaceDefinition) => boolean): string[] =>
  TENABLE_SURFACES.filter(predicate).map((surface) => surface.id);

const offsetWalk = (walked: readonly string[], pageSize: number, pageCap = 200): BatchPaginationDefinition => ({
  surfaceIds: walked,
  cursorFields: ["limit", "offset", "pagination.total"],
  pageSize,
  itemCap: "none",
  pageCap,
  totalSemantics: "When pagination.total is reported the walk must reach it; without a total a page shorter than the limit ends the list.",
  stopConditions: ["An empty page", "pagination.total reached", "A short page when no total is reported", "A page that opens with the same record as the previous page", `The ${pageCap}-page cap`],
});

export const TENABLE_SPEC = buildBatchIntegrationSpec({
  slug: "tenable-sec-inspector",
  displayName: "Tenable Security Inspector",
  vendor: "Tenable",
  category: "vulnerability-management",
  summary: "Portable contract for the shipped Tenable Vulnerability Management and Tenable Security Center scan program, sensor coverage, access control, and vulnerability management assessments.",
  sourceModule: "cli/extensions/grc-tools/tenable.ts",
  baseServices: [VM_SERVICE, SC_SERVICE],
  authentication: TENABLE_AUTH_RESOLVER,
  permissions: [
    {
      id: "vm-administrator",
      kind: "role",
      value: "Tenable Vulnerability Management Administrator [64]",
      unlocks: surfaceIds((surface) => surface.service === VM_SERVICE),
      notes: "Lower roles see only objects shared with them; users then come back in the reduced shape, which caps otherwise passing findings at warn.",
    },
    {
      id: "sc-security-manager",
      kind: "role",
      value: "Tenable Security Center Security Manager or Administrator",
      unlocks: surfaceIds((surface) => surface.service === SC_SERVICE),
      notes: "Security Center returns only the scans, scan results, scanners, and users the role can use or manage.",
    },
  ],
  surfaces: TENABLE_SURFACES,
  checks,
  tools: {
    tenable_check_access: [],
    tenable_assess_scan_program: idsFor(SCAN_PROGRAM),
    tenable_assess_sensor_coverage: idsFor(SENSOR_COVERAGE),
    tenable_assess_access_control: idsFor(ACCESS_CONTROL),
    tenable_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [
    offsetWalk(["exclusions", "access-groups", "credentials"], 200),
    offsetWalk(["agents"], 1000),
    offsetWalk(["networks"], 50),
    offsetWalk(["tag-categories", "tag-values"], 5000),
    offsetWalk(["audit-log"], 5000, 20),
    {
      surfaceIds: ["asset-export-request", "asset-export-chunks"],
      cursorFields: ["export_uuid", "chunks_available", "chunks_failed", "total_chunks"],
      pageSize: 10000,
      itemCap: "none",
      pageCap: 50,
      totalSemantics: "Each chunk holds up to 10000 assets. The first max_chunks available chunks are downloaded (default 50, clamped to 1 through 1000); listing more, a failed chunk, or total_chunks beyond the available list marks the export partial.",
      stopConditions: ["Export status FINISHED, ERROR, or CANCELLED", "The 300-second polling deadline", "Every listed chunk up to max_chunks requested"],
    },
  ],
  rateLimit: {
    documentedLimit: null,
    retryHeaders: ["Retry-After"],
    retryableStatuses: [429],
    retryableStatusRanges: [{ from: 500, to: 599 }],
    backoffPolicy: "Retry 429, every 5xx status, and network errors up to 4 times after the first attempt. A Retry-After header in seconds or as an HTTP date is honored up to 30 seconds; otherwise wait 500 ms doubled per attempt, capped at 15 seconds. Timed-out requests (30 seconds by default) are not retried.",
  },
  runtimeBehavior: [],
  knownGaps: [
    "Security Center scan results are requested for the last 30 days whatever stale_scan_days is set to, so a stale_scan_days above 30 cannot credit an older Security Center completion.",
  ],
  sensitiveFields: ["access_key", "secret_key", "sc_access_key", "sc_secret_key", "X-ApiKeys", "x-apikey", "credentials", "key"],
  credentialFormats: ["Tenable Vulnerability Management access and secret key pairs", "Tenable Security Center access and secret key pairs"],
  output: buildBatchOutputContract({
    files: [],
    overwritePolicy: "Allocate a new {host}-audit-bundle directory with a numeric suffix when needed; never overwrite a prior directory.",
    archivePairing: "Write a sibling zip named from the exact allocated bundle-directory path plus .zip.",
  }),
  lastUpdated: "2026-10-17",
});
