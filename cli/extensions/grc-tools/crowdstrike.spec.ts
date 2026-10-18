import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
  deriveDecisionRules,
  type BatchCheckDefinition,
  type BatchCompletenessDefinition,
  type BatchCriterionExample,
  type BatchPaginationDefinition,
  type BatchSurfaceDefinition,
  type PortableInputType,
} from "./batch-spec-builder.js";
import { CROWDSTRIKE_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import type { PortableValue, RequestParameterContract, VerdictCondition, VerdictOperand, VerdictRule } from "./spec-model.js";

// Alerts and RTR sessions are exported projected to these fields (plus each session's command count and distinct base
// commands); every other dataset is exported as read.
export const ALERT_SNAPSHOT_FIELDS: readonly string[] = [
  "id",
  "composite_id",
  "aggregate_id",
  "cid",
  "agent_id",
  "product",
  "type",
  "scenario",
  "objective",
  "tactic",
  "tactic_id",
  "technique",
  "technique_id",
  "pattern_id",
  "name",
  "display_name",
  "severity",
  "severity_name",
  "confidence",
  "status",
  "assigned_to_name",
  "resolution",
  "created_timestamp",
  "updated_timestamp",
  "timestamp",
  "seconds_to_triaged",
  "seconds_to_resolved",
  "data_domains",
  "tags",
];
export const ALERT_DEVICE_SNAPSHOT_FIELDS: readonly string[] = ["device_id", "hostname", "platform_name", "os_version", "agent_version"];
export const RTR_SESSION_SNAPSHOT_FIELDS: readonly string[] = [
  "id",
  "cid",
  "device_id",
  "hostname",
  "platform_name",
  "platform_id",
  "user_id",
  "user_uuid",
  "created_at",
  "updated_at",
  "deleted_at",
  "duration",
];

const API_SERVICE = "CrowdStrike Falcon API";
const API_DOCS = "https://developer.crowdstrike.com/api-reference/collections";
const API_HOST = "Use the resolved API host (base_url, else the selected cloud's host); member_cid scopes the bearer token and is never sent on a read.";
const READ_HEADERS = ["Accept: application/json", "Authorization: Bearer {access_token}"];
const POST_HEADERS = [...READ_HEADERS, "Content-Type: application/json"];
const RAW_EXPORT_STAGE = "The collector exports every returned record as read, after the data redaction pass has rewritten every string in it; decision facts read the listed fields.";
const projectedExport = (record: string, projection: string): string =>
  `The collector exports each ${record} cut to ${projection}, after the data redaction pass has rewritten every string in it; decision facts read the listed fields, which the cut keeps.`;
const PROBE_STAGE = "Never exported: the crowdstrike_check_access probe keeps only meta.pagination.total, else the number of returned IDs, as the surface's count.";
const idWalkStage = (lookup: string, probed: boolean): string =>
  `Never exported: the listed IDs are looked up through ${lookup}, whose records are exported instead${probed ? ", and the crowdstrike_check_access probe keeps only meta.pagination.total, else the number of returned IDs, as the surface's count" : ""}.`;

const REFUSAL = "a status outside 200 through 299 after retries, a body that is not a JSON object, or a missing resources array is a refusal";
const resourcesResponse = (records: string, pagination = "total, offset, and next"): string =>
  `A JSON object whose resources array holds ${records} and whose meta.pagination may carry ${pagination}; ${REFUSAL}.`;
const lookupResponse = (records: string): string =>
  `A JSON object whose resources array holds ${records}, a resource that is not a JSON object being dropped; ${REFUSAL}.`;

const param = (
  name: string,
  location: RequestParameterContract["location"],
  value: string,
  required = true,
  when?: string,
): RequestParameterContract => ({ name, location, required, value, ...(when ? { when } : {}) });

// A number is a fixed item cap; an option is a caller-supplied one.
type ItemCap = number | { option: string; fallback: number; max: number };
const capText = (cap: ItemCap): string =>
  typeof cap === "number" ? `the ${cap} cap` : `${cap.option} (default ${cap.fallback}, set from 1 through ${cap.max})`;
const capReached = (cap: ItemCap, records: string): string =>
  `${typeof cap === "number" ? cap : cap.option} ${records}`;
const HOST_LIMIT: ItemCap = { option: "host_limit", fallback: 5000, max: 100000 };
const ALERT_LIMIT: ItemCap = { option: "alert_limit", fallback: 2000, max: 10000 };
const RULE_LIMIT: ItemCap = { option: "rule_limit", fallback: 1000, max: 10000 };

const ACCESS_PROBE = "1 on the crowdstrike_check_access probe";
const nextOffset = (records: string): string =>
  `the previous page's meta.pagination.next (else meta.pagination.offset) when that is not a whole number; otherwise the previous page's offset (0 for the first page or after such a cursor) plus the number of ${records} it returned`;
const offsetParameters = (records: string, pageSize: number, cap: ItemCap, probed: boolean): RequestParameterContract[] => [
  param("limit", "query", `${pageSize}, or the ${records} left under ${capText(cap)} when fewer${probed ? `; ${ACCESS_PROBE}` : ""}`),
  param("offset", "query", `The offset: ${nextOffset(records)}`, false, "On every page after the first"),
];
const idsParameter = (records: string): RequestParameterContract =>
  param("ids", "query", `Up to 100 IDs of ${records}, each sent as its own ids parameter`);
const TEXT_IDS = "taking each id that is a non-blank string (sent trimmed) or a finite number, in list order";
const LISTED_TEXT_IDS = "non-blank strings (sent trimmed) or finite numbers, in list order";
const POLICY_FIELDS = ["id", "name", "enabled", "platform_default", "groups"];

const apiSurface = (
  id: string,
  path: string,
  collection: string,
  fields: readonly string[],
  parameters: readonly RequestParameterContract[],
  responseShape: string,
  { method, projectionStage = RAW_EXPORT_STAGE }: { method?: "POST"; projectionStage?: string } = {},
): BatchSurfaceDefinition => ({
  id,
  ...(method ? { method } : {}),
  path,
  service: API_SERVICE,
  documentationUrl: `${API_DOCS}/${collection}/`,
  fields,
  request: { clientRegion: API_HOST, headers: method === "POST" ? POST_HEADERS : READ_HEADERS, parameters, responseShape },
  projectionStage,
});

const PREVENTION_SURFACES: readonly BatchSurfaceDefinition[] = [
  apiSurface(
    "prevention_policies",
    "/policy/combined/prevention/v1",
    "prevention-policy",
    [
      ...POLICY_FIELDS,
      "platform_name",
      "prevention_settings.settings.id",
      "prevention_settings.settings.value.enabled",
      "prevention_settings.settings.value.detection",
      "prevention_settings.settings.value.prevention",
    ],
    offsetParameters("policies", 500, 5000, true),
    resourcesResponse("one prevention policy per entry"),
  ),
];

const EXCEPT_PROBE = "On every read except the crowdstrike_check_access probe";
const LOOKBACK_START = "now-{lookback_days}d";
const CONTAINMENT_FILTER = "status:['contained','containment_pending','lift_containment_pending']";
const HOST_FIELDS = "device_id,hostname,platform_name,os_version,agent_version,last_seen,first_seen,status,groups,product_type_desc,reduced_functionality_mode,modified_timestamp";

const RESPONSE_SURFACES: readonly BatchSurfaceDefinition[] = [
  apiSurface(
    "response_policies",
    "/policy/combined/response/v1",
    "response-policies",
    [...POLICY_FIELDS, "settings.settings.id", "settings.settings.value.enabled"],
    offsetParameters("policies", 500, 5000, true),
    resourcesResponse("one response policy per entry"),
  ),
  apiSurface(
    "rtr_audit_sessions",
    "/real-time-response-audit/combined/sessions/v1",
    "real-time-response-audit",
    ["id", "user_id", "user_uuid", "hostname", "created_at", "updated_at", "deleted_at", "duration"],
    [
      param("filter", "query", `created_at:>'${LOOKBACK_START}'`, true, EXCEPT_PROBE),
      param("sort", "query", "created_at|desc", true, EXCEPT_PROBE),
      ...offsetParameters("sessions", 500, 500, true),
    ],
    resourcesResponse("one RTR session per entry"),
    {
      projectionStage: projectedExport(
        "session",
        `the members it carries among ${RTR_SESSION_SNAPSHOT_FIELDS.join(", ")}, plus command_count (how many of its commands entries are JSON objects) and base_commands (their distinct trimmed base_command values)`,
      ),
    },
  ),
  apiSurface(
    "alerts",
    "/alerts/combined/alerts/v1",
    "alerts",
    ["composite_id", "id", "severity", "severity_name", "status", "created_timestamp", "timestamp", "updated_timestamp", "seconds_to_resolved"],
    [
      param("filter", "json-body", `severity:>=70+created_timestamp:>'${LOOKBACK_START}'`),
      param("limit", "json-body", `1000, or the alerts left under ${capText(ALERT_LIMIT)} when fewer`),
      param("sort", "json-body", "created_timestamp|desc"),
      param("after", "json-body", "The previous page's meta.pagination.after", false, "On every page after the first"),
    ],
    resourcesResponse("one alert per entry", "total and after"),
    {
      method: "POST",
      projectionStage: projectedExport(
        "alert",
        `the members it carries among ${ALERT_SNAPSHOT_FIELDS.join(", ")}, with device cut to its ${ALERT_DEVICE_SNAPSHOT_FIELDS.join(", ")}`,
      ),
    },
  ),
  apiSurface(
    "alert_ids",
    "/alerts/queries/alerts/v2",
    "alerts",
    ["meta.pagination.total", "resources"],
    [param("limit", "query", "1")],
    resourcesResponse("alert IDs", "total"),
    { projectionStage: PROBE_STAGE },
  ),
  apiSurface(
    "contained_hosts",
    `/devices/combined/devices/v1?filter=${CONTAINMENT_FILTER}`,
    "hosts",
    ["device_id", "hostname", "status", "last_seen", "modified_timestamp"],
    [param("sort", "query", "device_id.asc"), param("fields", "query", HOST_FIELDS), ...offsetParameters("hosts", 1000, HOST_LIMIT, false)],
    resourcesResponse("one host per entry"),
  ),
];

const DEVICE_FIREWALL_SURFACES: readonly BatchSurfaceDefinition[] = [
  apiSurface(
    "device_control_policies",
    "/policy/combined/device-control/v1",
    "device-control-policies",
    POLICY_FIELDS,
    offsetParameters("policies", 500, 5000, true),
    resourcesResponse("one device control policy per entry"),
  ),
  apiSurface(
    "device_control_policy_details",
    "/policy/entities/device-control/v2",
    "device-control-policies",
    [
      "id",
      "usb_settings.enforcement_mode",
      "usb_settings.pcie_enforcement_mode",
      "usb_settings.classes.id",
      "usb_settings.classes.class",
      "usb_settings.classes.action",
      "usb_settings.classes.exceptions",
      "bluetooth_settings.enforcement_mode",
      "bluetooth_settings.classes.action",
    ],
    [idsParameter(`the returned device control policies, ${TEXT_IDS}`)],
    lookupResponse("one device control policy's details per entry"),
  ),
  apiSurface(
    "firewall_policies",
    "/policy/combined/firewall/v1",
    "firewall-policies",
    POLICY_FIELDS,
    offsetParameters("policies", 500, 5000, true),
    resourcesResponse("one firewall policy per entry"),
  ),
  apiSurface(
    "firewall_policy_containers",
    "/fwmgr/entities/policies/v1",
    "firewall-management",
    ["policy_id", "enforce", "test_mode", "default_inbound", "rule_group_ids"],
    [idsParameter(`the firewall policies counted by assigned_firewall_policy_count, ${TEXT_IDS}`)],
    lookupResponse("one firewall policy container per entry"),
  ),
  apiSurface(
    "firewall_rule_group_ids",
    "/fwmgr/queries/rule-groups/v1",
    "firewall-management",
    ["resources"],
    offsetParameters("rule group IDs", 500, RULE_LIMIT, true),
    resourcesResponse("firewall rule group IDs"),
    { projectionStage: idWalkStage("GET /fwmgr/entities/rule-groups/v1", true) },
  ),
  apiSurface(
    "firewall_rule_groups",
    "/fwmgr/entities/rule-groups/v1",
    "firewall-management",
    ["id", "enabled", "rule_ids"],
    [idsParameter(`the rule group IDs listed by GET /fwmgr/queries/rule-groups/v1 that are ${LISTED_TEXT_IDS}`)],
    lookupResponse("one firewall rule group per entry"),
  ),
  apiSurface(
    "firewall_rule_ids",
    "/fwmgr/queries/rules/v1",
    "firewall-management",
    ["resources"],
    offsetParameters("rule IDs", 500, RULE_LIMIT, false),
    resourcesResponse("firewall rule IDs"),
    { projectionStage: idWalkStage("GET /fwmgr/entities/rules/v1", false) },
  ),
  apiSurface(
    "firewall_rules",
    "/fwmgr/entities/rules/v1",
    "firewall-management",
    ["action", "enabled", "description"],
    [idsParameter(`the rule IDs listed by GET /fwmgr/queries/rules/v1 that are ${LISTED_TEXT_IDS}`)],
    lookupResponse("one firewall rule per entry"),
  ),
];

const UNMANAGED_FILTER = "entity_type:'unmanaged'";
const ZTA_BELOW_FILTER = "score:<{min_zta_score}";
const countStage = (probed: boolean): string =>
  `Never exported: the read keeps only meta.pagination.total as the count${probed ? ", and the crowdstrike_check_access probe sends the same read and keeps meta.pagination.total, else the number of returned results, as the surface's count" : ""}.`;
const countSurface = (id: string, path: string, collection: string, records: string, probed = false): BatchSurfaceDefinition =>
  apiSurface(id, path, collection, ["meta.pagination.total"], [param("limit", "query", "1")], resourcesResponse(records, "total"), { projectionStage: countStage(probed) });

const SENSOR_COVERAGE_SURFACES: readonly BatchSurfaceDefinition[] = [
  apiSurface(
    "sensor_update_policies",
    "/policy/combined/sensor-update/v2",
    "sensor-update-policy",
    [...POLICY_FIELDS, "platform_name", "settings.build", "settings.variants.build", "settings.uninstall_protection"],
    offsetParameters("policies", 500, 5000, true),
    resourcesResponse("one sensor update policy per entry"),
  ),
  apiSurface(
    "sensor_update_builds",
    "/policy/combined/sensor-update-builds/v1",
    "sensor-update-policy",
    ["build", "sensor_version"],
    [param("platform", "query", "A platform_name of the assigned sensor update policies, trimmed and lowercased; one read per distinct non-blank value, in the order first seen")],
    lookupResponse("one sensor build per entry"),
    { projectionStage: "The collector exports every returned build as read, grouped under the platform it was read for, after the data redaction pass has rewritten every string in it; decision facts read the listed fields." },
  ),
  apiSurface(
    "hosts",
    "/devices/combined/devices/v1",
    "hosts",
    ["last_seen", "groups"],
    [
      param("sort", "query", "device_id.asc", true, EXCEPT_PROBE),
      param("fields", "query", HOST_FIELDS, true, EXCEPT_PROBE),
      ...offsetParameters("hosts", 1000, HOST_LIMIT, true),
    ],
    resourcesResponse("one host per entry"),
  ),
  apiSurface(
    "host_groups",
    "/devices/combined/host-groups/v1",
    "host-group",
    ["id", "group_type"],
    offsetParameters("host groups", 500, 5000, true),
    resourcesResponse("one host group per entry"),
  ),
  apiSurface(
    "discover_host_ids",
    "/discover/queries/hosts/v1",
    "discover",
    ["meta.pagination.total", "resources"],
    [param("limit", "query", "1")],
    resourcesResponse("Falcon Discover host IDs", "total"),
    { projectionStage: PROBE_STAGE },
  ),
  countSurface("discover_unmanaged_count", `/discover/queries/hosts/v1?filter=${UNMANAGED_FILTER}`, "discover", "Falcon Discover host IDs"),
  countSurface("discover_managed_count", "/discover/queries/hosts/v1?filter=entity_type:'managed'", "discover", "Falcon Discover host IDs"),
  apiSurface(
    "discover_unmanaged_hosts",
    `/discover/combined/hosts/v1?filter=${UNMANAGED_FILTER}`,
    "discover",
    ["hostname", "platform_name", "last_seen_timestamp", "local_ip_addresses"],
    [
      param("limit", "query", `100, or the hosts left under ${capText(100)} when fewer`),
      param("after", "query", "The previous page's meta.pagination.after", false, "On every page after the first"),
    ],
    resourcesResponse("one Falcon Discover host per entry", "total and after"),
  ),
  countSurface("zero_trust_scored_count", "/zero-trust-assessment/queries/assessments/v1?filter=score:>=0", "zero-trust-assessment", "Zero Trust Assessment results", true),
  apiSurface(
    "zero_trust_below_threshold",
    `/zero-trust-assessment/queries/assessments/v1?filter=${ZTA_BELOW_FILTER}&sort=score|asc`,
    "zero-trust-assessment",
    ["aid", "score"],
    [
      param("limit", "query", `1000, or the results left under ${capText(1000)} when fewer`),
      param("after", "query", "The previous page's meta.pagination.after", false, "On every page after the first"),
    ],
    resourcesResponse("one Zero Trust Assessment result per entry", "total and after"),
  ),
  countSurface("zero_trust_below_threshold_count", `/zero-trust-assessment/queries/assessments/v1?filter=${ZTA_BELOW_FILTER}`, "zero-trust-assessment", "Zero Trust Assessment results"),
];

const CROWDSTRIKE_SURFACES: readonly BatchSurfaceDefinition[] = [
  ...PREVENTION_SURFACES,
  ...RESPONSE_SURFACES,
  ...DEVICE_FIREWALL_SURFACES,
  ...SENSOR_COVERAGE_SURFACES,
];

const value = (entry: PortableValue): VerdictOperand => ({ kind: "value", value: entry });
const path = (name: string): VerdictOperand => ({ kind: "path", path: name });
type Comparator = "eq" | "ne" | "gt" | "lt" | "lte";
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
// Whole tenths of a percent: the runtime compares Math.round(part / total * 1000) / 10.
const perMille = (comparator: "lt" | "gt") => (numerator: string, denominator: string, threshold: string): VerdictCondition => ({
  op: "ratio",
  numerator: path(numerator),
  denominator: path(denominator),
  comparator,
  threshold: path(threshold),
  scale: 1000,
  roundDigits: 0,
});
const perMilleBelow = perMille("lt");
const perMilleAbove = perMille("gt");
const unreported = (name: string): VerdictCondition => ({ op: "not", condition: { op: "defined", operand: path(name) } });

const incomplete = (...complete: string[]): VerdictCondition =>
  complete.length === 1 ? ne(complete[0], true) : any(...complete.map((name) => ne(name, true)));
// A fail that rests on nothing being assigned is provable only against complete lists, so a partial list renders it manual.
const noneAssigned = (count: string, ...complete: string[]): VerdictRule[] => [
  rule("manual", all(eq(count, 0), incomplete(...complete))),
  rule("fail", eq(count, 0)),
];

const TRUTHY = "the boolean true or a string that trims to true, 1, yes, enabled, or on in any letter case";
const FALSY = "the boolean false or a string that trims to false, 0, no, disabled, or off in any letter case";
const assignedPolicyCount = (label: string): string =>
  `Number of returned ${label} policies whose enabled is ${TRUTHY} and that reach hosts through a non-empty groups array, a platform_default of ${TRUTHY}, or a name that trims and lowercases to platform_default.`;
const carries = (settingsKey: string): string =>
  `A policy carries a setting when one of its ${settingsKey}[].settings[] entries has that id after trimming, and the last such entry wins.`;
const ASSIGNED = "assigned prevention policies, as counted by assigned_prevention_policy_count";
const CARRIES = carries("prevention_settings");
const NOT_ENABLED = `A carried setting is enabled only when its value.enabled is ${TRUTHY}; false, absent, and every other value count as not enabled.`;
const CORE_MITIGATIONS = "ForceASLR, ForceDEP, HeapSprayPreallocation, NullPageAllocation, and SEHOverwriteProtection";
const EXTENDED_MITIGATIONS = "ApplicationExploitationActivity, ChopperWebshell, DriveByDownload, ProcessHollowing, JavaScriptViaRundll32, and HardwareEnhancedExploitDetection";
const SCRIPT_CONTROLS = "ScriptBasedExecutionMonitoring, InterpreterProtection, and EngineProtectionV2";
const ASSIGNED_RESPONSE = "assigned response policies, as counted by assigned_response_policy_count";
const RESPONSE_CARRIES = carries("settings");
const AS_NUMBER = "read as a number (a finite number, or a string that is not blank and parses as one)";
const optionValue = (name: string, fallback: number, max: number, min = 1): string =>
  `${name} argument ${AS_NUMBER}, ${fallback} when absent or not numeric, truncated to a whole number, and clamped to ${min} through ${max}`;
const LOOKBACK_WINDOW = `The lookback window is the last N days, where N is the ${optionValue("lookback_days", 30, 365)}.`;
const PARSES_AS_DATE = "A value parses as a date when ECMAScript Date.parse reads its trimmed text, a finite number being read as its decimal text.";
const SESSION_LENGTH = `A session's length in minutes is its duration, ${AS_NUMBER}, divided by 60 when that is above 0; otherwise the minutes from its created_at to the first of its deleted_at and updated_at that parses as a date, when created_at parses too; otherwise it has no length. ${PARSES_AS_DATE}`;
const ALERT_SLA = `An alert's SLA is 24 hours when its severity, ${AS_NUMBER}, is at least 90 or its severity_name trims and lowercases to critical, and 72 hours otherwise.`;
const ALERT_CLOSED = `An alert is closed when its status trims and lowercases to closed. A closed alert's resolution time is its seconds_to_resolved, ${AS_NUMBER}, divided by 3600 when that is above 0, else the hours from its creation to its updated_timestamp (0 when negative) when updated_timestamp parses as a date, else none.`;
const ALERT_CREATION = `An alert's creation is the first of its created_timestamp and timestamp that parses as a date. ${PARSES_AS_DATE}`;
const READS_AS_TEXT = "A value reads as text when it is a string that is not blank, trimmed, or a finite number, in decimal.";
const SAME_ID = "read as the same text, or both do not read as text";
const ASSIGNED_DEVICE = "assigned device control policies, as counted by assigned_device_control_policy_count";
const DEVICE_DETAILS = `A policy's details are the last returned device control policy details record whose id and the policy's id ${SAME_ID}; a policy without details has none of their settings. ${READS_AS_TEXT}`;
const MASS_STORAGE_CLASS = "A policy's mass storage class is the last JSON object in its details' usb_settings.classes whose id, or class when id does not read as text, reads as MASS_STORAGE in any letter case.";
const BLOCKS_MASS_STORAGE = `A policy blocks mass storage when its mass storage class has an action that reads as text other than FULL_ACCESS in any letter case. ${MASS_STORAGE_CLASS}`;
const PERIPHERALS = `The three peripheral restrictions are Bluetooth, enforced when the details' bluetooth_settings.enforcement_mode reads as MONITOR_ENFORCE in any letter case and at least one JSON object in bluetooth_settings.classes has an action that does not read as FULL_ACCESS in any letter case, an absent action included; PCIe, enforced when usb_settings.pcie_enforcement_mode reads as MONITOR_ENFORCE in any letter case; and mass storage, enforced when the policy blocks mass storage. ${BLOCKS_MASS_STORAGE}`;
const ASSIGNED_FIREWALL = "assigned firewall policies, as counted by assigned_firewall_policy_count";
const CONTAINER = `A policy's container is the last returned firewall policy container whose policy_id and the policy's id ${SAME_ID}. ${READS_AS_TEXT}`;
const RULE_GROUPS = `A container's rule groups are the entries of its rule_group_ids array that read as text. One is unknown when no returned firewall rule group has an id that reads as that text, and active when the last returned rule group whose id does has an enabled of ${TRUTHY} and a non-empty rule_ids array.`;
const ASSIGNED_CONTAINERS = "containers counted by assigned_firewall_container_count";
const ASSIGNED_SENSOR = "assigned sensor update policies, as counted by assigned_sensor_update_policy_count";
const JUDGED_BUILDS = `A policy's judged builds are its settings.build, whether or not it reads as text, plus the build of each JSON object in its settings.variants array whose build reads as text. ${READS_AS_TEXT}`;
const BUILD_FORMS = "A build that does not read as text turns updates off. Otherwise, trimmed and lowercased, it auto-updates when one of its pipe-separated segments is n, n-1, or n-2; else it is pinned when it starts with a run of digits, or with two runs of digits each followed by a dot and then a run of digits (as in 7.10.16004), and that last run ends the build or is followed by a pipe, the run being its build number; else its form is unknown.";
const BUILD_CATALOG = "A policy's platform is its platform_name read as text and lowercased, and its catalog is the GET /policy/combined/sensor-update-builds/v1 read for that platform. A catalog's supported build numbers come from its returned build records whose build, trimmed and lowercased, has a pipe-separated segment of n, n-1, or n-2: the leading run of digits of that build, else the trailing run of digits of the record's sensor_version, both read as text; a record with neither offers none.";
const SENSOR_BUILDS = `${JUDGED_BUILDS} ${BUILD_FORMS} ${BUILD_CATALOG}`;
const ZTA_THRESHOLD = `The below-threshold filter is score:<N, where N is the ${optionValue("min_zta_score", 60, 100)}.`;

const CROWDSTRIKE_INPUTS: Readonly<Record<string, string>> = {
  prevention_policies_readable: "True when GET /policy/combined/prevention/v1 returned its prevention policy list without a refusal.",
  prevention_policies_complete: "Prevention policy list coverage.",
  assigned_prevention_policy_count: assignedPolicyCount("prevention"),
  assigned_policy_min_ml_ranks: `Lowest ranked machine learning level of each of the ${ASSIGNED}, over the value.detection and value.prevention of its CloudAntiMalware and OnSensorMLSlider settings; a level trimmed and uppercased ranks DISABLED 0, CAUTIOUS 1, MODERATE 2, AGGRESSIVE 3, or EXTRA_AGGRESSIVE 4, any other level is unranked, and a policy with no ranked level contributes no entry. ${CARRIES}`,
  assigned_policies_with_unranked_sliders: `Number of ${ASSIGNED} that do not carry CloudAntiMalware or OnSensorMLSlider, or whose value.detection or value.prevention on either is absent or unranked as defined for assigned_policy_min_ml_ranks. ${CARRIES}`,
  platforms_without_assigned_policy_count: `Number of the platforms Windows, Mac, and Linux that are not the platform_name, compared trimmed and ignoring letter case, of any of the ${ASSIGNED}; recorded only when the prevention policy list is complete.`,
  exploit_mitigation_policy_count: `Number of ${ASSIGNED} that carry at least one of ${CORE_MITIGATIONS}, ${EXTENDED_MITIGATIONS}. ${CARRIES}`,
  policies_with_core_mitigation_disabled: `Number of ${ASSIGNED} that carry one of ${CORE_MITIGATIONS} without enabling it. ${CARRIES} ${NOT_ENABLED}`,
  policies_with_extended_mitigation_disabled: `Number of ${ASSIGNED} that carry one of ${EXTENDED_MITIGATIONS} without enabling it. ${CARRIES} ${NOT_ENABLED}`,
  script_control_policy_count: `Number of ${ASSIGNED} that carry at least one of ${SCRIPT_CONTROLS}. ${CARRIES}`,
  policies_with_script_control_disabled: `Number of ${ASSIGNED} that carry one of ${SCRIPT_CONTROLS} without enabling it. ${CARRIES} ${NOT_ENABLED}`,
  policies_with_tamper_protection_disabled: `Number of ${ASSIGNED} that carry SensorTamperingProtection without enabling it. ${CARRIES} ${NOT_ENABLED}`,
  policies_without_tamper_protection_setting: `Number of ${ASSIGNED} that do not carry SensorTamperingProtection. ${CARRIES}`,
  policies_with_detect_on_write_disabled: `Number of ${ASSIGNED} whose DetectOnWrite value.enabled is ${FALSY}. ${CARRIES}`,
  policies_with_detect_on_write_unknown: `Number of ${ASSIGNED} that do not carry DetectOnWrite, or whose DetectOnWrite value.enabled is neither ${TRUTHY} nor ${FALSY}. ${CARRIES}`,
  policies_without_quarantine_on_write: `Number of ${ASSIGNED} that do not carry QuarantineOnWrite, or whose QuarantineOnWrite value.enabled is not ${TRUTHY}. ${CARRIES}`,
  response_policies_readable: "True when GET /policy/combined/response/v1 returned its response policy list without a refusal.",
  response_policies_complete: "Response policy list coverage.",
  assigned_response_policy_count: assignedPolicyCount("response"),
  rtr_enabled_policy_count: `Number of ${ASSIGNED_RESPONSE} whose RealTimeFunctionality value.enabled is ${TRUTHY}. ${RESPONSE_CARRIES}`,
  policies_without_rtr: `Number of ${ASSIGNED_RESPONSE} that do not carry RealTimeFunctionality, or whose RealTimeFunctionality value.enabled is not ${TRUTHY}. ${RESPONSE_CARRIES}`,
  policies_with_custom_scripts: `Number of ${ASSIGNED_RESPONSE} whose CustomScripts value.enabled is ${TRUTHY}. ${RESPONSE_CARRIES}`,
  rtr_audit_sessions_readable: `True when GET /real-time-response-audit/combined/sessions/v1, filtered to the RTR sessions created in the lookback window, returned its session list without a refusal. ${LOOKBACK_WINDOW}`,
  longest_rtr_session_minutes: `Largest length in minutes, unrounded, among the returned RTR sessions, or 0 when no session has a length above 0. ${SESSION_LENGTH}`,
  peak_concurrent_rtr_sessions: `Largest number of one user's returned RTR sessions open at the start of one of that user's sessions, or 0 when no session's created_at parses as a date. Sessions whose created_at does not parse are skipped, and the rest are grouped by trimmed user_id, else trimmed user_uuid, else together under unknown. A session is open from its created_at to the first of its deleted_at and updated_at that parses, else to its created_at, and is open at a start when it began at or before that start and ends at or after it. ${PARSES_AS_DATE}`,
  max_session_minutes: `The ${optionValue("max_session_minutes", 30, 1440)}.`,
  max_concurrent_sessions: `The ${optionValue("max_concurrent_sessions", 3, 100)}.`,
  alerts_readable: `True when POST /alerts/combined/alerts/v1, filtered to the alerts of severity 70 or higher created in the lookback window, returned its alert list without a refusal. ${LOOKBACK_WINDOW}`,
  alerts_complete: "Alert list coverage.",
  dated_alert_count: `Number of returned alerts with a creation. ${ALERT_CREATION}`,
  undated_alert_count: `Number of returned alerts without a creation. ${ALERT_CREATION}`,
  sla_compliant_alert_count: `Number of returned alerts with a creation that count as within their SLA: the closed ones whose resolution time is at most their SLA hours, plus the ones that are not closed and whose age, the hours from creation to the assessment time (0 when negative), is at most their SLA hours. That second count is first reduced, never below 0, by the number of closed alerts with a creation and without a resolution time within their SLA whose status, trimmed, is not exactly the lowercase closed. ${ALERT_CREATION} ${ALERT_SLA} ${ALERT_CLOSED}`,
  contained_hosts_readable: "True when GET /devices/combined/devices/v1 with the containment status filter returned its host list without a refusal.",
  contained_hosts_complete: "Contained host list coverage.",
  contained_host_count: "Number of hosts returned by the read filtered to the status contained, containment_pending, or lift_containment_pending.",
  device_control_policies_readable: "True when GET /policy/combined/device-control/v1 returned its device control policy list, and every GET /policy/entities/device-control/v2 lookup of the listed policies' details returned, without a refusal.",
  device_control_policies_complete: "Device control policy list coverage.",
  assigned_device_control_policy_count: assignedPolicyCount("device control"),
  policies_without_usb_blocking: `Number of ${ASSIGNED_DEVICE} whose details' usb_settings.enforcement_mode does not read as MONITOR_ENFORCE in any letter case, or that do not block mass storage. ${BLOCKS_MASS_STORAGE} ${DEVICE_DETAILS}`,
  most_mass_storage_exceptions: `Largest number of entries in the exceptions array of the mass storage class of any of the ${ASSIGNED_DEVICE}, or 0 when none has a mass storage class with a non-empty exceptions array. ${MASS_STORAGE_CLASS} ${DEVICE_DETAILS}`,
  max_usb_exceptions: `The ${optionValue("max_usb_exceptions", 25, 10000, 0)}.`,
  policies_without_peripheral_restrictions: `Number of ${ASSIGNED_DEVICE} that enforce none of the three peripheral restrictions. ${PERIPHERALS} ${DEVICE_DETAILS}`,
  policies_missing_a_peripheral_restriction: `Number of ${ASSIGNED_DEVICE} that do not enforce all three peripheral restrictions. ${PERIPHERALS} ${DEVICE_DETAILS}`,
  firewall_policies_readable: "True when GET /policy/combined/firewall/v1 returned its firewall policy list, and every GET /fwmgr/entities/policies/v1 lookup of the assigned policies' containers returned, without a refusal.",
  firewall_policies_complete: "Firewall policy list coverage.",
  assigned_firewall_policy_count: assignedPolicyCount("firewall"),
  firewall_policies_without_container: `Number of ${ASSIGNED_FIREWALL} without a container. ${CONTAINER}`,
  firewall_policies_not_enforcing: `Number of ${ASSIGNED_FIREWALL} with a container whose enforce is not ${TRUTHY}, or whose rule groups include neither an active nor an unknown one. ${CONTAINER} ${RULE_GROUPS}`,
  firewall_policies_in_test_mode: `Number of ${ASSIGNED_FIREWALL} with a container whose test_mode is ${TRUTHY}. ${CONTAINER}`,
  firewall_policies_without_active_rule_group: `Number of ${ASSIGNED_FIREWALL} with a container whose rule groups include no active one. ${CONTAINER} ${RULE_GROUPS}`,
  firewall_rule_groups_readable: "True when the GET /fwmgr/queries/rule-groups/v1 walk and every GET /fwmgr/entities/rule-groups/v1 lookup of the IDs it listed returned without a refusal.",
  firewall_rule_groups_complete: "Firewall rule group list coverage.",
  assigned_firewall_container_count: `Number of returned firewall policy containers that match one of the ${ASSIGNED_FIREWALL}: the container's policy_id and the policy's id ${SAME_ID}. Two containers for one policy count twice. ${READS_AS_TEXT}`,
  containers_without_inbound_deny: `Number of ${ASSIGNED_CONTAINERS} whose default_inbound does not read as DENY in any letter case. ${READS_AS_TEXT}`,
  containers_not_enforced: `Number of ${ASSIGNED_CONTAINERS} whose enforce is not ${TRUTHY}.`,
  firewall_rules_readable: "True when the GET /fwmgr/queries/rules/v1 walk and every GET /fwmgr/entities/rules/v1 lookup of the IDs it listed returned without a refusal.",
  firewall_rules_complete: "Firewall rule list coverage.",
  firewall_rule_count: "Number of firewall rules returned by the GET /fwmgr/entities/rules/v1 lookups.",
  undocumented_allow_rule_count: `Number of returned firewall rules whose action reads as ALLOW in any letter case, whose enabled is ${TRUTHY}, and whose description does not read as text. ${READS_AS_TEXT}`,
  sensor_update_policies_readable: "True when GET /policy/combined/sensor-update/v2 returned its sensor update policy list without a refusal.",
  sensor_update_policies_complete: "Sensor update policy list coverage.",
  assigned_sensor_update_policy_count: assignedPolicyCount("sensor update"),
  sensor_update_builds_readable: "True when every GET /policy/combined/sensor-update-builds/v1 read, one per distinct platform of the assigned sensor update policies, returned without a refusal, including when no platform was read.",
  policies_with_updates_off: `Number of ${ASSIGNED_SENSOR} whose settings.build does not read as text. ${READS_AS_TEXT}`,
  policies_pinned_to_unsupported_build: `Number of ${ASSIGNED_SENSOR} with a pinned judged build whose build number is not among the supported build numbers of the policy's catalog, counted only when that catalog was read without a refusal. ${SENSOR_BUILDS}`,
  policies_with_unverified_builds: `Number of ${ASSIGNED_SENSOR} with a judged build whose form is unknown, or that is pinned while the policy has no platform or its catalog read was refused. ${SENSOR_BUILDS}`,
  policies_without_uninstall_protection: `Number of ${ASSIGNED_SENSOR} whose settings.uninstall_protection does not read as ENABLED in any letter case. ${READS_AS_TEXT}`,
  hosts_readable: "True when GET /devices/combined/devices/v1 without a filter returned its host list without a refusal.",
  hosts_complete: "Host list coverage.",
  host_count: "Number of hosts returned by the unfiltered host read.",
  dated_host_count: `Number of returned hosts whose last_seen parses as a date. ${PARSES_AS_DATE}`,
  recently_seen_host_count: `Number of returned hosts whose last_seen parses as a date no more than N days before the assessment time, where N is the ${optionValue("stale_sensor_days", 7, 365)}. ${PARSES_AS_DATE}`,
  grouped_host_count: "Number of returned hosts with a non-empty groups array.",
  host_groups_readable: "True when GET /devices/combined/host-groups/v1 returned its host group list without a refusal.",
  host_groups_complete: "Host group list coverage.",
  host_group_count: "Number of host groups returned by GET /devices/combined/host-groups/v1.",
  discover_counts_readable: `True when GET /discover/queries/hosts/v1 filtered to ${UNMANAGED_FILTER}, and then the same read filtered to entity_type:'managed', returned without a refusal.`,
  unmanaged_asset_total: `The meta.pagination.total of the Falcon Discover read filtered to ${UNMANAGED_FILTER}, ${AS_NUMBER}; null when it does not read as one.`,
  unmanaged_per_mille: `Unmanaged share of the discovered assets in tenths of a percent: unmanaged_asset_total divided by the sum of unmanaged_asset_total and the managed total, multiplied by 1000, and rounded half up; null when either total does not read as a number or the two sum to 0. The managed total is the meta.pagination.total of the read filtered to entity_type:'managed', ${AS_NUMBER}.`,
  discover_samples_readable: `True when the GET /discover/combined/hosts/v1 walk filtered to ${UNMANAGED_FILTER} returned without a refusal.`,
  zero_trust_readable: `True when GET /zero-trust-assessment/queries/assessments/v1 filtered to score:>=0, then the walk sorted by score under the below-threshold filter, then the read under that filter alone, all returned without a refusal. ${ZTA_THRESHOLD}`,
  scored_host_total: `The meta.pagination.total of the Zero Trust Assessment read filtered to score:>=0, ${AS_NUMBER}; null when it does not read as one.`,
  below_threshold_host_count: `The meta.pagination.total of the read under the below-threshold filter alone, ${AS_NUMBER}; when it does not read as one, the number of JSON objects the walk sorted by score under that filter returned. ${ZTA_THRESHOLD}`,
  below_threshold_total_reported: `True when the read under the below-threshold filter alone reported a meta.pagination.total that reads as a number. ${ZTA_THRESHOLD}`,
};

const inputs = (...names: string[]): Readonly<Record<string, string>> => Object.fromEntries(names.map((name) => {
  const definition = CROWDSTRIKE_INPUTS[name];
  if (!definition) throw new Error(`CrowdStrike decision input ${name} has no portable definition`);
  return [name, definition];
}));

const completeFrom = (
  semantics: string,
  sources: BatchCompletenessDefinition["sources"],
): BatchCompletenessDefinition => ({ semantics, sources });

const walkStops = (cap: string): string =>
  `stopped at ${cap} below meta.pagination.total (or, without a total, after a full last page or a cursor that is not a whole number), at an empty page before meta.pagination.total, or at a repeated cursor that is not a whole number`;
const offsetWalkComplete = (surfaceId: string, list: string, cap: string): BatchCompletenessDefinition => completeFrom(
  `false when the ${list} is partial: it ${walkStops(cap)}, or a returned resource is not a JSON object.`,
  [{ surfaceId, falseWhen: ["truncated"] }],
);
const lookupWalkComplete = (idSurfaceId: string, recordSurfaceId: string, list: string, records: string): BatchCompletenessDefinition => completeFrom(
  `false when the ${list} is partial: its ID walk ${walkStops("rule_limit IDs")}, or the lookups of the IDs it listed returned fewer ${records} than it listed.`,
  [
    { surfaceId: idSurfaceId, falseWhen: ["truncated"] },
    { surfaceId: recordSurfaceId, falseWhen: ["truncated"], scope: `fewer ${records} returned than IDs listed` },
  ],
);

const PREVENTION_POLICIES_COMPLETE = offsetWalkComplete("prevention_policies", "prevention policy list", "5000 policies");
const RESPONSE_POLICIES_COMPLETE = offsetWalkComplete("response_policies", "response policy list", "5000 policies");
const CONTAINED_HOSTS_COMPLETE = offsetWalkComplete("contained_hosts", "contained host list", "host_limit hosts");
const DEVICE_CONTROL_POLICIES_COMPLETE = offsetWalkComplete("device_control_policies", "device control policy list", "5000 policies");
const FIREWALL_POLICIES_COMPLETE = offsetWalkComplete("firewall_policies", "firewall policy list", "5000 policies");
const FIREWALL_RULE_GROUPS_COMPLETE = lookupWalkComplete("firewall_rule_group_ids", "firewall_rule_groups", "firewall rule group list", "rule groups");
const FIREWALL_RULES_COMPLETE = lookupWalkComplete("firewall_rule_ids", "firewall_rules", "firewall rule list", "rules");
const ALERTS_COMPLETE = completeFrom(
  "false when the alert list is partial: fewer alerts were kept than meta.pagination.total; or, without a total, the walk stopped at alert_limit alerts, at an empty page, or at an after cursor equal to the one the page was requested with, on a page that still carried meta.pagination.after; or a returned resource is not a JSON object.",
  [{ surfaceId: "alerts", falseWhen: ["truncated"] }],
);
const SENSOR_UPDATE_POLICIES_COMPLETE = offsetWalkComplete("sensor_update_policies", "sensor update policy list", "5000 policies");
const HOSTS_COMPLETE = offsetWalkComplete("hosts", "host list", "host_limit hosts");
const HOST_GROUPS_COMPLETE = offsetWalkComplete("host_groups", "host group list", "5000 host groups");

type CrowdstrikeCheck = {
  id: string;
  control: number;
  title: string;
  severity: BatchCheckDefinition["severity"];
  owner: string;
  surfaces: readonly string[];
  inputs: readonly string[];
  inputTypes?: Readonly<Record<string, readonly PortableInputType[]>>;
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

const PREVENTION = "crowdstrike_assess_prevention_policies";

const PREVENTION_BASE = ["prevention_policies_readable", "prevention_policies_complete", "assigned_prevention_policy_count"];
const preventionRules = (...decisive: VerdictRule[]): VerdictRule[] => [
  rule("manual", ne("prevention_policies_readable", true)),
  ...noneAssigned("assigned_prevention_policy_count", "prevention_policies_complete"),
  ...decisive,
  rule("warn", ne("prevention_policies_complete", true)),
  rule("pass", always),
];
const PREVENTION_UNREADABLE = "Manual when the prevention policy list is unreadable, or when it is partial and shows no assigned policy. Fail when no prevention policy is assigned.";
const PREVENTION_PARTIAL = "Warn instead of pass when the prevention policy list is partial. Otherwise pass.";
const preventionExamples = (
  check: string,
  readable: Readonly<Record<string, unknown>>,
): BatchCriterionExample[] => [
  example("noncompliant", "fail", "The complete prevention policy list holds no enabled policy that reaches hosts.", {
    prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 0, ...readable,
  }),
  example("partial", "manual", `The list stopped at the 5000-policy cap before any assigned policy was visible, so ${check} cannot rest on the absence.`, {
    prevention_policies_readable: true, prevention_policies_complete: false, assigned_prevention_policy_count: 0,
  }),
  example("unreadable", "manual", "The prevention policy list was refused.", { prevention_policies_readable: false }),
];

const PREVENTION_CHECKS: readonly CrowdstrikeCheck[] = [
  {
    id: "CS-01",
    control: 1,
    title: "Prevention Policy - ML Detection Levels",
    severity: "high",
    owner: PREVENTION,
    surfaces: ["prevention_policies"],
    inputs: [...PREVENTION_BASE, "assigned_policy_min_ml_ranks", "assigned_policies_with_unranked_sliders", "platforms_without_assigned_policy_count"],
    rules: preventionRules(
      rule("fail", some("assigned_policy_min_ml_ranks", lte("$", 1))),
      rule("warn", any(
        gt("assigned_policies_with_unranked_sliders", 0),
        some("assigned_policy_min_ml_ranks", lt("$", 3)),
        gt("platforms_without_assigned_policy_count", 0),
      )),
    ),
    completeness: { prevention_policies_complete: PREVENTION_POLICIES_COMPLETE },
    decision: `${PREVENTION_UNREADABLE} Fail when an assigned policy's lowest ranked machine learning level is CAUTIOUS or DISABLED. Warn when an assigned policy does not carry CloudAntiMalware or OnSensorMLSlider or leaves one of their detection or prevention levels unranked, when an assigned policy's lowest ranked level is below AGGRESSIVE, or when no assigned policy names Windows, Mac, or Linux. ${PREVENTION_PARTIAL}`,
    examples: [
      example("compliant", "pass", "Every assigned policy keeps both sliders at AGGRESSIVE or higher and the three platforms are covered.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 3,
        assigned_policy_min_ml_ranks: [3, 4, 3], assigned_policies_with_unranked_sliders: 0, platforms_without_assigned_policy_count: 0,
      }),
      example("noncompliant", "fail", "One assigned policy runs a slider at CAUTIOUS.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 2,
        assigned_policy_min_ml_ranks: [1, 3], assigned_policies_with_unranked_sliders: 0, platforms_without_assigned_policy_count: 0,
      }),
      example("partial", "warn", "One assigned policy's lowest level is MODERATE.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 2,
        assigned_policy_min_ml_ranks: [2, 3], assigned_policies_with_unranked_sliders: 0, platforms_without_assigned_policy_count: 0,
      }),
      example("partial", "warn", "No assigned policy names Linux.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 2,
        assigned_policy_min_ml_ranks: [3, 4], assigned_policies_with_unranked_sliders: 0, platforms_without_assigned_policy_count: 1,
      }),
      ...preventionExamples("CS-01", { assigned_policy_min_ml_ranks: [], assigned_policies_with_unranked_sliders: 0 }),
    ],
  },
  {
    id: "CS-02",
    control: 2,
    title: "Prevention Policy - Exploit Mitigation",
    severity: "high",
    owner: PREVENTION,
    surfaces: ["prevention_policies"],
    inputs: [...PREVENTION_BASE, "exploit_mitigation_policy_count", "policies_with_core_mitigation_disabled", "policies_with_extended_mitigation_disabled"],
    rules: preventionRules(
      rule("warn", eq("exploit_mitigation_policy_count", 0)),
      rule("fail", gt("policies_with_core_mitigation_disabled", 0)),
      rule("warn", gt("policies_with_extended_mitigation_disabled", 0)),
    ),
    completeness: { prevention_policies_complete: PREVENTION_POLICIES_COMPLETE },
    decision: `${PREVENTION_UNREADABLE} Warn when no assigned policy carries any of the eleven exploit mitigation settings. Fail when an assigned policy carries one of ${CORE_MITIGATIONS} without enabling it. Warn when an assigned policy carries one of ${EXTENDED_MITIGATIONS} without enabling it. ${PREVENTION_PARTIAL}`,
    examples: [
      example("compliant", "pass", "Both assigned policies enable every exploit mitigation they carry.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 2,
        exploit_mitigation_policy_count: 2, policies_with_core_mitigation_disabled: 0, policies_with_extended_mitigation_disabled: 0,
      }),
      example("noncompliant", "fail", "An assigned policy carries ForceDEP without enabling it.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 2,
        exploit_mitigation_policy_count: 2, policies_with_core_mitigation_disabled: 1, policies_with_extended_mitigation_disabled: 0,
      }),
      example("partial", "warn", "An assigned policy turns ProcessHollowing off and every core mitigation on.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 2,
        exploit_mitigation_policy_count: 2, policies_with_core_mitigation_disabled: 0, policies_with_extended_mitigation_disabled: 1,
      }),
      example("partial", "warn", "No assigned policy carries an exploit mitigation setting.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 2,
        exploit_mitigation_policy_count: 0, policies_with_core_mitigation_disabled: 0, policies_with_extended_mitigation_disabled: 0,
      }),
      ...preventionExamples("CS-02", { exploit_mitigation_policy_count: 0 }),
    ],
  },
  {
    id: "CS-03",
    control: 3,
    title: "Prevention Policy - Script-Based Execution Control",
    severity: "medium",
    owner: PREVENTION,
    surfaces: ["prevention_policies"],
    inputs: [...PREVENTION_BASE, "script_control_policy_count", "policies_with_script_control_disabled"],
    rules: preventionRules(
      rule("warn", eq("script_control_policy_count", 0)),
      rule("fail", gt("policies_with_script_control_disabled", 0)),
    ),
    completeness: { prevention_policies_complete: PREVENTION_POLICIES_COMPLETE },
    decision: `${PREVENTION_UNREADABLE} Warn when no assigned policy carries ${SCRIPT_CONTROLS.replace(", and", ", or")}. Fail when an assigned policy carries one of them without enabling it. ${PREVENTION_PARTIAL}`,
    examples: [
      example("compliant", "pass", "Every assigned policy enables the script controls it carries.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 2,
        script_control_policy_count: 2, policies_with_script_control_disabled: 0,
      }),
      example("noncompliant", "fail", "An assigned policy carries InterpreterProtection without enabling it.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 2,
        script_control_policy_count: 2, policies_with_script_control_disabled: 1,
      }),
      example("partial", "warn", "No assigned policy carries a script control setting.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 2,
        script_control_policy_count: 0, policies_with_script_control_disabled: 0,
      }),
      example("partial", "warn", "The script controls pass on the visible policies, but the list stopped at the cap.", {
        prevention_policies_readable: true, prevention_policies_complete: false, assigned_prevention_policy_count: 2,
        script_control_policy_count: 2, policies_with_script_control_disabled: 0,
      }),
      ...preventionExamples("CS-03", { script_control_policy_count: 0 }),
    ],
  },
  {
    id: "CS-04",
    control: 4,
    title: "Prevention Policy - Sensor Tamper Protection",
    severity: "critical",
    owner: PREVENTION,
    surfaces: ["prevention_policies"],
    inputs: [...PREVENTION_BASE, "policies_with_tamper_protection_disabled", "policies_without_tamper_protection_setting"],
    rules: preventionRules(
      rule("fail", gt("policies_with_tamper_protection_disabled", 0)),
      rule("warn", gt("policies_without_tamper_protection_setting", 0)),
    ),
    completeness: { prevention_policies_complete: PREVENTION_POLICIES_COMPLETE },
    decision: `${PREVENTION_UNREADABLE} Fail when an assigned policy carries SensorTamperingProtection without enabling it, including a value.enabled that is absent or unrecognized. Warn when an assigned policy does not carry SensorTamperingProtection. ${PREVENTION_PARTIAL}`,
    examples: [
      example("compliant", "pass", "Every assigned policy enables SensorTamperingProtection.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 3,
        policies_with_tamper_protection_disabled: 0, policies_without_tamper_protection_setting: 0,
      }),
      example("noncompliant", "fail", "An assigned policy carries SensorTamperingProtection with value.enabled false.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 3,
        policies_with_tamper_protection_disabled: 1, policies_without_tamper_protection_setting: 0,
      }),
      example("partial", "warn", "An assigned policy does not carry SensorTamperingProtection.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 3,
        policies_with_tamper_protection_disabled: 0, policies_without_tamper_protection_setting: 1,
      }),
      ...preventionExamples("CS-04", { policies_with_tamper_protection_disabled: 0, policies_without_tamper_protection_setting: 0 }),
    ],
  },
  {
    id: "CS-05",
    control: 5,
    title: "Prevention Policy - On-Write Detection",
    severity: "medium",
    owner: PREVENTION,
    surfaces: ["prevention_policies"],
    inputs: [
      ...PREVENTION_BASE,
      "policies_with_detect_on_write_disabled",
      "policies_with_detect_on_write_unknown",
      "policies_without_quarantine_on_write",
    ],
    rules: preventionRules(
      rule("fail", gt("policies_with_detect_on_write_disabled", 0)),
      rule("warn", any(gt("policies_with_detect_on_write_unknown", 0), gt("policies_without_quarantine_on_write", 0))),
    ),
    completeness: { prevention_policies_complete: PREVENTION_POLICIES_COMPLETE },
    decision: `${PREVENTION_UNREADABLE} Fail when an assigned policy turns DetectOnWrite off. Warn when an assigned policy does not carry DetectOnWrite or gives it an unrecognized value.enabled, or does not enable QuarantineOnWrite. ${PREVENTION_PARTIAL}`,
    examples: [
      example("compliant", "pass", "Every assigned policy enables DetectOnWrite and QuarantineOnWrite.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 2,
        policies_with_detect_on_write_disabled: 0, policies_with_detect_on_write_unknown: 0, policies_without_quarantine_on_write: 0,
      }),
      example("noncompliant", "fail", "An assigned policy sets DetectOnWrite value.enabled to false.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 2,
        policies_with_detect_on_write_disabled: 1, policies_with_detect_on_write_unknown: 0, policies_without_quarantine_on_write: 1,
      }),
      example("partial", "warn", "DetectOnWrite is on everywhere, but one assigned policy leaves QuarantineOnWrite off.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 2,
        policies_with_detect_on_write_disabled: 0, policies_with_detect_on_write_unknown: 0, policies_without_quarantine_on_write: 1,
      }),
      ...preventionExamples("CS-05", {
        policies_with_detect_on_write_disabled: 0, policies_with_detect_on_write_unknown: 0, policies_without_quarantine_on_write: 0,
      }),
    ],
  },
];

const RESPONSE = "crowdstrike_assess_response_readiness";

const RESPONSE_CHECKS: readonly CrowdstrikeCheck[] = [
  {
    id: "CS-06",
    control: 6,
    title: "Response Policy - RTR Enabled",
    severity: "medium",
    owner: RESPONSE,
    surfaces: ["response_policies"],
    inputs: [
      "response_policies_readable",
      "response_policies_complete",
      "assigned_response_policy_count",
      "rtr_enabled_policy_count",
      "policies_without_rtr",
      "policies_with_custom_scripts",
    ],
    rules: [
      rule("manual", ne("response_policies_readable", true)),
      ...noneAssigned("assigned_response_policy_count", "response_policies_complete"),
      rule("fail", eq("rtr_enabled_policy_count", 0)),
      rule("warn", any(gt("policies_without_rtr", 0), gt("policies_with_custom_scripts", 0))),
      rule("warn", ne("response_policies_complete", true)),
      rule("pass", always),
    ],
    completeness: { response_policies_complete: RESPONSE_POLICIES_COMPLETE },
    decision: "Manual when the response policy list is unreadable, or when it is partial and shows no assigned policy. Fail when no response policy is assigned, or when no assigned policy enables RealTimeFunctionality, even on a partial list. Warn when an assigned policy does not enable RealTimeFunctionality or enables CustomScripts. Warn instead of pass when the response policy list is partial. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Every assigned policy enables RealTimeFunctionality and leaves CustomScripts off.", {
        response_policies_readable: true, response_policies_complete: true, assigned_response_policy_count: 2,
        rtr_enabled_policy_count: 2, policies_without_rtr: 0, policies_with_custom_scripts: 0,
      }),
      example("noncompliant", "fail", "No assigned policy enables RealTimeFunctionality.", {
        response_policies_readable: true, response_policies_complete: true, assigned_response_policy_count: 2,
        rtr_enabled_policy_count: 0, policies_without_rtr: 2, policies_with_custom_scripts: 0,
      }),
      example("noncompliant", "fail", "No visible assigned policy enables RealTimeFunctionality, and the list stopped at the cap.", {
        response_policies_readable: true, response_policies_complete: false, assigned_response_policy_count: 1,
        rtr_enabled_policy_count: 0, policies_without_rtr: 1, policies_with_custom_scripts: 0,
      }),
      example("partial", "warn", "One assigned policy enables CustomScripts.", {
        response_policies_readable: true, response_policies_complete: true, assigned_response_policy_count: 2,
        rtr_enabled_policy_count: 2, policies_without_rtr: 0, policies_with_custom_scripts: 1,
      }),
      example("partial", "warn", "One of two assigned policies leaves RealTimeFunctionality off.", {
        response_policies_readable: true, response_policies_complete: true, assigned_response_policy_count: 2,
        rtr_enabled_policy_count: 1, policies_without_rtr: 1, policies_with_custom_scripts: 0,
      }),
      example("partial", "warn", "The visible policies pass, but the list stopped at the cap.", {
        response_policies_readable: true, response_policies_complete: false, assigned_response_policy_count: 2,
        rtr_enabled_policy_count: 2, policies_without_rtr: 0, policies_with_custom_scripts: 0,
      }),
      example("noncompliant", "fail", "The complete response policy list holds no enabled policy that reaches hosts.", {
        response_policies_readable: true, response_policies_complete: true, assigned_response_policy_count: 0,
      }),
      example("partial", "manual", "The list stopped at the cap before any assigned policy was visible.", {
        response_policies_readable: true, response_policies_complete: false, assigned_response_policy_count: 0,
      }),
      example("unreadable", "manual", "The response policy list was refused.", { response_policies_readable: false }),
    ],
  },
  {
    id: "CS-07",
    control: 7,
    title: "Response Policy - Session Limits",
    severity: "low",
    owner: RESPONSE,
    surfaces: ["rtr_audit_sessions"],
    inputs: ["rtr_audit_sessions_readable", "longest_rtr_session_minutes", "peak_concurrent_rtr_sessions", "max_session_minutes", "max_concurrent_sessions"],
    rules: [
      rule("manual", ne("rtr_audit_sessions_readable", true)),
      rule("warn", any(
        gt("longest_rtr_session_minutes", path("max_session_minutes")),
        gt("peak_concurrent_rtr_sessions", path("max_concurrent_sessions")),
      )),
      rule("manual", always),
    ],
    decision: "Manual when the RTR session list is unreadable. Warn when a returned session lasted longer than max_session_minutes, or when one user held more than max_concurrent_sessions returned sessions open at once. Otherwise manual: the Falcon API does not expose the configured RTR session timeout or concurrent session limit, so sessions within both thresholds cannot show that the limits are set. A partial session list never changes the verdict.",
    examples: [
      example("partial", "warn", "One session ran 30.5 minutes against a 30-minute threshold.", {
        rtr_audit_sessions_readable: true, longest_rtr_session_minutes: 30.5, peak_concurrent_rtr_sessions: 1, max_session_minutes: 30, max_concurrent_sessions: 3,
      }),
      example("partial", "warn", "One user held 4 sessions open at once against a threshold of 3.", {
        rtr_audit_sessions_readable: true, longest_rtr_session_minutes: 12, peak_concurrent_rtr_sessions: 4, max_session_minutes: 30, max_concurrent_sessions: 3,
      }),
      example("partial", "manual", "Every session stayed within both thresholds, but the API cannot show that the limits are configured.", {
        rtr_audit_sessions_readable: true, longest_rtr_session_minutes: 30, peak_concurrent_rtr_sessions: 3, max_session_minutes: 30, max_concurrent_sessions: 3,
      }),
      example("unreadable", "manual", "The RTR session list was refused.", { rtr_audit_sessions_readable: false }),
    ],
  },
  {
    id: "CS-22",
    control: 22,
    title: "Detection Response SLA",
    severity: "high",
    owner: RESPONSE,
    surfaces: ["alerts"],
    inputs: ["alerts_readable", "alerts_complete", "dated_alert_count", "undated_alert_count", "sla_compliant_alert_count"],
    constants: { sla_fail_below_per_mille: 800, sla_warn_below_per_mille: 950 },
    rules: [
      rule("manual", ne("alerts_readable", true)),
      rule("fail", perMilleBelow("sla_compliant_alert_count", "dated_alert_count", "sla_fail_below_per_mille")),
      rule("warn", any(
        perMilleBelow("sla_compliant_alert_count", "dated_alert_count", "sla_warn_below_per_mille"),
        gt("undated_alert_count", 0),
        ne("alerts_complete", true),
      )),
      rule("pass", always),
    ],
    completeness: { alerts_complete: ALERTS_COMPLETE },
    decision: "Manual when the alert list is unreadable. When at least one returned alert has a creation, divide the ones within their SLA by all of them, multiply by 1000, and round halves up: fail below sla_fail_below_per_mille (800, so 79.95 percent rounds to 80.0 and does not fail) and warn below sla_warn_below_per_mille (950). Warn instead of pass when a returned alert has no creation or the alert list is partial. Otherwise pass, including when no alert was returned.",
    examples: [
      example("compliant", "pass", "1899 of 2000 alerts within their SLA round to 950 per mille.", {
        alerts_readable: true, alerts_complete: true, dated_alert_count: 2000, undated_alert_count: 0, sla_compliant_alert_count: 1899,
      }),
      example("compliant", "pass", "The complete read returned no alert in the lookback window.", {
        alerts_readable: true, alerts_complete: true, dated_alert_count: 0, undated_alert_count: 0, sla_compliant_alert_count: 0,
      }),
      example("partial", "warn", "1599 of 2000 alerts within their SLA round to 800 per mille.", {
        alerts_readable: true, alerts_complete: true, dated_alert_count: 2000, undated_alert_count: 0, sla_compliant_alert_count: 1599,
      }),
      example("noncompliant", "fail", "1598 of 2000 alerts within their SLA are 799 per mille.", {
        alerts_readable: true, alerts_complete: true, dated_alert_count: 2000, undated_alert_count: 0, sla_compliant_alert_count: 1598,
      }),
      example("noncompliant", "fail", "Half the visible alerts breached their SLA, and the list stopped at alert_limit.", {
        alerts_readable: true, alerts_complete: false, dated_alert_count: 100, undated_alert_count: 0, sla_compliant_alert_count: 50,
      }),
      example("partial", "warn", "Every dated alert is within its SLA, but two alerts carry no creation.", {
        alerts_readable: true, alerts_complete: true, dated_alert_count: 40, undated_alert_count: 2, sla_compliant_alert_count: 40,
      }),
      example("partial", "warn", "The list stopped at alert_limit before any alert with a creation was visible.", {
        alerts_readable: true, alerts_complete: false, dated_alert_count: 0, undated_alert_count: 0, sla_compliant_alert_count: 0,
      }),
      example("unreadable", "manual", "The alert list was refused.", { alerts_readable: false }),
    ],
  },
  {
    id: "CS-23",
    control: 23,
    title: "Containment Policy",
    severity: "medium",
    owner: RESPONSE,
    surfaces: ["contained_hosts"],
    inputs: ["contained_hosts_readable", "contained_hosts_complete", "contained_host_count"],
    rules: [
      rule("manual", ne("contained_hosts_readable", true)),
      rule("warn", any(gt("contained_host_count", 0), ne("contained_hosts_complete", true))),
      rule("pass", always),
    ],
    completeness: { contained_hosts_complete: CONTAINED_HOSTS_COMPLETE },
    decision: "Manual when the contained host list is unreadable. Warn when a host is contained or has a containment change pending, since each containment needs its incident reference documented, or when the contained host list is partial. Otherwise pass. How long a host has been contained, and whether it carries a modified_timestamp, never change the verdict.",
    examples: [
      example("compliant", "pass", "The containment filter returned no host.", {
        contained_hosts_readable: true, contained_hosts_complete: true, contained_host_count: 0,
      }),
      example("partial", "warn", "Two hosts are contained.", {
        contained_hosts_readable: true, contained_hosts_complete: true, contained_host_count: 2,
      }),
      example("partial", "warn", "The list stopped at host_limit before any contained host was visible.", {
        contained_hosts_readable: true, contained_hosts_complete: false, contained_host_count: 0,
      }),
      example("unreadable", "manual", "The contained host read was refused.", { contained_hosts_readable: false }),
    ],
  },
];

const DEVICE_FIREWALL = "crowdstrike_assess_device_firewall";

const DEVICE_CONTROL_SURFACES = ["device_control_policies", "device_control_policy_details"];
const DEVICE_BASE = ["device_control_policies_readable", "device_control_policies_complete", "assigned_device_control_policy_count"];
const deviceRules = (...decisive: VerdictRule[]): VerdictRule[] => [
  rule("manual", ne("device_control_policies_readable", true)),
  ...noneAssigned("assigned_device_control_policy_count", "device_control_policies_complete"),
  ...decisive,
  rule("warn", ne("device_control_policies_complete", true)),
  rule("pass", always),
];
const DEVICE_HEAD = "Manual when the device control policy list or a details lookup is unreadable, or when the list is partial and shows no assigned policy. Fail when no device control policy is assigned.";
const DEVICE_TAIL = "Warn instead of pass when the device control policy list is partial. Otherwise pass.";
const deviceExamples = (check: string, healthy: Readonly<Record<string, unknown>>): BatchCriterionExample[] => [
  example("noncompliant", "fail", "The complete device control policy list holds no enabled policy that reaches hosts.", {
    ...healthy, assigned_device_control_policy_count: 0,
  }),
  example("partial", "manual", `The list stopped at the 5000-policy cap before any assigned policy was visible, so ${check} cannot rest on the absence.`, {
    ...healthy, device_control_policies_complete: false, assigned_device_control_policy_count: 0,
  }),
  example("unreadable", "manual", "A device control policy details lookup was refused.", { device_control_policies_readable: false }),
];
const USB_HEALTHY = {
  device_control_policies_readable: true, device_control_policies_complete: true, assigned_device_control_policy_count: 2,
  policies_without_usb_blocking: 0, most_mass_storage_exceptions: 3, max_usb_exceptions: 25,
};
const PERIPHERAL_HEALTHY = {
  device_control_policies_readable: true, device_control_policies_complete: true, assigned_device_control_policy_count: 2,
  policies_without_peripheral_restrictions: 0, policies_missing_a_peripheral_restriction: 0,
};

const FIREWALL_SURFACES = ["firewall_policies", "firewall_policy_containers"];
const HOST_FIREWALL_HEALTHY = {
  firewall_policies_readable: true, firewall_policies_complete: true, firewall_rule_groups_readable: true, firewall_rule_groups_complete: true,
  assigned_firewall_policy_count: 2, firewall_policies_without_container: 0, firewall_policies_not_enforcing: 0,
  firewall_policies_in_test_mode: 0, firewall_policies_without_active_rule_group: 0,
};
const DEFAULT_DENY_HEALTHY = {
  firewall_policies_readable: true, firewall_policies_complete: true, firewall_rules_readable: true, firewall_rules_complete: true,
  assigned_firewall_container_count: 2, containers_without_inbound_deny: 0, containers_not_enforced: 0,
  undocumented_allow_rule_count: 0, firewall_rule_count: 40,
};

const DEVICE_FIREWALL_CHECKS: readonly CrowdstrikeCheck[] = [
  {
    id: "CS-08",
    control: 8,
    title: "Device Control - USB Blocking",
    severity: "high",
    owner: DEVICE_FIREWALL,
    surfaces: DEVICE_CONTROL_SURFACES,
    inputs: [...DEVICE_BASE, "policies_without_usb_blocking", "most_mass_storage_exceptions", "max_usb_exceptions"],
    rules: deviceRules(
      rule("fail", gt("policies_without_usb_blocking", 0)),
      rule("warn", gt("most_mass_storage_exceptions", path("max_usb_exceptions"))),
    ),
    completeness: { device_control_policies_complete: DEVICE_CONTROL_POLICIES_COMPLETE },
    decision: `${DEVICE_HEAD} Fail when an assigned policy's USB enforcement mode is not MONITOR_ENFORCE, or when it does not block mass storage because its mass storage class is missing, has no action, or allows FULL_ACCESS. Warn when an assigned policy's mass storage class lists more than max_usb_exceptions exceptions. ${DEVICE_TAIL}`,
    examples: [
      example("compliant", "pass", "Both assigned policies enforce USB and block mass storage, with at most 3 exceptions.", USB_HEALTHY),
      example("compliant", "pass", "The largest exception list holds exactly the 25 exceptions max_usb_exceptions allows.", {
        ...USB_HEALTHY, most_mass_storage_exceptions: 25,
      }),
      example("noncompliant", "fail", "An assigned policy blocks mass storage but sets the USB enforcement mode to MONITOR_ONLY.", {
        ...USB_HEALTHY, policies_without_usb_blocking: 1,
      }),
      example("noncompliant", "fail", "An assigned policy allows mass storage FULL_ACCESS, and the list stopped at the cap.", {
        ...USB_HEALTHY, device_control_policies_complete: false, policies_without_usb_blocking: 1,
      }),
      example("partial", "warn", "An assigned policy's mass storage class lists 26 exceptions against a threshold of 25.", {
        ...USB_HEALTHY, most_mass_storage_exceptions: 26,
      }),
      example("partial", "warn", "The visible policies pass, but the list stopped at the cap.", {
        ...USB_HEALTHY, device_control_policies_complete: false,
      }),
      ...deviceExamples("CS-08", { ...USB_HEALTHY, most_mass_storage_exceptions: 0 }),
    ],
  },
  {
    id: "CS-09",
    control: 9,
    title: "Device Control - Peripheral Restrictions",
    severity: "medium",
    owner: DEVICE_FIREWALL,
    surfaces: DEVICE_CONTROL_SURFACES,
    inputs: [...DEVICE_BASE, "policies_without_peripheral_restrictions", "policies_missing_a_peripheral_restriction"],
    rules: deviceRules(
      rule("fail", gt("policies_without_peripheral_restrictions", 0)),
      rule("warn", gt("policies_missing_a_peripheral_restriction", 0)),
    ),
    completeness: { device_control_policies_complete: DEVICE_CONTROL_POLICIES_COMPLETE },
    decision: `${DEVICE_HEAD} Fail when an assigned policy enforces none of the Bluetooth, PCIe, and mass storage restrictions. Warn when an assigned policy enforces only one or two of them. ${DEVICE_TAIL}`,
    examples: [
      example("compliant", "pass", "Both assigned policies enforce the Bluetooth, PCIe, and mass storage restrictions.", PERIPHERAL_HEALTHY),
      example("noncompliant", "fail", "An assigned policy enforces none of the three restrictions.", {
        ...PERIPHERAL_HEALTHY, policies_without_peripheral_restrictions: 1, policies_missing_a_peripheral_restriction: 1,
      }),
      example("partial", "warn", "An assigned policy enforces PCIe and mass storage, but every Bluetooth class it lists has FULL_ACCESS.", {
        ...PERIPHERAL_HEALTHY, policies_missing_a_peripheral_restriction: 1,
      }),
      example("partial", "warn", "The visible policies pass, but the list stopped at the cap.", {
        ...PERIPHERAL_HEALTHY, device_control_policies_complete: false,
      }),
      ...deviceExamples("CS-09", PERIPHERAL_HEALTHY),
    ],
  },
  {
    id: "CS-10",
    control: 10,
    title: "Firewall - Host Firewall Enabled",
    severity: "medium",
    owner: DEVICE_FIREWALL,
    surfaces: [...FIREWALL_SURFACES, "firewall_rule_group_ids", "firewall_rule_groups"],
    inputs: [
      "firewall_policies_readable",
      "firewall_policies_complete",
      "firewall_rule_groups_readable",
      "firewall_rule_groups_complete",
      "assigned_firewall_policy_count",
      "firewall_policies_without_container",
      "firewall_policies_not_enforcing",
      "firewall_policies_in_test_mode",
      "firewall_policies_without_active_rule_group",
    ],
    rules: [
      rule("manual", any(ne("firewall_policies_readable", true), ne("firewall_rule_groups_readable", true))),
      ...noneAssigned("assigned_firewall_policy_count", "firewall_policies_complete", "firewall_rule_groups_complete"),
      rule("fail", gt("firewall_policies_not_enforcing", 0)),
      rule("warn", any(
        gt("firewall_policies_without_container", 0),
        gt("firewall_policies_in_test_mode", 0),
        gt("firewall_policies_without_active_rule_group", 0),
      )),
      rule("warn", incomplete("firewall_policies_complete", "firewall_rule_groups_complete")),
      rule("pass", always),
    ],
    completeness: {
      firewall_policies_complete: FIREWALL_POLICIES_COMPLETE,
      firewall_rule_groups_complete: FIREWALL_RULE_GROUPS_COMPLETE,
    },
    decision: "Manual when the firewall policy list, a container lookup, the rule group walk, or a rule group lookup is unreadable, or when the firewall policy list or the rule group list is partial and the policy list shows no assigned policy. Fail when no firewall policy is assigned, or when an assigned policy's container does not enforce, or lists neither an active rule group (enabled, with at least one rule) nor one the rule group list did not return. Warn when an assigned policy has no container, which is review evidence rather than a violation, when its container runs in test mode, or when it has no active rule group. Warn instead of pass when the firewall policy list or the rule group list is partial. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Both assigned policies enforce an active rule group outside test mode.", HOST_FIREWALL_HEALTHY),
      example("noncompliant", "fail", "An assigned policy's container sets enforce to false although it lists an active rule group.", {
        ...HOST_FIREWALL_HEALTHY, firewall_policies_not_enforcing: 1,
      }),
      example("noncompliant", "fail", "An assigned policy's container enforces but lists no rule group.", {
        ...HOST_FIREWALL_HEALTHY, firewall_policies_not_enforcing: 1, firewall_policies_without_active_rule_group: 1,
      }),
      example("partial", "warn", "No container was returned for an assigned policy.", {
        ...HOST_FIREWALL_HEALTHY, firewall_policies_without_container: 1,
      }),
      example("partial", "warn", "An assigned policy's container enforces an active rule group in test mode.", {
        ...HOST_FIREWALL_HEALTHY, firewall_policies_in_test_mode: 1,
      }),
      example("partial", "warn", "An assigned policy's container enforces only a rule group the rule group list did not return.", {
        ...HOST_FIREWALL_HEALTHY, firewall_policies_without_active_rule_group: 1,
      }),
      example("partial", "warn", "Every assigned policy passes, but the rule group walk stopped at rule_limit.", {
        ...HOST_FIREWALL_HEALTHY, firewall_rule_groups_complete: false,
      }),
      example("noncompliant", "fail", "The complete firewall policy list holds no enabled policy that reaches hosts.", {
        ...HOST_FIREWALL_HEALTHY, assigned_firewall_policy_count: 0,
      }),
      example("partial", "manual", "No assigned policy is visible and the rule group walk stopped at rule_limit, so CS-10 cannot rest on the absence.", {
        ...HOST_FIREWALL_HEALTHY, assigned_firewall_policy_count: 0, firewall_rule_groups_complete: false,
      }),
      example("unreadable", "manual", "A rule group lookup was refused.", { firewall_policies_readable: true, firewall_rule_groups_readable: false }),
    ],
  },
  {
    id: "CS-11",
    control: 11,
    title: "Firewall - Default Deny",
    severity: "high",
    owner: DEVICE_FIREWALL,
    surfaces: [...FIREWALL_SURFACES, "firewall_rule_ids", "firewall_rules"],
    inputs: [
      "firewall_policies_readable",
      "firewall_policies_complete",
      "firewall_rules_readable",
      "firewall_rules_complete",
      "assigned_firewall_container_count",
      "containers_without_inbound_deny",
      "containers_not_enforced",
      "undocumented_allow_rule_count",
      "firewall_rule_count",
    ],
    rules: [
      rule("manual", any(ne("firewall_policies_readable", true), ne("firewall_rules_readable", true))),
      ...noneAssigned("assigned_firewall_container_count", "firewall_policies_complete", "firewall_rules_complete"),
      rule("fail", gt("containers_without_inbound_deny", 0)),
      rule("warn", any(gt("containers_not_enforced", 0), gt("undocumented_allow_rule_count", 0), eq("firewall_rule_count", 0))),
      rule("warn", incomplete("firewall_policies_complete", "firewall_rules_complete")),
      rule("pass", always),
    ],
    completeness: {
      firewall_policies_complete: FIREWALL_POLICIES_COMPLETE,
      firewall_rules_complete: FIREWALL_RULES_COMPLETE,
    },
    decision: "Manual when the firewall policy list, a container lookup, the rule walk, or a rule lookup is unreadable, or when the firewall policy list or the rule list is partial and no container of an assigned policy was returned. Fail when no container of an assigned firewall policy was returned, or when such a container's default_inbound is not DENY. Warn when such a container does not enforce, when an enabled ALLOW rule has no description, or when no firewall rule was returned. Warn instead of pass when the firewall policy list or the rule list is partial. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Both assigned containers enforce a default inbound DENY, and every enabled ALLOW rule has a description.", DEFAULT_DENY_HEALTHY),
      example("noncompliant", "fail", "An assigned container's default_inbound is ALLOW.", {
        ...DEFAULT_DENY_HEALTHY, containers_without_inbound_deny: 1,
      }),
      example("noncompliant", "fail", "An assigned container's default_inbound is ALLOW, and the rule walk stopped at rule_limit.", {
        ...DEFAULT_DENY_HEALTHY, firewall_rules_complete: false, containers_without_inbound_deny: 1,
      }),
      example("partial", "warn", "An assigned container defaults inbound to DENY without enforcing.", {
        ...DEFAULT_DENY_HEALTHY, containers_not_enforced: 1,
      }),
      example("partial", "warn", "An enabled ALLOW rule has no description.", {
        ...DEFAULT_DENY_HEALTHY, undocumented_allow_rule_count: 1,
      }),
      example("partial", "warn", "The rule lookups returned no rule.", {
        ...DEFAULT_DENY_HEALTHY, firewall_rule_count: 0,
      }),
      example("partial", "warn", "Every assigned container passes, but the rule walk stopped at rule_limit.", {
        ...DEFAULT_DENY_HEALTHY, firewall_rules_complete: false,
      }),
      example("noncompliant", "fail", "The complete lists show no container for an assigned firewall policy.", {
        ...DEFAULT_DENY_HEALTHY, assigned_firewall_container_count: 0,
      }),
      example("partial", "manual", "No container of an assigned policy is visible and the firewall policy list stopped at the cap, so CS-11 cannot rest on the absence.", {
        ...DEFAULT_DENY_HEALTHY, firewall_policies_complete: false, assigned_firewall_container_count: 0,
      }),
      example("unreadable", "manual", "A container lookup was refused.", { firewall_policies_readable: false }),
    ],
  },
];

const SENSOR_COVERAGE = "crowdstrike_assess_sensor_coverage";

const SENSOR_UPDATE_HEALTHY = {
  sensor_update_policies_readable: true,
  sensor_update_policies_complete: true,
  assigned_sensor_update_policy_count: 2,
  sensor_update_builds_readable: true,
  policies_with_updates_off: 0,
  policies_pinned_to_unsupported_build: 0,
  policies_with_unverified_builds: 0,
  policies_without_uninstall_protection: 0,
};
const HOSTS_HEALTHY = { hosts_readable: true, hosts_complete: true, host_count: 1000 };
const DEPLOYMENT_HEALTHY = { ...HOSTS_HEALTHY, dated_host_count: 1000, recently_seen_host_count: 1000 };
const GROUPING_HEALTHY = { ...HOSTS_HEALTHY, grouped_host_count: 1000, host_groups_readable: true, host_groups_complete: true, host_group_count: 12 };
const DISCOVER_HEALTHY = { discover_counts_readable: true, unmanaged_asset_total: 0, unmanaged_per_mille: 0, discover_samples_readable: true };
const ZERO_TRUST_HEALTHY = { zero_trust_readable: true, scored_host_total: 2000, below_threshold_host_count: 0, below_threshold_total_reported: true };

const SENSOR_COVERAGE_CHECKS: readonly CrowdstrikeCheck[] = [
  {
    id: "CS-12",
    control: 12,
    title: "Sensor Update - Auto-Update Enabled",
    severity: "high",
    owner: SENSOR_COVERAGE,
    surfaces: ["sensor_update_policies", "sensor_update_builds"],
    inputs: Object.keys(SENSOR_UPDATE_HEALTHY),
    rules: [
      rule("manual", ne("sensor_update_policies_readable", true)),
      ...noneAssigned("assigned_sensor_update_policy_count", "sensor_update_policies_complete"),
      rule("fail", any(gt("policies_with_updates_off", 0), gt("policies_pinned_to_unsupported_build", 0))),
      rule("warn", any(
        gt("policies_with_unverified_builds", 0),
        gt("policies_without_uninstall_protection", 0),
        ne("sensor_update_builds_readable", true),
        ne("sensor_update_policies_complete", true),
      )),
      rule("pass", always),
    ],
    completeness: { sensor_update_policies_complete: SENSOR_UPDATE_POLICIES_COMPLETE },
    decision: "Manual when the sensor update policy list is unreadable, or when it is partial and shows no assigned policy. Fail when no sensor update policy is assigned. Fail when an assigned policy turns updates off, or pins a build whose number is not supported in its platform's readable catalog, even on a partial list. Warn when an assigned policy has a build of unknown form, pins a build that no readable catalog can check, or lacks uninstall protection, or when a catalog read was refused. Warn instead of pass when the sensor update policy list is partial. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Both assigned policies auto-update within N-2 and enable uninstall protection.", SENSOR_UPDATE_HEALTHY),
      example("noncompliant", "fail", "One assigned policy has no settings.build, so its sensors never update.", {
        ...SENSOR_UPDATE_HEALTHY, policies_with_updates_off: 1,
      }),
      example("noncompliant", "fail", "One assigned policy pins a build its platform's catalog no longer offers as n, n-1, or n-2.", {
        ...SENSOR_UPDATE_HEALTHY, policies_pinned_to_unsupported_build: 1,
      }),
      example("noncompliant", "fail", "A visible assigned policy turns updates off, and the list stopped at the cap.", {
        ...SENSOR_UPDATE_HEALTHY, sensor_update_policies_complete: false, policies_with_updates_off: 1,
      }),
      example("partial", "warn", "One assigned policy pins a build while its catalog read was refused.", {
        ...SENSOR_UPDATE_HEALTHY, sensor_update_builds_readable: false, policies_with_unverified_builds: 1,
      }),
      example("partial", "warn", "Every assigned policy auto-updates, but one catalog read was refused.", {
        ...SENSOR_UPDATE_HEALTHY, sensor_update_builds_readable: false,
      }),
      example("partial", "warn", "One assigned policy leaves uninstall protection off.", {
        ...SENSOR_UPDATE_HEALTHY, policies_without_uninstall_protection: 1,
      }),
      example("partial", "warn", "The visible policies pass, but the list stopped at the cap.", {
        ...SENSOR_UPDATE_HEALTHY, sensor_update_policies_complete: false,
      }),
      example("noncompliant", "fail", "The complete sensor update policy list holds no enabled policy that reaches hosts.", {
        sensor_update_policies_readable: true, sensor_update_policies_complete: true, assigned_sensor_update_policy_count: 0,
      }),
      example("partial", "manual", "The list stopped at the cap before any assigned policy was visible.", {
        sensor_update_policies_readable: true, sensor_update_policies_complete: false, assigned_sensor_update_policy_count: 0,
      }),
      example("unreadable", "manual", "The sensor update policy list was refused.", { sensor_update_policies_readable: false }),
    ],
  },
  {
    id: "CS-13",
    control: 13,
    title: "Sensor Coverage - Deployment Completeness",
    severity: "high",
    owner: SENSOR_COVERAGE,
    surfaces: ["hosts"],
    inputs: Object.keys(DEPLOYMENT_HEALTHY),
    constants: { deployment_fail_below_per_mille: 850, deployment_warn_below_per_mille: 950 },
    rules: [
      rule("manual", ne("hosts_readable", true)),
      rule("manual", all(eq("host_count", 0), incomplete("hosts_complete"))),
      rule("fail", eq("host_count", 0)),
      rule("fail", perMilleBelow("recently_seen_host_count", "dated_host_count", "deployment_fail_below_per_mille")),
      rule("warn", any(
        perMilleBelow("recently_seen_host_count", "dated_host_count", "deployment_warn_below_per_mille"),
        lt("dated_host_count", path("host_count")),
        incomplete("hosts_complete"),
      )),
      rule("pass", always),
    ],
    completeness: { hosts_complete: HOSTS_COMPLETE },
    decision: "Manual when the host list is unreadable, or when it is partial and returned no host. Fail when the complete host list returned no host. When at least one returned host has a last_seen that parses as a date, divide those seen within stale_sensor_days by all of them, multiply by 1000, and round halves up: fail below deployment_fail_below_per_mille (850, so 84.95 percent rounds to 85.0 and does not fail) and warn below deployment_warn_below_per_mille (950). Warn instead of pass when a returned host has no last_seen that parses as a date, including when none has one, or when the host list is partial. Otherwise pass.",
    examples: [
      example("compliant", "pass", "1899 of 2000 dated hosts seen within stale_sensor_days round to 950 per mille.", {
        ...DEPLOYMENT_HEALTHY, host_count: 2000, dated_host_count: 2000, recently_seen_host_count: 1899,
      }),
      example("partial", "warn", "949 of 1000 dated hosts were seen within stale_sensor_days.", {
        ...DEPLOYMENT_HEALTHY, recently_seen_host_count: 949,
      }),
      example("partial", "warn", "1699 of 2000 dated hosts round to 850 per mille, which does not fail.", {
        ...DEPLOYMENT_HEALTHY, host_count: 2000, dated_host_count: 2000, recently_seen_host_count: 1699,
      }),
      example("noncompliant", "fail", "1698 of 2000 dated hosts are 849 per mille.", {
        ...DEPLOYMENT_HEALTHY, host_count: 2000, dated_host_count: 2000, recently_seen_host_count: 1698,
      }),
      example("noncompliant", "fail", "Half the visible hosts are stale, and the list stopped at host_limit.", {
        ...DEPLOYMENT_HEALTHY, hosts_complete: false, host_count: 100, dated_host_count: 100, recently_seen_host_count: 50,
      }),
      example("partial", "warn", "Every dated host is fresh, but two returned hosts carry no last_seen.", {
        ...DEPLOYMENT_HEALTHY, host_count: 1002,
      }),
      example("partial", "warn", "No returned host carries a last_seen that parses as a date.", {
        ...DEPLOYMENT_HEALTHY, host_count: 5, dated_host_count: 0, recently_seen_host_count: 0,
      }),
      example("partial", "warn", "Every visible host is fresh, but the list stopped at host_limit.", {
        ...DEPLOYMENT_HEALTHY, hosts_complete: false,
      }),
      example("noncompliant", "fail", "The complete host list is empty.", {
        ...DEPLOYMENT_HEALTHY, host_count: 0, dated_host_count: 0, recently_seen_host_count: 0,
      }),
      example("partial", "manual", "The list stopped at host_limit before any host was visible.", {
        ...DEPLOYMENT_HEALTHY, hosts_complete: false, host_count: 0, dated_host_count: 0, recently_seen_host_count: 0,
      }),
      example("unreadable", "manual", "The host list was refused.", { hosts_readable: false }),
    ],
  },
  {
    id: "CS-14",
    control: 14,
    title: "Sensor Coverage - Host Group Assignment",
    severity: "medium",
    owner: SENSOR_COVERAGE,
    surfaces: ["hosts", "host_groups"],
    inputs: Object.keys(GROUPING_HEALTHY),
    constants: { grouping_fail_below_per_mille: 800, grouping_warn_below_per_mille: 950 },
    rules: [
      rule("manual", any(ne("hosts_readable", true), ne("host_groups_readable", true))),
      rule("manual", all(eq("host_group_count", 0), incomplete("host_groups_complete"))),
      rule("fail", eq("host_group_count", 0)),
      rule("manual", all(eq("host_count", 0), incomplete("hosts_complete"))),
      rule("fail", eq("host_count", 0)),
      rule("fail", perMilleBelow("grouped_host_count", "host_count", "grouping_fail_below_per_mille")),
      rule("warn", any(
        perMilleBelow("grouped_host_count", "host_count", "grouping_warn_below_per_mille"),
        incomplete("hosts_complete", "host_groups_complete"),
      )),
      rule("pass", always),
    ],
    completeness: { hosts_complete: HOSTS_COMPLETE, host_groups_complete: HOST_GROUPS_COMPLETE },
    decision: "Manual when the host list or the host group list is unreadable. Manual when the host group list is partial and returned no host group, and fail when the complete host group list returned none. Then manual when the host list is partial and returned no host, and fail when the complete host list returned none. Divide the returned hosts with a non-empty groups array by all returned hosts, multiply by 1000, and round halves up: fail below grouping_fail_below_per_mille (800, so 79.95 percent rounds to 80.0 and does not fail) and warn below grouping_warn_below_per_mille (950). Warn instead of pass when the host list or the host group list is partial. Otherwise pass.",
    examples: [
      example("compliant", "pass", "950 of 1000 hosts belong to a host group.", { ...GROUPING_HEALTHY, grouped_host_count: 950 }),
      example("partial", "warn", "949 of 1000 hosts belong to a host group.", { ...GROUPING_HEALTHY, grouped_host_count: 949 }),
      example("partial", "warn", "1599 of 2000 grouped hosts round to 800 per mille, which does not fail.", {
        ...GROUPING_HEALTHY, host_count: 2000, grouped_host_count: 1599,
      }),
      example("noncompliant", "fail", "799 of 1000 hosts belong to a host group.", { ...GROUPING_HEALTHY, grouped_host_count: 799 }),
      example("partial", "warn", "Every visible host is grouped, but the host group list stopped at the cap.", {
        ...GROUPING_HEALTHY, host_groups_complete: false,
      }),
      example("noncompliant", "fail", "The complete host group list is empty.", { ...GROUPING_HEALTHY, host_group_count: 0 }),
      example("partial", "manual", "The host group list stopped at the cap before any group was visible.", {
        ...GROUPING_HEALTHY, host_groups_complete: false, host_group_count: 0,
      }),
      example("noncompliant", "fail", "The complete host list is empty.", { ...GROUPING_HEALTHY, host_count: 0, grouped_host_count: 0 }),
      example("partial", "manual", "The host list stopped at host_limit before any host was visible.", {
        ...GROUPING_HEALTHY, hosts_complete: false, host_count: 0, grouped_host_count: 0,
      }),
      example("unreadable", "manual", "The host group list was refused.", { hosts_readable: true, host_groups_readable: false }),
      example("unreadable", "manual", "The host list was refused.", { hosts_readable: false }),
    ],
  },
  {
    id: "CS-15",
    control: 15,
    title: "Unmanaged Asset Detection",
    severity: "medium",
    owner: SENSOR_COVERAGE,
    surfaces: ["discover_unmanaged_count", "discover_managed_count", "discover_unmanaged_hosts"],
    inputs: Object.keys(DISCOVER_HEALTHY),
    inputTypes: { unmanaged_asset_total: ["null"], unmanaged_per_mille: ["null"] },
    constants: { unmanaged_fail_above_per_mille: 50 },
    rules: [
      rule("manual", any(ne("discover_counts_readable", true), unreported("unmanaged_per_mille"))),
      rule("fail", gt("unmanaged_per_mille", path("unmanaged_fail_above_per_mille"))),
      rule("warn", any(ne("unmanaged_asset_total", 0), ne("discover_samples_readable", true))),
      rule("pass", always),
    ],
    decision: "Manual when either Falcon Discover count read is unreadable, which includes a tenant without Falcon Discover, when either read reports no total, or when the two totals sum to 0. Fail when unmanaged_per_mille is above unmanaged_fail_above_per_mille (50, so 5.04 percent rounds to 5.0 and does not fail). Warn when any unmanaged asset is reported, or when the unmanaged sample walk was refused. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Falcon Discover reports no unmanaged asset.", DISCOVER_HEALTHY),
      example("partial", "warn", "1 of 20 discovered assets is unmanaged, exactly 50 per mille.", {
        ...DISCOVER_HEALTHY, unmanaged_asset_total: 1, unmanaged_per_mille: 50,
      }),
      example("noncompliant", "fail", "101 of 2000 discovered assets are unmanaged, which rounds to 51 per mille.", {
        ...DISCOVER_HEALTHY, unmanaged_asset_total: 101, unmanaged_per_mille: 51,
      }),
      example("partial", "warn", "No unmanaged asset is reported, but the sample walk was refused.", {
        ...DISCOVER_HEALTHY, discover_samples_readable: false,
      }),
      example("unreadable", "manual", "The managed count read reported no total.", {
        ...DISCOVER_HEALTHY, unmanaged_asset_total: 3, unmanaged_per_mille: null,
      }),
      example("unreadable", "manual", "Both totals are 0, so Discover is not collecting.", { ...DISCOVER_HEALTHY, unmanaged_per_mille: null }),
      example("unreadable", "manual", "The unmanaged count read was refused.", { discover_counts_readable: false }),
    ],
  },
  {
    id: "CS-25",
    control: 25,
    title: "Zero Trust Assessment",
    severity: "low",
    owner: SENSOR_COVERAGE,
    surfaces: ["zero_trust_scored_count", "zero_trust_below_threshold", "zero_trust_below_threshold_count"],
    inputs: Object.keys(ZERO_TRUST_HEALTHY),
    inputTypes: { scored_host_total: ["null"] },
    constants: { zta_fail_above_per_mille: 100 },
    rules: [
      rule("manual", any(ne("zero_trust_readable", true), unreported("scored_host_total"), eq("scored_host_total", 0))),
      rule("fail", perMilleAbove("below_threshold_host_count", "scored_host_total", "zta_fail_above_per_mille")),
      rule("warn", any(ne("below_threshold_host_count", 0), ne("below_threshold_total_reported", true))),
      rule("pass", always),
    ],
    decision: "Manual when a Zero Trust Assessment read is unreadable, which includes a tenant without Zero Trust Assessment, or when the scored read reports no total or a total of 0. Divide below_threshold_host_count by scored_host_total, multiply by 1000, and round halves up: fail above zta_fail_above_per_mille (100, so 10.05 percent rounds to 10.1 and fails). Warn when any host scores below the threshold, or when the below-threshold read reported no total, since the walk's count is then only a lower bound. Otherwise pass.",
    examples: [
      example("compliant", "pass", "No scored host is below the threshold.", ZERO_TRUST_HEALTHY),
      example("partial", "warn", "200 of 2000 scored hosts are below the threshold, exactly 100 per mille.", {
        ...ZERO_TRUST_HEALTHY, below_threshold_host_count: 200,
      }),
      example("noncompliant", "fail", "201 of 2000 scored hosts are below the threshold, which rounds to 101 per mille.", {
        ...ZERO_TRUST_HEALTHY, below_threshold_host_count: 201,
      }),
      example("noncompliant", "fail", "The walk alone found 400 of 2000 scored hosts below the threshold, a lower bound that already fails.", {
        ...ZERO_TRUST_HEALTHY, below_threshold_host_count: 400, below_threshold_total_reported: false,
      }),
      example("partial", "warn", "The walk found no host below the threshold, but the below-threshold read reported no total.", {
        ...ZERO_TRUST_HEALTHY, below_threshold_total_reported: false,
      }),
      example("unreadable", "manual", "The scored read reported no total.", { ...ZERO_TRUST_HEALTHY, scored_host_total: null }),
      example("unreadable", "manual", "Zero Trust Assessment scored no host.", { ...ZERO_TRUST_HEALTHY, scored_host_total: 0 }),
      example("unreadable", "manual", "The scored read was refused.", { zero_trust_readable: false }),
    ],
  },
];

const toCheck = (check: CrowdstrikeCheck): BatchCheckDefinition => {
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
    decisionConstants: check.constants ?? {},
    decisionRules: executable.rules,
    derivedFactRules: executable.derivedFactRules,
    ...(check.completeness ? { completeness: check.completeness } : {}),
    decision: check.decision,
    examples: check.examples,
  };
};

const checks: readonly BatchCheckDefinition[] = [
  ...PREVENTION_CHECKS,
  ...RESPONSE_CHECKS,
  ...DEVICE_FIREWALL_CHECKS,
  ...SENSOR_COVERAGE_CHECKS,
].map(toCheck);
const idsFor = (owner: string): string[] => checks.filter((check) => check.owner === owner).map((check) => check.id);

const DROPPED_RESOURCE = "A returned resource that is not a JSON object is dropped and marks the list partial.";
const LOOKED_UP = "The listed IDs that are non-blank strings or finite numbers are then looked up by ID, and fewer returned records than listed IDs marks the list partial.";

// pageSize stays null: the limit sent shrinks on the last page under the cap, so no single value is always sent.
const offsetWalk = (
  surfaceIds: readonly string[],
  records: string,
  pageSize: number,
  cap: ItemCap,
  partial = DROPPED_RESOURCE,
): BatchPaginationDefinition => ({
  surfaceIds,
  cursorFields: ["meta.pagination.total", "meta.pagination.next", "meta.pagination.offset"],
  pageSize: null,
  itemCap: typeof cap === "number" ? cap : null,
  pageCap: null,
  totalSemantics: `Pages of ${pageSize} ${records} (limit), or the ${records} left under ${capText(cap)} when fewer. The first page sends no offset; each later page sends ${nextOffset(records)}. Without meta.pagination.total the walk runs to an empty page or the cap. ${partial}`,
  stopConditions: [
    `meta.pagination.total ${records} read`,
    `An empty page, which marks the list partial when fewer than meta.pagination.total ${records} were read`,
    `${capReached(cap, records)} read, which marks the list partial when meta.pagination.total is larger or, without a total, when the last page was full or carried a cursor that is not a whole number`,
    "A cursor that is not a whole number and repeats an earlier page's, which marks the list partial",
  ],
});

const afterWalk = (surfaceIds: readonly string[], records: string, pageSize: number, cap: ItemCap): BatchPaginationDefinition => ({
  surfaceIds,
  cursorFields: ["meta.pagination.after", "meta.pagination.total"],
  pageSize: null,
  itemCap: typeof cap === "number" ? cap : null,
  pageCap: null,
  totalSemantics: `Pages of ${pageSize} ${records} (limit), or the ${records} left under ${capText(cap)} when fewer. The first page sends no after; each later page sends the previous page's meta.pagination.after. ${DROPPED_RESOURCE}`,
  stopConditions: [
    `A page without meta.pagination.after, which marks the list partial when fewer than meta.pagination.total ${records} were kept`,
    `${capReached(cap, records)} read, an empty page, or a meta.pagination.after equal to the one the page was requested with, each of which marks the list partial unless meta.pagination.total is reported and that many ${records} were kept`,
  ],
});

const FRAMEWORK_REPORTS = ["fedramp", "cmmc", "soc2", "cis", "pci_dss", "disa_stig", "irap", "ismap"];

// The export runs every assessment and writes each one's datasets under its own category.
const RAW_DATA_FILES: Readonly<Record<string, readonly string[]>> = {
  prevention_policies: ["prevention_policies"],
  response_readiness: ["response_policies", "rtr_audit_sessions", "alerts", "contained_hosts"],
  device_firewall: [
    "device_control_policies",
    "device_control_policy_details",
    "firewall_policies",
    "firewall_policy_containers",
    "firewall_rule_groups",
    "firewall_rules",
  ],
  sensor_coverage: [
    "sensor_update_policies",
    "sensor_update_builds",
    "hosts",
    "host_groups",
    "discover_unmanaged_samples",
    "zero_trust_assessments_below_threshold",
  ],
};

export const CROWDSTRIKE_SPEC = buildBatchIntegrationSpec({
  slug: "crowdstrike-sec-inspector",
  displayName: "CrowdStrike Security Inspector",
  vendor: "CrowdStrike",
  category: "endpoint-security",
  summary: "Portable contract for the shipped CrowdStrike Falcon prevention policy, response readiness, device control and firewall, sensor coverage, and access governance assessments over the CrowdStrike Falcon API.",
  sourceModule: "cli/extensions/grc-tools/crowdstrike.ts",
  baseServices: [API_SERVICE],
  authentication: CROWDSTRIKE_AUTH_RESOLVER,
  permissions: [
    {
      id: "prevention-policies-read",
      kind: "oauth-scope",
      value: "Prevention policies: Read",
      unlocks: ["prevention_policies"],
    },
    {
      id: "response-policies-read",
      kind: "oauth-scope",
      value: "Response policies: Read",
      unlocks: ["response_policies"],
    },
    {
      id: "rtr-audit-read",
      kind: "oauth-scope",
      value: "Real time response audit: Read",
      unlocks: ["rtr_audit_sessions"],
    },
    {
      id: "alerts-read",
      kind: "oauth-scope",
      value: "Alerts: Read",
      unlocks: ["alerts", "alert_ids"],
    },
    {
      id: "hosts-read",
      kind: "oauth-scope",
      value: "Hosts: Read",
      unlocks: ["contained_hosts", "hosts"],
    },
    {
      id: "device-control-policies-read",
      kind: "oauth-scope",
      value: "Device control policies: Read",
      unlocks: ["device_control_policies", "device_control_policy_details"],
    },
    {
      id: "firewall-management-read",
      kind: "oauth-scope",
      value: "Firewall management: Read",
      unlocks: ["firewall_policies", "firewall_policy_containers", "firewall_rule_group_ids", "firewall_rule_groups", "firewall_rule_ids", "firewall_rules"],
    },
    {
      id: "sensor-update-policies-read",
      kind: "oauth-scope",
      value: "Sensor update policies: Read",
      unlocks: ["sensor_update_policies", "sensor_update_builds"],
    },
    {
      id: "host-groups-read",
      kind: "oauth-scope",
      value: "Host groups: Read",
      unlocks: ["host_groups"],
    },
    {
      id: "discover-read",
      kind: "oauth-scope",
      value: "Assets (Falcon Discover): Read",
      unlocks: ["discover_host_ids", "discover_unmanaged_count", "discover_managed_count", "discover_unmanaged_hosts"],
    },
    {
      id: "zero-trust-assessment-read",
      kind: "oauth-scope",
      value: "Zero Trust Assessment: Read",
      unlocks: ["zero_trust_scored_count", "zero_trust_below_threshold", "zero_trust_below_threshold_count"],
    },
  ],
  surfaces: CROWDSTRIKE_SURFACES,
  checks,
  tools: {
    crowdstrike_check_access: [],
    crowdstrike_assess_prevention_policies: idsFor(PREVENTION),
    crowdstrike_assess_response_readiness: idsFor(RESPONSE),
    crowdstrike_assess_device_firewall: idsFor(DEVICE_FIREWALL),
    crowdstrike_assess_sensor_coverage: idsFor(SENSOR_COVERAGE),
    crowdstrike_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [
    offsetWalk(["prevention_policies", "response_policies", "device_control_policies", "firewall_policies", "sensor_update_policies"], "policies", 500, 5000),
    offsetWalk(["host_groups"], "host groups", 500, 5000),
    offsetWalk(["rtr_audit_sessions"], "sessions", 500, 500),
    afterWalk(["alerts"], "alerts", 1000, ALERT_LIMIT),
    offsetWalk(["contained_hosts", "hosts"], "hosts", 1000, HOST_LIMIT),
    afterWalk(["discover_unmanaged_hosts"], "hosts", 100, 100),
    afterWalk(["zero_trust_below_threshold"], "results", 1000, 1000),
    offsetWalk(["firewall_rule_group_ids", "firewall_rule_ids"], "IDs", 500, RULE_LIMIT, LOOKED_UP),
    {
      surfaceIds: ["device_control_policy_details", "firewall_policy_containers", "firewall_rule_groups", "firewall_rules"],
      cursorFields: ["ids"],
      pageSize: null,
      itemCap: "none",
      pageCap: null,
      totalSemantics: "Every ID to look up is requested in batches of 100, each ID sent as its own ids query parameter; each batch is one read, and no cursor in its response is followed.",
      stopConditions: ["Every batch of up to 100 IDs requested"],
    },
    {
      surfaceIds: ["alert_ids", "discover_host_ids"],
      cursorFields: ["meta.pagination.total"],
      pageSize: 1,
      itemCap: "none",
      pageCap: 1,
      totalSemantics: "One read of a single ID on the crowdstrike_check_access probe; meta.pagination.total, else the number of returned IDs, is the surface's count.",
      stopConditions: ["The first response"],
    },
    {
      surfaceIds: ["discover_unmanaged_count", "discover_managed_count", "zero_trust_scored_count", "zero_trust_below_threshold_count"],
      cursorFields: ["meta.pagination.total"],
      pageSize: 1,
      itemCap: "none",
      pageCap: 1,
      totalSemantics: "One read of a single ID whose meta.pagination.total is the count; the returned ID is never kept, and no cursor in the response is followed.",
      stopConditions: ["The first response"],
    },
    {
      surfaceIds: ["sensor_update_builds"],
      cursorFields: [],
      pageSize: null,
      itemCap: "none",
      pageCap: 1,
      totalSemantics: "One read per distinct platform keeps every returned build; no cursor in its response is followed.",
      stopConditions: ["The first response for each platform"],
    },
  ],
  rateLimit: {
    documentedLimit: "Per API client: responses report the limit in X-Ratelimit-Limit and the requests left in X-Ratelimit-Remaining, which the collector does not read.",
    retryHeaders: ["X-Ratelimit-RetryAfter", "Retry-After"],
    retryableStatuses: [429],
    retryableStatusRanges: [{ from: 500, to: 599 }],
    backoffPolicy: "Retry 429 and every status of 500 or above up to 4 times after the first attempt. The wait comes from X-Ratelimit-RetryAfter when the response carries it, else from Retry-After: a number above 1000000000000 is an epoch time in milliseconds, a number above 1000000000 an epoch time in seconds, any other non-negative number a count of seconds, and a value that is not a number is read as an HTTP date; an absent or unreadable value waits 250 milliseconds times 2 to the power of the number of earlier attempts. Every wait is clamped to 250 milliseconds through 15 seconds. A 401 discards the cached token and repeats the request once with a new one, and that repeat counts as one of the 4 retries. Requests that time out (30 seconds unless timeout_seconds or CS_TIMEOUT sets it) and network errors are not retried.",
  },
  runtimeBehavior: [],
  knownGaps: [],
  sensitiveFields: ["client_secret", "access_token", "Authorization"],
  credentialFormats: [
    "CrowdStrike Falcon API client ID and client secret, exchanged at /oauth2/token for a bearer token",
    "CrowdStrike Falcon OAuth2 bearer access token",
  ],
  output: buildBatchOutputContract({
    files: [
      "QUICK_REFERENCE.md",
      "metadata.json",
      ...Object.entries(RAW_DATA_FILES).flatMap(([category, names]) => names.map((name) => `core_data/${category}/${name}.json`)),
      ...Object.keys(RAW_DATA_FILES).map((category) => `analysis/${category}.json`),
      "analysis/access_check.json",
      "analysis/findings.json",
      "compliance/executive_summary.md",
      "compliance/unified_compliance_matrix.md",
      ...FRAMEWORK_REPORTS.map((key) => `compliance/frameworks/${key}.md`),
    ],
    conditionalFiles: ["_errors.log"],
    conditionalFileConditions: { "_errors.log": "Only when some reads fail but the bundle still completes." },
    overwritePolicy: "Allocate {cloud, else the base_url host}[-{member_cid}]-audit-bundle, lowercased with every run of characters outside a-z, 0-9, dot, underscore, and hyphen replaced by one hyphen, trimmed of leading and trailing hyphens, and cut to 80 characters (crowdstrike when nothing is left), or the first of -2 through -9 whose directory and zip are both free, and fail rather than overwrite.",
    archivePairing: "Write a sibling zip named from the exact allocated bundle-directory path plus .zip.",
  }),
  lastUpdated: "2026-10-18",
  redaction: {
    projectionStage: "Every response passes the data redaction pass when it is read, which rewrites remembered credential values in raw and encoded forms, credential carriers, and token-shaped text in every string. Alerts and RTR sessions are then exported projected to their declared snapshot fields, and every other dataset is exported as read.",
  },
});
