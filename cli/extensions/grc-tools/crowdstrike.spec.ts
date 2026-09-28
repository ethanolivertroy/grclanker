import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
} from "./batch-spec-builder.js";
import {
  batch2All,
  batch2Any,
  batch2Eq,
  batch2Gt,
  batch2Ne,
  batch2Path,
  batch2Rule,
  restSurface,
} from "./batch2-spec-helpers.js";
import { CROWDSTRIKE_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import {
  BATCH3_FRAMEWORK_FILES,
  batch3Checks,
  type Batch3CheckRow,
} from "./batch3-spec-helpers.js";
import type { RequestParameterContract } from "./spec-model.js";

const DOCS = "https://docs.crowdstrike.com/r/falconpy/Service-Collections";
export const CROWDSTRIKE_ML_SLIDER_LEVELS = ["DISABLED", "CAUTIOUS", "MODERATE", "AGGRESSIVE", "EXTRA_AGGRESSIVE"] as const;
export const CROWDSTRIKE_PRIMARY_ML_SLIDERS = ["CloudAntiMalware", "OnSensorMLSlider"] as const;
export const CROWDSTRIKE_SUPPLEMENTAL_ML_SLIDERS = [
  "AdwarePUP",
  "CloudAntiMalwareForMicrosoftOfficeFiles",
  "CloudMLSliderForPupAdwareCloudEndUserScans",
  "OnSensorMLAdwarePUPSlider",
  "OnSensorMLSliderForSensorEndUserScans",
  "OnSensorMLSliderForCloudEndUserScans",
] as const;
export const CROWDSTRIKE_CORE_EXPLOIT_MITIGATIONS = ["ForceASLR", "ForceDEP", "HeapSprayPreallocation", "NullPageAllocation", "SEHOverwriteProtection"] as const;
export const CROWDSTRIKE_EXTENDED_EXPLOIT_MITIGATIONS = [
  "ApplicationExploitationActivity",
  "ChopperWebshell",
  "DriveByDownload",
  "ProcessHollowing",
  "JavaScriptViaRundll32",
  "HardwareEnhancedExploitDetection",
] as const;
export const CROWDSTRIKE_SCRIPT_CONTROL_SETTINGS = ["ScriptBasedExecutionMonitoring", "InterpreterProtection", "EngineProtectionV2"] as const;
export const CROWDSTRIKE_ON_WRITE_SETTINGS = ["DetectOnWrite", "QuarantineOnWrite"] as const;
export const CROWDSTRIKE_SENSITIVE_WRITE_SCOPE_PATTERNS = [
  "prevention", "response", "sensor-update", "device-control", "firewall", "user-management",
  "api-clients?", "real-time-response", "hosts?", "host-groups?", "exclusions?",
  "identity-protection", "alerts?", "detects?", "incidents?",
] as const;
export const CROWDSTRIKE_SENSITIVE_EXCLUSION_PATH_PATTERNS = [
  "^(\\\\\\\\\\?\\\\)?[a-z]:\\\\(windows|program files|program files \\\\(x86\\\\)|programdata|users|temp)(\\\\|$)",
  "^/(usr|bin|sbin|etc|var|tmp|home|root|library|system)(/|$)",
  "^%(systemroot|windir|programfiles|programdata|userprofile|temp|appdata)%",
] as const;
export const CROWDSTRIKE_SHARED_ACCOUNT_PATTERN = "(^|[._-])(admin|administrator|root|shared|service|svc|soc|security|ops|team|helpdesk|noreply|generic|test)([._-]|$|@)";
const FALCON_HEADERS = ["Authorization: Bearer <OAuth access token>", "Accept: application/json", "Content-Type: application/json for POST requests"] as const;
const falconSurface = (
  id: string,
  path: string,
  service: string,
  fields: readonly string[],
  method: "GET" | "POST" = "GET",
  parameters: readonly RequestParameterContract[] = [],
) => restSurface(id, path, service, DOCS, fields, method, {
  headers: FALCON_HEADERS,
  parameters: [
    { name: "member_cid", location: "query", required: false, value: "Resolved Falcon member CID; appended to every tenant-scoped request when configured." },
    ...parameters,
  ],
  responseShape: `Falcon JSON envelope with resources and meta.pagination; projected fields: ${fields.join(", ")}.`,
});
const falconPagingParameters = [
  { name: "limit", location: "query" as const, required: false, value: "Runtime page size, bounded by the endpoint and collector caps." },
  { name: "offset_or_after", location: "query" as const, required: false, value: "The endpoint's returned offset or after cursor; omitted on the first request." },
] as const;
const listParameters = [
  ...falconPagingParameters,
  { name: "filter", location: "query" as const, required: false, value: "The exact check-specific Falcon FQL expression rendered by the consuming check." },
] as const;

const surfaces = [
  falconSurface("prevention-policies", "/policy/combined/prevention/v1", "Falcon Prevention Policies API", ["id", "name", "enabled", "groups", "prevention_settings", "platform_name"], "GET", listParameters),
  falconSurface("response-policies", "/policy/combined/response/v1", "Falcon Response Policies API", ["id", "name", "enabled", "groups", "settings"], "GET", listParameters),
  falconSurface("rtr-sessions", "/real-time-response-audit/combined/sessions/v1", "Falcon RTR Audit API", ["id", "user_id", "created_at", "updated_at", "duration", "status"], "GET", listParameters),
  falconSurface("alerts", "/alerts/combined/alerts/v1", "Falcon Alerts API", ["id", "severity", "status", "created_timestamp", "updated_timestamp"], "POST", [
    { name: "filter", location: "form-body", required: true, value: "severity:>=70+created_timestamp:>'now-<lookback_days>d', using the resolved lookback." },
    { name: "limit", location: "form-body", required: true, value: "Runtime page size, bounded by the alert_limit option." },
    { name: "sort", location: "form-body", required: true, value: "created_timestamp|desc" },
    { name: "after", location: "form-body", required: false, value: "Continuation cursor returned by meta.pagination.after." },
  ]),
  falconSurface("contained-hosts", "/devices/combined/devices/v1", "Falcon Hosts API", ["device_id", "hostname", "status", "modified_timestamp"], "GET", [
    ...falconPagingParameters,
    { name: "filter", location: "query", required: true, value: "status:['contained','containment_pending','lift_containment_pending']" },
  ]),
  falconSurface("device-control-policies", "/policy/combined/device-control/v1", "Falcon Device Control API", ["id", "name", "enabled", "groups", "settings"], "GET", listParameters),
  falconSurface("device-control-policy-details", "/policy/entities/device-control/v2", "Falcon Device Control API", ["id", "settings"], "GET", [
    { name: "ids", location: "query", required: true, value: "Comma-separated device-control policy IDs, batched at 100." },
  ]),
  falconSurface("firewall-policies", "/policy/combined/firewall/v1", "Falcon Firewall Management API", ["id", "name", "enabled", "groups"], "GET", listParameters),
  falconSurface("firewall-policy-containers", "/fwmgr/entities/policies/v1", "Falcon Firewall Management API", ["id", "platform", "rule_group_ids"], "GET", [
    { name: "ids", location: "query", required: true, value: "Comma-separated firewall policy IDs returned by the applied-policy inventory." },
  ]),
  falconSurface("firewall-rule-groups", "/fwmgr/queries/rule-groups/v1", "Falcon Firewall Management API", ["resources", "meta.pagination.total"], "GET", listParameters),
  falconSurface("firewall-rules", "/fwmgr/queries/rules/v1", "Falcon Firewall Management API", ["resources", "meta.pagination.total"], "GET", listParameters),
  falconSurface("sensor-update-policies", "/policy/combined/sensor-update/v2", "Falcon Sensor Update Policies API", ["id", "name", "enabled", "groups", "settings", "platform_name"], "GET", listParameters),
  falconSurface("sensor-update-builds", "/policy/combined/sensor-update-builds/v1", "Falcon Sensor Update Policies API", ["build", "platform", "version"], "GET", [
    { name: "platform", location: "query", required: true, value: "Each distinct platform_name observed in the sensor-update policy inventory." },
  ]),
  falconSurface("hosts", "/devices/combined/devices/v1", "Falcon Hosts API", ["device_id", "hostname", "platform_name", "agent_version", "last_seen", "status", "groups"], "GET", listParameters),
  falconSurface("host-groups", "/devices/combined/host-groups/v1", "Falcon Host Groups API", ["id", "name", "group_type", "assignment_rule"], "GET", listParameters),
  falconSurface("discover-hosts", "/discover/queries/hosts/v1", "Falcon Discover API", ["meta.pagination.total", "resources"], "GET", listParameters),
  falconSurface("zta-assessments", "/zero-trust-assessment/queries/assessments/v1", "Falcon Zero Trust Assessment API", ["score", "device_id", "meta.pagination.total"], "GET", listParameters),
  falconSurface("users", "/user-management/queries/users/v1", "Falcon User Management API", ["resources", "meta.pagination.total"], "GET", listParameters),
  falconSurface("user-details", "/user-management/entities/users/GET/v1", "Falcon User Management API", ["uuid", "uid", "status", "last_login_at"], "POST", [
    { name: "ids", location: "form-body", required: true, value: "Up to 100 user UUIDs returned by /user-management/queries/users/v1." },
  ]),
  falconSurface("user-roles", "/user-management/combined/user-roles/v2", "Falcon User Management API", ["id", "name", "description"], "GET", [
    { name: "user_uuid", location: "query", required: true, value: "UUID from the user-details response." },
  ]),
  falconSurface("roles", "/user-management/queries/roles/v1", "Falcon User Management API", ["resources"], "GET", listParameters),
  falconSurface("api-clients", "/api-clients/queries/api-clients/v1", "Falcon API Client Management API", ["id", "name", "scopes", "created_timestamp", "last_used_timestamp"], "GET", listParameters),
  falconSurface("ioa-exclusions", "/policy/queries/ioa-exclusions/v1", "Falcon IOA Exclusions API", ["id", "name", "cl_regex", "ifn_regex", "groups"], "GET", listParameters),
  falconSurface("ml-exclusions", "/policy/queries/ml-exclusions/v1", "Falcon ML Exclusions API", ["id", "value", "excluded_from", "groups"], "GET", listParameters),
  falconSurface("sv-exclusions", "/policy/queries/sv-exclusions/v1", "Falcon Sensor Visibility Exclusions API", ["id", "value", "groups"], "GET", listParameters),
  falconSurface("identity-rules", "/identity-protection/queries/policy-rules/v1", "Falcon Identity Protection API", ["id", "name", "enabled", "action", "rule_type"], "GET", listParameters),
] as const;

const PREVENTION_POLICY_COMPLETENESS = "The prevention-policies source owns the complete policy population. Truncation with one or more visible policies sets the check-owned population-complete fact false and retains visible primitive counts, capping a clean result at warn. Truncation with zero visible policies cannot prove an absence violation: it sets the check-owned readable fact false and the population, violation, and review counts to null, producing manual. Error, denied, not-collected, not-configured, and missing-required-field states have the same unavailable-fact effect. Finding previews and exported samples never establish source cardinality.";

const rows: readonly Batch3CheckRow[] = [
  { id: "CS-01", control: 1, title: "Prevention Policy - ML Detection Levels", severity: "high", owner: "crowdstrike_assess_prevention_policies", surfaces: ["prevention-policies"], predicate: "Fail when no enabled host-assigned prevention policy exists or any primary CloudAntiMalware or OnSensorMLSlider detection/prevention rank is DISABLED or CAUTIOUS; warn for missing primary values, ranks below AGGRESSIVE, or an uncovered Windows, Mac, or Linux platform.", completenessSemantics: PREVENTION_POLICY_COMPLETENESS, constants: { primary_ml_sliders: CROWDSTRIKE_PRIMARY_ML_SLIDERS, supplemental_ml_sliders: CROWDSTRIKE_SUPPLEMENTAL_ML_SLIDERS, ml_slider_levels_in_rank_order: CROWDSTRIKE_ML_SLIDER_LEVELS, cautious_max_rank: 1, aggressive_min_rank: 3 } },
  { id: "CS-02", control: 2, title: "Prevention Policy - Exploit Mitigation", severity: "high", owner: "crowdstrike_assess_prevention_policies", surfaces: ["prevention-policies"], predicate: `Fail when no enabled host-assigned prevention policy exists or any present required exploit toggle is false. Required toggles are ${[...CROWDSTRIKE_CORE_EXPLOIT_MITIGATIONS, ...CROWDSTRIKE_EXTENDED_EXPLOIT_MITIGATIONS].join(", ")}; a policy exposing none of them is review evidence.`, completenessSemantics: PREVENTION_POLICY_COMPLETENESS, constants: { core_exploit_mitigations: CROWDSTRIKE_CORE_EXPLOIT_MITIGATIONS, extended_exploit_mitigations: CROWDSTRIKE_EXTENDED_EXPLOIT_MITIGATIONS } },
  { id: "CS-03", control: 3, title: "Prevention Policy - Script-Based Execution Control", severity: "medium", owner: "crowdstrike_assess_prevention_policies", surfaces: ["prevention-policies"], predicate: `Fail when no enabled host-assigned prevention policy exists or any present required script-control toggle is false. Exact required field names: ${CROWDSTRIKE_SCRIPT_CONTROL_SETTINGS.join(", ")}; a policy exposing none is review evidence.`, completenessSemantics: PREVENTION_POLICY_COMPLETENESS, constants: { script_control_settings: CROWDSTRIKE_SCRIPT_CONTROL_SETTINGS } },
  { id: "CS-04", control: 4, title: "Prevention Policy - Sensor Tamper Protection", severity: "critical", owner: "crowdstrike_assess_prevention_policies", surfaces: ["prevention-policies"], predicate: "Fail when no enabled host-assigned prevention policy exists or SensorTamperingProtection is explicitly false; a missing SensorTamperingProtection setting is review evidence.", completenessSemantics: PREVENTION_POLICY_COMPLETENESS, constants: { tamper_protection_setting: "SensorTamperingProtection" } },
  { id: "CS-05", control: 5, title: "Prevention Policy - On-Write Detection", severity: "medium", owner: "crowdstrike_assess_prevention_policies", surfaces: ["prevention-policies"], predicate: "Fail when no enabled host-assigned prevention policy exists or DetectOnWrite is explicitly false; warn when DetectOnWrite is absent or QuarantineOnWrite is not true.", completenessSemantics: PREVENTION_POLICY_COMPLETENESS, constants: { required_on_write_settings: CROWDSTRIKE_ON_WRITE_SETTINGS } },
  { id: "CS-06", control: 6, title: "Response Policy - RTR Enabled", severity: "medium", owner: "crowdstrike_assess_response_readiness", surfaces: ["response-policies"], predicate: "Count response-policy inventories with no enabled host-assigned policy enabling RealTimeFunctionality; enabled CustomScripts contributes review_count." },
  { id: "CS-07", control: 7, title: "Response Policy - Session Limits", severity: "low", owner: "crowdstrike_assess_response_readiness", surfaces: ["response-policies", "rtr-sessions"], predicate: "Count RTR sessions exceeding max_session_minutes or users exceeding max_concurrent_sessions inside the configured lookback; policy settings above either maximum also violate.", violationOutcome: "warn", constants: { default_max_session_minutes: 30, default_max_concurrent_sessions: 3 } },
  { id: "CS-08", control: 8, title: "Device Control - USB Blocking", severity: "high", owner: "crowdstrike_assess_device_firewall", surfaces: ["device-control-policies", "device-control-policy-details"], predicate: "Count enabled host-assigned device-control policies that do not block USB mass storage by default; exception counts above max_usb_exceptions are review records.", constants: { default_max_usb_exceptions: 25 } },
  { id: "CS-09", control: 9, title: "Device Control - Peripheral Restrictions", severity: "medium", owner: "crowdstrike_assess_device_firewall", surfaces: ["device-control-policies", "device-control-policy-details"], predicate: "Count enabled host-assigned device-control policies missing restrictions for Bluetooth, Thunderbolt or PCIe, and SD-card classes." },
  { id: "CS-10", control: 10, title: "Firewall - Host Firewall Enabled", severity: "medium", owner: "crowdstrike_assess_device_firewall", surfaces: ["firewall-policies", "firewall-policy-containers", "firewall-rule-groups"], predicate: "Count the absence of an enabled host-assigned firewall policy container or the absence of assigned enabled rule groups; truncated rule inventories are incomplete." },
  { id: "CS-11", control: 11, title: "Firewall - Default Deny", severity: "high", owner: "crowdstrike_assess_device_firewall", surfaces: ["firewall-policies", "firewall-policy-containers", "firewall-rules"], predicate: "Count applied firewall policy containers with no terminal default-deny rule, or an empty container inventory when applied policies exist." },
  { id: "CS-12", control: 12, title: "Sensor Update - Auto-Update Enabled", severity: "high", owner: "crowdstrike_assess_sensor_coverage", surfaces: ["sensor-update-policies", "sensor-update-builds"], predicate: "Count enabled host-assigned sensor update policies configured off or pinned outside the current, N-1, or N-2 build set for their platform." },
  { id: "CS-13", control: 13, title: "Sensor Coverage - Deployment Completeness", severity: "high", owner: "crowdstrike_assess_sensor_coverage", surfaces: ["hosts"], predicate: "Count hosts whose last_seen is older than stale_sensor_days or absent; zero hosts is a violation, and a capped host inventory is incomplete.", emptyOutcome: "fail", constants: { default_stale_sensor_days: 7 } },
  {
    id: "CS-14",
    control: 14,
    title: "Sensor Coverage - Host Group Assignment",
    severity: "medium",
    owner: "crowdstrike_assess_sensor_coverage",
    surfaces: ["hosts", "host-groups"],
    predicate: "Compute assigned hosts divided by all readable hosts. Fail below 80 percent, warn from 80 percent through below 95 percent, and pass at or above 95 percent after both inventories are complete.",
    emptyOutcome: "fail",
    constants: { pass_assignment_percent: 95, fail_below_assignment_percent: 80 },
    runtimeFactNames: {
      readable: "cs_14_host_and_group_reads_succeeded",
      complete: "cs_14_host_and_group_lists_complete",
      population: "cs_14_host_count",
      failureMatches: "cs_14_host_group_count",
      reviewMatches: "cs_14_assigned_host_count",
    },
    decisionInputs: {
      cs_14_host_and_group_reads_succeeded: "Boolean true only when both the Falcon host inventory and host-group inventory returned parseable responses.",
      cs_14_host_and_group_lists_complete: "Boolean true only when pagination for both the Falcon host inventory and host-group inventory exhausted without a cap, repeated cursor, or rejected continuation.",
      cs_14_host_count: "Non-negative complete count of Falcon host records before the 25-row unassigned-host evidence sample is sliced.",
      cs_14_host_group_count: "Non-negative complete count of Falcon host-group records before group-type evidence is rendered.",
      cs_14_assigned_host_count: "Non-negative count over the complete host inventory of hosts whose raw groups array contains at least one identifier.",
    },
    decisionRules: [
      batch2Rule("manual", batch2Ne("cs_14_host_and_group_reads_succeeded", true)),
      batch2Rule("fail", batch2Any(batch2Eq("cs_14_host_count", 0), batch2Eq("cs_14_host_group_count", 0))),
      batch2Rule("fail", { op: "ratio", numerator: batch2Path("cs_14_assigned_host_count"), denominator: batch2Path("cs_14_host_count"), comparator: "lt", threshold: batch2Path("fail_below_assignment_percent"), scale: 100 }),
      batch2Rule("warn", batch2Any(
        batch2Ne("cs_14_host_and_group_lists_complete", true),
        { op: "ratio", numerator: batch2Path("cs_14_assigned_host_count"), denominator: batch2Path("cs_14_host_count"), comparator: "lt", threshold: batch2Path("pass_assignment_percent"), scale: 100 },
      )),
      batch2Rule("pass", { op: "always" }),
    ],
  },
  { id: "CS-15", control: 15, title: "Unmanaged Asset Detection", severity: "medium", owner: "crowdstrike_assess_sensor_coverage", surfaces: ["discover-hosts"], predicate: "Count one violation when Falcon Discover reports any unmanaged hosts; a positive count is proved even when the optional sample is capped." },
  { id: "CS-16", control: 16, title: "RBAC - Admin Count", severity: "medium", owner: "crowdstrike_assess_access_governance", surfaces: ["users", "user-details", "user-roles", "roles"], predicate: `Count active administrator users above max_admins and active administrator identifiers matching the case-insensitive portable regular expression ${CROWDSTRIKE_SHARED_ACCOUNT_PATTERN}; unresolved per-user role reads make evidence incomplete.`, constants: { default_max_admins: 5, shared_account_pattern: CROWDSTRIKE_SHARED_ACCOUNT_PATTERN } },
  { id: "CS-17", control: 17, title: "RBAC - Least Privilege", severity: "medium", owner: "crowdstrike_assess_access_governance", surfaces: ["users", "user-details", "user-roles", "roles"], predicate: "Count active users with more than max_roles_per_user roles or administrators inactive beyond stale_admin_login_days.", constants: { default_max_roles_per_user: 5, stale_admin_login_days: 90 } },
  { id: "CS-18", control: 18, title: "RBAC - API Client Permissions", severity: "high", owner: "crowdstrike_assess_access_governance", surfaces: ["api-clients"], predicate: `A client is write-capable when any lowercased scope matches one of these case-insensitive patterns: ${CROWDSTRIKE_SENSITIVE_WRITE_SCOPE_PATTERNS.join(", ")}. Fail when write-capable clients exceed max_write_clients; clients unused beyond stale_api_client_days require review.`, constants: { default_max_write_clients: 3, stale_api_client_days: 90, sensitive_write_scope_patterns: CROWDSTRIKE_SENSITIVE_WRITE_SCOPE_PATTERNS } },
  { id: "CS-19", control: 19, title: "Exclusion Review - IOA Exclusions", severity: "medium", owner: "crowdstrike_assess_access_governance", surfaces: ["ioa-exclusions"], predicate: "Fail for an IOA cl_regex or ifn_regex equal to match-all forms such as .*, ^.*$, .+, or ^.+$ after trimming; every other readable exclusion remains review evidence.", emptyOutcome: "pass", constants: { broad_ioa_regex_forms: [".*", "^.*$", ".+", "^.+$"] } },
  { id: "CS-20", control: 20, title: "Exclusion Review - ML Exclusions", severity: "medium", owner: "crowdstrike_assess_access_governance", surfaces: ["ml-exclusions"], predicate: `Fail when the normalized exclusion value is a whole drive, root, recursive wildcard, or matches one of these case-insensitive sensitive-root expressions: ${CROWDSTRIKE_SENSITIVE_EXCLUSION_PATH_PATTERNS.join(", ")}. Every other readable exclusion remains review evidence.`, emptyOutcome: "pass", constants: { sensitive_exclusion_path_patterns: CROWDSTRIKE_SENSITIVE_EXCLUSION_PATH_PATTERNS } },
  { id: "CS-21", control: 21, title: "Exclusion Review - Sensor Visibility", severity: "high", owner: "crowdstrike_assess_access_governance", surfaces: ["sv-exclusions"], predicate: `Fail when the normalized exclusion value is a whole drive, root, recursively broad directory tree, or matches one of these case-insensitive sensitive-root expressions: ${CROWDSTRIKE_SENSITIVE_EXCLUSION_PATH_PATTERNS.join(", ")}. Every other readable exclusion remains review evidence.`, emptyOutcome: "pass", constants: { sensitive_exclusion_path_patterns: CROWDSTRIKE_SENSITIVE_EXCLUSION_PATH_PATTERNS } },
  {
    id: "CS-22",
    control: 22,
    title: "Detection Response SLA",
    severity: "high",
    owner: "crowdstrike_assess_response_readiness",
    surfaces: ["alerts"],
    predicate: "Select alerts with severity at least 70 inside lookback_days. A severity at least 90 breaches after 24 hours; severity 70 through below 90 breaches after 72 hours. Compute on-SLA percent over dated alerts: fail below 80, warn from 80 through below 95, pass at or above 95. Undated alerts require review.",
    emptyOutcome: "pass",
    constants: { critical_sla_hours: 24, high_sla_hours: 72, default_lookback_days: 30, critical_severity_floor: 90, high_severity_floor: 70, pass_sla_percent: 95, fail_below_sla_percent: 80 },
    runtimeFactNames: {
      readable: "cs_22_alert_read_succeeded",
      complete: "cs_22_alert_list_complete",
      population: "cs_22_dated_alert_count",
      failureMatches: "cs_22_sla_compliant_alert_count",
      reviewMatches: "cs_22_undated_alert_count",
    },
    decisionInputs: {
      cs_22_alert_read_succeeded: "Boolean true only when POST /alerts/combined/alerts/v1 returned a parseable alert collection.",
      cs_22_alert_list_complete: "Boolean true only when the Falcon after cursor exhausted before the configured alert cap and no page failed.",
      cs_22_dated_alert_count: "Non-negative count of severity-at-least-70 alerts inside the configured lookback carrying a parseable created_timestamp.",
      cs_22_sla_compliant_alert_count: "Non-negative count of dated alerts resolved or still open within 24 hours at severity 90 or above, or within 72 hours at severity 70 through below 90.",
      cs_22_undated_alert_count: "Non-negative count of selected alerts lacking a parseable created_timestamp; these alerts are excluded from the percentage denominator and require review.",
    },
    decisionRules: [
      batch2Rule("manual", batch2Ne("cs_22_alert_read_succeeded", true)),
      batch2Rule("warn", batch2All(batch2Eq("cs_22_dated_alert_count", 0), batch2Ne("cs_22_alert_list_complete", true))),
      batch2Rule("pass", batch2All(batch2Eq("cs_22_dated_alert_count", 0), batch2Eq("cs_22_alert_list_complete", true), batch2Eq("cs_22_undated_alert_count", 0))),
      batch2Rule("fail", { op: "ratio", numerator: batch2Path("cs_22_sla_compliant_alert_count"), denominator: batch2Path("cs_22_dated_alert_count"), comparator: "lt", threshold: batch2Path("fail_below_sla_percent"), scale: 100 }),
      batch2Rule("warn", batch2Any(
        batch2Ne("cs_22_alert_list_complete", true),
        batch2Gt("cs_22_undated_alert_count", 0),
        { op: "ratio", numerator: batch2Path("cs_22_sla_compliant_alert_count"), denominator: batch2Path("cs_22_dated_alert_count"), comparator: "lt", threshold: batch2Path("pass_sla_percent"), scale: 100 },
      )),
      batch2Rule("pass", { op: "always" }),
    ],
  },
  {
    id: "CS-23",
    control: 23,
    title: "Containment Policy",
    severity: "medium",
    owner: "crowdstrike_assess_response_readiness",
    surfaces: ["contained-hosts"],
    predicate: "Count contained hosts whose containment age exceeds 72 hours; contained hosts inside the SLA remain review records requiring documented incident ownership.",
    emptyOutcome: "pass",
    constants: { containment_sla_hours: 72 },
    runtimeFactNames: {
      readable: "cs_23_contained_host_read_succeeded",
      complete: "cs_23_contained_host_list_complete",
      population: "cs_23_contained_host_count",
      failureMatches: "cs_23_max_containment_age_hours",
      reviewMatches: "cs_23_undated_contained_host_count",
    },
    decisionInputs: {
      cs_23_contained_host_read_succeeded: "Boolean true only when the exact three-status contained-host FQL query returned a parseable host collection.",
      cs_23_contained_host_list_complete: "Boolean true only when contained-host pagination exhausted without a cap, repeated cursor, or request failure.",
      cs_23_contained_host_count: "Non-negative complete count of hosts in contained, containment_pending, or lift_containment_pending state before the 50-row evidence sample.",
      cs_23_max_containment_age_hours: "Maximum whole hours since modified_timestamp among dated contained hosts; null means no contained host had a parseable timestamp.",
      cs_23_undated_contained_host_count: "Non-negative count of contained hosts whose modified_timestamp was absent or unparseable.",
    },
    decisionRules: [
      batch2Rule("manual", batch2Ne("cs_23_contained_host_read_succeeded", true)),
      batch2Rule("warn", batch2All(batch2Eq("cs_23_contained_host_count", 0), batch2Ne("cs_23_contained_host_list_complete", true))),
      batch2Rule("pass", batch2All(batch2Eq("cs_23_contained_host_count", 0), batch2Eq("cs_23_contained_host_list_complete", true))),
      batch2Rule("warn", { op: "gt", left: batch2Path("cs_23_max_containment_age_hours"), right: batch2Path("containment_sla_hours") }, "Every active containment reports warn; this ordered branch separately identifies hosts beyond the 72-hour SLA."),
      batch2Rule("warn", batch2Gt("cs_23_contained_host_count", 0)),
      batch2Rule("warn", batch2Any(batch2Ne("cs_23_contained_host_list_complete", true), batch2Gt("cs_23_undated_contained_host_count", 0))),
      batch2Rule("pass", { op: "always" }),
    ],
  },
  { id: "CS-24", control: 24, title: "Identity Protection", severity: "medium", owner: "crowdstrike_assess_access_governance", surfaces: ["identity-rules"], predicate: "Count the absence of enabled identity-protection policy rules or enabled rules whose action does not prevent or challenge risky identity behavior.", emptyOutcome: "fail" },
  { id: "CS-25", control: 25, title: "Zero Trust Assessment", severity: "low", owner: "crowdstrike_assess_sensor_coverage", surfaces: ["zta-assessments"], predicate: "Count assessments with score below min_zta_score; a zero total assessment population requires manual review.", constants: { default_min_zta_score: 60 } },
] as const;

const checks = batch3Checks(rows);
const idsFor = (owner: string) => checks.filter((check) => check.owner === owner).map((check) => check.id);

export const CROWDSTRIKE_RUNTIME_BEHAVIOR = [
  "The collector reads complete Falcon inventories before reducing them to verdict counts; displayed evidence samples never supply population denominators.",
  "A proved violation keeps its fail or warn branch when a companion inventory is partial, while an absence-based pass is demoted on truncation, denial, malformed records, or failed child reads.",
  "Falcon regional origins are selected from the resolved cloud or explicit same-origin base URL, and member_cid is attached to every tenant-scoped request when configured.",
] as const;

const outputFiles = [
  "README.md", "QUICK_REFERENCE.md", "metadata.json",
  "analysis/access_check.json", "analysis/findings.json",
  ...["prevention_policies", "response_readiness", "device_firewall", "sensor_coverage", "access_governance"].map((name) => `analysis/${name}.json`),
  "core_data/prevention_policies/prevention_policies.json",
  ...["response_policies", "rtr_audit_sessions", "alerts", "contained_hosts"].map((name) => `core_data/response_readiness/${name}.json`),
  ...["device_control_policies", "device_control_policy_details", "firewall_policies", "firewall_policy_containers", "firewall_rule_groups", "firewall_rules"].map((name) => `core_data/device_firewall/${name}.json`),
  ...["sensor_update_policies", "sensor_update_builds", "hosts", "host_groups", "discover_unmanaged_samples", "zero_trust_assessments_below_threshold"].map((name) => `core_data/sensor_coverage/${name}.json`),
  ...["users", "user_roles", "roles", "api_clients", "ioa_exclusions", "ml_exclusions", "sensor_visibility_exclusions", "identity_protection_rules"].map((name) => `core_data/access_governance/${name}.json`),
  "compliance/executive_summary.md", "compliance/unified_compliance_matrix.md",
  ...BATCH3_FRAMEWORK_FILES,
] as const;

export const CROWDSTRIKE_SPEC = buildBatchIntegrationSpec({
  slug: "crowdstrike-sec-inspector",
  displayName: "CrowdStrike Security Inspector",
  vendor: "CrowdStrike",
  category: "endpoint-security",
  summary: "Portable contract for Falcon policy, response, device, sensor, identity, exclusion, and Zero Trust assessments.",
  sourceModule: "cli/extensions/grc-tools/crowdstrike.ts",
  baseServices: ["CrowdStrike Falcon REST API", "Falcon OAuth 2.0"],
  authentication: CROWDSTRIKE_AUTH_RESOLVER,
  permissions: surfaces.map((surface) => ({
    id: `${surface.id}-read`,
    kind: "oauth-scope" as const,
    value: `Falcon read permission for ${surface.service}`,
    unlocks: [surface.id],
  })),
  surfaces,
  checks,
  tools: {
    crowdstrike_check_access: [],
    crowdstrike_assess_prevention_policies: idsFor("crowdstrike_assess_prevention_policies"),
    crowdstrike_assess_response_readiness: idsFor("crowdstrike_assess_response_readiness"),
    crowdstrike_assess_device_firewall: idsFor("crowdstrike_assess_device_firewall"),
    crowdstrike_assess_sensor_coverage: idsFor("crowdstrike_assess_sensor_coverage"),
    crowdstrike_assess_access_governance: idsFor("crowdstrike_assess_access_governance"),
    crowdstrike_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [
    {
      surfaceIds: surfaces.filter((surface) => !["device-control-policy-details", "user-details", "roles", "identity-rules"].includes(surface.id)).map((surface) => surface.id),
      cursorFields: ["meta.pagination.offset", "meta.pagination.after", "meta.pagination.total"],
      pageSize: 500,
      itemCap: 5000,
      pageCap: null,
      totalSemantics: "meta.pagination.total is authoritative when present; otherwise completion requires an empty or short page and no continuation cursor.",
      stopConditions: ["No continuation cursor", "Empty or short page", "Reported total reached", "Caller item cap", "Repeated offset or after cursor"],
    },
    {
      surfaceIds: ["device-control-policy-details", "user-details", "roles", "identity-rules"],
      cursorFields: [],
      pageSize: 100,
      itemCap: null,
      pageCap: null,
      totalSemantics: "Entity identifiers are batched at 100; completion requires a response for every requested identifier.",
      stopConditions: ["Every requested identifier resolved", "A batch request failed"],
    },
  ],
  rateLimit: {
    documentedLimit: "Falcon service collections publish per-route request limits in response headers; no single tenant-wide limit is assumed.",
    retryHeaders: ["Retry-After", "X-Ratelimit-Limit", "X-Ratelimit-Remaining"],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "Retry at most four times, honoring Retry-After up to 30 seconds and otherwise using bounded exponential backoff from 250 milliseconds.",
  },
  runtimeBehavior: CROWDSTRIKE_RUNTIME_BEHAVIOR,
  knownGaps: [
    "API client write-scope age and user last-login fields depend on Falcon tenant entitlements; absent fields remain review evidence rather than fabricated compliant values.",
  ],
  sensitiveFields: ["client_secret", "access_token", "authorization", "cookie", "email", "uid", "hostname", "device_id", "command_line", "file_path"],
  credentialFormats: ["Falcon OAuth client secrets", "Falcon bearer tokens", "authorization headers", "credential-like exclusion patterns"],
  output: buildBatchOutputContract({
    files: outputFiles,
    conditionalFiles: ["_errors.log"],
    conditionalFileConditions: { "_errors.log": "Written when any access probe, assessment dataset, child lookup, or archive step reports a collection error." },
    overwritePolicy: "Allocate crowdstrike-audit-<UTC timestamp> and add a numeric suffix when either the directory or paired archive exists.",
    archivePairing: "Create <allocated-directory>.zip beside the allocated CrowdStrike audit directory with the same suffix.",
  }),
});
