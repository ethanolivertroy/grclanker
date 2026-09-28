import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
  restSurface,
} from "./batch-spec-builder.js";
import { CROWDSTRIKE_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import {
  BATCH3_FRAMEWORK_FILES,
  batch3Checks,
  type Batch3CheckRow,
} from "./batch3-spec-helpers.js";

const DOCS = "https://docs.crowdstrike.com/r/falconpy/Service-Collections";

const surfaces = [
  restSurface("prevention-policies", "/policy/combined/prevention/v1", "Falcon Prevention Policies API", DOCS, ["id", "name", "enabled", "groups", "settings", "platform_name"]),
  restSurface("response-policies", "/policy/combined/response/v1", "Falcon Response Policies API", DOCS, ["id", "name", "enabled", "groups", "settings"]),
  restSurface("rtr-sessions", "/real-time-response-audit/combined/sessions/v1", "Falcon RTR Audit API", DOCS, ["id", "user_id", "created_at", "updated_at", "duration", "status"]),
  restSurface("alerts", "/alerts/combined/alerts/v1", "Falcon Alerts API", DOCS, ["id", "severity", "status", "created_timestamp", "updated_timestamp"]),
  restSurface("contained-hosts", "/devices/combined/devices/v1?filter=status:'contained'", "Falcon Hosts API", DOCS, ["device_id", "hostname", "status", "modified_timestamp"]),
  restSurface("device-control-policies", "/policy/combined/device-control/v1", "Falcon Device Control API", DOCS, ["id", "name", "enabled", "groups", "settings"]),
  restSurface("device-control-policy-details", "/policy/entities/device-control/v2?ids={ids}", "Falcon Device Control API", DOCS, ["id", "settings"]),
  restSurface("firewall-policies", "/policy/combined/firewall/v1", "Falcon Firewall Management API", DOCS, ["id", "name", "enabled", "groups"]),
  restSurface("firewall-policy-containers", "/fwmgr/entities/policies/v1?ids={ids}", "Falcon Firewall Management API", DOCS, ["id", "platform", "rule_group_ids"]),
  restSurface("firewall-rule-groups", "/fwmgr/queries/rule-groups/v1", "Falcon Firewall Management API", DOCS, ["resources", "meta.pagination.total"]),
  restSurface("firewall-rules", "/fwmgr/queries/rules/v1", "Falcon Firewall Management API", DOCS, ["resources", "meta.pagination.total"]),
  restSurface("sensor-update-policies", "/policy/combined/sensor-update/v2", "Falcon Sensor Update Policies API", DOCS, ["id", "name", "enabled", "groups", "settings", "platform_name"]),
  restSurface("sensor-update-builds", "/policy/combined/sensor-update-builds/v1?platform={platform}", "Falcon Sensor Update Policies API", DOCS, ["build", "platform", "version"]),
  restSurface("hosts", "/devices/combined/devices/v1", "Falcon Hosts API", DOCS, ["device_id", "hostname", "platform_name", "agent_version", "last_seen", "status", "groups"]),
  restSurface("host-groups", "/devices/combined/host-groups/v1", "Falcon Host Groups API", DOCS, ["id", "name", "group_type", "assignment_rule"]),
  restSurface("discover-hosts", "/discover/queries/hosts/v1", "Falcon Discover API", DOCS, ["meta.pagination.total", "resources"]),
  restSurface("zta-assessments", "/zero-trust-assessment/queries/assessments/v1", "Falcon Zero Trust Assessment API", DOCS, ["score", "device_id", "meta.pagination.total"]),
  restSurface("users", "/user-management/queries/users/v1", "Falcon User Management API", DOCS, ["resources", "meta.pagination.total"]),
  restSurface("user-details", "/user-management/entities/users/GET/v1", "Falcon User Management API", DOCS, ["uuid", "uid", "status", "last_login_at"]),
  restSurface("user-roles", "/user-management/combined/user-roles/v2?user_uuid={uuid}", "Falcon User Management API", DOCS, ["id", "name", "description"]),
  restSurface("roles", "/user-management/entities/roles/v1", "Falcon User Management API", DOCS, ["id", "name", "description"]),
  restSurface("api-clients", "/api-clients/entities/api-clients/v1", "Falcon API Client Management API", DOCS, ["id", "name", "scopes", "created_timestamp", "last_used_timestamp"]),
  restSurface("ioa-exclusions", "/policy/entities/ioa-exclusions/v1", "Falcon IOA Exclusions API", DOCS, ["id", "name", "cl_regex", "ifn_regex", "groups"]),
  restSurface("ml-exclusions", "/policy/entities/ml-exclusions/v1", "Falcon ML Exclusions API", DOCS, ["id", "value", "excluded_from", "groups"]),
  restSurface("sv-exclusions", "/policy/entities/sv-exclusions/v1", "Falcon Sensor Visibility Exclusions API", DOCS, ["id", "value", "groups"]),
  restSurface("identity-rules", "/identity-protection/entities/policy-rules/v1", "Falcon Identity Protection API", DOCS, ["id", "name", "enabled", "action", "rule_type"]),
] as const;

const rows: readonly Batch3CheckRow[] = [
  { id: "CS-01", control: 1, title: "Prevention Policy - ML Detection Levels", severity: "high", owner: "crowdstrike_assess_prevention_policies", surfaces: ["prevention-policies"], predicate: "Count enabled host-assigned prevention policies whose Windows, macOS, or Linux cloud and on-sensor machine-learning detection or prevention levels are absent or weaker than AGGRESSIVE." },
  { id: "CS-02", control: 2, title: "Prevention Policy - Exploit Mitigation", severity: "high", owner: "crowdstrike_assess_prevention_policies", surfaces: ["prevention-policies"], predicate: "Count enabled host-assigned prevention policies with any documented exploit-mitigation toggle explicitly disabled; absent required toggles are review records." },
  { id: "CS-03", control: 3, title: "Prevention Policy - Script-Based Execution Control", severity: "medium", owner: "crowdstrike_assess_prevention_policies", surfaces: ["prevention-policies"], predicate: "Count enabled host-assigned prevention policies with ScriptBasedExecutionMonitoring, InterpreterOnly, or EngineFull explicitly disabled; absent settings require review." },
  { id: "CS-04", control: 4, title: "Prevention Policy - Sensor Tamper Protection", severity: "critical", owner: "crowdstrike_assess_prevention_policies", surfaces: ["prevention-policies"], predicate: "Count enabled host-assigned prevention policies where SensorTamperProtection is explicitly false; a missing setting is review evidence." },
  { id: "CS-05", control: 5, title: "Prevention Policy - On-Write Detection", severity: "medium", owner: "crowdstrike_assess_prevention_policies", surfaces: ["prevention-policies"], predicate: "Count enabled host-assigned prevention policies with any documented on-write detection setting explicitly disabled; missing settings require review." },
  { id: "CS-06", control: 6, title: "Response Policy - RTR Enabled", severity: "medium", owner: "crowdstrike_assess_response_readiness", surfaces: ["response-policies"], predicate: "Count response-policy inventories with no enabled host-assigned policy enabling RealTimeFunctionality; enabled CustomScripts contributes review_count." },
  { id: "CS-07", control: 7, title: "Response Policy - Session Limits", severity: "low", owner: "crowdstrike_assess_response_readiness", surfaces: ["response-policies", "rtr-sessions"], predicate: "Count RTR sessions exceeding max_session_minutes or users exceeding max_concurrent_sessions inside the configured lookback; policy settings above either maximum also violate.", constants: { default_max_session_minutes: 30, default_max_concurrent_sessions: 3 } },
  { id: "CS-08", control: 8, title: "Device Control - USB Blocking", severity: "high", owner: "crowdstrike_assess_device_firewall", surfaces: ["device-control-policies", "device-control-policy-details"], predicate: "Count enabled host-assigned device-control policies that do not block USB mass storage by default; exception counts above max_usb_exceptions are review records.", constants: { default_max_usb_exceptions: 25 } },
  { id: "CS-09", control: 9, title: "Device Control - Peripheral Restrictions", severity: "medium", owner: "crowdstrike_assess_device_firewall", surfaces: ["device-control-policies", "device-control-policy-details"], predicate: "Count enabled host-assigned device-control policies missing restrictions for Bluetooth, Thunderbolt or PCIe, and SD-card classes." },
  { id: "CS-10", control: 10, title: "Firewall - Host Firewall Enabled", severity: "medium", owner: "crowdstrike_assess_device_firewall", surfaces: ["firewall-policies", "firewall-policy-containers", "firewall-rule-groups"], predicate: "Count the absence of an enabled host-assigned firewall policy container or the absence of assigned enabled rule groups; truncated rule inventories are incomplete." },
  { id: "CS-11", control: 11, title: "Firewall - Default Deny", severity: "high", owner: "crowdstrike_assess_device_firewall", surfaces: ["firewall-policies", "firewall-policy-containers", "firewall-rules"], predicate: "Count applied firewall policy containers with no terminal default-deny rule, or an empty container inventory when applied policies exist." },
  { id: "CS-12", control: 12, title: "Sensor Update - Auto-Update Enabled", severity: "high", owner: "crowdstrike_assess_sensor_coverage", surfaces: ["sensor-update-policies", "sensor-update-builds"], predicate: "Count enabled host-assigned sensor update policies configured off or pinned outside the current, N-1, or N-2 build set for their platform." },
  { id: "CS-13", control: 13, title: "Sensor Coverage - Deployment Completeness", severity: "high", owner: "crowdstrike_assess_sensor_coverage", surfaces: ["hosts"], predicate: "Count hosts whose last_seen is older than stale_sensor_days or absent; zero hosts is a violation, and a capped host inventory is incomplete.", constants: { default_stale_sensor_days: 7 } },
  { id: "CS-14", control: 14, title: "Sensor Coverage - Host Group Assignment", severity: "medium", owner: "crowdstrike_assess_sensor_coverage", surfaces: ["hosts", "host-groups"], predicate: "Count hosts with no group identifier or a group identifier absent from the readable host-group inventory." },
  { id: "CS-15", control: 15, title: "Unmanaged Asset Detection", severity: "medium", owner: "crowdstrike_assess_sensor_coverage", surfaces: ["discover-hosts"], predicate: "Count one violation when Falcon Discover reports any unmanaged hosts; a positive count is proved even when the optional sample is capped." },
  { id: "CS-16", control: 16, title: "RBAC - Admin Count", severity: "medium", owner: "crowdstrike_assess_access_governance", surfaces: ["users", "user-details", "user-roles", "roles"], predicate: "Count active administrator users above max_admins and suspected shared administrator accounts; unresolved per-user role reads make evidence incomplete.", constants: { default_max_admins: 5 } },
  { id: "CS-17", control: 17, title: "RBAC - Least Privilege", severity: "medium", owner: "crowdstrike_assess_access_governance", surfaces: ["users", "user-details", "user-roles", "roles"], predicate: "Count active users with more than max_roles_per_user roles or administrators inactive beyond stale_admin_login_days.", constants: { default_max_roles_per_user: 5, stale_admin_login_days: 90 } },
  { id: "CS-18", control: 18, title: "RBAC - API Client Permissions", severity: "high", owner: "crowdstrike_assess_access_governance", surfaces: ["api-clients"], predicate: "Count API clients with sensitive write scopes above max_write_clients; clients unused beyond stale_api_client_days contribute review_count.", constants: { default_max_write_clients: 3, stale_api_client_days: 90 } },
  { id: "CS-19", control: 19, title: "Exclusion Review - IOA Exclusions", severity: "medium", owner: "crowdstrike_assess_access_governance", surfaces: ["ioa-exclusions"], predicate: "Count IOA exclusions with broad match-all command-line or image-filename regexes; all other exclusions are review records." },
  { id: "CS-20", control: 20, title: "Exclusion Review - ML Exclusions", severity: "medium", owner: "crowdstrike_assess_access_governance", surfaces: ["ml-exclusions"], predicate: "Count machine-learning exclusions matching sensitive roots, whole drives, or broad wildcard paths; all other exclusions are review records." },
  { id: "CS-21", control: 21, title: "Exclusion Review - Sensor Visibility", severity: "high", owner: "crowdstrike_assess_access_governance", surfaces: ["sv-exclusions"], predicate: "Count sensor-visibility exclusions hiding entire drives, root directories, or recursively broad directory trees; all other exclusions are review records." },
  { id: "CS-22", control: 22, title: "Detection Response SLA", severity: "high", owner: "crowdstrike_assess_response_readiness", surfaces: ["alerts"], predicate: "Count critical alerts unresolved beyond 24 hours and high alerts unresolved beyond 72 hours inside lookback_days; undated alerts require review.", constants: { critical_sla_hours: 24, high_sla_hours: 72, default_lookback_days: 30 } },
  { id: "CS-23", control: 23, title: "Containment Policy", severity: "medium", owner: "crowdstrike_assess_response_readiness", surfaces: ["contained-hosts"], predicate: "Count contained hosts whose containment age exceeds 72 hours; contained hosts inside the SLA remain review records requiring documented incident ownership.", constants: { containment_sla_hours: 72 } },
  { id: "CS-24", control: 24, title: "Identity Protection", severity: "medium", owner: "crowdstrike_assess_access_governance", surfaces: ["identity-rules"], predicate: "Count the absence of enabled identity-protection policy rules or enabled rules whose action does not prevent or challenge risky identity behavior." },
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
