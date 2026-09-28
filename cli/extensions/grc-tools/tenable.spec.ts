import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
  restSurface,
} from "./batch-spec-builder.js";
import { TENABLE_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import { BATCH3_FRAMEWORK_FILES, batch3Checks, type Batch3CheckRow } from "./batch3-spec-helpers.js";

const DOCS = "https://developer.tenable.com/reference/navigate";
const surface = (id: string, path: string, fields: readonly string[], method: "GET" | "POST" = "GET") =>
  restSurface(id, path, path.startsWith("/rest/") ? "Tenable Security Center REST API" : "Tenable Vulnerability Management REST API", DOCS, fields, method);

const surfaces = [
  surface("server-properties", "/server/properties", ["plugin_set", "loaded_plugin_set", "server_version", "license"]),
  surface("scans", "/scans", ["id", "name", "status", "last_modification_date", "schedule_uuid", "enabled"]),
  surface("scan-details", "/scans/{scan_id}", ["info", "hosts", "history"]),
  surface("policies", "/policies", ["id", "name", "template_uuid", "last_modification_date"]),
  surface("policy-details", "/policies/{policy_id}", ["uuid", "settings", "plugins", "credentials"]),
  surface("scan-templates", "/editor/scan/templates", ["uuid", "name", "title", "subscription_only"]),
  surface("scanners", "/scanners", ["id", "name", "status", "last_connect", "plugin_set", "version"]),
  surface("agents", "/scanners/null/agents", ["id", "name", "status", "last_connect", "distro", "platform"]),
  surface("agent-groups", "/scanners/null/agent-groups", ["id", "name", "agent_count"]),
  surface("networks", "/networks", ["uuid", "name", "scanner_id", "created_at", "modified_at"]),
  surface("exclusions", "/exclusions", ["id", "name", "members", "schedule", "enabled"]),
  surface("credentials", "/credentials", ["uuid", "name", "type", "last_modified"]),
  surface("users", "/users?withRoles=true", ["id", "username", "permissions", "roles", "last_login", "enabled"]),
  surface("groups", "/groups", ["id", "name", "user_count"]),
  surface("roles", "/access-control/v1/roles", ["id", "name", "permissions"]),
  surface("permissions", "/api/v3/access-control/permissions", ["id", "name", "actions", "subjects"]),
  surface("access-groups", "/v2/access-groups", ["id", "name", "all_assets", "rules", "principals"]),
  surface("audit-events", "/audit-log/v1/events", ["id", "action", "actor", "date", "target"]),
  surface("tag-categories", "/tags/categories", ["uuid", "name", "description"]),
  surface("tag-values", "/tags/values", ["uuid", "category_uuid", "value", "asset_count"]),
  surface("target-groups", "/target-groups", ["id", "name", "members", "type"]),
  surface("vuln-export-jobs", "/vulns/export/status", ["exports", "status"]),
  surface("asset-export-jobs", "/assets/export/status", ["exports", "status"]),
  surface("asset-export", "/assets/export", ["export_uuid"], "POST"),
  surface("asset-export-status", "/assets/export/{export_uuid}/status", ["status", "chunks_available", "chunks_failed", "total_chunks"]),
  surface("asset-export-chunks", "/assets/export/{export_uuid}/chunks/{chunk_id}", ["id", "hostname", "last_seen", "agent_uuid", "tags"]),
  surface("vuln-export", "/vulns/export", ["export_uuid"], "POST"),
  surface("vuln-export-status", "/vulns/export/{export_uuid}/status", ["status", "chunks_available", "chunks_failed", "total_chunks"]),
  surface("vuln-export-chunks", "/vulns/export/{export_uuid}/chunks/{chunk_id}", ["asset", "plugin", "severity", "first_found", "last_found", "state", "vpr"]),
  surface("sc-scans", "/rest/scan", ["id", "name", "schedule", "status"]),
  surface("sc-scan-results", "/rest/scanResult", ["id", "name", "finishTime", "status"]),
  surface("sc-scanners", "/rest/scanner", ["id", "name", "status", "version"]),
  surface("sc-users", "/rest/user", ["id", "username", "role", "lastLogin"]),
] as const;

const rows: readonly Batch3CheckRow[] = [
  { id: "TENABLE-01", control: 1, title: "Scan policy configuration", severity: "high", owner: "tenable_assess_scan_program", surfaces: ["policies", "policy-details"], predicate: "Count policies whose readable detail omits safe checks, an appropriate port range, enabled plugin families, or credential configuration; failed detail reads make evidence incomplete." },
  { id: "TENABLE-02", control: 2, title: "Scan schedule discipline", severity: "high", owner: "tenable_assess_scan_program", surfaces: ["scans", "scan-details", "networks", "sc-scans", "sc-scan-results"], predicate: "Count enabled networks without a recurring scan or scans whose latest completed run is older than stale_scan_days.", constants: { default_stale_scan_days: 30 } },
  { id: "TENABLE-03", control: 3, title: "Asset discovery coverage", severity: "high", owner: "tenable_assess_sensor_coverage", surfaces: ["asset-export", "asset-export-status", "asset-export-chunks", "networks"], predicate: "Count assets not seen within stale_asset_days and configured network zones with no exported asset; incomplete export chunks prevent pass.", constants: { default_stale_asset_days: 30 } },
  { id: "TENABLE-04", control: 4, title: "Credentialed scan ratio", severity: "high", owner: "tenable_assess_scan_program", surfaces: ["scans", "scan-details", "policies", "policy-details"], predicate: "Compute credentialed scan count divided by the complete scan population; ratios below credential_threshold violate.", constants: { default_credential_threshold: 0.8 } },
  { id: "TENABLE-05", control: 5, title: "Agent deployment status", severity: "high", owner: "tenable_assess_sensor_coverage", surfaces: ["agents", "asset-export", "asset-export-status", "asset-export-chunks"], predicate: "Count linked agents offline beyond agent_offline_days and exported assets with no agent identifier.", constants: { default_agent_offline_days: 7 } },
  { id: "TENABLE-06", control: 6, title: "Agent group organization", severity: "medium", owner: "tenable_assess_sensor_coverage", surfaces: ["agents", "agent-groups"], predicate: "Count linked agents assigned to no agent group, plus empty group inventory when agents exist." },
  { id: "TENABLE-07", control: 7, title: "Scanner health and version", severity: "high", owner: "tenable_assess_sensor_coverage", surfaces: ["scanners", "server-properties", "sc-scanners"], predicate: "Count scanners that are offline, disconnected, or whose version/plugin set differs from the readable server baseline." },
  { id: "TENABLE-08", control: 8, title: "Plugin update currency", severity: "high", owner: "tenable_assess_sensor_coverage", surfaces: ["scanners", "server-properties", "sc-scanners"], predicate: "Count scanners whose plugin feed age exceeds plugin_stale_hours or whose plugin set is absent.", constants: { default_plugin_stale_hours: 24 } },
  { id: "TENABLE-09", control: 9, title: "Network zone configuration", severity: "medium", owner: "tenable_assess_sensor_coverage", surfaces: ["networks", "scanners"], predicate: "Count network zones without an assigned readable scanner or referencing a missing scanner." },
  { id: "TENABLE-10", control: 10, title: "User role and permission audit", severity: "high", owner: "tenable_assess_access_control", surfaces: ["users", "roles", "groups", "sc-users"], predicate: "Count active users inactive beyond inactive_user_days and administrator users above max_admins; unknown last-login fields require review.", constants: { default_inactive_user_days: 90, default_max_admins: 5 } },
  { id: "TENABLE-11", control: 11, title: "Access group review", severity: "high", owner: "tenable_assess_access_control", surfaces: ["access-groups", "permissions"], predicate: "Count access groups granting all-assets access without a constrained rule or permissions with unrestricted subjects." },
  { id: "TENABLE-12", control: 12, title: "Managed credential hygiene", severity: "high", owner: "tenable_assess_access_control", surfaces: ["credentials"], predicate: "Count managed credential metadata records with no type or modification timestamp; empty readable inventory requires review." },
  { id: "TENABLE-13", control: 13, title: "Scan exclusion audit", severity: "medium", owner: "tenable_assess_scan_program", surfaces: ["exclusions"], predicate: "Count enabled permanent exclusions, broad member ranges, and exclusions without a readable justification or expiry." },
  { id: "TENABLE-14", control: 14, title: "Vulnerability prioritization (VPR)", severity: "high", owner: "tenable_assess_vulnerability_management", surfaces: ["vuln-export", "vuln-export-status", "vuln-export-chunks"], predicate: "Count open critical or high vulnerabilities without a numeric VPR score; an export with no evaluable records requires manual review." },
  { id: "TENABLE-15", control: 15, title: "Vulnerability SLA tracking", severity: "critical", owner: "tenable_assess_vulnerability_management", surfaces: ["vuln-export", "vuln-export-status", "vuln-export-chunks"], predicate: "Count open vulnerabilities older than the configurable severity SLA: critical, high, medium, or low days.", constants: { default_sla_critical_days: 15, default_sla_high_days: 30, default_sla_medium_days: 90, default_sla_low_days: 180 } },
  { id: "TENABLE-16", control: 16, title: "Asset tagging strategy", severity: "medium", owner: "tenable_assess_sensor_coverage", surfaces: ["asset-export", "asset-export-status", "asset-export-chunks", "tag-categories", "tag-values"], predicate: "Compute assets carrying at least one tag divided by the complete asset export; ratios below tagged_threshold violate.", constants: { default_tagged_threshold: 0.9 } },
  { id: "TENABLE-17", control: 17, title: "Compliance audit templates", severity: "high", owner: "tenable_assess_scan_program", surfaces: ["scan-templates", "scans", "policies"], predicate: "Count the absence of a compliance audit template and the absence of an enabled recurring scan using one." },
  { id: "TENABLE-18", control: 18, title: "Audit log review", severity: "medium", owner: "tenable_assess_access_control", surfaces: ["audit-events"], predicate: "Count sensitive administrative events inside audit_lookback_days; an empty readable event window is review evidence, not proof that review occurs.", constants: { default_audit_lookback_days: 30 } },
  { id: "TENABLE-19", control: 19, title: "Export and reporting automation", severity: "medium", owner: "tenable_assess_vulnerability_management", surfaces: ["vuln-export-jobs", "asset-export-jobs"], predicate: "Count the absence of a completed or scheduled vulnerability or asset export job." },
  { id: "TENABLE-20", control: 20, title: "Target group management", severity: "medium", owner: "tenable_assess_scan_program", surfaces: ["target-groups"], predicate: "Count target groups with empty, broad, overlapping, or unparseable member definitions." },
] as const;

const checks = batch3Checks(rows);
const idsFor = (owner: string) => checks.filter((check) => check.owner === owner).map((check) => check.id);

export const TENABLE_RUNTIME_BEHAVIOR = [
  "Vulnerability Management and Security Center inventories remain separate sources; a Security Center equivalent adds a suffixed finding and never replaces the cloud control.",
  "Export status, every available chunk, failed chunks, unevaluable records, configured chunk caps, and poll failures contribute to completeness before any finding count is evaluated.",
  "A 2xx document missing the endpoint's documented collection member is unreadable rather than an empty inventory.",
] as const;

const core = [
  "access_check", "scans", "policies", "policy_details", "scan_templates", "exclusions", "target_groups",
  "assets_export", "server_properties", "scanners", "agents", "agent_groups", "networks", "tag_categories",
  "tag_values", "users", "groups", "roles", "permissions", "access_groups", "credentials",
  "audit_log_events", "vulns_export", "export_jobs", "security_center",
].map((name) => `core_data/${name}.json`);

export const TENABLE_SPEC = buildBatchIntegrationSpec({
  slug: "tenable-sec-inspector",
  displayName: "Tenable Security Inspector",
  vendor: "Tenable",
  category: "vulnerability-management",
  summary: "Portable contract for Tenable scan, sensor, access-control, and vulnerability-management assessments.",
  sourceModule: "cli/extensions/grc-tools/tenable.ts",
  baseServices: ["Tenable Vulnerability Management REST API", "Tenable Security Center REST API"],
  authentication: TENABLE_AUTH_RESOLVER,
  permissions: [
    { id: "administrator", kind: "role", value: "Administrator", unlocks: surfaces.map((entry) => entry.id), notes: "Full inventory and administrative metadata visibility." },
    { id: "scan-manager", kind: "role", value: "Scan Manager plus broad access-group membership", unlocks: ["scans", "scan-details", "policies", "policy-details", "scan-templates", "scanners", "agents", "agent-groups", "networks", "exclusions", "credentials", "target-groups"] },
  ],
  surfaces,
  checks,
  tools: {
    tenable_check_access: [],
    tenable_assess_scan_program: idsFor("tenable_assess_scan_program"),
    tenable_assess_sensor_coverage: idsFor("tenable_assess_sensor_coverage"),
    tenable_assess_access_control: idsFor("tenable_assess_access_control"),
    tenable_assess_vulnerability_management: idsFor("tenable_assess_vulnerability_management"),
    tenable_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [
    {
      surfaceIds: ["agents", "networks", "exclusions", "credentials", "access-groups", "audit-events", "tag-categories", "tag-values"],
      cursorFields: ["offset", "pagination.total"],
      pageSize: 1000,
      itemCap: null,
      pageCap: 200,
      totalSemantics: "pagination.total is authoritative when present; without it a short page establishes exhaustion.",
      stopConditions: ["Empty or short page", "Reported total reached", "200-page cap", "Repeated first-record key"],
    },
    {
      surfaceIds: ["asset-export-chunks", "vuln-export-chunks"],
      cursorFields: ["chunks_available", "chunks_failed", "total_chunks"],
      pageSize: null,
      itemCap: 50,
      pageCap: null,
      totalSemantics: "Completion requires a FINISHED export, every available chunk fetched, no failed chunk, no unevaluable record, and total_chunks accounted for.",
      stopConditions: ["Every available chunk downloaded", "Configured max_chunks reached", "Chunk failure", "Export ERROR or CANCELLED", "Poll timeout"],
    },
  ],
  rateLimit: {
    documentedLimit: "Tenable Vulnerability Management documents API concurrency and rate limits per endpoint and account; Security Center limits are deployment-specific.",
    retryHeaders: ["Retry-After", "X-RateLimit-Remaining", "X-RateLimit-Limit"],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "Retry four times with Retry-After when present and bounded exponential backoff otherwise; export polling uses a separate five-minute deadline.",
  },
  runtimeBehavior: TENABLE_RUNTIME_BEHAVIOR,
  knownGaps: ["Tenable Security Center contributes schedule, scanner, feed, and user equivalents only; cloud-only exports and access-group controls remain manual for Security Center-only tenants."],
  sensitiveFields: ["access_key", "secret_key", "x-apikey", "authorization", "cookie", "password", "credentials", "username"],
  credentialFormats: ["Tenable X-ApiKeys headers", "Security Center x-apikey headers", "managed credential payloads", "URL user information"],
  output: buildBatchOutputContract({
    files: [
      "QUICK_REFERENCE.md", "metadata.json", ...core,
      "analysis/findings.json", "analysis/scan_program.json", "analysis/sensor_coverage.json",
      "analysis/access_control.json", "analysis/vulnerability_management.json",
      "compliance/executive_summary.md", "compliance/unified_compliance_matrix.md", ...BATCH3_FRAMEWORK_FILES,
    ],
    conditionalFiles: ["_errors.log"],
    conditionalFileConditions: { "_errors.log": "Written when a platform read, child detail, export poll, chunk download, assessment, or archive step reports an error." },
    overwritePolicy: "Allocate <sanitized-platform-host>-audit-bundle and add a numeric suffix when the directory or archive already exists.",
    archivePairing: "Create <allocated-directory>.zip beside the allocated Tenable audit directory.",
  }),
});
