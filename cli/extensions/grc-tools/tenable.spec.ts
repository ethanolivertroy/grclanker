import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
} from "./batch-spec-builder.js";
import {
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
import { TENABLE_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import { BATCH3_FRAMEWORK_FILES, batch3Checks, batch3Source, type Batch3CheckRow } from "./batch3-spec-helpers.js";

const DOCS = "https://developer.tenable.com/reference/navigate";
const surface = (id: string, path: string, fields: readonly string[], method: "GET" | "POST" = "GET") => {
  const securityCenter = path.startsWith("/rest/");
  const parameters = path === "/assets/export"
    ? [{ name: "chunk_size", location: "form-body" as const, required: true, value: "10000" }]
    : path === "/vulns/export"
      ? [
          { name: "num_assets", location: "form-body" as const, required: true, value: "5000" },
          { name: "include_plugin_output", location: "form-body" as const, required: true, value: "false" },
          { name: "filters.since", location: "form-body" as const, required: true, value: "Unix seconds for now minus vuln_lookback_days." },
          { name: "filters.state", location: "form-body" as const, required: true, value: "open, reopened, fixed" },
        ]
      : path.includes("{export_uuid}")
        ? [
            { name: "export_uuid", location: "path" as const, required: true, value: "Identifier returned by the corresponding export POST." },
            ...(path.includes("{chunk_id}")
              ? [{ name: "chunk_id", location: "path" as const, required: true, value: "Each ID reported in chunks_available, bounded by max_chunks." }]
              : [
                  { name: "poll_interval_ms", location: "client" as const, required: true, value: "1000 milliseconds unless injected by the caller." },
                  { name: "poll_deadline_ms", location: "client" as const, required: true, value: "300000 milliseconds unless injected by the caller." },
                ]),
          ]
        : path.includes("{policy_id}") || path.includes("{scan_id}")
          ? [{ name: path.includes("{policy_id}") ? "policy_id" : "scan_id", location: "path" as const, required: true, value: "Identifier returned by the parent inventory." }]
          : [
              { name: "offset", location: "query" as const, required: false, value: "Returned pagination offset; omitted on the first page." },
              { name: "limit", location: "query" as const, required: false, value: "Concrete endpoint page size, normally 1000." },
            ];
  return restSurface(
    id,
    path,
    securityCenter ? "Tenable Security Center REST API" : "Tenable Vulnerability Management REST API",
    DOCS,
    fields,
    method,
    {
      headers: securityCenter
        ? ["x-apikey: accesskey=<resolved>; secretkey=<resolved>", "Accept: application/json"]
        : ["X-ApiKeys: accessKey=<resolved>; secretKey=<resolved>", "Accept: application/json", "Content-Type: application/json for export POST requests"],
      parameters,
      responseShape: `JSON ${method === "POST" ? "export workflow" : "resource"} document containing ${fields.join(", ")}.`,
    },
  );
};
const NON_TRUNCATION_FAILURES = ["error", "denied", "not-collected", "not-configured", "missing-required-field"] as const;

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
  surface("sc-feed", "/rest/feed", ["active.updateTime", "active.stale"]),
] as const;

const rows: readonly Batch3CheckRow[] = [
  { id: "TENABLE-01", control: 1, title: "Scan policy configuration", severity: "high", owner: "tenable_assess_scan_program", surfaces: ["policies", "policy-details"], predicate: "Count policies whose readable detail omits safe checks, an appropriate port range, enabled plugin families, or credential configuration; failed detail reads make evidence incomplete." },
  { id: "TENABLE-02", control: 2, title: "Scan schedule discipline", severity: "high", owner: "tenable_assess_scan_program", surfaces: ["scans", "scan-details", "networks", "sc-scans", "sc-scan-results"], predicate: "Count enabled networks without a recurring scan or scans whose latest completed run is older than stale_scan_days.", constants: { default_stale_scan_days: 30 } },
  {
    id: "TENABLE-03",
    control: 3,
    title: "Asset discovery coverage",
    severity: "high",
    owner: "tenable_assess_sensor_coverage",
    surfaces: ["asset-export", "asset-export-status", "asset-export-chunks", "networks"],
    predicate: "Fail when no assets are exported or fresh_assets divided by expected_asset_count is below 0.95; incomplete export chunks or network rows prevent pass.",
    emptyOutcome: "fail",
    constants: { default_stale_asset_days: 30, minimum_fresh_asset_ratio: 0.95 },
    runtimeFactNames: {
      readable: "tenable_03_asset_and_network_reads_succeeded",
      complete: "tenable_03_asset_export_and_networks_complete",
      population: "tenable_03_exported_asset_count",
      failureMatches: "tenable_03_fresh_asset_count",
      reviewMatches: "tenable_03_expected_asset_count",
    },
    decisionInputs: {
      tenable_03_asset_and_network_reads_succeeded: "Boolean true only when the asset export workflow and network inventory returned the fields needed for coverage.",
      tenable_03_asset_export_and_networks_complete: "Boolean true only when the export reached FINISHED, every advertised chunk was read, no record was unevaluable, and the network list exhausted.",
      tenable_03_exported_asset_count: "Non-negative complete count of asset records across every downloaded export chunk before evidence samples are sliced.",
      tenable_03_fresh_asset_count: "Non-negative count of exported assets whose last_seen falls inside default_stale_asset_days after applying the configured stale-asset option.",
      tenable_03_expected_asset_count: "Non-negative expected asset population supplied by the operator; null means coverage has no authoritative denominator and cannot pass.",
    },
    decisionRules: [
      batch2Rule("manual", batch2Ne("tenable_03_asset_and_network_reads_succeeded", true)),
      batch2Rule("fail", batch2Eq("tenable_03_exported_asset_count", 0)),
      batch2Rule("manual", batch2Not(batch2Defined("tenable_03_expected_asset_count"))),
      batch2Rule("fail", { op: "ratio", numerator: batch2Path("tenable_03_fresh_asset_count"), denominator: batch2Path("tenable_03_expected_asset_count"), comparator: "lt", threshold: batch2Path("minimum_fresh_asset_ratio") }),
      batch2Rule("warn", batch2Ne("tenable_03_asset_export_and_networks_complete", true)),
      batch2Rule("pass", { op: "always" }),
    ],
  },
  { id: "TENABLE-04", control: 4, title: "Credentialed scan ratio", severity: "high", owner: "tenable_assess_scan_program", surfaces: ["scans", "scan-details", "policies", "policy-details"], predicate: "Compute credentialed scan count divided by the complete scan population; ratios below credential_threshold violate.", constants: { default_credential_threshold: 0.8 } },
  {
    id: "TENABLE-05",
    control: 5,
    title: "Agent deployment status",
    severity: "high",
    owner: "tenable_assess_sensor_coverage",
    surfaces: ["agents", "asset-export", "asset-export-status", "asset-export-chunks"],
    predicate: "Fail when offline_agents plus stale_connect_agents divided by agent_count exceeds 0.1; undated or outdated agents and incomplete source inventories require review.",
    constants: { default_agent_offline_days: 7, maximum_unhealthy_agent_ratio: 0.1 },
    runtimeFactNames: {
      readable: "tenable_05_agent_reads_succeeded",
      complete: "tenable_05_agent_and_asset_sources_complete",
      population: "tenable_05_agent_count",
      failureMatches: "tenable_05_unhealthy_agent_count",
      reviewMatches: "tenable_05_agent_review_count",
    },
    decisionInputs: {
      tenable_05_agent_reads_succeeded: "Boolean true only when the linked-agent inventory and the server properties needed for version comparison are readable.",
      tenable_05_agent_and_asset_sources_complete: "Boolean true only when agent pagination and every required asset-export chunk exhausted without unevaluable records.",
      tenable_05_agent_count: "Non-negative complete count of linked agent records; zero means the deployment ratio cannot be established.",
      tenable_05_unhealthy_agent_count: "Non-negative count of linked agents whose raw status is offline or whose last_connect age exceeds default_agent_offline_days.",
      tenable_05_agent_review_count: "Non-negative count of linked agents missing last_connect or carrying an outdated version, plus one when a required source is partial.",
    },
    decisionRules: [
      batch2Rule("manual", batch2Any(batch2Ne("tenable_05_agent_reads_succeeded", true), batch2Eq("tenable_05_agent_count", 0))),
      batch2Rule("fail", { op: "ratio", numerator: batch2Path("tenable_05_unhealthy_agent_count"), denominator: batch2Path("tenable_05_agent_count"), comparator: "gt", threshold: batch2Path("maximum_unhealthy_agent_ratio") }),
      batch2Rule("warn", batch2Any(batch2Ne("tenable_05_agent_and_asset_sources_complete", true), batch2Gt("tenable_05_agent_review_count", 0))),
      batch2Rule("pass", { op: "always" }),
    ],
  },
  {
    id: "TENABLE-06",
    control: 6,
    title: "Agent group organization",
    severity: "medium",
    owner: "tenable_assess_sensor_coverage",
    surfaces: ["agents", "agent-groups"],
    predicate: "Fail when agents exist but no group exists, or ungrouped_agents_count divided by agent_count exceeds 0.1; any positive ungrouped count at or below that ratio requires review.",
    constants: { maximum_ungrouped_agent_ratio: 0.1 },
    runtimeFactNames: {
      readable: "tenable_06_agent_group_reads_succeeded",
      complete: "tenable_06_agent_and_group_lists_complete",
      population: "tenable_06_agent_count",
      failureMatches: "tenable_06_agent_group_count",
      reviewMatches: "tenable_06_ungrouped_agent_count",
    },
    decisionInputs: {
      tenable_06_agent_group_reads_succeeded: "Boolean true only when both the linked-agent inventory and agent-group inventory are readable.",
      tenable_06_agent_and_group_lists_complete: "Boolean true only when both the agent and agent-group listings exhausted without configured caps or failed pages.",
      tenable_06_agent_count: "Non-negative complete count of linked agents before any evidence sample is sliced.",
      tenable_06_agent_group_count: "Non-negative complete count of agent groups.",
      tenable_06_ungrouped_agent_count: "Non-negative count of linked agents that do not occur in any group membership list.",
    },
    decisionRules: [
      batch2Rule("manual", batch2Any(batch2Ne("tenable_06_agent_group_reads_succeeded", true), batch2Eq("tenable_06_agent_count", 0))),
      batch2Rule("fail", batch2Eq("tenable_06_agent_group_count", 0)),
      batch2Rule("fail", { op: "ratio", numerator: batch2Path("tenable_06_ungrouped_agent_count"), denominator: batch2Path("tenable_06_agent_count"), comparator: "gt", threshold: batch2Path("maximum_ungrouped_agent_ratio") }),
      batch2Rule("warn", batch2Any(batch2Ne("tenable_06_agent_and_group_lists_complete", true), batch2Gt("tenable_06_ungrouped_agent_count", 0))),
      batch2Rule("pass", { op: "always" }),
    ],
  },
  {
    id: "TENABLE-07",
    control: 7,
    title: "Scanner health and version",
    severity: "high",
    owner: "tenable_assess_sensor_coverage",
    surfaces: ["scanners", "server-properties", "sc-scanners", "sc-feed"],
    predicate: "Count scanners that are offline, disconnected, or whose version/plugin set differs from the readable server or Security Center feed baseline.",
    completenessSources: [
      batch3Source("scanners"),
      batch3Source("server-properties"),
      batch3Source("sc-scanners", NON_TRUNCATION_FAILURES),
      batch3Source("sc-feed"),
    ],
    completenessSemantics: "For TENABLE-07, Exact source-state effects: scanners sets evidence_complete false on truncated, error, denied, not-collected, not-configured, and missing-required-field. server-properties sets evidence_complete false on the same six states. sc-feed sets evidence_complete false on the same six states. sc-scanners sets evidence_complete false on error, denied, not-collected, not-configured, and missing-required-field; truncated leaves it unchanged for the suffixed Security Center finding, matching the shipped parent. Finding previews and exported samples never establish source cardinality.",
  },
  { id: "TENABLE-08", control: 8, title: "Plugin update currency", severity: "high", owner: "tenable_assess_sensor_coverage", surfaces: ["scanners", "server-properties", "sc-scanners"], predicate: "Count scanners whose plugin feed age exceeds plugin_stale_hours or whose plugin set is absent.", constants: { default_plugin_stale_hours: 24 } },
  { id: "TENABLE-09", control: 9, title: "Network zone configuration", severity: "medium", owner: "tenable_assess_sensor_coverage", surfaces: ["networks", "scanners"], predicate: "Count network zones without an assigned readable scanner or referencing a missing scanner." },
  { id: "TENABLE-10", control: 10, title: "User role and permission audit", severity: "high", owner: "tenable_assess_access_control", surfaces: ["users", "roles", "groups", "sc-users"], predicate: "Count active users inactive beyond inactive_user_days and administrator users above max_admins; unknown last-login fields require review.", constants: { default_inactive_user_days: 90, default_max_admins: 5 } },
  {
    id: "TENABLE-11",
    control: 11,
    title: "Access group review",
    severity: "high",
    owner: "tenable_assess_access_control",
    surfaces: ["access-groups", "groups", "permissions"],
    predicate: "Count access groups granting all-assets access without a constrained rule or permissions with unrestricted subjects; unreadable user-group membership prevents a clean permission inventory from passing.",
    completenessSources: [
      batch3Source("access-groups"),
      batch3Source("groups", NON_TRUNCATION_FAILURES),
      batch3Source("permissions", NON_TRUNCATION_FAILURES),
    ],
    completenessSemantics: "For TENABLE-11, Exact source-state effects: access-groups sets evidence_complete false on truncated, error, denied, not-collected, not-configured, and missing-required-field. groups sets evidence_complete false on error, denied, not-collected, not-configured, and missing-required-field; truncated leaves it unchanged when rows were delivered. permissions sets evidence_complete false on error, denied, not-collected, not-configured, and missing-required-field; truncated leaves it unchanged when delivered rows prove the shipped parent outcome. Finding previews and exported samples never establish source cardinality.",
  },
  { id: "TENABLE-12", control: 12, title: "Managed credential hygiene", severity: "high", owner: "tenable_assess_access_control", surfaces: ["credentials"], predicate: "Count managed credential metadata records with no type or modification timestamp; empty readable inventory requires review." },
  { id: "TENABLE-13", control: 13, title: "Scan exclusion audit", severity: "medium", owner: "tenable_assess_scan_program", surfaces: ["exclusions"], predicate: "Count enabled permanent exclusions, broad member ranges, and exclusions without a readable justification or expiry.", emptyOutcome: "pass" },
  { id: "TENABLE-14", control: 14, title: "Vulnerability prioritization (VPR)", severity: "high", owner: "tenable_assess_vulnerability_management", surfaces: ["vuln-export", "vuln-export-status", "vuln-export-chunks"], predicate: "Count open critical or high vulnerabilities without a numeric VPR score; an export with no evaluable records requires manual review." },
  { id: "TENABLE-15", control: 15, title: "Vulnerability SLA tracking", severity: "critical", owner: "tenable_assess_vulnerability_management", surfaces: ["vuln-export", "vuln-export-status", "vuln-export-chunks"], predicate: "Count open vulnerabilities older than the configurable severity SLA: critical, high, medium, or low days.", emptyOutcome: "pass", constants: { default_sla_critical_days: 15, default_sla_high_days: 30, default_sla_medium_days: 90, default_sla_low_days: 180 } },
  { id: "TENABLE-16", control: 16, title: "Asset tagging strategy", severity: "medium", owner: "tenable_assess_sensor_coverage", surfaces: ["asset-export", "asset-export-status", "asset-export-chunks", "tag-categories", "tag-values"], predicate: "Compute assets carrying at least one tag divided by the complete asset export; ratios below tagged_threshold violate.", constants: { default_tagged_threshold: 0.9 } },
  { id: "TENABLE-17", control: 17, title: "Compliance audit templates", severity: "high", owner: "tenable_assess_scan_program", surfaces: ["scan-templates", "scans", "policies"], predicate: "Count the absence of a compliance audit template and the absence of an enabled recurring scan using one." },
  { id: "TENABLE-18", control: 18, title: "Audit log review", severity: "medium", owner: "tenable_assess_access_control", surfaces: ["audit-events"], predicate: "Count sensitive administrative events inside audit_lookback_days; an empty readable event window is review evidence, not proof that review occurs.", emptyOutcome: "warn", constants: { default_audit_lookback_days: 30 } },
  {
    id: "TENABLE-19",
    control: 19,
    title: "Export and reporting automation",
    severity: "medium",
    owner: "tenable_assess_vulnerability_management",
    surfaces: ["vuln-export-jobs", "asset-export-jobs"],
    predicate: "Count the absence of a completed or scheduled vulnerability or asset export job.",
    completenessSources: [
      batch3Source("vuln-export-jobs", NON_TRUNCATION_FAILURES),
      batch3Source("asset-export-jobs", NON_TRUNCATION_FAILURES),
    ],
    completenessSemantics: "For TENABLE-19, Exact source-state effects: vuln-export-jobs sets evidence_complete false on error, denied, not-collected, not-configured, and missing-required-field; truncated leaves it unchanged when observed external jobs span at least two days. asset-export-jobs sets evidence_complete false on error, denied, not-collected, not-configured, and missing-required-field; truncated has the same no-change effect, matching the shipped parent. Finding previews and exported samples never establish source cardinality.",
  },
  { id: "TENABLE-20", control: 20, title: "Target group management", severity: "medium", owner: "tenable_assess_scan_program", surfaces: ["target-groups"], predicate: "Count target groups with empty, broad, overlapping, or unparseable member definitions.", emptyOutcome: "pass" },
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
  knownGaps: [
    "Tenable Security Center contributes schedule, scanner, feed, and user equivalents only; cloud-only exports and access-group controls remain manual for Security Center-only tenants.",
    "TENABLE-07-SC preserves the shipped parent behavior in which a healthy Security Center scanner sample can pass when the scanner inventory is truncated. This partial-pass exception is a report-only runtime candidate; the spec binding does not harden it.",
    "TENABLE-11 preserves the shipped parent behavior in which a clean permission result can pass when the permissions or user-group inventory is truncated; a broad permission observed in the loaded rows still fails. This partial-pass exception is a report-only runtime candidate; the spec binding does not harden it.",
    "TENABLE-19 preserves the shipped parent behavior in which external export jobs observed on at least two days can pass when either export-job listing is truncated. This partial-pass exception is a report-only runtime candidate; the spec binding does not harden it.",
  ],
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
