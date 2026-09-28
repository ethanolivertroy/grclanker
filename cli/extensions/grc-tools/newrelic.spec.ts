import { NEWRELIC_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import {
  batch4FrameworkFiles,
  batch4FrameworksFromMappings,
  batch4Surface,
  buildBatch4Spec,
  type Batch4Control,
} from "./batch4-spec-helpers.js";
import { NEWRELIC_CONTROL_CATALOG } from "./newrelic.js";

const NERDGRAPH_DOCS = "https://docs.newrelic.com/docs/apis/nerdgraph/";
const surfaces = [
  batch4Surface("identity", "POST", "NerdGraph: actor.organization, authenticationDomains, users, userManagement, authorizationManagement", "New Relic NerdGraph", NERDGRAPH_DOCS, ["id", "name", "authenticationType", "users", "groups", "roles", "lastActive", "email"]),
  batch4Surface("access-control", "POST", "NerdGraph: actor.accounts, apiAccess.keySearch, auditLog", "New Relic NerdGraph", NERDGRAPH_DOCS, ["accountId", "type", "createdAt", "lastUsed", "actor", "actionIdentifier", "roles"]),
  batch4Surface("alerting", "POST", "NerdGraph: alerts, aiNotifications, entitySearch, workload", "New Relic NerdGraph", NERDGRAPH_DOCS, ["policies", "nrqlConditions", "destinations", "channels", "workflows", "entities", "workloads"]),
  batch4Surface("data-governance", "POST", "NerdGraph: dataManagement, nrql, dashboard, synthetics, infrastructure", "New Relic NerdGraph", NERDGRAPH_DOCS, ["retention", "obfuscation", "dropRules", "permissions", "monitorType", "secureCredentials", "agentVersion"]),
] as const;

const controls: Batch4Control[] = NEWRELIC_CONTROL_CATALOG.map((definition) => ({
  id: definition.id,
  control: definition.number,
  title: definition.title,
  severity: definition.severity,
  owner: `newrelic_assess_${definition.category}`,
  surfaces: [definition.category.replaceAll("_", "-")],
  predicate: `Count complete-population NerdGraph records that violate ${definition.title}; per-account failures and missing schema fields stay unknown and cannot be converted to empty inventories.`,
  frameworks: batch4FrameworksFromMappings(definition.mappings),
  emptyOutcome: [4, 5, 6, 9, 10, 12, 13, 14, 17, 19, 20].includes(definition.number) ? "pass" : "manual",
}));
const coreDataFiles = [
  "organization", "authentication_domains", "authentication_domain_settings", "users", "group_role_grants",
  "roles", "accounts", "api_keys", "audit_api_key_actor_events", "audit_api_key_change_events",
  "alert_policies", "alert_nrql_conditions", "notification_destinations", "notification_channels",
  "workflows", "alertable_entities", "workloads", "retention_rules", "retention_namespaces",
  "obfuscation_rules", "obfuscation_expressions", "pipeline_cloud_rules", "nrql_drop_rules",
  "dashboards", "dashboard_live_urls", "synthetic_monitors", "secure_credentials",
  "synthetic_script_scan", "log_secret_scan", "infrastructure_hosts",
].map((name) => `core_data/${name}.json`);

export const NEWRELIC_RUNTIME_BEHAVIOR = [
  "NerdGraph queries request explicit schema-cited fields and apply a documented fallback only when the primary field or query is unavailable.",
  "Every account-scoped collection records success, denial, schema error, cursor anomaly, seen count, and total count independently before cross-account aggregation.",
  "A cursor is complete only when hasNextPage is false and any totalCount is reconciled; a missing or repeated endCursor and every cap exit are truncated.",
] as const;

export const NEWRELIC_SPEC = buildBatch4Spec({
  slug: "newrelic-sec-inspector",
  displayName: "New Relic Security Inspector",
  vendor: "New Relic",
  category: "observability",
  summary: "Portable contract for New Relic identity, API access, alerting, and telemetry-governance assessments.",
  sourceModule: "cli/extensions/grc-tools/newrelic.ts",
  baseServices: ["New Relic NerdGraph GraphQL API", "New Relic REST API"],
  authentication: NEWRELIC_AUTH_RESOLVER,
  surfaces,
  controls,
  tools: {
    newrelic_check_access: [],
    newrelic_assess_identity: controls.filter((item) => item.owner === "newrelic_assess_identity").map((item) => item.id),
    newrelic_assess_access_control: controls.filter((item) => item.owner === "newrelic_assess_access_control").map((item) => item.id),
    newrelic_assess_alerting: controls.filter((item) => item.owner === "newrelic_assess_alerting").map((item) => item.id),
    newrelic_assess_data_governance: controls.filter((item) => item.owner === "newrelic_assess_data_governance").map((item) => item.id),
    newrelic_export_audit_bundle: controls.map((item) => item.id),
  },
  pagination: [{
    surfaceIds: surfaces.map((surface) => surface.id),
    cursorFields: ["nextCursor", "pageInfo.hasNextPage", "pageInfo.endCursor", "totalCount"],
    pageSize: 50,
    itemCap: 10000,
    pageCap: 100,
    totalSemantics: "Completion requires hasNextPage=false and every reported totalCount no larger than the complete projected population.",
    stopConditions: ["hasNextPage=false", "Missing endCursor", "Repeated endCursor", "Item cap", "Page cap", "Total mismatch", "Per-account query failure"],
  }],
  documentedRateLimit: "NerdGraph returns query-cost and throttling errors rather than one fixed account-wide request limit.",
  retryHeaders: ["Retry-After", "NewRelic-Trace-Id"],
  runtimeBehavior: NEWRELIC_RUNTIME_BEHAVIOR,
  knownGaps: ["Controls whose decisive New Relic field is unavailable in the caller's schema or subscription remain manual."],
  sensitiveFields: ["apiKey", "email", "secureCredentials", "scriptText", "query", "authorization", "url"],
  credentialFormats: ["NRAK user API keys", "bearer headers", "synthetics secure credentials", "private-key and cloud-key patterns"],
  outputFiles: [
    "metadata.json", "QUICK_REFERENCE.md", ...coreDataFiles,
    "analysis/identity.json", "analysis/access_control.json", "analysis/alerting.json",
    "analysis/data_governance.json", "analysis/findings.json",
    "compliance/executive_summary.md", "compliance/unified_compliance_matrix.md",
    ...batch4FrameworkFiles(),
  ],
  overwritePolicy: "Allocate newrelic-audit-<UTC timestamp> and append a numeric suffix until both directory and archive names are unused.",
  archivePairing: "Create <allocated-directory>.zip beside the New Relic audit directory with the same suffix.",
});
