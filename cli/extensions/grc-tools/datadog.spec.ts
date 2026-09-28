import { DATADOG_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import {
  batch4FrameworkFiles,
  batch4Surface,
  buildBatch4Spec,
  type Batch4Control,
} from "./batch4-spec-helpers.js";
import { DATADOG_CONTROL_CATALOG } from "./datadog.js";
import type { FindingSeverity, FrameworkKey } from "./spec-model.js";

const DOCS = "https://docs.datadoghq.com/api/latest/";
const surfaces = [
  batch4Surface("organization-and-identity", "GET", "/api/v1/org; /api/v2/users; /api/v2/roles", "Datadog REST API", DOCS, ["settings", "users", "roles", "permissions", "created_at", "disabled"]),
  batch4Surface("keys-and-boundaries", "GET", "/api/v2/api_keys; /api/v2/application_keys; /api/v1/ip_allowlist", "Datadog REST API", DOCS, ["id", "name", "created_at", "date_last_used", "scopes", "enabled"]),
  batch4Surface("security-monitoring", "GET", "/api/v2/security_monitoring/rules; /api/v2/security_monitoring/signals; /api/v2/posture_management/findings; /api/v1/monitor", "Datadog REST API", DOCS, ["id", "name", "enabled", "status", "severity", "notification_targets", "total"]),
  batch4Surface("data-protection", "GET", "/api/v2/audit/events; /api/v1/logs/config/pipelines; /api/v1/logs/config/indexes; /api/v2/sensitive-data-scanner/config", "Datadog REST API", DOCS, ["data", "attributes", "filter", "retention_days", "is_enabled", "relationships"]),
] as const;

const owners: Readonly<Record<number, string>> = Object.fromEntries([
  ...[1, 2, 3, 4, 16, 19].map((number) => [number, "datadog_assess_identity"]),
  ...[5, 6, 14, 15, 18].map((number) => [number, "datadog_assess_access_controls"]),
  ...[7, 8, 9, 17].map((number) => [number, "datadog_assess_security_monitoring"]),
  ...[10, 11, 12, 13, 20].map((number) => [number, "datadog_assess_data_protection"]),
]);
const sourceFor = (number: number): string => (
  [1, 2, 3, 4, 16, 19].includes(number) ? "organization-and-identity"
    : [5, 6, 14, 15, 18].includes(number) ? "keys-and-boundaries"
      : [7, 8, 9, 17].includes(number) ? "security-monitoring"
        : "data-protection"
);
const severities: readonly FindingSeverity[] = [
  "critical", "critical", "high", "medium", "high", "high", "high", "high", "high", "medium",
  "high", "high", "medium", "medium", "high", "medium", "medium", "medium", "medium", "medium",
];
const controls: Batch4Control[] = Object.entries(DATADOG_CONTROL_CATALOG).map(([numberText, definition]) => {
  const number = Number(numberText);
  return {
    id: `DD-${String(number).padStart(2, "0")}`,
    control: number,
    title: definition.title,
    severity: severities[number - 1],
    owner: owners[number],
    surfaces: [sourceFor(number)],
    predicate: `Count complete-population Datadog records that violate ${definition.title}; retain unknown or absent required fields as review records rather than compliant values.`,
    frameworks: definition.frameworks as Partial<Record<FrameworkKey, readonly string[]>>,
    emptyOutcome: [5, 6, 9, 14, 17, 18, 19].includes(number) ? "pass" : "manual",
  };
});

const outputFiles = [
  "README.md", "QUICK_REFERENCE.md", "metadata.json",
  "core_data/access.json", "core_data/collection_status.json", "core_data/organization.json",
  "core_data/users.json", "core_data/roles.json", "core_data/org_configs.json",
  "core_data/api_keys.json", "core_data/application_keys.json", "core_data/shared_dashboards.json",
  "core_data/ip_allowlist.json", "core_data/cloud_integrations.json", "core_data/security_rules.json",
  "core_data/security_signals.json", "core_data/posture_findings.json", "core_data/monitors.json",
  "core_data/audit_events.json", "core_data/log_pipelines.json", "core_data/log_indexes.json",
  "core_data/log_archives.json", "core_data/sensitive_data_scanner.json", "core_data/org_connections.json",
  "analysis/findings.json", "analysis/identity.json", "analysis/access_controls.json",
  "analysis/security_monitoring.json", "analysis/data_protection.json", "analysis/summary.json",
  "compliance/executive_summary.md", "compliance/unified_compliance_matrix.md",
  ...batch4FrameworkFiles({
    "compliance/fedramp/fedramp_compliance_report.md": "compliance/frameworks/fedramp.md",
    "compliance/cmmc/cmmc_compliance_report.md": "compliance/frameworks/cmmc.md",
    "compliance/soc2/soc2_compliance_report.md": "compliance/frameworks/soc2.md",
    "compliance/cis/cis_compliance_report.md": "compliance/frameworks/cis.md",
    "compliance/pci_dss/pci_dss_compliance_report.md": "compliance/frameworks/pci-dss.md",
    "compliance/disa_stig/disa_stig_compliance_report.md": "compliance/frameworks/disa-stig.md",
    "compliance/irap/irap_compliance_report.md": "compliance/frameworks/irap.md",
    "compliance/ismap/ismap_compliance_report.md": "compliance/frameworks/ismap.md",
  }),
] as const;

export const DATADOG_RUNTIME_BEHAVIOR = [
  "Assessment counts come from complete Datadog inventories before the 25-record evidence samples are rendered; unreadable counts are null.",
  "A discovered violation remains non-passing on a partial companion read, while every absence-based pass requires every named source inventory to prove exhaustion.",
  "The resolver accepts documented Datadog site aliases and derives https://api.<site> unless an explicit same-origin API base URL is supplied.",
] as const;

export const DATADOG_SPEC = buildBatch4Spec({
  slug: "datadog-sec-inspector",
  displayName: "Datadog Security Inspector",
  vendor: "Datadog",
  category: "observability",
  summary: "Portable contract for Datadog identity, key, boundary, security-monitoring, and data-protection assessments.",
  sourceModule: "cli/extensions/grc-tools/datadog.ts",
  baseServices: ["Datadog REST API v1 and v2"],
  authentication: DATADOG_AUTH_RESOLVER,
  surfaces,
  controls,
  tools: {
    datadog_check_access: [],
    datadog_assess_identity: controls.filter((item) => item.owner === "datadog_assess_identity").map((item) => item.id),
    datadog_assess_access_controls: controls.filter((item) => item.owner === "datadog_assess_access_controls").map((item) => item.id),
    datadog_assess_security_monitoring: controls.filter((item) => item.owner === "datadog_assess_security_monitoring").map((item) => item.id),
    datadog_assess_data_protection: controls.filter((item) => item.owner === "datadog_assess_data_protection").map((item) => item.id),
    datadog_export_audit_bundle: controls.map((item) => item.id),
  },
  pagination: [{
    surfaceIds: surfaces.map((surface) => surface.id),
    cursorFields: ["meta.page.after", "links.next", "page[offset]", "page[limit]", "meta.page.total_count"],
    pageSize: 100,
    itemCap: 10000,
    pageCap: null,
    totalSemantics: "A listing is complete only after the endpoint proves no next cursor or offset and every reported total has been reached.",
    stopConditions: ["Proven exhaustion", "Configured item cap", "Repeated cursor", "Empty page with a next cursor", "Reported total mismatch"],
  }],
  documentedRateLimit: "Datadog publishes endpoint-specific limits through response headers rather than one tenant-wide request budget.",
  retryHeaders: ["Retry-After", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"],
  runtimeBehavior: DATADOG_RUNTIME_BEHAVIOR,
  knownGaps: ["Session timeout and integration-permission controls retain manual evidence where the public API exposes no decisive read field."],
  sensitiveFields: ["api_key", "application_key", "authorization", "email", "handle", "url", "webhook", "token"],
  credentialFormats: ["Datadog API keys", "Datadog application keys", "bearer headers", "webhook targets"],
  outputFiles,
  overwritePolicy: "Allocate <site>-audit-bundle and append a numeric suffix until neither the directory nor paired archive exists.",
  archivePairing: "Create <allocated-directory>.zip beside the Datadog evidence directory with the identical suffix.",
});
