import { ELASTIC_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import {
  batch4FrameworkFiles,
  batch4FrameworksFromMappings,
  batch4Surface,
  buildBatch4Spec,
  type Batch4Control,
} from "./batch4-spec-helpers.js";
import { ELASTIC_CONTROLS } from "./elastic.js";

const DOCS = "https://www.elastic.co/guide/en/elasticsearch/reference/current/rest-apis.html";
const surfaces = [
  batch4Surface("identity", "GET", "/_security/_authenticate; /_security/user; /_security/role_mapping; /_security/api_key", "Elasticsearch Security APIs", DOCS, ["username", "roles", "enabled", "realm", "metadata", "creation", "expiration"]),
  batch4Surface("access-control", "GET", "/_security/role; /_security/user/_privileges; /_security/privilege/_builtin", "Elasticsearch Security APIs", DOCS, ["cluster", "indices", "applications", "field_security", "query", "run_as"]),
  batch4Surface("transport-security", "GET", "/_cluster/settings; /_nodes/settings; /_ssl/certificates", "Elasticsearch Cluster APIs", DOCS, ["xpack.security.transport.ssl", "xpack.security.http.ssl", "supported_protocols", "expiry", "subject_dn"]),
  batch4Surface("cluster-hardening", "GET", "/_license; /_xpack/usage; /_ilm/policy; /_slm/policy; /_snapshot; /_watcher/watch; /_ingest/pipeline", "Elasticsearch Cluster APIs", DOCS, ["type", "status", "features", "policy", "repository", "encrypted", "actions", "processors"]),
  batch4Surface("kibana", "GET", "/api/status; /s/{space}/api/spaces/space; /s/{space}/api/security/role; /s/{space}/api/fleet/agent_policies", "Kibana APIs", "https://www.elastic.co/docs/api/doc/kibana/", ["version", "status", "id", "disabledFeatures", "elasticsearch", "feature", "is_managed", "namespace"]),
] as const;

const controls: Batch4Control[] = ELASTIC_CONTROLS.map((definition) => ({
  id: definition.id,
  control: definition.number,
  title: definition.title,
  severity: ["TLS enforcement on the transport layer", "TLS enforcement on the HTTP layer", "Anonymous access disabled"].includes(definition.title) ? "critical" : "high",
  owner: `elastic_assess_${definition.area}`,
  surfaces: [definition.area.replaceAll("_", "-")],
  predicate: `Count complete-population Elastic records that violate ${definition.title}; precedence-aware cluster settings are resolved before counting, and an absent or malformed required field is a review record.`,
  frameworks: batch4FrameworksFromMappings(definition.mappings),
  emptyOutcome: [7, 8, 9, 10, 15, 16, 17, 18, 20, 21, 22].includes(definition.number) ? "manual" : "fail",
}));

const datasetFiles = [
  "authenticate", "privileges", "license", "xpack_info", "xpack_usage", "cluster_settings",
  "node_settings", "ssl_certificates", "users", "roles", "role_mappings", "api_keys",
  "ilm_status", "ilm_policies", "slm_status", "slm_policies", "snapshot_repositories",
  "watches", "ingest_pipelines", "kibana_status", "spaces", "kibana_roles",
  "fleet_agent_policies", "fleet_outputs", "fleet_server_hosts", "fleet_enrollment_api_keys",
].map((name) => `core_data/${name}.json`);

export const ELASTIC_RUNTIME_BEHAVIOR = [
  "The collector resolves persistent settings before transient settings and transient settings before defaults, then projects only fields used by the 23 checks.",
  "Every paged users, roles, API-key, policy, watch, pipeline, space, and Fleet read carries seen, total, page count, truncation, and the exact terminal condition.",
  "Kibana reads are explicitly not configured when no Kibana origin exists; dependent checks remain manual and unrelated Elasticsearch checks retain their evidence-based verdicts.",
] as const;

export const ELASTIC_SPEC = buildBatch4Spec({
  slug: "elastic-sec-inspector",
  displayName: "Elastic Security Inspector",
  vendor: "Elastic",
  category: "observability",
  summary: "Portable contract for Elasticsearch identity, authorization, TLS, lifecycle, snapshot, Watcher, ingest, Kibana, and Fleet assessments.",
  sourceModule: "cli/extensions/grc-tools/elastic.ts",
  baseServices: ["Elasticsearch REST API", "Kibana REST API", "Elastic Cloud API"],
  authentication: ELASTIC_AUTH_RESOLVER,
  surfaces,
  controls,
  tools: {
    elastic_check_access: [],
    elastic_assess_identity: controls.filter((item) => item.owner === "elastic_assess_identity").map((item) => item.id),
    elastic_assess_access_control: controls.filter((item) => item.owner === "elastic_assess_access_control").map((item) => item.id),
    elastic_assess_transport_security: controls.filter((item) => item.owner === "elastic_assess_transport_security").map((item) => item.id),
    elastic_assess_cluster_hardening: controls.filter((item) => item.owner === "elastic_assess_cluster_hardening").map((item) => item.id),
    elastic_assess_kibana: controls.filter((item) => item.owner === "elastic_assess_kibana").map((item) => item.id),
    elastic_export_audit_bundle: controls.map((item) => item.id),
  },
  pagination: [{
    surfaceIds: surfaces.map((surface) => surface.id),
    cursorFields: ["from", "size", "page", "per_page", "next", "total"],
    pageSize: 100,
    itemCap: 10000,
    pageCap: 100,
    totalSemantics: "Each query-specific paginator must prove exhaustion and must reconcile any server total with the number of projected records.",
    stopConditions: ["Short or empty final page", "Reported total reached", "Item cap", "Page cap", "Repeated cursor", "Malformed page"],
  }],
  documentedRateLimit: "Elastic publishes deployment-specific resource limits; no universal Elasticsearch or Kibana request-per-minute value is assumed.",
  retryHeaders: ["Retry-After", "X-Elastic-Product"],
  runtimeBehavior: ELASTIC_RUNTIME_BEHAVIOR,
  knownGaps: ["Client certificates, custom certificate authorities, and transport skip-verify are not accepted authentication modes."],
  sensitiveFields: ["api_key", "password", "authorization", "bearer_token", "cloud_api_key", "email", "metadata", "url"],
  credentialFormats: ["Elasticsearch ApiKey headers", "Basic credentials", "bearer tokens", "Elastic Cloud API keys"],
  outputFiles: [
    "QUICK_REFERENCE.md", "metadata.json", "collection_status.json", ...datasetFiles,
    "analysis/access.json", "analysis/findings.json", "analysis/identity.json", "analysis/access_control.json",
    "analysis/transport_security.json", "analysis/cluster_hardening.json", "analysis/kibana.json",
    "compliance/executive_summary.md", "compliance/unified_compliance_matrix.md",
    ...batch4FrameworkFiles({
      "compliance/fedramp/fedramp_compliance_report.md": "compliance/frameworks/fedramp.md",
      "compliance/cmmc/cmmc_compliance_report.md": "compliance/frameworks/cmmc.md",
      "compliance/soc2/soc2_compliance_report.md": "compliance/frameworks/soc2.md",
      "compliance/cis/cis_compliance_report.md": "compliance/frameworks/cis.md",
      "compliance/pci_dss/pci_dss_compliance_report.md": "compliance/frameworks/pci_dss.md",
      "compliance/disa_stig/disa_stig_compliance_report.md": "compliance/frameworks/disa_stig.md",
      "compliance/irap/irap_compliance_report.md": "compliance/frameworks/irap.md",
      "compliance/ismap/ismap_compliance_report.md": "compliance/frameworks/ismap.md",
    }),
  ],
  overwritePolicy: "Allocate <cluster-host>-audit-bundle and append a numeric suffix until the directory and paired archive are both unused.",
  archivePairing: "Create <allocated-directory>.zip beside the Elastic audit directory and refuse to overwrite an existing archive.",
});
