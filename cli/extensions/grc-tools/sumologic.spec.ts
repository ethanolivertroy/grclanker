import { SUMOLOGIC_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import {
  batch4FrameworkFiles,
  batch4Surface,
  buildBatch4Spec,
  type Batch4Control,
} from "./batch4-spec-helpers.js";
import { SUMOLOGIC_CONTROLS } from "./sumologic.js";
import type { FindingSeverity, FrameworkKey } from "./spec-model.js";

const DOCS = "https://api.sumologic.com/docs/";
const surfaces = [
  batch4Surface("identity", "GET", "/v1/saml/identityProviders; /v1/users; /v1/passwordPolicy", "Sumo Logic Management API", DOCS, ["id", "enabled", "requireMfa", "allowlistedUsers", "roles", "status", "minLength", "maxPasswordAgeInDays"]),
  batch4Surface("access-control", "GET", "/v1/roles; /v1/accessKeys; /v1/serviceAllowlist/status; organization policies", "Sumo Logic Management API", DOCS, ["id", "capabilities", "users", "createdAt", "lastUsed", "loginEnabled", "contentEnabled", "maxUserSessionTimeout"]),
  batch4Surface("data-governance", "GET", "/v1/account/status; /v1/collectors; /v1/budgets; /v1/partitions; organization audit and forwarding settings", "Sumo Logic Management API", DOCS, ["planType", "enabled", "lastSeenAlive", "capacityBytes", "retentionPeriod", "destination", "audit"]),
  batch4Surface("content-sharing", "GET", "/v2/content/folders; /v2/content/{id}/permissions; /v1/scheduledViews; /v1/monitors", "Sumo Logic Content and Monitor APIs", DOCS, ["id", "itemType", "children", "explicitPermissions", "implicitPermissions", "schedule", "notifications"]),
] as const;

const groupControls: Readonly<Record<string, readonly number[]>> = {
  sumologic_assess_identity: [1, 2, 3, 4, 5],
  sumologic_assess_access_control: [6, 7, 8, 13, 14],
  sumologic_assess_data_governance: [9, 10, 12, 16, 17, 20],
  sumologic_assess_content_sharing: [11, 15, 18, 19],
};
const sourceForOwner: Readonly<Record<string, string>> = {
  sumologic_assess_identity: "identity",
  sumologic_assess_access_control: "access-control",
  sumologic_assess_data_governance: "data-governance",
  sumologic_assess_content_sharing: "content-sharing",
};
const severityFor = (number: number): FindingSeverity => (
  [1, 5, 7, 9].includes(number) ? "high"
    : [12, 14, 18, 19].includes(number) ? "low"
      : "medium"
);
const frameworkLabels: readonly [string, FrameworkKey][] = [
  ["FedRAMP", "fedramp"], ["CMMC", "cmmc"], ["SOC 2", "soc2"], ["CIS", "cis"],
  ["PCI-DSS", "pci_dss"], ["STIG", "disa_stig"], ["IRAP", "irap"], ["ISMAP", "ismap"],
];
const controls: Batch4Control[] = SUMOLOGIC_CONTROLS.map((definition) => {
  const owner = Object.entries(groupControls).find(([, numbers]) => numbers.includes(definition.number))?.[0];
  if (!owner) throw new Error(`No Sumo Logic tool owner for control ${definition.number}`);
  return {
    id: definition.id,
    control: definition.number,
    title: definition.title,
    severity: severityFor(definition.number),
    owner,
    surfaces: [sourceForOwner[owner]],
    predicate: `Count complete-population Sumo Logic records that violate ${definition.title}; personal-scope fallback results remain explicitly scoped and cannot establish organization-wide compliance.`,
    frameworks: Object.fromEntries(frameworkLabels.map(([label, key]) => [
      key,
      [definition.mappings[label as keyof typeof definition.mappings]],
    ])),
    emptyOutcome: [2, 7, 8, 10, 11, 15, 18, 19].includes(definition.number) ? "pass" : "manual",
  };
});

export const SUMOLOGIC_RUNTIME_BEHAVIOR = [
  "Organization-scoped and personal-scoped responses are never interchangeable; every collection records its exact scope and a personal fallback cannot prove an organization-wide pass.",
  "Cursor and offset walkers mark every cap, repeated cursor, missing total, rejected continuation, and failed child permission read as incomplete.",
  "The content permission sweep keeps folder witnesses and exact failed child IDs so aggregate completeness reflects mixed success, all-failed, and zero-attempt cases separately.",
] as const;

export const SUMOLOGIC_SPEC = buildBatch4Spec({
  slug: "sumologic-sec-inspector",
  displayName: "Sumo Logic Security Inspector",
  vendor: "Sumo Logic",
  category: "observability",
  summary: "Portable contract for Sumo Logic identity, key, collector, ingest, retention, monitor, and content-sharing assessments.",
  sourceModule: "cli/extensions/grc-tools/sumologic.ts",
  baseServices: ["Sumo Logic Management API", "Sumo Logic Content API", "Sumo Logic Monitor API"],
  authentication: SUMOLOGIC_AUTH_RESOLVER,
  surfaces,
  controls,
  tools: {
    sumologic_check_access: [],
    ...Object.fromEntries(Object.keys(groupControls).map((owner) => [owner, controls.filter((item) => item.owner === owner).map((item) => item.id)])),
    sumologic_export_audit_bundle: controls.map((item) => item.id),
  },
  pagination: [{
    surfaceIds: surfaces.map((surface) => surface.id),
    cursorFields: ["token", "next", "offset", "limit", "total"],
    pageSize: 100,
    itemCap: 10000,
    pageCap: 100,
    totalSemantics: "Cursor APIs require a terminal response without a token; offset APIs require a short page and reconciliation with any total.",
    stopConditions: ["No cursor", "Short offset page", "Reported total reached", "Item cap", "Page cap", "Repeated cursor", "Failed folder permission child read"],
  }],
  documentedRateLimit: "Sumo Logic documents API-specific throttles and returns 429 with rate headers; no single cross-product limit is assumed.",
  retryHeaders: ["Retry-After", "X-Rate-Limit-Remaining", "X-Rate-Limit-Reset"],
  runtimeBehavior: SUMOLOGIC_RUNTIME_BEHAVIOR,
  knownGaps: ["Three controls remain manual because the public API exposes no decisive read endpoint."],
  sensitiveFields: ["accessId", "accessKey", "authorization", "email", "url", "token", "headers"],
  credentialFormats: ["Sumo Logic access IDs", "Sumo Logic access keys", "Basic authorization headers", "webhook URLs"],
  outputFiles: [
    "README.md", "QUICK_REFERENCE.md", "metadata.json", "core_data/access_check.json",
    "analysis/findings.json", "analysis/identity.json", "analysis/access_control.json",
    "analysis/data_governance.json", "analysis/content_sharing.json",
    "compliance/executive_summary.md", "compliance/unified_compliance_matrix.md",
    ...batch4FrameworkFiles({
      "compliance/fedramp/fedramp_compliance_report.md": "compliance/fedramp.md",
      "compliance/cmmc/cmmc_compliance_report.md": "compliance/cmmc.md",
      "compliance/soc2/soc2_compliance_report.md": "compliance/soc-2.md",
      "compliance/cis/cis_compliance_report.md": "compliance/cis.md",
      "compliance/pci_dss/pci_dss_compliance_report.md": "compliance/pci-dss.md",
      "compliance/disa_stig/disa_stig_compliance_report.md": "compliance/stig.md",
      "compliance/irap/irap_compliance_report.md": "compliance/irap.md",
      "compliance/ismap/ismap_compliance_report.md": "compliance/ismap.md",
    }),
  ],
  overwritePolicy: "Allocate sumologic-audit-<UTC timestamp> and append a numeric suffix while either paired path exists.",
  archivePairing: "Create <allocated-directory>.zip beside the Sumo Logic audit directory with the same suffix.",
});
