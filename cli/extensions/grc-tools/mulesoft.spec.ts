import { MULESOFT_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import {
  batch4FrameworkFiles,
  batch4Surface,
  buildBatch4Spec,
  type Batch4Control,
} from "./batch4-spec-helpers.js";
import { getMulesoftControlCatalog } from "./mulesoft.js";

const DOCS = "https://docs.mulesoft.com/access-management/api-reference";
const surfaces = [
  batch4Surface("identity-access", "GET", "/accounts/api/organizations/{org}; /accounts/api/organizations/{org}/users; /accounts/api/organizations/{org}/rolegroups; /accounts/api/connectedApplications", "Anypoint Access Management API", DOCS, ["id", "name", "provider", "mfa", "roles", "permissions", "environmentId", "scopes", "lastUsed"]),
  batch4Surface("api-gateway", "GET", "/apimanager/api/v1/organizations/{org}/environments/{env}/apis; policies; /exchange/api/v2/assets", "Anypoint API Manager and Exchange APIs", "https://docs.mulesoft.com/api-manager/latest/api-manager-api", ["id", "assetId", "environmentId", "policyTemplateId", "enabled", "status", "version", "tags"]),
  batch4Surface("runtime-infrastructure", "GET", "/cloudhub/api/v2/applications; /cloudhub/api/organizations/{org}/vpcs; dedicatedLoadBalancers; hybrid/api/v1/servers; mq/admin/api/v1", "CloudHub, Runtime Manager, Hybrid, and MQ APIs", "https://docs.mulesoft.com/runtime-manager/api-reference", ["id", "environmentId", "muleVersion", "workers", "persistentQueues", "firewallRules", "tlsVersion", "certificateExpiration", "status"]),
  batch4Surface("audit-monitoring", "GET", "/audit/v2/organizations/{org}/query; /armui/api/v1/alerts; secrets-manager/api/v1", "Anypoint Audit, Alert, and Secrets APIs", DOCS, ["timestamp", "objectType", "action", "environmentId", "applicationId", "enabled", "secretGroup"]),
] as const;

const groups: Readonly<Record<string, readonly number[]>> = {
  mulesoft_assess_identity_access: [1, 2, 3, 4, 5, 6, 18, 19, 25],
  mulesoft_assess_api_gateway: [7, 8, 9, 20],
  mulesoft_assess_runtime_infrastructure: [10, 11, 12, 13, 14, 15, 16, 21, 22, 23],
  mulesoft_assess_audit_monitoring: [17, 24],
};
const sourceByOwner: Readonly<Record<string, string>> = {
  mulesoft_assess_identity_access: "identity-access",
  mulesoft_assess_api_gateway: "api-gateway",
  mulesoft_assess_runtime_infrastructure: "runtime-infrastructure",
  mulesoft_assess_audit_monitoring: "audit-monitoring",
};
const controls: Batch4Control[] = getMulesoftControlCatalog().map((definition) => {
  const owner = Object.entries(groups).find(([, numbers]) => numbers.includes(definition.number))?.[0];
  if (!owner) throw new Error(`No MuleSoft tool owner for control ${definition.number}`);
  return {
    id: definition.id,
    control: definition.number,
    title: definition.title,
    severity: definition.severity,
    owner,
    surfaces: [sourceByOwner[owner]],
    predicate: `Count complete-population Anypoint resources that violate ${definition.title}, preserving environment identifiers and product-specific collection state across every child request.`,
    frameworks: {
      fedramp: [definition.mappings.fedramp],
      cmmc: [definition.mappings.cmmc],
      soc2: [definition.mappings.soc2],
      cis: [definition.mappings.cis],
      pci_dss: [definition.mappings.pci_dss],
      disa_stig: [definition.mappings.disa_stig],
      irap: [definition.mappings.irap],
      ismap: [definition.mappings.ismap],
    },
    emptyOutcome: [8, 9, 13, 14, 16, 18, 19, 20, 21, 22, 23, 24].includes(definition.number) ? "pass" : "manual",
  };
});

export const MULESOFT_RUNTIME_BEHAVIOR = [
  "Organization and environment identifiers are carried into every product-specific request; a dataset from one environment never satisfies another environment's check.",
  "CloudHub, Runtime Manager, Hybrid, Exchange, MQ, Secrets Manager, and audit pagination retain independent seen, total, continuation, and error states.",
  "Dedicated-load-balancer certificate evidence combines API fields with a bounded live TLS handshake only when the API omits certificate dates.",
] as const;

export const MULESOFT_SPEC = buildBatch4Spec({
  slug: "mulesoft-sec-inspector",
  displayName: "MuleSoft Security Inspector",
  vendor: "MuleSoft",
  category: "developer-platform",
  summary: "Portable contract for Anypoint identity, API governance, runtime infrastructure, and audit-monitoring assessments.",
  sourceModule: "cli/extensions/grc-tools/mulesoft.ts",
  baseServices: ["Anypoint Access Management", "API Manager", "Exchange", "CloudHub", "Runtime Manager", "Anypoint MQ", "Audit Log"],
  authentication: MULESOFT_AUTH_RESOLVER,
  surfaces,
  controls,
  tools: {
    mulesoft_check_access: [],
    ...Object.fromEntries(Object.keys(groups).map((owner) => [owner, controls.filter((item) => item.owner === owner).map((item) => item.id)])),
    mulesoft_export_audit_bundle: controls.map((item) => item.id),
  },
  pagination: [{
    surfaceIds: surfaces.map((surface) => surface.id),
    cursorFields: ["offset", "limit", "total", "next", "page", "pageSize"],
    pageSize: 100,
    itemCap: 10000,
    pageCap: 100,
    totalSemantics: "Each product paginator must prove exhaustion under its documented offset, page, or next-link contract and reconcile any server total.",
    stopConditions: ["Reported total reached", "Short or empty final page", "No next link", "Item cap", "Page cap", "Repeated continuation", "Failed environment child read"],
  }],
  documentedRateLimit: "Anypoint products enforce service-specific limits; 429 and Retry-After are handled per originating service.",
  retryHeaders: ["Retry-After", "X-RateLimit-Remaining", "X-RateLimit-Reset"],
  runtimeBehavior: MULESOFT_RUNTIME_BEHAVIOR,
  knownGaps: ["Monitoring alerts, CloudHub 2.0 private spaces, Runtime Fabric, and governance-result surfaces remain manual or unavailable."],
  sensitiveFields: ["access_token", "client_secret", "password", "authorization", "cookie", "email", "url", "properties", "secureProperties"],
  credentialFormats: ["Anypoint bearer tokens", "OAuth client secrets", "username/password credentials", "application secure properties"],
  outputFiles: [
    "README.md", "QUICK_REFERENCE.md", "metadata.json", "core_data/access_check.json",
    "analysis/findings.json", "analysis/identity_access.json", "analysis/api_gateway.json",
    "analysis/runtime_infrastructure.json", "analysis/audit_monitoring.json",
    "compliance/executive_summary.md", "compliance/unified_compliance_matrix.md",
    ...batch4FrameworkFiles(),
  ],
  overwritePolicy: "Allocate mulesoft-audit-<UTC timestamp> and append a numeric suffix while either the directory or paired archive exists.",
  archivePairing: "Create <allocated-directory>.zip beside the MuleSoft audit directory with the same suffix.",
});
