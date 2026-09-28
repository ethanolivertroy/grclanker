import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
} from "./batch-spec-builder.js";
import {
  batch2Checks,
  restSurface,
  type Batch2CheckRow,
} from "./batch2-spec-helpers.js";
import { OCI_AUTH_RESOLVER } from "./auth-resolver-contracts.js";

const OCI_DOCS = "https://docs.oracle.com/en-us/iaas/api/";
const surfaces = [
  restSurface("identity", "oci iam {authentication-policy|user|compartment|policy|credential} read commands", "OCI CLI Identity", OCI_DOCS, ["lifecycleState", "isMfaActivated", "capabilities.canUseConsolePassword", "passwordPolicy", "timeCreated", "statements"]),
  restSurface("cloud-guard", "oci cloud-guard {configuration|target|problem|responder-recipe} read commands", "OCI CLI Cloud Guard", OCI_DOCS, ["status", "reportingRegion", "lifecycleState", "riskLevel", "responderRules.details.isEnabled"]),
  restSurface("audit-events", "oci audit {config get|event list}", "OCI CLI Audit", OCI_DOCS, ["retentionPeriodDays", "eventId", "eventTime"]),
  restSurface("event-rules", "oci events rule list", "OCI CLI Events", OCI_DOCS, ["displayName", "condition", "isEnabled", "lifecycleState"]),
  restSurface("networking", "oci network {security-list|nsg|internet-gateway} read commands", "OCI CLI Networking", OCI_DOCS, ["ingressSecurityRules", "direction", "source", "protocol", "tcpOptions", "isEnabled", "lifecycleState"]),
  restSurface("bastion", "oci bastion {bastion|session} read commands", "OCI CLI Bastion", OCI_DOCS, ["maxSessionTtlInSeconds", "clientCidrBlockAllowList", "sessionTtlInSeconds", "lifecycleState"]),
  restSurface("vault", "oci kms management {vault|key|key-version} read commands", "OCI CLI Vault", OCI_DOCS, ["algorithm", "protectionMode", "keyShape", "timeCreated", "lifecycleState"]),
  restSurface("object-storage", "oci os {bucket|preauth-request} read commands", "OCI CLI Object Storage", OCI_DOCS, ["publicAccessType", "kmsKeyId", "timeExpires", "accessType"]),
  restSurface("compute", "oci compute {instance|volume|boot-volume} read commands", "OCI CLI Compute", OCI_DOCS, ["instanceOptions.areLegacyImdsEndpointsDisabled", "kmsKeyId", "availabilityDomain", "lifecycleState"]),
] as const;

type Row = readonly [string, number, string, Batch2CheckRow["severity"], readonly string[], boolean?];
const rows: readonly Row[] = [
  ["OCI-IAM-01", 1, "IAM password policy length and complexity", "high", ["identity"]],
  ["OCI-IAM-02", 2, "Console MFA enforcement", "high", ["identity"]],
  ["OCI-IAM-03", 3, "API key, customer secret key, and auth token rotation", "high", ["identity"]],
  ["OCI-IAM-04", 4, "Broad IAM policies", "high", ["identity"]],
  ["OCI-IAM-05", 5, "Compartment hierarchy depth", "medium", ["identity"]],
  ["OCI-IAM-06", 6, "IAM password expiration (manual)", "medium", [], true],
  ["OCI-LOG-01", 7, "Cloud Guard enabled and active targets", "high", ["cloud-guard"]],
  ["OCI-LOG-02", 8, "Open Cloud Guard problems", "high", ["cloud-guard"]],
  ["OCI-LOG-03", 9, "Responder recipe activation", "medium", ["cloud-guard"]],
  ["OCI-LOG-04", 10, "Audit event visibility", "medium", ["audit-events"]],
  ["OCI-LOG-05", 11, "Event rules for critical operations", "medium", ["event-rules"]],
  ["OCI-LOG-06", 12, "Audit log retention", "high", ["audit-events"]],
  ["OCI-GRD-01", 13, "Security list ingress exposure", "critical", ["networking"]],
  ["OCI-GRD-02", 14, "Network security group ingress exposure", "critical", ["networking"]],
  ["OCI-GRD-03", 15, "Internet gateway exposure", "medium", ["networking"]],
  ["OCI-GRD-04", 16, "Bastion controls", "medium", ["bastion"]],
  ["OCI-GRD-05", 17, "Vault key rotation and algorithm", "high", ["vault"]],
  ["OCI-GRD-06", 18, "Object storage public access and pre-authenticated requests", "high", ["object-storage"]],
  ["OCI-CMP-01", 19, "IMDSv2-only instance metadata access", "high", ["compute"]],
  ["OCI-CMP-02", 20, "Block volume customer-managed encryption", "medium", ["compute"]],
  ["OCI-CMP-03", 21, "Boot volume customer-managed encryption", "medium", ["compute"]],
] as const;

function owner(id: string): string {
  if (id.startsWith("OCI-IAM-")) return "oci_assess_identity";
  if (id.startsWith("OCI-LOG-")) return "oci_assess_logging_detection";
  if (id.startsWith("OCI-GRD-")) return "oci_assess_tenancy_guardrails";
  return "oci_assess_compute_and_storage";
}

const checks = batch2Checks(rows.map(([id, control, title, severity, sourceSurfaces, manualOnly]) => ({
  id,
  control,
  title,
  severity,
  owner: owner(id),
  surfaces: sourceSurfaces,
  manualOnly,
  emptyOutcome: "manual",
  frameworks: {
    fedramp: [id.startsWith("OCI-IAM") ? "AC-6 / IA-2 / IA-5" : id.startsWith("OCI-LOG") ? "AU-2 / SI-4" : "SC-7 / SC-28"],
  },
  decision: manualOnly
    ? "Always return manual because the shipped OCI read surfaces do not expose the password-expiration setting."
    : `Use complete OCI CLI result cardinalities for ${title}; a proved violating record takes precedence over partial collection, review records or incomplete scope warn, empty or unreadable required inventories remain manual, and pass requires complete readable evidence with no violation.`,
})));
const idsFor = (tool: string): string[] => checks.filter((check) => check.owner === tool).map((check) => check.id);

export const OCI_RUNTIME_BEHAVIOR = [
  "The runtime invokes documented read-only OCI CLI commands and records command failures as unreadable evidence rather than empty arrays.",
  "Compartment, credential, policy, bucket, key, and resource caps mark dependent checks partial; displayed records are capped independently from verdict counts.",
  "Password expiration remains manual because the classic IAM PasswordPolicy datatype does not expose that identity-domain setting.",
] as const;

export const OCI_SPEC = buildBatchIntegrationSpec({
  slug: "oci-sec-inspector",
  displayName: "OCI Security Inspector",
  vendor: "Oracle Cloud Infrastructure",
  category: "cloud",
  summary: "Portable contract for the shipped OCI identity, Cloud Guard, Audit, networking, Vault, Object Storage, and Compute assessments.",
  sourceModule: "cli/extensions/grc-tools/oci.ts",
  baseServices: ["OCI CLI Identity", "OCI CLI Audit", "OCI CLI Cloud Guard", "OCI CLI Networking", "OCI CLI Vault", "OCI CLI Object Storage", "OCI CLI Compute"],
  authentication: OCI_AUTH_RESOLVER,
  permissions: [
    { id: "oci-audit-policy", kind: "iam-action", value: "inspect/read the documented resources in the selected tenancy and compartments", unlocks: surfaces.map((surface) => surface.id) },
  ],
  surfaces,
  checks,
  tools: {
    oci_check_access: [],
    oci_assess_identity: idsFor("oci_assess_identity"),
    oci_assess_logging_detection: idsFor("oci_assess_logging_detection"),
    oci_assess_tenancy_guardrails: idsFor("oci_assess_tenancy_guardrails"),
    oci_assess_compute_and_storage: idsFor("oci_assess_compute_and_storage"),
    oci_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [{
    surfaceIds: surfaces,
    cursorFields: ["opc-next-page", "CLI --all"],
    pageSize: null,
    itemCap: null,
    pageCap: null,
    totalSemantics: "CLI --all must exhaust opc-next-page; configured compartment, credential, policy, key, and bucket caps are explicit partial states.",
    stopConditions: ["No opc-next-page", "Configured item cap", "Command failure", "Dependent parent inventory unreadable"],
  }],
  rateLimit: {
    documentedLimit: "Service and tenancy specific",
    retryHeaders: ["opc-request-id", "Retry-After"],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "The OCI CLI owns service retry behavior; an exhausted command remains unreadable and is not replayed as an empty result.",
  },
  runtimeBehavior: OCI_RUNTIME_BEHAVIOR,
  knownGaps: ["Identity-domain password expiration and controls without a decisive classic IAM field remain manual."],
  sensitiveFields: ["key_file", "pass_phrase", "security_token_file", "authorization", "cookie", "private_key"],
  credentialFormats: ["OCI API signing keys", "OCI security tokens", "OCI CLI profile pass phrases"],
  output: buildBatchOutputContract({
    files: [
      "README.md", "QUICK_REFERENCE.md", "metadata.json", "core_data/access.json", "core_data/compartments.json",
      "analysis/findings.json", "analysis/identity.json", "analysis/logging-detection.json",
      "analysis/tenancy-guardrails.json", "analysis/compute-storage.json", "analysis/summary.md",
      "compliance/executive_summary.md", "compliance/unified_compliance_matrix.md",
      "compliance/fedramp/fedramp_compliance_report.md", "compliance/cmmc/cmmc_compliance_report.md",
      "compliance/soc2/soc2_compliance_report.md", "compliance/cis_oci/cis_oci_benchmark_report.md",
      "compliance/pci_dss/pci_dss_compliance_report.md", "compliance/disa_stig/stig_compliance_checklist.md",
      "compliance/irap/irap_compliance_report.md", "compliance/ismap/ismap_compliance_report.md",
    ],
    conditionalFiles: ["_errors.log"],
    overwritePolicy: "Allocate a new OCI audit directory and numeric suffix without overwriting either an existing directory or its paired archive.",
    archivePairing: "Create <allocated-directory>.zip beside the allocated OCI audit directory.",
  }),
});
