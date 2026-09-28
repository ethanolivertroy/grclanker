import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
} from "./batch-spec-builder.js";
import {
  batch2All,
  batch2Any,
  batch2Checks,
  batch2Defined,
  batch2Eq,
  batch2Gt,
  batch2Ne,
  batch2Not,
  batch2Rule,
  restSurface,
  type Batch2CheckRow,
} from "./batch2-spec-helpers.js";
import { GCP_AUTH_RESOLVER } from "./auth-resolver-contracts.js";

const ASSET_DOCS = "https://cloud.google.com/asset-inventory/docs/reference/rest";
export const GCP_MAX_KMS_ROTATION_DAYS = 365;
export const GCP_MIN_LOG_RETENTION_DAYS = 90;
export const GCP_ADMIN_PORTS = [22, 3389] as const;
export const GCP_FLOW_LOG_UNSUPPORTED_PURPOSES = ["REGIONAL_MANAGED_PROXY", "GLOBAL_MANAGED_PROXY", "INTERNAL_HTTPS_LOAD_BALANCER", "PRIVATE_SERVICE_CONNECT", "PRIVATE_NAT"] as const;
export const GCP_HTTP_BACKEND_PROTOCOLS = ["HTTP", "HTTPS", "HTTP2", "H2C"] as const;
const surfaces = [
  restSurface("organization", "cloudresourcemanager.googleapis.com/v1/organizations/{organization}", "Cloud Resource Manager", "https://cloud.google.com/resource-manager/reference/rest/v1/organizations/get", ["name", "displayName", "state"]),
  restSurface("projects", "cloudasset.googleapis.com/v1/{scope}:searchAllResources", "Cloud Asset Inventory", ASSET_DOCS, ["name", "displayName", "state", "project"]),
  restSurface("iam-policies", "cloudasset.googleapis.com/v1/{scope}:searchAllIamPolicies", "Cloud Asset Inventory", ASSET_DOCS, ["resource", "policy.bindings.role", "policy.bindings.members"]),
  restSurface("service-accounts", "iam.googleapis.com/v1/projects/{project}/serviceAccounts", "IAM", "https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/list", ["name", "email", "disabled"]),
  restSurface("service-account-keys", "iam.googleapis.com/v1/projects/{project}/serviceAccounts/{account}/keys", "IAM", "https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys/list", ["name", "keyType", "validAfterTime", "validBeforeTime"]),
  restSurface("logging", "logging.googleapis.com/v2/{resource}", "Cloud Logging", "https://cloud.google.com/logging/docs/reference/v2/rest", ["name", "disabled", "destination", "retentionDays", "timestamp"]),
  restSurface("security-command-center", "securitycenter.googleapis.com/v1/organizations/{organization}/{resource}", "Security Command Center", "https://cloud.google.com/security-command-center/docs/reference/rest", ["name", "state", "category", "severity"]),
  restSurface("effective-org-policy", "cloudresourcemanager.googleapis.com/v1/projects/{project}:getEffectiveOrgPolicy", "Cloud Resource Manager", "https://cloud.google.com/resource-manager/reference/rest/v1/projects/getEffectiveOrgPolicy", ["constraint", "booleanPolicy.enforced", "listPolicy"]),
  restSurface("compute", "compute.googleapis.com/compute/v1/projects/{project}/{resource}", "Compute Engine", "https://cloud.google.com/compute/docs/reference/rest/v1", ["name", "metadata", "shieldedInstanceConfig", "networkInterfaces", "logConfig", "sslPolicy", "securityPolicy"]),
  restSurface("binary-authorization", "binaryauthorization.googleapis.com/v1/projects/{project}/policy", "Binary Authorization", "https://cloud.google.com/binary-authorization/docs/reference/rest/v1/projects/getPolicy", ["defaultAdmissionRule", "clusterAdmissionRules", "kubernetesNamespaceAdmissionRules", "serviceAccountAdmissionRules", "istioServiceIdentityAdmissionRules"]),
  restSurface("storage", "storage.googleapis.com/storage/v1/b?project={project}", "Cloud Storage", "https://cloud.google.com/storage/docs/json_api/v1/buckets/list", ["name", "iamConfiguration", "encryption"]),
  restSurface("kms", "cloudasset.googleapis.com/v1/{scope}/assets?assetTypes=cloudkms.googleapis.com/CryptoKey", "Cloud Asset Inventory", ASSET_DOCS, ["name", "resource.data.rotationPeriod", "resource.data.nextRotationTime"]),
  restSurface("dns", "dns.googleapis.com/dns/v1/projects/{project}/managedZones", "Cloud DNS", "https://cloud.google.com/dns/docs/reference/rest/v1/managedZones/list", ["name", "dnssecConfig.state"]),
  restSurface("api-keys", "apikeys.googleapis.com/v2/projects/{project}/locations/global/keys", "API Keys", "https://cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys/list", ["name", "restrictions"]),
  restSurface("access-context-manager", "accesscontextmanager.googleapis.com/v1/{resource}", "Access Context Manager", "https://cloud.google.com/access-context-manager/docs/reference/rest/v1", ["name", "parent", "status.resources", "spec.resources"]),
] as const;

type Row = readonly [
  string,
  number,
  string,
  Batch2CheckRow["severity"],
  readonly string[],
  Batch2CheckRow["emptyOutcome"],
  Batch2CheckRow["violationOutcome"]?,
];

const rows: readonly Row[] = [
  ["GCP-IAM-01", 2, "Privileged IAM bindings", "high", ["iam-policies"], "manual"],
  ["GCP-IAM-02", 1, "Service account key rotation", "high", ["projects", "service-accounts", "service-account-keys"], "pass"],
  ["GCP-IAM-03", 1, "User-managed service account key minimization", "medium", ["projects", "service-accounts", "service-account-keys"], "manual", "warn"],
  ["GCP-IAM-04", 14, "Cross-project service account access", "medium", ["iam-policies"], "manual", "warn"],
  ["GCP-IAM-05", 13, "Default service account privilege", "high", ["iam-policies"], "manual"],
  ["GCP-LOG-01", 5, "Admin Activity visibility", "medium", ["projects", "logging"], "manual", "warn"],
  ["GCP-LOG-02", 5, "Data Access logging coverage", "high", ["projects", "logging"], "manual"],
  ["GCP-LOG-03", 5, "Log sink coverage", "high", ["projects", "logging"], "manual"],
  ["GCP-LOG-04", 5, "Log bucket retention", "medium", ["projects", "logging"], "manual"],
  ["GCP-LOG-05", 5, "Security Command Center visibility", "info", ["organization", "security-command-center"], "warn", "warn"],
  ["GCP-ORG-01", 6, "Organization visibility", "medium", ["organization", "projects"], "warn", "warn"],
  ["GCP-ORG-02", 6, "Domain-restricted sharing", "high", ["effective-org-policy"], "manual", "warn"],
  ["GCP-ORG-03", 6, "Service account key creation restriction", "high", ["effective-org-policy"], "manual"],
  ["GCP-ORG-04", 6, "Service account key upload restriction", "high", ["effective-org-policy"], "manual", "warn"],
  ["GCP-ORG-05", 12, "Serial port and Shielded VM guardrails", "medium", ["effective-org-policy"], "manual"],
  ["GCP-ORG-06", 11, "OS Login enforcement", "high", ["effective-org-policy", "compute"], "manual"],
  ["GCP-ORG-07", 8, "Binary Authorization admission policy", "medium", ["projects", "binary-authorization"], "manual"],
  ["GCP-ORG-08", 12, "Shielded VM and serial port instance configuration", "medium", ["projects", "compute"], "manual"],
  ["GCP-DATA-01", 15, "Uniform bucket-level access", "high", ["projects", "storage"], "manual"],
  ["GCP-DATA-02", 3, "Public resource exposure", "critical", ["iam-policies"], "manual"],
  ["GCP-DATA-03", 7, "KMS key rotation", "medium", ["kms"], "manual"],
  ["GCP-DATA-04", 16, "Customer-managed encryption keys", "medium", ["projects", "storage", "compute"], "manual", "warn"],
  ["GCP-DATA-05", 17, "Cloud DNS DNSSEC", "medium", ["projects", "dns"], "manual"],
  ["GCP-DATA-06", 20, "API key restrictions", "high", ["projects", "api-keys"], "pass"],
  ["GCP-DATA-07", 21, "VPC Service Controls perimeters", "medium", ["organization", "access-context-manager"], "fail", "warn"],
  ["GCP-NET-01", 4, "Firewall rules open to the internet on administrative ports", "high", ["projects", "compute"], "manual"],
  ["GCP-NET-02", 9, "VPC flow logs", "medium", ["projects", "compute"], "manual"],
  ["GCP-NET-03", 22, "Private Google Access", "low", ["projects", "compute"], "manual", "warn"],
  ["GCP-NET-04", 10, "Cloud NAT coverage and external IP usage", "medium", ["projects", "compute"], "manual", "warn"],
  ["GCP-NET-05", 18, "Load balancer SSL policies", "high", ["projects", "compute"], "manual"],
  ["GCP-NET-06", 19, "Cloud Armor on external backend services", "medium", ["projects", "compute"], "manual", "warn"],
] as const;

function owner(id: string): string {
  if (id.startsWith("GCP-IAM-")) return "gcp_assess_identity";
  if (id.startsWith("GCP-LOG-")) return "gcp_assess_logging_detection";
  if (id.startsWith("GCP-ORG-")) return "gcp_assess_org_guardrails";
  if (id.startsWith("GCP-DATA-")) return "gcp_assess_data_protection";
  return "gcp_assess_network_security";
}

const decisionConstants = (id: string): Batch2CheckRow["constants"] => ({
  "GCP-LOG-04": { minimum_log_retention_days: GCP_MIN_LOG_RETENTION_DAYS },
  "GCP-DATA-03": { maximum_kms_rotation_days: GCP_MAX_KMS_ROTATION_DAYS },
  "GCP-NET-01": { administrative_ports: GCP_ADMIN_PORTS },
  "GCP-NET-02": { flow_log_unsupported_subnet_purposes: GCP_FLOW_LOG_UNSUPPORTED_PURPOSES },
  "GCP-NET-06": { http_backend_protocols: GCP_HTTP_BACKEND_PROTOCOLS },
} as const)[id as "GCP-LOG-04" | "GCP-DATA-03" | "GCP-NET-01" | "GCP-NET-02" | "GCP-NET-06"];

const orgPolicyDecision = (outcome: "fail" | "warn") => ({
  decisionInputs: {
    evidence_readable: "Boolean. True only when the effective organization policy response was readable and its enforced state was present; null or missing means unavailable, never disabled.",
    evidence_complete: "Boolean. True only when the complete project inventory supports applying the sampled effective policy to the assessed scope; false means the scope is partial.",
    policy_enabled: "Boolean raw interpretation of booleanPolicy.enforced or a non-empty listPolicy.allowedValues/deniedValues result from the effective policy response; null means the documented policy fields were absent.",
  },
  decisionRules: [
    batch2Rule("manual", batch2Any(
      batch2Ne("evidence_readable", true),
      batch2Not(batch2Defined("policy_enabled")),
      batch2Eq("policy_enabled", null),
    )),
    batch2Rule(outcome, batch2Eq("policy_enabled", false)),
    batch2Rule("warn", batch2Ne("evidence_complete", true)),
    batch2Rule("pass", batch2All(batch2Eq("evidence_readable", true), batch2Eq("evidence_complete", true), batch2Eq("policy_enabled", true))),
    batch2Rule("manual", { op: "always" }),
  ],
});

function customDecision(id: string): Partial<Pick<Batch2CheckRow, "decisionInputs" | "decisionRules">> | undefined {
  if (id === "GCP-ORG-02") return orgPolicyDecision("warn");
  if (id === "GCP-ORG-03") return orgPolicyDecision("fail");
  if (id === "GCP-ORG-04") return orgPolicyDecision("warn");
  if (id === "GCP-ORG-05") {
    return {
      decisionInputs: {
        evidence_readable: "Boolean. True only when both effective policy responses were readable; null or missing means unavailable.",
        evidence_complete: "Boolean. True only when project inventory scope was complete; false means the sampled effective policies may not represent every project.",
        serial_port_access_disabled: "Boolean raw interpretation of constraints/compute.disableSerialPortAccess from booleanPolicy.enforced or listPolicy presence.",
        shielded_vm_required: "Boolean raw interpretation of constraints/compute.requireShieldedVm from booleanPolicy.enforced or listPolicy presence.",
      },
      decisionRules: [
        batch2Rule("manual", batch2Any(
          batch2Ne("evidence_readable", true),
          batch2Not(batch2Defined("serial_port_access_disabled")),
          batch2Eq("serial_port_access_disabled", null),
          batch2Not(batch2Defined("shielded_vm_required")),
          batch2Eq("shielded_vm_required", null),
        )),
        batch2Rule("fail", batch2All(batch2Eq("serial_port_access_disabled", false), batch2Eq("shielded_vm_required", false))),
        batch2Rule("warn", batch2Any(
          batch2Ne("evidence_complete", true),
          batch2Eq("serial_port_access_disabled", false),
          batch2Eq("shielded_vm_required", false),
        )),
        batch2Rule("pass", batch2All(
          batch2Eq("evidence_readable", true),
          batch2Eq("evidence_complete", true),
          batch2Eq("serial_port_access_disabled", true),
          batch2Eq("shielded_vm_required", true),
        )),
        batch2Rule("manual", { op: "always" }),
      ],
    };
  }
  if (id === "GCP-DATA-07") {
    return {
      decisionRules: [
        batch2Rule("manual", batch2Ne("evidence_readable", true)),
        batch2Rule("fail", batch2All(
          batch2Eq("inventory_count", 0),
          batch2Eq("evidence_complete", true),
        )),
        batch2Rule("warn", batch2Gt("violation_count", 0)),
        batch2Rule("warn", batch2Any(
          batch2Ne("evidence_complete", true),
          batch2Gt("review_count", 0),
        )),
        batch2Rule("pass", batch2All(
          batch2Eq("evidence_readable", true),
          batch2Eq("evidence_complete", true),
          batch2Eq("violation_count", 0),
          batch2Eq("review_count", 0),
        )),
        batch2Rule("manual", { op: "always" }),
      ],
    };
  }
  return undefined;
}

const decisionPredicate: Readonly<Record<string, string>> = {
  "GCP-IAM-01": "Fail for IAM bindings to owner, editor, or the runtime privileged-role set when a member is allUsers, allAuthenticatedUsers, a user, or an external principal outside the assessed organization.",
  "GCP-IAM-02": "Fail for a USER_MANAGED service-account key with missing creation time, expired validity, or age beyond the runtime rotation baseline; complete empty key inventories pass.",
  "GCP-IAM-03": "Warn when any enabled service account has a USER_MANAGED key; pass only after complete service-account and key inventories prove none.",
  "GCP-IAM-04": "Warn when an IAM member serviceAccount principal belongs to a project different from the resource project.",
  "GCP-IAM-05": "Fail when a default Compute or App Engine service account has an owner, editor, or other runtime broad role binding.",
  "GCP-LOG-01": "Warn when no recent Admin Activity entry is visible for a project; unreadable Logging responses remain manual.",
  "GCP-LOG-02": "Fail when project IAM auditConfigs do not enable DATA_READ and DATA_WRITE for allServices or equivalent complete service coverage.",
  "GCP-LOG-03": "Fail when a project has no enabled aggregated or project log sink with a nonempty destination.",
  "GCP-LOG-04": `Fail when a readable log bucket has retentionDays below ${GCP_MIN_LOG_RETENTION_DAYS}; missing retention warns.`,
  "GCP-LOG-05": "Return informational or warning evidence from readable Security Command Center findings; no organization scope or unreadable SCC evidence cannot pass.",
  "GCP-ORG-01": "Warn when no ACTIVE organization is visible or project ancestry cannot be tied to the configured organization.",
  "GCP-ORG-02": "Use the explicit effective-policy policy_enabled rules rendered below for constraints/iam.allowedPolicyMemberDomains.",
  "GCP-ORG-03": "Use the explicit effective-policy policy_enabled rules rendered below for constraints/iam.disableServiceAccountKeyCreation.",
  "GCP-ORG-04": "Use the explicit effective-policy policy_enabled rules rendered below for constraints/iam.disableServiceAccountKeyUpload.",
  "GCP-ORG-05": "Use the explicit disableSerialPortAccess and requireShieldedVm raw policy-field rules rendered below.",
  "GCP-ORG-06": "Fail when constraints/compute.requireOsLogin is not enabled or an instance metadata item explicitly disables enable-oslogin.",
  "GCP-ORG-07": "Fail when Binary Authorization defaultAdmissionRule evaluates to always allow or when no project policy is enforced; warn for permissive scoped admission rules.",
  "GCP-ORG-08": "Fail when a VM enables serial-port access or lacks required Shielded VM secure boot, vTPM, or integrity monitoring fields.",
  "GCP-DATA-01": "Fail when a bucket's iamConfiguration.uniformBucketLevelAccess.enabled is not true.",
  "GCP-DATA-02": "Fail when any IAM policy binding grants allUsers or allAuthenticatedUsers access to a resource.",
  "GCP-DATA-03": `Fail when a CryptoKey has no rotationPeriod, rotation exceeds ${GCP_MAX_KMS_ROTATION_DAYS} days, or nextRotationTime is absent or overdue.`,
  "GCP-DATA-04": "Warn when a bucket, disk, or image resource lacks a customer-managed KMS key reference; a complete empty encryptable-resource inventory remains manual.",
  "GCP-DATA-05": "Fail when a public Cloud DNS zone has dnssecConfig.state other than on.",
  "GCP-DATA-06": "Fail when an API key lacks both application restrictions and API target restrictions; complete empty key inventories pass.",
  "GCP-DATA-07": "Fail when no service perimeter exists; warn when a perimeter has no protected resources or is dry-run only.",
  "GCP-NET-01": `Fail for an enabled INGRESS firewall rule from 0.0.0.0/0 or ::/0 whose allowed protocol/port range includes ${GCP_ADMIN_PORTS.join(" or ")}.`,
  "GCP-NET-02": `Fail when a subnet whose purpose is not one of ${GCP_FLOW_LOG_UNSUPPORTED_PURPOSES.join(", ")} lacks enableFlowLogs/logConfig.enable=true.`,
  "GCP-NET-03": "Warn when a subnet has privateIpGoogleAccess other than true.",
  "GCP-NET-04": "Warn when an instance has an external accessConfig or a network with private workloads lacks Cloud NAT coverage.",
  "GCP-NET-05": "Fail when an external target HTTPS/SSL proxy has no SSL policy or uses a policy profile/minimum TLS version below the runtime secure baseline.",
  "GCP-NET-06": `Warn when an external backend service using ${GCP_HTTP_BACKEND_PROTOCOLS.join(", ")} has no securityPolicy Cloud Armor reference.`,
};

const checks = batch2Checks(rows.map(([id, control, title, severity, sourceSurfaces, emptyOutcome, violationOutcome]) => ({
  id,
  control,
  title,
  severity,
  owner: owner(id),
  surfaces: sourceSurfaces,
  emptyOutcome,
  violationOutcome,
  constants: decisionConstants(id),
  ...customDecision(id),
  decision: `${decisionPredicate[id]} Apply the check's explicit empty-inventory outcome; a proved violation returns ${violationOutcome ?? "fail"} with first-match precedence, and partial or unreadable evidence cannot pass.`,
})));
const idsFor = (tool: string): string[] => checks.filter((check) => check.owner === tool).map((check) => check.id);

export const GCP_RUNTIME_BEHAVIOR = [
  "Project-scoped APIs are sampled from the complete collected project inventory up to the configured project cap; reaching any project, page, key, finding, or asset cap marks dependent evidence partial.",
  "Security Command Center is organization-scoped and remains manual when no organization ID is configured.",
  "Rendered arrays are capped presentation samples; verdict counts are computed before those arrays are sliced.",
] as const;

export const GCP_SPEC = buildBatchIntegrationSpec({
  slug: "gcp-sec-inspector",
  displayName: "GCP Security Inspector",
  vendor: "Google Cloud",
  category: "cloud",
  summary: "Portable contract for the shipped Google Cloud identity, logging, organization, data-protection, and network assessments.",
  sourceModule: "cli/extensions/grc-tools/gcp.ts",
  baseServices: [...new Set(surfaces.map((surface) => surface.service))],
  authentication: GCP_AUTH_RESOLVER,
  permissions: [
    { id: "cloud-platform", kind: "oauth-scope", value: "https://www.googleapis.com/auth/cloud-platform", unlocks: surfaces.map((surface) => surface.id), notes: "OAuth scope only; IAM permissions still govern every read." },
    { id: "viewer-security-reviewer", kind: "role", value: "Viewer plus service-specific security, logging, asset, IAM, and organization read permissions", unlocks: surfaces.map((surface) => surface.id) },
  ],
  surfaces,
  checks,
  tools: {
    gcp_check_access: [],
    gcp_assess_identity: idsFor("gcp_assess_identity"),
    gcp_assess_logging_detection: idsFor("gcp_assess_logging_detection"),
    gcp_assess_org_guardrails: idsFor("gcp_assess_org_guardrails"),
    gcp_assess_data_protection: idsFor("gcp_assess_data_protection"),
    gcp_assess_network_security: idsFor("gcp_assess_network_security"),
    gcp_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [{
    surfaceIds: surfaces.filter((surface) => !["organization", "effective-org-policy", "binary-authorization"].includes(surface.id)).map((surface) => surface.id),
    cursorFields: ["nextPageToken"],
    pageSize: null,
    itemCap: null,
    pageCap: 250,
    totalSemantics: "Completion requires exhausting nextPageToken and remaining below every configured project, key, finding, asset, and resource cap; presentation slices never establish completion.",
    stopConditions: ["No nextPageToken", "Repeated page token", "Empty page with nextPageToken", "250-page cap", "Configured project or resource cap"],
  }],
  rateLimit: {
    documentedLimit: "API and quota-project specific",
    retryHeaders: ["Retry-After"],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "Honor bounded Retry-After and retry transient responses with bounded exponential delay; exhausted reads remain unreadable.",
  },
  runtimeBehavior: GCP_RUNTIME_BEHAVIOR,
  knownGaps: ["Organization-wide enumeration is bounded by explicit runtime caps and some organization-policy checks use a configured or sampled project as their effective-policy target."],
  sensitiveFields: ["private_key", "client_secret", "refresh_token", "access_token", "authorization", "cookie"],
  credentialFormats: ["OAuth bearer tokens", "service-account private keys", "authorized-user refresh tokens"],
  output: buildBatchOutputContract({
    files: [
      "QUICK_REFERENCE.md",
      "README.md",
      "metadata.json",
      "core_data/access.json",
      "core_data/identity.json",
      "core_data/logging-detection.json",
      "core_data/org-guardrails.json",
      "core_data/data-protection.json",
      "core_data/network-security.json",
      "analysis/identity.json",
      "analysis/logging-detection.json",
      "analysis/org-guardrails.json",
      "analysis/data-protection.json",
      "analysis/network-security.json",
      "analysis/identity.md",
      "analysis/logging-detection.md",
      "analysis/org-guardrails.md",
      "analysis/data-protection.md",
      "analysis/network-security.md",
      "analysis/findings.json",
      "analysis/category_summaries.json",
      "compliance/executive_summary.md",
      "compliance/unified_compliance_matrix.md",
      "compliance/frameworks/fedramp.md",
      "compliance/frameworks/cmmc.md",
      "compliance/frameworks/soc2.md",
      "compliance/frameworks/cis_gcp.md",
      "compliance/frameworks/pci_dss.md",
      "compliance/frameworks/disa_stig.md",
      "compliance/frameworks/irap.md",
      "compliance/frameworks/ismap.md",
    ],
    conditionalFiles: ["_errors.log"],
    overwritePolicy: "Allocate a new gcp-audit-<UTC timestamp> directory and numeric suffix when either directory or paired archive exists.",
    archivePairing: "Create <allocated-directory>.zip beside the allocated GCP audit directory.",
  }),
});
