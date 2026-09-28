import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
  type BatchCompletenessSourceDefinition,
} from "./batch-spec-builder.js";
import {
  batch2Any,
  batch2Checks,
  batch2ComparePaths,
  batch2Completeness,
  batch2Eq,
  batch2GenericDecisionInputs,
  batch2Ne,
  batch2Rule,
  restSurface,
  type Batch2CheckRow,
} from "./batch2-spec-helpers.js";
import { OCI_AUTH_RESOLVER } from "./auth-resolver-contracts.js";

const OCI_DOCS = "https://docs.oracle.com/en-us/iaas/api/";
export const OCI_AUDIT_RETENTION_REQUIRED_DAYS = 365;
export const OCI_KEY_ROTATION_MAX_DAYS = 365;
export const OCI_DEFAULT_CREDENTIAL_STALE_DAYS = 90;
export const OCI_BASTION_MAX_TTL_SECONDS = 10_800;
export const OCI_KEY_MIN_AES_BYTES = 32;
export const OCI_KEY_MIN_RSA_BYTES = 512;
export const OCI_ECDSA_ACCEPTED_CURVES = ["NIST_P256", "NIST_P384", "NIST_P521"] as const;
export const OCI_BASTION_SESSION_MAX_HOURS = 8;
export const OCI_PAR_LONG_LIVED_DAYS = 30;
export const OCI_MIN_PASSWORD_LENGTH = 14;
export const OCI_SENSITIVE_PORTS = [22, 3389, 1433, 3306, 5432] as const;
export const OCI_RUNTIME_FRAMEWORK_MAPPINGS: Readonly<Record<string, readonly string[]>> = {
  "OCI-IAM-01": ["FedRAMP IA-5", "CMMC L2 3.5.7", "SOC 2 CC6.1", "CIS OCI 1.1", "PCI-DSS 8.3.6", "STIG SRG-APP-000166", "IRAP ISM-0421", "ISMAP AM-03"],
  "OCI-IAM-02": ["FedRAMP IA-2(1)", "CMMC L2 3.5.3", "SOC 2 CC6.1", "CIS OCI 1.2", "PCI-DSS 8.4.2", "STIG SRG-APP-000149", "IRAP ISM-1401", "ISMAP AM-04"],
  "OCI-IAM-03": ["FedRAMP IA-5(1)", "CMMC L2 3.5.8", "SOC 2 CC6.1", "CIS OCI 1.7", "CIS OCI 1.8", "CIS OCI 1.9", "PCI-DSS 8.6.3", "STIG SRG-APP-000174", "IRAP ISM-1590", "ISMAP AM-05"],
  "OCI-IAM-04": ["FedRAMP AC-6", "CMMC L2 3.1.5", "SOC 2 CC6.3", "CIS OCI 1.14", "PCI-DSS 7.2.1", "STIG SRG-APP-000340", "IRAP ISM-0432", "ISMAP AC-01"],
  "OCI-IAM-05": ["FedRAMP AC-4", "CMMC L2 3.13.1", "SOC 2 CC6.1", "CIS OCI 1.3", "PCI-DSS 1.3.1", "STIG SRG-APP-000039", "IRAP ISM-1416", "ISMAP AC-02"],
  "OCI-IAM-06": ["FedRAMP IA-5", "CMMC L2 3.5.7", "SOC 2 CC6.1", "CIS OCI 1.1", "PCI-DSS 8.3.6", "STIG SRG-APP-000166", "IRAP ISM-0421", "ISMAP AM-03"],
  "OCI-LOG-01": ["FedRAMP SI-4", "CMMC L2 3.14.6", "SOC 2 CC7.2", "CIS OCI 3.1", "PCI-DSS 11.5.1", "STIG SRG-APP-000516", "IRAP ISM-0120", "ISMAP SO-01"],
  "OCI-LOG-02": ["FedRAMP SI-4(5)", "CMMC L2 3.14.7", "SOC 2 CC7.3", "CIS OCI 3.2", "PCI-DSS 11.5.1.1", "STIG SRG-APP-000516", "IRAP ISM-0123", "ISMAP SO-02"],
  "OCI-LOG-03": ["FedRAMP IR-4", "CMMC L2 3.6.1", "SOC 2 CC7.4", "CIS OCI 3.3", "PCI-DSS 12.10.5", "STIG SRG-APP-000516", "IRAP ISM-0125", "ISMAP IR-01"],
  "OCI-LOG-04": [],
  "OCI-LOG-05": ["FedRAMP AU-12", "CMMC L2 3.3.1", "SOC 2 CC7.2", "CIS OCI 3.5", "PCI-DSS 10.6.1", "STIG SRG-APP-000492", "IRAP ISM-0580", "ISMAP LG-02"],
  "OCI-LOG-06": ["FedRAMP AU-11", "CMMC L2 3.3.1", "SOC 2 CC7.2", "CIS OCI 3.4", "PCI-DSS 10.7.1", "STIG SRG-APP-000515", "IRAP ISM-0859", "ISMAP LG-01"],
  "OCI-GRD-01": ["FedRAMP SC-7", "CMMC L2 3.13.1", "SOC 2 CC6.6", "CIS OCI 2.1", "PCI-DSS 1.3.1", "STIG SRG-APP-000142", "IRAP ISM-1416", "ISMAP NW-01"],
  "OCI-GRD-02": ["FedRAMP SC-7", "CMMC L2 3.13.1", "SOC 2 CC6.6", "CIS OCI 2.2", "PCI-DSS 1.3.2", "STIG SRG-APP-000142", "IRAP ISM-1416", "ISMAP NW-01"],
  "OCI-GRD-03": ["FedRAMP SC-7(5)", "CMMC L2 3.13.6", "SOC 2 CC6.6", "CIS OCI 2.3", "PCI-DSS 1.3.1", "STIG SRG-APP-000383", "IRAP ISM-1417", "ISMAP NW-02"],
  "OCI-GRD-04": ["FedRAMP AC-17", "FedRAMP AC-17(1)", "CMMC L2 3.1.12", "SOC 2 CC6.1", "SOC 2 CC6.2", "CIS OCI 2.8", "CIS OCI 2.9", "PCI-DSS 8.6.1", "STIG SRG-APP-000190", "IRAP ISM-1506", "ISMAP AC-03"],
  "OCI-GRD-05": ["FedRAMP SC-12(1)", "FedRAMP SC-13", "CMMC L2 3.13.10", "CMMC L2 3.13.11", "SOC 2 CC6.1", "CIS OCI 4.1", "CIS OCI 4.2", "PCI-DSS 3.6.4", "PCI-DSS 3.6.1", "STIG SRG-APP-000514", "IRAP ISM-0490", "IRAP ISM-0457", "ISMAP CR-01", "ISMAP CR-02"],
  "OCI-GRD-06": ["FedRAMP AC-3", "CMMC L2 3.1.1", "CMMC L2 3.1.2", "SOC 2 CC6.1", "CIS OCI 5.1", "CIS OCI 5.2", "PCI-DSS 1.3.6", "PCI-DSS 7.2.2", "STIG SRG-APP-000033", "IRAP ISM-0405", "ISMAP DS-01", "ISMAP DS-02"],
  "OCI-CMP-01": ["FedRAMP CM-7", "CMMC L2 3.4.7", "SOC 2 CC6.1", "CIS OCI 2.10", "PCI-DSS 2.2.1", "STIG SRG-APP-000141", "IRAP ISM-1418", "ISMAP CM-01"],
  "OCI-CMP-02": ["FedRAMP SC-28", "CMMC L2 3.13.16", "SOC 2 CC6.1", "CIS OCI 4.3", "PCI-DSS 3.4.1", "STIG SRG-APP-000429", "IRAP ISM-1080", "ISMAP CR-03"],
  "OCI-CMP-03": ["FedRAMP SC-28", "CMMC L2 3.13.16", "SOC 2 CC6.1", "CIS OCI 4.3", "PCI-DSS 3.4.1", "STIG SRG-APP-000429", "IRAP ISM-1080", "ISMAP CR-03"],
};

function frameworkMappings(id: string): Batch2CheckRow["frameworks"] {
  const mappings = OCI_RUNTIME_FRAMEWORK_MAPPINGS[id] ?? [];
  const values = (prefix: string): string[] => mappings.filter((entry) => entry.startsWith(prefix)).map((entry) => entry.slice(prefix.length));
  return {
    fedramp: values("FedRAMP "),
    cmmc: values("CMMC L2 "),
    soc2: values("SOC 2 "),
    cis: values("CIS OCI "),
    pci_dss: values("PCI-DSS "),
    disa_stig: values("STIG "),
    irap: values("IRAP "),
    ismap: values("ISMAP "),
  };
}
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

const OCI_TRUNCATION_ONLY = ["truncated"] as const;
const ociCompletenessSources = (
  sourceSurfaces: readonly string[],
): readonly BatchCompletenessSourceDefinition[] => sourceSurfaces.map((surfaceId) => ({
  surfaceId,
  falseWhen: OCI_TRUNCATION_ONLY,
}));

function owner(id: string): string {
  if (id.startsWith("OCI-IAM-")) return "oci_assess_identity";
  if (id.startsWith("OCI-LOG-")) return "oci_assess_logging_detection";
  if (id.startsWith("OCI-GRD-")) return "oci_assess_tenancy_guardrails";
  return "oci_assess_compute_and_storage";
}

const decisionConstants = (id: string): Batch2CheckRow["constants"] => ({
  "OCI-IAM-01": { minimum_password_length_required: OCI_MIN_PASSWORD_LENGTH },
  "OCI-IAM-03": { default_maximum_credential_age_days: OCI_DEFAULT_CREDENTIAL_STALE_DAYS },
  "OCI-LOG-06": { minimum_audit_retention_days: OCI_AUDIT_RETENTION_REQUIRED_DAYS },
  "OCI-GRD-01": { sensitive_ingress_ports: OCI_SENSITIVE_PORTS },
  "OCI-GRD-02": { sensitive_ingress_ports: OCI_SENSITIVE_PORTS },
  "OCI-GRD-04": {
    maximum_bastion_ttl_seconds: OCI_BASTION_MAX_TTL_SECONDS,
    maximum_session_hours: OCI_BASTION_SESSION_MAX_HOURS,
  },
  "OCI-GRD-05": {
    maximum_key_rotation_days: OCI_KEY_ROTATION_MAX_DAYS,
    minimum_aes_key_bytes: OCI_KEY_MIN_AES_BYTES,
    minimum_rsa_key_bytes: OCI_KEY_MIN_RSA_BYTES,
    accepted_ecdsa_curves: OCI_ECDSA_ACCEPTED_CURVES,
  },
  "OCI-GRD-06": { long_lived_preauthenticated_request_days: OCI_PAR_LONG_LIVED_DAYS },
} as const)[id as "OCI-IAM-01" | "OCI-IAM-03" | "OCI-LOG-06" | "OCI-GRD-01" | "OCI-GRD-02" | "OCI-GRD-04" | "OCI-GRD-05" | "OCI-GRD-06"];

const decisionPredicate: Readonly<Record<string, string>> = {
  "OCI-IAM-01": `Fail when passwordPolicy.minimumPasswordLength is below ${OCI_MIN_PASSWORD_LENGTH} or any of passwordPolicy.isLowercaseCharactersRequired, isUppercaseCharactersRequired, isNumericCharactersRequired, and isSpecialCharactersRequired is not literally true. No reuse or lockout field participates in this finding.`,
  "OCI-IAM-02": "Fail when any active console-password-capable IAM user has isMfaActivated other than true; pass only after the complete user inventory has no such user.",
  "OCI-IAM-03": `Fail when any active API key, customer secret key, or auth token has no usable timeCreated or is older than stale_days. stale_days defaults to ${OCI_DEFAULT_CREDENTIAL_STALE_DAYS} and is clamped to 1 through 3650 days.`,
  "OCI-IAM-04": "Warn when an IAM policy statement grants any verb to any-user or grants manage to a broad subject or resource scope; retain the complete policy and statement counts.",
  "OCI-IAM-05": "Fail when the complete ACTIVE compartment inventory contains no non-root compartment whose compartmentId names either another returned compartment or the tenancy OCID. Pass when at least one such non-root compartment exists; maximum parent-chain depth is reported as evidence but does not change the verdict.",
  "OCI-IAM-06": "Always return manual because the shipped OCI read surfaces do not expose the password-expiration setting.",
  "OCI-LOG-01": "Fail when the Cloud Guard configuration status is not ENABLED or no ACTIVE target exists; pass only when both reads are complete and affirmative.",
  "OCI-LOG-02": "Pass on a complete empty open-problem inventory; fail when any unresolved Cloud Guard problem is HIGH or CRITICAL and warn for lower-risk open problems.",
  "OCI-LOG-03": "Fail when no ACTIVE responder recipe exists or no returned responder rule has details.isEnabled=true.",
  "OCI-LOG-04": "Warn when the complete audit query returns no event; pass when at least one event with eventTime is visible.",
  "OCI-LOG-05": "Normalize each Events rule condition to lowercase text. A rule covers critical operations when that text contains `com.oraclecloud.identitycontrolplane`, `com.oraclecloud.virtualnetwork`, `policy`, `identity`, or `network`; fail when no enabled ACTIVE rule matches, and warn when rule collection is partial.",
  "OCI-LOG-06": `Fail when Audit config retentionPeriodDays is below ${OCI_AUDIT_RETENTION_REQUIRED_DAYS}; missing or nonnumeric retention is manual.`,
  "OCI-GRD-01": `Fail for any ingress security-list rule from 0.0.0.0/0 or ::/0 whose protocol and TCP range expose one of ports ${OCI_SENSITIVE_PORTS.join(", ")}.`,
  "OCI-GRD-02": `Fail for any ingress network-security-group rule from 0.0.0.0/0 or ::/0 whose protocol and TCP range expose one of ports ${OCI_SENSITIVE_PORTS.join(", ")}.`,
  "OCI-GRD-03": "Warn when an enabled AVAILABLE internet gateway is attached in an assessed compartment; a complete empty gateway inventory passes.",
  "OCI-GRD-04": `Fail when a bastion has maxSessionTtlInSeconds above ${OCI_BASTION_MAX_TTL_SECONDS}, a broad client CIDR, or a session TTL above ${OCI_BASTION_SESSION_MAX_HOURS} hours; warn for missing limit fields.`,
  "OCI-GRD-05": `Fail when an enabled Vault key is older than ${OCI_KEY_ROTATION_MAX_DAYS} without a newer version, uses AES below ${OCI_KEY_MIN_AES_BYTES} bytes, RSA below ${OCI_KEY_MIN_RSA_BYTES} bytes, or an ECDSA curve outside ${OCI_ECDSA_ACCEPTED_CURVES.join(", ")}.`,
  "OCI-GRD-06": `Fail when a bucket publicAccessType is not NoPublicAccess; warn for a pre-authenticated request with no expiry or expiry more than ${OCI_PAR_LONG_LIVED_DAYS} days away.`,
  "OCI-CMP-01": "Fail when any RUNNING instance has instanceOptions.areLegacyImdsEndpointsDisabled other than true.",
  "OCI-CMP-02": "Fail when any AVAILABLE block volume has no kmsKeyId; complete readable inventories with every volume using a customer-managed key pass.",
  "OCI-CMP-03": "Fail when any AVAILABLE boot volume has no kmsKeyId; complete readable inventories with every boot volume using a customer-managed key pass.",
};

const checks = batch2Checks(rows.map(([id, control, title, severity, sourceSurfaces, manualOnly]) => {
  const decisionInputs = manualOnly
    ? {}
    : id === "OCI-IAM-01"
      ? {
          evidence_readable: "Boolean. True only when `oci iam authentication-policy get` returned passwordPolicy and a numeric minimumPasswordLength.",
          minimum_password_length: "Number from passwordPolicy.minimumPasswordLength; null or missing makes the finding manual.",
          lowercase_required: "Boolean from passwordPolicy.isLowercaseCharactersRequired; only literal true satisfies the complexity predicate.",
          uppercase_required: "Boolean from passwordPolicy.isUppercaseCharactersRequired; only literal true satisfies the complexity predicate.",
          numeric_required: "Boolean from passwordPolicy.isNumericCharactersRequired; only literal true satisfies the complexity predicate.",
          special_required: "Boolean from passwordPolicy.isSpecialCharactersRequired; only literal true satisfies the complexity predicate.",
        }
      : batch2GenericDecisionInputs(decisionPredicate[id]);
  return {
    id,
    control,
    title,
    severity,
    owner: owner(id),
    surfaces: sourceSurfaces,
    manualOnly,
    emptyOutcome: ({
      "OCI-IAM-05": "fail",
      "OCI-LOG-02": "pass",
      "OCI-LOG-04": "warn",
      "OCI-LOG-05": "fail",
    } as const)[id as "OCI-IAM-05" | "OCI-LOG-02" | "OCI-LOG-04" | "OCI-LOG-05"] ?? "manual",
    violationOutcome: id === "OCI-IAM-04" || id === "OCI-GRD-03" ? "warn" : "fail",
    constants: decisionConstants(id),
    decisionInputs,
    decisionRules: id === "OCI-IAM-01"
      ? [
          batch2Rule("manual", batch2Ne("evidence_readable", true)),
          batch2Rule("fail", batch2Any(
            batch2ComparePaths("lt", "minimum_password_length", "minimum_password_length_required"),
            batch2Ne("lowercase_required", true),
            batch2Ne("uppercase_required", true),
            batch2Ne("numeric_required", true),
            batch2Ne("special_required", true),
          )),
          batch2Rule("pass", batch2Eq("evidence_readable", true)),
          batch2Rule("manual", { op: "always" }),
        ]
      : undefined,
    completeness: batch2Completeness(
      decisionInputs,
      ociCompletenessSources(sourceSurfaces),
      `true for ${title} only when every list and child read represented by the listed OCI command surface reaches its configured collection end without truncation.`,
    ),
    frameworks: frameworkMappings(id),
    decision: `${decisionPredicate[id]} A proved violation takes precedence over partial collection; otherwise partial or unreadable evidence cannot pass.`,
  };
}));
const idsFor = (tool: string): string[] => checks.filter((check) => check.owner === tool).map((check) => check.id);

export const OCI_RUNTIME_BEHAVIOR = [
  "The collector invokes documented read-only OCI CLI commands and records command failures as unreadable evidence rather than empty arrays.",
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
    surfaceIds: surfaces.map((surface) => surface.id),
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
