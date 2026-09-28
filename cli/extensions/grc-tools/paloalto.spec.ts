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
  batch2Path,
  batch2Rule,
  batch2Value,
  restSurface,
  type Batch2CheckRow,
} from "./batch2-spec-helpers.js";
import { PALOALTO_AUTH_RESOLVER } from "./auth-resolver-contracts.js";

const PRISMA_DOCS = "https://pan.dev/prisma-cloud/api/cspm/";
const PANOS_DOCS = "https://docs.paloaltonetworks.com/pan-os/11-2/pan-os-panorama-api";
const surfaces = [
  restSurface("prisma-cspm", "/{compliance|alert|policy|cloud|user|integration} read endpoints", "Prisma Cloud CSPM", PRISMA_DOCS, ["compliance", "severity", "status", "policy", "cloudAccount", "role", "integration"]),
  restSurface("prisma-compute", "/api/v1/{defenders|policies|registry|stats|cloud-discovery|ci-scans}", "Prisma Cloud Compute", "https://pan.dev/compute/api/", ["rules", "collections", "effect", "status", "specifications", "vulnerabilities"]),
  restSurface("panos-operational", "/api/?type=op&cmd={system-info|high-availability}", "PAN-OS XML API", PANOS_DOCS, ["hostname", "sw-version", "app-version", "threat-version", "ha"]),
  restSurface("panos-configuration", "/api/?type=config&action=get&xpath={configuration subtree}", "PAN-OS XML API", PANOS_DOCS, ["security rules", "zones", "decryption rules", "profiles", "administrators", "logging", "deviceconfig"]),
] as const;

const titles = [
  "CSPM compliance posture",
  "Alert policy coverage",
  "IAM overprivileged access",
  "Cloud account governance",
  "Network exposure analysis",
  "Encryption at rest verification",
  "Container image vulnerability",
  "Host compliance posture",
  "Runtime protection policies",
  "Defender deployment coverage",
  "Registry scanning configuration",
  "Firewall security rule audit",
  "Zone segmentation verification",
  "SSL/TLS decryption coverage",
  "GlobalProtect VPN configuration",
  "Threat prevention profiles",
  "WildFire analysis configuration",
  "URL filtering enforcement",
  "Admin role and access audit",
  "Logging and SIEM integration",
  "Data loss prevention",
  "File blocking policies",
  "System hardening",
  "Cloud discovery and shadow IT",
  "CI/CD pipeline security",
] as const;

function owner(control: number): string {
  if (control <= 11 || control >= 24) return "paloalto_assess_cloud_posture";
  if (control <= 14) return "paloalto_assess_firewall_policy";
  if ([16, 17, 18, 21, 22].includes(control)) return "paloalto_assess_threat_prevention";
  return "paloalto_assess_device_hardening";
}

function sourceSurfaces(control: number): readonly string[] {
  if (control <= 6 || control >= 24) return ["prisma-cspm"];
  if (control <= 11) return ["prisma-compute"];
  if ([21].includes(control)) return ["prisma-cspm", "panos-configuration"];
  return control === 23 ? ["panos-operational", "panos-configuration"] : ["panos-configuration"];
}

const severities: readonly Batch2CheckRow["severity"][] = [
  "high", "high", "high", "medium", "critical", "high", "high", "medium", "high", "high",
  "medium", "critical", "high", "high", "high", "high", "medium", "high", "high", "high",
  "high", "medium", "medium", "medium", "high",
];

const completePassRules = [
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
] as const;

function paloaltoDecision(control: number): Partial<Pick<Batch2CheckRow, "decisionInputs" | "decisionRules" | "constants">> | undefined {
  if (control === 1) {
    return {
      constants: { warning_margin_percentage_points: 20 },
      decisionInputs: {
        evidence_readable: "Boolean. True only when the Prisma compliance posture summary was readable.",
        evidence_complete: "Boolean. True only when the posture inventory was complete; false means the result is partial.",
        passed_resource_count: "Non-negative integer from summary.passedResources; null means the field was unavailable.",
        total_resource_count: "Non-negative integer from summary.totalResources, or the complete sum of passedResources and failedResources when totalResources is absent; zero means no evaluated resources.",
        minimum_pass_rate_percent: "Number from the minCompliancePassRate operator option after clamping to 1 through 100; the default is 90.",
      },
      decisionRules: [
        batch2Rule("manual", batch2Any(
          batch2Ne("evidence_readable", true),
          batch2Not(batch2Defined("passed_resource_count")),
          batch2Not(batch2Defined("total_resource_count")),
          batch2Eq("total_resource_count", 0),
        )),
        batch2Rule("fail", {
          op: "ratio",
          numerator: batch2Path("passed_resource_count"),
          denominator: batch2Path("total_resource_count"),
          comparator: "lt",
          threshold: {
            kind: "subtract",
            left: batch2Path("minimum_pass_rate_percent"),
            right: batch2Path("warning_margin_percentage_points"),
          },
          scale: 100,
          roundDigits: 1,
        }),
        batch2Rule("warn", batch2Any(
          batch2Ne("evidence_complete", true),
          {
            op: "ratio",
            numerator: batch2Path("passed_resource_count"),
            denominator: batch2Path("total_resource_count"),
            comparator: "lt",
            threshold: batch2Path("minimum_pass_rate_percent"),
            scale: 100,
            roundDigits: 1,
          },
        )),
        batch2Rule("pass", batch2All(
          batch2Eq("evidence_readable", true),
          batch2Eq("evidence_complete", true),
          {
            op: "ratio",
            numerator: batch2Path("passed_resource_count"),
            denominator: batch2Path("total_resource_count"),
            comparator: "gte",
            threshold: batch2Path("minimum_pass_rate_percent"),
            scale: 100,
            roundDigits: 1,
          },
        )),
        batch2Rule("manual", { op: "always" }),
      ],
    };
  }
  if (control === 19) {
    return {
      decisionInputs: {
        evidence_readable: "Boolean. True only when every configured Prisma role and PAN-OS administrator/password-complexity surface used here was readable.",
        evidence_complete: "Boolean. False when a configured product inventory was truncated or contained unevaluable records.",
        panos_configured: "Boolean derived only from whether at least one PAN-OS device snapshot was configured.",
        prisma_configured: "Boolean derived only from whether a Prisma Cloud snapshot was configured.",
        panos_administrator_count: "Complete count of PAN-OS administrator entries before presentation slicing.",
        panos_superuser_count: "Complete count of administrator entries whose role resolves to superuser.",
        maximum_superuser_count: "Integer operator threshold maxSuperusers after clamping to 0 through 1000; default 3.",
        password_complexity_disabled_device_count: "Count of configured PAN-OS devices where password-complexity enabled is not exactly yes.",
        local_password_only_administrator_count: "Count of administrators with a local password and neither authentication profile nor public key.",
        prisma_system_admin_role_count: "Count of Prisma roles whose roleType or name matches System Admin.",
        prisma_role_count: "Complete count of Prisma user roles before presentation slicing.",
      },
      decisionRules: [
        batch2Rule("manual", batch2Any(
          batch2Ne("evidence_readable", true),
          batch2All(batch2Eq("panos_configured", true), batch2Eq("panos_administrator_count", 0)),
        )),
        batch2Rule("fail", batch2All(
          batch2Eq("panos_configured", true),
          batch2Any(
            { op: "gt", left: batch2Path("panos_superuser_count"), right: batch2Path("maximum_superuser_count") },
            batch2Gt("password_complexity_disabled_device_count", 0),
          ),
        )),
        batch2Rule("warn", batch2Any(
          batch2Ne("evidence_complete", true),
          batch2Gt("local_password_only_administrator_count", 0),
          batch2Ne("panos_configured", true),
          batch2Ne("prisma_configured", true),
          batch2All(batch2Eq("prisma_configured", true), batch2Any(
            { op: "gt", left: batch2Path("prisma_system_admin_role_count"), right: batch2Path("maximum_superuser_count") },
            batch2Eq("prisma_role_count", 0),
          )),
        )),
        batch2Rule("pass", { op: "always" }),
      ],
    };
  }
  if (control === 20) {
    return {
      decisionInputs: {
        evidence_readable: "Boolean. True only when every configured Prisma integration and PAN-OS security-rule/log-forwarding surface was readable.",
        evidence_complete: "Boolean. False when a configured product inventory was truncated or contained unevaluable records.",
        panos_configured: "Boolean derived only from whether at least one PAN-OS device snapshot was configured.",
        prisma_configured: "Boolean derived only from whether a Prisma Cloud snapshot was configured.",
        enabled_security_rule_count: "Complete count of PAN-OS security rules not explicitly disabled.",
        log_end_disabled_rule_count: "Count of enabled rules whose log-end value is exactly no.",
        implicit_log_end_rule_count: "Count of enabled rules with no explicit log-end value.",
        rule_without_forwarding_profile_count: "Count of enabled rules with no log forwarding profile.",
        external_forwarding_configured: "Boolean: true when at least one syslog server profile or Panorama forwarding setting exists.",
        prisma_siem_integration_count: "Count of Prisma integrations whose documented type or name identifies Splunk, SIEM, syslog, QRadar, Sentinel, webhook, SQS, Pub/Sub, ServiceNow, or SNOW.",
      },
      decisionRules: [
        batch2Rule("manual", batch2Ne("evidence_readable", true)),
        batch2Rule("fail", batch2All(batch2Eq("panos_configured", true), batch2Any(
          batch2Gt("log_end_disabled_rule_count", 0),
          batch2Eq("external_forwarding_configured", false),
        ))),
        batch2Rule("warn", batch2Any(
          batch2Ne("evidence_complete", true),
          batch2Ne("panos_configured", true),
          batch2Ne("prisma_configured", true),
          batch2Eq("enabled_security_rule_count", 0),
          batch2Gt("implicit_log_end_rule_count", 0),
          batch2Gt("rule_without_forwarding_profile_count", 0),
          batch2All(batch2Eq("prisma_configured", true), batch2Eq("prisma_siem_integration_count", 0)),
        )),
        batch2Rule("pass", { op: "always" }),
      ],
    };
  }
  return undefined;
}

const checks = batch2Checks(titles.map((title, index) => {
  const control = index + 1;
  const decisionRules = control === 10 || control === 25
    ? [
        batch2Rule("manual", batch2Ne("evidence_readable", true)),
        batch2Rule("fail", batch2Gt("violation_count", 0)),
        ...completePassRules,
      ]
    : undefined;
  return {
    id: `PA-${String(control).padStart(2, "0")}`,
    control,
    title,
    severity: severities[index],
    owner: owner(control),
    surfaces: sourceSurfaces(control),
    emptyOutcome: "manual" as const,
    decisionRules,
    ...paloaltoDecision(control),
    decision: `Evaluate ${title} from complete Prisma Cloud or PAN-OS raw inventories: unreadable product surfaces remain manual, a proved violation takes precedence over partial companion reads, partial or review records warn, and pass requires complete readable evidence with no violation.`,
  };
}));
const idsFor = (tool: string): string[] => checks.filter((check) => check.owner === tool).map((check) => check.id);

export const PALOALTO_RUNTIME_BEHAVIOR = [
  "Prisma Cloud CSPM, Prisma Cloud Compute, and each PAN-OS device are independent products; a product without credentials emits explicit manual findings rather than empty compliant inventories.",
  "PAN-OS XML responses are projected to the exact configuration subtrees used by each finding and credential-bearing values are scrubbed before tool or bundle output.",
  "Paged alert and Compute inventories retain total and truncation state; displayed records do not decide verdicts.",
] as const;

export const PALOALTO_SPEC = buildBatchIntegrationSpec({
  slug: "paloalto-sec-inspector",
  displayName: "Palo Alto Networks Security Inspector",
  vendor: "Palo Alto Networks",
  category: "cloud-and-network-security",
  summary: "Portable contract for the shipped Prisma Cloud CSPM, Prisma Cloud Compute, and PAN-OS assessments.",
  sourceModule: "cli/extensions/grc-tools/paloalto.ts",
  baseServices: ["Prisma Cloud CSPM", "Prisma Cloud Compute", "PAN-OS XML API"],
  authentication: PALOALTO_AUTH_RESOLVER,
  permissions: [
    { id: "prisma-read-role", kind: "role", value: "Prisma Cloud read access to compliance, alerts, policies, accounts, roles, integrations, and configured Compute surfaces", unlocks: ["prisma-cspm", "prisma-compute"] },
    { id: "panos-read-role", kind: "role", value: "PAN-OS XML API operational and configuration read access", unlocks: ["panos-operational", "panos-configuration"] },
  ],
  surfaces,
  checks,
  tools: {
    paloalto_check_access: [],
    paloalto_assess_cloud_posture: idsFor("paloalto_assess_cloud_posture"),
    paloalto_assess_firewall_policy: idsFor("paloalto_assess_firewall_policy"),
    paloalto_assess_threat_prevention: idsFor("paloalto_assess_threat_prevention"),
    paloalto_assess_device_hardening: idsFor("paloalto_assess_device_hardening"),
    paloalto_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [{
    surfaceIds: ["prisma-cspm", "prisma-compute"],
    cursorFields: ["offset", "limit", "total", "next"],
    pageSize: null,
    itemCap: null,
    pageCap: null,
    totalSemantics: "Completion requires reaching the reported total or an exhausted page without hitting the configured alert or product cap.",
    stopConditions: ["Reported total reached", "Short or empty final page", "Repeated cursor", "Configured item cap"],
  }],
  rateLimit: {
    documentedLimit: "Tenant, product, and endpoint specific",
    retryHeaders: ["Retry-After"],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "Honor bounded Retry-After and retry transient requests with bounded exponential delay; exhausted reads remain unreadable.",
  },
  runtimeBehavior: PALOALTO_RUNTIME_BEHAVIOR,
  knownGaps: ["Controls whose required Prisma Compute product or PAN-OS subtree is not configured remain manual and identify the missing evidence."],
  sensitiveFields: ["accessKey", "secretKey", "apiKey", "password", "authorization", "cookie", "token"],
  credentialFormats: ["Prisma access and secret keys", "Prisma Compute bearer tokens", "PAN-OS API keys", "PAN-OS administrator passwords"],
  output: buildBatchOutputContract({
    files: [
      "QUICK_REFERENCE.md", "metadata.json", "core_data/access.json", "analysis/findings.json",
      "analysis/cloud_posture.json", "analysis/firewall_policy.json", "analysis/threat_prevention.json",
      "analysis/device_hardening.json", "compliance/executive_summary.md",
      "compliance/unified_compliance_matrix.md", "compliance/fedramp.md", "compliance/cmmc.md",
      "compliance/soc2.md", "compliance/cis.md", "compliance/pci-dss.md",
      "compliance/disa-stig.md", "compliance/irap.md", "compliance/ismap.md",
    ],
    conditionalFiles: ["core_data/prisma_cloud.json", "core_data/panos_{host}.json", "_errors.log"],
    conditionalFileConditions: {
      "core_data/prisma_cloud.json": "When Prisma Cloud credentials are configured and a Prisma snapshot is collected.",
      "core_data/panos_{host}.json": "Once for each configured PAN-OS host whose snapshot collection was attempted.",
      "_errors.log": "When any Prisma Cloud or PAN-OS collection error was recorded.",
    },
    overwritePolicy: "Allocate a new Palo Alto audit directory and numeric suffix without overwriting an existing directory or archive.",
    archivePairing: "Create <allocated-directory>.zip beside the allocated Palo Alto audit directory.",
  }),
});
