import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
  type BatchCompletenessSourceDefinition,
} from "./batch-spec-builder.js";
import {
  batch2All,
  batch2Any,
  batch2Checks,
  batch2Completeness,
  batch2Defined,
  batch2Eq,
  batch2GenericDecisionInputs,
  batch2Gt,
  batch2Ne,
  batch2Not,
  batch2Path,
  batch2Rule,
  restSurface,
  type Batch2CheckRow,
} from "./batch2-spec-helpers.js";
import { PALOALTO_AUTH_RESOLVER } from "./auth-resolver-contracts.js";

const PRISMA_DOCS = "https://pan.dev/prisma-cloud/api/cspm/";
const PANOS_DOCS = "https://docs.paloaltonetworks.com/pan-os/11-2/pan-os-panorama-api";
export const PALOALTO_DEFAULT_MAX_CRITICAL_CVES = 0;
export const PALOALTO_DEFAULT_MIN_HOST_COMPLIANCE_RATE = 90;
export const PALOALTO_DEFAULT_MAX_SUPERUSERS = 3;
export const PALOALTO_DEFAULT_MIN_COMPLIANCE_PASS_RATE = 90;
const COMPUTE_DOCS = "https://pan.dev/compute/api/";
const prismaSurface = (id: string, path: string, fields: readonly string[]) =>
  restSurface(id, path, "Prisma Cloud CSPM", PRISMA_DOCS, fields);
const computeSurface = (id: string, path: string, fields: readonly string[]) =>
  restSurface(id, path, "Prisma Cloud Compute", COMPUTE_DOCS, fields);
const panosConfigSurface = (id: string, xpath: string, fields: readonly string[]) =>
  restSurface(id, `/api/?type=config&action=get&xpath=${xpath}`, "PAN-OS XML API", PANOS_DOCS, fields);
const surfaces = [
  prismaSurface("prisma-compliance-posture", "/compliance/posture", ["summary.passedResources", "summary.failedResources", "summary.totalResources", "complianceDetails"]),
  prismaSurface("prisma-alert-rules", "/alert/rule", ["name", "enabled", "alertRuleNotificationConfig"]),
  prismaSurface("prisma-open-alerts", "/alert", ["policy", "policyId", "policyType", "severity", "status"]),
  prismaSurface("prisma-policies", "/policy", ["name", "policyType", "severity", "enabled", "labels", "description"]),
  prismaSurface("prisma-cloud-accounts", "/cloud", ["name", "enabled", "groups", "groupIds", "status"]),
  prismaSurface("prisma-account-groups", "/cloud/group", ["id", "name"]),
  prismaSurface("prisma-user-roles", "/user/role", ["name", "roleType"]),
  prismaSurface("prisma-integrations", "/integration", ["name", "integrationType"]),
  computeSurface("compute-vulnerability-image-policy", "/api/v1/policies/vulnerability/images", ["rules", "effect", "disabled"]),
  computeSurface("compute-images", "/api/v1/images", ["id", "repoTag", "scanTime", "vulnerabilityDistribution"]),
  computeSurface("compute-vulnerability-stats", "/api/v1/stats/vulnerabilities", ["images", "registryImages", "containers", "hosts", "functions"]),
  computeSurface("compute-compliance-host-policy", "/api/v1/policies/compliance/host", ["rules", "effect", "disabled"]),
  computeSurface("compute-compliance-container-policy", "/api/v1/policies/compliance/container", ["rules", "effect", "disabled"]),
  computeSurface("compute-compliance-stats", "/api/v1/stats/compliance", ["rules", "categories", "failed", "total"]),
  computeSurface("compute-defenders", "/api/v1/defenders", ["hostname", "connected", "lastModified", "version"]),
  computeSurface("compute-runtime-container-policy", "/api/v1/policies/runtime/container", ["rules", "processes", "network", "filesystem", "dns"]),
  computeSurface("compute-registry-settings", "/api/v1/settings/registry", ["specifications", "registry", "repository", "cap", "scanners"]),
  computeSurface("compute-registry-scans", "/api/v1/registry", ["scanTime", "repoTag"]),
  computeSurface("compute-cloud-discovery", "/api/v1/cloud/discovery", ["provider", "serviceType", "total", "defended", "err"]),
  computeSurface("compute-ci-scans", "/api/v1/scans", ["time", "pass"]),
  panosConfigSurface("panos-policy-config", "{/vsys|/device-group|/config/shared}", ["security rules", "default security rules", "decryption rules", "security profiles", "profile groups"]),
  panosConfigSurface("panos-zone-config", "{/network|/template}", ["zones", "zone-protection-profile"]),
  panosConfigSurface("panos-device-config", "{/deviceconfig|/mgt-config|/config/shared|/template|/config/panorama}", ["administrators", "password complexity", "logging", "system settings", "Panorama forwarding"]),
  panosConfigSurface("panos-globalprotect-config", "{/vsys|/network|/template|/config/shared}", ["GlobalProtect portals", "GlobalProtect gateways", "authentication profiles", "multi-factor-auth"]),
  restSurface("panos-system-info", "/api/?type=op&cmd=show system info", "PAN-OS XML API", PANOS_DOCS, ["hostname", "model", "family", "system-mode", "sw-version"]),
  restSurface("panos-ha-state", "/api/?type=op&cmd=show high-availability state", "PAN-OS XML API", PANOS_DOCS, ["enabled", "state"]),
] as const;

const PF = ["error", "denied", "not-collected", "missing-required-field"] as const;
const PTF = ["truncated", "error", "denied", "not-collected", "missing-required-field"] as const;
const PE = ["error", "denied", "not-collected"] as const;
type PaloaltoCompletenessEntry = BatchCompletenessSourceDefinition & {
  product: "cspm" | "compute" | "panos";
};
const paloaltoSource = (
  surfaceId: string,
  falseWhen: BatchCompletenessSourceDefinition["falseWhen"],
  product: PaloaltoCompletenessEntry["product"],
): PaloaltoCompletenessEntry => ({ surfaceId, falseWhen, product });

export const PALOALTO_COMPLETENESS_SOURCES: Readonly<Record<string, readonly PaloaltoCompletenessEntry[]>> = {
  "PA-01": [paloaltoSource("prisma-compliance-posture", PF, "cspm")],
  "PA-02": [paloaltoSource("prisma-alert-rules", PF, "cspm"), paloaltoSource("prisma-open-alerts", PTF, "cspm")],
  "PA-03": [paloaltoSource("prisma-policies", PF, "cspm"), paloaltoSource("prisma-open-alerts", PTF, "cspm")],
  "PA-04": [paloaltoSource("prisma-cloud-accounts", PF, "cspm"), paloaltoSource("prisma-account-groups", PF, "cspm")],
  "PA-05": [paloaltoSource("prisma-policies", PF, "cspm"), paloaltoSource("prisma-open-alerts", PTF, "cspm")],
  "PA-06": [paloaltoSource("prisma-policies", PF, "cspm"), paloaltoSource("prisma-open-alerts", PTF, "cspm")],
  "PA-07": [paloaltoSource("compute-vulnerability-image-policy", PTF, "compute"), paloaltoSource("compute-images", PTF, "compute"), paloaltoSource("compute-vulnerability-stats", PTF, "compute")],
  "PA-08": [paloaltoSource("compute-compliance-host-policy", PTF, "compute"), paloaltoSource("compute-compliance-container-policy", PTF, "compute"), paloaltoSource("compute-compliance-stats", PTF, "compute"), paloaltoSource("compute-defenders", PTF, "compute")],
  "PA-09": [paloaltoSource("compute-runtime-container-policy", PTF, "compute"), paloaltoSource("compute-defenders", PTF, "compute")],
  "PA-10": [paloaltoSource("compute-defenders", PTF, "compute")],
  "PA-11": [paloaltoSource("compute-registry-settings", PTF, "compute"), paloaltoSource("compute-registry-scans", PTF, "compute")],
  "PA-12": [paloaltoSource("panos-system-info", PE, "panos"), paloaltoSource("panos-policy-config", PE, "panos")],
  "PA-13": [paloaltoSource("panos-system-info", PE, "panos"), paloaltoSource("panos-zone-config", PE, "panos"), paloaltoSource("panos-policy-config", PE, "panos")],
  "PA-14": [paloaltoSource("panos-system-info", PE, "panos"), paloaltoSource("panos-policy-config", PE, "panos"), paloaltoSource("panos-device-config", PE, "panos")],
  "PA-15": [paloaltoSource("panos-system-info", PE, "panos"), paloaltoSource("panos-globalprotect-config", PE, "panos")],
  "PA-16": [paloaltoSource("panos-system-info", PE, "panos"), paloaltoSource("panos-policy-config", PE, "panos")],
  "PA-17": [paloaltoSource("panos-system-info", PE, "panos"), paloaltoSource("panos-policy-config", PE, "panos")],
  "PA-18": [paloaltoSource("panos-system-info", PE, "panos"), paloaltoSource("panos-policy-config", PE, "panos")],
  "PA-19": [paloaltoSource("prisma-user-roles", PF, "cspm"), paloaltoSource("panos-system-info", PE, "panos"), paloaltoSource("panos-device-config", PE, "panos")],
  "PA-20": [paloaltoSource("prisma-integrations", PF, "cspm"), paloaltoSource("panos-system-info", PE, "panos"), paloaltoSource("panos-policy-config", PE, "panos"), paloaltoSource("panos-device-config", PE, "panos")],
  "PA-21": [paloaltoSource("prisma-policies", PF, "cspm"), paloaltoSource("panos-system-info", PE, "panos"), paloaltoSource("panos-policy-config", PE, "panos")],
  "PA-22": [paloaltoSource("panos-system-info", PE, "panos"), paloaltoSource("panos-policy-config", PE, "panos")],
  "PA-23": [paloaltoSource("panos-system-info", PE, "panos"), paloaltoSource("panos-device-config", PE, "panos"), paloaltoSource("panos-ha-state", PE, "panos")],
  "PA-24": [paloaltoSource("compute-cloud-discovery", PTF, "compute")],
  "PA-25": [paloaltoSource("compute-ci-scans", PTF, "compute")],
};

function paloaltoCompletenessSemantics(id: string): string {
  const entries = PALOALTO_COMPLETENESS_SOURCES[id];
  if (!entries) throw new Error(`${id} has no completeness source contract`);
  const products = [...new Set(entries.map((entry) => entry.product))];
  const sources = entries.map((entry) => `${entry.surfaceId}: ${entry.falseWhen.join(", ")} make evidence_complete false`).join("; ");
  const configurationEffect = products.length === 1
    ? `The ${products[0]} product not configured makes the finding manual and omits evidence_complete.`
    : "Only configured products participate in source gates: an unconfigured product is omitted and does not make evidence_complete false when another product is configured. With neither product configured, the manual fallback omits evidence_complete.";
  return `${configurationEffect} Exact configured-source effects: ${sources}.`;
}

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

const decisionPredicate: readonly string[] = [
  "Use the explicit passed-resource, total-resource, and minimum-pass-rate ratio rules rendered below.",
  "Fail when a readable open alert has no policy name or no severity, or when no enabled alert policy covers the observed alerts; warn for incomplete alert pagination or unevaluable alert records.",
  "Fail when a Prisma Cloud IAM alert or policy identifies excessive, administrative, or overprivileged access; warn for lower-confidence IAM review records.",
  "Fail when no cloud account is onboarded or an onboarded account is disabled or reports an error; warn for accounts with incomplete governance metadata.",
  "Fail when Prisma network-policy or alert evidence proves internet exposure; warn for review-level exposure and preserve alert truncation as incomplete evidence.",
  "Fail when an assessed cloud resource lacks encryption-at-rest or customer-managed-key evidence required by the declared predicate.",
  `Fail when no enabled image-vulnerability rule blocks or prevents, or critical CVEs exceed ${PALOALTO_DEFAULT_MAX_CRITICAL_CVES}; warn for partial image or registry evidence.`,
  `Fail when host/container compliance policy is absent or the measured compliance rate is below ${PALOALTO_DEFAULT_MIN_HOST_COMPLIANCE_RATE} percent; warn for incomplete Defender or compliance evidence.`,
  "Fail when no enabled runtime host or container protection rule has a blocking or preventive effect.",
  "Fail when the complete Defender inventory is empty or contains disconnected Defenders; partial Defender pagination warns.",
  "Fail when no registry scan configuration exists or an enabled registry is not covered by a vulnerability scan rule.",
  "Fail for enabled PAN-OS allow rules with any source, destination, application, or service and for disabled or shadowed security controls; warn for incomplete rule metadata.",
  "Fail when any enabled PAN-OS allow rule has source zone `any` or destination zone `any`. Otherwise warn unless an `intrazone-default` rule has action `deny`, an `interzone-default` rule has log-end `yes`, and every returned zone has a nonempty network.zone-protection-profile value.",
  "Fail when no enabled decryption rule applies decrypt action; warn for broad no-decrypt exceptions or incomplete profile evidence.",
  "Fail when GlobalProtect portal, gateway, tunnel, authentication-profile, or certificate-profile evidence required by the declared predicate is absent.",
  "Fail when antivirus, anti-spyware, vulnerability-protection, or security-profile-group coverage is absent from enabled security rules.",
  "Fail when WildFire analysis profiles or required file-type forwarding are absent from enabled security rules.",
  "Fail when no URL-filtering profile exists or any returned profile's block list omits malware, phishing, or command-and-control. Warn when credential-enforcement mode is absent or contains disabled, or when an enabled allow rule has no URL-filtering profile or profile group attachment.",
  "Use the explicit PAN-OS administrator, superuser, password-complexity, local-password, and Prisma-role rules rendered below.",
  "Use the explicit PAN-OS log-end, forwarding-profile, external-forwarding, and Prisma-SIEM rules rendered below.",
  "Fail when neither PAN-OS data-filtering profiles nor Prisma data-protection policy evidence provides DLP coverage; warn when only one configured product provides evidence.",
  "Fail when no file-blocking profile has a rule whose action text is block and whose file-type members contain any, pe, or PE. Warn when an enabled allow rule has no file-blocking profile or profile group attachment.",
  "Fail when any readable device has no NTP server, an SNMP community equal to public or private ignoring case, disable-telnet equal to no, or disable-http equal to no. Otherwise warn when the login banner is absent, permitted management IPs are empty, idle-timeout is absent, zero, or above 15 minutes, or primary DNS is absent.",
  "Fail when Prisma cloud-discovery evidence identifies unsanctioned services or no discovery inventory is readable; incomplete discovery warns.",
  "Fail when CI scan results contain a failed or vulnerable build, or when no CI scanning evidence exists; partial CI pagination warns.",
] as const;

function paloaltoDecision(control: number): Partial<Pick<Batch2CheckRow, "decisionInputs" | "decisionRules" | "constants">> | undefined {
  if (control === 1) {
    return {
      constants: {
        default_minimum_pass_rate_percent: PALOALTO_DEFAULT_MIN_COMPLIANCE_PASS_RATE,
        warning_margin_percentage_points: 20,
      },
      decisionInputs: {
        evidence_readable: "Boolean. True only when the Prisma compliance posture summary was readable.",
        evidence_complete: "Boolean. True only when the posture inventory was complete; false means the result is partial.",
        passed_resource_count: "Non-negative integer from summary.passedResources; null means the field was unavailable.",
        total_resource_count: "Non-negative integer from summary.totalResources, or the complete sum of passedResources and failedResources when totalResources is absent; zero means no evaluated resources.",
        minimum_pass_rate_percent: `Number from the minCompliancePassRate operator option after clamping to 1 through 100; the default is ${PALOALTO_DEFAULT_MIN_COMPLIANCE_PASS_RATE}.`,
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
  if (control === 13) {
    return {
      decisionInputs: {
        evidence_readable: "Boolean. True only when every configured PAN-OS device returned both its zone configuration and security/default-rule policy subtrees.",
        evidence_complete: "Boolean. True when all configured PAN-OS snapshots and required configuration subtrees were readable; PAN-OS configuration reads are not paged.",
        zone_count: "Non-negative integer count of every returned PAN-OS zone before the evidence list is capped.",
        any_zone_allow_rule_count: "Non-negative integer count of enabled security rules whose action is `allow` and whose source-zone list or destination-zone list contains `any`.",
        intrazone_default_denied: "Boolean. True when a returned default security rule named `intrazone-default` has action exactly `deny`.",
        interzone_default_logs_at_end: "Boolean. True when a returned default security rule named `interzone-default` has log-end exactly `yes`.",
        zone_without_protection_profile_count: "Non-negative integer count of returned zones whose network.zone-protection-profile value is absent or empty.",
      },
      decisionRules: [
        batch2Rule("manual", batch2Any(
          batch2Ne("evidence_readable", true),
          batch2Eq("zone_count", 0),
        )),
        batch2Rule("fail", batch2Gt("any_zone_allow_rule_count", 0)),
        batch2Rule("warn", batch2Any(
          batch2Ne("evidence_complete", true),
          batch2Ne("intrazone_default_denied", true),
          batch2Ne("interzone_default_logs_at_end", true),
          batch2Gt("zone_without_protection_profile_count", 0),
        )),
        batch2Rule("pass", { op: "always" }),
      ],
    };
  }
  return undefined;
}

const checks = batch2Checks(titles.map((title, index) => {
  const control = index + 1;
  const id = `PA-${String(control).padStart(2, "0")}`;
  const genericDecisionInputs = batch2GenericDecisionInputs(decisionPredicate[index]);
  const decisionRules = control === 10 || control === 25
    ? [
        batch2Rule("manual", batch2Ne("evidence_readable", true)),
        batch2Rule("fail", batch2Gt("violation_count", 0)),
        ...completePassRules,
      ]
    : undefined;
  const custom = paloaltoDecision(control);
  const decisionInputs = custom?.decisionInputs ?? (control === 10 || control === 25
    ? {
        evidence_readable: genericDecisionInputs.evidence_readable,
        evidence_complete: genericDecisionInputs.evidence_complete,
        violation_count: genericDecisionInputs.violation_count,
        review_count: genericDecisionInputs.review_count,
      }
    : genericDecisionInputs);
  const completenessSources = PALOALTO_COMPLETENESS_SOURCES[id];
  const sourceIds = completenessSources.map((source) => source.surfaceId);
  return {
    id,
    control,
    title,
    severity: severities[index],
    owner: owner(control),
    surfaces: sourceIds,
    emptyOutcome: "manual" as const,
    constants: ({
      7: { maximum_critical_cves: PALOALTO_DEFAULT_MAX_CRITICAL_CVES },
      8: { minimum_host_compliance_rate_percent: PALOALTO_DEFAULT_MIN_HOST_COMPLIANCE_RATE },
      19: { default_maximum_superusers: PALOALTO_DEFAULT_MAX_SUPERUSERS },
    } as const)[control as 7 | 8 | 19],
    decisionRules,
    decisionInputs,
    ...custom,
    completeness: batch2Completeness(
      decisionInputs,
      completenessSources.map(({ surfaceId, falseWhen }) => ({ surfaceId, falseWhen })),
      paloaltoCompletenessSemantics(id),
    ),
    decision: `${decisionPredicate[index]} Unreadable configured-product evidence remains manual, a proved violation has first-match precedence, and partial evidence cannot pass.`,
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
    { id: "prisma-read-role", kind: "role", value: "Prisma Cloud read access to compliance, alerts, policies, accounts, roles, integrations, and configured Compute surfaces", unlocks: surfaces.filter((surface) => surface.id.startsWith("prisma-") || surface.id.startsWith("compute-")).map((surface) => surface.id) },
    { id: "panos-read-role", kind: "role", value: "PAN-OS XML API operational and configuration read access", unlocks: surfaces.filter((surface) => surface.id.startsWith("panos-")).map((surface) => surface.id) },
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
    surfaceIds: surfaces.filter((surface) => surface.id.startsWith("prisma-") || surface.id.startsWith("compute-")).map((surface) => surface.id),
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
