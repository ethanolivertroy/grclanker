import { buildBatchIntegrationSpec, type BatchCheckDefinition } from "./batch-spec-builder.js";

const groups = {
  AUTH: [
    "Phishing-resistant authentication methods",
    "Deprecated authentication methods restricted",
    "New user enrollment policy",
    "Remembered devices posture",
    "Trusted endpoints and device health",
    "Bypass code hygiene",
    "Global MFA enforcement mode",
    "User enrollment completeness",
    "Inactive user detection",
    "WebAuthn and U2F credential adoption",
    "Offline access configuration",
  ],
  ADMIN: [
    "Owner and privileged admin concentration",
    "Administrator authentication strength",
    "Help desk bypass governance",
    "Stale privileged administrator review",
    "User lockout policy",
  ],
  INTEGRATIONS: [
    "Protected integrations have explicit policy coverage",
    "Universal Prompt adoption",
    "Self-service portal governance",
    "Administrative API integration permissions",
    "Critical application protection coverage",
    "Device health requirements depth",
  ],
  MON: [
    "Authentication log visibility and factor hygiene",
    "Trust Monitor coverage",
    "Telephony reliance and credit headroom",
    "Administrative and fraud notifications",
    "Authentication outcome and travel anomalies",
  ],
} as const;

const ownerFor = (group: keyof typeof groups): string => ({
  AUTH: "duo_assess_authentication",
  ADMIN: "duo_assess_admin_access",
  INTEGRATIONS: "duo_assess_integrations",
  MON: "duo_assess_monitoring",
})[group];

const checks: BatchCheckDefinition[] = Object.entries(groups).flatMap(([groupName, titles]) => {
  const group = groupName as keyof typeof groups;
  return titles.map((title, index) => ({
    id: `DUO-${group}-${String(index + 1).padStart(3, "0")}`,
    control: Object.values(groups).slice(0, Object.keys(groups).indexOf(group)).reduce((sum, entries) => sum + entries.length, 0) + index + 1,
    title,
    severity: /MFA|privileged|bypass|Critical|API integration/i.test(title) ? "high" : "medium",
    owner: ownerFor(group),
  }));
});

const idsFor = (owner: string): string[] => checks.filter((check) => check.owner === owner).map((check) => check.id);

export const DUO_RUNTIME_BEHAVIOR = [
  "Duo edition and endpoint availability gaps are explicit manual findings; a denied Admin API surface never becomes an empty compliant inventory.",
  "The Admin API offset walker records cap, repeated offset, empty-page, missing-total, and total-mismatch exits as incomplete evidence.",
  "Trust Monitor analysis is limited to the fields returned by the shipped Admin API collector and does not implement the deeper trend analysis described by the historical design.",
] as const;

export const DUO_SPEC = buildBatchIntegrationSpec({
  slug: "duo-sec-inspector",
  displayName: "Duo Security Inspector",
  vendor: "Cisco Duo",
  category: "identity-and-access",
  summary: "Portable contract for the shipped Duo authentication, administrator, protected-application, and monitoring assessments.",
  sourceModule: "cli/extensions/grc-tools/duo.ts",
  baseServices: ["Duo Admin API"],
  authentication: {
    modes: ["Duo Admin API HMAC integration key and secret key"],
    precedence: ["Explicit tool arguments", "Explicit config file", "DUO_* environment variables"],
    environment: ["DUO_IKEY", "DUO_SKEY", "DUO_API_HOSTNAME", "DUO_CONFIG_FILE"],
    configLocations: ["Explicit JSON or YAML config file"],
    variants: ["Commercial and FedRAMP Duo API hostnames selected by api_hostname"],
    configFields: ["integrationKey", "secretKey", "apiHostname", "timeoutMs"],
  },
  permissions: ["Grant resource - Read", "Grant administrators - Read", "Grant settings - Read", "Grant logs - Read", "Grant information - Read"],
  surfaces: [
    { id: "settings", path: "/admin/v1/settings", service: "Duo Admin API", documentationUrl: "https://duo.com/docs/adminapi", fields: ["global_policy", "user_lockout", "notifications", "helpdesk_bypass"] },
    { id: "policies", path: "/admin/v2/policies", service: "Duo Admin API", documentationUrl: "https://duo.com/docs/adminapi#policies", fields: ["policy_id", "name", "authentication_methods", "remembered_devices", "device_health"] },
    { id: "users", path: "/admin/v1/users", service: "Duo Admin API", documentationUrl: "https://duo.com/docs/adminapi#users", fields: ["user_id", "username", "status", "last_login", "is_enrolled"] },
    { id: "integrations", path: "/admin/v3/integrations", service: "Duo Admin API", documentationUrl: "https://duo.com/docs/adminapi#integrations", fields: ["integration_key", "name", "type", "policy", "prompt_type"] },
    { id: "authentication-logs", path: "/admin/v2/logs/authentication", service: "Duo Admin API", documentationUrl: "https://duo.com/docs/adminapi#authentication-logs", fields: ["timestamp", "result", "reason", "factor", "access_device", "location"] },
  ],
  checks,
  tools: {
    duo_check_access: [],
    duo_assess_authentication: idsFor("duo_assess_authentication"),
    duo_assess_admin_access: idsFor("duo_assess_admin_access"),
    duo_assess_integrations: idsFor("duo_assess_integrations"),
    duo_assess_monitoring: idsFor("duo_assess_monitoring"),
    duo_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: {
    cursorFields: ["offset", "next_offset", "metadata.total_objects"],
    pageSize: 500,
    itemCap: null,
    pageCap: 1000,
    totalSemantics: "metadata.total_objects is authoritative when present; seen records below that total are truncated.",
    stopConditions: ["Proven total reached", "No next offset", "Configured item cap", "Page cap", "Repeated offset", "Empty page with offset", "Missing or inconsistent total"],
  },
  rateLimit: {
    documentedLimit: "Duo applies integration- and endpoint-specific limits",
    retryHeaders: ["Retry-After", "X-RateLimit-Remaining"],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "Honor bounded Retry-After, otherwise use bounded exponential retry and surface exhaustion.",
  },
  runtimeBehavior: DUO_RUNTIME_BEHAVIOR,
  knownGaps: ["Auth API and Accounts API authentication modes, richer Trust Monitor analysis, and trend reporting are not shipped."],
  sensitiveFields: ["skey", "integration_key", "authorization", "cookie", "bypass_code"],
  credentialFormats: ["Duo integration keys", "Duo secret keys", "HMAC Authorization signatures"],
  outputPrefix: "duo-audit",
});
