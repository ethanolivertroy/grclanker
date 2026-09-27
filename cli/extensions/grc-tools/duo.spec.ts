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

const decisions = {
  AUTH: [
    "return pass when the global policy allows WebAuthn or requires Verified Duo Push, warn when only ordinary Duo Push or supporting administrator hardening exists, and fail when neither phishing-resistant option is present.",
    "return pass only when both SMS and phone callback are explicitly blocked, fail when neither is blocked, warn when only one is blocked or telephony is explicitly allowed alongside a partial block, and manual when the allow and block lists are absent.",
    "return pass for new_user_behavior=enroll, fail for no-mfa, warn for any other readable behavior, and manual when the value is absent.",
    "return pass when remembered devices are disabled or last at most 14 days, warn for 15 through 30 days, fail above 30 days, and manual when the duration cannot be normalized.",
    "return pass for trusted_endpoint_checking=require-trusted, warn for allow-all, and fail for any other readable configuration.",
    "return pass only for an empty bypass-code inventory with readable help-desk limits, fail when any unexpired code is older than 24 hours, has unlimited uses, lacks expiration, or help-desk issuance is unlimited, and warn for every other non-empty or undated inventory.",
    "return pass for user_auth_behavior=enforce, fail for bypass, warn for another readable value such as deny, and manual when the authentication policy or value is absent.",
    "for users with known enrollment state, return pass when all active users are enrolled and none has bypass status, warn when at least 90 percent are enrolled with no bypass users, and fail otherwise.",
    "for a non-empty active-or-bypass population, return pass when every last-login date is present and no login is older than 90 days, warn when dates are missing or at most 10 percent are stale, and fail when more than 10 percent are stale.",
    "for enrolled users, return pass when at least 75 percent have WebAuthn and none has deprecated U2F, warn when any user has WebAuthn but that bar is not met, and fail when none has WebAuthn.",
    "always return manual because the Admin API exposes offline-enrollment events but not the offline-access policy limits.",
  ],
  ADMIN: [
    "for a non-empty administrator inventory, return pass with at most two active owners, warn when owners are at most the greater of three or half of all administrators, and fail above that bound.",
    "return pass when WebAuthn or Verified Duo Push is enabled and SMS and voice are disabled, warn when a strong method is enabled alongside SMS or voice, and fail when neither strong method is enabled.",
    "return pass for helpdesk_bypass=deny, warn for limit with a positive expiration, and fail for every other readable setting.",
    "return pass when every active administrator has a parseable last login no older than 90 days, warn for missing dates or a smaller stale set, and fail when stale administrators are at least one third of active administrators.",
    "return fail when the numeric lockout threshold is zero or negative, pass from one through ten failed attempts, warn above ten, and manual when the threshold is absent or nonnumeric.",
  ],
  INTEGRATIONS: [
    "for non-empty active protected integrations, return pass when every integration has a policy key, warn when only some do, and fail when none do; an empty readable inventory is warn.",
    "for integrations exposing prompt posture, return pass when all use Universal Prompt, warn when only some do, and fail when none do.",
    "return pass when every protected integration exposing self_service_allowed disables it, warn when only some disable it or the protected inventory is empty, fail when all exposed values enable it, and manual when no integration exposes the field.",
    "return pass when all visible Admin API integrations omit write, settings, integration-management, and permission-management grants, warn when only some are overprivileged or the inventory omits the audit integration, and fail when all are overprivileged.",
    "for protected applications tagged Critical, High, or regulated, return pass when each has an explicit policy, warn when only some do, fail when none do, and manual when no protected application has usable criticality tags.",
    "evaluate five groups: Duo Desktop, encryption, firewall, system-password or screen-lock, and operating-system restrictions; return pass for all five, fail for none, warn for one through four, and manual when the tenant edition exposes no device-health sections.",
  ],
  MON: [
    "return pass for a non-empty authentication-log window with no bypass, SMS, phone, or fraud events; warn when the window is empty or any such event exists.",
    "return pass when the Trust Monitor window contains events and warn when its complete window is empty.",
    "return fail when telephony use exists and credits are below 25, warn when telephony use exists or credits are below 100, pass otherwise, and manual when credits or logs are unreadable.",
    "return pass when any fraud-email, push-activity, or email-activity notification is enabled and warn when all readable notification signals are false or absent.",
    "return fail for any successful country change within 60 minutes, warn for fraud or a denied-attempt share above 20 percent, pass otherwise, manual when counts or all location fields are absent, and warn when both summary and event windows are empty.",
  ],
} as const;

const checks: BatchCheckDefinition[] = Object.entries(groups).flatMap(([groupName, titles]) => {
  const group = groupName as keyof typeof groups;
  return titles.map((title, index) => ({
    id: `DUO-${group}-${String(index + 1).padStart(3, "0")}`,
    control: Object.values(groups).slice(0, Object.keys(groups).indexOf(group)).reduce((sum, entries) => sum + entries.length, 0) + index + 1,
    title,
    severity: /MFA|privileged|bypass|Critical|API integration/i.test(title) ? "high" : "medium",
    owner: ownerFor(group),
    decision: decisions[group][index],
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
