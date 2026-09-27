import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
  type BatchCheckDefinition,
  type BatchSurfaceDefinition,
} from "./batch-spec-builder.js";

const DUO_SURFACES: readonly BatchSurfaceDefinition[] = [
  ["settings", "/admin/v1/settings", ["helpdesk_bypass", "user_lockout", "notifications"]],
  ["info-summary", "/admin/v1/info/summary", ["telephony_credits_remaining", "user_count", "integration_count"]],
  ["authentication-attempts", "/admin/v1/info/authentication_attempts", ["count", "result", "reason"]],
  ["admin-auth-methods", "/admin/v1/admins/allowed_auth_methods", ["webauthn", "duo_push", "sms", "phone"]],
  ["global-policy", "/admin/v2/policies/global", ["authentication_methods", "new_user_policy", "remembered_devices", "trusted_endpoints", "device_health"]],
  ["policies", "/admin/v2/policies", ["policy_id", "name", "authentication_methods", "remembered_devices", "device_health"]],
  ["users", "/admin/v1/users", ["user_id", "username", "status", "last_login", "is_enrolled"]],
  ["bypass-codes", "/admin/v1/bypass_codes", ["user_id", "created", "expires", "remaining_uses"]],
  ["webauthn-credentials", "/admin/v1/webauthncredentials", ["user_id", "credential_name", "date_added"]],
  ["admins", "/admin/v1/admins", ["admin_id", "name", "role", "status", "last_login"]],
  ["integrations", "/admin/v3/integrations", ["integration_key", "name", "type", "policy", "prompt_type", "permissions"]],
  ["authentication-logs", "/admin/v2/logs/authentication", ["timestamp", "result", "reason", "factor", "access_device", "location"]],
  ["activity-logs", "/admin/v2/logs/activity", ["timestamp", "action", "username", "description"]],
  ["telephony-logs", "/admin/v2/logs/telephony", ["timestamp", "type", "context", "credits"]],
  ["offline-enrollment-logs", "/admin/v1/logs/offline_enrollment", ["timestamp", "username", "action", "application"]],
  ["trust-monitor-events", "/admin/v1/trust_monitor/events", ["id", "type", "timestamp", "risk", "location"]],
].map(([id, path, fields]) => ({
  id: id as string,
  path: path as string,
  service: "Duo Admin API",
  documentationUrl: "https://duo.com/docs/adminapi",
  fields: fields as string[],
}));

const DUO_CHECK_SURFACES: Readonly<Record<string, readonly string[]>> = {
  "DUO-AUTH-001": ["global-policy"], "DUO-AUTH-002": ["global-policy"], "DUO-AUTH-003": ["global-policy"],
  "DUO-AUTH-004": ["global-policy"], "DUO-AUTH-005": ["global-policy"], "DUO-AUTH-006": ["bypass-codes", "settings"],
  "DUO-AUTH-007": ["global-policy"], "DUO-AUTH-008": ["users"], "DUO-AUTH-009": ["users"],
  "DUO-AUTH-010": ["users", "webauthn-credentials"], "DUO-AUTH-011": ["global-policy", "offline-enrollment-logs"],
  "DUO-ADMIN-001": ["admins"], "DUO-ADMIN-002": ["admin-auth-methods", "global-policy"],
  "DUO-ADMIN-003": ["settings"], "DUO-ADMIN-004": ["admins"], "DUO-ADMIN-005": ["settings"],
  "DUO-INTEGRATIONS-001": ["integrations"], "DUO-INTEGRATIONS-002": ["integrations"],
  "DUO-INTEGRATIONS-003": ["integrations"], "DUO-INTEGRATIONS-004": ["integrations"],
  "DUO-INTEGRATIONS-005": ["integrations"], "DUO-INTEGRATIONS-006": ["global-policy"],
  "DUO-MON-001": ["authentication-logs"], "DUO-MON-002": ["trust-monitor-events"],
  "DUO-MON-003": ["info-summary", "telephony-logs"], "DUO-MON-004": ["settings"],
  "DUO-MON-005": ["authentication-attempts", "authentication-logs"],
};

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
    surfaces: DUO_CHECK_SURFACES[`DUO-${group}-${String(index + 1).padStart(3, "0")}`],
    evidenceFields: [...DUO_CHECK_SURFACES[`DUO-${group}-${String(index + 1).padStart(3, "0")}`], "complete_source_counts"],
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
  permissions: [
    { id: "resource-read", kind: "role", value: "Grant resource - Read", unlocks: ["global-policy", "policies", "users", "bypass-codes", "webauthn-credentials", "integrations", "offline-enrollment-logs"] },
    { id: "admins-read", kind: "role", value: "Grant administrators - Read", unlocks: ["admins", "admin-auth-methods"] },
    { id: "settings-read", kind: "role", value: "Grant settings", unlocks: ["settings"] },
    { id: "logs-read", kind: "role", value: "Grant read log", unlocks: ["authentication-logs", "activity-logs", "telephony-logs", "offline-enrollment-logs", "trust-monitor-events"] },
    { id: "information-read", kind: "role", value: "Grant read information", unlocks: ["info-summary", "authentication-attempts"] },
  ],
  surfaces: DUO_SURFACES,
  checks,
  tools: {
    duo_check_access: [],
    duo_assess_authentication: idsFor("duo_assess_authentication"),
    duo_assess_admin_access: idsFor("duo_assess_admin_access"),
    duo_assess_integrations: idsFor("duo_assess_integrations"),
    duo_assess_monitoring: idsFor("duo_assess_monitoring"),
    duo_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [
    {
      surfaceIds: ["policies", "users", "bypass-codes", "webauthn-credentials", "admins", "integrations"],
      cursorFields: ["offset", "metadata.next_offset", "metadata.total_objects"],
      pageSize: 100,
      itemCap: null,
      pageCap: 1000,
      totalSemantics: "metadata.total_objects is authoritative when present; seen records below that total are incomplete.",
      stopConditions: ["Total reached", "No next_offset", "Page cap", "Repeated offset", "Empty page with offset", "Missing or inconsistent total"],
    },
    {
      surfaceIds: ["authentication-logs", "activity-logs", "telephony-logs", "trust-monitor-events"],
      cursorFields: ["metadata.next_offset"],
      pageSize: 200,
      itemCap: 400,
      pageCap: 1000,
      totalSemantics: "Log walks are complete only when next_offset is absent before the caller record cap.",
      stopConditions: ["No next_offset", "400-record cap", "Repeated offset", "Empty page with offset", "Page cap"],
    },
    {
      surfaceIds: ["offline-enrollment-logs"],
      cursorFields: ["mintime", "timestamp"],
      pageSize: 1000,
      itemCap: 5000,
      pageCap: 5,
      totalSemantics: "Advance mintime from the latest event; the 5,000-record cap leaves the dataset incomplete.",
      stopConditions: ["Short page", "5,000-record cap", "Timestamp fails to advance"],
    },
  ],
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
  output: buildBatchOutputContract({
    files: [
      "QUICK_REFERENCE.md", "config.json", "core_data/settings.json", "core_data/policies.json", "core_data/global_policy.json",
      "core_data/users.json", "core_data/bypass_codes.json", "core_data/webauthn_credentials.json",
      "core_data/admin_allowed_auth_methods.json", "core_data/authentication_logs.json", "core_data/offline_enrollment_logs.json",
      "core_data/admins.json", "core_data/activity_logs.json", "core_data/integrations.json", "core_data/info_summary.json",
      "core_data/telephony_logs.json", "core_data/trust_monitor_events.json", "core_data/authentication_attempts.json",
      "core_data/collection_status.json", "analysis/authentication.json", "analysis/admin_access.json",
      "analysis/integrations.json", "analysis/monitoring.json", "analysis/findings.json",
      "compliance/executive_summary.md", "compliance/unified_compliance_matrix.md",
      "compliance/fedramp/fedramp_compliance_report.md", "compliance/cmmc/cmmc_compliance_report.md",
      "compliance/soc2/soc2_compliance_report.md", "compliance/cis/cis_compliance_report.md",
      "compliance/pci_dss/pci_dss_compliance_report.md", "compliance/disa_stig/stig_compliance_checklist.md",
      "compliance/irap/irap_compliance_report.md", "compliance/ismap/ismap_compliance_report.md",
    ],
    conditionalFiles: ["_errors.log"],
    overwritePolicy: "Allocate a timestamped <api-host> directory and add a numeric suffix if that directory already exists; allocate the archive independently without overwriting.",
    archivePairing: "Create a zip named from the allocated directory beside it; if that zip exists, add an independent numeric suffix.",
  }),
});
