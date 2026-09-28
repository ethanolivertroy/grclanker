import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
  type BatchCheckDefinition,
  type BatchSurfaceDefinition,
} from "./batch-spec-builder.js";
import { DUO_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import type { PortableValue, VerdictCondition, VerdictRule } from "./spec-model.js";

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

interface DuoExecutableDecision {
  inputs: Readonly<Record<string, string>>;
  constants?: Readonly<Record<string, PortableValue>>;
  rules: readonly VerdictRule[];
}

const value = (entry: PortableValue) => ({ kind: "value" as const, value: entry });
const path = (name: string) => ({ kind: "path" as const, path: name });
const compare = (
  op: "eq" | "ne" | "gt" | "gte" | "lt" | "lte",
  name: string,
  entry: PortableValue,
): VerdictCondition => ({ op, left: path(name), right: value(entry) });
const eq = (name: string, entry: PortableValue): VerdictCondition => compare("eq", name, entry);
const ne = (name: string, entry: PortableValue): VerdictCondition => compare("ne", name, entry);
const gt = (name: string, entry: PortableValue): VerdictCondition => compare("gt", name, entry);
const gte = (name: string, entry: PortableValue): VerdictCondition => compare("gte", name, entry);
const lte = (name: string, entry: PortableValue): VerdictCondition => compare("lte", name, entry);
const all = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "and", conditions });
const any = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "or", conditions });
const notDefined = (name: string): VerdictCondition => ({
  op: "not",
  condition: { op: "defined", operand: path(name) },
});
const rule = (status: VerdictRule["status"], condition: VerdictCondition, note?: string): VerdictRule => ({
  status,
  condition,
  ...(note ? { note } : {}),
});
const ordered = (branches: {
  fail?: VerdictCondition;
  manual?: VerdictCondition;
  warn?: VerdictCondition;
  pass?: VerdictCondition;
  failFirst?: boolean;
}): readonly VerdictRule[] => [
  ...(branches.failFirst && branches.fail ? [rule("fail", branches.fail, "A proven violation retains precedence over incomplete companion evidence.")] : []),
  ...(branches.manual ? [rule("manual", branches.manual)] : []),
  ...(!branches.failFirst && branches.fail ? [rule("fail", branches.fail)] : []),
  ...(branches.warn ? [rule("warn", branches.warn)] : []),
  ...(branches.pass ? [rule("pass", branches.pass)] : []),
  rule("manual", { op: "always" }, "Unknown or contradictory evidence requires manual review."),
];
const input = (...names: string[]): Readonly<Record<string, string>> => Object.fromEntries(
  names.map((name) => [name, `Runtime-owned ${name.replaceAll("_", " ")} computed from the complete declared source inventories.`]),
);
const unreadable = ne("readable", true);
const incomplete = ne("complete", true);

const DUO_EXECUTABLE_DECISIONS: Readonly<Record<string, DuoExecutableDecision>> = {
  "DUO-AUTH-001": {
    inputs: input("policy_readable", "has_webauthn", "allows_push", "requires_verified_push", "supporting_strong_method_count"),
    rules: ordered({
      manual: ne("policy_readable", true),
      warn: all(
        eq("has_webauthn", false),
        { op: "not", condition: all(eq("allows_push", true), eq("requires_verified_push", true)) },
        any(eq("allows_push", true), gt("supporting_strong_method_count", 0)),
      ),
      pass: any(eq("has_webauthn", true), all(eq("allows_push", true), eq("requires_verified_push", true))),
      fail: all(eq("has_webauthn", false), eq("allows_push", false), eq("supporting_strong_method_count", 0)),
    }),
  },
  "DUO-AUTH-002": {
    inputs: input("policy_readable", "allowed_list_exposed", "blocked_list_exposed", "explicitly_allowed_telephony_count", "blocked_telephony_count", "permitted_telephony_count"),
    rules: ordered({
      manual: any(
        ne("policy_readable", true),
        all(ne("allowed_list_exposed", true), ne("blocked_list_exposed", true)),
        all(ne("blocked_list_exposed", true), eq("explicitly_allowed_telephony_count", 0)),
      ),
      fail: all(
        any(gt("explicitly_allowed_telephony_count", 0), gt("permitted_telephony_count", 0)),
        eq("blocked_telephony_count", 0),
      ),
      warn: any(gt("explicitly_allowed_telephony_count", 0), gt("permitted_telephony_count", 0)),
      pass: eq("permitted_telephony_count", 0),
    }),
  },
  "DUO-AUTH-003": {
    inputs: input("new_user_behavior"),
    rules: ordered({
      manual: notDefined("new_user_behavior"),
      fail: eq("new_user_behavior", "no-mfa"),
      warn: ne("new_user_behavior", "enroll"),
      pass: eq("new_user_behavior", "enroll"),
    }),
  },
  "DUO-AUTH-004": {
    inputs: input("policy_readable", "remembered_device_days"),
    constants: { pass_maximum_days: 14, warn_maximum_days: 30 },
    rules: ordered({
      manual: any(ne("policy_readable", true), notDefined("remembered_device_days")),
      fail: gt("remembered_device_days", 30),
      warn: gt("remembered_device_days", 14),
      pass: lte("remembered_device_days", 14),
    }),
  },
  "DUO-AUTH-005": {
    inputs: input("policy_readable", "trusted_endpoint_checking"),
    rules: ordered({
      manual: ne("policy_readable", true),
      fail: all(ne("trusted_endpoint_checking", "require-trusted"), ne("trusted_endpoint_checking", "allow-all")),
      warn: eq("trusted_endpoint_checking", "allow-all"),
      pass: eq("trusted_endpoint_checking", "require-trusted"),
    }),
  },
  "DUO-AUTH-006": {
    inputs: input("readable", "complete", "settings_readable", "bypass_code_count", "flagged_code_count", "undated_code_count", "helpdesk_bypass", "helpdesk_bypass_expiration"),
    constants: { maximum_age_hours: 24 },
    rules: ordered({
      manual: unreadable,
      fail: any(
        gt("flagged_code_count", 0),
        eq("helpdesk_bypass", "allow"),
        all(eq("helpdesk_bypass", "limit"), lte("helpdesk_bypass_expiration", 0)),
      ),
      warn: any(incomplete, ne("settings_readable", true), gt("bypass_code_count", 0), gt("undated_code_count", 0)),
      pass: eq("bypass_code_count", 0),
    }),
  },
  "DUO-AUTH-007": {
    inputs: input("policy_readable", "user_auth_behavior"),
    rules: ordered({
      manual: any(ne("policy_readable", true), notDefined("user_auth_behavior")),
      fail: eq("user_auth_behavior", "bypass"),
      warn: ne("user_auth_behavior", "enforce"),
      pass: eq("user_auth_behavior", "enforce"),
    }),
  },
  "DUO-AUTH-008": {
    inputs: input("readable", "complete", "user_count", "known_enrollment_count", "bypass_user_count", "unenrolled_user_count", "enrollment_percent"),
    constants: { warning_minimum_percent: 90 },
    rules: ordered({
      manual: any(unreadable, eq("user_count", 0), eq("known_enrollment_count", 0)),
      fail: any(
        gt("bypass_user_count", 0),
        all(gt("unenrolled_user_count", 0), { op: "lt", left: path("enrollment_percent"), right: value(90) }),
      ),
      warn: any(incomplete, gt("unenrolled_user_count", 0)),
      pass: all(eq("bypass_user_count", 0), eq("unenrolled_user_count", 0)),
    }),
  },
  "DUO-AUTH-009": {
    inputs: input("readable", "complete", "access_user_count", "inactive_user_count", "undated_user_count", "inactive_percent"),
    constants: { inactive_days: 90, failure_percent: 10 },
    rules: ordered({
      manual: any(unreadable, eq("access_user_count", 0)),
      fail: gt("inactive_percent", 10),
      warn: any(incomplete, gt("inactive_user_count", 0), gt("undated_user_count", 0)),
      pass: all(eq("inactive_user_count", 0), eq("undated_user_count", 0)),
    }),
  },
  "DUO-AUTH-010": {
    inputs: input("readable", "complete", "enrolled_user_count", "webauthn_user_count", "deprecated_u2f_user_count", "adoption_percent"),
    constants: { pass_minimum_percent: 75 },
    rules: ordered({
      manual: any(unreadable, eq("enrolled_user_count", 0)),
      fail: eq("webauthn_user_count", 0),
      warn: any(incomplete, { op: "lt", left: path("adoption_percent"), right: value(75) }, gt("deprecated_u2f_user_count", 0)),
      pass: all(gte("adoption_percent", 75), eq("deprecated_u2f_user_count", 0)),
    }),
  },
  "DUO-AUTH-011": {
    inputs: {},
    rules: [rule("manual", { op: "always" })],
  },
  "DUO-ADMIN-001": {
    inputs: input("readable", "complete", "admin_count", "owner_count", "warning_owner_maximum"),
    constants: { pass_maximum: 2 },
    rules: ordered({
      manual: any(unreadable, eq("admin_count", 0)),
      fail: gt("owner_count", 0),
      warn: any(incomplete, gt("owner_count", 2)),
      pass: lte("owner_count", 2),
    }).map((entry, index) => index === 1
      ? rule("fail", { op: "gt", left: path("owner_count"), right: path("warning_owner_maximum") })
      : entry),
  },
  "DUO-ADMIN-002": {
    inputs: input("readable", "strong_method_enabled", "weak_method_enabled"),
    rules: ordered({
      manual: unreadable,
      fail: ne("strong_method_enabled", true),
      warn: eq("weak_method_enabled", true),
      pass: eq("weak_method_enabled", false),
    }),
  },
  "DUO-ADMIN-003": {
    inputs: input("readable", "helpdesk_bypass", "helpdesk_bypass_expiration"),
    rules: ordered({
      manual: unreadable,
      fail: all(
        ne("helpdesk_bypass", "deny"),
        { op: "not", condition: all(eq("helpdesk_bypass", "limit"), gt("helpdesk_bypass_expiration", 0)) },
      ),
      warn: all(eq("helpdesk_bypass", "limit"), gt("helpdesk_bypass_expiration", 0)),
      pass: eq("helpdesk_bypass", "deny"),
    }),
  },
  "DUO-ADMIN-004": {
    inputs: input("readable", "complete", "admin_count", "stale_admin_count", "undated_admin_count", "stale_at_least_one_third"),
    constants: { inactive_days: 90 },
    rules: ordered({
      manual: any(unreadable, eq("admin_count", 0)),
      fail: eq("stale_at_least_one_third", true),
      warn: any(incomplete, gt("stale_admin_count", 0), gt("undated_admin_count", 0)),
      pass: all(eq("stale_admin_count", 0), eq("undated_admin_count", 0)),
    }),
  },
  "DUO-ADMIN-005": {
    inputs: input("readable", "lockout_threshold"),
    constants: { pass_maximum: 10 },
    rules: ordered({
      manual: any(unreadable, notDefined("lockout_threshold")),
      fail: lte("lockout_threshold", 0),
      warn: gt("lockout_threshold", 10),
      pass: all(gt("lockout_threshold", 0), lte("lockout_threshold", 10)),
    }),
  },
  "DUO-INTEGRATIONS-001": {
    inputs: input("readable", "complete", "protected_integration_count", "policy_attached_count"),
    rules: ordered({
      manual: unreadable,
      fail: all(gt("protected_integration_count", 0), eq("policy_attached_count", 0)),
      warn: any(incomplete, eq("protected_integration_count", 0), {
        op: "lt",
        left: path("policy_attached_count"),
        right: path("protected_integration_count"),
      }),
      pass: { op: "eq", left: path("policy_attached_count"), right: path("protected_integration_count") },
    }),
  },
  "DUO-INTEGRATIONS-002": {
    inputs: input("readable", "complete", "applicable_integration_count", "universal_prompt_count"),
    rules: ordered({
      manual: any(unreadable, eq("applicable_integration_count", 0)),
      fail: eq("universal_prompt_count", 0),
      warn: any(incomplete, {
        op: "lt",
        left: path("universal_prompt_count"),
        right: path("applicable_integration_count"),
      }),
      pass: { op: "eq", left: path("universal_prompt_count"), right: path("applicable_integration_count") },
    }),
  },
  "DUO-INTEGRATIONS-003": {
    inputs: input("readable", "complete", "protected_integration_count", "field_exposed_count", "self_service_enabled_count"),
    rules: ordered({
      manual: any(unreadable, all(gt("protected_integration_count", 0), eq("field_exposed_count", 0))),
      fail: all(gt("field_exposed_count", 0), {
        op: "eq",
        left: path("self_service_enabled_count"),
        right: path("field_exposed_count"),
      }),
      warn: any(incomplete, eq("protected_integration_count", 0), gt("self_service_enabled_count", 0)),
      pass: all(gt("field_exposed_count", 0), eq("self_service_enabled_count", 0)),
    }),
  },
  "DUO-INTEGRATIONS-004": {
    inputs: input("readable", "complete", "admin_api_count", "overprivileged_admin_api_count"),
    rules: ordered({
      manual: unreadable,
      fail: all(gt("admin_api_count", 0), {
        op: "eq",
        left: path("overprivileged_admin_api_count"),
        right: path("admin_api_count"),
      }),
      warn: any(incomplete, eq("admin_api_count", 0), gt("overprivileged_admin_api_count", 0)),
      pass: all(gt("admin_api_count", 0), eq("overprivileged_admin_api_count", 0)),
    }),
  },
  "DUO-INTEGRATIONS-005": {
    inputs: input("readable", "complete", "protected_integration_count", "tagged_integration_count", "tagged_without_policy_count"),
    rules: ordered({
      manual: any(unreadable, eq("protected_integration_count", 0), eq("tagged_integration_count", 0)),
      fail: {
        op: "eq",
        left: path("tagged_without_policy_count"),
        right: path("tagged_integration_count"),
      },
      warn: any(incomplete, gt("tagged_without_policy_count", 0)),
      pass: eq("tagged_without_policy_count", 0),
    }),
  },
  "DUO-INTEGRATIONS-006": {
    inputs: input("policy_readable", "edition_sections_present", "satisfied_group_count"),
    constants: { requirement_group_count: 5 },
    rules: ordered({
      manual: any(ne("policy_readable", true), ne("edition_sections_present", true)),
      fail: eq("satisfied_group_count", 0),
      warn: { op: "lt", left: path("satisfied_group_count"), right: value(5) },
      pass: eq("satisfied_group_count", 5),
    }),
  },
  "DUO-MON-001": {
    inputs: input("readable", "complete", "event_count", "review_event_count"),
    rules: ordered({
      manual: unreadable,
      warn: any(incomplete, eq("event_count", 0), gt("review_event_count", 0)),
      pass: all(gt("event_count", 0), eq("review_event_count", 0)),
    }),
  },
  "DUO-MON-002": {
    inputs: input("readable", "complete", "event_count"),
    rules: ordered({
      manual: unreadable,
      warn: any(incomplete, eq("event_count", 0)),
      pass: gt("event_count", 0),
    }),
  },
  "DUO-MON-003": {
    inputs: input("readable", "complete", "credits_remaining", "telephony_event_count"),
    constants: { critical_credit_floor: 25, warning_credit_floor: 100 },
    rules: ordered({
      manual: any(unreadable, notDefined("credits_remaining")),
      fail: all(gt("telephony_event_count", 0), { op: "lt", left: path("credits_remaining"), right: value(25) }),
      warn: any(incomplete, gt("telephony_event_count", 0), { op: "lt", left: path("credits_remaining"), right: value(100) }),
      pass: gte("credits_remaining", 100),
    }),
  },
  "DUO-MON-004": {
    inputs: input("readable", "enabled_notification_count"),
    rules: ordered({
      manual: unreadable,
      warn: eq("enabled_notification_count", 0),
      pass: gt("enabled_notification_count", 0),
    }),
  },
  "DUO-MON-005": {
    inputs: input("attempts_readable", "logs_readable", "counts_present", "complete", "attempt_count", "event_count", "located_event_count", "impossible_travel_count", "fraud_count", "denied_percent"),
    constants: { travel_window_minutes: 60, denied_warning_percent: 20 },
    rules: ordered({
      manual: any(
        ne("attempts_readable", true),
        ne("logs_readable", true),
        ne("counts_present", true),
        all(eq("impossible_travel_count", 0), eq("located_event_count", 0), gt("event_count", 0)),
      ),
      fail: gt("impossible_travel_count", 0),
      warn: any(incomplete, all(eq("attempt_count", 0), eq("event_count", 0)), gt("fraud_count", 0), gt("denied_percent", 20)),
      pass: { op: "always" },
    }),
  },
};

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
    decisionInputs: DUO_EXECUTABLE_DECISIONS[`DUO-${group}-${String(index + 1).padStart(3, "0")}`].inputs,
    decisionConstants: DUO_EXECUTABLE_DECISIONS[`DUO-${group}-${String(index + 1).padStart(3, "0")}`].constants,
    decisionRules: DUO_EXECUTABLE_DECISIONS[`DUO-${group}-${String(index + 1).padStart(3, "0")}`].rules,
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
  authentication: DUO_AUTH_RESOLVER,
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
