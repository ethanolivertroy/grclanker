import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
  deriveDecisionRules,
  type BatchCheckDefinition,
} from "./batch-spec-builder.js";
import { BOX_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import type { PortableValue, VerdictCondition, VerdictRule } from "./spec-model.js";

const BOX_SURFACES = [
  ["current-user", "/2.0/users/me"], ["enterprise-configuration", "/2.0/enterprise_configurations/{enterpriseId}"],
  ["users", "/2.0/users"], ["groups", "/2.0/groups"], ["events", "/2.0/events"],
  ["device-pinners", "/2.0/enterprises/{enterpriseId}/device_pinners"], ["retention-policies", "/2.0/retention_policies"],
  ["retention-assignments", "/2.0/retention_policies/{policyId}/assignments"], ["legal-hold-policies", "/2.0/legal_hold_policies"],
  ["legal-hold-assignments", "/2.0/legal_hold_policy_assignments"], ["shield-barriers", "/2.0/shield_information_barriers"],
  ["shield-barrier-segments", "/2.0/shield_information_barrier_segments"], ["shield-lists", "/2.0/shield_lists"],
  ["allowlist-entries", "/2.0/collaboration_whitelist_entries"], ["allowlist-exempt-targets", "/2.0/collaboration_whitelist_exempt_targets"],
  ["metadata-templates", "/2.0/metadata_templates/enterprise"], ["classification-template", "/2.0/metadata_templates/enterprise/securityClassification-6VMVochwUWo/schema"],
  ["terms-of-service", "/2.0/terms_of_services"],
].map(([id, path]) => ({ id, path, service: "Box Content API", documentationUrl: "https://developer.box.com/reference/", fields: ["projected fields consumed by the corresponding runtime assessment"] }));

const BOX_CHECK_SURFACES: Readonly<Record<number, readonly string[]>> = {
  1: ["enterprise-configuration"], 2: ["enterprise-configuration", "users"], 3: ["enterprise-configuration", "users"],
  4: ["enterprise-configuration", "allowlist-entries"], 5: ["enterprise-configuration", "allowlist-entries", "allowlist-exempt-targets"],
  6: ["enterprise-configuration"], 7: ["enterprise-configuration"], 8: [], 9: ["enterprise-configuration"],
  10: ["device-pinners"], 11: ["classification-template", "metadata-templates"],
  12: ["retention-policies", "retention-assignments"], 13: ["legal-hold-policies", "legal-hold-assignments"],
  14: ["enterprise-configuration", "shield-lists"], 15: ["shield-barriers", "shield-barrier-segments"],
  16: ["events"], 17: ["users"], 18: ["users"], 19: ["events", "shield-lists"],
  20: ["terms-of-service"], 21: ["enterprise-configuration"], 22: ["enterprise-configuration"],
  23: ["shield-lists"], 24: ["users", "events"], 25: ["shield-lists", "events"],
};

const controls = [
  "SSO enforcement", "2FA for admins", "2FA for all users", "External collaboration restrictions",
  "Collaboration allowlist audit", "Sharing link policies", "Shared link expiration", "Shared link password policy",
  "Watermarking enabled", "Device trust and pins", "Classification labels", "Retention policies",
  "Legal hold policies", "Shield smart access policies", "Shield information barriers", "Enterprise event streaming",
  "Admin role minimization", "Co-admin permission scoping", "App approval process", "Custom terms of service",
  "Password policy strength", "Session duration limits", "IP allowlisting", "Inactive user detection",
  "Content access monitoring",
] as const;

const identity = new Set([1, 2, 3, 17, 18, 21, 22, 23, 24]);
const sharing = new Set([4, 5, 6, 7, 8, 9, 19, 20]);
const governance = new Set([10, 11, 12, 13]);
const ownerFor = (control: number): string => identity.has(control)
  ? "box_assess_identity_access"
  : sharing.has(control)
    ? "box_assess_sharing_collaboration"
    : governance.has(control)
      ? "box_assess_data_governance"
      : "box_assess_shield_monitoring";

const decisions = [
  "return pass when enterprise SSO is required and not in testing mode, warn when it is required but testing, unused, or not exposed, and fail when it is explicitly not required.",
  "return fail when enterprise MFA is required but any admin or co-admin is exempt, pass when MFA is required and the complete privileged inventory has no exemption, warn for unused or unknown settings, an incomplete inventory, or required SSO with Box-native MFA disabled, and fail when both MFA and required SSO are disabled.",
  "return pass when enterprise MFA is required and the complete user inventory has no non-privileged exemption, warn for any exemption, unused or unknown settings, an incomplete inventory, or required SSO with Box-native MFA disabled, and fail when neither MFA nor required SSO is enforced.",
  "return pass when external collaboration is enterprise-only or allowlist-only with at least one readable entry, fail when unrestricted, and warn for unused, unknown, empty, unreadable, or truncated-before-first-entry allowlist evidence.",
  "return fail when any allowlist entry is a public consumer email domain, warn for truncation, stale or undated entries, exemptions, or an empty allowlist while allowlist-only mode is selected, and pass when complete entries are recent non-public domains without exemptions or no allowlist is required and none exists.",
  "return fail when shared links default to open access, pass when the default is restricted and open links are not offered, and warn when the default is restricted but open links remain available or the setting is unused or unrecognized.",
  "return pass when mandatory expiration is enabled for all shared links, warn when only public links expire or the setting is unused or absent, and fail when mandatory expiration is explicitly disabled.",
  "always return manual because the enterprise configuration API does not expose whether passwords are required for open shared links.",
  "return pass when enterprise watermarking is enabled, fail when explicitly disabled, and warn when the flag is unused or absent.",
  "return warn when the complete device-pin inventory is empty and manual when pins exist because the API does not expose whether unpinned devices are blocked; a read that truncates before its first pin is also manual.",
  "return pass when the classification template defines at least one label and fail when a readable template or a 404 proves that it defines none.",
  "return pass when a complete retention-policy inventory has at least one active policy with visible assignments, warn when active policies lack assignments or any relevant inventory is truncated, and fail when a complete inventory has no active policy.",
  "return pass when a complete legal-hold inventory has at least one active or applying policy with visible assignments, and warn when policies or assignments are incomplete, active holds lack assignments, no hold is active, or no hold exists.",
  "return pass when at least one Shield smart-access or threat-detection rule is configured and fail when a readable complete Shield configuration has none.",
  "return pass when at least one enabled information barrier has a visible segment, including a lower-bound segment listing that stopped after proving one; return warn when no visible segment is proved, barriers or required segment reads are unreadable, no barrier is enabled, or no barrier exists.",
  "return pass when the readable enterprise admin event stream contains at least one event in the lookback and warn when it contains none; this verdict proves stream readability only and does not prove SIEM consumption.",
  "return warn when the complete count of admins plus co-admins exceeds the configured maximum and pass when it is at or below that maximum.",
  "return pass when the complete user inventory has no co-admin, warn when user evidence is partial, and manual when any co-admin exists because individual co-admin permissions are not exposed.",
  "always return manual because app creation events and Shield integration lists do not expose the app approval policy.",
  "return pass when at least one managed-user custom terms record is enabled, fail when managed-user terms exist but are disabled, and fail when a complete terms inventory has no managed-user terms.",
  "return pass when minimum password length meets the configured target, weak-password prevention is enabled, and at least two of uppercase, numeric, and special-character minima are positive; warn when length is at least eight but any target is missed or the setting is unused or absent, and fail below eight.",
  "return fail when the base session duration or an enabled custom group duration exceeds the configured maximum, pass when every applicable duration is at or below it, and warn when a duration is unused, absent, or cannot be normalized.",
  "always return manual because Shield IP lists do not expose whether enterprise sign-in or access-policy IP restrictions are enforced.",
  "return pass when every active human user has a successful activity event in the lookback, fail when more than 25 percent lack one, and warn when at most 25 percent lack one, no active human user exists, or user or event coverage is incomplete.",
  "return pass when at least one Shield anomaly rule or Shield alert or block event exists, warn when one required source is unavailable, only ordinary access events exist, or the event window is incomplete, and fail when complete readable evidence has no anomaly rule, alert, block, or content-access event.",
] as const;

interface BoxExecutableDecision {
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
const lt = (name: string, entry: PortableValue): VerdictCondition => compare("lt", name, entry);
const defined = (name: string): VerdictCondition => ({ op: "defined", operand: path(name) });
const matches = (name: string, pattern: string, flags?: string): VerdictCondition => ({
  op: "matches",
  operand: path(name),
  pattern,
  ...(flags ? { flags } : {}),
});
const ratio = (
  comparator: "gt" | "gte" | "lt" | "lte",
  numerator: string,
  denominator: string,
  threshold: number,
): VerdictCondition => ({
  op: "ratio",
  numerator: path(numerator),
  denominator: path(denominator),
  comparator,
  threshold: value(threshold),
});
const all = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "and", conditions });
const any = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "or", conditions });
const rule = (status: VerdictRule["status"], condition: VerdictCondition, note?: string): VerdictRule => ({
  status,
  condition,
  ...(note ? { note } : {}),
});
const ordered = (branches: {
  manual?: VerdictCondition;
  fail?: VerdictCondition;
  warn?: VerdictCondition;
  pass?: VerdictCondition;
}): readonly VerdictRule[] => [
  ...(branches.manual ? [rule("manual", branches.manual)] : []),
  ...(branches.fail ? [rule("fail", branches.fail)] : []),
  ...(branches.warn ? [rule("warn", branches.warn)] : []),
  ...(branches.pass ? [rule("pass", branches.pass)] : []),
  rule("manual", { op: "always" }, "Unknown or contradictory evidence requires manual review."),
];
const input = (...names: string[]): Readonly<Record<string, string>> => Object.fromEntries(
  names.map((name) => [name, `Runtime-owned ${name.replaceAll("_", " ")} derived from the complete collector state before evidence samples are capped.`]),
);
const manual = (): BoxExecutableDecision => ({ inputs: {}, rules: [rule("manual", { op: "always" })] });

const BOX_EXECUTABLE_DECISIONS: Readonly<Record<string, BoxExecutableDecision>> = {
  "BOX-01": {
    inputs: input("settings_readable", "unused_setting_count", "sso_required", "sso_testing"),
    rules: [
      rule("manual", ne("settings_readable", true)),
      rule("warn", gt("unused_setting_count", 0)),
      rule("fail", eq("sso_required", false)),
      rule("warn", any(ne("sso_required", true), eq("sso_testing", true))),
      rule("pass", all(eq("sso_required", true), ne("sso_testing", true))),
      rule("manual", { op: "always" }),
    ],
  },
  "BOX-02": {
    inputs: input("settings_readable", "users_readable", "unused_setting_count", "mfa_required", "sso_required", "user_count", "admin_count", "users_truncated", "exempt_privileged_count"),
    rules: [
      rule("manual", any(ne("settings_readable", true), ne("users_readable", true))),
      rule("warn", gt("unused_setting_count", 0)),
      rule("fail", any(
        all(eq("mfa_required", true), gt("exempt_privileged_count", 0)),
        all(eq("mfa_required", false), ne("sso_required", true)),
      )),
      rule("warn", any(
        ne("mfa_required", true),
        eq("users_truncated", true),
        eq("user_count", 0),
        eq("admin_count", 0),
      )),
      rule("pass", all(
        eq("mfa_required", true),
        eq("exempt_privileged_count", 0),
        ne("users_truncated", true),
        gt("user_count", 0),
        gt("admin_count", 0),
      )),
      rule("manual", { op: "always" }),
    ],
  },
  "BOX-03": {
    inputs: input("settings_readable", "users_readable", "unused_setting_count", "mfa_required", "sso_required", "user_count", "admin_count", "users_truncated", "exempt_user_count"),
    rules: [
      rule("manual", any(ne("settings_readable", true), ne("users_readable", true))),
      rule("warn", gt("unused_setting_count", 0)),
      rule("fail", all(eq("mfa_required", false), ne("sso_required", true))),
      rule("warn", any(
        ne("mfa_required", true),
        gt("exempt_user_count", 0),
        eq("users_truncated", true),
        eq("user_count", 0),
        eq("admin_count", 0),
      )),
      rule("pass", all(
        eq("mfa_required", true),
        eq("exempt_user_count", 0),
        ne("users_truncated", true),
        gt("user_count", 0),
        gt("admin_count", 0),
      )),
      rule("manual", { op: "always" }),
    ],
  },
  "BOX-04": {
    inputs: input("settings_readable", "allowlist_readable", "unused_setting_count", "external_status", "allowlist_entry_count"),
    rules: [
      rule("manual", all(ne("settings_readable", true), any(ne("allowlist_readable", true), eq("allowlist_entry_count", 0)))),
      rule("warn", gt("unused_setting_count", 0)),
      rule("fail", eq("external_status", "enable_external_collaboration")),
      rule("warn", any(
        ne("settings_readable", true),
        ne("allowlist_readable", true),
        all(eq("external_status", "limit_collaboration_to_allowlisted_domains"), eq("allowlist_entry_count", 0)),
        all(
          ne("external_status", "limit_collaboration_to_users_within_enterprise"),
          ne("external_status", "limit_collaboration_to_allowlisted_domains"),
        ),
      )),
      rule("pass", any(
        eq("external_status", "limit_collaboration_to_users_within_enterprise"),
        all(eq("external_status", "limit_collaboration_to_allowlisted_domains"), gt("allowlist_entry_count", 0)),
      )),
      rule("manual", { op: "always" }),
    ],
  },
  "BOX-05": {
    inputs: input("allowlist_readable", "config_readable", "exempt_targets_readable", "complete", "external_status", "allowlist_entry_count", "public_domain_count", "stale_entry_count", "undated_entry_count", "exempt_target_count"),
    rules: ordered({
      manual: ne("allowlist_readable", true),
      fail: gt("public_domain_count", 0),
      warn: any(
        ne("complete", true),
        ne("config_readable", true),
        ne("exempt_targets_readable", true),
        all(eq("allowlist_entry_count", 0), eq("external_status", "limit_collaboration_to_allowlisted_domains")),
        gt("stale_entry_count", 0),
        gt("undated_entry_count", 0),
        gt("exempt_target_count", 0),
      ),
      pass: { op: "always" },
    }),
  },
  "BOX-06": {
    inputs: input("settings_readable", "unused_setting_count", "shared_link_default_access", "shared_link_access"),
    rules: [
      rule("manual", ne("settings_readable", true)),
      rule("warn", gt("unused_setting_count", 0)),
      rule("fail", matches("shared_link_default_access", "open|public|anyone", "i")),
      rule("warn", any(
        { op: "not", condition: matches("shared_link_default_access", "company|collaborators|enterprise|people_in|invited", "i") },
        matches("shared_link_access", "open|public|anyone", "i"),
      )),
      rule("pass", all(
        matches("shared_link_default_access", "company|collaborators|enterprise|people_in|invited", "i"),
        { op: "not", condition: matches("shared_link_access", "open|public|anyone", "i") },
      )),
      rule("manual", { op: "always" }),
    ],
  },
  "BOX-07": {
    inputs: input("settings_readable", "unused_setting_count", "expiration_enabled", "public_expiration_enabled"),
    rules: [
      rule("manual", ne("settings_readable", true)),
      rule("warn", gt("unused_setting_count", 0)),
      rule("pass", eq("expiration_enabled", true)),
      rule("warn", eq("public_expiration_enabled", true)),
      rule("fail", eq("expiration_enabled", false)),
      rule("warn", { op: "always" }),
    ],
  },
  "BOX-08": manual(),
  "BOX-09": {
    inputs: input("settings_readable", "unused_setting_count", "watermarking_enabled"),
    rules: [
      rule("manual", ne("settings_readable", true)),
      rule("warn", gt("unused_setting_count", 0)),
      rule("pass", eq("watermarking_enabled", true)),
      rule("fail", eq("watermarking_enabled", false)),
      rule("warn", { op: "always" }),
    ],
  },
  "BOX-10": {
    inputs: input("readable", "complete", "pin_count"),
    rules: ordered({
      manual: any(ne("readable", true), gt("pin_count", 0), all(ne("complete", true), eq("pin_count", 0))),
      warn: all(eq("complete", true), eq("pin_count", 0)),
    }),
  },
  "BOX-11": {
    inputs: input("readable", "classification_count"),
    rules: ordered({
      manual: ne("readable", true),
      fail: eq("classification_count", 0),
      pass: gt("classification_count", 0),
    }),
  },
  "BOX-12": {
    inputs: input("policies_readable", "assignments_readable", "complete", "active_policy_count", "assigned_policy_count"),
    rules: ordered({
      manual: ne("policies_readable", true),
      fail: all(eq("complete", true), eq("active_policy_count", 0)),
      warn: any(ne("complete", true), ne("assignments_readable", true), eq("assigned_policy_count", 0)),
      pass: gt("assigned_policy_count", 0),
    }),
  },
  "BOX-13": {
    inputs: input("policies_readable", "assignments_readable", "complete", "active_policy_count", "assigned_policy_count"),
    rules: ordered({
      manual: ne("policies_readable", true),
      warn: any(ne("complete", true), ne("assignments_readable", true), eq("assigned_policy_count", 0)),
      pass: gt("assigned_policy_count", 0),
    }),
  },
  "BOX-14": {
    inputs: input("settings_readable", "shield_rule_count"),
    rules: ordered({
      manual: ne("settings_readable", true),
      fail: eq("shield_rule_count", 0),
      pass: gt("shield_rule_count", 0),
    }),
  },
  "BOX-15": {
    inputs: input("barriers_readable", "segments_readable", "complete", "barrier_count", "enabled_barrier_count", "enabled_with_segments_count"),
    rules: [
      rule("manual", ne("barriers_readable", true)),
      rule("warn", ne("segments_readable", true)),
      rule("pass", gt("enabled_with_segments_count", 0)),
      rule("warn", { op: "always" }),
    ],
  },
  "BOX-16": {
    inputs: input("events_readable", "event_count"),
    rules: ordered({
      manual: ne("events_readable", true),
      warn: eq("event_count", 0),
      pass: gt("event_count", 0),
    }),
  },
  "BOX-17": {
    inputs: input("users_readable", "users_truncated", "user_count", "admin_count", "privileged_user_count", "max_admins"),
    rules: ordered({
      manual: ne("users_readable", true),
      warn: any(
        eq("users_truncated", true),
        eq("user_count", 0),
        eq("admin_count", 0),
        { op: "gt", left: path("privileged_user_count"), right: path("max_admins") },
      ),
      pass: { op: "lte", left: path("privileged_user_count"), right: path("max_admins") },
    }),
  },
  "BOX-18": {
    inputs: input("users_readable", "users_truncated", "user_count", "admin_count", "coadmin_count"),
    rules: ordered({
      manual: any(ne("users_readable", true), gt("coadmin_count", 0)),
      warn: any(eq("users_truncated", true), eq("user_count", 0), eq("admin_count", 0)),
      pass: eq("coadmin_count", 0),
    }),
  },
  "BOX-19": manual(),
  "BOX-20": {
    inputs: input("terms_readable", "managed_term_count", "enabled_managed_term_count"),
    rules: ordered({
      manual: ne("terms_readable", true),
      fail: eq("enabled_managed_term_count", 0),
      pass: gt("enabled_managed_term_count", 0),
    }),
  },
  "BOX-21": {
    inputs: input("settings_readable", "unused_setting_count", "minimum_length", "required_minimum_length", "weak_password_prevention", "complexity_rule_count"),
    constants: { absolute_minimum_length: 8 },
    rules: [
      rule("manual", ne("settings_readable", true)),
      rule("warn", gt("unused_setting_count", 0)),
      rule("warn", { op: "not", condition: { op: "defined", operand: path("minimum_length") } }),
      rule("pass", all(
        { op: "gte", left: path("minimum_length"), right: path("required_minimum_length") },
        eq("weak_password_prevention", true),
        gte("complexity_rule_count", 2),
      )),
      rule("warn", any(
        { op: "not", condition: { op: "defined", operand: path("minimum_length") } },
        all(gte("minimum_length", 8), any(
          { op: "lt", left: path("minimum_length"), right: path("required_minimum_length") },
          ne("weak_password_prevention", true),
          { op: "lt", left: path("complexity_rule_count"), right: value(2) },
        )),
      )),
      rule("fail", lt("minimum_length", 8)),
      rule("warn", any(
        ne("weak_password_prevention", true),
        { op: "lt", left: path("complexity_rule_count"), right: value(2) },
      )),
      rule("manual", { op: "always" }),
    ],
  },
  "BOX-22": {
    inputs: input("settings_readable", "unused_setting_count", "session_duration_value", "session_hours", "custom_session_enabled", "custom_session_duration_value", "custom_session_hours", "max_session_hours"),
    rules: [
      rule("manual", ne("settings_readable", true)),
      rule("warn", any(
        gt("unused_setting_count", 0),
        { op: "not", condition: defined("session_duration_value") },
        { op: "not", condition: defined("session_hours") },
      )),
      rule("fail", { op: "gt", left: path("session_hours"), right: path("max_session_hours") }),
      rule("pass", ne("custom_session_enabled", true)),
      rule("warn", any(
        { op: "not", condition: defined("custom_session_duration_value") },
        { op: "not", condition: defined("custom_session_hours") },
      )),
      rule("pass", { op: "lte", left: path("custom_session_hours"), right: path("max_session_hours") }),
      rule("fail", { op: "gt", left: path("custom_session_hours"), right: path("max_session_hours") }),
      rule("manual", { op: "always" }),
    ],
  },
  "BOX-23": manual(),
  "BOX-24": {
    inputs: input("users_readable", "events_readable", "users_truncated", "user_count", "admin_count", "events_truncated", "active_user_count", "inactive_user_count"),
    constants: { failure_ratio: 0.25 },
    rules: [
      rule("manual", any(ne("users_readable", true), ne("events_readable", true))),
      rule("warn", any(
        eq("users_truncated", true),
        eq("user_count", 0),
        eq("admin_count", 0),
        eq("events_truncated", true),
        eq("active_user_count", 0),
      )),
      rule("pass", eq("inactive_user_count", 0)),
      rule("fail", ratio("gt", "inactive_user_count", "active_user_count", 0.25)),
      rule("warn", gt("inactive_user_count", 0)),
      rule("manual", { op: "always" }),
    ],
  },
  "BOX-25": {
    inputs: input("shield_settings_readable", "configuration_readable", "events_readable", "events_complete", "anomaly_rule_count", "anomaly_event_count", "access_event_count"),
    rules: [
      rule("manual", all(ne("shield_settings_readable", true), ne("events_readable", true))),
      rule("warn", any(ne("configuration_readable", true), ne("events_readable", true))),
      rule("pass", any(gt("anomaly_rule_count", 0), gt("anomaly_event_count", 0))),
      rule("warn", any(ne("shield_settings_readable", true), gt("access_event_count", 0), ne("events_complete", true))),
      rule("fail", { op: "always" }),
    ],
  },
};

const checks: BatchCheckDefinition[] = controls.map((title, index) => {
  const control = index + 1;
  const id = `BOX-${String(control).padStart(2, "0")}`;
  const decision = BOX_EXECUTABLE_DECISIONS[id];
  const executable = deriveDecisionRules(id, decision.rules);
  return {
    id,
    control,
    title,
    severity: [1, 2].includes(control) ? "critical" : [3, 4, 6, 14, 16, 17, 21, 25].includes(control) ? "high" : "medium",
    owner: ownerFor(control),
    surfaces: BOX_CHECK_SURFACES[control],
    evidenceFields: [...BOX_CHECK_SURFACES[control], "complete_source_counts"],
    decisionInputs: decision.inputs,
    decisionConstants: decision.constants,
    decisionRules: executable.rules,
    derivedFactRules: executable.derivedFactRules,
    decision: decisions[index],
  };
});
const idsFor = (owner: string): string[] => checks.filter((check) => check.owner === owner).map((check) => check.id);

export const BOX_RUNTIME_BEHAVIOR = [
  "Enterprise configuration categories can be returned but marked unused by Box; unused security settings never pass and render warning or manual evidence.",
  "Marker, offset, and event-stream walkers keep distinct completion rules, including repeated markers, empty pages, server totals, item caps, and stream-position exits.",
  "Five policy areas remain partly or wholly manual because the Box Content API does not expose a decisive read field; the runtime names Admin Console evidence.",
] as const;

export const BOX_SPEC = buildBatchIntegrationSpec({
  slug: "box-sec-inspector",
  displayName: "Box Security Inspector",
  vendor: "Box",
  category: "collaboration-and-content",
  summary: "Portable contract for the shipped Box identity, sharing, governance, Shield, and monitoring assessments.",
  sourceModule: "cli/extensions/grc-tools/box.ts",
  baseServices: ["Box Content API", "Box OAuth 2.0 token service"],
  authentication: BOX_AUTH_RESOLVER,
  permissions: [
    { id: "box-enterprise-read", kind: "role", value: "Box application scopes and enterprise authorization for users, groups, events, governance, and enterprise configuration", unlocks: BOX_SURFACES.map((surface) => surface.id) },
    { id: "box-governance", kind: "license", value: "Box Governance entitlement", unlocks: ["retention-policies", "retention-assignments", "legal-hold-policies", "legal-hold-assignments"] },
    { id: "box-shield", kind: "license", value: "Box Shield entitlement", unlocks: ["shield-barriers", "shield-barrier-segments", "shield-lists"] },
  ],
  surfaces: BOX_SURFACES,
  checks,
  tools: {
    box_check_access: [],
    box_assess_identity_access: idsFor("box_assess_identity_access"),
    box_assess_sharing_collaboration: idsFor("box_assess_sharing_collaboration"),
    box_assess_data_governance: idsFor("box_assess_data_governance"),
    box_assess_shield_monitoring: idsFor("box_assess_shield_monitoring"),
    box_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [
    {
      surfaceIds: ["users", "device-pinners", "retention-policies", "retention-assignments", "legal-hold-policies", "legal-hold-assignments", "shield-barriers", "shield-barrier-segments", "allowlist-entries", "allowlist-exempt-targets", "metadata-templates"],
      cursorFields: ["next_marker"], pageSize: 1000, itemCap: null, pageCap: null,
      totalSemantics: "Completion requires next_marker exhaustion; a cap with a remaining marker is incomplete.",
      stopConditions: ["No next_marker", "Configured record cap", "Repeated marker", "Empty page with marker"],
    },
    {
      surfaceIds: ["groups"], cursorFields: ["offset", "limit", "total_count"], pageSize: 1000, itemCap: null, pageCap: null,
      totalSemantics: "total_count is authoritative; seen below total is incomplete.", stopConditions: ["Seen reaches total", "Configured cap", "Offset fails to advance", "Empty page before total"],
    },
    {
      surfaceIds: ["events"], cursorFields: ["next_stream_position", "stream_position"], pageSize: 500, itemCap: null, pageCap: null,
      totalSemantics: "The event stream has no total; the walker requires an empty page and advancing stream positions.",
      stopConditions: ["Empty page", "Configured event cap", "Repeated position", "Fresh position adds no unseen event", "Page budget"],
    },
    {
      surfaceIds: ["shield-lists", "terms-of-service", "current-user", "enterprise-configuration", "classification-template"],
      cursorFields: [], pageSize: null, itemCap: null, pageCap: null, totalSemantics: "Single request; a successful response is complete.", stopConditions: ["Single response"],
    },
  ],
  rateLimit: {
    documentedLimit: "Box rate limits vary by endpoint, user, and enterprise",
    retryHeaders: ["Retry-After", "X-Rate-Limit-Limit", "X-Rate-Limit-Remaining"],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "Honor Retry-After up to 60 seconds and retry three times with bounded exponential delay.",
  },
  runtimeBehavior: BOX_RUNTIME_BEHAVIOR,
  knownGaps: ["CSV, HTML, SARIF, TUI output, and several policy reads remain absent."],
  sensitiveFields: ["client_secret", "private_key", "passphrase", "access_token", "refresh_token", "authorization", "login"],
  credentialFormats: ["Box OAuth access and refresh tokens", "JWT private keys and passphrases", "signed JWT assertions"],
  output: buildBatchOutputContract({
    files: [
      "core_data/access_check.json", "core_data/enterprise_configuration.json", "core_data/current_user.json", "core_data/users.json",
      "core_data/groups.json", "core_data/enterprise_events_activity.json", "core_data/enterprise_events_sharing.json",
      "core_data/enterprise_events_shield.json", "core_data/device_pinners.json", "core_data/classification_template.json",
      "core_data/metadata_templates.json", "core_data/retention_policies.json", "core_data/retention_policy_assignments.json",
      "core_data/legal_hold_policies.json", "core_data/legal_hold_policy_assignments.json", "core_data/shield_information_barriers.json",
      "core_data/shield_information_barrier_segments.json", "core_data/shield_lists.json", "core_data/collaboration_allowlist_entries.json",
      "core_data/collaboration_allowlist_exempt_targets.json", "core_data/terms_of_services.json", "core_data/collection_status.json",
      "analysis/identity_access.json", "analysis/sharing_collaboration.json", "analysis/data_governance.json", "analysis/shield_monitoring.json",
      "analysis/findings.json", "analysis/summary.json", "compliance/executive_summary.md", "compliance/unified_compliance_matrix.md",
      "compliance/fedramp/fedramp_compliance_report.md", "compliance/cmmc/cmmc_compliance_report.md",
      "compliance/soc2/soc2_compliance_report.md", "compliance/cis/cis_compliance_report.md",
      "compliance/pci_dss/pci_dss_compliance_report.md", "compliance/disa_stig/stig_compliance_checklist.md",
      "compliance/irap/irap_compliance_report.md", "compliance/ismap/ismap_compliance_report.md", "QUICK_REFERENCE.md", "metadata.json",
    ],
    conditionalFiles: ["_errors.log"],
    overwritePolicy: "Allocate a new <enterprise>-audit-bundle directory and numeric suffix without overwriting either directory or archive.",
    archivePairing: "Create <allocated-directory>.zip beside the allocated enterprise audit directory.",
  }),
});
