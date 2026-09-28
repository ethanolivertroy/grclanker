import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
  deriveDecisionRules,
  type BatchCheckDefinition,
} from "./batch-spec-builder.js";
import { ZOOM_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import type { PortableValue, VerdictCondition, VerdictRule } from "./spec-model.js";

const ZOOM_SURFACES = [
  ["current-user", "/v2/users/me"], ["account-settings", "/v2/accounts/{accountId}/settings"],
  ["account-lock-settings", "/v2/accounts/{accountId}/lock_settings"], ["users", "/v2/users"],
  ["user-settings", "/v2/users/{userId}/settings"], ["roles", "/v2/roles"],
  ["role-members", "/v2/roles/{roleId}/members"], ["groups", "/v2/groups"],
  ["group-settings", "/v2/groups/{groupId}/settings"], ["group-lock-settings", "/v2/groups/{groupId}/lock_settings"],
  ["operation-logs", "/v2/report/operationlogs"], ["im-groups", "/v2/im/groups"],
  ["managed-domains", "/v2/accounts/{accountId}/managed_domains"], ["trusted-domains", "/v2/accounts/{accountId}/trusted_domains"],
  ["phone-settings", "/v2/phone/account_settings"],
].map(([id, path]) => ({ id, path, service: "Zoom REST API", documentationUrl: "https://developers.zoom.us/docs/api/", fields: ["projected fields consumed by the corresponding runtime assessment"] }));

const ZOOM_CHECK_SURFACES: Readonly<Record<string, readonly string[]>> = {
  "ZOOM-ID-01": ["users"], "ZOOM-ID-02": ["account-settings", "roles", "role-members"],
  "ZOOM-ID-03": ["managed-domains"], "ZOOM-ID-04": ["roles", "role-members"], "ZOOM-ID-05": ["users"],
  "ZOOM-ID-06": ["account-settings"], "ZOOM-ID-07": [],
  "ZOOM-COLLAB-01": ["trusted-domains"], "ZOOM-COLLAB-02": ["account-settings", "account-lock-settings", "groups", "group-settings", "group-lock-settings"],
  "ZOOM-COLLAB-03": ["account-settings", "account-lock-settings", "groups", "group-settings", "group-lock-settings"],
  "ZOOM-COLLAB-04": ["phone-settings"], "ZOOM-COLLAB-05": ["operation-logs"], "ZOOM-COLLAB-06": ["im-groups"],
  "ZOOM-COLLAB-07": ["account-settings", "account-lock-settings", "groups", "group-settings", "group-lock-settings"],
  "ZOOM-COLLAB-08": [],
  "ZOOM-MTG-01": ["account-settings", "account-lock-settings", "groups", "group-settings", "group-lock-settings"],
  "ZOOM-MTG-02": ["account-settings", "account-lock-settings", "groups", "group-settings", "group-lock-settings"],
  "ZOOM-MTG-03": ["account-settings", "account-lock-settings", "groups", "group-settings", "group-lock-settings"],
  "ZOOM-MTG-04": ["account-settings", "account-lock-settings", "groups", "group-settings", "group-lock-settings"],
  "ZOOM-MTG-05": ["account-settings", "account-lock-settings", "groups", "group-settings", "group-lock-settings"],
  "ZOOM-MTG-06": ["account-settings", "account-lock-settings", "groups", "group-settings", "group-lock-settings"],
  "ZOOM-MTG-07": ["account-settings", "account-lock-settings", "groups", "group-settings", "group-lock-settings"],
  "ZOOM-MTG-08": ["account-settings", "account-lock-settings", "groups", "group-settings", "group-lock-settings"],
  "ZOOM-MTG-09": ["account-settings", "account-lock-settings", "groups", "group-settings", "group-lock-settings"],
  "ZOOM-MTG-10": ["account-settings", "account-lock-settings", "groups", "group-settings", "group-lock-settings"],
};

const rows = [
  ["ZOOM-ID-01", 5, "SSO enforcement for all users", "critical", "zoom_assess_identity"],
  ["ZOOM-ID-02", 6, "Two-factor authentication for admins", "critical", "zoom_assess_identity"],
  ["ZOOM-ID-03", 14, "Managed domains verified", "high", "zoom_assess_identity"],
  ["ZOOM-ID-04", 6, "Administrative privilege concentration", "medium", "zoom_assess_identity"],
  ["ZOOM-ID-05", 16, "Personal and social sign-in methods blocked", "high", "zoom_assess_identity"],
  ["ZOOM-ID-06", 17, "Session inactivity timeout enforced", "medium", "zoom_assess_identity"],
  ["ZOOM-ID-07", 13, "Vanity URL configured and secured", "low", "zoom_assess_identity"],
  ["ZOOM-COLLAB-01", 12, "Trusted domain restrictions", "high", "zoom_assess_collaboration_governance"],
  ["ZOOM-COLLAB-02", 9, "In-meeting file transfer restricted", "high", "zoom_assess_collaboration_governance"],
  ["ZOOM-COLLAB-03", 10, "Cloud recording auto-delete retention", "high", "zoom_assess_collaboration_governance"],
  ["ZOOM-COLLAB-04", 19, "Zoom Phone recording policies enforced", "medium", "zoom_assess_collaboration_governance"],
  ["ZOOM-COLLAB-05", 24, "Admin operation logs readable and recent", "medium", "zoom_assess_collaboration_governance"],
  ["ZOOM-COLLAB-06", 15, "IM group restrictions enforced", "medium", "zoom_assess_collaboration_governance"],
  ["ZOOM-COLLAB-07", 12, "External contacts restricted", "medium", "zoom_assess_collaboration_governance"],
  ["ZOOM-COLLAB-08", 8, "Chat encryption enabled", "medium", "zoom_assess_collaboration_governance"],
  ["ZOOM-MTG-01", 1, "Meeting password enforcement and account lock", "critical", "zoom_assess_meeting_security"],
  ["ZOOM-MTG-02", 2, "Waiting room enabled by default", "critical", "zoom_assess_meeting_security"],
  ["ZOOM-MTG-03", 3, "Screen sharing restricted to host only", "high", "zoom_assess_meeting_security"],
  ["ZOOM-MTG-04", 20, "Local recording disabled", "high", "zoom_assess_meeting_security"],
  ["ZOOM-MTG-05", 7, "End-to-end encryption available and default", "high", "zoom_assess_meeting_security"],
  ["ZOOM-MTG-06", 22, "Embed password in join link disabled", "medium", "zoom_assess_meeting_security"],
  ["ZOOM-MTG-07", 25, "Personal Meeting ID usage restricted", "medium", "zoom_assess_meeting_security"],
  ["ZOOM-MTG-08", 23, "Only authenticated users can join meetings", "high", "zoom_assess_meeting_security"],
  ["ZOOM-MTG-09", 18, "Data routing control enabled", "critical", "zoom_assess_meeting_security"],
  ["ZOOM-MTG-10", 4, "Recording consent disclaimer shown to participants", "high", "zoom_assess_meeting_security"],
] as const;

const decisions = [
  "return fail when any active user has a login type other than 101, pass when every user in a complete non-empty inventory is SSO-only, and warn for unknown login types or partial evidence.",
  "return pass for two-factor mode all with complete roles or mode role covering every admin role, fail for none or an uncovered admin role, warn for group mode or partial roles, and manual for absent or undocumented settings.",
  "return fail when any managed domain is not verified, pass when every domain in a complete non-empty inventory is verified, warn for truncation, and manual when no domain is returned.",
  "return pass when complete admin-role membership contains at most the configured administrator maximum and warn when it exceeds that maximum or role evidence is partial.",
  "return fail when any active user uses a password or social login, pass when every login code in a complete non-empty inventory is documented and neither category, and warn for unknown, other, or partial evidence.",
  "return fail when client or web inactivity sign-out is disabled, warn when either exceeds the configured maximum, pass when both positive values are within it, and manual when neither setting is exposed.",
  "always return manual because the account settings API exposes no account vanity URL field.",
  "return pass when the non-empty trusted-domain inventory contains no wildcard, fail when any wildcard exists, and manual when the inventory is empty or unreadable.",
  "return fail when in-meeting file transfer is enabled, pass when disabled, locked, and no group relaxes it, and warn when disabled but unlocked or group evidence is incomplete.",
  "return fail when cloud recording is enabled without auto-delete, pass when auto-delete days are at or below the configured maximum, locked, and not relaxed by a group, warn for missing days, excessive retention, or incomplete enforcement, and manual when cloud recording is disabled.",
  "return pass when both auto-call and ad-hoc Zoom Phone recording policies expose enable flags and are locked, warn when either is unlocked, and manual when Phone or either policy is unavailable.",
  "return pass when a complete admin-operation-log window is non-empty and every row is dated, and warn when the window is empty, truncated, or contains undated rows.",
  "return pass when every IM group in a complete non-empty inventory is normal or restricted without master-account search, warn for shared, unknown, cross-account, or partial groups, and manual when no group exists.",
  "return fail when add-contact or chat-with-others policy allows anyone, pass when both are organization-restricted, locked, and not relaxed by groups, warn when restrictions are not fully locked, and manual for absent policy fields.",
  "always return manual because the account settings API documents no account-level Team Chat encryption setting.",
  "return fail when new scheduled meetings do not require a password, pass when the requirement is true, locked, and not relaxed by groups, and warn when compliant but not fully enforced.",
  "return fail when waiting room is disabled, pass when enabled, locked, and not relaxed by groups, and warn when enabled but not fully enforced.",
  "return fail when screen sharing is enabled for all participants, pass when disabled or host-only and locked without relaxed groups, warn when compliant but not fully enforced, and manual for absent or undocumented values.",
  "return fail when local recording is enabled, pass when disabled, locked, and not relaxed by groups, and warn when disabled but not fully enforced.",
  "return fail when end-to-end encrypted meetings are unavailable, pass when available, default, locked, and not relaxed by groups, and warn when available but not default or not fully enforced.",
  "return fail when passcodes are embedded in join links, pass when embedding is disabled, locked, and not relaxed by groups, and warn when disabled but not fully enforced.",
  "return fail when PMI is used for scheduled or instant meetings, pass when PMI is disabled or unused and both controls are locked without relaxed groups, and warn when compliant but not fully enforced.",
  "return fail when meeting authentication is disabled, pass when enabled, locked, and not relaxed by groups, and warn when enabled but not fully enforced.",
  "return fail when custom data-center routing is disabled, pass when enabled with a non-empty region list, locked, and not relaxed by groups, and warn when regions are absent or enforcement is incomplete.",
  "return pass when every participant sees the recording disclaimer, warn for guest-only, unknown, or group-relaxed settings, fail when the legacy disclaimer is explicitly false, and manual when no documented setting is exposed.",
] as const;

interface ZoomExecutableDecision {
  inputs: Readonly<Record<string, string>>;
  constants?: Readonly<Record<string, PortableValue>>;
  rules: readonly VerdictRule[];
}
const value = (entry: PortableValue) => ({ kind: "value" as const, value: entry });
const path = (name: string) => ({ kind: "path" as const, path: name });
const cmp = (op: "eq" | "ne" | "gt" | "gte" | "lt" | "lte", name: string, entry: PortableValue): VerdictCondition => ({ op, left: path(name), right: value(entry) });
const eq = (name: string, entry: PortableValue) => cmp("eq", name, entry);
const ne = (name: string, entry: PortableValue) => cmp("ne", name, entry);
const gt = (name: string, entry: PortableValue) => cmp("gt", name, entry);
const ltePaths = (left: string, right: string): VerdictCondition => ({ op: "lte", left: path(left), right: path(right) });
const defined = (name: string): VerdictCondition => ({ op: "defined", operand: path(name) });
const matches = (name: string, pattern: string, flags?: string): VerdictCondition => ({ op: "matches", operand: path(name), pattern, ...(flags ? { flags } : {}) });
const not = (condition: VerdictCondition): VerdictCondition => ({ op: "not", condition });
const all = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "and", conditions });
const any = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "or", conditions });
const rule = (status: VerdictRule["status"], condition: VerdictCondition): VerdictRule => ({ status, condition });
const input = (...names: string[]) => Object.fromEntries(names.map((name) => [name, `Runtime-owned ${name.replaceAll("_", " ")} derived from complete collector state before evidence samples are capped.`]));
const groupInputs = ["relaxing_group_count", "group_list_state", "unreadable_group_setting_count", "group_list_truncated"] as const;
const groupEvidenceIncomplete = any(
  gt("relaxing_group_count", 0),
  eq("group_list_state", "denied"),
  eq("group_list_state", "error"),
  gt("unreadable_group_setting_count", 0),
  eq("group_list_truncated", true),
);
const booleanSetting = (requiredValue: boolean): ZoomExecutableDecision => ({
  inputs: input("settings_readable", "setting_present", "setting_value", "lock_value", ...groupInputs),
  constants: { required_setting_value: requiredValue },
  rules: [
    rule("manual", any(ne("settings_readable", true), ne("setting_present", true))),
    rule("fail", { op: "ne", left: path("setting_value"), right: path("required_setting_value") }),
    rule("warn", any(ne("lock_value", true), groupEvidenceIncomplete)),
    rule("pass", all(
      { op: "eq", left: path("setting_value"), right: path("required_setting_value") },
      eq("lock_value", true),
      not(groupEvidenceIncomplete),
    )),
    rule("manual", { op: "always" }),
  ],
});
const manual = (): ZoomExecutableDecision => ({ inputs: {}, rules: [rule("manual", { op: "always" })] });
const inventory = (empty: "manual" | "warn", bad: "fail" | "warn"): ZoomExecutableDecision => ({
  inputs: input("readable", "complete", "count", "bad_count"),
  rules: [rule("manual", ne("readable", true)), rule(empty, eq("count", 0)), rule(bad, gt("bad_count", 0)), rule("warn", ne("complete", true)), rule("pass", { op: "always" })],
});
const ZOOM_EXECUTABLE_DECISIONS: Readonly<Record<string, ZoomExecutableDecision>> = {
  "ZOOM-ID-01": {
    inputs: input("readable", "complete", "count", "bad_count", "unknown_count"),
    rules: [rule("manual", any(ne("readable", true), eq("count", 0))), rule("fail", gt("bad_count", 0)), rule("warn", any(gt("unknown_count", 0), ne("complete", true))), rule("pass", { op: "always" })],
  },
  "ZOOM-ID-02": {
    inputs: input("settings_readable", "setting_present", "setting_value", "roles_readable", "roles_complete", "admin_role_count", "uncovered_admin_role_count"),
    rules: [
      rule("manual", any(ne("settings_readable", true), ne("setting_present", true))),
      rule("manual", all(eq("setting_value", "role"), any(ne("roles_readable", true), eq("admin_role_count", 0)))),
      rule("fail", any(eq("setting_value", "none"), all(eq("setting_value", "role"), gt("uncovered_admin_role_count", 0)))),
      rule("warn", any(eq("setting_value", "group"), all(any(eq("setting_value", "all"), eq("setting_value", "role")), ne("roles_complete", true)))),
      rule("pass", any(
        all(eq("setting_value", "all"), eq("roles_readable", true), eq("roles_complete", true)),
        all(
          eq("setting_value", "role"),
          eq("roles_readable", true),
          eq("roles_complete", true),
          gt("admin_role_count", 0),
          eq("uncovered_admin_role_count", 0),
        ),
      )),
      rule("manual", { op: "always" }),
    ],
  },
  "ZOOM-ID-03": inventory("manual", "fail"),
  "ZOOM-ID-04": {
    inputs: input("roles_readable", "admin_role_count", "member_read_denied", "complete", "admin_count", "max_admins"),
    rules: [
      rule("manual", any(ne("roles_readable", true), eq("admin_role_count", 0), eq("member_read_denied", true))),
      rule("warn", any(ne("complete", true), { op: "gt", left: path("admin_count"), right: path("max_admins") })),
      rule("pass", ltePaths("admin_count", "max_admins")),
      rule("manual", { op: "always" }),
    ],
  },
  "ZOOM-ID-05": { inputs: input("readable", "complete", "count", "bad_count", "unknown_count"), rules: [rule("manual", any(ne("readable", true), eq("count", 0))), rule("fail", gt("bad_count", 0)), rule("warn", any(gt("unknown_count", 0), ne("complete", true))), rule("pass", { op: "always" })] },
  "ZOOM-ID-06": {
    inputs: input("settings_readable", "client_setting_present", "web_setting_present", "client_minutes", "web_minutes", "max_minutes"),
    rules: [
      rule("manual", any(ne("settings_readable", true), all(ne("client_setting_present", true), ne("web_setting_present", true)))),
      rule("fail", any(not(defined("client_minutes")), not(defined("web_minutes")), cmp("lte", "client_minutes", 0), cmp("lte", "web_minutes", 0))),
      rule("warn", any({ op: "gt", left: path("client_minutes"), right: path("max_minutes") }, { op: "gt", left: path("web_minutes"), right: path("max_minutes") })),
      rule("pass", { op: "always" }),
    ],
  },
  "ZOOM-ID-07": manual(),
  "ZOOM-COLLAB-01": inventory("manual", "fail"),
  "ZOOM-COLLAB-02": booleanSetting(false),
  "ZOOM-COLLAB-03": {
    inputs: input("settings_readable", "cloud_recording_present", "cloud_recording_value", "auto_delete_present", "auto_delete_value", "retention_days", "max_retention_days", "lock_value", ...groupInputs),
    rules: [
      rule("manual", any(
        ne("settings_readable", true),
        all(ne("cloud_recording_present", true), ne("auto_delete_present", true)),
        eq("cloud_recording_value", false),
      )),
      rule("fail", ne("auto_delete_value", true)),
      rule("warn", any(
        not(defined("retention_days")),
        { op: "gt", left: path("retention_days"), right: path("max_retention_days") },
        ne("lock_value", true),
        groupEvidenceIncomplete,
      )),
      rule("pass", { op: "always" }),
    ],
  },
  "ZOOM-COLLAB-04": {
    inputs: input("phone_readable", "auto_call_present", "ad_hoc_present", "auto_call_enable", "ad_hoc_enable", "auto_call_lock", "ad_hoc_lock"),
    rules: [
      rule("manual", any(
        ne("phone_readable", true),
        ne("auto_call_present", true),
        ne("ad_hoc_present", true),
        not(defined("auto_call_enable")),
        not(defined("ad_hoc_enable")),
      )),
      rule("warn", any(ne("auto_call_lock", true), ne("ad_hoc_lock", true))),
      rule("pass", { op: "always" }),
    ],
  },
  "ZOOM-COLLAB-05": inventory("warn", "warn"),
  "ZOOM-COLLAB-06": inventory("manual", "warn"),
  "ZOOM-COLLAB-07": {
    inputs: input(
      "settings_readable",
      "add_policy_present",
      "add_policy_enabled",
      "add_policy_selected_option",
      "chat_policy_present",
      "chat_policy_enabled",
      "chat_policy_selected_option",
      "add_policy_lock",
      "chat_policy_lock",
      ...groupInputs,
    ),
    rules: [
      rule("manual", any(
        ne("settings_readable", true),
        ne("add_policy_present", true),
        ne("chat_policy_present", true),
        not(defined("add_policy_enabled")),
        not(defined("chat_policy_enabled")),
        all(eq("add_policy_enabled", true), not(defined("add_policy_selected_option"))),
        all(eq("chat_policy_enabled", true), not(defined("chat_policy_selected_option"))),
      )),
      rule("fail", any(
        all(eq("add_policy_enabled", true), eq("add_policy_selected_option", 1)),
        all(eq("chat_policy_enabled", true), eq("chat_policy_selected_option", 1)),
      )),
      rule("warn", any(ne("add_policy_lock", true), ne("chat_policy_lock", true), groupEvidenceIncomplete)),
      rule("pass", { op: "always" }),
    ],
  },
  "ZOOM-COLLAB-08": manual(),
  "ZOOM-MTG-01": booleanSetting(true),
  "ZOOM-MTG-02": booleanSetting(true),
  "ZOOM-MTG-03": {
    inputs: input("settings_readable", "screen_setting_present", "screen_setting_value", "share_setting_present", "share_setting_value", "lock_value", ...groupInputs),
    rules: [
      rule("manual", any(
        ne("settings_readable", true),
        ne("screen_setting_present", true),
        all(ne("screen_setting_value", false), ne("share_setting_present", true)),
        all(ne("screen_setting_value", false), ne("share_setting_value", "host"), ne("share_setting_value", "all")),
      )),
      rule("fail", all(ne("screen_setting_value", false), eq("share_setting_value", "all"))),
      rule("warn", any(ne("lock_value", true), groupEvidenceIncomplete)),
      rule("pass", { op: "always" }),
    ],
  },
  "ZOOM-MTG-04": booleanSetting(false),
  "ZOOM-MTG-05": {
    inputs: input("settings_readable", "e2ee_setting_present", "e2ee_setting_value", "encryption_type_value", "lock_value", ...groupInputs),
    rules: [
      rule("manual", any(ne("settings_readable", true), ne("e2ee_setting_present", true))),
      rule("fail", ne("e2ee_setting_value", true)),
      rule("warn", any(ne("encryption_type_value", "e2ee"), ne("lock_value", true), groupEvidenceIncomplete)),
      rule("pass", { op: "always" }),
    ],
  },
  "ZOOM-MTG-06": booleanSetting(false),
  "ZOOM-MTG-07": {
    inputs: input("settings_readable", "personal_meeting_value", "scheduled_setting_present", "scheduled_setting_value", "instant_setting_present", "instant_setting_value", "scheduled_lock_value", "instant_lock_value", ...groupInputs),
    rules: [
      rule("manual", any(
        ne("settings_readable", true),
        all(ne("personal_meeting_value", false), any(ne("scheduled_setting_present", true), ne("instant_setting_present", true))),
      )),
      rule("fail", all(
        ne("personal_meeting_value", false),
        any(ne("scheduled_setting_value", false), ne("instant_setting_value", false)),
      )),
      rule("warn", any(ne("scheduled_lock_value", true), ne("instant_lock_value", true), groupEvidenceIncomplete)),
      rule("pass", { op: "always" }),
    ],
  },
  "ZOOM-MTG-08": booleanSetting(true),
  "ZOOM-MTG-09": {
    inputs: input("settings_readable", "setting_present", "setting_value", "region_count", "lock_value", ...groupInputs),
    rules: [
      rule("manual", any(ne("settings_readable", true), ne("setting_present", true))),
      rule("fail", ne("setting_value", true)),
      rule("warn", any(eq("region_count", 0), ne("lock_value", true), groupEvidenceIncomplete)),
      rule("pass", { op: "always" }),
    ],
  },
  "ZOOM-MTG-10": {
    inputs: input("settings_readable", "disclaimer_option", "legacy_setting_present", "legacy_setting_value", ...groupInputs),
    rules: [
      rule("manual", any(
        ne("settings_readable", true),
        all(not(defined("disclaimer_option")), ne("legacy_setting_present", true)),
      )),
      rule("fail", all(not(defined("disclaimer_option")), eq("legacy_setting_present", true), ne("legacy_setting_value", true))),
      rule("warn", any(
        all(defined("disclaimer_option"), not(matches("disclaimer_option", "all participants", "i"))),
        groupEvidenceIncomplete,
      )),
      rule("pass", any(matches("disclaimer_option", "all participants", "i"), eq("legacy_setting_value", true))),
      rule("manual", { op: "always" }),
    ],
  },
};

const checks: BatchCheckDefinition[] = rows.map(([id, control, title, severity, owner], index) => {
  const decision = ZOOM_EXECUTABLE_DECISIONS[id];
  const executable = deriveDecisionRules(id, decision.rules);
  return {
    id,
    control,
    title,
    severity,
    owner,
    surfaces: ZOOM_CHECK_SURFACES[id],
    evidenceFields: [...ZOOM_CHECK_SURFACES[id], "complete_source_counts"],
    decisionInputs: decision.inputs,
    decisionConstants: decision.constants,
    decisionRules: executable.rules,
    derivedFactRules: executable.derivedFactRules,
    decision: decisions[index],
  };
});
const idsFor = (owner: string): string[] => checks.filter((check) => check.owner === owner).map((check) => check.id);

export const ZOOM_RUNTIME_BEHAVIOR = [
  "Account settings are read through documented option views and sampled group overrides; a pass requires complete account and group evidence plus every required account-level lock.",
  "User, role-member, group, operation-log, and IM-group verdict facts use complete seen and declared-total counts, while exported evidence may retain bounded record samples.",
  "The account API exposes neither a decisive Team Chat encryption setting nor account vanity URL field; those findings remain manual rather than inferred from unrelated fields.",
] as const;

export const ZOOM_SPEC = buildBatchIntegrationSpec({
  slug: "zoom-sec-inspector",
  displayName: "Zoom Security Inspector",
  vendor: "Zoom",
  category: "collaboration",
  summary: "Portable contract for the shipped Zoom identity, collaboration-governance, and meeting-security assessments.",
  sourceModule: "cli/extensions/grc-tools/zoom.ts",
  baseServices: ["Zoom REST API", "Zoom Server-to-Server OAuth"],
  authentication: ZOOM_AUTH_RESOLVER,
  permissions: [
    { id: "account-settings-read", kind: "oauth-scope", value: "account:read:admin", unlocks: ["account-settings", "account-lock-settings", "managed-domains", "trusted-domains"] },
    { id: "users-read", kind: "oauth-scope", value: "user:read:list_users:admin", unlocks: ["current-user", "users", "user-settings"] },
    { id: "roles-read", kind: "oauth-scope", value: "role:read:list_roles:admin", unlocks: ["roles", "role-members"] },
    { id: "groups-read", kind: "oauth-scope", value: "group:read:list_groups:admin", unlocks: ["groups", "group-settings", "group-lock-settings"] },
    { id: "operation-logs-read", kind: "oauth-scope", value: "report:read:operation_logs:admin", unlocks: ["operation-logs"] },
    { id: "im-groups-read", kind: "oauth-scope", value: "imgroup:read:admin", unlocks: ["im-groups"] },
    { id: "phone-settings-read", kind: "oauth-scope", value: "phone:read:admin", unlocks: ["phone-settings"], notes: "Requires Zoom Phone licensing in addition to scope." },
  ],
  surfaces: ZOOM_SURFACES,
  checks,
  tools: {
    zoom_check_access: [],
    zoom_assess_identity: idsFor("zoom_assess_identity"),
    zoom_assess_collaboration_governance: idsFor("zoom_assess_collaboration_governance"),
    zoom_assess_meeting_security: idsFor("zoom_assess_meeting_security"),
    zoom_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [
    {
      surfaceIds: ["users", "role-members", "groups", "operation-logs"], cursorFields: ["next_page_token", "total_records"], pageSize: 300, itemCap: null, pageCap: 500,
      totalSemantics: "total_records is authoritative when returned; otherwise completion requires next_page_token exhaustion.",
      stopConditions: ["No next_page_token", "Declared total reached", "Caller cap", "500-page cap", "Repeated token", "Empty page with token", "Missing or inconsistent total"],
    },
    {
      surfaceIds: ["roles", "im-groups", "managed-domains", "trusted-domains"], cursorFields: [], pageSize: null, itemCap: null, pageCap: null,
      totalSemantics: "The runtime treats these documented single-response lists as complete on success.", stopConditions: ["Single response"],
    },
  ],
  rateLimit: {
    documentedLimit: "Zoom applies endpoint labels and app-level daily request limits",
    retryHeaders: ["Retry-After", "X-RateLimit-Category", "X-RateLimit-Remaining"],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "Honor Retry-After up to 30 seconds and retry three times with bounded backoff.",
  },
  runtimeBehavior: ZOOM_RUNTIME_BEHAVIOR,
  knownGaps: ["User OAuth, per-user settings drift, deeper Zoom Phone policy, and usage analytics are deferred."],
  sensitiveFields: ["client_secret", "access_token", "authorization", "cookie", "join_url", "start_url"],
  credentialFormats: ["Zoom OAuth bearer tokens", "OAuth client secrets", "meeting start and join URLs"],
  output: buildBatchOutputContract({
    files: [
      "README.md", "QUICK_REFERENCE.md", "metadata.json", "summary.md", "core_data/access.json", "core_data/current_user.json",
      "core_data/account_settings.json", "core_data/account_lock_settings.json", "core_data/users.json", "core_data/roles.json",
      "core_data/groups.json", "core_data/im_groups.json", "core_data/managed_domains.json", "core_data/trusted_domains.json",
      "core_data/operation_logs.json", "core_data/phone_account_settings.json", "analysis/findings.json", "analysis/identity.json",
      "analysis/collaboration-governance.json", "analysis/meeting-security.json", "analysis/summary.json",
      "compliance/executive_summary.md", "compliance/unified_compliance_matrix.md", "compliance/fedramp.md",
      "compliance/cmmc.md", "compliance/soc-2.md", "compliance/cis.md", "compliance/pci-dss.md",
      "compliance/stig.md", "compliance/irap.md", "compliance/ismap.md",
    ],
    conditionalFiles: ["_errors.log"],
    overwritePolicy: "Allocate zoom-audit-<UTC timestamp> and add a numeric suffix when either the directory or paired archive exists.",
    archivePairing: "Create <allocated-directory>.zip beside the allocated Zoom audit directory with the same suffix.",
  }),
});
