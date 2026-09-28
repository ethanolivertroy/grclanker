import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
  deriveDecisionRules,
  type BatchCheckDefinition,
  type BatchCompletenessDefinition,
} from "./batch-spec-builder.js";
import { SLACK_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import type { PortableValue, VerdictCondition, VerdictRule } from "./spec-model.js";

const SLACK_SURFACES = [
  ["auth-test", "POST", "/api/auth.test"], ["users", "GET", "/api/users.list"],
  ["workspaces", "POST", "/api/admin.teams.list"], ["workspace-settings", "POST", "/api/admin.teams.settings.info"],
  ["workspace-admins", "GET", "/api/admin.teams.admins.list"], ["admin-users", "POST", "/api/admin.users.list"],
  ["session-settings", "POST", "/api/admin.users.session.getSettings"], ["approved-apps", "GET", "/api/admin.apps.approved.list"],
  ["restricted-apps", "GET", "/api/admin.apps.restricted.list"], ["barriers", "GET", "/api/admin.barriers.list"],
  ["channels", "POST", "/api/admin.conversations.search"], ["channel-preferences", "POST", "/api/admin.conversations.getConversationPrefs"],
  ["channel-retention", "POST", "/api/admin.conversations.getCustomRetention"], ["emoji", "GET", "/api/admin.emoji.list"],
  ["analytics-export", "GET", "/api/admin.analytics.getFile"], ["team-preferences", "POST", "/api/team.preferences.list"],
  ["scim-users", "GET", "/scim/v2/Users"], ["audit-logs", "GET", "/audit/v1/logs"], ["audit-schemas", "GET", "/audit/v1/schemas"],
].map(([id, method, path]) => ({
  id,
  method: method as "GET" | "POST",
  path,
  service: path.startsWith("/scim") ? "Slack SCIM API" : path.startsWith("/audit") ? "Slack Audit Logs API" : "Slack Web/Admin API",
  documentationUrl: path.startsWith("/scim") ? "https://docs.slack.dev/admins/scim-api/" : path.startsWith("/audit") ? "https://docs.slack.dev/admins/audit-logs-api/" : `https://api.slack.com/methods/${path.split("/").at(-1)}`,
  fields: ["projected response fields consumed by the corresponding runtime assessment"],
}));

const SLACK_CHECK_SURFACES: Readonly<Record<string, readonly string[]>> = {
  "SLACK-ID-01": ["users"], "SLACK-ID-02": ["users"], "SLACK-ID-03": ["scim-users"],
  "SLACK-ID-04": ["users", "scim-users"], "SLACK-ID-05": ["users"],
  "SLACK-ADMIN-01": ["workspaces", "workspace-admins"], "SLACK-ADMIN-02": ["admin-users"],
  "SLACK-ADMIN-03": ["admin-users", "session-settings"], "SLACK-ADMIN-04": [],
  "SLACK-ADMIN-05": ["workspaces", "workspace-settings"], "SLACK-ADMIN-06": [],
  "SLACK-ADMIN-07": ["workspaces", "workspace-settings"], "SLACK-ADMIN-08": ["emoji", "admin-users", "workspaces", "workspace-admins"],
  "SLACK-ADMIN-09": ["analytics-export"], "SLACK-APP-01": ["approved-apps"], "SLACK-APP-02": ["restricted-apps"],
  "SLACK-APP-03": ["approved-apps"], "SLACK-APP-04": ["barriers"], "SLACK-APP-05": [],
  "SLACK-APP-06": ["auth-test", "workspaces", "team-preferences"], "SLACK-APP-07": [],
  "SLACK-CHAN-01": ["channels"], "SLACK-CHAN-02": ["channels", "channel-preferences"],
  "SLACK-CHAN-03": ["channels", "channel-retention"], "SLACK-CHAN-04": [], "SLACK-CHAN-05": [],
  "SLACK-MON-01": ["audit-logs"], "SLACK-MON-02": ["audit-logs"], "SLACK-MON-03": ["audit-logs"],
  "SLACK-MON-04": ["audit-schemas"], "SLACK-MON-05": ["audit-logs"], "SLACK-MON-06": [],
};

const ALL_FAILURE_MODES = ["truncated", "error", "denied", "not-collected"] as const;
const completeFrom = (sourceIds: readonly string[], semantics: string): BatchCompletenessDefinition => ({
  sources: sourceIds.map((surfaceId) => ({ surfaceId, falseWhen: ALL_FAILURE_MODES })),
  semantics,
});
const SLACK_COMPLETENESS: Readonly<Record<string, Readonly<Record<string, BatchCompletenessDefinition>>>> = {
  "SLACK-ID-01": { users_complete: completeFrom(["users"], "true only when users.list is readable and its cursor is exhausted without a page or item cap.") },
  "SLACK-ID-02": { users_complete: completeFrom(["users"], "true only when users.list is readable and its cursor is exhausted without a page or item cap.") },
  "SLACK-ID-03": { scim_complete: completeFrom(["scim-users"], "true only when SCIM /Users is readable and its cursor is exhausted without a page or item cap.") },
  "SLACK-ID-04": { complete: completeFrom(["users", "scim-users"], "true only when both users.list and SCIM /Users are readable and completely paged.") },
  "SLACK-ID-05": { users_complete: completeFrom(["users"], "true only when users.list is readable and its cursor is exhausted without a page or item cap.") },
  "SLACK-ADMIN-01": { complete: completeFrom(["workspaces", "workspace-admins"], "true only when the workspace list is completely paged and every listed workspace has a readable, completely paged administrator roster.") },
  "SLACK-ADMIN-02": { users_complete: completeFrom(["admin-users"], "true only when admin.users.list is readable and its cursor is exhausted without a page or item cap.") },
  "SLACK-ADMIN-03": { complete: completeFrom(["admin-users", "session-settings"], "true only when admin.users.list is completely paged and every active organization user has a successful explicit session-settings response.") },
  "SLACK-ADMIN-05": { teams_complete: completeFrom(["workspaces"], "true only when admin.teams.list is readable and completely paged; workspace-settings failures do not change this fact.") },
  "SLACK-ADMIN-07": { teams_complete: completeFrom(["workspaces"], "true only when admin.teams.list is readable and completely paged; workspace-settings failures are counted separately and do not change this fact.") },
  "SLACK-ADMIN-08": {
    emoji_complete: completeFrom(["emoji"], "true only when admin.emoji.list is readable and completely paged."),
    roster_complete: completeFrom(["admin-users", "workspaces", "workspace-admins"], "true only when the organization-user roster and workspace list are readable and completely paged and every listed workspace has a readable, completely paged administrator roster."),
  },
  "SLACK-APP-01": { approved_complete: completeFrom(["approved-apps"], "true only when the approved-app inventory is readable and completely paged.") },
  "SLACK-APP-02": { restricted_complete: completeFrom(["restricted-apps"], "true only when the restricted-app inventory is readable and completely paged.") },
  "SLACK-APP-03": { approved_complete: completeFrom(["approved-apps"], "true only when the approved-app inventory is readable and completely paged.") },
  "SLACK-APP-04": { barrier_complete: completeFrom(["barriers"], "true only when the information-barrier inventory is readable and completely paged.") },
  "SLACK-APP-06": {
    coverage_complete: {
      sources: [
        { surfaceId: "workspaces", falseWhen: ALL_FAILURE_MODES },
        { surfaceId: "auth-test", falseWhen: ["error", "denied", "not-collected", "missing-required-field"] },
      ],
      semantics: "true only when admin.teams.list is readable, completely paged, and returns no more than one workspace while auth.test is readable and returns a non-empty team_id; team.preferences.list readability does not change this fact.",
    },
  },
  "SLACK-CHAN-01": { external_complete: completeFrom(["channels"], "true only when the external-shared-channel search is readable and completely paged.") },
  "SLACK-CHAN-02": { complete: completeFrom(["channels", "channel-preferences"], "true only when the channel search is completely paged, every announcement channel is classifiable, and every required conversation-preferences read succeeds.") },
  "SLACK-CHAN-03": { complete: completeFrom(["channels", "channel-retention"], "true only when the channel search is completely paged and every required custom-retention read succeeds.") },
  "SLACK-MON-01": { audit_complete: completeFrom(["audit-logs"], "true only when the audit-log lookback is readable and completely paged within its configured limit.") },
  "SLACK-MON-02": { audit_complete: completeFrom(["audit-logs"], "true only when the audit-log lookback is readable and completely paged within its configured limit.") },
  "SLACK-MON-03": { audit_complete: completeFrom(["audit-logs"], "true only when the audit-log lookback is readable and completely paged within its configured limit.") },
  "SLACK-MON-04": { schema_complete: completeFrom(["audit-schemas"], "true only when the audit-schema inventory is readable and completely paged.") },
  "SLACK-MON-05": { audit_complete: completeFrom(["audit-logs"], "true only when the audit-log lookback is readable and completely paged within its configured limit.") },
};

const checkRows = [
  ["SLACK-ID-01", 2, "MFA enrollment", "critical", "slack_assess_identity"],
  ["SLACK-ID-02", 15, "Guest account inventory", "medium", "slack_assess_identity"],
  ["SLACK-ID-03", 22, "SCIM provisioning coverage", "high", "slack_assess_identity"],
  ["SLACK-ID-04", 23, "User lifecycle alignment", "high", "slack_assess_identity"],
  ["SLACK-ID-05", 23, "Deactivated user visibility", "info", "slack_assess_identity"],
  ["SLACK-ADMIN-01", 14, "Workspace admin inventory", "high", "slack_assess_admin_access"],
  ["SLACK-ADMIN-02", 1, "SSO enforcement", "critical", "slack_assess_admin_access"],
  ["SLACK-ADMIN-03", 3, "Session duration limits", "high", "slack_assess_admin_access"],
  ["SLACK-ADMIN-04", 4, "Session idle timeout", "medium", "slack_assess_admin_access"],
  ["SLACK-ADMIN-05", 17, "Workspace discoverability", "medium", "slack_assess_admin_access"],
  ["SLACK-ADMIN-06", 5, "Mobile session controls", "medium", "slack_assess_admin_access"],
  ["SLACK-ADMIN-07", 16, "Email domain restrictions", "high", "slack_assess_admin_access"],
  ["SLACK-ADMIN-08", 19, "Custom emoji governance", "low", "slack_assess_admin_access"],
  ["SLACK-ADMIN-09", 24, "Workspace analytics access", "medium", "slack_assess_admin_access"],
  ["SLACK-APP-01", 9, "Approved app inventory", "high", "slack_assess_integrations"],
  ["SLACK-APP-02", 9, "Restricted app policy", "medium", "slack_assess_integrations"],
  ["SLACK-APP-03", 10, "Custom and sensitive-scope apps", "medium", "slack_assess_integrations"],
  ["SLACK-APP-04", 8, "Information barriers", "high", "slack_assess_integrations"],
  ["SLACK-APP-05", 11, "DLP and Discovery evidence", "medium", "slack_assess_integrations"],
  ["SLACK-APP-06", 6, "File upload restrictions", "medium", "slack_assess_integrations"],
  ["SLACK-APP-07", 25, "Token rotation and revocation", "medium", "slack_assess_integrations"],
  ["SLACK-CHAN-01", 7, "Slack Connect exposure", "high", "slack_assess_channel_governance"],
  ["SLACK-CHAN-02", 18, "Channel posting restrictions", "medium", "slack_assess_channel_governance"],
  ["SLACK-CHAN-03", 12, "Channel retention overrides", "medium", "slack_assess_channel_governance"],
  ["SLACK-CHAN-04", 20, "External email ingestion", "medium", "slack_assess_channel_governance"],
  ["SLACK-CHAN-05", 21, "Link previews and URL unfurling", "medium", "slack_assess_channel_governance"],
  ["SLACK-MON-01", 13, "Audit Logs API access", "critical", "slack_assess_monitoring"],
  ["SLACK-MON-02", 13, "Audit log recency", "high", "slack_assess_monitoring"],
  ["SLACK-MON-03", 13, "Security event visibility", "medium", "slack_assess_monitoring"],
  ["SLACK-MON-04", 13, "Audit schema visibility", "low", "slack_assess_monitoring"],
  ["SLACK-MON-05", 7, "External sharing monitoring", "medium", "slack_assess_monitoring"],
  ["SLACK-MON-06", 13, "SIEM streaming evidence", "medium", "slack_assess_monitoring"],
] as const;

const decisions = [
  "return fail when any active human user has has_2fa=false, pass when every active human in a complete non-empty inventory has has_2fa=true, and warn for empty, unknown, or partial enrollment evidence.",
  "return warn when any active guest exists or the inventory is empty or partial, and pass only when a complete non-empty human inventory contains no active guest.",
  "return fail when readable SCIM configuration has zero users, pass when the complete SCIM user inventory is non-empty, and warn when that non-empty inventory is partial.",
  "return fail when any SCIM-active user is deactivated in Slack, pass when complete non-empty SCIM and Slack inventories have no mismatch, and warn for partial or empty comparison evidence.",
  "return pass when a complete non-empty human inventory exposes deactivated users for review, and warn when the inventory is empty or partial.",
  "return fail when any workspace exceeds the configured administrator maximum, pass when every workspace and admin list is complete and within it, and warn for partial coverage.",
  "return fail when any active organization user has has_sso=false, pass when every active user in a complete non-empty inventory has has_sso=true, and warn for empty, unknown, or partial SSO evidence.",
  "return fail when any sampled user session exceeds the configured hour maximum, pass when every active user has an explicit duration within it, warn for inherited defaults or sampled or partial coverage, and manual when no duration can be read.",
  "always return manual because Slack exposes session duration but no idle-timeout setting.",
  "return fail when any workspace has discoverability=open, pass when every workspace in a complete non-empty inventory has a known non-open value, and warn for unknown or partial evidence.",
  "always return manual because mobile-specific session and jailbreak controls are not exposed by the read API.",
  "return fail when any readable workspace has an empty email-domain restriction, pass when every workspace has a populated domain and coverage is complete, and warn for unreadable or partial workspace settings.",
  "return fail when any custom emoji was uploaded by a proven non-admin, pass when complete emoji and admin inventories show every uploader is an admin or owner, warn for partial evidence, and manual when the uploader cannot be compared to an admin roster.",
  "always return manual because the API can probe analytics export but cannot list which administrators hold analytics access.",
  "return pass when the complete approved-app inventory is non-empty and warn when it is empty or partial.",
  "return pass when the complete restricted-app inventory is non-empty and warn when it is empty or partial because emptiness does not prove an approval policy.",
  "return warn when any approved app is internal, outside the Marketplace, or has a sensitive scope, pass when a complete non-empty inventory has none, and warn for empty or partial evidence.",
  "return pass when the complete information-barrier inventory is non-empty and warn when it is empty or partial.",
  "always return manual because public APIs expose neither Discovery entitlement nor DLP scanning status.",
  "return pass for disable_file_uploads=disallow_all or type:owner,type:admin with complete workspace scope, warn for type:regular or incomplete scope, fail for allow_all, and warn for an undocumented value.",
  "always return manual because token rotation is app-level and no read method lists token age, rotation state, or legacy-token revocation.",
  "return warn when any externally shared channel exists, pass when a complete search is empty, and warn when emptiness comes from a partial search.",
  "return fail when any general, org-default, or mandatory channel allows unrestricted posting, pass when every such channel restricts posting to admins or owners and coverage is complete, and warn for unknown or partial preferences.",
  "return fail when any readable channel override retains data for less than the configured minimum, pass when complete channel and override evidence has none, and warn for unreadable or partial coverage.",
  "always return manual because the Admin conversations API exposes no channel email-address or email-to-channel setting.",
  "always return manual because admin team settings expose no link-preview or URL-unfurl control.",
  "return fail when the readable audit lookback is empty, pass when it is non-empty and complete, and warn when it is non-empty but truncated.",
  "return fail when the newest dated audit event is older than one day, pass when it is at most one day old with a complete window, and warn when dates are absent or the window is partial.",
  "return pass when a complete audit window contains at least one common security-administration action and warn when none is visible or the window is partial.",
  "return pass when the Audit Logs schemas endpoint returns at least one schema and warn when it returns none.",
  "return pass when a complete audit window contains at least one Slack Connect or external-sharing action and warn when none is visible or the window is partial.",
  "always return manual because the pull-based Audit Logs API does not report SIEM streaming or export destinations.",
] as const;

interface SlackExecutableDecision {
  inputs: Readonly<Record<string, string>>;
  rules: readonly VerdictRule[];
}
const value = (entry: PortableValue) => ({ kind: "value" as const, value: entry });
const path = (name: string) => ({ kind: "path" as const, path: name });
const compare = (op: "eq" | "ne" | "gt" | "gte" | "lt" | "lte", name: string, entry: PortableValue): VerdictCondition => ({
  op,
  left: path(name),
  right: value(entry),
});
const eq = (name: string, entry: PortableValue): VerdictCondition => compare("eq", name, entry);
const ne = (name: string, entry: PortableValue): VerdictCondition => compare("ne", name, entry);
const gt = (name: string, entry: PortableValue): VerdictCondition => compare("gt", name, entry);
const defined = (name: string): VerdictCondition => ({ op: "defined", operand: path(name) });
const all = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "and", conditions });
const any = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "or", conditions });
const rule = (status: VerdictRule["status"], condition: VerdictCondition): VerdictRule => ({ status, condition });
const ordered = (manual: VerdictCondition, fail: VerdictCondition | undefined, warn: VerdictCondition | undefined, pass: VerdictCondition | undefined): readonly VerdictRule[] => [
  rule("manual", manual),
  ...(fail ? [rule("fail", fail)] : []),
  ...(warn ? [rule("warn", warn)] : []),
  ...(pass ? [rule("pass", pass)] : []),
  rule("manual", { op: "always" }),
];
const input = (...names: string[]): Readonly<Record<string, string>> => Object.fromEntries(
  names.map((name) => {
    const counts: Readonly<Record<string, string>> = {
      human_user_count: "non-bot users", active_user_count: "active human users", admin_user_count: "active owners and administrators",
      admin_inventory_count: "administrator assignments across readable workspaces", excessive_admin_workspace_count: "workspaces above the administrator threshold",
      guest_count: "active guest users", unknown_mfa_count: "active human users without known MFA state", without_mfa_count: "active human users with MFA disabled",
      unknown_sso_count: "active organization users without known SSO state", without_sso_count: "active organization users with SSO disabled", workspace_count: "Grid workspaces",
      channel_count: "channels", announcement_channel_count: "announcement-only channels",
      external_count: "external organizations or externally shared channels", external_event_count: "external-collaboration audit events",
      approved_count: "approved applications", scim_count: "SCIM user records", scim_user_count: "active users represented in SCIM",
      settings_error_count: "workspace preference reads that failed", duration_count: "readable session durations",
      overlong_count: "session durations above the maximum", audit_count: "audit events in the lookback", security_event_count: "events in the security action set",
      non_admin_upload_count: "uploads by non-administrators", retention_record_count: "retention preference records", short_retention_count: "retention values below the minimum",
      restricted_count: "restricted applications", schema_count: "audit schemas",
      barrier_count: "information barriers", emoji_count: "custom emoji",
      unknown_count: "records whose required classification is unknown", domain_count: "distinct verified or allowed domains",
    };
    const booleans: Readonly<Record<string, string>> = {
      complete: "defined by this check's structured completeness contract", users_readable: "user rosters were returned", users_complete: "defined by this check's structured completeness contract",
      teams_readable: "Grid workspaces were returned", teams_complete: "all workspace pages completed", every_admin_list_unreadable: "no workspace admin roster was readable",
      channels_readable: "channels were returned", external_readable: "external-collaboration records were returned", external_complete: "all external pages completed",
      approved_readable: "approved applications were returned", approved_complete: "all approved-app pages completed", scim_readable: "SCIM users were returned",
      scim_complete: "all SCIM pages completed", preferences_readable: "workspace preferences were returned", session_readable: "session controls were returned",
      audit_readable: "audit events were returned", audit_complete: "audit collection covered the lookback", restricted_readable: "restricted applications were returned",
      restricted_complete: "all restricted-app pages completed", schema_readable: "audit schemas were returned", schema_complete: "all schema pages completed",
      barrier_readable: "information barriers were returned", barrier_complete: "all barrier pages completed", coverage_complete: "all users and barrier assignments were readable",
      emoji_readable: "custom emoji were returned", emoji_complete: "all emoji pages completed", roster_complete: "all required rosters completed",
    };
    const raw: Readonly<Record<string, string>> = {
      setting_value: "Raw Slack preference value retained without outcome translation.", latest_age_days: "Age in whole days of the newest relevant audit event.",
    };
    const definition = counts[name] ? `Non-negative cardinality of ${counts[name]} in the complete Slack inventory at the verdict point.`
      : booleans[name] ? `Boolean true exactly when ${booleans[name]}.` : raw[name];
    if (!definition) throw new Error(`Slack primitive ${name} lacks an explicit portable definition`);
    return [name, definition];
  }),
);
const inputWith = (
  overrides: Readonly<Record<string, string>>,
  ...names: string[]
): Readonly<Record<string, string>> => Object.fromEntries(
  names.map((name) => [name, overrides[name] ?? input(name)[name]]),
);
const manual = (): SlackExecutableDecision => ({ inputs: {}, rules: [rule("manual", { op: "always" })] });
const inventory = (prefix: string, options: { empty?: "fail" | "warn" | "manual"; positive?: "pass" | "warn" } = {}): SlackExecutableDecision => {
  const readable = `${prefix}_readable`;
  const complete = `${prefix}_complete`;
  const count = `${prefix}_count`;
  const empty = options.empty ?? "warn";
  const positive = options.positive ?? "pass";
  return {
    inputs: input(readable, complete, count),
    rules: [
      rule("manual", ne(readable, true)),
      ...(empty === "manual" ? [rule("manual", eq(count, 0))] : [rule(empty, eq(count, 0))]),
      rule("warn", ne(complete, true)),
      rule(positive, gt(count, 0)),
      rule("manual", { op: "always" }),
    ],
  };
};

const SLACK_EXECUTABLE_DECISIONS: Readonly<Record<string, SlackExecutableDecision>> = {
  "SLACK-ID-01": {
    inputs: input("users_readable", "users_complete", "active_user_count", "without_mfa_count", "unknown_mfa_count"),
    rules: ordered(ne("users_readable", true), gt("without_mfa_count", 0), any(eq("active_user_count", 0), gt("unknown_mfa_count", 0), ne("users_complete", true)), gt("active_user_count", 0)),
  },
  "SLACK-ID-02": {
    inputs: input("users_readable", "users_complete", "active_user_count", "guest_count"),
    rules: ordered(ne("users_readable", true), undefined, any(gt("guest_count", 0), eq("active_user_count", 0), ne("users_complete", true)), all(gt("active_user_count", 0), eq("guest_count", 0))),
  },
  "SLACK-ID-03": inventory("scim", { empty: "fail" }),
  "SLACK-ID-04": {
    inputs: inputWith({
      mismatch_count: "Non-negative cardinality of SCIM user records whose `active` field is not false and whose normalized `userName` equals the normalized email of a deactivated Slack user; only when `userName` is absent does the comparison use the SCIM record's normalized primary email instead.",
    }, "users_readable", "scim_readable", "complete", "scim_user_count", "mismatch_count"),
    rules: ordered(any(ne("users_readable", true), ne("scim_readable", true)), gt("mismatch_count", 0), any(ne("complete", true), eq("scim_user_count", 0)), gt("scim_user_count", 0)),
  },
  "SLACK-ID-05": {
    inputs: input("users_readable", "users_complete", "human_user_count"),
    rules: ordered(ne("users_readable", true), undefined, any(ne("users_complete", true), eq("human_user_count", 0)), gt("human_user_count", 0)),
  },
  "SLACK-ADMIN-01": {
    inputs: input("teams_readable", "admin_inventory_count", "complete", "excessive_admin_workspace_count"),
    rules: ordered(any(ne("teams_readable", true), eq("admin_inventory_count", 0)), gt("excessive_admin_workspace_count", 0), ne("complete", true), gt("admin_inventory_count", 0)),
  },
  "SLACK-ADMIN-02": {
    inputs: input("users_readable", "users_complete", "active_user_count", "without_sso_count", "unknown_sso_count"),
    rules: ordered(ne("users_readable", true), gt("without_sso_count", 0), any(eq("active_user_count", 0), gt("unknown_sso_count", 0), ne("users_complete", true)), gt("active_user_count", 0)),
  },
  "SLACK-ADMIN-03": {
    inputs: input("session_readable", "complete", "duration_count", "overlong_count"),
    rules: ordered(any(ne("session_readable", true), eq("duration_count", 0)), gt("overlong_count", 0), ne("complete", true), gt("duration_count", 0)),
  },
  "SLACK-ADMIN-04": manual(),
  "SLACK-ADMIN-05": {
    inputs: inputWith({
      open_count: "Non-negative cardinality of Slack Grid workspaces whose normalized `discoverability` value from admin.teams.list equals `open`.",
    }, "teams_readable", "teams_complete", "workspace_count", "open_count", "unknown_count"),
    rules: ordered(any(ne("teams_readable", true), eq("workspace_count", 0)), gt("open_count", 0), any(gt("unknown_count", 0), ne("teams_complete", true)), gt("workspace_count", 0)),
  },
  "SLACK-ADMIN-06": manual(),
  "SLACK-ADMIN-07": {
    inputs: inputWith({
      unrestricted_count: "Non-negative cardinality of readable admin.teams.settings.info responses whose trimmed `team.email_domain` value is an empty string.",
    }, "teams_readable", "teams_complete", "domain_count", "unrestricted_count", "settings_error_count"),
    rules: ordered(any(ne("teams_readable", true), eq("domain_count", 0)), gt("unrestricted_count", 0), any(gt("settings_error_count", 0), ne("teams_complete", true)), gt("domain_count", 0)),
  },
  "SLACK-ADMIN-08": {
    inputs: input("emoji_readable", "emoji_complete", "emoji_count", "admin_user_count", "every_admin_list_unreadable", "roster_complete", "non_admin_upload_count"),
    rules: ordered(any(ne("emoji_readable", true), eq("emoji_count", 0), eq("admin_user_count", 0), eq("every_admin_list_unreadable", true)), gt("non_admin_upload_count", 0), any(ne("roster_complete", true), ne("emoji_complete", true)), gt("emoji_count", 0)),
  },
  "SLACK-ADMIN-09": manual(),
  "SLACK-APP-01": inventory("approved"),
  "SLACK-APP-02": inventory("restricted"),
  "SLACK-APP-03": {
    inputs: inputWith({
      flagged_count: "Non-negative cardinality of distinct approved-app names for which the app is internal, is outside the Slack Marketplace, or has at least one scope whose `is_sensitive` field is true.",
    }, "approved_readable", "approved_complete", "approved_count", "flagged_count"),
    rules: ordered(ne("approved_readable", true), undefined, any(eq("approved_count", 0), gt("flagged_count", 0), ne("approved_complete", true)), all(gt("approved_count", 0), eq("flagged_count", 0))),
  },
  "SLACK-APP-04": inventory("barrier"),
  "SLACK-APP-05": manual(),
  "SLACK-APP-06": {
    inputs: input("preferences_readable", "setting_value", "coverage_complete"),
    rules: ordered(
      any(ne("preferences_readable", true), { op: "not", condition: defined("setting_value") }),
      eq("setting_value", "allow_all"),
      any(
        eq("setting_value", "type:regular"),
        ne("coverage_complete", true),
        all(
          ne("setting_value", "disallow_all"),
          ne("setting_value", "type:owner,type:admin"),
        ),
      ),
      any(eq("setting_value", "disallow_all"), eq("setting_value", "type:owner,type:admin")),
    ),
  },
  "SLACK-APP-07": manual(),
  "SLACK-CHAN-01": {
    inputs: input("external_readable", "external_complete", "external_count"),
    rules: [
      rule("manual", ne("external_readable", true)),
      rule("warn", gt("external_count", 0)),
      rule("warn", ne("external_complete", true)),
      rule("pass", eq("external_count", 0)),
      rule("manual", { op: "always" }),
    ],
  },
  "SLACK-CHAN-02": {
    inputs: inputWith({
      preference_count: "Non-negative cardinality of announcement-channel records with a successful admin.conversations.getConversationPrefs response.",
      unrestricted_count: "Non-negative cardinality of announcement-channel preference records whose posting-restriction classifier returns false.",
    }, "channels_readable", "channel_count", "announcement_channel_count", "preference_count", "complete", "unrestricted_count", "unknown_count"),
    rules: ordered(any(ne("channels_readable", true), eq("channel_count", 0), eq("announcement_channel_count", 0), eq("preference_count", 0)), gt("unrestricted_count", 0), any(gt("unknown_count", 0), ne("complete", true)), eq("unrestricted_count", 0)),
  },
  "SLACK-CHAN-03": {
    inputs: input("channels_readable", "retention_record_count", "complete", "short_retention_count"),
    rules: ordered(any(ne("channels_readable", true), eq("retention_record_count", 0)), gt("short_retention_count", 0), ne("complete", true), eq("short_retention_count", 0)),
  },
  "SLACK-CHAN-04": manual(),
  "SLACK-CHAN-05": manual(),
  "SLACK-MON-01": inventory("audit", { empty: "fail" }),
  "SLACK-MON-02": {
    inputs: input("audit_readable", "audit_complete", "latest_age_days"),
    rules: ordered(ne("audit_readable", true), gt("latest_age_days", 1), any({ op: "not", condition: defined("latest_age_days") }, ne("audit_complete", true)), compare("lte", "latest_age_days", 1)),
  },
  "SLACK-MON-03": {
    inputs: input("audit_readable", "audit_complete", "security_event_count"),
    rules: ordered(ne("audit_readable", true), undefined, any(eq("security_event_count", 0), ne("audit_complete", true)), gt("security_event_count", 0)),
  },
  "SLACK-MON-04": inventory("schema"),
  "SLACK-MON-05": {
    inputs: input("audit_readable", "audit_complete", "external_event_count"),
    rules: ordered(ne("audit_readable", true), undefined, any(eq("external_event_count", 0), ne("audit_complete", true)), gt("external_event_count", 0)),
  },
  "SLACK-MON-06": manual(),
};

const checks: BatchCheckDefinition[] = checkRows.map(([id, control, title, severity, owner], index) => {
  const decision = SLACK_EXECUTABLE_DECISIONS[id];
  const executable = deriveDecisionRules(id, decision.rules);
  return {
    id,
    control,
    title,
    severity,
    owner,
    surfaces: SLACK_CHECK_SURFACES[id],
    evidenceFields: [...SLACK_CHECK_SURFACES[id], "complete_source_counts"],
    decisionInputs: decision.inputs,
    decisionRules: executable.rules,
    derivedFactRules: executable.derivedFactRules,
    completeness: SLACK_COMPLETENESS[id],
    decision: decisions[index],
  };
});
const idsFor = (owner: string): string[] => checks.filter((check) => check.owner === owner).map((check) => check.id);

export const SLACK_RUNTIME_BEHAVIOR = [
  "Eight controls remain manual because the public read APIs do not expose a decisive setting; the runtime names the exact Admin Console or SIEM evidence instead of calling write endpoints.",
  "Cross-inventory findings require every dependent workspace, admin, channel, SCIM, or audit inventory to be complete before pass; partial secondary reads demote the dependent result.",
  "SCIM, Web API, Admin API, and Audit Logs pagination use different cursor locations and preserve stalled cursors, page caps, item caps, and unknown totals as incomplete evidence.",
] as const;

export const SLACK_SPEC = buildBatchIntegrationSpec({
  slug: "slack-sec-inspector",
  displayName: "Slack Security Inspector",
  vendor: "Slack",
  category: "collaboration",
  summary: "Portable contract for the shipped Slack Enterprise Grid identity, administration, app, channel, and monitoring assessments.",
  sourceModule: "cli/extensions/grc-tools/slack.ts",
  baseServices: ["Slack Web API", "Slack Admin API", "Slack SCIM API", "Slack Audit Logs API"],
  authentication: SLACK_AUTH_RESOLVER,
  permissions: [
    { id: "users-read", kind: "oauth-scope", value: "users:read", unlocks: ["users"] },
    { id: "admin-teams-read", kind: "oauth-scope", value: "admin.teams:read", unlocks: ["workspaces", "workspace-settings", "workspace-admins", "team-preferences"] },
    { id: "admin-users-read", kind: "oauth-scope", value: "admin.users:read", unlocks: ["admin-users", "session-settings"] },
    { id: "admin-apps-read", kind: "oauth-scope", value: "admin.apps:read", unlocks: ["approved-apps", "restricted-apps"] },
    { id: "admin-barriers-read", kind: "oauth-scope", value: "admin.barriers:read", unlocks: ["barriers"] },
    { id: "admin-conversations-read", kind: "oauth-scope", value: "admin.conversations:read", unlocks: ["channels", "channel-preferences", "channel-retention"] },
    { id: "admin-emoji-read", kind: "oauth-scope", value: "admin.emoji:read", unlocks: ["emoji"] },
    { id: "admin-analytics-read", kind: "oauth-scope", value: "admin.analytics:read", unlocks: ["analytics-export"] },
    { id: "auditlogs-read", kind: "oauth-scope", value: "auditlogs:read", unlocks: ["audit-logs", "audit-schemas"] },
    { id: "scim-read", kind: "license", value: "SCIM API entitlement with a read-capable SCIM token", unlocks: ["scim-users"] },
    { id: "enterprise-grid", kind: "plan", value: "Enterprise Grid for org-level Admin and Audit Logs APIs", unlocks: SLACK_SURFACES.filter((surface) => surface.path.includes("/admin.") || surface.path.startsWith("/audit")).map((surface) => surface.id) },
  ],
  surfaces: SLACK_SURFACES,
  checks,
  tools: {
    slack_check_access: [],
    slack_assess_identity: idsFor("slack_assess_identity"),
    slack_assess_admin_access: idsFor("slack_assess_admin_access"),
    slack_assess_integrations: idsFor("slack_assess_integrations"),
    slack_assess_channel_governance: idsFor("slack_assess_channel_governance"),
    slack_assess_monitoring: idsFor("slack_assess_monitoring"),
    slack_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [
    {
      surfaceIds: SLACK_SURFACES.filter((surface) => !surface.path.startsWith("/scim") && !["auth-test", "workspace-settings", "session-settings", "channel-preferences", "channel-retention", "analytics-export", "team-preferences"].includes(surface.id)).map((surface) => surface.id),
      cursorFields: ["response_metadata.next_cursor", "next_cursor"], pageSize: null, itemCap: null, pageCap: 50,
      totalSemantics: "Completion requires an empty cursor; item and page caps, repeated cursors, and a page adding no records remain partial.",
      stopConditions: ["Empty cursor", "Caller item cap", "50-page cap", "Repeated cursor", "Page adds no records while cursor remains"],
    },
    {
      surfaceIds: ["scim-users"], cursorFields: ["startIndex", "itemsPerPage", "totalResults"], pageSize: 100, itemCap: null, pageCap: 50,
      totalSemantics: "totalResults is authoritative and must be reached; missing or inconsistent totals are partial.",
      stopConditions: ["Seen reaches totalResults", "Caller item cap", "50-page cap", "Non-advancing startIndex", "Empty page before total"],
    },
  ],
  rateLimit: {
    documentedLimit: "Method-specific Slack rate tiers",
    retryHeaders: ["Retry-After"],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "Honor Retry-After up to the runtime bound and retry 429 responses twice; exhausted reads stay explicit.",
  },
  runtimeBehavior: SLACK_RUNTIME_BEHAVIOR,
  knownGaps: ["Discovery DLP details, guest expiry, several workspace restrictions, and standalone reporters remain unavailable."],
  sensitiveFields: ["token", "scimToken", "authorization", "cookie", "webhook_url"],
  credentialFormats: ["xoxb, xoxp, xoxe, and xapp token families", "SCIM bearer tokens", "webhook path secrets"],
  output: buildBatchOutputContract({
    files: [
      "README.md", "QUICK_REFERENCE.md", "metadata.json", "core_data/access.json", "core_data/identity.json",
      "core_data/admin-access.json", "core_data/integrations.json", "core_data/channel-governance.json", "core_data/monitoring.json",
      "analysis/identity.json", "analysis/admin-access.json", "analysis/integrations.json", "analysis/channel-governance.json",
      "analysis/monitoring.json", "reports/identity.md", "reports/admin-access.md", "reports/integrations.md",
      "reports/channel-governance.md", "reports/monitoring.md", "analysis/findings.json",
      "compliance/executive_summary.md", "compliance/unified_compliance_matrix.md", "compliance/fedramp.md",
      "compliance/cmmc.md", "compliance/soc-2.md", "compliance/cis.md", "compliance/pci-dss.md",
      "compliance/stig.md", "compliance/irap.md", "compliance/ismap.md",
    ],
    conditionalFiles: ["_errors.log"],
    overwritePolicy: "Allocate slack-audit-<UTC timestamp> and add a numeric suffix when either the directory or paired archive exists.",
    archivePairing: "Create <allocated-directory>.zip beside the allocated Slack audit directory.",
  }),
});
