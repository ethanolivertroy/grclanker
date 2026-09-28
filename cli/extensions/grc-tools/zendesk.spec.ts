import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
  deriveDecisionRules,
  type BatchCheckDefinition,
  type BatchCompletenessDefinition,
} from "./batch-spec-builder.js";
import { ZENDESK_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import type { PortableValue, VerdictCondition, VerdictRule } from "./spec-model.js";

const zendeskSurface = (id: string, path: string, fields: readonly string[]) => ({
  id,
  path: `/api/v2${path}`,
  service: "Zendesk Support API",
  documentationUrl: "https://developer.zendesk.com/api-reference/ticketing/",
  fields,
});
const ZENDESK_SURFACES = [
  zendeskSurface("current-user", "/users/me", ["user.id", "user.email", "user.role"]),
  zendeskSurface("account-settings", "/account/settings", ["settings.api", "settings.tickets", "settings.attachments", "settings.sandbox"]),
  zendeskSurface("security-settings", "/security_settings", ["security_settings.authentication", "security_settings.ip", "security_settings.session_expiration", "security_settings.mobile_session_expiration"]),
  zendeskSurface("team-members", "/users?role[]=agent&role[]=admin", ["users.id", "users.email", "users.role", "users.custom_role_id", "users.active", "users.suspended", "users.last_login_at", "users.two_factor_auth_enabled", "users.restricted_agent"]),
  zendeskSurface("custom-roles", "/custom_roles", ["custom_roles.id", "custom_roles.name", "custom_roles.configuration", "custom_roles.team_member_count"]),
  zendeskSurface("groups", "/groups", ["groups.id", "groups.name", "groups.deleted"]),
  zendeskSurface("group-memberships", "/group_memberships", ["group_memberships.id", "group_memberships.group_id", "group_memberships.user_id"]),
  zendeskSurface("audit-logs-recent", "/audit_logs?sort=-created_at", ["audit_logs.id", "audit_logs.created_at", "audit_logs.action", "audit_logs.source_type", "audit_logs.source_id", "audit_logs.actor_id"]),
  zendeskSurface("audit-log-oldest", "/audit_logs?sort=created_at&page[size]=1", ["audit_logs.id", "audit_logs.created_at"]),
  zendeskSurface("api-token-audit-logs", "/audit_logs?filter[source_type]=apitoken&sort=-created_at", ["audit_logs.id", "audit_logs.created_at", "audit_logs.action", "audit_logs.source_type", "audit_logs.source_id", "audit_logs.source_label"]),
  zendeskSurface("deletion-schedules", "/deletion_schedules", ["deletion_schedules.id", "deletion_schedules.title", "deletion_schedules.object", "deletion_schedules.active", "deletion_schedules.default", "deletion_schedules.conditions", "deletion_schedules.updated_at"]),
  zendeskSurface("oauth-clients", "/oauth/clients", ["clients.id", "clients.name", "clients.allowed_scopes", "clients.redirect_uri", "clients.public"]),
  zendeskSurface("oauth-tokens", "/oauth/tokens?all=true", ["tokens.id", "tokens.client_id", "tokens.user_id", "tokens.scopes", "tokens.expires_at", "tokens.used_at"]),
  zendeskSurface("app-installations", "/apps/installations", ["installations.id", "installations.app_id", "installations.enabled", "installations.settings", "installations.product", "installations.role_restrictions", "installations.group_restrictions"]),
  zendeskSurface("owned-apps", "/apps/owned", ["apps.id", "apps.name", "apps.deprecated", "apps.obsolete"]),
  zendeskSurface("brands", "/brands", ["brands.id", "brands.name", "brands.active", "brands.has_help_center"]),
  zendeskSurface("webhooks", "/webhooks", ["webhooks.id", "webhooks.name", "webhooks.active", "webhooks.endpoint", "webhooks.http_method", "webhooks.authentication"]),
  zendeskSurface("targets", "/targets", ["targets.id", "targets.title", "targets.active", "targets.type", "targets.target_url"]),
  zendeskSurface("triggers", "/triggers", ["triggers.id", "triggers.title", "triggers.active", "triggers.actions"]),
  zendeskSurface("automations", "/automations", ["automations.id", "automations.title", "automations.active", "automations.actions"]),
  zendeskSurface("sharing-agreements", "/sharing_agreements", ["sharing_agreements.id", "sharing_agreements.name", "sharing_agreements.status"]),
  zendeskSurface("suspended-tickets", "/suspended_tickets?sort_by=created_at&sort_order=asc", ["suspended_tickets.id", "suspended_tickets.created_at", "suspended_tickets.subject", "suspended_tickets.cause"]),
] as const;

const ZENDESK_CHECK_SURFACES: Readonly<Record<number, readonly string[]>> = {
  1: ["security-settings"],
  2: ["security-settings", "team-members"],
  3: ["security-settings"],
  4: ["security-settings"],
  5: ["security-settings"],
  6: ["team-members", "custom-roles"],
  7: ["team-members"],
  8: ["groups", "group-memberships"],
  9: ["audit-logs-recent"],
  10: ["audit-log-oldest"],
  11: ["account-settings", "security-settings"],
  12: ["deletion-schedules", "account-settings", "custom-roles"],
  13: ["account-settings", "api-token-audit-logs"],
  14: ["oauth-clients", "oauth-tokens"],
  15: ["app-installations", "owned-apps"],
  16: ["owned-apps"],
  17: ["account-settings"],
  18: ["account-settings"],
  19: ["account-settings"],
  20: ["suspended-tickets"],
  21: ["security-settings", "account-settings"],
  22: ["brands"],
  23: ["sharing-agreements"],
  24: ["targets", "webhooks"],
  25: ["triggers", "automations", "targets", "webhooks"],
};

const ALL_FAILURE_MODES = ["truncated", "error", "denied", "not-collected"] as const;
const TRUNCATION_ONLY = ["truncated"] as const;
const completeFrom = (
  sourceIds: readonly string[],
  semantics: string,
  falseWhen: readonly ("truncated" | "error" | "denied" | "not-collected")[] = ALL_FAILURE_MODES,
): BatchCompletenessDefinition => ({
  sources: sourceIds.map((surfaceId) => ({ surfaceId, falseWhen })),
  semantics,
});
const ZENDESK_COMPLETENESS: Readonly<Record<string, Readonly<Record<string, BatchCompletenessDefinition>>>> = {
  "ZD-02": { complete: completeFrom(["team-members"], "true when the team-member inventory is untruncated; read errors, denials, and not-collected states are handled by readability facts and do not themselves change this fact.", TRUNCATION_ONLY) },
  "ZD-06": { complete: completeFrom(["team-members", "custom-roles"], "true when team members and custom roles are untruncated; read errors, denials, and not-collected states are handled by readability facts and do not themselves change this fact.", TRUNCATION_ONLY) },
  "ZD-07": { complete: completeFrom(["team-members"], "true when the team-member inventory is untruncated; read errors, denials, and not-collected states are handled by readability facts and do not themselves change this fact.", TRUNCATION_ONLY) },
  "ZD-08": { complete: completeFrom(["groups", "group-memberships"], "true when group and membership inventories are untruncated; read errors, denials, and not-collected states are handled by readability facts and do not themselves change this fact.", TRUNCATION_ONLY) },
  "ZD-12": {
    complete: completeFrom(["deletion-schedules"], "true only when the deletion-schedule inventory is readable and untruncated."),
    secondary_complete: completeFrom(["account-settings", "custom-roles"], "true only when account settings and custom roles are readable and the custom-role inventory is untruncated."),
  },
  "ZD-13": { token_history_complete: completeFrom(["api-token-audit-logs"], "true only when API-token audit history is readable and untruncated; account settings do not contribute.") },
  "ZD-14": {
    clients_complete: completeFrom(["oauth-clients"], "true only when OAuth clients are readable and untruncated."),
    tokens_complete: completeFrom(["oauth-tokens"], "true only when OAuth tokens are readable and untruncated."),
  },
  "ZD-15": {
    installations_complete: completeFrom(["app-installations"], "true only when app installations are readable and untruncated."),
    owned_apps_complete: completeFrom(["owned-apps"], "true only when owned apps are readable and untruncated."),
  },
  "ZD-16": { complete: completeFrom(["owned-apps"], "true only when owned apps are readable and untruncated.") },
  "ZD-20": { complete: completeFrom(["suspended-tickets"], "true only when suspended tickets are readable and untruncated.") },
  "ZD-21": { account_settings_complete: completeFrom(["account-settings"], "true only when account settings are readable; security settings do not contribute.") },
  "ZD-22": { complete: completeFrom(["brands"], "true only when brands are readable and untruncated.") },
  "ZD-23": { complete: completeFrom(["sharing-agreements"], "true only when sharing agreements are readable and untruncated.") },
  "ZD-24": { complete: completeFrom(["targets", "webhooks"], "true only when targets and webhooks are both readable and untruncated.") },
  "ZD-25": {
    rules_complete: completeFrom(["triggers", "automations"], "true only when triggers and automations are both readable and untruncated."),
    destination_sources_complete: completeFrom(["targets", "webhooks"], "true only when targets and webhooks are both readable and untruncated."),
  },
};

const titles = [
  "SSO enforcement enabled", "Two-factor authentication required for agents", "Password policy meets complexity requirements",
  "IP restrictions configured for agent access", "Session timeout configured and reasonable", "Agent roles follow least privilege",
  "No excessive admin accounts", "Group-based access controls configured", "Audit logging enabled and accessible",
  "Audit log retention meets compliance requirements", "HIPAA compliance mode enabled when applicable",
  "Data deletion and redaction policies configured", "API tokens are minimal and reviewed",
  "OAuth application permissions are scoped", "Marketplace apps reviewed for permissions",
  "Private and custom apps have appropriate scope", "Sandbox environment used for testing",
  "Authenticated attachment downloads configured", "File attachment restrictions configured",
  "Suspended ticket handling automated", "End-user authentication required", "Brand security settings consistent",
  "External sharing agreements reviewed", "External notification targets use HTTPS",
  "Triggers and automations do not send data to external URLs",
] as const;
const ownerFor = (control: number): string => [1, 2, 3, 4, 5, 21].includes(control)
  ? "zendesk_assess_authentication"
  : [6, 7, 8, 13, 14].includes(control)
    ? "zendesk_assess_access_control"
    : [9, 10, 11, 12, 18, 19, 20].includes(control)
      ? "zendesk_assess_data_protection"
      : "zendesk_assess_integrations";

const decisions = [
  "return pass when team-member SSO is enforced, Zendesk password login is disabled, and at least one SSO method is enabled; warn when SSO is enforced without a method or while password login remains enabled; and fail when SSO is not enforced.",
  "return fail when any active team member explicitly lacks 2FA or account enforcement is disabled without enforced SSO, pass when enforcement is enabled and every member in a complete inventory reports 2FA enabled, warn for missing enrollment flags or partial coverage, and manual when MFA depends on the identity provider.",
  "return pass for the Recommended preset or a Custom policy with length at least 12, complexity at least two, mixed case, at most ten failed attempts, email-local-part rejection, and history at least five or unlimited; warn for High or a deficient Custom policy, and fail for every lower preset.",
  "return pass when IP restriction is enabled with at least one range, warn when enabled with no range, and fail when disabled.",
  "return pass when positive agent and applicable mobile inactivity timeouts are at or below the configured threshold, fail when the agent timeout is zero or above three times the threshold, and warn for every other threshold violation.",
  "return fail when any populated custom role grants administrator-equivalent permissions, warn for partial inventories, unassigned administrator-equivalent roles, or an all-unrestricted agent population, and pass when complete role and team inventories show none.",
  "return fail when active administrators exceed the configured threshold, warn when any administrator is stale, undated, or the inventory is partial, and pass when the non-empty complete inventory is within the threshold and all administrators are recent.",
  "return pass when complete inventories contain more than one group and at least one membership, and warn when only one group exists, no membership exists, or either inventory is truncated.",
  "return pass when the recent audit-log endpoint returns at least one entry and fills or cleanly completes its 25-entry sample, warn when paging cuts that sample short, and manual when the endpoint is unavailable or a completed sample is unexpectedly empty.",
  "return pass when the dated oldest audit entry is at least the configured retention age and warn when it is younger; an absent or undated oldest entry is manual.",
  "always return manual because the published Account Settings and Security Settings APIs expose no HIPAA or Advanced Data Privacy and Protection field.",
  "return fail when a complete deletion-schedule inventory is empty or has no active schedule, pass when it has a conditioned active ticket schedule and all companion evidence is complete, and warn for truncation, no active ticket schedule, or any active schedule without conditions.",
  "return pass when API-token authentication is disabled and audit evidence is complete, warn when it is enabled but the event history shows no outstanding token, and manual when enabled tokens remain or account settings or token history are unavailable.",
  "return fail when any OAuth client is unscoped or has a non-local HTTP redirect, pass when complete client and token inventories are empty or all clients are scoped with HTTPS redirects and every token is expiring and recently used, and warn for public, privileged, non-expiring, stale, undated, hidden, partial, or unreadable token evidence.",
  "return pass when complete installation and owned-app inventories prove no installed apps, warn when the installation inventory truncates before its first app, and manual when any installation exists because the API does not prove that marketplace permissions were reviewed.",
  "return pass when the complete owned-app inventory is empty, warn when any owned app is deprecated or obsolete or the inventory truncates before its first app, and manual for other non-empty inventories because manifest scope review is not automated.",
  "return pass when account settings report the sandbox feature enabled, warn when disabled, and manual when the flag is absent.",
  "return pass when authenticated attachment downloads are enabled and every listed CDN host uses HTTPS, warn when authentication is enabled but any CDN host is insecure, and fail when authenticated downloads are disabled.",
  "always return manual because the API exposes attachment size and email-attachment posture but not allowed file types or malicious-attachment detection.",
  "return pass when the complete suspended-ticket queue is empty or every queued ticket is dated and newer than the configured age, and warn for stale, undated, or partial queue evidence.",
  "return pass when end users have enforced SSO with a method, password login under Recommended or High, or SSO-only login; warn for enforced SSO without a method or a weaker password preset, fail when no login method exists, and keep anonymous-ticket submission as a named manual limitation.",
  "return pass when an administrator reads every active brand and all have one known help-center state, warn for a non-admin view, truncation, or mixed or unknown states, and manual when no brand is visible.",
  "return pass when the complete sharing-agreement inventory is empty, warn when any agreement is failed, ssl_error, or configuration_error or the inventory truncates before its first record, and manual when accepted or pending external agreements require business review.",
  "return fail when any active target or webhook uses a non-HTTPS endpoint, pass when complete readable inventories contain no active destination or every destination is HTTPS and every webhook has authentication, and warn for missing, partial, or unauthenticated destination evidence.",
  "return fail when any active trigger or automation sends ticket data to an HTTP destination, pass when the complete non-empty rule inventory has no external notification action and destination lookups are complete, warn for external actions or partial evidence, and manual when no active rule is visible or either rule inventory is unavailable.",
] as const;

interface ZendeskExecutableDecision { inputs: Readonly<Record<string, string>>; rules: readonly VerdictRule[] }
const value = (entry: PortableValue) => ({ kind: "value" as const, value: entry });
const path = (name: string) => ({ kind: "path" as const, path: name });
const cmp = (op: "eq" | "ne" | "gt" | "gte" | "lt" | "lte", name: string, entry: PortableValue): VerdictCondition => ({ op, left: path(name), right: value(entry) });
const eq = (name: string, entry: PortableValue) => cmp("eq", name, entry);
const ne = (name: string, entry: PortableValue) => cmp("ne", name, entry);
const gt = (name: string, entry: PortableValue) => cmp("gt", name, entry);
const lte = (name: string, entry: PortableValue) => cmp("lte", name, entry);
const all = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "and", conditions });
const any = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "or", conditions });
const rule = (status: VerdictRule["status"], condition: VerdictCondition): VerdictRule => ({ status, condition });
const input = (...names: string[]) => Object.fromEntries(names.map((name) => {
  const counts: Readonly<Record<string, string>> = {
    sso_method_count: "configured SSO methods", team_count: "agent and administrator users", without_two_factor_count: "team members explicitly lacking two-factor",
    unknown_two_factor_count: "team members with unknown two-factor state", custom_gap_count: "custom policy fields missing secure values", range_count: "allowed network ranges",
    populated_admin_equivalent_count: "assigned administrator-equivalent roles", unassigned_admin_equivalent_count: "unassigned administrator-equivalent roles",
    agent_count: "agents", unrestricted_agent_count: "agents with unrestricted access", admin_count: "administrators", stale_admin_count: "stale administrators",
    undated_admin_count: "administrators without last login", group_count: "groups", membership_count: "group memberships", entry_count: "audit entries",
    schedule_count: "automation or trigger schedules", active_count: "active records", active_ticket_count: "active tickets matched by schedules",
    active_without_conditions_count: "active schedules without limiting conditions", outstanding_token_count: "active API tokens", client_count: "OAuth clients",
    unscoped_count: "OAuth clients without limited scopes", insecure_redirect_count: "clients with HTTP or wildcard redirects", token_count: "OAuth tokens",
    public_client_count: "public OAuth clients", privileged_token_count: "tokens carrying administrator-equivalent scopes", non_expiring_token_count: "tokens without expiry",
    stale_token_count: "tokens beyond the age threshold", undated_token_count: "tokens without creation dates", installation_count: "installed applications",
    owned_app_count: "account-owned applications", retired_count: "retired owned applications", insecure_cdn_count: "attachments outside the accepted HTTPS CDN",
    stale_count: "records beyond the review threshold", undated_count: "records without timestamps", brand_count: "brands",
    inconsistent_state_count: "brands with conflicting host or security state", agreement_count: "agreements", broken_count: "agreements missing acceptance or current state",
    insecure_count: "webhooks failing HTTPS or authentication requirements", unauthenticated_webhook_count: "webhooks without authentication",
    rule_count: "triggers and automations", insecure_destination_count: "external destinations with insecure transport or missing auth", external_action_count: "actions sending data externally",
  };
  const booleans: Readonly<Record<string, string>> = {
    readable: "the check's required Zendesk response was returned", complete: "all check-specific pages and child reads completed",
    credential_is_admin: "the authenticated principal is an administrator", fields_present: "all required account fields exist", enforce_sso: "SSO enforcement is enabled",
    zendesk_login: "native Zendesk login remains enabled", team_readable: "agent and administrator users were returned", security_readable: "security settings were returned",
    two_factor_enforce_present: "the two-factor enforcement field exists", two_factor_enforce_value: "two-factor enforcement is enabled",
    enforce_sso_value: "the raw enforce-SSO field is enabled", enabled_present: "the network restriction enabled field exists", enabled: "network restrictions are enabled",
    mobile_app_access: "mobile app access is enabled", roles_readable: "custom roles were returned", groups_readable: "groups were returned",
    memberships_readable: "group memberships were returned", truncated: "the audit collection stopped before exhaustion", dateable: "a parseable timestamp exists",
    secondary_complete: "the secondary ticket or condition inventory completed", settings_readable: "API and authentication settings were returned",
    api_token_access: "API token access is enabled", token_history_readable: "API token history was returned", token_history_complete: "all token history pages completed",
    clients_readable: "OAuth clients were returned", clients_complete: "all client pages completed", tokens_readable: "OAuth tokens were returned",
    tokens_complete: "all token pages completed", installations_readable: "app installations were returned", installations_complete: "all installation pages completed",
    owned_apps_complete: "metadata reads completed for every owned app", flag_present: "the named account setting exists", sandbox_enabled: "sandbox mode is enabled",
    private_attachments: "attachments require authentication", account_settings_complete: "all required security fields were present", admin_view: "the principal can read admin-only brand settings",
    any_readable: "at least one webhook source was readable", rules_readable: "trigger and automation rules were returned", rules_complete: "all rule pages completed",
    destination_sources_complete: "all referenced destination records were readable",
  };
  const raw: Readonly<Record<string, string>> = {
    security_policy_name: "Raw normalized selected security-policy name.", agent_session_timeout: "Agent browser timeout in minutes.",
    mobile_app_session_timeout: "Mobile app timeout in minutes.", threshold_minutes: "Preferred maximum timeout in minutes.",
    severe_threshold_minutes: "Failure timeout threshold in minutes.", admin_threshold: "Maximum accepted administrator population.",
    sample_size: "Maximum audit records requested.", oldest_age_days: "Age in whole days of the oldest retained audit record.",
    required_retention_days: "Minimum required audit retention in days.",
  };
  const definition = counts[name] ? `Non-negative cardinality of ${counts[name]} in the complete Zendesk inventory at the verdict point.`
    : booleans[name] ? `Boolean true exactly when ${booleans[name]}.` : raw[name];
  if (!definition) throw new Error(`Zendesk primitive ${name} lacks an explicit portable definition`);
  return [name, definition];
}));
const manual = (): ZendeskExecutableDecision => ({ inputs: {}, rules: [rule("manual", { op: "always" })] });
const withCredentialPassCap = (rules: readonly VerdictRule[]): readonly VerdictRule[] =>
  rules.flatMap((entry) => entry.status === "pass"
    ? [
        {
          status: "warn" as const,
          condition: all(ne("credential_is_admin", true), entry.condition),
          note: "An otherwise passing finding is capped at warn unless the current-user response confirms an administrator principal.",
        },
        entry,
      ]
    : [entry]);

const ZENDESK_EXECUTABLE_DECISIONS: Readonly<Record<string, ZendeskExecutableDecision>> = {
  "ZD-01": {
    inputs: input("readable", "fields_present", "enforce_sso", "zendesk_login", "sso_method_count"),
    rules: [
      rule("manual", any(ne("readable", true), ne("fields_present", true))),
      rule("pass", all(eq("enforce_sso", true), eq("zendesk_login", false), gt("sso_method_count", 0))),
      rule("warn", eq("enforce_sso", true)),
      rule("fail", { op: "always" }),
    ],
  },
  "ZD-02": {
    inputs: input("team_readable", "team_count", "security_readable", "two_factor_enforce_present", "two_factor_enforce_value", "enforce_sso_value", "without_two_factor_count", "unknown_two_factor_count", "complete"),
    rules: [
      rule("manual", any(ne("team_readable", true), eq("team_count", 0))),
      rule("fail", all(gt("without_two_factor_count", 0), ne("security_readable", true))),
      rule("manual", any(ne("security_readable", true), ne("two_factor_enforce_present", true))),
      rule("manual", all(eq("two_factor_enforce_value", false), eq("enforce_sso_value", true))),
      rule("fail", eq("two_factor_enforce_value", false)),
      rule("warn", any(gt("without_two_factor_count", 0), gt("unknown_two_factor_count", 0), ne("complete", true))),
      rule("pass", { op: "always" }),
    ],
  },
  "ZD-03": {
    inputs: input("readable", "security_policy_name", "custom_gap_count"),
    rules: [
      rule("manual", any(ne("readable", true), { op: "not", condition: { op: "defined", operand: path("security_policy_name") } })),
      rule("pass", any(eq("security_policy_name", "recommended"), all(eq("security_policy_name", "custom"), eq("custom_gap_count", 0)))),
      rule("warn", any(eq("security_policy_name", "custom"), eq("security_policy_name", "high"))),
      rule("fail", { op: "always" }),
    ],
  },
  "ZD-04": {
    inputs: input("readable", "enabled_present", "enabled", "range_count"),
    rules: [
      rule("manual", any(ne("readable", true), ne("enabled_present", true))),
      rule("pass", all(eq("enabled", true), gt("range_count", 0))),
      rule("warn", eq("enabled", true)),
      rule("fail", { op: "always" }),
    ],
  },
  "ZD-05": {
    inputs: input("readable", "agent_session_timeout", "mobile_app_access", "mobile_app_session_timeout", "threshold_minutes", "severe_threshold_minutes"),
    rules: [
      rule("manual", any(ne("readable", true), { op: "not", condition: { op: "defined", operand: path("agent_session_timeout") } })),
      rule("fail", any(lte("agent_session_timeout", 0), { op: "gt", left: path("agent_session_timeout"), right: path("severe_threshold_minutes") })),
      rule("warn", any(
        { op: "gt", left: path("agent_session_timeout"), right: path("threshold_minutes") },
        all(
          ne("mobile_app_access", false),
          { op: "defined", operand: path("mobile_app_session_timeout") },
          any(lte("mobile_app_session_timeout", 0), { op: "gt", left: path("mobile_app_session_timeout"), right: path("threshold_minutes") }),
        ),
      )),
      rule("pass", { op: "always" }),
    ],
  },
  "ZD-06": {
    inputs: input("team_readable", "team_count", "roles_readable", "complete", "populated_admin_equivalent_count", "unassigned_admin_equivalent_count", "agent_count", "unrestricted_agent_count"),
    rules: [
      rule("manual", any(ne("team_readable", true), eq("team_count", 0), ne("roles_readable", true))),
      rule("fail", gt("populated_admin_equivalent_count", 0)),
      rule("warn", any(ne("complete", true), gt("unassigned_admin_equivalent_count", 0), all(gt("agent_count", 0), { op: "eq", left: path("unrestricted_agent_count"), right: path("agent_count") }))),
      rule("pass", { op: "always" }),
    ],
  },
  "ZD-07": {
    inputs: input("team_readable", "admin_count", "admin_threshold", "stale_admin_count", "undated_admin_count", "complete"),
    rules: [
      rule("manual", any(ne("team_readable", true), eq("admin_count", 0))),
      rule("fail", { op: "gt", left: path("admin_count"), right: path("admin_threshold") }),
      rule("warn", any(gt("stale_admin_count", 0), gt("undated_admin_count", 0), ne("complete", true))),
      rule("pass", { op: "always" }),
    ],
  },
  "ZD-08": {
    inputs: input("groups_readable", "memberships_readable", "group_count", "membership_count", "complete"),
    rules: [
      rule("manual", any(ne("groups_readable", true), ne("memberships_readable", true), eq("group_count", 0))),
      rule("warn", any(eq("group_count", 1), eq("membership_count", 0), ne("complete", true))),
      rule("pass", { op: "always" }),
    ],
  },
  "ZD-09": {
    inputs: input("readable", "entry_count", "truncated", "sample_size"),
    rules: [
      rule("manual", any(ne("readable", true), eq("entry_count", 0))),
      rule("warn", all(eq("truncated", true), { op: "lt", left: path("entry_count"), right: path("sample_size") })),
      rule("pass", { op: "always" }),
    ],
  },
  "ZD-10": {
    inputs: input("readable", "dateable", "oldest_age_days", "required_retention_days"),
    rules: [
      rule("manual", any(ne("readable", true), ne("dateable", true))),
      rule("pass", { op: "gte", left: path("oldest_age_days"), right: path("required_retention_days") }),
      rule("warn", { op: "always" }),
    ],
  },
  "ZD-11": manual(),
  "ZD-12": {
    inputs: input("readable", "complete", "schedule_count", "active_count", "active_ticket_count", "active_without_conditions_count", "secondary_complete"),
    rules: [
      rule("manual", ne("readable", true)),
      rule("warn", all(ne("complete", true), any(eq("schedule_count", 0), eq("active_count", 0)))),
      rule("fail", any(eq("schedule_count", 0), eq("active_count", 0))),
      rule("warn", any(eq("active_ticket_count", 0), gt("active_without_conditions_count", 0), ne("complete", true), ne("secondary_complete", true))),
      rule("pass", { op: "always" }),
    ],
  },
  "ZD-13": {
    inputs: input("settings_readable", "api_token_access", "token_history_readable", "token_history_complete", "outstanding_token_count"),
    rules: [
      rule("manual", ne("settings_readable", true)),
      rule("warn", all(eq("api_token_access", false), ne("token_history_complete", true))),
      rule("pass", eq("api_token_access", false)),
      rule("manual", ne("token_history_readable", true)),
      rule("warn", eq("outstanding_token_count", 0)),
      rule("manual", { op: "always" }),
    ],
  },
  "ZD-14": {
    inputs: input("clients_readable", "clients_complete", "client_count", "unscoped_count", "insecure_redirect_count", "tokens_readable", "tokens_complete", "token_count", "public_client_count", "privileged_token_count", "non_expiring_token_count", "stale_token_count", "undated_token_count"),
    rules: [
      rule("manual", ne("clients_readable", true)),
      rule("fail", any(gt("unscoped_count", 0), gt("insecure_redirect_count", 0))),
      rule("warn", any(
        ne("tokens_readable", true),
        ne("clients_complete", true),
        ne("tokens_complete", true),
        gt("public_client_count", 0),
        gt("privileged_token_count", 0),
        gt("non_expiring_token_count", 0),
        gt("stale_token_count", 0),
        gt("undated_token_count", 0),
        all(eq("client_count", 0), gt("token_count", 0)),
      )),
      rule("pass", { op: "always" }),
    ],
  },
  "ZD-15": {
    inputs: input("installations_readable", "installations_complete", "installation_count", "owned_apps_complete"),
    rules: [
      rule("manual", ne("installations_readable", true)),
      rule("warn", all(eq("installation_count", 0), ne("installations_complete", true))),
      rule("warn", all(eq("installation_count", 0), ne("owned_apps_complete", true))),
      rule("pass", eq("installation_count", 0)),
      rule("manual", { op: "always" }),
    ],
  },
  "ZD-16": {
    inputs: input("readable", "complete", "owned_app_count", "retired_count"),
    rules: [
      rule("manual", ne("readable", true)),
      rule("warn", all(eq("owned_app_count", 0), ne("complete", true))),
      rule("pass", eq("owned_app_count", 0)),
      rule("warn", gt("retired_count", 0)),
      rule("manual", { op: "always" }),
    ],
  },
  "ZD-17": {
    inputs: input("readable", "flag_present", "sandbox_enabled"),
    rules: [rule("manual", any(ne("readable", true), ne("flag_present", true))), rule("pass", eq("sandbox_enabled", true)), rule("warn", { op: "always" })],
  },
  "ZD-18": {
    inputs: input("readable", "flag_present", "private_attachments", "insecure_cdn_count"),
    rules: [
      rule("manual", any(ne("readable", true), ne("flag_present", true))),
      rule("pass", all(eq("private_attachments", true), eq("insecure_cdn_count", 0))),
      rule("warn", eq("private_attachments", true)),
      rule("fail", { op: "always" }),
    ],
  },
  "ZD-19": manual(),
  "ZD-20": {
    inputs: input("readable", "complete", "stale_count", "undated_count"),
    rules: [
      rule("manual", ne("readable", true)),
      rule("warn", any(gt("stale_count", 0), gt("undated_count", 0), ne("complete", true))),
      rule("pass", { op: "always" }),
    ],
  },
  "ZD-21": {
    inputs: input("security_readable", "fields_present", "enforce_sso", "zendesk_login", "sso_method_count", "security_policy_name", "account_settings_complete"),
    rules: [
      rule("manual", any(ne("security_readable", true), ne("fields_present", true))),
      rule("warn", all(eq("enforce_sso", true), eq("sso_method_count", 0))),
      rule("warn", all(eq("zendesk_login", true), ne("security_policy_name", "recommended"), ne("security_policy_name", "high"))),
      rule("fail", all(eq("enforce_sso", false), eq("zendesk_login", false), eq("sso_method_count", 0))),
      rule("warn", ne("account_settings_complete", true)),
      rule("pass", { op: "always" }),
    ],
  },
  "ZD-22": {
    inputs: input("readable", "brand_count", "admin_view", "complete", "inconsistent_state_count"),
    rules: [
      rule("manual", any(ne("readable", true), eq("brand_count", 0))),
      rule("warn", any(ne("admin_view", true), ne("complete", true), gt("inconsistent_state_count", 0))),
      rule("pass", { op: "always" }),
    ],
  },
  "ZD-23": {
    inputs: input("readable", "complete", "agreement_count", "broken_count"),
    rules: [
      rule("manual", ne("readable", true)),
      rule("warn", all(eq("agreement_count", 0), ne("complete", true))),
      rule("pass", eq("agreement_count", 0)),
      rule("warn", gt("broken_count", 0)),
      rule("manual", { op: "always" }),
    ],
  },
  "ZD-24": {
    inputs: input("any_readable", "complete", "insecure_count", "unauthenticated_webhook_count"),
    rules: [
      rule("manual", ne("any_readable", true)),
      rule("fail", gt("insecure_count", 0)),
      rule("warn", any(ne("complete", true), gt("unauthenticated_webhook_count", 0))),
      rule("pass", { op: "always" }),
    ],
  },
  "ZD-25": {
    inputs: input("rules_readable", "rule_count", "rules_complete", "insecure_destination_count", "external_action_count", "destination_sources_complete"),
    rules: [
      rule("manual", any(ne("rules_readable", true), eq("rule_count", 0))),
      rule("fail", gt("insecure_destination_count", 0)),
      rule("warn", any(gt("external_action_count", 0), ne("rules_complete", true), ne("destination_sources_complete", true))),
      rule("pass", { op: "always" }),
    ],
  },
};

const checks: BatchCheckDefinition[] = titles.map((title, index) => {
  const control = index + 1;
  const id = `ZD-${String(control).padStart(2, "0")}`;
  const decision = ZENDESK_EXECUTABLE_DECISIONS[id];
  const executable = deriveDecisionRules(id, withCredentialPassCap(decision.rules));
  return {
    id,
    control,
    title,
    severity: [1, 2, 6, 11].includes(control) ? "critical" : [3, 4, 7, 9, 12, 13, 14, 21, 24, 25].includes(control) ? "high" : "medium",
    owner: ownerFor(control),
    surfaces: ZENDESK_CHECK_SURFACES[control],
    evidenceFields: [...ZENDESK_CHECK_SURFACES[control], "complete_source_counts"],
    decisionInputs: decision.rules.some((entry) => entry.status === "pass")
      ? {
        ...decision.inputs,
        credential_is_admin: "True only when a complete current-user response identifies the authenticated vendor principal as a Zendesk administrator; false includes a non-admin, missing, or unreadable role and caps only an otherwise passing finding.",
      }
      : decision.inputs,
    decisionRules: executable.rules,
    derivedFactRules: executable.derivedFactRules,
    completeness: ZENDESK_COMPLETENESS[id],
    decision: decisions[index],
  };
});
const idsFor = (owner: string): string[] => checks.filter((check) => check.owner === owner).map((check) => check.id);

export const ZENDESK_RUNTIME_BEHAVIOR = [
  "Cursor pagination is preferred and offset pagination is retained defensively; both deduplicate stable record IDs and mark cap, repeated-link, and inconsistent-total exits partial.",
  "Admin-only, Enterprise-only, and plan-gated reads produce explicit manual findings with endpoint and evidence instructions; forbidden evidence never becomes an empty pass.",
  "HIPAA mode, allowed attachment types, and anonymous-ticket posture have no decisive published read field and remain manual.",
] as const;

export const ZENDESK_SPEC = buildBatchIntegrationSpec({
  slug: "zendesk-sec-inspector",
  displayName: "Zendesk Security Inspector",
  vendor: "Zendesk",
  category: "customer-support",
  summary: "Portable contract for the shipped Zendesk authentication, access-control, data-protection, and integration assessments.",
  sourceModule: "cli/extensions/grc-tools/zendesk.ts",
  baseServices: ["Zendesk Support API"],
  authentication: ZENDESK_AUTH_RESOLVER,
  permissions: [
    { id: "agent-role", kind: "role", value: "Zendesk agent", unlocks: ["current-user", "team-members", "groups", "group-memberships"] },
    { id: "admin-role", kind: "role", value: "Zendesk administrator", unlocks: ZENDESK_SURFACES.filter((surface) => !["custom-roles", "audit-logs-recent", "audit-log-oldest", "api-token-audit-logs"].includes(surface.id)).map((surface) => surface.id), notes: "Individual endpoint and plan entitlements still apply." },
    { id: "enterprise-plan", kind: "plan", value: "Zendesk Enterprise audit-log and custom-role entitlements", unlocks: ["custom-roles", "audit-logs-recent", "audit-log-oldest", "api-token-audit-logs"] },
    { id: "oauth-read", kind: "oauth-scope", value: "read", unlocks: ZENDESK_SURFACES.map((surface) => surface.id), notes: "Used only for OAuth bearer authentication; API-token Basic authentication has no OAuth scope." },
  ],
  surfaces: ZENDESK_SURFACES,
  checks,
  tools: {
    zendesk_check_access: [],
    zendesk_assess_authentication: idsFor("zendesk_assess_authentication"),
    zendesk_assess_access_control: idsFor("zendesk_assess_access_control"),
    zendesk_assess_data_protection: idsFor("zendesk_assess_data_protection"),
    zendesk_assess_integrations: idsFor("zendesk_assess_integrations"),
    zendesk_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [{
    surfaceIds: ["team-members", "groups", "group-memberships", "audit-logs-recent", "api-token-audit-logs", "oauth-clients", "oauth-tokens", "brands", "webhooks", "triggers", "automations", "suspended-tickets"],
    cursorFields: ["meta.has_more", "links.next", "next_page", "count"],
    pageSize: 100,
    itemCap: 2000,
    pageCap: 100,
    totalSemantics: "Cursor exhaustion proves completeness; count is retained as a boundary check when supplied.",
    stopConditions: ["has_more false or no next page", "Declared total reached", "Configured item cap", "Repeated next link", "Empty page with continuation", "Rejected cross-origin next link"],
  }, {
    surfaceIds: ["custom-roles", "deletion-schedules", "app-installations", "owned-apps", "targets", "sharing-agreements"],
    cursorFields: ["next_page", "count", "page", "per_page"],
    pageSize: 100,
    itemCap: 2000,
    pageCap: 100,
    totalSemantics: "A null next_page or equality with a stable count proves completeness; missing or larger totals keep the dataset partial.",
    stopConditions: ["No next_page", "Declared count reached", "Configured item cap", "Page cap", "Repeated next_page", "Empty page with continuation", "Rejected cross-origin next link"],
  }],
  rateLimit: {
    documentedLimit: "400 requests/minute on Team and 700 requests/minute on Professional or Enterprise by default",
    retryHeaders: ["Retry-After", "X-Rate-Limit", "X-Rate-Limit-Remaining"],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "Honor bounded Retry-After and retry transient failures; expose exhausted reads without copying response bodies.",
  },
  runtimeBehavior: ZENDESK_RUNTIME_BEHAVIOR,
  knownGaps: ["Guide, Talk, Chat, Sell, and real-tenant validation remain outside the shipped scope."],
  sensitiveFields: ["api_token", "oauth_token", "authorization", "cookie", "email", "webhook_url"],
  credentialFormats: ["Zendesk API tokens", "OAuth bearer tokens", "Basic authorization values", "webhook path secrets"],
  output: buildBatchOutputContract({
    files: [
      "metadata.json",
      "QUICK_REFERENCE.md",
      "core_data/access_check.json",
      "core_data/current_user.json",
      "core_data/account_settings.json",
      "core_data/security_settings.json",
      "core_data/team_members.json",
      "core_data/custom_roles.json",
      "core_data/groups.json",
      "core_data/group_memberships.json",
      "core_data/oauth_clients.json",
      "core_data/oauth_tokens.json",
      "core_data/api_token_audit_logs.json",
      "core_data/audit_logs_recent.json",
      "core_data/audit_log_oldest.json",
      "core_data/deletion_schedules.json",
      "core_data/suspended_tickets.json",
      "core_data/app_installations.json",
      "core_data/owned_apps.json",
      "core_data/brands.json",
      "core_data/sharing_agreements.json",
      "core_data/targets.json",
      "core_data/webhooks.json",
      "core_data/triggers.json",
      "core_data/automations.json",
      "analysis/authentication.json",
      "analysis/access-control.json",
      "analysis/data-protection.json",
      "analysis/integrations.json",
      "analysis/findings.json",
      "compliance/executive_summary.md",
      "compliance/unified_compliance_matrix.md",
      "compliance/fedramp_compliance_report.md",
      "compliance/cmmc_compliance_report.md",
      "compliance/soc2_compliance_report.md",
      "compliance/cis_compliance_report.md",
      "compliance/pci_dss_compliance_report.md",
      "compliance/disa_stig_compliance_report.md",
      "compliance/irap_compliance_report.md",
      "compliance/ismap_compliance_report.md",
    ],
    conditionalFiles: ["_errors.log"],
    overwritePolicy: "Allocate a new {subdomain}-zendesk-audit-bundle directory with a numeric suffix when needed; never overwrite a prior directory.",
    archivePairing: "Write a sibling zip named from the exact allocated bundle-directory path plus .zip.",
  }),
});
