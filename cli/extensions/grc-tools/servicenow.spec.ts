import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
  deriveDecisionRules,
  type BatchCheckDefinition,
  type BatchCompletenessDefinition,
} from "./batch-spec-builder.js";
import { SERVICENOW_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import type { PortableValue, VerdictCondition, VerdictRule } from "./spec-model.js";

export const SERVICENOW_INSTANCE_SECURITY_PROPERTIES = [
  { name: "glide.security.use_csrf_token", expected: "true", describe: "true" },
  { name: "glide.security.csrf.strict.validation.mode", expected: "true", describe: "true" },
  { name: "glide.security.file.mime_type.validation", expected: "true", describe: "true" },
  { name: "glide.security.diag_txns_acl", expected: "true", describe: "true" },
  { name: "glide.security.strict.user_image_upload", expected: "true", describe: "true" },
] as const;
export const SERVICENOW_SCRIPT_RESTRICTION_PROPERTIES = [
  { name: "glide.script.use.sandbox", expected: "true", describe: "true" },
  { name: "glide.script.allow.ajaxevaluate", expected: "false", describe: "false" },
  { name: "glide.script.secure.ajaxgliderecord", expected: "true", describe: "true" },
  { name: "glide.script.ccsi.ispublic", expected: "false", describe: "false" },
] as const;
export const SERVICENOW_BASELINE_HARDENING_PROPERTIES = [
  { name: "glide.security.strict.updates", expected: "true", describe: "true" },
  { name: "glide.security.strict.actions", expected: "true", describe: "true" },
  { name: "glide.ui.escape_html_list_field", expected: "true", describe: "true" },
  { name: "glide.ui.escape_all_script", expected: "true", describe: "true" },
  { name: "glide.html.escape_script", expected: "true", describe: "true" },
  { name: "glide.html.sanitize_all_fields", expected: "true", describe: "true" },
  { name: "glide.ui.security.allow_codetag", expected: "false", describe: "false" },
  { name: "glide.ui.security.codetag.allow_script", expected: "false", describe: "false" },
  { name: "glide.set_x_frame_options", expected: "true", describe: "true" },
  { name: "glide.ui.secure_cookies", expected: "true", describe: "true" },
  { name: "glide.cookies.http_only", expected: "true", describe: "true" },
] as const;
export const SERVICENOW_PROPERTY_SOURCES = {
  "SNOW-01": SERVICENOW_INSTANCE_SECURITY_PROPERTIES.map((property) => property.name),
  "SNOW-05": ["glide.ui.session_timeout", "glide.ui.rotate_sessions", "glide.ui.user_cookie.max_life_span_in_days"],
  "SNOW-06": ["glide.enable.password_policy", "glide.apply.password_policy.on_login", "glide.login.no_blank_password"],
  "SNOW-07": ["glide.authenticate.multifactor", "glide.authenticate.multifactor.email.otp.enabled"],
  "SNOW-08": ["glide.authenticate.multisso.enabled", "glide.authenticate.sso.redirect.idp", "glide.sso.acr.enabled"],
  "SNOW-12": SERVICENOW_SCRIPT_RESTRICTION_PROPERTIES.map((property) => property.name),
  "SNOW-13": SERVICENOW_BASELINE_HARDENING_PROPERTIES.map((property) => property.name),
  "SNOW-16": ["dynamic sys_properties query: nameLIKEdebug and value=true"],
  "SNOW-17": ["glide.ip.authenticate.strict"],
  "SNOW-18": ["glide.smtp.auth", "glide.email.email_with_no_target_visible_to_all"],
  "SNOW-19": ["mid.version.override"],
} as const;

const ALL_FAILURE_MODES = ["truncated", "error", "denied", "not-collected"] as const;
const PARTIAL_ONLY = ["truncated"] as const;
const completeFrom = (
  sourceIds: readonly string[],
  semantics: string,
  falseWhen: readonly ("truncated" | "error" | "denied" | "not-collected")[] = PARTIAL_ONLY,
): BatchCompletenessDefinition => ({
  sources: sourceIds.map((surfaceId) => ({ surfaceId, falseWhen })),
  semantics,
});
const partialTableSemantics = (description: string): string =>
  `true when ${description} has no truncation, hidden-row total mismatch, zero-row response with unproven visibility, or unknown total; unreadable, denied, and not-collected states are handled by the separate readability fact and do not themselves change this fact.`;
const SERVICENOW_COMPLETENESS: Readonly<Record<string, Readonly<Record<string, BatchCompletenessDefinition>>>> = {
  "SNOW-01": { complete: completeFrom(["hardening-properties"], partialTableSemantics("the hardening-property table read")) },
  "SNOW-02": { complete: completeFrom(["acls", "acl-roles", "public-pages"], partialTableSemantics("ACL, ACL-role, and public-page table reads")) },
  "SNOW-03": { complete: completeFrom(["role-inheritance"], partialTableSemantics("the role-inheritance table read")) },
  "SNOW-04": { complete: completeFrom(["users", "privileged-assignments"], partialTableSemantics("user and privileged-assignment table reads")) },
  "SNOW-05": { complete: completeFrom(["hardening-properties"], partialTableSemantics("the hardening-property table read")) },
  "SNOW-06": { complete: completeFrom(["identity-properties", "password-policies"], partialTableSemantics("identity-property and password-policy table reads")) },
  "SNOW-07": {
    complete: completeFrom(["identity-properties", "users", "privileged-assignments", "mfa-criteria"], partialTableSemantics("identity-property, user, privileged-assignment, and MFA-criteria table reads")),
    properties_complete: completeFrom(["identity-properties"], "true only when the identity-property table read is readable and has proven full visibility.", ALL_FAILURE_MODES),
  },
  "SNOW-08": {
    complete: completeFrom(["sso-providers", "ldap-servers", "identity-properties", "certificates"], partialTableSemantics("SSO-provider, LDAP-server, identity-property, and certificate table reads")),
    providers_complete: completeFrom(["sso-providers", "ldap-servers"], "true only when both provider inventories are readable and have proven full visibility.", ALL_FAILURE_MODES),
  },
  "SNOW-11": { complete: completeFrom(["acls", "acl-roles"], "true only when ACL and ACL-role inventories are readable and have proven full visibility; the ACL aggregate is represented by a separate fact.", ALL_FAILURE_MODES) },
  "SNOW-12": { complete: completeFrom(["hardening-properties", "eval-scripts"], partialTableSemantics("hardening-property and evaluatable-script table reads")) },
  "SNOW-13": { complete: completeFrom(["hardening-properties"], partialTableSemantics("the hardening-property table read")) },
  "SNOW-14": { complete: completeFrom(["users", "privileged-assignments", "oauth-entities"], partialTableSemantics("user, privileged-assignment, and OAuth-entity table reads")) },
  "SNOW-15": { complete: completeFrom(["update-sets", "sensitive-update-xml"], partialTableSemantics("in-progress update-set and sensitive update-XML table reads")) },
  "SNOW-16": { complete: completeFrom(["hardening-properties", "debug-properties"], partialTableSemantics("hardening-property and debug-property table reads")) },
  "SNOW-17": {
    complete: completeFrom(["hardening-properties", "ip-access", "ip-authenticator-plugin"], partialTableSemantics("hardening-property, IP-access-rule, and IP-authenticator-plugin table reads")),
    plugin_inventory_complete: completeFrom(["ip-authenticator-plugin"], "true only when the IP-authenticator plugin inventory is readable and has proven full visibility.", ALL_FAILURE_MODES),
    rule_inventory_complete: completeFrom(["ip-access"], "true only when the IP-access-rule inventory is readable and has proven full visibility.", ALL_FAILURE_MODES),
  },
  "SNOW-20": { complete: completeFrom(["plugins"], "true only when the plugin inventory is readable and has proven full visibility.", ALL_FAILURE_MODES) },
};

const tableSurface = (id: string, table: string, fields: readonly string[]) => ({
  id,
  path: `/api/now/table/${table}`,
  service: "ServiceNow Table API",
  documentationUrl: "https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html",
  fields,
});
const countSurface = (id: string, table: string) => ({
  id,
  path: `/api/now/stats/${table}`,
  service: "ServiceNow Aggregate API",
  documentationUrl: "https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_AggregateAPI.html",
  fields: ["result.stats.count"],
});
const SERVICENOW_SURFACES = [
  tableSurface("users", "sys_user", ["sys_id", "user_name", "active", "last_login_time", "web_service_access_only", "internal_integration_user", "enable_multifactor_authn", "sys_updated_on"]),
  tableSurface("privileged-assignments", "sys_user_has_role", ["sys_id", "user", "user.user_name", "user.active", "user.web_service_access_only", "user.internal_integration_user", "role", "role.name"]),
  tableSurface("role-inheritance", "sys_user_role_contains", ["sys_id", "role", "role.name", "contains", "contains.name"]),
  countSurface("role-inheritance-count", "sys_user_role_contains"),
  tableSurface("identity-properties", "sys_properties", ["sys_id", "name", "value", "description", "sys_updated_on"]),
  tableSurface("password-policies", "password_policy", ["sys_id", "name", "active", "minimum_password_length", "maximum_password_length", "strength", "sys_updated_on"]),
  tableSurface("sso-providers", "sso_properties", ["sys_id", "name", "active", "default", "auto_redirect_idp", "sys_updated_on"]),
  tableSurface("ldap-servers", "ldap_server_config", ["sys_id", "name", "active", "sys_updated_on"]),
  tableSurface("certificates", "sys_certificate", ["sys_id", "name", "active", "valid_from", "expires", "sys_updated_on"]),
  tableSurface("oauth-entities", "oauth_entity", ["sys_id", "name", "type", "active", "client_id", "sys_updated_on"]),
  tableSurface("mfa-criteria", "multi_factor_criteria", ["sys_id", "name", "active", "order", "roles", "multi_factor_roles", "sys_updated_on"]),
  tableSurface("hardening-properties", "sys_properties", ["sys_id", "name", "value", "description", "sys_updated_on"]),
  tableSurface("debug-properties", "sys_properties", ["sys_id", "name", "value", "description", "sys_updated_on"]),
  tableSurface("eval-scripts", "sys_script", ["sys_id", "name", "collection", "sys_updated_on"]),
  tableSurface("ip-access", "ip_access", ["sys_id", "type", "direction", "active", "range_start", "range_end", "description", "sys_updated_on"]),
  tableSurface("ip-authenticator-plugin", "sys_plugins", ["sys_id", "name", "source", "active", "state", "version", "sys_updated_on"]),
  tableSurface("email-accounts", "sys_email_account", ["sys_id", "name", "type", "active", "connection_security", "enable_ssl", "enable_tls", "authentication", "server", "port", "sys_updated_on"]),
  tableSurface("acls", "sys_security_acl", ["sys_id", "name", "operation", "type", "active", "admin_overrides", "condition-present", "script-present", "sys_updated_on"]),
  tableSurface("acl-roles", "sys_security_acl_role", ["sys_id", "sys_security_acl", "sys_user_role", "sys_user_role.name"]),
  countSurface("acl-count", "sys_security_acl"),
  tableSurface("public-pages", "sys_public", ["sys_id", "page", "active", "sys_updated_on"]),
  tableSurface("encryption-contexts", "sys_encryption_context", ["sys_id", "name", "type", "sys_updated_on"]),
  tableSurface("crypto-modules", "sys_kmf_crypto_module", ["sys_id", "name", "module_name", "state", "sys_scope", "sys_updated_on"]),
  tableSurface("encrypted-fields", "sys_dictionary", ["sys_id", "name", "element", "internal_type"]),
  tableSurface("audit-dictionary", "sys_dictionary", ["sys_id", "name", "audit", "attributes"]),
  countSurface("recent-audit-count", "sys_audit"),
  countSurface("recent-transaction-count", "syslog_transaction"),
  tableSurface("update-sets", "sys_update_set", ["sys_id", "name", "state", "application", "sys_created_by", "sys_updated_on"]),
  countSurface("update-set-count", "sys_update_set"),
  tableSurface("sensitive-update-xml", "sys_update_xml", ["sys_id", "name", "type", "target_name", "action", "update_set", "update_set.name", "sys_updated_on"]),
  tableSurface("mid-servers", "ecc_agent", ["sys_id", "name", "status", "validated", "version", "host_name", "sys_updated_on"]),
  tableSurface("mid-properties", "sys_properties", ["sys_id", "name", "value", "description", "sys_updated_on"]),
  tableSurface("plugins", "sys_plugins", ["sys_id", "name", "source", "active", "state", "version", "sys_updated_on"]),
] as const;

const SERVICENOW_CHECK_SURFACES: Readonly<Record<number, readonly string[]>> = {
  1: ["hardening-properties"],
  2: ["acls", "acl-roles", "acl-count", "public-pages"],
  3: ["role-inheritance", "role-inheritance-count"],
  4: ["users", "privileged-assignments"],
  5: ["hardening-properties"],
  6: ["identity-properties", "password-policies"],
  7: ["identity-properties", "users", "privileged-assignments", "mfa-criteria"],
  8: ["sso-providers", "ldap-servers", "identity-properties", "certificates"],
  9: ["encryption-contexts", "crypto-modules", "encrypted-fields"],
  10: ["audit-dictionary", "recent-audit-count", "recent-transaction-count"],
  11: ["acls", "acl-roles", "acl-count"],
  12: ["hardening-properties", "eval-scripts"],
  13: ["hardening-properties"],
  14: ["users", "privileged-assignments", "oauth-entities"],
  15: ["update-sets", "update-set-count", "sensitive-update-xml"],
  16: ["hardening-properties", "debug-properties"],
  17: ["hardening-properties", "ip-access", "ip-authenticator-plugin"],
  18: ["hardening-properties", "email-accounts"],
  19: ["mid-servers", "mid-properties"],
  20: ["plugins"],
};

const titles = [
  "Instance security properties", "ACL rule completeness", "Role hierarchy audit", "User access review",
  "Session timeout configuration", "Password policy enforcement", "MFA enforcement", "LDAP and SSO integration",
  "Encryption at rest", "Audit logging configuration", "Table-level access controls", "Script execution restrictions",
  "Instance hardening", "Integration user permissions", "Update set management", "Debug mode verification",
  "IP access restrictions", "Email security", "MID Server security", "Plugin inventory and licensing",
] as const;
const identity = new Set([3, 4, 6, 7, 8, 14]);
const hardening = new Set([1, 5, 12, 13, 16, 17, 18]);
const access = new Set([2, 11]);
const ownerFor = (control: number): string => identity.has(control)
  ? "servicenow_assess_identity_access"
  : hardening.has(control)
    ? "servicenow_assess_platform_hardening"
    : access.has(control)
      ? "servicenow_assess_access_control"
      : "servicenow_assess_operations_governance";
const decisions = [
  "return pass when the complete security-property set enables the documented secure defaults, fail when any required property is explicitly insecure, and warn when optional hardening is absent or evidence is partial.",
  "return fail when any active ACL lacks both a role and a condition or script, warn when questionable ACLs remain or ACL and role joins are partial, and pass when every active ACL has an explicit restriction.",
  "return fail when administrator-equivalent roles exceed the configured population threshold, warn for broad inheritance, stale assignments, or partial role data, and pass when complete role and assignment evidence stays within the threshold.",
  "return fail when active privileged users exceed the configured maximum or include stale accounts beyond the configured age, warn for undated users or partial evidence, and pass when the complete population is bounded and recent.",
  "return pass when the inactivity timeout is positive and at or below the configured threshold, warn when it exceeds the threshold, fail when disabled, and manual when the property is absent or unreadable.",
  "return pass when the password policy meets minimum and maximum length, character-class, and strength requirements, warn when only some fields miss the baseline, fail for a weak preset or multiple gaps, and manual when decisive fields are absent.",
  "return pass when an active multi-factor criterion covers every required privileged role, fail when no active criterion exists, warn for incomplete role coverage, and manual when criteria or role evidence is unavailable.",
  "return pass when an active SSO or LDAP integration is visible with enabled redirect policy and valid dated certificates, fail when complete evidence has no active external identity provider or an active certificate is expired, warn for weak redirect policy or near-expiry and undated certificates, and manual when integration evidence is unreadable or partial.",
  "return pass when an active customer encryption module or encrypted field evidence is visible, warn when only platform-default encryption is evident, fail when readable evidence explicitly disables encryption, and manual when the licensed encryption surface is unavailable.",
  "return pass when system auditing is enabled and the complete lookback contains records, warn when the readable window is empty or partial, fail when auditing is explicitly disabled, and manual when properties or audit rows are unavailable.",
  "for sys_user, sys_user_has_role, sys_user_role, sys_properties, sys_script, sys_security_acl, syslog, and sys_audit, return fail when a complete ACL inventory contains no record ACL for any table, warn when a covered table lacks read, write, or delete operations or the inventory is incomplete, pass when every table has coverage for all three operations, and manual when the ACL aggregate is unavailable or zero.",
  "return fail when unrestricted server-side script execution is enabled, pass when the documented script restrictions are enabled, warn for mixed settings, and manual when the required properties are absent.",
  "return pass when all documented baseline hardening properties are secure, fail when any critical property is explicitly insecure, and warn when noncritical settings are weak or evidence is partial.",
  "return fail when an active integration user has administrator-equivalent roles, warn for broad non-admin roles, stale users, or partial assignments, and pass when complete evidence shows least-privileged integration identities.",
  "return pass when complete update-set evidence shows recent completed sets with no unresolved preview or commit errors, warn for in-progress, stale, failed, or partial sets, and manual when update-set tables are unavailable.",
  "return pass when debug and diagnostic properties are disabled, fail when any is enabled, warn when the property inventory is partial, and manual when no decisive debug property is readable.",
  "return pass when the complete IP access-control inventory contains active restrictive ranges, fail when an explicit allow-all rule exists, warn when no rule exists or coverage is partial, and manual when the table is unavailable.",
  "return pass when documented outbound email TLS and security properties are enabled, fail when TLS is explicitly disabled, warn for weaker optional settings, and manual when decisive properties are absent.",
  "return pass when every active MID Server is validated, recent, and uses a non-administrator service identity, fail for administrator identities or failed validation, warn for stale, down, or partial records, and manual when the MID inventory is unavailable.",
  "return fail when a complete plugin inventory is missing a required baseline security plugin or a visible required plugin is inactive, and manual when the inventory is empty, partial around a missing baseline plugin, or all required plugins are active because licensing and intended use cannot be inferred from the API.",
] as const;

interface ServicenowExecutableDecision { inputs: Readonly<Record<string, string>>; rules: readonly VerdictRule[] }
const value = (entry: PortableValue) => ({ kind: "value" as const, value: entry });
const path = (name: string) => ({ kind: "path" as const, path: name });
const cmp = (op: "eq" | "ne" | "gt" | "gte" | "lt" | "lte", name: string, entry: PortableValue): VerdictCondition => ({ op, left: path(name), right: value(entry) });
const eq = (name: string, entry: PortableValue) => cmp("eq", name, entry);
const ne = (name: string, entry: PortableValue) => cmp("ne", name, entry);
const gt = (name: string, entry: PortableValue) => cmp("gt", name, entry);
const lte = (name: string, entry: PortableValue) => cmp("lte", name, entry);
const defined = (name: string): VerdictCondition => ({ op: "defined", operand: path(name) });
const not = (condition: VerdictCondition): VerdictCondition => ({ op: "not", condition });
const all = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "and", conditions });
const any = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "or", conditions });
const rule = (status: VerdictRule["status"], condition: VerdictCondition): VerdictRule => ({ status, condition });
const input = (...names: string[]) => Object.fromEntries(names.map((name) => {
  const counts: Readonly<Record<string, string>> = {
    unexpected_value_count: "required properties with explicitly insecure values", absent_count: "required properties absent from the visible complete inventory",
    user_count: "active users", admin_count: "active administrator-equivalent users", privileged_assignment_count: "active privileged role assignments",
    role_aggregate_count: "role assignments reported by Aggregate API", inheriting_count: "privileged roles inherited through containment",
    admin_assignment_count: "administrator role assignments", stale_admin_count: "stale administrators", warning_count: "records in the check warning condition",
    provider_count: "active identity providers", plugin_count: "required plugin records", visible_required_plugin_inactive_count: "visible required plugins whose active field is false",
    criteria_count: "active MFA criteria", active_role_criteria_count: "active criteria targeting privileged roles", required_privileged_role_count: "roles requiring MFA coverage",
    covered_privileged_role_count: "required roles covered by active criteria", admins_without_mfa_flag_count: "admins without the user MFA flag",
    policy_count: "active password policies", policy_with_minimum_length_count: "policies meeting the minimum length", weak_policy_count: "policies missing complexity controls",
    active_rule_count: "active business rules", eval_rule_count: "active rules using dynamic evaluation", wildcard_count: "wildcard ACLs", unrestricted_count: "ACLs without role requirements",
    acl_aggregate_count: "record ACLs reported by Aggregate API", visible_acl_count: "record ACL rows visible to the caller",
    uncovered_table_count: "sensitive tables without a privileged read ACL", missing_dictionary_count: "sensitive tables without dictionary records",
    operation_gap_count: "sensitive tables missing required ACL operations", hardening_property_count: "baseline properties owned by the check",
    enabled_debug_count: "debug properties whose value is true", smtp_account_count: "outbound SMTP accounts", starttls_count: "SMTP accounts requiring STARTTLS",
    insecure_count: "records matching the adjacent insecure predicate", server_count: "MID servers", recent_audit_count: "recent sys_audit records",
    sensitive_change_count: "recent sensitive changes", unaudited_count: "sensitive changes without audit evidence", update_set_aggregate_count: "update sets reported by Aggregate API",
    in_progress_count: "in-progress update sets", in_progress_row_count: "visible in-progress update sets",
    integration_user_count: "active integration users", admin_integration_count: "integration users with admin roles",
    public_page_count: "public pages", missing_required_count: "required controls absent from complete evidence", expired_certificate_count: "expired certificates",
  };
  const booleans: Readonly<Record<string, string>> = {
    readable: "the required table, aggregate, or property response was returned", complete: "defined by this check's structured completeness contract",
    role_aggregate_readable: "the role aggregate was returned", role_total_known: "role total is reported or pagination exhausted", providers_complete: "all provider pages completed",
    plugin_present: "the named plugin has a visible record", plugin_active_value: "the named plugin is active", plugin_inventory_complete: "all plugin pages completed",
    password_policy_property_present: "glide.enable.password_policy has a visible row", platform_property_present: "the required platform property has a visible row",
    properties_complete: "sys_properties exhausted without ACL-hidden remainder", timeout_present: "glide.ui.session_timeout has a visible row",
    rule_inventory_complete: "all relevant ACL or business-rule pages completed", table_readable: "the required sensitive-table inventory was returned",
    acl_aggregate_readable: "the ACL aggregate was returned", smtp_auth_disabled: "glide.smtp.auth is explicitly false",
    version_override_present: "mid.version.override has a non-empty visible value", recent_audit_count_known: "an aggregate or exhausted pages establish the recent audit count",
    update_set_aggregate_readable: "the update-set aggregate was returned", in_progress_total_known: "the update-set total is reported or pages exhausted",
  };
  const raw: Readonly<Record<string, string>> = {
    role_pages: "Number of role-assignment pages read.", max_admins: "Maximum accepted administrator population.", plugin_active_value: "Raw plugin active flag.",
    multifactor_property_value: "Raw glide.authenticate.multifactor value.", email_otp_property_value: "Raw glide.authenticate.multifactor.email.otp.enabled value.",
    password_policy_property_value: "Raw glide.enable.password_policy value.", timeout_minutes: "Session timeout converted to minutes.",
    max_timeout_minutes: "Maximum accepted timeout in minutes.", rotate_sessions_value: "Raw glide.ui.rotate_sessions value.",
    strict_property_value: "Raw glide.ip.authenticate.strict value.", in_progress_pages: "Number of in-progress update-set pages read.",
  };
  const definition = counts[name] ? `Non-negative cardinality of ${counts[name]} in the complete ServiceNow inventory at the verdict point.`
    : booleans[name] ? `Boolean true exactly when ${booleans[name]}.` : raw[name];
  if (!definition) throw new Error(`ServiceNow primitive ${name} lacks an explicit portable definition`);
  return [name, definition];
}));
const inputWith = (
  overrides: Readonly<Record<string, string>>,
  ...names: string[]
): Readonly<Record<string, string>> => Object.fromEntries(
  names.map((name) => [name, overrides[name] ?? input(name)[name]]),
);
const propertyDecision = (): ServicenowExecutableDecision => ({
  inputs: input("readable", "complete", "unexpected_value_count", "absent_count"),
  rules: [rule("manual", ne("readable", true)), rule("fail", gt("unexpected_value_count", 0)), rule("warn", any(gt("absent_count", 0), ne("complete", true))), rule("pass", { op: "always" })],
});
const manualDecision = (): ServicenowExecutableDecision => ({ inputs: {}, rules: [rule("manual", { op: "always" })] });

const SERVICENOW_EXECUTABLE_DECISIONS: Readonly<Record<string, ServicenowExecutableDecision>> = {
  "SNOW-01": propertyDecision(),
  "SNOW-02": {
    inputs: input("readable", "complete", "acl_aggregate_readable", "acl_aggregate_count", "visible_acl_count", "unrestricted_count", "wildcard_count", "public_page_count"),
    rules: [rule("manual", any(ne("readable", true), ne("acl_aggregate_readable", true), lte("acl_aggregate_count", 0), eq("visible_acl_count", 0))), rule("fail", gt("unrestricted_count", 0)), rule("warn", any(gt("wildcard_count", 0), gt("public_page_count", 0), ne("complete", true))), rule("pass", { op: "always" })],
  },
  "SNOW-03": {
    inputs: input("readable", "complete", "role_aggregate_readable", "role_aggregate_count", "role_pages", "role_total_known", "inheriting_count"),
    rules: [
      rule("manual", any(
        ne("readable", true),
        ne("role_aggregate_readable", true),
        lte("role_aggregate_count", 0),
        all(eq("inheriting_count", 0), gt("role_pages", 0), ne("role_total_known", true)),
      )),
      rule("warn", gt("inheriting_count", 0)),
      rule("warn", ne("complete", true)),
      rule("pass", { op: "always" }),
    ],
  },
  "SNOW-04": {
    inputs: input("readable", "complete", "user_count", "admin_assignment_count", "admin_count", "max_admins", "stale_admin_count", "warning_count"),
    rules: [rule("manual", any(ne("readable", true), eq("user_count", 0), eq("admin_assignment_count", 0))), rule("fail", any({ op: "gt", left: path("admin_count"), right: path("max_admins") }, gt("stale_admin_count", 0))), rule("warn", any(gt("warning_count", 0), ne("complete", true))), rule("pass", { op: "always" })],
  },
  "SNOW-05": {
    inputs: input("readable", "complete", "timeout_present", "timeout_minutes", "max_timeout_minutes", "rotate_sessions_value"),
    rules: [
      rule("manual", ne("readable", true)),
      rule("fail", all(eq("timeout_present", true), any(
        not(defined("timeout_minutes")),
        lte("timeout_minutes", 0),
        { op: "gt", left: path("timeout_minutes"), right: path("max_timeout_minutes") },
      ))),
      rule("warn", any(ne("timeout_present", true), eq("rotate_sessions_value", false), ne("complete", true))),
      rule("pass", { op: "always" }),
    ],
  },
  "SNOW-06": {
    inputs: input("readable", "complete", "password_policy_property_value", "policy_count", "policy_with_minimum_length_count", "weak_policy_count", "password_policy_property_present"),
    rules: [
      rule("manual", ne("readable", true)),
      rule("fail", eq("password_policy_property_value", false)),
      rule("manual", all(eq("policy_count", 0), ne("complete", true))),
      rule("fail", eq("policy_count", 0)),
      rule("manual", eq("policy_with_minimum_length_count", 0)),
      rule("fail", gt("weak_policy_count", 0)),
      rule("warn", any(ne("password_policy_property_present", true), ne("complete", true))),
      rule("pass", { op: "always" }),
    ],
  },
  "SNOW-07": {
    inputs: input("readable", "complete", "properties_complete", "platform_property_present", "multifactor_property_value", "criteria_count", "admin_count", "active_role_criteria_count", "required_privileged_role_count", "covered_privileged_role_count", "admins_without_mfa_flag_count", "email_otp_property_value"),
    rules: [
      rule("manual", ne("readable", true)),
      rule("manual", all(ne("platform_property_present", true), ne("properties_complete", true))),
      rule("fail", ne("multifactor_property_value", true)),
      rule("manual", any(eq("criteria_count", 0), eq("admin_count", 0))),
      rule("fail", all(eq("active_role_criteria_count", 0), gt("admins_without_mfa_flag_count", 0))),
      rule("warn", any(
        eq("active_role_criteria_count", 0),
        all(
          { op: "lt", left: path("covered_privileged_role_count"), right: path("required_privileged_role_count") },
          gt("admins_without_mfa_flag_count", 0),
        ),
        eq("email_otp_property_value", true),
        ne("complete", true),
      )),
      rule("pass", { op: "always" }),
    ],
  },
  "SNOW-08": {
    inputs: inputWith({
      concern_count: "Non-negative sum of active identity-provider certificate concerns and SSO configuration concerns: active certificates with an absent or unparseable expiry, active certificates expiring within the configured warning window, plus one when an active SSO provider exists while `glide.authenticate.multisso.enabled` is not true, plus one when an active SSO provider exists without a populated `glide.authenticate.sso.redirect.idp` value.",
    }, "readable", "complete", "providers_complete", "provider_count", "expired_certificate_count", "concern_count"),
    rules: [rule("manual", ne("readable", true)), rule("manual", all(eq("provider_count", 0), ne("providers_complete", true))), rule("fail", eq("provider_count", 0)), rule("fail", gt("expired_certificate_count", 0)), rule("warn", any(gt("concern_count", 0), ne("complete", true))), rule("pass", { op: "always" })],
  },
  "SNOW-09": manualDecision(),
  "SNOW-10": {
    inputs: input("readable", "unaudited_count", "missing_dictionary_count", "recent_audit_count_known", "recent_audit_count"),
    rules: [rule("manual", ne("readable", true)), rule("fail", gt("unaudited_count", 0)), rule("manual", gt("missing_dictionary_count", 0)), rule("fail", all(eq("recent_audit_count_known", true), eq("recent_audit_count", 0))), rule("manual", { op: "always" })],
  },
  "SNOW-11": {
    inputs: input("readable", "complete", "acl_aggregate_readable", "acl_aggregate_count", "uncovered_table_count", "operation_gap_count"),
    rules: [rule("manual", any(ne("readable", true), ne("acl_aggregate_readable", true), lte("acl_aggregate_count", 0))), rule("manual", all(ne("complete", true), any(gt("uncovered_table_count", 0), gt("operation_gap_count", 0)))), rule("fail", gt("uncovered_table_count", 0)), rule("warn", gt("operation_gap_count", 0)), rule("warn", ne("complete", true)), rule("pass", { op: "always" })],
  },
  "SNOW-12": {
    inputs: input("readable", "complete", "unexpected_value_count", "absent_count", "eval_rule_count"),
    rules: [rule("manual", ne("readable", true)), rule("fail", any(gt("eval_rule_count", 0), gt("unexpected_value_count", 0))), rule("warn", any(gt("absent_count", 0), ne("complete", true))), rule("pass", { op: "always" })],
  },
  "SNOW-13": propertyDecision(),
  "SNOW-14": {
    inputs: input("readable", "complete", "integration_user_count", "admin_integration_count", "privileged_assignment_count"),
    rules: [rule("manual", ne("readable", true)), rule("fail", gt("admin_integration_count", 0)), rule("manual", eq("integration_user_count", 0)), rule("warn", any(gt("privileged_assignment_count", 0), ne("complete", true))), rule("pass", { op: "always" })],
  },
  "SNOW-15": {
    inputs: input("readable", "complete", "update_set_aggregate_readable", "update_set_aggregate_count", "in_progress_row_count", "in_progress_pages", "in_progress_total_known", "in_progress_count", "sensitive_change_count"),
    rules: [
      rule("manual", any(
        ne("readable", true),
        ne("update_set_aggregate_readable", true),
        lte("update_set_aggregate_count", 0),
        all(eq("in_progress_row_count", 0), gt("in_progress_pages", 0), ne("in_progress_total_known", true)),
      )),
      rule("warn", any(gt("in_progress_count", 0), gt("sensitive_change_count", 0), ne("complete", true))),
      rule("pass", { op: "always" }),
    ],
  },
  "SNOW-16": {
    inputs: input("readable", "complete", "enabled_debug_count", "hardening_property_count"),
    rules: [rule("manual", ne("readable", true)), rule("fail", gt("enabled_debug_count", 0)), rule("manual", eq("hardening_property_count", 0)), rule("warn", ne("complete", true)), rule("pass", { op: "always" })],
  },
  "SNOW-17": {
    inputs: input("readable", "complete", "plugin_present", "plugin_inventory_complete", "plugin_active_value", "active_rule_count", "rule_inventory_complete", "table_readable", "strict_property_value"),
    rules: [
      rule("manual", ne("readable", true)),
      rule("warn", all(ne("plugin_present", true), gt("active_rule_count", 0))),
      rule("manual", all(ne("plugin_present", true), ne("plugin_inventory_complete", true))),
      rule("fail", ne("plugin_active_value", true)),
      rule("manual", ne("table_readable", true)),
      rule("manual", all(eq("active_rule_count", 0), ne("rule_inventory_complete", true))),
      rule("fail", eq("active_rule_count", 0)),
      rule("warn", any(ne("strict_property_value", true), ne("complete", true))),
      rule("pass", { op: "always" }),
    ],
  },
  "SNOW-18": {
    inputs: inputWith({
      unverified_count: "Non-negative cardinality of active SMTP email-account rows whose connection-security fields cannot be classified as no transport security, STARTTLS, or SSL/TLS.",
    }, "readable", "smtp_account_count", "insecure_count", "smtp_auth_disabled", "unverified_count", "starttls_count"),
    rules: [rule("manual", ne("readable", true)), rule("fail", any(gt("insecure_count", 0), eq("smtp_auth_disabled", true))), rule("manual", eq("smtp_account_count", 0)), rule("manual", gt("unverified_count", 0)), rule("warn", gt("starttls_count", 0)), rule("manual", { op: "always" })],
  },
  "SNOW-19": {
    inputs: inputWith({
      not_validated_count: "Non-negative cardinality of MID Server rows from `ecc_agent` whose normalized `validated` field is not true, including false, null, absent, and unrecognized values.",
    }, "readable", "server_count", "not_validated_count", "version_override_present"),
    rules: [rule("manual", any(ne("readable", true), eq("server_count", 0))), rule("fail", gt("not_validated_count", 0)), rule("warn", eq("version_override_present", true)), rule("manual", { op: "always" })],
  },
  "SNOW-20": {
    inputs: input("readable", "complete", "plugin_count", "visible_required_plugin_inactive_count", "missing_required_count"),
    rules: [rule("manual", any(ne("readable", true), eq("plugin_count", 0))), rule("fail", gt("visible_required_plugin_inactive_count", 0)), rule("manual", all(gt("missing_required_count", 0), ne("complete", true))), rule("fail", gt("missing_required_count", 0)), rule("manual", { op: "always" })],
  },
};

const checks: BatchCheckDefinition[] = titles.map((title, index) => {
  const control = index + 1;
  const id = `SNOW-${String(control).padStart(2, "0")}`;
  const decision = SERVICENOW_EXECUTABLE_DECISIONS[id];
  const executable = deriveDecisionRules(id, decision.rules);
  return {
    id,
    control,
    title,
    severity: control === 7 ? "critical" : [1, 2, 3, 4, 6, 8, 10, 11, 12, 13, 14].includes(control) ? "high" : "medium",
    owner: ownerFor(control),
    surfaces: SERVICENOW_CHECK_SURFACES[control],
    evidenceFields: [...SERVICENOW_CHECK_SURFACES[control], "complete_source_counts"],
    decisionInputs: decision.inputs,
    decisionRules: executable.rules,
    derivedFactRules: executable.derivedFactRules,
    completeness: SERVICENOW_COMPLETENESS[id],
    decision: decisions[index],
  };
});
const idsFor = (owner: string): string[] => checks.filter((check) => check.owner === owner).map((check) => check.id);

export const SERVICENOW_RUNTIME_BEHAVIOR = [
  "Table API rows and Aggregate API counts are cross-checked; missing totals, ACL-filtered visibility, truncation, denied reads, and skipped child requests prevent pass.",
  "Encoded-query pagination uses sysparm_offset plus X-Total-Count, rejects foreign next links, and preserves exact seen, total, page, and stop-reason evidence.",
  "MFA, encryption, script, IP, email, and outbound TLS controls use documented properties and tables available to the runtime; unavailable Instance Security Center and product-specific proofs remain manual.",
  "SNOW-11 evaluates record ACL coverage for exactly these sensitive tables: sys_user, sys_user_has_role, sys_user_role, sys_properties, sys_script, sys_security_acl, syslog, and sys_audit.",
  `ServiceNow property ownership is check-specific: ${Object.entries(SERVICENOW_PROPERTY_SOURCES).map(([checkId, properties]) => `${checkId} reads ${properties.join(", ")}`).join("; ")}.`,
] as const;

export const SERVICENOW_SPEC = buildBatchIntegrationSpec({
  slug: "servicenow-sec-inspector",
  displayName: "ServiceNow Security Inspector",
  vendor: "ServiceNow",
  category: "it-service-management",
  summary: "Portable contract for the shipped ServiceNow identity, hardening, access-control, and operations-governance assessments.",
  sourceModule: "cli/extensions/grc-tools/servicenow.ts",
  baseServices: ["ServiceNow Table API", "ServiceNow Aggregate API", "ServiceNow OAuth token endpoint"],
  authentication: SERVICENOW_AUTH_RESOLVER,
  permissions: [
    { id: "table-read", kind: "role", value: "Table API read ACLs for every listed table", unlocks: SERVICENOW_SURFACES.filter((surface) => surface.service === "ServiceNow Table API").map((surface) => surface.id), notes: "The exact ServiceNow roles are instance-specific because table and field ACLs can be customized." },
    { id: "aggregate-read", kind: "role", value: "Aggregate API count ACLs matching the Table API population", unlocks: SERVICENOW_SURFACES.filter((surface) => surface.service === "ServiceNow Aggregate API").map((surface) => surface.id) },
    { id: "security-admin", kind: "role", value: "security_admin where protected security tables require elevation", unlocks: ["acls", "acl-roles", "acl-count"], notes: "Elevation does not replace each table's read ACL." },
  ],
  surfaces: SERVICENOW_SURFACES,
  checks,
  tools: {
    servicenow_check_access: [],
    servicenow_assess_identity_access: idsFor("servicenow_assess_identity_access"),
    servicenow_assess_platform_hardening: idsFor("servicenow_assess_platform_hardening"),
    servicenow_assess_access_control: idsFor("servicenow_assess_access_control"),
    servicenow_assess_operations_governance: idsFor("servicenow_assess_operations_governance"),
    servicenow_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [{
    surfaceIds: SERVICENOW_SURFACES.filter((surface) => surface.service === "ServiceNow Table API").map((surface) => surface.id),
    cursorFields: ["sysparm_offset", "sysparm_limit", "X-Total-Count", "Link rel=next"],
    pageSize: 500,
    itemCap: 10000,
    pageCap: null,
    totalSemantics: "X-Total-Count or Aggregate count is authoritative; absent or mismatched totals prevent proven exhaustion.",
    stopConditions: ["Seen count reaches authoritative total", "Short page with authoritative completion", "Configured item cap", "Empty page before total", "Repeated offset", "Missing total", "Rejected next link"],
  }],
  rateLimit: {
    documentedLimit: "Instance and node configuration determine ServiceNow inbound REST limits",
    retryHeaders: ["Retry-After", "X-RateLimit-Limit", "X-RateLimit-Remaining"],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "Honor bounded Retry-After and retry transient reads three times; exhausted reads remain unavailable.",
  },
  runtimeBehavior: SERVICENOW_RUNTIME_BEHAVIOR,
  knownGaps: ["The configuration parser recognizes the legacy mtls selector only to reject it with an explicit unsupported-mode error; no mTLS transport is implemented.", "Several Instance Security Center, Scan, DKIM, adaptive MFA, MID mutual-authentication, and retention proofs remain manual."],
  sensitiveFields: ["password", "client_secret", "access_token", "refresh_token", "authorization", "cookie", "sysparm_query"],
  credentialFormats: ["ServiceNow passwords", "OAuth bearer and refresh tokens", "client secrets", "JSESSIONID cookies"],
  output: buildBatchOutputContract({
    files: [
      "metadata.json",
      "QUICK_REFERENCE.md",
      "core_data/access_check.json",
      "core_data/sys_user.json",
      "core_data/sys_user_has_role_privileged.json",
      "core_data/sys_user_role_contains.json",
      "core_data/sys_user_role_contains_count.json",
      "core_data/sys_properties_identity.json",
      "core_data/password_policy.json",
      "core_data/sso_properties.json",
      "core_data/ldap_server_config.json",
      "core_data/sys_certificate.json",
      "core_data/oauth_entity.json",
      "core_data/multi_factor_criteria.json",
      "core_data/sys_properties_hardening.json",
      "core_data/sys_properties_debug.json",
      "core_data/sys_script_eval.json",
      "core_data/ip_access.json",
      "core_data/sys_plugins_ip_authenticator.json",
      "core_data/sys_email_account.json",
      "core_data/sys_security_acl.json",
      "core_data/sys_security_acl_role.json",
      "core_data/sys_security_acl_count.json",
      "core_data/sys_public.json",
      "core_data/sys_encryption_context.json",
      "core_data/sys_kmf_crypto_module.json",
      "core_data/sys_dictionary_encrypted.json",
      "core_data/sys_dictionary_audit.json",
      "core_data/sys_audit_count.json",
      "core_data/syslog_transaction_count.json",
      "core_data/sys_update_set_in_progress.json",
      "core_data/sys_update_set_count.json",
      "core_data/sys_update_xml_sensitive.json",
      "core_data/ecc_agent.json",
      "core_data/sys_properties_mid.json",
      "core_data/sys_plugins.json",
      "analysis/identity_access.json",
      "analysis/platform_hardening.json",
      "analysis/access_control.json",
      "analysis/operations_governance.json",
      "analysis/findings.json",
      "analysis/summary.json",
      "compliance/executive_summary.md",
      "compliance/unified_compliance_matrix.md",
      "compliance/fedramp/fedramp_compliance_report.md",
      "compliance/cmmc/cmmc_compliance_report.md",
      "compliance/soc2/soc2_compliance_report.md",
      "compliance/cis/cis_compliance_report.md",
      "compliance/pci_dss/pci_dss_compliance_report.md",
      "compliance/disa_stig/stig_compliance_checklist.md",
      "compliance/irap/irap_compliance_report.md",
      "compliance/ismap/ismap_compliance_report.md",
    ],
    conditionalFiles: ["_errors.log"],
    overwritePolicy: "Allocate a new {instance}-audit-bundle directory with a numeric suffix when needed; never overwrite a prior directory.",
    archivePairing: "Write a sibling zip named from the exact allocated bundle-directory basename plus .zip.",
  }),
});
