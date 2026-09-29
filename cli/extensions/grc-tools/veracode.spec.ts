import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
} from "./batch-spec-builder.js";
import { restSurface } from "./batch2-spec-helpers.js";
import { VERACODE_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import { batch3Checks, batch3Threshold, type Batch3CheckRow } from "./batch3-spec-helpers.js";

const DOCS = "https://docs.veracode.com/r/c_rest_api";
const HAL_LIST_SURFACES = new Set([
  "applications",
  "sandboxes",
  "findings",
  "policies",
  "users",
  "teams",
  "roles",
  "sca-workspaces",
  "sca-issues",
  "sca-libraries",
  "sca-projects",
  "dynamic-analyses",
  "dynamic-analysis-scans",
]);
const surface = (id: string, path: string, fields: readonly string[]) =>
  restSurface(id, path, "Veracode HMAC-signed REST API", DOCS, fields, "GET", {
    headers: ["Authorization: VERACODE-HMAC-SHA-256 signed over the exact GET host, path, and query", "Accept: application/json"],
    parameters: [
      ...(path.includes("{guid}") ? [{ name: "guid", location: "path" as const, required: true, value: "Application GUID returned by /appsec/v1/applications." }] : []),
      ...(path.includes("{id}") ? [{ name: "id", location: "path" as const, required: true, value: "Workspace ID returned by /srcclr/v3/workspaces." }] : []),
      ...(path.includes("{user_id}") ? [{ name: "user_id", location: "path" as const, required: true, value: "User ID returned by /api/authn/v2/users." }] : []),
      ...(path.includes("{analysis_id}") ? [{ name: "analysis_id", location: "path" as const, required: true, value: "Analysis ID returned by /was/configservice/v1/analyses." }] : []),
      ...(path.includes("{scan_id}") ? [{ name: "scan_id", location: "path" as const, required: true, value: "Scan ID returned by the dynamic-analysis scan inventory." }] : []),
      ...(HAL_LIST_SURFACES.has(id)
        ? [
            { name: "page", location: "query" as const, required: false, value: "Zero-based HAL page number, advanced until the response page count is exhausted." },
            { name: "size", location: "query" as const, required: false, value: id === "findings" ? "500 on every findings page." : "100 on every list page." },
          ]
        : []),
      ...(id === "findings"
        ? [{ name: "include_annot", location: "query" as const, required: true, value: "TRUE so mitigation annotations drive controls 12 and 16." }]
        : []),
      ...(id === "users"
        ? [
            { name: "detailed", location: "query" as const, required: true, value: "true" },
            { name: "include_roles", location: "query" as const, required: true, value: "true" },
            { name: "include_teams", location: "query" as const, required: true, value: "true" },
          ]
        : []),
      ...(id === "teams"
        ? [{ name: "all_for_org", location: "query" as const, required: false, value: "true on the organization-wide request; omitted on the member-team fallback after a 400 or 403." }]
        : []),
      ...(id === "sca-issues"
        ? [
            { name: "type", location: "query" as const, required: true, value: "vulnerability, license, or library for the requested issue family." },
            { name: "status", location: "query" as const, required: true, value: "open" },
          ]
        : []),
    ],
    responseShape: `HAL JSON object or documented single resource containing ${fields.join(", ")}.`,
  });
const surfaces = [
  surface("self", "/api/authn/v2/users/self", ["user_id", "user_name", "roles", "teams", "active"]),
  surface("self-api-credentials", "/api/authn/v2/api_credentials", ["api_id", "expiration_ts", "last_used_ts"]),
  surface("applications", "/appsec/v1/applications", ["guid", "profile", "policy", "last_completed_scan_date", "business_criticality"]),
  surface("sandboxes", "/appsec/v1/applications/{guid}/sandboxes", ["guid", "name", "modified_date", "scan_status"]),
  surface("findings", "/appsec/v2/applications/{guid}/findings", ["issue_id", "finding_details.severity", "finding_status.status", "finding_status.resolution", "finding_status.resolution_status", "finding_status.first_found_date", "annotations.action", "annotations.comment"]),
  surface("summary-reports", "/appsec/v2/applications/{guid}/summary_report", ["static_analysis.modules.module.loc", "static_analysis.modules.module.numflawssev5", "static_analysis.modules.module.numflawssev4"]),
  surface("policies", "/appsec/v1/policies", ["guid", "name", "policy_type", "rules", "grace_periods"]),
  surface("users", "/api/authn/v2/users", ["user_id", "user_name", "active", "login_enabled", "account_type", "api_user", "roles", "teams", "last_login", "saml_user"]),
  surface("teams", "/api/authn/v2/teams", ["team_id", "team_name", "applications", "users"]),
  surface("roles", "/api/authn/v2/roles", ["role_id", "role_name", "permissions"]),
  surface("user-api-credentials", "/api/authn/v2/api_credentials/user_id/{user_id}", ["api_id", "expiration_ts", "last_used_ts"]),
  surface("sca-workspaces", "/srcclr/v3/workspaces", ["id", "name", "site_id", "updated_at"]),
  surface("sca-issues", "/srcclr/v3/workspaces/{id}/issues", ["id", "type", "severity", "vulnerability.cvss3_score", "vulnerability.cvss2_score", "license", "library", "status"]),
  surface("sca-libraries", "/srcclr/v3/workspaces/{id}/libraries", ["id", "name", "version", "latest_version", "licenses"]),
  surface("sca-projects", "/srcclr/v3/applications/{guid}/projects", ["projects", "workspace_id", "application_guid"]),
  surface("dynamic-analyses", "/was/configservice/v1/analyses", ["analysis_id", "name", "scans", "schedule", "auth_configuration"]),
  surface("dynamic-analysis-scans", "/was/configservice/v1/analyses/{analysis_id}/scans", ["scan_id", "status", "start_date", "end_date"]),
  surface("dynamic-scan-configuration", "/was/configservice/v1/scans/{scan_id}/configuration", ["auth_configuration", "crawl_scope", "scan_depth"]),
] as const;

const rows: readonly Batch3CheckRow[] = [
  { id: "VERACODE-01", control: 1, title: "Application scan coverage", severity: "critical", owner: "veracode_assess_scan_coverage", surfaces: ["applications", "summary-reports"], predicate: "Count applications with no completed scan or a last completed scan older than max_scan_age_days.", constants: { default_max_scan_age_days: 90 }, thresholds: [batch3Threshold("VERACODE-01", "default_max_scan_age_days", "max_observed_scan_age_days", "gt", "fail", "Greatest elapsed days since a published completed scan across the complete application inventory.", "max_scan_age_days")] },
  { id: "VERACODE-02", control: 2, title: "Policy compliance status", severity: "critical", owner: "veracode_assess_policy_compliance", surfaces: ["applications", "summary-reports"], predicate: "Count applications whose raw policy_compliance_status is not Pass; absent summary reports are unreadable evidence rather than compliant." },
  { id: "VERACODE-03", control: 3, title: "Flaw aging", severity: "critical", owner: "veracode_assess_findings_hygiene", surfaces: ["applications", "findings"], predicate: "Count open findings older than the severity-specific age windows: Very High 30, High 60, Medium 90, and Low 180 days.", constants: { very_high_sla_days: 30, high_sla_days: 60, medium_sla_days: 90, low_sla_days: 180 }, thresholds: [
    batch3Threshold("VERACODE-03", "very_high_sla_days", "max_very_high_age_days", "gt", "fail", "Greatest age in days among uncapped open Very High findings."),
    batch3Threshold("VERACODE-03", "high_sla_days", "max_high_age_days", "gt", "fail", "Greatest age in days among uncapped open High findings."),
    batch3Threshold("VERACODE-03", "medium_sla_days", "max_medium_age_days", "gt", "fail", "Greatest age in days among uncapped open Medium findings."),
    batch3Threshold("VERACODE-03", "low_sla_days", "max_low_age_days", "gt", "fail", "Greatest age in days among uncapped open Low findings."),
  ] },
  { id: "VERACODE-04", control: 4, title: "Scan frequency compliance", severity: "high", owner: "veracode_assess_scan_coverage", surfaces: ["applications", "summary-reports"], predicate: "Count critical applications whose last completed scan exceeds critical_scan_interval_days and other applications exceeding standard_scan_interval_days.", constants: { default_critical_scan_interval_days: 7, default_standard_scan_interval_days: 31 }, thresholds: [
    batch3Threshold("VERACODE-04", "default_critical_scan_interval_days", "max_critical_application_scan_age_days", "gt", "fail", "Greatest completed-scan age in days among critical applications.", "critical_scan_interval_days"),
    batch3Threshold("VERACODE-04", "default_standard_scan_interval_days", "max_standard_application_scan_age_days", "gt", "fail", "Greatest completed-scan age in days among non-critical applications.", "standard_scan_interval_days"),
  ] },
  { id: "VERACODE-05", control: 5, title: "SCA library currency", severity: "high", owner: "veracode_assess_sca_posture", surfaces: ["sca-workspaces", "sca-issues", "sca-libraries"], predicate: "Count open SCA vulnerability issues with CVSS at or above sca_cvss_threshold. Current and latest library versions are collected as evidence, but version drift does not affect this control's result.", emptyOutcome: "pass", constants: { default_sca_cvss_threshold: 7 }, thresholds: [batch3Threshold("VERACODE-05", "default_sca_cvss_threshold", "max_open_sca_cvss", "gte", "fail", "Greatest numeric CVSS score among all uncapped open SCA vulnerability issues.", "sca_cvss_threshold")] },
  { id: "VERACODE-06", control: 6, title: "SCA license risk", severity: "high", owner: "veracode_assess_sca_posture", surfaces: ["sca-workspaces", "sca-issues", "sca-libraries"], predicate: "Count open license issues or libraries declaring GPL, AGPL, SSPL, or another configured restrictive license.", emptyOutcome: "pass" },
  { id: "VERACODE-07", control: 7, title: "Team access controls", severity: "high", owner: "veracode_assess_access_controls", surfaces: ["teams", "applications"], predicate: "Count active users carrying a role that ignores team restrictions above max_unrestricted_users, applications with no team assignment, or an absent organization-wide team inventory.", constants: { default_max_unrestricted_users: 10 }, thresholds: [
    batch3Threshold("VERACODE-07", "default_max_unrestricted_users", "users_with_all_application_access_count", "gt", "fail", "Uncapped active user count carrying a role whose ignore_team_restrictions field is true.", "max_unrestricted_users"),
  ] },
  { id: "VERACODE-08", control: 8, title: "User role audit", severity: "high", owner: "veracode_assess_access_controls", surfaces: ["self", "users", "roles", "teams"], predicate: "Count active administrators above max_admins, users inactive beyond inactive_days, and service accounts without a team.", constants: { default_max_admins: 5, default_inactive_days: 90 }, thresholds: [
    batch3Threshold("VERACODE-08", "default_max_admins", "administrator_count", "gt", "fail", "Uncapped active Administrator user count.", "max_admins"),
    batch3Threshold("VERACODE-08", "default_inactive_days", "max_observed_inactive_days", "gt", "fail", "Greatest elapsed days since last login among active human users.", "inactive_days"),
  ] },
  { id: "VERACODE-09", control: 9, title: "API credential management", severity: "high", owner: "veracode_assess_access_controls", surfaces: ["users", "self-api-credentials", "user-api-credentials"], predicate: "Count API credentials older than max_credential_age_days or without readable expiration and last-used timestamps; denied per-user credential reads make evidence incomplete.", constants: { default_max_credential_age_days: 365 }, thresholds: [batch3Threshold("VERACODE-09", "default_max_credential_age_days", "max_observed_credential_age_days", "gt", "fail", "Greatest age in days among every readable API credential.", "max_credential_age_days")] },
  { id: "VERACODE-10", control: 10, title: "Sandbox usage", severity: "medium", owner: "veracode_assess_scan_coverage", surfaces: ["applications", "sandboxes"], predicate: "Count applications with no sandbox and sandboxes with no readable recent scan activity." },
  { id: "VERACODE-11", control: 11, title: "Prescan module coverage", severity: "medium", owner: "veracode_assess_scan_coverage", surfaces: [], predicate: "Manually export the latest static prescan results from the XML getprescanresults.do API for every in-scope application and confirm that selected modules divided by discovered modules is at least 80 percent.", manualOnly: true },
  { id: "VERACODE-12", control: 12, title: "Mitigation approval workflow", severity: "high", owner: "veracode_assess_findings_hygiene", surfaces: ["applications", "findings"], predicate: "Count findings with a proposed or pending mitigation not accepted or approved and bulk mitigations with no readable justification." },
  { id: "VERACODE-13", control: 13, title: "Dynamic scan configuration", severity: "high", owner: "veracode_assess_scan_coverage", surfaces: ["dynamic-analyses", "dynamic-analysis-scans", "dynamic-scan-configuration"], predicate: "Count dynamic analyses with no completed scan, no authentication configuration, empty crawl scope, or insufficient scan depth." },
  { id: "VERACODE-14", control: 14, title: "Pipeline integration status", severity: "medium", owner: "veracode_assess_scan_coverage", surfaces: ["applications", "findings", "summary-reports"], predicate: "Count applications with no recent pipeline or IDE scan evidence and applications relying only on manual upload scans." },
  { id: "VERACODE-15", control: 15, title: "Custom policy profiles", severity: "medium", owner: "veracode_assess_policy_compliance", surfaces: ["policies", "applications"], predicate: "Count the absence of a custom policy and applications assigned only to the default policy; missing rule thresholds require review." },
  { id: "VERACODE-16", control: 16, title: "Finding false positive rate", severity: "medium", owner: "veracode_assess_findings_hygiene", surfaces: ["applications", "findings"], predicate: "Compute mitigated-as-false-positive findings divided by all evaluable findings per application; percentages above max_fp_rate_percent violate.", constants: { default_max_fp_rate_percent: 20 }, thresholds: [batch3Threshold("VERACODE-16", "default_max_fp_rate_percent", "maximum_false_positive_percent", "gt", "warn", "Greatest per-application false-positive mitigation percentage over complete finding populations.", "max_fp_rate_percent")] },
  { id: "VERACODE-17", control: 17, title: "Very High/High flaw density", severity: "high", owner: "veracode_assess_findings_hygiene", surfaces: ["applications", "findings", "summary-reports"], predicate: "Compute open Very High and High findings per thousand lines of code; density above max_flaw_density_per_kloc violates.", constants: { default_max_flaw_density_per_kloc: 1 }, thresholds: [batch3Threshold("VERACODE-17", "default_max_flaw_density_per_kloc", "maximum_flaw_density_per_kloc", "gt", "fail", "Greatest per-application open Very High and High finding count per thousand lines of code.", "max_flaw_density_per_kloc")] },
  { id: "VERACODE-18", control: 18, title: "SCA workspace coverage", severity: "high", owner: "veracode_assess_sca_posture", surfaces: ["applications", "sca-workspaces", "sca-projects"], predicate: "Count applications with third-party dependency evidence but no associated SCA project or workspace; failed per-application project reads make evidence incomplete." },
  { id: "VERACODE-19", control: 19, title: "Scan completion rate", severity: "high", owner: "veracode_assess_scan_coverage", surfaces: ["applications", "summary-reports", "dynamic-analysis-scans"], predicate: "Count applications whose latest static or dynamic scan failed, was incomplete, or has no terminal result." },
  { id: "VERACODE-20", control: 20, title: "Collections compliance posture", severity: "high", owner: "veracode_assess_policy_compliance", surfaces: ["applications", "summary-reports"], predicate: "Count application collections where non-passing applications exceed 20 percent of the complete collection membership.", constants: { maximum_noncompliant_percent: 20 }, thresholds: [batch3Threshold("VERACODE-20", "maximum_noncompliant_percent", "maximum_collection_noncompliant_percent", "gt", "fail", "Greatest non-passing application percentage among complete collection memberships.")] },
] as const;

const checks = batch3Checks(rows);
const idsFor = (owner: string) => checks.filter((check) => check.owner === owner).map((check) => check.id);

export const VERACODE_RUNTIME_BEHAVIOR = [
  "Every HAL list proves page exhaustion from page.number, page.total_pages, and page.total_elements; caller application, workspace, and analysis sampling caps mark dependent checks incomplete.",
  "Per-application findings, reports, sandboxes, SCA projects, and dynamic scan configuration failures remain named not-collected markers and never become empty lists.",
  "Every request is signed over the exact method, host, path, and query using VERACODE-HMAC-SHA-256 after same-origin URL resolution.",
] as const;

export const VERACODE_SPEC = buildBatchIntegrationSpec({
  slug: "veracode-sec-inspector",
  displayName: "Veracode Security Inspector",
  vendor: "Veracode",
  category: "application-security",
  summary: "Portable contract for Veracode scan coverage, policy, findings, SCA, DAST, and access-control assessments.",
  sourceModule: "cli/extensions/grc-tools/veracode.ts",
  baseServices: ["Veracode AppSec REST API", "Veracode Identity API", "Veracode SCA Agent API", "Veracode DAST Configuration API"],
  authentication: VERACODE_AUTH_RESOLVER,
  permissions: [
    { id: "results-api", kind: "role", value: "Results API or Security Lead", unlocks: ["applications", "sandboxes", "findings", "summary-reports", "policies", "dynamic-analyses", "dynamic-analysis-scans", "dynamic-scan-configuration"] },
    { id: "admin-api", kind: "role", value: "Admin API", unlocks: ["self", "self-api-credentials", "users", "teams", "roles", "user-api-credentials"] },
    { id: "workspace-read", kind: "role", value: "Workspace Administrator or Workspace Editor", unlocks: ["sca-workspaces", "sca-issues", "sca-libraries", "sca-projects"] },
  ],
  surfaces,
  checks,
  tools: {
    veracode_check_access: [],
    veracode_assess_scan_coverage: idsFor("veracode_assess_scan_coverage"),
    veracode_assess_policy_compliance: idsFor("veracode_assess_policy_compliance"),
    veracode_assess_findings_hygiene: idsFor("veracode_assess_findings_hygiene"),
    veracode_assess_sca_posture: idsFor("veracode_assess_sca_posture"),
    veracode_assess_access_controls: idsFor("veracode_assess_access_controls"),
    veracode_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [{
    surfaceIds: surfaces.filter((entry) => entry.id !== "findings" && !["self", "self-api-credentials", "summary-reports", "user-api-credentials", "sca-projects", "dynamic-scan-configuration"].includes(entry.id)).map((entry) => entry.id),
    cursorFields: ["page.number", "page.total_pages", "page.total_elements", "_links.next.href"],
    pageSize: 100,
    itemCap: null,
    pageCap: 50,
    totalSemantics: "Completion requires page.number to reach page.total_pages and collected records to reach page.total_elements; rejected or off-origin next links are partial.",
    stopConditions: ["Total pages reached", "Total elements reached", "No next link on a terminal page", "50-page cap", "Repeated page", "Off-origin next link"],
  }, {
    surfaceIds: ["findings"],
    cursorFields: ["page.number", "page.total_pages", "page.total_elements", "_links.next.href"],
    pageSize: 500,
    itemCap: null,
    pageCap: 50,
    totalSemantics: "Each application findings walk requests size=500 with include_annot=TRUE and is complete only after every declared page and element is collected.",
    stopConditions: ["Total pages reached", "Total elements reached", "Terminal short page", "50-page cap", "Repeated page"],
  }],
  rateLimit: {
    documentedLimit: "Veracode documents fair-use throttling without a fixed account-wide request number.",
    retryHeaders: ["Retry-After"],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "Retry three times with Retry-After when present and bounded exponential delay otherwise; each retry receives a fresh HMAC timestamp and nonce.",
  },
  runtimeBehavior: VERACODE_RUNTIME_BEHAVIOR,
  knownGaps: ["XML APIs are not called; controls without decisive REST fields remain manual rather than inferred from fields unavailable through the declared REST surfaces."],
  sensitiveFields: ["veracode_api_key_secret", "api_id", "authorization", "nonce", "signature", "user_name", "email", "application_name"],
  credentialFormats: ["Veracode API key IDs", "128-character HMAC secret keys", "VERACODE-HMAC-SHA-256 Authorization headers"],
  output: buildBatchOutputContract({
    files: [
      "QUICK_REFERENCE.md", "metadata.json", "core_data/access.json",
      "core_data/scan-coverage.json", "core_data/policy-compliance.json", "core_data/findings-hygiene.json",
      "core_data/sca-posture.json", "core_data/access-controls.json",
      "analysis/findings.json", "analysis/scan-coverage.json", "analysis/policy-compliance.json",
      "analysis/findings-hygiene.json", "analysis/sca-posture.json", "analysis/access-controls.json", "analysis/summary.md",
      "compliance/executive_summary.md", "compliance/unified_compliance_matrix.md",
      "compliance/fedramp.md", "compliance/cmmc.md", "compliance/soc2.md", "compliance/cis-controls-v8.md",
      "compliance/pci-dss.md", "compliance/stig.md", "compliance/irap.md", "compliance/ismap.md",
    ],
    conditionalFiles: ["_errors.log"],
    conditionalFileConditions: { "_errors.log": "Written when a top-level or per-parent collection, assessment, or archive operation reports an error." },
    overwritePolicy: "Allocate veracode-audit-<UTC timestamp> and add a numeric suffix when the directory or archive exists.",
    archivePairing: "Create <allocated-directory>.zip beside the allocated Veracode audit directory.",
  }),
});
