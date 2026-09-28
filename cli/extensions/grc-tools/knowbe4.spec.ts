import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
} from "./batch-spec-builder.js";
import { restSurface } from "./batch2-spec-helpers.js";
import { KNOWBE4_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import { batch3Checks, type Batch3CheckRow } from "./batch3-spec-helpers.js";

const DOCS = "https://developer.knowbe4.com/rest/reporting";
const kb = (id: string, path: string, fields: readonly string[], method: "GET" | "POST" = "GET") =>
  restSurface(id, path, path.startsWith("/graphql") ? "KnowBe4 PhishER Product API GraphQL" : "KnowBe4 Reporting API v1", DOCS, fields, method, {
    headers: ["Authorization: Bearer <resolved product-specific token>", "Accept: application/json", ...(method === "POST" ? ["Content-Type: application/json"] : [])],
    parameters: method === "POST"
      ? [
          { name: "query", location: "form-body", required: true, value: `Named ${path.replace("/graphql ", "")} GraphQL query.` },
          { name: "variables.pagination", location: "form-body", required: true, value: "page=1, perPage=100, then each returned nextPageKey until exhaustion." },
        ]
      : [
          ...(path.includes("{group_id}") ? [{ name: "group_id", location: "path" as const, required: true, value: "Group ID returned by /v1/groups." }] : []),
          ...(path.includes("{pst_id}") ? [{ name: "pst_id", location: "path" as const, required: true, value: "Security-test ID returned by /v1/phishing/security_tests." }] : []),
          { name: "page", location: "query", required: false, value: "One-based page number advanced through same-origin Link rel=next." },
          { name: "per_page", location: "query", required: false, value: "500 unless the remaining configured inventory cap is smaller." },
        ],
    responseShape: `JSON ${method === "POST" ? "GraphQL data envelope" : "Reporting API resource or list"} containing ${fields.join(", ")}.`,
  });
const surfaces = [
  kb("account", "/v1/account", ["name", "subscription_level", "number_of_seats", "current_risk_score", "sso_enabled", "admins"]),
  kb("risk-history", "/v1/account/risk_score_history?full=true", ["date", "risk_score"]),
  kb("users", "/v1/users?status=active", ["id", "email", "status", "risk_score", "phish_prone_percentage", "created_at", "last_login"]),
  kb("groups", "/v1/groups?status=active", ["id", "name", "member_count"]),
  kb("group-members", "/v1/groups/{group_id}/members", ["id", "email", "status"]),
  kb("phishing-campaigns", "/v1/phishing/campaigns", ["campaign_id", "name", "status", "start_date", "frequency", "groups"]),
  kb("security-tests", "/v1/phishing/security_tests", ["pst_id", "campaign_id", "started_at", "status", "phish_prone_percentage"]),
  kb("security-test-recipients", "/v1/phishing/security_tests/{pst_id}/recipients", ["user_id", "sent_at", "opened_at", "clicked_at", "reported_at", "status"]),
  kb("callback-tests", "/v1/phishing/security_tests?campaign_type=callback", ["pst_id", "campaign_id", "started_at", "status"]),
  kb("training-campaigns", "/v1/training/campaigns", ["campaign_id", "name", "status", "start_date", "end_date", "groups"]),
  kb("training-enrollments", "/v1/training/enrollments", ["enrollment_id", "user_id", "campaign_id", "store_purchase_id", "status", "enrollment_date", "completion_date"]),
  kb("store-purchases", "/v1/training/store_purchases", ["store_purchase_id", "name", "publisher", "published_at", "topics"]),
  kb("training-policies", "/v1/training/policies", ["id", "name", "trigger", "remedial_training", "active"]),
  kb("phisher-messages", "/graphql phisherMessages", ["id", "receivedAt", "classification", "reportedBy", "status"], "POST"),
  kb("phisher-rules", "/graphql phisherRules", ["id", "name", "active", "action"], "POST"),
] as const;

const rows: readonly Batch3CheckRow[] = [
  { id: "KNOWBE4-01", control: 1, title: "Phishing simulation frequency", severity: "high", owner: "knowbe4_assess_phishing_program", surfaces: ["phishing-campaigns", "security-tests"], predicate: "Count the absence of a completed phishing test inside max_campaign_gap_days and adjacent completed tests separated by more than that threshold.", constants: { default_max_campaign_gap_days: 30 } },
  { id: "KNOWBE4-02", control: 2, title: "Phishing simulation coverage", severity: "high", owner: "knowbe4_assess_phishing_program", surfaces: ["users", "security-tests", "security-test-recipients"], predicate: "Compute unique active users receiving a test inside lookback_days divided by the complete active-user population; percentages below min_coverage_pct violate.", constants: { default_lookback_days: 90, default_min_coverage_pct: 90 } },
  { id: "KNOWBE4-03", control: 3, title: "Training completion rates", severity: "high", owner: "knowbe4_assess_training_program", surfaces: ["training-campaigns", "training-enrollments"], predicate: "Compute completed enrollments divided by all due enrollments for each active campaign; below fail_completion_pct fails and below min_completion_pct warns.", emptyOutcome: "warn", constants: { default_min_completion_pct: 90, default_fail_completion_pct: 80 } },
  { id: "KNOWBE4-04", control: 4, title: "Training enrollment timeliness", severity: "high", owner: "knowbe4_assess_training_program", surfaces: ["users", "training-enrollments"], predicate: "Count active users not enrolled within enrollment_grace_days after creation.", emptyOutcome: "pass", constants: { default_enrollment_grace_days: 30 } },
  { id: "KNOWBE4-05", control: 5, title: "User risk score distribution", severity: "medium", owner: "knowbe4_assess_user_risk", surfaces: ["users", "risk-history"], predicate: "Compute mean and population standard deviation over every user with a numeric risk score; mean above max_mean_risk_score or deviation above max_risk_score_stddev violates.", emptyOutcome: "warn", constants: { default_max_mean_risk_score: 50, default_max_risk_score_stddev: 25 } },
  { id: "KNOWBE4-06", control: 6, title: "Phish-prone percentage tracking", severity: "high", owner: "knowbe4_assess_phishing_program", surfaces: ["security-tests", "security-test-recipients"], predicate: "Compute failed recipients divided by all evaluable recipients in the lookback window; percentages above max_phish_prone_pct violate.", emptyOutcome: "warn", constants: { default_max_phish_prone_pct: 15 } },
  { id: "KNOWBE4-07", control: 7, title: "Phishing failure rate trending", severity: "medium", owner: "knowbe4_assess_phishing_program", surfaces: ["security-tests", "security-test-recipients"], predicate: "Compare complete chronological test failure rates; a positive recent trend versus the preceding period violates, insufficient periods require review.", emptyOutcome: "warn" },
  { id: "KNOWBE4-08", control: 8, title: "Group coverage analysis", severity: "medium", owner: "knowbe4_assess_user_risk", surfaces: ["groups", "phishing-campaigns", "training-campaigns"], predicate: "Count active groups absent from both a phishing campaign and a training campaign inside lookback_days.", emptyOutcome: "warn" },
  { id: "KNOWBE4-09", control: 9, title: "Campaign targeting completeness", severity: "high", owner: "knowbe4_assess_phishing_program", surfaces: ["users", "phishing-campaigns", "security-test-recipients"], predicate: "Count campaigns whose unique recipient coverage is below min_coverage_pct, or below 100 percent when require_full_targeting is true.", constants: { default_min_coverage_pct: 90 } },
  { id: "KNOWBE4-10", control: 10, title: "Remedial training triggers", severity: "high", owner: "knowbe4_assess_training_program", surfaces: ["security-test-recipients", "training-enrollments", "training-policies"], predicate: "Count phishing failures not followed by remedial enrollment within remedial_window_days and the absence of an active remedial training policy.", emptyOutcome: "warn", constants: { default_remedial_window_days: 14 } },
  { id: "KNOWBE4-11", control: 11, title: "Training content currency", severity: "medium", owner: "knowbe4_assess_training_program", surfaces: ["training-campaigns", "training-enrollments", "store-purchases"], predicate: "Count assigned store purchases whose publication or update age exceeds max_content_age_days or whose date is absent.", emptyOutcome: "warn", constants: { default_max_content_age_days: 365 } },
  { id: "KNOWBE4-12", control: 12, title: "Admin role audit", severity: "high", owner: "knowbe4_assess_account_governance", surfaces: ["account", "users"], predicate: "Count active KnowBe4 administrators above max_admin_count and administrator identifiers absent from the readable active-user inventory.", emptyOutcome: "warn", constants: { default_max_admin_count: 3 } },
  { id: "KNOWBE4-13", control: 13, title: "SSO integration status", severity: "critical", owner: "knowbe4_assess_account_governance", surfaces: ["account"], predicate: "Count one violation when the documented account SSO flag is explicitly false; absent SSO state requires manual review." },
  { id: "KNOWBE4-14", control: 14, title: "Reporting frequency", severity: "medium", owner: "knowbe4_assess_account_governance", surfaces: ["security-tests", "training-enrollments", "phisher-messages"], predicate: "Count the absence of recent phishing, training, and optional PhishER reporting evidence; unconfigured PhishER cannot independently fail the control." },
  { id: "KNOWBE4-15", control: 15, title: "USB test campaign execution", severity: "medium", owner: "knowbe4_assess_account_governance", surfaces: [], predicate: "No Reporting API surface exposes USB drop tests; when require_usb_tests is true the check is manual and otherwise informational.", manualOnly: true },
  { id: "KNOWBE4-16", control: 16, title: "Vishing campaign execution", severity: "medium", owner: "knowbe4_assess_account_governance", surfaces: ["callback-tests"], predicate: "Count the absence of a callback or vishing security test inside lookback_days when require_vishing_tests is true; otherwise report the observed inventory." },
  { id: "KNOWBE4-17", control: 17, title: "Compliance training modules", severity: "high", owner: "knowbe4_assess_training_program", surfaces: ["training-campaigns", "training-enrollments", "store-purchases"], predicate: "Count configured required topics absent from assigned content and required-topic enrollments whose completion percentage is below min_completion_pct.", constants: { default_min_completion_pct: 90 } },
  { id: "KNOWBE4-18", control: 18, title: "Inactive user cleanup", severity: "medium", owner: "knowbe4_assess_user_risk", surfaces: ["users", "security-test-recipients", "training-enrollments"], predicate: "Count active users with no phishing or training participation inside inactive_days.", emptyOutcome: "pass", constants: { default_inactive_days: 180 } },
  { id: "KNOWBE4-19", control: 19, title: "Phishing report rate", severity: "medium", owner: "knowbe4_assess_phishing_program", surfaces: ["security-tests", "security-test-recipients"], predicate: "Compute recipients who reported the simulation divided by delivered evaluable recipients; percentages below min_report_rate_pct violate.", emptyOutcome: "warn", constants: { default_min_report_rate_pct: 50 } },
  { id: "KNOWBE4-20", control: 20, title: "Campaign scheduling regularity", severity: "medium", owner: "knowbe4_assess_phishing_program", surfaces: ["phishing-campaigns", "security-tests"], predicate: "Count adjacent completed security tests separated by more than max_schedule_gap_days and no upcoming recurring campaign schedule.", emptyOutcome: "fail", constants: { default_max_schedule_gap_days: 45 } },
] as const;

const checks = batch3Checks(rows);
const idsFor = (owner: string) => checks.filter((check) => check.owner === owner).map((check) => check.id);

export const KNOWBE4_RUNTIME_BEHAVIOR = [
  "Reporting API Link rel=next pagination is exhausted before population metrics are calculated; per-test recipients preserve individual read failures and sample caps.",
  "PhishER is optional and independently authenticated; not configured is retained as a named collection state and cannot be mistaken for an empty message or rule inventory.",
  "PII redaction changes exported labels only after counts and joins are computed from stable vendor identifiers.",
] as const;

export const KNOWBE4_SPEC = buildBatchIntegrationSpec({
  slug: "knowbe4-sec-inspector",
  displayName: "KnowBe4 Security Inspector",
  vendor: "KnowBe4",
  category: "security-awareness",
  summary: "Portable contract for KnowBe4 phishing, training, user-risk, account-governance, and optional PhishER assessments.",
  sourceModule: "cli/extensions/grc-tools/knowbe4.ts",
  baseServices: ["KnowBe4 Reporting API v1", "KnowBe4 PhishER Product API GraphQL"],
  authentication: KNOWBE4_AUTH_RESOLVER,
  permissions: [
    { id: "reporting-api", kind: "role", value: "KnowBe4 Reporting API read access", unlocks: surfaces.filter((entry) => !entry.id.startsWith("phisher-")).map((entry) => entry.id) },
    { id: "phisher-product-api", kind: "license", value: "PhishER subscription and Product API token", unlocks: ["phisher-messages", "phisher-rules"] },
  ],
  surfaces,
  checks,
  tools: {
    knowbe4_check_access: [],
    knowbe4_assess_phishing_program: idsFor("knowbe4_assess_phishing_program"),
    knowbe4_assess_training_program: idsFor("knowbe4_assess_training_program"),
    knowbe4_assess_user_risk: idsFor("knowbe4_assess_user_risk"),
    knowbe4_assess_account_governance: idsFor("knowbe4_assess_account_governance"),
    knowbe4_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [
    {
      surfaceIds: surfaces.filter((entry) => !["account", "phisher-messages", "phisher-rules"].includes(entry.id)).map((entry) => entry.id),
      cursorFields: ["Link: rel=next", "page", "per_page"],
      pageSize: 500,
      itemCap: 20000,
      pageCap: null,
      totalSemantics: "Completion requires the same-origin Link rel=next chain to end before the inventory-specific item cap.",
      stopConditions: ["No rel=next link", "Inventory item cap", "Repeated next link", "Off-origin next link", "Empty page with next link"],
    },
    {
      surfaceIds: ["phisher-messages", "phisher-rules"],
      cursorFields: ["pagination.page", "pagination.pages", "pagination.totalCount", "pagination.nextPageKey"],
      pageSize: 100,
      itemCap: 1000,
      pageCap: null,
      totalSemantics: "Completion requires pages and totalCount to be accounted for and nextPageKey to advance until absent.",
      stopConditions: ["Last page", "Reported total reached", "Configured item cap", "Repeated nextPageKey", "Empty page before reported total"],
    },
  ],
  rateLimit: {
    documentedLimit: "Reporting API daily request quota varies by subscription tier; the runtime does not assume a fixed remaining quota.",
    retryHeaders: ["Retry-After", "X-RateLimit-Remaining", "X-RateLimit-Reset"],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "Retry three times, honoring Retry-After up to 30 seconds and otherwise using exponential backoff from one second.",
  },
  runtimeBehavior: KNOWBE4_RUNTIME_BEHAVIOR,
  knownGaps: [
    "The Reporting API exposes neither USB drop campaign execution nor a complete administrative-role directory on every subscription; unavailable fields remain manual.",
    "KNOWBE4-10 preserves the shipped parent behavior when the security-test collection is empty but previously collected recipient samples remain present: a clean sampled outcome (no failures due or a 90% or higher remediation rate) can pass even though recipient_reads_complete is false. This contradictory snapshot is a report-only runtime candidate; the spec binding does not harden it.",
    "KNOWBE4-18 preserves the shipped parent behavior when the security-test collection is empty but stale activity metadata marks the read partial: zero users_without_loaded_activity can pass even though inactive_users is null and partial_activity_data is true. This contradictory snapshot is a report-only runtime candidate; the spec binding does not harden it.",
  ],
  sensitiveFields: ["api_token", "phisher_api_token", "authorization", "cookie", "email", "first_name", "last_name", "manager_name", "ip_address"],
  credentialFormats: ["KnowBe4 Reporting API bearer tokens", "PhishER Product API bearer tokens", "authorization headers", "user PII"],
  output: buildBatchOutputContract({
    files: [
      "QUICK_REFERENCE.md", "metadata.json", "core_data/access.json", "core_data/collection_status.json",
      "core_data/account.json", "core_data/account_risk_score_history.json", "core_data/users_active.json", "core_data/groups.json",
      "core_data/phishing_campaigns.json", "core_data/security_tests.json", "core_data/security_test_recipients.json",
      "core_data/callback_security_tests.json", "core_data/training_campaigns.json", "core_data/training_enrollments.json",
      "core_data/store_purchases.json", "core_data/training_policies.json", "core_data/phisher_messages.json",
      "analysis/findings.json", "analysis/control_coverage.json", "analysis/access_check.md",
      "analysis/phishing.json", "analysis/phishing.md", "analysis/training.json", "analysis/training.md",
      "analysis/risk.json", "analysis/risk.md", "analysis/governance.json", "analysis/governance.md",
      "compliance/executive_summary.md", "compliance/unified_compliance_matrix.md",
      "compliance/fedramp/fedramp_compliance_report.md", "compliance/cmmc/cmmc_compliance_report.md",
      "compliance/soc2/soc2_compliance_report.md", "compliance/cis_controls/cis_controls_v8_report.md",
      "compliance/pci_dss/pci_dss_compliance_report.md", "compliance/disa_stig/stig_compliance_checklist.md",
      "compliance/irap/irap_compliance_report.md", "compliance/ismap/ismap_compliance_report.md",
    ],
    conditionalFiles: ["_errors.log"],
    conditionalFileConditions: { "_errors.log": "Written when any Reporting API, recipient, PhishER, assessment, or archive operation reports an error." },
    overwritePolicy: "Allocate knowbe4-audit-<UTC timestamp> and add a numeric suffix when the directory or archive exists.",
    archivePairing: "Create <allocated-directory>.zip beside the allocated KnowBe4 audit directory.",
  }),
});
