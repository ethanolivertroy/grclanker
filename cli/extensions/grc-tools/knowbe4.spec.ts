import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
} from "./batch-spec-builder.js";
import {
  batch2All,
  batch2Any,
  batch2Defined,
  batch2Eq,
  batch2Gt,
  batch2Ne,
  batch2Not,
  batch2Path,
  batch2Rule,
  restSurface,
} from "./batch2-spec-helpers.js";
import { KNOWBE4_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import { batch3Checks, batch3Threshold, type Batch3CheckRow } from "./batch3-spec-helpers.js";
import type { RequestParameterContract } from "./spec-model.js";

const DOCS = "https://developer.knowbe4.com/rest/reporting";
const kb = (
  id: string,
  path: string,
  fields: readonly string[],
  method: "GET" | "POST" = "GET",
  options: { paginated?: boolean; parameters?: readonly RequestParameterContract[] } = {},
) =>
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
          ...(options.paginated === false
            ? []
            : [
                { name: "page", location: "query" as const, required: true, value: "One-based page number advanced until a page contains fewer than per_page records." },
                { name: "per_page", location: "query" as const, required: true, value: "500 unless the endpoint-specific page size or remaining configured inventory cap is smaller." },
              ]),
          ...(options.parameters ?? []),
        ],
    responseShape: `JSON ${method === "POST" ? "GraphQL data envelope" : "Reporting API resource or list"} containing ${fields.join(", ")}.`,
  });
const surfaces = [
  kb("account", "/v1/account", ["name", "subscription_level", "number_of_seats", "current_risk_score", "sso_enabled", "admins"], "GET", { paginated: false }),
  kb("risk-history", "/v1/account/risk_score_history?full=true", ["date", "risk_score"]),
  kb("users", "/v1/users?status=active", ["id", "email", "status", "risk_score", "phish_prone_percentage", "created_at", "last_login"]),
  kb("groups", "/v1/groups?status=active", ["id", "name", "member_count"]),
  kb("group-members", "/v1/groups/{group_id}/members", ["id", "email", "status"]),
  kb("phishing-campaigns", "/v1/phishing/campaigns", ["campaign_id", "name", "status", "start_date", "frequency", "groups"]),
  kb("security-tests", "/v1/phishing/security_tests", ["pst_id", "campaign_id", "started_at", "status", "phish_prone_percentage"]),
  kb("security-test-recipients", "/v1/phishing/security_tests/{pst_id}/recipients", ["user_id", "sent_at", "opened_at", "clicked_at", "reported_at", "status"]),
  kb("callback-tests", "/v1/phishing/security_tests?campaign_type=callback", ["pst_id", "campaign_id", "started_at", "status"]),
  kb("training-campaigns", "/v1/training/campaigns", ["campaign_id", "name", "status", "start_date", "end_date", "groups"]),
  kb("training-enrollments", "/v1/training/enrollments", ["enrollment_id", "user_id", "campaign_id", "store_purchase_id", "status", "enrollment_date", "completion_date"], "GET", {
    parameters: [
      { name: "campaign_id", location: "query", required: false, value: "Optional campaign identifier supplied by a caller; omitted by whole-program assessments." },
      { name: "user_id", location: "query", required: false, value: "Optional user identifier supplied by a caller; omitted by whole-program assessments." },
      { name: "store_purchase_id", location: "query", required: false, value: "Optional store-purchase identifier supplied by a caller; omitted by whole-program assessments." },
      { name: "exclude_archived_users", location: "query", required: true, value: "true unless a caller explicitly requests archived users; whole-program assessments send true." },
      { name: "include_campaign_id", location: "query", required: true, value: "true" },
      { name: "include_store_purchase_id", location: "query", required: true, value: "true" },
    ],
  }),
  kb("store-purchases", "/v1/training/store_purchases", ["store_purchase_id", "name", "publisher", "published_at", "topics"]),
  kb("training-policies", "/v1/training/policies", ["id", "name", "trigger", "remedial_training", "active"]),
  kb("phisher-messages", "/graphql phisherMessages", ["id", "receivedAt", "classification", "reportedBy", "status"], "POST"),
  kb("phisher-rules", "/graphql phisherRules", ["id", "name", "active", "action"], "POST"),
] as const;

const KNOWBE4_02_COMPLETE = batch2Eq(
  "knowbe4_02_phishing_simulation_coverage_population_complete",
  true,
);

const rows: readonly Batch3CheckRow[] = [
  { id: "KNOWBE4-01", control: 1, title: "Phishing simulation frequency", severity: "high", owner: "knowbe4_assess_phishing_program", surfaces: ["phishing-campaigns", "security-tests"], predicate: "Count the absence of a completed phishing test inside max_campaign_gap_days and adjacent completed tests separated by more than that threshold.", constants: { default_max_campaign_gap_days: 30 }, thresholds: [batch3Threshold("KNOWBE4-01", "default_max_campaign_gap_days", "days_since_last_test", "gt", "fail", "Whole days since the latest completed phishing test.", "max_campaign_gap_days")] },
  { id: "KNOWBE4-02", control: 2, title: "Phishing simulation coverage", severity: "high", owner: "knowbe4_assess_phishing_program", surfaces: ["users", "security-tests", "security-test-recipients"], predicate: "Compute unique active users receiving a test inside lookback_days divided by the complete active-user population; percentages below min_coverage_pct violate.", constants: { default_lookback_days: 90, default_min_coverage_pct: 90 }, thresholds: [
    batch3Threshold("KNOWBE4-02", "default_lookback_days", "oldest_included_test_age_days", "gt", "fail", "Age of the oldest security test included in the coverage numerator.", "lookback_days", KNOWBE4_02_COMPLETE),
    batch3Threshold("KNOWBE4-02", "default_min_coverage_pct", "coverage_pct", "lt", "fail", "Unique tested active users divided by all active users, multiplied by 100.", "min_coverage_pct", KNOWBE4_02_COMPLETE),
  ] },
  { id: "KNOWBE4-03", control: 3, title: "Training completion rates", severity: "high", owner: "knowbe4_assess_training_program", surfaces: ["training-campaigns", "training-enrollments"], predicate: "Compute completed enrollments divided by all due enrollments for each active campaign; below fail_completion_pct fails and below min_completion_pct warns.", emptyOutcome: "warn", constants: { default_min_completion_pct: 90, default_fail_completion_pct: 80 }, thresholds: [
    batch3Threshold("KNOWBE4-03", "default_fail_completion_pct", "min:campaigns_evaluated.completion_pct", "lt", "fail", "Lowest uncapped completed-campaign enrollment completion percentage.", "fail_completion_pct"),
    batch3Threshold("KNOWBE4-03", "default_min_completion_pct", "min:campaigns_evaluated.completion_pct", "lt", "warn", "Lowest uncapped completed-campaign enrollment completion percentage.", "min_completion_pct"),
  ] },
  {
    id: "KNOWBE4-04",
    control: 4,
    title: "Training enrollment timeliness",
    severity: "high",
    owner: "knowbe4_assess_training_program",
    surfaces: ["users", "training-enrollments"],
    predicate: "Fail when more than 5 percent of evaluated new users lack an enrollment inside enrollment_grace_days; warn for any positive late count at or below 5 percent or incomplete reads.",
    emptyOutcome: "pass",
    constants: { default_enrollment_grace_days: 30, fail_above_late_enrollment_percent: 5 },
    thresholds: [batch3Threshold("KNOWBE4-04", "default_enrollment_grace_days", "maximum_enrollment_delay_days", "gt", "warn", "Greatest elapsed days from active-user creation to first training enrollment.", "enrollment_grace_days")],
    runtimeFactNames: {
      readable: "knowbe4_04_user_and_enrollment_reads_succeeded",
      complete: "knowbe4_04_user_and_enrollment_lists_complete",
      population: "knowbe4_04_new_user_count",
      failureMatches: "knowbe4_04_late_or_missing_enrollment_count",
      reviewMatches: "knowbe4_04_late_enrollment_percent",
    },
    decisionInputs: {
      knowbe4_04_user_and_enrollment_reads_succeeded: "Boolean true only when active users and training enrollments returned the creation, enrollment, and campaign fields needed for the grace-window join.",
      knowbe4_04_user_and_enrollment_lists_complete: "Boolean true only when user and enrollment pagination exhausted and no user was omitted by configured caps.",
      knowbe4_04_new_user_count: "Non-negative complete count of active users created early enough for enrollment_grace_days to have elapsed.",
      knowbe4_04_late_or_missing_enrollment_count: "Non-negative count of evaluated new users with no enrollment dated inside enrollment_grace_days after user creation.",
      knowbe4_04_late_enrollment_percent: "Percentage equal to late_or_missing_enrollment_count divided by new_user_count times 100; null means either complete operand was unavailable.",
    },
    decisionRules: [
      batch2Rule("manual", batch2Ne("knowbe4_04_user_and_enrollment_reads_succeeded", true)),
      batch2Rule("pass", batch2All(
        batch2Eq("knowbe4_04_new_user_count", 0),
        batch2Eq("knowbe4_04_user_and_enrollment_lists_complete", true),
      )),
      batch2Rule("fail", { op: "gt", left: batch2Path("knowbe4_04_late_enrollment_percent"), right: batch2Path("fail_above_late_enrollment_percent") }),
      batch2Rule("warn", batch2Any(
        batch2Ne("knowbe4_04_user_and_enrollment_lists_complete", true),
        batch2Gt("knowbe4_04_late_or_missing_enrollment_count", 0),
      )),
      batch2Rule("pass", { op: "always" }),
    ],
  },
  { id: "KNOWBE4-05", control: 5, title: "User risk score distribution", severity: "medium", owner: "knowbe4_assess_user_risk", surfaces: ["users", "risk-history"], predicate: "Compute mean and population standard deviation over every user with a numeric risk score; mean above max_mean_risk_score or deviation above max_risk_score_stddev violates.", emptyOutcome: "warn", constants: { default_max_mean_risk_score: 50, default_max_risk_score_stddev: 25 }, thresholds: [
    batch3Threshold("KNOWBE4-05", "default_max_mean_risk_score", "mean_risk_score", "gt", "fail", "Arithmetic mean over every returned numeric user risk score.", "max_mean_risk_score"),
    batch3Threshold("KNOWBE4-05", "default_max_risk_score_stddev", "stddev_risk_score", "gt", "warn", "Population standard deviation over every returned numeric user risk score.", "max_risk_score_stddev"),
  ] },
  {
    id: "KNOWBE4-06",
    control: 6,
    title: "Phish-prone percentage tracking",
    severity: "high",
    owner: "knowbe4_assess_phishing_program",
    surfaces: ["security-tests", "security-test-recipients"],
    predicate: "Fail when the raw current phish-prone percentage exceeds configured_max_phish_prone_percent; warn when no measurable test exists, recipient reads are incomplete, or the current percentage rose above a readable baseline.",
    emptyOutcome: "warn",
    constants: { default_max_phish_prone_pct: 15 },
    thresholds: [batch3Threshold("KNOWBE4-06", "default_max_phish_prone_pct", "current_phish_prone_pct", "gt", "fail", "Raw current failed-recipient percentage over every evaluable delivered recipient.", "max_phish_prone_pct")],
    runtimeFactNames: {
      readable: "knowbe4_06_security_test_sources_readable",
      complete: "knowbe4_06_recipient_population_complete",
      population: "knowbe4_06_security_test_count",
      failureMatches: "knowbe4_06_current_phish_prone_percent",
      reviewMatches: "knowbe4_06_baseline_phish_prone_percent",
    },
    decisionInputs: {
      knowbe4_06_security_test_sources_readable: "Boolean true only when security-test and selected recipient responses contain the status and recipient outcome fields needed for the current percentage.",
      knowbe4_06_recipient_population_complete: "Boolean true only when security-test pagination and every selected recipient list exhaust without caps, failed child reads, or missing recipient outcomes.",
      knowbe4_06_security_test_count: "Uncapped count of completed security tests evaluated inside the selected lookback window.",
      knowbe4_06_current_phish_prone_percent: "Raw current failed-recipient percentage over every evaluable delivered recipient; null means no measurable denominator.",
      knowbe4_06_baseline_phish_prone_percent: "Raw preceding-period phish-prone percentage computed over the same recipient semantics; null means no comparable baseline.",
      knowbe4_06_configured_max_phish_prone_percent: "Resolved maxPhishPronePercent after validation in the 0 through 100 domain; null means configuration was not established and requires manual review.",
    },
    decisionRules: [
      batch2Rule("manual", batch2Any(
        batch2Ne("knowbe4_06_security_test_sources_readable", true),
        batch2Not(batch2Defined("knowbe4_06_configured_max_phish_prone_percent")),
      )),
      batch2Rule("warn", batch2Any(
        batch2Eq("knowbe4_06_security_test_count", 0),
        batch2Not(batch2Defined("knowbe4_06_current_phish_prone_percent")),
      )),
      batch2Rule("fail", {
        op: "gt",
        left: batch2Path("knowbe4_06_current_phish_prone_percent"),
        right: batch2Path("knowbe4_06_configured_max_phish_prone_percent"),
      }),
      batch2Rule("warn", batch2Any(
        batch2Ne("knowbe4_06_recipient_population_complete", true),
        batch2All(
          batch2Defined("knowbe4_06_baseline_phish_prone_percent"),
          {
            op: "gt",
            left: batch2Path("knowbe4_06_current_phish_prone_percent"),
            right: batch2Path("knowbe4_06_baseline_phish_prone_percent"),
          },
        ),
      )),
      batch2Rule("pass", batch2All(
        batch2Eq("knowbe4_06_security_test_sources_readable", true),
        batch2Eq("knowbe4_06_recipient_population_complete", true),
        batch2Gt("knowbe4_06_security_test_count", 0),
        batch2Defined("knowbe4_06_current_phish_prone_percent"),
        batch2Defined("knowbe4_06_configured_max_phish_prone_percent"),
      ), "A missing baseline is allowed because the current raw percentage and configured ceiling independently establish compliance."),
    ],
  },
  {
    id: "KNOWBE4-07",
    control: 7,
    title: "Phishing failure rate trending",
    severity: "medium",
    owner: "knowbe4_assess_phishing_program",
    surfaces: ["security-tests", "security-test-recipients"],
    predicate: "Compare complete chronological test failure rates; fail when the recent-minus-prior delta exceeds 5 percentage points, warn for a positive delta through 5 or insufficient periods, and pass for a non-positive delta.",
    emptyOutcome: "warn",
    constants: { fail_above_delta_points: 5 },
    runtimeFactNames: {
      readable: "knowbe4_07_test_reads_succeeded",
      complete: "knowbe4_07_test_and_recipient_lists_complete",
      population: "knowbe4_07_security_tests_compared",
      failureMatches: "knowbe4_07_failure_rate_delta_points",
      reviewMatches: "knowbe4_07_security_tests_compared",
    },
    decisionInputs: {
      knowbe4_07_test_reads_succeeded: "Boolean true only when security-test and required recipient records were readable for both chronological comparison periods.",
      knowbe4_07_test_and_recipient_lists_complete: "Boolean true only when security-test pagination and every selected recipient read exhausted without caps or failures.",
      knowbe4_07_security_tests_compared: "Non-negative complete count of chronological tests included across the recent and preceding periods.",
      knowbe4_07_failure_rate_delta_points: "Recent-period failure percentage minus preceding-period failure percentage; null means fewer than two measurable periods.",
    },
    decisionRules: [
      batch2Rule("manual", batch2Ne("knowbe4_07_test_reads_succeeded", true)),
      batch2Rule("warn", batch2Any(
        batch2Eq("knowbe4_07_security_tests_compared", 0),
        batch2Not(batch2Defined("knowbe4_07_failure_rate_delta_points")),
      )),
      batch2Rule("fail", { op: "gt", left: batch2Path("knowbe4_07_failure_rate_delta_points"), right: batch2Path("fail_above_delta_points") }),
      batch2Rule("warn", batch2Any(
        batch2Ne("knowbe4_07_test_and_recipient_lists_complete", true),
        batch2Gt("knowbe4_07_failure_rate_delta_points", 0),
      )),
      batch2Rule("pass", { op: "always" }),
    ],
  },
  { id: "KNOWBE4-08", control: 8, title: "Group coverage analysis", severity: "medium", owner: "knowbe4_assess_user_risk", surfaces: ["groups", "phishing-campaigns", "training-campaigns"], predicate: "Count active groups absent from both a phishing campaign and a training campaign inside lookback_days.", emptyOutcome: "warn" },
  { id: "KNOWBE4-09", control: 9, title: "Campaign targeting completeness", severity: "high", owner: "knowbe4_assess_phishing_program", surfaces: ["users", "phishing-campaigns", "security-test-recipients"], predicate: "Count campaigns whose unique recipient coverage is below min_coverage_pct, or below 100 percent when require_full_targeting is true.", constants: { default_min_coverage_pct: 90 }, thresholds: [batch3Threshold("KNOWBE4-09", "default_min_coverage_pct", "estimated_coverage_pct", "lt", "fail", "Estimated percentage of the complete active-user population targeted by active campaigns.", "min_coverage_pct")] },
  {
    id: "KNOWBE4-10",
    control: 10,
    title: "Remedial training triggers",
    severity: "high",
    owner: "knowbe4_assess_training_program",
    surfaces: ["security-test-recipients", "training-enrollments", "training-policies"],
    predicate: "Among failed users with measurable follow-up, fail below 50 percent remediated inside remedial_window_days, warn from 50 through below 90 percent, and pass at 90 percent or when no sampled failure requires remediation.",
    emptyOutcome: "warn",
    constants: { default_remedial_window_days: 14, pass_remediated_percent: 90, fail_below_remediated_percent: 50 },
    thresholds: [batch3Threshold("KNOWBE4-10", "default_remedial_window_days", "maximum_remedial_enrollment_delay_days", "gt", "warn", "Greatest elapsed days from phishing failure to remedial enrollment among followed-up failed users.", "remedial_window_days")],
    runtimeFactNames: {
      readable: "knowbe4_10_remediation_reads_succeeded",
      complete: "knowbe4_10_recipient_and_enrollment_reads_complete",
      population: "knowbe4_10_failed_user_count",
      failureMatches: "knowbe4_10_remediated_percent",
      reviewMatches: "knowbe4_10_no_remediation_due",
    },
    decisionInputs: {
      knowbe4_10_remediation_reads_succeeded: "Boolean true only when sampled failed-recipient, training-enrollment, and active remediation-policy evidence is readable.",
      knowbe4_10_recipient_and_enrollment_reads_complete: "Boolean true when every selected security test recipient list was read and no sampled failed user lacks a completed enrollment lookup; the inherited no-failure snapshot exception is rendered separately.",
      knowbe4_10_failed_user_count: "Non-negative count of distinct failed users in sampled security tests for whom remediation is due.",
      knowbe4_10_remediated_percent: "Percentage of failed sampled users enrolled in remedial training inside default_remedial_window_days; null means the sampled denominator or follow-up join was unavailable.",
      knowbe4_10_no_remediation_due: "Boolean true only when at least one security test was sampled, those sampled tests contain zero failed users, and there are no unsampled tests; an empty test window is false and warns.",
    },
    decisionRules: [
      batch2Rule("manual", batch2Ne("knowbe4_10_remediation_reads_succeeded", true)),
      batch2Rule("pass", batch2All(
        batch2Eq("knowbe4_10_no_remediation_due", true),
        batch2Eq("knowbe4_10_recipient_and_enrollment_reads_complete", true),
      ), "Preserves the inherited clean sampled exception only when no failed user is due and no runtime collection decorator marked the evidence incomplete."),
      batch2Rule("warn", batch2Not(batch2Defined("knowbe4_10_remediated_percent"))),
      batch2Rule("fail", batch2All(
        batch2Gt("knowbe4_10_failed_user_count", 0),
        { op: "lt", left: batch2Path("knowbe4_10_remediated_percent"), right: batch2Path("fail_below_remediated_percent") },
      )),
      batch2Rule("warn", batch2Any(
        batch2Ne("knowbe4_10_recipient_and_enrollment_reads_complete", true),
        { op: "lt", left: batch2Path("knowbe4_10_remediated_percent"), right: batch2Path("pass_remediated_percent") },
      )),
      batch2Rule("pass", { op: "always" }),
    ],
  },
  { id: "KNOWBE4-11", control: 11, title: "Training content currency", severity: "medium", owner: "knowbe4_assess_training_program", surfaces: ["training-campaigns", "training-enrollments", "store-purchases"], predicate: "Fail for any assigned retired store purchase; warn when an assigned module's publication or update age exceeds max_content_age_days or its date is absent.", emptyOutcome: "warn", constants: { default_max_content_age_days: 365 }, thresholds: [batch3Threshold("KNOWBE4-11", "default_max_content_age_days", "max_observed_content_age_days", "gt", "warn", "Greatest age in days among all assigned dated store purchases.", "max_content_age_days")] },
  {
    id: "KNOWBE4-12",
    control: 12,
    title: "Admin role audit",
    severity: "high",
    owner: "knowbe4_assess_account_governance",
    surfaces: ["account", "users"],
    predicate: "Fail when the raw administrator count exceeds configured_max_admin_count; warn when no administrator is visible, any administrator identifier is absent from the active-user inventory, or either source is incomplete.",
    emptyOutcome: "warn",
    constants: { default_max_admin_count: 3 },
    thresholds: [batch3Threshold("KNOWBE4-12", "default_max_admin_count", "admin_count", "gt", "fail", "Uncapped administrator identifier count from the account object.", "max_admin_count")],
    runtimeFactNames: {
      readable: "knowbe4_12_account_and_user_sources_readable",
      complete: "knowbe4_12_account_and_user_population_complete",
      population: "knowbe4_12_administrator_count",
      failureMatches: "knowbe4_12_administrator_count",
      reviewMatches: "knowbe4_12_external_administrator_count",
    },
    decisionInputs: {
      knowbe4_12_account_and_user_sources_readable: "Boolean true only when the account administrator list and active-user inventory return parseable administrator identifiers and user status fields.",
      knowbe4_12_account_and_user_population_complete: "Boolean true only when the account object is readable and active-user pagination exhausts without caps, failures, or missing identifiers.",
      knowbe4_12_administrator_count: "Uncapped count of administrator identifiers returned by the account object before any evidence sample is sliced.",
      knowbe4_12_external_administrator_count: "Uncapped count of administrator identifiers that cannot be joined to the complete active-user inventory.",
      knowbe4_12_configured_max_admin_count: "Resolved maxAdminCount after configuration validation; null means the limit was not established and requires manual review.",
    },
    decisionRules: [
      batch2Rule("manual", batch2Any(
        batch2Ne("knowbe4_12_account_and_user_sources_readable", true),
        batch2Not(batch2Defined("knowbe4_12_configured_max_admin_count")),
      )),
      batch2Rule("warn", batch2Eq("knowbe4_12_administrator_count", 0)),
      batch2Rule("fail", {
        op: "gt",
        left: batch2Path("knowbe4_12_administrator_count"),
        right: batch2Path("knowbe4_12_configured_max_admin_count"),
      }),
      batch2Rule("warn", batch2Any(
        batch2Ne("knowbe4_12_account_and_user_population_complete", true),
        batch2Gt("knowbe4_12_external_administrator_count", 0),
      )),
      batch2Rule("pass", { op: "always" }),
    ],
  },
  { id: "KNOWBE4-13", control: 13, title: "SSO integration status", severity: "critical", owner: "knowbe4_assess_account_governance", surfaces: ["account"], predicate: "Count one violation when the documented account SSO flag is explicitly false; absent SSO state requires manual review." },
  { id: "KNOWBE4-14", control: 14, title: "Reporting frequency", severity: "medium", owner: "knowbe4_assess_account_governance", surfaces: ["security-tests", "training-enrollments", "phisher-messages"], predicate: "Count the absence of recent phishing, training, and optional PhishER reporting evidence; unconfigured PhishER cannot independently fail the control." },
  {
    id: "KNOWBE4-15",
    control: 15,
    title: "USB test campaign execution",
    severity: "medium",
    owner: "knowbe4_assess_account_governance",
    surfaces: [],
    predicate: "No Reporting API surface exposes USB drop tests, so the API capability fact is false and the check requires console evidence regardless of the configured requirement.",
    decisionInputs: {
      knowbe4_15_reporting_api_exposes_usb_tests: "Boolean capability fact owned by KNOWBE4-15. Type/domain: boolean. Source/owner: the fixed KnowBe4 Reporting API v1 surface inventory for this check, which has no USB-test resource. Completeness/sample semantics: false describes the complete documented API capability rather than a sampled tenant response. Null/missing meaning: the capability inventory was not supplied and the check requires manual review.",
    },
    decisionRules: [
      batch2Rule("manual", batch2Ne("knowbe4_15_reporting_api_exposes_usb_tests", true)),
      batch2Rule("manual", { op: "always" }),
    ],
  },
  { id: "KNOWBE4-16", control: 16, title: "Vishing campaign execution", severity: "medium", owner: "knowbe4_assess_account_governance", surfaces: ["callback-tests"], predicate: "Count the absence of a callback or vishing security test inside lookback_days when require_vishing_tests is true; otherwise report the observed inventory." },
  { id: "KNOWBE4-17", control: 17, title: "Compliance training modules", severity: "high", owner: "knowbe4_assess_training_program", surfaces: ["training-campaigns", "training-enrollments", "store-purchases"], predicate: "Count configured required topics absent from assigned content and required-topic enrollments whose completion percentage is below min_completion_pct.", constants: { default_min_completion_pct: 90 }, thresholds: [batch3Threshold("KNOWBE4-17", "default_min_completion_pct", "min:topics.completion_pct", "lt", "warn", "Lowest uncapped completion percentage among required compliance topics.", "min_completion_pct")] },
  { id: "KNOWBE4-18", control: 18, title: "Inactive user cleanup", severity: "medium", owner: "knowbe4_assess_user_risk", surfaces: ["users", "security-test-recipients", "training-enrollments"], predicate: "Count active users with no phishing or training participation inside inactive_days.", emptyOutcome: "pass", constants: { default_inactive_days: 180 }, thresholds: [batch3Threshold("KNOWBE4-18", "default_inactive_days", "max_observed_inactivity_days", "gt", "warn", "Greatest elapsed days since phishing, training, or sign-in activity among active users.", "inactive_days")] },
  {
    id: "KNOWBE4-19",
    control: 19,
    title: "Phishing report rate",
    severity: "medium",
    owner: "knowbe4_assess_phishing_program",
    surfaces: ["security-tests", "security-test-recipients"],
    predicate: "Compute reported recipients divided by delivered evaluable recipients; fail below one half of min_report_rate_pct, warn from that half through below the configured minimum, and pass at or above the minimum.",
    emptyOutcome: "warn",
    constants: { default_min_report_rate_pct: 50, default_fail_report_rate_pct: 25 },
    thresholds: [
      batch3Threshold("KNOWBE4-19", "default_fail_report_rate_pct", "report_rate_pct", "lt", "fail", "Reported-recipient count divided by delivered-recipient count, multiplied by 100."),
      batch3Threshold("KNOWBE4-19", "default_min_report_rate_pct", "report_rate_pct", "lt", "warn", "Reported-recipient count divided by delivered-recipient count, multiplied by 100.", "min_report_rate_pct"),
    ],
    runtimeFactNames: {
      readable: "knowbe4_19_security_test_reads_succeeded",
      complete: "knowbe4_19_security_test_and_recipient_lists_complete",
      population: "knowbe4_19_delivered_recipient_count",
      failureMatches: "knowbe4_19_report_rate_percent",
      reviewMatches: "knowbe4_19_configured_minimum_percent",
    },
    decisionInputs: {
      knowbe4_19_security_test_reads_succeeded: "Boolean true only when security tests and their delivered and reported counters were readable for the selected lookback.",
      knowbe4_19_security_test_and_recipient_lists_complete: "Boolean true only when security-test pagination and all verdict-bearing recipient reads exhausted; optional PhishER enrichment does not change this percentage.",
      knowbe4_19_delivered_recipient_count: "Non-negative total delivered recipients over every complete security test in the lookback; zero has warn semantics because the rate denominator is absent.",
      knowbe4_19_report_rate_percent: "Reported-recipient count divided by delivered-recipient count times 100; null means delivered count is zero or a required counter is unavailable.",
      knowbe4_19_configured_minimum_percent: "Configured min_report_rate_pct after clamping to 0 through 100.",
      knowbe4_19_configured_fail_percent: "Exactly configured min_report_rate_pct divided by 2; this is the strict failure boundary.",
    },
    decisionRules: [
      batch2Rule("manual", batch2Ne("knowbe4_19_security_test_reads_succeeded", true)),
      batch2Rule("warn", batch2Any(
        batch2Eq("knowbe4_19_delivered_recipient_count", 0),
        batch2Not(batch2Defined("knowbe4_19_report_rate_percent")),
      )),
      batch2Rule("fail", { op: "lt", left: batch2Path("knowbe4_19_report_rate_percent"), right: batch2Path("knowbe4_19_configured_fail_percent") }),
      batch2Rule("warn", batch2Any(
        batch2Ne("knowbe4_19_security_test_and_recipient_lists_complete", true),
        { op: "lt", left: batch2Path("knowbe4_19_report_rate_percent"), right: batch2Path("knowbe4_19_configured_minimum_percent") },
      )),
      batch2Rule("pass", { op: "always" }),
    ],
  },
  { id: "KNOWBE4-20", control: 20, title: "Campaign scheduling regularity", severity: "medium", owner: "knowbe4_assess_phishing_program", surfaces: ["phishing-campaigns", "security-tests"], predicate: "Count adjacent completed security tests separated by more than max_schedule_gap_days and no upcoming recurring campaign schedule.", emptyOutcome: "fail", constants: { default_max_schedule_gap_days: 45 }, thresholds: [batch3Threshold("KNOWBE4-20", "default_max_schedule_gap_days", "max_gap_days", "gt", "fail", "Greatest adjacent or current-boundary gap in days across the complete test series.", "max_schedule_gap_days")] },
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
    "KNOWBE4-10 can pass when the security-test collection is empty but retained recipient samples show no remediation is due or at least 90 percent remediation even though recipient_reads_complete is false; unread recipients are not reflected.",
    "KNOWBE4-18 can pass when the security-test collection is empty, activity metadata marks the read partial, users_without_loaded_activity is zero, and inactive_users is null; unobserved activity is not reflected.",
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
