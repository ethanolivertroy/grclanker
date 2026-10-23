import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
  deriveDecisionRules,
  type BatchCheckDefinition,
  type BatchCompletenessDefinition,
  type BatchCriterionExample,
  type BatchPaginationDefinition,
  type BatchSurfaceDefinition,
} from "./batch-spec-builder.js";
import { KNOWBE4_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import type { PortableValue, RequestParameterContract, VerdictCondition, VerdictOperand, VerdictRule } from "./spec-model.js";

// The account record is exported cut to these fields, each admin to its own list; certificate-shaped account fields are
// summarized as present with their length.
export const ACCOUNT_FIELDS: readonly string[] = [
  "name",
  "type",
  "domains",
  "subscription_level",
  "subscription_end_date",
  "number_of_seats",
  "current_risk_score",
];
export const ACCOUNT_ADMIN_FIELDS: readonly string[] = ["id", "first_name", "last_name", "email"];
// Free-form buckets on the user record that the assessments never read and that could carry anything an admin typed.
export const USER_FREE_FORM_FIELDS: readonly string[] = [
  "comment",
  "custom_field_1",
  "custom_field_2",
  "custom_field_3",
  "custom_field_4",
  "custom_date_1",
  "custom_date_2",
];
// With redact_pii, exported values under these keys are pseudonymized (hash) or replaced with [redacted] (mask).
export const PII_HASH_FIELDS: readonly string[] = ["email", "manager_email", "reportedBy", "reported_by", "from", "to", "cc"];
export const PII_MASK_FIELDS: readonly string[] = [
  "first_name",
  "last_name",
  "manager_name",
  "phone_number",
  "mobile_phone_number",
  "extension",
  "aliases",
  "employee_number",
  "comment",
  "subject",
  "ip",
  "ip_location",
  "custom_field_1",
  "custom_field_2",
  "custom_field_3",
  "custom_field_4",
  "custom_date_1",
  "custom_date_2",
];
// A recipient failed a security test at the earliest of these timestamps that parses as a date.
export const FAILURE_TIMESTAMP_KEYS: readonly string[] = [
  "clicked_at",
  "replied_at",
  "attachment_opened_at",
  "macro_enabled_at",
  "data_entered_at",
  "qr_code_scanned",
];
// Without required_compliance_topics, an assigned training module counts as compliance content when its name matches.
export const COMPLIANCE_TOPIC_PATTERN = /\b(hipaa|pci|gdpr|sox|ferpa|ccpa|cpra|glba|cmmc|nist|iso\s?27001|fedramp|privacy|compliance|acceptable use|insider threat)\b/i;
// Each control's framework references, in the order FedRAMP, CMMC, SOC 2, CIS Controls v8, PCI-DSS, DISA STIG, IRAP, ISMAP.
export const KNOWBE4_FRAMEWORK_MAPPINGS: Readonly<Record<number, readonly [string, string, string, string, string, string, string, string]>> = {
  1: ["AT-2(1)", "L2 3.2.1", "CC1.4", "14.1", "12.6.2", "SRG-APP-000516", "ISM-0252", "HR-01"],
  2: ["AT-2(1)", "L2 3.2.2", "CC1.4", "14.2", "12.6.2", "SRG-APP-000516", "ISM-0252", "HR-01"],
  3: ["AT-2", "L2 3.2.1", "CC1.4", "14.1", "12.6.1", "SRG-APP-000516", "ISM-0252", "HR-02"],
  4: ["AT-2", "L2 3.2.2", "CC1.4", "14.2", "12.6.1", "SRG-APP-000516", "ISM-0252", "HR-02"],
  5: ["RA-3", "L2 3.11.1", "CC3.2", "14.4", "12.6.2", "SRG-APP-000516", "ISM-0253", "RA-01"],
  6: ["AT-2(1)", "L2 3.2.3", "CC1.4", "14.4", "12.6.3.1", "SRG-APP-000516", "ISM-0252", "HR-03"],
  7: ["AT-2(1)", "L2 3.2.3", "CC1.4", "14.4", "12.6.3.1", "SRG-APP-000516", "ISM-0252", "HR-03"],
  8: ["AT-2", "L2 3.2.2", "CC1.4", "14.2", "12.6.1", "SRG-APP-000516", "ISM-0252", "HR-01"],
  9: ["AT-2", "L2 3.2.2", "CC1.4", "14.2", "12.6.2", "SRG-APP-000516", "ISM-0252", "HR-01"],
  10: ["AT-2(2)", "L2 3.2.3", "CC1.4", "14.3", "12.6.3", "SRG-APP-000516", "ISM-0253", "HR-04"],
  11: ["AT-3", "L2 3.2.1", "CC1.4", "14.1", "12.6.1", "SRG-APP-000516", "ISM-0252", "HR-02"],
  12: ["AC-6(5)", "L2 3.1.5", "CC6.3", "5.4", "7.2.2", "SRG-APP-000340", "ISM-0432", "AC-01"],
  13: ["IA-2(1)", "L2 3.5.3", "CC6.1", "6.5", "8.4.2", "SRG-APP-000149", "ISM-1401", "AM-01"],
  14: ["CA-7", "L2 3.12.3", "CC7.2", "14.4", "12.6.2", "SRG-APP-000516", "ISM-0253", "SO-01"],
  15: ["AT-2(1)", "L2 3.2.1", "CC1.4", "14.1", "12.6.2", "SRG-APP-000516", "ISM-0252", "HR-05"],
  16: ["AT-2(1)", "L2 3.2.1", "CC1.4", "14.1", "12.6.2", "SRG-APP-000516", "ISM-0252", "HR-05"],
  17: ["AT-2", "L2 3.2.1", "CC1.4", "14.1", "12.6.1", "SRG-APP-000516", "ISM-0252", "HR-06"],
  18: ["AC-2(3)", "L2 3.1.1", "CC6.2", "5.3", "8.1.4", "SRG-APP-000025", "ISM-1648", "AC-02"],
  19: ["AT-2(1)", "L2 3.2.3", "CC1.4", "14.4", "12.6.3.1", "SRG-APP-000516", "ISM-0252", "HR-03"],
  20: ["AT-2", "L2 3.2.1", "CC1.4", "14.1", "12.6.2", "SRG-APP-000516", "ISM-0252", "HR-01"],
};

const series = (items: readonly string[], conjunction = "and"): string =>
  items.length <= 2 ? items.join(` ${conjunction} `) : `${items.slice(0, -1).join(", ")}, ${conjunction} ${items[items.length - 1]}`;

const REPORTING_SERVICE = "KnowBe4 Reporting API";
const PHISHER_SERVICE = "KnowBe4 PhishER GraphQL API";
const REPORTING_DOCS = "https://developer.knowbe4.com/rest/reporting";
const PHISHER_DOCS = "https://developer.knowbe4.com/graphql/phisher";
const REPORTING_HOST = "Use the resolved Reporting API base URL: base_url, else the selected region's https://{region}.api.knowbe4.com.";
const PHISHER_HOST = "Use the resolved PhishER GraphQL URL: phisher_graphql_url, else https://training.knowbe4.com/graphql for the us region and https://{region}.knowbe4.com/graphql for the others.";
const REPORTING_HEADERS = ["Accept: application/json", "Authorization: Bearer {api_token}"];
const PHISHER_HEADERS = ["Accept: application/json", "Authorization: Bearer {phisher_api_token}", "Content-Type: application/json"];
const EXPORT_PASSES = "the export's PII pass, when redact_pii is set, and its credential pass";
const RAW_EXPORT_STAGE = `The collector exports every returned record as read, through ${EXPORT_PASSES}; decision facts read the listed fields.`;
const withoutFreeForm = (records: string): string =>
  `The collector exports ${records} without its ${series(USER_FREE_FORM_FIELDS)}, through ${EXPORT_PASSES}; decision facts read the listed fields.`;
const ACCOUNT_STAGE = `The collector keeps the account's ${series(ACCOUNT_FIELDS)} when present, each entry of admins that is a JSON object cut to its ${series(ACCOUNT_ADMIN_FIELDS)}, and, under certificates, only whether each field whose name contains cert, fingerprint, or thumbprint in any letter case is present and the length of its text; every other field is dropped, and the result is exported through ${EXPORT_PASSES}.`;

const REFUSAL = "a status outside 200 through 299 after retries, an empty body, or a body that is not JSON is a refusal";
const arrayResponse = (records: string): string =>
  `A JSON array holding ${records}, an entry that is not a JSON object being dropped; ${REFUSAL}, as is JSON that is not an array.`;
const ACCOUNT_RESPONSE = `A JSON object carrying at least one of ${series(["name", "type", "domains", "admins", "subscription_level", "subscription_end_date", "number_of_seats", "current_risk_score"], "or")}; ${REFUSAL}, as is any other JSON.`;
const GRAPHQL_RESPONSE = `A JSON object carrying data or errors, whose data.phisherMessages may carry nodes, one reported message per entry (an entry that is not a JSON object being dropped), and pagination with page, pages, per, totalCount, and nextPageKey; ${REFUSAL}, as is any other JSON or a non-empty errors array.`;

const param = (
  name: string,
  location: RequestParameterContract["location"],
  value: string,
  required = true,
  when?: string,
): RequestParameterContract => ({ name, location, required, value, ...(when ? { when } : {}) });

const PAGE_NUMBER = "The page number: 1 for the first page, then one more than the previous page's";
const pagedParameters = (pageSize: number, probed: boolean, filters: readonly RequestParameterContract[]): RequestParameterContract[] => [
  ...filters,
  param("page", "query", PAGE_NUMBER),
  param("per_page", "query", probed ? `${pageSize}, or 1 on the knowbe4_check_access probe` : `${pageSize}`),
];
const listParameters = (probed: boolean, ...filters: RequestParameterContract[]): RequestParameterContract[] =>
  pagedParameters(500, probed, filters);
const EXCEPT_COUNT = "On every read except the knowbe4_check_access count";
const EXCEPT_PROBE = "On every read except the knowbe4_check_access probe";
const PHISHER_PARAMETERS: readonly RequestParameterContract[] = [
  param("query", "json-body", "The phisherMessages query document, sorted by REPORTED_AT DESCENDING; the count-only document on the knowbe4_check_access count"),
  param("variables.query", "json-body", "The PhishER filter reported_at:[{date} TO *], {date} being the UTC calendar date (YYYY-MM-DD) of the assessment time minus the lookback days; an empty string on the knowbe4_check_access count"),
  param("variables.per", "json-body", "200, or phisher_message_limit when that is smaller", true, EXCEPT_COUNT),
  param("variables.page", "json-body", PAGE_NUMBER, true, EXCEPT_COUNT),
  param("variables.nextPageKey", "json-body", "The previous page's pagination.nextPageKey", false, "On a page after the first, when the previous page returned a nextPageKey"),
];

const reportingSurface = (
  id: string,
  path: string,
  fields: readonly string[],
  parameters: readonly RequestParameterContract[],
  responseShape: string,
  projectionStage = RAW_EXPORT_STAGE,
): BatchSurfaceDefinition => ({
  id,
  path,
  service: REPORTING_SERVICE,
  documentationUrl: REPORTING_DOCS,
  fields,
  request: { clientRegion: REPORTING_HOST, headers: REPORTING_HEADERS, parameters, responseShape },
  projectionStage,
});

const ACTIVE_STATUS = param("status", "query", "active");

const PHISHING_SURFACES: readonly BatchSurfaceDefinition[] = [
  reportingSurface(
    "account",
    "/v1/account",
    [...ACCOUNT_FIELDS, ...ACCOUNT_ADMIN_FIELDS.map((field) => `admins.${field}`)],
    [],
    ACCOUNT_RESPONSE,
    ACCOUNT_STAGE,
  ),
  reportingSurface(
    "account_risk_score_history",
    "/v1/account/risk_score_history",
    ["risk_score", "date"],
    listParameters(false, param("full", "query", "true")),
    arrayResponse("one organization risk score point per entry"),
  ),
  reportingSurface(
    "users",
    "/v1/users",
    ["id", "joined_on", "last_sign_in", "current_risk_score"],
    listParameters(true, ACTIVE_STATUS),
    arrayResponse("one user per entry"),
    withoutFreeForm("each returned user"),
  ),
  reportingSurface("groups", "/v1/groups", ["id", "member_count"], listParameters(true, ACTIVE_STATUS), arrayResponse("one group per entry")),
  reportingSurface(
    "phishing_campaigns",
    "/v1/phishing/campaigns",
    ["campaign_id", "hidden", "last_run", "status", "groups.group_id", "groups.name", "psts.start_date"],
    listParameters(true),
    arrayResponse("one phishing campaign per entry"),
  ),
  reportingSurface(
    "security_tests",
    "/v1/phishing/security_tests",
    ["pst_id", "campaign_id", "started_at", "start_date", "phish_prone_percentage", "delivered_count", "scheduled_count", "reported_count"],
    listParameters(true),
    arrayResponse("one phishing security test per entry"),
  ),
  reportingSurface(
    "security_test_recipients",
    "/v1/phishing/security_tests/{pst_id}/recipients",
    ["user.id", ...FAILURE_TIMESTAMP_KEYS, "delivered_at", "bounced_at", "scheduled_at"],
    [param("pst_id", "path", "The sampled test's pst_id read as text"), ...listParameters(false)],
    arrayResponse("one recipient per entry"),
    withoutFreeForm("each sampled test's recipients, each embedded user"),
  ),
  {
    id: "phisher_messages",
    method: "POST",
    path: "/graphql",
    service: PHISHER_SERVICE,
    documentationUrl: PHISHER_DOCS,
    fields: ["id", "reportedAt", "reportedBy", "from", "subject", "category", "severity", "actionStatus", "pipelineStatus"],
    request: { clientRegion: PHISHER_HOST, headers: PHISHER_HEADERS, parameters: PHISHER_PARAMETERS, responseShape: GRAPHQL_RESPONSE },
    projectionStage: RAW_EXPORT_STAGE,
  },
];

const TRAINING_SURFACES: readonly BatchSurfaceDefinition[] = [
  reportingSurface(
    "training_campaigns",
    "/v1/training/campaigns",
    [
      "campaign_id",
      "status",
      "start_date",
      "end_date",
      "completion_percentage",
      "groups.group_id",
      "groups.name",
      ...["name", "content_type", "store_purchase_id", "store_purchased_id", "retired", "publish_date"].map((field) => `content.${field}`),
    ],
    pagedParameters(10, true, []),
    arrayResponse("one training campaign per entry"),
  ),
  reportingSurface(
    "training_enrollments",
    "/v1/training/enrollments",
    ["campaign_id", "module_name", "status", "user.id", "enrollment_date", "start_date", "completion_date"],
    listParameters(
      true,
      param("exclude_archived_users", "query", "true", true, EXCEPT_PROBE),
      param("include_campaign_id", "query", "true", true, EXCEPT_PROBE),
      param("include_store_purchase_id", "query", "true", true, EXCEPT_PROBE),
    ),
    arrayResponse("one training enrollment per entry"),
  ),
  reportingSurface(
    "store_purchases",
    "/v1/training/store_purchases",
    ["store_purchase_id", "store_purchased_id", "retired", "publish_date"],
    listParameters(true),
    arrayResponse("one ModStore purchase per entry"),
  ),
  reportingSurface("training_policies", "/v1/training/policies", [], listParameters(true), arrayResponse("one uploaded policy per entry")),
];

const GOVERNANCE_SURFACES: readonly BatchSurfaceDefinition[] = [
  reportingSurface(
    "callback_security_tests",
    "/v1/phishing/security_tests?campaign_type=callback",
    ["started_at", "start_date"],
    listParameters(false),
    arrayResponse("one callback phishing security test per entry"),
  ),
];

const KNOWBE4_SURFACES: readonly BatchSurfaceDefinition[] = [...PHISHING_SURFACES, ...TRAINING_SURFACES, ...GOVERNANCE_SURFACES];

const value = (entry: PortableValue): VerdictOperand => ({ kind: "value", value: entry });
const path = (name: string): VerdictOperand => ({ kind: "path", path: name });
type Comparator = "eq" | "ne" | "gt" | "lt";
const cmp = (op: Comparator, left: string | VerdictOperand, right: PortableValue | VerdictOperand): VerdictCondition => ({
  op,
  left: typeof left === "string" ? path(left) : left,
  right: right !== null && typeof right === "object" && !Array.isArray(right) ? right as VerdictOperand : value(right as PortableValue),
});
const eq = (left: string | VerdictOperand, right: PortableValue | VerdictOperand) => cmp("eq", left, right);
const ne = (left: string | VerdictOperand, right: PortableValue | VerdictOperand) => cmp("ne", left, right);
const gt = (left: string | VerdictOperand, right: PortableValue | VerdictOperand) => cmp("gt", left, right);
const lt = (left: string | VerdictOperand, right: PortableValue | VerdictOperand) => cmp("lt", left, right);
const all = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "and", conditions });
const any = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "or", conditions });
const not = (condition: VerdictCondition): VerdictCondition => ({ op: "not", condition });
const always: VerdictCondition = { op: "always" };
const rule = (status: VerdictRule["status"], condition: VerdictCondition): VerdictRule => ({ status, condition });
const unreported = (name: string): VerdictCondition => not({ op: "defined", operand: path(name) });
const incomplete = (...complete: string[]): VerdictCondition =>
  complete.length === 1 ? ne(complete[0], true) : any(...complete.map((name) => ne(name, true)));
// The runtime's percentage(): part / total * 100 rounded half up to one decimal place, and no value (false here) when
// total is not above 0.
const percent = (comparator: "gt" | "gte" | "lt", numerator: string, denominator: string, threshold: string): VerdictCondition => ({
  op: "ratio",
  numerator: path(numerator),
  denominator: path(denominator),
  comparator,
  threshold: path(threshold),
  scale: 100,
  roundDigits: 1,
});

const AS_NUMBER = "read as a number (a finite number, or a string that is not blank and parses as one)";
const READS_AS_TEXT = "A value reads as text when it is a string that is not blank, trimmed, or a finite number, in decimal.";
const PARSES_AS_DATE = "A value parses as a date when ECMAScript Date.parse reads its trimmed text, a finite number being read as its decimal text.";
const dayOption = (name: string, fallback: number, max = 3650): string =>
  `${name} argument when it is a finite number, else ${fallback}, clamped to 1 through ${max} and then truncated to a whole number`;
const percentOption = (name: string, fallback: number): string =>
  `${name} argument when it is a finite number, else ${fallback}, clamped to 0 through 100`;
const DAY = "a day being 86400000 milliseconds";
const LOOKBACK = `The lookback window runs from N days before the assessment time to the assessment time, ${DAY} and N being the ${dayOption("lookback_days", 90)}.`;
const TEST_START = `A security test's start is the first of its started_at and start_date that parses as a date; the test ran when it has a start no later than the assessment time, and ran in a window when that start also falls in the window. ${PARSES_AS_DATE}`;
const OLDEST_FIRST = "ordered oldest first by start, tests of equal start in the reverse of their returned order";
const TEST_PERCENTAGE = `A test's percentage is its phish_prone_percentage, ${AS_NUMBER}, times 100 and rounded half up to 2 decimal places.`;
const WEIGHTED = `${TEST_PERCENTAGE} Its weight is its delivered_count when that reads as a number, else its scheduled_count when that does, else 0. A weighted percentage over a set of tests is the sum of percentage times weight over the tests with a percentage and a weight above 0, divided by the sum of those weights, rounded half up to 2 decimal places.`;
const RECIPIENT_SAMPLE = `The recipient sample is the first N security tests that ran in the sample window, newest first by start with tests of equal start in their returned order, N being the ${dayOption("security_test_sample_limit", 12, 200).replace("clamped to 1", "clamped to 0")}. The sample window is the lookback window, or the last M days when the user risk assessment runs in the same call and M is larger, M being the ${dayOption("inactive_days", 180)}. A sampled test is read only when its pst_id reads as text, from GET /v1/phishing/security_tests/{pst_id}/recipients. ${READS_AS_TEXT}`;
const IS_TRUE = "the boolean true, the number 1, or a string that trims to true, 1, yes, or on in any letter case";
const ACTIVE_CAMPAIGN = `A campaign is active when it is not hidden and its campaign_id, read as text, is the campaign_id, read as text, of a security test that ran in the lookback window; or its last_run parses as a date at or after the start of the lookback window; or its status, read as text, contains active, scheduled, or in progress in any letter case. A campaign is hidden when its hidden is ${IS_TRUE}. ${TEST_START} ${LOOKBACK} ${READS_AS_TEXT}`;
const ALL_USERS = `A campaign targets All Users when one of the JSON object entries of its groups array has a group_id that, ${AS_NUMBER}, is 0, or a name that trims to All Users in any letter case.`;
const TRAINING_LOOKBACK = `The training lookback window runs from N days before the assessment time to the assessment time, ${DAY} and N being the ${dayOption("training_lookback_days", 365)}.`;
const trainingCampaign = (window: string, windowDefinition: string): string => `A training campaign is cancelled when its status, read as text, contains cancelled or canceled in any letter case, and closed when its status, read as text, contains completed in any letter case or its end_date parses as a date no later than the assessment time. It is in the ${window} when its start_date parses as a date in the window, its end_date parses as a date at or after the window's start, or its status, read as text, contains in progress, enrolling, or created in any letter case and its end_date does not parse as a date or parses as one at or after the window's start. ${windowDefinition} ${PARSES_AS_DATE} ${READS_AS_TEXT}`;
const TRAINING_CAMPAIGN = trainingCampaign("training lookback window", TRAINING_LOOKBACK);
const COMPLETED_ENROLLMENT = "An enrollment is completed when its status reads as text that is completed or passed in any letter case.";
const CAMPAIGN_COMPLETION = `A campaign's loaded enrollments are the returned enrollments whose campaign_id, read as text, is the campaign's campaign_id, read as text; a campaign without one has none. Its completion is its completion_percentage, ${AS_NUMBER}, when that is at or above 0, and otherwise the percentage of its loaded enrollments that are completed, rounded half up to 1 decimal place, when it has any. ${COMPLETED_ENROLLMENT}`;
const ENROLLMENT_LIMIT = `enrollment_limit (the ${dayOption("enrollment_limit", 20000, 1000000)})`;
const NOT_OBJECT_PAGE = "a page held an entry that is not a JSON object";
const ENROLLMENTS_CUT = `the enrollment list was read but is partial because a page held more enrollments than were left under ${ENROLLMENT_LIMIT}, a full page brought the enrollments kept to it, or ${NOT_OBJECT_PAGE}`;
const ENROLLMENT_DATE = "An enrollment belongs to the user whose ID is its user.id read as text, and its date is its enrollment_date when that parses as a date, else its start_date when that does.";
const GRACE_DAYS = `the ${dayOption("enrollment_grace_days", 30, 365)}`;
const FAILED_USERS = `A failed user is a distinct ID that is the user.id, read as text, of a recipient with a failure time among the recipients of the sampled tests counted by sampled_test_count, a recipient's failure time being the earliest of its ${series(FAILURE_TIMESTAMP_KEYS)} that parse as dates; the user's failure time is the earliest across those recipients. ${PARSES_AS_DATE} ${READS_AS_TEXT}`;
const STORE_MODULES = `An assigned store module is a JSON object entry of the content array of a training campaign that is not cancelled and is in the training lookback window, whose content_type does not read as text or contains store purchase in any letter case. A module's store purchase ID is its store_purchase_id read as text, else its store_purchased_id read as text, and a returned store purchase's ID is read the same way. ${TRAINING_CAMPAIGN}`;
const RETIRED_MODULE = `A module is retired when its retired is ${IS_TRUE}, or its store purchase ID is the ID of a returned store purchase whose retired is.`;
const MODULE_PUBLISHED = "A module's publish date is its publish_date when that parses as a date, else the publish_date of the last returned store purchase with the same ID whose publish_date parses as a date.";
const REQUIRED_TOPICS = "The required compliance topics are the entries of the required_compliance_topics argument that read as text, trimmed, when it is an array, or the non-blank comma-separated pieces of its text, trimmed, when it reads as text; a repeated topic counts each time.";
const COMPLIANCE_TOPICS = `The compliance topics are the required compliance topics, each matching the assigned modules whose name, lowercased by ECMAScript toLowerCase, contains the topic so lowercased; when no topic is required, a single topic matching the assigned modules whose name matches the ECMAScript regular expression /${COMPLIANCE_TOPIC_PATTERN.source}/${COMPLIANCE_TOPIC_PATTERN.flags}. The assigned modules are the distinct names, read as text, of the JSON object entries of the content arrays of the training campaigns that are not cancelled and are in the training lookback window. ${REQUIRED_TOPICS} ${TRAINING_CAMPAIGN}`;
const TOPIC_COMPLETION = `A topic's loaded enrollments are the returned enrollments whose module_name, read as text, is the name of one of its matching modules, and its completion is the percentage of them that are completed, rounded half up to 1 decimal place. ${COMPLETED_ENROLLMENT}`;
const PHISHING_CAMPAIGN_IN_WINDOW = "A phishing campaign is in the lookback window when its last_run, or the start_date of one of the JSON object entries of its psts array, parses as a date in the window.";
const GROUP_COVERED = "A set of campaigns covers a group when one of them targets All Users, or the group's id, read as text, is one of their targeted group IDs, a campaign's targeted group IDs being the group_id values, read as text, of the JSON object entries of its groups array.";
const INACTIVITY_WINDOW = `The inactivity window runs from N days before the assessment time to the assessment time, ${DAY} and N being the ${dayOption("inactive_days", 180)}.`;
const ACTIVE_ID = "An active ID is the user.id, read as text, of a delivered recipient of a sampled security test whose recipient list was read without a refusal and whose start falls in the inactivity window, or the user.id, read as text, of a returned training enrollment whose activity date is at or after the start of the inactivity window. A recipient is delivered when its delivered_at parses as a date, or its bounced_at does not and its scheduled_at does. An enrollment's activity date is its completion_date when that parses as a date, else its start_date when that does.";
const ACCOUNT_DOMAINS = "The account's allowed domains are the entries of the account record's domains that read as text, trimmed, when it is an array, or the non-blank comma-separated pieces of its text, trimmed, when it reads as text, each lowercased by ECMAScript toLowerCase.";

const KNOWBE4_INPUTS: Readonly<Record<string, string>> = {
  security_tests_readable: "True when the GET /v1/phishing/security_tests walk returned without a refusal.",
  security_tests_complete: "Security test list coverage.",
  days_since_latest_test: `Days from the start of the newest security test that ran to the assessment time, rounded half up to 1 decimal place; unreported when no security test ran. ${TEST_START}`,
  max_campaign_gap_days: `The ${dayOption("max_campaign_gap_days", 30)}.`,
  users_readable: "True when the GET /v1/users walk filtered to status=active returned without a refusal.",
  users_complete: "Active user list coverage.",
  user_record_count: "Number of user records the active user walk kept, entries that are not JSON objects being dropped.",
  active_user_count: `Number of distinct IDs among the returned active users, a user's ID being its id read as text; users without one are not counted, and the value is unreported when the active user walk was refused. ${READS_AS_TEXT}`,
  security_tests_in_window: `Number of security tests that ran in the lookback window. ${TEST_START} ${LOOKBACK}`,
  sampled_test_count: `Number of sampled security tests whose recipient list was read without a refusal and whose start falls in the lookback window. ${RECIPIENT_SAMPLE} ${TEST_START} ${LOOKBACK}`,
  tested_user_count: `Number of distinct IDs, among those counted by active_user_count, that are the user.id, read as text, of a recipient of a sampled test counted by sampled_test_count. ${READS_AS_TEXT}`,
  recipient_reads_complete: "Recipient read coverage of the lookback window.",
  min_coverage_pct: `The ${percentOption("min_coverage_pct", 90)}.`,
  current_phish_prone_pct: `Weighted percentage over the security tests that ran in the lookback window; unreported when none of them has a percentage and a weight above 0. ${WEIGHTED} ${TEST_START} ${LOOKBACK}`,
  baseline_phish_prone_pct: `Weighted percentage over the first three security tests that ran, ${OLDEST_FIRST}, when at least four ran; unreported when fewer than four ran or none of those three has a percentage and a weight above 0. ${WEIGHTED} ${TEST_START}`,
  max_phish_prone_pct: `The ${percentOption("max_phish_prone_pct", 15)}.`,
  account_readable: "True when GET /v1/account returned the account record without a refusal.",
  trend_test_count: `Number of security tests that ran in the trend window and have a percentage. The trend window runs from 2N days before the assessment time to the assessment time, ${DAY} and N being the ${dayOption("lookback_days", 90)}. ${TEST_PERCENTAGE} ${TEST_START}`,
  phish_prone_delta_points: `Mean percentage of the later part minus mean percentage of the earlier part of the tests counted by trend_test_count, ${OLDEST_FIRST} and split after the first floor(n / 2) of the n tests, rounded half up to 2 decimal places; unreported when fewer than four such tests ran. ${TEST_PERCENTAGE} ${TEST_START}`,
  account_risk_score_history_readable: "True when the GET /v1/account/risk_score_history walk with full=true returned without a refusal.",
  phishing_campaigns_readable: "True when the GET /v1/phishing/campaigns walk returned without a refusal.",
  phishing_campaigns_complete: "Phishing campaign list coverage.",
  active_campaign_count: `Number of returned phishing campaigns that are active. ${ACTIVE_CAMPAIGN}`,
  full_targeting_campaign_count: `Number of active campaigns that target All Users. ${ALL_USERS} ${ACTIVE_CAMPAIGN}`,
  groups_readable: "True when the GET /v1/groups walk filtered to status=active returned without a refusal.",
  groups_complete: "Active group list coverage.",
  targeted_member_count: `Sum, over the distinct group IDs that active campaigns not targeting All Users target, of each ID's member count; unreported when the active group walk was refused. A campaign's targeted group IDs are the group_id values, read as text, of the JSON object entries of its groups array. An ID's member count is the member_count, ${AS_NUMBER}, of the last returned group whose id reads as that text and whose member_count reads as a number, else 0. ${ALL_USERS} ${ACTIVE_CAMPAIGN}`,
  require_full_targeting: "The require_full_targeting argument, true when it is absent.",
  delivered_count: `Sum of the delivered_count, ${AS_NUMBER} (0 when it does not read as one), of the security tests that ran in the lookback window. ${TEST_START} ${LOOKBACK}`,
  reported_count: `Sum of the reported_count, ${AS_NUMBER} (0 when it does not read as one), of the security tests that ran in the lookback window. ${TEST_START} ${LOOKBACK}`,
  min_report_rate_pct: `The ${percentOption("min_report_rate_pct", 50)}.`,
  report_rate_warn_floor_pct: `Half of the ${percentOption("min_report_rate_pct", 50)}, unrounded.`,
  phisher_messages_readable: "True when the PhishER GraphQL phisherMessages walk over the messages reported in the lookback window returned without a refusal; unreported when no PhishER API token is configured.",
  largest_schedule_gap_days: `Largest gap, in days rounded half up to 1 decimal place, between consecutive starts in the series formed by the newest security test that ran before the lookback window, when there is one, followed by the tests that ran in the lookback window oldest first, and between the start of the newest test that ran and the assessment time; unreported when no security test ran. ${TEST_START} ${LOOKBACK}`,
  max_schedule_gap_days: `The ${dayOption("max_schedule_gap_days", 45)}.`,
  training_campaigns_readable: "True when the GET /v1/training/campaigns walk returned without a refusal.",
  training_campaigns_complete: "Training campaign list coverage.",
  training_enrollments_readable: "True when the GET /v1/training/enrollments walk returned without a refusal.",
  training_enrollments_complete: "Training enrollment list coverage.",
  lowest_completion_pct: `Lowest completion, rounded half up to 1 decimal place, among the closed training campaigns that are not cancelled, are in the training lookback window, and have a completion, leaving out those counted by enrollment_cut_campaign_count; unreported when there is none. ${CAMPAIGN_COMPLETION} ${TRAINING_CAMPAIGN}`,
  enrollment_cut_campaign_count: `Number of closed training campaigns that are not cancelled and are in the training lookback window, whose completion_percentage does not read as a number at or above 0, and that have a loaded enrollment, when ${ENROLLMENTS_CUT}; 0 otherwise. ${CAMPAIGN_COMPLETION} ${TRAINING_CAMPAIGN}`,
  unmeasured_campaign_count: `Number of closed training campaigns that are not cancelled, are in the training lookback window, and have no completion. ${CAMPAIGN_COMPLETION} ${TRAINING_CAMPAIGN}`,
  min_completion_pct: `The ${percentOption("min_completion_pct", 90)}.`,
  fail_completion_pct: `The ${percentOption("fail_completion_pct", 80)}, lowered to min_completion_pct when above it.`,
  new_user_count: `Number of returned active users whose joined_on parses as a date from N days before the assessment time through G days before it, ${DAY}, N being the ${dayOption("training_lookback_days", 365)}, and G ${GRACE_DAYS}. ${PARSES_AS_DATE}`,
  late_user_count: `Number of the users counted by new_user_count whose id reads as text and who either have no enrollment with a date or have an earliest enrollment date more than G days after their joined_on, ${DAY} and G being ${GRACE_DAYS}. ${ENROLLMENT_DATE} ${PARSES_AS_DATE} ${READS_AS_TEXT}`,
  failed_user_count: `Number of failed users. ${FAILED_USERS}`,
  overdue_failed_user_count: `Number of failed users whose failure time is at least R days before the assessment time, ${DAY} and R being the ${dayOption("remedial_window_days", 14, 365)}. ${FAILED_USERS}`,
  remediated_user_count: `Number of the users counted by overdue_failed_user_count who have an enrollment whose date is no earlier than 1 day, 86400000 milliseconds, before their failure time. ${ENROLLMENT_DATE} ${FAILED_USERS}`,
  assigned_module_count: `Number of assigned store modules. ${STORE_MODULES}`,
  retired_module_count: `Number of assigned store modules that are retired. ${RETIRED_MODULE} ${STORE_MODULES}`,
  stale_module_count: `Number of assigned store modules that are not retired and whose publish date is more than N days before the assessment time, ${DAY} and N being the ${dayOption("max_content_age_days", 365)}. ${MODULE_PUBLISHED} ${RETIRED_MODULE} ${STORE_MODULES}`,
  undated_module_count: `Number of assigned store modules that are not retired and have no publish date. ${MODULE_PUBLISHED} ${RETIRED_MODULE} ${STORE_MODULES}`,
  store_purchases_complete: "Store purchase list coverage.",
  required_topic_count: `Number of required compliance topics. ${REQUIRED_TOPICS}`,
  topics_without_modules: `Number of compliance topics with no matching assigned module. ${COMPLIANCE_TOPICS}`,
  topics_without_enrollments: `Number of compliance topics with a matching assigned module but no loaded enrollment. ${TOPIC_COMPLETION} ${COMPLIANCE_TOPICS}`,
  lowest_topic_completion_pct: `Lowest completion among the compliance topics with a loaded enrollment; unreported when none has one. ${TOPIC_COMPLETION} ${COMPLIANCE_TOPICS}`,
  training_policies_readable: "True when the GET /v1/training/policies walk returned without a refusal.",
  mean_risk_score: `Arithmetic mean, unrounded, of the current_risk_score values, ${AS_NUMBER}, of the returned active users whose current_risk_score reads as one; unreported when none does.`,
  risk_score_stddev: "Population standard deviation, unrounded, of the values averaged by mean_risk_score: the square root of the mean of their squared differences from that mean; unreported when there is no such value.",
  max_mean_risk_score: `The ${percentOption("max_mean_risk_score", 50)}.`,
  max_risk_score_stddev: `The ${percentOption("max_risk_score_stddev", 25)}.`,
  active_group_count: `Number of returned active groups whose member_count, ${AS_NUMBER}, is above 0 or does not read as one.`,
  uncovered_group_count: `Number of the groups counted by active_group_count that are not covered both by the phishing campaigns in the lookback window and by the training campaigns that are not cancelled and are in the lookback window. ${GROUP_COVERED} ${ALL_USERS} ${PHISHING_CAMPAIGN_IN_WINDOW} ${trainingCampaign("lookback window", LOOKBACK)}`,
  long_standing_user_count: `Number of returned active users whose joined_on does not parse as a date, or parses as one at or before the start of the inactivity window. ${INACTIVITY_WINDOW} ${PARSES_AS_DATE}`,
  inactive_user_count: `Number of the users counted by long_standing_user_count whose last_sign_in does not parse as a date at or after the start of the inactivity window, and whose id, read as text, is missing or is not an active ID. ${ACTIVE_ID} ${RECIPIENT_SAMPLE} ${TEST_START} ${INACTIVITY_WINDOW} ${PARSES_AS_DATE} ${READS_AS_TEXT}`,
  recipient_walks_complete: "Recipient walk completeness.",
  activity_data_complete: "Activity signal coverage.",
  admin_count: "Number of the JSON object entries of the account record's admins array; 0 when admins is not an array.",
  max_admin_count: `The ${dayOption("max_admin_count", 3, 10000).replace("clamped to 1", "clamped to 0")}.`,
  external_admin_count: `Number of the admins counted by admin_count whose email reads as text containing an @ and whose email domain, the text after its last @ lowercased by ECMAScript toLowerCase, is not empty and is not an allowed domain; 0 when the account has no allowed domain. ${ACCOUNT_DOMAINS} ${READS_AS_TEXT}`,
  callback_security_tests_readable: "True when the GET /v1/phishing/security_tests walk filtered to campaign_type=callback returned without a refusal.",
  callback_security_tests_complete: "Callback security test list coverage.",
  require_vishing_tests: "The require_vishing_tests argument, true when it is absent.",
  callback_tests_in_window: `Number of returned callback security tests that ran in the lookback window. ${TEST_START} ${LOOKBACK}`,
};

const inputs = (...names: string[]): Readonly<Record<string, string>> => Object.fromEntries(names.map((name) => {
  const definition = KNOWBE4_INPUTS[name];
  if (!definition) throw new Error(`KnowBe4 decision input ${name} has no portable definition`);
  return [name, definition];
}));

const USER_LIMIT = `user_limit (the ${dayOption("user_limit", 5000, 200000)})`;
// Some checks read these lists without a manual gate, so a refused read must make them incomplete too.
const pageWalkComplete = (surfaceId: string, list: string, cap: string): BatchCompletenessDefinition => ({
  semantics: `false when the ${list} read was refused, or the list is partial because a page held more records than were left under ${cap}, a full page brought the records kept to ${cap}, or ${NOT_OBJECT_PAGE}.`,
  sources: [{ surfaceId, falseWhen: ["truncated", "error", "denied"] }],
});
const SECURITY_TESTS_COMPLETE = pageWalkComplete("security_tests", "security test list", "20000 records");
const USERS_COMPLETE = pageWalkComplete("users", "active user list", USER_LIMIT);
const GROUPS_COMPLETE = pageWalkComplete("groups", "active group list", "20000 records");
const PHISHING_CAMPAIGNS_COMPLETE = pageWalkComplete("phishing_campaigns", "phishing campaign list", "20000 records");
const TRAINING_CAMPAIGNS_COMPLETE = pageWalkComplete("training_campaigns", "training campaign list", "20000 records");
const TRAINING_ENROLLMENTS_COMPLETE = pageWalkComplete("training_enrollments", "training enrollment list", ENROLLMENT_LIMIT);
const STORE_PURCHASES_COMPLETE = pageWalkComplete("store_purchases", "store purchase list", "20000 records");
const CALLBACK_TESTS_COMPLETE = pageWalkComplete("callback_security_tests", "callback security test list", "20000 records");
const RECIPIENT_WALK = `a recipient walk was partial because a page held more recipients than were left under 20000, a full page brought the recipients kept to 20000, or ${NOT_OBJECT_PAGE}`;
const RECIPIENT_READS_COMPLETE: BatchCompletenessDefinition = {
  semantics: `false when the recipient reads do not cover every security test that ran in the lookback window: fewer sampled tests with a start in that window were read than ran in it (the sample holds at most security_test_sample_limit tests, and a sampled test whose pst_id does not read as text takes a place without being read), a recipient read was refused or never made, or ${RECIPIENT_WALK}. ${RECIPIENT_SAMPLE} ${TEST_START} ${LOOKBACK}`,
  sources: [{ surfaceId: "security_test_recipients", falseWhen: ["truncated", "error", "denied", "not-collected"] }],
};
const RECIPIENT_WALKS_COMPLETE: BatchCompletenessDefinition = {
  semantics: `false when a recipient read was refused, or ${RECIPIENT_WALK}; true when no recipient read was made.`,
  sources: [{ surfaceId: "security_test_recipients", falseWhen: ["truncated", "error", "denied"] }],
};
const ACTIVITY_DATA_COMPLETE: BatchCompletenessDefinition = {
  semantics: `false when an activity signal may be missing: a security test that ran in the sample window and has a pst_id that reads as text was left out of the recipient sample, a recipient read was refused or, the security test list being refused, never made, ${RECIPIENT_WALK}, or the security test or training enrollment list read was refused or is partial. ${RECIPIENT_SAMPLE} ${TEST_START} ${LOOKBACK}`,
  sources: [
    { surfaceId: "security_tests", falseWhen: ["truncated", "error", "denied"] },
    { surfaceId: "security_test_recipients", falseWhen: ["truncated", "error", "denied", "not-collected"] },
    { surfaceId: "training_enrollments", falseWhen: ["truncated", "error", "denied"] },
  ],
};

type Knowbe4Check = {
  id: string;
  control: number;
  title: string;
  severity: BatchCheckDefinition["severity"];
  owner: string;
  surfaces: readonly string[];
  inputs: readonly string[];
  constants?: Readonly<Record<string, PortableValue>>;
  rules: readonly VerdictRule[];
  completeness?: Readonly<Record<string, BatchCompletenessDefinition>>;
  decision: string;
  examples: readonly BatchCriterionExample[];
};

const example = (
  kind: BatchCriterionExample["kind"],
  expected: BatchCriterionExample["expected"],
  reason: string,
  facts: Readonly<Record<string, unknown>>,
): BatchCriterionExample => ({ kind, expected, reason, facts });

const PHISHING = "knowbe4_assess_phishing_program";
const TESTS_READ = { security_tests_readable: true, security_tests_complete: true };
const COVERAGE_HEALTHY = {
  ...TESTS_READ,
  users_readable: true,
  users_complete: true,
  security_tests_in_window: 3,
  user_record_count: 200,
  active_user_count: 200,
  sampled_test_count: 3,
  recipient_reads_complete: true,
  min_coverage_pct: 90,
};
const PHISH_PRONE_HEALTHY = { ...TESTS_READ, users_readable: true, account_readable: true, max_phish_prone_pct: 15, baseline_phish_prone_pct: 9.75 };
const TREND_HEALTHY = { ...TESTS_READ, account_risk_score_history_readable: true, trend_test_count: 6 };
const TARGETING_HEALTHY = {
  phishing_campaigns_readable: true,
  phishing_campaigns_complete: true,
  security_tests_complete: true,
  users_readable: true,
  users_complete: true,
  groups_readable: true,
  groups_complete: true,
  active_user_count: 500,
  min_coverage_pct: 90,
  require_full_targeting: true,
};
const PARTIAL_TARGETING = { ...TARGETING_HEALTHY, active_campaign_count: 3, full_targeting_campaign_count: 0 };
const REPORT_HEALTHY = { ...TESTS_READ, delivered_count: 1000, min_report_rate_pct: 50, report_rate_warn_floor_pct: 25, phisher_messages_readable: true };
const UNREADABLE_TESTS = example("unreadable", "manual", "The security test list was refused.", { security_tests_readable: false });

const PHISHING_CHECKS: readonly Knowbe4Check[] = [
  {
    id: "KNOWBE4-01",
    control: 1,
    title: "Phishing simulation frequency",
    severity: "high",
    owner: PHISHING,
    surfaces: ["security_tests"],
    inputs: ["security_tests_readable", "security_tests_complete", "days_since_latest_test", "max_campaign_gap_days"],
    rules: [
      rule("manual", ne("security_tests_readable", true)),
      rule("fail", unreported("days_since_latest_test")),
      rule("fail", gt("days_since_latest_test", path("max_campaign_gap_days"))),
      rule("warn", ne("security_tests_complete", true)),
      rule("pass", always),
    ],
    completeness: { security_tests_complete: SECURITY_TESTS_COMPLETE },
    decision: "Manual when the security test list is unreadable. Fail when no security test has run, or when more than max_campaign_gap_days days have passed since the newest one started. Warn instead of pass when the security test list is partial. Otherwise pass.",
    examples: [
      example("compliant", "pass", "The newest test started 12.5 days ago, within the 30-day maximum.", { ...TESTS_READ, days_since_latest_test: 12.5, max_campaign_gap_days: 30 }),
      example("noncompliant", "fail", "The newest test started 41 days ago.", { ...TESTS_READ, days_since_latest_test: 41, max_campaign_gap_days: 30 }),
      example("noncompliant", "fail", "No security test has ever run.", { ...TESTS_READ, max_campaign_gap_days: 30 }),
      example("partial", "warn", "The newest returned test is recent, but the list stopped at the 20000-record cap.", {
        security_tests_readable: true, security_tests_complete: false, days_since_latest_test: 3, max_campaign_gap_days: 30,
      }),
      UNREADABLE_TESTS,
    ],
  },
  {
    id: "KNOWBE4-02",
    control: 2,
    title: "Phishing simulation coverage",
    severity: "high",
    owner: PHISHING,
    surfaces: ["security_tests", "users", "security_test_recipients"],
    inputs: [
      "security_tests_readable",
      "users_readable",
      "security_tests_in_window",
      "user_record_count",
      "sampled_test_count",
      "users_complete",
      "recipient_reads_complete",
      "tested_user_count",
      "active_user_count",
      "min_coverage_pct",
      "security_tests_complete",
    ],
    rules: [
      rule("manual", ne("security_tests_readable", true)),
      rule("manual", ne("users_readable", true)),
      rule("warn", all(gt("security_tests_in_window", 0), eq("user_record_count", 0))),
      rule("fail", eq("security_tests_in_window", 0)),
      rule("warn", eq("sampled_test_count", 0)),
      rule("warn", incomplete("users_complete", "recipient_reads_complete")),
      rule("fail", not(percent("gte", "tested_user_count", "active_user_count", "min_coverage_pct"))),
      rule("warn", ne("security_tests_complete", true)),
      rule("pass", always),
    ],
    completeness: {
      users_complete: USERS_COMPLETE,
      recipient_reads_complete: RECIPIENT_READS_COMPLETE,
      security_tests_complete: SECURITY_TESTS_COMPLETE,
    },
    decision: "Manual when the security test list or the active user list is unreadable. Warn when tests ran in the lookback window but the active user list returned no user. Fail when no test ran in the lookback window. Warn when no recipient list of a test in the window was read, or when the active user list or the recipient reads are partial. Fail when the active users who appear as recipients of the sampled tests in the window are fewer than min_coverage_pct percent of active users, rounded half up to 1 decimal place. Warn instead of pass when the security test list is partial. Otherwise pass.",
    examples: [
      example("compliant", "pass", "190 of 200 active users received a sampled test in the window.", { ...COVERAGE_HEALTHY, tested_user_count: 190 }),
      example("noncompliant", "fail", "150 of 200 active users received a sampled test.", { ...COVERAGE_HEALTHY, tested_user_count: 150 }),
      example("noncompliant", "fail", "No security test ran in the lookback window.", {
        ...COVERAGE_HEALTHY, security_tests_in_window: 0, sampled_test_count: 0, tested_user_count: 0,
      }),
      example("partial", "warn", "13 tests ran in the window and only the 12 newest were sampled, so coverage is unknown.", {
        ...COVERAGE_HEALTHY, security_tests_in_window: 13, sampled_test_count: 12, recipient_reads_complete: false, tested_user_count: 150,
      }),
      example("partial", "warn", "Tests ran, but the active user list returned no user, as it does for an anonymized account.", {
        ...COVERAGE_HEALTHY, user_record_count: 0, active_user_count: 0, tested_user_count: 0,
      }),
      example("partial", "warn", "Every recipient read failed, so no test in the window was sampled.", {
        ...COVERAGE_HEALTHY, sampled_test_count: 0, recipient_reads_complete: false, tested_user_count: 0,
      }),
      UNREADABLE_TESTS,
      example("unreadable", "manual", "The active user list was refused.", { security_tests_readable: true, users_readable: false }),
    ],
  },
  {
    id: "KNOWBE4-06",
    control: 6,
    title: "Phish-prone percentage tracking",
    severity: "high",
    owner: PHISHING,
    surfaces: ["security_tests", "users", "account"],
    inputs: [
      "security_tests_readable",
      "security_tests_complete",
      "current_phish_prone_pct",
      "baseline_phish_prone_pct",
      "max_phish_prone_pct",
      "users_readable",
      "account_readable",
    ],
    rules: [
      rule("manual", ne("security_tests_readable", true)),
      rule("warn", unreported("current_phish_prone_pct")),
      rule("fail", gt("current_phish_prone_pct", path("max_phish_prone_pct"))),
      rule("warn", gt("current_phish_prone_pct", path("baseline_phish_prone_pct"))),
      rule("warn", any(ne("security_tests_complete", true), ne("users_readable", true), ne("account_readable", true))),
      rule("pass", always),
    ],
    completeness: { security_tests_complete: SECURITY_TESTS_COMPLETE },
    decision: "Manual when the security test list is unreadable. Warn when no security test that ran in the lookback window has a percentage and a weight above 0. Fail when the weighted phish-prone percentage of those tests is above max_phish_prone_pct. Warn when it is above the baseline, the weighted percentage of the three oldest tests that ran, which exists once at least four have run. Warn instead of pass when the security test list is partial or the active user list or the account record is unreadable. Otherwise pass.",
    examples: [
      example("compliant", "pass", "The window's weighted phish-prone percentage is 4.2, under the maximum and the 9.75 baseline.", {
        ...PHISH_PRONE_HEALTHY, current_phish_prone_pct: 4.2,
      }),
      example("noncompliant", "fail", "The window's weighted phish-prone percentage is 18.4.", { ...PHISH_PRONE_HEALTHY, current_phish_prone_pct: 18.4 }),
      example("partial", "warn", "The window's percentage, 11.5, is above the 9.75 baseline.", { ...PHISH_PRONE_HEALTHY, current_phish_prone_pct: 11.5 }),
      example("partial", "warn", "No test in the window carries a percentage and a delivered or scheduled count.", { ...PHISH_PRONE_HEALTHY }),
      example("partial", "warn", "The account record was refused.", { ...PHISH_PRONE_HEALTHY, current_phish_prone_pct: 4.2, account_readable: false }),
      UNREADABLE_TESTS,
    ],
  },
  {
    id: "KNOWBE4-07",
    control: 7,
    title: "Phishing failure rate trending",
    severity: "medium",
    owner: PHISHING,
    surfaces: ["security_tests", "account_risk_score_history"],
    inputs: [
      "security_tests_readable",
      "security_tests_complete",
      "trend_test_count",
      "phish_prone_delta_points",
      "account_risk_score_history_readable",
    ],
    constants: { min_trend_tests: 4, trend_fail_delta_points: 2, trend_warn_delta_points: 0.5 },
    rules: [
      rule("manual", ne("security_tests_readable", true)),
      rule("warn", lt("trend_test_count", path("min_trend_tests"))),
      rule("fail", gt("phish_prone_delta_points", path("trend_fail_delta_points"))),
      rule("warn", gt("phish_prone_delta_points", path("trend_warn_delta_points"))),
      rule("warn", any(ne("security_tests_complete", true), ne("account_risk_score_history_readable", true))),
      rule("pass", always),
    ],
    completeness: { security_tests_complete: SECURITY_TESTS_COMPLETE },
    decision: "Manual when the security test list is unreadable. Warn when fewer than 4 tests with a percentage ran in twice the lookback window. Fail when the later half's mean percentage exceeds the earlier half's by more than 2 points, and warn when it does by more than 0.5 points. Warn instead of pass when the security test list is partial or the organization risk score history is unreadable. Otherwise pass.",
    examples: [
      example("compliant", "pass", "The later half's mean percentage rose by exactly 0.5 points, which is not above the warning delta.", {
        ...TREND_HEALTHY, phish_prone_delta_points: 0.5,
      }),
      example("noncompliant", "fail", "The later half's mean percentage rose by 2.01 points.", { ...TREND_HEALTHY, phish_prone_delta_points: 2.01 }),
      example("partial", "warn", "The later half's mean percentage rose by 1.25 points.", { ...TREND_HEALTHY, phish_prone_delta_points: 1.25 }),
      example("partial", "warn", "Only 3 tests with a percentage ran in the trend window.", { ...TREND_HEALTHY, trend_test_count: 3 }),
      UNREADABLE_TESTS,
    ],
  },
  {
    id: "KNOWBE4-09",
    control: 9,
    title: "Campaign targeting completeness",
    severity: "medium",
    owner: PHISHING,
    surfaces: ["phishing_campaigns", "security_tests", "users", "groups"],
    inputs: [
      "phishing_campaigns_readable",
      "phishing_campaigns_complete",
      "active_campaign_count",
      "full_targeting_campaign_count",
      "users_readable",
      "groups_readable",
      "targeted_member_count",
      "active_user_count",
      "min_coverage_pct",
      "require_full_targeting",
      "security_tests_complete",
      "users_complete",
      "groups_complete",
    ],
    rules: [
      rule("manual", ne("phishing_campaigns_readable", true)),
      rule("manual", all(
        gt("active_campaign_count", 0),
        eq("full_targeting_campaign_count", 0),
        any(ne("users_readable", true), ne("groups_readable", true)),
      )),
      rule("fail", eq("active_campaign_count", 0)),
      rule("fail", all(
        eq("full_targeting_campaign_count", 0),
        not(percent("gte", "targeted_member_count", "active_user_count", "min_coverage_pct")),
        eq("require_full_targeting", true),
      )),
      rule("warn", incomplete("phishing_campaigns_complete", "security_tests_complete", "users_complete", "groups_complete")),
      rule("pass", always),
    ],
    completeness: {
      phishing_campaigns_complete: PHISHING_CAMPAIGNS_COMPLETE,
      security_tests_complete: SECURITY_TESTS_COMPLETE,
      users_complete: USERS_COMPLETE,
      groups_complete: GROUPS_COMPLETE,
    },
    decision: "Manual when the phishing campaign list is unreadable, or when no active campaign targets All Users and the active user list or the active group list is unreadable. Fail when no campaign is active. Fail when no active campaign targets All Users, require_full_targeting is true, and the member counts of the groups the active campaigns target add up to less than min_coverage_pct percent of active users, rounded half up to 1 decimal place. Warn instead of pass when the phishing campaign, security test, active user, or active group list is partial or unreadable. Otherwise pass.",
    examples: [
      example("compliant", "pass", "One of the two active campaigns targets All Users.", {
        ...TARGETING_HEALTHY, active_campaign_count: 2, full_targeting_campaign_count: 1, targeted_member_count: 0,
      }),
      example("compliant", "pass", "The targeted groups hold 460 members against 500 active users, 92 percent.", { ...PARTIAL_TARGETING, targeted_member_count: 460 }),
      example("noncompliant", "fail", "No phishing campaign is active.", { ...TARGETING_HEALTHY, active_campaign_count: 0, full_targeting_campaign_count: 0, targeted_member_count: 0 }),
      example("noncompliant", "fail", "The targeted groups hold 300 members against 500 active users, 60 percent.", { ...PARTIAL_TARGETING, targeted_member_count: 300 }),
      example("compliant", "pass", "Coverage is 60 percent, but require_full_targeting is false.", {
        ...PARTIAL_TARGETING, targeted_member_count: 300, require_full_targeting: false,
      }),
      example("partial", "warn", "A campaign targets All Users, but the group list stopped at the 20000-record cap.", {
        ...TARGETING_HEALTHY, active_campaign_count: 2, full_targeting_campaign_count: 1, targeted_member_count: 0, groups_complete: false,
      }),
      example("unreadable", "manual", "The phishing campaign list was refused.", { phishing_campaigns_readable: false }),
      example("unreadable", "manual", "No active campaign targets All Users and the group list was refused.", {
        ...PARTIAL_TARGETING, groups_readable: false, groups_complete: false,
      }),
    ],
  },
  {
    id: "KNOWBE4-19",
    control: 19,
    title: "Phishing report rate",
    severity: "medium",
    owner: PHISHING,
    surfaces: ["security_tests", "phisher_messages"],
    inputs: [
      "security_tests_readable",
      "security_tests_complete",
      "delivered_count",
      "reported_count",
      "min_report_rate_pct",
      "report_rate_warn_floor_pct",
      "phisher_messages_readable",
    ],
    rules: [
      rule("manual", ne("security_tests_readable", true)),
      rule("warn", eq("delivered_count", 0)),
      rule("fail", not(percent("gte", "reported_count", "delivered_count", "report_rate_warn_floor_pct"))),
      rule("warn", not(percent("gte", "reported_count", "delivered_count", "min_report_rate_pct"))),
      rule("warn", any(ne("security_tests_complete", true), eq("phisher_messages_readable", false))),
      rule("pass", always),
    ],
    completeness: { security_tests_complete: SECURITY_TESTS_COMPLETE },
    decision: "Manual when the security test list is unreadable. Warn when the tests that ran in the lookback window delivered no message. Fail when the reported share of delivered messages, rounded half up to 1 decimal place, is below half of min_report_rate_pct, and warn when it is below min_report_rate_pct. Warn instead of pass when the security test list is partial or the PhishER message read was refused. Otherwise pass.",
    examples: [
      example("compliant", "pass", "620 of 1000 delivered messages were reported, 62 percent.", { ...REPORT_HEALTHY, reported_count: 620 }),
      example("compliant", "pass", "The report rate meets the minimum and no PhishER API token is configured.", {
        ...TESTS_READ, delivered_count: 1000, reported_count: 620, min_report_rate_pct: 50, report_rate_warn_floor_pct: 25,
      }),
      example("noncompliant", "fail", "200 of 1000 delivered messages were reported, below half the minimum.", { ...REPORT_HEALTHY, reported_count: 200 }),
      example("partial", "warn", "400 of 1000 delivered messages were reported, below the minimum but above half of it.", { ...REPORT_HEALTHY, reported_count: 400 }),
      example("partial", "warn", "The tests in the window delivered no message.", { ...REPORT_HEALTHY, delivered_count: 0, reported_count: 0 }),
      example("partial", "warn", "The report rate meets the minimum, but the PhishER read was refused.", {
        ...REPORT_HEALTHY, reported_count: 620, phisher_messages_readable: false,
      }),
      UNREADABLE_TESTS,
    ],
  },
  {
    id: "KNOWBE4-20",
    control: 20,
    title: "Campaign scheduling regularity",
    severity: "medium",
    owner: PHISHING,
    surfaces: ["security_tests"],
    inputs: ["security_tests_readable", "security_tests_complete", "largest_schedule_gap_days", "max_schedule_gap_days"],
    rules: [
      rule("manual", ne("security_tests_readable", true)),
      rule("fail", unreported("largest_schedule_gap_days")),
      rule("fail", gt("largest_schedule_gap_days", path("max_schedule_gap_days"))),
      rule("warn", ne("security_tests_complete", true)),
      rule("pass", always),
    ],
    completeness: { security_tests_complete: SECURITY_TESTS_COMPLETE },
    decision: "Manual when the security test list is unreadable. Fail when no security test has run, or when a gap between consecutive test starts, counted from the newest test before the lookback window through the assessment time, is longer than max_schedule_gap_days days. Warn instead of pass when the security test list is partial. Otherwise pass.",
    examples: [
      example("compliant", "pass", "The largest gap, including the one since the newest test, is 31.5 days.", { ...TESTS_READ, largest_schedule_gap_days: 31.5, max_schedule_gap_days: 45 }),
      example("noncompliant", "fail", "A 52-day gap separates two tests.", { ...TESTS_READ, largest_schedule_gap_days: 52, max_schedule_gap_days: 45 }),
      example("noncompliant", "fail", "No security test has ever run.", { ...TESTS_READ, max_schedule_gap_days: 45 }),
      example("partial", "warn", "The returned tests are evenly spaced, but the list stopped at the 20000-record cap.", {
        security_tests_readable: true, security_tests_complete: false, largest_schedule_gap_days: 20, max_schedule_gap_days: 45,
      }),
      UNREADABLE_TESTS,
    ],
  },
];

const TRAINING = "knowbe4_assess_training_program";
const CAMPAIGNS_READ = { training_campaigns_readable: true, training_campaigns_complete: true };
const ENROLLMENTS_READ = { training_enrollments_readable: true, training_enrollments_complete: true };
const COMPLETION_HEALTHY = {
  ...CAMPAIGNS_READ,
  training_enrollments_readable: true,
  enrollment_cut_campaign_count: 0,
  unmeasured_campaign_count: 0,
  min_completion_pct: 90,
  fail_completion_pct: 80,
};
const TIMELINESS_HEALTHY = { users_readable: true, users_complete: true, ...ENROLLMENTS_READ, user_record_count: 500, new_user_count: 40 };
const REMEDIAL_HEALTHY = {
  ...TESTS_READ,
  ...ENROLLMENTS_READ,
  training_campaigns_readable: true,
  sampled_test_count: 3,
  recipient_reads_complete: true,
  failed_user_count: 20,
  overdue_failed_user_count: 20,
};
const CONTENT_HEALTHY = {
  ...CAMPAIGNS_READ,
  store_purchases_complete: true,
  assigned_module_count: 12,
  retired_module_count: 0,
  stale_module_count: 0,
  undated_module_count: 0,
};
const COMPLIANCE_READ = {
  ...CAMPAIGNS_READ,
  training_enrollments_complete: true,
  training_policies_readable: true,
  required_topic_count: 2,
  topics_without_modules: 0,
  topics_without_enrollments: 0,
  min_completion_pct: 90,
};
const COMPLIANCE_HEALTHY = { ...COMPLIANCE_READ, lowest_topic_completion_pct: 94.2 };
const UNREADABLE_CAMPAIGNS = example("unreadable", "manual", "The training campaign list was refused.", { training_campaigns_readable: false });

const TRAINING_CHECKS: readonly Knowbe4Check[] = [
  {
    id: "KNOWBE4-03",
    control: 3,
    title: "Training completion rates",
    severity: "high",
    owner: TRAINING,
    surfaces: ["training_campaigns", "training_enrollments"],
    inputs: [
      "training_campaigns_readable",
      "lowest_completion_pct",
      "fail_completion_pct",
      "min_completion_pct",
      "enrollment_cut_campaign_count",
      "unmeasured_campaign_count",
      "training_campaigns_complete",
      "training_enrollments_readable",
    ],
    rules: [
      rule("manual", ne("training_campaigns_readable", true)),
      rule("fail", lt("lowest_completion_pct", path("fail_completion_pct"))),
      rule("warn", lt("lowest_completion_pct", path("min_completion_pct"))),
      rule("warn", any(gt("enrollment_cut_campaign_count", 0), gt("unmeasured_campaign_count", 0), unreported("lowest_completion_pct"))),
      rule("warn", any(ne("training_campaigns_complete", true), ne("training_enrollments_readable", true))),
      rule("pass", always),
    ],
    completeness: { training_campaigns_complete: TRAINING_CAMPAIGNS_COMPLETE },
    decision: "Manual when the training campaign list is unreadable. Fail when a closed, uncancelled campaign in the training lookback window finished below fail_completion_pct percent completion, and warn when one finished below min_completion_pct percent. Warn when such a campaign's completion could only come from enrollments and the enrollment list is partial, when such a campaign has neither a completion_percentage of 0 or more nor a loaded enrollment, or when no such campaign has a completion. Warn instead of pass when the training campaign list is partial or the enrollment list is unreadable. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Every closed campaign in the window met the target; the lowest finished at 93.5 percent.", { ...COMPLETION_HEALTHY, lowest_completion_pct: 93.5 }),
      example("compliant", "pass", "The lowest closed campaign finished exactly at the 90 percent target.", { ...COMPLETION_HEALTHY, lowest_completion_pct: 90 }),
      example("noncompliant", "fail", "A closed campaign finished at 72.4 percent, below the 80 percent floor.", { ...COMPLETION_HEALTHY, lowest_completion_pct: 72.4 }),
      example("partial", "warn", "A closed campaign finished at 85 percent, between the floor and the target.", { ...COMPLETION_HEALTHY, lowest_completion_pct: 85 }),
      example("partial", "warn", "A closed campaign reports the -1 completion sentinel and the enrollment list stopped at enrollment_limit.", {
        ...COMPLETION_HEALTHY, lowest_completion_pct: 95, enrollment_cut_campaign_count: 1,
      }),
      example("partial", "warn", "A closed campaign reports the -1 completion sentinel and has no loaded enrollment.", {
        ...COMPLETION_HEALTHY, lowest_completion_pct: 95, unmeasured_campaign_count: 1,
      }),
      example("partial", "warn", "No closed campaign in the training lookback window has a completion.", { ...COMPLETION_HEALTHY }),
      example("partial", "warn", "Every closed campaign met the target, but the enrollment list was refused.", {
        ...COMPLETION_HEALTHY, lowest_completion_pct: 95, training_enrollments_readable: false,
      }),
      UNREADABLE_CAMPAIGNS,
    ],
  },
  {
    id: "KNOWBE4-04",
    control: 4,
    title: "Training enrollment timeliness",
    severity: "medium",
    owner: TRAINING,
    surfaces: ["users", "training_enrollments"],
    inputs: [
      "users_readable",
      "training_enrollments_readable",
      "user_record_count",
      "late_user_count",
      "new_user_count",
      "training_enrollments_complete",
      "users_complete",
    ],
    constants: { max_late_pct: 5 },
    rules: [
      rule("manual", ne("users_readable", true)),
      rule("manual", ne("training_enrollments_readable", true)),
      rule("warn", eq("user_record_count", 0)),
      rule("warn", all(gt("late_user_count", 0), ne("training_enrollments_complete", true))),
      rule("fail", percent("gt", "late_user_count", "new_user_count", "max_late_pct")),
      rule("warn", gt("late_user_count", 0)),
      rule("warn", incomplete("users_complete", "training_enrollments_complete")),
      rule("pass", always),
    ],
    completeness: { training_enrollments_complete: TRAINING_ENROLLMENTS_COMPLETE, users_complete: USERS_COMPLETE },
    decision: "Manual when the active user list or the training enrollment list is unreadable. Warn when the active user list returned no user. Among active users who joined between training_lookback_days and enrollment_grace_days days ago, a user is late without a training enrollment dated within enrollment_grace_days days of joining: warn when any is late but the enrollment list is partial, fail when the late users are more than 5 percent of those users, rounded half up to 1 decimal place, and warn when any is late. Warn instead of pass when the active user list or the enrollment list is partial. Otherwise pass.",
    examples: [
      example("compliant", "pass", "All 40 users who joined in the span were enrolled within the grace period.", { ...TIMELINESS_HEALTHY, late_user_count: 0 }),
      example("compliant", "pass", "Nobody joined in the span, so no enrollment deadline has passed.", { ...TIMELINESS_HEALTHY, new_user_count: 0, late_user_count: 0 }),
      example("noncompliant", "fail", "6 of the 40 users who joined in the span, 15 percent, were not enrolled in time.", { ...TIMELINESS_HEALTHY, late_user_count: 6 }),
      example("partial", "warn", "2 of the 40 users, exactly 5 percent, were not enrolled in time.", { ...TIMELINESS_HEALTHY, late_user_count: 2 }),
      example("partial", "warn", "6 of the 40 users have no enrollment among those read, but the enrollment list stopped at enrollment_limit.", {
        ...TIMELINESS_HEALTHY, late_user_count: 6, training_enrollments_complete: false,
      }),
      example("partial", "warn", "The active user list returned no user, as it does for an anonymized account.", {
        ...TIMELINESS_HEALTHY, user_record_count: 0, new_user_count: 0, late_user_count: 0,
      }),
      example("partial", "warn", "Every user read was enrolled in time, but the active user list stopped at user_limit.", {
        ...TIMELINESS_HEALTHY, late_user_count: 0, users_complete: false,
      }),
      example("unreadable", "manual", "The active user list was refused.", { users_readable: false }),
      example("unreadable", "manual", "The training enrollment list was refused.", { users_readable: true, training_enrollments_readable: false }),
    ],
  },
  {
    id: "KNOWBE4-10",
    control: 10,
    title: "Remedial training triggers",
    severity: "medium",
    owner: TRAINING,
    surfaces: ["security_tests", "security_test_recipients", "training_enrollments", "training_campaigns"],
    inputs: [
      "security_tests_readable",
      "training_enrollments_readable",
      "sampled_test_count",
      "overdue_failed_user_count",
      "failed_user_count",
      "remediated_user_count",
      "training_enrollments_complete",
      "recipient_reads_complete",
      "security_tests_complete",
      "training_campaigns_readable",
    ],
    constants: { remediated_floor_pct: 50, remediated_target_pct: 90 },
    rules: [
      rule("manual", ne("security_tests_readable", true)),
      rule("manual", ne("training_enrollments_readable", true)),
      rule("warn", eq("sampled_test_count", 0)),
      rule("warn", all(eq("overdue_failed_user_count", 0), gt("failed_user_count", 0))),
      rule("warn", all(lt("remediated_user_count", path("overdue_failed_user_count")), ne("training_enrollments_complete", true))),
      rule("fail", percent("lt", "remediated_user_count", "overdue_failed_user_count", "remediated_floor_pct")),
      rule("warn", percent("lt", "remediated_user_count", "overdue_failed_user_count", "remediated_target_pct")),
      rule("warn", any(
        ne("recipient_reads_complete", true),
        ne("security_tests_complete", true),
        ne("training_enrollments_complete", true),
        ne("training_campaigns_readable", true),
      )),
      rule("pass", always),
    ],
    completeness: {
      training_enrollments_complete: TRAINING_ENROLLMENTS_COMPLETE,
      recipient_reads_complete: RECIPIENT_READS_COMPLETE,
      security_tests_complete: SECURITY_TESTS_COMPLETE,
    },
    decision: "Manual when the security test list or the training enrollment list is unreadable. Warn when no recipient list of a test in the lookback window was read, or when users failed a sampled test but none failed at least remedial_window_days days ago. Among users who did, a user is remediated by a training enrollment dated no earlier than 1 day before the failure: warn when any is not remediated but the enrollment list is partial, fail when fewer than 50 percent are remediated, and warn when fewer than 90 percent are, each rounded half up to 1 decimal place. Warn instead of pass when the recipient reads, the security test list, or the enrollment list are partial, or the training campaign list is unreadable. Otherwise pass.",
    examples: [
      example("compliant", "pass", "19 of the 20 users who failed at least 14 days ago, 95 percent, were enrolled after the failure.", { ...REMEDIAL_HEALTHY, remediated_user_count: 19 }),
      example("compliant", "pass", "No user failed a sampled test in the window.", {
        ...REMEDIAL_HEALTHY, failed_user_count: 0, overdue_failed_user_count: 0, remediated_user_count: 0,
      }),
      example("noncompliant", "fail", "8 of the 20 users, 40 percent, were enrolled after the failure.", { ...REMEDIAL_HEALTHY, remediated_user_count: 8 }),
      example("partial", "warn", "Exactly half of the 20 users were enrolled after the failure.", { ...REMEDIAL_HEALTHY, remediated_user_count: 10 }),
      example("partial", "warn", "14 of the 20 users, 70 percent, were enrolled after the failure.", { ...REMEDIAL_HEALTHY, remediated_user_count: 14 }),
      example("partial", "warn", "12 of the 20 users have no enrollment among those read, but the enrollment list stopped at enrollment_limit.", {
        ...REMEDIAL_HEALTHY, remediated_user_count: 8, training_enrollments_complete: false,
      }),
      example("partial", "warn", "5 users failed within the last 14 days, so their remedial window is still open.", {
        ...REMEDIAL_HEALTHY, failed_user_count: 5, overdue_failed_user_count: 0, remediated_user_count: 0,
      }),
      example("partial", "warn", "No recipient list of a test in the window was read.", {
        ...REMEDIAL_HEALTHY, sampled_test_count: 0, recipient_reads_complete: false, failed_user_count: 0, overdue_failed_user_count: 0, remediated_user_count: 0,
      }),
      example("partial", "warn", "19 of the 20 users were remediated, but tests in the window went unsampled.", {
        ...REMEDIAL_HEALTHY, remediated_user_count: 19, recipient_reads_complete: false,
      }),
      example("unreadable", "manual", "The security test list was refused.", { security_tests_readable: false }),
      example("unreadable", "manual", "The training enrollment list was refused.", { security_tests_readable: true, training_enrollments_readable: false }),
    ],
  },
  {
    id: "KNOWBE4-11",
    control: 11,
    title: "Training content currency",
    severity: "low",
    owner: TRAINING,
    surfaces: ["training_campaigns", "store_purchases"],
    inputs: [
      "training_campaigns_readable",
      "assigned_module_count",
      "retired_module_count",
      "stale_module_count",
      "undated_module_count",
      "training_campaigns_complete",
      "store_purchases_complete",
    ],
    rules: [
      rule("manual", ne("training_campaigns_readable", true)),
      rule("warn", eq("assigned_module_count", 0)),
      rule("fail", gt("retired_module_count", 0)),
      rule("warn", any(gt("stale_module_count", 0), gt("undated_module_count", 0))),
      rule("warn", incomplete("training_campaigns_complete", "store_purchases_complete")),
      rule("pass", always),
    ],
    completeness: { training_campaigns_complete: TRAINING_CAMPAIGNS_COMPLETE, store_purchases_complete: STORE_PURCHASES_COMPLETE },
    decision: "Manual when the training campaign list is unreadable. Warn when no store-purchased module is assigned in an uncancelled campaign in the training lookback window. Fail when an assigned module is retired. Warn when an assigned module was published more than max_content_age_days days ago or has no publish date. Warn instead of pass when the training campaign list or the store purchase list is partial or unreadable. Otherwise pass.",
    examples: [
      example("compliant", "pass", "All 12 assigned modules are current and none is retired.", { ...CONTENT_HEALTHY }),
      example("noncompliant", "fail", "An assigned module is retired by its publisher.", { ...CONTENT_HEALTHY, retired_module_count: 1 }),
      example("partial", "warn", "Two assigned modules were published more than 365 days ago.", { ...CONTENT_HEALTHY, stale_module_count: 2 }),
      example("partial", "warn", "An assigned module has no publish date in the campaign or the store catalog.", { ...CONTENT_HEALTHY, undated_module_count: 1 }),
      example("partial", "warn", "No store-purchased module is assigned in the window.", { ...CONTENT_HEALTHY, assigned_module_count: 0 }),
      example("partial", "warn", "The modules are current, but the store purchase list was refused, so retirement was not cross-checked.", {
        ...CONTENT_HEALTHY, store_purchases_complete: false,
      }),
      UNREADABLE_CAMPAIGNS,
    ],
  },
  {
    id: "KNOWBE4-17",
    control: 17,
    title: "Compliance training modules",
    severity: "medium",
    owner: TRAINING,
    surfaces: ["training_campaigns", "training_enrollments", "training_policies"],
    inputs: [
      "training_campaigns_readable",
      "topics_without_modules",
      "required_topic_count",
      "topics_without_enrollments",
      "training_enrollments_complete",
      "lowest_topic_completion_pct",
      "min_completion_pct",
      "training_campaigns_complete",
      "training_policies_readable",
    ],
    rules: [
      rule("manual", ne("training_campaigns_readable", true)),
      rule("fail", all(gt("topics_without_modules", 0), gt("required_topic_count", 0))),
      rule("warn", gt("topics_without_modules", 0)),
      rule("fail", all(gt("topics_without_enrollments", 0), gt("required_topic_count", 0), eq("training_enrollments_complete", true))),
      rule("warn", gt("topics_without_enrollments", 0)),
      rule("warn", lt("lowest_topic_completion_pct", path("min_completion_pct"))),
      rule("warn", any(ne("training_enrollments_complete", true), ne("training_campaigns_complete", true), ne("training_policies_readable", true))),
      rule("pass", always),
    ],
    completeness: { training_enrollments_complete: TRAINING_ENROLLMENTS_COMPLETE, training_campaigns_complete: TRAINING_CAMPAIGNS_COMPLETE },
    decision: "Manual when the training campaign list is unreadable. Fail when a required compliance topic matches no module assigned in an uncancelled campaign in the training lookback window, and warn when no topic is required and no assigned module matches the built-in compliance pattern. Fail when a required topic's modules have no enrollment in a complete enrollment list, and warn when any topic's modules have no loaded enrollment. Warn when a topic's completion is below min_completion_pct percent. Warn instead of pass when the training enrollment or campaign list is partial or unreadable, or the training policy list is unreadable. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Both required topics have assigned modules with completion of at least 94.2 percent.", { ...COMPLIANCE_HEALTHY }),
      example("compliant", "pass", "No topic is required, and modules matching the built-in pattern are 96 percent complete.", {
        ...COMPLIANCE_HEALTHY, required_topic_count: 0, lowest_topic_completion_pct: 96,
      }),
      example("noncompliant", "fail", "A required topic matches no assigned module.", { ...COMPLIANCE_HEALTHY, topics_without_modules: 1 }),
      example("partial", "warn", "No topic is required and no assigned module matches the built-in pattern.", {
        ...COMPLIANCE_READ, required_topic_count: 0, topics_without_modules: 1,
      }),
      example("noncompliant", "fail", "A required topic's modules have no enrollment in the complete enrollment list.", { ...COMPLIANCE_HEALTHY, topics_without_enrollments: 1 }),
      example("partial", "warn", "A required topic's modules have no loaded enrollment, but the enrollment list stopped at enrollment_limit.", {
        ...COMPLIANCE_HEALTHY, topics_without_enrollments: 1, training_enrollments_complete: false,
      }),
      example("partial", "warn", "A topic's modules are 85 percent complete.", { ...COMPLIANCE_HEALTHY, lowest_topic_completion_pct: 85 }),
      example("partial", "warn", "The modules are complete, but the training policy list was refused.", { ...COMPLIANCE_HEALTHY, training_policies_readable: false }),
      UNREADABLE_CAMPAIGNS,
    ],
  },
];

const RISK = "knowbe4_assess_user_risk";
const ACTIVE_USERS_READ = { users_readable: true, users_complete: true, user_record_count: 400 };
const RISK_SCORES_HEALTHY = {
  ...ACTIVE_USERS_READ,
  account_readable: true,
  account_risk_score_history_readable: true,
  mean_risk_score: 31.4,
  risk_score_stddev: 12.8,
  max_mean_risk_score: 50,
  max_risk_score_stddev: 25,
};
const GROUP_COVERAGE_HEALTHY = {
  groups_readable: true,
  groups_complete: true,
  phishing_campaigns_readable: true,
  phishing_campaigns_complete: true,
  ...CAMPAIGNS_READ,
  active_group_count: 14,
  uncovered_group_count: 0,
};
const INACTIVITY_HEALTHY = {
  ...ACTIVE_USERS_READ,
  security_tests_complete: true,
  recipient_walks_complete: true,
  training_enrollments_complete: true,
  activity_data_complete: true,
  long_standing_user_count: 360,
  inactive_user_count: 0,
};
const UNREADABLE_USERS = example("unreadable", "manual", "The active user list was refused.", { users_readable: false });
const EMPTY_USERS = example("partial", "warn", "The active user list came back empty.", { users_readable: true, users_complete: true, user_record_count: 0 });

const RISK_CHECKS: readonly Knowbe4Check[] = [
  {
    id: "KNOWBE4-05",
    control: 5,
    title: "User risk score distribution",
    severity: "medium",
    owner: RISK,
    surfaces: ["users", "account", "account_risk_score_history"],
    inputs: [
      "users_readable",
      "user_record_count",
      "mean_risk_score",
      "max_mean_risk_score",
      "risk_score_stddev",
      "max_risk_score_stddev",
      "users_complete",
      "account_readable",
      "account_risk_score_history_readable",
    ],
    rules: [
      rule("manual", ne("users_readable", true)),
      rule("warn", eq("user_record_count", 0)),
      rule("warn", unreported("mean_risk_score")),
      rule("fail", gt("mean_risk_score", path("max_mean_risk_score"))),
      rule("warn", gt("risk_score_stddev", path("max_risk_score_stddev"))),
      rule("warn", any(ne("users_complete", true), ne("account_readable", true), ne("account_risk_score_history_readable", true))),
      rule("pass", always),
    ],
    completeness: { users_complete: USERS_COMPLETE },
    decision: "Manual when the active user list is unreadable. Warn when it is empty or no returned user has a current_risk_score that reads as a number. Fail when the mean score of the users read is above max_mean_risk_score, and warn when their population standard deviation is above max_risk_score_stddev. Warn instead of pass when the active user list is partial, or the account record or the account risk score history is unreadable. Otherwise pass.",
    examples: [
      example("compliant", "pass", "The mean risk score is 31.4 with a standard deviation of 12.8.", { ...RISK_SCORES_HEALTHY }),
      example("compliant", "pass", "The mean and the deviation sit exactly at their ceilings of 50 and 25.", { ...RISK_SCORES_HEALTHY, mean_risk_score: 50, risk_score_stddev: 25 }),
      example("noncompliant", "fail", "The mean risk score of 57.2 is above the 50 ceiling.", { ...RISK_SCORES_HEALTHY, mean_risk_score: 57.2 }),
      example("noncompliant", "fail", "The users read average 57.2, above the ceiling, though the active user list stopped at user_limit.", {
        ...RISK_SCORES_HEALTHY, mean_risk_score: 57.2, users_complete: false,
      }),
      example("partial", "warn", "The mean is under the ceiling, but the standard deviation of 31.6 exceeds 25.", { ...RISK_SCORES_HEALTHY, risk_score_stddev: 31.6 }),
      example("partial", "warn", "No returned user has a current_risk_score that reads as a number.", {
        ...ACTIVE_USERS_READ, account_readable: true, account_risk_score_history_readable: true, max_mean_risk_score: 50, max_risk_score_stddev: 25,
      }),
      example("partial", "warn", "The scores are within policy, but the active user list stopped at user_limit.", { ...RISK_SCORES_HEALTHY, users_complete: false }),
      example("partial", "warn", "The scores are within policy, but the account risk score history was refused.", {
        ...RISK_SCORES_HEALTHY, account_risk_score_history_readable: false,
      }),
      EMPTY_USERS,
      UNREADABLE_USERS,
    ],
  },
  {
    id: "KNOWBE4-08",
    control: 8,
    title: "Group coverage analysis",
    severity: "medium",
    owner: RISK,
    surfaces: ["groups", "phishing_campaigns", "training_campaigns"],
    inputs: [
      "groups_readable",
      "phishing_campaigns_readable",
      "training_campaigns_readable",
      "active_group_count",
      "uncovered_group_count",
      "groups_complete",
      "phishing_campaigns_complete",
      "training_campaigns_complete",
    ],
    rules: [
      rule("manual", ne("groups_readable", true)),
      rule("manual", ne("phishing_campaigns_readable", true)),
      rule("manual", ne("training_campaigns_readable", true)),
      rule("warn", eq("active_group_count", 0)),
      rule("warn", all(gt("uncovered_group_count", 0), incomplete("phishing_campaigns_complete", "training_campaigns_complete"))),
      rule("fail", gt("uncovered_group_count", 0)),
      rule("warn", incomplete("groups_complete", "phishing_campaigns_complete", "training_campaigns_complete")),
      rule("pass", always),
    ],
    completeness: {
      groups_complete: GROUPS_COMPLETE,
      phishing_campaigns_complete: PHISHING_CAMPAIGNS_COMPLETE,
      training_campaigns_complete: TRAINING_CAMPAIGNS_COMPLETE,
    },
    decision: "Manual when the active group, phishing campaign, or training campaign list is unreadable. Warn when no returned active group has members. Fail when a group with members is not covered both by a phishing campaign and by an uncancelled training campaign in the lookback window, through an All Users target or its group ID, and warn instead when the phishing or training campaign list is partial. Warn instead of pass when any of the three lists is partial. Otherwise pass.",
    examples: [
      example("compliant", "pass", "All 14 active groups with members are covered by phishing and training campaigns in the lookback window.", { ...GROUP_COVERAGE_HEALTHY }),
      example("noncompliant", "fail", "3 groups lack a phishing or a training campaign in the lookback window.", { ...GROUP_COVERAGE_HEALTHY, uncovered_group_count: 3 }),
      example("noncompliant", "fail", "3 groups are uncovered by complete campaign lists, though the group list stopped at 20000 records.", {
        ...GROUP_COVERAGE_HEALTHY, uncovered_group_count: 3, groups_complete: false,
      }),
      example("partial", "warn", "3 groups look uncovered, but the phishing campaign list stopped at 20000 records.", {
        ...GROUP_COVERAGE_HEALTHY, uncovered_group_count: 3, phishing_campaigns_complete: false,
      }),
      example("partial", "warn", "No returned active group has members.", { ...GROUP_COVERAGE_HEALTHY, active_group_count: 0 }),
      example("partial", "warn", "Every group read is covered, but the group list stopped at 20000 records.", { ...GROUP_COVERAGE_HEALTHY, groups_complete: false }),
      example("unreadable", "manual", "The active group list was refused.", { groups_readable: false }),
      example("unreadable", "manual", "The phishing campaign list was refused.", { groups_readable: true, phishing_campaigns_readable: false }),
      example("unreadable", "manual", "The training campaign list was refused.", { groups_readable: true, phishing_campaigns_readable: true, training_campaigns_readable: false }),
    ],
  },
  {
    id: "KNOWBE4-18",
    control: 18,
    title: "Inactive user cleanup",
    severity: "medium",
    owner: RISK,
    surfaces: ["users", "security_tests", "security_test_recipients", "training_enrollments"],
    inputs: [
      "users_readable",
      "user_record_count",
      "long_standing_user_count",
      "inactive_user_count",
      "activity_data_complete",
      "users_complete",
      "security_tests_complete",
      "recipient_walks_complete",
      "training_enrollments_complete",
    ],
    constants: { max_inactive_pct: 5 },
    rules: [
      rule("manual", ne("users_readable", true)),
      rule("warn", eq("user_record_count", 0)),
      rule("warn", all(gt("inactive_user_count", 0), ne("activity_data_complete", true))),
      rule("fail", percent("gt", "inactive_user_count", "long_standing_user_count", "max_inactive_pct")),
      rule("warn", gt("inactive_user_count", 0)),
      rule("warn", incomplete("users_complete", "security_tests_complete", "recipient_walks_complete", "training_enrollments_complete")),
      rule("pass", always),
    ],
    completeness: {
      activity_data_complete: ACTIVITY_DATA_COMPLETE,
      users_complete: USERS_COMPLETE,
      security_tests_complete: SECURITY_TESTS_COMPLETE,
      recipient_walks_complete: RECIPIENT_WALKS_COMPLETE,
      training_enrollments_complete: TRAINING_ENROLLMENTS_COMPLETE,
    },
    decision: "Manual when the active user list is unreadable. Warn when it is empty. A long-standing user, one whose joined_on is missing or at or before the start of the inactivity window, is inactive when they have not signed in since that start, received no delivered phishing test that ran in the window among the sampled tests, and have no training enrollment activity since that start. When any is inactive, warn when an activity source is incomplete; otherwise fail when more than 5 percent of long-standing users are inactive, and warn at 5 percent or less. Warn instead of pass when the active user, security test, recipient, or training enrollment read is partial or refused. Otherwise pass.",
    examples: [
      example("compliant", "pass", "All 360 long-standing users show sign-in, phishing, or training activity in the inactivity window.", { ...INACTIVITY_HEALTHY }),
      example("compliant", "pass", "Every active user joined within the inactivity window.", { ...INACTIVITY_HEALTHY, long_standing_user_count: 0 }),
      example("compliant", "pass", "No long-standing user lacks activity, and the tests left out of the sample could only have added more.", {
        ...INACTIVITY_HEALTHY, activity_data_complete: false,
      }),
      example("noncompliant", "fail", "27 of 360 long-standing users (7.5 percent) show no activity.", { ...INACTIVITY_HEALTHY, inactive_user_count: 27 }),
      example("noncompliant", "fail", "27 of the 360 long-standing users read show no activity, though the active user list stopped at user_limit.", {
        ...INACTIVITY_HEALTHY, inactive_user_count: 27, users_complete: false,
      }),
      example("partial", "warn", "18 of 360 long-standing users (5 percent) show no activity, within the 5 percent tolerance.", { ...INACTIVITY_HEALTHY, inactive_user_count: 18 }),
      example("partial", "warn", "27 users show no loaded activity, but tests in the sample window were left out of the sample.", {
        ...INACTIVITY_HEALTHY, inactive_user_count: 27, activity_data_complete: false,
      }),
      example("partial", "warn", "No user is inactive, but a recipient read was refused.", {
        ...INACTIVITY_HEALTHY, recipient_walks_complete: false, activity_data_complete: false,
      }),
      example("partial", "warn", "No user is inactive, but the training enrollment list stopped at enrollment_limit.", {
        ...INACTIVITY_HEALTHY, training_enrollments_complete: false, activity_data_complete: false,
      }),
      example("partial", "warn", "No user is inactive, but the active user list stopped at user_limit.", { ...INACTIVITY_HEALTHY, users_complete: false }),
      EMPTY_USERS,
      UNREADABLE_USERS,
    ],
  },
];

const GOVERNANCE = "knowbe4_assess_account_governance";
const ADMINS_HEALTHY = { account_readable: true, admin_count: 3, max_admin_count: 3, external_admin_count: 0 };
const VISHING_HEALTHY = {
  require_vishing_tests: true,
  callback_security_tests_readable: true,
  callback_security_tests_complete: true,
  callback_tests_in_window: 2,
};

const GOVERNANCE_CHECKS: readonly Knowbe4Check[] = [
  {
    id: "KNOWBE4-12",
    control: 12,
    title: "Admin role audit",
    severity: "high",
    owner: GOVERNANCE,
    surfaces: ["account"],
    inputs: ["account_readable", "admin_count", "max_admin_count", "external_admin_count"],
    rules: [
      rule("manual", ne("account_readable", true)),
      rule("warn", eq("admin_count", 0)),
      rule("fail", gt("admin_count", path("max_admin_count"))),
      rule("warn", gt("external_admin_count", 0)),
      rule("pass", always),
    ],
    decision: "Manual when the account record is unreadable. Warn when it lists no admin, since console administrator membership cannot then be enumerated. Fail when it lists more admins than max_admin_count. Warn when an admin's email domain is outside the account's allowed domains. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Three admins, all on allowed domains, meet the maximum of 3.", { ...ADMINS_HEALTHY }),
      example("noncompliant", "fail", "Five admins exceed the maximum of 3.", { ...ADMINS_HEALTHY, admin_count: 5 }),
      example("noncompliant", "fail", "Five admins exceed the maximum of 3, one of them on an outside domain.", { ...ADMINS_HEALTHY, admin_count: 5, external_admin_count: 1 }),
      example("partial", "warn", "Two admins are within the maximum, but one uses an outside email domain.", { ...ADMINS_HEALTHY, admin_count: 2, external_admin_count: 1 }),
      example("partial", "warn", "The account record lists no admin.", { ...ADMINS_HEALTHY, admin_count: 0 }),
      example("unreadable", "manual", "The account record was refused.", { account_readable: false }),
    ],
  },
  {
    id: "KNOWBE4-13",
    control: 13,
    title: "SSO integration status",
    severity: "high",
    owner: GOVERNANCE,
    surfaces: ["account"],
    inputs: [],
    rules: [rule("manual", always)],
    decision: "Always return manual, because the Reporting API does not expose SAML SSO or admin MFA settings, so a reviewer must verify SSO enforcement in the console.",
    examples: [example("partial", "manual", "SSO enforcement is left to a reviewer whatever the account record holds.", {})],
  },
  {
    id: "KNOWBE4-14",
    control: 14,
    title: "Reporting frequency",
    severity: "medium",
    owner: GOVERNANCE,
    surfaces: ["security_tests", "training_campaigns"],
    inputs: [],
    rules: [rule("manual", always)],
    decision: "Always return manual, because the Reporting API keeps no log of generated or reviewed reports, so a reviewer must evidence report cadence from console report schedules and review records.",
    examples: [example("partial", "manual", "Report cadence is left to a reviewer whatever the security test and training campaign lists hold.", {})],
  },
  {
    id: "KNOWBE4-15",
    control: 15,
    title: "USB test campaign execution",
    severity: "low",
    owner: GOVERNANCE,
    surfaces: [],
    inputs: [],
    rules: [rule("manual", always)],
    decision: "Always return manual, because the Reporting API does not expose USB drive tests, so a reviewer needs the console's USB drive test list, or the recorded decision scoping physical media testing out when require_usb_tests is false.",
    examples: [example("partial", "manual", "USB drive testing is left to a reviewer whatever require_usb_tests holds.", {})],
  },
  {
    id: "KNOWBE4-16",
    control: 16,
    title: "Vishing campaign execution",
    severity: "low",
    owner: GOVERNANCE,
    surfaces: ["callback_security_tests"],
    inputs: ["require_vishing_tests", "callback_security_tests_readable", "callback_security_tests_complete", "callback_tests_in_window"],
    rules: [
      rule("manual", ne("require_vishing_tests", true)),
      rule("manual", ne("callback_security_tests_readable", true)),
      rule("fail", all(eq("callback_tests_in_window", 0), eq("callback_security_tests_complete", true))),
      rule("warn", eq("callback_tests_in_window", 0)),
      rule("warn", incomplete("callback_security_tests_complete")),
      rule("pass", always),
    ],
    completeness: { callback_security_tests_complete: CALLBACK_TESTS_COMPLETE },
    decision: "Manual when require_vishing_tests is false, which scopes voice-channel testing out, or when the callback security test list is unreadable. Fail when no callback test ran in the lookback window and the list is complete, and warn when none did but the list is partial. Warn instead of pass when the list is partial. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Two callback tests ran in the lookback window.", { ...VISHING_HEALTHY }),
      example("noncompliant", "fail", "No callback test ran in the lookback window, and the list is complete.", { ...VISHING_HEALTHY, callback_tests_in_window: 0 }),
      example("partial", "warn", "No loaded callback test ran in the lookback window, but the list stopped at 20000 records.", {
        ...VISHING_HEALTHY, callback_tests_in_window: 0, callback_security_tests_complete: false,
      }),
      example("partial", "warn", "Two callback tests ran in the lookback window, though the list stopped at 20000 records.", {
        ...VISHING_HEALTHY, callback_security_tests_complete: false,
      }),
      example("partial", "manual", "Voice-channel testing was scoped out with require_vishing_tests false.", {
        ...VISHING_HEALTHY, require_vishing_tests: false, callback_tests_in_window: 0,
      }),
      example("unreadable", "manual", "The callback security test list was refused.", { require_vishing_tests: true, callback_security_tests_readable: false }),
    ],
  },
];

const toCheck = (check: Knowbe4Check): BatchCheckDefinition => {
  const executable = deriveDecisionRules(check.id, check.rules);
  const [fedramp, cmmc, soc2, cis, pciDss, disaStig, irap, ismap] = KNOWBE4_FRAMEWORK_MAPPINGS[check.control];
  return {
    id: check.id,
    control: check.control,
    title: check.title,
    severity: check.severity,
    owner: check.owner,
    surfaces: check.surfaces,
    frameworks: {
      fedramp: [fedramp],
      cmmc: [cmmc],
      soc2: [soc2],
      cis: [cis],
      pci_dss: [pciDss],
      disa_stig: [disaStig],
      irap: [irap],
      ismap: [ismap],
    },
    evidenceFields: check.inputs,
    decisionInputs: inputs(...check.inputs),
    decisionConstants: check.constants ?? {},
    decisionRules: executable.rules,
    derivedFactRules: executable.derivedFactRules,
    ...(check.completeness ? { completeness: check.completeness } : {}),
    decision: check.decision,
    examples: check.examples,
  };
};

const checks: readonly BatchCheckDefinition[] = [...PHISHING_CHECKS, ...TRAINING_CHECKS, ...RISK_CHECKS, ...GOVERNANCE_CHECKS].map(toCheck);
const idsFor = (owner: string): string[] => checks.filter((check) => check.owner === owner).map((check) => check.id);

const NOT_OBJECTS = "An entry that is not a JSON object is dropped, and the page holding it ends the walk with the list partial.";
const pageWalk = (
  surfaceIds: readonly string[],
  records: string,
  cap: string,
  itemCap: number | null,
  probed: boolean,
  scope = "",
  pageSize = 500,
): BatchPaginationDefinition => ({
  surfaceIds,
  cursorFields: ["page"],
  pageSize: probed ? null : pageSize,
  itemCap,
  pageCap: null,
  totalSemantics: `${scope}Pages of ${pageSize} ${records} (per_page), numbered from 1 (page)${probed ? "; the knowbe4_check_access probe reads only page 1 with per_page 1" : ""}. ${NOT_OBJECTS} Up to ${cap} ${records} are kept; no total, Link header, or cursor is read.`,
  stopConditions: [
    `A page holding fewer than ${pageSize} ${records}`,
    `A page holding more ${records} than were left under ${cap}, which marks the list partial`,
    `A full page that brings the ${records} kept to ${cap}, which marks the list partial`,
    "A page holding an entry that is not a JSON object, which marks the list partial",
  ],
});

const FRAMEWORK_REPORT_FILES = [
  "compliance/fedramp/fedramp_compliance_report.md",
  "compliance/cmmc/cmmc_compliance_report.md",
  "compliance/soc2/soc2_compliance_report.md",
  "compliance/cis_controls/cis_controls_v8_report.md",
  "compliance/pci_dss/pci_dss_compliance_report.md",
  "compliance/disa_stig/stig_compliance_checklist.md",
  "compliance/irap/irap_compliance_report.md",
  "compliance/ismap/ismap_compliance_report.md",
];
const CORE_DATA_FILES = [
  "access",
  "collection_status",
  "account",
  "account_risk_score_history",
  "users_active",
  "groups",
  "phishing_campaigns",
  "security_tests",
  "security_test_recipients",
  "callback_security_tests",
  "training_campaigns",
  "training_enrollments",
  "store_purchases",
  "training_policies",
  "phisher_messages",
];
const ASSESSMENT_AREAS = ["phishing", "training", "risk", "governance"];

export const KNOWBE4_SPEC = buildBatchIntegrationSpec({
  slug: "knowbe4-sec-inspector",
  displayName: "KnowBe4 Security Inspector",
  vendor: "KnowBe4",
  category: "security-awareness",
  summary: "Portable contract for the shipped KnowBe4 phishing program, training program, user risk, and account governance assessments over the KnowBe4 Reporting API and the optional PhishER GraphQL API.",
  sourceModule: "cli/extensions/grc-tools/knowbe4.ts",
  baseServices: [REPORTING_SERVICE, PHISHER_SERVICE],
  authentication: KNOWBE4_AUTH_RESOLVER,
  permissions: [
    {
      id: "reporting-api",
      kind: "license",
      value: "KnowBe4 Reporting API access and a Reporting API key",
      unlocks: [
        "account",
        "account_risk_score_history",
        "users",
        "groups",
        "phishing_campaigns",
        "security_tests",
        "security_test_recipients",
        "callback_security_tests",
        "training_campaigns",
        "training_enrollments",
        "store_purchases",
        "training_policies",
      ],
    },
    {
      id: "phisher-api",
      kind: "license",
      value: "PhishER and a PhishER Product API key; without the key PhishER is not read",
      unlocks: ["phisher_messages"],
    },
  ],
  surfaces: KNOWBE4_SURFACES,
  checks,
  tools: {
    knowbe4_check_access: [],
    knowbe4_assess_phishing_program: idsFor(PHISHING),
    knowbe4_assess_training_program: idsFor(TRAINING),
    knowbe4_assess_user_risk: idsFor(RISK),
    knowbe4_assess_account_governance: idsFor(GOVERNANCE),
    knowbe4_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [
    pageWalk(["users"], "users", USER_LIMIT, null, true),
    pageWalk(["training_enrollments"], "enrollments", ENROLLMENT_LIMIT, null, true),
    pageWalk(["groups", "phishing_campaigns", "security_tests", "store_purchases", "training_policies"], "records", "20000", 20000, true),
    pageWalk(["callback_security_tests"], "records", "20000", 20000, false),
    pageWalk(["training_campaigns"], "campaigns", "20000", 20000, true, "", 10),
    pageWalk(["account_risk_score_history"], "points", "20000", 20000, false),
    pageWalk(["security_test_recipients"], "recipients", "20000", 20000, false, "Each sampled test's recipient list is walked separately. "),
    {
      surfaceIds: ["phisher_messages"],
      cursorFields: ["pagination.totalCount", "pagination.pages", "pagination.nextPageKey"],
      pageSize: null,
      itemCap: null,
      pageCap: null,
      totalSemantics: `Pages of 200 messages, or phisher_message_limit when that is smaller (variables.per), numbered from 1 (variables.page), each later page also sending the previous page's pagination.nextPageKey when it returned one. Up to phisher_message_limit messages are kept, the ${dayOption("phisher_message_limit", 1000, 100000)}, and the list is partial whenever the walk ends with fewer messages kept than the last reported pagination.totalCount. The knowbe4_check_access count reads pagination.totalCount from one count-only request.`,
      stopConditions: [
        "A page holding more messages than were left under phisher_message_limit, which marks the list partial",
        "An empty page",
        "A page numbered pagination.pages or higher that returned no nextPageKey",
        "A nextPageKey equal to the one the page was requested with, which marks the list partial",
        "phisher_message_limit messages kept, which marks the list partial",
      ],
    },
    {
      surfaceIds: ["account"],
      cursorFields: [],
      pageSize: null,
      itemCap: "none",
      pageCap: 1,
      totalSemantics: "One read of the account record.",
      stopConditions: ["The first response"],
    },
  ],
  rateLimit: {
    documentedLimit: "KnowBe4 documents per-second, burst, and daily request limits per account for the Reporting API; the collector does not read rate-limit headers.",
    retryHeaders: ["Retry-After"],
    retryableStatuses: [429, 500, 502, 503, 504],
    backoffPolicy: "Retry 429, 500, 502, 503, and 504, requests that time out, and network errors up to 3 times after the first attempt; every request is a GET or a PhishER GraphQL query, so sending one again changes nothing. A Retry-After whose ECMAScript Number value is finite and 0 or more waits that many seconds; one that Date.parse reads as a date waits until then on the client clock, or not at all when it has passed; otherwise, and after a timeout or a network error, the wait is 1 second, doubling on each later retry. Every wait is capped at 60 seconds, and every attempt starts at least 250 milliseconds after the previous one. A request times out after 30 seconds unless timeout_seconds or KNOWBE4_TIMEOUT sets it, and the timer covers reading the body. When the retries run out, the request fails with its method and path (never its query), the HTTP status, the timeout (\"timed out after <ms>ms\"), or the network error, and the number of attempts, and the dataset it was reading is reported as not readable. Other statuses, including 501, and PhishER responses carrying GraphQL errors are not retried.",
  },
  runtimeBehavior: [],
  knownGaps: [],
  sensitiveFields: ["api_token", "phisher_api_token", "Authorization", ...PII_HASH_FIELDS, ...PII_MASK_FIELDS],
  credentialFormats: [
    "KnowBe4 Reporting API key, sent as a bearer token",
    "KnowBe4 PhishER Product API key, sent as a bearer token",
  ],
  output: buildBatchOutputContract({
    files: [
      "QUICK_REFERENCE.md",
      "metadata.json",
      ...CORE_DATA_FILES.map((name) => `core_data/${name}.json`),
      ...ASSESSMENT_AREAS.flatMap((area) => [`analysis/${area}.json`, `analysis/${area}.md`]),
      "analysis/findings.json",
      "analysis/control_coverage.json",
      "analysis/access_check.md",
      "compliance/executive_summary.md",
      "compliance/unified_compliance_matrix.md",
      ...FRAMEWORK_REPORT_FILES,
    ],
    conditionalFiles: ["_errors.log"],
    conditionalFileConditions: { "_errors.log": "Only when some reads fail but the bundle still completes." },
    overwritePolicy: "Allocate the account name read as text, else knowbe4-{region}, lowercased with every run of characters outside a-z, 0-9, dot, underscore, and hyphen replaced by one hyphen, trimmed of leading and trailing hyphens, and cut to 80 characters (knowbe4 when nothing is left), followed by -knowbe4-audit-bundle, or by that and the first of -2 through -6 whose directory and zip are both free, and fail rather than overwrite.",
    archivePairing: "Write a sibling zip named from the exact allocated bundle-directory path plus .zip.",
  }),
  lastUpdated: "2026-10-18",
  redaction: {
    projectionStage: `Responses are kept as read, except that the account record is cut to its listed fields with certificate-like fields summarized, and every user, including each recipient's embedded user, loses its ${series(USER_FREE_FORM_FIELDS)}. The export writes every core_data dataset through the PII pass when redact_pii is set, which replaces each ${series(PII_HASH_FIELDS, "or")} value that reads as text with user- followed by the first 12 hexadecimal digits of the SHA-256 of its trimmed, lowercased text and each non-null ${series(PII_MASK_FIELDS, "or")} value with [redacted], and always through the credential pass, which replaces the values of credential-shaped keys with [REDACTED], cuts the values of URL-shaped keys to their scheme and host, and scrubs token-shaped text from every other string. Analysis and compliance files skip both passes.`,
    integrationRules: [
      "A refused Reporting API or PhishER response is reported with its status line and, when its body is a JSON object, the text of its message, error, and errors[].message fields joined by semicolons, whitespace runs collapsed, credential values scrubbed, and cut to 300 characters; any other body is described by its status line, media type, and byte length and never echoed.",
      "A 2xx response whose body is not JSON is described by its media type and byte length and never echoed.",
      "PhishER GraphQL errors are reported as each error's message, else unknown error, joined by semicolons and scrubbed, without the 300-character cut.",
      "An inventory that was not requested, not readable, or not configured is exported as an explicit marker naming the reason, never as an empty dataset.",
    ],
  },
});
