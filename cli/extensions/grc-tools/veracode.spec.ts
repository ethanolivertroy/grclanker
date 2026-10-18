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
import { VERACODE_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import type { PortableValue, RequestParameterContract, VerdictCondition, VerdictOperand, VerdictRule } from "./spec-model.js";

// The members the documented user and API credential records carry; a 200 body with none of them is not the resource
// and is never read as evidence.
export const USER_MEMBERS: readonly string[] = ["user_id", "user_name", "email_address", "roles"];
export const API_CREDENTIAL_MEMBERS: readonly string[] = ["api_id", "created_ts", "expiration_ts", "revocation_ts"];
// Scan statuses, uppercased, that count as a published scan, and those that count as a failed one.
export const COMPLETED_SCAN_STATUSES: readonly string[] = [
  "PUBLISHED",
  "PUBLISHED_TO_VENDOR",
  "PUBLISHED_TO_ENTERPRISE",
  "PUBLISHED_TO_ENTERPRISEINT",
];
export const FAILED_SCAN_STATUSES: readonly string[] = [
  "ANALYSIS_ERRORS",
  "SCAN_CANCELED",
  "PRE_SCAN_FAILED",
  "PRE_SCAN_CANCELED",
  "NTO_PRE_SCAN_CANCELED",
  "INCOMPLETE",
  "MODULE_SELECTION_REQUIRED",
];
// Days each policy scan frequency allows between scans; ONCE asks for one scan ever, and any other frequency is ignored.
export const FREQUENCY_DAYS: Readonly<Record<string, number>> = {
  WEEKLY: 7,
  MONTHLY: 31,
  QUARTERLY: 92,
  SEMI_ANNUALLY: 183,
  ANNUALLY: 366,
  EVERY_18_MONTHS: 548,
  EVERY_2_YEARS: 731,
  EVERY_3_YEARS: 1096,
};
// Finding annotation actions, uppercased, that record a mitigation.
export const MITIGATION_ACTIONS: readonly string[] = [
  "FP",
  "APPDESIGN",
  "OSENV",
  "NETENV",
  "ACCEPTRISK",
  "BYENV",
  "BYDESIGN",
  "LIBRARY",
  "DEFER",
  "CUSTOMCLEANSERPROPOSED",
];
// Days an open, unresolved flaw may stay open, by numeric severity; flaws of any other severity are not aged.
export const FLAW_AGE_THRESHOLDS: Readonly<Record<number, number>> = { 5: 30, 4: 60, 3: 90, 2: 180 };
// Each control's framework references, in the order FedRAMP, CMMC, SOC 2, CIS Controls v8, PCI-DSS, STIG, IRAP, ISMAP.
export const VERACODE_FRAMEWORK_MAPPINGS: Readonly<Record<number, readonly [string, string, string, string, string, string, string, string]>> = {
  1: ["SA-11", "L2 3.14.1", "CC7.1", "16.12", "6.5", "SRG-APP-000456", "ISM-1143", "VM-01"],
  2: ["SA-11(1)", "L2 3.14.3", "CC7.1", "16.2", "6.3", "SRG-APP-000456", "ISM-1143", "VM-02"],
  3: ["SI-2", "L2 3.14.1", "CC7.1", "7.4", "6.3.3", "SRG-APP-000456", "ISM-1143", "VM-03"],
  4: ["SA-11", "L2 3.14.1", "CC7.1", "16.12", "6.5.6", "SRG-APP-000456", "ISM-1143", "VM-01"],
  5: ["SA-11(2)", "L2 3.14.2", "CC7.1", "16.4", "6.3.2", "SRG-APP-000454", "ISM-1490", "VM-04"],
  6: ["SA-4(2)", "L2 3.4.2", "CC3.2", "2.2", "6.3.2", "SRG-APP-000516", "ISM-1490", "RM-01"],
  7: ["AC-6", "L2 3.1.5", "CC6.3", "6.8", "7.2.2", "SRG-APP-000340", "ISM-0432", "AC-01"],
  8: ["AC-6(5)", "L2 3.1.5", "CC6.3", "5.4", "7.2.1", "SRG-APP-000340", "ISM-0432", "AC-02"],
  9: ["IA-5(1)", "L2 3.5.8", "CC6.1", "5.2", "8.6.3", "SRG-APP-000174", "ISM-1590", "AM-01"],
  10: ["SA-11", "L2 3.14.1", "CC8.1", "16.7", "6.5", "SRG-APP-000456", "ISM-1143", "SD-01"],
  11: ["SA-11", "L2 3.14.1", "CC7.1", "16.12", "6.5", "SRG-APP-000456", "ISM-1143", "VM-01"],
  12: ["SI-2", "L2 3.14.1", "CC7.4", "7.2", "6.3.3", "SRG-APP-000456", "ISM-1143", "VM-05"],
  13: ["SA-11(8)", "L2 3.14.6", "CC7.1", "16.6", "6.6", "SRG-APP-000456", "ISM-1143", "VM-06"],
  14: ["SA-11", "L2 3.14.1", "CC8.1", "16.12", "6.5.6", "SRG-APP-000456", "ISM-1143", "SD-02"],
  15: ["SA-11(1)", "L2 3.14.3", "CC7.1", "16.2", "6.3", "SRG-APP-000516", "ISM-1143", "VM-02"],
  16: ["SA-11", "L2 3.14.1", "CC7.1", "16.12", "6.5", "SRG-APP-000456", "ISM-1143", "VM-07"],
  17: ["SA-11", "L2 3.14.1", "CC7.1", "16.12", "6.5", "SRG-APP-000456", "ISM-1143", "VM-03"],
  18: ["SA-11(2)", "L2 3.14.2", "CC7.1", "16.4", "6.3.2", "SRG-APP-000454", "ISM-1490", "VM-04"],
  19: ["SA-11", "L2 3.14.1", "CC7.1", "16.12", "6.5", "SRG-APP-000456", "ISM-1143", "VM-01"],
  20: ["SA-11(1)", "L2 3.14.3", "CC7.1", "16.2", "6.3", "SRG-APP-000456", "ISM-1143", "VM-02"],
};
// Each sampled analysis has at most this many of its returned scans inspected.
export const MAX_DYNAMIC_SCANS_PER_ANALYSIS = 10;

const series = (items: readonly string[], conjunction = "and"): string =>
  items.length <= 2 ? items.join(` ${conjunction} `) : `${items.slice(0, -1).join(", ")}, ${conjunction} ${items[items.length - 1]}`;

const APPLICATIONS_SERVICE = "Veracode Applications REST API";
const POLICY_SERVICE = "Veracode Policy REST API";
const IDENTITY_SERVICE = "Veracode Identity REST API";
const DYNAMIC_SERVICE = "Veracode Dynamic Analysis REST API";
const APPLICATIONS_DOCS = "https://docs.veracode.com/r/c_apps_intro";
const POLICY_DOCS = "https://api.swaggerhub.com/apis/Veracode/veracode-policy_api_specification/1.0";
const IDENTITY_DOCS = "https://docs.veracode.com/r/c_identity_intro";
const DYNAMIC_DOCS = "https://docs.veracode.com/r/c_dynamic_intro";
const API_HOST = "Use the resolved API base URL: base_url, else VERACODE_API_BASE_URL, else the region's host, with any query, fragment, and trailing slashes removed. The region is the region argument, else VERACODE_REGION, else us, trimmed and lowercased: us or commercial is https://api.veracode.com, eu, europe, or european is https://api.veracode.eu, and us-fed, fedramp, or federal is https://api.veracode.us.";
const API_HEADERS = ["Accept: application/json", "Authorization: VERACODE-HMAC-SHA-256 id={api_key_id},ts={timestamp},nonce={nonce},sig={signature}"];
const CREDENTIAL_PASS = "the export's credential pass";
const LIST_STAGE = `The collector exports the walk's result as read, every returned record with all its fields alongside pagesFetched, complete, and, when known, totalPages, totalElements, and notes, through ${CREDENTIAL_PASS}; decision facts read the listed fields.`;

const REFUSAL = "a status outside 200 through 299 after retries, or a 2xx body that is not JSON, is a refusal";
const halResponse = (key: string, records: string): string =>
  `A JSON object whose _embedded.${key} array holds ${records}, an entry that is not a JSON object being dropped (an _embedded that is itself an array is read in place of that array), and whose page object reports total_pages (else totalPages) and total_elements (else totalElements), each read as a number when present. An empty 2xx body, or JSON that is not an object, is read as a page holding no records; ${REFUSAL}.`;
const SELF_RESPONSE = `A JSON object carrying at least one of ${series(USER_MEMBERS, "or")}; any other 2xx body, an empty one included, is a refusal, as is a status outside 200 through 299 after retries.`;
const SCAN_CONFIGURATION_RESPONSE = `A JSON object read for auth_configuration.authentications, whose members name the configured authentication methods, crawl_configuration.disabled and crawl_script_data, target_url (its url when it is an object), and scan_setting.allowed_hosts, else allowed_hosts. An empty 2xx body, or JSON that is not an object, is read as a configuration without authentication; ${REFUSAL}.`;

const param = (
  name: string,
  location: RequestParameterContract["location"],
  value: string,
  required = true,
  when?: string,
): RequestParameterContract => ({ name, location, required, value, ...(when ? { when } : {}) });

const PAGE_INDEX = "The zero-based page index: 0 for the first page, then one more than the previous page's";
const HAL_PAGE_PARAMETERS: readonly RequestParameterContract[] = [param("page", "query", PAGE_INDEX), param("size", "query", "100")];
const pathId = (name: string, record: string): RequestParameterContract =>
  param(name, "path", `The ${record}'s ${name.replace("application_", "")} read as text and percent-encoded, empty when it has none`);

const surface = (
  id: string,
  service: string,
  documentationUrl: string,
  path: string,
  fields: readonly string[],
  parameters: readonly RequestParameterContract[],
  responseShape: string,
  projectionStage: string,
): BatchSurfaceDefinition => ({
  id,
  path,
  service,
  documentationUrl,
  fields,
  request: { clientRegion: API_HOST, headers: API_HEADERS, parameters, responseShape },
  projectionStage,
});

const SCAN_COVERAGE_SURFACES: readonly BatchSurfaceDefinition[] = [
  surface(
    "self",
    IDENTITY_SERVICE,
    IDENTITY_DOCS,
    "/api/authn/v2/users/self",
    ["user_id", "user_name", "email_address", "roles.role_name"],
    [],
    SELF_RESPONSE,
    `The access control assessment exports the record as read through ${CREDENTIAL_PASS}; the other assessments request it without exporting it, and veracode_check_access reads it for the principal and its roles.`,
  ),
  surface(
    "applications",
    APPLICATIONS_SERVICE,
    APPLICATIONS_DOCS,
    "/appsec/v1/applications",
    [
      "guid",
      "profile.name",
      "profile.policies.guid",
      "profile.policies.policy_compliance_status",
      "profile.business_criticality",
      "profile.business_unit.name",
      "scans.scan_type",
      "scans.status",
      "scans.modified_date",
      "last_completed_scan_date",
    ],
    HAL_PAGE_PARAMETERS,
    halResponse("applications", "one application profile per entry"),
    LIST_STAGE,
  ),
  surface(
    "policies",
    POLICY_SERVICE,
    POLICY_DOCS,
    "/appsec/v1/policies",
    [
      "guid",
      "name",
      "type",
      "finding_rules",
      ...[0, 1, 2, 3, 4, 5].map((level) => `sev${level}_grace_period`),
      "scan_frequency_rules.scan_type",
      "scan_frequency_rules.frequency",
    ],
    HAL_PAGE_PARAMETERS,
    halResponse("policy_versions", "one policy per entry"),
    LIST_STAGE,
  ),
  surface(
    "sandboxes",
    APPLICATIONS_SERVICE,
    APPLICATIONS_DOCS,
    "/appsec/v1/applications/{application_guid}/sandboxes",
    [],
    [pathId("application_guid", "sampled application"), ...HAL_PAGE_PARAMETERS],
    halResponse("sandboxes", "one development sandbox per entry"),
    `The collector exports each sampled application's sandbox records as read, keyed by the application's guid read as text (empty text when it has none), without the walk's pagination state, through ${CREDENTIAL_PASS}; decisions count the records and read no field.`,
  ),
  surface(
    "dynamic_analyses",
    DYNAMIC_SERVICE,
    DYNAMIC_DOCS,
    "/was/configservice/v1/analyses",
    ["analysis_id", "name"],
    HAL_PAGE_PARAMETERS,
    halResponse("analyses", "one Dynamic Analysis per entry"),
    `The collector exports the returned analysis records as read, without the walk's pagination state, through ${CREDENTIAL_PASS}; decisions count the records, and each sampled analysis's analysis_id selects its scan list.`,
  ),
  surface(
    "dynamic_analysis_scans",
    DYNAMIC_SERVICE,
    DYNAMIC_DOCS,
    "/was/configservice/v1/analyses/{analysis_id}/scans",
    ["scan_id", "target_url"],
    [pathId("analysis_id", "sampled analysis"), ...HAL_PAGE_PARAMETERS],
    halResponse("scans", "one Dynamic Analysis scan per entry"),
    `The collector keeps each returned scan's scan_id read as text, else null, and its target_url read as text with any userinfo and query replaced by [REDACTED] and any fragment dropped, else null; every other field is dropped, and the scans are exported keyed by the analysis_id through ${CREDENTIAL_PASS}. Decisions read scan_id to select the configurations to inspect.`,
  ),
  surface(
    "dynamic_scan_configurations",
    DYNAMIC_SERVICE,
    DYNAMIC_DOCS,
    "/was/configservice/v1/scans/{scan_id}/configuration",
    [
      "auth_configuration.authentications",
      "crawl_configuration.disabled",
      "crawl_configuration.crawl_script_data",
      "target_url",
      "target_url.url",
      "scan_setting.allowed_hosts",
      "allowed_hosts",
    ],
    [pathId("scan_id", "inspected scan")],
    SCAN_CONFIGURATION_RESPONSE,
    `The collector keeps, per inspected scan, its analysis_id and scan_id; target_url (its url when it is an object) read as text with any userinfo and query replaced by [REDACTED] and any fragment dropped, else null; the member names of auth_configuration.authentications, with one [REDACTED] marker in place of their contents; crawl_configuration.disabled read as a boolean, else null; whether crawl_configuration.crawl_script_data is a JSON object; and the number of JSON object entries in scan_setting.allowed_hosts, else allowed_hosts. Every other field is dropped, and the result is exported through ${CREDENTIAL_PASS}.`,
  ),
];

const VERACODE_SURFACES: readonly BatchSurfaceDefinition[] = [...SCAN_COVERAGE_SURFACES];

const value = (entry: PortableValue): VerdictOperand => ({ kind: "value", value: entry });
const path = (name: string): VerdictOperand => ({ kind: "path", path: name });
type Comparator = "eq" | "ne" | "gt" | "lt";
const cmp = (op: Comparator, left: string | VerdictOperand, right: PortableValue | VerdictOperand): VerdictCondition => ({
  op,
  left: typeof left === "string" ? path(left) : left,
  right: right !== null && typeof right === "object" && !Array.isArray(right) ? right as VerdictOperand : value(right as PortableValue),
});
const ne = (left: string | VerdictOperand, right: PortableValue | VerdictOperand) => cmp("ne", left, right);
const gt = (left: string | VerdictOperand, right: PortableValue | VerdictOperand) => cmp("gt", left, right);
const any = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "or", conditions });
const not = (condition: VerdictCondition): VerdictCondition => ({ op: "not", condition });
const always: VerdictCondition = { op: "always" };
const rule = (status: VerdictRule["status"], condition: VerdictCondition): VerdictRule => ({ status, condition });
const incomplete = (...complete: string[]): VerdictCondition =>
  complete.length === 1 ? ne(complete[0], true) : any(...complete.map((name) => ne(name, true)));

const AS_NUMBER = "read as a number (a finite number, or a string that is not blank and parses as one)";
const READS_AS_TEXT = "A value reads as text when it is a string that is not blank, trimmed, or a finite number, as ECMAScript writes it.";
const PARSES_AS_DATE = "A value parses as a date when it reads as text and ECMAScript Date.parse reads that text.";
const option = (name: string, fallback: number, max: number): string =>
  `the ${name} argument ${AS_NUMBER}, else ${fallback}, truncated to a whole number and clamped to 1 through ${max}`;
const WHOLE_DAYS = "Whole days before the assessment time are the milliseconds from a date to the assessment time divided by 86400000 and rounded down.";
const APPLICATION_SCANS = `An application's scans of a type are the JSON object entries of its scans array whose scan_type, read as text and uppercased, is that type. A scan is published when its status, read as text and uppercased, is ${series(COMPLETED_SCAN_STATUSES, "or")}, and an application's published date for a type is the latest modified_date that parses as a date among its published scans of that type. ${READS_AS_TEXT} ${PARSES_AS_DATE}`;
const LISTED_SCANS = `An application's listed scans are the JSON object entries of its scans array, of every scan type, and a listed scan has failed when its status, read as text and uppercased, is ${series(FAILED_SCAN_STATUSES, "or")}. ${READS_AS_TEXT}`;
const FREQUENCIES = Object.entries(FREQUENCY_DAYS).map(([name, days]) => `${name} (${days} days)`);
const ASSIGNED_POLICIES = "An application's assigned policies are the JSON object entries of its profile.policies, and an assigned policy resolves to the last returned policy whose guid, read as text, is the same, a guid that does not read as text counting as empty text.";
const POLICY_STATUSES = `An application's assigned policies are the JSON object entries of its profile.policies, and an assigned policy's status is its policy_compliance_status read as text and uppercased. ${READS_AS_TEXT}`;
const CUSTOM_POLICY = `A custom policy is a returned policy whose type, read as text and uppercased, is CUSTOMER. ${READS_AS_TEXT}`;
const FREQUENCY_REQUIREMENTS = `${ASSIGNED_POLICIES} Each resolved policy adds one requirement per JSON object entry of its scan_frequency_rules whose frequency, read as text and uppercased, is ONCE (at least once) or ${series(FREQUENCIES, "or")}, for the scan type that the entry's scan_type gives, read as text and uppercased, else ANY. An application whose profile.business_criticality reads as text adds an ANY requirement of N days, N being ${option("critical_scan_interval_days", 7, 3650)} when that text uppercases to VERY_HIGH, and otherwise ${option("standard_scan_interval_days", 31, 3650)}. Only the strictest requirement per scan type counts: the one with the fewest days, the first on ties, the policies' requirements coming in assignment and rule order before the business criticality one.`;
const REQUIREMENT_OUTCOMES = `A counted requirement of type ANY is unconfirmed when the application's last_completed_scan_date does not parse as a date, and overdue when that date is more of the requirement's days in whole days before the assessment time. A counted requirement of another type is overdue when the application has no scan of that type, unconfirmed when it has none published or no published date for that type, and overdue when that published date is more of the requirement's days in whole days before the assessment time; an at-least-once requirement is never overdue by age. An application is overdue when one of its counted requirements is overdue, and otherwise unconfirmed when one is unconfirmed or one of its assigned policies does not resolve. ${APPLICATION_SCANS} ${WHOLE_DAYS}`;
const SANDBOX_SAMPLE = `The sampled applications are the first N returned applications, N being ${option("max_applications", 100, 5000)}; each sampled application's sandbox list is read from GET /appsec/v1/applications/{application_guid}/sandboxes, its records being the entries that are JSON objects.`;
const DYNAMIC_SAMPLE = `The sampled analyses are the first N returned Dynamic Analysis records, N being ${option("max_analyses", 25, 500)}. Each sampled analysis's scan list is read from GET /was/configservice/v1/analyses/{analysis_id}/scans, and the first ${MAX_DYNAMIC_SCANS_PER_ANALYSIS} returned scans of each are inspected by reading GET /was/configservice/v1/scans/{scan_id}/configuration.`;
const SCAN_AUTH = "An inspected scan is unauthenticated when its configuration's auth_configuration.authentications is not a JSON object with at least one member, and crawl-disabled when it is not unauthenticated and its configuration's crawl_configuration.disabled is the boolean true or a string that trims to true in any letter case.";

const VERACODE_INPUTS: Readonly<Record<string, string>> = {
  applications_readable: "True when the GET /appsec/v1/applications walk returned without a refusal.",
  applications_complete: "Application inventory coverage.",
  application_count: "Number of application profiles the walk kept, entries that are not JSON objects being dropped.",
  stale_static_scan_application_count: `Number of applications whose published date for STATIC is more than N whole days before the assessment time, N being ${option("max_scan_age_days", 90, 3650)}. ${APPLICATION_SCANS} ${WHOLE_DAYS}`,
  no_static_scan_application_count: `Number of applications without a scan of type STATIC. ${APPLICATION_SCANS}`,
  unpublished_static_scan_application_count: `Number of applications with scans of type STATIC but none published. ${APPLICATION_SCANS}`,
  undated_static_scan_application_count: `Number of applications with published scans of type STATIC but no published date for STATIC. ${APPLICATION_SCANS}`,
  policies_readable: "True when the GET /appsec/v1/policies walk returned without a refusal.",
  policies_complete: "Policy list coverage.",
  overdue_application_count: `Number of overdue applications. ${FREQUENCY_REQUIREMENTS} ${REQUIREMENT_OUTCOMES}`,
  unconfirmed_frequency_application_count: `Number of applications that are unconfirmed and not overdue. ${FREQUENCY_REQUIREMENTS} ${REQUIREMENT_OUTCOMES}`,
  no_frequency_requirement_application_count: `Number of applications with no counted requirement and no assigned policy that fails to resolve. ${FREQUENCY_REQUIREMENTS}`,
  sandbox_list_read_count: `Number of sampled applications whose sandbox list was read without a refusal. ${SANDBOX_SAMPLE}`,
  no_sandbox_application_count: `Number of sampled applications whose sandbox list was read without a refusal and holds no record. ${SANDBOX_SAMPLE}`,
  sandbox_reads_complete: "Sandbox read coverage.",
  dynamic_analyses_readable: "True when the GET /was/configservice/v1/analyses walk returned without a refusal.",
  dynamic_analysis_count: "Number of Dynamic Analysis records the walk kept, entries that are not JSON objects being dropped.",
  scan_configuration_read_count: `Number of inspected scans whose configuration was read without a refusal. ${DYNAMIC_SAMPLE}`,
  unauthenticated_scan_count: `Number of inspected scans whose configuration was read without a refusal and that are unauthenticated. ${SCAN_AUTH} ${DYNAMIC_SAMPLE}`,
  crawl_disabled_scan_count: `Number of inspected scans whose configuration was read without a refusal and that are crawl-disabled. ${SCAN_AUTH} ${DYNAMIC_SAMPLE}`,
  dynamic_scan_coverage_complete: "Dynamic Analysis scan coverage.",
  failed_scan_application_count: `Number of applications with a failed listed scan. ${LISTED_SCANS}`,
  healthy_scan_application_count: `Number of applications with at least one listed scan and no failed one. ${LISTED_SCANS}`,
  no_scan_application_count: `Number of applications without a listed scan. ${LISTED_SCANS}`,
  failing_policy_application_count: `Number of applications with an assigned policy whose status is DID_NOT_PASS. ${POLICY_STATUSES}`,
  no_policy_application_count: `Number of applications without an assigned policy. ${POLICY_STATUSES}`,
  conditional_pass_application_count: `Number of applications with an assigned policy whose status is CONDITIONAL_PASS and none whose status is DID_NOT_PASS. ${POLICY_STATUSES}`,
  unassessed_policy_application_count: `Number of applications with assigned policies, none of whose status is DID_NOT_PASS or CONDITIONAL_PASS, and one whose status is not PASSED, a missing status included. ${POLICY_STATUSES}`,
  policy_count: "Number of policies the walk kept, entries that are not JSON objects being dropped.",
  custom_policy_count: `Number of custom policies. ${CUSTOM_POLICY}`,
  custom_policy_without_finding_rules_count: `Number of custom policies whose finding_rules holds no JSON object entry. ${CUSTOM_POLICY}`,
  no_custom_policy_application_count: `Number of applications none of whose assigned policies resolves to a custom policy, applications without an assigned policy included; 0 when the GET /appsec/v1/applications walk was refused. ${ASSIGNED_POLICIES} ${CUSTOM_POLICY}`,
};

const inputs = (...names: string[]): Readonly<Record<string, string>> => Object.fromEntries(names.map((name) => {
  const definition = VERACODE_INPUTS[name];
  if (!definition) throw new Error(`Veracode decision input ${name} has no portable definition`);
  return [name, definition];
}));

const walkPartial = (cap: number): string =>
  `the walk reached its ${cap}-page cap before a stop condition, met a non-empty page repeating the previous page's records, or ended with fewer records kept than the last reported total_elements`;
const halWalkComplete = (surfaceId: string, list: string): BatchCompletenessDefinition => ({
  semantics: `false when the ${list} read was refused, or the list is partial because ${walkPartial(50)}.`,
  sources: [{ surfaceId, falseWhen: ["truncated", "error", "denied"] }],
});
const APPLICATIONS_COMPLETE = halWalkComplete("applications", "application inventory");
const POLICIES_COMPLETE = halWalkComplete("policies", "policy list");
const SANDBOX_READS_COMPLETE: BatchCompletenessDefinition = {
  semantics: `false when the sandbox reads do not cover the whole application inventory: the inventory read was refused or is partial because ${walkPartial(50)}, the inventory holds more applications than were sampled, or a sampled application's sandbox list was refused. A sandbox list that stopped at its 10-page cap still holds records, so its truncation does not lower this fact. ${SANDBOX_SAMPLE}`,
  sources: [
    { surfaceId: "applications", falseWhen: ["truncated", "error", "denied"] },
    { surfaceId: "sandboxes", falseWhen: ["error", "denied", "not-collected"] },
  ],
};
const DYNAMIC_SCAN_COVERAGE_COMPLETE: BatchCompletenessDefinition = {
  semantics: `false when the inspected configurations do not cover every Dynamic Analysis scan: the analysis list read was refused or is partial because ${walkPartial(50)}; the list holds more analyses than were sampled; a sampled analysis's scan list was refused or is partial because ${walkPartial(5)}; a sampled analysis has more than ${MAX_DYNAMIC_SCANS_PER_ANALYSIS} returned scans; or an inspected scan's configuration was refused. ${DYNAMIC_SAMPLE}`,
  sources: [
    { surfaceId: "dynamic_analyses", falseWhen: ["truncated", "error", "denied"] },
    { surfaceId: "dynamic_analysis_scans", falseWhen: ["truncated", "error", "denied", "not-collected"] },
    { surfaceId: "dynamic_scan_configurations", falseWhen: ["error", "denied", "not-collected"] },
  ],
};

type VeracodeCheck = {
  id: string;
  control: number;
  title: string;
  severity: BatchCheckDefinition["severity"];
  owner: string;
  surfaces: readonly string[];
  inputs: readonly string[];
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

const APPLICATIONS_GATE = [rule("manual", ne("applications_readable", true)), rule("manual", not(gt("application_count", 0)))];
const APPLICATIONS_READ = { applications_readable: true, application_count: 12 };
const FULL_INVENTORY = { ...APPLICATIONS_READ, applications_complete: true };
const EMPTY_APPLICATIONS = example("partial", "manual", "The application inventory came back empty, which is not a compliant inventory.", {
  ...APPLICATIONS_READ,
  application_count: 0,
});
const UNREADABLE_APPLICATIONS = example("unreadable", "manual", "The application inventory was refused.", { applications_readable: false });

const SCAN_COVERAGE = "veracode_assess_scan_coverage";
const STATIC_SCANS_HEALTHY = {
  ...FULL_INVENTORY,
  stale_static_scan_application_count: 0,
  no_static_scan_application_count: 0,
  unpublished_static_scan_application_count: 0,
  undated_static_scan_application_count: 0,
};
const FREQUENCY_HEALTHY = {
  ...FULL_INVENTORY,
  policies_readable: true,
  policies_complete: true,
  overdue_application_count: 0,
  unconfirmed_frequency_application_count: 0,
  no_frequency_requirement_application_count: 0,
};
const SANDBOXES_HEALTHY = { ...APPLICATIONS_READ, sandbox_list_read_count: 12, no_sandbox_application_count: 0, sandbox_reads_complete: true };
const DYNAMIC_HEALTHY = {
  dynamic_analyses_readable: true,
  dynamic_analysis_count: 4,
  scan_configuration_read_count: 6,
  unauthenticated_scan_count: 0,
  crawl_disabled_scan_count: 0,
  dynamic_scan_coverage_complete: true,
};
const SCANS_HEALTHY = { ...FULL_INVENTORY, failed_scan_application_count: 0, healthy_scan_application_count: 12, no_scan_application_count: 0 };

const SCAN_COVERAGE_CHECKS: readonly VeracodeCheck[] = [
  {
    id: "VERACODE-01",
    control: 1,
    title: "Application scan coverage",
    severity: "critical",
    owner: SCAN_COVERAGE,
    surfaces: ["applications"],
    inputs: [
      "applications_readable",
      "application_count",
      "stale_static_scan_application_count",
      "no_static_scan_application_count",
      "unpublished_static_scan_application_count",
      "undated_static_scan_application_count",
      "applications_complete",
    ],
    rules: [
      ...APPLICATIONS_GATE,
      rule("fail", any(gt("stale_static_scan_application_count", 0), gt("no_static_scan_application_count", 0))),
      rule("warn", any(gt("unpublished_static_scan_application_count", 0), gt("undated_static_scan_application_count", 0))),
      rule("warn", incomplete("applications_complete")),
      rule("pass", always),
    ],
    completeness: { applications_complete: APPLICATIONS_COMPLETE },
    decision: "Manual when the application inventory is unreadable or empty. Fail when an application has no static scan, or its newest published static scan is older than max_scan_age_days. Warn when an application has static scans but none published, or none published with a readable date. Warn instead of pass when the application inventory is partial. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Every application's newest published static scan is within max_scan_age_days.", STATIC_SCANS_HEALTHY),
      example("noncompliant", "fail", "Two applications' newest published static scans are older than max_scan_age_days.", {
        ...STATIC_SCANS_HEALTHY,
        stale_static_scan_application_count: 2,
      }),
      example("noncompliant", "fail", "One application has only dynamic and SCA scans.", { ...STATIC_SCANS_HEALTHY, no_static_scan_application_count: 1 }),
      example("partial", "warn", "One application's only static scan is still in progress.", { ...STATIC_SCANS_HEALTHY, unpublished_static_scan_application_count: 1 }),
      example("partial", "warn", "One application's published static scan carries no modified_date.", { ...STATIC_SCANS_HEALTHY, undated_static_scan_application_count: 1 }),
      example("partial", "warn", "The application walk stopped at its page cap.", { ...STATIC_SCANS_HEALTHY, applications_complete: false }),
      EMPTY_APPLICATIONS,
      UNREADABLE_APPLICATIONS,
    ],
  },
  {
    id: "VERACODE-04",
    control: 4,
    title: "Scan frequency compliance",
    severity: "high",
    owner: SCAN_COVERAGE,
    surfaces: ["applications", "policies"],
    inputs: [
      "applications_readable",
      "application_count",
      "policies_readable",
      "overdue_application_count",
      "no_frequency_requirement_application_count",
      "unconfirmed_frequency_application_count",
      "applications_complete",
      "policies_complete",
    ],
    rules: [
      ...APPLICATIONS_GATE,
      rule("manual", ne("policies_readable", true)),
      rule("fail", gt("overdue_application_count", 0)),
      rule("warn", any(gt("no_frequency_requirement_application_count", 0), gt("unconfirmed_frequency_application_count", 0))),
      rule("warn", incomplete("applications_complete", "policies_complete")),
      rule("pass", always),
    ],
    completeness: { applications_complete: APPLICATIONS_COMPLETE, policies_complete: POLICIES_COMPLETE },
    decision: "Manual when the application inventory is unreadable or empty, or the policy list is unreadable. Fail when an application is overdue against its strictest scan frequency requirement from its assigned policies and business criticality. Warn when an application has no frequency requirement, or its compliance cannot be confirmed because a scan is unpublished or undated or an assigned policy is missing from the policy list. Warn instead of pass when the application inventory or the policy list is partial. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Every application meets its strictest scan frequency requirement.", FREQUENCY_HEALTHY),
      example("noncompliant", "fail", "One application's last published static scan is older than its policy's monthly rule allows.", {
        ...FREQUENCY_HEALTHY,
        overdue_application_count: 1,
      }),
      example("partial", "warn", "Three applications have neither a policy scan frequency rule nor a business criticality.", {
        ...FREQUENCY_HEALTHY,
        no_frequency_requirement_application_count: 3,
      }),
      example("partial", "warn", "One application's assigned policy is missing from the policy list.", { ...FREQUENCY_HEALTHY, unconfirmed_frequency_application_count: 1 }),
      example("partial", "warn", "The policy walk stopped at its page cap.", { ...FREQUENCY_HEALTHY, policies_complete: false }),
      example("unreadable", "manual", "The policy list was refused.", { ...APPLICATIONS_READ, policies_readable: false }),
      EMPTY_APPLICATIONS,
      UNREADABLE_APPLICATIONS,
    ],
  },
  {
    id: "VERACODE-10",
    control: 10,
    title: "Sandbox usage",
    severity: "medium",
    owner: SCAN_COVERAGE,
    surfaces: ["applications", "sandboxes"],
    inputs: ["applications_readable", "application_count", "sandbox_list_read_count", "no_sandbox_application_count", "sandbox_reads_complete"],
    rules: [
      ...APPLICATIONS_GATE,
      rule("manual", not(gt("sandbox_list_read_count", 0))),
      rule("warn", gt("no_sandbox_application_count", 0)),
      rule("warn", incomplete("sandbox_reads_complete")),
      rule("pass", always),
    ],
    completeness: { sandbox_reads_complete: SANDBOX_READS_COMPLETE },
    decision: "Manual when the application inventory is unreadable or empty, or no sampled application's sandbox list could be read. Warn when a sampled application has no development sandbox. Warn instead of pass when the sandbox reads do not cover the whole application inventory. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Every sampled application has at least one development sandbox.", SANDBOXES_HEALTHY),
      example("noncompliant", "warn", "Two sampled applications have no development sandbox.", { ...SANDBOXES_HEALTHY, no_sandbox_application_count: 2 }),
      example("partial", "warn", "The inventory holds more applications than max_applications lets the assessment sample.", {
        ...SANDBOXES_HEALTHY,
        sandbox_reads_complete: false,
      }),
      example("unreadable", "manual", "Every sampled application's sandbox list was refused.", {
        ...SANDBOXES_HEALTHY,
        sandbox_list_read_count: 0,
        sandbox_reads_complete: false,
      }),
      EMPTY_APPLICATIONS,
      UNREADABLE_APPLICATIONS,
    ],
  },
  {
    id: "VERACODE-11",
    control: 11,
    title: "Prescan module coverage",
    severity: "low",
    owner: SCAN_COVERAGE,
    surfaces: ["applications"],
    inputs: [],
    rules: [rule("manual", always)],
    decision: "Always return manual, because prescan module selection results are only exposed by the XML getprescanresults.do API, which the inspector does not call, so a reviewer must export the module selection for each application's latest static scan.",
    examples: [example("partial", "manual", "Module selection is left to a reviewer whatever the application inventory holds.", {})],
  },
  {
    id: "VERACODE-13",
    control: 13,
    title: "Dynamic scan configuration",
    severity: "medium",
    owner: SCAN_COVERAGE,
    surfaces: ["dynamic_analyses", "dynamic_analysis_scans", "dynamic_scan_configurations"],
    inputs: [
      "dynamic_analyses_readable",
      "dynamic_analysis_count",
      "scan_configuration_read_count",
      "unauthenticated_scan_count",
      "crawl_disabled_scan_count",
      "dynamic_scan_coverage_complete",
    ],
    rules: [
      rule("manual", ne("dynamic_analyses_readable", true)),
      rule("manual", not(gt("dynamic_analysis_count", 0))),
      rule("manual", not(gt("scan_configuration_read_count", 0))),
      rule("fail", any(gt("unauthenticated_scan_count", 0), gt("crawl_disabled_scan_count", 0))),
      rule("warn", incomplete("dynamic_scan_coverage_complete")),
      rule("pass", always),
    ],
    completeness: { dynamic_scan_coverage_complete: DYNAMIC_SCAN_COVERAGE_COMPLETE },
    decision: "Manual when the Dynamic Analysis list is unreadable or empty, or no inspected scan's configuration could be read. Fail when an inspected scan has no authentication configured or has crawling disabled. Warn instead of pass when the inspected configurations do not cover every Dynamic Analysis scan. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Every inspected scan authenticates and keeps crawling enabled.", DYNAMIC_HEALTHY),
      example("noncompliant", "fail", "One inspected scan has no authentication configured.", { ...DYNAMIC_HEALTHY, unauthenticated_scan_count: 1 }),
      example("noncompliant", "fail", "Two inspected scans have crawling disabled.", { ...DYNAMIC_HEALTHY, crawl_disabled_scan_count: 2 }),
      example("partial", "warn", "One analysis has more scans than the inspection reads.", { ...DYNAMIC_HEALTHY, dynamic_scan_coverage_complete: false }),
      example("partial", "manual", "No Dynamic Analysis exists, which is not applicable rather than compliant.", {
        ...DYNAMIC_HEALTHY,
        dynamic_analysis_count: 0,
        scan_configuration_read_count: 0,
      }),
      example("unreadable", "manual", "Every scan list was refused, so no configuration was read.", {
        ...DYNAMIC_HEALTHY,
        scan_configuration_read_count: 0,
        dynamic_scan_coverage_complete: false,
      }),
      example("unreadable", "manual", "The Dynamic Analysis list was refused.", { dynamic_analyses_readable: false }),
    ],
  },
  {
    id: "VERACODE-14",
    control: 14,
    title: "Pipeline integration status",
    severity: "low",
    owner: SCAN_COVERAGE,
    surfaces: ["applications"],
    inputs: [],
    rules: [rule("manual", always)],
    decision: "Always return manual, because Pipeline Scan and IDE scan results are not kept on application profiles and the Applications API scans array lists only platform scans, so a reviewer must collect CI/CD pipeline configuration or scan job logs.",
    examples: [example("partial", "manual", "CI/CD integration is left to a reviewer whatever the application inventory holds.", {})],
  },
  {
    id: "VERACODE-19",
    control: 19,
    title: "Scan completion rate",
    severity: "medium",
    owner: SCAN_COVERAGE,
    surfaces: ["applications"],
    inputs: [
      "applications_readable",
      "application_count",
      "failed_scan_application_count",
      "healthy_scan_application_count",
      "no_scan_application_count",
      "applications_complete",
    ],
    rules: [
      ...APPLICATIONS_GATE,
      rule("fail", gt("failed_scan_application_count", 0)),
      rule("manual", not(gt("healthy_scan_application_count", 0))),
      rule("warn", gt("no_scan_application_count", 0)),
      rule("warn", incomplete("applications_complete")),
      rule("pass", always),
    ],
    completeness: { applications_complete: APPLICATIONS_COMPLETE },
    decision: "Manual when the application inventory is unreadable or empty. Fail when an application lists a scan in a failed, canceled, or incomplete status. Otherwise manual when no application lists a scan. Warn when an application lists no scan. Warn instead of pass when the application inventory is partial. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Every application lists scans and none failed.", SCANS_HEALTHY),
      example("noncompliant", "fail", "One application lists a scan in ANALYSIS_ERRORS.", {
        ...SCANS_HEALTHY,
        failed_scan_application_count: 1,
        healthy_scan_application_count: 11,
      }),
      example("partial", "warn", "Two applications list no scan.", { ...SCANS_HEALTHY, healthy_scan_application_count: 10, no_scan_application_count: 2 }),
      example("partial", "warn", "The application walk stopped at its page cap.", { ...SCANS_HEALTHY, applications_complete: false }),
      example("partial", "manual", "No application lists a scan, so no completion rate exists.", {
        ...SCANS_HEALTHY,
        healthy_scan_application_count: 0,
        no_scan_application_count: 12,
      }),
      EMPTY_APPLICATIONS,
      UNREADABLE_APPLICATIONS,
    ],
  },
];

const POLICY_COMPLIANCE = "veracode_assess_policy_compliance";
const POLICY_STATUS_HEALTHY = {
  ...FULL_INVENTORY,
  failing_policy_application_count: 0,
  no_policy_application_count: 0,
  conditional_pass_application_count: 0,
  unassessed_policy_application_count: 0,
};
const CUSTOM_POLICIES_HEALTHY = {
  policies_readable: true,
  policies_complete: true,
  policy_count: 9,
  custom_policy_count: 2,
  custom_policy_without_finding_rules_count: 0,
  no_custom_policy_application_count: 0,
  applications_complete: true,
};

const POLICY_COMPLIANCE_CHECKS: readonly VeracodeCheck[] = [
  {
    id: "VERACODE-02",
    control: 2,
    title: "Policy compliance status",
    severity: "critical",
    owner: POLICY_COMPLIANCE,
    surfaces: ["applications"],
    inputs: [
      "applications_readable",
      "application_count",
      "failing_policy_application_count",
      "no_policy_application_count",
      "conditional_pass_application_count",
      "unassessed_policy_application_count",
      "applications_complete",
    ],
    rules: [
      ...APPLICATIONS_GATE,
      rule("fail", any(gt("failing_policy_application_count", 0), gt("no_policy_application_count", 0))),
      rule("warn", any(gt("conditional_pass_application_count", 0), gt("unassessed_policy_application_count", 0))),
      rule("warn", incomplete("applications_complete")),
      rule("pass", always),
    ],
    completeness: { applications_complete: APPLICATIONS_COMPLETE },
    decision: "Manual when the application inventory is unreadable or empty. Fail when an application did not pass an assigned policy or has no policy assigned. Warn when an application is in conditional pass, or reports a policy status other than PASSED (NOT_ASSESSED, DETERMINING, VENDOR_REVIEW, or none). Warn instead of pass when the application inventory is partial. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Every application reports PASSED for every assigned policy.", POLICY_STATUS_HEALTHY),
      example("noncompliant", "fail", "One application did not pass its assigned policy.", { ...POLICY_STATUS_HEALTHY, failing_policy_application_count: 1 }),
      example("noncompliant", "fail", "Two applications have no policy assigned.", { ...POLICY_STATUS_HEALTHY, no_policy_application_count: 2 }),
      example("partial", "warn", "One application is in conditional pass during its grace period.", { ...POLICY_STATUS_HEALTHY, conditional_pass_application_count: 1 }),
      example("partial", "warn", "Three applications are still NOT_ASSESSED.", { ...POLICY_STATUS_HEALTHY, unassessed_policy_application_count: 3 }),
      example("partial", "warn", "The application walk stopped at its page cap.", { ...POLICY_STATUS_HEALTHY, applications_complete: false }),
      EMPTY_APPLICATIONS,
      UNREADABLE_APPLICATIONS,
    ],
  },
  {
    id: "VERACODE-15",
    control: 15,
    title: "Custom policy profiles",
    severity: "high",
    owner: POLICY_COMPLIANCE,
    surfaces: ["policies", "applications"],
    inputs: [
      "policies_readable",
      "policy_count",
      "custom_policy_count",
      "custom_policy_without_finding_rules_count",
      "no_custom_policy_application_count",
      "policies_complete",
      "applications_complete",
    ],
    rules: [
      rule("manual", ne("policies_readable", true)),
      rule("manual", not(gt("policy_count", 0))),
      rule("fail", not(gt("custom_policy_count", 0))),
      rule("warn", any(gt("no_custom_policy_application_count", 0), gt("custom_policy_without_finding_rules_count", 0))),
      rule("warn", incomplete("policies_complete", "applications_complete")),
      rule("pass", always),
    ],
    completeness: { policies_complete: POLICIES_COMPLETE, applications_complete: APPLICATIONS_COMPLETE },
    decision: "Manual when the policy list is unreadable or empty, since every Veracode account exposes the built-in policies. Fail when no policy is a custom (CUSTOMER type) policy. Warn when an application is assigned no custom policy, or a custom policy defines no finding rules. Warn instead of pass when the policy list is partial, or the application inventory is unreadable or partial. Otherwise pass, which an empty application inventory allows.",
    examples: [
      example("compliant", "pass", "Two custom policies define finding rules and every application is assigned one.", CUSTOM_POLICIES_HEALTHY),
      example("noncompliant", "fail", "Every policy is a built-in Veracode policy.", { ...CUSTOM_POLICIES_HEALTHY, custom_policy_count: 0 }),
      example("partial", "warn", "Three applications are assigned only built-in policies.", { ...CUSTOM_POLICIES_HEALTHY, no_custom_policy_application_count: 3 }),
      example("partial", "warn", "One custom policy defines no finding rules.", { ...CUSTOM_POLICIES_HEALTHY, custom_policy_without_finding_rules_count: 1 }),
      example("partial", "warn", "The application inventory was refused, so no assignment was checked.", { ...CUSTOM_POLICIES_HEALTHY, applications_complete: false }),
      example("partial", "warn", "The policy walk stopped at its page cap.", { ...CUSTOM_POLICIES_HEALTHY, policies_complete: false }),
      example("partial", "manual", "The policy list came back empty, though every account exposes the built-in policies.", {
        ...CUSTOM_POLICIES_HEALTHY,
        policy_count: 0,
        custom_policy_count: 0,
      }),
      example("unreadable", "manual", "The policy list was refused.", { policies_readable: false }),
    ],
  },
  {
    id: "VERACODE-20",
    control: 20,
    title: "Collections compliance posture",
    severity: "medium",
    owner: POLICY_COMPLIANCE,
    surfaces: ["applications"],
    inputs: [],
    rules: [rule("manual", always)],
    decision: "Always return manual, because the Collections API is not part of the published Veracode REST API reference the inspector uses, so a reviewer must export each application collection's aggregate compliance; the applications grouped by profile.business_unit.name with their DID_NOT_PASS counts are supporting evidence only.",
    examples: [example("partial", "manual", "Collection posture is left to a reviewer whatever the application inventory holds.", {})],
  },
];

const toCheck = (check: VeracodeCheck): BatchCheckDefinition => {
  const executable = deriveDecisionRules(check.id, check.rules);
  const [fedramp, cmmc, soc2, cis, pciDss, disaStig, irap, ismap] = VERACODE_FRAMEWORK_MAPPINGS[check.control];
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
    decisionRules: executable.rules,
    derivedFactRules: executable.derivedFactRules,
    ...(check.completeness ? { completeness: check.completeness } : {}),
    decision: check.decision,
    examples: check.examples,
  };
};

const checks: readonly BatchCheckDefinition[] = [...SCAN_COVERAGE_CHECKS, ...POLICY_COMPLIANCE_CHECKS].map(toCheck);
const idsFor = (owner: string): string[] => checks.filter((check) => check.owner === owner).map((check) => check.id);

const RECORD_KEY = "a record's key being the first of its guid, id, user_id, team_id, issue_id, and scan_id that is not null, else the whole record";
const halWalk = (surfaceIds: readonly string[], records: string, pageCap: number, probed: boolean, scope = ""): BatchPaginationDefinition => ({
  surfaceIds,
  cursorFields: ["page", "page.total_pages", "page.total_elements"],
  pageSize: 100,
  itemCap: "none",
  pageCap,
  totalSemantics: `${scope}Pages of 100 ${records} (size), indexed from 0 (page), up to ${pageCap} pages${probed ? "; the veracode_check_access probe reads only page 0" : ""}. A page's total_pages and total_elements replace the values read before when present, and no _links.next link is read. An entry that is not a JSON object is dropped without marking the list partial. The list is partial when ${walkPartial(pageCap)}.`,
  stopConditions: [
    "Once a page has reported total_pages, the page whose index plus one reaches the last reported total_pages",
    `Before any page has reported total_pages, a page holding fewer than 100 ${records}, entries that are not JSON objects not counting`,
    `A non-empty page whose ${records}' keys, in order, equal the previous page's, ${RECORD_KEY}; the repeated page is not kept, and the list is partial`,
    `${pageCap} pages read without another stop, which leaves the list partial unless the last reported total_pages was reached`,
    "A refused page, which makes the whole list a refusal",
  ],
});

const FRAMEWORK_REPORT_FILES = [
  "compliance/fedramp.md",
  "compliance/cmmc.md",
  "compliance/soc2.md",
  "compliance/cis-controls-v8.md",
  "compliance/pci-dss.md",
  "compliance/stig.md",
  "compliance/irap.md",
  "compliance/ismap.md",
];
const ASSESSMENT_FILES = ["scan-coverage", "policy-compliance", "findings-hygiene", "sca-posture", "access-controls"];
const OUTPUT = buildBatchOutputContract({
  files: [
    "QUICK_REFERENCE.md",
    "metadata.json",
    "core_data/access.json",
    ...ASSESSMENT_FILES.map((name) => `core_data/${name}.json`),
    ...ASSESSMENT_FILES.map((name) => `analysis/${name}.json`),
    "analysis/findings.json",
    "analysis/summary.md",
    "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md",
    ...FRAMEWORK_REPORT_FILES,
  ],
  conditionalFiles: ["_errors.log"],
  conditionalFileConditions: { "_errors.log": "Only when some reads fail but the bundle still completes." },
  overwritePolicy: "Allocate the resolved API base URL's host (with its port when it has one), lowercased with every run of characters outside a-z, 0-9, dot, underscore, and hyphen replaced by one hyphen, trimmed of leading and trailing hyphens, and cut to 80 characters (veracode when nothing is left), followed by -audit-bundle, or by that and the first of -2 through -50 whose directory and zip are both free, and fail rather than overwrite.",
  archivePairing: "Write a sibling zip named from the allocated bundle directory's name plus .zip in the output root.",
});

export const VERACODE_SPEC = buildBatchIntegrationSpec({
  slug: "veracode-sec-inspector",
  displayName: "Veracode Security Inspector",
  vendor: "Veracode",
  category: "application-security",
  summary: "Portable contract for the shipped Veracode scan coverage and policy compliance assessments over the Veracode Applications, Policy, Identity, and Dynamic Analysis REST APIs.",
  sourceModule: "cli/extensions/grc-tools/veracode.ts",
  baseServices: [APPLICATIONS_SERVICE, POLICY_SERVICE, IDENTITY_SERVICE, DYNAMIC_SERVICE],
  authentication: VERACODE_AUTH_RESOLVER,
  permissions: [
    {
      id: "api-user",
      kind: "role",
      value: "Any Veracode API user",
      unlocks: ["self"],
    },
    {
      id: "application-reader",
      kind: "role",
      value: "Security Insights or Reviewer API role",
      unlocks: ["applications", "policies", "sandboxes"],
      notes: "veracode_check_access names this role for applications and policies; the Applications REST API documentation names a user account with the Creator or Security Lead role.",
    },
    {
      id: "dynamic-analysis",
      kind: "license",
      value: "Dynamic Analysis license and the Security Insights API role",
      unlocks: ["dynamic_analyses", "dynamic_analysis_scans", "dynamic_scan_configurations"],
      notes: "veracode_check_access names this role; the Dynamic Analysis REST API documentation names an API user account with the Upload and Scan API role.",
    },
  ],
  surfaces: VERACODE_SURFACES,
  checks,
  tools: {
    veracode_check_access: [],
    veracode_assess_scan_coverage: idsFor(SCAN_COVERAGE),
    veracode_assess_policy_compliance: idsFor(POLICY_COMPLIANCE),
    veracode_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [
    halWalk(["applications", "policies", "dynamic_analyses"], "records", 50, true),
    halWalk(["sandboxes"], "sandboxes", 10, false, "Each sampled application's sandbox list is walked separately. "),
    halWalk(["dynamic_analysis_scans"], "scans", 5, false, "Each sampled analysis's scan list is walked separately. "),
    {
      surfaceIds: ["self"],
      cursorFields: [],
      pageSize: null,
      itemCap: "none",
      pageCap: 1,
      totalSemantics: "One read of the API user's own record.",
      stopConditions: ["The first response"],
    },
    {
      surfaceIds: ["dynamic_scan_configurations"],
      cursorFields: [],
      pageSize: null,
      itemCap: "none",
      pageCap: 1,
      totalSemantics: "One read of each inspected scan's configuration.",
      stopConditions: ["The first response"],
    },
  ],
  rateLimit: {
    documentedLimit: "Veracode documents 500 REST API calls per minute from one IP address, answering a 429 with a retry-after time in seconds beyond it; the collector reads neither the limit nor the retry-after time.",
    retryHeaders: [],
    retryableStatuses: [429],
    retryableStatusRanges: [{ from: 500, to: 599 }],
    backoffPolicy: "Retry 429, every status of 500 or above, network errors, and requests that time out up to 3 times after the first attempt, waiting 500, 1000, then 2000 milliseconds; Retry-After is ignored. A request times out after timeout_seconds, else VERACODE_TIMEOUT, else 30 seconds, truncated and clamped to 1 through 300. A 2xx body that is not JSON is a refusal and is not retried.",
  },
  runtimeBehavior: [],
  knownGaps: [
    "A list entry that is not a JSON object is dropped without marking the list partial, and before any page reports total_pages a full page holding one counts as short and ends the walk with the list complete.",
    "An empty 2xx list page, or one whose JSON is not an object, is read as a page holding no records, which ends the walk with the list complete when no total_pages has been reported.",
    "VERACODE-15 can pass when the application inventory is read and empty, though the other application checks treat an empty inventory as unverifiable.",
  ],
  sensitiveFields: ["api_key_id", "api_key_secret", "veracode_api_key_id", "veracode_api_key_secret", "Authorization", "authentications", "crawl_script_data"],
  credentialFormats: ["Veracode API key ID and hex API key secret, used to sign every request with VERACODE-HMAC-SHA-256"],
  output: {
    ...OUTPUT,
    recordSchemas: { ...OUTPUT.recordSchemas, pagination_state: ["items", "pagesFetched", "totalPages", "totalElements", "complete", "notes"] },
  },
  lastUpdated: "2026-10-18",
  findingPreviewLimit: 100,
  redaction: {
    projectionStage: "Responses are kept as read, except that each sampled analysis's scans are cut to scan_id and a scrubbed target_url, and each scan configuration to a summary that keeps the authentication method names but none of their contents. Every core_data and analysis JSON file is written through the credential pass: the value of each credential-named key, and the value member of an object whose name (else key) member is credential-named, becomes [REDACTED]; a string under a webhook-named key keeps only its URL's origin; a JWT-shaped string becomes [REDACTED]; and every other string loses URL userinfo, query, and fragment and has credential-shaped text scrubbed. metadata.json, analysis/summary.md, the compliance reports, and QUICK_REFERENCE.md are written as generated.",
    integrationRules: [
      "A refused response is reported with its status line and, when its body is JSON, the text of its message, error_description, error, and each _embedded.errors[] detail (else message) joined by semicolons, whitespace runs collapsed, cut to 240 characters, and scrubbed of the key ID and secret; a body that is not JSON is described by its media type and byte length and never echoed.",
      "A 2xx response whose body is not JSON is described by its media type and byte length and never echoed.",
      "A dataset that was not requested because the inventory it depends on was refused is exported as an explicit marker naming the reason, never as an empty dataset.",
    ],
  },
});
