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
// The credential records of at most this many active API accounts are read, the first in user list order.
export const MAX_CREDENTIAL_ACCOUNTS = 200;

const series = (items: readonly string[], conjunction = "and"): string =>
  items.length <= 2 ? items.join(` ${conjunction} `) : `${items.slice(0, -1).join(", ")}, ${conjunction} ${items[items.length - 1]}`;

const APPLICATIONS_SERVICE = "Veracode Applications REST API";
const POLICY_SERVICE = "Veracode Policy REST API";
const IDENTITY_SERVICE = "Veracode Identity REST API";
const DYNAMIC_SERVICE = "Veracode Dynamic Analysis REST API";
const FINDINGS_SERVICE = "Veracode Findings REST API";
const SUMMARY_REPORT_SERVICE = "Veracode Summary Report REST API";
const SCA_SERVICE = "Veracode SCA Agent REST API";
const APPLICATIONS_DOCS = "https://docs.veracode.com/r/c_apps_intro";
const POLICY_DOCS = "https://api.swaggerhub.com/apis/Veracode/veracode-policy_api_specification/1.0";
const IDENTITY_DOCS = "https://docs.veracode.com/r/c_identity_intro";
const DYNAMIC_DOCS = "https://docs.veracode.com/r/c_dynamic_intro";
const FINDINGS_DOCS = "https://docs.veracode.com/r/c_findings_v2_intro";
const SUMMARY_REPORT_DOCS = "https://docs.veracode.com/r/c_rest_summary_report_intro";
const SCA_DOCS = "https://docs.veracode.com/r/c_sourceclear_intro";
const API_HOST = "Use the resolved API base URL: base_url, else VERACODE_API_BASE_URL, else the region's host, with any query, fragment, and trailing slashes removed. The region is the region argument, else VERACODE_REGION, else us, trimmed and lowercased: us or commercial is https://api.veracode.com, eu, europe, or european is https://api.veracode.eu, and us-fed, fedramp, or federal is https://api.veracode.us.";
const API_HEADERS = ["Accept: application/json", "Authorization: VERACODE-HMAC-SHA-256 id={api_key_id},ts={timestamp},nonce={nonce},sig={signature}"];
const CREDENTIAL_PASS = "the export's credential pass";
const WALK_EXPORT = "every returned record with all its fields alongside pagesFetched, complete, and, when known, totalPages, totalElements, and notes";
const LIST_STAGE = `The collector exports the walk's result as read, ${WALK_EXPORT}, through ${CREDENTIAL_PASS}; decision facts read the listed fields.`;
const keyedWalkStage = (list: string, keyed: string, reads = "decision facts read the listed fields"): string =>
  `The collector exports ${list} as the walk returned it, ${WALK_EXPORT}, ${keyed}, through ${CREDENTIAL_PASS}; ${reads}.`;
const BY_APPLICATION = "keyed by the application's guid read as text (empty text when it has none)";
const BY_WORKSPACE = "keyed by the workspace's id read as text (empty text when it has none)";

const REFUSAL = "a status outside 200 through 299 after retries, or a 2xx body that is not JSON, is a refusal";
const halResponse = (key: string, records: string): string =>
  `A JSON object whose _embedded.${key} array holds ${records}, an entry that is not a JSON object being dropped (an _embedded that is itself an array is read in place of that array), and whose page object reports total_pages (else totalPages) and total_elements (else totalElements), each read as a number when present. An empty 2xx body, or JSON that is not an object, is read as a page holding no records; ${REFUSAL}.`;
const memberResponse = (members: readonly string[]): string =>
  `A JSON object carrying at least one of ${series(members, "or")}; any other 2xx body, an empty one included, is a refusal, as is a status outside 200 through 299 after retries.`;
const SELF_RESPONSE = memberResponse(USER_MEMBERS);
const CREDENTIAL_RESPONSE = memberResponse(API_CREDENTIAL_MEMBERS);
const SCAN_CONFIGURATION_RESPONSE = `A JSON object read for auth_configuration.authentications, whose members name the configured authentication methods, crawl_configuration.disabled and crawl_script_data, target_url (its url when it is an object), and scan_setting.allowed_hosts, else allowed_hosts. An empty 2xx body, or JSON that is not an object, is read as a configuration without authentication; ${REFUSAL}.`;
const SUMMARY_REPORT_RESPONSE = `A JSON object whose static_analysis.modules.module array holds one static module per JSON object entry, each read for loc, numflawssev5, and numflawssev4. An empty 2xx body, or JSON that is not an object, is read as a report without static modules; ${REFUSAL}.`;
const LINKED_PROJECTS_RESPONSE = `A JSON object whose linked_projects array holds one linked SCA agent project per JSON object entry. An empty 2xx body, or JSON that is not an object, is read as a response without linked projects; ${REFUSAL}.`;

const param = (
  name: string,
  location: RequestParameterContract["location"],
  value: string,
  required = true,
  when?: string,
): RequestParameterContract => ({ name, location, required, value, ...(when ? { when } : {}) });

const PAGE_INDEX = "The zero-based page index: 0 for the first page, then one more than the previous page's";
const HAL_PAGE_PARAMETERS: readonly RequestParameterContract[] = [param("page", "query", PAGE_INDEX), param("size", "query", "100")];
const pathId = (name: string, record: string, field = name.replace("application_", "")): RequestParameterContract =>
  param(name, "path", `The ${record}'s ${field} read as text and percent-encoded, empty when it has none`);

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
      "profile.teams",
      "profile.upload_and_scan_sca_enabled",
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
    `The collector exports each sampled application's sandbox records as read, ${BY_APPLICATION}, without the walk's pagination state, through ${CREDENTIAL_PASS}; decisions count the records and read no field.`,
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

const FINDINGS_HYGIENE_SURFACES: readonly BatchSurfaceDefinition[] = [
  surface(
    "findings",
    FINDINGS_SERVICE,
    FINDINGS_DOCS,
    "/appsec/v2/applications/{application_guid}/findings",
    [
      "issue_id",
      "finding_details.severity",
      "finding_status.status",
      "finding_status.resolution",
      "finding_status.resolution_status",
      "finding_status.first_found_date",
      "annotations.action",
      "annotations.comment",
    ],
    [pathId("application_guid", "sampled application"), param("include_annot", "query", "TRUE"), param("page", "query", PAGE_INDEX), param("size", "query", "500")],
    halResponse("findings", "one finding per entry"),
    keyedWalkStage("each sampled application's finding list", BY_APPLICATION),
  ),
  surface(
    "summary_reports",
    SUMMARY_REPORT_SERVICE,
    SUMMARY_REPORT_DOCS,
    "/appsec/v2/applications/{application_guid}/summary_report",
    ["static_analysis.modules.module.loc", "static_analysis.modules.module.numflawssev5", "static_analysis.modules.module.numflawssev4"],
    [pathId("application_guid", "sampled application")],
    SUMMARY_REPORT_RESPONSE,
    `The collector exports each sampled application's summary report as read, ${BY_APPLICATION}, through ${CREDENTIAL_PASS}; decision facts read the listed fields.`,
  ),
];

const WORKSPACE_ID = pathId("workspace_id", "sampled workspace", "id");
const workspaceIssues = (type: string, records: string, fields: readonly string[], member: string): BatchSurfaceDefinition =>
  surface(
    `sca_${type}_issues`,
    SCA_SERVICE,
    SCA_DOCS,
    `/srcclr/v3/workspaces/{workspace_id}/issues?type=${type}&status=open`,
    fields,
    [WORKSPACE_ID, ...HAL_PAGE_PARAMETERS],
    halResponse("issues", records),
    keyedWalkStage(`each sampled workspace's ${type} issue list`, `as the ${member} member of an entry ${BY_WORKSPACE}`),
  );

const SCA_POSTURE_SURFACES: readonly BatchSurfaceDefinition[] = [
  surface(
    "sca_workspaces",
    SCA_SERVICE,
    SCA_DOCS,
    "/srcclr/v3/workspaces",
    ["id", "name"],
    HAL_PAGE_PARAMETERS,
    halResponse("workspaces", "one SCA agent workspace per entry"),
    LIST_STAGE,
  ),
  workspaceIssues(
    "vulnerability",
    "one open vulnerability issue per entry",
    ["severity", "vulnerability.cvss3_score", "vulnerability.cvss2_score", "vulnerability.cve", "library.name"],
    "vulnerabilities",
  ),
  workspaceIssues("license", "one open license issue per entry", ["license.risk", "license.name", "library.name"], "licenses"),
  surface(
    "sca_libraries",
    SCA_SERVICE,
    SCA_DOCS,
    "/srcclr/v3/workspaces/{workspace_id}/libraries",
    [],
    [WORKSPACE_ID, ...HAL_PAGE_PARAMETERS],
    halResponse("libraries", "one library per entry"),
    keyedWalkStage("each sampled workspace's library list", `as the libraries member of an entry ${BY_WORKSPACE}`, "decisions count the records and read no field"),
  ),
  surface(
    "sca_application_projects",
    SCA_SERVICE,
    SCA_DOCS,
    "/srcclr/v3/applications/{application_guid}/projects",
    ["linked_projects.name", "linked_projects.id", "linked_projects.workspace.name", "linked_projects.last_scan_date"],
    [pathId("application_guid", "sampled application")],
    LINKED_PROJECTS_RESPONSE,
    `The collector exports each requested linked project response as read, ${BY_APPLICATION}, through ${CREDENTIAL_PASS}; decision facts read the listed fields. When no list was requested the dataset is a marker naming the reason, which calls the SCA Agent API not readable both when its workspace list was refused and when it held no workspace.`,
  ),
];

const ACCESS_CONTROL_SURFACES: readonly BatchSurfaceDefinition[] = [
  surface(
    "users",
    IDENTITY_SERVICE,
    IDENTITY_DOCS,
    "/api/authn/v2/users",
    [
      "user_id",
      "user_name",
      "email_address",
      "active",
      "login_enabled",
      "account_type",
      "api_user",
      "roles.role_name",
      "teams",
      "no_teams_required",
      "last_login",
      "saml_user",
    ],
    [param("detailed", "query", "true"), param("include_roles", "query", "true"), param("include_teams", "query", "true"), ...HAL_PAGE_PARAMETERS],
    halResponse("users", "one user per entry"),
    LIST_STAGE,
  ),
  surface(
    "teams",
    IDENTITY_SERVICE,
    IDENTITY_DOCS,
    "/api/authn/v2/teams",
    [],
    [
      param("all_for_org", "query", "true", false, "On every page until a page is refused with status 400 or 403, after which the walk restarts from page 0 without it"),
      ...HAL_PAGE_PARAMETERS,
    ],
    halResponse("teams", "one team per entry"),
    `The collector exports the walk's result as read, ${WALK_EXPORT}, through ${CREDENTIAL_PASS}; decisions count the records and read no field. After a restart without all_for_org, notes ends with "all_for_org=true was refused (<status>), so only teams the API user is a member of were listed and the team inventory is a partial view."`,
  ),
  surface(
    "roles",
    IDENTITY_SERVICE,
    IDENTITY_DOCS,
    "/api/authn/v2/roles",
    ["role_name", "ignore_team_restrictions"],
    HAL_PAGE_PARAMETERS,
    halResponse("roles", "one role per entry"),
    LIST_STAGE,
  ),
  surface(
    "api_credentials",
    IDENTITY_SERVICE,
    IDENTITY_DOCS,
    "/api/authn/v2/api_credentials/user_id/{user_id}",
    ["api_id", "created_ts", "expiration_ts", "revocation_ts", "last_used_ts"],
    [pathId("user_id", "sampled API account")],
    CREDENTIAL_RESPONSE,
    `The collector keeps each sampled API account's api_id, created_ts, expiration_ts, revocation_ts, and last_used_ts, each read as text, else null; every other field is dropped, and the records are exported keyed by the account's user_id read as text (empty text when it has none) through ${CREDENTIAL_PASS}. Decisions read created_ts, expiration_ts, and revocation_ts. When no record was requested the dataset is a marker naming the reason.`,
  ),
  surface(
    "self_api_credentials",
    IDENTITY_SERVICE,
    IDENTITY_DOCS,
    "/api/authn/v2/api_credentials",
    [],
    [],
    CREDENTIAL_RESPONSE,
    "Only veracode_check_access requests it, to report whether it is readable; the record is neither exported nor read for a decision.",
  ),
];

const VERACODE_SURFACES: readonly BatchSurfaceDefinition[] = [
  ...SCAN_COVERAGE_SURFACES,
  ...FINDINGS_HYGIENE_SURFACES,
  ...SCA_POSTURE_SURFACES,
  ...ACCESS_CONTROL_SURFACES,
];

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
const any = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "or", conditions });
const all = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "and", conditions });
const not = (condition: VerdictCondition): VerdictCondition => ({ op: "not", condition });
const always: VerdictCondition = { op: "always" };
const rule = (status: VerdictRule["status"], condition: VerdictCondition): VerdictRule => ({ status, condition });
const incomplete = (...complete: string[]): VerdictCondition =>
  complete.length === 1 ? ne(complete[0], true) : any(...complete.map((name) => ne(name, true)));

const AS_NUMBER = "read as a number (a finite number, or a string that is not blank and parses as one)";
const READS_AS_TEXT = "A value reads as text when it is a string that is not blank, trimmed, or a finite number, as ECMAScript writes it.";
const PARSES_AS_DATE = "A value parses as a date when it reads as text and ECMAScript Date.parse reads that text.";
const argument = (name: string, fallback: number, max: number, min = 1): string =>
  `${name} argument ${AS_NUMBER}, else ${fallback}, truncated to a whole number and clamped to ${min} through ${max}`;
const option = (name: string, fallback: number, max: number): string => `the ${argument(name, fallback, max)}`;
const IS_TRUE = "the boolean true or a string that trims to true in any letter case";
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
const SCAN_AUTH = `An inspected scan is unauthenticated when its configuration's auth_configuration.authentications is not a JSON object with at least one member, and crawl-disabled when it is not unauthenticated and its configuration's crawl_configuration.disabled is ${IS_TRUE}.`;
const limit = (name: string, fallback: number, max: number): string => `the ${name} argument ${AS_NUMBER}, else ${fallback}, clamped to 0 through ${max}`;
const FINDING_SAMPLE = `The sampled applications are the first N returned applications, N being ${option("max_applications", 100, 5000)}; each sampled application's finding list is read from GET /appsec/v2/applications/{application_guid}/findings with include_annot=TRUE, its findings being the entries that are JSON objects.`;
const AGED_SEVERITIES = series(Object.keys(FLAW_AGE_THRESHOLDS), "or");
const FLAW_AGE_LIMITS = series(Object.entries(FLAW_AGE_THRESHOLDS).reverse().map(([severity, days]) => `${days} days for severity ${severity}`));
const OPEN_FINDING = `A finding is open when its finding_status.status, read as text and uppercased, is OPEN and its finding_status.resolution, read as text and uppercased, is UNRESOLVED. ${READS_AS_TEXT}`;
const OVERDUE_FINDING = `An open finding is overdue when its finding_details.severity, ${AS_NUMBER}, is ${AGED_SEVERITIES} and its finding_status.first_found_date parses as a date that is more whole days before the assessment time than the limit for that severity: ${FLAW_AGE_LIMITS}. ${OPEN_FINDING} ${PARSES_AS_DATE} ${WHOLE_DAYS}`;
const MITIGATION_ANNOTATION = `A mitigation annotation is a JSON object entry of a finding's annotations whose action, read as text and uppercased, is ${series(MITIGATION_ACTIONS, "or")}. ${READS_AS_TEXT}`;
const FP_RATE = `An application's false positive rate is (F / N) * 100 in IEEE 754 double precision, N being the number of findings in its finding list and F the number of those with an annotation, a JSON object entry of their annotations, whose action, read as text and uppercased, is FP. ${READS_AS_TEXT}`;
const SUMMARY_SAMPLE = `The sampled applications are the first N returned applications, N being ${option("max_applications", 100, 5000)}; each sampled application's summary report is read from GET /appsec/v2/applications/{application_guid}/summary_report.`;
const STATIC_MODULES = `A summary report's static modules are the JSON object entries of its static_analysis.modules.module array, and its lines of code are the sum of their loc values, each ${AS_NUMBER}, else 0. A summary report counts lines of code when it has a static module and its lines of code are more than 0. ${SUMMARY_SAMPLE}`;
const FLAW_DENSITY = `A summary report's flaw density is H / (L / 1000) in IEEE 754 double precision, L being its lines of code and H the sum of its static modules' numflawssev5 and numflawssev4 values, each ${AS_NUMBER}, else 0. ${STATIC_MODULES}`;
const WORKSPACE_SAMPLE = `The sampled workspaces are the first N returned workspaces, N being ${option("max_workspaces", 25, 500)}. Each sampled workspace in turn has its open vulnerability issues read from GET /srcclr/v3/workspaces/{workspace_id}/issues with type=vulnerability and status=open, its open license issues from the same path with type=license and status=open, and its libraries from GET /srcclr/v3/workspaces/{workspace_id}/libraries, each list's records being the entries that are JSON objects.`;
const UPLOAD_SCAN_SCA = `An application has upload-and-scan SCA when its profile.upload_and_scan_sca_enabled is ${IS_TRUE}.`;
const LINKED_PROJECT_SAMPLE = `${UPLOAD_SCAN_SCA} The sampled applications are the first N returned applications, N being ${option("max_applications", 100, 5000)}. When the GET /srcclr/v3/workspaces walk returned without a refusal and kept a workspace, each sampled application without upload-and-scan SCA has its linked project list read from GET /srcclr/v3/applications/{application_guid}/projects, its linked projects being the JSON object entries of the response's linked_projects array; otherwise no linked project list is requested.`;
const USER_KINDS = `A user is active when its active is ${IS_TRUE}, and an API account when its account_type, read as text and uppercased, is API or its api_user is ${IS_TRUE}. An active human is an active user that is not an API account and whose login_enabled is ${IS_TRUE}. ${READS_AS_TEXT}`;
const ROLE_NAMES = "A user's role names are the role_name values, read as text, of the JSON object entries of its roles.";
const TEAM_LIST = "The team list is the GET /api/authn/v2/teams walk with all_for_org=true, or, when a page of that walk is refused with status 400 or 403, the same walk without all_for_org, which lists only the teams the API user is a member of.";
const CREDENTIAL_SAMPLE = `The sampled API accounts are the first ${MAX_CREDENTIAL_ACCOUNTS} active API accounts in user list order, and each has its credential record read from GET /api/authn/v2/api_credentials/user_id/{user_id}. ${USER_KINDS}`;
const CREDENTIAL_STATES = `A credential record is revoked when its revocation_ts reads as text, and dated when its created_ts and its expiration_ts both parse as dates. ${PARSES_AS_DATE}`;

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
  finding_list_read_count: `Number of sampled applications whose finding list was read without a refusal. ${FINDING_SAMPLE}`,
  finding_count: `Number of findings in the finding lists read without a refusal. ${FINDING_SAMPLE}`,
  overdue_finding_count: `Number of overdue findings in the finding lists read without a refusal. ${OVERDUE_FINDING} ${FINDING_SAMPLE}`,
  undated_open_finding_count: `Number of open findings in the finding lists read without a refusal whose finding_details.severity, ${AS_NUMBER}, is ${AGED_SEVERITIES} and whose finding_status.first_found_date does not parse as a date. ${OPEN_FINDING} ${PARSES_AS_DATE} ${FINDING_SAMPLE}`,
  pending_mitigation_count: `Number of findings in the finding lists read without a refusal whose finding_status.resolution_status, read as text and uppercased, is PROPOSED. ${READS_AS_TEXT} ${FINDING_SAMPLE}`,
  unjustified_mitigation_count: `Number of mitigation annotations in the finding lists read without a refusal whose comment does not read as text. ${MITIGATION_ANNOTATION} ${FINDING_SAMPLE}`,
  finding_reads_complete: "Finding read coverage.",
  fp_rate_exceeding_application_count: `Number of sampled applications whose finding list was read without a refusal and holds a finding, and whose false positive rate is more than M, M being ${limit("max_fp_rate_percent", 20, 100)}. ${FP_RATE} ${FINDING_SAMPLE}`,
  fp_rate_coverage_complete: "False positive rate coverage.",
  summary_report_read_count: `Number of sampled applications whose summary report was read without a refusal. ${SUMMARY_SAMPLE}`,
  density_evaluated_application_count: `Number of sampled applications whose summary report was read without a refusal and counts lines of code. ${STATIC_MODULES}`,
  density_exceeding_application_count: `Number of sampled applications whose summary report was read without a refusal, counts lines of code, and has a flaw density of more than D, D being ${limit("max_flaw_density_per_kloc", 1, 1000)}. ${FLAW_DENSITY}`,
  no_loc_application_count: `Number of sampled applications whose summary report was read without a refusal and does not count lines of code. ${STATIC_MODULES}`,
  summary_reports_complete: "Summary report coverage.",
  sca_workspaces_readable: "True when the GET /srcclr/v3/workspaces walk returned without a refusal.",
  sca_workspace_count: "Number of SCA agent workspaces the walk kept, entries that are not JSON objects being dropped.",
  vulnerability_list_read_count: `Number of sampled workspaces whose vulnerability issue list was read without a refusal. ${WORKSPACE_SAMPLE}`,
  high_severity_issue_count: `Number of issues in the vulnerability issue lists read without a refusal whose score is at least T, T being ${limit("sca_cvss_threshold", 7, 10)}; an issue's score is its severity, else its vulnerability.cvss3_score, else its vulnerability.cvss2_score, the first of them that reads as a number (a finite number, or a string that is not blank and parses as one), and an issue with none has no score. ${WORKSPACE_SAMPLE}`,
  library_count: `Number of libraries in the library lists read without a refusal, counting only sampled workspaces whose vulnerability issue list was read without a refusal. ${WORKSPACE_SAMPLE}`,
  vulnerability_reads_complete: "Vulnerability read coverage.",
  license_list_read_count: `Number of sampled workspaces whose license issue list was read without a refusal. ${WORKSPACE_SAMPLE}`,
  high_risk_license_issue_count: `Number of issues in the license issue lists read without a refusal whose license.risk, read as text and uppercased, is HIGH. ${READS_AS_TEXT} ${WORKSPACE_SAMPLE}`,
  unknown_risk_license_issue_count: `Number of issues in the license issue lists read without a refusal whose license.risk does not read as text or, read as text and uppercased, is UNKNOWN. ${READS_AS_TEXT} ${WORKSPACE_SAMPLE}`,
  license_reads_complete: "License read coverage.",
  sca_covered_application_count: `Number of sampled applications that have upload-and-scan SCA, or whose linked project list was read without a refusal and holds a linked project. ${LINKED_PROJECT_SAMPLE}`,
  sca_uncovered_application_count: `Number of sampled applications without upload-and-scan SCA whose linked project list was read without a refusal and holds no linked project. ${LINKED_PROJECT_SAMPLE}`,
  sca_unchecked_application_count: `Number of sampled applications without upload-and-scan SCA whose linked project list was not requested because the GET /srcclr/v3/workspaces walk was refused or kept no workspace. ${LINKED_PROJECT_SAMPLE}`,
  linked_project_reads_complete: "Linked project read coverage.",
  users_readable: "True when the GET /api/authn/v2/users walk returned without a refusal.",
  user_count: "Number of users the walk kept, entries that are not JSON objects being dropped.",
  roles_readable: "True when the GET /api/authn/v2/roles walk returned without a refusal.",
  role_count: "Number of roles the walk kept, entries that are not JSON objects being dropped.",
  teams_readable: `True when the team list was read without a refusal. ${TEAM_LIST}`,
  team_count: `Number of teams the team list kept, entries that are not JSON objects being dropped. ${TEAM_LIST}`,
  teams_member_only: `True when the team list was read by the walk without all_for_org. ${TEAM_LIST}`,
  unrestricted_user_count: `Number of active humans with a role name equal to the role_name, read as text, of a returned role whose ignore_team_restrictions is ${IS_TRUE}. ${USER_KINDS} ${ROLE_NAMES}`,
  max_unrestricted_users: `The ${argument("max_unrestricted_users", 10, 10000, 0)}.`,
  application_without_team_count: "Number of applications the GET /appsec/v1/applications walk kept whose profile.teams holds no JSON object entry; 0 when that walk was refused.",
  team_scope_complete: "Team access coverage.",
  administrator_count: `Number of active users, API accounts included, with a role name that is administrator in any letter case. ${USER_KINDS} ${ROLE_NAMES}`,
  max_admins: `The ${argument("max_admins", 5, 10000, 0)}.`,
  inactive_user_count: `Number of active humans whose last_login parses as a date more than N whole days before the assessment time, N being ${option("inactive_days", 90, 3650)}. ${USER_KINDS} ${PARSES_AS_DATE} ${WHOLE_DAYS}`,
  users_without_last_login_count: `Number of active humans whose last_login does not parse as a date. ${USER_KINDS} ${PARSES_AS_DATE}`,
  api_account_without_team_count: `Number of active API accounts whose teams holds no JSON object entry and whose no_teams_required is not ${IS_TRUE}. ${USER_KINDS}`,
  users_complete: "User list coverage.",
  active_api_account_count: `Number of active API accounts among the users the walk kept. ${USER_KINDS}`,
  credential_record_read_count: `Number of sampled API accounts whose credential record was read without a refusal. ${CREDENTIAL_SAMPLE}`,
  aged_credential_count: `Number of credential records read without a refusal that are unrevoked and dated and whose created_ts is more than N whole days before the assessment time, N being ${option("max_credential_age_days", 365, 3650)}. ${CREDENTIAL_STATES} ${CREDENTIAL_SAMPLE} ${WHOLE_DAYS}`,
  undated_credential_count: `Number of credential records read without a refusal that are unrevoked and not dated. ${CREDENTIAL_STATES} ${CREDENTIAL_SAMPLE}`,
  expired_credential_count: `Number of credential records read without a refusal that are unrevoked and dated and whose expiration_ts is before the assessment time, whatever their age. ${CREDENTIAL_STATES} ${CREDENTIAL_SAMPLE}`,
  credential_reads_complete: "API credential read coverage.",
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
const INVENTORY_UNCOVERED = `the inventory read was refused or is partial because ${walkPartial(50)}, the inventory holds more applications than were sampled`;
const SANDBOX_READS_COMPLETE: BatchCompletenessDefinition = {
  semantics: `false when the sandbox reads do not cover the whole application inventory: ${INVENTORY_UNCOVERED}, or a sampled application's sandbox list was refused. A sandbox list that stopped at its 10-page cap still holds records, so its truncation does not lower this fact. ${SANDBOX_SAMPLE}`,
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
const FINDING_SOURCES: BatchCompletenessDefinition["sources"] = [
  { surfaceId: "applications", falseWhen: ["truncated", "error", "denied"] },
  { surfaceId: "findings", falseWhen: ["truncated", "error", "denied", "not-collected"] },
];
const FINDING_READS_COMPLETE: BatchCompletenessDefinition = {
  semantics: `false when the finding reads do not cover the whole application inventory: ${INVENTORY_UNCOVERED}, or a sampled application's finding list was refused or is partial because ${walkPartial(50)}. ${FINDING_SAMPLE}`,
  sources: FINDING_SOURCES,
};
const FP_RATE_COVERAGE_COMPLETE: BatchCompletenessDefinition = {
  semantics: `false when the false positive rates do not cover the whole application inventory: ${INVENTORY_UNCOVERED}, a sampled application's finding list was refused, or a finding list that holds a finding is partial because ${walkPartial(50)}. A partial finding list that holds no finding does not lower this fact. ${FINDING_SAMPLE}`,
  sources: FINDING_SOURCES,
};
const SUMMARY_REPORTS_COMPLETE: BatchCompletenessDefinition = {
  semantics: `false when the summary reports do not cover the whole application inventory: ${INVENTORY_UNCOVERED}, or a sampled application's summary report was refused. ${SUMMARY_SAMPLE}`,
  sources: [
    { surfaceId: "applications", falseWhen: ["truncated", "error", "denied"] },
    { surfaceId: "summary_reports", falseWhen: ["error", "denied", "not-collected"] },
  ],
};
const WORKSPACES_UNCOVERED = `the workspace list read was refused or is partial because ${walkPartial(50)}; the list holds more workspaces than were sampled`;
const VULNERABILITY_READS_COMPLETE: BatchCompletenessDefinition = {
  semantics: `false when the vulnerability reads do not cover every workspace: ${WORKSPACES_UNCOVERED}; a sampled workspace's vulnerability issue list was refused or is partial because ${walkPartial(20)}; or a sampled workspace whose vulnerability issue list was read had its library list refused, or partial because ${walkPartial(5)}. ${WORKSPACE_SAMPLE}`,
  sources: [
    { surfaceId: "sca_workspaces", falseWhen: ["truncated", "error", "denied"] },
    { surfaceId: "sca_vulnerability_issues", falseWhen: ["truncated", "error", "denied", "not-collected"] },
    { surfaceId: "sca_libraries", falseWhen: ["truncated", "error", "denied", "not-collected"] },
  ],
};
const LICENSE_READS_COMPLETE: BatchCompletenessDefinition = {
  semantics: `false when the license reads do not cover every workspace: ${WORKSPACES_UNCOVERED}; or a sampled workspace's license issue list was refused or is partial because ${walkPartial(20)}. ${WORKSPACE_SAMPLE}`,
  sources: [
    { surfaceId: "sca_workspaces", falseWhen: ["truncated", "error", "denied"] },
    { surfaceId: "sca_license_issues", falseWhen: ["truncated", "error", "denied", "not-collected"] },
  ],
};
const LINKED_PROJECT_READS_COMPLETE: BatchCompletenessDefinition = {
  semantics: `false when the coverage reads do not cover the whole application inventory: ${INVENTORY_UNCOVERED}, or a sampled application without upload-and-scan SCA did not have its linked project list read, because that read was refused or because the GET /srcclr/v3/workspaces walk was refused or kept no workspace. ${LINKED_PROJECT_SAMPLE}`,
  sources: [
    { surfaceId: "applications", falseWhen: ["truncated", "error", "denied"] },
    { surfaceId: "sca_workspaces", falseWhen: ["error", "denied"] },
    { surfaceId: "sca_application_projects", falseWhen: ["error", "denied", "not-collected"] },
  ],
};
const USERS_COMPLETE = halWalkComplete("users", "user list");
const TEAM_SCOPE_COMPLETE: BatchCompletenessDefinition = {
  semantics: `false when the team access reads do not cover the whole organization: the user, role, or team list read was refused or is partial because ${walkPartial(50)}; the team list was read without all_for_org, so it lists only the API user's own teams; or the application inventory read was refused or is partial because ${walkPartial(50)}. ${TEAM_LIST}`,
  sources: [
    { surfaceId: "users", falseWhen: ["truncated", "error", "denied"] },
    { surfaceId: "roles", falseWhen: ["truncated", "error", "denied"] },
    { surfaceId: "teams", falseWhen: ["truncated", "error", "denied"] },
    { surfaceId: "applications", falseWhen: ["truncated", "error", "denied"] },
  ],
};
const CREDENTIAL_READS_COMPLETE: BatchCompletenessDefinition = {
  semantics: `false when the credential reads do not cover every active API account: the user list read was refused or is partial because ${walkPartial(50)}; the user list holds more than ${MAX_CREDENTIAL_ACCOUNTS} active API accounts; or a sampled API account's credential record was refused. ${CREDENTIAL_SAMPLE}`,
  sources: [
    { surfaceId: "users", falseWhen: ["truncated", "error", "denied"] },
    { surfaceId: "api_credentials", falseWhen: ["error", "denied", "not-collected"] },
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

const FINDINGS_HYGIENE = "veracode_assess_findings_hygiene";
const FINDING_LISTS_GATE = [
  ...APPLICATIONS_GATE,
  rule("manual", not(gt("finding_list_read_count", 0))),
];
const FINDING_LISTS_READ = { ...APPLICATIONS_READ, finding_list_read_count: 12, finding_count: 340 };
const NO_FINDINGS = { finding_count: 0 };
const REFUSED_FINDING_LISTS = { finding_list_read_count: 0, finding_count: 0 };
const AGING_HEALTHY = { ...FINDING_LISTS_READ, overdue_finding_count: 0, undated_open_finding_count: 0, finding_reads_complete: true };
const MITIGATIONS_HEALTHY = { ...FINDING_LISTS_READ, pending_mitigation_count: 0, unjustified_mitigation_count: 0, finding_reads_complete: true };
const FP_RATES_HEALTHY = { ...FINDING_LISTS_READ, fp_rate_exceeding_application_count: 0, fp_rate_coverage_complete: true };
const DENSITY_HEALTHY = {
  ...APPLICATIONS_READ,
  summary_report_read_count: 12,
  density_evaluated_application_count: 12,
  density_exceeding_application_count: 0,
  no_loc_application_count: 0,
  summary_reports_complete: true,
};

const FINDINGS_HYGIENE_CHECKS: readonly VeracodeCheck[] = [
  {
    id: "VERACODE-03",
    control: 3,
    title: "Flaw aging",
    severity: "high",
    owner: FINDINGS_HYGIENE,
    surfaces: ["applications", "findings"],
    inputs: [
      "applications_readable",
      "application_count",
      "finding_list_read_count",
      "finding_count",
      "overdue_finding_count",
      "undated_open_finding_count",
      "finding_reads_complete",
    ],
    rules: [
      ...FINDING_LISTS_GATE,
      rule("fail", gt("overdue_finding_count", 0)),
      rule("warn", gt("undated_open_finding_count", 0)),
      rule("manual", not(gt("finding_count", 0))),
      rule("warn", incomplete("finding_reads_complete")),
      rule("pass", always),
    ],
    completeness: { finding_reads_complete: FINDING_READS_COMPLETE },
    decision: `Manual when the application inventory is unreadable or empty, or no sampled application's finding list could be read. Fail when an open, unresolved finding has been open longer than its severity allows: ${FLAW_AGE_LIMITS}. Warn when such a finding carries no readable first_found_date. Otherwise manual when the finding lists read hold no finding, since an empty list does not show that flaws are remediated. Warn instead of pass when the finding reads do not cover the whole application inventory. Otherwise pass.`,
    examples: [
      example("compliant", "pass", "Every open finding is within its severity's age limit.", AGING_HEALTHY),
      example("noncompliant", "fail", "Three open Very High findings have been open for more than 30 days.", { ...AGING_HEALTHY, overdue_finding_count: 3 }),
      example("partial", "warn", "Two open findings carry no first_found_date, so they cannot be aged.", { ...AGING_HEALTHY, undated_open_finding_count: 2 }),
      example("partial", "warn", "One application's finding list stopped at its page cap.", { ...AGING_HEALTHY, finding_reads_complete: false }),
      example("partial", "manual", "The sampled applications returned no findings, so there is nothing to age.", { ...AGING_HEALTHY, ...NO_FINDINGS }),
      example("unreadable", "manual", "Every sampled application's finding list was refused.", {
        ...AGING_HEALTHY,
        ...REFUSED_FINDING_LISTS,
        finding_reads_complete: false,
      }),
      EMPTY_APPLICATIONS,
      UNREADABLE_APPLICATIONS,
    ],
  },
  {
    id: "VERACODE-12",
    control: 12,
    title: "Mitigation approval workflow",
    severity: "high",
    owner: FINDINGS_HYGIENE,
    surfaces: ["applications", "findings"],
    inputs: [
      "applications_readable",
      "application_count",
      "finding_list_read_count",
      "finding_count",
      "pending_mitigation_count",
      "unjustified_mitigation_count",
      "finding_reads_complete",
    ],
    rules: [
      ...FINDING_LISTS_GATE,
      rule("manual", not(gt("finding_count", 0))),
      rule("fail", any(gt("pending_mitigation_count", 0), gt("unjustified_mitigation_count", 0))),
      rule("warn", incomplete("finding_reads_complete")),
      rule("pass", always),
    ],
    completeness: { finding_reads_complete: FINDING_READS_COMPLETE },
    decision: "Manual when the application inventory is unreadable or empty, no sampled application's finding list could be read, or the finding lists read hold no finding. Fail when a mitigation is proposed but not reviewed, or a mitigation annotation carries no justification comment. Warn instead of pass when the finding reads do not cover the whole application inventory. Otherwise pass.",
    examples: [
      example("compliant", "pass", "No mitigation awaits review and every mitigation annotation carries a comment.", MITIGATIONS_HEALTHY),
      example("noncompliant", "fail", "Four mitigations are proposed but not reviewed.", { ...MITIGATIONS_HEALTHY, pending_mitigation_count: 4 }),
      example("noncompliant", "fail", "Two accepted-risk annotations carry no justification comment.", { ...MITIGATIONS_HEALTHY, unjustified_mitigation_count: 2 }),
      example("partial", "warn", "The inventory holds more applications than max_applications lets the assessment sample.", {
        ...MITIGATIONS_HEALTHY,
        finding_reads_complete: false,
      }),
      example("partial", "manual", "The sampled applications returned no findings, so there is no mitigation to audit.", { ...MITIGATIONS_HEALTHY, ...NO_FINDINGS }),
      example("unreadable", "manual", "Every sampled application's finding list was refused.", {
        ...MITIGATIONS_HEALTHY,
        ...REFUSED_FINDING_LISTS,
        finding_reads_complete: false,
      }),
      EMPTY_APPLICATIONS,
      UNREADABLE_APPLICATIONS,
    ],
  },
  {
    id: "VERACODE-16",
    control: 16,
    title: "Finding false positive rate",
    severity: "medium",
    owner: FINDINGS_HYGIENE,
    surfaces: ["applications", "findings"],
    inputs: [
      "applications_readable",
      "application_count",
      "finding_list_read_count",
      "finding_count",
      "fp_rate_exceeding_application_count",
      "fp_rate_coverage_complete",
    ],
    rules: [
      ...FINDING_LISTS_GATE,
      rule("manual", not(gt("finding_count", 0))),
      rule("warn", gt("fp_rate_exceeding_application_count", 0)),
      rule("warn", incomplete("fp_rate_coverage_complete")),
      rule("pass", always),
    ],
    completeness: { fp_rate_coverage_complete: FP_RATE_COVERAGE_COMPLETE },
    decision: "Manual when the application inventory is unreadable or empty, no sampled application's finding list could be read, or the finding lists read hold no finding. Warn when an application marks more than max_fp_rate_percent percent of its findings with an FP mitigation annotation, which may point to scan tuning issues. Warn instead of pass when the false positive rates do not cover the whole application inventory. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Every application with findings stays at or below max_fp_rate_percent.", FP_RATES_HEALTHY),
      example("noncompliant", "warn", "Two applications mark more than max_fp_rate_percent of their findings as false positives.", {
        ...FP_RATES_HEALTHY,
        fp_rate_exceeding_application_count: 2,
      }),
      example("partial", "warn", "One sampled application's finding list was refused.", {
        ...FP_RATES_HEALTHY,
        finding_list_read_count: 11,
        fp_rate_coverage_complete: false,
      }),
      example("partial", "manual", "The sampled applications returned no findings, so no false positive rate exists.", { ...FP_RATES_HEALTHY, ...NO_FINDINGS }),
      example("unreadable", "manual", "Every sampled application's finding list was refused.", {
        ...FP_RATES_HEALTHY,
        ...REFUSED_FINDING_LISTS,
        fp_rate_coverage_complete: false,
      }),
      EMPTY_APPLICATIONS,
      UNREADABLE_APPLICATIONS,
    ],
  },
  {
    id: "VERACODE-17",
    control: 17,
    title: "Very High/High flaw density",
    severity: "medium",
    owner: FINDINGS_HYGIENE,
    surfaces: ["applications", "summary_reports"],
    inputs: [
      "applications_readable",
      "application_count",
      "summary_report_read_count",
      "density_evaluated_application_count",
      "density_exceeding_application_count",
      "no_loc_application_count",
      "summary_reports_complete",
    ],
    rules: [
      ...APPLICATIONS_GATE,
      rule("manual", not(gt("summary_report_read_count", 0))),
      rule("fail", gt("density_exceeding_application_count", 0)),
      rule("manual", not(gt("density_evaluated_application_count", 0))),
      rule("warn", gt("no_loc_application_count", 0)),
      rule("warn", incomplete("summary_reports_complete")),
      rule("pass", always),
    ],
    completeness: { summary_reports_complete: SUMMARY_REPORTS_COMPLETE },
    decision: "Manual when the application inventory is unreadable or empty, or no sampled application's summary report could be read. Fail when an application has more than max_flaw_density_per_kloc Very High and High static flaws per thousand lines of code. Otherwise manual when no summary report exposes static module lines of code. Warn when an application's summary report exposes none. Warn instead of pass when the summary reports do not cover the whole application inventory. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Every application with static module data stays within max_flaw_density_per_kloc.", DENSITY_HEALTHY),
      example("noncompliant", "fail", "One application has 2.4 Very High and High flaws per thousand lines of code.", {
        ...DENSITY_HEALTHY,
        density_exceeding_application_count: 1,
      }),
      example("partial", "warn", "Two applications' summary reports expose no static module lines of code.", {
        ...DENSITY_HEALTHY,
        density_evaluated_application_count: 10,
        no_loc_application_count: 2,
      }),
      example("partial", "warn", "One sampled application's summary report was refused.", {
        ...DENSITY_HEALTHY,
        summary_report_read_count: 11,
        density_evaluated_application_count: 11,
        summary_reports_complete: false,
      }),
      example("partial", "manual", "No summary report exposes static module lines of code, so no density can be computed.", {
        ...DENSITY_HEALTHY,
        density_evaluated_application_count: 0,
        no_loc_application_count: 12,
      }),
      example("unreadable", "manual", "Every sampled application's summary report was refused.", {
        ...DENSITY_HEALTHY,
        summary_report_read_count: 0,
        density_evaluated_application_count: 0,
        summary_reports_complete: false,
      }),
      EMPTY_APPLICATIONS,
      UNREADABLE_APPLICATIONS,
    ],
  },
];

const SCA_POSTURE = "veracode_assess_sca_posture";
const SCA_UNAVAILABLE = any(ne("sca_workspaces_readable", true), not(gt("sca_workspace_count", 0)));
const SCA_WORKSPACES_GATE = [rule("manual", ne("sca_workspaces_readable", true)), rule("manual", not(gt("sca_workspace_count", 0)))];
const SCA_WORKSPACES_READ = { sca_workspaces_readable: true, sca_workspace_count: 4 };
const NO_SCA_WORKSPACES = { sca_workspaces_readable: true, sca_workspace_count: 0 };
const REFUSED_SCA_WORKSPACES = { sca_workspaces_readable: false, sca_workspace_count: 0 };
const EMPTY_SCA_WORKSPACES = example("partial", "manual", "The SCA workspace list came back empty, so agent-based SCA is treated as not applicable rather than compliant.", NO_SCA_WORKSPACES);
const UNREADABLE_SCA_WORKSPACES = example("unreadable", "manual", "The SCA workspace list was refused, which can mean agent-based SCA is unlicensed.", REFUSED_SCA_WORKSPACES);
const VULNERABILITIES_HEALTHY = {
  ...SCA_WORKSPACES_READ,
  vulnerability_list_read_count: 4,
  high_severity_issue_count: 0,
  library_count: 230,
  vulnerability_reads_complete: true,
};
const LICENSES_HEALTHY = {
  ...SCA_WORKSPACES_READ,
  license_list_read_count: 4,
  high_risk_license_issue_count: 0,
  unknown_risk_license_issue_count: 0,
  license_reads_complete: true,
};
const SCA_COVERAGE_HEALTHY = {
  ...APPLICATIONS_READ,
  ...SCA_WORKSPACES_READ,
  sca_covered_application_count: 12,
  sca_uncovered_application_count: 0,
  sca_unchecked_application_count: 0,
  linked_project_reads_complete: true,
};

const SCA_POSTURE_CHECKS: readonly VeracodeCheck[] = [
  {
    id: "VERACODE-05",
    control: 5,
    title: "SCA library currency",
    severity: "high",
    owner: SCA_POSTURE,
    surfaces: ["sca_workspaces", "sca_vulnerability_issues", "sca_libraries"],
    inputs: [
      "sca_workspaces_readable",
      "sca_workspace_count",
      "vulnerability_list_read_count",
      "high_severity_issue_count",
      "library_count",
      "vulnerability_reads_complete",
    ],
    rules: [
      ...SCA_WORKSPACES_GATE,
      rule("manual", not(gt("vulnerability_list_read_count", 0))),
      rule("fail", gt("high_severity_issue_count", 0)),
      rule("manual", not(gt("library_count", 0))),
      rule("warn", incomplete("vulnerability_reads_complete")),
      rule("pass", always),
    ],
    completeness: { vulnerability_reads_complete: VULNERABILITY_READS_COMPLETE },
    decision: "Manual when the SCA workspace list is refused or empty, which can mean agent-based SCA is unlicensed or unused, or when no sampled workspace's vulnerability issue list could be read. Fail when an open vulnerability issue scores at or above sca_cvss_threshold. Otherwise manual when no library was read in the workspaces whose issues were read, since it is then unknown whether any scan populated them. Warn instead of pass when the vulnerability reads do not cover every workspace. Otherwise pass.",
    examples: [
      example("compliant", "pass", "No open vulnerability issue reaches sca_cvss_threshold, and the sampled workspaces hold scanned libraries.", VULNERABILITIES_HEALTHY),
      example("noncompliant", "fail", "Six open vulnerability issues score at or above sca_cvss_threshold.", { ...VULNERABILITIES_HEALTHY, high_severity_issue_count: 6 }),
      example("partial", "warn", "One sampled workspace's library list stopped at its page cap.", { ...VULNERABILITIES_HEALTHY, vulnerability_reads_complete: false }),
      example("partial", "manual", "No open vulnerability issue was returned, but no library was read either, so the workspaces may never have been scanned.", {
        ...VULNERABILITIES_HEALTHY,
        library_count: 0,
      }),
      example("unreadable", "manual", "Every sampled workspace's vulnerability issue list was refused.", {
        ...VULNERABILITIES_HEALTHY,
        vulnerability_list_read_count: 0,
        library_count: 0,
        vulnerability_reads_complete: false,
      }),
      EMPTY_SCA_WORKSPACES,
      UNREADABLE_SCA_WORKSPACES,
    ],
  },
  {
    id: "VERACODE-06",
    control: 6,
    title: "SCA license risk",
    severity: "medium",
    owner: SCA_POSTURE,
    surfaces: ["sca_workspaces", "sca_license_issues"],
    inputs: [
      "sca_workspaces_readable",
      "sca_workspace_count",
      "license_list_read_count",
      "high_risk_license_issue_count",
      "unknown_risk_license_issue_count",
      "license_reads_complete",
    ],
    rules: [
      ...SCA_WORKSPACES_GATE,
      rule("manual", not(gt("license_list_read_count", 0))),
      rule("fail", gt("high_risk_license_issue_count", 0)),
      rule("warn", gt("unknown_risk_license_issue_count", 0)),
      rule("warn", incomplete("license_reads_complete")),
      rule("pass", always),
    ],
    completeness: { license_reads_complete: LICENSE_READS_COMPLETE },
    decision: "Manual when the SCA workspace list is refused or empty, which can mean agent-based SCA is unlicensed or unused, or when no sampled workspace's license issue list could be read. Fail when an open license issue carries HIGH license risk (restrictive or copyleft). Warn when an open license issue carries an UNKNOWN or missing risk rating, which needs review. Warn instead of pass when the license reads do not cover every workspace. Otherwise pass, including when the license issue lists read are empty.",
    examples: [
      example("compliant", "pass", "No open license issue carries a HIGH, UNKNOWN, or missing license risk.", LICENSES_HEALTHY),
      example("noncompliant", "fail", "Three open license issues carry HIGH license risk.", { ...LICENSES_HEALTHY, high_risk_license_issue_count: 3 }),
      example("partial", "warn", "Two open license issues carry no license risk rating.", { ...LICENSES_HEALTHY, unknown_risk_license_issue_count: 2 }),
      example("partial", "warn", "The workspace list holds more workspaces than max_workspaces lets the assessment sample.", {
        ...LICENSES_HEALTHY,
        license_reads_complete: false,
      }),
      example("unreadable", "manual", "Every sampled workspace's license issue list was refused.", {
        ...LICENSES_HEALTHY,
        license_list_read_count: 0,
        license_reads_complete: false,
      }),
      EMPTY_SCA_WORKSPACES,
      UNREADABLE_SCA_WORKSPACES,
    ],
  },
  {
    id: "VERACODE-18",
    control: 18,
    title: "SCA workspace coverage",
    severity: "medium",
    owner: SCA_POSTURE,
    surfaces: ["applications", "sca_workspaces", "sca_application_projects"],
    inputs: [
      "applications_readable",
      "application_count",
      "sca_workspaces_readable",
      "sca_workspace_count",
      "sca_covered_application_count",
      "sca_uncovered_application_count",
      "sca_unchecked_application_count",
      "linked_project_reads_complete",
    ],
    rules: [
      ...APPLICATIONS_GATE,
      rule("manual", all(SCA_UNAVAILABLE, not(gt("sca_covered_application_count", 0)))),
      rule("warn", gt("sca_unchecked_application_count", 0)),
      rule("warn", gt("sca_uncovered_application_count", 0)),
      rule("manual", not(gt("sca_covered_application_count", 0))),
      rule("warn", incomplete("linked_project_reads_complete")),
      rule("pass", always),
    ],
    completeness: { linked_project_reads_complete: LINKED_PROJECT_READS_COMPLETE },
    decision: "Manual when the application inventory is unreadable or empty, or when the SCA workspace list is refused or empty and no sampled application has upload-and-scan SCA. An application counts as covered when its profile enables upload-and-scan SCA or the SCA Agent API lists a linked project for it; neither shows that a scan has run. Warn when an application without upload-and-scan SCA could not be checked for linked projects because the SCA workspace list is refused or empty, or when an application has neither. Otherwise manual when every requested linked project list was refused. Warn instead of pass when the coverage reads do not cover the whole application inventory. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Every sampled application has upload-and-scan SCA or a linked SCA agent project.", SCA_COVERAGE_HEALTHY),
      example("compliant", "pass", "The SCA workspace list was refused, but every sampled application has upload-and-scan SCA, so no linked project list was needed.", {
        ...SCA_COVERAGE_HEALTHY,
        ...REFUSED_SCA_WORKSPACES,
      }),
      example("noncompliant", "warn", "Three applications have neither upload-and-scan SCA nor a linked SCA agent project.", {
        ...SCA_COVERAGE_HEALTHY,
        sca_covered_application_count: 9,
        sca_uncovered_application_count: 3,
      }),
      example("partial", "warn", "The SCA workspace list was refused, so four applications without upload-and-scan SCA were not checked for linked projects.", {
        ...SCA_COVERAGE_HEALTHY,
        ...REFUSED_SCA_WORKSPACES,
        sca_covered_application_count: 8,
        sca_unchecked_application_count: 4,
        linked_project_reads_complete: false,
      }),
      example("partial", "warn", "One sampled application's linked project list was refused.", {
        ...SCA_COVERAGE_HEALTHY,
        sca_covered_application_count: 11,
        linked_project_reads_complete: false,
      }),
      example("partial", "manual", "The SCA workspace list came back empty and no sampled application has upload-and-scan SCA.", {
        ...SCA_COVERAGE_HEALTHY,
        ...NO_SCA_WORKSPACES,
        sca_covered_application_count: 0,
        sca_unchecked_application_count: 12,
        linked_project_reads_complete: false,
      }),
      example("unreadable", "manual", "The SCA workspace list was refused and no sampled application has upload-and-scan SCA.", {
        ...SCA_COVERAGE_HEALTHY,
        ...REFUSED_SCA_WORKSPACES,
        sca_covered_application_count: 0,
        sca_unchecked_application_count: 12,
        linked_project_reads_complete: false,
      }),
      example("unreadable", "manual", "Every requested linked project list was refused.", {
        ...SCA_COVERAGE_HEALTHY,
        sca_covered_application_count: 0,
        linked_project_reads_complete: false,
      }),
      EMPTY_APPLICATIONS,
      UNREADABLE_APPLICATIONS,
    ],
  },
];

const ACCESS_CONTROLS = "veracode_assess_access_controls";
const USERS_GATE = [rule("manual", ne("users_readable", true)), rule("manual", not(gt("user_count", 0)))];
const USERS_READ = { users_readable: true, user_count: 40 };
const EMPTY_USERS = example("partial", "manual", "The user list came back empty, which cannot be complete because the API credential belongs to a user.", {
  ...USERS_READ,
  user_count: 0,
});
const UNREADABLE_USERS = example("unreadable", "manual", "The user list was refused.", { users_readable: false });
const TEAM_ACCESS_HEALTHY = {
  ...USERS_READ,
  roles_readable: true,
  role_count: 30,
  teams_readable: true,
  team_count: 6,
  teams_member_only: false,
  unrestricted_user_count: 3,
  max_unrestricted_users: 10,
  application_without_team_count: 0,
  team_scope_complete: true,
};
const USER_ROLES_HEALTHY = {
  ...USERS_READ,
  administrator_count: 3,
  max_admins: 5,
  inactive_user_count: 0,
  users_without_last_login_count: 0,
  api_account_without_team_count: 0,
  users_complete: true,
};
const CREDENTIALS_HEALTHY = {
  ...USERS_READ,
  active_api_account_count: 4,
  credential_record_read_count: 4,
  aged_credential_count: 0,
  undated_credential_count: 0,
  expired_credential_count: 0,
  credential_reads_complete: true,
};

const ACCESS_CONTROL_CHECKS: readonly VeracodeCheck[] = [
  {
    id: "VERACODE-07",
    control: 7,
    title: "Team access controls",
    severity: "high",
    owner: ACCESS_CONTROLS,
    surfaces: ["users", "roles", "teams", "applications"],
    inputs: [
      "users_readable",
      "user_count",
      "roles_readable",
      "role_count",
      "teams_readable",
      "team_count",
      "teams_member_only",
      "unrestricted_user_count",
      "max_unrestricted_users",
      "application_without_team_count",
      "team_scope_complete",
    ],
    rules: [
      ...USERS_GATE,
      rule("manual", ne("roles_readable", true)),
      rule("manual", ne("teams_readable", true)),
      rule("manual", not(gt("role_count", 0))),
      rule("manual", all(not(gt("team_count", 0)), eq("teams_member_only", true))),
      rule("fail", not(gt("team_count", 0))),
      rule("fail", gt("unrestricted_user_count", path("max_unrestricted_users"))),
      rule("warn", gt("application_without_team_count", 0)),
      rule("warn", incomplete("team_scope_complete")),
      rule("pass", always),
    ],
    completeness: { team_scope_complete: TEAM_SCOPE_COMPLETE },
    decision: "Manual when the user, role, or team list is unreadable, the user or role list is empty, or the organization-wide team list was refused and the API user is a member of no team. Fail when the organization-wide team list holds no team, since no team then scopes application access, or when more than max_unrestricted_users active human users hold a role that ignores team restrictions. Warn when an application has no team assigned. Warn instead of pass when the user, role, or team list is partial, the team list covers only the API user's own teams, or the application inventory is unreadable or partial. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Six teams scope access, every application has a team, and three active users hold team-unrestricted roles against a maximum of 10.", TEAM_ACCESS_HEALTHY),
      example("noncompliant", "fail", "Twelve active users hold roles that ignore team restrictions, against a maximum of 10.", {
        ...TEAM_ACCESS_HEALTHY,
        unrestricted_user_count: 12,
      }),
      example("noncompliant", "fail", "The organization-wide team list holds no team, so no team scopes application access.", { ...TEAM_ACCESS_HEALTHY, team_count: 0 }),
      example("noncompliant", "warn", "Two applications have no team assigned, so only team-unrestricted roles can see them.", {
        ...TEAM_ACCESS_HEALTHY,
        application_without_team_count: 2,
      }),
      example("partial", "warn", "The organization-wide team list was refused, so only the API user's own teams were listed.", {
        ...TEAM_ACCESS_HEALTHY,
        team_count: 2,
        teams_member_only: true,
        team_scope_complete: false,
      }),
      example("partial", "warn", "The application inventory was refused, so application team assignment was not verified.", {
        ...TEAM_ACCESS_HEALTHY,
        team_scope_complete: false,
      }),
      example("partial", "manual", "The organization-wide team list was refused and the API user is a member of no team.", {
        ...TEAM_ACCESS_HEALTHY,
        team_count: 0,
        teams_member_only: true,
        team_scope_complete: false,
      }),
      example("partial", "manual", "The role list came back empty, though Veracode ships built-in roles.", { ...TEAM_ACCESS_HEALTHY, role_count: 0 }),
      example("unreadable", "manual", "The team list was refused.", { ...TEAM_ACCESS_HEALTHY, teams_readable: false, team_count: 0, team_scope_complete: false }),
      example("unreadable", "manual", "The role list was refused.", { ...TEAM_ACCESS_HEALTHY, roles_readable: false, role_count: 0, team_scope_complete: false }),
      EMPTY_USERS,
      UNREADABLE_USERS,
    ],
  },
  {
    id: "VERACODE-08",
    control: 8,
    title: "User role audit",
    severity: "high",
    owner: ACCESS_CONTROLS,
    surfaces: ["users"],
    inputs: [
      "users_readable",
      "user_count",
      "administrator_count",
      "max_admins",
      "inactive_user_count",
      "users_without_last_login_count",
      "api_account_without_team_count",
      "users_complete",
    ],
    rules: [
      ...USERS_GATE,
      rule("fail", any(gt("inactive_user_count", 0), gt("api_account_without_team_count", 0), gt("administrator_count", path("max_admins")))),
      rule("warn", gt("users_without_last_login_count", 0)),
      rule("warn", incomplete("users_complete")),
      rule("pass", always),
    ],
    completeness: { users_complete: USERS_COMPLETE },
    decision: "Manual when the user list is unreadable or empty. Fail when an active human user last logged in more than inactive_days ago, an active API account has no team and does not set no_teams_required, or more than max_admins active users, API accounts included, hold the Administrator role. Warn when an active human user exposes no readable last_login. Warn instead of pass when the user list is partial. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Three active users hold the Administrator role against a maximum of 5, every active human user logged in within inactive_days, and every active API account has a team.", USER_ROLES_HEALTHY),
      example("noncompliant", "fail", "Seven active users hold the Administrator role, against a maximum of 5.", { ...USER_ROLES_HEALTHY, administrator_count: 7 }),
      example("noncompliant", "fail", "Two active human users have not logged in within inactive_days.", { ...USER_ROLES_HEALTHY, inactive_user_count: 2 }),
      example("noncompliant", "fail", "One active API account has no team and does not set no_teams_required.", { ...USER_ROLES_HEALTHY, api_account_without_team_count: 1 }),
      example("partial", "warn", "Three active human users expose no last_login.", { ...USER_ROLES_HEALTHY, users_without_last_login_count: 3 }),
      example("partial", "warn", "The user walk stopped at its page cap.", { ...USER_ROLES_HEALTHY, users_complete: false }),
      EMPTY_USERS,
      UNREADABLE_USERS,
    ],
  },
  {
    id: "VERACODE-09",
    control: 9,
    title: "API credential management",
    severity: "high",
    owner: ACCESS_CONTROLS,
    surfaces: ["users", "api_credentials"],
    inputs: [
      "users_readable",
      "user_count",
      "active_api_account_count",
      "credential_record_read_count",
      "aged_credential_count",
      "undated_credential_count",
      "expired_credential_count",
      "credential_reads_complete",
    ],
    rules: [
      ...USERS_GATE,
      rule("manual", not(gt("active_api_account_count", 0))),
      rule("manual", not(gt("credential_record_read_count", 0))),
      rule("fail", gt("aged_credential_count", 0)),
      rule("warn", any(gt("undated_credential_count", 0), gt("expired_credential_count", 0))),
      rule("warn", incomplete("credential_reads_complete")),
      rule("pass", always),
    ],
    completeness: { credential_reads_complete: CREDENTIAL_READS_COMPLETE },
    decision: "Manual when the user list is unreadable or empty, when no active API account is among the users read, which a partial user list leaves unread rather than empty, or when no sampled API account's credential record could be read. Fail when an unrevoked credential was created more than max_credential_age_days ago. Warn when an unrevoked credential lacks a readable created_ts or expiration_ts, or has expired without being revoked. Warn instead of pass when the credential reads do not cover every active API account. Otherwise pass, including when every credential read is revoked.",
    examples: [
      example("compliant", "pass", "Every unrevoked credential of the four active API accounts was created within max_credential_age_days and carries an expiration_ts.", CREDENTIALS_HEALTHY),
      example("noncompliant", "fail", "One unrevoked credential was created more than max_credential_age_days ago.", { ...CREDENTIALS_HEALTHY, aged_credential_count: 1 }),
      example("partial", "warn", "One credential expired but was never revoked.", { ...CREDENTIALS_HEALTHY, expired_credential_count: 1 }),
      example("partial", "warn", "One unrevoked credential carries no expiration_ts.", { ...CREDENTIALS_HEALTHY, undated_credential_count: 1 }),
      example("partial", "warn", "One sampled API account's credential record was refused.", {
        ...CREDENTIALS_HEALTHY,
        credential_record_read_count: 3,
        credential_reads_complete: false,
      }),
      example("partial", "manual", "No active API account was among the users read before the user walk stopped, so the credential inventory is unread rather than empty.", {
        ...CREDENTIALS_HEALTHY,
        active_api_account_count: 0,
        credential_record_read_count: 0,
        credential_reads_complete: false,
      }),
      example("partial", "manual", "The user list holds no active API account.", { ...CREDENTIALS_HEALTHY, active_api_account_count: 0, credential_record_read_count: 0 }),
      example("unreadable", "manual", "Every sampled API account's credential record was refused.", {
        ...CREDENTIALS_HEALTHY,
        credential_record_read_count: 0,
        credential_reads_complete: false,
      }),
      EMPTY_USERS,
      UNREADABLE_USERS,
    ],
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

const checks: readonly BatchCheckDefinition[] = [
  ...SCAN_COVERAGE_CHECKS,
  ...POLICY_COMPLIANCE_CHECKS,
  ...FINDINGS_HYGIENE_CHECKS,
  ...SCA_POSTURE_CHECKS,
  ...ACCESS_CONTROL_CHECKS,
].map(toCheck);
const idsFor = (owner: string): string[] => checks.filter((check) => check.owner === owner).map((check) => check.id);

const RECORD_KEY = "a record's key being the first of its guid, id, user_id, team_id, issue_id, and scan_id that is present and not null, else the whole record";
type HalWalkOptions = { pageCap: number; pageSize?: number; probed?: boolean; scope?: string };
const halWalk = (surfaceIds: readonly string[], records: string, { pageCap, pageSize = 100, probed = false, scope = "" }: HalWalkOptions): BatchPaginationDefinition => ({
  surfaceIds,
  cursorFields: ["page", "page.total_pages", "page.total_elements"],
  pageSize,
  itemCap: "none",
  pageCap,
  totalSemantics: `${scope}Pages of ${pageSize} ${records} (size), indexed from 0 (page), up to ${pageCap} pages${probed ? "; the veracode_check_access probe reads only page 0" : ""}. A page's total_pages and total_elements replace the values read before when present, and no _links.next link is read. An entry that is not a JSON object is dropped without marking the list partial. The list is partial when ${walkPartial(pageCap)}.`,
  stopConditions: [
    "Once a page has reported total_pages, the page whose index plus one reaches the last reported total_pages",
    `Before any page has reported total_pages, a page holding fewer than ${pageSize} ${records}, entries that are not JSON objects not counting`,
    `A non-empty page whose ${records}' keys, in order, equal the previous page's, ${RECORD_KEY}; the repeated page is not kept, and the list is partial`,
    `${pageCap} pages read without another stop, which leaves the list partial unless the last reported total_pages was reached`,
    "A refused page, which makes the whole list a refusal",
  ],
});
const singleRead = (surfaceIds: readonly string[], totalSemantics: string): BatchPaginationDefinition => ({
  surfaceIds,
  cursorFields: [],
  pageSize: null,
  itemCap: "none",
  pageCap: 1,
  totalSemantics,
  stopConditions: ["The first response"],
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
  summary: "Portable contract for the shipped Veracode scan coverage, policy compliance, findings hygiene, SCA posture, and access control assessments over the Veracode Applications, Policy, Identity, Dynamic Analysis, Findings, Summary Report, and SCA Agent REST APIs.",
  sourceModule: "cli/extensions/grc-tools/veracode.ts",
  baseServices: [APPLICATIONS_SERVICE, POLICY_SERVICE, IDENTITY_SERVICE, DYNAMIC_SERVICE, FINDINGS_SERVICE, SUMMARY_REPORT_SERVICE, SCA_SERVICE],
  authentication: VERACODE_AUTH_RESOLVER,
  permissions: [
    {
      id: "api-user",
      kind: "role",
      value: "Any Veracode API user",
      unlocks: ["self", "self_api_credentials"],
      notes: "The Identity REST API documentation lets an account without the Admin API or Administrator role read its own user record and API credentials.",
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
    {
      id: "results-reader",
      kind: "role",
      value: "Results API role",
      unlocks: ["findings", "summary_reports"],
      notes: "veracode_check_access does not probe these APIs; the Findings and Summary Report REST API documentation names an API user account with the Results API role, or a user account with the Reviewer or Security Lead role.",
    },
    {
      id: "sca-agent",
      kind: "license",
      value: "SCA license and the Workspace Administrator or Workspace Editor role",
      unlocks: ["sca_workspaces", "sca_vulnerability_issues", "sca_license_issues", "sca_libraries", "sca_application_projects"],
      notes: "veracode_check_access names these roles for the workspace list; the SCA REST API documentation requires the API credentials of a UI user account and does not support API user accounts.",
    },
    {
      id: "identity-administrator",
      kind: "role",
      value: "Administrator role",
      unlocks: ["users", "teams", "roles", "api_credentials"],
      notes: "veracode_check_access names this role for users, teams, and roles; the Identity REST API documentation names an API user account with the Admin API role or a user account with the Administrator role, and reading another user's API credentials needs the Administrator role or being that user's administrator.",
    },
  ],
  surfaces: VERACODE_SURFACES,
  checks,
  tools: {
    veracode_check_access: [],
    veracode_assess_scan_coverage: idsFor(SCAN_COVERAGE),
    veracode_assess_policy_compliance: idsFor(POLICY_COMPLIANCE),
    veracode_assess_findings_hygiene: idsFor(FINDINGS_HYGIENE),
    veracode_assess_sca_posture: idsFor(SCA_POSTURE),
    veracode_assess_access_controls: idsFor(ACCESS_CONTROLS),
    veracode_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [
    halWalk(["applications", "policies", "dynamic_analyses", "sca_workspaces", "users", "roles"], "records", { pageCap: 50, probed: true }),
    halWalk(["teams"], "teams", {
      pageCap: 50,
      probed: true,
      scope: "The team list is walked with all_for_org=true; when a page of that walk is refused with status 400 or 403, the walk restarts from page 0 without it, and only the restarted walk's pages are kept. ",
    }),
    halWalk(["sandboxes"], "sandboxes", { pageCap: 10, scope: "Each sampled application's sandbox list is walked separately. " }),
    halWalk(["findings"], "findings", { pageCap: 50, pageSize: 500, scope: "Each sampled application's finding list is walked separately. " }),
    halWalk(["dynamic_analysis_scans"], "scans", { pageCap: 5, scope: "Each sampled analysis's scan list is walked separately. " }),
    halWalk(["sca_vulnerability_issues", "sca_license_issues"], "issues", { pageCap: 20, scope: "Each sampled workspace's vulnerability and license issue lists are walked separately. " }),
    halWalk(["sca_libraries"], "libraries", { pageCap: 5, scope: "Each sampled workspace's library list is walked separately. " }),
    singleRead(["self"], "One read of the API user's own record."),
    singleRead(["summary_reports"], "One read of each sampled application's summary report."),
    singleRead(["dynamic_scan_configurations"], "One read of each inspected scan's configuration."),
    singleRead(["sca_application_projects"], "One read of each requested linked project list."),
    singleRead(["api_credentials"], `One read of each sampled API account's credential record, at most ${MAX_CREDENTIAL_ACCOUNTS}, all requested at once.`),
    singleRead(["self_api_credentials"], "One read of the API user's own API credentials, by veracode_check_access only."),
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
    "When the application inventory is unreadable or empty, the findings hygiene assessment reports VERACODE-16 and VERACODE-17 at high severity, copied from VERACODE-03's manual finding, instead of their own medium severity.",
    "VERACODE-16 skips a finding list that kept no finding before checking whether that list is partial, so a truncated empty list does not lower fp_rate_coverage_complete and the check can pass without that application's rate; changing that behavior requires a separate runtime fix.",
    "VERACODE-06 can pass when the license issue lists read hold no issue, even when the sampled workspaces hold no scanned library, though VERACODE-05 treats an empty library set as unverifiable.",
    "VERACODE-18 counts an application as covered when its profile enables upload-and-scan SCA or it has a linked SCA agent project, without checking that either has produced a scan.",
    "VERACODE-07 fails when the organization-wide team list kept no team even when that list is partial, for example when its only page is empty but reports a positive total_elements.",
    "The SCA REST API documentation asks for a user-agent header and accept-encoding: gzip on every request; the collector sets neither itself and relies on Node.js fetch, which sends user-agent: node and accept-encoding: gzip, deflate.",
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
