import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
  deriveDecisionRules,
  type BatchCheckDefinition,
  type BatchCompletenessDefinition,
  type BatchCriterionExample,
  type BatchSurfaceDefinition,
} from "./batch-spec-builder.js";
import { TENABLE_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import type { PortableValue, RequestParameterContract, VerdictCondition, VerdictOperand, VerdictRule } from "./spec-model.js";

const VM_SERVICE = "Tenable Vulnerability Management API";
const SC_SERVICE = "Tenable Security Center REST API";
const VM_AUTH_HEADER = "X-ApiKeys: accessKey={access_key};secretKey={secret_key}";
const SC_AUTH_HEADER = "x-apikey: accesskey={sc_access_key}; secretkey={sc_secret_key};";

type SurfaceRequestOptions = {
  method?: "GET" | "POST";
  parameters?: readonly RequestParameterContract[];
  responseShape: string;
};

const vmSurface = (
  id: string,
  path: string,
  slug: string,
  fields: readonly string[],
  { method, parameters = [], responseShape }: SurfaceRequestOptions,
): BatchSurfaceDefinition => ({
  id,
  ...(method ? { method } : {}),
  path,
  service: VM_SERVICE,
  documentationUrl: `https://developer.tenable.com/reference/${slug}`,
  fields,
  request: {
    headers: [
      "Accept: application/json",
      VM_AUTH_HEADER,
      ...(method === "POST" ? ["Content-Type: application/json"] : []),
    ],
    parameters,
    responseShape,
  },
});

const scSurface = (
  id: string,
  resource: string,
  page: string,
  fields: readonly string[],
  parameters: readonly RequestParameterContract[],
  responseShape: string,
): BatchSurfaceDefinition => ({
  id,
  path: `/rest/${resource}`,
  service: SC_SERVICE,
  documentationUrl: `https://docs.tenable.com/security-center/api/${page}`,
  fields,
  request: {
    clientRegion: "Use the configured Tenable Security Center origin (sc_url, or url when it names a Security Center host); never follow a server link to a different origin.",
    headers: ["Accept: application/json", SC_AUTH_HEADER],
    parameters,
    responseShape,
  },
});

const param = (
  name: string,
  location: RequestParameterContract["location"],
  value: string,
  required = true,
): RequestParameterContract => ({ name, location, required, value });

const SC_LIST_SHAPE = "A JSON object whose response is either an array of records or an object with usable and manageable arrays, merged by id; a nonzero error_code is a refusal.";

const TENABLE_SURFACES: readonly BatchSurfaceDefinition[] = [
  vmSurface("scans", "/scans", "scans-list", [
    "id", "name", "type", "status", "enabled", "rrules", "policy_id", "wizard_uuid", "template_uuid", "last_modification_date",
  ], { responseShape: "A JSON object with a scans array." }),
  vmSurface("policies", "/policies", "policies-list", ["id", "name", "template_uuid"], {
    responseShape: "A JSON object with a policies array.",
  }),
  vmSurface("policy-details", "/policies/{policy_id}", "policies-details", [
    "uuid", "name", "settings.safe_checks", "settings.portscan_range", "settings.max_hosts_per_scan", "settings.max_checks_per_host",
    "settings.thorough_tests", "settings.report_paranoia", "plugins.*.status",
  ], {
    parameters: [param("policy_id", "path", "Each distinct policy_id carried by a visible scan, for the first 100 such policies")],
    responseShape: "A JSON object carrying at least one of uuid, settings, plugins, or credentials; credential properties under settings are redacted before evidence export.",
  }),
  vmSurface("scan-templates", "/editor/scan/templates", "editor-list-templates", ["uuid", "name", "title"], {
    responseShape: "A JSON object with a templates array.",
  }),
  vmSurface("users", "/users", "users-list", ["permissions"], {
    parameters: [param("withRoles", "query", "true")],
    responseShape: "A JSON object with a users array; only an Administrator key receives the numeric permissions attribute on each user.",
  }),
  vmSurface("target-groups", "/target-groups", "target-groups-list", ["name", "members", "last_modification_date"], {
    responseShape: "A JSON object with a target_groups array.",
  }),
  vmSurface("exclusions", "/exclusions", "exclusions-list", ["id", "name", "description", "members", "schedule.enabled"], {
    parameters: [
      param("limit", "query", "200"),
      param("offset", "query", "Number of exclusion records already received, starting at 0"),
    ],
    responseShape: "A JSON object with an exclusions array and pagination.total.",
  }),
  vmSurface("asset-export-request", "/assets/export", "exports-assets-request-export", ["export_uuid"], {
    method: "POST",
    parameters: [param("chunk_size", "json-body", "10000")],
    responseShape: "A JSON object with export_uuid.",
  }),
  vmSurface("asset-export-status", "/assets/export/{export_uuid}/status", "exports-assets-export-status", [
    "status", "reason", "chunks_available", "chunks_failed", "total_chunks",
  ], {
    parameters: [param("export_uuid", "path", "The export_uuid returned by POST /assets/export, polled every 2 seconds for up to 300 seconds")],
    responseShape: "A JSON object with a status string and the chunks_available, chunks_failed, and total_chunks members.",
  }),
  vmSurface("asset-export-chunks", "/assets/export/{export_uuid}/chunks/{chunk_id}", "exports-assets-download-chunk", [
    "id", "uuid", "has_agent", "last_seen", "network_id", "tags", "last_authentication_scan_status",
  ], {
    parameters: [
      param("export_uuid", "path", "The export_uuid returned by POST /assets/export"),
      param("chunk_id", "path", "Each id in chunks_available, for the first max_chunks ids (default 50, clamped to 1 through 1000)"),
    ],
    responseShape: "A JSON array of asset records; a record carrying none of id, uuid, has_agent, last_seen, network_id, or tags is counted as unevaluable and kept out.",
  }),
  scSurface("sc-scans", "scan", "Scan.htm", ["id", "name", "schedule.type"], [
    param("fields", "query", "id,name,status,schedule,policy,repository,credentials,modifiedTime"),
  ], SC_LIST_SHAPE),
  scSurface("sc-scan-results", "scanResult", "Scan-Result.htm", ["status", "finishTime"], [
    param("fields", "query", "id,name,status,startTime,finishTime,scannedIPs,totalIPs"),
    param("startTime", "query", "Unix seconds 30 days before the assessment time"),
  ], SC_LIST_SHAPE),
];

const value = (entry: PortableValue): VerdictOperand => ({ kind: "value", value: entry });
const path = (name: string): VerdictOperand => ({ kind: "path", path: name });
type Comparator = "eq" | "ne" | "gt" | "gte" | "lt" | "lte";
const cmp = (op: Comparator, name: string, right: PortableValue | VerdictOperand): VerdictCondition => ({
  op,
  left: path(name),
  right: right !== null && typeof right === "object" && !Array.isArray(right) ? right as VerdictOperand : value(right as PortableValue),
});
const eq = (name: string, right: PortableValue | VerdictOperand) => cmp("eq", name, right);
const ne = (name: string, right: PortableValue | VerdictOperand) => cmp("ne", name, right);
const gt = (name: string, right: PortableValue | VerdictOperand) => cmp("gt", name, right);
const lt = (name: string, right: PortableValue | VerdictOperand) => cmp("lt", name, right);
const lte = (name: string, right: PortableValue | VerdictOperand) => cmp("lte", name, right);
const all = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "and", conditions });
const any = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "or", conditions });
const some = (name: string, condition: VerdictCondition): VerdictCondition => ({ op: "some", path: name, condition });
const always: VerdictCondition = { op: "always" };
const rule = (status: VerdictRule["status"], condition: VerdictCondition): VerdictRule => ({ status, condition });

const TENABLE_INPUTS: Readonly<Record<string, string>> = {
  caller_is_administrator: "True only when GET /users returned at least one user record carrying a numeric permissions attribute, which Tenable returns only to an Administrator key; false when the user list is unreadable, empty, or returned in the reduced shape.",
  stale_scan_days: "The stale_scan_days assessment option in days, clamped to 1 through 365; default 30.",
  credential_threshold: "The credential_threshold assessment option, clamped to 0 through 1; default 0.8.",
  scans_readable: "True when GET /scans returned its documented scans array.",
  scan_count: "Number of scan records GET /scans returned.",
  discovery_scan_count: "Number of scans whose wizard_uuid, or else template_uuid, resolves to a GET /editor/scan/templates record whose name or title contains discovery, case-insensitively; 0 when the template list is unreadable.",
  failing_policy_count: "Number of referenced policies whose GET /policies/{policy_id} detail was read and either sets settings.safe_checks to no or has a non-empty plugins family map in which no family status is enabled or mixed.",
  policy_details_readable: "False when the scan list was unreadable or every attempted GET /policies/{policy_id} read was refused or failed; true otherwise, including when no policy detail was requested.",
  evaluated_policy_count: "Number of GET /policies/{policy_id} reads attempted: one per distinct scan policy_id, for at most the first 100.",
  scans_without_policy_id_count: "Number of visible scans with no policy_id string.",
  unreadable_policy_count: "Number of attempted policy detail reads that were refused or failed.",
  unverified_policy_count: "Number of read policy details that are not failing and either omit settings.safe_checks or expose an empty plugins family map.",
  policy_details_complete: "Policy detail coverage of the referenced policies.",
  warning_policy_count: "Number of read policy details that are neither failing nor unverified and have a safe_checks value other than yes, a missing settings.portscan_range or one that is not default, all, or 1-65535, or more than half of their plugin families disabled.",
  templates_readable: "True when GET /editor/scan/templates returned its documented templates array.",
  policies_readable: "True when GET /policies returned its documented policies array.",
  enabled_recurring_scan_count: "Number of scans with enabled true and a non-empty rrules string that does not contain FREQ=ONETIME.",
  recurring_scan_age_days: "For each enabled recurring scan whose last_modification_date parses as epoch seconds, epoch milliseconds, or a date string, the days from that timestamp to the assessment time as a fraction, floored at 0.",
  never_run_or_undated_recurring_scan_count: "Number of enabled recurring scans whose status is empty or whose last_modification_date does not parse as a timestamp.",
  active_compliance_scan_count: "Number of enabled recurring scans whose resolved template name or title contains compliance, pci, scap, audit, offline config, or stig, case-insensitively.",
  asset_export_readable: "True when the POST /assets/export job reached FINISHED and, when Tenable listed any available chunk, at least one chunk downloaded.",
  asset_count: "Number of exported asset records carrying at least one of id, uuid, has_agent, last_seen, network_id, or tags.",
  credentialed_coverage_ratio: "Exported assets whose last_authentication_scan_status is Success or whose has_agent is true, divided by the exported asset count and rounded to four decimal places with ties rounded up; 0 when no asset was exported.",
  asset_export_complete: "Asset export coverage.",
  exclusions_readable: "True when the GET /exclusions offset walk returned documented exclusions pages.",
  exclusions_complete: "Exclusion inventory coverage.",
  permanent_exclusion_count: "Number of exclusion records whose schedule.enabled is not true.",
  broad_exclusion_count: "Number of exclusions whose comma-separated members include a CIDR block with a prefix length of 16 or less, or an IPv4 range whose start and end differ in the second octet.",
  undocumented_exclusion_count: "Number of exclusions without a non-empty description string.",
  target_groups_readable: "True when GET /target-groups returned its documented target_groups array.",
  target_group_age_days: "For each target group whose last_modification_date parses as a timestamp, the days from that timestamp to the assessment time as a fraction, floored at 0.",
  undated_target_group_count: "Number of target groups whose last_modification_date does not parse as a timestamp.",
  overlapping_member_count: "Number of distinct trimmed member targets listed more than once across the comma-separated members strings of all target groups, including a target repeated within one group.",
  sc_scans_readable: "True when Tenable Security Center is configured and GET /rest/scan returned a scan list.",
  sc_scan_count: "Number of Security Center scan records, with the usable and manageable lists merged by id.",
  sc_recurring_scan_count: "Number of Security Center scans whose schedule.type is ical.",
  sc_scan_results_readable: "True when GET /rest/scanResult returned a result list.",
  sc_finished_result_age_days: "For each returned Security Center scan result whose status contains completed, case-insensitively, and whose finishTime parses as a timestamp, the days from finishTime to the assessment time as a fraction, floored at 0.",
};

const inputs = (...names: string[]): Readonly<Record<string, string>> => Object.fromEntries(names.map((name) => {
  const definition = TENABLE_INPUTS[name];
  if (!definition) throw new Error(`Tenable decision input ${name} has no portable definition`);
  return [name, definition];
}));

const completeFrom = (
  semantics: string,
  sources: BatchCompletenessDefinition["sources"],
): BatchCompletenessDefinition => ({ semantics, sources });

type TenableCheck = {
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

const SCAN_PROGRAM = "tenable_assess_scan_program";

const SCAN_PROGRAM_CHECKS: readonly TenableCheck[] = [
  {
    id: "TENABLE-01",
    control: 1,
    title: "Scan policy configuration",
    severity: "high",
    owner: SCAN_PROGRAM,
    surfaces: ["scans", "policies", "policy-details", "scan-templates", "users"],
    inputs: [
      "scans_readable", "scan_count", "discovery_scan_count", "failing_policy_count", "policy_details_readable", "evaluated_policy_count",
      "scans_without_policy_id_count", "unreadable_policy_count", "unverified_policy_count", "policy_details_complete", "warning_policy_count",
      "templates_readable", "policies_readable", "caller_is_administrator",
    ],
    rules: [
      rule("manual", ne("scans_readable", true)),
      rule("fail", eq("scan_count", 0)),
      rule("fail", eq("discovery_scan_count", path("scan_count"))),
      rule("fail", gt("failing_policy_count", 0)),
      rule("manual", any(
        ne("policy_details_readable", true),
        all(eq("evaluated_policy_count", 0), eq("scans_without_policy_id_count", path("scan_count"))),
      )),
      rule("manual", any(gt("unreadable_policy_count", 0), gt("unverified_policy_count", 0), ne("policy_details_complete", true))),
      rule("warn", gt("warning_policy_count", 0)),
      rule("warn", any(
        ne("templates_readable", true),
        ne("policies_readable", true),
        ne("caller_is_administrator", true),
        gt("scans_without_policy_id_count", 0),
      )),
      rule("pass", always),
    ],
    completeness: {
      policy_details_complete: completeFrom(
        "true unless more than 100 distinct policies are referenced by visible scans, so the policies past the first 100 were never requested; individually refused or failed reads are counted separately and do not change this fact.",
        [{ surfaceId: "policy-details", falseWhen: ["truncated"] }],
      ),
    },
    decision: "Manual when GET /scans is unreadable. Fail when no scan is visible, when every visible scan resolves to a discovery template, or when any referenced policy detail sets safe_checks to no or disables every plugin family. Manual when every policy detail read failed, when no visible scan carries a policy_id, when any referenced policy detail was unreadable or omits safe_checks or its plugin family map, or when more than 100 referenced policies left the rest unrequested. Warn when an evaluated policy has a safe_checks value other than yes, a missing or custom port range, or more than half of its plugin families disabled. Warn instead of pass when the template or policy list is unreadable, when the key is not confirmed as Administrator, or when any visible scan carries no policy_id. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Every referenced policy was read and verified safe, and the key is an Administrator.", {
        scans_readable: true, scan_count: 3, discovery_scan_count: 1, failing_policy_count: 0, policy_details_readable: true, evaluated_policy_count: 2,
        scans_without_policy_id_count: 0, unreadable_policy_count: 0, unverified_policy_count: 0, policy_details_complete: true, warning_policy_count: 0,
        templates_readable: true, policies_readable: true, caller_is_administrator: true,
      }),
      example("noncompliant", "fail", "A referenced policy turns safe checks off, which fails even though another policy detail was unreadable.", {
        scans_readable: true, scan_count: 3, discovery_scan_count: 0, failing_policy_count: 1, policy_details_readable: true, evaluated_policy_count: 2,
        scans_without_policy_id_count: 0, unreadable_policy_count: 1, unverified_policy_count: 0, policy_details_complete: true, warning_policy_count: 0,
        templates_readable: true, policies_readable: true, caller_is_administrator: true,
      }),
      example("partial", "warn", "Every policy is safe, but one visible scan carries no policy_id and was not evaluated.", {
        scans_readable: true, scan_count: 3, discovery_scan_count: 0, failing_policy_count: 0, policy_details_readable: true, evaluated_policy_count: 2,
        scans_without_policy_id_count: 1, unreadable_policy_count: 0, unverified_policy_count: 0, policy_details_complete: true, warning_policy_count: 0,
        templates_readable: true, policies_readable: true, caller_is_administrator: true,
      }),
      example("unreadable", "manual", "The scan list was refused, so no policy can be located.", { scans_readable: false }),
    ],
  },
  {
    id: "TENABLE-02-SC",
    control: 2,
    title: "Scan schedule discipline (Tenable Security Center)",
    severity: "high",
    owner: SCAN_PROGRAM,
    surfaces: ["sc-scans", "sc-scan-results"],
    inputs: ["sc_scans_readable", "sc_scan_count", "sc_recurring_scan_count", "sc_scan_results_readable", "sc_finished_result_age_days", "stale_scan_days"],
    rules: [
      rule("manual", ne("sc_scans_readable", true)),
      rule("fail", eq("sc_scan_count", 0)),
      rule("fail", eq("sc_recurring_scan_count", 0)),
      rule("manual", ne("sc_scan_results_readable", true)),
      rule("pass", some("sc_finished_result_age_days", lte("$", path("stale_scan_days")))),
      rule("fail", always),
    ],
    decision: "Manual when Security Center is not configured or GET /rest/scan is unreadable. Fail when Security Center returns no scan or no scan has an ical (recurring) schedule. Manual when GET /rest/scanResult is unreadable. Pass when at least one scan result whose status mentions completed finished within stale_scan_days; otherwise fail.",
    examples: [
      example("compliant", "pass", "A completed result finished exactly 30 days ago, inside the 30-day window.", {
        sc_scans_readable: true, sc_scan_count: 2, sc_recurring_scan_count: 1, sc_scan_results_readable: true, sc_finished_result_age_days: [30], stale_scan_days: 30,
      }),
      example("noncompliant", "fail", "Scans are visible, but none uses an ical schedule, which fails before the results are consulted.", {
        sc_scans_readable: true, sc_scan_count: 2, sc_recurring_scan_count: 0, sc_scan_results_readable: false,
      }),
      example("unreadable", "manual", "Security Center is not configured.", { sc_scans_readable: false }),
    ],
  },
  {
    id: "TENABLE-02",
    control: 2,
    title: "Scan schedule discipline",
    severity: "high",
    owner: SCAN_PROGRAM,
    surfaces: ["scans", "users"],
    inputs: [
      "scans_readable", "scan_count", "enabled_recurring_scan_count", "recurring_scan_age_days", "stale_scan_days",
      "never_run_or_undated_recurring_scan_count", "caller_is_administrator",
    ],
    rules: [
      rule("manual", ne("scans_readable", true)),
      rule("fail", eq("scan_count", 0)),
      rule("fail", eq("enabled_recurring_scan_count", 0)),
      rule("fail", some("recurring_scan_age_days", gt("$", path("stale_scan_days")))),
      rule("warn", gt("never_run_or_undated_recurring_scan_count", 0)),
      rule("warn", ne("caller_is_administrator", true)),
      rule("pass", always),
    ],
    decision: "Manual when GET /scans is unreadable. Fail when no scan is visible, when no scan is enabled with a recurring rrules schedule, or when any enabled recurring scan last launched more than stale_scan_days ago. Warn when an enabled recurring scan has never run or carries no parseable launch date. Warn instead of pass when the key is not confirmed as Administrator. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Both recurring scans launched within the window, and the key is an Administrator.", {
        scans_readable: true, scan_count: 4, enabled_recurring_scan_count: 2, recurring_scan_age_days: [2, 30], stale_scan_days: 30,
        never_run_or_undated_recurring_scan_count: 0, caller_is_administrator: true,
      }),
      example("noncompliant", "fail", "One recurring scan last launched 31 days ago, past the 30-day window.", {
        scans_readable: true, scan_count: 4, enabled_recurring_scan_count: 2, recurring_scan_age_days: [2, 31], stale_scan_days: 30,
        never_run_or_undated_recurring_scan_count: 0, caller_is_administrator: true,
      }),
      example("partial", "warn", "A third recurring scan has never run, so it is not counted as fresh.", {
        scans_readable: true, scan_count: 4, enabled_recurring_scan_count: 3, recurring_scan_age_days: [2, 30], stale_scan_days: 30,
        never_run_or_undated_recurring_scan_count: 1, caller_is_administrator: true,
      }),
      example("unreadable", "manual", "The scan list failed, so no schedule can be assessed.", { scans_readable: false }),
    ],
  },
  {
    id: "TENABLE-17",
    control: 17,
    title: "Compliance audit templates",
    severity: "medium",
    owner: SCAN_PROGRAM,
    surfaces: ["scans", "scan-templates", "users"],
    inputs: ["scans_readable", "templates_readable", "scan_count", "active_compliance_scan_count", "caller_is_administrator"],
    rules: [
      rule("manual", ne("scans_readable", true)),
      rule("manual", ne("templates_readable", true)),
      rule("fail", eq("scan_count", 0)),
      rule("fail", eq("active_compliance_scan_count", 0)),
      rule("warn", ne("caller_is_administrator", true)),
      rule("pass", always),
    ],
    decision: "Manual when GET /scans or GET /editor/scan/templates is unreadable. Fail when no scan is visible or when no enabled recurring scan resolves to a template whose name or title mentions compliance, PCI, SCAP, audit, offline config, or STIG. Warn instead of pass when the key is not confirmed as Administrator. Otherwise pass.",
    examples: [
      example("compliant", "pass", "An enabled recurring scan uses a compliance audit template, and the key is an Administrator.", {
        scans_readable: true, templates_readable: true, scan_count: 5, active_compliance_scan_count: 1, caller_is_administrator: true,
      }),
      example("noncompliant", "fail", "Scans exist, but none is an enabled recurring compliance scan.", {
        scans_readable: true, templates_readable: true, scan_count: 5, active_compliance_scan_count: 0, caller_is_administrator: true,
      }),
      example("partial", "warn", "A compliance scan runs, but the key is not confirmed as Administrator, so other scans may be hidden.", {
        scans_readable: true, templates_readable: true, scan_count: 5, active_compliance_scan_count: 1, caller_is_administrator: false,
      }),
      example("unreadable", "manual", "The template list was refused, so compliance templates cannot be recognized.", {
        scans_readable: true, templates_readable: false,
      }),
    ],
  },
  {
    id: "TENABLE-04",
    control: 4,
    title: "Credentialed scan ratio",
    severity: "high",
    owner: SCAN_PROGRAM,
    surfaces: ["asset-export-request", "asset-export-status", "asset-export-chunks"],
    inputs: ["asset_export_readable", "asset_count", "credentialed_coverage_ratio", "credential_threshold", "asset_export_complete"],
    rules: [
      rule("manual", ne("asset_export_readable", true)),
      rule("manual", eq("asset_count", 0)),
      rule("fail", lt("credentialed_coverage_ratio", path("credential_threshold"))),
      rule("warn", ne("asset_export_complete", true)),
      rule("pass", always),
    ],
    completeness: {
      asset_export_complete: completeFrom(
        "true when the finished export listed no more than max_chunks available chunks, Tenable reported no failed chunk and no total_chunks beyond the available list, every requested chunk downloaded, and every downloaded record carried a documented asset member.",
        [
          { surfaceId: "asset-export-status", falseWhen: ["truncated"] },
          { surfaceId: "asset-export-chunks", falseWhen: ["truncated", "missing-required-field"] },
        ],
      ),
    },
    decision: "Manual when the asset export did not finish or no available chunk could be downloaded, and manual when it finished with zero assets. Fail when the share of exported assets with a successful authenticated scan or an agent is below credential_threshold. Warn instead of pass when the export left chunks unread, reported failed chunks, or held records that could not be evaluated. Otherwise pass.",
    examples: [
      example("compliant", "pass", "Nine of ten exported assets were scanned with credentials or by an agent, above the 0.8 threshold.", {
        asset_export_readable: true, asset_count: 10, credentialed_coverage_ratio: 0.9, credential_threshold: 0.8, asset_export_complete: true,
      }),
      example("noncompliant", "fail", "Seven of ten assets were credentialed, below the 0.8 threshold, even though the export was partial.", {
        asset_export_readable: true, asset_count: 10, credentialed_coverage_ratio: 0.7, credential_threshold: 0.8, asset_export_complete: false,
      }),
      example("partial", "warn", "Coverage meets the threshold exactly, but the export left chunks unread.", {
        asset_export_readable: true, asset_count: 10, credentialed_coverage_ratio: 0.8, credential_threshold: 0.8, asset_export_complete: false,
      }),
      example("unreadable", "manual", "The export finished with zero assets, so no ratio exists.", {
        asset_export_readable: true, asset_count: 0, credentialed_coverage_ratio: 0, credential_threshold: 0.8, asset_export_complete: true,
      }),
    ],
  },
  {
    id: "TENABLE-13",
    control: 13,
    title: "Scan exclusion audit",
    severity: "medium",
    owner: SCAN_PROGRAM,
    surfaces: ["exclusions"],
    inputs: ["exclusions_readable", "exclusions_complete", "permanent_exclusion_count", "broad_exclusion_count", "undocumented_exclusion_count"],
    rules: [
      rule("manual", ne("exclusions_readable", true)),
      rule("fail", any(gt("permanent_exclusion_count", 0), gt("broad_exclusion_count", 0))),
      rule("warn", gt("undocumented_exclusion_count", 0)),
      rule("warn", ne("exclusions_complete", true)),
      rule("pass", always),
    ],
    completeness: {
      exclusions_complete: completeFrom(
        "true when the offset walk ended on an empty or short page or reached pagination.total; false when it stopped at the 200-page cap, delivered fewer records than pagination.total, or the endpoint replayed a page.",
        [{ surfaceId: "exclusions", falseWhen: ["truncated"] }],
      ),
    },
    decision: "Manual when GET /exclusions is unreadable. Fail when any delivered exclusion is always on (schedule.enabled is not true) or covers a /16 or wider range. Warn when an exclusion has no description. Warn instead of pass when the exclusion walk stopped before the end of the list. Otherwise pass, including when no exclusion exists.",
    examples: [
      example("compliant", "pass", "The complete list holds no always-on, broad, or undocumented exclusion.", {
        exclusions_readable: true, exclusions_complete: true, permanent_exclusion_count: 0, broad_exclusion_count: 0, undocumented_exclusion_count: 0,
      }),
      example("noncompliant", "fail", "One delivered exclusion is always on; the partial walk does not soften the failure.", {
        exclusions_readable: true, exclusions_complete: false, permanent_exclusion_count: 1, broad_exclusion_count: 0, undocumented_exclusion_count: 0,
      }),
      example("partial", "warn", "Every delivered exclusion is clean, but the walk stopped short of pagination.total.", {
        exclusions_readable: true, exclusions_complete: false, permanent_exclusion_count: 0, broad_exclusion_count: 0, undocumented_exclusion_count: 0,
      }),
      example("unreadable", "manual", "GET /exclusions was refused.", { exclusions_readable: false }),
    ],
  },
  {
    id: "TENABLE-20",
    control: 20,
    title: "Target group management",
    severity: "low",
    owner: SCAN_PROGRAM,
    surfaces: ["target-groups", "users"],
    inputs: ["target_groups_readable", "target_group_age_days", "undated_target_group_count", "overlapping_member_count", "caller_is_administrator"],
    rules: [
      rule("manual", ne("target_groups_readable", true)),
      rule("warn", any(
        some("target_group_age_days", gt("$", 365)),
        gt("undated_target_group_count", 0),
        gt("overlapping_member_count", 0),
      )),
      rule("warn", ne("caller_is_administrator", true)),
      rule("pass", always),
    ],
    decision: "Manual when GET /target-groups is unreadable. Warn when any legacy target group was last modified more than 365 days ago or carries no parseable modification date, or when any member target appears more than once across target groups. Warn instead of pass when the key is not confirmed as Administrator. Otherwise pass, including when no target group exists.",
    examples: [
      example("compliant", "pass", "No legacy target group remains, and the key is an Administrator.", {
        target_groups_readable: true, target_group_age_days: [], undated_target_group_count: 0, overlapping_member_count: 0, caller_is_administrator: true,
      }),
      example("partial", "warn", "One target group was last modified 366 days ago.", {
        target_groups_readable: true, target_group_age_days: [10, 366], undated_target_group_count: 0, overlapping_member_count: 0, caller_is_administrator: true,
      }),
      example("unreadable", "manual", "GET /target-groups failed.", { target_groups_readable: false }),
    ],
  },
];

const toCheck = (check: TenableCheck): BatchCheckDefinition => {
  const executable = deriveDecisionRules(check.id, check.rules);
  return {
    id: check.id,
    control: check.control,
    title: check.title,
    severity: check.severity,
    owner: check.owner,
    surfaces: check.surfaces,
    evidenceFields: check.inputs,
    decisionInputs: inputs(...check.inputs),
    decisionConstants: {},
    decisionRules: executable.rules,
    derivedFactRules: executable.derivedFactRules,
    ...(check.completeness ? { completeness: check.completeness } : {}),
    decision: check.decision,
    examples: check.examples,
  };
};

const checks: readonly BatchCheckDefinition[] = [...SCAN_PROGRAM_CHECKS].map(toCheck);
const idsFor = (owner: string): string[] => checks.filter((check) => check.owner === owner).map((check) => check.id);
const surfaceIds = (predicate: (surface: BatchSurfaceDefinition) => boolean): string[] =>
  TENABLE_SURFACES.filter(predicate).map((surface) => surface.id);

export const TENABLE_SPEC = buildBatchIntegrationSpec({
  slug: "tenable-sec-inspector",
  displayName: "Tenable Security Inspector",
  vendor: "Tenable",
  category: "vulnerability-management",
  summary: "Portable contract for the shipped Tenable Vulnerability Management and Tenable Security Center scan program, sensor coverage, access control, and vulnerability management assessments.",
  sourceModule: "cli/extensions/grc-tools/tenable.ts",
  baseServices: [VM_SERVICE, SC_SERVICE],
  authentication: TENABLE_AUTH_RESOLVER,
  permissions: [
    {
      id: "vm-administrator",
      kind: "role",
      value: "Tenable Vulnerability Management Administrator [64]",
      unlocks: surfaceIds((surface) => surface.service === VM_SERVICE),
      notes: "Lower roles see only objects shared with them; users then come back in the reduced shape, which caps otherwise passing findings at warn.",
    },
    {
      id: "sc-security-manager",
      kind: "role",
      value: "Tenable Security Center Security Manager or Administrator",
      unlocks: surfaceIds((surface) => surface.service === SC_SERVICE),
      notes: "Security Center returns only the scans and scan results the role can use or manage.",
    },
  ],
  surfaces: TENABLE_SURFACES,
  checks,
  tools: {
    tenable_check_access: [],
    tenable_assess_scan_program: idsFor(SCAN_PROGRAM),
    tenable_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [
    {
      surfaceIds: ["exclusions"],
      cursorFields: ["limit", "offset", "pagination.total"],
      pageSize: 200,
      itemCap: "none",
      pageCap: 200,
      totalSemantics: "When pagination.total is reported the walk must reach it; without a total a page shorter than the limit ends the list.",
      stopConditions: ["An empty page", "pagination.total reached", "A short page when no total is reported", "A page that opens with the same record as the previous page", "The 200-page cap"],
    },
    {
      surfaceIds: ["asset-export-request", "asset-export-chunks"],
      cursorFields: ["export_uuid", "chunks_available", "chunks_failed", "total_chunks"],
      pageSize: 10000,
      itemCap: "none",
      pageCap: 50,
      totalSemantics: "Each chunk holds up to 10000 assets. The first max_chunks available chunks are downloaded (default 50, clamped to 1 through 1000); listing more, a failed chunk, or total_chunks beyond the available list marks the export partial.",
      stopConditions: ["Export status FINISHED, ERROR, or CANCELLED", "The 300-second polling deadline", "Every listed chunk up to max_chunks requested"],
    },
  ],
  rateLimit: {
    documentedLimit: null,
    retryHeaders: ["Retry-After"],
    retryableStatuses: [429],
    retryableStatusRanges: [{ from: 500, to: 599 }],
    backoffPolicy: "Retry 429, every 5xx status, and network errors up to 4 times after the first attempt. A Retry-After header in seconds or as an HTTP date is honored up to 30 seconds; otherwise wait 500 ms doubled per attempt, capped at 15 seconds. Timed-out requests (30 seconds by default) are not retried.",
  },
  runtimeBehavior: [],
  knownGaps: [
    "Security Center scan results are requested for the last 30 days whatever stale_scan_days is set to, so a stale_scan_days above 30 cannot credit an older Security Center completion.",
  ],
  sensitiveFields: ["access_key", "secret_key", "sc_access_key", "sc_secret_key", "X-ApiKeys", "x-apikey", "credentials", "key"],
  credentialFormats: ["Tenable Vulnerability Management access and secret key pairs", "Tenable Security Center access and secret key pairs"],
  output: buildBatchOutputContract({
    files: [],
    overwritePolicy: "Allocate a new {host}-audit-bundle directory with a numeric suffix when needed; never overwrite a prior directory.",
    archivePairing: "Write a sibling zip named from the exact allocated bundle-directory path plus .zip.",
  }),
  lastUpdated: "2026-10-17",
});
