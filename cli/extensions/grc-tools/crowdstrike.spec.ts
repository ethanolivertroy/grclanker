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
import { CROWDSTRIKE_AUTH_RESOLVER } from "./auth-resolver-contracts.js";
import type { PortableValue, RequestParameterContract, VerdictCondition, VerdictOperand, VerdictRule } from "./spec-model.js";

// Alerts and RTR sessions are exported projected to these fields (plus each session's command count and distinct base
// commands); every other dataset is exported as read.
export const ALERT_SNAPSHOT_FIELDS: readonly string[] = [
  "id",
  "composite_id",
  "aggregate_id",
  "cid",
  "agent_id",
  "product",
  "type",
  "scenario",
  "objective",
  "tactic",
  "tactic_id",
  "technique",
  "technique_id",
  "pattern_id",
  "name",
  "display_name",
  "severity",
  "severity_name",
  "confidence",
  "status",
  "assigned_to_name",
  "resolution",
  "created_timestamp",
  "updated_timestamp",
  "timestamp",
  "seconds_to_triaged",
  "seconds_to_resolved",
  "data_domains",
  "tags",
];
export const ALERT_DEVICE_SNAPSHOT_FIELDS: readonly string[] = ["device_id", "hostname", "platform_name", "os_version", "agent_version"];
export const RTR_SESSION_SNAPSHOT_FIELDS: readonly string[] = [
  "id",
  "cid",
  "device_id",
  "hostname",
  "platform_name",
  "platform_id",
  "user_id",
  "user_uuid",
  "created_at",
  "updated_at",
  "deleted_at",
  "duration",
];

const API_SERVICE = "CrowdStrike Falcon API";
const API_DOCS = "https://developer.crowdstrike.com/api-reference/collections";
const API_HOST = "Use the resolved API host (base_url, else the selected cloud's host); member_cid scopes the bearer token and is never sent on a read.";
const READ_HEADERS = ["Accept: application/json", "Authorization: Bearer {access_token}"];
const RAW_EXPORT_STAGE = "The collector exports every returned record as read, after the data redaction pass has rewritten every string in it; decision facts read the listed fields.";

const resourcesResponse = (records: string): string =>
  `A JSON object whose resources array holds ${records} and whose meta.pagination may carry total, offset, and next; a status outside 200 through 299 after retries, a body that is not a JSON object, or a missing resources array is a refusal.`;

const param = (
  name: string,
  location: RequestParameterContract["location"],
  value: string,
  required = true,
  when?: string,
): RequestParameterContract => ({ name, location, required, value, ...(when ? { when } : {}) });

const ACCESS_PROBE = "1 on the crowdstrike_check_access probe";
const offsetParameters = (records: string, pageSize: number, itemCap: number, probed: boolean): RequestParameterContract[] => [
  param("limit", "query", `${pageSize}, or the ${records} left under the ${itemCap} cap when fewer${probed ? `; ${ACCESS_PROBE}` : ""}`),
  param(
    "offset",
    "query",
    `The number of ${records} already read, or the previous page's meta.pagination.next (else meta.pagination.offset) when that is not a whole number`,
    false,
    "On every page after the first",
  ),
];

const apiSurface = (
  id: string,
  path: string,
  collection: string,
  fields: readonly string[],
  parameters: readonly RequestParameterContract[],
  responseShape: string,
): BatchSurfaceDefinition => ({
  id,
  path,
  service: API_SERVICE,
  documentationUrl: `${API_DOCS}/${collection}/`,
  fields,
  request: { clientRegion: API_HOST, headers: READ_HEADERS, parameters, responseShape },
  projectionStage: RAW_EXPORT_STAGE,
});

const PREVENTION_SURFACES: readonly BatchSurfaceDefinition[] = [
  apiSurface(
    "prevention_policies",
    "/policy/combined/prevention/v1",
    "prevention-policy",
    [
      "id",
      "name",
      "platform_name",
      "enabled",
      "platform_default",
      "groups",
      "prevention_settings.settings.id",
      "prevention_settings.settings.value.enabled",
      "prevention_settings.settings.value.detection",
      "prevention_settings.settings.value.prevention",
    ],
    offsetParameters("policies", 500, 5000, true),
    resourcesResponse("one prevention policy per entry"),
  ),
];

const CROWDSTRIKE_SURFACES: readonly BatchSurfaceDefinition[] = [
  ...PREVENTION_SURFACES,
];

const value = (entry: PortableValue): VerdictOperand => ({ kind: "value", value: entry });
const path = (name: string): VerdictOperand => ({ kind: "path", path: name });
type Comparator = "eq" | "ne" | "gt" | "lt" | "lte";
const cmp = (op: Comparator, left: string | VerdictOperand, right: PortableValue | VerdictOperand): VerdictCondition => ({
  op,
  left: typeof left === "string" ? path(left) : left,
  right: right !== null && typeof right === "object" && !Array.isArray(right) ? right as VerdictOperand : value(right as PortableValue),
});
const eq = (left: string | VerdictOperand, right: PortableValue | VerdictOperand) => cmp("eq", left, right);
const ne = (left: string | VerdictOperand, right: PortableValue | VerdictOperand) => cmp("ne", left, right);
const gt = (left: string | VerdictOperand, right: PortableValue | VerdictOperand) => cmp("gt", left, right);
const lt = (left: string | VerdictOperand, right: PortableValue | VerdictOperand) => cmp("lt", left, right);
const lte = (left: string | VerdictOperand, right: PortableValue | VerdictOperand) => cmp("lte", left, right);
const all = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "and", conditions });
const any = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "or", conditions });
const some = (name: string, condition: VerdictCondition): VerdictCondition => ({ op: "some", path: name, condition });
const always: VerdictCondition = { op: "always" };
const rule = (status: VerdictRule["status"], condition: VerdictCondition): VerdictRule => ({ status, condition });

// A fail that rests on no assigned policy is provable only against a complete list, so a partial list renders it manual.
const noAssignedPolicy = (count: string, complete: string): VerdictRule[] => [
  rule("manual", all(eq(count, 0), ne(complete, true))),
  rule("fail", eq(count, 0)),
];

const TRUTHY = "the boolean true or a string that trims to true, 1, yes, enabled, or on in any letter case";
const FALSY = "the boolean false or a string that trims to false, 0, no, disabled, or off in any letter case";
const ASSIGNED = "assigned prevention policies, as counted by assigned_prevention_policy_count";
const CARRIES = "A policy carries a setting when one of its prevention_settings[].settings[] entries has that id after trimming, and the last such entry wins.";
const NOT_ENABLED = `A carried setting is enabled only when its value.enabled is ${TRUTHY}; false, absent, and every other value count as not enabled.`;
const CORE_MITIGATIONS = "ForceASLR, ForceDEP, HeapSprayPreallocation, NullPageAllocation, and SEHOverwriteProtection";
const EXTENDED_MITIGATIONS = "ApplicationExploitationActivity, ChopperWebshell, DriveByDownload, ProcessHollowing, JavaScriptViaRundll32, and HardwareEnhancedExploitDetection";
const SCRIPT_CONTROLS = "ScriptBasedExecutionMonitoring, InterpreterProtection, and EngineProtectionV2";

const CROWDSTRIKE_INPUTS: Readonly<Record<string, string>> = {
  prevention_policies_readable: "True when GET /policy/combined/prevention/v1 returned its prevention policy list without a refusal.",
  prevention_policies_complete: "Prevention policy list coverage.",
  assigned_prevention_policy_count: `Number of returned prevention policies whose enabled is ${TRUTHY} and that reach hosts through a non-empty groups array, a platform_default of ${TRUTHY}, or a name that trims and lowercases to platform_default.`,
  assigned_policy_min_ml_ranks: `Lowest ranked machine learning level of each of the ${ASSIGNED}, over the value.detection and value.prevention of its CloudAntiMalware and OnSensorMLSlider settings; a level trimmed and uppercased ranks DISABLED 0, CAUTIOUS 1, MODERATE 2, AGGRESSIVE 3, or EXTRA_AGGRESSIVE 4, any other level is unranked, and a policy with no ranked level contributes no entry. ${CARRIES}`,
  assigned_policies_with_unranked_sliders: `Number of ${ASSIGNED} that do not carry CloudAntiMalware or OnSensorMLSlider, or whose value.detection or value.prevention on either is absent or unranked as defined for assigned_policy_min_ml_ranks. ${CARRIES}`,
  platforms_without_assigned_policy_count: `Number of the platforms Windows, Mac, and Linux that are not the platform_name, compared trimmed and ignoring letter case, of any of the ${ASSIGNED}; recorded only when the prevention policy list is complete.`,
  exploit_mitigation_policy_count: `Number of ${ASSIGNED} that carry at least one of ${CORE_MITIGATIONS}, ${EXTENDED_MITIGATIONS}. ${CARRIES}`,
  policies_with_core_mitigation_disabled: `Number of ${ASSIGNED} that carry one of ${CORE_MITIGATIONS} without enabling it. ${CARRIES} ${NOT_ENABLED}`,
  policies_with_extended_mitigation_disabled: `Number of ${ASSIGNED} that carry one of ${EXTENDED_MITIGATIONS} without enabling it. ${CARRIES} ${NOT_ENABLED}`,
  script_control_policy_count: `Number of ${ASSIGNED} that carry at least one of ${SCRIPT_CONTROLS}. ${CARRIES}`,
  policies_with_script_control_disabled: `Number of ${ASSIGNED} that carry one of ${SCRIPT_CONTROLS} without enabling it. ${CARRIES} ${NOT_ENABLED}`,
  policies_with_tamper_protection_disabled: `Number of ${ASSIGNED} that carry SensorTamperingProtection without enabling it. ${CARRIES} ${NOT_ENABLED}`,
  policies_without_tamper_protection_setting: `Number of ${ASSIGNED} that do not carry SensorTamperingProtection. ${CARRIES}`,
  policies_with_detect_on_write_disabled: `Number of ${ASSIGNED} whose DetectOnWrite value.enabled is ${FALSY}. ${CARRIES}`,
  policies_with_detect_on_write_unknown: `Number of ${ASSIGNED} that do not carry DetectOnWrite, or whose DetectOnWrite value.enabled is neither ${TRUTHY} nor ${FALSY}. ${CARRIES}`,
  policies_without_quarantine_on_write: `Number of ${ASSIGNED} that do not carry QuarantineOnWrite, or whose QuarantineOnWrite value.enabled is not ${TRUTHY}. ${CARRIES}`,
};

const inputs = (...names: string[]): Readonly<Record<string, string>> => Object.fromEntries(names.map((name) => {
  const definition = CROWDSTRIKE_INPUTS[name];
  if (!definition) throw new Error(`CrowdStrike decision input ${name} has no portable definition`);
  return [name, definition];
}));

const completeFrom = (
  semantics: string,
  sources: BatchCompletenessDefinition["sources"],
): BatchCompletenessDefinition => ({ semantics, sources });

const offsetWalkComplete = (surfaceId: string, list: string, cap: string): BatchCompletenessDefinition => completeFrom(
  `false when the ${list} is partial: it stopped at ${cap} below meta.pagination.total (or, without a total, after a full last page or a cursor that is not a whole number), at an empty page before meta.pagination.total, or at a repeated cursor that is not a whole number, or a returned resource is not a JSON object.`,
  [{ surfaceId, falseWhen: ["truncated"] }],
);

const PREVENTION_POLICIES_COMPLETE = offsetWalkComplete("prevention_policies", "prevention policy list", "5000 policies");

type CrowdstrikeCheck = {
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

const PREVENTION = "crowdstrike_assess_prevention_policies";

const PREVENTION_BASE = ["prevention_policies_readable", "prevention_policies_complete", "assigned_prevention_policy_count"];
const preventionRules = (...decisive: VerdictRule[]): VerdictRule[] => [
  rule("manual", ne("prevention_policies_readable", true)),
  ...noAssignedPolicy("assigned_prevention_policy_count", "prevention_policies_complete"),
  ...decisive,
  rule("warn", ne("prevention_policies_complete", true)),
  rule("pass", always),
];
const PREVENTION_UNREADABLE = "Manual when the prevention policy list is unreadable, or when it is partial and shows no assigned policy. Fail when no prevention policy is assigned.";
const PREVENTION_PARTIAL = "Warn instead of pass when the prevention policy list is partial. Otherwise pass.";
const preventionExamples = (
  check: string,
  readable: Readonly<Record<string, unknown>>,
): BatchCriterionExample[] => [
  example("noncompliant", "fail", "The complete prevention policy list holds no enabled policy that reaches hosts.", {
    prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 0, ...readable,
  }),
  example("partial", "manual", `The list stopped at the 5000-policy cap before any assigned policy was visible, so ${check} cannot rest on the absence.`, {
    prevention_policies_readable: true, prevention_policies_complete: false, assigned_prevention_policy_count: 0,
  }),
  example("unreadable", "manual", "The prevention policy list was refused.", { prevention_policies_readable: false }),
];

const PREVENTION_CHECKS: readonly CrowdstrikeCheck[] = [
  {
    id: "CS-01",
    control: 1,
    title: "Prevention Policy - ML Detection Levels",
    severity: "high",
    owner: PREVENTION,
    surfaces: ["prevention_policies"],
    inputs: [...PREVENTION_BASE, "assigned_policy_min_ml_ranks", "assigned_policies_with_unranked_sliders", "platforms_without_assigned_policy_count"],
    rules: preventionRules(
      rule("fail", some("assigned_policy_min_ml_ranks", lte("$", 1))),
      rule("warn", any(
        gt("assigned_policies_with_unranked_sliders", 0),
        some("assigned_policy_min_ml_ranks", lt("$", 3)),
        gt("platforms_without_assigned_policy_count", 0),
      )),
    ),
    completeness: { prevention_policies_complete: PREVENTION_POLICIES_COMPLETE },
    decision: `${PREVENTION_UNREADABLE} Fail when an assigned policy's lowest ranked machine learning level is CAUTIOUS or DISABLED. Warn when an assigned policy does not carry CloudAntiMalware or OnSensorMLSlider or leaves one of their detection or prevention levels unranked, when an assigned policy's lowest ranked level is below AGGRESSIVE, or when no assigned policy names Windows, Mac, or Linux. ${PREVENTION_PARTIAL}`,
    examples: [
      example("compliant", "pass", "Every assigned policy keeps both sliders at AGGRESSIVE or higher and the three platforms are covered.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 3,
        assigned_policy_min_ml_ranks: [3, 4, 3], assigned_policies_with_unranked_sliders: 0, platforms_without_assigned_policy_count: 0,
      }),
      example("noncompliant", "fail", "One assigned policy runs a slider at CAUTIOUS.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 2,
        assigned_policy_min_ml_ranks: [1, 3], assigned_policies_with_unranked_sliders: 0, platforms_without_assigned_policy_count: 0,
      }),
      example("partial", "warn", "One assigned policy's lowest level is MODERATE.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 2,
        assigned_policy_min_ml_ranks: [2, 3], assigned_policies_with_unranked_sliders: 0, platforms_without_assigned_policy_count: 0,
      }),
      example("partial", "warn", "No assigned policy names Linux.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 2,
        assigned_policy_min_ml_ranks: [3, 4], assigned_policies_with_unranked_sliders: 0, platforms_without_assigned_policy_count: 1,
      }),
      ...preventionExamples("CS-01", { assigned_policy_min_ml_ranks: [], assigned_policies_with_unranked_sliders: 0 }),
    ],
  },
  {
    id: "CS-02",
    control: 2,
    title: "Prevention Policy - Exploit Mitigation",
    severity: "high",
    owner: PREVENTION,
    surfaces: ["prevention_policies"],
    inputs: [...PREVENTION_BASE, "exploit_mitigation_policy_count", "policies_with_core_mitigation_disabled", "policies_with_extended_mitigation_disabled"],
    rules: preventionRules(
      rule("warn", eq("exploit_mitigation_policy_count", 0)),
      rule("fail", gt("policies_with_core_mitigation_disabled", 0)),
      rule("warn", gt("policies_with_extended_mitigation_disabled", 0)),
    ),
    completeness: { prevention_policies_complete: PREVENTION_POLICIES_COMPLETE },
    decision: `${PREVENTION_UNREADABLE} Warn when no assigned policy carries any of the eleven exploit mitigation settings. Fail when an assigned policy carries one of ${CORE_MITIGATIONS} without enabling it. Warn when an assigned policy carries one of ${EXTENDED_MITIGATIONS} without enabling it. ${PREVENTION_PARTIAL}`,
    examples: [
      example("compliant", "pass", "Both assigned policies enable every exploit mitigation they carry.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 2,
        exploit_mitigation_policy_count: 2, policies_with_core_mitigation_disabled: 0, policies_with_extended_mitigation_disabled: 0,
      }),
      example("noncompliant", "fail", "An assigned policy carries ForceDEP without enabling it.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 2,
        exploit_mitigation_policy_count: 2, policies_with_core_mitigation_disabled: 1, policies_with_extended_mitigation_disabled: 0,
      }),
      example("partial", "warn", "An assigned policy turns ProcessHollowing off and every core mitigation on.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 2,
        exploit_mitigation_policy_count: 2, policies_with_core_mitigation_disabled: 0, policies_with_extended_mitigation_disabled: 1,
      }),
      example("partial", "warn", "No assigned policy carries an exploit mitigation setting.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 2,
        exploit_mitigation_policy_count: 0, policies_with_core_mitigation_disabled: 0, policies_with_extended_mitigation_disabled: 0,
      }),
      ...preventionExamples("CS-02", { exploit_mitigation_policy_count: 0 }),
    ],
  },
  {
    id: "CS-03",
    control: 3,
    title: "Prevention Policy - Script-Based Execution Control",
    severity: "medium",
    owner: PREVENTION,
    surfaces: ["prevention_policies"],
    inputs: [...PREVENTION_BASE, "script_control_policy_count", "policies_with_script_control_disabled"],
    rules: preventionRules(
      rule("warn", eq("script_control_policy_count", 0)),
      rule("fail", gt("policies_with_script_control_disabled", 0)),
    ),
    completeness: { prevention_policies_complete: PREVENTION_POLICIES_COMPLETE },
    decision: `${PREVENTION_UNREADABLE} Warn when no assigned policy carries ${SCRIPT_CONTROLS.replace(", and", ", or")}. Fail when an assigned policy carries one of them without enabling it. ${PREVENTION_PARTIAL}`,
    examples: [
      example("compliant", "pass", "Every assigned policy enables the script controls it carries.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 2,
        script_control_policy_count: 2, policies_with_script_control_disabled: 0,
      }),
      example("noncompliant", "fail", "An assigned policy carries InterpreterProtection without enabling it.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 2,
        script_control_policy_count: 2, policies_with_script_control_disabled: 1,
      }),
      example("partial", "warn", "No assigned policy carries a script control setting.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 2,
        script_control_policy_count: 0, policies_with_script_control_disabled: 0,
      }),
      example("partial", "warn", "The script controls pass on the visible policies, but the list stopped at the cap.", {
        prevention_policies_readable: true, prevention_policies_complete: false, assigned_prevention_policy_count: 2,
        script_control_policy_count: 2, policies_with_script_control_disabled: 0,
      }),
      ...preventionExamples("CS-03", { script_control_policy_count: 0 }),
    ],
  },
  {
    id: "CS-04",
    control: 4,
    title: "Prevention Policy - Sensor Tamper Protection",
    severity: "critical",
    owner: PREVENTION,
    surfaces: ["prevention_policies"],
    inputs: [...PREVENTION_BASE, "policies_with_tamper_protection_disabled", "policies_without_tamper_protection_setting"],
    rules: preventionRules(
      rule("fail", gt("policies_with_tamper_protection_disabled", 0)),
      rule("warn", gt("policies_without_tamper_protection_setting", 0)),
    ),
    completeness: { prevention_policies_complete: PREVENTION_POLICIES_COMPLETE },
    decision: `${PREVENTION_UNREADABLE} Fail when an assigned policy carries SensorTamperingProtection without enabling it, including a value.enabled that is absent or unrecognized. Warn when an assigned policy does not carry SensorTamperingProtection. ${PREVENTION_PARTIAL}`,
    examples: [
      example("compliant", "pass", "Every assigned policy enables SensorTamperingProtection.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 3,
        policies_with_tamper_protection_disabled: 0, policies_without_tamper_protection_setting: 0,
      }),
      example("noncompliant", "fail", "An assigned policy carries SensorTamperingProtection with value.enabled false.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 3,
        policies_with_tamper_protection_disabled: 1, policies_without_tamper_protection_setting: 0,
      }),
      example("partial", "warn", "An assigned policy does not carry SensorTamperingProtection.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 3,
        policies_with_tamper_protection_disabled: 0, policies_without_tamper_protection_setting: 1,
      }),
      ...preventionExamples("CS-04", { policies_with_tamper_protection_disabled: 0, policies_without_tamper_protection_setting: 0 }),
    ],
  },
  {
    id: "CS-05",
    control: 5,
    title: "Prevention Policy - On-Write Detection",
    severity: "medium",
    owner: PREVENTION,
    surfaces: ["prevention_policies"],
    inputs: [
      ...PREVENTION_BASE,
      "policies_with_detect_on_write_disabled",
      "policies_with_detect_on_write_unknown",
      "policies_without_quarantine_on_write",
    ],
    rules: preventionRules(
      rule("fail", gt("policies_with_detect_on_write_disabled", 0)),
      rule("warn", any(gt("policies_with_detect_on_write_unknown", 0), gt("policies_without_quarantine_on_write", 0))),
    ),
    completeness: { prevention_policies_complete: PREVENTION_POLICIES_COMPLETE },
    decision: `${PREVENTION_UNREADABLE} Fail when an assigned policy turns DetectOnWrite off. Warn when an assigned policy does not carry DetectOnWrite or gives it an unrecognized value.enabled, or does not enable QuarantineOnWrite. ${PREVENTION_PARTIAL}`,
    examples: [
      example("compliant", "pass", "Every assigned policy enables DetectOnWrite and QuarantineOnWrite.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 2,
        policies_with_detect_on_write_disabled: 0, policies_with_detect_on_write_unknown: 0, policies_without_quarantine_on_write: 0,
      }),
      example("noncompliant", "fail", "An assigned policy sets DetectOnWrite value.enabled to false.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 2,
        policies_with_detect_on_write_disabled: 1, policies_with_detect_on_write_unknown: 0, policies_without_quarantine_on_write: 1,
      }),
      example("partial", "warn", "DetectOnWrite is on everywhere, but one assigned policy leaves QuarantineOnWrite off.", {
        prevention_policies_readable: true, prevention_policies_complete: true, assigned_prevention_policy_count: 2,
        policies_with_detect_on_write_disabled: 0, policies_with_detect_on_write_unknown: 0, policies_without_quarantine_on_write: 1,
      }),
      ...preventionExamples("CS-05", {
        policies_with_detect_on_write_disabled: 0, policies_with_detect_on_write_unknown: 0, policies_without_quarantine_on_write: 0,
      }),
    ],
  },
];

const toCheck = (check: CrowdstrikeCheck): BatchCheckDefinition => {
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
    decisionConstants: check.constants ?? {},
    decisionRules: executable.rules,
    derivedFactRules: executable.derivedFactRules,
    ...(check.completeness ? { completeness: check.completeness } : {}),
    decision: check.decision,
    examples: check.examples,
  };
};

const checks: readonly BatchCheckDefinition[] = [
  ...PREVENTION_CHECKS,
].map(toCheck);
const idsFor = (owner: string): string[] => checks.filter((check) => check.owner === owner).map((check) => check.id);

const offsetWalk = (surfaceIds: readonly string[], records: string, pageSize: number, itemCap: number): BatchPaginationDefinition => ({
  surfaceIds,
  cursorFields: ["meta.pagination.total", "meta.pagination.next", "meta.pagination.offset"],
  pageSize,
  itemCap,
  pageCap: null,
  totalSemantics: `Pages of ${pageSize} ${records} (limit), or the ${records} left under the ${itemCap} cap when fewer. The first page sends no offset; each later page sends the previous page's meta.pagination.next (else meta.pagination.offset) when that is not a whole number, otherwise the number of ${records} already read. Without meta.pagination.total the walk runs to an empty page or the cap. A returned resource that is not a JSON object is dropped and marks the list partial.`,
  stopConditions: [
    `meta.pagination.total ${records} read`,
    `An empty page, which marks the list partial when fewer than meta.pagination.total ${records} were read`,
    `${itemCap} ${records} read, which marks the list partial when meta.pagination.total is larger or, without a total, when the last page was full or carried a cursor that is not a whole number`,
    "A cursor that is not a whole number and repeats an earlier page's, which marks the list partial",
  ],
});

const FRAMEWORK_REPORTS = ["fedramp", "cmmc", "soc2", "cis", "pci_dss", "disa_stig", "irap", "ismap"];

// The export runs every assessment and writes each one's datasets under its own category.
const RAW_DATA_FILES: Readonly<Record<string, readonly string[]>> = {
  prevention_policies: ["prevention_policies"],
};

export const CROWDSTRIKE_SPEC = buildBatchIntegrationSpec({
  slug: "crowdstrike-sec-inspector",
  displayName: "CrowdStrike Security Inspector",
  vendor: "CrowdStrike",
  category: "endpoint-security",
  summary: "Portable contract for the shipped CrowdStrike Falcon prevention policy, response readiness, device control and firewall, sensor coverage, and access governance assessments over the CrowdStrike Falcon API.",
  sourceModule: "cli/extensions/grc-tools/crowdstrike.ts",
  baseServices: [API_SERVICE],
  authentication: CROWDSTRIKE_AUTH_RESOLVER,
  permissions: [
    {
      id: "prevention-policies-read",
      kind: "oauth-scope",
      value: "Prevention policies: Read",
      unlocks: ["prevention_policies"],
    },
  ],
  surfaces: CROWDSTRIKE_SURFACES,
  checks,
  tools: {
    crowdstrike_check_access: [],
    crowdstrike_assess_prevention_policies: idsFor(PREVENTION),
    crowdstrike_export_audit_bundle: checks.map((check) => check.id),
  },
  pagination: [
    offsetWalk(["prevention_policies"], "policies", 500, 5000),
  ],
  rateLimit: {
    documentedLimit: "Per API client: responses report the limit in X-Ratelimit-Limit and the requests left in X-Ratelimit-Remaining, which the collector does not read.",
    retryHeaders: ["X-Ratelimit-RetryAfter", "Retry-After"],
    retryableStatuses: [429],
    retryableStatusRanges: [{ from: 500, to: 599 }],
    backoffPolicy: "Retry 429 and every status of 500 or above up to 4 times after the first attempt. The wait comes from X-Ratelimit-RetryAfter when the response carries it, else from Retry-After: a number above 1000000000000 is an epoch time in milliseconds, a number above 1000000000 an epoch time in seconds, any other non-negative number a count of seconds, and a value that is not a number is read as an HTTP date; an absent or unreadable value waits 250 milliseconds times 2 to the power of the number of earlier attempts. Every wait is clamped to 250 milliseconds through 15 seconds. A 401 discards the cached token and repeats the request once with a new one, and that repeat counts as one of the 4 retries. Requests that time out (30 seconds unless timeout_seconds or CS_TIMEOUT sets it) and network errors are not retried.",
  },
  runtimeBehavior: [],
  knownGaps: [],
  sensitiveFields: ["client_secret", "access_token", "Authorization"],
  credentialFormats: [
    "CrowdStrike Falcon API client ID and client secret, exchanged at /oauth2/token for a bearer token",
    "CrowdStrike Falcon OAuth2 bearer access token",
  ],
  output: buildBatchOutputContract({
    files: [
      "QUICK_REFERENCE.md",
      "metadata.json",
      ...Object.entries(RAW_DATA_FILES).flatMap(([category, names]) => names.map((name) => `core_data/${category}/${name}.json`)),
      ...Object.keys(RAW_DATA_FILES).map((category) => `analysis/${category}.json`),
      "analysis/access_check.json",
      "analysis/findings.json",
      "compliance/executive_summary.md",
      "compliance/unified_compliance_matrix.md",
      ...FRAMEWORK_REPORTS.map((key) => `compliance/frameworks/${key}.md`),
    ],
    conditionalFiles: ["_errors.log"],
    conditionalFileConditions: { "_errors.log": "Only when some reads fail but the bundle still completes." },
    overwritePolicy: "Allocate {cloud, else the base_url host}[-{member_cid}]-audit-bundle, lowercased with every run of characters outside a-z, 0-9, dot, underscore, and hyphen replaced by one hyphen, trimmed of leading and trailing hyphens, and cut to 80 characters (crowdstrike when nothing is left), or the first of -2 through -9 whose directory and zip are both free, and fail rather than overwrite.",
    archivePairing: "Write a sibling zip named from the exact allocated bundle-directory path plus .zip.",
  }),
  lastUpdated: "2026-10-18",
  redaction: {
    projectionStage: "Every response passes the data redaction pass when it is read, which rewrites remembered credential values in raw and encoded forms, credential carriers, and token-shaped text in every string. Alerts and RTR sessions are then exported projected to their declared snapshot fields, and every other dataset is exported as read.",
  },
});
