import {
  batch2Checks,
  batch2Completeness,
  batch2All,
  batch2Any,
  batch2Defined,
  batch2Eq,
  batch2Gt,
  batch2Ne,
  batch2Not,
  batch2Path,
  batch2Rule,
  type Batch2CheckRow,
} from "./batch2-spec-helpers.js";
import type {
  BatchCheckDefinition,
  BatchCompletenessDefinition,
  BatchCompletenessSourceDefinition,
} from "./batch-spec-builder.js";
import type { FindingSeverity, PortableValue, VerdictCondition, VerdictRule } from "./spec-model.js";

export interface Batch3CheckRow {
  id: string;
  control: number;
  title: string;
  severity: FindingSeverity;
  owner: string;
  surfaces: readonly string[];
  predicate: string;
  emptyOutcome?: "pass" | "warn" | "fail" | "manual" | "info";
  violationOutcome?: "fail" | "warn";
  incompleteOutcome?: "warn" | "manual";
  manualOnly?: boolean;
  constants?: Readonly<Record<string, PortableValue>>;
  decisionInputs?: Readonly<Record<string, string>>;
  decisionRules?: readonly VerdictRule[];
  completeness?: Readonly<Record<string, BatchCompletenessDefinition>>;
  completenessSources?: readonly BatchCompletenessSourceDefinition[];
  completenessSemantics?: string;
  runtimeFactNames?: Batch3FactNames;
  thresholds?: readonly Batch3ThresholdDefinition[];
  collectionRules?: readonly Batch3CollectionRuleDefinition[];
  thresholdOnly?: boolean;
  primitiveRuleIndex?: number;
}

export interface Batch3CollectionRuleDefinition {
  constant: string;
  observedFact: string;
  evidencePath: string;
  operator: "intersects" | "matchesAny";
  status: "fail" | "warn";
  observedDescription: string;
  flags?: string;
}

export function batch3CollectionRule(
  id: string,
  constant: string,
  evidencePath: string,
  operator: Batch3CollectionRuleDefinition["operator"],
  status: Batch3CollectionRuleDefinition["status"],
  observedMeaning: string,
  flags?: string,
): Batch3CollectionRuleDefinition {
  return {
    constant,
    observedFact: `${checkPrefix(id)}_${constant}_observed_values`,
    evidencePath,
    operator,
    status,
    observedDescription: `${id} primitive collection from ${evidencePath}: ${observedMeaning} The uncapped values are captured before any finding status or presentation sample; null means the named source did not expose the collection.`,
    ...(flags ? { flags } : {}),
  };
}

export interface Batch3ThresholdDefinition {
  constant: string;
  observedFact: string;
  evidencePath: string;
  configuredFact?: string;
  configuredEvidencePath?: string;
  comparator: "gt" | "gte" | "lt" | "lte";
  status: "fail" | "warn";
  observedDescription: string;
  configuredDescription?: string;
  guard?: VerdictCondition;
}

export function batch3Threshold(
  id: string,
  constant: string,
  evidencePath: string,
  comparator: Batch3ThresholdDefinition["comparator"],
  status: Batch3ThresholdDefinition["status"],
  observedMeaning: string,
  configuredEvidencePath?: string,
  guard?: VerdictCondition,
): Batch3ThresholdDefinition {
  const prefix = checkPrefix(id);
  return {
    constant,
    observedFact: `${prefix}_${constant}_observed_value`,
    evidencePath,
    ...(configuredEvidencePath
      ? {
          configuredFact: `${prefix}_${constant}_configured_value`,
          configuredEvidencePath,
          configuredDescription: `${id} resolved configuration read from ${configuredEvidencePath}; null means the configured boundary was unavailable, so the declared ${constant} default is used.`,
        }
      : {}),
    comparator,
    status,
    observedDescription: `${id} primitive from ${evidencePath}: ${observedMeaning} This value is captured before a finding status is selected; null means the named source did not expose a comparable value.`,
    ...(guard ? { guard } : {}),
  };
}

export interface Batch3FactNames {
  readable: string;
  complete: string;
  population: string;
  failureMatches: string;
  reviewMatches: string;
}

export interface Batch3RuntimeFactValues {
  readable: boolean;
  complete: boolean;
  population: number | null;
  failureMatches: number | null;
  reviewMatches: number | null;
}

export const BATCH3_RUNTIME_FACTS = Symbol("batch3-runtime-facts");
const BATCH3_PRIMITIVE_EVIDENCE = Symbol("batch3-primitive-evidence");

export type Batch3FindingWithFacts = {
  [BATCH3_RUNTIME_FACTS]?: Readonly<Record<string, unknown>>;
};

const REGISTERED_FACT_NAMES = new Map<string, Batch3FactNames>();
const REGISTERED_THRESHOLDS = new Map<string, readonly Batch3ThresholdDefinition[]>();
const REGISTERED_COLLECTION_RULES = new Map<string, readonly Batch3CollectionRuleDefinition[]>();

function checkPrefix(id: string): string {
  return id.toLowerCase().replaceAll("-", "_");
}

function semanticStem(title: string): string {
  return title
    .toLowerCase()
    .replaceAll(/\bcompleteness\b/g, "coverage")
    .replaceAll(/\bstatus\b/g, "state")
    .replaceAll(/\b(?:label|verdict|outcome)\b/g, "result")
    .replaceAll(/[^a-z0-9]+/g, "_")
    .replaceAll(/^_+|_+$/g, "");
}

function checkOwnedFactNames(row: Pick<Batch3CheckRow, "id" | "title">): Batch3FactNames {
  const prefix = checkPrefix(row.id);
  const stem = semanticStem(row.title);
  return {
    readable: `${prefix}_${stem}_sources_readable`,
    complete: `${prefix}_${stem}_population_complete`,
    population: `${prefix}_${stem}_population_count`,
    failureMatches: `${prefix}_${stem}_violation_count`,
    reviewMatches: `${prefix}_${stem}_review_count`,
  };
}

export function batch3FactNames(id: string): Batch3FactNames {
  const registered = REGISTERED_FACT_NAMES.get(id);
  if (!registered) throw new Error(`${id}: check-owned runtime fact names were not registered by its adjacent specification`);
  return registered;
}

function evidencePathValue(evidence: Readonly<Record<string, unknown>>, path: string): unknown {
  const valuesAtPath = (value: unknown, segments: readonly string[]): unknown[] => {
    if (segments.length === 0) return Array.isArray(value) ? value.flatMap((entry) => valuesAtPath(entry, [])) : [value];
    if (Array.isArray(value)) return value.flatMap((entry) => valuesAtPath(entry, segments));
    if (value === null || typeof value !== "object") return [];
    return valuesAtPath((value as Readonly<Record<string, unknown>>)[segments[0]], segments.slice(1));
  };
  const containersAtPath = (value: unknown, segments: readonly string[]): unknown[] => {
    if (segments.length === 0) return [value];
    if (Array.isArray(value)) return value.flatMap((entry) => containersAtPath(entry, segments));
    if (value === null || typeof value !== "object") return [];
    return containersAtPath((value as Readonly<Record<string, unknown>>)[segments[0]], segments.slice(1));
  };
  const aggregate = /^(min|max|length|flatten|maxLength|keys):(.+)$/.exec(path);
  if (aggregate) {
    const [, operation, nestedPath] = aggregate;
    const values = valuesAtPath(evidence, nestedPath.split("."));
    if (operation === "length") {
      const containers = containersAtPath(evidence, nestedPath.split("."));
      return containers.length === 1 && Array.isArray(containers[0]) ? containers[0].length : values.length;
    }
    if (operation === "flatten") return values.filter((value) => value !== undefined && value !== null);
    if (operation === "keys") {
      return [...new Set(values.flatMap((value) =>
        value !== null && typeof value === "object" && !Array.isArray(value) ? Object.keys(value) : []))];
    }
    if (operation === "maxLength") {
      const lengths = containersAtPath(evidence, nestedPath.split("."))
        .map((value) => Array.isArray(value) ? value.length : undefined)
        .filter((value): value is number => value !== undefined);
      return lengths.length === 0 ? undefined : Math.max(...lengths);
    }
    const numbers = values.filter((value): value is number => typeof value === "number" && Number.isFinite(value));
    if (numbers.length === 0) return undefined;
    return operation === "min" ? Math.min(...numbers) : Math.max(...numbers);
  }
  let current: unknown = evidence;
  for (const segment of path.split(".")) {
    if (current === null || typeof current !== "object" || Array.isArray(current)) return undefined;
    current = (current as Readonly<Record<string, unknown>>)[segment];
  }
  return current;
}

function finiteNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

export function batch3PrimitiveEvidence<T extends Readonly<Record<string, unknown>>>(
  evidence: T,
  values: Readonly<Record<string, unknown>>,
): T {
  Object.defineProperty(evidence, BATCH3_PRIMITIVE_EVIDENCE, { value: values });
  return evidence;
}

export function batch3MergePrimitiveEvidence(
  evidence: Readonly<Record<string, unknown>>,
  extra: Readonly<Record<string, unknown>>,
): Readonly<Record<string, unknown>> {
  const primitiveEvidence = (evidence as { [BATCH3_PRIMITIVE_EVIDENCE]?: Readonly<Record<string, unknown>> })[
    BATCH3_PRIMITIVE_EVIDENCE
  ] ?? {};
  return batch3PrimitiveEvidence({ ...evidence, ...extra }, primitiveEvidence);
}

export function batch3AttachRuntimeFacts<T extends object>(
  finding: T,
  facts: Readonly<Record<string, unknown>>,
): T & Batch3FindingWithFacts {
  Object.defineProperty(finding, BATCH3_RUNTIME_FACTS, { value: facts });
  return finding;
}

export function batch3PrimitiveFacts(
  id: string,
  evidence: Readonly<Record<string, unknown>>,
  facts: Readonly<Record<string, unknown>>,
): Readonly<Record<string, unknown>> {
  const thresholds = REGISTERED_THRESHOLDS.get(id) ?? [];
  const collectionRules = REGISTERED_COLLECTION_RULES.get(id) ?? [];
  const primitiveEvidence = (evidence as { [BATCH3_PRIMITIVE_EVIDENCE]?: Readonly<Record<string, unknown>> })[
    BATCH3_PRIMITIVE_EVIDENCE
  ] ?? {};
  const valueFor = (factName: string, evidencePath: string): unknown =>
    Object.hasOwn(facts, factName)
      ? facts[factName]
      : Object.hasOwn(primitiveEvidence, evidencePath)
        ? primitiveEvidence[evidencePath]
        : evidencePathValue(evidence, evidencePath);
  return {
    ...facts,
    ...Object.fromEntries(thresholds.flatMap((threshold) => [
      [threshold.observedFact, finiteNumber(valueFor(threshold.observedFact, threshold.evidencePath))],
      ...(threshold.configuredFact
        ? [[
            threshold.configuredFact,
            finiteNumber(valueFor(
              threshold.configuredFact,
              threshold.configuredEvidencePath ?? threshold.evidencePath,
            )),
          ] as const]
        : []),
    ])),
    ...Object.fromEntries(collectionRules.map((rule) => [
      rule.observedFact,
      valueFor(rule.observedFact, rule.evidencePath) ?? null,
    ])),
  };
}

export function batch3RuntimeFacts(
  id: string,
  values: Batch3RuntimeFactValues,
): Readonly<Record<string, unknown>> {
  const names = batch3FactNames(id);
  return {
    [names.readable]: values.readable,
    [names.complete]: values.complete,
    [names.population]: values.population,
    [names.failureMatches]: values.failureMatches,
    [names.reviewMatches]: values.reviewMatches,
  };
}

export function batch3UnavailableFacts(id: string): Readonly<Record<string, unknown>> {
  return batch3RuntimeFacts(id, {
    readable: false,
    complete: false,
    population: null,
    failureMatches: null,
    reviewMatches: null,
  });
}

export function batch3SetCompleteness(
  id: string,
  facts: Readonly<Record<string, unknown>>,
  complete: boolean,
): Readonly<Record<string, unknown>> {
  return { ...facts, [batch3FactNames(id).complete]: complete };
}

export function batch3SetReadability(
  id: string,
  facts: Readonly<Record<string, unknown>>,
  readable: boolean,
): Readonly<Record<string, unknown>> {
  return { ...facts, [batch3FactNames(id).readable]: readable };
}

export function batch3SetReviewMinimum(
  id: string,
  facts: Readonly<Record<string, unknown>>,
  minimum: number,
): Readonly<Record<string, unknown>> {
  const reviewName = batch3FactNames(id).reviewMatches;
  const current = facts[reviewName];
  return {
    ...facts,
    [reviewName]: Math.max(typeof current === "number" ? current : 0, minimum),
  };
}

export function batch3SetPopulation(
  id: string,
  facts: Readonly<Record<string, unknown>>,
  population: number | null,
): Readonly<Record<string, unknown>> {
  return { ...facts, [batch3FactNames(id).population]: population };
}

const ALL_INCOMPLETE_STATES = [
  "truncated",
  "error",
  "denied",
  "not-collected",
  "not-configured",
  "missing-required-field",
] as const;

export function batch3Source(
  surfaceId: string,
  falseWhen: BatchCompletenessSourceDefinition["falseWhen"] = ALL_INCOMPLETE_STATES,
): BatchCompletenessSourceDefinition {
  return { surfaceId, falseWhen };
}

export function batch3Checks(rows: readonly Batch3CheckRow[]): BatchCheckDefinition[] {
  return batch2Checks(rows.map((row): Batch2CheckRow => {
    REGISTERED_FACT_NAMES.set(row.id, row.runtimeFactNames ?? checkOwnedFactNames(row));
    REGISTERED_THRESHOLDS.set(row.id, row.thresholds ?? []);
    REGISTERED_COLLECTION_RULES.set(row.id, row.collectionRules ?? []);
    const names = batch3FactNames(row.id);
    const baseDecisionInputs = row.decisionInputs ?? (row.manualOnly ? {} : {
      [names.readable]: `Boolean set from the named source read results before any finding is created. True only when every response and required field used by ${row.id} is readable.`,
      [names.complete]: `Boolean set from the named pagination and child-read states before any finding is created. Its exact source-state effects are defined by the ${row.id} completeness contract.`,
      [names.population]: `Non-negative integer cardinality of the exact ${row.id} record population evaluated before evidence samples are sliced. It is null when that population was not established.`,
      [names.failureMatches]: `Non-negative integer counted from the named vendor fields before any finding is created. Exact predicate: ${row.predicate}`,
      [names.reviewMatches]: `Non-negative integer counted from missing, unknown, or review-only vendor fields before any finding is created. Exact predicate and precedence: ${row.predicate}`,
    });
    const thresholdDecisionInputs = Object.fromEntries((row.thresholds ?? []).flatMap((threshold) => [
      [threshold.observedFact, threshold.observedDescription],
      ...(threshold.configuredFact
        ? [[threshold.configuredFact, threshold.configuredDescription
          ?? `Resolved runtime configuration for ${threshold.constant}; null means configuration resolution failed and cannot independently pass.`] as const]
        : []),
    ]));
    const collectionDecisionInputs = Object.fromEntries((row.collectionRules ?? []).map((rule) => [
      rule.observedFact,
      rule.observedDescription,
    ]));
    const decisionInputs = { ...baseDecisionInputs, ...thresholdDecisionInputs, ...collectionDecisionInputs };
    const comparison = (
      comparator: Batch3ThresholdDefinition["comparator"],
      leftPath: string,
      rightPath: string,
    ) => ({
      op: comparator,
      left: batch2Path(leftPath),
      right: batch2Path(rightPath),
    } as const);
    const thresholdRules = (row.thresholds ?? []).map((threshold) => {
      const thresholdCondition = batch2All(
        batch2Eq(names.readable, true),
        batch2Gt(names.population, 0),
        batch2Defined(threshold.observedFact),
        threshold.configuredFact
          ? batch2Any(
              batch2All(
                batch2Defined(threshold.configuredFact),
                comparison(threshold.comparator, threshold.observedFact, threshold.configuredFact),
              ),
              batch2All(
                batch2Not(batch2Defined(threshold.configuredFact)),
                comparison(threshold.comparator, threshold.observedFact, threshold.constant),
              ),
            )
          : comparison(threshold.comparator, threshold.observedFact, threshold.constant),
      );
      return batch2Rule(
        threshold.status,
        threshold.guard ? batch2All(threshold.guard, thresholdCondition) : thresholdCondition,
        `${threshold.observedFact} is compared directly to ${threshold.configuredFact ?? threshold.constant}; ${threshold.constant} is the executable default boundary.`,
      );
    });
    const collectionRules = (row.collectionRules ?? []).map((rule) => batch2Rule(
      rule.status,
      batch2All(
        batch2Eq(names.readable, true),
        batch2Gt(names.population, 0),
        rule.operator === "intersects"
          ? {
              op: "intersects",
              left: batch2Path(rule.observedFact),
              right: batch2Path(rule.constant),
            }
          : {
              op: "matchesAny",
              candidates: batch2Path(rule.observedFact),
              patterns: batch2Path(rule.constant),
              ...(rule.flags ? { flags: rule.flags } : {}),
            },
      ),
      `${rule.observedFact} is evaluated directly against executable ${rule.constant}.`,
    ));
    const primitiveRules = [...thresholdRules, ...collectionRules];
    const unreadableRule = batch2Rule("manual", batch2Any(
      batch2Ne(names.readable, true),
      batch2Not(batch2Defined(names.readable)),
      ...(row.incompleteOutcome === "manual" ? [batch2Ne(names.complete, true)] : []),
    ));
    const violationRule = batch2Rule(row.violationOutcome ?? "fail", batch2Gt(names.failureMatches, 0));
    const primitiveFailRules = primitiveRules.filter((rule) => rule.status === "fail");
    const primitiveWarnRules = primitiveRules.filter((rule) => rule.status === "warn");
    const primitiveRulesBeforeViolation = row.violationOutcome === "warn"
      ? [...primitiveFailRules, ...primitiveWarnRules]
      : primitiveFailRules;
    const primitiveRulesAfterViolation = row.violationOutcome === "warn"
      ? []
      : primitiveWarnRules;
    const explicitRules = row.decisionRules && primitiveRules.length > 0
      ? [
          ...row.decisionRules.slice(0, row.primitiveRuleIndex ?? -1),
          ...primitiveRules,
          ...row.decisionRules.slice(row.primitiveRuleIndex ?? -1),
        ]
      : row.decisionRules;
    const suppliedDecisionRules = explicitRules ?? (row.manualOnly ? undefined : [
      ...(row.incompleteOutcome === "manual"
        ? [
            unreadableRule,
            ...primitiveRulesBeforeViolation,
            ...(row.thresholdOnly ? [] : [violationRule]),
            ...primitiveRulesAfterViolation,
          ]
        : [
            ...primitiveRulesBeforeViolation,
            ...(row.thresholdOnly ? [] : [violationRule]),
            unreadableRule,
            ...primitiveRulesAfterViolation,
          ]),
      ...(row.emptyOutcome === undefined || row.emptyOutcome === "manual"
        ? [batch2Rule("manual", batch2Eq(names.population, 0))]
        : [batch2Rule(row.emptyOutcome, batch2All(batch2Eq(names.population, 0), batch2Eq(names.complete, true)))]),
      batch2Rule("warn", batch2Any(
        batch2Ne(names.complete, true),
        batch2Gt(names.reviewMatches, 0),
      )),
      batch2Rule("pass", batch2All(
        batch2Eq(names.readable, true),
        batch2Eq(names.complete, true),
        batch2Eq(names.failureMatches, 0),
        batch2Eq(names.reviewMatches, 0),
      )),
      batch2Rule("manual", { op: "always" }),
    ]);
    const terminalRule = suppliedDecisionRules?.at(-1);
    const coreDecisionRules = suppliedDecisionRules
      ? [
          ...suppliedDecisionRules.map((rule) =>
            rule.status === "pass" && rule.condition.op === "always"
              ? batch2Rule(
                  "pass",
                  batch2All(...Object.keys(baseDecisionInputs).map((name) => batch2Defined(name))),
                  "Every declared primitive must be present and non-null before the fallback pass branch can match.",
                )
              : rule),
          ...(terminalRule?.status === "manual" && terminalRule.condition.op === "always"
            ? []
            : [batch2Rule("manual", { op: "always" }, "Missing, null, malformed, or contradictory primitives require manual review.")]),
        ]
      : undefined;
    const decisionRules = coreDecisionRules;
    const completenessSources = row.completenessSources
      ?? row.surfaces.map((surfaceId) => batch3Source(surfaceId));
    const exactCompletenessSemantics = completenessSources.length === 0
      ? `${names.complete} is always false because ${row.id} has no automated source dataset. No request is made, so truncated, error, denied, not-collected, not-configured, and missing-required-field states cannot establish completeness. Finding previews and exported samples never establish source cardinality.`
      : `${names.complete} is true only after ${completenessSources.map((source) => source.surfaceId).join(", ")} each completed and returned every field required by this check. Exact source-state effects: ${completenessSources.map((source) => `${source.surfaceId} sets ${names.complete} false on ${source.falseWhen.join(", ") || "no collection state"}`).join("; ")}. Finding previews and exported samples never establish source cardinality.`;
    return {
      id: row.id,
      control: row.control,
      title: row.title,
      severity: row.severity,
      owner: row.owner,
      surfaces: row.surfaces,
      decision: `${row.predicate} Counts are computed over the complete named source datasets before any finding preview or export sampling. Rules execute in the rendered order; proved violations precede incompleteness, and unavailable evidence cannot pass.`,
      emptyOutcome: row.emptyOutcome,
      violationOutcome: row.violationOutcome,
      manualOnly: row.manualOnly,
      constants: row.constants,
      decisionInputs,
      decisionRules,
      completeness: row.completeness ?? batch2Completeness(
        decisionInputs,
        completenessSources,
        row.completenessSemantics
          ? `${names.complete}: ${row.completenessSemantics} ${exactCompletenessSemantics}`
          : exactCompletenessSemantics,
      ),
      specificCriteria: true,
    };
  }));
}

export const BATCH3_FRAMEWORK_FILES = [
  "compliance/fedramp/fedramp_compliance_report.md",
  "compliance/cmmc/cmmc_compliance_report.md",
  "compliance/soc2/soc2_compliance_report.md",
  "compliance/cis/cis_compliance_report.md",
  "compliance/pci_dss/pci_dss_compliance_report.md",
  "compliance/disa_stig/disa_stig_compliance_report.md",
  "compliance/irap/irap_compliance_report.md",
  "compliance/ismap/ismap_compliance_report.md",
] as const;
