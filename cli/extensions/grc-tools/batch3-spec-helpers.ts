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
  batch2Rule,
  type Batch2CheckRow,
} from "./batch2-spec-helpers.js";
import type {
  BatchCheckDefinition,
  BatchCompletenessDefinition,
  BatchCompletenessSourceDefinition,
} from "./batch-spec-builder.js";
import type { FindingSeverity, PortableValue, VerdictRule } from "./spec-model.js";

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
  thresholdOnly?: boolean;
}

export interface Batch3ThresholdDefinition {
  constant: string;
  observedFact: string;
  configuredFact?: string;
  comparator: "gt" | "gte" | "lt" | "lte";
  status: "fail" | "warn";
  observedDescription: string;
  configuredDescription?: string;
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

const REGISTERED_FACT_NAMES = new Map<string, Batch3FactNames>();

function checkPrefix(id: string): string {
  return id.toLowerCase().replaceAll("-", "_");
}

function semanticStem(title: string): string {
  return title
    .toLowerCase()
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
    const names = batch3FactNames(row.id);
    const baseDecisionInputs = row.decisionInputs ?? (row.manualOnly ? {} : {
      [names.readable]: `Boolean set from the named source read results before any finding is created. True only when every response and required field used by ${row.id} is readable.`,
      [names.complete]: `Boolean set from the named pagination and child-read states before any finding is created. Its exact source-state effects are defined by the ${row.id} completeness contract.`,
      [names.population]: `Non-negative integer cardinality of the exact ${row.id} record population evaluated before evidence samples are sliced. It is null when that population was not established.`,
      [names.failureMatches]: `Non-negative integer counted directly from primitive vendor fields before any per-record status exists. Exact predicate: ${row.predicate}`,
      [names.reviewMatches]: `Non-negative integer counted directly from missing, unknown, or review-only primitive fields before any per-record status exists. Exact predicate and precedence: ${row.predicate}`,
    });
    const thresholdDecisionInputs = Object.fromEntries((row.thresholds ?? []).flatMap((threshold) => [
      [threshold.observedFact, threshold.observedDescription],
      ...(threshold.configuredFact
        ? [[threshold.configuredFact, threshold.configuredDescription
          ?? `Resolved runtime configuration for ${threshold.constant}; null means configuration resolution failed and cannot independently pass.`] as const]
        : []),
    ]));
    const decisionInputs = { ...baseDecisionInputs, ...thresholdDecisionInputs };
    const comparison = (
      comparator: Batch3ThresholdDefinition["comparator"],
      leftPath: string,
      rightPath: string,
    ) => ({
      op: comparator,
      left: batch2Path(leftPath),
      right: batch2Path(rightPath),
    } as const);
    const thresholdRules = (row.thresholds ?? []).map((threshold) => batch2Rule(
      threshold.status,
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
      `${threshold.observedFact} is compared directly to ${threshold.configuredFact ?? threshold.constant}; ${threshold.constant} is the executable default boundary.`,
    ));
    const unreadableRule = batch2Rule("manual", batch2Any(
      batch2Ne(names.readable, true),
      batch2Not(batch2Defined(names.readable)),
      ...(row.incompleteOutcome === "manual" ? [batch2Ne(names.complete, true)] : []),
    ));
    const violationRule = batch2Rule(row.violationOutcome ?? "fail", batch2Gt(names.failureMatches, 0));
    const suppliedDecisionRules = row.decisionRules ?? (row.manualOnly ? undefined : [
      ...(row.incompleteOutcome === "manual"
        ? [unreadableRule, ...thresholdRules, ...(row.thresholdOnly ? [] : [violationRule])]
        : [...thresholdRules, ...(row.thresholdOnly ? [] : [violationRule]), unreadableRule]),
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
                  batch2All(...Object.keys(decisionInputs).map((name) => batch2Defined(name))),
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
      ? `${row.id} has no automated source dataset; no collection state can establish completeness.`
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
          ? `${names.complete}: ${row.completenessSemantics}`
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
