import {
  deriveDecisionRules,
  type BatchCheckDefinition,
  type BatchCompletenessDefinition,
  type BatchCompletenessSourceDefinition,
  type PortableInputType,
  type BatchSurfaceDefinition,
} from "./batch-spec-builder.js";
import type {
  FindingSeverity,
  FrameworkKey,
  PortableValue,
  VerdictCondition,
  VerdictOperand,
  VerdictRule,
} from "./spec-model.js";

export interface Batch2CheckRow {
  id: string;
  control: number;
  title: string;
  severity: FindingSeverity;
  owner: string;
  surfaces: readonly string[];
  decision: string;
  frameworks?: Partial<Record<FrameworkKey, readonly string[]>>;
  manualOnly?: boolean;
  emptyOutcome?: "pass" | "warn" | "fail" | "manual" | "info";
  violationOutcome?: "fail" | "warn";
  constants?: Readonly<Record<string, PortableValue>>;
  decisionInputs?: Readonly<Record<string, string>>;
  decisionRules?: readonly VerdictRule[];
  completeness?: Readonly<Record<string, BatchCompletenessDefinition>>;
}

export const batch2Value = (entry: PortableValue) => ({ kind: "value" as const, value: entry });
export const batch2Path = (name: string) => ({ kind: "path" as const, path: name });
export const batch2Compare = (
  op: "eq" | "ne" | "gt" | "gte" | "lt" | "lte",
  name: string,
  entry: PortableValue,
): VerdictCondition => ({ op, left: batch2Path(name), right: batch2Value(entry) });
export const batch2ComparePaths = (
  op: "eq" | "ne" | "gt" | "gte" | "lt" | "lte",
  left: string,
  right: string,
): VerdictCondition => ({ op, left: batch2Path(left), right: batch2Path(right) });
export const batch2Eq = (name: string, entry: PortableValue): VerdictCondition => batch2Compare("eq", name, entry);
export const batch2Ne = (name: string, entry: PortableValue): VerdictCondition => batch2Compare("ne", name, entry);
export const batch2Gt = (name: string, entry: PortableValue): VerdictCondition => batch2Compare("gt", name, entry);
export const batch2Gte = (name: string, entry: PortableValue): VerdictCondition => batch2Compare("gte", name, entry);
export const batch2Lt = (name: string, entry: PortableValue): VerdictCondition => batch2Compare("lt", name, entry);
export const batch2Lte = (name: string, entry: PortableValue): VerdictCondition => batch2Compare("lte", name, entry);
export const batch2All = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "and", conditions });
export const batch2Any = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "or", conditions });
export const batch2Defined = (name: string): VerdictCondition => ({ op: "defined", operand: batch2Path(name) });
export const batch2Not = (condition: VerdictCondition): VerdictCondition => ({ op: "not", condition });
export const batch2Rule = (status: VerdictRule["status"], condition: VerdictCondition, note?: string): VerdictRule => ({
  status,
  condition,
  ...(note ? { note } : {}),
});

export function batch2GenericDecisionInputs(
  predicate: string,
): Readonly<Record<string, string>> {
  return {
    evidence_readable: "Boolean collector state. True only when every vendor response and raw field needed by this check was returned and parseable; false, null, or missing means the check cannot pass.",
    evidence_complete: "Boolean collector state defined by this check's structured completeness contract; false, null, or missing cannot support pass.",
    inventory_count: "Non-negative integer computed over the complete required vendor inventories before any evidence-display slicing. Zero retains the check-specific empty-inventory outcome; null or missing means cardinality is unknown.",
    violation_count: `Non-negative integer computed over the complete required vendor inventories before display slicing. It counts records satisfying this exact predicate: ${predicate}`,
    review_count: `Non-negative integer computed over the complete required vendor inventories before display slicing. It counts records satisfying the warning or manual-review branches of this exact predicate, excluding records already counted as violations: ${predicate}`,
  };
}

export function batch2Completeness(
  decisionInputs: Readonly<Record<string, string>>,
  sources: readonly BatchCompletenessSourceDefinition[] | undefined,
  semantics: string | Readonly<Record<string, string>>,
): Readonly<Record<string, BatchCompletenessDefinition>> | undefined {
  const completenessInputs = Object.entries(decisionInputs).filter(([name]) => name.includes("complete"));
  if (completenessInputs.length > 0 && sources === undefined) {
    throw new Error(`Explicit completeness sources are required for ${completenessInputs.map(([name]) => name).join(", ")}`);
  }
  const declaredSources = sources ?? [];
  const entries = completenessInputs
    .map(([name]) => {
      const definition = typeof semantics === "string" ? semantics : semantics[name];
      if (!definition?.trim()) throw new Error(`Explicit completeness semantics are required for ${name}`);
      return [name, { sources: declaredSources, semantics: definition }] as const;
    });
  return entries.length > 0 ? Object.fromEntries(entries) : undefined;
}

function executableRules(row: Batch2CheckRow): readonly VerdictRule[] {
  if (row.decisionRules) return row.decisionRules;
  if (row.manualOnly) return [batch2Rule("manual", { op: "always" }, "The shipped runtime has no decisive read surface for this check.")];
  const emptyOutcome = row.emptyOutcome ?? "manual";
  const violationOutcome = row.violationOutcome ?? "fail";
  return [
    batch2Rule("manual", batch2Any(
      batch2Ne("evidence_readable", true),
      batch2Not(batch2Defined("evidence_readable")),
    ), "Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass."),
    batch2Rule(violationOutcome, batch2Gt("violation_count", 0), "A violation proved by readable evidence has precedence over partial companion inventories."),
    ...(emptyOutcome === "manual"
      ? [batch2Rule("manual", batch2Eq("inventory_count", 0), "This check's documented empty-inventory behavior requires manual confirmation.")]
      : [batch2Rule(emptyOutcome, batch2All(batch2Eq("inventory_count", 0), batch2Eq("evidence_complete", true)))]),
    batch2Rule("warn", batch2Any(
      batch2Ne("evidence_complete", true),
      batch2Gt("review_count", 0),
    ), "Incomplete source cardinality or an explicit review condition prevents pass."),
    batch2Rule("pass", batch2All(
      batch2Eq("evidence_readable", true),
      batch2Eq("evidence_complete", true),
      batch2Eq("violation_count", 0),
      batch2Eq("review_count", 0),
    )),
    batch2Rule("manual", { op: "always" }, "Unknown or contradictory evidence requires manual review."),
  ];
}

function collectOperandPaths(operand: VerdictOperand, paths: Set<string>): void {
  switch (operand.kind) {
    case "value":
      return;
    case "path":
    case "length":
      paths.add(operand.path);
      return;
    case "subtract":
      collectOperandPaths(operand.left, paths);
      collectOperandPaths(operand.right, paths);
      return;
    default: {
      const exhaustive: never = operand;
      return exhaustive;
    }
  }
}

function collectConditionPaths(condition: VerdictCondition, paths: Set<string>): void {
  switch (condition.op) {
    case "always":
      return;
    case "and":
    case "or":
      for (const child of condition.conditions) collectConditionPaths(child, paths);
      return;
    case "not":
      collectConditionPaths(condition.condition, paths);
      return;
    case "eq":
    case "ne":
    case "gt":
    case "gte":
    case "lt":
    case "lte":
      collectOperandPaths(condition.left, paths);
      collectOperandPaths(condition.right, paths);
      return;
    case "ratio":
      collectOperandPaths(condition.numerator, paths);
      collectOperandPaths(condition.denominator, paths);
      collectOperandPaths(condition.threshold, paths);
      return;
    case "matches":
    case "defined":
    case "null":
      collectOperandPaths(condition.operand, paths);
      return;
    case "some":
    case "every":
      paths.add(condition.path);
      collectConditionPaths(condition.condition, paths);
      return;
    default: {
      const exhaustive: never = condition;
      return exhaustive;
    }
  }
}

export function batch2DecisionInputPaths(rules: readonly VerdictRule[]): ReadonlySet<string> {
  const paths = new Set<string>();
  for (const rule of rules) collectConditionPaths(rule.condition, paths);
  return paths;
}

function portableTypes(name: string): readonly PortableInputType[] {
  if (
    /(?:^|_)(?:count|ratio|maximum|minimum|days?|hours?|seconds|percent|length)(?:_|$)/.test(name)
    || ["maximum_score", "score_ratio"].includes(name)
  ) {
    return ["number"];
  }
  if (
    /(?:^|_)(?:readable|complete|present|enabled|configured|required|denied|logged)(?:_|$)/.test(name)
    || [
      "license_present",
      "domain_allowlist",
      "external_resharing",
      "gateway_provisioned",
      "dns_or_http_filter_present",
      "exemptions_readable",
      "block_unscannable_files",
      "panos_configured",
      "prisma_configured",
      "external_forwarding_configured",
      "lowercase_required",
      "uppercase_required",
      "numeric_required",
      "special_required",
    ].includes(name)
  ) {
    return ["boolean"];
  }
  return ["string"];
}

export function batch2Checks(rows: readonly Batch2CheckRow[]): BatchCheckDefinition[] {
  const unusedInputs = rows.flatMap((row) => {
    const referenced = batch2DecisionInputPaths(executableRules(row));
    return Object.keys(row.decisionInputs ?? {})
      .filter((name) => !referenced.has(name))
      .map((name) => `${row.id}.${name}`);
  });
  if (unusedInputs.length > 0) {
    throw new Error(`Batch 2 decision inputs must feed executable rules: ${unusedInputs.join(", ")}`);
  }
  return rows.map((row) => {
    if (row.decisionInputs === undefined) {
      throw new Error(`${row.id} must declare explicit portable decision input definitions`);
    }
    const inputs = row.decisionInputs;
    const executable = deriveDecisionRules(row.id, executableRules(row));
    return {
      id: row.id,
      control: row.control,
      title: row.title,
      severity: row.severity,
      owner: row.owner,
      surfaces: row.surfaces,
      frameworks: row.frameworks,
      evidenceFields: [...row.surfaces, "complete_source_counts"],
      decisionInputs: inputs,
      decisionInputTypes: Object.fromEntries(Object.keys(inputs).map((name) => [name, portableTypes(name)])),
      decisionConstants: row.constants,
      decisionRules: executable.rules,
      derivedFactRules: executable.derivedFactRules,
      completeness: row.completeness,
      decision: row.decision,
    };
  });
}

export function restSurface(
  id: string,
  pathValue: string,
  service: string,
  documentationUrl: string,
  fields: readonly string[],
  method: "GET" | "POST" = "GET",
  request: Partial<Pick<BatchSurfaceDefinition, "clientRegion" | "headers" | "parameters" | "responseShape">> = {},
): BatchSurfaceDefinition {
  return { id, path: pathValue, service, documentationUrl, fields, method, ...request };
}
