import {
  deriveDecisionRules,
  type BatchCheckDefinition,
  type BatchSurfaceDefinition,
} from "./batch-spec-builder.js";
import type {
  FindingSeverity,
  PortableValue,
  VerdictCondition,
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
  manualOnly?: boolean;
  emptyOutcome?: "pass" | "warn" | "fail" | "manual" | "info";
  violationOutcome?: "fail" | "warn";
  constants?: Readonly<Record<string, PortableValue>>;
}

const value = (entry: PortableValue) => ({ kind: "value" as const, value: entry });
const path = (name: string) => ({ kind: "path" as const, path: name });
const compare = (
  op: "eq" | "ne" | "gt" | "gte" | "lt" | "lte",
  name: string,
  entry: PortableValue,
): VerdictCondition => ({ op, left: path(name), right: value(entry) });
const eq = (name: string, entry: PortableValue): VerdictCondition => compare("eq", name, entry);
const ne = (name: string, entry: PortableValue): VerdictCondition => compare("ne", name, entry);
const gt = (name: string, entry: PortableValue): VerdictCondition => compare("gt", name, entry);
const all = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "and", conditions });
const any = (...conditions: VerdictCondition[]): VerdictCondition => ({ op: "or", conditions });
const rule = (status: VerdictRule["status"], condition: VerdictCondition, note?: string): VerdictRule => ({
  status,
  condition,
  ...(note ? { note } : {}),
});

function executableRules(row: Batch2CheckRow): readonly VerdictRule[] {
  if (row.manualOnly) return [rule("manual", { op: "always" }, "The shipped runtime has no decisive read surface for this check.")];
  const emptyOutcome = row.emptyOutcome ?? "manual";
  const violationOutcome = row.violationOutcome ?? "fail";
  return [
    rule("manual", any(
      ne("evidence_readable", true),
      { op: "not", condition: { op: "defined", operand: path("evidence_readable") } },
    ), "Denied, unreadable, missing, null, malformed, or never-requested evidence cannot pass."),
    rule(violationOutcome, gt("violation_count", 0), "A violation proved by readable evidence has precedence over partial companion inventories."),
    ...(emptyOutcome === "manual"
      ? [rule("manual", eq("inventory_count", 0), "This check's documented empty-inventory behavior requires manual confirmation.")]
      : [rule(emptyOutcome, all(eq("inventory_count", 0), eq("evidence_complete", true)))]),
    rule("warn", any(
      ne("evidence_complete", true),
      gt("review_count", 0),
    ), "Incomplete source cardinality or an explicit review condition prevents pass."),
    rule("pass", all(
      eq("evidence_readable", true),
      eq("evidence_complete", true),
      eq("violation_count", 0),
      eq("review_count", 0),
    )),
    rule("manual", { op: "always" }, "Unknown or contradictory evidence requires manual review."),
  ];
}

export function batch2Checks(rows: readonly Batch2CheckRow[]): BatchCheckDefinition[] {
  return rows.map((row) => {
    const inputs = row.manualOnly
      ? {}
      : {
          evidence_readable: "True only when every raw vendor field required by this finding was returned and is non-null.",
          evidence_complete: "True only when every required inventory proved exhaustion before any presentation sample was capped.",
          inventory_count: "The complete number of source records evaluated by this finding, before presentation truncation.",
          violation_count: "The complete count of source records that satisfy the finding-specific violation predicate.",
          review_count: "The complete count of readable source records that satisfy the finding-specific warning or review predicate.",
        };
    const executable = deriveDecisionRules(row.id, executableRules(row));
    return {
      id: row.id,
      control: row.control,
      title: row.title,
      severity: row.severity,
      owner: row.owner,
      surfaces: row.surfaces,
      evidenceFields: [...row.surfaces, "complete_source_counts"],
      decisionInputs: inputs,
      decisionConstants: row.constants,
      decisionRules: executable.rules,
      derivedFactRules: executable.derivedFactRules,
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
): BatchSurfaceDefinition {
  return { id, path: pathValue, service, documentationUrl, fields, method };
}
