import {
  batch2Checks,
  batch2Completeness,
  batch2GenericDecisionInputs,
  type Batch2CheckRow,
} from "./batch2-spec-helpers.js";
import type {
  BatchCheckDefinition,
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
  manualOnly?: boolean;
  constants?: Readonly<Record<string, PortableValue>>;
  decisionInputs?: Readonly<Record<string, string>>;
  decisionRules?: readonly VerdictRule[];
  completenessSources?: readonly BatchCompletenessSourceDefinition[];
  completenessSemantics?: string;
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
    const decisionInputs = row.decisionInputs ?? batch2GenericDecisionInputs(row.predicate);
    const completenessSources = row.completenessSources
      ?? row.surfaces.map((surfaceId) => batch3Source(surfaceId));
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
      decisionRules: row.decisionRules,
      completeness: batch2Completeness(
        decisionInputs,
        completenessSources,
        row.completenessSemantics
          ?? `For ${row.id}, evidence_complete is true only when every explicitly named source dataset completed and every required response field was present. Truncated, errored, denied, not-collected, not-configured, and missing-required-field states have the exact per-source effects listed below.`,
      ),
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
