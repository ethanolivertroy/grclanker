import {
  SHARED_COLLECTION_STATES,
  SHARED_INTEGRATION_CONTRACT_VERSION,
} from "./hardening/contract.js";
import {
  checkContract,
  defineGrcTool,
  evaluateCheckVerdict,
  type CheckContract,
  type CompletenessContract,
  type CompletenessFailureMode,
  type CompletenessSourceContract,
  type DerivedFactRule,
  type EvaluatedFindingStatus,
  type ExportContract,
  type FindingSeverity,
  type FrameworkKey,
  type IntegrationSpecContract,
  type PermissionKind,
  type PortableValue,
  type RequestParameterContract,
  type VerdictCondition,
  type VerdictOperand,
  type VerdictRule,
  toolContract,
} from "./spec-model.js";
import { AsyncLocalStorage } from "node:async_hooks";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const FRAMEWORK_KEYS: readonly FrameworkKey[] = [
  "fedramp",
  "cmmc",
  "soc2",
  "cis",
  "pci_dss",
  "disa_stig",
  "irap",
  "ismap",
];

export interface BatchSurfaceDefinition {
  id: string;
  method?: "GET" | "POST";
  path: string;
  service: string;
  documentationUrl: string;
  fields: readonly string[];
  clientRegion?: string;
  headers?: readonly string[];
  parameters?: readonly RequestParameterContract[];
  responseShape?: string;
}

export interface BatchCheckDefinition {
  id: string;
  control: number;
  title: string;
  severity: FindingSeverity;
  owner: string;
  surfaces: readonly string[];
  frameworks?: Partial<Record<FrameworkKey, readonly string[]>>;
  evidenceFields: readonly string[];
  decisionInputs?: Readonly<Record<string, string>>;
  decisionInputTypes?: Readonly<Record<string, readonly PortableInputType[]>>;
  decisionConstants?: Readonly<Record<string, PortableValue>>;
  decisionRules?: readonly VerdictRule[];
  derivedFacts?: Readonly<Record<string, string>>;
  derivedFactRules?: Readonly<Record<string, DerivedFactRule>>;
  completeness?: Readonly<Record<string, BatchCompletenessDefinition>>;
  decision: string;
  outcomes?: {
    fail?: boolean;
    warn?: boolean;
    pass?: boolean;
  };
}

export type BatchCompletenessFailureMode = CompletenessFailureMode;
export type BatchCompletenessSourceDefinition = CompletenessSourceContract;
export type BatchCompletenessDefinition = CompletenessContract;

export interface BatchPermissionDefinition {
  id: string;
  kind: PermissionKind;
  value: string;
  unlocks: readonly string[];
  notes?: string;
}

export interface BatchPaginationDefinition {
  surfaceIds: readonly string[];
  cursorFields: readonly string[];
  pageSize: number | null;
  itemCap: number | null;
  pageCap: number | null;
  totalSemantics: string;
  stopConditions: readonly string[];
}

export interface BatchSpecDefinition {
  slug: string;
  displayName: string;
  vendor: string;
  category: string;
  summary: string;
  sourceModule: string;
  baseServices: readonly string[];
  authentication: {
    modes: readonly string[];
    precedence: readonly string[];
    environment: readonly string[];
    configLocations: readonly string[];
    variants: readonly string[];
    configFields: readonly string[];
    refreshRequest?: string;
  };
  permissions: readonly BatchPermissionDefinition[];
  surfaces: readonly BatchSurfaceDefinition[];
  checks: readonly BatchCheckDefinition[];
  tools: Readonly<Record<string, readonly string[]>>;
  pagination: readonly BatchPaginationDefinition[];
  rateLimit: {
    documentedLimit: string | null;
    retryHeaders: readonly string[];
    retryableStatuses: readonly number[];
    backoffPolicy: string;
  };
  runtimeBehavior: readonly string[];
  knownGaps: readonly string[];
  sensitiveFields: readonly string[];
  credentialFormats: readonly string[];
  output: ExportContract;
}

export interface BatchOutputDefinition {
  files: readonly string[];
  conditionalFiles?: readonly string[];
  conditionalFileConditions?: Readonly<Record<string, string>>;
  overwritePolicy: string;
  archivePairing: string;
  jsonFormatting?: string;
}

export function deriveDecisionRules(
  checkId: string,
  rules: readonly VerdictRule[],
): { rules: readonly VerdictRule[]; derivedFactRules: Readonly<Record<string, DerivedFactRule>> } {
  const derivedFactRules: Record<string, DerivedFactRule> = {};
  const unconditionalIndex = rules.findIndex((entry) => entry.condition.op === "always");
  const reachableRules = unconditionalIndex >= 0 ? rules.slice(0, unconditionalIndex + 1) : rules;
  const rewritten = reachableRules.map((entry, index) => {
    const name = `${checkId.toLowerCase().replaceAll("-", "_")}_branch_${String(index + 1).padStart(2, "0")}_matches`;
    derivedFactRules[name] = {
      description: `${checkId} ordered branch ${index + 1} (${entry.status}) is true exactly when its portable evidence condition matches.`,
      condition: entry.condition,
    };
    return {
      ...entry,
      condition: {
        op: "eq" as const,
        left: { kind: "path" as const, path: name },
        right: { kind: "value" as const, value: true },
      },
    };
  });
  return { rules: rewritten, derivedFactRules };
}

export function buildBatchOutputContract(definition: BatchOutputDefinition): ExportContract {
  const conditional = new Set(definition.conditionalFiles ?? []);
  const artifact = (path: string) => ({
    path,
    format: path.endsWith(".json")
      ? "json" as const
      : path.endsWith(".md")
        ? "markdown" as const
        : "text" as const,
    requiredWhen: conditional.has(path)
      ? definition.conditionalFileConditions?.[path] ?? "Only under the runtime condition stated for this conditional file."
      : "Always.",
    schema: path.startsWith("core_data/")
      ? "The projected runtime dataset or its explicit unavailable marker."
      : path.startsWith("analysis/")
        ? "Runtime assessment or finding records."
        : path.startsWith("compliance/")
          ? "The runtime-generated human-readable compliance report."
          : "The runtime-generated bundle metadata or operator guidance.",
    serialization: path.endsWith(".json")
      ? definition.jsonFormatting ?? "UTF-8 JSON with two-space indentation and a trailing newline."
      : "UTF-8 text.",
  });
  return {
    files: definition.files,
    conditionalFiles: definition.conditionalFiles ?? [],
    artifacts: [...definition.files, ...(definition.conditionalFiles ?? [])].map(artifact),
    overwritePolicy: definition.overwritePolicy,
    pathSafetyPolicy: "Resolve beneath the configured output root and reject traversal, unsafe parents, files, and symbolic-link escapes.",
    archivePairing: definition.archivePairing,
    recordSchemas: {
      finding: ["id", "title", "severity", "status", "summary", "evidence", "framework mappings"],
      collection_marker: ["collected", "status", "endpoint", "error"],
      bundle_result: ["outputDir", "zipPath", "fileCount", "findingCount", "errorCount"],
      assessment: ["title or category", "summary", "findings", "errors when collection was partial"],
      pagination_state: ["items or rows seen", "reported total when available", "pages", "truncated", "stop reason"],
    },
    jsonFormatting: definition.jsonFormatting ?? "UTF-8 JSON with two-space indentation and a trailing newline.",
  };
}

/**
 * The runtime remains the owner of framework mappings. Runtime modules call
 * this immediately after declaring their existing control/check catalog so the
 * generator and reports consume the same values without duplicating them in an
 * adjacent manifest.
 */
export function hydrateBatchFrameworkMappings(
  spec: IntegrationSpecContract,
  mappingsByCheck: Readonly<Record<string, Partial<Record<FrameworkKey, readonly string[]>>>>,
): void {
  for (const check of spec.checks) {
    const mappings = mappingsByCheck[check.id];
    if (!mappings) throw new Error(`${spec.identity.slug}: no runtime framework mapping exists for ${check.id}`);
    for (const controlNumber of check.controlNumbers) {
      const control = spec.controls.find((entry) => entry.number === controlNumber);
      if (!control) throw new Error(`${check.id}: no published control ${controlNumber}`);
      for (const key of FRAMEWORK_KEYS) {
        const target = control.frameworks[key] as string[];
        for (const value of mappings[key] ?? []) {
          if (!target.includes(value)) target.push(value);
        }
      }
    }
  }
}

function frameworkMap(values: BatchCheckDefinition["frameworks"] = {}): Record<FrameworkKey, readonly string[]> {
  return Object.fromEntries(FRAMEWORK_KEYS.map((key) => [key, values[key] ?? []])) as Record<FrameworkKey, readonly string[]>;
}

function factName(check: Pick<BatchCheckDefinition, "id">, suffix: string): string {
  return `${check.id.toLowerCase().replaceAll("-", "_")}_${suffix}`;
}

function factPath(check: BatchCheckDefinition, suffix: string): { kind: "path"; path: string } {
  return { kind: "path", path: factName(check, suffix) };
}

function factEquals(check: BatchCheckDefinition, suffix: string, value: PortableValue): VerdictCondition {
  return {
    op: "eq",
    left: factPath(check, suffix),
    right: { kind: "value", value },
  };
}

function criterion(check: BatchCheckDefinition): CheckContract["criteria"] {
  const manualOnly = /^always return manual\b/i.test(check.decision)
    && !/\b(?:pass|warn|fail)\b/i.test(check.decision.replace(/^always return manual\b/i, ""));
  const declaredStatuses = new Set(check.decisionRules?.map((rule) => rule.status) ?? []);
  const outcomes = {
    fail: check.outcomes?.fail ?? (check.decisionRules ? declaredStatuses.has("fail") : !manualOnly && /\bfail\b/i.test(check.decision)),
    warn: check.outcomes?.warn ?? (check.decisionRules ? declaredStatuses.has("warn") : !manualOnly && /\bwarn\b/i.test(check.decision)),
    pass: check.outcomes?.pass ?? (check.decisionRules ? declaredStatuses.has("pass") : !manualOnly && /\bpass\b/i.test(check.decision)),
  };
  const rules: VerdictRule[] = [];
  if (outcomes.fail) {
    rules.push({
      status: "fail",
      condition: factEquals(check, "failure_matches", true),
      note: "A violation proved by readable evidence has first-match precedence over partial companion evidence.",
    });
  }
  rules.push({
    status: "manual",
    condition: {
      op: "or",
      conditions: [
        factEquals(check, "required_evidence_readable", false),
        { op: "not", condition: { op: "defined", operand: factPath(check, "required_evidence_readable") } },
      ],
    },
    note: "Missing, null, denied, unreadable, or never-requested required evidence cannot pass.",
  });
  if (outcomes.warn) {
    rules.push({
      status: "warn",
      condition: {
        op: "or",
        conditions: [
          factEquals(check, "warning_matches", true),
          factEquals(check, "required_evidence_complete", false),
        ],
      },
      note: "A review predicate or incomplete required inventory prevents pass.",
    });
  }
  if (outcomes.pass) {
    rules.push({
      status: "pass",
      condition: {
        op: "and",
        conditions: [
          factEquals(check, "compliant_matches", true),
          factEquals(check, "required_evidence_readable", true),
          factEquals(check, "required_evidence_complete", true),
        ],
      },
      note: "Pass requires the integration-specific compliant predicate and complete readable dependencies.",
    });
  }
  rules.push({
    status: "manual",
    condition: { op: "always" },
    note: "Unknown, contradictory, malformed, and otherwise insufficient evidence falls back to manual.",
  });
  const renderedRules = check.decisionRules ?? rules;
  const sourceConditionFor = (status: EvaluatedFindingStatus): string => {
    const rendered = renderedRules.find((entry) => entry.status === status);
    if (!rendered) return `No ${status} branch exists for this check.`;
    if (rendered.condition.op === "eq" && rendered.condition.left.kind === "path") {
      const derivation = check.derivedFactRules?.[rendered.condition.left.path];
      if (derivation) return JSON.stringify(derivation.condition);
    }
    return JSON.stringify(rendered.condition);
  };
  const noncompliantStatus: EvaluatedFindingStatus = outcomes.fail
    ? "fail"
    : outcomes.warn
      ? "warn"
      : "manual";
  const partialStatus: EvaluatedFindingStatus = outcomes.warn ? "warn" : "manual";
  const compliantStatus: EvaluatedFindingStatus = outcomes.pass ? "pass" : "manual";
  return {
    pass: `${check.id} returns pass at the first ordered pass condition ${sourceConditionFor("pass")}. Portable derivation: ${check.decision}`,
    warn: `${check.id} returns warn at the first ordered warn condition ${sourceConditionFor("warn")}. Portable derivation: ${check.decision}`,
    fail: `${check.id} returns fail at the first ordered fail condition ${sourceConditionFor("fail")}. Portable derivation: ${check.decision}`,
    manual: `${check.id} returns manual at the first ordered manual condition ${sourceConditionFor("manual")}; absent, null, denied, unreadable, not-requested, and malformed primitives cannot pass.`,
    constants: check.decisionConstants ?? {
      requiredEvidenceReadable: true,
      requiredEvidenceComplete: true,
    },
    examples: [
      {
        kind: "compliant",
        input: `${check.id} primitive assignment satisfies this exact first-match condition: ${sourceConditionFor(compliantStatus)}`,
        expected: compliantStatus,
        reason: `${check.id} evaluates the rendered ordered rules directly; the assignment reaches ${compliantStatus} without a preselected label.`,
      },
      {
        kind: "noncompliant",
        input: `${check.id} primitive assignment satisfies this exact first-match condition: ${sourceConditionFor(noncompliantStatus)}`,
        expected: noncompliantStatus,
        reason: `${check.id} reaches the first executable ${noncompliantStatus} branch from the named primitive fields and constants.`,
      },
      {
        kind: "partial",
        input: `${check.id} has no earlier proved violation and satisfies this exact partial/review condition: ${sourceConditionFor(partialStatus)}`,
        expected: partialStatus,
        reason: `${check.id} applies the rendered ${partialStatus} branch to its explicitly named source-completeness primitives.`,
      },
      {
        kind: "unreadable",
        input: `${check.id} satisfies this exact unreadable or fallback condition: ${sourceConditionFor("manual")}`,
        expected: "manual",
        reason: `${check.id} does not coerce unavailable vendor evidence to an empty collection, zero, false, or passing fact.`,
      },
    ],
    rules: renderedRules,
  };
}

export type PortableInputType = "array" | "boolean" | "null" | "number" | "string";

interface PortableInputUsage {
  types: Set<PortableInputType>;
  values: Set<string>;
  derivedFacts: Set<string>;
}

function portableValueType(value: PortableValue): PortableInputType {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (typeof value === "boolean") return "boolean";
  if (typeof value === "number") return "number";
  if (typeof value === "string") return "string";
  throw new Error(`Unsupported portable value type: ${typeof value}`);
}

function recordOperandUsage(
  usage: Map<string, PortableInputUsage>,
  operand: VerdictOperand,
  derivedFact: string,
  expectedType?: PortableInputType,
  comparedValue?: PortableValue,
): void {
  switch (operand.kind) {
    case "value":
      return;
    case "subtract":
      recordOperandUsage(usage, operand.left, derivedFact, "number");
      recordOperandUsage(usage, operand.right, derivedFact, "number");
      return;
    case "path":
    case "length":
      break;
    default: {
      const exhaustive: never = operand;
      return exhaustive;
    }
  }
  const name = operand.path;
  const entry = usage.get(name) ?? { types: new Set<PortableInputType>(), values: new Set<string>(), derivedFacts: new Set<string>() };
  if (operand.kind === "length") entry.types.add("array");
  if (expectedType) entry.types.add(expectedType);
  if (comparedValue !== undefined && comparedValue !== null && !Array.isArray(comparedValue)) {
    entry.values.add(JSON.stringify(comparedValue));
  }
  entry.derivedFacts.add(derivedFact);
  usage.set(name, entry);
}

function collectPortableInputUsage(
  condition: VerdictCondition,
  derivedFact: string,
  usage: Map<string, PortableInputUsage>,
): void {
  switch (condition.op) {
    case "always":
      return;
    case "and":
    case "or":
      for (const child of condition.conditions) collectPortableInputUsage(child, derivedFact, usage);
      return;
    case "not":
      collectPortableInputUsage(condition.condition, derivedFact, usage);
      return;
    case "eq":
    case "ne":
    case "gt":
    case "gte":
    case "lt":
    case "lte": {
      const leftValue = condition.left.kind === "value" ? condition.left.value : undefined;
      const rightValue = condition.right.kind === "value" ? condition.right.value : undefined;
      const pathComparisonType = leftValue === undefined && rightValue === undefined ? "number" : undefined;
      recordOperandUsage(
        usage,
        condition.left,
        derivedFact,
        rightValue === undefined ? pathComparisonType : portableValueType(rightValue),
        rightValue,
      );
      recordOperandUsage(
        usage,
        condition.right,
        derivedFact,
        leftValue === undefined ? pathComparisonType : portableValueType(leftValue),
        leftValue,
      );
      return;
    }
    case "ratio":
      recordOperandUsage(usage, condition.numerator, derivedFact, "number");
      recordOperandUsage(usage, condition.denominator, derivedFact, "number");
      recordOperandUsage(usage, condition.threshold, derivedFact, "number");
      return;
    case "matches":
      recordOperandUsage(usage, condition.operand, derivedFact, "string");
      return;
    case "defined":
    case "null":
      recordOperandUsage(usage, condition.operand, derivedFact);
      return;
    case "some":
    case "every":
      recordOperandUsage(usage, { kind: "path", path: condition.path }, derivedFact, "array");
      collectPortableInputUsage(condition.condition, derivedFact, usage);
      return;
    default: {
      const exhaustive: never = condition;
      return exhaustive;
    }
  }
}

function renderPortableInputDefinitions(
  definition: BatchSpecDefinition,
  check: BatchCheckDefinition,
): Readonly<Record<string, string>> | undefined {
  if (!check.decisionInputs) return undefined;
  const usage = new Map<string, PortableInputUsage>();
  for (const [name, rule] of Object.entries(check.derivedFactRules ?? {})) {
    collectPortableInputUsage(rule.condition, name, usage);
  }
  return Object.fromEntries(Object.entries(check.decisionInputs).map(([name, supplied]) => {
    const inputUsage = usage.get(name);
    for (const inputType of check.decisionInputTypes?.[name] ?? []) {
      inputUsage?.types.add(inputType);
    }
    if (!inputUsage || inputUsage.types.size === 0) {
      throw new Error(`${check.id} input ${name} has no explicit executable type/domain`);
    }
    const inputTypes = [...inputUsage.types].sort().join(" or ");
    if (
      !supplied.trim()
      || /Runtime-owned .* (?:computed|derived) from (?:the )?complete/i.test(supplied)
      || supplied.trim().toLowerCase() === name.replaceAll("_", " ").toLowerCase()
    ) {
      throw new Error(`${check.id} input ${name} uses a fallback or name-restating definition`);
    }
    const values = inputUsage && inputUsage.values.size > 0
      ? ` Compared literal domain: ${[...inputUsage.values].sort().join(", ")}.`
      : "";
    const usedBy = inputUsage && inputUsage.derivedFacts.size > 0
      ? ` It feeds executable derived facts ${[...inputUsage.derivedFacts].sort().map((fact) => `\`${fact}\``).join(", ")}.`
      : " It is declared for the finding's explicit manual-only contract.";
    const completenessContract = check.completeness?.[name];
    const ownedSourceIds = completenessContract
      ? completenessContract.sources.map((entry) => entry.surfaceId)
      : check.surfaces;
    const source = ownedSourceIds.length > 0
      ? ownedSourceIds.map((surfaceId) => {
        const surface = definition.surfaces.find((candidate) => candidate.id === surfaceId);
        if (!surface) throw new Error(`${check.id} input ${name} references unknown source ${surfaceId}`);
        return `\`${surface.method ?? "GET"} ${surface.path}\` (${surface.id})`;
      }).join(", ")
      : "the explicitly manual collector state; this check performs no vendor read";
    const completeness = name.includes("complete")
      ? renderCompletenessSemantics(check, name, completenessContract)
      : "The primitive is calculated from the uncapped collector state before any 25-item finding preview or export sample; list cardinalities therefore refer to every item the collector obtained";
    const portableMeaning = completenessContract?.semantics ?? supplied;
    return [
      name,
      `Semantic owner: \`${check.id}.${name}\`. Type/domain: ${inputTypes}.${values} Source/owner: ${definition.vendor} collector projection from ${source}. Completeness/sample semantics: ${completeness}. Null/missing meaning: the named source did not establish this primitive; null or absence cannot independently satisfy a passing rule.${usedBy} Portable meaning: ${portableMeaning}`,
    ];
  }));
}

function renderCompletenessSemantics(
  check: BatchCheckDefinition,
  inputName: string,
  contract: BatchCompletenessDefinition | undefined,
): string {
  if (!contract) throw new Error(`${check.id} input ${inputName} requires an explicit completeness contract`);
  if (!contract.semantics.trim()) throw new Error(`${check.id} input ${inputName} completeness semantics are empty`);
  if (contract.sources.length === 0) {
    return `For ${check.id}, this fact has no vendor dataset dependency. ${contract.semantics}`;
  }
  const sourceText = contract.sources.map((source) => {
    if (!source.scope && !source.aggregate) {
      if (source.falseWhen.length === 0) {
        return `\`${source.surfaceId}\`: does not lower this fact for any declared failure mode`;
      }
      return `\`${source.surfaceId}\`: false on ${source.falseWhen.join(", ")}; other failure modes do not change this fact`;
    }
    const scope = source.scope ? ` (${source.scope})` : "";
    const aggregate = source.aggregate
      ? `; aggregate rule: count ${source.aggregate.attemptedUnit} under \`${source.aggregate.parentSurfaceId}\`; `
        + `${source.aggregate.mixedFailureModes.join(" or ")} makes this fact false only when at least one attempted child read succeeds and at least one fails; `
        + "if every attempted child read fails, this fact is unchanged and evidence_readable is false; "
        + "zero attempted child reads leave this fact unchanged"
      : "";
    if (source.falseWhen.length === 0) {
      return `\`${source.surfaceId}\`${scope}: does not lower this fact for any declared failure mode${aggregate}`;
    }
    return `\`${source.surfaceId}\`${scope}: false on ${source.falseWhen.join(", ")}; other failure modes do not change this fact${aggregate}`;
  }).join("; ");
  return `For ${check.id}, ${contract.semantics} Exact source-state effects: ${sourceText}`;
}

export function buildBatchIntegrationSpec(definition: BatchSpecDefinition): IntegrationSpecContract {
  for (const check of definition.checks) {
    if (!check.decision.trim()) {
      throw new Error(`${check.id} requires a portable decision derivation`);
    }
    if (/\b(?:TypeScript|JavaScript|buildFinding|cli\/|runtime predicates?)\b/i.test(check.decision)) {
      throw new Error(`${check.id} decision derivation contains an implementation-specific reference`);
    }
    const completionInputs = Object.keys(check.decisionInputs ?? {}).filter((name) => name.includes("complete"));
    const completionContracts = Object.keys(check.completeness ?? {});
    if (completionInputs.sort().join("\0") !== completionContracts.sort().join("\0")) {
      throw new Error(`${check.id} completeness contracts must exactly cover ${completionInputs.join(", ") || "(none)"}`);
    }
    for (const [inputName, completeness] of Object.entries(check.completeness ?? {})) {
      const seen = new Set<string>();
      for (const source of completeness.sources) {
        if (!check.surfaces.includes(source.surfaceId)) {
          throw new Error(`${check.id} completeness input ${inputName} references undeclared source ${source.surfaceId}`);
        }
        if (seen.has(source.surfaceId)) throw new Error(`${check.id} completeness input ${inputName} repeats source ${source.surfaceId}`);
        seen.add(source.surfaceId);
        if (new Set(source.falseWhen).size !== source.falseWhen.length) {
          throw new Error(`${check.id} completeness input ${inputName} repeats a failure mode for ${source.surfaceId}`);
        }
        if (source.scope !== undefined && !source.scope.trim()) {
          throw new Error(`${check.id} completeness input ${inputName} has an empty scope qualifier for ${source.surfaceId}`);
        }
        if (source.aggregate) {
          if (!check.surfaces.includes(source.aggregate.parentSurfaceId)) {
            throw new Error(`${check.id} completeness input ${inputName} aggregate for ${source.surfaceId} references undeclared parent ${source.aggregate.parentSurfaceId}`);
          }
          if (!source.aggregate.attemptedUnit.trim()) {
            throw new Error(`${check.id} completeness input ${inputName} aggregate for ${source.surfaceId} has no attempted unit`);
          }
          if (source.aggregate.mixedFailureModes.length === 0) {
            throw new Error(`${check.id} completeness input ${inputName} aggregate for ${source.surfaceId} has no mixed-failure modes`);
          }
          if (new Set(source.aggregate.mixedFailureModes).size !== source.aggregate.mixedFailureModes.length) {
            throw new Error(`${check.id} completeness input ${inputName} aggregate for ${source.surfaceId} repeats a mixed-failure mode`);
          }
        }
      }
    }
  }
  const controls = [...new Map(
    [...definition.checks]
      .sort((left, right) => left.control - right.control)
      .map((check) => [check.control, {
        number: check.control,
        title: check.title,
        frameworks: frameworkMap(check.frameworks),
      }]),
  ).values()];
  const surfaces = definition.surfaces.map((surface) => ({
    id: surface.id,
    kind: "rest" as const,
    method: surface.method ?? "GET",
    path: surface.path,
    baseService: surface.service,
    documentationUrl: surface.documentationUrl,
    fieldsConsumed: surface.fields,
    projectionStage: "The collector projects the response to the listed verdict fields before evidence export.",
    request: {
      clientRegion: surface.clientRegion ?? `Use the configured ${surface.service} origin; never follow a server link to a different origin.`,
      headers: surface.headers ?? ["Authorization appropriate to the selected authentication mode", "Accept: application/json"],
      parameters: surface.parameters ?? [],
      responseShape: surface.responseShape ?? `A JSON object or list containing only the documented ${surface.fields.join(", ")} members consumed by verdicts.`,
    },
    intent: "read" as const,
  }));
  const surfaceIds = new Set(surfaces.map((surface) => surface.id));
  for (const check of definition.checks) {
    for (const surfaceId of check.surfaces) {
      if (!surfaceIds.has(surfaceId)) throw new Error(`${check.id} references unknown surface ${surfaceId}`);
    }
  }
  for (const permission of definition.permissions) {
    for (const surfaceId of permission.unlocks) {
      if (!surfaceIds.has(surfaceId)) throw new Error(`${permission.id} references unknown surface ${surfaceId}`);
    }
  }
  for (const pagination of definition.pagination) {
    for (const surfaceId of pagination.surfaceIds) {
      if (!surfaceIds.has(surfaceId)) throw new Error(`Pagination references unknown surface ${surfaceId}`);
    }
  }
  const checks = definition.checks.map((check) => ({
    id: check.id,
    controlNumbers: [check.control],
    title: check.title,
    severity: check.severity,
    owningTool: check.owner,
    sourceSurfaceIds: check.surfaces,
    evidenceFields: check.decisionInputs
      ? Object.keys(check.decisionInputs)
      : [...new Set(check.evidenceFields.flatMap((field) =>
        definition.surfaces.find((surface) => surface.id === field)?.fields ?? [field]))],
    ...(check.decisionInputs ? { evidenceFieldDefinitions: renderPortableInputDefinitions(definition, check) } : {}),
    ...(check.completeness ? { completeness: check.completeness } : {}),
    derivedFacts: check.decisionInputs
      ? Object.fromEntries(Object.entries(check.derivedFactRules ?? {}).map(([name, rule]) => [name, rule.description]))
      : {
        [factName(check, "required_evidence_readable")]: `From the declared source surfaces, set true only when every value required by ${check.id} was returned and is non-null; denied, missing, malformed, not-requested, and unreadable dependencies set false.`,
        [factName(check, "required_evidence_complete")]: `From complete source cardinalities rather than rendered samples, set true only after every required list proves exhaustion; any cap, repeated cursor, missing total, rejected link, sampled child read, or other partial state sets false.`,
        [factName(check, "failure_matches")]: `Using the declared evidence fields and complete counts, evaluate only the failure branch of this portable derivation and return a boolean: ${check.decision}`,
        [factName(check, "warning_matches")]: `Using the declared evidence fields and complete counts, evaluate only the warning or review branch of this portable derivation and return a boolean: ${check.decision}`,
        [factName(check, "compliant_matches")]: `Using the declared evidence fields and complete counts, evaluate only the compliant branch of this portable derivation and return a boolean: ${check.decision}`,
        ...check.derivedFacts,
      },
    ...(check.derivedFactRules ? { derivedFactRules: check.derivedFactRules } : {}),
    criteria: criterion(check),
  }));
  const tools = Object.entries(definition.tools).map(([name, checkIds]) => ({
    name,
    checkIds,
    resultSchema: name.endsWith("_export_audit_bundle")
      ? "A text result plus output directory, paired archive path, file count, finding count, and collection-error count."
      : "A text result whose structured details preserve the runtime assessment or access-check object byte-for-byte.",
    ...(name.endsWith("_export_audit_bundle") ? { output: undefined } : {}),
  }));
  const projections = Object.fromEntries(surfaces.map((surface) => [surface.id, surface.fieldsConsumed]));
  return {
    identity: {
      slug: definition.slug,
      displayName: definition.displayName,
      vendor: definition.vendor,
      category: definition.category,
      kind: "security-inspector",
      version: "1.0.0",
      lastUpdated: "2026-09-27",
      summary: definition.summary,
    },
    sourceModule: definition.sourceModule,
    baseServices: definition.baseServices,
    apiSurfaces: surfaces,
    authentication: {
      modes: definition.authentication.modes,
      credentialPrecedence: definition.authentication.precedence,
      environmentVariables: definition.authentication.environment,
      configLocations: definition.authentication.configLocations,
      variants: definition.authentication.variants,
      refreshRequest: definition.authentication.refreshRequest,
      configFields: definition.authentication.configFields,
      malformedConfigBehavior: "Reject malformed or ambiguous configuration before any request; never echo credential values.",
    },
    permissions: definition.permissions,
    pagination: definition.pagination,
    rateLimits: [{
      scope: definition.displayName,
      documentedLimit: definition.rateLimit.documentedLimit,
      retryHeaders: definition.rateLimit.retryHeaders,
      retryableStatuses: definition.rateLimit.retryableStatuses,
      backoffPolicy: definition.rateLimit.backoffPolicy,
    }],
    controls,
    checks,
    collectionStates: {
      complete: `${SHARED_COLLECTION_STATES[0]}: proven API exhaustion or a successful single-object read.`,
      truncated: `${SHARED_COLLECTION_STATES[1]}: preserve seen and total when available plus the exact stop reason.`,
      unreadable: `${SHARED_COLLECTION_STATES[2]}: render data and counts as null and retain a scrubbed error envelope.`,
      denied: `${SHARED_COLLECTION_STATES[3]}: render null evidence with the endpoint and HTTP status, never an empty inventory.`,
      notRequested: `${SHARED_COLLECTION_STATES[4]}: identify the unreadable parent dependency and do not invent an HTTP status.`,
      notConfigured: `${SHARED_COLLECTION_STATES[5]}: identify the absent optional feature or credential without treating it as compliant.`,
    },
    knownGaps: [...definition.runtimeBehavior, ...definition.knownGaps],
    redaction: {
      sharedContractVersion: SHARED_INTEGRATION_CONTRACT_VERSION,
      projections,
      projectionStage: "Project records to verdict-consumed fields, scrub configured and discovered credentials, then scrub again at every report and archive write sink.",
      sensitiveFields: definition.sensitiveFields,
      benignExceptions: ["Stable non-secret resource identifiers and public documentation URLs remain visible unless carried in a credential field."],
      credentialFormats: definition.credentialFormats,
      integrationRules: [
        "Withhold undocumented error bodies; retain only status, media type, byte length, and allowlisted vendor error codes.",
        "Remove URL user information, queries, and fragments from evidence and reject off-origin pagination links.",
        "Unavailable counts, arrays, maps, and negative flags are null rather than fabricated empty values.",
      ],
    },
    output: definition.output,
    tools,
  };
}

export function evaluateBatchCheckVerdict(
  spec: IntegrationSpecContract,
  checkId: string,
  rawFacts: Readonly<Record<string, unknown>>,
): EvaluatedFindingStatus {
  return evaluateCheckVerdict(checkContract(spec, checkId), rawFacts);
}

export function evaluateBatchRuntimeCheckVerdict(
  spec: IntegrationSpecContract,
  checkId: string,
  collectedFacts: Readonly<Record<string, unknown>>,
): EvaluatedFindingStatus {
  BATCH_DECISION_CAPTURE.getStore()?.push({
    integration: spec.identity.slug,
    checks: new Map([[checkId, collectedFacts]]),
  });
  return evaluateCheckVerdict(checkContract(spec, checkId), collectedFacts);
}

export function assertBatchCheckVerdict<T extends string>(
  spec: IntegrationSpecContract,
  checkId: string,
  rawFacts: Readonly<Record<string, unknown>>,
  expectedStatus: T,
): T {
  const normalizedExpected = ({
    Pass: "pass",
    Partial: "warn",
    Fail: "fail",
    Manual: "manual",
    Info: "info",
  } as Record<string, EvaluatedFindingStatus>)[expectedStatus]
    ?? expectedStatus.toLowerCase() as EvaluatedFindingStatus;
  const evaluated = evaluateBatchCheckVerdict(spec, checkId, rawFacts);
  if (evaluated !== normalizedExpected) {
    throw new Error(`${checkId} runtime status ${expectedStatus} disagrees with evidence contract (${evaluated})`);
  }
  return expectedStatus;
}

interface BatchVerdictContextStorage {
  run<T>(
    store: Map<string, Readonly<Record<string, unknown>>>,
    callback: () => T,
  ): T;
}

interface BatchVerdictFinding {
  id: string;
  status: string;
}

interface BatchVerdictResult {
  findings: readonly BatchVerdictFinding[];
}

export interface CapturedBatchDecisionFacts {
  integration: string;
  checks: ReadonlyMap<string, Readonly<Record<string, unknown>>>;
}

const BATCH_DECISION_CAPTURE = new AsyncLocalStorage<CapturedBatchDecisionFacts[]>();

export async function captureBatchDecisionFacts<T>(
  callback: () => T | Promise<T>,
): Promise<{ result: T; captures: readonly CapturedBatchDecisionFacts[] }> {
  const captures: CapturedBatchDecisionFacts[] = [];
  const result = await BATCH_DECISION_CAPTURE.run(captures, callback);
  return { result, captures };
}

function assertBatchResultVerdicts<T>(
  spec: IntegrationSpecContract,
  factsByCheck: ReadonlyMap<string, Readonly<Record<string, unknown>>>,
  result: T,
): T {
  const candidate = result as Partial<BatchVerdictResult> | null;
  if (!candidate || !Array.isArray(candidate.findings)) {
    throw new Error(`${spec.identity.slug} assessment did not return a findings array`);
  }
  BATCH_DECISION_CAPTURE.getStore()?.push({
    integration: spec.identity.slug,
    checks: new Map(factsByCheck),
  });
  for (const finding of candidate.findings) {
    const facts = factsByCheck.get(finding.id);
    if (!facts) throw new Error(`${finding.id} has no runtime decision facts`);
    assertBatchCheckVerdict(spec, finding.id, facts, finding.status);
  }
  return result;
}

/**
 * Runs one assessment with an isolated fact store, then verifies the final
 * findings after all legacy partial/truncation decorators have been applied.
 * The assessment result is returned unchanged.
 */
export function runBatchVerdictContext<T>(
  storage: BatchVerdictContextStorage,
  spec: IntegrationSpecContract,
  callback: () => T,
): T {
  const factsByCheck = new Map<string, Readonly<Record<string, unknown>>>();
  return storage.run(factsByCheck, () => {
    const result = callback();
    if (
      typeof result === "object"
      && result !== null
      && "then" in result
      && typeof result.then === "function"
    ) {
      return result.then((resolved: unknown) =>
        assertBatchResultVerdicts(spec, factsByCheck, resolved)) as T;
    }
    return assertBatchResultVerdicts(spec, factsByCheck, result);
  });
}

export function materializeBatchCheckVerdict(
  spec: IntegrationSpecContract,
  checkId: string,
  rawFacts: Readonly<Record<string, unknown>>,
): "Pass" | "Partial" | "Fail" | "Manual" | "Info" {
  const evaluated = evaluateBatchCheckVerdict(spec, checkId, rawFacts);
  return ({
    pass: "Pass",
    warn: "Partial",
    fail: "Fail",
    manual: "Manual",
    info: "Info",
  } as const)[evaluated];
}

export function withIntegrationToolContracts(pi: ExtensionAPI, spec: IntegrationSpecContract): ExtensionAPI {
  return new Proxy(pi, {
    get(target, property, receiver) {
      if (property !== "registerTool") return Reflect.get(target, property, receiver);
      return (definition: Parameters<ExtensionAPI["registerTool"]>[0]) => {
        target.registerTool(defineGrcTool(definition, toolContract(spec, definition.name)));
      };
    },
  });
}
