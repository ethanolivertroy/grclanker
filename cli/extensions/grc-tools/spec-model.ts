import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

export type IntegrationKind = "security-inspector" | "operator-bridge" | "runtime-architecture";
export type ApiSurfaceKind = "rest" | "sdk";
export type ApiIntent = "read" | "auth-only";
export type PermissionKind = "oauth-scope" | "iam-action" | "role" | "license" | "plan";
export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info" | "dynamic";
export type FrameworkKey = "fedramp" | "cmmc" | "soc2" | "cis" | "pci_dss" | "disa_stig" | "irap" | "ismap";
export type RequestParameterLocation = "path" | "query" | "header" | "form-body" | "operation-input" | "client";
export type CriterionExampleKind = "compliant" | "noncompliant" | "partial" | "unreadable";
export type PortableValue = string | number | boolean | null | readonly string[] | readonly number[];

export interface IntegrationIdentity {
  slug: string;
  displayName: string;
  vendor: string;
  category: string;
  kind: IntegrationKind;
  version: string;
  lastUpdated: string;
  summary: string;
}

export interface ApiSurfaceContract {
  id: string;
  kind: ApiSurfaceKind;
  method?: "GET" | "POST";
  path?: string;
  operation?: string;
  sdkService?: string;
  iamAction?: string;
  documentationNamespace?: string;
  baseService: string;
  documentationUrl: string;
  fieldsConsumed: readonly string[];
  projectionStage: string;
  request: RequestContract;
  intent: ApiIntent;
}

export interface RequestParameterContract {
  name: string;
  location: RequestParameterLocation;
  required: boolean;
  value: string;
  when?: string;
}

export interface RequestContract {
  clientRegion: string;
  headers: readonly string[];
  parameters: readonly RequestParameterContract[];
  responseShape: string;
}

export interface AuthenticationContract {
  modes: readonly string[];
  credentialPrecedence: readonly string[];
  environmentVariables: readonly string[];
  configLocations: readonly string[];
  variants: readonly string[];
  refreshRequest?: string;
  configFields: readonly string[];
  malformedConfigBehavior: string;
}

export interface PermissionContract {
  id: string;
  kind: PermissionKind;
  value: string;
  unlocks: readonly string[];
  notes?: string;
}

export interface PaginationContract {
  surfaceIds: readonly string[];
  cursorFields: readonly string[];
  pageSize: number | null;
  itemCap: number | null;
  pageCap: number | null;
  totalSemantics: string;
  stopConditions: readonly string[];
}

export interface RateLimitContract {
  scope: string;
  documentedLimit: string | null;
  retryHeaders: readonly string[];
  retryableStatuses: readonly number[];
  backoffPolicy: string;
}

export interface VerdictCriteria {
  pass: string;
  warn: string;
  fail: string;
  manual: string;
  info?: string;
  constants: Readonly<Record<string, PortableValue>>;
  examples: readonly CriterionExample[];
  rules: readonly VerdictRule[];
}

export type EvaluatedFindingStatus = "pass" | "warn" | "fail" | "manual" | "info";
export type VerdictFacts = Readonly<Record<string, unknown>>;

export interface VerdictRule {
  status: EvaluatedFindingStatus;
  condition: VerdictCondition;
  note?: string;
}

export interface DerivedFactRule {
  description: string;
  condition: VerdictCondition;
}

export type VerdictOperand =
  | { kind: "value"; value: PortableValue }
  | { kind: "path"; path: string; fallback?: PortableValue }
  | { kind: "length"; path: string };

export type VerdictCondition =
  | { op: "always" }
  | { op: "and" | "or"; conditions: readonly VerdictCondition[] }
  | { op: "not"; condition: VerdictCondition }
  | { op: "eq" | "ne" | "gt" | "gte" | "lt" | "lte"; left: VerdictOperand; right: VerdictOperand }
  | {
      op: "ratio";
      numerator: VerdictOperand;
      denominator: VerdictOperand;
      comparator: "gt" | "gte" | "lt" | "lte";
      threshold: VerdictOperand;
      scale?: number;
      roundDigits?: number;
    }
  | { op: "matches"; operand: VerdictOperand; pattern: string; flags?: string }
  | { op: "defined" | "null"; operand: VerdictOperand }
  | { op: "some" | "every"; path: string; condition: VerdictCondition };

export interface CriterionExample {
  kind: CriterionExampleKind;
  input: string;
  expected: EvaluatedFindingStatus;
  reason: string;
}

export interface CheckContract {
  id: string;
  controlNumbers: readonly number[];
  title: string;
  severity: FindingSeverity;
  owningTool: string;
  sourceSurfaceIds: readonly string[];
  evidenceFields: readonly string[];
  evidenceFieldDefinitions?: Readonly<Record<string, string>>;
  completeness?: Readonly<Record<string, CompletenessContract>>;
  derivedFacts: Readonly<Record<string, string>>;
  derivedFactRules?: Readonly<Record<string, DerivedFactRule>>;
  criteria: VerdictCriteria;
}

export type CompletenessFailureMode =
  | "truncated"
  | "error"
  | "denied"
  | "not-collected"
  | "missing-required-field";

export interface CompletenessSourceContract {
  surfaceId: string;
  falseWhen: readonly CompletenessFailureMode[];
}

export interface CompletenessContract {
  sources: readonly CompletenessSourceContract[];
  semantics: string;
}

export interface ControlContract {
  number: number;
  title: string;
  frameworks: Readonly<Record<FrameworkKey, readonly string[]>>;
}

export interface CollectionStateContract {
  complete: string;
  truncated: string;
  unreadable: string;
  denied: string;
  notRequested: string;
  notConfigured: string;
}

export interface RedactionContract {
  sharedContractVersion: string;
  projections: Readonly<Record<string, readonly string[]>>;
  projectionStage: string;
  sensitiveFields: readonly string[];
  benignExceptions: readonly string[];
  credentialFormats: readonly string[];
  integrationRules: readonly string[];
}

export interface ExportArtifactContract {
  path: string;
  format: "json" | "markdown" | "text" | "zip";
  requiredWhen: string;
  schema: string;
  serialization: string;
}

export interface ExportContract {
  files: readonly string[];
  conditionalFiles: readonly string[];
  artifacts: readonly ExportArtifactContract[];
  overwritePolicy: string;
  pathSafetyPolicy: string;
  archivePairing: string;
  recordSchemas: Readonly<Record<string, readonly string[]>>;
  jsonFormatting: string;
}

export interface ToolContract {
  checkIds: readonly string[];
  resultSchema?: string;
  output?: ExportContract;
}

export interface PublishedToolContract extends ToolContract {
  name: string;
}

export interface IntegrationSpecContract {
  identity: IntegrationIdentity;
  sourceModule: string;
  baseServices: readonly string[];
  apiSurfaces: readonly ApiSurfaceContract[];
  authentication: AuthenticationContract;
  permissions: readonly PermissionContract[];
  pagination: readonly PaginationContract[];
  rateLimits: readonly RateLimitContract[];
  controls: readonly ControlContract[];
  checks: readonly CheckContract[];
  collectionStates: CollectionStateContract;
  knownGaps: readonly string[];
  redaction: RedactionContract;
  output: ExportContract;
  tools: readonly PublishedToolContract[];
}

type RegisteredToolDefinition = Parameters<ExtensionAPI["registerTool"]>[0];

const GRC_TOOL_CONTRACT = Symbol.for("grclanker.grc-tool-contract");

export type DefinedGrcTool<T extends RegisteredToolDefinition = RegisteredToolDefinition> = T & {
  readonly [GRC_TOOL_CONTRACT]?: ToolContract;
};

export interface CollectedGrcTool {
  definition: RegisteredToolDefinition;
  contract: ToolContract;
}

export function defineGrcTool<T extends RegisteredToolDefinition>(definition: T, contract: ToolContract): T {
  Object.defineProperty(definition, GRC_TOOL_CONTRACT, {
    configurable: false,
    enumerable: false,
    value: contract,
    writable: false,
  });
  return definition;
}

export function grcToolContract(definition: RegisteredToolDefinition): ToolContract | undefined {
  return (definition as DefinedGrcTool)[GRC_TOOL_CONTRACT];
}

export function collectDefinedGrcTools(register: (pi: ExtensionAPI) => void): CollectedGrcTool[] {
  const tools: CollectedGrcTool[] = [];
  const pi = {
    registerTool(definition: RegisteredToolDefinition) {
      const contract = grcToolContract(definition);
      if (contract) tools.push({ definition, contract });
    },
  } as ExtensionAPI;
  register(pi);
  return tools;
}

export function toolContract(spec: IntegrationSpecContract, toolName: string): ToolContract {
  const contract = spec.tools.find((tool) => tool.name === toolName);
  if (!contract) throw new Error(`No integration contract exists for tool ${toolName}`);
  return contract;
}

export function checkContract(spec: IntegrationSpecContract, checkId: string): CheckContract {
  const contract = spec.checks.find((check) => check.id === checkId);
  if (!contract) throw new Error(`No integration contract exists for check ${checkId}`);
  return contract;
}

export function evaluateVerdictCriteria(criteria: VerdictCriteria, facts: VerdictFacts): EvaluatedFindingStatus {
  for (const rule of criteria.rules) {
    if (evaluateVerdictCondition(rule.condition, facts)) return rule.status;
  }
  throw new Error("No verdict criterion matched the supplied facts");
}

export function evaluateCheckVerdict(check: CheckContract, rawFacts: VerdictFacts): EvaluatedFindingStatus {
  const declaredRawInputs = new Set(check.evidenceFields);
  const undeclared = Object.keys(rawFacts).filter((name) => !declaredRawInputs.has(name));
  if (undeclared.length > 0) {
    throw new Error(`${check.id} received undeclared decision input(s): ${undeclared.sort().join(", ")}`);
  }
  const facts: Record<string, unknown> = {
    ...check.criteria.constants,
    ...rawFacts,
  };
  for (const [name, derivation] of Object.entries(check.derivedFactRules ?? {})) {
    facts[name] = evaluateVerdictCondition(derivation.condition, facts);
  }
  return evaluateVerdictCriteria(check.criteria, facts);
}

function pathValue(root: unknown, path: string, item: unknown): unknown {
  const fromItem = path === "$" || path.startsWith("$.");
  const segments = (fromItem ? path.slice(1).replace(/^\./, "") : path).split(".").filter(Boolean);
  let value: unknown = fromItem ? item : root;
  for (const segment of segments) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
    value = (value as Record<string, unknown>)[segment];
  }
  return value;
}

function operandValue(operand: VerdictOperand, facts: VerdictFacts, item: unknown): unknown {
  switch (operand.kind) {
    case "value":
      return operand.value;
    case "path": {
      const value = pathValue(facts, operand.path, item);
      return value === undefined && "fallback" in operand ? operand.fallback : value;
    }
    case "length": {
      const value = pathValue(facts, operand.path, item);
      return Array.isArray(value) || typeof value === "string" ? value.length : undefined;
    }
    default: {
      const unhandled: never = operand;
      return unhandled;
    }
  }
}

function evaluateCondition(condition: VerdictCondition, facts: VerdictFacts, item: unknown): boolean {
  switch (condition.op) {
    case "always":
      return true;
    case "and":
      return condition.conditions.every((entry) => evaluateCondition(entry, facts, item));
    case "or":
      return condition.conditions.some((entry) => evaluateCondition(entry, facts, item));
    case "not":
      return !evaluateCondition(condition.condition, facts, item);
    case "defined":
      return operandValue(condition.operand, facts, item) !== undefined
        && operandValue(condition.operand, facts, item) !== null;
    case "null":
      return operandValue(condition.operand, facts, item) === null;
    case "eq":
      return operandValue(condition.left, facts, item) === operandValue(condition.right, facts, item);
    case "ne":
      return operandValue(condition.left, facts, item) !== operandValue(condition.right, facts, item);
    case "matches": {
      const candidate = operandValue(condition.operand, facts, item);
      return typeof candidate === "string" && new RegExp(condition.pattern, condition.flags).test(candidate);
    }
    case "gt":
    case "gte":
    case "lt":
    case "lte": {
      const left = operandValue(condition.left, facts, item);
      const right = operandValue(condition.right, facts, item);
      if (left === null || left === undefined || right === null || right === undefined) return false;
      if (condition.op === "gt") return Number(left) > Number(right);
      if (condition.op === "gte") return Number(left) >= Number(right);
      if (condition.op === "lt") return Number(left) < Number(right);
      return Number(left) <= Number(right);
    }
    case "ratio": {
      const numeratorValue = operandValue(condition.numerator, facts, item);
      const denominatorValue = operandValue(condition.denominator, facts, item);
      const thresholdValue = operandValue(condition.threshold, facts, item);
      if (
        numeratorValue === null || numeratorValue === undefined
        || denominatorValue === null || denominatorValue === undefined
        || thresholdValue === null || thresholdValue === undefined
      ) {
        return false;
      }
      const numerator = Number(numeratorValue);
      const denominator = Number(denominatorValue);
      const threshold = Number(thresholdValue);
      if (!Number.isFinite(numerator) || !Number.isFinite(denominator) || denominator <= 0 || !Number.isFinite(threshold)) {
        return false;
      }
      const scaledRatio = (numerator / denominator) * (condition.scale ?? 1);
      const ratio = condition.roundDigits === undefined
        ? scaledRatio
        : Math.round(scaledRatio * (10 ** condition.roundDigits)) / (10 ** condition.roundDigits);
      if (condition.comparator === "gt") return ratio > threshold;
      if (condition.comparator === "gte") return ratio >= threshold;
      if (condition.comparator === "lt") return ratio < threshold;
      return ratio <= threshold;
    }
    case "some":
    case "every": {
      const value = pathValue(facts, condition.path, item);
      if (!Array.isArray(value)) return false;
      return condition.op === "some"
        ? value.some((entry) => evaluateCondition(condition.condition, facts, entry))
        : value.every((entry) => evaluateCondition(condition.condition, facts, entry));
    }
    default: {
      const unhandled: never = condition;
      return unhandled;
    }
  }
}

export function evaluateVerdictCondition(condition: VerdictCondition, facts: VerdictFacts): boolean {
  return evaluateCondition(condition, facts, undefined);
}

function renderOperand(operand: VerdictOperand): string {
  switch (operand.kind) {
    case "value":
      return Array.isArray(operand.value) ? `[${operand.value.join(", ")}]` : JSON.stringify(operand.value);
    case "path":
      return `\`${operand.path}\`${"fallback" in operand ? ` (default ${JSON.stringify(operand.fallback)})` : ""}`;
    case "length":
      return `length of \`${operand.path}\``;
    default: {
      const unhandled: never = operand;
      return String(unhandled);
    }
  }
}

export function renderVerdictCondition(condition: VerdictCondition): string {
  switch (condition.op) {
    case "always":
      return "always";
    case "and":
      return `all of (${condition.conditions.map(renderVerdictCondition).join("; ")})`;
    case "or":
      return `any of (${condition.conditions.map(renderVerdictCondition).join("; ")})`;
    case "not":
      return `not (${renderVerdictCondition(condition.condition)})`;
    case "defined":
      return `${renderOperand(condition.operand)} is present and non-null`;
    case "null":
      return `${renderOperand(condition.operand)} is null`;
    case "eq":
      return `${renderOperand(condition.left)} equals ${renderOperand(condition.right)}`;
    case "ne":
      return `${renderOperand(condition.left)} does not equal ${renderOperand(condition.right)}`;
    case "matches":
      return `${renderOperand(condition.operand)} matches portable regular expression \`${condition.pattern}\`${condition.flags ? ` with flags \`${condition.flags}\`` : ""}`;
    case "gt":
      return `${renderOperand(condition.left)} is greater than ${renderOperand(condition.right)}`;
    case "gte":
      return `${renderOperand(condition.left)} is at least ${renderOperand(condition.right)}`;
    case "lt":
      return `${renderOperand(condition.left)} is less than ${renderOperand(condition.right)}`;
    case "lte":
      return `${renderOperand(condition.left)} is at most ${renderOperand(condition.right)}`;
    case "ratio":
      return `${renderOperand(condition.numerator)} divided by ${renderOperand(condition.denominator)}${
        condition.scale === undefined ? "" : `, multiplied by ${condition.scale}`
      }${
        condition.roundDigits === undefined ? "" : `, rounded to ${condition.roundDigits} decimal place(s)`
      } is ${
        condition.comparator === "gt"
          ? "greater than"
          : condition.comparator === "gte"
            ? "at least"
            : condition.comparator === "lt"
              ? "less than"
              : "at most"
      } ${renderOperand(condition.threshold)}; a missing, nonnumeric, or nonpositive denominator does not match`;
    case "some":
      return `some item in \`${condition.path}\` satisfies (${renderVerdictCondition(condition.condition)})`;
    case "every":
      return `every item in \`${condition.path}\` satisfies (${renderVerdictCondition(condition.condition)})`;
    default: {
      const unhandled: never = condition;
      return String(unhandled);
    }
  }
}

function operandPaths(operand: VerdictOperand): string[] {
  return operand.kind === "path" || operand.kind === "length" ? [operand.path] : [];
}

export function verdictConditionPaths(condition: VerdictCondition): string[] {
  switch (condition.op) {
    case "always":
      return [];
    case "and":
    case "or":
      return condition.conditions.flatMap(verdictConditionPaths);
    case "not":
      return verdictConditionPaths(condition.condition);
    case "defined":
    case "null":
      return operandPaths(condition.operand);
    case "matches":
      return operandPaths(condition.operand);
    case "eq":
    case "ne":
    case "gt":
    case "gte":
    case "lt":
    case "lte":
      return [...operandPaths(condition.left), ...operandPaths(condition.right)];
    case "ratio":
      return [
        ...operandPaths(condition.numerator),
        ...operandPaths(condition.denominator),
        ...operandPaths(condition.threshold),
      ];
    case "some":
    case "every":
      return [condition.path, ...verdictConditionPaths(condition.condition)];
    default: {
      const unhandled: never = condition;
      return [String(unhandled)];
    }
  }
}
