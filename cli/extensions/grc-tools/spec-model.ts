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
  constants: Readonly<Record<string, PortableValue>>;
  examples: readonly CriterionExample[];
}

export interface CriterionExample {
  kind: CriterionExampleKind;
  input: string;
  expected: "pass" | "warn" | "fail" | "manual";
  reason: string;
}

export interface CheckContract {
  id: string;
  controlNumbers: readonly number[];
  title: string;
  severity: FindingSeverity;
  owningTool: string;
  sourceSurfaceIds: readonly string[];
  criteria: VerdictCriteria;
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

export function criterionConstant<T extends PortableValue>(
  spec: IntegrationSpecContract,
  checkId: string,
  name: string,
): T {
  const value = checkContract(spec, checkId).criteria.constants[name];
  if (value === undefined) throw new Error(`Check ${checkId} has no criterion constant ${name}`);
  return value as T;
}
