import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

export type IntegrationKind = "security-inspector" | "operator-bridge" | "runtime-architecture";
export type ApiSurfaceKind = "rest" | "sdk";
export type ApiIntent = "read" | "auth-only";
export type PermissionKind = "oauth-scope" | "iam-action" | "role" | "license" | "plan";
export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";
export type FrameworkKey = "fedramp" | "cmmc" | "soc2" | "cis" | "pci_dss" | "disa_stig" | "irap" | "ismap";

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
  baseService: string;
  documentationUrl: string;
  fieldsConsumed: readonly string[];
  intent: ApiIntent;
}

export interface AuthenticationContract {
  modes: readonly string[];
  credentialPrecedence: readonly string[];
  environmentVariables: readonly string[];
  configLocations: readonly string[];
  variants: readonly string[];
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
  sensitiveFields: readonly string[];
  benignExceptions: readonly string[];
  credentialFormats: readonly string[];
}

export interface ExportContract {
  files: readonly string[];
  conditionalFiles: readonly string[];
  overwritePolicy: string;
  pathSafetyPolicy: string;
  archivePairing: string;
}

export interface ToolContract {
  checkIds: readonly string[];
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
