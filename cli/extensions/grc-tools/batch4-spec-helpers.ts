import type { ResolverAuthenticationContract } from "./auth-resolver-contracts.js";
import {
  buildBatchIntegrationSpec,
  buildBatchOutputContract,
  type BatchPaginationDefinition,
  type BatchSurfaceDefinition,
} from "./batch-spec-builder.js";
import {
  BATCH3_FRAMEWORK_FILES,
  batch3Checks,
  type Batch3CheckRow,
} from "./batch3-spec-helpers.js";
import type {
  FindingSeverity,
  FrameworkKey,
  IntegrationSpecContract,
  PortableValue,
} from "./spec-model.js";

export interface Batch4Control {
  id: string;
  control: number;
  title: string;
  severity: FindingSeverity;
  owner: string;
  surfaces: readonly string[];
  predicate: string;
  frameworks?: Partial<Record<FrameworkKey, readonly string[]>>;
  constants?: Readonly<Record<string, PortableValue>>;
  emptyOutcome?: "pass" | "warn" | "fail" | "manual" | "info";
  violationOutcome?: "fail" | "warn";
  manualOnly?: boolean;
}

export interface Batch4SpecDefinition {
  slug: string;
  displayName: string;
  vendor: string;
  category: string;
  summary: string;
  sourceModule: string;
  baseServices: readonly string[];
  authentication: ResolverAuthenticationContract;
  surfaces: readonly BatchSurfaceDefinition[];
  controls: readonly Batch4Control[];
  tools: Readonly<Record<string, readonly string[]>>;
  pagination: readonly BatchPaginationDefinition[];
  documentedRateLimit: string | null;
  retryHeaders: readonly string[];
  retryableStatuses?: readonly number[];
  runtimeBehavior: readonly string[];
  knownGaps?: readonly string[];
  sensitiveFields: readonly string[];
  credentialFormats: readonly string[];
  outputFiles: readonly string[];
  conditionalFiles?: readonly string[];
  conditionalFileConditions?: Readonly<Record<string, string>>;
  overwritePolicy: string;
  archivePairing: string;
  permissionKind?: "oauth-scope" | "iam-action" | "role" | "license" | "plan";
}

export function batch4Surface(
  id: string,
  method: "GET" | "POST",
  path: string,
  service: string,
  documentationUrl: string,
  fields: readonly string[],
): BatchSurfaceDefinition {
  return { id, method, path, service, documentationUrl, fields };
}

export function batch4FrameworkFiles(
  overrides: Readonly<Record<string, string>> = {},
): string[] {
  return BATCH3_FRAMEWORK_FILES.map((path) => overrides[path] ?? path);
}

const FRAMEWORK_LABEL_KEYS: readonly [string, FrameworkKey][] = [
  ["FedRAMP", "fedramp"],
  ["CMMC", "cmmc"],
  ["SOC 2", "soc2"],
  ["CIS", "cis"],
  ["PCI-DSS", "pci_dss"],
  ["STIG", "disa_stig"],
  ["DISA STIG", "disa_stig"],
  ["IRAP", "irap"],
  ["ISMAP", "ismap"],
];

export function batch4FrameworksFromMappings(
  mappings: readonly string[],
): Partial<Record<FrameworkKey, readonly string[]>> {
  const result: Partial<Record<FrameworkKey, string[]>> = {};
  for (const mapping of mappings) {
    const label = FRAMEWORK_LABEL_KEYS.find(([candidate]) => mapping.startsWith(`${candidate} `));
    if (!label) continue;
    const value = mapping.slice(label[0].length + 1).trim();
    result[label[1]] = value.split(",").map((entry) => entry.trim()).filter(Boolean);
  }
  return result;
}

export function buildBatch4Spec(definition: Batch4SpecDefinition): IntegrationSpecContract {
  const rows: Batch3CheckRow[] = definition.controls.map((control) => ({
    id: control.id,
    control: control.control,
    title: control.title,
    severity: control.severity,
    owner: control.owner,
    surfaces: control.surfaces,
    predicate: control.predicate,
    frameworks: control.frameworks,
    constants: control.constants,
    emptyOutcome: control.emptyOutcome,
    violationOutcome: control.violationOutcome,
    manualOnly: control.manualOnly,
  }));
  const checks = batch3Checks(rows);
  return buildBatchIntegrationSpec({
    slug: definition.slug,
    displayName: definition.displayName,
    vendor: definition.vendor,
    category: definition.category,
    summary: definition.summary,
    sourceModule: definition.sourceModule,
    baseServices: definition.baseServices,
    authentication: definition.authentication,
    permissions: definition.surfaces.map((surface) => ({
      id: `${surface.id}-read`,
      kind: definition.permissionKind ?? "role",
      value: `${definition.vendor} read permission required for ${surface.service} ${surface.method ?? "GET"} ${surface.path}`,
      unlocks: [surface.id],
    })),
    surfaces: definition.surfaces,
    checks,
    tools: definition.tools,
    pagination: definition.pagination,
    rateLimit: {
      documentedLimit: definition.documentedRateLimit,
      retryHeaders: definition.retryHeaders,
      retryableStatuses: definition.retryableStatuses ?? [429, 500, 502, 503, 504],
      backoffPolicy: "Honor the vendor retry header when present; otherwise retry the declared transient statuses with bounded exponential backoff and jitter, preserving the final failure as unreadable evidence.",
    },
    runtimeBehavior: definition.runtimeBehavior,
    knownGaps: definition.knownGaps ?? [],
    sensitiveFields: definition.sensitiveFields,
    credentialFormats: definition.credentialFormats,
    output: buildBatchOutputContract({
      files: definition.outputFiles,
      conditionalFiles: definition.conditionalFiles ?? ["_errors.log"],
      conditionalFileConditions: definition.conditionalFileConditions ?? {
        "_errors.log": "Written when any access probe, assessment dataset, child lookup, SQL statement, or archive step reports a collection error.",
      },
      overwritePolicy: definition.overwritePolicy,
      archivePairing: definition.archivePairing,
    }),
  });
}
