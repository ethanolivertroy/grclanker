import {
  SHARED_COLLECTION_STATES,
  SHARED_INTEGRATION_CONTRACT_VERSION,
} from "./hardening/contract.js";
import {
  checkContract,
  defineGrcTool,
  evaluateVerdictCriteria,
  type CheckContract,
  type EvaluatedFindingStatus,
  type FindingSeverity,
  type FrameworkKey,
  type IntegrationSpecContract,
  toolContract,
} from "./spec-model.js";
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
}

export interface BatchCheckDefinition {
  id: string;
  control: number;
  title: string;
  severity: FindingSeverity;
  owner: string;
  surfaces?: readonly string[];
  frameworks?: Partial<Record<FrameworkKey, readonly string[]>>;
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
  permissions: readonly string[];
  surfaces: readonly BatchSurfaceDefinition[];
  checks: readonly BatchCheckDefinition[];
  tools: Readonly<Record<string, readonly string[]>>;
  pagination: {
    cursorFields: readonly string[];
    pageSize: number | null;
    itemCap: number | null;
    pageCap: number | null;
    totalSemantics: string;
    stopConditions: readonly string[];
  };
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
  outputPrefix: string;
}

function frameworkMap(values: BatchCheckDefinition["frameworks"] = {}): Record<FrameworkKey, readonly string[]> {
  return Object.fromEntries(FRAMEWORK_KEYS.map((key) => [key, values[key] ?? []])) as Record<FrameworkKey, readonly string[]>;
}

function criterion(check: BatchCheckDefinition): CheckContract["criteria"] {
  return {
    pass: `Complete, readable evidence satisfies the runtime predicates for ${check.title}; partial, denied, missing, or null evidence cannot select this outcome.`,
    warn: `Readable evidence establishes an incomplete or review-required posture for ${check.title}, including any runtime sampling or truncation limitation.`,
    fail: `Readable evidence establishes a configured violation of ${check.title}; this outcome has first-match precedence over partial-evidence warnings.`,
    manual: `The required evidence for ${check.title} is absent, null, denied, unreadable, not requested, or otherwise insufficient for an automated verdict.`,
    constants: {
      passStatus: "pass",
      warnStatus: "warn",
      failStatus: "fail",
      manualStatus: "manual",
    },
    examples: [
      {
        kind: "compliant",
        input: "All required source reads are complete and the evidence-specific runtime evaluation returns pass.",
        expected: "pass",
        reason: "A pass is preserved only after the integration-specific evaluator has proved the compliant predicate from complete evidence.",
      },
      {
        kind: "noncompliant",
        input: "A complete source read proves a configured violation and the evidence-specific runtime evaluation returns fail.",
        expected: "fail",
        reason: "A proven violation remains fail even when another dependent inventory is also partial because fail has first-match precedence.",
      },
      {
        kind: "partial",
        input: "At least one required inventory is capped, truncated, sampled, or incomplete and no proven violation exists.",
        expected: "warn",
        reason: "Incomplete coverage cannot prove compliance and is therefore retained as a warning or stricter outcome selected by runtime.",
      },
      {
        kind: "unreadable",
        input: "A required value is null, missing, denied, never requested, malformed, or unreadable.",
        expected: "manual",
        reason: "Unavailable evidence is not treated as an empty collection or a false negative and therefore never passes.",
      },
    ],
    rules: [
      {
        status: "fail",
        condition: {
          op: "eq",
          left: { kind: "path", path: "decision_status" },
          right: { kind: "value", value: "fail" },
        },
        note: "A proven violation wins before incomplete-evidence outcomes.",
      },
      {
        status: "warn",
        condition: {
          op: "eq",
          left: { kind: "path", path: "decision_status" },
          right: { kind: "value", value: "warn" },
        },
        note: "The runtime selected warning from readable but incomplete or review-required evidence.",
      },
      {
        status: "pass",
        condition: {
          op: "eq",
          left: { kind: "path", path: "decision_status" },
          right: { kind: "value", value: "pass" },
        },
        note: "The runtime may select pass only after every required dependency is complete.",
      },
      {
        status: "manual",
        condition: { op: "always" },
        note: "Null, missing, denied, partial-without-a-runtime-warning, malformed, and unknown states fall back to manual.",
      },
    ],
  };
}

const OUTPUT_FILES = [
  "core_data/access.json",
  "analysis/findings.json",
  "compliance/executive_summary.md",
  "compliance/unified_compliance_matrix.md",
  "compliance/fedramp/fedramp_compliance_report.md",
  "compliance/cmmc/cmmc_compliance_report.md",
  "compliance/soc2/soc2_compliance_report.md",
  "compliance/cis/cis_compliance_report.md",
  "compliance/pci_dss/pci_dss_compliance_report.md",
  "compliance/disa_stig/stig_compliance_checklist.md",
  "compliance/irap/irap_compliance_report.md",
  "compliance/ismap/ismap_compliance_report.md",
  "QUICK_REFERENCE.md",
] as const;

export function buildBatchIntegrationSpec(definition: BatchSpecDefinition): IntegrationSpecContract {
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
      clientRegion: `Use the configured ${surface.service} origin; never follow a server link to a different origin.`,
      headers: ["Authorization appropriate to the selected authentication mode", "Accept: application/json"],
      parameters: [],
      responseShape: `A JSON object or list containing only the documented ${surface.fields.join(", ")} members consumed by verdicts.`,
    },
    intent: "read" as const,
  }));
  const surfaceIds = surfaces.map((surface) => surface.id);
  const checks = definition.checks.map((check) => ({
    id: check.id,
    controlNumbers: [check.control],
    title: check.title,
    severity: check.severity,
    owningTool: check.owner,
    sourceSurfaceIds: check.surfaces ?? surfaceIds,
    evidenceFields: ["decision_status"],
    derivedFacts: {
      decision_status: "Run the integration's evidence-specific, dependency-aware evaluator over complete cardinalities and projected source values. Preserve fail, warn, pass, or manual exactly; null, missing, denied, and unreadable required evidence derives manual, never pass.",
    },
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
  const projections = Object.fromEntries(surfaces.map((surface) => [surface.id, surface.fields]));
  const outputArtifacts = [
    { path: "core_data/{dataset}.json", format: "json" as const, requiredWhen: "The dataset is part of the assessment, including explicit not-collected markers.", schema: "Projected source records or a structured unavailable marker; unavailable values remain null.", serialization: "UTF-8 JSON with two-space indentation and a trailing newline." },
    { path: "analysis/findings.json", format: "json" as const, requiredWhen: "Always.", schema: "Array of finding id, control, title, severity, status, summary, evidence, mappings, and optional manual evidence.", serialization: "UTF-8 JSON with two-space indentation and a trailing newline." },
    { path: "compliance/executive_summary.md", format: "markdown" as const, requiredWhen: "Always.", schema: "Human-readable counts and findings grouped by status.", serialization: "UTF-8 Markdown." },
    { path: "compliance/unified_compliance_matrix.md", format: "markdown" as const, requiredWhen: "Always.", schema: "Finding-to-framework mapping matrix.", serialization: "UTF-8 Markdown." },
    { path: "compliance/{framework}/{report}.md", format: "markdown" as const, requiredWhen: "Always for each supported framework.", schema: "Framework-specific finding rows and mappings.", serialization: "UTF-8 Markdown." },
    { path: "QUICK_REFERENCE.md", format: "markdown" as const, requiredWhen: "Always.", schema: "Bundle navigation and operator next steps.", serialization: "UTF-8 Markdown." },
    { path: "_errors.log", format: "text" as const, requiredWhen: "At least one collection read failed, was denied, or was incomplete.", schema: "Scrubbed collection error summaries without response bodies or credentials.", serialization: "UTF-8 text." },
  ];
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
    permissions: definition.permissions.map((permission, index) => ({
      id: `permission-${index + 1}`,
      kind: "role",
      value: permission,
      unlocks: surfaceIds,
      notes: "Read-only access; denied or plan-gated surfaces remain explicit unavailable evidence.",
    })),
    pagination: [{
      surfaceIds,
      cursorFields: definition.pagination.cursorFields,
      pageSize: definition.pagination.pageSize,
      itemCap: definition.pagination.itemCap,
      pageCap: definition.pagination.pageCap,
      totalSemantics: definition.pagination.totalSemantics,
      stopConditions: definition.pagination.stopConditions,
    }],
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
    output: {
      files: OUTPUT_FILES,
      conditionalFiles: ["_errors.log"],
      artifacts: outputArtifacts,
      overwritePolicy: "Allocate a new suffixed output directory on every rerun; never overwrite an earlier bundle.",
      pathSafetyPolicy: "Resolve beneath the configured output root and reject traversal, unsafe parents, files, and symbolic-link escapes.",
      archivePairing: `Create ${definition.outputPrefix}.zip beside the allocated ${definition.outputPrefix} directory, applying the same suffix to both.`,
      recordSchemas: {
        finding: ["id", "control", "title", "severity", "status", "summary", "evidence", "mappings", "manualEvidence"],
        collection_marker: ["collected", "status", "endpoint", "error", "reason"],
        access_surface: ["name", "endpoint", "status", "count", "error"],
        assessment: ["area", "title", "summary", "findings", "errors"],
        bundle_manifest: ["outputDir", "zipPath", "fileCount", "findingCount", "errorCount"],
      },
      jsonFormatting: "UTF-8 JSON with deterministic field order, two-space indentation, and a trailing newline.",
    },
    tools,
  };
}

export function evaluateObservedFindingStatus(
  spec: IntegrationSpecContract,
  checkId: string,
  status: EvaluatedFindingStatus,
): EvaluatedFindingStatus {
  return evaluateVerdictCriteria(checkContract(spec, checkId).criteria, { decision_status: status });
}

export function preserveRuntimeFindingStatus<T extends string>(
  spec: IntegrationSpecContract,
  checkId: string,
  status: T,
): T {
  const normalized = ({
    Pass: "pass",
    Partial: "warn",
    Fail: "fail",
    Manual: "manual",
    Info: "manual",
  } as Record<string, EvaluatedFindingStatus>)[status] ?? status.toLowerCase() as EvaluatedFindingStatus;
  const evaluated = evaluateObservedFindingStatus(spec, checkId, normalized);
  if (evaluated !== normalized) {
    throw new Error(`${checkId} runtime status ${status} disagrees with its ordered contract (${evaluated})`);
  }
  return status;
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
