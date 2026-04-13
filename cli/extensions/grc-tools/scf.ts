/**
 * Secure Controls Framework (SCF) tools.
 *
 * Wraps the static JSON API at hackidle.github.io/scf-api and provides
 * practical GRC lookups for controls, crosswalks, and evidence requests.
 */
import { Type } from "@sinclair/typebox";
import { cachedFetch, errorResult, formatTable, textResult } from "./shared.js";

const BASE = "https://hackidle.github.io/scf-api/api";
const TTL = 24 * 60 * 60 * 1000;
const DEFAULT_LIMIT = 10;

export interface ScfControl {
  control_id: string;
  title: string;
  family: string;
  family_name?: string;
  description: string;
  scf_question?: string;
  relative_weight?: number;
  conformity_cadence?: string;
  evidence_requests?: string[];
  pptdf?: string;
  nist_csf_function?: string;
  profiles?: string[];
  risks?: string[];
  threats?: string[];
  errata?: string;
  crosswalks?: Record<string, string[]>;
}

interface ControlsIndexResponse {
  total: number;
  controls: ScfControl[];
}

export interface ScfAssessmentObjective {
  scf_control_id: string;
  ao_id: string;
  objective: string;
  pptdf?: string;
  origin?: string;
  assessment_rigor?: string;
  scf_defined_parameters?: string;
  org_defined_parameters?: string;
}

interface AssessmentObjectivesResponse {
  scf_control_id: string;
  total: number;
  assessment_objectives: ScfAssessmentObjective[];
}

export interface ScfEvidenceRequest {
  erl_id: string;
  area: string;
  artifact_name: string;
  artifact_description: string;
  scf_controls: string[];
  cmmc_mapping?: string;
}

export interface ScfFrameworkIndexEntry {
  framework_id: string;
  display_name: string;
  scf_controls_mapped: number;
  framework_controls_mapped: number;
}

interface CrosswalkIndexResponse {
  total_frameworks: number;
  frameworks: ScfFrameworkIndexEntry[];
}

interface CrosswalkMappings {
  total_mappings: number;
  mappings: Record<string, string[]>;
}

export interface ScfCrosswalkFile {
  display_name: string;
  framework_id: string;
  scf_to_framework: CrosswalkMappings;
  framework_to_scf: CrosswalkMappings;
}

export interface ScfControlBundle {
  control: ScfControl;
  assessment_objectives: ScfAssessmentObjective[];
  evidence_requests: ScfEvidenceRequest[];
  evidence_request_errors: string[];
  framework?: ScfFrameworkIndexEntry;
  framework_mappings?: string[];
}

type SearchArgs = { query: string; limit?: number };
type ControlArgs = { control_id: string; framework?: string };
type CrosswalkArgs = {
  framework: string;
  control_id?: string;
  framework_control_id?: string;
  limit?: number;
};
type EvidenceArgs = { erl_id: string };

function asString(value: unknown): string | undefined {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }

  if (typeof value === "number" && Number.isFinite(value)) {
    return String(value);
  }

  return undefined;
}

function asNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === "string" && value.trim().length > 0) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }

  return undefined;
}

function clampLimit(value: number | undefined, fallback = DEFAULT_LIMIT): number {
  const parsed = value ?? fallback;
  return Math.min(Math.max(Math.trunc(parsed), 1), 50);
}

function normalizeControlId(value: string): string {
  return value.trim().toUpperCase();
}

function normalizeEvidenceId(value: string): string {
  return value.trim().toUpperCase();
}

function normalizeSearchArgs(args: unknown): SearchArgs {
  if (typeof args === "string" || typeof args === "number") {
    return { query: String(args), limit: DEFAULT_LIMIT };
  }

  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    return {
      query:
        asString(value.query) ??
        asString(value.control) ??
        asString(value.control_id) ??
        asString(value.family) ??
        "",
      limit: clampLimit(asNumber(value.limit)),
    };
  }

  return { query: "", limit: DEFAULT_LIMIT };
}

function normalizeControlArgs(args: unknown): ControlArgs {
  if (typeof args === "string" || typeof args === "number") {
    return { control_id: String(args) };
  }

  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    return {
      control_id:
        asString(value.control_id) ??
        asString(value.control) ??
        asString(value.id) ??
        asString(value.query) ??
        "",
      framework:
        asString(value.framework) ??
        asString(value.framework_id) ??
        asString(value.framework_name),
    };
  }

  return { control_id: "" };
}

function normalizeCrosswalkArgs(args: unknown): CrosswalkArgs {
  if (typeof args === "string" || typeof args === "number") {
    return { framework: String(args), limit: DEFAULT_LIMIT };
  }

  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    return {
      framework:
        asString(value.framework) ??
        asString(value.framework_id) ??
        asString(value.query) ??
        "",
      control_id: asString(value.control_id) ?? asString(value.scf_control_id),
      framework_control_id:
        asString(value.framework_control_id) ??
        asString(value.source_control_id) ??
        asString(value.requirement_id),
      limit: clampLimit(asNumber(value.limit)),
    };
  }

  return { framework: "", limit: DEFAULT_LIMIT };
}

function normalizeEvidenceArgs(args: unknown): EvidenceArgs {
  if (typeof args === "string" || typeof args === "number") {
    return { erl_id: String(args) };
  }

  if (args && typeof args === "object") {
    const value = args as Record<string, unknown>;
    return {
      erl_id:
        asString(value.erl_id) ??
        asString(value.evidence_request) ??
        asString(value.id) ??
        asString(value.query) ??
        "",
    };
  }

  return { erl_id: "" };
}

function summarizeList(values: string[] | undefined, limit = 5): string {
  if (!values?.length) return "None";
  if (values.length <= limit) return values.join(", ");
  return `${values.slice(0, limit).join(", ")} (+${values.length - limit} more)`;
}

function truncate(text: string | undefined, length = 120): string | undefined {
  if (!text) return undefined;
  if (text.length <= length) return text;
  return `${text.slice(0, length - 3)}...`;
}

function buildControlSearchText(control: ScfControl): string {
  const crosswalkKeys = Object.keys(control.crosswalks ?? {});
  const crosswalkValues = crosswalkKeys.flatMap((key) => control.crosswalks?.[key] ?? []);

  return [
    control.control_id,
    control.title,
    control.family,
    control.family_name ?? "",
    control.description,
    control.scf_question ?? "",
    control.nist_csf_function ?? "",
    ...(control.evidence_requests ?? []),
    ...crosswalkKeys,
    ...crosswalkValues,
  ]
    .join(" ")
    .toLowerCase();
}

export function findMatchingScfControls(
  controls: ScfControl[],
  query: string,
): ScfControl[] {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) return [];
  return controls.filter((control) => buildControlSearchText(control).includes(normalizedQuery));
}

export function resolveScfFrameworkMatch(
  frameworks: ScfFrameworkIndexEntry[],
  query: string,
): ScfFrameworkIndexEntry {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) {
    throw new Error("A non-empty framework query is required.");
  }

  const exactId = frameworks.find(
    (framework) => framework.framework_id.toLowerCase() === normalizedQuery,
  );
  if (exactId) return exactId;

  const exactName = frameworks.find(
    (framework) => framework.display_name.toLowerCase() === normalizedQuery,
  );
  if (exactName) return exactName;

  const partial = frameworks.filter((framework) =>
    framework.framework_id.toLowerCase().includes(normalizedQuery) ||
    framework.display_name.toLowerCase().includes(normalizedQuery)
  );

  if (partial.length === 1) {
    return partial[0]!;
  }

  const tokens = normalizedQuery.split(/\s+/).filter(Boolean);
  const tokenMatches = frameworks.filter((framework) => {
    const haystack = `${framework.framework_id} ${framework.display_name}`.toLowerCase();
    return tokens.every((token) => haystack.includes(token));
  });

  if (tokenMatches.length === 1) {
    return tokenMatches[0]!;
  }

  const candidates = partial.length > 0 ? partial : tokenMatches;

  if (candidates.length === 0) {
    throw new Error(`No SCF framework matched "${query}".`);
  }

  const examples = candidates
    .slice(0, 5)
    .map((framework) => `${framework.display_name} [${framework.framework_id}]`)
    .join("; ");
  throw new Error(
    `Framework query "${query}" matched multiple SCF frameworks. Narrow it down. Examples: ${examples}`,
  );
}

async function fetchControlsIndex(): Promise<ControlsIndexResponse> {
  return cachedFetch<ControlsIndexResponse>(`${BASE}/controls.json`, TTL);
}

async function fetchControl(controlId: string): Promise<ScfControl> {
  return cachedFetch<ScfControl>(`${BASE}/controls/${encodeURIComponent(normalizeControlId(controlId))}.json`, TTL);
}

async function fetchAssessmentObjectives(controlId: string): Promise<AssessmentObjectivesResponse> {
  return cachedFetch<AssessmentObjectivesResponse>(
    `${BASE}/assessment-objectives/${encodeURIComponent(normalizeControlId(controlId))}.json`,
    TTL,
  );
}

async function fetchEvidenceRequest(erlId: string): Promise<ScfEvidenceRequest> {
  return cachedFetch<ScfEvidenceRequest>(
    `${BASE}/evidence-requests/${encodeURIComponent(normalizeEvidenceId(erlId))}.json`,
    TTL,
  );
}

async function fetchCrosswalkIndex(): Promise<CrosswalkIndexResponse> {
  return cachedFetch<CrosswalkIndexResponse>(`${BASE}/crosswalks.json`, TTL);
}

async function fetchCrosswalk(frameworkId: string): Promise<ScfCrosswalkFile> {
  return cachedFetch<ScfCrosswalkFile>(
    `${BASE}/crosswalks/${encodeURIComponent(frameworkId)}.json`,
    TTL,
  );
}

export async function loadScfControlBundle(
  controlId: string,
  frameworkQuery?: string,
): Promise<ScfControlBundle> {
  const control = await fetchControl(controlId);
  const [objectivesPayload, evidenceResults, frameworkIndex] = await Promise.all([
    fetchAssessmentObjectives(control.control_id),
    Promise.allSettled((control.evidence_requests ?? []).map((erlId) => fetchEvidenceRequest(erlId))),
    frameworkQuery ? fetchCrosswalkIndex() : Promise.resolve(undefined),
  ]);

  const evidence_requests: ScfEvidenceRequest[] = [];
  const evidence_request_errors: string[] = [];

  for (const result of evidenceResults) {
    if (result.status === "fulfilled") {
      evidence_requests.push(result.value);
    } else {
      evidence_request_errors.push(result.reason instanceof Error ? result.reason.message : String(result.reason));
    }
  }

  let framework: ScfFrameworkIndexEntry | undefined;
  let framework_mappings: string[] | undefined;

  if (frameworkQuery && frameworkIndex) {
    framework = resolveScfFrameworkMatch(frameworkIndex.frameworks, frameworkQuery);
    framework_mappings = control.crosswalks?.[framework.framework_id] ?? [];
  }

  return {
    control,
    assessment_objectives: objectivesPayload.assessment_objectives,
    evidence_requests,
    evidence_request_errors,
    framework,
    framework_mappings,
  };
}

export async function loadScfFrameworkCrosswalk(
  frameworkQuery: string,
): Promise<{ framework: ScfFrameworkIndexEntry; crosswalk: ScfCrosswalkFile }> {
  const index = await fetchCrosswalkIndex();
  const framework = resolveScfFrameworkMatch(index.frameworks, frameworkQuery);
  const crosswalk = await fetchCrosswalk(framework.framework_id);
  return { framework, crosswalk };
}

function formatControlSummary(control: ScfControl): string {
  const lines = [
    `${control.control_id} - ${control.title}`,
    `  Family:            ${control.family}${control.family_name ? ` - ${control.family_name}` : ""}`,
    `  Cadence:           ${control.conformity_cadence ?? "Unknown"}`,
    `  Relative weight:   ${control.relative_weight ?? "Unknown"}`,
    `  PPTDF:             ${control.pptdf ?? "Unknown"}`,
    `  NIST CSF function: ${control.nist_csf_function ?? "Unknown"}`,
    `  Evidence refs:     ${summarizeList(control.evidence_requests, 6)}`,
    `  Profiles:          ${summarizeList(control.profiles, 4)}`,
    `  Risks:             ${control.risks?.length ?? 0} refs`,
    `  Threats:           ${control.threats?.length ?? 0} refs`,
  ];

  const description = truncate(control.description, 220);
  if (description) {
    lines.push(`  Description:       ${description}`);
  }

  return lines.join("\n");
}

function buildControlBundleText(bundle: ScfControlBundle): string {
  const lines = [formatControlSummary(bundle.control)];

  if (bundle.framework) {
    const mappings = bundle.framework_mappings?.length
      ? bundle.framework_mappings.join(", ")
      : "No mapping found for this control in the selected framework.";
    lines.push(
      `  Framework:         ${bundle.framework.display_name} [${bundle.framework.framework_id}]`,
      `  Mapping:           ${mappings}`,
    );
  }

  if (bundle.assessment_objectives.length > 0) {
    const sample = bundle.assessment_objectives
      .slice(0, 5)
      .map((objective) => `- ${objective.ao_id}: ${truncate(objective.objective, 140)}`)
      .join("\n");
    lines.push(
      "",
      `Assessment objectives (${bundle.assessment_objectives.length}):`,
      sample,
    );
  }

  if (bundle.evidence_requests.length > 0) {
    const evidence = bundle.evidence_requests
      .map(
        (request) =>
          `- ${request.erl_id}: ${request.artifact_name} — ${truncate(request.artifact_description, 120)}`,
      )
      .join("\n");
    lines.push("", "Evidence requests:", evidence);
  }

  if (bundle.evidence_request_errors.length > 0) {
    lines.push(
      "",
      `Warnings: ${bundle.evidence_request_errors.length} evidence request lookup(s) failed.`,
    );
  }

  return lines.join("\n");
}

function buildCrosswalkText(
  framework: ScfFrameworkIndexEntry,
  crosswalk: ScfCrosswalkFile,
  args: CrosswalkArgs,
): string {
  const scfControlId = args.control_id ? normalizeControlId(args.control_id) : undefined;
  const frameworkControlId = args.framework_control_id?.trim();

  if (scfControlId) {
    const mappings = crosswalk.scf_to_framework.mappings[scfControlId] ?? [];
    const mappingText = mappings.length ? mappings.join(", ") : "No mappings found.";
    return [
      `${framework.display_name} [${framework.framework_id}]`,
      `SCF control: ${scfControlId}`,
      `Mapped framework controls: ${mappingText}`,
    ].join("\n");
  }

  if (frameworkControlId) {
    const mappings = crosswalk.framework_to_scf.mappings[frameworkControlId] ?? [];
    const mappingText = mappings.length ? mappings.join(", ") : "No mappings found.";
    return [
      `${framework.display_name} [${framework.framework_id}]`,
      `Framework control: ${frameworkControlId}`,
      `Mapped SCF controls: ${mappingText}`,
    ].join("\n");
  }

  const limit = clampLimit(args.limit, 8);
  const scfRows = Object.entries(crosswalk.scf_to_framework.mappings)
    .slice(0, limit)
    .map(([controlId, mapped]) => [controlId, summarizeList(mapped, 3)]);
  const frameworkRows = Object.entries(crosswalk.framework_to_scf.mappings)
    .slice(0, limit)
    .map(([controlId, mapped]) => [controlId, summarizeList(mapped, 3)]);

  return [
    `${framework.display_name} [${framework.framework_id}]`,
    `  SCF controls mapped:       ${framework.scf_controls_mapped}`,
    `  Framework controls mapped: ${framework.framework_controls_mapped}`,
    "",
    "SCF -> framework samples:",
    formatTable(["scf_control", "mapped_framework_controls"], scfRows),
    "",
    "Framework -> SCF samples:",
    formatTable(["framework_control", "mapped_scf_controls"], frameworkRows),
  ].join("\n");
}

function formatEvidenceRequest(request: ScfEvidenceRequest): string {
  const lines = [
    `${request.erl_id} - ${request.artifact_name}`,
    `  Area:          ${request.area}`,
    `  SCF controls:  ${summarizeList(request.scf_controls, 8)}`,
    `  CMMC mapping:  ${request.cmmc_mapping?.trim() || "None"}`,
  ];

  const description = truncate(request.artifact_description, 220);
  if (description) {
    lines.push(`  Description:   ${description}`);
  }

  return lines.join("\n");
}

function missingQueryResult(toolName: string, example: string) {
  return errorResult(
    `${toolName} requires a non-empty query. Example: ${example}`,
    { tool: toolName },
  );
}

export function registerScfTools(pi: any): void {
  pi.registerTool({
    name: "scf_search_controls",
    label: "Search SCF controls",
    description:
      "Search Secure Controls Framework controls by SCF control ID, title, family, evidence request reference, or mapped framework control.",
    parameters: Type.Object({
      query: Type.String({
        description:
          "Search term such as GOV-01, governance, E-GOV-01, PM-01, or NIST.",
      }),
      limit: Type.Optional(
        Type.Number({
          description: "Max results to return (default: 10).",
          default: DEFAULT_LIMIT,
        }),
      ),
    }),
    prepareArguments: normalizeSearchArgs,
    async execute(_toolCallId: string, args: SearchArgs) {
      if (!args.query.trim()) {
        return missingQueryResult("scf_search_controls", '{"query":"GOV-01"}');
      }

      try {
        const data = await fetchControlsIndex();
        const matches = findMatchingScfControls(data.controls, args.query).slice(
          0,
          clampLimit(args.limit),
        );

        if (matches.length === 0) {
          return textResult(`No SCF controls found matching "${args.query}".`, {
            tool: "scf_search_controls",
            query: args.query,
            count: 0,
          });
        }

        const rows = matches.map((control) => [
          control.control_id,
          control.family,
          truncate(control.title, 50) ?? control.title,
          summarizeList(control.evidence_requests, 2),
        ]);

        return textResult(
          `Found ${matches.length} SCF control(s) matching "${args.query}" (of ${data.total} total).\n\n` +
            formatTable(["control_id", "family", "title", "evidence_refs"], rows),
          {
            tool: "scf_search_controls",
            query: args.query,
            count: matches.length,
            controls: matches.map((control) => ({
              control_id: control.control_id,
              title: control.title,
              family: control.family,
              family_name: control.family_name ?? null,
              evidence_requests: control.evidence_requests ?? [],
            })),
          },
        );
      } catch (error) {
        return errorResult(
          `SCF control search failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "scf_search_controls", query: args.query },
        );
      }
    },
  });

  pi.registerTool({
    name: "scf_get_control",
    label: "Get SCF control bundle",
    description:
      "Fetch a Secure Controls Framework control with linked assessment objectives and evidence request details. Optionally spotlight a specific framework mapping.",
    parameters: Type.Object({
      control_id: Type.String({
        description: "SCF control ID such as GOV-01 or IAM-02.1.",
      }),
      framework: Type.Optional(
        Type.String({
          description:
            "Optional framework ID or explicit display-name query to spotlight matching crosswalk mappings for this control, such as general-nist-800-53-r5-2 or NIST SP 800-53 R5.",
        }),
      ),
    }),
    prepareArguments: normalizeControlArgs,
    async execute(_toolCallId: string, args: ControlArgs) {
      if (!args.control_id.trim()) {
        return missingQueryResult("scf_get_control", '{"control_id":"GOV-01"}');
      }

      try {
        const bundle = await loadScfControlBundle(args.control_id, args.framework);
        return textResult(buildControlBundleText(bundle), {
          tool: "scf_get_control",
          control_id: bundle.control.control_id,
          title: bundle.control.title,
          family: bundle.control.family,
          framework: bundle.framework
            ? {
                framework_id: bundle.framework.framework_id,
                display_name: bundle.framework.display_name,
                mappings: bundle.framework_mappings ?? [],
              }
            : null,
          assessment_objective_count: bundle.assessment_objectives.length,
          evidence_request_count: bundle.evidence_requests.length,
          evidence_request_errors: bundle.evidence_request_errors,
        });
      } catch (error) {
        return errorResult(
          `SCF control lookup failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "scf_get_control", control_id: args.control_id, framework: args.framework ?? null },
        );
      }
    },
  });

  pi.registerTool({
    name: "scf_get_crosswalk",
    label: "Get SCF framework crosswalk",
    description:
      "Resolve a Secure Controls Framework crosswalk by framework ID or display name. Optionally filter by SCF control ID or framework control ID.",
    parameters: Type.Object({
      framework: Type.String({
        description:
          "Framework ID or explicit display-name query, such as general-nist-800-53-r5-2 or NIST SP 800-53 R5.",
      }),
      control_id: Type.Optional(
        Type.String({
          description: "Optional SCF control ID to filter mappings, such as GOV-01.",
        }),
      ),
      framework_control_id: Type.Optional(
        Type.String({
          description: "Optional framework control ID to reverse-map, such as PM-01.",
        }),
      ),
      limit: Type.Optional(
        Type.Number({
          description: "Sample size when returning an overview (default: 8).",
          default: 8,
        }),
      ),
    }),
    prepareArguments: normalizeCrosswalkArgs,
    async execute(_toolCallId: string, args: CrosswalkArgs) {
      if (!args.framework.trim()) {
        return missingQueryResult("scf_get_crosswalk", '{"framework":"NIST SP 800-53 R5"}');
      }

      try {
        const { framework, crosswalk } = await loadScfFrameworkCrosswalk(args.framework);
        return textResult(buildCrosswalkText(framework, crosswalk, args), {
          tool: "scf_get_crosswalk",
          framework_id: framework.framework_id,
          display_name: framework.display_name,
          scf_controls_mapped: framework.scf_controls_mapped,
          framework_controls_mapped: framework.framework_controls_mapped,
          control_id: args.control_id ?? null,
          framework_control_id: args.framework_control_id ?? null,
        });
      } catch (error) {
        return errorResult(
          `SCF crosswalk lookup failed: ${error instanceof Error ? error.message : String(error)}`,
          {
            tool: "scf_get_crosswalk",
            framework: args.framework,
            control_id: args.control_id ?? null,
            framework_control_id: args.framework_control_id ?? null,
          },
        );
      }
    },
  });

  pi.registerTool({
    name: "scf_get_evidence_request",
    label: "Get SCF evidence request",
    description:
      "Fetch an SCF evidence request by ERL ID to see artifact guidance and linked control references.",
    parameters: Type.Object({
      erl_id: Type.String({
        description: "Evidence request ID such as E-GOV-01.",
      }),
    }),
    prepareArguments: normalizeEvidenceArgs,
    async execute(_toolCallId: string, args: EvidenceArgs) {
      if (!args.erl_id.trim()) {
        return missingQueryResult("scf_get_evidence_request", '{"erl_id":"E-GOV-01"}');
      }

      try {
        const request = await fetchEvidenceRequest(args.erl_id);
        return textResult(formatEvidenceRequest(request), {
          tool: "scf_get_evidence_request",
          erl_id: request.erl_id,
          artifact_name: request.artifact_name,
          area: request.area,
          scf_controls: request.scf_controls,
          cmmc_mapping: request.cmmc_mapping?.trim() || null,
        });
      } catch (error) {
        return errorResult(
          `SCF evidence request lookup failed: ${error instanceof Error ? error.message : String(error)}`,
          { tool: "scf_get_evidence_request", erl_id: args.erl_id },
        );
      }
    },
  });
}
