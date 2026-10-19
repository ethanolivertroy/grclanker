/**
 * The durable assessment document: what the grclanker tools established in
 * one conversation, stored next to the transcript.
 *
 * Every entry is keyed by something a rerun reproduces (the tool call id, or
 * a domain and finding id), so a replay-safe tool that reruns after a crash
 * overwrites its own record instead of adding a second one.
 */
import type { JsonValue } from "@earendil-works/chord";
import { defineDoc, type JsonObject } from "@earendil-works/pi-durable";
import { isJsonObject } from "./json.js";
import type { DurableReplayPolicy } from "./replay.js";

export type AssessmentCallStatus = "completed" | "error";

export type AssessmentCall = {
  tool: string;
  replay: DurableReplayPolicy;
  status: AssessmentCallStatus;
  findings: number;
  recordedAt: string;
};

export type AssessmentFinding = {
  tool: string;
  callId: string;
  status: string;
  severity: string | null;
  title: string | null;
};

export type AssessmentArtifact = {
  tool: string;
  zipPath: string | null;
  outputDir: string | null;
};

export type AssessmentState = {
  /** Keyed by tool call id. */
  calls: { [callId: string]: AssessmentCall };
  /** Keyed `<domain>:<finding id>`, so the latest assessment of a control wins. */
  findings: { [key: string]: AssessmentFinding };
  /** Keyed by tool call id. */
  artifacts: { [callId: string]: AssessmentArtifact };
};

export const ASSESSMENT_DOC_KIND = "grclanker.assessment";

export function emptyAssessmentState(): AssessmentState {
  // Call ids come from the model, so an id of `__proto__` must land as an entry, not on the prototype. Chord accepts and
  // keeps null prototypes, and its drafts write own properties even into documents reloaded as ordinary objects.
  return { calls: Object.create(null), findings: Object.create(null), artifacts: Object.create(null) };
}

export const Assessment = defineDoc<AssessmentState>({
  kind: ASSESSMENT_DOC_KIND,
  version: 1,
  scope: "conversation",
  history: "latest",
  fork: "current",
  initial: emptyAssessmentState,
});

export interface ToolOutcome {
  callId: string;
  tool: string;
  replay: DurableReplayPolicy;
  isError: boolean;
  details: JsonValue | undefined;
  recordedAt: string;
}

function optionalString(value: JsonValue | undefined): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value : null;
}

function readFindings(details: JsonObject): JsonObject[] {
  const findings = details.findings;
  if (!Array.isArray(findings)) return [];
  return findings.filter(
    (finding): finding is JsonObject =>
      isJsonObject(finding) && optionalString(finding.id) !== null && optionalString(finding.status) !== null,
  );
}

function domainOf(toolName: string): string {
  return toolName.split("_")[0] ?? toolName;
}

/** Record one finished tool call on the document draft. */
export function recordToolOutcome(state: AssessmentState, outcome: ToolOutcome): void {
  const details = isJsonObject(outcome.details) && !outcome.isError ? outcome.details : undefined;
  const findings = details ? readFindings(details) : [];

  state.calls[outcome.callId] = {
    tool: outcome.tool,
    replay: outcome.replay,
    status: outcome.isError ? "error" : "completed",
    findings: findings.length,
    recordedAt: outcome.recordedAt,
  };

  for (const finding of findings) {
    state.findings[`${domainOf(outcome.tool)}:${finding.id as string}`] = {
      tool: outcome.tool,
      callId: outcome.callId,
      status: finding.status as string,
      severity: optionalString(finding.severity),
      title: optionalString(finding.title),
    };
  }

  const zipPath = details ? optionalString(details.zip_path) : null;
  const outputDir = details ? optionalString(details.output_dir) : null;
  if (zipPath !== null || outputDir !== null) {
    state.artifacts[outcome.callId] = { tool: outcome.tool, zipPath, outputDir };
  }
}

const MAX_LISTED_FINDINGS = 25;
const MAX_LISTED_EXPORTS = 10;
const PASSING_STATUSES = new Set(["pass", "passed", "satisfied", "compliant", "ok"]);

function countBy<T>(items: readonly T[], key: (item: T) => string): string {
  const counts = new Map<string, number>();
  for (const item of items) counts.set(key(item), (counts.get(key(item)) ?? 0) + 1);
  return [...counts.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, count]) => `${name} ${count}`)
    .join(", ");
}

/**
 * A short, bounded summary for the system prompt. It changes only when a tool
 * records something new, so it costs one re-sent section per tool round.
 */
export function renderAssessmentSummary(state: Readonly<AssessmentState> | undefined): string | undefined {
  if (!state) return undefined;
  const calls = Object.values(state.calls);
  if (calls.length === 0) return undefined;

  const lines = [`Recorded tool calls: ${calls.length} (${countBy(calls, (call) => call.status)}).`];

  const findings = Object.entries(state.findings);
  if (findings.length > 0) {
    lines.push(`Findings: ${findings.length} (${countBy(findings, ([, finding]) => finding.status)}).`);
    const open = findings.filter(([, finding]) => !PASSING_STATUSES.has(finding.status.toLowerCase()));
    for (const [key, finding] of open.slice(0, MAX_LISTED_FINDINGS)) {
      const severity = finding.severity ? ` ${finding.severity}` : "";
      const title = finding.title ? ` ${finding.title}` : "";
      lines.push(`- ${key}: ${finding.status}${severity}${title}`);
    }
    if (open.length > MAX_LISTED_FINDINGS) {
      lines.push(`- ... ${open.length - MAX_LISTED_FINDINGS} more not shown`);
    }
  }

  // Key order is not recording order: integer-like call ids enumerate first, and a rerun keeps its key's place.
  const recordedAt = (callId: string) => state.calls[callId].recordedAt;
  const artifacts = Object.entries(state.artifacts)
    .sort(([left], [right]) => recordedAt(left).localeCompare(recordedAt(right)))
    .map(([, artifact]) => artifact);
  if (artifacts.length > 0) {
    lines.push(`Exports: ${artifacts.length} (${countBy(artifacts, (artifact) => artifact.tool)}).`);
    for (const artifact of artifacts.slice(-MAX_LISTED_EXPORTS)) {
      lines.push(`- ${artifact.tool}: ${artifact.zipPath ?? artifact.outputDir}`);
    }
    if (artifacts.length > MAX_LISTED_EXPORTS) {
      lines.push(`- ... ${artifacts.length - MAX_LISTED_EXPORTS} earlier exports not shown`);
    }
  }

  return lines.join("\n");
}
