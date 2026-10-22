/**
 * One `grclanker durable` command: open the session under its lock, run or
 * resume the root conversation until its request settles, and report the
 * answer, the tool calls of that request, and the assessment document.
 */
import { mkdirSync } from "node:fs";
import type { Context } from "@earendil-works/chord";
import { BACKGROUND_CONTEXT, withAbortSignal } from "@earendil-works/chord/context";
import type { Models, ModelThinkingLevel } from "@earendil-works/pi-ai";
import {
  AssistantEntry,
  createRegistry,
  Harness,
  ToolResultEntry,
  watchEvents,
  type AgentChange,
  type AgentEvent,
  type AgentEventStream,
  type Conversation,
  type ConversationId,
  type Cursor,
  type EntryId,
  type EntryRecord,
  type HarnessSettings,
  type ModelRef,
  type SettledSubmissionRecord,
  type Submission,
  type ToolRegistration,
} from "@earendil-works/pi-durable";
import { Assessment, emptyAssessmentState, type AssessmentState } from "./document.js";
import { acquireSessionLock } from "./lock.js";
import { assertModelAvailable, formatModelRef } from "./models.js";
import { createGrclankerDurableExtension } from "./prompts.js";
import { durableReplayPolicy, type DurableReplayPolicy } from "./replay.js";
import type { DurableSessionPaths } from "./session.js";
import { openDurableSessionStorage } from "./storage.js";

export const INTERRUPTED_DIAGNOSTIC = "interrupted";

const ENTRY_PAGE_SIZE = 200;
const ACTIVITY_PREVIEW_LENGTH = 200;

interface DurableRequestBase {
  session: DurableSessionPaths;
  model: ModelRef;
  thinkingLevel?: ModelThinkingLevel;
}

/** `run` starts or continues the session with a message; `resume` finishes what an earlier process left unsettled. */
export type DurableRunRequest =
  | (DurableRequestBase & { command: "run"; message: string; requestId: string })
  | (DurableRequestBase & { command: "resume" });

export type DurableCommand = DurableRunRequest["command"];

export type DurableOutcome = "completed" | "unanswered" | "interrupted" | "nothing_to_resume";

export type DurableToolCallStatus = "ok" | "error" | "interrupted";

export interface DurableToolCallReport {
  callId: string;
  tool: string;
  replay: DurableReplayPolicy;
  status: DurableToolCallStatus;
}

export interface DurableRunReport {
  experimental: true;
  command: DurableCommand;
  session: string;
  sessionDir: string;
  conversationId: number;
  model: string;
  requestId?: string;
  submissionId?: number;
  outcome: DurableOutcome;
  answer?: string;
  /** Why the request settled without an answer. */
  reason?: string;
  /** The tool results recorded for this request, in transcript order. */
  tools: DurableToolCallReport[];
  assessment: AssessmentState;
}

export interface DurableRunDeps {
  loadModels: () => Promise<Models>;
  /** Defaults to every grclanker domain tool. */
  tools?: () => readonly ToolRegistration[];
  settings?: HarnessSettings;
  /** One line per notable event: the session, tool starts and results, retries, failures. */
  onActivity?: (line: string) => void;
  /** Failures Pi Durable reports without failing the command, such as a throwing listener. */
  onReport?: (error: unknown) => void;
  /** Aborting stops waiting and closes the session with its work pending, for a later `resume`. */
  signal?: AbortSignal;
}

function preview(text: string): string {
  const line = text.replace(/\s+/g, " ").trim();
  return line.length > ACTIVITY_PREVIEW_LENGTH ? `${line.slice(0, ACTIVITY_PREVIEW_LENGTH - 3)}...` : line;
}

function toolCallStatus(entry: EntryRecord | undefined): DurableToolCallStatus | undefined {
  if (!ToolResultEntry.is(entry)) return undefined;
  if (entry.data.diagnostics.some((diagnostic) => diagnostic.code === INTERRUPTED_DIAGNOSTIC)) return "interrupted";
  const message = entry.model?.[0];
  return message?.role === "toolResult" && message.isError ? "error" : "ok";
}

function describeToolEnd(toolName: string, entry: EntryRecord | undefined): string {
  const status = toolCallStatus(entry);
  switch (status) {
    case undefined:
      return `<- ${toolName} ended without a result`;
    case "ok":
    case "error":
      return `<- ${toolName} ${status}`;
    case "interrupted":
      return durableReplayPolicy(toolName) === "safe"
        ? `<- ${toolName} interrupted`
        : `<- ${toolName} interrupted; not rerun because it can write`;
    default: {
      const exhaustive: never = status;
      throw new Error(`Unhandled tool call status: ${String(exhaustive)}`);
    }
  }
}

/** A one-line rendering of an agent event for stderr, or undefined for events not worth a line. */
export function formatDurableActivity(event: AgentEvent): string | undefined {
  switch (event.type) {
    case "snapshot": {
      const unfinished = event.tools.filter((slot) => slot.status !== "done");
      if (unfinished.length === 0) return undefined;
      const finished = event.tools.length - unfinished.length;
      return `resuming a tool round left by an earlier process: ${finished} finished and kept, unfinished: ${unfinished.map((slot) => slot.name).join(", ")}`;
    }
    case "tool_execution_start":
      return event.parentToolCallId === undefined ? `-> ${event.toolName}` : undefined;
    case "tool_execution_end":
      return event.parentToolCallId === undefined ? describeToolEnd(event.toolName, event.entry) : undefined;
    case "auto_retry_start":
      return `model request failed, retry ${event.attempt}: ${preview(event.errorMessage)}`;
    case "task_failed":
      return `task ${event.kind} failed: ${preview(event.message)}`;
    case "compaction_start":
      return `compacting the conversation (${event.reason})`;
    case "run_start":
    case "run_end":
    case "turn_start":
    case "turn_end":
    case "message_start":
    case "message_update":
    case "message_end":
    case "tool_execution_update":
    case "inbox_update":
    case "submission":
    case "auto_retry_end":
    case "deferred_poll":
    case "entry_appended":
    case "agent_changed":
    case "usage_changed":
    case "compaction_end":
      return undefined;
    default: {
      const exhaustive: never = event;
      throw new Error(`Unhandled agent event: ${JSON.stringify(exhaustive)}`);
    }
  }
}

async function watchActivity(
  harness: Harness,
  conversationId: ConversationId,
  onActivity: (line: string) => void,
): Promise<AgentEventStream> {
  const stream = await watchEvents(harness, conversationId, BACKGROUND_CONTEXT);
  const initial = formatDurableActivity(stream.snapshot);
  if (initial !== undefined) onActivity(initial);
  stream.start(async (events) => {
    for (const event of events) {
      const line = formatDurableActivity(event);
      if (line !== undefined) onActivity(line);
    }
  });
  return stream;
}

async function readAssessment(harness: Harness, conversationId: ConversationId): Promise<AssessmentState> {
  const snapshot = await harness.snapshot(Assessment, conversationId, BACKGROUND_CONTEXT);
  return snapshot ? structuredClone(snapshot) : emptyAssessmentState();
}

/** The entries of one request, from its input to its answer (or the end), whatever compaction did since. */
async function requestEntries(
  conversation: Conversation,
  from: EntryId,
  to: EntryId | undefined,
  context: Context,
): Promise<EntryRecord[]> {
  const query = { minEntryId: from, ...(to === undefined ? {} : { maxEntryId: to }), order: "ascending" as const };
  const entries: EntryRecord[] = [];
  let cursor: Cursor | undefined;
  do {
    const page = await conversation.entries(query, ENTRY_PAGE_SIZE, cursor, context);
    entries.push(...page.items);
    cursor = page.next;
  } while (cursor !== undefined);
  return entries;
}

function toolCallsOf(entries: readonly EntryRecord[]): DurableToolCallReport[] {
  return entries.flatMap((entry) => {
    const status = toolCallStatus(entry);
    const message = entry.model?.[0];
    if (status === undefined || message?.role !== "toolResult") return [];
    return [{ callId: message.toolCallId, tool: message.toolName, replay: durableReplayPolicy(message.toolName), status }];
  });
}

function answerText(entry: EntryRecord | undefined): string | undefined {
  if (!AssistantEntry.is(entry)) return undefined;
  const message = entry.model?.[0];
  if (message?.role !== "assistant") return undefined;
  return message.content.flatMap((block) => (block.type === "text" ? [block.text] : [])).join("");
}

function describeUnanswered(record: SettledSubmissionRecord): string {
  if (record.status !== "unanswered") return "";
  const detail = record.detail;
  const message =
    typeof detail === "string"
      ? detail
      : detail && typeof detail === "object" && !Array.isArray(detail) && typeof detail.message === "string"
        ? detail.message
        : undefined;
  return message ? `${record.reason}: ${message}` : record.reason;
}

async function pendingSubmissions(
  harness: Harness,
  conversationId: ConversationId,
  context: Context,
): Promise<Submission[]> {
  const inspection = await harness.inspect(context);
  const handles = await Promise.all(
    inspection.submissions
      .filter((record) => record.conversationId === conversationId && record.type === "input")
      .map((record) => harness.submission(record.id, context)),
  );
  return handles.filter((handle): handle is Submission => handle !== undefined);
}

type ReportBase = Pick<
  DurableRunReport,
  "experimental" | "command" | "session" | "sessionDir" | "conversationId" | "model" | "requestId"
>;

async function settledReport(
  base: ReportBase,
  conversation: Conversation,
  record: SettledSubmissionRecord,
  assessment: AssessmentState,
  context: Context,
): Promise<DurableRunReport> {
  const answerId = record.status === "done" ? record.answer : undefined;
  const entries = record.entry === undefined ? [] : await requestEntries(conversation, record.entry, answerId, context);
  const report: DurableRunReport = {
    ...base,
    ...(record.requestId === undefined ? {} : { requestId: record.requestId }),
    submissionId: record.id,
    outcome: record.status === "done" ? "completed" : "unanswered",
    tools: toolCallsOf(entries),
    assessment,
  };
  if (record.status === "done") {
    report.answer = answerText(entries.find((entry) => entry.id === answerId)) ?? "";
  } else {
    report.reason = describeUnanswered(record);
  }
  return report;
}

async function driveConversation(
  harness: Harness,
  request: DurableRunRequest,
  deps: DurableRunDeps,
): Promise<DurableRunReport> {
  const agent: AgentChange = { model: request.model, thinkingLevel: request.thinkingLevel ?? null };
  const conversation = await harness.root(BACKGROUND_CONTEXT, { agent });
  // `root()` applies `agent` only when it creates the conversation; a continued session takes the current choice here.
  await conversation.configure(agent, BACKGROUND_CONTEXT);

  const base: ReportBase = {
    experimental: true,
    command: request.command,
    session: request.session.id,
    sessionDir: request.session.dir,
    conversationId: conversation.id,
    model: formatModelRef(request.model),
    ...(request.command === "run" ? { requestId: request.requestId } : {}),
  };
  const context = deps.signal ? withAbortSignal(deps.signal, BACKGROUND_CONTEXT) : BACKGROUND_CONTEXT;
  const activity = deps.onActivity ? await watchActivity(harness, conversation.id, deps.onActivity) : undefined;

  try {
    const submissions =
      request.command === "run"
        ? [await conversation.submit({ type: "input", content: request.message, requestId: request.requestId }, context)]
        : await pendingSubmissions(harness, conversation.id, context);
    harness.resume();

    let last: SettledSubmissionRecord | undefined;
    for (const submission of submissions) last = await submission.wait(context);
    await conversation.waitForIdle(context);

    const assessment = await readAssessment(harness, conversation.id);
    if (last === undefined) return { ...base, outcome: "nothing_to_resume", tools: [], assessment };
    return await settledReport(base, conversation, last, assessment, context);
  } catch (error) {
    if (!deps.signal?.aborted) throw error;
    return { ...base, outcome: "interrupted", tools: [], assessment: await readAssessment(harness, conversation.id) };
  } finally {
    await activity?.stop();
  }
}

/** Run one durable command. Configuration problems throw before the session is touched. */
export async function runDurable(request: DurableRunRequest, deps: DurableRunDeps): Promise<DurableRunReport> {
  const models = await deps.loadModels();
  assertModelAvailable(models, request.model);

  mkdirSync(request.session.dir, { recursive: true });
  const lock = acquireSessionLock(request.session.lock);
  try {
    deps.onActivity?.(`session ${request.session.id} (${request.session.dir})`);
    if (request.command === "run") deps.onActivity?.(`request ${request.requestId}`);

    const registry = createRegistry();
    registry.install(createGrclankerDurableExtension(deps.tools?.()));
    const harness = await Harness.open(
      await openDurableSessionStorage(request.session),
      {
        models,
        registry,
        ...(deps.settings ? { settings: deps.settings } : {}),
        ...(deps.onReport ? { onReport: deps.onReport } : {}),
      },
      BACKGROUND_CONTEXT,
    );
    try {
      return await driveConversation(harness, request, deps);
    } finally {
      await harness.close(BACKGROUND_CONTEXT);
    }
  } finally {
    lock.release();
  }
}
