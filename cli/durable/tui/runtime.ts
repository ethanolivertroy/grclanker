/**
 * The durable terminal app's runtime: one grclanker durable session opened
 * under its lock, the plain view the terminal app renders, and the commands
 * it may send. Recovery is the Harness's: an interrupted turn continues once
 * the session opens, with the same replay policy as `grclanker durable resume`.
 *
 * Adapted from Pi's experimental durable coding agent
 * (`packages/coding-agent/src/experimental/durable/runtime.ts` at Pi commit
 * e6b9a6af5, its last version before Pi removed it ahead of v1.3.0).
 * Copyright (c) 2025 Mario Zechner. MIT License; see NOTICE. grclanker opens
 * its own session directories, installs its domain tools in place of Pi's
 * coding tools, has no subagents, and adds the assessment document and
 * recovery notices to the view.
 */
import { mkdirSync } from "node:fs";
import type { AttachedReplicatedState } from "@earendil-works/chord";
import { BACKGROUND_CONTEXT } from "@earendil-works/chord/context";
import { clampThinkingLevel, getSupportedThinkingLevels, type ModelThinkingLevel } from "@earendil-works/pi-ai";
import {
  createRegistry,
  Harness,
  ToolResultEntry,
  watchEvents,
  type AgentChange,
  type AgentEvent,
  type AgentState,
  type ConversationView,
  type EntryRecord,
  type ModelRef,
  type Submission,
  type TaskGraph,
} from "@earendil-works/pi-durable";
import { openNodeSqliteStorage } from "@earendil-works/pi-durable/storage/sqlite/node";
import { Assessment, ASSESSMENT_DOC_KIND, emptyAssessmentState, type AssessmentState } from "../document.js";
import { acquireSessionLock } from "../lock.js";
import { assertModelAvailable } from "../models.js";
import { createGrclankerDurableExtension } from "../prompts.js";
import { durableReplayPolicy } from "../replay.js";
import { INTERRUPTED_DIAGNOSTIC, type DurableRunDeps } from "../run.js";
import type { DurableSessionPaths } from "../session.js";

const context = BACKGROUND_CONTEXT;

export interface ModelSummary extends ModelRef {
  readonly name: string;
  readonly contextWindow: number;
}

export interface Notice {
  readonly id: number;
  readonly level: "info" | "warning" | "error";
  readonly message: string;
}

/** Everything the terminal app renders. Plain values; no Harness objects cross this boundary. */
export interface DurableView {
  readonly session: { readonly id: string; readonly directory: string };
  readonly conversation: ConversationView;
  readonly models: readonly ModelSummary[];
  readonly notices: readonly Notice[];
  /** What the grclanker tools recorded in this conversation. */
  readonly assessment: AssessmentState;
  /** The live task graph while the task panel is open. */
  readonly tasks?: TaskGraph;
}

export interface DurableViewSource {
  current(): DurableView;
  subscribe(listener: () => void): () => void;
}

/** What the terminal app may ask for. */
export interface DurableController {
  /** Prompt when idle; otherwise steer or queue a follow-up. */
  submit(text: string, whenBusy: "steer" | "followUp"): Promise<void>;
  compact(instructions: string | undefined): Promise<void>;
  abort(): Promise<void>;
  cycleThinking(): Promise<void>;
  setModel(model: ModelRef): Promise<void>;
  toggleTasks(): Promise<void>;
}

export interface DurableTuiRequest {
  session: DurableSessionPaths;
  model: ModelRef;
  thinkingLevel?: ModelThinkingLevel;
}

export type DurableTuiDeps = Pick<DurableRunDeps, "loadModels" | "tools" | "settings">;

export interface OpenDurableTuiResult {
  readonly view: DurableViewSource;
  readonly controller: DurableController;
  /** Close the session and release its lock. Work in flight stays in the session and continues when it is opened again. */
  close(): Promise<void>;
}

/** The agent document of a view; absent while the conversation has none. */
export function agentOf(view: ConversationView): AgentState {
  return (view.docs["pi.agent"] ?? {}) as AgentState;
}

function isInterrupted(entry: EntryRecord | undefined): boolean {
  return (
    ToolResultEntry.is(entry) && entry.data.diagnostics.some((diagnostic) => diagnostic.code === INTERRUPTED_DIAGNOSTIC)
  );
}

/** A notice for what the transcript does not make plain: work left by an earlier process, interrupted calls, failed tasks. */
function noticeFor(event: AgentEvent): Omit<Notice, "id"> | undefined {
  if (event.type === "snapshot") {
    const unfinished = event.tools.filter((slot) => slot.status !== "done");
    if (unfinished.length === 0) return undefined;
    const finished = event.tools.length - unfinished.length;
    const names = unfinished.map((slot) => slot.name).join(", ");
    return {
      level: "info",
      message: `Resuming a tool round left by an earlier process: ${finished} finished and kept, unfinished: ${names}.`,
    };
  }
  if (event.type === "tool_execution_end" && event.parentToolCallId === undefined && isInterrupted(event.entry)) {
    return {
      level: "warning",
      message:
        durableReplayPolicy(event.toolName) === "safe"
          ? `${event.toolName} was interrupted.`
          : `${event.toolName} was interrupted and not rerun because it can write. Check what it wrote before running it again.`,
    };
  }
  if (event.type === "task_failed") return { level: "error", message: `Task ${event.kind} failed: ${event.message}` };
  return undefined;
}

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Open a session for the terminal app. Configuration problems and a held lock throw before anything is shown. */
export async function openDurableTui(request: DurableTuiRequest, deps: DurableTuiDeps): Promise<OpenDurableTuiResult> {
  const models = await deps.loadModels();
  assertModelAvailable(models, request.model);
  const available = await models.getAvailable();

  mkdirSync(request.session.dir, { recursive: true });
  const lock = acquireSessionLock(request.session.lock);
  let harness: Harness | undefined;
  try {
    const registry = createRegistry();
    registry.install(createGrclankerDurableExtension(deps.tools?.()));
    const pendingReports: unknown[] = [];
    let report: (error: unknown) => void = (error) => pendingReports.push(error);
    harness = await Harness.open(
      await openNodeSqliteStorage(request.session.database),
      {
        models,
        registry,
        ...(deps.settings ? { settings: deps.settings } : {}),
        onReport: (error) => report(error),
      },
      context,
    );
    const opened = harness;
    const agent: AgentChange = { model: request.model, thinkingLevel: request.thinkingLevel ?? null };
    const root = await opened.root(context, { agent });
    // `root()` applies `agent` only when it creates the conversation; a continued session takes the current choice here.
    await root.configure(agent, context);
    const conversation: AttachedReplicatedState<ConversationView> = await root.viewState(context);
    const assessment = await opened.snapshot(Assessment, root.id, context);

    let state: DurableView = {
      session: { id: request.session.id, directory: request.session.dir },
      conversation: conversation.value,
      models: available.map((model) => ({
        provider: model.provider,
        modelId: model.id,
        name: model.name,
        contextWindow: model.contextWindow,
      })),
      notices: [],
      assessment: assessment ?? emptyAssessmentState(),
    };
    const listeners = new Set<() => void>();
    let notifying = false;
    // Commit listeners, event batches, and Chord frames call this on the Session line; rendering runs afterwards, once per burst.
    const update = (patch: Partial<DurableView>): void => {
      state = { ...state, ...patch };
      if (notifying) return;
      notifying = true;
      setImmediate(() => {
        notifying = false;
        for (const listener of listeners) listener();
      });
    };
    let nextNotice = 1;
    const notice = (level: Notice["level"], message: string): void => {
      update({ notices: [...state.notices, { id: nextNotice++, level, message }].slice(-20) });
    };
    const fail = (error: unknown): void => notice("error", describeError(error));
    report = (error) => notice("warning", describeError(error));
    for (const error of pendingReports) report(error);

    const unsubscribe = conversation.subscribe((value) => update({ conversation: value }));
    // A commit listener only records; it calls no Session API.
    const unsubscribeCommits = opened.subscribeCommits((publication) => {
      for (const change of publication.changes) {
        if (
          change.type === "document" &&
          change.record.kind === ASSESSMENT_DOC_KIND &&
          change.conversationId === root.id &&
          change.value !== null
        ) {
          update({ assessment: change.value as AssessmentState });
        }
      }
    });
    const events = await watchEvents(opened, root.id, context);
    const resumed = noticeFor(events.snapshot);
    if (resumed !== undefined) notice(resumed.level, resumed.message);
    events.start(async (batch) => {
      for (const event of batch) {
        const next = noticeFor(event);
        if (next !== undefined) notice(next.level, next.message);
      }
    });

    let tasks: AttachedReplicatedState<TaskGraph> | undefined;
    let unsubscribeTasks = (): void => {};
    const closeTasks = (): void => {
      unsubscribeTasks();
      tasks?.dispose();
      tasks = undefined;
    };

    let queue = Promise.resolve();
    // One at a time, so toggles and key presses apply in order.
    const command = (operation: () => Promise<void>): Promise<void> => {
      queue = queue.then(operation).catch(fail);
      return queue;
    };
    const watchAnswer = (submission: Submission): void => {
      void submission.wait(context).then((settled) => {
        if (settled.status === "unanswered" && settled.reason !== "aborted") {
          notice(
            "error",
            `No answer: ${settled.reason}${settled.detail === undefined ? "" : ` ${JSON.stringify(settled.detail)}`}`,
          );
        }
      }, fail);
    };
    const agentModel = () => {
      const ref = agentOf(state.conversation).model;
      const model = ref === undefined ? undefined : models.getModel(ref.provider, ref.modelId);
      if (model === undefined) throw new Error(ref === undefined ? "No model selected" : "Current model is unavailable");
      return model;
    };
    const controller: DurableController = {
      submit: (text, whenBusy) =>
        command(async () => watchAnswer(await root.submit({ type: "input", content: text, whenBusy }, context))),
      compact: (instructions) =>
        command(async () => {
          const id = await root.compact(instructions, context);
          // Report the outcome once it is known; the status line shows the compaction meanwhile.
          void opened.waitForTask(id, context).then(async (receipt) => {
            const outcome = receipt.state.outcome;
            if (outcome.status === "completed") {
              const { entryId, submissionId } = outcome.result;
              // A summary written while busy is a submission: placed now, queued, or dropped as stale.
              const status =
                submissionId === undefined
                  ? undefined
                  : (await (await opened.submission(submissionId, context))?.status(context))?.status;
              notice(
                "info",
                entryId !== undefined || status === "done"
                  ? "Compacted."
                  : status === "queued"
                    ? "Compaction summary queued; it is placed at the next turn boundary."
                    : status === "unanswered"
                      ? "Compaction summary dropped: the context changed under it."
                      : "Nothing to compact: the context fits in the recent window that is kept verbatim.",
              );
            } else if (outcome.status === "aborted") notice("info", "Compaction aborted.");
            else notice("error", `Compaction ${outcome.status}: ${outcome.error?.message ?? outcome.reason ?? ""}`);
          }, fail);
        }),
      // Not queued: it waits until the conversation is idle.
      abort: () => root.abort(context).catch(fail),
      cycleThinking: () =>
        command(async () => {
          const model = agentModel();
          if (!model.reasoning) throw new Error("Current model does not support thinking");
          const levels = getSupportedThinkingLevels(model);
          const level = agentOf(state.conversation).thinkingLevel ?? "off";
          const next = levels[(levels.indexOf(level) + 1) % levels.length] ?? "off";
          await root.configure({ thinkingLevel: next }, context);
        }),
      setModel: (ref) =>
        command(async () => {
          const model = models.getModel(ref.provider, ref.modelId);
          if (model === undefined) throw new Error(`Unknown model: ${ref.provider}/${ref.modelId}`);
          const thinking: ModelThinkingLevel = agentOf(state.conversation).thinkingLevel ?? "off";
          await root.configure({ model: ref, thinkingLevel: clampThinkingLevel(model, thinking) }, context);
        }),
      toggleTasks: () =>
        command(async () => {
          if (tasks !== undefined) {
            closeTasks();
            update({ tasks: undefined });
            return;
          }
          const graph = await opened.taskGraph(context);
          tasks = graph;
          unsubscribeTasks = graph.subscribe((value) => update({ tasks: value }));
        }),
    };

    // The task panel starts open; /tasks hides it.
    await controller.toggleTasks();
    // Recovered work from an interrupted turn continues now.
    opened.resume();

    let closing: Promise<void> | undefined;
    return {
      view: {
        current: () => state,
        subscribe: (listener) => {
          listeners.add(listener);
          return () => listeners.delete(listener);
        },
      },
      controller,
      close() {
        closing ??= (async () => {
          unsubscribe();
          unsubscribeCommits();
          conversation.dispose();
          closeTasks();
          try {
            await events.stop();
            // Close writes no outcome: a running turn continues when the session is opened again.
            await opened.close(context);
          } finally {
            lock.release();
          }
        })();
        return closing;
      },
    };
  } catch (error) {
    await harness?.close(context).catch(() => {});
    lock.release();
    throw error;
  }
}
