/**
 * Standalone runner for the grclanker Flue agent.
 *
 * Mirrors the `flue run` contract (one message in, the reply on stdout,
 * activity on stderr, persisted conversations keyed by `--id`) using Flue's
 * documented `start()` and `init()` APIs, so no `@flue/cli` install is needed.
 * All runtime entry points are injectable for tests.
 */
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { inspect } from "node:util";
import {
  init as flueInit,
  type Agent,
  type AgentInstanceHandle,
  type ConversationStreamChunk,
  type InitOptions,
} from "@flue/runtime";
import { sqlite as flueSqlite, start as flueStart, type Flue, type StartOptions } from "@flue/runtime/node";
import { getGrclankerHome } from "../config/paths.js";
import { Grclanker, prepareGrclankerAgent } from "./agent.js";
import { flueConversationStreamPath, readPriorSensitiveValues } from "./history.js";
import { collectSensitiveValues, redactSensitiveArguments, scrubSensitiveValues, withholdEchoedArguments } from "./redact.js";
import { collectGrclankerDomainTools } from "./tools.js";

export const FLUE_AGENT_NAME = "grclanker";
export const FLUE_MEMORY_DATABASE = ":memory:";

export type FlueRunOutcomeKind = "completed" | "failed" | "aborted";

export interface FlueRunRequest {
  message: string;
  id?: string;
  db?: string;
}

export interface FlueRunOutcome {
  id: string;
  agent: string;
  submissionId?: string;
  outcome: FlueRunOutcomeKind;
  message?: string;
  error?: string;
}

export interface FlueRunDeps {
  start: (options: StartOptions) => Promise<Flue>;
  init: (agent: Agent, options?: InitOptions) => AgentInstanceHandle;
  sqlite: (path?: string) => StartOptions["db"];
  agent: Agent;
  prepare: () => void;
  writeErr: (line: string) => void;
  /** Tool name to JSON Schema parameters, so activity lines can honor schema-marked sensitive fields. */
  toolParameterSchemas?: () => ReadonlyMap<string, unknown>;
}

export interface FlueActivityFormatterOptions {
  parameterSchemas?: ReadonlyMap<string, unknown>;
  /** Called with the sensitive values of each tool input, so a later reply can be scrubbed too. */
  onSensitiveValues?: (values: readonly string[]) => void;
}

interface AgentRunErrorLike extends Error {
  outcome: "failed" | "aborted";
  submissionId: string;
}

const ACTIVITY_PREVIEW_LENGTH = 160;

export function collectToolParameterSchemas(): ReadonlyMap<string, unknown> {
  return new Map(collectGrclankerDomainTools().map((tool) => [tool.name, tool.parameters]));
}

export function createDefaultFlueRunDeps(): FlueRunDeps {
  return {
    start: flueStart,
    init: flueInit,
    sqlite: flueSqlite,
    agent: Grclanker,
    prepare: prepareGrclankerAgent,
    writeErr: (line) => process.stderr.write(`${line}\n`),
    toolParameterSchemas: collectToolParameterSchemas,
  };
}

export function resolveFlueDatabasePath(requested: string | undefined, home = getGrclankerHome()): string {
  const trimmed = requested?.trim();
  if (trimmed === FLUE_MEMORY_DATABASE) return FLUE_MEMORY_DATABASE;
  return trimmed ? resolve(trimmed) : resolve(home, "flue", "conversations.db");
}

function truncate(text: string, limit = ACTIVITY_PREVIEW_LENGTH): string {
  const singleLine = text.replace(/\s+/g, " ").trim();
  return singleLine.length > limit ? `${singleLine.slice(0, limit - 3)}...` : singleLine;
}

/**
 * Compact one-line renderings of tool activity for stderr. Tool inputs and
 * repeated sensitive values are redacted before they are written.
 */
export function createFlueActivityFormatter(
  options: FlueActivityFormatterOptions = {},
): (chunk: ConversationStreamChunk) => string | undefined {
  const toolNames = new Map<string, string>();
  const sensitiveValues = new Map<string, string[]>();

  return (chunk) => {
    switch (chunk.type) {
      case "tool-input": {
        toolNames.set(chunk.toolCallId, chunk.toolName);
        const schema = options.parameterSchemas?.get(chunk.toolName);
        const input = chunk.input ?? {};
        const values = collectSensitiveValues(input, schema);
        sensitiveValues.set(chunk.toolCallId, values);
        options.onSensitiveValues?.(values);
        return `-> ${chunk.toolName} ${truncate(JSON.stringify(redactSensitiveArguments(input, schema)))}`;
      }
      case "tool-output": {
        sensitiveValues.delete(chunk.toolCallId);
        const duration = chunk.durationMs === undefined ? "" : ` (${chunk.durationMs}ms)`;
        return `<- ${toolNames.get(chunk.toolCallId) ?? chunk.toolCallId} ok${duration}`;
      }
      case "tool-output-error": {
        const values = sensitiveValues.get(chunk.toolCallId) ?? [];
        sensitiveValues.delete(chunk.toolCallId);
        const shown = scrubSensitiveValues(withholdEchoedArguments(chunk.errorText), values);
        return `<- ${toolNames.get(chunk.toolCallId) ?? chunk.toolCallId} error: ${truncate(shown)}`;
      }
      case "conversation-reset":
      case "message-appended":
      case "message-started":
      case "message-metadata":
      case "data-part":
      case "message-delta":
      case "message-completed":
      case "submission-settled":
        return undefined;
      default: {
        const exhaustive: never = chunk;
        throw new Error(`Unhandled conversation chunk: ${JSON.stringify(exhaustive)}`);
      }
    }
  };
}

function isAgentRunError(error: unknown): error is AgentRunErrorLike {
  return (
    error instanceof Error &&
    "outcome" in error &&
    (error.outcome === "failed" || error.outcome === "aborted") &&
    "submissionId" in error &&
    typeof error.submissionId === "string"
  );
}

function readStringField(value: unknown, key: string): string | undefined {
  if (!value || typeof value !== "object") return undefined;
  const field = (value as Record<string, unknown>)[key];
  return typeof field === "string" && field.trim().length > 0 ? field : undefined;
}

/** Flue settles failures with a serialized cause (`{ message, meta: { reason } }`), so prefer its reason. */
export function describeAgentRunError(error: Error): string {
  const cause: unknown = error.cause;
  const meta = cause && typeof cause === "object" ? (cause as Record<string, unknown>).meta : undefined;
  return readStringField(meta, "reason") ?? readStringField(cause, "message") ?? error.message;
}

export function exitCodeForOutcome(outcome: FlueRunOutcomeKind): number {
  switch (outcome) {
    case "completed":
      return 0;
    case "failed":
      return 1;
    case "aborted":
      return 130;
    default: {
      const exhaustive: never = outcome;
      throw new Error(`Unhandled outcome: ${String(exhaustive)}`);
    }
  }
}

/**
 * Boot the Flue runtime, deliver one message to the grclanker agent, await the
 * settled reply, and shut the runtime down. Configuration problems surface
 * before the runtime starts; model or tool failures come back as an outcome.
 */
export async function runGrclankerFlueAgent(
  request: FlueRunRequest,
  deps: FlueRunDeps = createDefaultFlueRunDeps(),
): Promise<FlueRunOutcome> {
  deps.prepare();

  const dbPath = resolveFlueDatabasePath(request.db);
  if (dbPath !== FLUE_MEMORY_DATABASE) mkdirSync(dirname(dbPath), { recursive: true });

  const parameterSchemas = deps.toolParameterSchemas?.();
  // A resumed `--id` does not replay earlier tool-input events, so rebuild the
  // redaction list from the conversation file before this turn starts.
  const rememberedSensitiveValues: string[] = request.id
    ? readPriorSensitiveValues({
        dbPath,
        streamPath: flueConversationStreamPath(FLUE_AGENT_NAME, request.id),
        schemas: parameterSchemas,
      })
    : [];

  const flue = await deps.start({ agents: [deps.agent], db: deps.sqlite(dbPath) });
  try {
    const handle = deps.init(deps.agent, request.id ? { id: request.id } : undefined);
    deps.writeErr(`conversation: ${handle.id}`);
    const receipt = await handle.dispatch(request.message);
    const formatActivity = createFlueActivityFormatter({
      parameterSchemas,
      onSensitiveValues: (values) => {
        rememberedSensitiveValues.push(...values);
      },
    });

    try {
      const reply = await handle.read(receipt, {
        onEvent: (chunk) => {
          const line = formatActivity(chunk);
          if (line) deps.writeErr(line);
        },
      });
      return {
        id: handle.id,
        agent: FLUE_AGENT_NAME,
        submissionId: reply.submissionId,
        outcome: "completed",
        message: scrubSensitiveValues(reply.text, rememberedSensitiveValues),
      };
    } catch (error) {
      if (isAgentRunError(error)) {
        return {
          id: handle.id,
          agent: FLUE_AGENT_NAME,
          submissionId: error.submissionId,
          outcome: error.outcome,
          error: scrubSensitiveValues(describeAgentRunError(error), rememberedSensitiveValues),
        };
      }
      // Formatted by the runtime catch below, which also covers dispatch.
      throw error;
    }
  } catch (error) {
    // Both CLI sinks use console.error, which prints the cached stack, custom
    // fields, and cause, and inspects a non-Error. Scrub that rendering.
    throw scrubSensitiveValues(inspect(error), rememberedSensitiveValues);
  } finally {
    await flue.stop();
  }
}
