import type { JsonObject, JsonSchemaObject } from "@cursor/july";
import type { ToolContext, ToolExecuteResult } from "@cursor/july/tools";
import { validateToolArguments, type Tool, type ToolCall } from "@earendil-works/pi-ai";
import { runWithoutPersistentCaches } from "../../extensions/grc-tools/shared.js";
import { classifyGrcToolEffect, type GrcToolEffect, isGrcWriteTool } from "./effects.js";
import { getRegisteredGrcTool, type RegisteredGrcTool } from "./registry.js";
import { errorEnvelope, toSdkToolResult } from "./results.js";
import { toJsonSchema } from "./schema.js";

/**
 * The slice of the Agent SDK `ToolContext` the adapter reads: the call id
 * and the session's dry-run flag (`SessionInfo.dryRun`, true when the host
 * answers write-classified calls instead of running them).
 */
export interface GrcToolExecutionContext {
  toolCallId?: string;
  session?: Pick<ToolContext["session"], "dryRun">;
}

/** Server tool config accepted by `defineTool` from `@cursor/july/tools`. */
export interface GrclankerSdkToolConfig {
  description: string;
  inputSchema: JsonSchemaObject;
  effect: GrcToolEffect;
  /**
   * Writers (exports, generators, evidence collectors, OSCAL workspace
   * commands) park model-initiated calls until a person approves them.
   * Deterministic `agent-sdk call` runs bypass the gate.
   */
  needsApproval: boolean;
  execute: (input: JsonObject, ctx: GrcToolExecutionContext) => Promise<ToolExecuteResult>;
}

export interface ExecuteGrcToolOptions {
  toolCallId?: string;
  /**
   * Run the tool with on-disk caches disabled. Read-classified tools such as
   * the FedRAMP lookups mirror public catalogs to the grclanker state
   * directory; in a dry-run session that mirror must stay in memory so the
   * session changes nothing on the user's disk.
   */
  dryRun?: boolean;
}

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Mirror the Pi runtime: run the tool's `prepareArguments` shim, then coerce
 * and validate against the TypeBox schema with Pi's own validator.
 */
export function prepareGrcToolArguments(tool: RegisteredGrcTool, toolCallId: string, input: unknown): unknown {
  const prepared = tool.prepareArguments ? tool.prepareArguments(input) : input;
  const piTool = { name: tool.name, description: tool.description, parameters: tool.parameters } as unknown as Tool;
  const toolCall: ToolCall = {
    type: "toolCall",
    id: toolCallId,
    name: tool.name,
    arguments: prepared as Record<string, unknown>,
  };
  return validateToolArguments(piTool, toolCall) as unknown;
}

/** Execute a registered grc tool with Agent SDK input and return the SDK envelope. */
export async function executeGrcTool(
  tool: RegisteredGrcTool,
  input: JsonObject,
  options: ExecuteGrcToolOptions = {},
): Promise<ToolExecuteResult> {
  const toolCallId = options.toolCallId ?? `grclanker_${tool.name}`;
  let args: unknown;
  try {
    args = prepareGrcToolArguments(tool, toolCallId, input);
  } catch (error) {
    return errorEnvelope(describeError(error));
  }

  const run = () => tool.execute(toolCallId, args);
  try {
    const result = options.dryRun === true ? await runWithoutPersistentCaches(run) : await run();
    return toSdkToolResult(result);
  } catch (error) {
    return errorEnvelope(`${tool.name} failed: ${describeError(error)}`);
  }
}

/** Build the Agent SDK server tool config for one registered grc tool. */
export function buildSdkToolConfig(tool: RegisteredGrcTool): GrclankerSdkToolConfig {
  return {
    description: tool.description,
    inputSchema: toJsonSchema(tool.parameters),
    effect: classifyGrcToolEffect(tool.name),
    needsApproval: isGrcWriteTool(tool.name),
    execute: (input, ctx) =>
      executeGrcTool(tool, input, { toolCallId: ctx.toolCallId, dryRun: ctx.session?.dryRun === true }),
  };
}

/** Look up a grclanker domain tool by name and adapt it for `defineTool`. */
export function grclankerToolConfig(name: string): GrclankerSdkToolConfig {
  return buildSdkToolConfig(getRegisteredGrcTool(name));
}
