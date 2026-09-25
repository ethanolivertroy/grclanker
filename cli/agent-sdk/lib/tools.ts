import type { JsonObject, JsonSchemaObject } from "@cursor/july";
import type { ToolContext, ToolExecuteResult } from "@cursor/july/tools";
import { validateToolArguments, type Tool, type ToolCall } from "@earendil-works/pi-ai";
import { runWithoutPersistentCaches } from "../../extensions/grc-tools/shared.js";
import { classifyGrcToolEffect, type GrcToolEffect, isGrcWriteTool } from "./effects.js";
import { getRegisteredGrcTool, type RegisteredGrcTool } from "./registry.js";
import { errorEnvelope, toSdkToolResult } from "./results.js";
import { toJsonSchema } from "./schema.js";

export interface GrcToolExecutionContext {
  toolCallId?: string;
  session?: Pick<ToolContext["session"], "dryRun">;
}

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
  /** Keep dry-run catalog mirrors out of the persistent state directory. */
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

export function grclankerToolConfig(name: string): GrclankerSdkToolConfig {
  return buildSdkToolConfig(getRegisteredGrcTool(name));
}
