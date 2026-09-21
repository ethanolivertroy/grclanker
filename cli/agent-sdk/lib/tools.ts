import type { JsonObject, JsonSchemaObject } from "@cursor/july";
import type { ToolContext, ToolExecuteResult } from "@cursor/july/tools";
import { validateToolArguments, type Tool, type ToolCall } from "@earendil-works/pi-ai";
import { classifyGrcToolEffect, type GrcToolEffect } from "./effects.js";
import { getRegisteredGrcTool, type RegisteredGrcTool } from "./registry.js";
import { errorEnvelope, toSdkToolResult } from "./results.js";
import { toJsonSchema } from "./schema.js";

/** Server tool config accepted by `defineTool` from `@cursor/july/tools`. */
export interface GrclankerSdkToolConfig {
  description: string;
  inputSchema: JsonSchemaObject;
  effect: GrcToolEffect;
  execute: (input: JsonObject, ctx: Pick<ToolContext, "toolCallId">) => Promise<ToolExecuteResult>;
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
  toolCallId: string = `grclanker_${tool.name}`,
): Promise<ToolExecuteResult> {
  let args: unknown;
  try {
    args = prepareGrcToolArguments(tool, toolCallId, input);
  } catch (error) {
    return errorEnvelope(describeError(error));
  }

  try {
    return toSdkToolResult(await tool.execute(toolCallId, args));
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
    execute: (input, ctx) => executeGrcTool(tool, input, ctx.toolCallId),
  };
}

/** Look up a grclanker domain tool by name and adapt it for `defineTool`. */
export function grclankerToolConfig(name: string): GrclankerSdkToolConfig {
  return buildSdkToolConfig(getRegisteredGrcTool(name));
}
