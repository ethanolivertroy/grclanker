import type { JsonObject, JsonSchemaObject } from "@grok/agent-sdk";
import type { ToolContext, ToolExecuteResult } from "@grok/agent-sdk/tools";
import { classifyGrcToolEffect, type GrcToolEffect, isGrcWriteTool } from "../../../core/effects.js";
import { getRegisteredGrcTool, type RegisteredGrcTool } from "../../../core/registry.js";
import { executeGrcTool } from "../../../core/tools.js";
import { toJsonSchema } from "../../../core/schema.js";

export interface GrcToolExecutionContext {
  toolCallId?: string;
  session?: Pick<ToolContext["session"], "dryRun">;
}

export interface GrclankerSdkToolConfig {
  description: string;
  inputSchema: JsonSchemaObject;
  effect: GrcToolEffect;
  /** Model-initiated writes use the Cursor harness approval gate. */
  needsApproval: boolean;
  execute: (input: JsonObject, ctx: GrcToolExecutionContext) => Promise<ToolExecuteResult>;
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
