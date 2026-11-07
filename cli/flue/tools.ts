/**
 * Bridge grclanker's shared GRC tools into Flue `ToolDefinition`s.
 *
 * Domain tools stay shared; this module collects them directly from core
 * without initializing Pi's terminal extension, converts their TypeBox parameter
 * schemas to Valibot at the boundary, and converts the common executor
 * result to Flue's `run()` envelope.
 */
import { defineTool, type ToolDefinition as FlueToolDefinition } from "@flue/runtime";
import { collectRegisteredGrcTools, type RegisteredGrcTool, type GrcToolResult } from "../core/registry.js";
import { executeGrcTool } from "../core/tools.js";
import { jsonSchemaToToolInput } from "./schema.js";

export type GrcBridgeableTool = RegisteredGrcTool;
/** Compatibility names for callers of the original Flue bridge. */
export type PiBridgeableTool = GrcBridgeableTool;
export type PiBridgeToolResult = GrcToolResult;

export interface FlueToolRunEnvelope {
  output: string;
  terminate?: boolean;
}

/** Thrown from `run()` so Flue records a model-visible tool error, matching the native error-result intent. */
export class GrclankerToolError extends Error {
  readonly toolName: string;
  readonly details: unknown;

  constructor(toolName: string, message: string, details: unknown) {
    super(message);
    this.name = "GrclankerToolError";
    this.toolName = toolName;
    this.details = details;
  }
}

export function renderGrcToolContent(content: GrcToolResult["content"]): string {
  return content
    .map((block) => {
      switch (block.type) {
        case "text":
          return block.text;
        case "image":
          return `[image content omitted: ${block.mimeType}]`;
        default: {
          const exhaustive: never = block;
          void exhaustive;
          throw new Error("Unsupported native tool content block.");
        }
      }
    })
    .join("\n")
    .trim();
}

export function toFlueToolResult(toolName: string, result: GrcToolResult): FlueToolRunEnvelope {
  const output = renderGrcToolContent(result.content);
  if (result.isError) {
    throw new GrclankerToolError(toolName, output || `${toolName} failed without a message.`, result.details);
  }
  return result.terminate ? { output, terminate: true } : { output };
}

/** Compatibility export; content formatting belongs to the native GRC contract. */
export const renderPiToolContent = renderGrcToolContent;

export function toFlueTool(tool: GrcBridgeableTool): FlueToolDefinition {
  const input = jsonSchemaToToolInput(tool.parameters, tool.name, tool.prepareArguments);
  return defineTool({
    name: tool.name,
    description: tool.description,
    input,
    async run({ data, signal, toolCallId }) {
      signal?.throwIfAborted();
      let abortFailure: Error | undefined;
      // Flue's input pipe already prepared arguments. Core still performs strict
      // validation and owns execution, error sanitation, metadata, and signals.
      const preparedTool: RegisteredGrcTool = {
        ...tool,
        prepareArguments: undefined,
        async execute(id, args, executionSignal) {
          try {
            return await tool.execute(id, args, executionSignal);
          } catch (error) {
            // Flue treats cancellation as control flow; the shared SDK executor
            // returns error envelopes, so preserve this host's native abort.
            if (error instanceof Error && error.name === "AbortError") abortFailure = error;
            throw error;
          }
        },
      };
      const result = await executeGrcTool(preparedTool, data, { toolCallId, signal });
      if (result.isError) {
        signal?.throwIfAborted();
        if (abortFailure) throw abortFailure;
      }
      return toFlueToolResult(tool.name, result);
    },
  });
}

/** Every native GRC domain tool; each host supplies its own compute tools. */
export function collectGrclankerDomainTools(): RegisteredGrcTool[] {
  return collectRegisteredGrcTools();
}

export function createGrclankerFlueTools(tools: GrcBridgeableTool[] = collectGrclankerDomainTools()): FlueToolDefinition[] {
  return tools.map(toFlueTool);
}
