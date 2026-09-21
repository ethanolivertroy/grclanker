/**
 * Bridge grclanker's native Pi tools into Flue `ToolDefinition`s.
 *
 * The Pi tools stay untouched; this module collects them from the same
 * registration path `grclanker tools` uses, converts their TypeBox parameter
 * schemas to Valibot at the boundary, and adapts the Pi `execute()` contract
 * to Flue's `run()` envelope.
 */
import type {
  AgentToolResult,
  ExtensionContext,
  ToolDefinition as PiToolDefinition,
} from "@earendil-works/pi-coding-agent";
import { defineTool, type ToolDefinition as FlueToolDefinition } from "@flue/runtime";
import { collectRegisteredTools, isComputeToolName } from "../pi/tool-catalog.js";
import { jsonSchemaToToolInput } from "./schema.js";

/** The subset of a Pi tool definition the bridge relies on. */
export type PiBridgeableTool = Pick<
  PiToolDefinition,
  "name" | "label" | "description" | "parameters" | "prepareArguments" | "execute"
>;

/** Pi tool results may carry the `isError` flag grclanker's `errorResult()` sets. */
export type PiBridgeToolResult = AgentToolResult<unknown> & { isError?: boolean };

export interface FlueToolRunEnvelope {
  output: string;
  terminate?: boolean;
}

/** Thrown from `run()` so Flue records a model-visible tool error, matching Pi's `errorResult()` intent. */
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

// grclanker's domain tools never read the Pi extension context (they only use
// `toolCallId` and `params`), so the bridge hands them an inert placeholder.
const DETACHED_EXTENSION_CONTEXT = Object.freeze({}) as unknown as ExtensionContext;

export function renderPiToolContent(content: PiBridgeToolResult["content"]): string {
  return content
    .map((block) => {
      switch (block.type) {
        case "text":
          return block.text;
        case "image":
          return `[image content omitted: ${block.mimeType}]`;
        default: {
          const exhaustive: never = block;
          throw new Error(`Unhandled Pi tool content block: ${JSON.stringify(exhaustive)}`);
        }
      }
    })
    .join("\n")
    .trim();
}

export function toFlueToolResult(toolName: string, result: PiBridgeToolResult): FlueToolRunEnvelope {
  const output = renderPiToolContent(result.content);
  if (result.isError) {
    throw new GrclankerToolError(toolName, output || `${toolName} failed without a message.`, result.details);
  }
  return result.terminate ? { output, terminate: true } : { output };
}

export function toFlueTool(tool: PiBridgeableTool): FlueToolDefinition {
  const input = jsonSchemaToToolInput(tool.parameters, tool.name);
  return defineTool({
    name: tool.name,
    description: tool.description,
    input,
    async run({ data, signal, toolCallId }) {
      const params = tool.prepareArguments ? tool.prepareArguments(data) : data;
      const result = (await tool.execute(
        toolCallId,
        params,
        signal,
        undefined,
        DETACHED_EXTENSION_CONTEXT,
      )) as PiBridgeToolResult;
      return toFlueToolResult(tool.name, result);
    },
  });
}

/** Every grclanker domain tool (compute-backend wrappers are Pi-specific and excluded). */
export function collectGrclankerDomainTools(): PiToolDefinition[] {
  return collectRegisteredTools().filter((tool) => !isComputeToolName(tool.name));
}

export function createGrclankerFlueTools(tools: PiBridgeableTool[] = collectGrclankerDomainTools()): FlueToolDefinition[] {
  return tools.map(toFlueTool);
}
