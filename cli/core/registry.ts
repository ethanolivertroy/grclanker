import type { ExtensionToolContext, ToolDefinition } from "@earendil-works/pi-coding-agent";
import { collectDomainToolDefinitions } from "./domain-tools.js";

export type GrcToolContent =
  | { type: "text"; text: string }
  | { type: "image"; data: string; mimeType: string };

/** Result envelope produced by the native grc-tools (`textResult` / `errorResult`). */
export interface GrcToolResult {
  content: GrcToolContent[];
  details?: unknown;
  isError?: boolean;
}

/**
 * The slice of a native tool definition shared by runtime adapters.
 *
 * grclanker domain tools read the tool call id, their arguments, and the abort
 * signal, which cancels their in-flight API requests and makes the call reject.
 * The Pi `onUpdate` and extension `ctx` parameters are unused.
 */
export interface RegisteredGrcTool {
  name: string;
  label: string;
  description: string;
  /** TypeBox parameter schema (a JSON Schema object at runtime). */
  parameters: Record<string, unknown>;
  prepareArguments?: (args: unknown) => unknown;
  execute: (toolCallId: string, args: unknown, signal?: AbortSignal) => Promise<GrcToolResult>;
}

let registry: Map<string, RegisteredGrcTool> | undefined;

function toRegisteredGrcTool(tool: ToolDefinition): RegisteredGrcTool {
  // Pi itself passes `undefined` for the extension context when no context
  // factory is configured (see pi-coding-agent's wrapToolDefinition), and no
  // grclanker domain tool reads it.
  const extensionContext = undefined as unknown as ExtensionToolContext;

  return {
    name: tool.name,
    label: tool.label,
    description: tool.description,
    parameters: tool.parameters as Record<string, unknown>,
    prepareArguments: tool.prepareArguments,
    execute: async (toolCallId, args, signal) =>
      (await tool.execute(toolCallId, args, signal, undefined, extensionContext)) as GrcToolResult,
  };
}

/**
 * Collect only GRC domain tools. Each agent host supplies its own shell,
 * file tools, compute backends, and lifecycle hooks.
 */
export function collectRegisteredGrcTools(): RegisteredGrcTool[] {
  return collectDomainToolDefinitions().map(toRegisteredGrcTool);
}

export function getGrcToolRegistry(): Map<string, RegisteredGrcTool> {
  if (!registry) {
    registry = new Map(collectRegisteredGrcTools().map((tool) => [tool.name, tool]));
  }
  return registry;
}

export function listRegisteredGrcToolNames(): string[] {
  return [...getGrcToolRegistry().keys()];
}

export function getRegisteredGrcTool(name: string): RegisteredGrcTool {
  const tool = getGrcToolRegistry().get(name);
  if (!tool) {
    throw new Error(
      `Unknown grclanker tool "${name}". List the registered GRC tools before selecting one.`,
    );
  }
  return tool;
}

export function resetGrcToolRegistryForTests(): void {
  registry = undefined;
}
