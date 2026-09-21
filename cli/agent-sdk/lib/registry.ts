import type { ExtensionContext, ToolDefinition } from "@earendil-works/pi-coding-agent";
import { collectRegisteredToolDefinitions, resolveToolGroup } from "../../pi/tool-catalog.js";

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
 * The slice of a Pi `ToolDefinition` the Agent SDK adapter consumes.
 *
 * grclanker domain tools only read the tool call id and their arguments. The
 * Pi `signal`, `onUpdate`, and extension `ctx` parameters are unused, so the
 * adapter exposes a two-argument `execute`.
 */
export interface RegisteredGrcTool {
  name: string;
  label: string;
  description: string;
  /** TypeBox parameter schema (a JSON Schema object at runtime). */
  parameters: Record<string, unknown>;
  prepareArguments?: (args: unknown) => unknown;
  execute: (toolCallId: string, args: unknown) => Promise<GrcToolResult>;
}

let registry: Map<string, RegisteredGrcTool> | undefined;

function toRegisteredGrcTool(tool: ToolDefinition): RegisteredGrcTool {
  // Pi itself passes `undefined` for the extension context when no context
  // factory is configured (see pi-coding-agent's wrapToolDefinition), and no
  // grclanker domain tool reads it.
  const extensionContext = undefined as unknown as ExtensionContext;

  return {
    name: tool.name,
    label: tool.label,
    description: tool.description,
    parameters: tool.parameters as Record<string, unknown>,
    prepareArguments: tool.prepareArguments,
    execute: async (toolCallId, args) =>
      (await tool.execute(toolCallId, args, undefined, undefined, extensionContext)) as GrcToolResult,
  };
}

/**
 * Collect the grclanker domain tools from the bundled extension. Compute
 * backend tools (`bash`, `read`, `write`, `edit`, `ls`, `find`, `grep`) are
 * excluded: the Cursor harness supplies its own shell and file tools.
 */
export function collectRegisteredGrcTools(): RegisteredGrcTool[] {
  return collectRegisteredToolDefinitions()
    .filter((tool) => resolveToolGroup(tool.name).kind === "domain")
    .map(toRegisteredGrcTool);
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
      `Unknown grclanker tool "${name}". Run "npm run sync:agent-sdk-tools" to regenerate agent-sdk/agent/tools.`,
    );
  }
  return tool;
}

export function resetGrcToolRegistryForTests(): void {
  registry = undefined;
}
