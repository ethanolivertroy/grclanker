import type { GrcToolDefinition } from "./tool-definition.js";
import { collectDomainToolDefinitions } from "./domain-tools.js";

export type { GrcToolContent, GrcToolResult } from "./tool-definition.js";
export type RegisteredGrcTool = GrcToolDefinition;

let registry: Map<string, RegisteredGrcTool> | undefined;

/**
 * Collect only GRC domain tools. Each agent host supplies its own shell,
 * file tools, compute backends, and lifecycle hooks.
 */
export function collectRegisteredGrcTools(): RegisteredGrcTool[] {
  return collectDomainToolDefinitions();
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
