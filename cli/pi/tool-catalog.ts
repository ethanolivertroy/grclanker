/** Pi catalog includes host compute tools alongside the shared GRC domain tools. */
import type { ExtensionAPI, ToolDefinition } from "@earendil-works/pi-coding-agent";
import grcTools from "../extensions/grc-tools.js";
import { summarizeToolDefinitions, type RegisteredToolSummary } from "../core/tool-catalog.js";

export {
  resolveToolGroup,
  groupRegisteredTools,
  formatToolCatalogText,
  findRegisteredTool,
  formatToolDetailText,
} from "../core/tool-catalog.js";
export type { RegisteredToolSummary, RegisteredToolParameter } from "../core/tool-catalog.js";

/** The Pi CLI's complete domain and compute catalog. Other hosts use core/domain-tools. */
export function collectRegisteredToolDefinitions(): ToolDefinition[] {
  const tools: ToolDefinition[] = [];
  const api = {
    registerTool(tool: ToolDefinition) {
      tools.push(tool);
    },
    on() {
      return undefined;
    },
  } as unknown as ExtensionAPI;
  grcTools(api);
  return tools;
}

export function getRegisteredToolSummaries(): RegisteredToolSummary[] {
  return summarizeToolDefinitions(collectRegisteredToolDefinitions());
}
