import { getRegisteredGrcTool } from "../../dist/core/registry.js";
import { isGrcWriteTool } from "../../dist/core/effects.js";

export const defaultTools = ["kevs_search", "kevs_get_epss"];

export function selectTools(names = defaultTools) {
  if (names.length === 0 || names.some((name) => !name)) {
    throw new Error("Select at least one grclanker tool name.");
  }
  return [...new Set(names)].map((name) => {
    const tool = getRegisteredGrcTool(name);
    if (isGrcWriteTool(name)) {
      throw new Error(`This Codex example exposes read tools only: ${name}`);
    }
    return tool;
  });
}
