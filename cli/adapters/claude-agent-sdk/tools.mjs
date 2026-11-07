import { getRegisteredGrcTool } from "../../dist/core/registry.js";

/** Public-data lookups that need no tenant credentials. */
export const DEFAULT_CLAUDE_GRC_TOOLS = [
  "cmvp_search_modules",
  "cmvp_get_module",
  "kevs_search",
  "kevs_get_epss",
];

/** Parse a comma-separated tool list from a flag or GRCLANKER_TOOLS. */
export function parseToolList(value) {
  return value.split(",").map((name) => name.trim());
}

/**
 * Resolve the deployment's domain tools. Unknown names fail before a model
 * request; write tools are allowed here and gated per call by operator approval.
 * @param {readonly string[]} [names]
 */
export function selectTools(names = DEFAULT_CLAUDE_GRC_TOOLS) {
  if (names.length === 0 || names.some((name) => !name)) {
    throw new Error("Select at least one grclanker tool name.");
  }
  return [...new Set(names)].map((name) => getRegisteredGrcTool(name));
}
