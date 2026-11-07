import { isGrcWriteTool } from "../../dist/core/effects.js";
import { getRegisteredGrcTool, listRegisteredGrcToolNames } from "../../dist/core/registry.js";

/** Public-data lookups that need no tenant credentials. */
export const DEFAULT_TOOLS = ["cmvp_search_modules", "cmvp_get_module", "kevs_search", "kevs_get_epss"];

/**
 * Parse server arguments: tool names or `family_*` patterns, separated by
 * spaces or commas, plus `--allow-writes`. GRCLANKER_TOOLS is used when no
 * names are given.
 * @param {string[]} argv
 * @param {Record<string, string | undefined>} [env]
 */
export function parseServerArgs(argv, env = process.env) {
  let allowWrites = false;
  const names = [];
  for (const arg of argv) {
    if (arg === "--allow-writes") allowWrites = true;
    else if (arg.startsWith("--")) throw new Error(`Unknown option: ${arg}`);
    else names.push(...arg.split(",").map((name) => name.trim()));
  }
  if (names.length === 0 && env.GRCLANKER_TOOLS !== undefined) {
    names.push(...env.GRCLANKER_TOOLS.split(",").map((name) => name.trim()));
  }
  return { names: names.length ? names : DEFAULT_TOOLS, allowWrites };
}

/**
 * Resolve the selection. `github_*` expands to every registered tool with that
 * prefix; writers in an expansion are skipped unless writes are allowed, and a
 * writer named exactly without `--allow-writes` is an error.
 * @param {readonly string[]} names
 * @param {{ allowWrites?: boolean }} [options]
 */
export function selectTools(names, { allowWrites = false } = {}) {
  if (names.length === 0 || names.some((name) => !name)) {
    throw new Error("Select at least one grclanker tool name.");
  }
  const registered = listRegisteredGrcToolNames();
  const selected = new Set();
  for (const name of names) {
    if (name.endsWith("*")) {
      const prefix = name.slice(0, -1);
      const matches = registered.filter((candidate) => candidate.startsWith(prefix) && (allowWrites || !isGrcWriteTool(candidate)));
      if (!prefix || matches.length === 0) throw new Error(`No grclanker tools match "${name}".`);
      matches.forEach((match) => selected.add(match));
      continue;
    }
    getRegisteredGrcTool(name);
    if (isGrcWriteTool(name) && !allowWrites) {
      throw new Error(`${name} writes files; add --allow-writes to expose it.`);
    }
    selected.add(name);
  }
  return [...selected].map((name) => getRegisteredGrcTool(name));
}
