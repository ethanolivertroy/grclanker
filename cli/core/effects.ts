/**
 * Conservative effect classification shared by all agent adapters.
 *
 * Only tools that query external systems or public data sets and write
 * nothing outside the session are read-only. Exporters, generators, OSCAL
 * workspace writers, evidence collectors, and unknown operations require
 * the host's write policy. The Cursor/Grok adapter also uses this value for
 * its SDK effect declaration and dry-run behavior.
 *
 * Classification is by name segment and write verbs win: a tool whose name
 * carries any write verb is never declared read-only, whatever else it says.
 */

const READ_ONLY_VERBS = new Set([
  "assess",
  "check",
  "get",
  "investigate",
  "list",
  "plan",
  "recent",
  "review",
  "search",
  "trace",
  "validate",
]);

/** Name segments that mark a tool as a writer. */
export const WRITE_VERBS: ReadonlySet<string> = new Set(["assemble", "collect", "create", "export", "generate", "import", "init"]);

export type GrcToolEffect = "read" | undefined;

/** True when any name segment after the domain prefix is a write verb, wherever it sits in the name. */
export function hasWriteVerb(toolName: string): boolean {
  return toolName.split("_").slice(1).some((segment) => WRITE_VERBS.has(segment));
}

/**
 * `"read"` when a name segment after the domain prefix is a read-only verb
 * and no segment is a write verb; `undefined` (treated as a write) otherwise.
 */
export function classifyGrcToolEffect(toolName: string): GrcToolEffect {
  if (hasWriteVerb(toolName)) {
    return undefined;
  }
  return toolName.split("_").slice(1).some((segment) => READ_ONLY_VERBS.has(segment)) ? "read" : undefined;
}

/** True for tools the adapter treats as writers (undeclared effect). */
export function isGrcWriteTool(toolName: string): boolean {
  return classifyGrcToolEffect(toolName) === undefined;
}
