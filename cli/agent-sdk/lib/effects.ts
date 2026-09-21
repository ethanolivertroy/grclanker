/**
 * Effect classification for the Agent SDK `effect` declaration.
 *
 * A dry-run session executes `"read"` tools for real and stubs everything
 * else, so only tools that query external systems or public data sets and
 * write nothing outside the session are declared read-only. Exports,
 * generators, OSCAL workspace writers, evidence collectors, and planning
 * tools stay undeclared, which the Agent SDK treats as a write.
 */

const READ_ONLY_VERBS = new Set([
  "assess",
  "check",
  "get",
  "investigate",
  "list",
  "recent",
  "review",
  "search",
  "trace",
  "validate",
]);

export type GrcToolEffect = "read" | undefined;

/** `"read"` when a name segment after the domain prefix is a read-only verb. */
export function classifyGrcToolEffect(toolName: string): GrcToolEffect {
  const segments = toolName.split("_").slice(1);
  return segments.some((segment) => READ_ONLY_VERBS.has(segment)) ? "read" : undefined;
}
