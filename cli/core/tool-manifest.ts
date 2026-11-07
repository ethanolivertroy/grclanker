import type { RegisteredToolSummary } from "./tool-catalog.js";
import { classifyGrcToolEffect } from "./effects.js";

export interface ManifestTool extends RegisteredToolSummary {
  effect: "read" | "write";
}

export interface ToolManifest {
  schemaVersion: 1;
  toolPrefixes: string[];
  tools: ManifestTool[];
  environmentVariables: string[];
}

const READ_COMPUTE_TOOLS = new Set(["find", "grep", "ls", "read"]);
const compare = (left: string, right: string): number => left < right ? -1 : left > right ? 1 : 0;

/** Build metadata supplied by a host; core never imports or initializes that host. */
export function buildToolManifest(input: {
  tools: readonly RegisteredToolSummary[];
  toolPrefixes: readonly string[];
  environmentVariables: readonly string[];
}): ToolManifest {
  const names = new Set<string>();
  const tools = input.tools.map((tool): ManifestTool => {
    if (names.has(tool.name)) throw new Error(`Duplicate tool manifest name: ${tool.name}`);
    names.add(tool.name);
    const read = tool.kind === "compute" ? READ_COMPUTE_TOOLS.has(tool.name) : classifyGrcToolEffect(tool.name) === "read";
    return { ...tool, effect: read ? "read" : "write" };
  }).sort((left, right) => compare(left.name, right.name));
  return {
    schemaVersion: 1,
    toolPrefixes: [...new Set(input.toolPrefixes)].sort(compare),
    tools,
    environmentVariables: [...new Set(input.environmentVariables)].sort(compare),
  };
}

export function serializeToolManifest(manifest: ToolManifest): string {
  return `${JSON.stringify(manifest, null, 2)}\n`;
}
