import { readCliAsset } from "../../runtime/paths.js";
import { buildGrclankerInstructions as buildRuntimeInstructions } from "../../runtime/instructions.js";

export { readGrclankerSystemPrompt } from "../../runtime/instructions.js";

/** Add the Cursor/Grok-specific runtime note to the shared GRC methodology. */
export function buildGrclankerInstructions(): string {
  return buildRuntimeInstructions(readCliAsset("agent-sdk", "prompts", "runtime.md"));
}
