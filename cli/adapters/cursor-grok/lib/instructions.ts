import { readCliAsset } from "../../../core/paths.js";
import { buildGrclankerInstructions as buildCoreInstructions } from "../../../core/instructions.js";

/** Add the Cursor/Grok-specific runtime note to the shared GRC methodology. */
export function buildGrclankerInstructions(): string {
  return buildCoreInstructions(readCliAsset("adapters", "cursor-grok", "prompts", "runtime.md"));
}
