import { readCliAsset } from "./paths.js";

/**
 * The always-on system prompt: the bundled Pi `SYSTEM.md` followed by a short
 * note describing how the tool surface differs under the Cursor Agent SDK.
 */
export function buildGrclankerInstructions(): string {
  const systemPrompt = readCliAsset(".grclanker", "SYSTEM.md").trimEnd();
  const runtimeNote = readCliAsset("agent-sdk", "prompts", "runtime.md").trim();
  return `${systemPrompt}\n\n${runtimeNote}\n`;
}
