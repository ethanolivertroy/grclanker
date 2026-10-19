import { readCliAsset } from "./paths.js";

/** The bundled Pi `SYSTEM.md`, shared by every runtime that hosts the grclanker agent. */
export function readGrclankerSystemPrompt(): string {
  return readCliAsset(".grclanker", "SYSTEM.md").trimEnd();
}

/**
 * The always-on system prompt: the bundled Pi `SYSTEM.md` followed by a short
 * note describing how the tool surface differs under the Cursor Agent SDK.
 */
export function buildGrclankerInstructions(): string {
  const runtimeNote = readCliAsset("agent-sdk", "prompts", "runtime.md").trim();
  return `${readGrclankerSystemPrompt()}\n\n${runtimeNote}\n`;
}
