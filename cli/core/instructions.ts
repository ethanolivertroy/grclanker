import { readCliAsset } from "./paths.js";

/** The bundled GRC methodology, shared by every agent harness. */
export function readGrclankerSystemPrompt(): string {
  return readCliAsset(".grclanker", "SYSTEM.md").trimEnd();
}

/** Combine the shared methodology with a host-specific description of available capabilities. */
export function buildGrclankerInstructions(runtimeNote: string = ""): string {
  const note = runtimeNote.trim();
  return `${readGrclankerSystemPrompt()}${note ? `\n\n${note}` : ""}\n`;
}
