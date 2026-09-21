import { readCliAsset } from "./paths.js";

export const PERSONA_NAMES = ["auditor", "verifier"] as const;

export type PersonaName = (typeof PERSONA_NAMES)[number];

/** Subagent config accepted by `defineAgent` (description plus inline instructions). */
export interface PersonaAgentConfig {
  description: string;
  instructions: string;
}

/**
 * Bundled Pi personas (`cli/.grclanker/agents/<name>.md`) start with `Name:`
 * and `Purpose:` lines followed by the operating instructions.
 */
export function parsePersona(markdown: string): PersonaAgentConfig {
  const purpose = /^Purpose:\s*(.+)$/m.exec(markdown)?.[1]?.trim();
  if (!purpose) {
    throw new Error("Persona file is missing a Purpose: line.");
  }
  const instructions = markdown
    .replace(/^Name:.*\r?\n/m, "")
    .replace(/^Purpose:.*\r?\n/m, "")
    .trim();
  return { description: purpose, instructions };
}

/** Expose a bundled persona as an Agent SDK subagent. */
export function personaAgentConfig(name: PersonaName): PersonaAgentConfig {
  return parsePersona(readCliAsset(".grclanker", "agents", `${name}.md`));
}
