import type { AgentConfig } from "@cursor/july";

export const AGENT_NAME = "grclanker";

export const AGENT_DESCRIPTION =
  "Governance, risk, and compliance specialist backed by grclanker's native CMVP, KEV/EPSS, FedRAMP, SCF, OSCAL, and cloud and SaaS evidence tools.";

/** Environment variable that overrides the Cursor model id for Agent SDK turns. */
export const MODEL_ENV_VAR = "GRCLANKER_AGENT_SDK_MODEL";

/**
 * Root `defineAgent` config. Turns run on the local Cursor harness so the
 * in-process server tools apply; the model falls back to the Agent SDK default
 * unless `GRCLANKER_AGENT_SDK_MODEL` names a Cursor model id.
 */
export function grclankerAgentConfig(env: NodeJS.ProcessEnv = process.env): AgentConfig {
  const model = env[MODEL_ENV_VAR]?.trim();
  return {
    name: AGENT_NAME,
    description: AGENT_DESCRIPTION,
    runtime: "local",
    model: model ? model : undefined,
  };
}
