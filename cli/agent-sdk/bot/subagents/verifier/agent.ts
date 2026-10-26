import { defineAgent } from "@grok/agent-sdk";
import { personaAgentConfig } from "../../../lib/personas.js";

export default defineAgent(personaAgentConfig("verifier"));
