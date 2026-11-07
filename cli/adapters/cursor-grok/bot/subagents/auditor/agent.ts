import { defineAgent } from "@grok/agent-sdk";
import { personaAgentConfig } from "../../../../../core/personas.js";

export default defineAgent(personaAgentConfig("auditor"));
