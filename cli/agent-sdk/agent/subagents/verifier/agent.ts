import { defineAgent } from "@cursor/bdk";
import { personaAgentConfig } from "../../../lib/personas.js";

export default defineAgent(personaAgentConfig("verifier"));
