import { defineAgent } from "@cursor/july";
import { personaAgentConfig } from "../../../lib/personas.js";

export default defineAgent(personaAgentConfig("auditor"));
