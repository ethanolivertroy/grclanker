import { defineInstructions } from "@grok/agent-sdk";
import { buildGrclankerInstructions } from "../lib/instructions.js";

export default defineInstructions({ markdown: buildGrclankerInstructions() });
