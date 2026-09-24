import { defineInstructions } from "@cursor/july";
import { buildGrclankerInstructions } from "../lib/instructions.js";

export default defineInstructions({ markdown: buildGrclankerInstructions() });
