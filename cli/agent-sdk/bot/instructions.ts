import { defineInstructions } from "@cursor/bdk";
import { buildGrclankerInstructions } from "../lib/instructions.js";

export default defineInstructions({ markdown: buildGrclankerInstructions() });
