import { defineTool } from "@cursor/bdk/tools";
import { grclankerToolConfig } from "../../lib/tools.js";

export default defineTool(grclankerToolConfig("crowdstrike_assess_response_readiness"));
