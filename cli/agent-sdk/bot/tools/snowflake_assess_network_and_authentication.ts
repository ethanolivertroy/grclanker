import { defineTool } from "@grok/agent-sdk/tools";
import { grclankerToolConfig } from "../../lib/tools.js";

export default defineTool(grclankerToolConfig("snowflake_assess_network_and_authentication"));
