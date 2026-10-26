import { defineTool } from "@grok/agent-sdk/tools";
import { grclankerToolConfig } from "../../lib/tools.js";

export default defineTool(grclankerToolConfig("ansible_assess_host_coverage"));
