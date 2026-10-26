import { defineTool } from "@grok/agent-sdk/tools";
import { grclankerToolConfig } from "../../lib/tools.js";

export default defineTool(grclankerToolConfig("aws_assess_logging_detection"));
