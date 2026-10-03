import { defineTool } from "@cursor/bdk/tools";
import { grclankerToolConfig } from "../../lib/tools.js";

export default defineTool(grclankerToolConfig("launchdarkly_assess_identity"));
