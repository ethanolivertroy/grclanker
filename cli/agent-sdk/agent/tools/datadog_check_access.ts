import { defineTool } from "@cursor/bdk/tools";
import { grclankerToolConfig } from "../../lib/tools.js";

export default defineTool(grclankerToolConfig("datadog_check_access"));
