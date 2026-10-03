import { defineTool } from "@cursor/bdk/tools";
import { grclankerToolConfig } from "../../lib/tools.js";

export default defineTool(grclankerToolConfig("pagerduty_export_audit_bundle"));
