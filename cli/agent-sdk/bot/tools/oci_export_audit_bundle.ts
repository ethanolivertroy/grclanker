import { defineTool } from "@grok/agent-sdk/tools";
import { grclankerToolConfig } from "../../lib/tools.js";

export default defineTool(grclankerToolConfig("oci_export_audit_bundle"));
