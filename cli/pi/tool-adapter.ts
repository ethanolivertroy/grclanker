import type { ToolDefinition } from "@earendil-works/pi-coding-agent";
import type { GrcToolDefinition } from "../core/tool-definition.js";
import { disableArgumentCoercion } from "./schema.js";
export { disableArgumentCoercion } from "./schema.js";

export function toPiToolDefinition(tool: GrcToolDefinition): ToolDefinition {
  const adapted: ToolDefinition = {
    ...tool,
    async execute(id, args, signal) {
      const result = await tool.execute(id, args, signal);
      return { ...result, details: result.details };
    },
  };
  return disableArgumentCoercion(adapted);
}
