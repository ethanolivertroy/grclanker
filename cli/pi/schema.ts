import type { GrcToolDefinition } from "../core/tool-definition.js";

/** Keep Pi's coercion switches at the Pi/Pi Durable host boundary. */
export function disableArgumentCoercion<T extends Pick<GrcToolDefinition, "parameters">>(tool: T): T {
  const parameters = JSON.parse(JSON.stringify(tool.parameters)) as T["parameters"];
  return { ...tool, parameters: Object.assign(parameters, { [Symbol.for("TypeBox.Kind")]: "Object" }) };
}
