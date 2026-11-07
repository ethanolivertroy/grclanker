import { Compile } from "typebox/compile";
import type { TSchema } from "typebox";
import type { GrcToolDefinition } from "./tool-definition.js";

type JsonSchema = Record<string, unknown>;
const validators = new WeakMap<object, ReturnType<typeof Compile>>();

function object(value: unknown): JsonSchema | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as JsonSchema : undefined;
}

function validator(schema: TSchema) {
  let compiled = validators.get(schema);
  if (!compiled) {
    compiled = Compile(schema);
    validators.set(schema, compiled);
  }
  return compiled;
}

/** An optional null means omitted only when that property's schema rejects null. */
export function normalizeOptionalNulls(value: unknown, schema: JsonSchema): unknown {
  if (Array.isArray(value)) {
    return value.map((item, index) => {
      const itemSchema = object(Array.isArray(schema.items) ? schema.items[index] : schema.items);
      return itemSchema ? normalizeOptionalNulls(item, itemSchema) : item;
    });
  }
  const record = object(value);
  const properties = object(schema.properties);
  if (!record || !properties) return value;
  const result = { ...record };
  const required = new Set(Array.isArray(schema.required) ? schema.required : []);
  for (const [key, property] of Object.entries(properties)) {
    if (!(key in result)) continue;
    const child = object(property);
    if (!child) continue;
    if (result[key] === null && !required.has(key) && typeof child.$ref !== "string" && !validator(child).Check(null)) {
      delete result[key];
    } else {
      result[key] = normalizeOptionalNulls(result[key], child);
    }
  }
  return result;
}

/** Strict native validation is independent of a provider's coercion or schema gate. */
export function prepareGrcToolArguments(tool: Pick<GrcToolDefinition, "name" | "parameters" | "prepareArguments">, _toolCallId: string, input: unknown): unknown {
  const prepared = tool.prepareArguments ? tool.prepareArguments(input) : input;
  return validateGrcToolArguments(tool.name, tool.parameters, prepared);
}

export function validateGrcToolArguments(name: string, schema: TSchema, input: unknown): unknown {
  const args = normalizeOptionalNulls(structuredClone(input), schema as JsonSchema);
  const check = validator(schema);
  if (!check.Check(args)) {
    const details = check.Errors(args).map((error) => `  - ${error.instancePath || "root"}: ${error.message}`).join("\n");
    // Do not echo the supplied arguments into a validation error.
    throw new Error(`Validation failed for tool "${name}":\n${details}`);
  }
  return args;
}
