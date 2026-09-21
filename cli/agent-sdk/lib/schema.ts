/**
 * Convert TypeBox parameter schemas into the plain JSON Schema objects the
 * Cursor Agent SDK forwards to the model as a tool `inputSchema`.
 */

export type JsonSchema = Record<string, unknown>;

const NESTED_SCHEMA_KEYS = new Set(["items", "anyOf", "oneOf", "allOf", "not", "additionalProperties"]);
const SCHEMA_MAP_KEYS = new Set(["properties", "patternProperties", "$defs", "definitions"]);
const LITERAL_VARIANT_KEYS = new Set(["const", "type"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Drop TypeBox symbol keys, functions, and undefined values via a JSON round trip. */
function stripNonJson(value: unknown): unknown {
  if (value === undefined) return undefined;
  return JSON.parse(JSON.stringify(value)) as unknown;
}

function isLiteralVariant(value: unknown): value is { const: unknown; type?: unknown } {
  return isRecord(value) && "const" in value && Object.keys(value).every((key) => LITERAL_VARIANT_KEYS.has(key));
}

/**
 * Collapse an `anyOf` / `oneOf` made only of `const` literals into `enum`.
 * TypeBox emits `Type.Union([Type.Literal("a"), Type.Literal("b")])` as
 * `{ anyOf: [{ const: "a", type: "string" }, ...] }`; `enum` is part of every
 * model provider's function-calling schema subset, `const` inside `anyOf` is not.
 */
function collapseLiteralUnion(schema: Record<string, unknown>): Record<string, unknown> {
  const variantsKey = Array.isArray(schema.anyOf) ? "anyOf" : Array.isArray(schema.oneOf) ? "oneOf" : undefined;
  if (variantsKey === undefined) return schema;

  const variants = schema[variantsKey] as unknown[];
  if (variants.length === 0 || !variants.every(isLiteralVariant)) return schema;

  const { [variantsKey]: _variants, ...rest } = schema;
  const collapsed: Record<string, unknown> = { ...rest, enum: variants.map((variant) => variant.const) };
  const types = new Set(variants.map((variant) => variant.type).filter((type) => typeof type === "string"));
  if (types.size === 1) {
    collapsed.type = [...types][0];
  }
  return collapsed;
}

function normalizeSchemaMap(value: unknown): unknown {
  if (!isRecord(value)) return value;
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, normalizeSchemaNode(child)]));
}

function normalizeSchemaNode(node: unknown): unknown {
  if (Array.isArray(node)) return node.map(normalizeSchemaNode);
  if (!isRecord(node)) return node;

  const normalized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(collapseLiteralUnion(node))) {
    if (NESTED_SCHEMA_KEYS.has(key)) {
      normalized[key] = normalizeSchemaNode(value);
    } else if (SCHEMA_MAP_KEYS.has(key)) {
      normalized[key] = normalizeSchemaMap(value);
    } else {
      normalized[key] = value;
    }
  }
  return normalized;
}

/**
 * Build the model-facing JSON Schema for a tool's TypeBox `parameters`.
 * The result is always an object schema with a `properties` map, and an empty
 * `required` list is dropped.
 */
export function toJsonSchema(parameters: unknown): JsonSchema {
  const stripped = stripNonJson(parameters);
  if (!isRecord(stripped)) {
    return { type: "object", properties: {} };
  }

  const schema: JsonSchema = { ...(normalizeSchemaNode(stripped) as Record<string, unknown>), type: "object" };
  if (!isRecord(schema.properties)) {
    schema.properties = {};
  }
  if (Array.isArray(schema.required) && schema.required.length === 0) {
    delete schema.required;
  }
  return schema;
}
