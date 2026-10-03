/**
 * JSON Schema to Valibot conversion for the Flue adapter boundary.
 *
 * grclanker's native tools declare their parameters as TypeBox JSON Schema,
 * and Pi's tool loop runs each tool's `prepareArguments` shim, treats `null`
 * for an optional property that does not accept it as omitted, and then checks
 * the result against that schema. Flue's `defineTool()`
 * requires a Valibot top-level object schema and renders the model-facing JSON
 * Schema back out of it with `@valibot/to-json-schema`. This module bridges
 * the two without touching the tool definitions: the converted schema renders
 * like the source, and the tool input pipe runs the shim before validation
 * exactly as Pi does.
 */
import type { ToolInputSchema } from "@flue/runtime";
import * as v from "valibot";

export type JsonSchemaObject = Record<string, unknown>;

export type PrepareToolArguments = (args: unknown) => unknown;

const JSON_SCHEMA_TYPES = ["string", "number", "integer", "boolean", "null", "array", "object"] as const;

type JsonSchemaType = (typeof JSON_SCHEMA_TYPES)[number];

type LiteralValue = string | number | boolean;

const TOOL_INPUT_OBJECT_TYPES = new Set(["object", "strict_object", "loose_object", "object_with_rest"]);

function asSchemaObject(value: unknown): JsonSchemaObject | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as JsonSchemaObject;
}

function asFiniteNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];
}

function isLiteralValue(value: unknown): value is LiteralValue {
  return typeof value === "string" || typeof value === "number" || typeof value === "boolean";
}

function isJsonSchemaType(value: unknown): value is JsonSchemaType {
  return typeof value === "string" && (JSON_SCHEMA_TYPES as readonly string[]).includes(value);
}

function convertConst(value: unknown): v.GenericSchema {
  if (value === null) return v.null();
  return isLiteralValue(value) ? v.literal(value) : v.unknown();
}

function convertEnum(values: unknown[]): v.GenericSchema {
  const strings = values.filter((value): value is string => typeof value === "string");
  if (strings.length === values.length && strings.length > 0) {
    return v.picklist(strings);
  }
  return v.union(values.map(convertConst));
}

function collectVariants(node: JsonSchemaObject): JsonSchemaObject[] | undefined {
  const variants = Array.isArray(node.anyOf) ? node.anyOf : Array.isArray(node.oneOf) ? node.oneOf : undefined;
  const objects = variants?.map(asSchemaObject).filter((entry): entry is JsonSchemaObject => Boolean(entry));
  return objects && objects.length > 0 ? objects : undefined;
}

function convertVariants(variants: JsonSchemaObject[]): v.GenericSchema {
  const constants = variants.map((variant) => variant.const);
  if (constants.every((value): value is string => typeof value === "string")) {
    return v.picklist(constants);
  }
  return v.union(variants.map((variant) => jsonSchemaToValibot(variant)));
}

function convertString(node: JsonSchemaObject): v.GenericSchema {
  let schema: v.GenericSchema<string, string> = v.string();
  const minLength = asFiniteNumber(node.minLength);
  const maxLength = asFiniteNumber(node.maxLength);
  if (minLength !== undefined) schema = v.pipe(schema, v.minLength(minLength));
  if (maxLength !== undefined) schema = v.pipe(schema, v.maxLength(maxLength));
  // `pattern` is not compiled into a RegExp here; `withAnnotations` renders it
  // into the model-facing schema, where Flue's own argument check enforces it.
  return schema;
}

function convertNumber(node: JsonSchemaObject, integer: boolean): v.GenericSchema {
  let schema: v.GenericSchema<number, number> = integer ? v.pipe(v.number(), v.integer()) : v.number();
  const minimum = asFiniteNumber(node.minimum);
  const maximum = asFiniteNumber(node.maximum);
  const exclusiveMinimum = asFiniteNumber(node.exclusiveMinimum);
  const exclusiveMaximum = asFiniteNumber(node.exclusiveMaximum);
  const multipleOf = asFiniteNumber(node.multipleOf);
  if (minimum !== undefined) schema = v.pipe(schema, v.minValue(minimum));
  if (maximum !== undefined) schema = v.pipe(schema, v.maxValue(maximum));
  if (exclusiveMinimum !== undefined) schema = v.pipe(schema, v.gtValue(exclusiveMinimum));
  if (exclusiveMaximum !== undefined) schema = v.pipe(schema, v.ltValue(exclusiveMaximum));
  if (multipleOf !== undefined) schema = v.pipe(schema, v.multipleOf(multipleOf));
  return schema;
}

function convertArray(node: JsonSchemaObject): v.GenericSchema {
  let schema: v.GenericSchema<unknown[], unknown[]> = v.array(jsonSchemaToValibot(node.items));
  const minItems = asFiniteNumber(node.minItems);
  const maxItems = asFiniteNumber(node.maxItems);
  if (minItems !== undefined) schema = v.pipe(schema, v.minLength(minItems));
  if (maxItems !== undefined) schema = v.pipe(schema, v.maxLength(maxItems));
  return schema;
}

function convertObject(node: JsonSchemaObject): v.GenericSchema {
  const properties = asSchemaObject(node.properties) ?? {};
  const required = new Set(asStringArray(node.required));
  const entries: v.ObjectEntries = {};

  for (const [key, property] of Object.entries(properties)) {
    const converted = jsonSchemaToValibot(property);
    entries[key] = required.has(key) ? converted : v.optional(converted);
  }

  const additional = node.additionalProperties;
  if (additional === false) return v.strictObject(entries);
  const additionalSchema = asSchemaObject(additional);
  if (additionalSchema) return v.objectWithRest(entries, jsonSchemaToValibot(additionalSchema));
  // TypeBox objects allow unknown keys by default. Keeping them mirrors Pi,
  // where extra keys reach the tool untouched.
  return v.looseObject(entries);
}

function resolveType(node: JsonSchemaObject): JsonSchemaType | undefined {
  if (isJsonSchemaType(node.type)) return node.type;
  if (node.type === undefined && asSchemaObject(node.properties)) return "object";
  return undefined;
}

function convertTyped(node: JsonSchemaObject): v.GenericSchema {
  const type = resolveType(node);
  if (type === undefined) return v.unknown();

  switch (type) {
    case "string":
      return convertString(node);
    case "number":
      return convertNumber(node, false);
    case "integer":
      return convertNumber(node, true);
    case "boolean":
      return v.boolean();
    case "null":
      return v.null();
    case "array":
      return convertArray(node);
    case "object":
      return convertObject(node);
    default: {
      const exhaustive: never = type;
      throw new Error(`Unhandled JSON Schema type: ${String(exhaustive)}`);
    }
  }
}

function convertNode(node: JsonSchemaObject): v.GenericSchema {
  if ("const" in node) return convertConst(node.const);
  if (Array.isArray(node.enum)) return convertEnum(node.enum);

  const variants = collectVariants(node);
  if (variants) return convertVariants(variants);

  if (Array.isArray(node.type)) {
    const types = node.type.filter(isJsonSchemaType);
    if (types.length > 0) {
      return v.union(types.map((type) => convertTyped({ ...node, type })));
    }
  }

  return convertTyped(node);
}

function withAnnotations(node: JsonSchemaObject, schema: v.GenericSchema): v.GenericSchema {
  let annotated = schema;
  if (typeof node.title === "string" && node.title.length > 0) {
    annotated = v.pipe(annotated, v.title(node.title));
  }
  if (typeof node.description === "string" && node.description.length > 0) {
    annotated = v.pipe(annotated, v.description(node.description));
  }

  const metadata: Record<string, unknown> = {};
  if (node.default !== undefined) metadata.default = node.default;
  if (Array.isArray(node.examples)) metadata.examples = node.examples;
  if (typeof node.pattern === "string") metadata.pattern = node.pattern;
  if (Object.keys(metadata).length > 0) {
    // `v.metadata()` carries these keys into the rendered JSON Schema without
    // applying them at parse time. Pi treats TypeBox defaults as informational
    // too, and `pattern` is enforced by Flue's argument check on the rendered
    // schema rather than by a RegExp compiled from schema input here.
    annotated = v.pipe(annotated, v.metadata(metadata));
  }
  return annotated;
}

/**
 * Convert one JSON Schema node into an equivalent Valibot schema. Unknown or
 * unsupported constructs degrade to `v.unknown()` rather than failing, so a
 * tool always stays mountable.
 */
export function jsonSchemaToValibot(schema: unknown): v.GenericSchema {
  const node = asSchemaObject(schema);
  if (!node) return v.unknown();
  return withAnnotations(node, convertNode(node));
}

const nullAcceptance = new WeakMap<JsonSchemaObject, boolean>();

function acceptsNull(node: JsonSchemaObject): boolean {
  let accepts = nullAcceptance.get(node);
  if (accepts === undefined) {
    accepts = v.is(jsonSchemaToValibot(node), null);
    nullAcceptance.set(node, accepts);
  }
  return accepts;
}

/** Pi's `normalizeOptionalNulls`, without mutating the caller's value. */
function withoutOptionalNulls(value: unknown, schema: unknown): unknown {
  const node = asSchemaObject(schema);
  if (!node) return value;
  if (Array.isArray(value)) {
    const items = node.items;
    return value.map((item, index) => withoutOptionalNulls(item, Array.isArray(items) ? items[index] : items));
  }
  const properties = asSchemaObject(node.properties);
  if (!properties || !value || typeof value !== "object") return value;

  const required = new Set(asStringArray(node.required));
  const result: Record<string, unknown> = { ...(value as Record<string, unknown>) };
  for (const [key, property] of Object.entries(properties)) {
    if (!(key in result)) continue;
    const propertyNode = asSchemaObject(property);
    if (result[key] === null && !required.has(key) && propertyNode && !acceptsNull(propertyNode)) {
      delete result[key];
    } else {
      result[key] = withoutOptionalNulls(result[key], property);
    }
  }
  return result;
}

function piArgumentsStep(toolName: string, schema: unknown, prepare: PrepareToolArguments | undefined) {
  return v.rawTransform<Record<string, unknown>, unknown>(({ dataset, addIssue }) => {
    let prepared: unknown = dataset.value;
    if (prepare) {
      try {
        prepared = prepare(dataset.value);
      } catch (error) {
        addIssue({
          message: `${toolName} could not normalize its arguments: ${error instanceof Error ? error.message : String(error)}`,
        });
        return dataset.value;
      }
    }
    return withoutOptionalNulls(prepared, schema);
  });
}

/**
 * Convert a tool parameter schema into the top-level object schema Flue's
 * `defineTool()` requires. The input runs through the same steps as in Pi's
 * tool loop: the leading `v.looseObject({})` only asserts that the model sent
 * an object, the tool's `prepareArguments` shim (when declared) normalizes it,
 * optional `null`s the schema rejects are dropped, and the result is validated
 * by the converted schema. The whole pipe still renders as the converted
 * schema for the model. Throws when the source is not an object schema.
 */
export function jsonSchemaToToolInput(
  schema: unknown,
  toolName = "tool",
  prepareArguments?: PrepareToolArguments,
): ToolInputSchema {
  const converted = jsonSchemaToValibot(schema);
  if (!TOOL_INPUT_OBJECT_TYPES.has(converted.type)) {
    throw new Error(
      `Tool "${toolName}" parameters must be a JSON Schema object (got type "${String(asSchemaObject(schema)?.type)}").`,
    );
  }
  return v.pipe(v.looseObject({}), piArgumentsStep(toolName, schema, prepareArguments), converted) as ToolInputSchema;
}

/** True when a Valibot schema satisfies Flue's top-level object requirement for tool input. */
export function isToolInputObjectSchema(schema: v.GenericSchema): boolean {
  return TOOL_INPUT_OBJECT_TYPES.has(schema.type);
}
