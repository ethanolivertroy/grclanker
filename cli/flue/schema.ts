/**
 * JSON Schema to Valibot conversion for the Flue adapter boundary.
 *
 * grclanker's native tools declare their parameters as TypeBox JSON Schema and
 * Pi validates calls with `prepareArguments` first, then TypeBox
 * `Value.Convert` (lenient coercion) and `Value.Check`. Flue's `defineTool()`
 * requires a Valibot top-level object schema and renders the model-facing JSON
 * Schema from it with `@valibot/to-json-schema`.
 *
 * Each converted node therefore carries a `convert` step that reproduces
 * TypeBox's coercion rules and a validating schema that renders exactly like
 * the source (a `v.pipe(v.unknown(), v.transform(convert), strict)` pipe
 * renders as its strict member), so the model sees the same schema it sees
 * under Pi while arguments are accepted and normalized the same way.
 */
import type { ToolInputSchema } from "@flue/runtime";
import * as v from "valibot";

export type JsonSchemaObject = Record<string, unknown>;

export type PrepareToolArguments = (args: unknown) => unknown;

interface ConvertedNode {
  /** TypeBox `Value.Convert` equivalent for this node; idempotent on converted values. */
  convert: (value: unknown) => unknown;
  /** Validating schema that coerces on parse and renders like the source schema. */
  schema: v.GenericSchema;
  /** The same validation without coercion, used for union member matching. */
  strict: v.GenericSchema;
}

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

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// TypeBox `Value.Convert` rules (value/convert/convert.mjs), reproduced verbatim
// so a call that Pi accepts is accepted here with the same normalized value.

function isStringNumeric(value: unknown): value is string {
  return typeof value === "string" && !Number.isNaN(Number(value)) && !Number.isNaN(parseFloat(value));
}

function isValueTrue(value: unknown): boolean {
  return (
    value === true ||
    value === 1 ||
    (typeof value === "bigint" && value === BigInt(1)) ||
    (typeof value === "string" && (value.toLowerCase() === "true" || value === "1"))
  );
}

function isValueFalse(value: unknown): boolean {
  return (
    value === false ||
    (typeof value === "number" && (value === 0 || Object.is(value, -0))) ||
    (typeof value === "bigint" && value === BigInt(0)) ||
    (typeof value === "string" && (value.toLowerCase() === "false" || value === "0" || value === "-0"))
  );
}

function tryConvertString(value: unknown): unknown {
  if (typeof value === "symbol" && value.description !== undefined) return value.description.toString();
  return typeof value === "bigint" || typeof value === "boolean" || typeof value === "number" ? value.toString() : value;
}

function tryConvertNumber(value: unknown): unknown {
  if (isStringNumeric(value)) return parseFloat(value);
  if (isValueTrue(value)) return 1;
  if (isValueFalse(value)) return 0;
  return value;
}

function tryConvertInteger(value: unknown): unknown {
  // TypeBox calls parseInt without a radix, so hex-looking strings ("0x10") parse as hex there too.
  if (isStringNumeric(value)) return Number.parseInt(value);
  if (typeof value === "number") return Math.trunc(value);
  if (isValueTrue(value)) return 1;
  if (isValueFalse(value)) return 0;
  return value;
}

function tryConvertBoolean(value: unknown): unknown {
  if (isValueTrue(value)) return true;
  if (isValueFalse(value)) return false;
  return value;
}

function tryConvertNull(value: unknown): unknown {
  return typeof value === "string" && value.toLowerCase() === "null" ? null : value;
}

function tryConvertLiteral(target: LiteralValue): (value: unknown) => unknown {
  return (value) => {
    const converted =
      typeof target === "string"
        ? tryConvertString(value)
        : typeof target === "number"
          ? tryConvertNumber(value)
          : tryConvertBoolean(value);
    return converted === target ? target : value;
  };
}

function cloneJson(value: unknown): unknown {
  return value === undefined ? undefined : structuredClone(value);
}

/** Wrap a strict schema so parsing coerces first; renders identically to `strict`. */
function coercing(convert: (value: unknown) => unknown, strict: v.GenericSchema): v.GenericSchema {
  return v.pipe(v.unknown(), v.transform(convert), strict);
}

function leafNode(convert: (value: unknown) => unknown, strict: v.GenericSchema): ConvertedNode {
  return { convert, strict, schema: coercing(convert, strict) };
}

function unknownNode(): ConvertedNode {
  const schema = v.unknown();
  return { convert: (value) => value, strict: schema, schema };
}

function convertConst(value: unknown): ConvertedNode {
  if (value === null) return leafNode(tryConvertNull, v.null());
  if (!isLiteralValue(value)) return unknownNode();
  return leafNode(tryConvertLiteral(value), v.literal(value));
}

function convertStringPicklist(options: string[]): ConvertedNode {
  const strict = v.picklist(options);
  const convert = (value: unknown): unknown => {
    if (typeof value === "string" && options.includes(value)) return value;
    const converted = tryConvertString(value);
    return typeof converted === "string" && options.includes(converted) ? converted : value;
  };
  return leafNode(convert, strict);
}

/** TypeBox `FromUnion`: keep a value that already matches, else the first variant that matches after conversion. */
function convertUnion(variants: ConvertedNode[]): ConvertedNode {
  const strict = v.union(variants.map((variant) => variant.strict));
  const convert = (value: unknown): unknown => {
    if (variants.some((variant) => v.is(variant.strict, value))) return value;
    for (const variant of variants) {
      const converted = variant.convert(cloneJson(value));
      if (v.is(variant.strict, converted)) return converted;
    }
    return value;
  };
  return leafNode(convert, strict);
}

function convertEnum(values: unknown[]): ConvertedNode {
  const strings = values.filter((value): value is string => typeof value === "string");
  if (strings.length === values.length && strings.length > 0) {
    return convertStringPicklist(strings);
  }
  return convertUnion(values.map(convertConst));
}

function collectVariants(node: JsonSchemaObject): JsonSchemaObject[] | undefined {
  const variants = Array.isArray(node.anyOf) ? node.anyOf : Array.isArray(node.oneOf) ? node.oneOf : undefined;
  const objects = variants?.map(asSchemaObject).filter((entry): entry is JsonSchemaObject => Boolean(entry));
  return objects && objects.length > 0 ? objects : undefined;
}

function convertVariants(variants: JsonSchemaObject[]): ConvertedNode {
  const constants = variants.map((variant) => variant.const);
  if (constants.every((value): value is string => typeof value === "string")) {
    return convertStringPicklist(constants);
  }
  return convertUnion(variants.map((variant) => convertNode(variant)));
}

function convertString(node: JsonSchemaObject): ConvertedNode {
  let strict: v.GenericSchema<string, string> = v.string();
  const minLength = asFiniteNumber(node.minLength);
  const maxLength = asFiniteNumber(node.maxLength);
  if (minLength !== undefined) strict = v.pipe(strict, v.minLength(minLength));
  if (maxLength !== undefined) strict = v.pipe(strict, v.maxLength(maxLength));
  if (typeof node.pattern === "string") strict = v.pipe(strict, v.regex(new RegExp(node.pattern)));
  return leafNode(tryConvertString, strict);
}

function convertNumber(node: JsonSchemaObject, integer: boolean): ConvertedNode {
  let strict: v.GenericSchema<number, number> = integer ? v.pipe(v.number(), v.integer()) : v.number();
  const minimum = asFiniteNumber(node.minimum);
  const maximum = asFiniteNumber(node.maximum);
  const exclusiveMinimum = asFiniteNumber(node.exclusiveMinimum);
  const exclusiveMaximum = asFiniteNumber(node.exclusiveMaximum);
  const multipleOf = asFiniteNumber(node.multipleOf);
  if (minimum !== undefined) strict = v.pipe(strict, v.minValue(minimum));
  if (maximum !== undefined) strict = v.pipe(strict, v.maxValue(maximum));
  if (exclusiveMinimum !== undefined) strict = v.pipe(strict, v.gtValue(exclusiveMinimum));
  if (exclusiveMaximum !== undefined) strict = v.pipe(strict, v.ltValue(exclusiveMaximum));
  if (multipleOf !== undefined) strict = v.pipe(strict, v.multipleOf(multipleOf));
  return leafNode(integer ? tryConvertInteger : tryConvertNumber, strict);
}

function convertArray(node: JsonSchemaObject): ConvertedNode {
  const item = convertNode(asSchemaObject(node.items));
  let strict: v.GenericSchema<unknown[], unknown[]> = v.array(item.strict);
  const minItems = asFiniteNumber(node.minItems);
  const maxItems = asFiniteNumber(node.maxItems);
  if (minItems !== undefined) strict = v.pipe(strict, v.minLength(minItems));
  if (maxItems !== undefined) strict = v.pipe(strict, v.maxLength(maxItems));
  // TypeBox wraps a lone value into a one-element array before converting items.
  const convert = (value: unknown): unknown => (Array.isArray(value) ? value : [value]).map(item.convert);
  return leafNode(convert, strict);
}

function convertObject(node: JsonSchemaObject): ConvertedNode {
  const properties = asSchemaObject(node.properties) ?? {};
  const required = new Set(asStringArray(node.required));
  const nodes = new Map<string, ConvertedNode>();
  const entries: v.ObjectEntries = {};
  const strictEntries: v.ObjectEntries = {};

  for (const [key, property] of Object.entries(properties)) {
    const converted = convertNode(asSchemaObject(property));
    nodes.set(key, converted);
    entries[key] = required.has(key) ? converted.schema : v.optional(converted.schema);
    strictEntries[key] = required.has(key) ? converted.strict : v.optional(converted.strict);
  }

  const additional = node.additionalProperties;
  const additionalSchema = asSchemaObject(additional);
  const rest = additionalSchema ? convertNode(additionalSchema) : undefined;

  const buildObject = (objectEntries: v.ObjectEntries, restSchema: v.GenericSchema | undefined): v.GenericSchema => {
    if (additional === false) return v.strictObject(objectEntries);
    if (restSchema) return v.objectWithRest(objectEntries, restSchema);
    // TypeBox objects allow unknown keys by default. Keeping them mirrors Pi,
    // where extra keys reach the tool untouched.
    return v.looseObject(objectEntries);
  };

  // TypeBox `FromObject` converts only the declared properties that are present.
  const convert = (value: unknown): unknown => {
    if (!isPlainObject(value)) return value;
    const result: Record<string, unknown> = { ...value };
    for (const [key, property] of nodes) {
      if (key in result) result[key] = property.convert(result[key]);
    }
    return result;
  };

  return {
    convert,
    schema: buildObject(entries, rest?.schema),
    strict: buildObject(strictEntries, rest?.strict),
  };
}

function resolveType(node: JsonSchemaObject): JsonSchemaType | undefined {
  if (isJsonSchemaType(node.type)) return node.type;
  if (node.type === undefined && asSchemaObject(node.properties)) return "object";
  return undefined;
}

function convertTyped(node: JsonSchemaObject): ConvertedNode {
  const type = resolveType(node);
  if (type === undefined) return unknownNode();

  switch (type) {
    case "string":
      return convertString(node);
    case "number":
      return convertNumber(node, false);
    case "integer":
      return convertNumber(node, true);
    case "boolean":
      return leafNode(tryConvertBoolean, v.boolean());
    case "null":
      return leafNode(tryConvertNull, v.null());
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
  if (Object.keys(metadata).length > 0) {
    // `v.metadata()` carries `default` into the rendered JSON Schema without
    // applying it at parse time; Pi treats TypeBox defaults as informational too.
    annotated = v.pipe(annotated, v.metadata(metadata));
  }
  return annotated;
}

function convertNode(node: JsonSchemaObject | undefined): ConvertedNode {
  if (!node) return unknownNode();

  const converted = convertUnannotated(node);
  return {
    convert: converted.convert,
    schema: withAnnotations(node, converted.schema),
    strict: withAnnotations(node, converted.strict),
  };
}

function convertUnannotated(node: JsonSchemaObject): ConvertedNode {
  if ("const" in node) return convertConst(node.const);
  if (Array.isArray(node.enum)) return convertEnum(node.enum);

  const variants = collectVariants(node);
  if (variants) return convertVariants(variants);

  if (Array.isArray(node.type)) {
    const types = node.type.filter(isJsonSchemaType);
    if (types.length > 0) {
      return convertUnion(types.map((type) => convertTyped({ ...node, type })));
    }
  }

  return convertTyped(node);
}

/**
 * Convert one JSON Schema node into a Valibot schema that coerces like TypeBox
 * `Value.Convert` and renders like the source. Unsupported constructs degrade
 * to `v.unknown()` rather than failing, so a tool always stays mountable.
 */
export function jsonSchemaToValibot(schema: unknown): v.GenericSchema {
  return convertNode(asSchemaObject(schema)).schema;
}

function prepareArgumentsStep(toolName: string, prepare: PrepareToolArguments) {
  return v.rawTransform<Record<string, unknown>, unknown>(({ dataset, addIssue }) => {
    try {
      return prepare(dataset.value);
    } catch (error) {
      addIssue({
        message: `${toolName} could not normalize its arguments: ${error instanceof Error ? error.message : String(error)}`,
      });
      return dataset.value;
    }
  });
}

/**
 * Convert a tool parameter schema into the top-level object schema Flue's
 * `defineTool()` requires. When the Pi tool declares `prepareArguments`, the
 * shim runs before validation exactly as in Pi's tool loop: the leading
 * `v.looseObject({})` only asserts that the model sent an object, the
 * normalized value is then validated (and coerced) by the converted schema,
 * and the whole pipe still renders as the converted schema for the model.
 * Throws when the source is not an object schema.
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
  if (!prepareArguments) return converted as ToolInputSchema;
  return v.pipe(v.looseObject({}), prepareArgumentsStep(toolName, prepareArguments), converted) as ToolInputSchema;
}

/** True when a Valibot schema satisfies Flue's top-level object requirement for tool input. */
export function isToolInputObjectSchema(schema: v.GenericSchema): boolean {
  return TOOL_INPUT_OBJECT_TYPES.has(schema.type);
}
