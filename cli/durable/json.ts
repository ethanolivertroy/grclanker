/**
 * Strict JSON for values that enter a durable session.
 *
 * Chord stores tool details and documents as strict JSON and rejects
 * `undefined`, non-finite numbers, and anything else JSON cannot round-trip.
 * The native tools build their details for Pi, which never had that rule, so
 * every value crossing into the session goes through `toStrictJson()`.
 *
 * The result matches `JSON.parse(JSON.stringify(value))` wherever that
 * succeeds. Where `JSON.stringify` would throw, a bigint becomes its decimal
 * string and a cycle becomes `"[Circular]"`. Errors keep their name and message
 * instead of collapsing to `{}`, and `__proto__` keys are dropped.
 */
import type { JsonValue } from "@earendil-works/chord";
import type { JsonObject } from "@earendil-works/pi-durable";

export const CIRCULAR_PLACEHOLDER = "[Circular]";

/** `JSON.stringify` looks for `toJSON` on objects, functions, and bigints. */
function hasToJson(value: unknown): value is { toJSON: () => unknown } {
  const kind = typeof value;
  if (value === null || (kind !== "object" && kind !== "function" && kind !== "bigint")) return false;
  return typeof (value as { toJSON?: unknown }).toJSON === "function";
}

/** What `JSON.stringify` serializes in place of `value`: its `toJSON()` result, with boxed primitives unwrapped. */
function serializationInput(value: unknown): unknown {
  const replaced = hasToJson(value) ? value.toJSON() : value;
  if (replaced instanceof Number) return Number(replaced);
  if (replaced instanceof String) return String(replaced);
  if (replaced instanceof Boolean || replaced instanceof BigInt) return replaced.valueOf();
  return replaced;
}

function isReference(value: unknown): value is object {
  return (typeof value === "object" && value !== null) || typeof value === "function";
}

function convert(input: unknown, ancestors: Set<object>): JsonValue | undefined {
  if (isReference(input) && ancestors.has(input)) return CIRCULAR_PLACEHOLDER;
  const value = serializationInput(input);
  if (value === input || !isReference(input)) return convertValue(value, ancestors);
  // The original stays on the path while its replacement converts, so a `toJSON()` that wraps its own object ends as a cycle.
  ancestors.add(input);
  try {
    return convertValue(value, ancestors);
  } finally {
    ancestors.delete(input);
  }
}

function convertValue(value: unknown, ancestors: Set<object>): JsonValue | undefined {
  const kind = typeof value;
  switch (kind) {
    case "string":
    case "boolean":
      return value as string | boolean;
    case "number": {
      const number = value as number;
      if (!Number.isFinite(number)) return null;
      return Object.is(number, -0) ? 0 : number;
    }
    case "bigint":
      return (value as bigint).toString();
    case "undefined":
    case "function":
    case "symbol":
      return undefined;
    case "object":
      break;
    default: {
      const exhaustive: never = kind;
      throw new Error(`Unhandled value type: ${String(exhaustive)}`);
    }
  }

  if (value === null || typeof value !== "object") return null;
  if (ancestors.has(value)) return CIRCULAR_PLACEHOLDER;

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const items: JsonValue[] = [];
      for (let index = 0; index < value.length; index += 1) {
        items.push(convert(value[index], ancestors) ?? null);
      }
      return items;
    }

    const result: JsonObject = {};
    if (value instanceof Error) {
      result.name = value.name;
      result.message = value.message;
    }
    for (const key of Object.keys(value)) {
      if (key === "__proto__") continue;
      const converted = convert((value as Record<string, unknown>)[key], ancestors);
      if (converted !== undefined) result[key] = converted;
    }
    return result;
  } finally {
    ancestors.delete(value);
  }
}

/** The strict-JSON form of `value`; `undefined` when JSON would omit it (undefined, functions, symbols). */
export function toStrictJson(value: unknown): JsonValue | undefined {
  return convert(value, new Set());
}

export function isJsonObject(value: JsonValue | undefined): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
