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

function hasToJson(value: object): value is { toJSON: () => unknown } {
  return typeof (value as { toJSON?: unknown }).toJSON === "function";
}

function convert(value: unknown, ancestors: Set<object>): JsonValue | undefined {
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

  if (hasToJson(value)) {
    ancestors.add(value);
    try {
      return convert(value.toJSON(), ancestors);
    } finally {
      ancestors.delete(value);
    }
  }

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
