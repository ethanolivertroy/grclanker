/**
 * Redaction of credential-bearing tool arguments before they are logged.
 *
 * Tool calls are the one place credentials legitimately travel as plain
 * values (Cloudflare `api_token`, Okta `private_key`, GitHub
 * `app_private_key`, Zoom and Vanta `client_secret`, Duo `skey`, ...), so any
 * activity line that echoes a tool input has to go through here first.
 */

export const REDACTED_VALUE = "[redacted]";

// Matched against each argument name, case-insensitively, at any depth. The
// Duo integration and secret keys (`ikey`, `skey`) are listed by name.
const SENSITIVE_KEY_PATTERN = /token|secret|pass(?:word|wd|phrase)|private_?key|api_?key|credential|authorization|assertion|^[is]key$/i;

type SchemaNode = Record<string, unknown>;

function asSchemaNode(value: unknown): SchemaNode | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as SchemaNode;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/** True when an argument name looks like it carries a credential. */
export function isSensitiveArgumentKey(key: string): boolean {
  return SENSITIVE_KEY_PATTERN.test(key);
}

/**
 * True when a JSON Schema property is marked sensitive: the standard
 * `writeOnly` and `format: "password"` markers, or a `sensitive: true`
 * annotation on the tool's TypeBox schema.
 */
export function isSensitiveSchema(schema: unknown): boolean {
  const node = asSchemaNode(schema);
  if (!node) return false;
  return node.writeOnly === true || node.format === "password" || node.sensitive === true;
}

function propertySchema(schema: SchemaNode | undefined, key: string): unknown {
  if (!schema) return undefined;
  const properties = asSchemaNode(schema.properties);
  if (properties && key in properties) return properties[key];
  return asSchemaNode(schema.additionalProperties);
}

/**
 * Return a copy of `value` safe to log: every entry whose key matches the
 * sensitive pattern, or whose schema marks it sensitive, is replaced by
 * `[redacted]` wholesale (nested objects and arrays included), and the rest is
 * walked recursively. `schema` is the tool's JSON Schema parameters, when known.
 */
export function redactSensitiveArguments(value: unknown, schema?: unknown): unknown {
  const node = asSchemaNode(schema);

  if (Array.isArray(value)) {
    return value.map((item) => redactSensitiveArguments(item, node?.items));
  }

  if (!isPlainObject(value)) return value;

  const redacted: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) {
    const entrySchema = propertySchema(node, key);
    redacted[key] =
      isSensitiveArgumentKey(key) || isSensitiveSchema(entrySchema) ? REDACTED_VALUE : redactSensitiveArguments(entry, entrySchema);
  }
  return redacted;
}
