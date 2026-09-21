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

// Pi's `validateToolArguments` appends the raw payload after this marker.
const ECHOED_ARGUMENTS_MARKER = "Received arguments:";

export const ARGUMENTS_WITHHELD_NOTE = "(arguments withheld)";

// Shorter values are not scrubbed from free text: they are too likely to be
// ordinary substrings, and structural redaction already covers them.
const MIN_SCRUBBED_VALUE_LENGTH = 8;

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

function collectStrings(value: unknown, out: Set<string>): void {
  if (typeof value === "string") {
    if (value.length >= MIN_SCRUBBED_VALUE_LENGTH) out.add(value);
  } else if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, out);
  } else if (isPlainObject(value)) {
    for (const item of Object.values(value)) collectStrings(item, out);
  }
}

function collectSensitive(value: unknown, schema: SchemaNode | undefined, out: Set<string>): void {
  if (Array.isArray(value)) {
    for (const item of value) collectSensitive(item, asSchemaNode(schema?.items), out);
    return;
  }
  if (!isPlainObject(value)) return;
  for (const [key, entry] of Object.entries(value)) {
    const entrySchema = propertySchema(schema, key);
    if (isSensitiveArgumentKey(key) || isSensitiveSchema(entrySchema)) collectStrings(entry, out);
    else collectSensitive(entry, asSchemaNode(entrySchema), out);
  }
}

/**
 * Every string that `redactSensitiveArguments` would hide for this input
 * (including strings nested inside a sensitive object), so free text that
 * echoes the input, such as a tool's error message, can be scrubbed too.
 */
export function collectSensitiveValues(value: unknown, schema?: unknown): string[] {
  const out = new Set<string>();
  collectSensitive(value, asSchemaNode(schema), out);
  return [...out].sort((left, right) => right.length - left.length);
}

/** Replace each value, raw or JSON-escaped (as inside a serialized payload), with `[redacted]`. */
export function scrubSensitiveValues(text: string, values: readonly string[]): string {
  let scrubbed = text;
  for (const value of values) {
    const escaped = JSON.stringify(value).slice(1, -1);
    for (const needle of escaped === value ? [value] : [value, escaped]) {
      scrubbed = scrubbed.split(needle).join(REDACTED_VALUE);
    }
  }
  return scrubbed;
}

/**
 * Pi's validation errors end with the raw payload (`Received arguments:` and
 * the JSON). Keep the field-level reasons, which are what an operator needs,
 * and drop the payload; the redacted input is already on the `->` line.
 */
export function withholdEchoedArguments(errorText: string): string {
  const index = errorText.indexOf(ECHOED_ARGUMENTS_MARKER);
  if (index === -1) return errorText;
  return `${errorText.slice(0, index).trimEnd()} ${ARGUMENTS_WITHHELD_NOTE}`;
}
