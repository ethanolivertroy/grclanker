/**
 * Redaction of credential-bearing tool arguments before they are logged.
 *
 * Tool calls are the one place credentials legitimately travel as plain
 * values (Cloudflare `api_token`, Okta `private_key`, GitHub
 * `app_private_key`, Zoom and Vanta `client_secret`, Duo `skey`, ...), so any
 * activity line that echoes a tool input has to go through here first.
 */
import { Buffer } from "node:buffer";
import { URLSearchParams } from "node:url";

export const REDACTED_VALUE = "[redacted]";

// Names shaped like thresholds, durations, counts, or file references are
// never credentials (`max_keys`, `token_limit`, `stale_token_days`,
// `credentials_file`, `app_private_key_path`) and stay visible.
const SAFE_SHAPE_PATTERN = /^(?:max|min)[_-]|[_-](?:limit|days|hours|minutes|seconds|count|path|file|dir)$/i;

// Words that name a credential wherever they appear inside a key. The last
// alternative covers concatenated spellings such as `apikey` or `privatekey`,
// which the segment rule below cannot see.
const SENSITIVE_SUBSTRING_PATTERN =
  /token|secret|passw|passphrase|passcode|credential|authorization|assertion|bearer|hmac|signature|kubeconfig|connection[_-]?string|webhook[_-]?url|session[_-]?id|auth[_-]?header|basic[_-]?auth|(?:api|private|secret|access|signing|encryption|master|shared|account|client|service|session|license|ssh|hmac)[_-]?keys?/i;

// Short words that only count as whole segments of a key (`api_key`, `pin_code`,
// `sas_url`, Duo's `ikey` and `skey`), never as substrings (`keyword`, `monkey`).
const SENSITIVE_KEY_SEGMENTS = new Set(["key", "keys", "pin", "otp", "totp", "jwt", "dsn", "sas", "pem", "cookie", "cookies", "ikey", "skey"]);

// Pi's `validateToolArguments` appends the raw payload after this marker.
const ECHOED_ARGUMENTS_MARKER = "Received arguments:";

export const ARGUMENTS_WITHHELD_NOTE = "(arguments withheld)";

// A value (or one of its forms) this long is scrubbed wherever it appears.
const MIN_SCRUBBED_VALUE_LENGTH = 8;

// Shorter values are scrubbed only as whole tokens, so a four-digit passcode
// disappears from "passcode 4711 rejected" but ordinary substrings survive.
// Anything shorter than this is not scrubbed at all.
const MIN_WHOLE_TOKEN_VALUE_LENGTH = 4;

const TOKEN_CHARACTER = /[A-Za-z0-9]/;

type SchemaNode = Record<string, unknown>;

interface ScrubNeedle {
  text: string;
  lower: string;
  wholeToken: boolean;
}

function asSchemaNode(value: unknown): SchemaNode | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return value as SchemaNode;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function keySegments(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

/** True when an argument name looks like it carries a credential. */
export function isSensitiveArgumentKey(key: string): boolean {
  if (SAFE_SHAPE_PATTERN.test(key)) return false;
  if (SENSITIVE_SUBSTRING_PATTERN.test(key)) return true;
  return keySegments(key).some((segment) => SENSITIVE_KEY_SEGMENTS.has(segment));
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

function collectScalars(value: unknown, out: Set<string>): void {
  if (typeof value === "string") {
    if (value.length >= MIN_WHOLE_TOKEN_VALUE_LENGTH) out.add(value);
  } else if (typeof value === "number" || typeof value === "bigint") {
    // A numeric secret echoes in its decimal form, which is what JSON.stringify prints too.
    const text = String(value);
    if (text.length >= MIN_WHOLE_TOKEN_VALUE_LENGTH) out.add(text);
  } else if (Array.isArray(value)) {
    for (const item of value) collectScalars(item, out);
  } else if (isPlainObject(value)) {
    for (const item of Object.values(value)) collectScalars(item, out);
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
    if (isSensitiveArgumentKey(key) || isSensitiveSchema(entrySchema)) collectScalars(entry, out);
    else collectSensitive(entry, asSchemaNode(entrySchema), out);
  }
}

/**
 * Every value that `redactSensitiveArguments` would hide for this input
 * (including values nested inside a sensitive object, and numbers in their
 * decimal form), so free text that echoes the input, such as a tool's error
 * message, can be scrubbed too. Longest first.
 */
export function collectSensitiveValues(value: unknown, schema?: unknown): string[] {
  const out = new Set<string>();
  collectSensitive(value, asSchemaNode(schema), out);
  return [...out].sort((left, right) => right.length - left.length);
}

/** The URI-component form (`encodeURIComponent`): spaces become `%20`, and `~ ! ' ( ) *` stay as they are. */
function urlEncoded(value: string): string | undefined {
  try {
    return encodeURIComponent(value);
  } catch {
    return undefined;
  }
}

/**
 * The application/x-www-form-urlencoded form `URLSearchParams` produces for a
 * field value, as in an echoed request body: spaces become `+`, and
 * `~ ! ' ( ) *` are percent-encoded.
 */
function formEncoded(value: string): string {
  return new URLSearchParams({ v: value }).toString().slice("v=".length);
}

/**
 * The forms a tool might echo a secret in: as is, JSON-escaped (inside a
 * serialized payload), URL-encoded as a URI component and as a form field,
 * base64 (with and without padding, and URL-encoded) and base64url, re-flowed
 * onto one line, and each individual line of a multi-line value such as a PEM
 * key.
 */
export function scrubbedFormsOf(value: string): string[] {
  const lines = value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  const bytes = Buffer.from(value, "utf8");
  const base64 = bytes.toString("base64");
  const forms = new Set<string>([
    value,
    JSON.stringify(value).slice(1, -1),
    formEncoded(value),
    base64,
    base64.replace(/=+$/, ""),
    bytes.toString("base64url"),
    lines.join(" "),
    lines.join(""),
    ...lines,
  ]);
  // Base64 output has no spaces or `~ ! ' ( ) *`, so its form-encoded and URI-component forms coincide.
  for (const encoded of [urlEncoded(value), urlEncoded(base64)]) {
    if (encoded !== undefined) forms.add(encoded);
  }
  return [...forms];
}

function buildNeedles(values: readonly string[]): ScrubNeedle[] {
  const seen = new Set<string>();
  const needles: ScrubNeedle[] = [];
  for (const value of values) {
    for (const form of scrubbedFormsOf(value)) {
      const lower = form.toLowerCase();
      if (form.length < MIN_WHOLE_TOKEN_VALUE_LENGTH || seen.has(lower)) continue;
      seen.add(lower);
      needles.push({ text: form, lower, wholeToken: form.length < MIN_SCRUBBED_VALUE_LENGTH });
    }
  }
  return needles.sort((left, right) => right.text.length - left.text.length);
}

function isTokenBoundary(text: string, index: number): boolean {
  return index < 0 || index >= text.length || !TOKEN_CHARACTER.test(text[index]);
}

/** Lower-case `text` for index-preserving comparison, or undefined when folding would move indexes. */
function foldCase(text: string): string | undefined {
  const lower = text.toLowerCase();
  return lower.length === text.length ? lower : undefined;
}

function replaceNeedle(text: string, needle: ScrubNeedle): string {
  const folded = foldCase(text);
  const haystack = folded ?? text;
  const target = folded === undefined ? needle.text : needle.lower;
  let out = "";
  let last = 0;
  let from = 0;
  while (from <= haystack.length - target.length) {
    const index = haystack.indexOf(target, from);
    if (index === -1) break;
    const end = index + target.length;
    if (!needle.wholeToken || (isTokenBoundary(text, index - 1) && isTokenBoundary(text, end))) {
      out += `${text.slice(last, index)}${REDACTED_VALUE}`;
      last = end;
      from = end;
    } else {
      from = index + 1;
    }
  }
  return last === 0 ? text : `${out}${text.slice(last)}`;
}

/**
 * Replace each collected value with `[redacted]` in every form
 * `scrubbedFormsOf` produces, matching case-insensitively. Forms shorter than
 * eight characters are replaced only where they stand as a whole token.
 */
export function scrubSensitiveValues(text: string, values: readonly string[]): string {
  let scrubbed = text;
  for (const needle of buildNeedles(values)) scrubbed = replaceNeedle(scrubbed, needle);
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
