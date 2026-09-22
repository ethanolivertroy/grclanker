/**
 * Error-text hygiene for integration errors (rule 9, error-body credential class).
 *
 * Every error string an integration records (findings, summaries, access checks, `_errors.log`,
 * bundle files, tool results) is built at one of three points: an API failure constructor, the
 * conversion of a thrown value into text, or a config-loader guard. This module is the sink for the
 * first two. It never echoes a response body: `describeErrorBody` keeps only documented vendor
 * message fields and substitutes a status-and-length note for everything else, and `scrubErrorText`
 * removes credential material from whatever text is left, wherever it sits in the string.
 *
 * Distilled from the New Relic (#30), Qualys (#32), Webex (#48), and group D (#64) scrubbers on top
 * of the Flue redaction primitives in `cli/flue/redact.ts`, which own the credential key heuristic
 * and the encoded forms of a configured secret.
 */
import { Buffer } from "node:buffer";
import { REDACTED_VALUE, isSensitiveArgumentKey, scrubSensitiveValues } from "../../../flue/redact.js";

/** The marker every scrub in this library writes; the Flue marker is folded into it so one message carries one marker. */
export const REDACTED = "[REDACTED]";

/**
 * Configured secret values shorter than this are never scrubbed by value: a two-character value would
 * match ordinary prose. Values of 4 to 7 characters are replaced only where they stand as a whole
 * token, longer values wherever they appear, in every form `scrubbedFormsOf` produces (JSON-escaped,
 * URL-encoded, form-encoded, base64, base64url, re-flowed PEM lines).
 */
export const MIN_CONFIGURED_SECRET_LENGTH = 4;

/**
 * The long-token rule replaces any run of this many or more token characters that carries a digit or
 * mixed case and is not shaped like an identifier (uppercase code, camelCase or PascalCase word,
 * snake_case or Header-Case words, digits alone, canonical UUID). Error text is the only place a bare
 * token can arrive, which is why the rule is on by default there; the trade-off is that opaque
 * resource identifiers (instance ids, entity guids, hashes) are also removed from error text. Data
 * values and bundle content use `scrubDataText`, which leaves the rule off because such identifiers
 * are evidence.
 */
export const LONG_TOKEN_MIN_LENGTH = 16;

/** A documented vendor message longer than this is cut; it is one field of the body, not the body, and it can be arbitrarily long. */
export const MAX_VENDOR_MESSAGE_LENGTH = 400;

/** The longest error message `scrubError` produces after folding in cause chains and aggregate members. */
export const MAX_ERROR_MESSAGE_LENGTH = 2000;

const TRUNCATION_NOTE = " [truncated]";
const MAX_CAUSE_DEPTH = 5;
const MAX_AGGREGATE_MEMBERS = 3;
const MAX_VENDOR_MESSAGES = 5;

export interface ScrubErrorTextOptions {
  /**
   * Credential values the running client was configured with (API keys, passwords, tokens, private
   * keys). Each is removed by exact match in every encoded form; entries shorter than
   * `MIN_CONFIGURED_SECRET_LENGTH`, undefined, and null are ignored.
   */
  secrets?: ReadonlyArray<string | undefined | null>;
  /** Apply the long-token rule (see `LONG_TOKEN_MIN_LENGTH`). On unless set to false. */
  longTokens?: boolean;
}

type JsonRecord = Record<string, unknown>;

// ---------------------------------------------------------------------------------------------
// Patterns. Every pattern is unanchored so a header, URL, cookie, or name-value pair embedded anywhere
// in free text is caught, and every replacement is idempotent: text that has been scrubbed once
// comes back unchanged because `[REDACTED]` matches none of them.
// ---------------------------------------------------------------------------------------------

// PEM blocks (private keys, certificates) and an unterminated PEM header, which is redacted to the end.
const PEM_BLOCK_PATTERN = /-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----/g;
const PEM_OPEN_PATTERN = /-----BEGIN [A-Z0-9 ]+-----[\s\S]*$/;

// Any scheme-prefixed URL wherever it sits in the text: the userinfo is dropped, the query and the
// fragment are replaced, the scheme, host, and path stay because they name the surface.
const EMBEDDED_URL_PATTERN = /\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>()[\]{}]+/gi;
const URL_PARTS_PATTERN = /^([a-z][a-z0-9+.-]*:\/\/)(?:[^\s/@"'<>]+@)?([^?#]*)(\?[^#]*)?(#.*)?$/i;
const TRAILING_PUNCTUATION_PATTERN = /[.,;:!?]+$/;

// A relative path or bare query string: the named parameter keeps its name, the value goes.
const QUERY_PAIR_PATTERN = /([?&])([A-Za-z0-9_.[\]-]+)=([^&#\s"'<>]+)/g;

// Cookie and Set-Cookie headers carry session values in free form; the whole value is replaced.
const COOKIE_HEADER_PATTERN = /\b(set-cookie|cookies?)(["']?\s*[:=]\s*)(?!\[REDACTED\])[^\s<>"'][^\r\n<>"']*/gi;

// Authorization scheme values wherever they appear (`Bearer <token>`, `Basic <base64>`, Okta `SSWS`,
// GitHub `token`, Splunk `Splunk`). Scheme spellings are enumerated so `[a-z]` in the value guard
// stays case-sensitive: a plain lowercase word after the scheme ("Basic authentication") is prose.
const SCHEME_VALUE_PATTERN =
  /\b(Bearer|BEARER|bearer|Basic|BASIC|basic|Digest|digest|Token|TOKEN|token|OAuth|oauth|Negotiate|NTLM|SSWS|ApiKey|Apikey|apikey|APIKEY|Api-Key|api-key|Splunk|splunk)\s+(?![a-z]+\b)([A-Za-z0-9._~+/=-]{8,})/g;

// `key=value`, `key: value`, `"key":"value"`, and `Header-Name: value` where the key names a credential.
const ASSIGNMENT_KEY_PATTERN = /(["']?)\b([A-Za-z][A-Za-z0-9_.-]{0,63})\b(["']?\s*[:=]\s*["']?)/g;
const ASSIGNMENT_VALUE_PATTERN = /(?!\[REDACTED\])[^\s"'<>;,&]+/y;

// JWT and JWE compact serialisations, AWS access key ids, and 40-character AWS secret access keys.
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)*/g;
const AWS_ACCESS_KEY_ID_PATTERN = /\b(?:AKIA|ASIA|AROA|AIDA|AGPA|ANPA|ANVA|APKA|ABIA|ACCA)[A-Z0-9]{16}\b/g;
const AWS_SECRET_PATTERN = /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])/g;

// Vendor token prefixes that identify a credential on their own, so they are removed even when the
// long-token rule is off.
const VENDOR_TOKEN_PATTERNS: readonly RegExp[] = [
  /\bxox[abopers]-[A-Za-z0-9-]{10,}/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,}/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}/g,
  /\bglpat-[A-Za-z0-9_-]{20,}/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  /\bya29\.[0-9A-Za-z._-]{20,}/g,
  /\bNR(?:AK|II|JS|BR)-[A-Za-z0-9_-]{6,}/g,
  /\bsk_(?:live|test)_[A-Za-z0-9]{10,}/g,
  /\bdop_v1_[a-f0-9]{64}\b/g,
  /\bpypi-[A-Za-z0-9_-]{20,}/g,
  /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g,
];

// The long-token rule. "/", ".", ":", "@", and whitespace are not run characters, so URL paths, dotted
// names, timestamps, and emails split into segments that are judged on their own.
const LONG_TOKEN_RUN_PATTERN = new RegExp(`[A-Za-z0-9+=_-]{${LONG_TOKEN_MIN_LENGTH},}`, "g");
const UPPERCASE_CODE_PATTERN = /^[A-Z][A-Z_]*$|^[A-Z][A-Z0-9]*(?:[_-][A-Z0-9]+)+$/;
const DIGITS_ONLY_PATTERN = /^\d+$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const WORD_SEGMENT_PATTERN = /^(?:[A-Z]?[a-z]+|[A-Z]+|[a-z]+(?:[A-Z][a-z]+)+|(?:[A-Z][a-z]+)+)$/;

// Keys that name a credential in query strings and name-value pairs beyond what the Flue heuristic
// covers: bare `sid`, `sig`, `pwd`, `session`, `auth`, and the signed-URL parameters of S3 and GCS.
const EXTRA_CREDENTIAL_KEY_SEGMENTS = new Set(["sid", "sig", "pwd", "passwd", "pass", "session", "sessid", "auth", "nonce", "sas"]);
const EXTRA_CREDENTIAL_KEYS = new Set([
  "x-amz-signature",
  "x-amz-credential",
  "x-amz-security-token",
  "x-goog-signature",
  "x-goog-credential",
  "oauth_signature",
  "oauth_token",
  "oauth_verifier",
  "proxy-authorization",
]);

const JSON_MEDIA_TYPE_PATTERN = /^(?:application\/(?:[a-z0-9.+-]+\+)?json|text\/json)$/i;
const MEDIA_TYPE_PATTERN = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/i;
const ERROR_NAME_PATTERN = /^[A-Za-z_$][A-Za-z0-9_$]{0,63}$/;
const ERROR_CODE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$/;
const HTTP_METHOD_PATTERN = /^[A-Z]{3,10}$/;
const STATUS_TEXT_PATTERN = /^[A-Za-z0-9 '._-]{1,64}$/;
const MAX_ENDPOINT_LENGTH = 512;

// ---------------------------------------------------------------------------------------------
// Text scrubbing
// ---------------------------------------------------------------------------------------------

function keySegments(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

/**
 * True when a name in a query string, header, or name-value pair carries a credential: the Flue
 * argument-key heuristic (`token`, `secret`, `password`, `api_key`, `authorization`, `cookie`, ...)
 * plus the bare and signed-URL names it does not cover.
 */
export function isCredentialKey(key: string): boolean {
  if (isSensitiveArgumentKey(key)) return true;
  const normalized = key.toLowerCase();
  if (EXTRA_CREDENTIAL_KEYS.has(normalized)) return true;
  return keySegments(key).some((segment) => EXTRA_CREDENTIAL_KEY_SEGMENTS.has(segment));
}

/**
 * A value after a credential key is treated as the credential when it is at least six characters and
 * either carries a digit, is twelve characters or longer, contains a character that is not a letter
 * (base64 padding, path separators, punctuation), or changes case inside the word. Short plain words
 * after a colon ("InvalidAuthenticationToken: Access token has expired") are prose and stay.
 */
function looksLikeCredentialValue(value: string): boolean {
  if (value.length < 6) return false;
  if (/\d/.test(value) || value.length >= 12) return true;
  if (/[^A-Za-z]/.test(value)) return true;
  return /[a-z][A-Z]/.test(value);
}

/** A value after an authorization scheme is a credential unless it is a plain word: it carries a digit, base64 characters, mixed case, or is 20 characters or longer. */
function looksLikeSchemeValue(value: string): boolean {
  if (/\d/.test(value) || /[+/=]/.test(value) || value.length >= 20) return true;
  return /[a-z]/.test(value) && /[A-Z]/.test(value);
}

/** A 40-character run is an AWS secret access key when it carries base64 symbols or a digit with both cases; lowercase hex digests are left to the long-token rule. */
function looksLikeAwsSecret(run: string): boolean {
  if (/[/+]/.test(run)) return true;
  return /\d/.test(run) && /[a-z]/.test(run) && /[A-Z]/.test(run);
}

/** The long-token rule's identifier exclusions (see `LONG_TOKEN_MIN_LENGTH`). */
function looksLikeToken(run: string): boolean {
  if (UPPERCASE_CODE_PATTERN.test(run) || DIGITS_ONLY_PATTERN.test(run) || UUID_PATTERN.test(run)) return false;
  if (run.split(/[-_]/).every((segment) => segment.length === 0 || WORD_SEGMENT_PATTERN.test(segment))) return false;
  if (/\d/.test(run)) return true;
  return /[a-z]/.test(run) && /[A-Z]/.test(run);
}

function scrubConfiguredSecrets(text: string, secrets: ScrubErrorTextOptions["secrets"]): string {
  const values = (secrets ?? []).filter((value): value is string => typeof value === "string" && value.length >= MIN_CONFIGURED_SECRET_LENGTH);
  if (values.length === 0) return text;
  return scrubSensitiveValues(text, values).split(REDACTED_VALUE).join(REDACTED);
}

function scrubEmbeddedUrl(match: string): string {
  const trailing = TRAILING_PUNCTUATION_PATTERN.exec(match)?.[0] ?? "";
  const url = match.slice(0, match.length - trailing.length);
  const parts = URL_PARTS_PATTERN.exec(url);
  if (!parts) return match;
  const [, scheme, hostAndPath, query, fragment] = parts;
  return `${scheme}${hostAndPath}${query ? `?${REDACTED}` : ""}${fragment ? `#${REDACTED}` : ""}${trailing}`;
}

function scrubQueryPair(match: string, separator: string, key: string): string {
  return isCredentialKey(key) ? `${separator}${key}=${REDACTED}` : match;
}

function scrubSchemeValue(match: string, scheme: string, value: string): string {
  return looksLikeSchemeValue(value) ? `${scheme} ${REDACTED}` : match;
}

/**
 * Replaces the value of every credential name-value pair. The key and separator are matched on their
 * own and the value is consumed only when the key names a credential, so the value of an ordinary
 * pair is rescanned and a credential pair nested inside it (`data=token=...`) is still caught.
 */
function replaceCredentialAssignments(text: string): string {
  ASSIGNMENT_KEY_PATTERN.lastIndex = 0;
  let out = "";
  let last = 0;
  let match: RegExpExecArray | null;
  while ((match = ASSIGNMENT_KEY_PATTERN.exec(text)) !== null) {
    const [whole, openingQuote, key, separator] = match;
    if (whole.length === 0) {
      ASSIGNMENT_KEY_PATTERN.lastIndex += 1;
      continue;
    }
    if (!isCredentialKey(key)) continue;
    ASSIGNMENT_VALUE_PATTERN.lastIndex = match.index + whole.length;
    const value = ASSIGNMENT_VALUE_PATTERN.exec(text)?.[0];
    if (value === undefined || !looksLikeCredentialValue(value)) continue;
    out += `${text.slice(last, match.index)}${openingQuote}${key}${separator}${REDACTED}`;
    last = match.index + whole.length + value.length;
    ASSIGNMENT_KEY_PATTERN.lastIndex = last;
  }
  return last === 0 ? text : `${out}${text.slice(last)}`;
}

/**
 * Removes credential material from free text: the configured secrets in every encoded form, PEM
 * blocks, the userinfo, query, and fragment of every embedded URL, credential parameters of bare
 * query strings, Cookie and Set-Cookie values, authorization scheme values (Bearer, Basic, Digest,
 * Token, OAuth, Negotiate, NTLM, SSWS, ApiKey, Splunk), credential name-value pairs in prose,
 * headers, and JSON fragments, JWTs, AWS key ids and secret keys, well-known vendor token prefixes,
 * and (unless turned off) long token-shaped runs. Idempotent. Every integration error string passes
 * through here at the point it is created; a scrub at the tool boundary is a second layer, not a
 * substitute, because the exported resolvers and collectors throw before the boundary is reached.
 */
export function scrubErrorText(text: string, options: ScrubErrorTextOptions = {}): string {
  let scrubbed = scrubConfiguredSecrets(text, options.secrets);
  scrubbed = scrubbed
    .replace(PEM_BLOCK_PATTERN, REDACTED)
    .replace(PEM_OPEN_PATTERN, REDACTED)
    .replace(EMBEDDED_URL_PATTERN, scrubEmbeddedUrl)
    .replace(QUERY_PAIR_PATTERN, scrubQueryPair)
    .replace(COOKIE_HEADER_PATTERN, `$1$2${REDACTED}`)
    .replace(SCHEME_VALUE_PATTERN, scrubSchemeValue);
  scrubbed = replaceCredentialAssignments(scrubbed)
    .replace(JWT_PATTERN, REDACTED)
    .replace(AWS_ACCESS_KEY_ID_PATTERN, REDACTED)
    .replace(AWS_SECRET_PATTERN, (run) => (looksLikeAwsSecret(run) ? REDACTED : run));
  for (const pattern of VENDOR_TOKEN_PATTERNS) scrubbed = scrubbed.replace(pattern, REDACTED);
  if (options.longTokens === false) return scrubbed;
  return scrubbed.replace(LONG_TOKEN_RUN_PATTERN, (run) => (looksLikeToken(run) ? REDACTED : run));
}

/**
 * The scrub for data values and bundle content: every rule of `scrubErrorText` except the long-token
 * rule, because account ids, entity guids, policy ids, and hashes in evidence are not secrets.
 */
export function scrubDataText(text: string, options: ScrubErrorTextOptions = {}): string {
  return scrubErrorText(text, { ...options, longTokens: false });
}

export interface RedactSecretValuesOptions extends ScrubErrorTextOptions {
  /** Keys that name a policy rather than a credential (`requireStrongPassword`, `passwordCriteria`) and keep their value. */
  preserveKey?: (key: string) => boolean;
}

/**
 * Rule 9 for exported records: walks a value and replaces every entry whose key names a credential
 * (nested objects and arrays included, booleans and null excepted because a `password_required: true`
 * flag holds no credential) with `[REDACTED]`, and passes every remaining string through
 * `scrubDataText`. Arrays and plain objects are copied; other objects are returned as they are.
 */
export function redactSecretValues(value: unknown, options: RedactSecretValuesOptions = {}): unknown {
  if (typeof value === "string") return scrubDataText(value, options);
  if (Array.isArray(value)) return value.map((item) => redactSecretValues(item, options));
  if (!isPlainObject(value)) return value;
  const output: JsonRecord = {};
  for (const [key, entry] of Object.entries(value)) {
    const credential = isCredentialKey(key) && !(options.preserveKey?.(key) ?? false);
    output[key] = credential && entry !== null && entry !== undefined && typeof entry !== "boolean" ? REDACTED : redactSecretValues(entry, options);
  }
  return output;
}

// ---------------------------------------------------------------------------------------------
// Response bodies
// ---------------------------------------------------------------------------------------------

function isPlainObject(value: unknown): value is JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function asRecord(value: unknown): JsonRecord | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as JsonRecord) : undefined;
}

function asText(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value : undefined;
}

function truncate(text: string, limit: number): string {
  return text.length <= limit ? text : `${text.slice(0, limit)}${TRUNCATION_NOTE}`;
}

/** The media type of a Content-Type header value, lowercased and without parameters; "unknown" when missing or malformed. */
export function mediaTypeOf(contentType: string | null | undefined): string {
  const type = (contentType ?? "").split(";")[0].trim().toLowerCase();
  return MEDIA_TYPE_PATTERN.test(type) ? type : "unknown";
}

function parseJsonValue(rawText: string): unknown {
  try {
    return JSON.parse(rawText);
  } catch {
    return undefined;
  }
}

const MESSAGE_FIELDS = ["message", "Message", "errorMessage", "error_description", "errorSummary", "title", "detail", "description"] as const;
const MEMBER_LIST_FIELDS = ["errors", "errorCauses", "messages"] as const;

/**
 * The documented message fields of a JSON error body: `message`, `error` (when it is a string),
 * `error_description`, `errorSummary`, RFC 7807 `title` and `detail`, the same fields under `error`,
 * and the `message`, `detail`, `title`, `description`, or `errorSummary` of each member of `errors`,
 * `errorCauses`, or `messages`. Nothing else in the body is read.
 */
function documentedMessages(payload: unknown): string[] {
  const root = asRecord(payload);
  if (!root) return [];
  const found: string[] = [];
  const push = (value: unknown): void => {
    const text = asText(value);
    if (text && !found.includes(text) && found.length < MAX_VENDOR_MESSAGES) found.push(text);
  };
  const readFields = (record: JsonRecord): void => {
    for (const field of MESSAGE_FIELDS) push(record[field]);
  };
  readFields(root);
  push(root.error);
  const nested = asRecord(root.error);
  if (nested) readFields(nested);
  for (const field of MEMBER_LIST_FIELDS) {
    const members = root[field] ?? nested?.[field];
    if (!Array.isArray(members)) continue;
    for (const member of members) {
      push(member);
      const record = asRecord(member);
      if (record) readFields(record);
    }
  }
  return found;
}

/**
 * What a response body contributes to an error string. A body declared and parseable as JSON
 * contributes only its documented message fields, scrubbed and cut at `MAX_VENDOR_MESSAGE_LENGTH`;
 * a body that is not declared JSON (a proxy's HTML page, a sign-in redirect), or that does not
 * parse, contributes `non-JSON body (<media type>, <n> bytes)` or `malformed JSON body (...)` and
 * never a slice of its text; an empty body contributes `empty body`. The status does not change the
 * description: a 200 with a non-JSON body is an unreadable surface for the caller to record, not an
 * empty inventory.
 */
export function describeErrorBody(contentType: string | null | undefined, rawText: string, options: ScrubErrorTextOptions = {}): string {
  const bytes = Buffer.byteLength(rawText, "utf8");
  if (bytes === 0) return "empty body";
  const mediaType = mediaTypeOf(contentType);
  if (!JSON_MEDIA_TYPE_PATTERN.test(mediaType)) return `non-JSON body (${mediaType}, ${bytes} bytes)`;
  const payload = parseJsonValue(rawText);
  if (payload === undefined) return `malformed JSON body (${mediaType}, ${bytes} bytes)`;
  const messages = documentedMessages(payload).map((message) => truncate(scrubErrorText(message, options), MAX_VENDOR_MESSAGE_LENGTH));
  if (messages.length === 0) return `JSON body without a documented message field (${bytes} bytes)`;
  return messages.join("; ");
}

export interface FailedResponse {
  method: string;
  /** The request URL or path; its query string is scrubbed with the rest of the message. */
  endpoint: string;
  status: number;
  statusText?: string | null;
  contentType?: string | null;
  /** The raw body text; described, never echoed. */
  body: string;
}

/**
 * The standard message for a failed HTTP request: `GET /v1/users failed with 502 Bad Gateway:
 * non-JSON body (text/html, 1234 bytes)`. The status text comes from the server and is kept only
 * when it is a short plain reason phrase; the body goes through `describeErrorBody`.
 */
export function describeFailedResponse(response: FailedResponse, options: ScrubErrorTextOptions = {}): string {
  const method = HTTP_METHOD_PATTERN.test(response.method) ? response.method : "Request";
  const statusText = response.statusText && STATUS_TEXT_PATTERN.test(response.statusText) ? ` ${response.statusText.trim()}` : "";
  const status = validHttpStatus(response.status) ?? "unknown status";
  return scrubErrorText(`${method} ${response.endpoint} failed with ${status}${statusText}: ${describeErrorBody(response.contentType, response.body, options)}`, options);
}

// ---------------------------------------------------------------------------------------------
// Thrown values
// ---------------------------------------------------------------------------------------------

/** A thrown value reduced to fixed fields; every string was scrubbed and no response body was read. */
export interface ScrubbedError {
  name: string;
  message: string;
  /** A short error code (`ECONNREFUSED`, `AccessDeniedException`, `E0000011`) when the value carried one that is shaped like a code. */
  code?: string;
  /** The HTTP status the value carried (`status`, `statusCode`, AWS SDK `$metadata.httpStatusCode`, `response.status`). */
  status?: number;
  /** The request URL or path the value carried, scrubbed. */
  endpoint?: string;
}

function validHttpStatus(value: unknown): number | undefined {
  return typeof value === "number" && Number.isInteger(value) && value >= 100 && value <= 599 ? value : undefined;
}

function validErrorCode(value: unknown): string | undefined {
  if (typeof value === "number" && Number.isInteger(value)) return String(value);
  return typeof value === "string" && ERROR_CODE_PATTERN.test(value) ? value : undefined;
}

function errorNameOf(record: JsonRecord): string {
  return typeof record.name === "string" && ERROR_NAME_PATTERN.test(record.name) ? record.name : "Error";
}

function statusOf(record: JsonRecord): number | undefined {
  const metadata = asRecord(record.$metadata);
  const response = asRecord(record.response) ?? asRecord(record.$response);
  return (
    validHttpStatus(record.status) ??
    validHttpStatus(record.statusCode) ??
    validHttpStatus(record.httpStatusCode) ??
    validHttpStatus(metadata?.httpStatusCode) ??
    validHttpStatus(response?.status) ??
    validHttpStatus(response?.statusCode)
  );
}

function endpointOf(record: JsonRecord, options: ScrubErrorTextOptions): string | undefined {
  const request = asRecord(record.request);
  const candidate = asText(record.endpoint) ?? asText(record.path) ?? asText(record.url) ?? asText(request?.url) ?? asText(request?.path);
  if (!candidate || candidate.length > MAX_ENDPOINT_LENGTH) return undefined;
  return scrubErrorText(candidate, options);
}

function scrubErrorValue(value: unknown, options: ScrubErrorTextOptions, seen: Set<object>, depth: number): ScrubbedError {
  if (typeof value === "string") return { name: "Error", message: scrubErrorText(value, options) };
  if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") return { name: "Error", message: String(value) };
  if (value === null || value === undefined) return { name: "Error", message: "unknown error" };
  if (typeof value !== "object" && typeof value !== "function") return { name: "Error", message: "unknown error" };
  const record = value as JsonRecord;
  const name = errorNameOf(record);
  if (seen.has(value) || depth > MAX_CAUSE_DEPTH) return { name, message: "cause chain truncated" };
  seen.add(value);

  const ownMessage = asText(record.message) ?? asText(record.error) ?? asText(record.error_description);
  const parts = [ownMessage ? scrubErrorText(ownMessage, options) : `${name} without a message`];
  let code = validErrorCode(record.code) ?? validErrorCode(record.Code);
  let status = statusOf(record);
  let endpoint = endpointOf(record, options);

  const members = Array.isArray(record.errors) ? record.errors : [];
  if (members.length > 0) {
    const summaries = members.slice(0, MAX_AGGREGATE_MEMBERS).map((member) => scrubErrorValue(member, options, seen, depth + 1));
    const rest = members.length > MAX_AGGREGATE_MEMBERS ? `; and ${members.length - MAX_AGGREGATE_MEMBERS} more` : "";
    parts.push(`(${members.length} error${members.length === 1 ? "" : "s"}: ${summaries.map((summary) => summary.message).join("; ")}${rest})`);
    for (const summary of summaries) {
      code ??= summary.code;
      status ??= summary.status;
      endpoint ??= summary.endpoint;
    }
  }
  if (record.cause !== undefined && record.cause !== null) {
    const cause = scrubErrorValue(record.cause, options, seen, depth + 1);
    parts.push(`(cause: ${cause.message})`);
    code ??= cause.code;
    status ??= cause.status;
    endpoint ??= cause.endpoint;
  }

  const scrubbed: ScrubbedError = { name, message: truncate(parts.join(" "), MAX_ERROR_MESSAGE_LENGTH) };
  if (code !== undefined) scrubbed.code = code;
  if (status !== undefined) scrubbed.status = status;
  if (endpoint !== undefined) scrubbed.endpoint = endpoint;
  return scrubbed;
}

/**
 * Reduces any thrown value to `{ name, message, code?, status?, endpoint? }`: Error instances,
 * AggregateError members, `cause` chains (up to five deep, cycles cut), AWS SDK errors (`$metadata`,
 * `$response`), plain objects, and strings. Only the `message`, `error`, and `error_description`
 * strings are read for text and each is scrubbed; a custom `toString`, a response body field such
 * as `$responseBodyText`, and every other property are never read, so a foreign object thrown by a
 * client library cannot smuggle a body or a credential into the recorded text.
 */
export function scrubError(error: unknown, options: ScrubErrorTextOptions = {}): ScrubbedError {
  return scrubErrorValue(error, options, new Set<object>(), 0);
}

/** The one-line form of `scrubError`: the scrubbed message with cause chain folded in and whitespace collapsed. */
export function errorMessage(error: unknown, options: ScrubErrorTextOptions = {}): string {
  return scrubError(error, options).message.replace(/\s+/g, " ").trim();
}

export interface IntegrationErrorDetails {
  /** HTTP status the request observed; omitted for transport failures. */
  status?: number;
  /** The request URL or path; scrubbed before it is stored. */
  endpoint?: string;
  /** A short vendor or transport error code; stored only when it is shaped like a code. */
  code?: string;
  /** The underlying thrown value, kept as `cause` for `scrubError` to fold in. */
  cause?: unknown;
}

/**
 * Base class for every integration's API error. The constructor scrubs its own message with
 * `scrubErrorText` (configured secrets included when passed), so a subclass such as
 * `class QualysApiError extends IntegrationError {}` gets the rule 9 sink for free and no site that
 * builds a failure message can hand an unscrubbed string to the errors array, a status field, a
 * summary, `_errors.log`, or a tool result. `status`, `endpoint`, and `code` are validated fields
 * for callers that branch on them; `name` follows the subclass.
 */
export class IntegrationError extends Error {
  readonly status: number | undefined;
  readonly endpoint: string | undefined;
  readonly code: string | undefined;

  constructor(message: string, details: IntegrationErrorDetails = {}, options: ScrubErrorTextOptions = {}) {
    super(scrubErrorText(message, options), details.cause === undefined ? undefined : { cause: details.cause });
    this.name = new.target.name || "IntegrationError";
    this.status = validHttpStatus(details.status);
    this.endpoint = details.endpoint === undefined ? undefined : scrubErrorText(details.endpoint, options);
    this.code = validErrorCode(details.code);
  }
}
