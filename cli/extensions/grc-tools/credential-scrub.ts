/**
 * Credential scrub for integration error text (rule 9, error-body credential class, and the coordinator's ruling on
 * the scrub boundary).
 *
 * Every error string the Box, Datadog, Elastic, KnowBe4, and LaunchDarkly integrations record (findings, summaries,
 * analysis objects, access surfaces, `_errors.log`, tool results, the bundle) passes through a scrubber built here.
 * The boundary is the coordinator's: a bare value shaped like a name (words joined by hyphens or underscores, digits
 * standing in whole segments, such as `prod-us-east-2026` or `sess-canary-COOKIE-31415926535897`) is
 * indistinguishable from a resource name and stays. Two guards make that safe, and both are construction requirements:
 *
 * 1. A value inside a carrier is removed whatever its shape: Authorization, Proxy-Authorization, Cookie, Set-Cookie,
 *    x-api-key and similar headers; cookie and session assignments; URL userinfo and query pairs; the schemes Bearer,
 *    Basic, Token, and ApiKey; credential-named key/value pairs (`token=`, `"password":`, `api_key:`). A quoted value
 *    (`X-Api-Key: "value"`, `Cookie: sid='value'`, `Authorization: Bearer "value"`, the JSON pair
 *    `"Authorization": "Bearer value"`, and their JSON-escaped forms `\"X-Api-Key\": \"value\"`) is removed whole up to
 *    its closing quote, spaces and all, with the quotes and the scheme word kept.
 * 2. A configured secret is removed whatever its shape and in its base64, base64url, URL-encoded, form-encoded, and
 *    JSON-escaped forms; the Flue redaction primitives own the encoded forms.
 *
 * Real token shapes are removed bare: runs of 16 or more characters with base64 symbols, digits scattered through
 * letters, or token casing; hex digests; JWTs; AWS access key ids and secret keys; PEM blocks; and well-known vendor
 * prefixes. Every rule is unanchored so a carrier embedded mid-sentence is caught, and every replacement is idempotent:
 * scrubbed text comes back unchanged because `[REDACTED]` matches none of the rules.
 *
 * The same rules run over collected data (`scrubData`): every string in every record written to core_data, an analysis
 * object, or finding evidence gets the pattern pass above, so a query token, a bearer value, an assignment pair, or a
 * bare token inside free text (a terms-of-service body, an audit comment, a monitor note, a settings value) goes the
 * way it would in an error message; and the whole subtree under a credential-shaped key is replaced, arrays and
 * nested objects included, so `tokens: ["..."]` and `credentials: { value }` cannot keep what their key names.
 */
import { REDACTED_VALUE, isSensitiveArgumentKey, scrubSensitiveValues } from "../../flue/redact.js";

/** The marker every scrub writes; the Flue marker is folded into it so one message carries one marker. */
export const REDACTED = "[REDACTED]";

// A control-character sentinel no API text carries; it parks a pre-existing Flue marker across a secret scrub.
const PRESERVED_MARKER_SENTINEL = "\u0000\u0001redacted\u0001\u0000";

/**
 * Configured secrets shorter than this are never scrubbed by value because a two-character value would match ordinary
 * prose. Values of 4 to 7 characters are replaced only where they stand as a whole token, longer values wherever they
 * appear, in every encoded form.
 */
export const MIN_CONFIGURED_SECRET_LENGTH = 4;

/** A run of token characters this long or longer is judged by the long-token rule (see `looksLikeToken`). */
export const LONG_TOKEN_MIN_LENGTH = 16;

export interface CredentialScrubberOptions {
  /** Header names (matched case-insensitively) whose values are credentials, in addition to the common set. */
  headers?: readonly string[];
  /** Vendor token shapes removed bare wherever they appear, in addition to the common set. Each must carry the `g` flag. */
  vendorPatterns?: readonly RegExp[];
}

export interface ScrubTextOptions {
  /**
   * Whether bare values are judged by shape (the long-token, hex digest, and AWS secret rules). Off for a string
   * stored under an identifier key, where a base64 API key id or a cluster UUID is a name, not a credential; carriers,
   * configured secrets, JWTs, PEM blocks, and vendor prefixes are removed either way.
   */
  shapes?: boolean;
}

export interface ScrubDataOptions {
  /**
   * True for a key whose whole subtree is a credential (`token`, `tokens`, `credentials`, `client_secret`, ...). The
   * module's own key rule when given, so vendor field names are honoured (a LaunchDarkly flag `key` or an Elastic
   * `api_keys` inventory container is not a credential); `isCredentialDataKey` otherwise. The header and query rule
   * `isCredentialKey` is deliberately not used here: it treats a bare `key` as sensitive, which is right for a query
   * string and wrong for a record. The enclosing record's key is passed as well (undefined at the root or inside an
   * array), so a rule that reads a bare `key` under `ssl`, `tls`, or `keystore` as a private key can apply.
   */
  isCredentialKey?: (key: string, parentKey?: string) => boolean;
  /**
   * Rewrites a string before the pattern pass, given the key it is stored under (undefined inside an array or at the
   * root): the module's URL-key reduction, request-label allowances, and similar field-aware rules.
   */
  transformString?: (value: string, key: string | undefined) => string;
  /**
   * Nesting deeper than this is replaced by the marker: containers and strings alike, so a string one level past the
   * cap cannot skip the pattern pass. Numbers, booleans, and nulls pass through.
   */
  maxDepth?: number;
}

export interface CredentialScrubber {
  /** Removes credential material from error text under every rule of this module. Idempotent. */
  scrub(text: string, options?: ScrubTextOptions): string;
  /**
   * Data-side scrub for a collected record (see `scrubDataValue`): the whole subtree under a credential-shaped key
   * becomes the marker, `{name, value}` pairs with a credential-shaped name lose their value, and every string runs
   * through `scrub`, with shape rules off under identifier keys. Shape is otherwise preserved.
   */
  scrubData(value: unknown, options?: ScrubDataOptions): unknown;
  /**
   * Registers configured secret values (API keys, tokens, passwords, private keys); each is removed from every string
   * scrubbed from then on, in every encoded form. Entries shorter than `MIN_CONFIGURED_SECRET_LENGTH`, undefined, and
   * null are ignored.
   */
  registerSecrets(values: ReadonlyArray<string | undefined | null>): void;
  /** The configured secrets registered so far, in their plain form. */
  readonly secrets: ReadonlySet<string>;
}

/** Default nesting cap for `scrubData`. */
export const DEFAULT_DATA_SCRUB_DEPTH = 24;

// Keys whose string value names a thing rather than proving possession of it: an API key id, a cluster or node UUID,
// a digest, an etag. Shape rules are off under them; carriers and configured secrets still apply.
const IDENTIFIER_KEY_SEGMENTS = new Set(["id", "ids", "uuid", "uuids", "guid", "guids", "sha", "sha1", "sha256", "sha512", "md5", "hash", "digest", "fingerprint", "etag", "checksum"]);

// The conservative record-key rule: the last segment names a credential outright, or is `key`/`keys` qualified by a
// word that makes it one (`api_key`, `private_keys`, `client_key`); a bare `key`, `keys`, or `id` is an identifier.
const CREDENTIAL_DATA_LAST_SEGMENTS = new Set([
  "token", "tokens", "secret", "secrets", "password", "passwords", "passwd", "pwd", "passphrase", "passphrases", "apikey",
  "apikeys", "appkey", "appkeys", "applicationkey", "applicationkeys", "authorization", "credential", "credentials", "bearer",
  "privatekey", "privatekeys",
]);
const CREDENTIAL_DATA_KEY_QUALIFIERS = new Set([
  "api", "app", "application", "private", "secret", "signing", "access", "shared", "encryption", "session", "master", "client",
  "auth", "sdk", "mobile", "relay", "service", "license", "ssh", "hmac", "enrollment",
]);

// An id that is itself the credential (rule 9): possession of a Vault AppRole `secret_id` (a UUID, which the identifier
// rule would otherwise keep) or of a session id (`session_id`, `sid`, `JSESSIONID`, `PHPSESSID`, `ASP.NET_SessionId`)
// is what authenticates. These keys are credential keys on both sides whatever the value's shape, checked before the
// setting-suffix and identifier rules; any prefix, casing, and separator (`VAULT_SECRET_ID`, `role_secret_id`,
// `roleSecretId`). Every other `*_id` names a thing and stays an identifier: `client_id`, `enterprise_id`, `key_id`,
// `api_key_id`, `tenant_id`, `token_id`, `access_key_id` (an AWS access key id is removed by its `AKIA` shape), and
// `secret_name` likewise (CodeRabbit on #78, r4077259415).
const BEARER_ID_LAST_SEGMENTS = new Set(["secretid", "sid", "sessid", "sessionid", "jsessionid", "phpsessid", "aspnetsessionid"]);
const BEARER_ID_QUALIFIERS = new Set(["secret", "session"]);

/** True for a key whose id value is itself a bearer credential: `secret_id` and the session-id keys, in any spelling. */
export function isBearerIdKey(key: string): boolean {
  const segments = keySegments(key);
  const last = segments[segments.length - 1];
  if (last === undefined) return false;
  if (BEARER_ID_LAST_SEGMENTS.has(last)) return true;
  return last === "id" && segments.length >= 2 && BEARER_ID_QUALIFIERS.has(segments[segments.length - 2]);
}

/** True for a record key whose whole value is a credential under the conservative rule above. */
export function isCredentialDataKey(key: string): boolean {
  if (isBearerIdKey(key)) return true;
  const segments = keySegments(key);
  const last = segments[segments.length - 1];
  if (!last) return false;
  if (CREDENTIAL_DATA_LAST_SEGMENTS.has(last)) return true;
  if (last === "key" || last === "keys") return segments.slice(0, -1).some((segment) => CREDENTIAL_DATA_KEY_QUALIFIERS.has(segment));
  return false;
}

/** True when the last segment of the key names an identifier or digest. */
export function isIdentifierKey(key: string): boolean {
  const segments = keySegments(key);
  const last = segments[segments.length - 1];
  return last !== undefined && IDENTIFIER_KEY_SEGMENTS.has(last) && !isCredentialDataKey(key);
}

function isNameValuePair(record: Record<string, unknown>): string | undefined {
  if (!("value" in record)) return undefined;
  const name = record.name ?? record.key;
  return typeof name === "string" ? name : undefined;
}

/**
 * Walks a collected record. Under a credential-shaped key the whole entry goes, whether it is a string, an array
 * (`tokens: ["..."]`), an object (`credentials: { value }`), or a number (a PIN under `password`), so no nested
 * container keeps a value its key names as a credential; the key itself survives so a reader sees the field existed.
 * Booleans and nulls pass through everywhere because they carry no secret (`serviceToken: true`), and numbers pass
 * through under every other key.
 */
function scrubDataValue(value: unknown, scrubText: (text: string, options?: ScrubTextOptions) => string, options: ScrubDataOptions, key: string | undefined, depth: number): unknown {
  const maxDepth = options.maxDepth ?? DEFAULT_DATA_SCRUB_DEPTH;
  if (depth > maxDepth) return typeof value === "string" || (value !== null && typeof value === "object") ? REDACTED : value;
  if (typeof value === "string") {
    const transformed = options.transformString ? options.transformString(value, key) : value;
    return scrubText(transformed, { shapes: key === undefined || !isIdentifierKey(key) });
  }
  if (Array.isArray(value)) return value.map((entry) => scrubDataValue(entry, scrubText, options, key, depth + 1));
  if (value === null || typeof value !== "object") return value;
  const record = value as Record<string, unknown>;
  const pairName = isNameValuePair(record);
  const credentialKey = options.isCredentialKey ?? isCredentialDataKey;
  const out: Record<string, unknown> = {};
  for (const [entryKey, entry] of Object.entries(record)) {
    if (entry === null || entry === undefined || typeof entry === "boolean") {
      out[entryKey] = entry;
    } else if (credentialKey(entryKey, key) || (entryKey === "value" && pairName !== undefined && credentialKey(pairName))) {
      out[entryKey] = REDACTED;
    } else if (typeof entry === "number") {
      out[entryKey] = entry;
    } else {
      out[entryKey] = scrubDataValue(entry, scrubText, options, entryKey, depth + 1);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------------------------------------------------

// PEM blocks (private keys, certificates) and an unterminated PEM header, which is redacted to the end of the text.
const PEM_BLOCK_PATTERN = /-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----/g;
const PEM_OPEN_PATTERN = /-----BEGIN [A-Z0-9 ]+-----[\s\S]*$/;

// Any scheme-prefixed URL wherever it sits: the userinfo is dropped and the query and fragment are replaced by one
// marker; the scheme, host, and path stay because they name the surface. An already-scrubbed `?[REDACTED]` tail is
// consumed whole so a second pass is a no-op. A backslash ends the URL so a JSON-escaped closing quote is kept.
const EMBEDDED_URL_PATTERN = /\b[a-z][a-z0-9+.-]*:\/\/(?:\[REDACTED\]|[^\s"'<>()[\]{}\\])+/gi;
const TRAILING_PUNCTUATION_PATTERN = /[.,;:!?]+$/;

// A relative path or bare query string: a credential-named parameter keeps its name and loses its value. A backslash
// ends the value so a JSON-escaped closing quote is kept.
const QUERY_PAIR_PATTERN = /([?&])([A-Za-z0-9_.[\]-]+)=(?!\[REDACTED\])([^&#\s"'<>\\]+)/g;

// A carrier name must stand on its own: preceded by neither a word character nor "-", ".", or "/", so `sdk-keys:`,
// `environment-token`, `settings.token`, and `/_security/api_key:` are names and paths, not carriers.
const NAME_START = String.raw`(?<![A-Za-z0-9_/.-])`;

// A quote that may close a quoted carrier name in JSON or JSON-escaped text (`"X-Api-Key":`, `\"X-Api-Key\":`), then
// the separator. Each carrier pattern below matches through the separator only; the value that follows is read by a
// quote-aware reader (see "Quoted values"), never by the pattern itself.
const NAME_CLOSE_AND_SEPARATOR = String.raw`(?:\\*["'])?\s*[:=]\s*`;

// Cookie and Set-Cookie headers: every `name=value` pair and every attribute after the first pair is replaced, whatever
// the values look like, up to the first character that ends the header value in free text.
const COOKIE_HEADER_PATTERN = new RegExp(String.raw`${NAME_START}(set-cookie|cookie)${NAME_CLOSE_AND_SEPARATOR}`, "gi");
// A cookie pair name, a later pair or attribute name after `;`, and a bare cookie value take every RFC 6265 token
// character (`!#$%&'*+-.^_` + "`|~" and alphanumerics: `my.sid`, `ASP.NET_SessionId`, `.AspNetCore.Session`,
// `~sid!`; CodeRabbit on #78, r4076392614), the apostrophe included when it stands inside the token (`my'pref`,
// `sid=O'<v>`, `x&'*y`). A class of letters, digits, "_", and "-" alone ended the attribute scan at the "." in
// `; my.sid=` and left that pair's value in place. The attribute class is the name class less ":", so on a compound
// line `; Name:` is the next header and never an attribute (see FOLLOWING_HEADER_PATTERN). The bracket separators
// are never token characters, so `(Cookie: sid=<v>)` keeps its closing bracket and a `{` after `; ` belongs to the
// JSON that follows the header. A header line is often quoted whole in single quotes (`-H 'Cookie: sid=<v>;
// HttpOnly'`, a Python dict repr, a sentence that ends after the quote), so an apostrophe followed by a space, a
// bracket, sentence punctuation, or the end closes that quote rather than continuing the name or value; a name may
// also end in one right before `=`.
const COOKIE_NAME_CHARACTER = String.raw`[^\s;,"'<>=()[\]{}\\]`;
const COOKIE_VALUE_CHARACTER = String.raw`[^\s;,"'<>()[\]{}\\]`;
const COOKIE_ATTRIBUTE_CHARACTER = String.raw`[^\s;,:"'<>=()[\]{}\\]`;
const cookieToken = (character: string): string => String.raw`${character}+(?:'(?![.:!?])${character}+)*`;
const NAME_FINAL_APOSTROPHE = String.raw`(?:'(?=[ \t]*=))?`;
const COOKIE_PAIR_NAME_PATTERN = new RegExp(String.raw`${cookieToken(COOKIE_NAME_CHARACTER)}${NAME_FINAL_APOSTROPHE}`, "y");
const COOKIE_BARE_VALUE_PATTERN = new RegExp(String.raw`(?:${cookieToken(COOKIE_VALUE_CHARACTER)})?`, "y");
const COOKIE_ATTRIBUTE_PATTERN = new RegExp(String.raw`;[ \t]*${cookieToken(COOKIE_ATTRIBUTE_CHARACTER)}${NAME_FINAL_APOSTROPHE}`, "y");
// On one `;`- or `,`-separated line, the next header's `Name:` token ends the value before it: a cookie attribute is
// `Name` or `Name=value`, never `Name:`, and a quoted value that has not closed by then was never terminated. The
// header keeps its name and gets its own carrier treatment. A header name may hold a "." (`X.Api.Key:`, an RFC 7230
// token character).
const FOLLOWING_HEADER_PATTERN = /[;,][ \t]*[A-Za-z][A-Za-z0-9_.-]*[ \t]*:/y;
const HEADER_NAME_COLON_PATTERN = /[ \t]*:/y;

// Session assignments in free text or query strings (`session=...`, `sid=...`, `JSESSIONID=...`), whatever the value.
const SESSION_ASSIGNMENT_PATTERN = new RegExp(
  String.raw`${NAME_START}["']?(session(?:[_-]?(?:id|token|key))?|sid|sessid|jsessionid|phpsessid|asp\.net_sessionid|xsrf[_-]?token|csrf[_-]?token)\b${NAME_CLOSE_AND_SEPARATOR}`,
  "gi",
);
// A bare value after a session or credential-named key runs to the first character that ends a value in prose, a
// header, a query string, or a JSON fragment; a backslash ends it so a JSON-escaped closing quote is kept.
const PAIR_BARE_VALUE_PATTERN = /[^\s"',;&}<>\\]+/y;

// Header names whose value is a credential in any shape; a scheme word in front of the value is kept so the message
// still says which scheme was replayed.
const COMMON_CREDENTIAL_HEADERS: readonly string[] = [
  "authorization",
  "proxy-authorization",
  "x-api-key",
  "api-key",
  "apikey",
  "x-auth-token",
  "x-access-token",
  "x-session-token",
  "x-amz-security-token",
  "x-goog-api-key",
  "x-vault-token",
  "x-auth-key",
  "x-csrf-token",
  "x-xsrf-token",
  "private-token",
];
// Any `x-` header whose name carries a credential word.
const GENERIC_CREDENTIAL_HEADER = "x-[a-z0-9-]*(?:key|token|secret|auth|session|password|credential)[a-z0-9-]*";
// A scheme word in front of a header or pair value is kept so the message still says which scheme was replayed. The
// space after it does not cross a line, so a scheme word ending a line is not joined to the next line's first word.
const HEADER_SCHEME_PATTERN = /(?:bearer|basic|token|apikey|api-key|digest|ssws)[ \t]+/iy;
// A bare header value runs to the first character that ends a header value in free text; a backslash ends it so a
// JSON-escaped closing quote is kept.
const HEADER_BARE_VALUE_PATTERN = /[^\s,;"'<>\\]+/y;

// Authorization scheme values in free text (`Bearer <value>`, `Basic <value>`, `Token <value>`, `ApiKey <value>`):
// the value goes whatever its shape unless it is one plain word, which is prose ("Basic authentication is disabled",
// "an Owner token for a complete inventory"). A bare value starts with a letter or digit and is at least four
// characters, so an arrow or a dash after the word ("environment-token -> config") is punctuation, not a credential;
// a quoted value (`Bearer "token"`) is delimited by its quotes and goes whole whatever it holds. "Token" and "Basic"
// are English words as often as schemes, so they count as schemes only in their conventional capitalised spelling
// ("token canary-noexpiry-token-zq has no expiry" names a token; "Token canary-noexpiry-token-zq" replays one).
const SCHEME_WORD_PATTERN = new RegExp(String.raw`${NAME_START}(bearer|basic|token|apikey|api-key)[ \t]+`, "gi");
const SCHEME_BARE_VALUE_PATTERN = /[A-Za-z0-9][A-Za-z0-9._~+/=-]{3,}/y;
const CAPITALISED_SCHEMES = new Map([["token", "Token"], ["basic", "Basic"]]);
const PLAIN_WORD_PATTERN = /^(?:[A-Z]?[a-z]+|[A-Z]+)$/;
const PLAIN_WORD_MAX_LENGTH = 20;
// A quoted value after a bare scheme word in prose is a credential when it begins like one; in `"Basic ", "token"`
// inside a JSON document the quote after the scheme word closes one string rather than opening a value.
const QUOTED_SCHEME_VALUE_START_PATTERN = /^[A-Za-z0-9]/;

// Credential-named key/value pairs in prose, headers, query strings, and JSON fragments: the key and separator stay,
// the value goes whatever its shape. A name preceded by "/" is a URL path segment (`GET /_security/api_key: 403`), not
// a key, and is left alone.
const CREDENTIAL_PAIR_NAMES: readonly string[] = [
  "api[_-]?key",
  "x-api-key",
  "app[_-]?key",
  "application[_-]?key",
  "access[_-]?key",
  "secret[_-]?key",
  "secret[_-]?access[_-]?key",
  "client[_-]?secret",
  "password",
  "passwd",
  "pwd",
  "passphrase",
  "secret",
  "token",
  "access[_-]?token",
  "refresh[_-]?token",
  "id[_-]?token",
  "auth[_-]?token",
  "session[_-]?token",
  "bearer[_-]?token",
  "sas[_-]?token",
  "api[_-]?token",
  "private[_-]?key",
  "credentials?",
  "signature",
  "sig",
];
const CREDENTIAL_PAIR_PATTERN = new RegExp(String.raw`${NAME_START}["']?(${CREDENTIAL_PAIR_NAMES.join("|")})\b${NAME_CLOSE_AND_SEPARATOR}`, "gi");

// Every other `key=value`, `key: value`, or `"key":"value"` pair whose key carries a credential word anywhere
// (`BOX_CLIENT_SECRET`, `developer_token`, `cloudApiKey`, `user_session`): the value goes whatever its shape and
// length when the pair is a tight assignment (`=`), a quoted or JSON value, or a `:` or spaced `=` pair under a
// singular key, or under any key when the value stands alone on the line or is followed by the next pair. A plural
// inventory label or a PascalCase code whose `:` value opens a clause is prose, not an assignment
// ("InvalidAuthenticationToken: Access token has expired", "access_tokens: LaunchDarkly request failed",
// "sdk_keys:web/production: ..."), so only a token-shaped first word is removed there. A bare value does not end in
// ":" or ".", which close a clause, and a backslash ends it so a JSON-escaped closing quote is kept.
const GENERIC_PAIR_KEY_PATTERN = new RegExp(String.raw`${NAME_START}(["']?)([A-Za-z][A-Za-z0-9_.-]{0,63})\b(${NAME_CLOSE_AND_SEPARATOR})`, "g");
const GENERIC_PAIR_VALUE_PATTERN = /(?!\[REDACTED\])[^\s"',;&}<>\\]*[^\s"',;&}<>\\:.]/y;
// After a bare `:` value: the next pair on the line (`password: x client_secret: y`), which makes the value an assignment.
const FOLLOWING_PAIR_PATTERN = /[A-Za-z][A-Za-z0-9_.-]{0,63}\s*[:=]/y;
// A bare `:` value that ends a sentence (`developer_token: letmein.`) stands alone as well.
const SENTENCE_END_PATTERN = /\.(?:\s|$)/y;
// An unquoted JSON, YAML, or report literal after `:` carries no secret text: `"has_private_key": true`,
// `"api_keys_total": 2`, `"authorization_realms": null`, `Pass: 7`. A quoted or `=` value of the same spelling goes.
const UNQUOTED_LITERAL_PATTERN = /^(?:true|false|null|-?\d+(?:\.\d+)?(?:e[+-]?\d+)?)$/i;
// The labels that open a clause in prose: a key with a plural credential word (`access_tokens: LaunchDarkly request
// failed`, `api_keys: 3 of 5 keys have no expiry`, `Access tokens: name, role or custom role`, the Datadog permission
// `org_app_keys_read: Datadog request failed`), a verdict count under a plural subject (`posture_findings_pass: Datadog
// request failed`), or a PascalCase error code (`InvalidAuthenticationToken: Access token has expired`). A singular
// key followed by words (`developer_token: letmein was rejected`) is a config or env pair quoted mid-sentence and goes.
const PLURAL_LABEL_SEGMENTS = new Set(["tokens", "keys", "secrets", "passwords", "credentials", "sessions", "passphrases", "signatures", "cookies", "apikeys"]);
const VERDICT_COUNT_LAST_SEGMENTS = new Set(["pass"]);
const PLURAL_SUBJECT_PATTERN = /^[a-z]{2,}[a-rt-z]s$/;
const PASCAL_CASE_CODE_PATTERN = /^[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]*)+$/;
// A tight `=` (`BOX_CLIENT_SECRET=v`) is an assignment whatever follows; a spaced `=` (TOML, INI, prose such as
// "a key = value pair") is judged like `:`.
const WHITESPACE_PATTERN = /\s/;

// JWT and JWE compact serialisations, AWS access key ids, and 40-character AWS secret access keys.
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)*/g;
const AWS_ACCESS_KEY_ID_PATTERN = /\b(?:AKIA|ASIA|AROA|AIDA|AGPA|ANPA|ANVA|APKA|ABIA|ACCA)[A-Z0-9]{16}\b/g;
const AWS_SECRET_PATTERN = /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])/g;

// Hex digests and hex-encoded keys of 32 or more characters (MD5, SHA-1, SHA-256, Datadog API and application keys,
// compact UUIDs) carrying at least one digit and one letter; a bare digit string or a bare word is not a digest.
const HEX_DIGEST_PATTERN = /\b(?=[0-9A-Fa-f]*\d)(?=[0-9A-Fa-f]*[A-Fa-f])[0-9A-Fa-f]{32,}\b/g;

// Vendor token prefixes that identify a credential on their own.
const COMMON_VENDOR_PATTERNS: readonly RegExp[] = [
  /\bxox[abopers]-[A-Za-z0-9-]{10,}/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,}/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}/g,
  /\bglpat-[A-Za-z0-9_-]{20,}/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  /\bya29\.[0-9A-Za-z._-]{20,}/g,
  /\bsk_(?:live|test)_[A-Za-z0-9]{10,}/g,
  /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g,
];

// The long-token rule. "/", ".", ":", "@", "%", and whitespace are not run characters, so URL path segments, dotted
// hostnames, colon-separated identifiers, emails, and percent-encoded labels are judged piece by piece; "=" joins a
// run only as trailing base64 padding; "-" and "_" stay in the run and split it into name segments.
const LONG_TOKEN_RUN_PATTERN = new RegExp(`[A-Za-z0-9+_-]{${LONG_TOKEN_MIN_LENGTH},}(?:={1,2}(?![A-Za-z0-9&]))?`, "g");
const UPPERCASE_CODE_PATTERN = /^[A-Z][A-Z_]*$|^[A-Z][A-Z0-9]*(?:[_-][A-Z0-9]+)+$/;
const DIGITS_ONLY_PATTERN = /^\d+$/;
const DIGIT_GROUP_PATTERN = /\d+/g;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Below this many letters a segment's casing is not judged: `eBay`, `iOS`, `McD`, and the six-character suffix
// `mkdtemp` gives a directory (`SeSovG`) are names, and a token this short is caught by its digit groups or by its
// neighbours.
const MIN_LETTERS_FOR_CASING = 7;
// Below this length a segment's digit scatter is not judged either: `a1B2c3` is the suffix `mkdtemp` gives a directory,
// `v1a2` a version, `ip10` a label. A token that hides in segments this short is caught where a carrier names it.
const MIN_SEGMENT_FOR_DIGIT_SCATTER = 8;
// The first word of a clause after a credential-named label is judged for token shape only from this length.
const MIN_CREDENTIAL_VALUE_LENGTH = 8;

// A key whose final segment names a setting is a setting, not a credential key, even when an earlier segment is a
// credential word: `BOX_AUTH_METHOD=ccg`, `BOX_TOKEN_URL`, `BOX_JWT_ALGORITHM`, `BOX_JWT_AUDIENCE`,
// `LAUNCHDARKLY_KEY_SHAPE`, `token_limit`, `client_id`, `key_name`. Its value stays unless it is token-shaped or a
// registered secret, and a URL value still passes the URL rule (userinfo and query removed, path kept).
const SETTING_KEY_SUFFIXES = new Set([
  "url", "uri", "endpoint", "method", "algorithm", "audience", "issuer", "shape", "type", "mode",
  "path", "file", "dir", "limit", "count", "id", "name",
  // Thresholds, timestamps, and labels under a credential-named prefix (`stale_token_days`, `token_created_at`,
  // `key_expiry`, `token_inventory_scope`, `caller_token_role`, `key_status`).
  "days", "hours", "minutes", "seconds", "ttl", "at", "date", "time", "timestamp", "expiry", "expiration", "expires", "version",
  "scope", "role", "status", "state", "kind", "label", "title", "description", "owner",
]);
const THRESHOLD_KEY_PREFIX_PATTERN = /^(?:max|min)[_-]/i;
// A `key` without a credential qualifier names an identifier as often as a credential (`key`, `integrationKey`,
// `flagKey`, `projectKey`), so it keeps a name-shaped value and loses a token-shaped one, as the data side already
// rules; `api_key`, `sdk_key`, `client_key`, and the other qualified spellings are credentials outright.
function isUnqualifiedKeyName(key: string): boolean {
  const segments = keySegments(key);
  const last = segments[segments.length - 1];
  return (last === "key" || last === "keys") && !isCredentialDataKey(key);
}
// Incoming-webhook and callback URLs carry their credential in the path (rule 9), so these stay credential keys
// whatever their suffix: `webhook_url`, `webhookUrl`, `slack_hook_url`, `callback_url`. Their URL value keeps only its
// origin and loses its path and query; a value that is not a URL (a webhook's name) has nothing to lose.
const WEBHOOK_KEY_LAST_SEGMENTS = new Set(["url", "uri"]);

// Names that carry a credential in query strings and pairs beyond the Flue heuristic: bare `sid`, `sig`, `pwd`,
// `session`, `auth`, the concatenated application-key spellings (`appkey` in `~/.dogrc`), and the signed-URL parameters
// of S3 and GCS.
const EXTRA_CREDENTIAL_KEY_SEGMENTS = new Set([
  "sid", "sig", "pwd", "passwd", "pass", "session", "sessid", "auth", "nonce", "sas", "appkey", "appkeys", "applicationkey", "applicationkeys",
]);
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

// ---------------------------------------------------------------------------------------------------------------------
// Decisions
// ---------------------------------------------------------------------------------------------------------------------

function keySegments(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

/** True for `webhook*`, `*hook_url`, `*hook_uri`, and `callback_url` keys, whose URL value carries a credential in its path. */
export function isWebhookKey(key: string): boolean {
  const segments = keySegments(key);
  if (segments.length === 0) return false;
  if (segments[0].startsWith("webhook")) return true;
  if (segments.length < 2 || !WEBHOOK_KEY_LAST_SEGMENTS.has(segments[segments.length - 1])) return false;
  const qualifier = segments[segments.length - 2];
  return qualifier.endsWith("hook") || qualifier === "callback";
}

/** True when the key's final segment names a setting (`token_url`, `auth_method`, `client_id`) or a threshold (`max_keys`). */
export function isSettingKey(key: string): boolean {
  const segments = keySegments(key);
  if (segments.length < 2) return false;
  if (THRESHOLD_KEY_PREFIX_PATTERN.test(key) || segments[0] === "max" || segments[0] === "min") return true;
  return SETTING_KEY_SUFFIXES.has(segments[segments.length - 1]);
}

/**
 * True when a name in a query string or name/value pair carries a credential: a webhook or callback URL key and a
 * bearer id (`secret_id`, `session_id`) first, whatever their suffix; then a setting key is never a credential key;
 * then the Flue argument-key heuristic (`token`, `secret`, `password`, `api_key`, `authorization`, `cookie`, ...
 * anywhere in the name) plus the bare and signed-URL names it does not cover.
 */
export function isCredentialKey(key: string): boolean {
  if (isWebhookKey(key) || isBearerIdKey(key)) return true;
  if (isSettingKey(key)) return false;
  if (isSensitiveArgumentKey(key)) return true;
  const normalized = key.toLowerCase();
  if (EXTRA_CREDENTIAL_KEYS.has(normalized)) return true;
  return keySegments(key).some((segment) => EXTRA_CREDENTIAL_KEY_SEGMENTS.has(segment));
}

/**
 * A value after an authorization scheme is the credential unless it is one plain word ("Basic authentication",
 * "Owner token for", "Bearer token") shorter than 20 characters.
 */
function looksLikeSchemeValue(value: string): boolean {
  return !(PLAIN_WORD_PATTERN.test(value) && value.length < PLAIN_WORD_MAX_LENGTH);
}

/**
 * The first word of a clause after a credential-named label (`InvalidAuthenticationToken: Access token has expired`,
 * `access_tokens: LaunchDarkly request failed`, `sdk_keys:web/production`) is a credential only when it is at least
 * eight characters and shaped like a token: base64 symbols, or a segment between "-", "_", "/", ".", or ":" that is
 * not shaped like part of a name. This test never applies to an assignment, a quoted value, or a `:` value that stands
 * alone: those go whatever their shape (see `replaceCompoundCredentialPairs`).
 */
function looksLikeCredentialValue(value: string): boolean {
  if (value.length < MIN_CREDENTIAL_VALUE_LENGTH) return false;
  if (/[+=]/.test(value)) return true;
  return !value.split(/[-_/.:]/).every(isNameSegment);
}

/**
 * A 40-character run is an AWS secret access key when it carries a digit and both letter cases and does not start
 * with "/": a URL path of exactly forty characters ("/api/v2/projects/web/environments/canary") is a path.
 */
function looksLikeAwsSecret(run: string): boolean {
  if (run.startsWith("/")) return false;
  return /\d/.test(run) && /[a-z]/.test(run) && /[A-Z]/.test(run);
}

function isLower(letter: string): boolean {
  return letter >= "a" && letter <= "z";
}

/**
 * Token-shaped casing: the case changes more often than once every three letters, and at least one lowercase letter
 * stands alone between two uppercase letters. Words, acronyms, camelCase, and PascalCase names change case at word
 * boundaries and keep their lowercase letters in runs (`AWSLambdaBasicExecutionRole`, `getHTTPSUrl`,
 * `CanaryRequireSsoChangeZq`); a random run changes about every second letter and isolates lowercase letters
 * (`bPxRfiCYcanaryKEY`, `wDLfuPPgnnJsUDTXrCUrQwJLnZ`).
 */
function hasTokenCasing(letters: string): boolean {
  if (letters.length < MIN_LETTERS_FOR_CASING) return false;
  let changes = 0;
  let isolatedLowercase = 0;
  for (let index = 1; index < letters.length; index += 1) {
    if (isLower(letters[index - 1]) !== isLower(letters[index])) changes += 1;
    if (index + 1 < letters.length && isLower(letters[index]) && !isLower(letters[index - 1]) && !isLower(letters[index + 1])) {
      isolatedLowercase += 1;
    }
  }
  return isolatedLowercase > 0 && changes * 3 > letters.length;
}

/**
 * A segment between "-" or "_" that is shaped like part of a name: empty, digits alone (account ids, ports, years),
 * short enough that digit scatter is not judged, or letters with at most one digit group (`west2`, `sha256`, `ec2`,
 * `oauth2Client`) whose casing is not token-shaped. Digits scattered through a longer segment (`0f9e8d7c6b5a4938`,
 * `Kq7Zx2Vw9Lm4Tp8R`) are the token signal.
 */
function isNameSegment(segment: string): boolean {
  if (segment.length === 0 || DIGITS_ONLY_PATTERN.test(segment)) return true;
  const digitGroups = segment.match(DIGIT_GROUP_PATTERN) ?? [];
  if (digitGroups.length > 1 && segment.length >= MIN_SEGMENT_FOR_DIGIT_SCATTER) return false;
  return !hasTokenCasing(segment.replace(DIGIT_GROUP_PATTERN, ""));
}

/**
 * The long-token rule's decision: a run is a token when it carries the base64 symbol "+", when it is standard base64
 * with "=" padding (no "-" or "_" in the body) whose body is not itself shaped like a name (so `Proxy-Authorization=`
 * and `InvalidAuthenticationToken=` are names followed by an assignment, while `QUJDREVGR0hJSktMTU5PUA==` is a token
 * by its digit scatter), or when any of its "-" or "_" separated segments is not shaped like part of a name.
 * Uppercase codes, digit strings, and canonical UUIDs are names outright.
 */
export function looksLikeToken(run: string): boolean {
  if (run.length < LONG_TOKEN_MIN_LENGTH) return false;
  const body = run.replace(/=+$/, "");
  if (UPPERCASE_CODE_PATTERN.test(body) || DIGITS_ONLY_PATTERN.test(body) || UUID_PATTERN.test(body)) return false;
  if (/\+/.test(body)) return true;
  const segments = body.split(/[-_]/);
  if (body.length < run.length && segments.length === 1) return !isNameSegment(body);
  return !segments.every(isNameSegment);
}

// ---------------------------------------------------------------------------------------------------------------------
// Quoted values
// ---------------------------------------------------------------------------------------------------------------------

interface QuotedValue {
  /** The opening quote as written: the quote character with the backslashes that escape it (`"`, `'`, `\"`, `\\\"`). */
  open: string;
  /** The closing quote as written, or "" when the value runs to the end of the line or of the text. */
  close: string;
  /** Index of the first character of the value. */
  start: number;
  /** Index just past the last character of the value. */
  end: number;
  /** Index just past the closing quote, where scanning resumes. */
  after: number;
}

function backslashRun(text: string, index: number): number {
  let count = 0;
  while (text[index + count] === "\\") count += 1;
  return count;
}

/**
 * Reads a quoted value opening at `index`: a double or single quote, with any backslashes that escape it in JSON or
 * JavaScript-escaped text (`\"value\"`, `\\\"value\\\"`). The value ends at the same quote token; a quote escaped one
 * level deeper is content, a quote escaped less deeply closes an enclosing string and leaves the value unterminated,
 * and a value with no closing quote on its line runs to the next header's `Name:` token on the line (`; X-Api-Key:`),
 * or to the end of the line or of the text, so a truncated carrier still loses its value and the header after it
 * keeps its name. A closing quote on the line wins over that cut, so `"abc; Foo: def"` is one value; the exception is
 * a following header whose own value opens with a quote (`sid="abc; X-Api-Key: "def"`), where that quote is an opener
 * and the unterminated value ends at the header's name.
 */
function readQuotedValue(text: string, index: number): QuotedValue | null {
  const whole = scanQuotedValue(text, index, "quoted-value");
  if (whole === null || whole.terminated) return whole?.value ?? null;
  return scanQuotedValue(text, index, "always")?.value ?? null;
}

/** When a quoted-value scan ends at the next header's `Name:` token: never, only when that header's value opens with a quote, or always. */
type FollowingHeaderCut = "quoted-value" | "always";

/** True when the text after a `; Name:` token opens a quoted value, so the quote there is an opener rather than our closer. */
function followingHeaderOpensQuote(text: string, headerEnd: number): boolean {
  let cursor = headerEnd;
  while (text[cursor] === " " || text[cursor] === "\t") cursor += 1;
  const next = text[cursor + backslashRun(text, cursor)];
  return next === '"' || next === "'";
}

/**
 * One pass of the quoted-value scan. `terminated` is true when the value ended at a quote token rather than at the
 * line end, a header cut, or the text end.
 */
function scanQuotedValue(text: string, index: number, cut: FollowingHeaderCut): { value: QuotedValue; terminated: boolean } | null {
  const depth = backslashRun(text, index);
  const quote = text[index + depth];
  if (quote !== '"' && quote !== "'") return null;
  const open = text.slice(index, index + depth + 1);
  const start = index + open.length;
  let cursor = start;
  while (cursor < text.length) {
    const char = text[cursor];
    if (char === "\n" || char === "\r") break;
    if (char === ";" || char === ",") {
      const header = stickyExec(FOLLOWING_HEADER_PATTERN, text, cursor);
      if (header !== null && (cut === "always" || followingHeaderOpensQuote(text, cursor + header.length))) break;
    }
    if (char !== "\\" && char !== quote) {
      cursor += 1;
      continue;
    }
    const run = backslashRun(text, cursor);
    const next = text[cursor + run];
    if (next !== quote) {
      // The run escapes the character after it, unless that is a line end, which the loop then sees.
      cursor += run + (next === undefined || next === "\n" || next === "\r" ? 0 : 1);
      continue;
    }
    if (run < depth) return { value: { open, close: "", start, end: cursor, after: cursor }, terminated: true };
    if ((run - depth) % 2 === 0) {
      const end = cursor + run - depth;
      return { value: { open, close: text.slice(end, cursor + run + 1), start, end, after: cursor + run + 1 }, terminated: true };
    }
    cursor += run + 1;
  }
  return { value: { open, close: "", start, end: cursor, after: cursor }, terminated: false };
}

interface ValueReplacement {
  /** Index just past the text the replacement covers. */
  end: number;
  /** The text written in place of `text.slice(valueStart, end)`. */
  replacement: string;
}

/** The value a reader receives: the text and the index just past the carrier's name and separator. */
type ValueReader = (text: string, valueStart: number, carrier: RegExpExecArray) => ValueReplacement | null;

function stickyExec(pattern: RegExp, text: string, index: number): string | null {
  pattern.lastIndex = index;
  return pattern.exec(text)?.[0] ?? null;
}

/** A value position already holding the marker is left alone so a second pass over scrubbed text is a no-op. */
function isBlankOrScrubbed(value: string): boolean {
  const trimmed = value.trim();
  return trimmed.length === 0 || trimmed === REDACTED;
}

/**
 * Replaces the value after every match of `carrierPattern` (a global pattern that matches a carrier's name and
 * separator) with what `readValue` returns for it, leaving the name and separator in place. A reader that returns
 * null leaves the text alone and scanning continues after the carrier's name.
 */
function replaceCarrierValues(text: string, carrierPattern: RegExp, readValue: ValueReader): string {
  carrierPattern.lastIndex = 0;
  let out = "";
  let last = 0;
  let match: RegExpExecArray | null;
  while ((match = carrierPattern.exec(text)) !== null) {
    if (match[0].length === 0) {
      carrierPattern.lastIndex += 1;
      continue;
    }
    const valueStart = match.index + match[0].length;
    const read = readValue(text, valueStart, match);
    if (read === null) continue;
    out += `${text.slice(last, valueStart)}${read.replacement}`;
    last = read.end;
    carrierPattern.lastIndex = last;
  }
  return last === 0 ? text : `${out}${text.slice(last)}`;
}

/**
 * Reads the value of a header, session, or credential-named pair: a quoted value goes whole up to its closing quote
 * with the quotes and a leading scheme word kept (`"Bearer value"` becomes `"Bearer [REDACTED]"`); a bare value may
 * carry a scheme word in front of it and then either a quoted value (`Bearer "value"`) or a bare run.
 */
function readCarrierValue(text: string, valueStart: number, barePattern: RegExp): ValueReplacement | null {
  const quoted = readQuotedValue(text, valueStart);
  if (quoted !== null) {
    const content = text.slice(quoted.start, quoted.end);
    const scheme = stickyExec(HEADER_SCHEME_PATTERN, content, 0) ?? "";
    if (isBlankOrScrubbed(content.slice(scheme.length))) return null;
    return { end: quoted.after, replacement: `${quoted.open}${scheme}${REDACTED}${quoted.close}` };
  }
  const scheme = stickyExec(HEADER_SCHEME_PATTERN, text, valueStart) ?? "";
  const afterScheme = valueStart + scheme.length;
  const quotedAfterScheme = scheme.length > 0 ? readQuotedValue(text, afterScheme) : null;
  if (quotedAfterScheme !== null) {
    if (isBlankOrScrubbed(text.slice(quotedAfterScheme.start, quotedAfterScheme.end))) return null;
    return { end: quotedAfterScheme.after, replacement: `${scheme}${quotedAfterScheme.open}${REDACTED}${quotedAfterScheme.close}` };
  }
  const bare = stickyExec(barePattern, text, afterScheme);
  if (bare === null || isBlankOrScrubbed(bare)) return null;
  return { end: afterScheme + bare.length, replacement: `${scheme}${REDACTED}` };
}

const readHeaderValue: ValueReader = (text, valueStart) => readCarrierValue(text, valueStart, HEADER_BARE_VALUE_PATTERN);
const readPairValue: ValueReader = (text, valueStart) => readCarrierValue(text, valueStart, PAIR_BARE_VALUE_PATTERN);

/** Index past any markers an earlier rule left at `index` (`Cookie: a=1&sid=[REDACTED]` after the query rule), so they fold into one. */
function absorbMarkers(text: string, index: number): number {
  let cursor = index;
  while (text.startsWith(REDACTED, cursor)) cursor += REDACTED.length;
  return cursor;
}

/**
 * Index just past a cookie pair's or attribute's value, which may be quoted. A marker an earlier rule left inside a
 * bare value (a configured secret or a query pair already replaced), or after an apostrophe inside it (`O'[REDACTED]`),
 * is stepped over, so the attributes after it (`; Path=/`) still belong to the header value rather than surviving
 * beside the marker.
 */
function cookieValueEnd(text: string, index: number): number {
  const quoted = readQuotedValue(text, index);
  if (quoted !== null) return quoted.after;
  let cursor = index;
  for (;;) {
    cursor += stickyExec(COOKIE_BARE_VALUE_PATTERN, text, cursor)?.length ?? 0;
    const joiner = text[cursor] === "'" && text.startsWith(REDACTED, cursor + 1) ? 1 : 0;
    const afterMarkers = absorbMarkers(text, cursor + joiner);
    if (afterMarkers === cursor) return cursor;
    cursor = afterMarkers;
  }
}

/**
 * Reads a Cookie or Set-Cookie header value: quoted whole, or `name=value` followed by attributes and further pairs
 * (`; Path=/; HttpOnly`, `; ASP.NET_SessionId=...`), where each name is any RFC 6265 token and each value may itself
 * be quoted. The whole header value is replaced by one marker, a marker an earlier rule left at its end folded in.
 * The value ends at `,`, at a `; Name:` token (the next header on the line, which is never a cookie attribute), or
 * at the line end.
 */
const readCookieHeaderValue: ValueReader = (text, valueStart) => {
  const quoted = readQuotedValue(text, valueStart);
  if (quoted !== null) {
    if (isBlankOrScrubbed(text.slice(quoted.start, quoted.end))) return null;
    return { end: quoted.after, replacement: `${quoted.open}${REDACTED}${quoted.close}` };
  }
  if (text.startsWith(REDACTED, valueStart)) return null;
  const name = stickyExec(COOKIE_PAIR_NAME_PATTERN, text, valueStart);
  if (name === null || text[valueStart + name.length] !== "=") return null;
  let cursor = cookieValueEnd(text, valueStart + name.length + 1);
  let attribute: string | null;
  while ((attribute = stickyExec(COOKIE_ATTRIBUTE_PATTERN, text, cursor)) !== null) {
    if (stickyExec(HEADER_NAME_COLON_PATTERN, text, cursor + attribute.length) !== null) break;
    cursor += attribute.length;
    if (text[cursor] === "=") cursor = cookieValueEnd(text, cursor + 1);
  }
  return { end: absorbMarkers(text, cursor), replacement: REDACTED };
};

/**
 * Reads the value after a bare scheme word in free text: a quoted value goes whole when it begins like a credential;
 * a bare value goes unless it is one plain word.
 */
const readSchemeValue: ValueReader = (text, valueStart, carrier) => {
  const scheme = carrier[1];
  const conventional = CAPITALISED_SCHEMES.get(scheme.toLowerCase());
  if (conventional !== undefined && scheme !== conventional) return null;
  const quoted = readQuotedValue(text, valueStart);
  if (quoted !== null) {
    const content = text.slice(quoted.start, quoted.end);
    if (isBlankOrScrubbed(content) || !QUOTED_SCHEME_VALUE_START_PATTERN.test(content)) return null;
    return { end: quoted.after, replacement: `${quoted.open}${REDACTED}${quoted.close}` };
  }
  const bare = stickyExec(SCHEME_BARE_VALUE_PATTERN, text, valueStart);
  if (bare === null || !looksLikeSchemeValue(bare)) return null;
  return { end: valueStart + bare.length, replacement: REDACTED };
};

// ---------------------------------------------------------------------------------------------------------------------
// Replacements
// ---------------------------------------------------------------------------------------------------------------------

// Incoming-webhook URLs carry the credential in the path: Slack `/services/T.../B.../<token>`, Discord and Microsoft
// Teams `/api/webhooks/<id>/<token>` and `/webhookb2/<id>@<tenant>/IncomingWebhook/<id>/<token>`, Google Chat
// `/v1/spaces/<space>/messages` with `key` and `token` in the query (already a query rule). The last segment goes.
const WEBHOOK_PATH_PATTERN = /^(\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/|\/api\/webhooks\/\d+\/|\/webhookb2\/[^/]+\/IncomingWebhook\/[^/]+\/)[^/]+/i;

function scrubEmbeddedUrl(match: string): string {
  const trailing = TRAILING_PUNCTUATION_PATTERN.exec(match)?.[0] ?? "";
  const url = match.slice(0, match.length - trailing.length);
  try {
    const parsed = new URL(url);
    const hadUserinfo = parsed.username.length > 0 || parsed.password.length > 0;
    const hadDetail = parsed.search.length > 0 || parsed.hash.length > 0 || hadUserinfo || url.endsWith("?") || url.endsWith("#");
    const pathname = parsed.pathname.replace(WEBHOOK_PATH_PATTERN, `$1${REDACTED}`);
    if (hadDetail) return `${parsed.protocol}//${parsed.host}${pathname}?${REDACTED}${trailing}`;
    return pathname === parsed.pathname ? match : `${parsed.protocol}//${parsed.host}${pathname}${trailing}`;
  } catch {
    return `${REDACTED}${trailing}`;
  }
}

function scrubQueryPair(match: string, separator: string, key: string): string {
  return isCredentialKey(key) ? `${separator}${key}=${REDACTED}` : match;
}

function scrubLongToken(run: string): string {
  return looksLikeToken(run) ? REDACTED : run;
}

function scrubAwsSecret(run: string): string {
  return looksLikeAwsSecret(run) ? REDACTED : run;
}

/**
 * True for a key that labels a clause in prose rather than naming one credential: a plural credential word in any
 * segment, a verdict count under a plural subject, or a PascalCase code.
 */
function isClauseLabel(key: string): boolean {
  if (PASCAL_CASE_CODE_PATTERN.test(key)) return true;
  const segments = keySegments(key);
  if (segments.some((segment) => PLURAL_LABEL_SEGMENTS.has(segment))) return true;
  return segments.length >= 2 && VERDICT_COUNT_LAST_SEGMENTS.has(segments[segments.length - 1]) && PLURAL_SUBJECT_PATTERN.test(segments[segments.length - 2]);
}

/**
 * Whether a bare value after a `:` separator stands alone as an assignment (`developer_token: letmein`, end of the
 * line, `;`, `}`, or the next pair after it) or opens a clause (`access_tokens: LaunchDarkly request failed`,
 * `Access tokens: name, role or custom role`, `sdk_keys:web/production: ...`), in which case it is a label's first
 * word. Only the first word is judged; the words after it are prose either way. A clause after a singular key is
 * not an exemption: only `isClauseLabel` keys open one, and a label chain (`sdk_keys:web/production: ...`) is a chain
 * only under such a key, so `developer_token: letmein: security_exception` is an assignment whose value is followed
 * by a colon.
 */
function bareValueOpensClause(text: string, key: string, valueEnd: number): boolean {
  if (!isClauseLabel(key)) return false;
  // A label chain: the value is itself followed by a `:` and its own clause.
  if (text[valueEnd] === ":") return true;
  let index = valueEnd;
  while (text[index] === " " || text[index] === "\t") index += 1;
  if (index >= text.length) return false;
  const next = text[index];
  if (next === "\n" || next === "\r" || next === ";" || next === "}" || next === ")" || next === "]" || next === "&" || next === "|" || next === "\\" || next === '"' || next === "'") return false;
  if (next === ".") return stickyExec(SENTENCE_END_PATTERN, text, index) === null;
  if (next === ",") {
    index += 1;
    while (text[index] === " " || text[index] === "\t") index += 1;
    if (index >= text.length || text[index] === "\n" || text[index] === "\r") return false;
  }
  // The next pair on the line makes the value an assignment; any other word continues a clause.
  return stickyExec(FOLLOWING_PAIR_PATTERN, text, index) === null;
}

/** A webhook or callback URL keeps its origin and loses its path and query; a value that is not a URL is left to the other rules. */
function webhookValueReplacement(value: string): string | null {
  if (!/^https?:\/\//i.test(value)) return null;
  try {
    const parsed = new URL(value);
    return `${parsed.protocol}//${parsed.host}/${REDACTED}`;
  } catch {
    return REDACTED;
  }
}

/**
 * Replaces the value of every compound credential-named pair (`BOX_CLIENT_SECRET=v`, `developer_token: v`,
 * `"cloudApiKey": "v"`). The key and separator are matched on their own; a quoted value goes whole up to its closing
 * quote (a leading scheme word kept), a bare value after `=` or a bare `:` value that stands alone goes whatever its
 * shape, and the first word of a clause after a credential-named label goes only when it is token-shaped. The value of
 * an ordinary pair is rescanned, so a credential pair nested inside it is still caught.
 */
function replaceCompoundCredentialPairs(text: string): string {
  GENERIC_PAIR_KEY_PATTERN.lastIndex = 0;
  let out = "";
  let last = 0;
  let match: RegExpExecArray | null;
  while ((match = GENERIC_PAIR_KEY_PATTERN.exec(text)) !== null) {
    const [whole, openingQuote, key, separator] = match;
    if (whole.length === 0) {
      GENERIC_PAIR_KEY_PATTERN.lastIndex += 1;
      continue;
    }
    if (!isCredentialKey(key)) continue;
    const valueStart = match.index + whole.length;
    const webhook = isWebhookKey(key);
    // An unqualified `key` keeps the identifier treatment: only a token-shaped value goes.
    const shapeGated = isUnqualifiedKeyName(key);
    const quoted = readQuotedValue(text, valueStart);
    let replacement: string;
    let end: number;
    if (quoted !== null) {
      const content = text.slice(quoted.start, quoted.end);
      if (webhook) {
        const reduced = webhookValueReplacement(content);
        if (reduced === null) continue;
        replacement = `${quoted.open}${reduced}${quoted.close}`;
      } else {
        const scheme = stickyExec(HEADER_SCHEME_PATTERN, content, 0) ?? "";
        if (isBlankOrScrubbed(content.slice(scheme.length))) continue;
        if (shapeGated && !looksLikeCredentialValue(content.slice(scheme.length))) continue;
        replacement = `${quoted.open}${scheme}${REDACTED}${quoted.close}`;
      }
      end = quoted.after;
    } else {
      // A scheme word in front of the value stays, as in a header (`auth_header: Bearer "v"`, `Authorization: Bearer v`).
      const scheme = webhook ? "" : stickyExec(HEADER_SCHEME_PATTERN, text, valueStart) ?? "";
      const afterScheme = valueStart + scheme.length;
      const quotedAfterScheme = scheme.length > 0 ? readQuotedValue(text, afterScheme) : null;
      if (quotedAfterScheme !== null) {
        if (isBlankOrScrubbed(text.slice(quotedAfterScheme.start, quotedAfterScheme.end))) continue;
        replacement = `${scheme}${quotedAfterScheme.open}${REDACTED}${quotedAfterScheme.close}`;
        end = quotedAfterScheme.after;
      } else {
        const value = stickyExec(GENERIC_PAIR_VALUE_PATTERN, text, afterScheme);
        // A container opener is rescanned element by element; an unquoted literal after `:` carries no secret text.
        if (value === null || value.startsWith("[") || value.startsWith("{")) continue;
        if (!separator.includes("=") && UNQUOTED_LITERAL_PATTERN.test(value)) continue;
        end = afterScheme + value.length;
        if (webhook) {
          const reduced = webhookValueReplacement(value);
          if (reduced === null) continue;
          replacement = reduced;
        } else {
          const tightAssignment = separator.includes("=") && !WHITESPACE_PATTERN.test(separator);
          const assignment = !shapeGated && (tightAssignment || scheme.length > 0 || !bareValueOpensClause(text, key, end));
          if (!assignment && !looksLikeCredentialValue(value)) continue;
          replacement = `${scheme}${REDACTED}`;
        }
      }
    }
    out += `${text.slice(last, match.index)}${openingQuote}${key}${separator}${replacement}`;
    last = end;
    GENERIC_PAIR_KEY_PATTERN.lastIndex = last;
  }
  return last === 0 ? text : `${out}${text.slice(last)}`;
}

/**
 * Builds the scrubber an integration module owns. The scrubber carries the configured secrets of every client the
 * module constructed, so the sink that turns a thrown value into recorded text removes them without knowing which
 * client the error came from.
 */
export function createCredentialScrubber(options: CredentialScrubberOptions = {}): CredentialScrubber {
  const secrets = new Set<string>();
  const headerNames = [...new Set([...COMMON_CREDENTIAL_HEADERS, ...(options.headers ?? []).map((name) => name.toLowerCase())])]
    .sort((left, right) => right.length - left.length)
    .map((name) => name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  // The header carrier: a credential header name, its optional closing quote, and the separator; the value is read
  // quote-aware by `readHeaderValue`.
  const headerPattern = new RegExp(String.raw`${NAME_START}(${headerNames.join("|")}|${GENERIC_CREDENTIAL_HEADER})${NAME_CLOSE_AND_SEPARATOR}`, "gi");
  const vendorPatterns = [...COMMON_VENDOR_PATTERNS, ...(options.vendorPatterns ?? [])];

  // The Flue marker is folded into this module's marker only where Flue wrote it: a `[redacted]` already in the text
  // (KnowBe4's PII mask uses the same spelling) is parked behind a sentinel first and restored afterwards.
  function scrubConfiguredSecrets(text: string): string {
    if (secrets.size === 0) return text;
    const parked = text.split(REDACTED_VALUE).join(PRESERVED_MARKER_SENTINEL);
    return scrubSensitiveValues(parked, [...secrets]).split(REDACTED_VALUE).join(REDACTED).split(PRESERVED_MARKER_SENTINEL).join(REDACTED_VALUE);
  }

  function scrub(text: string, textOptions: ScrubTextOptions = {}): string {
    const shapes = textOptions.shapes ?? true;
    let scrubbed = scrubConfiguredSecrets(text)
      .replace(PEM_BLOCK_PATTERN, REDACTED)
      .replace(PEM_OPEN_PATTERN, REDACTED)
      .replace(EMBEDDED_URL_PATTERN, scrubEmbeddedUrl)
      .replace(QUERY_PAIR_PATTERN, scrubQueryPair);
    scrubbed = replaceCarrierValues(scrubbed, COOKIE_HEADER_PATTERN, readCookieHeaderValue);
    scrubbed = replaceCarrierValues(scrubbed, headerPattern, readHeaderValue);
    scrubbed = replaceCarrierValues(scrubbed, SCHEME_WORD_PATTERN, readSchemeValue);
    scrubbed = replaceCarrierValues(scrubbed, SESSION_ASSIGNMENT_PATTERN, readPairValue);
    scrubbed = replaceCarrierValues(scrubbed, CREDENTIAL_PAIR_PATTERN, readPairValue);
    scrubbed = replaceCompoundCredentialPairs(scrubbed)
      .replace(JWT_PATTERN, REDACTED)
      .replace(AWS_ACCESS_KEY_ID_PATTERN, REDACTED);
    if (shapes) scrubbed = scrubbed.replace(AWS_SECRET_PATTERN, scrubAwsSecret).replace(HEX_DIGEST_PATTERN, REDACTED);
    for (const pattern of vendorPatterns) scrubbed = scrubbed.replace(pattern, REDACTED);
    return shapes ? scrubbed.replace(LONG_TOKEN_RUN_PATTERN, scrubLongToken) : scrubbed;
  }

  function scrubData(value: unknown, dataOptions: ScrubDataOptions = {}): unknown {
    return scrubDataValue(value, scrub, dataOptions, undefined, 0);
  }

  function registerSecrets(values: ReadonlyArray<string | undefined | null>): void {
    for (const value of values) {
      if (typeof value === "string" && value.length >= MIN_CONFIGURED_SECRET_LENGTH) secrets.add(value);
    }
  }

  return { scrub, scrubData, registerSecrets, secrets };
}
