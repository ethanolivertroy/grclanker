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
 *    its closing quote, spaces and all, with the quotes kept, and the scheme word kept under a header or an
 *    Authorization-style key (under any other credential key a leading scheme word is the value's first word and goes
 *    with it; see `keepsSchemeWord`). A carrier fires after a JSON escape (`\napi_key=`, `\/password=`), after a
 *    command-line flag's dashes (`--password=`, `-Dpassword=` read as the flag `-D` and the key `password`, and
 *    `--password v` with the value after a space), and after a path segment (`kv/password:`) as it does after a space
 *    (see `NAME_START`, `javaPropertyPrefixOf`, and `FLAG_VALUE_PATTERN`). On the data side a webhook or callback URL
 *    keeps its origin alone (see `scrubDataValue`).
 * 2. A configured secret is removed whatever its shape and in its base64, base64url, URL-encoded, form-encoded, and
 *    JSON-escaped forms; the Flue redaction primitives own the encoded forms. A configured secret that is itself a
 *    carrier word (`password`, `Authorization`, `Bearer`) is removed after the carriers rather than before them, so
 *    the pair or header it names still loses its value (see `isCarrierVocabulary`).
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
   * Nesting deeper than this is replaced by the marker: a container past the cap becomes the marker whole, so nothing
   * below it is copied. Every string at every depth still gets the pattern pass first, so the strings inside the
   * deepest kept container are scrubbed rather than dropped. Numbers, booleans, and nulls pass through.
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
   * null are ignored. A value that is itself a carrier vocabulary word (`password`, `Authorization`, `Bearer`; see
   * `isCarrierVocabulary`) is removed after the carriers have run rather than before, so the pair it names still loses
   * its value.
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
// rule would otherwise keep), of a token id (`token_id`, `tokenId`: the id a token API hands back is the token as often
// as a handle to it, so it fails closed; 01:40 rulings), or of a session id (`session_id`, `sid`, `JSESSIONID`,
// `PHPSESSID`, `ASP.NET_SessionId`) is what authenticates. These keys are credential keys on both sides whatever the
// value's shape, checked before the setting-suffix and identifier rules; any prefix, casing, and separator
// (`VAULT_SECRET_ID`, `role_secret_id`, `roleSecretId`). Every other `*_id` names a thing and stays an identifier:
// `client_id`, `enterprise_id`, `key_id`, `api_key_id`, `tenant_id`, `access_key_id` (an AWS access key id is removed by
// its `AKIA` shape), and `secret_name` likewise (CodeRabbit on #78, r4077259415).
const BEARER_ID_LAST_SEGMENTS = new Set(["secretid", "sid", "sessid", "sessionid", "jsessionid", "phpsessid", "aspnetsessionid"]);
const BEARER_ID_QUALIFIERS = new Set(["secret", "session", "token"]);

/** True for a key whose id value is itself a bearer credential: `secret_id`, `token_id`, and the session-id keys, in any spelling. */
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
 * through under every other key. The string branch runs before the depth test (gap 36): a string at any depth is
 * scrubbed, never dropped, and a container past the cap becomes the marker whole.
 */
function scrubDataValue(value: unknown, scrubText: (text: string, options?: ScrubTextOptions) => string, options: ScrubDataOptions, key: string | undefined, depth: number): unknown {
  if (typeof value === "string") {
    const transformed = options.transformString ? options.transformString(value, key) : value;
    // A webhook or callback URL keeps its origin only on the data side, whatever the module's own URL rule left of it
    // (a rule that drops only the query would keep the path). Under a key that names a URL (`webhook_url`), a value of
    // any other shape becomes the marker, since a schemeless path would keep its token; under a bare `webhook` key a
    // non-URL value is a name and takes the ordinary pass.
    if (key !== undefined && isWebhookKey(key)) {
      const origin = webhookDataOrigin(transformed);
      if (origin !== null) return origin;
      if (isWebhookUrlKey(key) && !isBlankOrScrubbed(transformed)) return REDACTED;
    }
    return scrubText(transformed, { shapes: key === undefined || !isIdentifierKey(key) });
  }
  if (value === null || typeof value !== "object") return value;
  if (depth > (options.maxDepth ?? DEFAULT_DATA_SCRUB_DEPTH)) return REDACTED;
  if (Array.isArray(value)) return value.map((entry) => scrubDataValue(entry, scrubText, options, key, depth + 1));
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
// consumed whole so a second pass is a no-op. A URL written with JSON-escaped slashes (`https:\/\/svc:pw@host\/v1`)
// is read the same way and written back in that form. Any other backslash ends the URL so a JSON-escaped closing
// quote is kept.
const EMBEDDED_URL_PATTERN = /\b[a-z][a-z0-9+.-]*:(?:\/\/|\\\/\\\/)(?:\[REDACTED\]|\\\/|[^\s"'<>()[\]{}\\])+/gi;
const ESCAPED_SLASH_PATTERN = /\\\//g;
const TRAILING_PUNCTUATION_PATTERN = /[.,;:!?]+$/;

// A relative path or bare query string: a credential-named parameter keeps its name and loses its value. The value
// runs to the next parameter, the fragment, whitespace, or a quote or bracket that closes the text around it, and a
// backslash ends it so a JSON-escaped closing quote is kept. A ";" inside the value is part of it, as URLSearchParams
// reads it (`?token=<v>;<rest>` is one value and goes whole; Codex on #81): only the Cookie and Set-Cookie readers
// treat ";" as a boundary, and they run before this rule so a header's `; pref=w` is read as its attribute rather than
// taken off the header as the tail of a query value.
const QUERY_PAIR_PATTERN = /([?&])([A-Za-z0-9_.[\]-]+)=(?!\[REDACTED\])([^&#\s"'<>\\]+)/g;

// A carrier name must stand on its own: preceded by neither a word character nor "-", ".", or "/", so `sdk-keys:`,
// `environment-token`, `settings.token`, and `GET /_security/api_key: 403` are names and paths, not carriers. Three
// positions count as standing on its own although a name character precedes them (coordinator rulings, rows A and D):
// - after the letters of a JSON escape written into the text (`\napi_key=`, `\r\nAuthorization:`, `\u000asdk_key=`),
//   which is a line break or tab in the decoded text;
// - after the one or two dashes that open a command-line flag (`--password=`, `-Dpassword=`), where the dashes start a
//   word; a dash inside a word (`user-session:`, `environment-token`) still joins the name;
// - after a raw or JSON-escaped slash that ends a path segment (`kv/password: v`, `path\/password=v`), unless the
//   slash sits inside a request line or a URL (`GET /_security/api_key: 403`, `POST /oauth2/token: invalid_grant`,
//   `https://api.box.com/oauth2/token: 400`), where the word after it is a path segment naming the surface.
const NAME_CHARACTER_CLASS = String.raw`[A-Za-z0-9_/.-]`;
const NAME_CHARACTER_PATTERN = new RegExp(NAME_CHARACTER_CLASS);
const REQUEST_PATH_CONTEXT = String.raw`(?:\b(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)[ \t]|:\/\/|:\\\/\\\/)\S{0,512}`;
const NAME_START = String.raw`(?:(?<!${NAME_CHARACTER_CLASS})|(?<=\\[nrtbfv]|\\u[0-9A-Fa-f]{4})|(?<=(?<!${NAME_CHARACTER_CLASS})-{1,2})|(?<=/)(?<!${REQUEST_PATH_CONTEXT}))`;
// The letters a JSON escape leaves in front of a word when the pattern above starts a name at the escape's backslash
// (`\nsdk_key=` read as the key `nsdk_key`); see `replaceCompoundCredentialPairs` and `escapePrefixOf`.
const ESCAPE_LETTER_PATTERN = /^(?:[nrtbfv]|u[0-9A-Fa-f]{4})/;

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
// A scheme word in front of a header value, in any casing, is kept so the message still says which scheme was replayed
// (RFC 7235 schemes, the Okta `SSWS`, `ApiKey`, `Splunk`, `Snowflake`, and SigV4). The space after it does not cross a
// line, so a scheme word ending a line is not joined to the next line's first word. Under a credential-named pair key
// that is not an Authorization-style header (`sslPassword=bearer rejected`) the word is the value's first word and
// goes with it; see `keepsSchemeWord`.
const HEADER_SCHEME_WORDS: readonly string[] = ["bearer", "basic", "token", "apikey", "api-key", "digest", "ssws", "oauth", "negotiate", "ntlm", "splunk", "snowflake", "aws4-hmac-sha256"];
const HEADER_SCHEME_PATTERN = new RegExp(String.raw`(?:${HEADER_SCHEME_WORDS.join("|")})[ \t]+`, "iy");
// A bare header value runs to the first character that ends a header value in free text; a backslash ends it so a
// JSON-escaped closing quote is kept.
const HEADER_BARE_VALUE_PATTERN = /[^\s,;"'<>\\]+/y;

// An RFC 7235 auth-param list after the scheme word of a credential header value (`Snowflake Token="v"`, `Digest
// username="v", realm="api", nonce="v", response="v"`, `AWS4-HMAC-SHA256 Credential=v, SignedHeaders=host;range,
// Signature=v`, `Hawk id="v", mac="v"`): comma-separated `name=value` parameters whose values are quoted or bare. The
// list is the credential and goes whole with the run that opens it, so the quoted value after `Token=` is never left
// standing beside the marker (CodeRabbit on #81, r4081238237). A bare parameter value may hold ";"
// (`SignedHeaders=host;range`) but ends before a `;Name:` token, the next header on a compound line, and before "&"
// or "}", which close a query pair or a JSON fragment around the value. The first parameter's quoted value must begin
// like a value: after the "=" padding of a base64 credential (`Basic YWJjZGU="}`, `Basic YWJjZGU=", "next": 1`) the
// quote closes the string the header sits in and opens no parameter. A word standing where the scheme would be
// (`Hawk`) is an unregistered scheme when a parameter list follows it, and goes with the list.
const AUTH_PARAM_NAME_PATTERN = /[A-Za-z][A-Za-z0-9_.-]*[ \t]*=[ \t]*/y;
const AUTH_PARAM_BARE_VALUE_PATTERN = /[^\s,"'<>&}\\]+/y;
const AUTH_PARAM_SEPARATOR_PATTERN = /[ \t]*,[ \t]*/y;
const AUTH_PARAM_FIRST_VALUE_PATTERN = /^[^\s,;)\]}>]/;
const SCHEME_TOKEN_PATTERN = /^[A-Za-z][A-Za-z0-9-]*$/;
// The auth-params that carry a proof (an RFC 7616 `response`, an OAuth 1.0 `oauth_signature`, a MAC token's `mac`, an
// HMAC `sig` or `hmac`, a SAML or JWT `assertion`), read as the final segment of the parameter name (`X-Amz-Signature`,
// `oauth_signature`): a list that holds one is a credential whatever parameter it begins with, so the challenge
// exemption of the prose scheme reader does not reach it (CodeRabbit r4081776771 on #81: `Digest realm="api",
// nonce="n", response="<proof>"` kept its proof because the list began with `realm=` and no pair rule names
// `response`). A name that only begins with one of these words is a setting (`oauth_signature_method`), a challenge's
// `nonce`, `opaque`, and `cnonce` name no proof, and a credential-named parameter (`access_token=`, `Token=`) is
// scrubbed in place by the pair rules, which leave the challenge's other parameters standing.
const PROOF_PARAM_WORDS: ReadonlySet<string> = new Set(["response", "signature", "sig", "mac", "hmac", "assertion"]);

// Authorization scheme values in free text (`Bearer <value>`, `Basic <value>`, `Token <value>`, `ApiKey <value>`,
// `Digest <value>`): the value goes whatever its shape unless it is one plain word, which is prose ("Basic
// authentication is disabled", "an Owner token for a complete inventory", "Digest access authentication"). A bare value
// starts with a letter or digit and is at least four characters, so an arrow or a dash after the word
// ("environment-token -> config") is punctuation, not a credential; a quoted value (`Bearer "token"`) is delimited by
// its quotes and goes whole whatever it holds. "Token", "Basic", and "Digest" are English words as often as schemes, so
// they count as schemes only in their conventional capitalised spelling ("token canary-noexpiry-token-zq has no expiry"
// names a token; "Token canary-noexpiry-token-zq" replays one; "sha256 digest mismatch" names a checksum).
const SCHEME_WORD_PATTERN = new RegExp(String.raw`${NAME_START}(bearer|basic|token|apikey|api-key|digest)[ \t]+`, "gi");
const SCHEME_BARE_VALUE_PATTERN = /[A-Za-z0-9][A-Za-z0-9._~+/=-]{3,}/y;
const CAPITALISED_SCHEMES = new Map([["token", "Token"], ["basic", "Basic"], ["digest", "Digest"]]);
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

// A command-line flag whose name carries a credential word, with its value after a space rather than "="
// (`psql --password v -h db`, `vault login --secret-id v`; the `--name=v` form is a pair). The dashes must start a word;
// the flag keeps its name and the value that follows goes whatever its shape, unless it is itself a flag.
const FLAG_VALUE_PATTERN = new RegExp(String.raw`(?<!${NAME_CHARACTER_CLASS})--([A-Za-z][A-Za-z0-9_.-]{0,63})[ \t]+(?=[^\s-])`, "g");

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
  // The enterprise settings an assessment reports as words (`session_duration: 12 hours`, `session_duration: never`,
  // `password_reset_frequency: 90 days`, `key_rotation_interval`, `password_min_length`).
  "duration", "frequency", "interval", "length",
  // The Vault AppRole and token settings an assessment reports (`secret_id_bound_cidrs`, `token_bound_cidrs`,
  // `secret_id_num_uses`) and the accessor, a UUID handle to a token or secret id that cannot be used in its place
  // (`secret_id_accessor`, `token_accessor`; 01:40 rulings).
  "cidrs", "cidr", "uses", "accessor",
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
// whatever their suffix: `webhook_url`, `webhookUrl`, `slack_hook_url`, `callback_url`, and the bare `webhook` or
// `webhooks` a URL stands under. Their URL value keeps only its origin and loses its path and query; a value that is
// not a URL becomes the marker under a URL-named key (a schemeless path would keep its token) and is a webhook's name
// under the bare key. A `webhook`-prefixed key whose last segment says what it holds is judged by that segment, not by
// the prefix: `webhook_secret`, `webhook_token`, `webhookSigningKey` are credential keys outright and lose their value
// whatever its shape; `webhook_name`, `webhook_id`, `webhook_count` are settings (gap 39).
const WEBHOOK_KEY_LAST_SEGMENTS = new Set(["url", "uri"]);
const BARE_WEBHOOK_KEYS = new Set(["webhook", "webhooks"]);

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

/**
 * True for the keys whose value is a webhook or callback URL: `webhook*_url`, `*hook_uri`, `callback_url`, and the
 * bare `webhook` or `webhooks`. A `webhook`-prefixed key with any other last segment (`webhook_secret`, `webhook_name`)
 * is not a URL key and is judged by that segment.
 */
export function isWebhookKey(key: string): boolean {
  const segments = keySegments(key);
  if (segments.length === 0) return false;
  if (segments.length === 1) return BARE_WEBHOOK_KEYS.has(segments[0]);
  if (!WEBHOOK_KEY_LAST_SEGMENTS.has(segments[segments.length - 1])) return false;
  const qualifier = segments[segments.length - 2];
  return segments[0].startsWith("webhook") || qualifier.endsWith("hook") || qualifier === "callback";
}

/** True for the webhook keys whose last segment names a URL (`webhook_url`, `callbackUri`), as opposed to the bare `webhook` name. */
function isWebhookUrlKey(key: string): boolean {
  return isWebhookKey(key) && keySegments(key).length >= 2;
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

// The auth-params a challenge carries after its scheme word (`WWW-Authenticate: Bearer realm="api", error="invalid_token"`,
// `Basic realm="Restricted"`, `Digest qop="auth"`, RFC 7235, 6750, 7616, 9470, and UMA): a name and "=" where a
// credential would stand, so the challenge keeps its parameters.
const AUTH_PARAM_PATTERN = /^(?:realm|error|error_description|error_uri|scope|charset|algorithm|qop|stale|domain|opaque|title|resource|client_id|authorization_uri|as_uri|ticket)=/i;

/**
 * A value after an authorization scheme is the credential unless it is one plain word ("Basic authentication",
 * "Owner token for", "Bearer token") shorter than 20 characters, or a challenge's auth-param (`Bearer realm="api"`).
 */
function looksLikeSchemeValue(value: string): boolean {
  if (PLAIN_WORD_PATTERN.test(value) && value.length < PLAIN_WORD_MAX_LENGTH) return false;
  return !AUTH_PARAM_PATTERN.test(value);
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
 * Whether the value under a pair key keeps a leading scheme word. An Authorization-style key names a header whose value
 * a scheme word opens (`auth_header: Bearer v`, `Proxy-Authorization=Basic v`, `www_authenticate`), so the word stays
 * as it does in the header itself. Under every other credential-named key the scheme word is the value's first word
 * (`sslPassword=bearer rejected`, `db_password: token`) and goes with whatever follows it, so a password that happens to
 * start with a scheme word is never written back (CodeRabbit r4078025849 on #63).
 */
function keepsSchemeWord(key: string): boolean {
  const segments = keySegments(key);
  return segments.includes("authorization") || segments.includes("authenticate") || (segments.includes("auth") && segments.includes("header"));
}

/** Index just past a bare auth-param value starting at `start`: the run less a `;Name:` header cut and any trailing ";". */
function authParamBareValueEnd(text: string, start: number): number {
  const run = stickyExec(AUTH_PARAM_BARE_VALUE_PATTERN, text, start);
  if (run === null) return start;
  let length = run.length;
  for (let cut = run.indexOf(";"); cut !== -1; cut = run.indexOf(";", cut + 1)) {
    if (stickyExec(FOLLOWING_HEADER_PATTERN, text, start + cut) !== null) {
      length = cut;
      break;
    }
  }
  while (length > 0 && run[length - 1] === ";") length -= 1;
  return start + length;
}

/** An auth-param list read from the text: where it ends, and whether one of its parameters names a proof. */
interface AuthParamList {
  end: number;
  /** True when a parameter of the list, the first included, names a proof (see PROOF_PARAM_WORDS). */
  proof: boolean;
}

/** Whether a parameter name's final segment is a proof word (`response`, `oauth_signature`, `X-Amz-Signature`, `mac`). */
function isProofParamName(name: string): boolean {
  const segments = keySegments(name);
  return segments.length > 0 && PROOF_PARAM_WORDS.has(segments[segments.length - 1]);
}

/**
 * The auth-param list that starts at `index`, or null when no parameter starts there. The first parameter's quoted
 * value must begin like a value (see AUTH_PARAM_FIRST_VALUE_PATTERN); a later parameter's value goes whatever it
 * holds, so `uri="/v1"` or `realm=""` in the middle of a Digest list does not end the list. Without `continueList`
 * only the first parameter is read: outside a header value a comma after a pair's value starts the next pair of the
 * line (`client_secret=abc==, scope=read`), not the next parameter of the same credential.
 */
function readAuthParamList(text: string, index: number, continueList: boolean): AuthParamList | null {
  let cursor = index;
  let count = 0;
  let proof = false;
  for (;;) {
    const name = stickyExec(AUTH_PARAM_NAME_PATTERN, text, cursor);
    if (name === null) break;
    const valueStart = cursor + name.length;
    const quoted = readQuotedValue(text, valueStart);
    let valueEnd: number;
    if (quoted !== null) {
      if (count === 0 && !AUTH_PARAM_FIRST_VALUE_PATTERN.test(text.slice(quoted.start, quoted.end))) break;
      valueEnd = quoted.after;
    } else {
      valueEnd = authParamBareValueEnd(text, valueStart);
      if (valueEnd === valueStart) break;
    }
    cursor = valueEnd;
    count += 1;
    if (isProofParamName(name)) proof = true;
    if (!continueList) break;
    const separator = stickyExec(AUTH_PARAM_SEPARATOR_PATTERN, text, cursor);
    if (separator === null || stickyExec(AUTH_PARAM_NAME_PATTERN, text, cursor + separator.length) === null) break;
    cursor += separator.length;
  }
  return count === 0 ? null : { end: cursor, proof };
}

/** Index just past the auth-param list that starts at `index`, or null when no parameter starts there. */
function authParamListEnd(text: string, index: number, continueList: boolean): number | null {
  return readAuthParamList(text, index, continueList)?.end ?? null;
}

/**
 * Index just past a bare carrier value that begins with `run` at `afterScheme`: the run itself, or the auth-param
 * list it opens or stands in front of. The run opens a list when it is the first parameter's name and "=" (`Token=`
 * before `"v"`) or a whole bare parameter (`Credential=v` before `, Signature=v`). In a header value (`headerValue`:
 * under any credential header name, or under an Authorization-style pair key) the list continues over commas, and a
 * run that is one word where no registered scheme was read is an unregistered scheme when a list follows it (`Hawk
 * id="v", mac="v"`); under any other carrier only the parameter the run opens goes with it, since the pairs after a
 * comma or a space belong to the line (`password=hunter2 user=alice`). Either way what is taken is credential
 * material and goes with the run.
 */
function bareValueEndWithAuthParams(text: string, valueStart: number, afterScheme: number, run: string, headerValue: boolean): number {
  const runEnd = afterScheme + run.length;
  const opened = authParamListEnd(text, afterScheme, headerValue);
  if (opened !== null && opened > runEnd) return opened;
  if (!headerValue || afterScheme > valueStart || !SCHEME_TOKEN_PATTERN.test(run)) return runEnd;
  let cursor = runEnd;
  while (text[cursor] === " " || text[cursor] === "\t") cursor += 1;
  return (cursor > runEnd ? authParamListEnd(text, cursor, true) : null) ?? runEnd;
}

/**
 * Reads the value of a header, session, or credential-named pair: a quoted value goes whole up to its closing quote
 * with the quotes kept; a bare value may carry a scheme word in front of it and then either a quoted value
 * (`Bearer "value"`), a bare run, or an auth-param list (`Token="value"`, `username="v", response="v"`), which goes
 * whole in a header value and by its first parameter elsewhere. With `keepScheme` the scheme word is written back
 * (`"Bearer value"` becomes `"Bearer [REDACTED]"`); without it the word is part of the value and the marker covers both.
 */
function readCarrierValue(text: string, valueStart: number, barePattern: RegExp, keepScheme: boolean, headerValue: boolean): ValueReplacement | null {
  const quoted = readQuotedValue(text, valueStart);
  if (quoted !== null) {
    const content = text.slice(quoted.start, quoted.end);
    const scheme = keepScheme ? stickyExec(HEADER_SCHEME_PATTERN, content, 0) ?? "" : "";
    if (isBlankOrScrubbed(content.slice(scheme.length))) return null;
    return { end: quoted.after, replacement: `${quoted.open}${scheme}${REDACTED}${quoted.close}` };
  }
  const scheme = stickyExec(HEADER_SCHEME_PATTERN, text, valueStart) ?? "";
  const kept = keepScheme ? scheme : "";
  const afterScheme = valueStart + scheme.length;
  const quotedAfterScheme = scheme.length > 0 ? readQuotedValue(text, afterScheme) : null;
  if (quotedAfterScheme !== null) {
    if (isBlankOrScrubbed(text.slice(quotedAfterScheme.start, quotedAfterScheme.end))) return null;
    return { end: quotedAfterScheme.after, replacement: `${kept}${quotedAfterScheme.open}${REDACTED}${quotedAfterScheme.close}` };
  }
  const bare = stickyExec(barePattern, text, afterScheme);
  if (bare === null || isBlankOrScrubbed(bare)) return null;
  return { end: bareValueEndWithAuthParams(text, valueStart, afterScheme, bare, headerValue), replacement: `${kept}${REDACTED}` };
}

/**
 * The value of a credential header. The scheme word stays only under an Authorization-style name (`Authorization:
 * Bearer v`, `Proxy-Authorization: Basic v`); under an API-key or token header (`X-Api-Key: token rejected`,
 * `apiKey=splunk rejected`, `X-Vault-Token: splunk v`) a scheme word is the value's first word and goes with it. An
 * auth-param list goes whole under any header name; under a pair key only an Authorization-style key
 * (`auth_header=Digest username="v", response="v"`) holds a header value, and any other pair's value ends at the
 * parameter it opens so the next pair on the line keeps its own name.
 */
const readHeaderValue: ValueReader = (text, valueStart, carrier) => readCarrierValue(text, valueStart, HEADER_BARE_VALUE_PATTERN, keepsSchemeWord(carrier[1]), true);
const readPairValue: ValueReader = (text, valueStart, carrier) => {
  const keepScheme = keepsSchemeWord(carrier[1]);
  return readCarrierValue(text, valueStart, PAIR_BARE_VALUE_PATTERN, keepScheme, keepScheme);
};
/** The value after a credential-named `--flag`: read like a pair value once the flag's name is a credential key. */
const readFlagValue: ValueReader = (text, valueStart, carrier) => (isCredentialKey(carrier[1]) ? readCarrierValue(text, valueStart, PAIR_BARE_VALUE_PATTERN, false, false) : null);

/** Index past any markers an earlier rule left at `index` (`Cookie: a=1&sid=[REDACTED]` after the query rule), so they fold into one. */
function absorbMarkers(text: string, index: number): number {
  let cursor = index;
  while (text.startsWith(REDACTED, cursor)) cursor += REDACTED.length;
  return cursor;
}

/**
 * Index just past a cookie pair's or attribute's value, which may be quoted. A marker an earlier rule left inside a
 * bare value (a configured secret or an embedded URL's query already replaced), or after an apostrophe inside it
 * (`O'[REDACTED]`), is stepped over, so the attributes after it (`; Path=/`) still belong to the header value rather
 * than surviving beside the marker.
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
 * a bare value goes unless it is one plain word or a challenge's auth-param (`Bearer realm="api"`), and when it opens
 * an auth-param list that is not a challenge (`Bearer Token="v"`) the list goes whole. A list that holds a proof
 * parameter (`Digest realm="api", nonce="n", response="<proof>"`, `Bearer realm="api", error="invalid_token",
 * mac="<proof>"`; see PROOF_PARAM_WORDS) is a credential whatever parameter it begins with and goes whole, as the same
 * list does under a header, so the rendering does not depend on the order of the parameters; a challenge without a
 * proof keeps its parameters (CodeRabbit r4081776771 on #81).
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
  if (bare === null) return null;
  const list = readAuthParamList(text, valueStart, true);
  if (list?.proof) return { end: list.end, replacement: REDACTED };
  if (!looksLikeSchemeValue(bare)) return null;
  return { end: Math.max(valueStart + bare.length, list?.end ?? 0), replacement: REDACTED };
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
  const written = match.slice(0, match.length - trailing.length);
  // A slash-escaped URL is judged unescaped and written back escaped, so the text keeps the form it came in.
  const escaped = written.includes("\\/");
  const url = escaped ? written.replace(ESCAPED_SLASH_PATTERN, "/") : written;
  const rewrite = (text: string): string => (escaped ? text.replace(/\//g, "\\/") : text);
  try {
    const parsed = new URL(url);
    const hadUserinfo = parsed.username.length > 0 || parsed.password.length > 0;
    const hadDetail = parsed.search.length > 0 || parsed.hash.length > 0 || hadUserinfo || url.endsWith("?") || url.endsWith("#");
    const pathname = parsed.pathname.replace(WEBHOOK_PATH_PATTERN, `$1${REDACTED}`);
    if (hadDetail) return `${rewrite(`${parsed.protocol}//${parsed.host}${pathname}`)}?${REDACTED}${trailing}`;
    return pathname === parsed.pathname ? match : `${rewrite(`${parsed.protocol}//${parsed.host}${pathname}`)}${trailing}`;
  } catch {
    return `${REDACTED}${trailing}`;
  }
}

function scrubQueryPair(match: string, separator: string, key: string): string {
  return isCredentialKey(key) ? `${separator}${key}=${REDACTED}` : match;
}

/**
 * The letters of a JSON escape written into the text, when `run` starts right after its backslash: `\u000a` glues
 * `u000a` to the word that follows, so `\u000aKNOWBE4_API_TOKEN` reads as the run `u000aKNOWBE4_API_TOKEN`, whose first
 * segment carries two digit groups and would be judged a token. The escape is written back as it was and only the run
 * after it is judged. Empty when no escape precedes the run.
 */
function escapePrefixOf(run: string, offset: number, text: string): string {
  return offset > 0 && text[offset - 1] === "\\" ? ESCAPE_LETTER_PATTERN.exec(run)?.[0] ?? "" : "";
}

/**
 * The `D` a Java system-property flag leaves in front of a key when the carrier pattern starts a name after the flag's
 * one dash (`-Dsecret_id=` is the flag `-D` and the key `secret_id`; read as `Dsecret_id` it would be an `_id` setting,
 * and `Dapi_key` an unqualified key whose name-shaped value stays).
 */
function javaPropertyPrefixOf(run: string, offset: number, text: string): string {
  const oneDashStartsWord = offset > 0 && text[offset - 1] === "-" && (offset === 1 || !NAME_CHARACTER_PATTERN.test(text[offset - 2]));
  return oneDashStartsWord && run.startsWith("D") ? "D" : "";
}

function scrubLongToken(run: string, offset: number, text: string): string {
  const escape = escapePrefixOf(run, offset, text);
  return looksLikeToken(run.slice(escape.length)) ? `${escape}${REDACTED}` : run;
}

function scrubAwsSecret(run: string, offset: number, text: string): string {
  // Forty characters that begin with an escape are a shorter run after it, which this rule does not judge.
  return escapePrefixOf(run, offset, text).length === 0 && looksLikeAwsSecret(run) ? REDACTED : run;
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
  return isClauseLabel(key) && clauseContinues(text, valueEnd);
}

/** True when more of a clause follows the bare value ending at `valueEnd`: another word, rather than a line end, a closer, or the next pair. */
function clauseContinues(text: string, valueEnd: number): boolean {
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

/**
 * The data-side form of a webhook or callback URL: its origin alone, as the module URL reductions write it; null when
 * the value is not an http(s) URL, and the marker when it starts like one but does not parse.
 */
function webhookDataOrigin(value: string): string | null {
  const trimmed = value.trim();
  if (!/^https?:\/\//i.test(trimmed)) return null;
  try {
    const parsed = new URL(trimmed);
    return `${parsed.protocol}//${parsed.host}`;
  } catch {
    return REDACTED;
  }
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
    const [whole, openingQuote, matchedKey, separator] = match;
    if (whole.length === 0) {
      GENERIC_PAIR_KEY_PATTERN.lastIndex += 1;
      continue;
    }
    // After a backslash or a flag's one dash, a key that begins with the letters of a JSON escape or the `D` of a Java
    // system property is read without them when that reading is the credential (`\nsdk_key=` is the escape `\n` and
    // the key `sdk_key`; `-Dsecret_id=` is the flag `-D` and the key `secret_id`); the letters are written back untouched.
    const prefix = openingQuote === "" ? escapePrefixOf(matchedKey, match.index, text) || javaPropertyPrefixOf(matchedKey, match.index, text) : "";
    const key = prefix.length > 0 && isCredentialKey(matchedKey.slice(prefix.length)) ? matchedKey.slice(prefix.length) : matchedKey;
    if (!isCredentialKey(key)) continue;
    const valueStart = match.index + whole.length;
    const webhook = isWebhookKey(key);
    // A scheme word in front of the value stays only under an Authorization-style key (`auth_header: Bearer "v"`); under
    // any other credential key it is the value's first word and goes with it (`sslPassword=bearer rejected`).
    const keepScheme = !webhook && keepsSchemeWord(key);
    // An unqualified `key` keeps the identifier treatment: only a token-shaped value goes.
    const shapeGated = isUnqualifiedKeyName(key);
    const quoted = readQuotedValue(text, valueStart);
    let replacement: string;
    let end: number;
    if (quoted !== null) {
      const content = text.slice(quoted.start, quoted.end);
      if (webhook) {
        // A URL keeps its origin; under a URL-named key (`webhook_url`) any other value becomes the marker, since a
        // schemeless path would keep its token; under the bare `webhook` key it is a name and stays.
        const reduced = webhookValueReplacement(content);
        if (reduced === null && (!isWebhookUrlKey(key) || isBlankOrScrubbed(content))) continue;
        replacement = `${quoted.open}${reduced ?? REDACTED}${quoted.close}`;
      } else {
        const scheme = keepScheme ? stickyExec(HEADER_SCHEME_PATTERN, content, 0) ?? "" : "";
        if (isBlankOrScrubbed(content.slice(scheme.length))) continue;
        if (shapeGated && !looksLikeCredentialValue(content.slice(scheme.length))) continue;
        replacement = `${quoted.open}${scheme}${REDACTED}${quoted.close}`;
      }
      end = quoted.after;
    } else {
      const scheme = webhook ? "" : stickyExec(HEADER_SCHEME_PATTERN, text, valueStart) ?? "";
      const kept = keepScheme ? scheme : "";
      const afterScheme = valueStart + scheme.length;
      const quotedAfterScheme = scheme.length > 0 ? readQuotedValue(text, afterScheme) : null;
      if (quotedAfterScheme !== null) {
        if (isBlankOrScrubbed(text.slice(quotedAfterScheme.start, quotedAfterScheme.end))) continue;
        replacement = `${kept}${quotedAfterScheme.open}${REDACTED}${quotedAfterScheme.close}`;
        end = quotedAfterScheme.after;
      } else if (scheme.length > 0 && !keepScheme && text.startsWith(REDACTED, afterScheme)) {
        // The bare scheme-word pass already replaced the value after the word (`password: bearer [REDACTED]`); under
        // a non-Authorization key the word is part of the value, so the two fold into one marker.
        replacement = REDACTED;
        end = absorbMarkers(text, afterScheme);
      } else {
        const value = stickyExec(GENERIC_PAIR_VALUE_PATTERN, text, afterScheme);
        // A container opener is rescanned element by element; an unquoted literal after `:` carries no secret text.
        if (value === null || value.startsWith("[") || value.startsWith("{")) continue;
        if (!separator.includes("=") && UNQUOTED_LITERAL_PATTERN.test(value)) continue;
        end = afterScheme + value.length;
        if (webhook) {
          const reduced = webhookValueReplacement(value);
          // A URL-named key's non-URL value goes when it stands as an assignment or alone; a clause after
          // `webhook_url:` is prose. A name under the bare `webhook` key stays.
          const standsAlone = separator.includes("=") || !clauseContinues(text, end);
          if (reduced === null && (!isWebhookUrlKey(key) || !standsAlone)) continue;
          replacement = reduced ?? REDACTED;
        } else {
          const tightAssignment = separator.includes("=") && !WHITESPACE_PATTERN.test(separator);
          const assignment = !shapeGated && (tightAssignment || scheme.length > 0 || !bareValueOpensClause(text, key, end));
          if (!assignment && !looksLikeCredentialValue(value)) continue;
          // A quoted value the run opens goes with it (`BOX_CLIENT_SECRET=Token="v"`), and under an Authorization-style
          // key the whole auth-param list after the scheme word does (`auth_header: Snowflake Token="v"`).
          end = bareValueEndWithAuthParams(text, valueStart, afterScheme, value, keepScheme);
          replacement = `${kept}${REDACTED}`;
        }
      }
    }
    out += `${text.slice(last, match.index)}${openingQuote}${matchedKey}${separator}${replacement}`;
    last = end;
    GENERIC_PAIR_KEY_PATTERN.lastIndex = last;
  }
  return last === 0 ? text : `${out}${text.slice(last)}`;
}

// Header names the cookie carrier reads; with the credential header names and the scheme words they make up the
// carrier vocabulary a configured secret can collide with (see `isCarrierVocabulary`).
const COOKIE_HEADER_NAMES: readonly string[] = ["cookie", "set-cookie"];
const GENERIC_CREDENTIAL_HEADER_NAME_PATTERN = new RegExp(`^${GENERIC_CREDENTIAL_HEADER}$`, "i");
// A key, header, or scheme word: letters, digits, and the separators a key carries; no spaces, quotes, or symbols.
const KEY_SHAPED_WORD_PATTERN = /^[a-z][a-z0-9_.-]*$/;

/**
 * True when a configured secret is one of the words the carriers key on: a credential-named key (`password`, `secret`,
 * `token`, `api_key`, `client-secret`, `webhook`), a credential or cookie header name (`Authorization`, `X-Api-Key`,
 * `Cookie`), or a scheme word (`Bearer`, `Basic`). Such a secret cannot be told from the vocabulary, so removing it
 * first would erase the key or header name the carrier needs (`client_[REDACTED]=<value>`) and leave the value beside
 * it standing; it is removed after the carriers have read the pair instead.
 */
function isCarrierVocabulary(secret: string, headerNames: ReadonlySet<string>): boolean {
  const word = secret.toLowerCase();
  if (!KEY_SHAPED_WORD_PATTERN.test(word)) return false;
  if (HEADER_SCHEME_WORDS.includes(word) || COOKIE_HEADER_NAMES.includes(word)) return true;
  if (headerNames.has(word) || GENERIC_CREDENTIAL_HEADER_NAME_PATTERN.test(word)) return true;
  return isCredentialKey(word);
}

/**
 * Builds the scrubber an integration module owns. The scrubber carries the configured secrets of every client the
 * module constructed, so the sink that turns a thrown value into recorded text removes them without knowing which
 * client the error came from.
 */
export function createCredentialScrubber(options: CredentialScrubberOptions = {}): CredentialScrubber {
  const secrets = new Set<string>();
  // Configured secrets in the order they run: plain values before every carrier, so a secret is removed whole before
  // a pattern can split it; values equal to a carrier vocabulary word after the carriers (see `isCarrierVocabulary`).
  const plainSecrets = new Set<string>();
  const vocabularySecrets = new Set<string>();
  const headerNameSet = new Set([...COMMON_CREDENTIAL_HEADERS, ...(options.headers ?? []).map((name) => name.toLowerCase())]);
  const headerNames = [...headerNameSet]
    .sort((left, right) => right.length - left.length)
    .map((name) => name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  // The header carrier: a credential header name, its optional closing quote, and the separator; the value is read
  // quote-aware by `readHeaderValue`.
  const headerPattern = new RegExp(String.raw`${NAME_START}(${headerNames.join("|")}|${GENERIC_CREDENTIAL_HEADER})${NAME_CLOSE_AND_SEPARATOR}`, "gi");
  const vendorPatterns = [...COMMON_VENDOR_PATTERNS, ...(options.vendorPatterns ?? [])];

  // The Flue marker is folded into this module's marker only where Flue wrote it: a `[redacted]` already in the text
  // (KnowBe4's PII mask uses the same spelling) is parked behind a sentinel first and restored afterwards.
  function scrubConfiguredSecrets(text: string, values: ReadonlySet<string>): string {
    if (values.size === 0) return text;
    const parked = text.split(REDACTED_VALUE).join(PRESERVED_MARKER_SENTINEL);
    return scrubSensitiveValues(parked, [...values]).split(REDACTED_VALUE).join(REDACTED).split(PRESERVED_MARKER_SENTINEL).join(REDACTED_VALUE);
  }

  function scrub(text: string, textOptions: ScrubTextOptions = {}): string {
    const shapes = textOptions.shapes ?? true;
    let scrubbed = scrubConfiguredSecrets(text, plainSecrets)
      .replace(PEM_BLOCK_PATTERN, REDACTED)
      .replace(PEM_OPEN_PATTERN, REDACTED)
      .replace(EMBEDDED_URL_PATTERN, scrubEmbeddedUrl);
    // The cookie reader runs before the query rule: ";" separates a cookie header's pairs and attributes but is part
    // of a query value, so the query rule would otherwise take `; pref=w` off `Cookie: &sid=v; pref=w` as the tail of
    // the value before the cookie reader saw the header.
    scrubbed = replaceCarrierValues(scrubbed, COOKIE_HEADER_PATTERN, readCookieHeaderValue).replace(QUERY_PAIR_PATTERN, scrubQueryPair);
    scrubbed = replaceCarrierValues(scrubbed, headerPattern, readHeaderValue);
    scrubbed = replaceCarrierValues(scrubbed, SCHEME_WORD_PATTERN, readSchemeValue);
    scrubbed = replaceCarrierValues(scrubbed, SESSION_ASSIGNMENT_PATTERN, readPairValue);
    scrubbed = replaceCarrierValues(scrubbed, CREDENTIAL_PAIR_PATTERN, readPairValue);
    scrubbed = replaceCarrierValues(scrubbed, FLAG_VALUE_PATTERN, readFlagValue);
    scrubbed = replaceCompoundCredentialPairs(scrubbed);
    // A configured secret spelled like a key, header, or scheme word goes once the carriers have read the pairs it
    // names, so the value beside it is gone before the word is.
    scrubbed = scrubConfiguredSecrets(scrubbed, vocabularySecrets)
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
      if (typeof value !== "string" || value.length < MIN_CONFIGURED_SECRET_LENGTH) continue;
      secrets.add(value);
      (isCarrierVocabulary(value, headerNameSet) ? vocabularySecrets : plainSecrets).add(value);
    }
  }

  return { scrub, scrubData, registerSecrets, secrets };
}
