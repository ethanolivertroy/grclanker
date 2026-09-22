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
 *    Basic, Token, and ApiKey; credential-named key/value pairs (`token=`, `"password":`, `api_key:`).
 * 2. A configured secret is removed whatever its shape and in its base64, base64url, URL-encoded, form-encoded, and
 *    JSON-escaped forms; the Flue redaction primitives own the encoded forms.
 *
 * Real token shapes are removed bare: runs of 16 or more characters with base64 symbols, digits scattered through
 * letters, or token casing; hex digests; JWTs; AWS access key ids and secret keys; PEM blocks; and well-known vendor
 * prefixes. Every rule is unanchored so a carrier embedded mid-sentence is caught, and every replacement is idempotent:
 * scrubbed text comes back unchanged because `[REDACTED]` matches none of the rules.
 */
import { REDACTED_VALUE, isSensitiveArgumentKey, scrubSensitiveValues } from "../../flue/redact.js";

/** The marker every scrub writes; the Flue marker is folded into it so one message carries one marker. */
export const REDACTED = "[REDACTED]";

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

export interface CredentialScrubber {
  /** Removes credential material from error text under every rule of this module. Idempotent. */
  scrub(text: string): string;
  /**
   * Registers configured secret values (API keys, tokens, passwords, private keys); each is removed from every string
   * scrubbed from then on, in every encoded form. Entries shorter than `MIN_CONFIGURED_SECRET_LENGTH`, undefined, and
   * null are ignored.
   */
  registerSecrets(values: ReadonlyArray<string | undefined | null>): void;
  /** The configured secrets registered so far, in their plain form. */
  readonly secrets: ReadonlySet<string>;
}

// ---------------------------------------------------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------------------------------------------------

// PEM blocks (private keys, certificates) and an unterminated PEM header, which is redacted to the end of the text.
const PEM_BLOCK_PATTERN = /-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----/g;
const PEM_OPEN_PATTERN = /-----BEGIN [A-Z0-9 ]+-----[\s\S]*$/;

// Any scheme-prefixed URL wherever it sits: the userinfo is dropped and the query and fragment are replaced by one
// marker; the scheme, host, and path stay because they name the surface. An already-scrubbed `?[REDACTED]` tail is
// consumed whole so a second pass is a no-op.
const EMBEDDED_URL_PATTERN = /\b[a-z][a-z0-9+.-]*:\/\/(?:\[REDACTED\]|[^\s"'<>()[\]{}])+/gi;
const TRAILING_PUNCTUATION_PATTERN = /[.,;:!?]+$/;

// A relative path or bare query string: a credential-named parameter keeps its name and loses its value.
const QUERY_PAIR_PATTERN = /([?&])([A-Za-z0-9_.[\]-]+)=(?!\[REDACTED\])([^&#\s"'<>]+)/g;

// A carrier name must stand on its own: preceded by neither a word character nor "-", ".", or "/", so `sdk-keys:`,
// `environment-token`, `settings.token`, and `/_security/api_key:` are names and paths, not carriers.
const NAME_START = String.raw`(?<![A-Za-z0-9_/.-])`;

// Cookie and Set-Cookie headers: every `name=value` pair and every attribute after the first pair is replaced, whatever
// the values look like, up to the first character that ends the header value in free text.
const COOKIE_HEADER_PATTERN = new RegExp(
  String.raw`${NAME_START}(set-cookie|cookie)(\s*[:=]\s*)(?!\[REDACTED\])([^\s;,"'<>=]+=[^\s;,"'<>]*(?:;\s*[A-Za-z0-9_-]+(?:=[^\s;,"'<>]*)?)*)`,
  "gi",
);

// Session assignments in free text or query strings (`session=...`, `sid=...`, `JSESSIONID=...`), whatever the value.
const SESSION_ASSIGNMENT_PATTERN = new RegExp(
  String.raw`${NAME_START}(session(?:[_-]?(?:id|token|key))?|sid|sessid|jsessionid|phpsessid|asp\.net_sessionid|xsrf[_-]?token|csrf[_-]?token)(["']?\s*[:=]\s*["']?)(?!\[REDACTED\])([^\s"',;&}<>]+)`,
  "gi",
);

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
const HEADER_SCHEMES = String.raw`(?:bearer|basic|token|apikey|api-key|digest|ssws)\s+`;
// A value position already holding the marker, with or without a scheme word in front of it, is left alone so a
// second pass over scrubbed text is a no-op.
const NOT_ALREADY_SCRUBBED = String.raw`(?!\[REDACTED\]|${HEADER_SCHEMES}\[REDACTED\])`;

// Authorization scheme values in free text (`Bearer <value>`, `Basic <value>`, `Token <value>`, `ApiKey <value>`):
// the value goes whatever its shape unless it is one plain word, which is prose ("Basic authentication is disabled",
// "an Owner token for a complete inventory"). The value starts with a letter or digit and is at least four characters,
// so an arrow or a dash after the word ("environment-token -> config") is punctuation, not a credential. "Token" and
// "Basic" are English words as often as schemes, so they count as schemes only in their conventional capitalised
// spelling ("token canary-noexpiry-token-zq has no expiry" names a token; "Token canary-noexpiry-token-zq" replays one).
const SCHEME_VALUE_PATTERN = new RegExp(
  String.raw`${NAME_START}(bearer|basic|token|apikey|api-key)\s+(?!\[REDACTED\])([A-Za-z0-9][A-Za-z0-9._~+/=-]{3,})`,
  "gi",
);
const CAPITALISED_SCHEMES = new Map([["token", "Token"], ["basic", "Basic"]]);
const PLAIN_WORD_PATTERN = /^(?:[A-Z]?[a-z]+|[A-Z]+)$/;
const PLAIN_WORD_MAX_LENGTH = 20;

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
const CREDENTIAL_PAIR_PATTERN = new RegExp(
  String.raw`${NAME_START}(["']?)(${CREDENTIAL_PAIR_NAMES.join("|")})\b(["']?\s*[:=]\s*["']?(?:${HEADER_SCHEMES})?)${NOT_ALREADY_SCRUBBED}([^\s"',;&}<>]+)`,
  "gi",
);

// Every other `key=value`, `key: value`, or `"key":"value"` pair whose key names a credential by the Flue heuristic
// (`client_token`, `user_session`, `tokens`, `InvalidAuthenticationToken`): the value goes when it is shaped like a
// credential rather than a prose word, so "InvalidAuthenticationToken: Access token has expired" stays readable. A
// value does not end in ":" or ".", which close a clause ("sdk-keys: forbidden: Forbidden").
const GENERIC_PAIR_KEY_PATTERN = new RegExp(String.raw`${NAME_START}(["']?)([A-Za-z][A-Za-z0-9_.-]{0,63})\b(["']?\s*[:=]\s*["']?)`, "g");
const GENERIC_PAIR_VALUE_PATTERN = /(?!\[REDACTED\])[^\s"',;&}<>]*[^\s"',;&}<>:.]/y;

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
// A value after a compound credential-named key is judged for token shape only from this length.
const MIN_CREDENTIAL_VALUE_LENGTH = 8;

// Names that carry a credential in query strings beyond the Flue heuristic: bare `sid`, `sig`, `pwd`, `session`, `auth`,
// and the signed-URL parameters of S3 and GCS. Thresholds, counts, and file references are exempt.
const SAFE_KEY_SHAPE_PATTERN = /^(?:max|min)[_-]|[_-](?:limit|days|hours|minutes|seconds|count|path|file|dir)$/i;
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
 * True when a name in a query string, header, or name/value pair carries a credential: the Flue argument-key heuristic
 * (`token`, `secret`, `password`, `api_key`, `authorization`, `cookie`, ...) plus the bare and signed-URL names it does
 * not cover, under the same exemption for thresholds, counts, and file references.
 */
export function isCredentialKey(key: string): boolean {
  if (isSensitiveArgumentKey(key)) return true;
  if (SAFE_KEY_SHAPE_PATTERN.test(key)) return false;
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
 * A value after a compound credential-named key (`sdk_keys`, `client_token`, `user_session`) is the credential when
 * it is at least eight characters and shaped like a token: base64 symbols, or a segment between "-", "_", "/", ".",
 * or ":" that is not shaped like part of a name. Words, scopes, counts, and labels after such a key are prose
 * ("InvalidAuthenticationToken: Access token has expired", "access_tokens: LaunchDarkly request failed",
 * "sdk_keys:web/production").
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
 * with "=" padding (no "-" or "_" in the body, so `Proxy-Authorization=` is a name followed by an assignment), or when
 * any of its "-" or "_" separated segments is not shaped like part of a name. Uppercase codes, digit strings, and
 * canonical UUIDs are names outright.
 */
export function looksLikeToken(run: string): boolean {
  if (run.length < LONG_TOKEN_MIN_LENGTH) return false;
  const body = run.replace(/=+$/, "");
  if (UPPERCASE_CODE_PATTERN.test(body) || DIGITS_ONLY_PATTERN.test(body) || UUID_PATTERN.test(body)) return false;
  if (/\+/.test(body)) return true;
  const segments = body.split(/[-_]/);
  if (body.length < run.length && segments.length === 1) return true;
  return !segments.every(isNameSegment);
}

// ---------------------------------------------------------------------------------------------------------------------
// Replacements
// ---------------------------------------------------------------------------------------------------------------------

function scrubEmbeddedUrl(match: string): string {
  const trailing = TRAILING_PUNCTUATION_PATTERN.exec(match)?.[0] ?? "";
  const url = match.slice(0, match.length - trailing.length);
  try {
    const parsed = new URL(url);
    const hadUserinfo = parsed.username.length > 0 || parsed.password.length > 0;
    const hadDetail = parsed.search.length > 0 || parsed.hash.length > 0 || hadUserinfo || url.endsWith("?") || url.endsWith("#");
    return hadDetail ? `${parsed.protocol}//${parsed.host}${parsed.pathname}?${REDACTED}${trailing}` : match;
  } catch {
    return `${REDACTED}${trailing}`;
  }
}

function scrubQueryPair(match: string, separator: string, key: string): string {
  return isCredentialKey(key) ? `${separator}${key}=${REDACTED}` : match;
}

function scrubSchemeValue(match: string, scheme: string, value: string): string {
  const conventional = CAPITALISED_SCHEMES.get(scheme.toLowerCase());
  if (conventional !== undefined && scheme !== conventional) return match;
  return looksLikeSchemeValue(value) ? `${scheme} ${REDACTED}` : match;
}

function scrubLongToken(run: string): string {
  return looksLikeToken(run) ? REDACTED : run;
}

function scrubAwsSecret(run: string): string {
  return looksLikeAwsSecret(run) ? REDACTED : run;
}

/**
 * Replaces the value of every compound credential-named pair. The key and separator are matched on their own and the
 * value is consumed only when the key names a credential and the value is shaped like one, so the value of an
 * ordinary pair is rescanned and a credential pair nested inside it is still caught.
 */
function replaceGenericCredentialPairs(text: string): string {
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
    GENERIC_PAIR_VALUE_PATTERN.lastIndex = match.index + whole.length;
    const value = GENERIC_PAIR_VALUE_PATTERN.exec(text)?.[0];
    if (value === undefined || !looksLikeCredentialValue(value)) continue;
    out += `${text.slice(last, match.index)}${openingQuote}${key}${separator}${REDACTED}`;
    last = match.index + whole.length + value.length;
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
  const headerPattern = new RegExp(
    String.raw`${NAME_START}(${headerNames.join("|")}|${GENERIC_CREDENTIAL_HEADER})(\s*[:=]\s*)(${HEADER_SCHEMES})?${NOT_ALREADY_SCRUBBED}[^\s,;"'<>]+`,
    "gi",
  );
  const vendorPatterns = [...COMMON_VENDOR_PATTERNS, ...(options.vendorPatterns ?? [])];

  function scrubConfiguredSecrets(text: string): string {
    if (secrets.size === 0) return text;
    return scrubSensitiveValues(text, [...secrets]).split(REDACTED_VALUE).join(REDACTED);
  }

  function scrub(text: string): string {
    let scrubbed = scrubConfiguredSecrets(text)
      .replace(PEM_BLOCK_PATTERN, REDACTED)
      .replace(PEM_OPEN_PATTERN, REDACTED)
      .replace(EMBEDDED_URL_PATTERN, scrubEmbeddedUrl)
      .replace(QUERY_PAIR_PATTERN, scrubQueryPair)
      .replace(COOKIE_HEADER_PATTERN, `$1$2${REDACTED}`)
      .replace(headerPattern, `$1$2$3${REDACTED}`)
      .replace(SCHEME_VALUE_PATTERN, scrubSchemeValue)
      .replace(SESSION_ASSIGNMENT_PATTERN, `$1$2${REDACTED}`)
      .replace(CREDENTIAL_PAIR_PATTERN, `$1$2$3${REDACTED}`);
    scrubbed = replaceGenericCredentialPairs(scrubbed)
      .replace(JWT_PATTERN, REDACTED)
      .replace(AWS_ACCESS_KEY_ID_PATTERN, REDACTED)
      .replace(AWS_SECRET_PATTERN, scrubAwsSecret)
      .replace(HEX_DIGEST_PATTERN, REDACTED);
    for (const pattern of vendorPatterns) scrubbed = scrubbed.replace(pattern, REDACTED);
    return scrubbed.replace(LONG_TOKEN_RUN_PATTERN, scrubLongToken);
  }

  function registerSecrets(values: ReadonlyArray<string | undefined | null>): void {
    for (const value of values) {
      if (typeof value === "string" && value.length >= MIN_CONFIGURED_SECRET_LENGTH) secrets.add(value);
    }
  }

  return { scrub, registerSecrets, secrets };
}
