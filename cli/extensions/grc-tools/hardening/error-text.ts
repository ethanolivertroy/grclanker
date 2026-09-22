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
 * The scrub boundary is the coordinator's: a bare value shaped like a name (words joined by hyphens
 * or underscores, digits standing in whole segments) is indistinguishable from a resource name and
 * stays. Two guards make that safe, and both are construction requirements. (1) A value inside a
 * carrier is removed whatever its shape: the Cookie, Set-Cookie, Authorization, Proxy-Authorization,
 * x-api-key and similar headers; the schemes Bearer, Basic, Token, ApiKey, Digest, OAuth, SSWS, and
 * Splunk; credential-named pairs (`token=`, `"password":`, `api_key:`, `session_id=`); URL userinfo
 * and query pairs. A quoted value (`X-Api-Key: "value"`, `Cookie: sid='value'`, `Authorization:
 * Bearer "value"`, the JSON pair `"Authorization": "Bearer value"`, and their JSON-escaped forms
 * `\"X-Api-Key\": \"value\"` at any depth) is removed whole up to its closing quote, spaces and all,
 * with the quotes and the scheme word kept. On a compound line (`Cookie: sid=<v>; X-Api-Key: "<v>";
 * Content-Type: "application/json"`) an unquoted value, or a quoted one that is never closed, ends at
 * the `;` or `,` that introduces the next `Name:` token, otherwise at the end of the line, and that
 * header keeps its name and gets its own treatment. (2) A configured secret is removed whatever its
 * shape and in its encoded forms.
 *
 * Distilled from the New Relic (#30), Qualys (#32), Webex (#48), and group D (#64) scrubbers on top
 * of the Flue redaction primitives in `cli/flue/redact.ts`, which own the credential key heuristic
 * and the encoded forms of a configured secret; the quoted-value reader follows the shape group A
 * settled on for its `credential-scrub.ts` (Codex P1, quoted header value) so both scrubbers agree.
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
 * The long-token rule replaces any run of this many or more token characters that is not shaped like
 * a name. It is path-safe by construction (coordinator addendum 7): "/", ".", ":", "@", and "=" end a
 * run, so URL path segments, dotted hostnames, colon-separated ARNs, emails, and `key=value` pairs are
 * judged piece by piece, and "-" or "_" split a run into segments that are names when each is letters
 * in any casing (words, acronyms, camelCase, PascalCase: `AWSLambdaBasicExecutionRole`), digits alone,
 * or letters with one digit group (`west2`, `sha256`, `AmazonS3ReadOnlyAccess`), so region, tenant,
 * project, bucket, and hostname names with digits and hyphens stay (`prod-us-east-2026`,
 * `my-project-123456`, `ec2-54-123-45-67`), as do uppercase codes, finding ids, and UUIDs. A run is a
 * token when it carries base64 symbols, when digits are scattered through its letters
 * (`0f9e8d7c6b5a4938`, `Kq7Zx2Vw9Lm4Tp8R`), or when its casing changes more often than once every
 * three letters. Error text is the only place a bare token can arrive, which is why the rule is on by
 * default there; the trade-off is that opaque identifiers whose shape is a token's (instance ids,
 * Okta and ServiceNow record ids, entity guids, OCID unique parts, hashes) are also removed from error
 * text and must travel in a validated structured field (`code`, `status`, `endpoint`) instead, and
 * that a bare value shaped like a name (`sess-canary-COOKIE-31415926535897`, a passphrase) is caught
 * only when a carrier names it (`Cookie:`, `api_key=`, `Bearer`). Data values and bundle content use
 * `scrubDataText`, which leaves the rule off because such identifiers are evidence.
 */
export const LONG_TOKEN_MIN_LENGTH = 16;

/** A documented vendor message longer than this is cut; it is one field of the body, not the body, and it can be arbitrarily long. */
export const MAX_VENDOR_MESSAGE_LENGTH = 400;

/** The longest error message `scrubError` produces after folding in cause chains and aggregate members. */
export const MAX_ERROR_MESSAGE_LENGTH = 2000;

const TRUNCATION_NOTE = " [truncated]";
// The cut of a long message (see `truncate`): a word is not split when a space stands within this
// many characters before the limit, and the head is moved back to a space at most this many times
// until it is a fixed point of the scrub.
const CUT_WORD_BOUNDARY_WINDOW = 40;
const MAX_CUT_ATTEMPTS = 4;
// The tail of a cut head that a second pass would read as a value: a separator followed only by a
// quote, a scheme word, or both (`X-Api-Key: "`, `"Authorization": "Bearer`), a trailing partial query
// or fragment of a URL (`?token=`, `#`), trailing spaces, and a dangling escape backslash.
const CUT_VALUE_OPENER_PATTERN = /([:=])[ \t]*(?:\\*["'])?[ \t]*(?:(?:Bearer|Basic|Token|Digest|OAuth|Negotiate|NTLM|SSWS|ApiKey|Api-Key|Splunk)[ \t]*)?$/i;
const CUT_URL_TAIL_PATTERN = /([a-z][a-z0-9+.-]*:\/\/(?:\[REDACTED\]|[^\s"'<>()[\]{}\\])*?)[?#&](?!\[REDACTED\]$)[^\s?#&"'<>()[\]{}\\]*$/i;
const CUT_TAIL_PATTERN = /(?:[ \t]|\\+|[?#&]+)+$/;
const CUT_WORD_CHARACTER_PATTERN = /[A-Za-z0-9_-]/;
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
// comes back unchanged because `[REDACTED]` matches none of them and a value position that already
// holds the marker is left alone.
// ---------------------------------------------------------------------------------------------

// PEM blocks (private keys, certificates) and an unterminated PEM header, which is redacted to the end.
const PEM_BLOCK_PATTERN = /-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----/g;
const PEM_OPEN_PATTERN = /-----BEGIN [A-Z0-9 ]+-----[\s\S]*$/;

// Any scheme-prefixed URL wherever it sits in the text: the userinfo is dropped, the query and the
// fragment are replaced, the scheme, host, and path stay because they name the surface. A marker
// already standing in the query or fragment is consumed with the URL so a second pass is a no-op,
// and a backslash ends the URL so a JSON-escaped closing quote is kept.
const EMBEDDED_URL_PATTERN = /\b[a-z][a-z0-9+.-]*:\/\/(?:\[REDACTED\]|[^\s"'<>()[\]{}\\])+/gi;
const URL_PARTS_PATTERN = /^([a-z][a-z0-9+.-]*:\/\/)(?:[^\s/@"'<>]+@)?([^?#]*)(\?[^#]*)?(#.*)?$/i;
const TRAILING_PUNCTUATION_PATTERN = /[.,;:!?]+$/;

// A relative path or bare query string: the named parameter keeps its name, the value goes. A
// backslash ends the value so a JSON-escaped closing quote is kept.
const QUERY_PAIR_PATTERN = /([?&])([A-Za-z0-9_.[\]-]+)=(?!\[REDACTED\])([^&#\s"'<>\\]+)/g;

// Carriers. Each carrier pattern matches a name and its separator only; the value that follows is read
// by a quote-aware reader (see "Carrier values"), never by the pattern, so a quoted value is removed
// whole and a JSON-escaped quote is a quote rather than a value character. A carrier name stands on
// its own: it is preceded by neither a word character nor "-", ".", or "/", so `sdk-keys:`,
// `environment-token`, `settings.token`, and `/_security/api_key:` are names and paths, not carriers.
// A JSON escape sequence ends the run before a name: over JSON-encoded text, and inside the nested
// strings `describeErrorBody` reads, a line break or tab is the two characters `\n`, `\r`, `\t`
// (also `\b`, `\f`, `\v`, and `\uXXXX`), so the letter of the escape is a boundary and
// `request failed\napi_key=<value>`, `\tpassword: <value>`, `\nX-Api-Key: <value>`, and
// `\r\nBearer <value>` are carriers as they are after a raw line break.
const NAME_START = String.raw`(?:(?<![A-Za-z0-9_/.-])|(?<=\\[nrtbfv]|\\u[0-9A-Fa-f]{4}))`;
// The quote that may close a quoted carrier name in JSON or JSON-escaped text (`"X-Api-Key":`,
// `\"X-Api-Key\":`), then the separator with any spacing around it.
const NAME_CLOSE_AND_SEPARATOR = String.raw`(?:\\*["'])?\s*[:=]\s*`;

// Cookie and Set-Cookie headers: the whole header value is replaced by one marker, whether it is
// quoted, a `name=value` pair followed by attributes whose values may themselves be quoted, or a bare
// run after the singular header name (`cookies: enabled` is prose). No cookie name or value begins at
// a bracket, so a JSON array or object after `"cookies":` is left to the rules that read inside it.
const COOKIE_HEADER_PATTERN = new RegExp(String.raw`${NAME_START}(set-cookie|cookies?)${NAME_CLOSE_AND_SEPARATOR}`, "gi");
const COOKIE_PAIR_NAME_PATTERN = /[^\s;,"'<>=()[\]{}\\]+/y;
const COOKIE_BARE_VALUE_PATTERN = /[^\s;,"'<>()[\]{}\\]*/y;
// A later pair or attribute name after `;`: the pair-name class less `:`, so any RFC 6265 token
// character continues the scan (`my.sid`, `ASP.NET_SessionId`, `.AspNetCore.Session`, `~sid!`) and a
// `; Name:` token still ends the value for the next header on a compound line (CodeRabbit on #78).
const COOKIE_ATTRIBUTE_PATTERN = /;[ \t]*[^\s;,:"'<>=()[\]{}\\]+/y;
// The compound-line rule, the same in every scrubber: a quoted value ends at its closing quote; an
// unquoted cookie or header value, and a quoted one that is never closed, ends at the `;` or `,` that
// introduces the next `Name:` token on the line (`Cookie: sid=<v>; X-Api-Key: "<v>"; Content-Type:
// "application/json"`), or at the end of the line; the header after it keeps its name and gets its
// own carrier treatment. A cookie attribute is `Name` or `Name=value`, never `Name:`, so the token is
// unambiguous there, and a closed quoted value with a plain `;` or `,` inside (`"text/html;
// charset=utf-8"`, `"Mon, 22 Sep 2026 12:30:00 GMT"`) or even a `; Name:` inside still ends at its
// closing quote.
const FOLLOWING_HEADER_PATTERN = /[;,][ \t]*[A-Za-z][A-Za-z0-9_-]*[ \t]*:/y;

// Headers whose value is a credential in any shape: the standard and vendor names, and any `x-` header
// whose name carries a credential word unless its last segment says the value is a descriptor
// (`x-snowflake-authorization-token-type: KEYPAIR_JWT`). A scheme word in front of the value is kept
// so the message still says which scheme was replayed.
const CREDENTIAL_HEADER_NAMES: readonly string[] = ["authorization", "proxy-authorization", "api-key", "apikey", "private-token", "dd-api-key", "dd-application-key", "ocp-apim-subscription-key"];
const GENERIC_CREDENTIAL_HEADER = String.raw`x-[a-z0-9-]*(?:key|token|secret|auth|session|password|credential)[a-z0-9-]*`;
const CREDENTIAL_HEADER_PATTERN = new RegExp(String.raw`${NAME_START}(${CREDENTIAL_HEADER_NAMES.join("|")}|${GENERIC_CREDENTIAL_HEADER})\b${NAME_CLOSE_AND_SEPARATOR}`, "gi");
const HEADER_DESCRIPTOR_SUFFIX_PATTERN = /-(?:type|mode|scheme|method|status|version|timeout|ttl|expires|expiry|expiration|count|limit|name|url|uri|endpoint|header)$/i;

// A scheme word in front of a header or pair value (`Authorization: Bearer <value>`, `"Bearer <value>"`)
// is kept and the value after it goes; a scheme word with nothing after it (`Authorization: Bearer` at
// the end of a line) is the whole value and stays. The spacing does not cross a line, so a scheme word
// ending a line is not joined to the next line's first word.
const VALUE_SCHEME_PATTERN = /(?:Bearer|Basic|Token|Digest|OAuth|Negotiate|NTLM|SSWS|ApiKey|Api-Key|Splunk)(?![A-Za-z0-9_-])[ \t]*/iy;
// A bare header value runs to the first character that ends a header value in free text; a bare pair
// value also stops at "&" and the closing brackets of a JSON or query fragment. A backslash ends both
// so a JSON-escaped closing quote is kept, and neither can begin at "[" so the marker is never a value.
const HEADER_BARE_VALUE_PATTERN = /[^\s,;"'<>()[\]{}\\]+/y;
const PAIR_BARE_VALUE_PATTERN = /[^\s"',;&<>()[\]{}\\]+/y;
// Punctuation that closes a clause rather than a value (`password: <value>.`, `token=<value>:`); it is
// left standing after the marker so the sentence keeps its shape.
const CLAUSE_PUNCTUATION_PATTERN = /[.:]+$/;
// A character that continues a value glued to a marker (`[REDACTED]abc` is not scrubbed text; see
// `isBlankOrScrubbed`).
const VALUE_CHARACTER_PATTERN = /[A-Za-z0-9_~+/=%-]/;
// What follows a quote that closes the enclosing JSON string rather than opening a value: the
// structure after a string (`{"detail":"Authorization: Bearer"}`, `"note":"X-Api-Key:", "next"`). No
// credential value begins with one of these, so such a quote is not a value opener (see `opensValue`).
const ENCLOSING_STRING_CLOSE_PATTERN = /^[}\],]/;
// The JSON literals hold no credential (`"password": null`, `"otp": true`), as in `redactSecretValues`.
const JSON_LITERAL_PATTERN = /^(?:null|true|false)$/;

// Authorization schemes in free text (`Bearer <value>`, `Basic <base64>`, Okta `SSWS`, GitHub `Token`,
// Splunk `Splunk`): the value goes whatever its casing or entropy unless it is one plain word, which
// is prose ("Basic authentication is disabled", "Token request failed", "OAuth bearer token", "Splunk
// Enterprise"). The exemption is derived from the fixed texts the integrations emit after these
// words (121 distinct continuations across every integration source): every one is a single word of
// letters in one casing (the longest, "authentication", has 14) or a hyphenated compound of lowercase
// words ("OAuth sign-in", "OAuth service-app"), a dotted version ("OAuth 2.0"), or an auth-param of a
// challenge (`Bearer realm="api"`, `error="invalid_token"`). A value with a digit, a symbol, or mixed
// casing inside a word is never prose. "token", "basic", "digest", "oauth", and "splunk" in lowercase
// are English words as often as schemes ("token canary-noexpiry-token-zq has no expiry" names a
// LaunchDarkly token; "basic authentication is disabled"), yet a peer's error text may spell a scheme
// in lowercase (Codex P1 on #78: "replayed basic dXNlcjpwYXNz upstream"), so the lowercase spellings
// are weaker carriers: the value goes only when it cannot be a word or a name, that is when it carries
// a digit, a symbol, or mixed casing inside the word, and is at least `LOWERCASE_SCHEME_VALUE_MIN_LENGTH`
// characters (main's floor at 02967cc); a word in either casing or a hyphenated lowercase compound of
// any length after them is prose. Every one of the 103 distinct continuations after these spellings in
// the sources is prose under this rule. A quoted value is delimited by its quotes and goes whole when
// it begins like a credential; in `"Basic ", "token"` inside a JSON document the quote after the
// scheme word closes one string rather than opening a value.
const SCHEME_WORD_PATTERN = new RegExp(String.raw`${NAME_START}(?:Bearer|BEARER|bearer|Basic|BASIC|basic|Token|TOKEN|token|Digest|digest|OAuth|oauth|Negotiate|NTLM|SSWS|ApiKey|Apikey|apikey|APIKEY|Api-Key|api-key|Splunk|splunk)[ \t]+`, "g");
const LOWERCASE_SCHEME_WORDS = new Set(["basic", "token", "digest", "oauth", "splunk"]);
const SCHEME_BARE_VALUE_PATTERN = /[A-Za-z0-9][A-Za-z0-9._~+/=-]{3,}/y;
const SCHEME_VALUE_MIN_LENGTH = 4;
const LOWERCASE_SCHEME_VALUE_MIN_LENGTH = 8;
const QUOTED_SCHEME_VALUE_START_PATTERN = /^[A-Za-z0-9]/;
const PLAIN_WORD_PATTERN = /^(?:[A-Z]?[a-z]+(?:-[a-z]+)*|[A-Z]+)$/;
const PLAIN_WORD_MAX_LENGTH = 20;
const VERSION_PATTERN = /^\d+(?:\.\d+)+$/;
const AUTH_PARAM_PATTERN = /^(?:realm|error|error_description|error_uri|scope|charset|algorithm|qop|stale|domain|opaque|title|resource|client_id|authorization_uri|as_uri|ticket)=/i;

// Credential-named pairs in prose, headers, query strings, and JSON fragments: the key and separator
// stay, the value goes whatever its shape (coordinator ruling on the Codex P2: any nonempty value
// under a credential-classified key is redacted regardless of shape). The names are the credential
// words themselves, the session names, the signed-URL and OAuth 1 parameters, and Duo's key names;
// compound keys the Flue heuristic classifies (`client_token`, `DB_PASSWORD`, `clientToken`,
// `InvalidAuthenticationToken`) are handled by the generic pair rule below under the same ruling,
// with the one prose exemption described there, and a compound key whose final segment is a setting
// suffix (`token_url`, `auth_method`, `client_id`) is a setting, not a credential key (see
// `SETTING_SUFFIXES`).
const CREDENTIAL_PAIR_NAMES: readonly string[] = [
  "api[_-]?key",
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
  "passcode",
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
  "session(?:[_-]?(?:id|token|key))?",
  "sid",
  "sessid",
  "jsessionid",
  "phpsessid",
  "asp\\.net_sessionid",
  "xsrf[_-]?token",
  "csrf[_-]?token",
  "x-amz-signature",
  "x-amz-credential",
  "x-amz-security-token",
  "x-goog-signature",
  "x-goog-credential",
  "oauth_signature",
  "oauth_token",
  "oauth_verifier",
  "nonce",
  "otp",
  "totp",
  "ikey",
  "skey",
];
const CREDENTIAL_PAIR_PATTERN = new RegExp(String.raw`${NAME_START}(?:${CREDENTIAL_PAIR_NAMES.join("|")})\b${NAME_CLOSE_AND_SEPARATOR}`, "gi");

// Every other `key=value`, `key: value`, `"key":"value"`, or `Header-Name: value` pair whose key names
// a credential by the Flue heuristic (`client_token`, `DB_PASSWORD`, `clientToken`, `user_session`,
// `tokens`, `InvalidAuthenticationToken`): the key and separator stay and the value goes whatever its
// shape, as under `CREDENTIAL_PAIR_PATTERN` (a human-chosen password under `DB_PASSWORD=` or
// `admin_password:` is a credential as much as an issued token). The separator is captured because
// the one exemption, a value that continues as prose, is read only after `Key: ` (see
// `continuesAsProse`); `=` is an assignment and its value is always the credential.
const GENERIC_PAIR_KEY_PATTERN = new RegExp(String.raw`${NAME_START}([A-Za-z][A-Za-z0-9_.-]{0,63})\b(?:\\*["'])?(\s*[:=]\s*)`, "g");
// The prose exemption of the generic pair rule: a value continues as prose when it is one plain word
// of letters (lowercase or capitalised, at most `PROSE_WORD_MAX_LENGTH` letters) or a count of at
// most five digits, followed on the same line by a space and another word, number, or parenthesis,
// as in "InvalidAuthenticationToken: Access token has expired", "TokenExpired: The token has
// expired", "access_tokens: seen 40 of 120", "tokens: 3 of 5 rotated", or "secrets: unreadable (GET
// /v1/secrets failed with 403 Forbidden)". The shape is no wider than the rule main shipped at
// 02967cc (a value of six characters or more with a digit, a symbol, a case change inside the word,
// or twelve characters redacts); the continuation requirement is new, so a word standing alone after
// the separator (`client_token: expired`, `secrets: truncated`) is the value and goes.
const PROSE_WORD_PATTERN = /^(?:[a-z]+|[A-Z][a-z]*|\d{1,5})$/;
const PROSE_WORD_MAX_LENGTH = 11;
const PROSE_SEPARATOR_PATTERN = /:[ \t]+$/;
const PROSE_CONTINUATION_PATTERN = /[ \t]+[A-Za-z0-9(]/y;

// JWT and JWE compact serialisations, AWS access key ids, and 40-character AWS secret access keys.
// The secret shape is matched after any assignment operator too: `=` is not in the lookbehind, since
// base64 padding ends a value and never precedes one, so `x=<secret>` and `ENV_VALUE=<secret>` under a
// key that does not name a credential are caught by this rule (the pair rule handles credential keys).
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)*/g;
const AWS_ACCESS_KEY_ID_PATTERN = /\b(?:AKIA|ASIA|AROA|AIDA|AGPA|ANPA|ANVA|APKA|ABIA|ACCA)[A-Z0-9]{16}\b/g;
const AWS_SECRET_PATTERN = /(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])/g;

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

// The long-token rule. "/", ".", ":", "@", "=", and whitespace are not run characters, so URL path
// segments, dotted hostnames, colon-separated ARNs, emails, and the two sides of a `key=value` pair
// are judged on their own; "=" joins a run only as trailing base64 padding. "-" and "_" stay in the
// run and split it into name segments (see `isNameSegment`).
const LONG_TOKEN_RUN_PATTERN = new RegExp(`[A-Za-z0-9+_-]{${LONG_TOKEN_MIN_LENGTH},}(?:={1,2}(?![A-Za-z0-9&]))?`, "g");
// The letter of a JSON escape in front of a run (`\n`, `\t`, `\uXXXX`, see `NAME_START`) belongs to
// the escape, not to the run: over JSON-encoded text `\nInvalidAuthenticationToken=` is the code
// after a line break, not a 28-character padded token.
const ESCAPE_LETTER_PATTERN = /^(?:[nrtbfv]|u[0-9A-Fa-f]{4})/;
const UPPERCASE_CODE_PATTERN = /^[A-Z][A-Z_]*$|^[A-Z][A-Z0-9]*(?:[_-][A-Z0-9]+)+$/;
const DIGITS_ONLY_PATTERN = /^\d+$/;
const DIGIT_GROUP_PATTERN = /\d+/g;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Below this many letters a segment's casing is not judged: `eBay`, `iOS`, `McD` are names, and a
// token this short is caught by its digit groups or its neighbours.
const MIN_LETTERS_FOR_CASING = 6;

// Keys that name a credential in query strings and name-value pairs beyond what the Flue heuristic
// covers: bare `sid`, `sig`, `pwd`, `session`, `auth`, and the signed-URL parameters of S3 and GCS.
const EXTRA_CREDENTIAL_KEY_SEGMENTS = new Set(["sid", "sig", "pwd", "passwd", "pass", "session", "sessid", "auth", "nonce", "sas"]);

// Settings beside a credential word (coordinator ruling after reviewer A found five settings
// over-redacted in group A once its shape gate went): a key whose final segment is a setting suffix
// names a setting, not a credential, even when an earlier segment is a credential word
// (`BOX_AUTH_METHOD=ccg`, `BOX_TOKEN_URL=https://api.box.com/oauth2/token`, `BOX_JWT_ALGORITHM=RS256`,
// `auth_method=client_secret`, `token_endpoint=<url>`, `oauth_signature_method=HMAC-SHA1`,
// `secret_name`, `private_key_path`, `credentials_file`, `token_limit`), as does a threshold
// (`max_keys`, `min_password_length`) and an identifier (`client_id`, `api_key_id`, `tenant_id`,
// `key_name`). Its value stays unless it is token-shaped (the long-token decision, which the data
// scrubs apply to the value under such a key even though their long-token rule is otherwise off, so
// a 40-character `private_key_id` still goes) or a registered secret, and a URL value passes the URL
// rule like any other (userinfo and query removed, path kept). Two families stay credential keys
// whatever their suffix: the webhook and callback keys (`webhook*`, `*hook_url`, `callback_url`; rule
// 9 names webhook URLs with embedded tokens, `webhook_url=https://hooks.example.com/services/<token>`
// loses its whole value), and the session identifiers (`session_id`, `sid`, `PHPSESSID`,
// `ASP.NET_SessionId`), which are bearer credentials, not identifiers, and are explicit credential
// pair names. Both patterns and `SESSION_ID_KEY_PATTERN` read the key in its segment form
// (`webhookUrl` and `WEBHOOK_URL` are `webhook_url`).
const SETTING_SUFFIXES = new Set(["url", "uri", "endpoint", "method", "algorithm", "audience", "issuer", "shape", "type", "mode", "path", "file", "dir", "limit", "count", "id", "name", "days", "hours", "minutes", "seconds"]);
const THRESHOLD_KEY_PATTERN = /^(?:max|min)[_-]/i;
const WEBHOOK_KEY_PATTERN = /(?:^|_)webhooks?(?:_|$)|hook_url$|callback_url$/;
const SESSION_ID_KEY_PATTERN = /(?:^|_)(?:sid|sessid|jsessionid|phpsessid|session_id)$/;
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

/** The Flue argument-key heuristic plus the bare and signed-URL names it does not cover, before the setting rule. */
function namesCredential(key: string): boolean {
  if (isSensitiveArgumentKey(key)) return true;
  const normalized = key.toLowerCase();
  if (EXTRA_CREDENTIAL_KEYS.has(normalized)) return true;
  return keySegments(key).some((segment) => EXTRA_CREDENTIAL_KEY_SEGMENTS.has(segment));
}

/** A key whose final segment is a setting suffix, or a threshold (`max_`, `min_`); see `SETTING_SUFFIXES`. */
function isSettingKey(key: string): boolean {
  if (THRESHOLD_KEY_PATTERN.test(key)) return true;
  const segments = keySegments(key);
  return segments.length > 1 && SETTING_SUFFIXES.has(segments[segments.length - 1]);
}

/**
 * True when a name in a query string, header, or name-value pair carries a credential: the Flue
 * argument-key heuristic (`token`, `secret`, `password`, `api_key`, `authorization`, `cookie`, ...)
 * plus the bare and signed-URL names it does not cover. A key whose final segment is a setting suffix
 * (`token_url`, `auth_method`, `client_id`, `credentials_file`, see `SETTING_SUFFIXES`) is a setting
 * and is not a credential key; the webhook, callback, and session-identifier keys are credential keys
 * whatever their suffix.
 */
export function isCredentialKey(key: string): boolean {
  const joined = keySegments(key).join("_");
  if (WEBHOOK_KEY_PATTERN.test(joined) || SESSION_ID_KEY_PATTERN.test(joined)) return true;
  if (isSettingKey(key)) return false;
  return namesCredential(key);
}

/**
 * A setting whose earlier segments name a credential (`token_url`, `BOX_AUTH_METHOD`, `private_key_id`,
 * `api_key_name`): the value is a setting and stays, except that a token-shaped run inside it goes
 * under every scrub, the data scrubs included (see `SETTING_SUFFIXES`).
 */
function isCredentialWordSetting(key: string): boolean {
  if (!isSettingKey(key)) return false;
  const segments = keySegments(key);
  return segments.length > 1 && namesCredential(segments.slice(0, -1).join("_"));
}

/**
 * The prose exemption of the generic pair rule (see `PROSE_WORD_PATTERN`): true when the bare value
 * that starts after `separator` is one plain word that another word or number follows on the same
 * line. `valueEnd` is the index just past the value.
 */
function continuesAsProse(text: string, separator: string, value: string, valueEnd: number): boolean {
  if (!PROSE_SEPARATOR_PATTERN.test(separator)) return false;
  if (value.length > PROSE_WORD_MAX_LENGTH || !PROSE_WORD_PATTERN.test(value)) return false;
  return stickyExec(PROSE_CONTINUATION_PATTERN, text, valueEnd) !== null;
}

/**
 * A bare value after an authorization scheme word in free text is the credential whatever its casing
 * or entropy, except for the shapes the fixed texts put there (see `SCHEME_WORD_PATTERN`): one plain
 * word or hyphenated compound of lowercase words shorter than `PLAIN_WORD_MAX_LENGTH` ("Basic
 * authentication", "Splunk Enterprise", "SSWS API", "OAuth sign-in"), a dotted version ("OAuth 2.0"),
 * or an auth-param of a challenge (`Bearer realm="api"`). The residue of the exemption is a
 * credential made only of lowercase letters and hyphens and shorter than 20 characters, which is a
 * passphrase rather than an issued token; anything with a digit, a symbol, or mixed casing goes.
 */
function looksLikeSchemeValue(value: string, lowercaseScheme = false): boolean {
  if (lowercaseScheme && value.length < LOWERCASE_SCHEME_VALUE_MIN_LENGTH) return false;
  if (PLAIN_WORD_PATTERN.test(value) && (lowercaseScheme || value.length < PLAIN_WORD_MAX_LENGTH)) return false;
  return !VERSION_PATTERN.test(value) && !AUTH_PARAM_PATTERN.test(value);
}

/** A 40-character run is an AWS secret access key when it carries base64 symbols or a digit with both cases; lowercase hex digests are left to the long-token rule. */
function looksLikeAwsSecret(run: string): boolean {
  if (/[/+]/.test(run)) return true;
  return /\d/.test(run) && /[a-z]/.test(run) && /[A-Z]/.test(run);
}

/**
 * Token-shaped casing: the case changes more often than once every three letters. Words, acronyms,
 * camelCase, and PascalCase names change case at word boundaries (`AWSLambdaBasicExecutionRole`,
 * `IAMReadOnlyAccess`, `getHTTPSUrl`: one change per four letters or fewer); a random run changes
 * about every second letter (`bPxRfiCYcanaryKEY`).
 */
function hasTokenCasing(letters: string): boolean {
  if (letters.length < MIN_LETTERS_FOR_CASING) return false;
  let changes = 0;
  for (let index = 1; index < letters.length; index += 1) {
    const previousLower = letters[index - 1] >= "a" && letters[index - 1] <= "z";
    const currentLower = letters[index] >= "a" && letters[index] <= "z";
    if (previousLower !== currentLower) changes += 1;
  }
  return changes * 3 > letters.length;
}

/**
 * A segment between "-" or "_" that is shaped like part of a name: empty, digits alone (account ids,
 * ports, years, project numbers), or letters with at most one digit group anywhere (`west2`, `ec2`,
 * `sha256`, `oauth2Client`, `AmazonS3ReadOnlyAccess`, `2fa`) whose casing is not token-shaped.
 * Digits scattered through letters (`0f9e8d7c6b5a4938`, `Kq7Zx2Vw9Lm4Tp8R`) are the token signal.
 */
function isNameSegment(segment: string): boolean {
  if (segment.length === 0 || DIGITS_ONLY_PATTERN.test(segment)) return true;
  const digitGroups = segment.match(DIGIT_GROUP_PATTERN) ?? [];
  if (digitGroups.length > 1) return false;
  return !hasTokenCasing(segment.replace(DIGIT_GROUP_PATTERN, ""));
}

/**
 * The long-token rule's decision (see `LONG_TOKEN_MIN_LENGTH`): a run is a token when it carries
 * base64 symbols, or when any of its "-" or "_" separated segments is not shaped like part of a name.
 * Uppercase codes, digit strings, and canonical UUIDs are names outright.
 */
function looksLikeToken(run: string): boolean {
  if (UPPERCASE_CODE_PATTERN.test(run) || DIGITS_ONLY_PATTERN.test(run) || UUID_PATTERN.test(run)) return false;
  if (/[+=]/.test(run)) return true;
  return !run.split(/[-_]/).every(isNameSegment);
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

// ---------------------------------------------------------------------------------------------
// Carrier values. A carrier pattern matches a name and its separator; the value after it is read
// here, quote-aware, and replaced whole. Group A settled this shape for its `credential-scrub.ts`
// (Codex P1, quoted header value) and the two scrubbers agree on it.
// ---------------------------------------------------------------------------------------------

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
 * Reads a quoted value opening at `index`: a double or single quote with any backslashes that escape
 * it in JSON or JSON-escaped text (`"value"`, `\"value\"`, `\\\"value\\\"`). The value ends at the same
 * quote token at the same escaping depth. Inside a value whose opening quote carries `depth`
 * backslashes, one literal backslash is written as `depth + 1` backslashes and the quote's own escape
 * as `depth`, so a run of `r` backslashes before the quote character stands for `(r - depth) /
 * (depth + 1)` literal backslashes: an even number of them means the quote closes the value, an odd
 * number means the quote is content (`"a\"b"`, and its JSON form `\"a\\\"b\"`), and a non-integer means
 * the quote belongs to an enclosing string and the value is unterminated. The closing quote comes
 * first: a closed value that holds `; Name:` is one value (`X-Api-Key: "<v>; note: x"`). Only an
 * unterminated value is cut at the compound-line rule: it ends at the first `; Name:` or `, Name:`
 * token passed on the line, otherwise at the enclosing quote or the end of the line or text. A quote
 * that stands right after such a token opens that header's value rather than closing this one
 * (`sid="<v>; X-Api-Key: "<v>"` ends before `; X-Api-Key:`), so a truncated carrier still loses its
 * value and the header after it keeps its name and gets its own rule.
 */
function readQuotedValue(text: string, index: number): QuotedValue | null {
  const depth = backslashRun(text, index);
  const quote = text[index + depth];
  if (quote !== '"' && quote !== "'") return null;
  const open = text.slice(index, index + depth + 1);
  const start = index + open.length;
  let cursor = start;
  // The first following-header token passed (where an unterminated value ends) and the index just
  // past the separator of the latest one (a quote standing there opens that header's value).
  let firstHeaderCut = -1;
  let latestHeaderValueStart = -1;
  const unterminated = (end: number): QuotedValue => {
    const cut = firstHeaderCut >= 0 && firstHeaderCut < end ? firstHeaderCut : end;
    return { open, close: "", start, end: cut, after: cut };
  };
  while (cursor < text.length) {
    const char = text[cursor];
    if (char === "\n" || char === "\r") break;
    if (char === ";" || char === ",") {
      const token = stickyExec(FOLLOWING_HEADER_PATTERN, text, cursor);
      if (token !== null) {
        if (firstHeaderCut < 0) firstHeaderCut = cursor;
        latestHeaderValueStart = skipSpaces(text, cursor + token.length);
      }
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
    const literalBackslashes = (run - depth) / (depth + 1);
    if (run < depth || !Number.isInteger(literalBackslashes)) {
      return unterminated(cursor + Math.floor(run / (depth + 1)) * (depth + 1));
    }
    if (literalBackslashes % 2 === 0) {
      if (cursor === latestHeaderValueStart) return unterminated(cursor);
      const end = cursor + run - depth;
      return { open, close: text.slice(end, cursor + run + 1), start, end, after: cursor + run + 1 };
    }
    cursor += run + 1;
  }
  return unterminated(cursor);
}

interface ValueReplacement {
  /** Index just past the text the replacement covers. */
  end: number;
  /** The text written in place of `text.slice(valueStart, end)`. */
  replacement: string;
}

/** A reader receives the text, the index just past the carrier's name and separator, and the carrier match. */
type ValueReader = (text: string, valueStart: number, carrier: RegExpExecArray) => ValueReplacement | null;

function stickyExec(pattern: RegExp, text: string, index: number): string | null {
  pattern.lastIndex = index;
  return pattern.exec(text)?.[0] ?? null;
}

/**
 * A value position already holding the marker is left alone so a second pass over scrubbed text is a
 * no-op: blank, the marker alone, or the marker followed by something that is not a value character,
 * which is what a renderer or the cut appends after an unterminated quoted value (`"password":
 * "[REDACTED])`, `"[REDACTED]; two)`, `"[REDACTED] [truncated]`). A marker glued to a value
 * (`[REDACTED]abc`) is not scrubbed text and goes with it.
 */
function isBlankOrScrubbed(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed === REDACTED) return true;
  return trimmed.startsWith(REDACTED) && !VALUE_CHARACTER_PATTERN.test(trimmed.charAt(REDACTED.length));
}

/**
 * Whether a quote read at a value position opens a value: false when what it encloses begins with
 * the structure that follows a JSON string (`}`, `]`, `,`), which means the quote closed the string
 * the carrier stands in (`{"detail":"Authorization: Bearer"}`) and the carrier has no value here.
 */
function opensValue(text: string, quoted: QuotedValue): boolean {
  return !ENCLOSING_STRING_CLOSE_PATTERN.test(text.slice(quoted.start, quoted.end));
}

function skipSpaces(text: string, index: number): number {
  let cursor = index;
  while (text[cursor] === " " || text[cursor] === "\t") cursor += 1;
  return cursor;
}

/**
 * Replaces the value after every match of `carrierPattern` (a global pattern matching a carrier's name
 * and separator) with what `readValue` returns for it, leaving the name and separator in place. A
 * reader that returns null leaves the text alone and scanning continues after the carrier's name.
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
 * The bare value at `index` under a header or pair carrier, without the clause punctuation that may
 * follow it; null when there is none to remove (nothing, the marker, a JSON literal, or the rest of a
 * comparison operator: `tokens == 3` and `tokensSnap.status === "ok"` compare, they assign nothing).
 */
function readBareValue(text: string, index: number, barePattern: RegExp): string | null {
  const bare = stickyExec(barePattern, text, index);
  if (bare === null) return null;
  const value = bare.replace(CLAUSE_PUNCTUATION_PATTERN, "");
  if (value.length === 0 || value.startsWith("=") || isBlankOrScrubbed(value) || JSON_LITERAL_PATTERN.test(value)) return null;
  return value;
}

/**
 * Reads the value of a header or credential-named pair: a quoted value goes whole up to its closing
 * quote with the quotes and a leading scheme word kept (`"Bearer value"` becomes `"Bearer
 * [REDACTED]"`); a bare value may carry a scheme word in front of it and then either a quoted value
 * (`Bearer "value"`) or a bare run. A bare run is kept when `keepBare` says so (the generic pair
 * rule's prose exemption, which reads the word after a scheme word too so `token_type: Bearer token
 * expected` stays); a quoted value is never prose.
 */
function readCarrierValue(text: string, valueStart: number, barePattern: RegExp, keepBare?: (value: string, valueEnd: number) => boolean): ValueReplacement | null {
  const quoted = readQuotedValue(text, valueStart);
  if (quoted !== null) {
    if (!opensValue(text, quoted)) return null;
    const content = text.slice(quoted.start, quoted.end);
    const scheme = stickyExec(VALUE_SCHEME_PATTERN, content, 0) ?? "";
    if (isBlankOrScrubbed(content.slice(scheme.length))) return null;
    return { end: quoted.after, replacement: `${quoted.open}${scheme}${REDACTED}${quoted.close}` };
  }
  const scheme = stickyExec(VALUE_SCHEME_PATTERN, text, valueStart) ?? "";
  const afterScheme = valueStart + scheme.length;
  const quotedAfterScheme = scheme.length > 0 ? readQuotedValue(text, afterScheme) : null;
  if (quotedAfterScheme !== null) {
    if (!opensValue(text, quotedAfterScheme) || isBlankOrScrubbed(text.slice(quotedAfterScheme.start, quotedAfterScheme.end))) return null;
    return { end: quotedAfterScheme.after, replacement: `${scheme}${quotedAfterScheme.open}${REDACTED}${quotedAfterScheme.close}` };
  }
  const value = readBareValue(text, afterScheme, barePattern);
  if (value === null) return null;
  const valueEnd = afterScheme + value.length;
  if (keepBare?.(value, valueEnd)) return null;
  return { end: absorbMarkers(text, valueEnd), replacement: `${scheme}${REDACTED}` };
}

/**
 * Extends a bare value's end over the markers an earlier rule left glued to it: the URL rule has
 * already turned the query and fragment of a URL value into `?[REDACTED]#[REDACTED]`, so the pair
 * renders one marker (`callback_url=[REDACTED]`) rather than `[REDACTED][REDACTED]#[REDACTED]`.
 */
function absorbMarkers(text: string, index: number): number {
  let cursor = index;
  for (;;) {
    if (text.startsWith(REDACTED, cursor)) cursor += REDACTED.length;
    else if ((text[cursor] === "?" || text[cursor] === "#") && text.startsWith(REDACTED, cursor + 1)) cursor += REDACTED.length + 1;
    else return cursor;
  }
}

/**
 * The value under a credential-word setting (see `isCredentialWordSetting`): kept as it is unless the
 * long-token rule finds a token-shaped run in it, in which case the run is replaced and the rest of
 * the value (the scheme, host, and path of a URL, a name) stays.
 */
function readSettingValue(text: string, valueStart: number): ValueReplacement | null {
  const quoted = readQuotedValue(text, valueStart);
  if (quoted !== null) {
    if (!opensValue(text, quoted)) return null;
    const content = text.slice(quoted.start, quoted.end);
    const scrubbed = replaceLongTokenRuns(content);
    return scrubbed === content ? null : { end: quoted.after, replacement: `${quoted.open}${scrubbed}${quoted.close}` };
  }
  const value = readBareValue(text, valueStart, PAIR_BARE_VALUE_PATTERN);
  if (value === null) return null;
  const scrubbed = replaceLongTokenRuns(value);
  return scrubbed === value ? null : { end: valueStart + value.length, replacement: scrubbed };
}

/** A credential header's value, unless the header name says the value is a descriptor (`...-token-type`). */
const readHeaderValue: ValueReader = (text, valueStart, carrier) => (HEADER_DESCRIPTOR_SUFFIX_PATTERN.test(carrier[1]) ? null : readCarrierValue(text, valueStart, HEADER_BARE_VALUE_PATTERN));
const readPairValue: ValueReader = (text, valueStart) => readCarrierValue(text, valueStart, PAIR_BARE_VALUE_PATTERN);

/** Index just past a cookie pair's or attribute's value, which may be quoted. */
function cookieValueEnd(text: string, index: number): number {
  const quoted = readQuotedValue(text, index);
  if (quoted !== null) return quoted.after;
  return index + (stickyExec(COOKIE_BARE_VALUE_PATTERN, text, index)?.length ?? 0);
}

/**
 * Reads a Cookie or Set-Cookie header value: quoted whole; `name=value` (spaces around "=" allowed)
 * followed by attributes (`; Path=/; HttpOnly`) whose values may themselves be quoted; or a bare run
 * after the singular header name. The whole header value is replaced by one marker. The value ends at
 * ",", at a `; Name:` token (the next header on a compound line, which is never a cookie attribute, so
 * the ";" and the name stay for that header's own rule), or at the line end.
 */
const readCookieHeaderValue: ValueReader = (text, valueStart, carrier) => {
  const quoted = readQuotedValue(text, valueStart);
  if (quoted !== null) {
    if (!opensValue(text, quoted) || isBlankOrScrubbed(text.slice(quoted.start, quoted.end))) return null;
    return { end: quoted.after, replacement: `${quoted.open}${REDACTED}${quoted.close}` };
  }
  const name = stickyExec(COOKIE_PAIR_NAME_PATTERN, text, valueStart);
  if (name === null) return null;
  const separator = skipSpaces(text, valueStart + name.length);
  if (text[separator] !== "=") {
    if (carrier[1].toLowerCase() === "cookies") return null;
    const value = readBareValue(text, valueStart, COOKIE_PAIR_NAME_PATTERN);
    return value === null ? null : { end: valueStart + value.length, replacement: REDACTED };
  }
  let cursor = cookieValueEnd(text, skipSpaces(text, separator + 1));
  let attribute: string | null;
  while ((attribute = stickyExec(COOKIE_ATTRIBUTE_PATTERN, text, cursor)) !== null) {
    const attributeSeparator = skipSpaces(text, cursor + attribute.length);
    if (text[attributeSeparator] === ":") break;
    cursor += attribute.length;
    if (text[attributeSeparator] === "=") cursor = cookieValueEnd(text, skipSpaces(text, attributeSeparator + 1));
  }
  return { end: cursor, replacement: REDACTED };
};

/**
 * Reads the value after a bare scheme word in free text: a quoted value goes whole when it begins like
 * a credential; a bare value goes unless it is one of the prose shapes (see `looksLikeSchemeValue`).
 * After a lowercase English-word spelling (`basic`, `token`, `digest`, `oauth`, `splunk`) a bare or
 * quoted value goes only when it cannot be a word or a name.
 */
const readSchemeValue: ValueReader = (text, valueStart, carrier) => {
  const lowercaseScheme = LOWERCASE_SCHEME_WORDS.has(carrier[0].trim());
  const quoted = readQuotedValue(text, valueStart);
  if (quoted !== null) {
    const content = text.slice(quoted.start, quoted.end);
    if (isBlankOrScrubbed(content) || !QUOTED_SCHEME_VALUE_START_PATTERN.test(content)) return null;
    if (lowercaseScheme && !looksLikeSchemeValue(content, true)) return null;
    return { end: quoted.after, replacement: `${quoted.open}${REDACTED}${quoted.close}` };
  }
  const bare = stickyExec(SCHEME_BARE_VALUE_PATTERN, text, valueStart);
  if (bare === null) return null;
  const value = bare.replace(CLAUSE_PUNCTUATION_PATTERN, "");
  if (value.length < SCHEME_VALUE_MIN_LENGTH || !looksLikeSchemeValue(value, lowercaseScheme)) return null;
  return { end: valueStart + value.length, replacement: REDACTED };
};

/**
 * Replaces the value of every compound credential-named pair (the generic rule, see
 * `GENERIC_PAIR_KEY_PATTERN`). The key and separator are matched on their own and the value is
 * consumed only when the key names a credential, so the value of an ordinary pair is rescanned from
 * its second character and a credential pair nested inside it (`data=token=...`) or starting one
 * character later (`\napi_key=...`, where the pattern first takes `napi_key`) is still caught. The
 * value is read like a header's or an explicit credential pair's and goes whatever its shape, except
 * a bare word after `Key: ` that continues as prose (see `continuesAsProse`). Under a setting key
 * whose earlier segments name a credential (`token_url`, `auth_method`, `private_key_id`) only a
 * token-shaped run in the value goes (see `readSettingValue`).
 */
function replaceGenericCredentialPairs(text: string): string {
  GENERIC_PAIR_KEY_PATTERN.lastIndex = 0;
  let out = "";
  let last = 0;
  let match: RegExpExecArray | null;
  while ((match = GENERIC_PAIR_KEY_PATTERN.exec(text)) !== null) {
    const [whole, key, separator] = match;
    if (whole.length === 0) {
      GENERIC_PAIR_KEY_PATTERN.lastIndex += 1;
      continue;
    }
    const valueStart = match.index + whole.length;
    const credential = isCredentialKey(key);
    const read = credential
      ? readCarrierValue(text, valueStart, PAIR_BARE_VALUE_PATTERN, (value, valueEnd) => continuesAsProse(text, separator, value, valueEnd))
      : isCredentialWordSetting(key)
        ? readSettingValue(text, valueStart)
        : null;
    if (read === null) {
      if (!credential) GENERIC_PAIR_KEY_PATTERN.lastIndex = match.index + 1;
      continue;
    }
    out += `${text.slice(last, valueStart)}${read.replacement}`;
    last = read.end;
    GENERIC_PAIR_KEY_PATTERN.lastIndex = last;
  }
  return last === 0 ? text : `${out}${text.slice(last)}`;
}

/**
 * Removes credential material from free text: the configured secrets in every encoded form, PEM
 * blocks, the userinfo, query, and fragment of every embedded URL, credential parameters of bare
 * query strings, Cookie and Set-Cookie values, credential header values (Authorization,
 * Proxy-Authorization, x-api-key and the like, a scheme word in front of the value kept),
 * authorization scheme values in free text (Bearer, Basic, Digest, Token, OAuth, Negotiate, NTLM,
 * SSWS, ApiKey, Splunk), credential-named pairs in prose, headers, query strings, and JSON fragments
 * (the value whatever its shape, under the credential words themselves and under every compound or
 * env-style key `isCredentialKey` classifies, `DB_PASSWORD`, `client_token`, `clientToken`; the one
 * exemption is a plain word after `Key: ` that continues as prose, see `continuesAsProse`; a key whose
 * final segment is a setting suffix, `BOX_TOKEN_URL`, `auth_method`, `client_id`, is a setting whose
 * value stays unless token-shaped, see `SETTING_SUFFIXES`), JWTs,
 * AWS key ids and secret keys, well-known vendor token prefixes, and (unless turned
 * off) long token-shaped runs. A quoted carrier value is removed whole, quotes kept, in double or
 * single quotes and JSON-escaped at any depth; on a compound line the next header's `Name:` token ends
 * a cookie's attributes and an unterminated quoted value, so that header keeps its name and gets its
 * own rule. Idempotent. Every integration error string passes
 * through here at the point it is created; a scrub at the tool boundary is a second layer, not a
 * substitute, because the exported resolvers and collectors throw before the boundary is reached.
 *
 * Fixed text rule: every fixed-text message this library renders is chosen so it comes back from
 * this scrub unchanged (`hardening-fixed-text.test.mjs` renders each one and checks). Concretely, no
 * fixed credential word (`token`, `password`, `secret`, `credentials`, `api_key`, `session`, and the
 * rest of `CREDENTIAL_PAIR_NAMES`) and no credential header name is followed by a colon or an equals
 * sign, because the carrier rules take whatever follows as the value whatever its shape (`Service
 * account credentials: <path>` loses the path; `Token: non-JSON body` loses `non-JSON`;
 * `credentials: seen 40 of 120` loses `seen`); a path or other free value is rendered after a plain
 * word and a space (`config file <path>`, `in <path>`), never as the value of such a pair; an
 * inventory whose label `isCredentialKey` classifies (`tokens`, `secrets`, `api keys`) is followed
 * by a colon only when the text after it continues as prose (`tokens: seen 40 of 120`, `secrets:
 * unreadable (GET /v1/secrets failed with 403 Forbidden)`, `tokens: not collected`), never by a
 * colon and one bare word (`secrets: truncated` loses `truncated`; write `secrets truncated` or
 * `secrets inventory: truncated`); server text that could end in
 * a credential word is validated before it is placed in front of a colon (`reasonPhrase`); a scheme
 * word (`Bearer`, `Basic`, `Token`, `OAuth`, `Splunk`, ...) is followed only by a single plain word
 * or a hyphenated compound of lowercase words (`OAuth sign-in`), a dotted version (`OAuth 2.0`), a
 * bracket, or a line end; and no fixed word is a 16-character run with a digit or mixed case. A
 * message that must hand the scrub a free value labels it with a plain word (`file`, `in`, `for`),
 * not with a credential word.
 */
export function scrubErrorText(text: string, options: ScrubErrorTextOptions = {}): string {
  let scrubbed = scrubConfiguredSecrets(text, options.secrets);
  scrubbed = scrubbed
    .replace(PEM_BLOCK_PATTERN, REDACTED)
    .replace(PEM_OPEN_PATTERN, REDACTED)
    .replace(EMBEDDED_URL_PATTERN, scrubEmbeddedUrl)
    .replace(QUERY_PAIR_PATTERN, scrubQueryPair);
  scrubbed = replaceCarrierValues(scrubbed, COOKIE_HEADER_PATTERN, readCookieHeaderValue);
  scrubbed = replaceCarrierValues(scrubbed, CREDENTIAL_HEADER_PATTERN, readHeaderValue);
  scrubbed = replaceCarrierValues(scrubbed, SCHEME_WORD_PATTERN, readSchemeValue);
  scrubbed = replaceCarrierValues(scrubbed, CREDENTIAL_PAIR_PATTERN, readPairValue);
  scrubbed = replaceGenericCredentialPairs(scrubbed)
    .replace(JWT_PATTERN, REDACTED)
    .replace(AWS_ACCESS_KEY_ID_PATTERN, REDACTED)
    .replace(AWS_SECRET_PATTERN, (run) => (looksLikeAwsSecret(run) ? REDACTED : run));
  for (const pattern of VENDOR_TOKEN_PATTERNS) scrubbed = scrubbed.replace(pattern, REDACTED);
  if (options.longTokens === false) return scrubbed;
  return replaceLongTokenRuns(scrubbed);
}

/**
 * The long-token rule over `text`: every run of `LONG_TOKEN_RUN_PATTERN` through `scrubLongTokenRun`.
 * A run that starts with the letter of a JSON escape (`\nInvalidAuthenticationToken=`, see
 * `ESCAPE_LETTER_PATTERN`) is judged without that letter, so the escape stays a boundary as it is
 * for the carriers and the code after it is read as the code.
 */
function replaceLongTokenRuns(text: string): string {
  return text.replace(LONG_TOKEN_RUN_PATTERN, (run: string, offset: number) => {
    const escape = offset > 0 && text[offset - 1] === "\\" ? ESCAPE_LETTER_PATTERN.exec(run)?.[0] : undefined;
    if (escape === undefined) return scrubLongTokenRun(run);
    const rest = run.slice(escape.length);
    const body = rest.replace(/=+$/, "");
    return `${escape}${body.length >= LONG_TOKEN_MIN_LENGTH ? scrubLongTokenRun(rest) : rest}`;
  });
}

/**
 * A run that ends in "=" is a padded base64 value only when the padding completes a multiple of four
 * and the body uses the standard alphabet (no "-" or "_"); otherwise the "=" is an assignment operator
 * after a long key (`secret_access_key=`, whose value the pair rule has already replaced), and the key
 * alone is judged so the diagnostic keeps its key name in front of the marker.
 */
function scrubLongTokenRun(run: string): string {
  const padding = /=+$/.exec(run)?.[0] ?? "";
  if (padding.length > 0 && (run.length % 4 !== 0 || /[_-]/.test(run))) {
    const key = run.slice(0, run.length - padding.length);
    return looksLikeToken(key) ? `${REDACTED}${padding}` : run;
  }
  return looksLikeToken(run) ? REDACTED : run;
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
 * `scrubDataText`. A string under a setting key whose earlier segments name a credential
 * (`token_url`, `private_key_id`, see `SETTING_SUFFIXES`) is a setting and stays, unless a run in it
 * is token-shaped, which the long-token rule removes here even though the data scrub otherwise leaves
 * long runs alone. Arrays and plain objects are copied; other objects are returned as they are.
 */
export function redactSecretValues(value: unknown, options: RedactSecretValuesOptions = {}): unknown {
  if (typeof value === "string") return scrubDataText(value, options);
  if (Array.isArray(value)) return value.map((item) => redactSecretValues(item, options));
  if (!isPlainObject(value)) return value;
  const output: JsonRecord = {};
  for (const [key, entry] of Object.entries(value)) {
    const credential = isCredentialKey(key) && !(options.preserveKey?.(key) ?? false);
    if (credential && entry !== null && entry !== undefined && typeof entry !== "boolean") output[key] = REDACTED;
    else if (typeof entry === "string" && isCredentialWordSetting(key)) output[key] = scrubErrorText(entry, options);
    else output[key] = redactSecretValues(entry, options);
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
  try {
    return value && typeof value === "object" && !Array.isArray(value) ? (value as JsonRecord) : undefined;
  } catch {
    // Array.isArray throws on a revoked Proxy; such a value holds nothing readable.
    return undefined;
  }
}

function asText(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value : undefined;
}

/**
 * Cuts scrubbed `text` to at most `limit` characters and appends the truncation note; a text already
 * cut and carrying the note is returned as it is. The cut falls where a second scrub over the cut
 * text is a no-op: never inside a marker (the head ends before it), at a space rather than inside a
 * word when one stands within `CUT_WORD_BOUNDARY_WINDOW` characters (a scheme word or a kept prose
 * word cut in half would be read as a value), and never on a value opener the cut leaves standing
 * (a separator followed only by a quote or a scheme word drops back to the separator; a partial query
 * or fragment of a URL is dropped). The head is then checked as a fixed point of `scrubErrorText`
 * with the same options and moved back to the previous space while it is not, a few times at most.
 */
function truncate(text: string, limit: number, options: ScrubErrorTextOptions = {}): string {
  if (text.length <= limit) return text;
  if (text.endsWith(TRUNCATION_NOTE) && text.length <= limit + TRUNCATION_NOTE.length) return text;
  let end = limit;
  let candidate = "";
  for (let attempt = 0; attempt < MAX_CUT_ATTEMPTS; attempt += 1) {
    const head = cutHead(text, end);
    candidate = `${head}${TRUNCATION_NOTE}`;
    if (scrubErrorText(candidate, options) === candidate) return candidate;
    const space = head.search(/\s\S*$/);
    if (space <= 0) break;
    end = space;
  }
  return candidate;
}

/** The head of `text` cut at or before `end` under the rules of `truncate`, without the note. */
function cutHead(text: string, end: number): string {
  let cut = end;
  const marker = text.lastIndexOf(REDACTED, cut - 1);
  if (marker >= 0 && marker + REDACTED.length > cut) cut = marker;
  if (cut > 0 && cut < text.length && CUT_WORD_CHARACTER_PATTERN.test(text[cut]) && CUT_WORD_CHARACTER_PATTERN.test(text[cut - 1])) {
    const window = text.slice(Math.max(0, cut - CUT_WORD_BOUNDARY_WINDOW), cut);
    const space = window.search(/\s\S*$/);
    if (space >= 0) cut -= window.length - space;
  }
  return text
    .slice(0, cut)
    .replace(CUT_TAIL_PATTERN, "")
    .replace(CUT_URL_TAIL_PATTERN, "$1")
    .replace(CUT_VALUE_OPENER_PATTERN, "$1")
    .replace(CUT_TAIL_PATTERN, "");
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
  const messages = documentedMessages(payload).map((message) => truncate(scrubErrorText(message, options), MAX_VENDOR_MESSAGE_LENGTH, options));
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
 * The reason phrase is server text and stands right before the colon that introduces the body note,
 * so one whose last word names a credential (`Invalid Token`, `Expired Session`) would make the
 * credential-pair rule read the fixed note as the pair's value (`Token: non-JSON` loses `non-JSON`).
 * Such a phrase is dropped and the status number stands alone; every standard reason phrase passes.
 */
function reasonPhrase(statusText: string | null | undefined): string {
  if (!statusText || !STATUS_TEXT_PATTERN.test(statusText)) return "";
  const trimmed = statusText.trim();
  const lastWord = /[A-Za-z0-9_.-]+$/.exec(trimmed.replace(/['\s]+$/, ""))?.[0];
  if (lastWord !== undefined && isCredentialKey(lastWord)) return "";
  return ` ${trimmed}`;
}

/**
 * The standard message for a failed HTTP request: `GET /v1/users failed with 502 Bad Gateway:
 * non-JSON body (text/html, 1234 bytes)`. The status text comes from the server and is kept only
 * when it is a short plain reason phrase that does not end in a credential word (see
 * `reasonPhrase`); the body goes through `describeErrorBody`. The fixed words are chosen so the
 * line comes back from `scrubErrorText` unchanged.
 */
export function describeFailedResponse(response: FailedResponse, options: ScrubErrorTextOptions = {}): string {
  const method = HTTP_METHOD_PATTERN.test(response.method) ? response.method : "Request";
  const status = validHttpStatus(response.status) ?? "unknown status";
  return scrubErrorText(`${method} ${response.endpoint} failed with ${status}${reasonPhrase(response.statusText)}: ${describeErrorBody(response.contentType, response.body, options)}`, options);
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

/**
 * One property of a thrown value. A thrown value is foreign: a getter that throws, a Proxy trap that
 * throws, or a revoked Proxy would otherwise raise from inside the error path and replace the failure
 * being recorded with its own, so a property that cannot be read is treated as absent.
 */
function propertyOf(record: JsonRecord, key: string): unknown {
  try {
    return record[key];
  } catch {
    return undefined;
  }
}

/** The members of an `errors` array and its length, read under the same guard; anything unreadable is no member list. */
function memberListOf(value: unknown): { members: unknown[]; count: number } {
  try {
    if (!Array.isArray(value)) return { members: [], count: 0 };
    const count = value.length;
    if (!Number.isSafeInteger(count) || count <= 0) return { members: [], count: 0 };
    return { members: value.slice(0, MAX_AGGREGATE_MEMBERS), count };
  } catch {
    return { members: [], count: 0 };
  }
}

function errorNameOf(record: JsonRecord): string {
  const name = propertyOf(record, "name");
  return typeof name === "string" && ERROR_NAME_PATTERN.test(name) ? name : "Error";
}

function statusOf(record: JsonRecord): number | undefined {
  const metadata = asRecord(propertyOf(record, "$metadata"));
  const response = asRecord(propertyOf(record, "response")) ?? asRecord(propertyOf(record, "$response"));
  return (
    validHttpStatus(propertyOf(record, "status")) ??
    validHttpStatus(propertyOf(record, "statusCode")) ??
    validHttpStatus(propertyOf(record, "httpStatusCode")) ??
    validHttpStatus(metadata && propertyOf(metadata, "httpStatusCode")) ??
    validHttpStatus(response && propertyOf(response, "status")) ??
    validHttpStatus(response && propertyOf(response, "statusCode"))
  );
}

function endpointOf(record: JsonRecord, options: ScrubErrorTextOptions): string | undefined {
  const request = asRecord(propertyOf(record, "request"));
  const candidate =
    asText(propertyOf(record, "endpoint")) ??
    asText(propertyOf(record, "path")) ??
    asText(propertyOf(record, "url")) ??
    asText(request && propertyOf(request, "url")) ??
    asText(request && propertyOf(request, "path"));
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

  const ownMessage = asText(propertyOf(record, "message")) ?? asText(propertyOf(record, "error")) ?? asText(propertyOf(record, "error_description"));
  const parts = [ownMessage ? scrubErrorText(ownMessage, options) : `${name} without a message`];
  let code = validErrorCode(propertyOf(record, "code")) ?? validErrorCode(propertyOf(record, "Code"));
  let status = statusOf(record);
  let endpoint = endpointOf(record, options);

  const { members, count } = memberListOf(propertyOf(record, "errors"));
  if (count > 0) {
    const summaries = members.map((member) => scrubErrorValue(member, options, seen, depth + 1));
    const rest = count > MAX_AGGREGATE_MEMBERS ? `; and ${count - MAX_AGGREGATE_MEMBERS} more` : "";
    parts.push(`(${count} error${count === 1 ? "" : "s"}: ${summaries.map((summary) => summary.message).join("; ")}${rest})`);
    for (const summary of summaries) {
      code ??= summary.code;
      status ??= summary.status;
      endpoint ??= summary.endpoint;
    }
  }
  const cause = propertyOf(record, "cause");
  if (cause !== undefined && cause !== null) {
    const scrubbedCause = scrubErrorValue(cause, options, seen, depth + 1);
    parts.push(`(cause: ${scrubbedCause.message})`);
    code ??= scrubbedCause.code;
    status ??= scrubbedCause.status;
    endpoint ??= scrubbedCause.endpoint;
  }

  const scrubbed: ScrubbedError = { name, message: truncate(parts.join(" "), MAX_ERROR_MESSAGE_LENGTH, options) };
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
 * client library cannot smuggle a body or a credential into the recorded text. Every property is
 * read under a guard: a getter or Proxy trap that throws counts as an absent property, and a value
 * that cannot be reduced at all becomes the fixed message `thrown value could not be read`, so this
 * function never throws and never lets a foreign value replace the failure being recorded.
 */
export function scrubError(error: unknown, options: ScrubErrorTextOptions = {}): ScrubbedError {
  try {
    return scrubErrorValue(error, options, new Set<object>(), 0);
  } catch {
    return { name: "Error", message: "thrown value could not be read" };
  }
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
