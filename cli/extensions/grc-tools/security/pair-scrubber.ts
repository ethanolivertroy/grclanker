/** Quote-aware credential pairs and data/error modes shared by identity and SQL integrations. */
import { REDACTED_VALUE, isSensitiveArgumentKey, scrubSensitiveValues, scrubbedFormsOf } from "../../../core/redact.js";

export interface PairCredentialScrubber {
  registerConfiguredSecrets(values: ReadonlyArray<string | undefined>): void;
  scrubErrorText(text: string, secrets?: ReadonlyArray<string | undefined>): string;
  scrubDataText(text: string, secrets?: ReadonlyArray<string | undefined>): string;
  pairRuleFor(key: string): "credential" | "webhook" | "setting" | "none";
  webhookReplacement(value: string): string;
}

/** Opaque vendor authorization payloads run after the common scheme parser. */
export function createPairCredentialScrubber(opaqueHeaderSchemes: readonly string[] = []): PairCredentialScrubber {
  const REDACTED = "[REDACTED]";
  const MIN_CONFIGURED_SECRET_LENGTH = 4;
  const LONG_TOKEN_MIN_LENGTH = 16;
  const MIN_LETTERS_FOR_CASING = 6;

  // A literal JSON escape ("\n", "\r", "\t", "\b", "\f", "\/", "\uXXXX": the two- or six-character
  // sequence, not the control character) is a boundary before every carrier opener. A header name,
  // scheme word, pair key, URL, or token that begins right after one is read on its own, never as the
  // value of the word before the escape and never with the escape letter as its first character, and
  // a value, URL, or query pair ends at the backslash that opens the next escape. A backslash joins a
  // quote only as its escape, so a lone backslash is never read as an opening quote.
  const ESCAPE_LETTER = String.raw`(?:[nrtbf/]|u[0-9A-Fa-f]{4})`;
  /** The start of a carrier or token: outside a word (none of `wordCharacters` before it) or right after a literal escape, and not on an escape letter. */
  function carrierStart(wordCharacters: string): string {
    return String.raw`(?:(?<![${wordCharacters}])|(?<=\\[nrtbf/]|\\u[0-9A-Fa-f]{4}))(?!(?<=\\)${ESCAPE_LETTER})`;
  }
  const CARRIER_START = carrierStart("A-Za-z0-9_");
  /** A quote unit at any JSON depth: the quote character and the backslashes that escape it (`"`, `\"`, `\\\"`). */
  const QUOTE_UNIT = String.raw`(?:\\*["'])`;
  const schemeRules = opaqueHeaderSchemes.map((scheme) => [
    new RegExp(String.raw`${CARRIER_START}(${scheme.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")})\s+(?!${QUOTE_UNIT}?\[REDACTED\])(?![A-Za-z][A-Za-z0-9_.-]*=${QUOTE_UNIT}?\[REDACTED\])(${QUOTE_UNIT}?)[^\s"'\\]+`, "g"),
    `$1 $2${REDACTED}`,
  ] as const);

  const PEM_BLOCK_PATTERN = /-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----/g;
  const PEM_OPEN_PATTERN = /-----BEGIN [A-Z0-9 ]+-----[\s\S]*$/;
  // A URL wherever it sits in the text, spelled with "://" or with the JSON-escaped slashes a serialized
  // body carries ("https:\/\/host\/path"). In the escaped spelling "\/" is the URL's own path separator
  // and goes with it; after "://" it is the boundary every literal escape is, and the URL ends there.
  // The escaped form is unescaped for reading and written back escaped.
  const ESCAPED_SLASH = "\\/";
  const EMBEDDED_URL_PATTERN = new RegExp(String.raw`${CARRIER_START}[a-z][a-z0-9+.-]*:(?:\/\/[^\s"'<>()[\]{}\\]+|\\\/\\\/(?:\\\/|[^\s"'<>()[\]{}\\])+)`, "gi");
  // The userinfo ends at the first "/", "?", or "#": an "@" inside a query or fragment ("https://h?e=a@x.com&q=v") never turns the query into the host.
  const URL_PARTS_PATTERN = /^([a-z][a-z0-9+.-]*:\/\/)(?:[^\s\/?#@"'<>\\]+@)?([^?#]*)(\?[^#]*)?(#.*)?$/i;
  const TRAILING_PUNCTUATION_PATTERN = /[.,;:!?]+$/;
  // A ";" inside a query value is part of the value (URLSearchParams semantics), so "?token=<v>;<rest>"
  // loses the whole value with no tail. The ";" separator belongs to Cookie and Set-Cookie parsing alone,
  // and the cookie reader runs before this pass, so a pair inside a cookie header is already gone. A pair
  // whose value is already the marker is left alone, so a second pass never grows it to "[REDACTED]]".
  const QUERY_PAIR_PATTERN = /([?&])([A-Za-z0-9_.[\]-]+)=(?!\[REDACTED\])([^&#\s"'<>)\]}\\]+)/g;
  // The authorization scheme words, matched in any casing on both sides: a peer's error text may spell
  // "bearer" or "BASIC", and an Authorization carrier may carry "sNoWfLaKe". In prose, a scheme word
  // followed by a run of 8 or more token characters is a credential unless the run is prose: a mechanism
  // word ("Basic authentication"), a dotted version ("OAuth 2.0"), an auth-param of a challenge
  // (`Bearer realm="api"`), or one plain word or hyphenated lowercase compound after a spelling that is
  // as often an English word or a product name as a scheme: a lowercase spelling ("token provided", "the
  // bearer presented") or a product name in any casing ("Splunk Enterprise", "Snowflake statement
  // failed", "HMAC signature"). After a header-cased or upper-cased authorization scheme ("Bearer",
  // "BASIC", "SSWS") the run is the credential whatever its shape. A run with a digit, a symbol, or mixed
  // casing inside a word is never prose. The token after a scheme word may be quoted (plain, single, or
  // JSON-escaped); the quote is kept and the token removed.
  const SCHEME_WORDS = "bearer|basic|digest|token|oauth|negotiate|ntlm|ssws|apikey|api-key|splunk|snowflake|hmac|aws4-hmac-sha256|veracode-hmac-sha-256";
  const SCHEME_VALUE_PATTERN = new RegExp(String.raw`${CARRIER_START}(${SCHEME_WORDS})\s+(${QUOTE_UNIT}?)([A-Za-z0-9._~+/=-]{8,})`, "gi");
  const SCHEME_PROSE_WORDS = new Set(["authentication", "authorization", "authenticated", "authorized", "credential", "credentials", "challenge"]);
  const PRODUCT_SCHEME_WORDS = new Set(["splunk", "snowflake", "hmac"]);
  const SCHEME_WORD_PATTERN = new RegExp(`^(?:${SCHEME_WORDS})$`, "i");
  const PLAIN_WORD_PATTERN = /^(?:[A-Z]?[a-z]+(?:-[a-z]+)*|[A-Z]+)$/;
  const VERSION_PATTERN = /^\d+(?:\.\d+)+$/;
  const AUTH_PARAM_PATTERN = /^(?:realm|error|error_description|error_uri|scope|charset|algorithm|qop|stale|domain|opaque|title|resource|client_id|authorization_uri|as_uri|ticket)=/i;
  // A value may begin with backslashes that open no escape and no quote (a Windows path, a stray
  // backslash); they go with the value rather than hiding it.
  const STRAY_BACKSLASHES = String.raw`(?:\\+(?![nrtbf/u"']))?`;
  const SCHEME_TOKEN_PATTERN = new RegExp(String.raw`^(\s+)(?!\[REDACTED\])(${QUOTE_UNIT}?)(${STRAY_BACKSLASHES}[^\s"'<>;,()[\]{}\\]+)`);
  // A pair key or value may sit in plain, single, or JSON-escaped quotes at any depth; the value ends at a quote or the escaping backslash.
  const ASSIGNMENT_KEY_PATTERN = new RegExp(String.raw`(${QUOTE_UNIT}?)${CARRIER_START}([A-Za-z][A-Za-z0-9_.-]{0,63})\b(${QUOTE_UNIT}?\s*([:=])\s*(${QUOTE_UNIT}?))`, "g");
  const ASSIGNMENT_VALUE_PATTERN = new RegExp(String.raw`(?!\[REDACTED\])${STRAY_BACKSLASHES}[^\s"'<>;,&()[\]{}\\]+`, "y");
  const URL_ORIGIN_PATTERN = /^[a-z][a-z0-9+.-]*:\/\/[^\s/?#@"'<>]+(?=[/?#]|$)/i;
  const SINGLE_RUN_PATTERN = /^[A-Za-z0-9+=_-]+$/;
  const BEARER_ID_KEY_PATTERN = /(?:secret|session|token)[_.-]?id$/i;
  const BEARER_ID_KEY_SEGMENTS = new Set(["sid", "jsessionid", "phpsessid", "sessid"]);
  const BEARER_ID_KEY_TAILS = new Set(["secret_id", "session_id", "token_id"]);
  // The final segments that name a setting rather than a credential, the AppRole settings an assessment
  // reports included (secret_id_ttl, token_max_ttl, secret_id_num_uses, token_bound_cidrs, token_accessor).
  const SETTING_KEY_SUFFIXES = new Set(["url", "uri", "endpoint", "method", "algorithm", "audience", "issuer", "shape", "type", "mode", "path", "file", "dir", "limit", "count", "id", "name", "policy", "policies", "ttl", "uses", "cidrs", "accessor"]);
  // A webhook key is URL-valued: the bare word, or a *_url, *_uri, or *_endpoint key with a hook word
  // before the suffix (webhook_url, slack_hook_uri, callback_url). webhook_count and webhook_secret are
  // not URLs and follow the pair rule for their own final segment.
  const WEBHOOK_KEYS = new Set(["webhook", "webhooks", "hook", "hooks"]);
  const WEBHOOK_URL_WORDS = new Set(["webhook", "webhooks", "hook", "hooks", "callback"]);
  const URL_KEY_SUFFIXES = new Set(["url", "uri", "endpoint"]);
  // Every token shape starts at a carrier start, so a token glued to a literal escape ("\neyJ...",
  // "\u000aAKIA...") is read after the escape and never with the escape letter as its first character.
  const JWT_IN_TEXT_PATTERN = new RegExp(String.raw`${CARRIER_START}eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)*`, "g");
  const AWS_ACCESS_KEY_ID_PATTERN = new RegExp(String.raw`${CARRIER_START}(?:AKIA|ASIA|AROA|AIDA|AGPA|ANPA|ANVA|APKA|ABIA|ACCA)[A-Z0-9]{16}\b`, "g");
  const AWS_SECRET_PATTERN = new RegExp(String.raw`${carrierStart("A-Za-z0-9/+=")}[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])`, "g");
  const HEX_DIGEST_PATTERN = new RegExp(String.raw`${CARRIER_START}[A-Fa-f0-9]{32,}\b`, "g");
  const VENDOR_TOKEN_SHAPES: readonly string[] = [
    String.raw`00[A-Za-z0-9_-]{40}\b`,
    String.raw`xox[abopers]-[A-Za-z0-9-]{10,}`,
    String.raw`gh[pousr]_[A-Za-z0-9]{20,}`,
    String.raw`github_pat_[A-Za-z0-9_]{20,}`,
    String.raw`glpat-[A-Za-z0-9_-]{20,}`,
    String.raw`AIza[0-9A-Za-z_-]{35}\b`,
    String.raw`ya29\.[0-9A-Za-z._-]{20,}`,
    String.raw`sk_(?:live|test)_[A-Za-z0-9]{10,}`,
    String.raw`SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}`,
  ];
  const VENDOR_TOKEN_PATTERNS: readonly RegExp[] = VENDOR_TOKEN_SHAPES.map((shape) => new RegExp(`${CARRIER_START}${shape}`, "g"));
  // "/", ".", ":", "@", "=", "\", and whitespace end a run, so URL path segments, dotted hostnames, the
  // two sides of a pair, and the text on either side of a literal escape are judged on their own; "="
  // joins a run only as trailing base64 padding that no value follows, so a key whose value was already
  // replaced or is quoted ("httpEventCollectorToken=[REDACTED]", "SPLUNK_ACS_TOKEN='[REDACTED]'") keeps its name.
  const LONG_TOKEN_RUN_PATTERN = new RegExp(String.raw`${carrierStart("A-Za-z0-9+_-")}[A-Za-z0-9+_-]{${LONG_TOKEN_MIN_LENGTH},}(?:={1,2}(?![A-Za-z0-9&\["'\\]))?`, "g");
  const DIGIT_GROUP_PATTERN = /\d+/g;
  const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  // Trailing base64 padding is judged apart from the run it follows: `private_key_file=` is a setting
  // key whose value starts with a symbol, not a padded token.
  const BASE64_PADDING_PATTERN = /={1,2}$/;
  // A setting suffix concatenated onto another word (OKTA_CLIENT_AUTHORIZATIONMODE, OKTA_CLIENT_PRIVATEKEYID) still names the setting.
  const SETTING_KEY_SUFFIX_PATTERN = new RegExp(`(?:${[...SETTING_KEY_SUFFIXES].join("|")})$`);
  const SAFE_KEY_SHAPE_PATTERN = /^(?:max|min)[_-]|[_-](?:limit|days|hours|minutes|seconds|count|path|file|dir)$/i;
  const EXTRA_CREDENTIAL_KEY_SEGMENTS = new Set(["sid", "sig", "pwd", "passwd", "pass", "sessid", "phpsessid", "auth", "nonce", "sas"]);
  // "session" carries a credential only as the final segment (session=, user_session=); session_context and session_policy name settings.
  const FINAL_CREDENTIAL_KEY_SEGMENTS = new Set(["session"]);
  const EXTRA_CREDENTIAL_KEYS = new Set(["x-amz-signature", "x-amz-credential", "x-amz-security-token", "x-goog-signature", "x-goog-credential", "oauth_signature", "oauth_token", "oauth_verifier", "proxy-authorization"]);

  function keySegments(key: string): string[] {
    return key
      .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter(Boolean);
  }

  /** True when a header, query parameter, or pair name carries a credential; thresholds and file references are exempt. */
  function isCredentialCarrierKey(key: string): boolean {
    if (isSensitiveArgumentKey(key)) return true;
    if (SAFE_KEY_SHAPE_PATTERN.test(key)) return false;
    if (EXTRA_CREDENTIAL_KEYS.has(key.toLowerCase())) return true;
    const segments = keySegments(key);
    if (FINAL_CREDENTIAL_KEY_SEGMENTS.has(segments[segments.length - 1] ?? "")) return true;
    return segments.some((segment) => EXTRA_CREDENTIAL_KEY_SEGMENTS.has(segment));
  }

  type PairRule = "credential" | "setting" | "webhook" | "none";

  /** A key ending in "secret_id", "token_id", or a session id name carries a bearer credential whatever the value's shape: a Vault secret id is a UUID, a token id is the token, a session id is the session. */
  function isBearerIdKey(key: string, segments: readonly string[]): boolean {
    if (BEARER_ID_KEY_PATTERN.test(key)) return true;
    return BEARER_ID_KEY_TAILS.has(segments.slice(-2).join("_")) || BEARER_ID_KEY_SEGMENTS.has(segments[segments.length - 1] ?? "");
  }

  /** A URL-valued webhook key (webhook, webhook_url, slack_hook_uri, callback_url) whose path carries the token; see WEBHOOK_KEYS. */
  function isWebhookKey(segments: readonly string[]): boolean {
    if (segments.length === 1) return WEBHOOK_KEYS.has(segments[0] ?? "");
    return URL_KEY_SUFFIXES.has(segments[segments.length - 1] ?? "") && segments.slice(0, -1).some((segment) => WEBHOOK_URL_WORDS.has(segment));
  }

  /** Whether a key's last word is a credential noun or the key is a bearer id: the test a bare path label must pass to be read as a pair. */
  function namesCredential(key: string): boolean {
    const segments = keySegments(key);
    const last = segments[segments.length - 1] ?? "";
    const noun = CREDENTIAL_ENCODING_WORDS.has(last) ? segments[segments.length - 2] ?? "" : last;
    return CREDENTIAL_NOUN_PATTERN.test(noun) || isBearerIdKey(key, segments);
  }

  /** Authorization, Proxy-Authorization, and WWW-Authenticate carry a scheme word in front of the credential; every other key's value goes whatever word it starts with. */
  function isAuthorizationStyleKey(segments: readonly string[]): boolean {
    return segments[segments.length - 1] === "authorization" || segments.slice(-2).join("_") === "www_authenticate";
  }

  /** The final segment names a setting, as its own word or concatenated onto another (OKTA_CLIENT_AUTHORIZATIONMODE, OKTA_CLIENT_PRIVATEKEYID); a bearer id is read before this test. */
  function isSettingSegment(segment: string): boolean {
    return SETTING_KEY_SUFFIXES.has(segment) || SETTING_KEY_SUFFIX_PATTERN.test(segment);
  }

  /** How the value of a `key=value` or `key: value` pair is treated; see the pair rule above. */
  function pairRuleFor(key: string): PairRule {
    const segments = keySegments(key);
    if (isBearerIdKey(key, segments)) return "credential";
    if (isWebhookKey(segments)) return "webhook";
    if (!isCredentialCarrierKey(key)) return "none";
    return isSettingSegment(segments[segments.length - 1] ?? "") ? "setting" : "credential";
  }

  /** A setting value is removed only when it is a single run of 16 or more characters with a real token shape (base64 symbols, scattered digits, or token casing); an identifier (0oa1audit, key-2024-01), a UUID, a scheme word, a mode name, or a URL stays for the later shape rules to judge. */
  function isTokenShapedValue(value: string): boolean {
    return value.length >= LONG_TOKEN_MIN_LENGTH && SINGLE_RUN_PATTERN.test(value) && looksLikeToken(value);
  }

  /** A webhook value keeps its origin and loses its path and query; a value that is not a URL goes whole. */
  function webhookReplacement(value: string): string {
    const origin = URL_ORIGIN_PATTERN.exec(value)?.[0];
    return origin === undefined ? REDACTED : `${origin}/${REDACTED}`;
  }

  /** A 40-character base64 run is an AWS secret access key when it is random-looking; a bare path of word segments ("/api/v1/users/<id>/roles") that happens to span 40 characters is a request target and stays. */
  function looksLikeAwsSecret(run: string): boolean {
    if (run.startsWith("/") || run.split("/").some((segment) => /^(?:[a-z]+|v\d+)$/.test(segment))) return false;
    if (/[/+]/.test(run)) return true;
    return /\d/.test(run) && /[a-z]/.test(run) && /[A-Z]/.test(run);
  }

  /** MD5, SHA-1, and SHA-256 digests and hex-encoded keys: 32 or more hex characters mixing letters and digits. */
  function looksLikeHexDigest(run: string): boolean {
    return /[A-Fa-f]/.test(run) && /\d/.test(run);
  }

  // camelCase and PascalCase identifiers: an optional lowercase head, capitalized words, and at most a
  // short trailing acronym ("frozenTimePeriodInSecs", "maxTotalDataSizeMB").
  const CAMEL_CASE_PATTERN = /^[a-z]*(?:[A-Z][a-z]+)*[A-Z]{0,4}$/;

  /**
   * Token casing changes more often than once every three letters. Words and acronyms change at word
   * boundaries only, and a camelCase identifier whose words average three or more letters is a name
   * even when its case changes often ("frozenTimePeriodInSecs"); an alternating run of capitalized
   * one- or two-letter fragments ("xKqZvBnMwLpRtYsHdG") has no such word structure and is a token.
   */
  function hasTokenCasing(letters: string): boolean {
    if (letters.length < MIN_LETTERS_FOR_CASING) return false;
    let changes = 0;
    for (let index = 1; index < letters.length; index += 1) {
      const previousLower = letters[index - 1] >= "a" && letters[index - 1] <= "z";
      const currentLower = letters[index] >= "a" && letters[index] <= "z";
      if (previousLower !== currentLower) changes += 1;
    }
    if (changes * 3 <= letters.length) return false;
    if (!CAMEL_CASE_PATTERN.test(letters)) return true;
    const words = (letters.match(/[A-Z]/g) ?? []).length + (/^[a-z]/.test(letters) ? 1 : 0);
    return words * 3 > letters.length;
  }

  /** The long-token rule: a UUID is an identifier; a base64 symbol, a second digit group anywhere in the run, or a "-" or "_" separated segment with token casing makes a token; words joined by "-" or "_" with at most one digit group are a name. */
  function looksLikeToken(run: string): boolean {
    if (UUID_PATTERN.test(run)) return false;
    if (/[+=]/.test(run)) return true;
    if ((run.match(DIGIT_GROUP_PATTERN) ?? []).length > 1) return true;
    return run.split(/[-_]/).some((segment) => hasTokenCasing(segment.replace(DIGIT_GROUP_PATTERN, "")));
  }

  /** True when the run at `index` is a segment of a bare path: preceded by a path separator ("/" or a lone "\"; the escape "\/" is a boundary, not a separator) and not inside a URL that carries a scheme. */
  function isBarePathSegment(text: string, index: number, urlSpans: ReadonlyArray<readonly [number, number]>): boolean {
    const before = text[index - 1];
    if (before === "/" ? text[index - 2] === "\\" : before !== "\\") return false;
    return !urlSpans.some(([start, end]) => index >= start && index < end);
  }

  /** The long-token rule over the text; a scheme word that happens to carry digits ("aws4-hmac-sha256") names a mechanism and stays. */
  function scrubBareTokens(text: string): string {
    const urlSpans = [...text.matchAll(EMBEDDED_URL_PATTERN)].map((match) => [match.index ?? 0, (match.index ?? 0) + match[0].length] as const);
    return text.replace(LONG_TOKEN_RUN_PATTERN, (run: string, offset: number) =>
      looksLikeToken(run.replace(BASE64_PADDING_PATTERN, "")) && !SCHEME_WORD_PATTERN.test(run) && !isBarePathSegment(text, offset, urlSpans) ? REDACTED : run,
    );
  }

  // The credentials this process has configured or minted (a client's token, private key, client
  // assertion, and the access token or session it obtained), so every scrub pass removes them without
  // being handed the client: redactSnapshot on a string leaf, an error text built outside the client.
  // Each entry keeps its encoded forms, lower-cased, so a leaf that carries none of them is passed over
  // with a substring check; bounded so a long-lived process that mints tokens does not grow it without limit.
  const REGISTERED_SECRET_LIMIT = 64;
  interface RegisteredSecret {
    readonly value: string;
    readonly forms: readonly string[];
  }
  const registeredSecrets: RegisteredSecret[] = [];

  /** Registers the credentials a client was configured with or minted; a value under the configured-secret minimum is ignored. */
  function registerConfiguredSecrets(values: ReadonlyArray<string | undefined>): void {
    for (const value of values) {
      if (typeof value !== "string" || value.length < MIN_CONFIGURED_SECRET_LENGTH || registeredSecrets.some((entry) => entry.value === value)) continue;
      const forms = [...new Set(scrubbedFormsOf(value).map((form) => form.toLowerCase()))].filter((form) => form.length >= MIN_CONFIGURED_SECRET_LENGTH);
      registeredSecrets.push({ value, forms });
      if (registeredSecrets.length > REGISTERED_SECRET_LIMIT) registeredSecrets.shift();
    }
  }

  /** The registered credentials whose encoded forms may occur in the text; a text that carries none skips the full pass. */
  function registeredSecretsIn(text: string): string[] {
    if (registeredSecrets.length === 0) return [];
    const lower = text.toLowerCase();
    if (lower.length !== text.length) return registeredSecrets.map((entry) => entry.value);
    return registeredSecrets.filter((entry) => entry.forms.some((form) => lower.includes(form))).map((entry) => entry.value);
  }

  /** Removes the secrets handed in and every registered credential in each encoded form; a handed-in value also goes wherever it stands. */
  function scrubConfiguredSecrets(text: string, secrets: ReadonlyArray<string | undefined>): string {
    const handed = [...new Set(secrets)].filter((value): value is string => typeof value === "string" && value.length >= MIN_CONFIGURED_SECRET_LENGTH);
    const values = [...new Set([...handed, ...registeredSecretsIn(text)])];
    if (values.length === 0) return text;
    return scrubLiteralSecrets(scrubSensitiveValues(text, values).split(REDACTED_VALUE).join(REDACTED), handed);
  }

  /**
   * The shared needle rule matches a form under eight characters only as a whole token, so a short
   * passphrase glued into a longer run ("xhunter2y") would survive it. A value handed to the call is
   * this client's own credential wherever it stands, so it goes literally as well, longest first; a
   * value that is part of the marker itself is skipped so a second pass changes nothing.
   */
  function scrubLiteralSecrets(text: string, values: readonly string[]): string {
    let output = text;
    for (const value of [...values].sort((left, right) => right.length - left.length)) {
      if (!REDACTED.includes(value) && output.includes(value)) output = output.split(value).join(REDACTED);
    }
    return output;
  }

  /** A URL keeps its scheme, host, and path and loses its userinfo, query, and fragment; a slash-escaped URL is written back with its slashes escaped. */
  function scrubEmbeddedUrl(match: string): string {
    const escaped = match.includes(ESCAPED_SLASH);
    const spelled = escaped ? match.split(ESCAPED_SLASH).join("/") : match;
    const trailing = TRAILING_PUNCTUATION_PATTERN.exec(spelled)?.[0] ?? "";
    const url = spelled.slice(0, spelled.length - trailing.length);
    const parts = URL_PARTS_PATTERN.exec(url);
    if (!parts) return match;
    const [, scheme, hostAndPath, query, fragment] = parts;
    const kept = `${scheme}${hostAndPath}`;
    return `${escaped ? kept.split("/").join(ESCAPED_SLASH) : kept}${redactedUrlPart(query)}${redactedUrlPart(fragment)}${trailing}`;
  }

  /** A query or fragment with content becomes its delimiter and the marker; a bare delimiter (what an earlier pass left before its marker) carries nothing and stays, so a second pass adds no second marker. */
  function redactedUrlPart(part: string | undefined): string {
    if (!part) return "";
    return part.length > 1 ? `${part[0]}${REDACTED}` : part;
  }

  function scrubQueryPair(match: string, separator: string, key: string): string {
    return isCredentialCarrierKey(key) ? `${separator}${key}=${REDACTED}` : match;
  }

  /** The word after a scheme word in prose is prose, not a credential, when it is a mechanism word, a dotted version, an auth-param, or one plain word after a lowercase spelling or a product name. */
  function isSchemeProse(scheme: string, word: string): boolean {
    if (SCHEME_PROSE_WORDS.has(word.toLowerCase())) return true;
    if (PLAIN_WORD_PATTERN.test(word) && (scheme === scheme.toLowerCase() || PRODUCT_SCHEME_WORDS.has(scheme.toLowerCase()))) return true;
    return VERSION_PATTERN.test(word) || AUTH_PARAM_PATTERN.test(word);
  }

  function scrubSchemeValue(match: string, scheme: string, quote: string, value: string, offset: number, text: string): string {
    const trailing = TRAILING_PUNCTUATION_PATTERN.exec(value)?.[0] ?? "";
    const word = value.slice(0, value.length - trailing.length);
    if (isSchemeProse(scheme, word) || isRedactedPairKey(word, text, offset + match.length)) return match;
    return `${scheme} ${quote}${REDACTED}${trailing}`;
  }

  /** A run that is a bare pair key with the marker right after it (`username="[REDACTED]"`, `access_token=[REDACTED]`) names a pair whose value an earlier pass removed, and keeps its name. */
  function isRedactedPairKey(word: string, text: string, index: number): boolean {
    if (!PAIR_KEY_ONLY_PATTERN.test(word)) return false;
    REDACTED_PAIR_VALUE_PATTERN.lastIndex = index;
    return REDACTED_PAIR_VALUE_PATTERN.test(text);
  }

  // Use the full RFC 7230 token set so punctuation in the next header name is not swallowed.
  const NEXT_HEADER_NAME = "[!#$%&'*+.^_`|~0-9A-Za-z-]+";
  // A ";" or "," ends a carrier value when the text after it (past optional spaces) opens the next
  // header "Name:" token or a JSON fragment.
  const NEXT_HEADER_AFTER_SEPARATOR = new RegExp(String.raw`^[ \t]*(?:[{[]|${QUOTE_UNIT}?${NEXT_HEADER_NAME}${QUOTE_UNIT}?[ \t]*:)`);
  // A quoted value that opens with a scheme word keeps the scheme and its gap and loses the rest, except
  // that a scheme followed by a pair list is read pair by pair. The pairs are the credential: a quoted
  // value goes whatever its key (`Snowflake Token="<v>"`, `Digest response="<v>"`, `Bearer blob="<v>"`)
  // unless the key is a descriptive parameter (realm, qop, algorithm, ...), and a bare value follows its
  // key's own rule, so an HMAC header's "id=...,ts=...,nonce=...,sig=..." keeps its timestamp. A
  // challenge header (WWW-Authenticate) is read the same way, so its `realm="api"` stays and its nonce goes.
  const LEADING_SCHEME_IN_VALUE = /^([A-Za-z][A-Za-z0-9-]*)(\s+)(\S[\s\S]*)$/;
  const PAIR_LIST_START = /^[A-Za-z][A-Za-z0-9_.-]*=/;
  // The run after the scheme is a bare key ("Token=", "username=") whose value follows it.
  const PAIR_KEY_ONLY_PATTERN = /^[A-Za-z][A-Za-z0-9_.-]*=$/;
  // The pairs of a request credential's list: a key up to its "=", a bare value, and the separator before
  // the next pair ("," with optional spaces, or spaces alone).
  const LIST_PAIR_KEY_PATTERN = /[A-Za-z][A-Za-z0-9_.-]*=/y;
  // A bare value that is already the marker reads as one value, so the list goes on past a pair an earlier pass removed.
  const LIST_BARE_VALUE_PATTERN = /\[REDACTED\]|[^\s"'<>;,()[\]{}\\]*/y;
  const LIST_PAIR_SEPARATOR_PATTERN = /[ \t]*,[ \t]*|[ \t]+/y;
  // The descriptive parameters of a credential's pair list, whose quoted value stays (`realm="api"`,
  // `qop="auth"`, `algorithm="SHA-256"`, a challenge's `error="invalid_token"`); every other quoted value
  // in the list is the credential.
  const LIST_KEPT_PARAM_PATTERN = /^(?:realm|qop|algorithm|charset|error|error_description|error_uri|scope)$/i;
  // The proof parameters of an authentication exchange: Digest's `response`, an HTTP Signatures or
  // OAuth 1.0 `signature` and `oauth_signature`, the MAC and Hawk schemes' `mac`, and an HMAC header's
  // `sig`. A proof's value is the credential wherever its pair sits in a list with a challenge parameter
  // (realm, nonce, cnonce, opaque, qop, or an oauth_* name), with or without a scheme word or a header in
  // front of the list, so `realm="api", nonce="n", response="<proof>"` is never read as a bare challenge;
  // a proof-free challenge (`realm="api", qop="auth"`) and a pair list of another kind (`status=500
  // response=slow`) keep their values. Inside a scheme word's list a bare proof goes whatever its neighbours.
  const PROOF_PARAM_PATTERN = /^(?:response|signature|oauth_signature|mac|sig)$/i;
  const CHALLENGE_PARAM_PATTERN = /^(?:realm|nonce|cnonce|opaque|qop|oauth_[a-z0-9_]+)$/i;
  // The first key of a pair list, at a carrier start; the keys after it are read past the list separator.
  const PAIR_LIST_KEY_PATTERN = new RegExp(String.raw`${CARRIER_START}[A-Za-z][A-Za-z0-9_.-]*=`, "g");
  // The marker, in quotes or bare, where a pair's value stood before an earlier pass removed it.
  const REDACTED_PAIR_VALUE_PATTERN = new RegExp(String.raw`${QUOTE_UNIT}?\[REDACTED\]`, "y");
  // In prose, an authorization scheme word followed by a quoted pair opens a credential's pair list
  // ("Digest username="...", response="..."", "Bearer blob="..."") and the list rule applies; a product
  // name (Splunk, Snowflake, HMAC) followed by a quoted pair is prose about the product.
  const SCHEME_PAIR_LIST_PATTERN = new RegExp(String.raw`${CARRIER_START}(?:bearer|basic|digest|token|oauth|negotiate|ntlm|ssws|apikey|api-key|aws4-hmac-sha256|veracode-hmac-sha-256)\s+(?=[A-Za-z][A-Za-z0-9_.-]*=${QUOTE_UNIT})`, "gi");
  // After a bare path label the text is prose ("/api/v1/api-tokens: request failed with 403",
  // "/oauth/token-request: invalid_client") and stays, unless the segment itself names a credential
  // in the singular (its last word is password, key, secret, token, passphrase, or assertion, alone
  // or followed by an encoding word such as pem or base64, or it is a bearer id): then the next token
  // is the value whatever its shape and whatever follows it ("kv/password: <value> [code 003001]",
  // "kv/privateKeyPem: <value>"), while a plural label ("api-tokens", "secrets") names a collection
  // and its colon continues as prose, and so does a label whose last word names a file or path
  // ("kv/private_key_file: /x/y.pem").
  const CREDENTIAL_NOUN_PATTERN = /(?:password|passwd|passphrase|pwd|secret|token|key|assertion)$/;
  const CREDENTIAL_ENCODING_WORDS = new Set(["pem", "der", "b64", "base64", "jwk"]);
  // A credential-named flag whose value is the next argument (`psql --password <value> -h db`), as a
  // spawned CLI echoes its command line; `--name=value` is a pair and is read by the pair rule.
  const FLAG_VALUE_PATTERN = new RegExp(String.raw`(?<![A-Za-z0-9_-])--([A-Za-z][A-Za-z0-9_.-]{0,63})([ \t]+)(?!\[REDACTED\])(?!-)([^\s"'<>;,&()[\]{}\\]+)`, "g");

  /** The number of backslashes in the run ending immediately before `index`. */
  function backslashRunBefore(text: string, index: number): number {
    let count = 0;
    while (index - count - 1 >= 0 && text[index - count - 1] === "\\") count += 1;
    return count;
  }

  /** True when a ";" or "," at `index` precedes the next header "Name:" token or a JSON fragment. */
  function endsAtNextHeader(text: string, index: number): boolean {
    const ch = text[index];
    if (ch !== ";" && ch !== ",") return false;
    return NEXT_HEADER_AFTER_SEPARATOR.test(text.slice(index + 1));
  }

  interface QuotedRead {
    /** The value content between the opener and the closer (or the unterminated stop), to be redacted. */
    content: string;
    /** The index just past the value: past the closing quote unit when terminated, at the stop otherwise. */
    end: number;
    /** True when a matching closer was found; false when a raw newline, an outer string, or the next header token ended the value. */
    terminated: boolean;
  }

  /** A quote unit opening a value at `start`: its leading backslash run and quote character, or undefined when `start` is not on a quote unit. */
  function openingQuoteUnit(text: string, start: number): { backslashes: number; quoteChar: string; contentStart: number } | undefined {
    let backslashes = 0;
    while (text[start + backslashes] === "\\") backslashes += 1;
    const quoteChar = text[start + backslashes];
    if (quoteChar !== '"' && quoteChar !== "'") return undefined;
    return { backslashes, quoteChar, contentStart: start + backslashes + 1 };
  }

  /**
   * Reads the content of a quoted value that opened with `openBackslashes` backslashes and quote char
   * `quoteChar`. A quote of the same char preceded by the same backslash run closes it, so a deeper
   * quote (more backslashes: an escaped inner quote at any JSON depth) is inner content; a raw newline,
   * a shallower quote (an outer string closing), or a ";"/"," before the next header token ends it
   * unterminated so the following header keeps its name.
   */
  function readQuotedContent(text: string, contentStart: number, openBackslashes: number, quoteChar: string): QuotedRead {
    let i = contentStart;
    while (i < text.length) {
      const ch = text[i];
      if (ch === "\n" || ch === "\r") return { content: text.slice(contentStart, i), end: i, terminated: false };
      if (ch === quoteChar) {
        const run = backslashRunBefore(text, i);
        if (run === openBackslashes) return { content: text.slice(contentStart, i - run), end: i + 1, terminated: true };
        if (run < openBackslashes) return { content: text.slice(contentStart, i - run), end: i - run, terminated: false };
      }
      if (endsAtNextHeader(text, i)) return { content: text.slice(contentStart, i), end: i, terminated: false };
      i += 1;
    }
    return { content: text.slice(contentStart, i), end: i, terminated: false };
  }

  // A cookie header value that is not wholly quoted runs across ";"/"," separated pairs; these are the
  // characters that make up a bare pair name or value (everything but the delimiters handled below). An
  // apostrophe is an RFC 6265 token character ("my'pref=", "sid=O'..."), so it is content, not a quote.
  const COOKIE_PLAIN_CHAR = /[^\r\n\t <>"\\;,=]/;
  const SPACE_BEFORE_JSON = /^[ \t]*[{[]/;

  /**
   * Reads an unquoted cookie header value from `start`: it runs across ";"/"," separated pairs whose
   * values may themselves be quoted, and ends before a ";"/"," or a space that precedes the next header
   * token or a JSON fragment, at a raw newline or tab, at a literal escape, or at a bare quote. A pair
   * value opened with a quote is read quote-aware, and an unterminated one ends the whole value there so
   * the following header keeps its name. Returns the index just past the value.
   */
  function readUnquotedCookieValue(text: string, start: number): number {
    if (!COOKIE_PLAIN_CHAR.test(text[start] ?? "")) return start;
    let i = start + 1;
    while (i < text.length) {
      const ch = text[i];
      if (COOKIE_PLAIN_CHAR.test(ch)) {
        i += 1;
        continue;
      }
      if (ch === "=") {
        i += 1;
        while (text[i] === " " || text[i] === "\t") i += 1;
        const opener = openingQuoteUnit(text, i);
        if (opener) {
          const read = readQuotedContent(text, opener.contentStart, opener.backslashes, opener.quoteChar);
          if (!read.terminated) return read.end;
          i = read.end;
        }
        continue;
      }
      if (ch === ";" || ch === ",") {
        if (endsAtNextHeader(text, i)) break;
        i += 1;
        continue;
      }
      if (ch === " " || ch === "\t") {
        if (SPACE_BEFORE_JSON.test(text.slice(i + 1))) break;
        i += 1;
        continue;
      }
      break;
    }
    return i;
  }

  // A cookie or session header at a carrier start, up to the separator; the value is read procedurally.
  const COOKIE_HEADER_START = new RegExp(String.raw`${CARRIER_START}(set-cookie|cookies?)(${QUOTE_UNIT}?\s*[:=]\s*)`, "gi");

  /**
   * Removes the value of every Cookie and Set-Cookie header. A wholly quoted value is read to its
   * matching closer (an escaped inner quote at any JSON depth is inner content); an unquoted value runs
   * across its pairs and ends before the next header token, so the following header keeps its name. The
   * marker `[REDACTED]` is left untouched so the pass is idempotent.
   */
  function scrubCookieHeaders(text: string): string {
    COOKIE_HEADER_START.lastIndex = 0;
    let out = "";
    let last = 0;
    let match: RegExpExecArray | null;
    while ((match = COOKIE_HEADER_START.exec(text)) !== null) {
      const [whole, header, separator] = match;
      if (whole.length === 0) {
        COOKIE_HEADER_START.lastIndex += 1;
        continue;
      }
      const valueStart = match.index + whole.length;
      const opener = openingQuoteUnit(text, valueStart);
      let prefix: string;
      let redacted: string;
      let end: number;
      if (opener) {
        const read = readQuotedContent(text, opener.contentStart, opener.backslashes, opener.quoteChar);
        if (read.content.length === 0 || read.content === REDACTED) {
          COOKIE_HEADER_START.lastIndex = valueStart;
          continue;
        }
        const openerText = text.slice(valueStart, opener.contentStart);
        const closerText = read.terminated ? text.slice(read.end - (opener.backslashes + 1), read.end) : "";
        prefix = openerText;
        redacted = `${REDACTED}${closerText}`;
        end = read.end;
      } else {
        const valueEnd = readUnquotedCookieValue(text, valueStart);
        if (valueEnd === valueStart) {
          COOKIE_HEADER_START.lastIndex = valueStart;
          continue;
        }
        let contentEnd = valueEnd;
        while (contentEnd > valueStart && (text[contentEnd - 1] === " " || text[contentEnd - 1] === "\t")) contentEnd -= 1;
        if (text.slice(valueStart, contentEnd) === REDACTED) {
          COOKIE_HEADER_START.lastIndex = valueStart;
          continue;
        }
        prefix = "";
        redacted = `${REDACTED}${text.slice(contentEnd, valueEnd)}`;
        end = valueEnd;
      }
      out += `${text.slice(last, match.index)}${header}${separator}${prefix}${redacted}`;
      last = end;
      COOKIE_HEADER_START.lastIndex = last;
    }
    return last === 0 ? text : `${out}${text.slice(last)}`;
  }

  interface ListRead {
    /** The text written in place of the list, from its first key to `end`. */
    replacement: string;
    /** The index just past the last pair read. */
    end: number;
  }

  /** The bare value of a pair in a request credential's list follows its key's own rule: a credential or proof key loses it, a setting key loses a token-shaped one, a webhook key keeps its origin, and any other key keeps it. */
  function scrubBareListValue(key: string, value: string): string {
    if (value.length === 0 || value === REDACTED) return value;
    if (PROOF_PARAM_PATTERN.test(key)) return REDACTED;
    const rule = pairRuleFor(key);
    switch (rule) {
      case "credential":
        return REDACTED;
      case "setting":
        return isTokenShapedValue(value) ? REDACTED : value;
      case "webhook":
        return webhookReplacement(value);
      case "none":
        return value;
      default: {
        const unhandled: never = rule;
        return unhandled;
      }
    }
  }

  /**
   * Reads one pair's value at `valueStart`, up to `limit`. The pairs of a credential's list are the
   * credential, so a quoted value is removed whatever its key (`Snowflake Token="<v>"`, `Digest
   * response="<v>"`, `Bearer blob="<v>"`) unless the key is a descriptive parameter (`realm="api"`),
   * while a bare value follows its key's own rule so `qop=auth`, `nc=00000001`, and an HMAC header's
   * timestamp stay legible and a bare proof (`response=<v>`, `sig=<v>`) goes. `terminated` is false when a
   * quoted value never closed, which ends the list there.
   */
  function readListPairValue(text: string, valueStart: number, key: string, limit: number): ListRead & { terminated: boolean } {
    const opener = openingQuoteUnit(text, valueStart);
    if (!opener) {
      LIST_BARE_VALUE_PATTERN.lastIndex = valueStart;
      const run = LIST_BARE_VALUE_PATTERN.exec(text)?.[0] ?? "";
      const value = text.slice(valueStart, Math.min(valueStart + run.length, limit));
      return { replacement: scrubBareListValue(key, value), end: valueStart + value.length, terminated: true };
    }
    const read = readQuotedContent(text, opener.contentStart, opener.backslashes, opener.quoteChar);
    const terminated = read.terminated && read.end <= limit;
    const end = Math.min(read.end, limit);
    const content = terminated ? read.content : text.slice(opener.contentStart, end);
    const closer = terminated ? text.slice(read.end - opener.backslashes - 1, read.end) : "";
    const value = content.length === 0 || content === REDACTED || LIST_KEPT_PARAM_PATTERN.test(key) ? content : REDACTED;
    return { replacement: `${text.slice(valueStart, opener.contentStart)}${value}${closer}`, end, terminated };
  }

  /** Reads a credential's pair list from `start`, its first key, up to `limit`; the list ends at the first text that is not another pair. */
  function scrubRequestPairList(text: string, start: number, limit: number): ListRead {
    let replacement = "";
    let end = start;
    let position = start;
    while (position < limit) {
      LIST_PAIR_KEY_PATTERN.lastIndex = position;
      const key = LIST_PAIR_KEY_PATTERN.exec(text)?.[0];
      if (key === undefined || position + key.length > limit) break;
      const pair = readListPairValue(text, position + key.length, key.slice(0, -1), limit);
      replacement += `${text.slice(end, position)}${key}${pair.replacement}`;
      end = pair.end;
      if (!pair.terminated) break;
      LIST_PAIR_SEPARATOR_PATTERN.lastIndex = end;
      const separator = LIST_PAIR_SEPARATOR_PATTERN.exec(text)?.[0];
      if (separator === undefined) break;
      position = end + separator.length;
    }
    return { replacement, end };
  }

  /**
   * The run after a scheme word under an Authorization-style key, when it is a bare key whose value
   * follows ("Token=", "username="). A quoted value opens the credential's pair list, read with the list
   * rule under a request header and a challenge header alike. A key whose value is already the
   * marker stays as it is, so a second pass adds nothing. Undefined when the run is the credential
   * itself, which goes whole.
   */
  function readSchemePairList(text: string, start: number, run: string, limit: number): ListRead | undefined {
    if (!PAIR_KEY_ONLY_PATTERN.test(run)) return undefined;
    const valueStart = start + run.length;
    if (valueStart < limit && openingQuoteUnit(text, valueStart)) return scrubRequestPairList(text, start, limit);
    if (text.startsWith(REDACTED, valueStart)) return { replacement: `${run}${REDACTED}`, end: valueStart + REDACTED.length };
    return undefined;
  }

  /** Reads the quoted pair list after every authorization scheme word in prose (see SCHEME_PAIR_LIST_PATTERN) with the list rule; a list under a header was read by the assignment pass and reads the same a second time. */
  function scrubSchemePairLists(text: string): string {
    SCHEME_PAIR_LIST_PATTERN.lastIndex = 0;
    let out = "";
    let last = 0;
    let match: RegExpExecArray | null;
    while ((match = SCHEME_PAIR_LIST_PATTERN.exec(text)) !== null) {
      if (match[0].length === 0) {
        SCHEME_PAIR_LIST_PATTERN.lastIndex += 1;
        continue;
      }
      const list = scrubRequestPairList(text, match.index + match[0].length, text.length);
      out += `${text.slice(last, match.index + match[0].length)}${list.replacement}`;
      last = list.end;
      SCHEME_PAIR_LIST_PATTERN.lastIndex = last;
    }
    return last === 0 ? text : `${out}${text.slice(last)}`;
  }

  interface ListPair {
    /** The pair's key, without its "=". */
    key: string;
    /** The value's content: between the quote units when quoted, the bare run otherwise. */
    content: string;
    /** The index of the content's first character. */
    contentStart: number;
  }

  /**
   * Reads the pair list whose first key starts at `start`: pairs separated by "," or spaces, with values
   * quoted at any depth or bare. The list ends at the first text that is not another pair, and an
   * unterminated quoted value ends it there.
   */
  function readPairList(text: string, start: number): { pairs: ListPair[]; end: number } {
    const pairs: ListPair[] = [];
    let position = start;
    let end = start;
    while (position < text.length) {
      LIST_PAIR_KEY_PATTERN.lastIndex = position;
      const key = LIST_PAIR_KEY_PATTERN.exec(text)?.[0];
      if (key === undefined) break;
      const valueStart = position + key.length;
      const opener = openingQuoteUnit(text, valueStart);
      if (opener) {
        const read = readQuotedContent(text, opener.contentStart, opener.backslashes, opener.quoteChar);
        pairs.push({ key: key.slice(0, -1), content: read.content, contentStart: opener.contentStart });
        end = read.end;
        if (!read.terminated) break;
      } else {
        LIST_BARE_VALUE_PATTERN.lastIndex = valueStart;
        const content = LIST_BARE_VALUE_PATTERN.exec(text)?.[0] ?? "";
        pairs.push({ key: key.slice(0, -1), content, contentStart: valueStart });
        end = valueStart + content.length;
      }
      LIST_PAIR_SEPARATOR_PATTERN.lastIndex = end;
      const separator = LIST_PAIR_SEPARATOR_PATTERN.exec(text)?.[0];
      if (separator === undefined) break;
      position = end + separator.length;
    }
    return { pairs, end };
  }

  /**
   * Removes the value of every proof parameter (see PROOF_PARAM_PATTERN) in a pair list that also carries
   * a challenge parameter, whatever the value's shape and whether or not a scheme word or a header
   * precedes the list: `realm="api", nonce="n", response="<proof>"` as a data value, after a literal
   * escape, or inside a JSON string. The other pairs keep their own rule, so `realm="api"` stays.
   */
  function scrubProofPairLists(text: string): string {
    PAIR_LIST_KEY_PATTERN.lastIndex = 0;
    let out = "";
    let last = 0;
    let match: RegExpExecArray | null;
    while ((match = PAIR_LIST_KEY_PATTERN.exec(text)) !== null) {
      const list = readPairList(text, match.index);
      if (list.pairs.some((pair) => CHALLENGE_PARAM_PATTERN.test(pair.key))) {
        for (const pair of list.pairs) {
          if (!PROOF_PARAM_PATTERN.test(pair.key) || pair.content.length === 0 || pair.content === REDACTED) continue;
          out += `${text.slice(last, pair.contentStart)}${REDACTED}`;
          last = pair.contentStart + pair.content.length;
        }
      }
      PAIR_LIST_KEY_PATTERN.lastIndex = list.end;
    }
    return last === 0 ? text : `${out}${text.slice(last)}`;
  }

  /**
   * Replaces the value of every credential-named pair: `key=value`, `key: value`, `"key": "value"`,
   * and `Header-Name: value`. The value goes whatever its shape (an `=` pair, a quoted value, a header
   * value, a plain word in prose, or a word that happens to be a scheme word: `sslPassword=splunk
   * rejected` and `db_password: token` lose their value). Only an Authorization-style key
   * (Authorization, Proxy-Authorization, WWW-Authenticate) carries a scheme word in front of its
   * credential, where the scheme is kept and the token removed (`Authorization: Bearer <token>`); a
   * pair list after the scheme is read pair by pair, see LEADING_SCHEME_IN_VALUE. A setting key keeps
   * a value that is not token-shaped, a bearer-id key loses a UUID, and a webhook key keeps only the
   * origin. The last segment of a bare path used as a label
   * ("/api/authn/v2/api_credentials: <detail>") is a request target, not a pair key, so the prose
   * after it is kept, unless the segment names a credential in the singular ("kv/password: <value>"),
   * whose next token is the value; inside a URL with a scheme the pair rule still applies.
   */
  function replaceCredentialAssignments(text: string): string {
    const urlSpans = [...text.matchAll(EMBEDDED_URL_PATTERN)].map((match) => [match.index ?? 0, (match.index ?? 0) + match[0].length] as const);
    ASSIGNMENT_KEY_PATTERN.lastIndex = 0;
    let out = "";
    let last = 0;
    let match: RegExpExecArray | null;
    while ((match = ASSIGNMENT_KEY_PATTERN.exec(text)) !== null) {
      const [whole, openingQuote, key, separator, separatorChar, valueOpenQuote] = match;
      if (whole.length === 0) {
        ASSIGNMENT_KEY_PATTERN.lastIndex += 1;
        continue;
      }
      const rule = pairRuleFor(key);
      if (rule === "none") continue;
      const valueStart = match.index + whole.length;
      const barePathLabel = openingQuote === "" && separatorChar === ":" && isBarePathSegment(text, match.index, urlSpans);
      if (barePathLabel && !namesCredential(key)) continue;
      const schemeCarrier = isAuthorizationStyleKey(keySegments(key));
      let kept = "";
      let consumed: number;
      let replacement = REDACTED;
      if (valueOpenQuote !== "") {
        // The value is quoted; read to its matching closer so an escaped inner quote at any JSON depth stays inner content and the value never ends early.
        const { content } = readQuotedContent(text, valueStart, valueOpenQuote.length - 1, valueOpenQuote[valueOpenQuote.length - 1] ?? '"');
        if (content.length === 0 || content === REDACTED) {
          ASSIGNMENT_KEY_PATTERN.lastIndex = valueStart;
          continue;
        }
        consumed = content.length;
        const lead = LEADING_SCHEME_IN_VALUE.exec(content);
        if (schemeCarrier && lead && SCHEME_WORD_PATTERN.test(lead[1])) {
          if (lead[3].startsWith(REDACTED)) {
            ASSIGNMENT_KEY_PATTERN.lastIndex = valueStart;
            continue;
          }
          kept = `${lead[1]}${lead[2]}`;
          const firstPair = PAIR_LIST_START.test(lead[3]) ? SCHEME_TOKEN_PATTERN.exec(text.slice(valueStart + lead[1].length)) : null;
          if (firstPair) {
            const list = readSchemePairList(text, valueStart + lead[1].length + firstPair[1].length, firstPair[3], valueStart + content.length);
            kept = `${lead[1]}${firstPair[1]}${firstPair[2]}`;
            if (list) {
              replacement = list.replacement;
              consumed = list.end - valueStart;
            } else {
              consumed = lead[1].length + firstPair[0].length;
            }
          }
        } else if (rule === "setting") {
          if (!isTokenShapedValue(content)) {
            ASSIGNMENT_KEY_PATTERN.lastIndex = valueStart;
            continue;
          }
        } else if (rule === "webhook") {
          replacement = webhookReplacement(content);
        }
      } else {
        ASSIGNMENT_VALUE_PATTERN.lastIndex = valueStart;
        const value = ASSIGNMENT_VALUE_PATTERN.exec(text)?.[0];
        if (value === undefined) continue;
        consumed = value.length;
        if (schemeCarrier && SCHEME_WORD_PATTERN.test(value)) {
          const token = SCHEME_TOKEN_PATTERN.exec(text.slice(valueStart + value.length));
          if (!token) continue;
          const list = token[2] === "" ? readSchemePairList(text, valueStart + value.length + token[1].length, token[3], text.length) : undefined;
          kept = `${value}${token[1]}${token[2]}`;
          if (list) {
            replacement = list.replacement;
            consumed = list.end - valueStart;
          } else {
            consumed += token[0].length;
          }
        } else if (rule === "setting") {
          if (!isTokenShapedValue(value)) continue;
        } else if (rule === "webhook") {
          replacement = webhookReplacement(value);
          if (text.startsWith(REDACTED, valueStart + consumed)) consumed += REDACTED.length;
        }
      }
      out += `${text.slice(last, match.index)}${openingQuote}${key}${separator}${kept}${replacement}`;
      last = valueStart + consumed;
      ASSIGNMENT_KEY_PATTERN.lastIndex = last;
    }
    return last === 0 ? text : `${out}${text.slice(last)}`;
  }

  /** Replaces the value argument of every credential-named flag (`--password <value>`); a setting flag (`--token-type bearer`) keeps its value. */
  function replaceFlagValues(text: string): string {
    return text.replace(FLAG_VALUE_PATTERN, (match: string, name: string, gap: string) => (pairRuleFor(name) === "credential" ? `--${name}${gap}${REDACTED}` : match));
  }

  /**
   * The carrier and shape rules shared by the error and data passes: PEM blocks, configured secrets,
   * cookie headers, URLs, query pairs, the proof parameters of a pair list, credential pairs and flags,
   * pair lists and scheme words in prose, JWTs, AWS keys, and vendor-prefixed tokens. `longTokens` adds the
   * generic long-token and hex-digest rules, which the error pass runs and the data pass leaves off so
   * identifiers survive in evidence.
   */
  function scrubText(text: string, secrets: ReadonlyArray<string | undefined>, longTokens: boolean): string {
    let scrubbed = text.replace(PEM_BLOCK_PATTERN, REDACTED).replace(PEM_OPEN_PATTERN, REDACTED);
    scrubbed = scrubCookieHeaders(scrubConfiguredSecrets(scrubbed, secrets))
      .replace(EMBEDDED_URL_PATTERN, scrubEmbeddedUrl)
      .replace(QUERY_PAIR_PATTERN, scrubQueryPair);
    scrubbed = scrubSchemePairLists(replaceFlagValues(replaceCredentialAssignments(scrubProofPairLists(scrubbed))))
      .replace(SCHEME_VALUE_PATTERN, scrubSchemeValue);
    for (const [pattern, replacement] of schemeRules) scrubbed = scrubbed.replace(pattern, replacement);
    scrubbed = scrubbed.replace(JWT_IN_TEXT_PATTERN, REDACTED)
      .replace(AWS_ACCESS_KEY_ID_PATTERN, REDACTED)
      .replace(AWS_SECRET_PATTERN, (run) => (looksLikeAwsSecret(run) ? REDACTED : run));
    if (longTokens) scrubbed = scrubbed.replace(HEX_DIGEST_PATTERN, (run) => (looksLikeHexDigest(run) ? REDACTED : run));
    for (const pattern of VENDOR_TOKEN_PATTERNS) scrubbed = scrubbed.replace(pattern, REDACTED);
    return longTokens ? scrubBareTokens(scrubbed) : scrubbed;
  }

  /**
   * The single redaction pass for error text. Idempotent: text that has been scrubbed once comes
   * back unchanged because `[REDACTED]` matches none of the patterns.
   */
  function scrubErrorText(text: string, secrets: ReadonlyArray<string | undefined> = []): string {
    return scrubText(text, secrets, true);
  }

  /**
   * The redaction pass for data-side text: every string a snapshot walker visits. A credential carrier
   * (`Authorization: Bearer <token>`, `password=<value>`, a webhook URL) or an unambiguous credential
   * shape (a vendor-prefixed token, a JWT, a PEM block, an AWS key) inside a free-text field is
   * removed on the data side too, while the generic long-token rule stays off so a name or an id that
   * merely looks random survives. Idempotent like the error pass.
   */
  function scrubDataText(text: string, secrets: ReadonlyArray<string | undefined> = []): string {
    return scrubText(text, secrets, false);
  }
  return { registerConfiguredSecrets, scrubErrorText, scrubDataText, pairRuleFor, webhookReplacement };
}
