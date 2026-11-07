/** Shared credential carrier parser with separate public-PEM evidence and strict error modes. */
import { REDACTED_VALUE, scrubSensitiveValues } from "../../../core/redact.js";
import { NON_CREDENTIAL_KEY_QUALIFIERS, propertyNameSegments } from "./credential-keys.js";

export interface PemCredentialScrubber {
  MIN_CONFIGURED_SECRET_LENGTH: number;
  LONG_TOKEN_MIN_LENGTH: number;
  URL_VALUE_PATTERN: RegExp;
  SESSION_ID_PATTERN: RegExp;
  isCredentialKey(key: string): boolean;
  isWebhookUrlKey(key: string): boolean;
  redactedWebhookUrl(url: string): string;
  scrubCarriers(text: string, pemScope: "all" | "private"): string;
  redactErrorText(text: string): string;
  redactConfiguredSecrets(text: string, secrets: ReadonlyArray<string | undefined>): string;
}

export function createPemCredentialScrubber(): PemCredentialScrubber {
  const REDACTION_MARKER = "[REDACTED]";
  const MIN_CONFIGURED_SECRET_LENGTH = 4;

  const LONG_TOKEN_MIN_LENGTH = 16;

  type PemScope = "all" | "private";

  const PEM_BLOCK_PATTERN = /-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?-----END [A-Z0-9 ]+-----/g;

  const PEM_OPEN_PATTERN = /-----BEGIN ([A-Z0-9 ]+)-----(?:(?!-----END )[\s\S])*$/;

  const PUBLIC_PEM_LABELS = new Set(["CERTIFICATE", "TRUSTED CERTIFICATE", "X509 CRL", "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST", "PUBLIC KEY", "RSA PUBLIC KEY", "PKCS7", "CMS"]);

  const EMBEDDED_URL_PATTERN = /\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>()[\]{}]+/gi;

  const URL_USERINFO_PATTERN = /^([a-z][a-z0-9+.-]*:\/\/)[^\s\/?#@"'<>\\]+@/i;

  const QUERY_PAIR_PATTERN = /([?&#])([A-Za-z0-9_.[\]-]+)=((?!\[REDACTED\])[^&#\s"'<>,\\]+(?:["'](?![:)}\]])[^&#\s"'<>,\\]+)*)/g;

  const HEADER_LINE_PATTERN = /(?:(?<![A-Za-z0-9_])|(?<=\\[nrtbfv0]|\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}))(authorization|proxy-authorization|cookie|set-cookie|x-cookie|x-api-key|x-apikeys?|api-key|apikey|x-securitycenter|x-pan-key|x-redlock-auth|x-auth-token|x-access-token|x-amz-security-token|x-vault-token|private-token|x-goog-api-key|x-csrf-token|x-xsrf-token)((?:\\*["'])?\s*:\s*)/gi;

  const ESCAPE_LETTER_PATTERN = /^(?:[nrtbfv0]|u[0-9A-Fa-f]{4}|x[0-9A-Fa-f]{2})/;

  const HEADER_VALUE_OPENER_PATTERN = /[=:,;(\s]/;

  const QUOTE_BOUNDARY_PATTERN = /[\s,;:)}\]<>"'\\]/;

  const HEADER_VALUE_TERMINATOR_PATTERN = /[\r\n<>]/;

  const FOLLOWING_HEADER_PATTERN = /^\s*(?:\\*["'])?[A-Za-z][A-Za-z0-9.-]*(?:\\*["'])?\s*:(?!\/\/)/;

  const FOLLOWING_HEADER_LOOKAHEAD = 96;

  const AUTHORIZATION_HEADERS = new Set(["authorization", "proxy-authorization"]);

  const LIST_VALUE_HEADERS = new Set(["cookie", "set-cookie", "x-cookie", "x-apikeys", "x-apikey"]);

  const AUTH_SCHEME_WORDS = new Set([
    "basic", "bearer", "digest", "hoba", "mutual", "negotiate", "oauth", "scram-sha-1", "scram-sha-256", "vapid", "dpop", "gnap",
    "privatetoken", "concealed", "ntlm", "token", "ssws", "apikey", "api-key", "splunk", "snowflake", "aws4-hmac-sha256",
  ]);

  const AUTH_SCHEME_PATTERN = /^([A-Za-z][A-Za-z0-9-]*)(?:\s+|$)/;

  const REDACTED_SCHEME_VALUE_PATTERN = /^([A-Za-z][A-Za-z0-9-]*)\s+((?:\\*["'])?)\[REDACTED\]/;

  const AUTH_PARAM_LIST_PATTERN = /^[A-Za-z][A-Za-z0-9_-]*=/;

  const SCHEME_WORD_SOURCE = "Bearer|Basic|Digest|Token|OAuth|Negotiate|NTLM|SSWS|ApiKey|Api-Key|Splunk|Snowflake|AWS4-HMAC-SHA256";

  const SCHEME_VALUE_PATTERN = new RegExp(String.raw`\b(${SCHEME_WORD_SOURCE})\s+((?!\[REDACTED\])[A-Za-z0-9._~+/=-]{4,})`, "gi");

  const NOUN_SCHEME_WORDS = new Set(["token", "oauth", "splunk", "snowflake"]);

  const AUTH_PARAM_PATTERN = /^([A-Za-z][A-Za-z0-9_-]*)=$/;

  const AUTH_PARAM_NAMES = new Set([
    "realm", "error", "error_description", "error_uri", "scope", "charset", "nonce", "opaque", "qop", "algorithm", "stale", "domain",
    "uri", "response", "cnonce", "nc", "username", "credential", "signedheaders", "signature", "oauth_consumer_key", "oauth_token",
    "oauth_signature_method", "oauth_signature", "oauth_timestamp", "oauth_nonce", "oauth_version", "oauth_callback", "oauth_verifier",
  ]);

  const CHALLENGE_PARAM_NAMES = new Set(["realm", "error", "error_description", "error_uri", "scope", "charset", "domain", "nonce", "opaque", "stale", "algorithm", "qop", "userhash"]);

  const PROOF_PARAM_NAMES = new Set(["response", "signature", "oauth_signature", "mac", "sig"]);

  const AUTH_PARAMETER_LIST_OPENER_PATTERN = /(?<![A-Za-z0-9_.:-])[A-Za-z][A-Za-z0-9_-]*=/g;

  const SCHEME_LED_LIST_PATTERN = new RegExp(String.raw`\b(?:${SCHEME_WORD_SOURCE})\s+$`, "i");

  const SCHEME_PARAMETER_LIST_PATTERN = new RegExp(String.raw`\b(${SCHEME_WORD_SOURCE})\s+(?=[A-Za-z][A-Za-z0-9_-]*=)`, "gi");

  const AUTH_PARAM_ITEM_PATTERN = /([A-Za-z][A-Za-z0-9_-]*)=/y;

  const AUTH_PARAM_BARE_VALUE_PATTERN = /[^\s,"'\\<>]+/y;

  const AUTH_PARAM_SEPARATOR_PATTERN = /\s*,\s*/y;

  const PLAIN_WORD_PATTERN = /^[a-z]+$/;

  const TITLE_WORD_PATTERN = /^[A-Z][a-z]{1,19}$/;

  const SCHEME_PROSE_WORDS = new Set([
    "authentication", "authorization", "auth", "token", "tokens", "credential", "credentials", "scheme", "schemes", "header", "headers",
    "realm", "challenge", "access", "mode", "method", "login", "flow", "grant", "type", "string", "value", "values", "user", "users",
    "account", "client", "clients", "error", "request", "requests", "response", "with", "without", "and", "or", "is", "was", "are",
    "not", "the", "this", "that", "these", "those", "to", "in", "for", "from", "on", "of", "by", "as", "at", "if", "then", "but", "so",
    "than", "when", "where", "over", "via", "per", "only", "still", "also", "use", "used", "using", "required", "requires", "failed",
    "rejected", "expired", "invalid", "missing", "unsupported", "supported", "unauthorized", "forbidden", "denied", "allowed", "enabled",
    "disabled", "preferred", "deprecated", "retired", "retiring", "must", "should", "can", "cannot", "could", "will", "would", "may",
    "has", "have", "does", "did", "do", "be", "been",
  ]);

  const JSON_QUOTED_PAIR_PATTERN = /"([A-Za-z_][A-Za-z0-9_.-]{0,63})"(\s*:\s*)"((?!\[REDACTED\])[^"\r\n]+)"/g;

  const JSON_ESCAPED_PAIR_PATTERN = /(\\+)"([A-Za-z_][A-Za-z0-9_.-]{0,63})\1"(\s*:\s*)\1"((?!\[REDACTED\])(?:(?!\1")[^\r\n])+?)\1"/g;

  const QUOTED_ATTRIBUTE_PATTERN = /(?<![A-Za-z0-9_.:-])([A-Za-z_][A-Za-z0-9_.:-]{0,63})\s*=\s*(\\*["'])((?!\[REDACTED\])(?:[^"'\r\n]|["'](?=[^\s"'\r\n<>;,&:)}\]\\]))+)\2/g;

  const ASSIGNMENT_KEY_PATTERN = /(?:(?<![A-Za-z0-9_])|(?<=\\0))((?:\\*["'])?)([A-Za-z_][A-Za-z0-9_.-]{0,63})((?:\\*["'])?\s*([:=])\s*(?:\\*["'])?)/g;

  const ESCAPED_CONTROL_SOURCE = String.raw`\\(?:[nrtbfv0]|u(?:00[01][0-9a-fA-F]|007[fF]|202[89])|x(?:[01][0-9a-fA-F]|7[fF]))`;

  const FLAG_VALUE_PATTERN = new RegExp(String.raw`(?<![A-Za-z0-9_-])--([A-Za-z_][A-Za-z0-9_.-]{0,63})([ \t]+)((?!\[REDACTED\])(?!-)(?:(?!${ESCAPED_CONTROL_SOURCE})[^\s\x00-\x1f\x7f"'<>;,&])+)`, "g");

  const PROSE_CONTINUATION_PATTERN = /^[ \t]+[A-Za-z]/;

  const PLURAL_CREDENTIAL_LABEL_PATTERN = /(?:token|secret|key|cookie|password|credential|passphrase|signature|session)s$/;

  const JAVA_PROPERTY_PREFIX_PATTERN = /(?:^|\s)-$/;

  const DELIMITED_VALUE_PATTERN = new RegExp(String.raw`(?!\[REDACTED\])(?!["'])(?:(?!\\+["'])(?!${ESCAPED_CONTROL_SOURCE})[^\s\x00-\x1f\x7f"'<>;,&]|["'](?=[^\s"'<>;,&:)}\]\\]))+`, "y");

  const LINE_VALUE_PATTERN = /(?!\[REDACTED\])(?!["'])(?:(?!\\+["'])(?!\\(?:[nr]|u000[adAD]|x0[adAD]))[^\r\n<>"',;{}[\]]|["'](?=[^\s\r\n<>"',;{}[\]:)\\]))*(?!\\+["'])(?!\\(?:[nr]|u000[adAD]|x0[adAD]))[^\s\r\n<>"',;{}[\]]/y;

  const TOKEN_IN_PATH_WEBHOOK_PATTERN = /(https?:\/\/(?:hooks\.slack\.com\/services|discord(?:app)?\.com\/api\/webhooks|[a-z0-9.-]*webhook\.office\.com\/webhookb2)\/)(?!\[REDACTED\])(?:[^\s"'<>\\]|["'](?=[^\s"'<>\\,;:)}\]]))+/gi;

  const SLASH_ESCAPED_URL_USERINFO_PATTERN = /\b([a-z][a-z0-9+.-]*:\\\/\\\/)[^\s\/?#@"'<>\\]+@/gi;

  const WEBHOOK_URL_TAIL_WORDS = new Set(["url", "uri", "endpoint", "address", "link"]);

  const URL_VALUE_PATTERN = /^[a-z][a-z0-9+.-]*:\/\/\S+$/i;

  const WEBHOOK_VALUE_PATTERN = /[a-z][a-z0-9+.-]*:\/\/[^\s"'<>]+/iy;

  const URL_ORIGIN_PATTERN = /^([a-z][a-z0-9+.-]*:\/\/)(?:[^/?#@]*@)?([^/?#]*)/i;

  const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)*/g;

  const PANOS_API_KEY_PATTERN = /\bLUFRPT[A-Za-z0-9+/=_-]{16,}/g;

  const AWS_ACCESS_KEY_ID_PATTERN = /\b(?:AKIA|ASIA|AROA|AIDA|AGPA|ANPA|ANVA|APKA|ABIA|ACCA)[A-Z0-9]{16}\b/g;

  const GITHUB_TOKEN_PATTERN = /\b(?:gh[oprsu]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})/g;

  const STRIPE_KEY_PATTERN = /\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}/g;

  const SLACK_TOKEN_PATTERN = /\bxox[abeoprs]-[A-Za-z0-9-]{10,}/g;

  const LONG_TOKEN_RUN_PATTERN = /[A-Za-z0-9+_-]{16,}(?:={1,2}(?![A-Za-z0-9&]))?/g;

  const TOKEN_VALUE_PATTERN = /^[A-Za-z0-9+_-]{16,}={0,2}$/;

  const UPPERCASE_CODE_PATTERN = /^[A-Z][A-Z_]*$|^[A-Z][A-Z0-9]*(?:[_-][A-Z0-9]+)+$/;

  const DIGITS_ONLY_PATTERN = /^\d+$/;

  const DIGIT_GROUP_PATTERN = /\d+/g;

  const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

  const MIN_LETTERS_FOR_CASING = 6;

  const MIN_TOKEN_SEGMENT_LENGTH = 8;

  const CREDENTIAL_KEY_WORDS = new Set([
    "token", "tokens", "secret", "secrets", "password", "passwords", "passwd", "pwd", "passphrase", "passcode", "phash",
    "apikey", "authorization", "credential", "credentials", "key", "keys", "cookie", "cookies", "sid", "sig", "signature",
    "auth", "nonce", "sas", "community", "authpwd", "privpwd", "pin", "otp", "totp", "jwt", "assertion", "bearer", "hmac",
    "session", "sessid", "kubeconfig", "dsn", "pem", "ikey", "skey",
  ]);

  const CREDENTIAL_KEY_SUFFIX_PATTERN = /(?:token|secret|passw(?:or)?d|passphrase|passcode|phash|authorization|credential|signature|nonce|community|assertion|session|sessid|authpwd|privpwd|(?:api|private|secret|access|signing|encryption|master|shared|account|client|service|session|license|ssh|hmac)keys?)$/;

  const CREDENTIAL_VALUE_FORM_WORDS = new Set(["value", "values", "plain", "plaintext", "data", "string", "text", "header", "raw", "encrypted", "hash", "digest", "blob", "content"]);

  const SESSION_ID_PATTERN = /sess(?:ion)?[_.-]?id$/i;

  const BOUND_KEY_SEGMENTS = new Set(["max", "min"]);

  const EXTRA_CREDENTIAL_KEYS = new Set(["x-pan-key", "x-redlock-auth", "proxy-authorization", "x-amz-signature", "x-amz-credential", "x-amz-security-token", "oauth_signature", "oauth_token", "oauth_verifier"]);

  const ASSIGNMENT_ONLY_CREDENTIAL_WORDS = new Set(["pass"]);

  const STRUCTURAL_VALUE_PATTERN = /^(?:[{[]|\{\}|\[\]|true|false|null)$/;

  const PLURAL_CREDENTIAL_WORDS = new Set(["tokens", "secrets", "keys", "cookies", "passwords", "credentials"]);

  const COUNT_VALUE_PATTERN = new RegExp(String.raw`^\d+(?:\s|${ESCAPED_CONTROL_SOURCE}|$)`);

  const CREDENTIAL_CODE_QUALIFIERS = new Set(["registration", "activation", "linking", "auth", "authorization", "access", "verification", "recovery", "backup", "security", "mfa", "otp", "pairing", "enrollment", "license"]);

  const BEARER_ID_QUALIFIER_PATTERN = /(?:secret|token)$/;

  function credentialKeyWord(segment: string): boolean {
    return CREDENTIAL_KEY_WORDS.has(segment) || CREDENTIAL_KEY_SUFFIX_PATTERN.test(segment);
  }

  function keyWords(key: string): string[] {
    return propertyNameSegments(key).map((segment) => segment.replace(/\d+$/, "")).filter((segment) => segment.length > 0);
  }

  function isCredentialKey(key: string): boolean {
    if (SESSION_ID_PATTERN.test(key) || EXTRA_CREDENTIAL_KEYS.has(key.toLowerCase())) return true;
    const words = keyWords(key);
    const last = words[words.length - 1];
    if (last === undefined || BOUND_KEY_SEGMENTS.has(words[0])) return false;
    if ((last === "key" || last === "keys") && words.length > 1 && NON_CREDENTIAL_KEY_QUALIFIERS.has(words[words.length - 2])) return false;
    if (last === "code" || last === "codes") return words.length > 1 && CREDENTIAL_CODE_QUALIFIERS.has(words[words.length - 2]);
    if (last === "id") return words.length > 1 && BEARER_ID_QUALIFIER_PATTERN.test(words[words.length - 2]);
    // A connection string (connection_string, connectionString, DB_CONNECTION_STRING) embeds
    // the password of the account it connects as.
    if (last === "string" && words[words.length - 2] === "connection") return true;
    if (credentialKeyWord(last)) return true;
    return CREDENTIAL_VALUE_FORM_WORDS.has(last) && words.slice(0, -1).some(credentialKeyWord);
  }

  function isWebhookUrlKey(key: string): boolean {
    const words = keyWords(key);
    const last = words[words.length - 1];
    if (last === "webhook") return true;
    return last !== undefined && WEBHOOK_URL_TAIL_WORDS.has(last) && words[words.length - 2] === "webhook";
  }

  function redactedWebhookUrl(url: string): string {
    const origin = URL_ORIGIN_PATTERN.exec(url);
    return `${origin ? `${origin[1]}${origin[2]}` : ""}/${REDACTION_MARKER}`;
  }

  function isCountValue(key: string, value: string): boolean {
    if (!COUNT_VALUE_PATTERN.test(value)) return false;
    const words = keyWords(key);
    return words.length > 0 && PLURAL_CREDENTIAL_WORDS.has(words[words.length - 1]);
  }

  function isPluralCredentialKey(key: string): boolean {
    const words = keyWords(key);
    const last = words[words.length - 1];
    return last !== undefined && (PLURAL_CREDENTIAL_WORDS.has(last) || PLURAL_CREDENTIAL_LABEL_PATTERN.test(last));
  }

  function isCredentialAssignmentKey(key: string): boolean {
    if (isCredentialKey(key)) return true;
    const words = keyWords(key);
    return words.length > 0 && ASSIGNMENT_ONLY_CREDENTIAL_WORDS.has(words[words.length - 1]);
  }

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

  function isNameSegment(segment: string): boolean {
    if (segment.length === 0 || DIGITS_ONLY_PATTERN.test(segment)) return true;
    const digitGroups = segment.match(DIGIT_GROUP_PATTERN) ?? [];
    if (digitGroups.length > 1) return false;
    return !hasTokenCasing(segment.replace(DIGIT_GROUP_PATTERN, ""));
  }

  function looksLikeToken(run: string): boolean {
    const padding = /=+$/.exec(run)?.[0] ?? "";
    const body = run.slice(0, run.length - padding.length);
    if (UPPERCASE_CODE_PATTERN.test(body) || DIGITS_ONLY_PATTERN.test(body) || UUID_PATTERN.test(body)) return false;
    if (body.includes("+")) return true;
    if (padding.length > 0) return run.length % 4 === 0 && !/[-_]/.test(body);
    const segments = body.split(/[-_]/).filter((segment) => segment.length > 0);
    const tokenSegments = segments.filter((segment) => !isNameSegment(segment));
    if (tokenSegments.length === 0) return false;
    return tokenSegments.some((segment) => segment.length >= MIN_TOKEN_SEGMENT_LENGTH) || tokenSegments.length * 2 >= segments.length;
  }

  function isTokenShapedValue(value: string): boolean {
    return TOKEN_VALUE_PATTERN.test(value) && looksLikeToken(value);
  }

  function isSchemeProse(scheme: string, value: string): boolean {
    if (TITLE_WORD_PATTERN.test(value)) return true;
    const authParam = AUTH_PARAM_PATTERN.exec(value);
    if (authParam) return AUTH_PARAM_NAMES.has(authParam[1].toLowerCase());
    if (!PLAIN_WORD_PATTERN.test(value)) return false;
    if (SCHEME_PROSE_WORDS.has(value)) return true;
    return NOUN_SCHEME_WORDS.has(scheme.toLowerCase()) && value.length < LONG_TOKEN_MIN_LENGTH;
  }

  function isPublicPemLabel(label: string): boolean {
    return PUBLIC_PEM_LABELS.has(label.trim());
  }

  function scrubPem(text: string, scope: PemScope): string {
    const keeps = (label: string): boolean => {
      switch (scope) {
        case "all":
          return false;
        case "private":
          return isPublicPemLabel(label);
        default: {
          const exhaustive: never = scope;
          return exhaustive;
        }
      }
    };
    return text
      .replace(PEM_BLOCK_PATTERN, (match, label: string) => (keeps(label) ? match : REDACTION_MARKER))
      .replace(PEM_OPEN_PATTERN, (match, label: string) => (keeps(label) ? match : REDACTION_MARKER));
  }

  function scrubUrlUserinfo(url: string): string {
    return url.replace(URL_USERINFO_PATTERN, `$1${REDACTION_MARKER}@`);
  }

  function backslashRun(text: string, index: number): number {
    let run = 0;
    while (text[index + run] === "\\") run += 1;
    return run;
  }

  function quoteTokenAt(text: string, index: number): string | undefined {
    const run = backslashRun(text, index);
    const quote = text[index + run];
    if ((quote !== '"' && quote !== "'") || (run > 0 && run % 2 === 0)) return undefined;
    return text.slice(index, index + run + 1);
  }

  function midTokenQuoteAt(text: string, index: number, tokenLength: number): boolean {
    const before = text[index - 1];
    const after = text[index + tokenLength];
    if (before === undefined || after === undefined) return false;
    if (HEADER_VALUE_OPENER_PATTERN.test(before) || before === '"' || before === "'" || before === "\\") return false;
    return !QUOTE_BOUNDARY_PATTERN.test(after);
  }

  function closingQuoteAfterOpener(text: string, index: number, tokenLength: number): boolean {
    const after = text[index + tokenLength];
    return after === undefined || /[\s,;:)}\]<>]/.test(after);
  }

  function lineEndFrom(text: string, start: number): number {
    const terminator = HEADER_VALUE_TERMINATOR_PATTERN.exec(text.slice(start));
    return terminator ? start + terminator.index : text.length;
  }

  const CONTROL_ESCAPE_LETTERS = new Map<string, number>([["n", 0x0a], ["r", 0x0d], ["t", 0x09], ["b", 0x08], ["f", 0x0c], ["v", 0x0b], ["0", 0x00]]);

  function isControlCode(code: number): boolean {
    return code <= 0x1f || code === 0x7f || code === 0x2028 || code === 0x2029;
  }

  function escapedControlCodeAt(text: string, index: number): number {
    const run = backslashRun(text, index);
    if (run === 0 || run % 2 === 0) return -1;
    const letter = text[index + run];
    if (letter === undefined) return -1;
    const simple = CONTROL_ESCAPE_LETTERS.get(letter);
    if (simple !== undefined) return simple;
    const digits = letter === "u" ? 4 : letter === "x" ? 2 : 0;
    if (digits === 0) return -1;
    const hex = text.slice(index + run + 1, index + run + 1 + digits);
    if (hex.length !== digits || !/^[0-9a-f]+$/i.test(hex)) return -1;
    const code = parseInt(hex, 16);
    return isControlCode(code) ? code : -1;
  }

  function escapedLineBreakAt(text: string, index: number): boolean {
    const code = escapedControlCodeAt(text, index);
    return code === 0x0a || code === 0x0d;
  }

  function unquotedTokenEnd(text: string, start: number, limit: number): number {
    let index = start;
    while (index < limit) {
      const char = text[index];
      if (/\s/.test(char) || isControlCode(char.charCodeAt(0))) break;
      if (char === "\\") {
        if (escapedControlCodeAt(text, index) !== -1) break;
        index += backslashRun(text, index);
        continue;
      }
      index += 1;
    }
    return index;
  }

  function keyAfterEscape(text: string, keyStart: number, key: string): string {
    let run = 0;
    while (keyStart - 1 - run >= 0 && text[keyStart - 1 - run] === "\\") run += 1;
    if (run % 2 === 0) return key;
    const letter = ESCAPE_LETTER_PATTERN.exec(key);
    return letter ? key.slice(letter[0].length) : key;
  }

  function closingQuoteIndex(text: string, from: number, token: string, limit: number): number {
    let index = from;
    while (index < limit) {
      const candidate = quoteTokenAt(text, index);
      if (candidate === undefined) {
        index += text[index] === "\\" ? backslashRun(text, index) : 1;
        continue;
      }
      if (midTokenQuoteAt(text, index, candidate.length)) {
        index += candidate.length;
        continue;
      }
      if (candidate === token) return index;
      if (candidate.length < token.length) return -1;
      index += candidate.length;
    }
    return -1;
  }

  function headerValueEnd(text: string, start: number): number {
    const limit = lineEndFrom(text, start);
    const opening = quoteTokenAt(text, start);
    if (opening !== undefined) {
      const close = closingQuoteIndex(text, start + opening.length, opening, limit);
      if (close !== -1) return close + opening.length;
    }
    let index = opening === undefined ? start : start + opening.length;
    while (index < limit) {
      const char = text[index];
      if ((char === ";" || char === ",") && FOLLOWING_HEADER_PATTERN.test(text.slice(index + 1, index + 1 + FOLLOWING_HEADER_LOOKAHEAD))) break;
      if (char === "\\" && escapedLineBreakAt(text, index)) break;
      const token = quoteTokenAt(text, index);
      if (token === undefined) {
        index += char === "\\" ? backslashRun(text, index) : 1;
        continue;
      }
      if (!HEADER_VALUE_OPENER_PATTERN.test(text[index - 1])) {
        if (!midTokenQuoteAt(text, index, token.length)) break;
        index += token.length;
        continue;
      }
      if (closingQuoteAfterOpener(text, index, token.length)) break;
      const close = closingQuoteIndex(text, index + token.length, token, limit);
      index = close === -1 ? index + token.length : close + token.length;
    }
    while (index > start && /\s/.test(text[index - 1])) index -= 1;
    return index;
  }

  function enclosingQuote(value: string): string {
    const token = quoteTokenAt(value, 0);
    return token !== undefined && value.length >= token.length * 2 && value.endsWith(token) ? token : "";
  }

  function keepsSchemeWord(key: string, value: string): boolean {
    if (!AUTHORIZATION_HEADERS.has(key.toLowerCase())) return false;
    const scheme = REDACTED_SCHEME_VALUE_PATTERN.exec(value);
    return scheme !== null && AUTH_SCHEME_WORDS.has(scheme[1].toLowerCase());
  }

  function leadingSchemeWord(value: string): RegExpExecArray | undefined {
    const scheme = AUTH_SCHEME_PATTERN.exec(value);
    if (!scheme || scheme[0].length === value.length || !AUTH_SCHEME_WORDS.has(scheme[1].toLowerCase())) return undefined;
    return scheme;
  }

  function schemeCredentialsEnd(text: string, credentialsStart: number, end: number): number {
    const credentials = text.slice(credentialsStart, end);
    if (AUTH_PARAM_LIST_PATTERN.test(credentials)) return end;
    const quote = quoteTokenAt(credentials, 0);
    if (quote !== undefined) {
      const close = closingQuoteIndex(text, credentialsStart + quote.length, quote, end);
      return close === -1 ? end : close + quote.length;
    }
    return unquotedTokenEnd(text, credentialsStart, end);
  }

  function singleTokenEnd(text: string, start: number, end: number): number {
    const value = text.slice(start, end);
    if (enclosingQuote(value) !== "") return end;
    const scheme = leadingSchemeWord(value);
    if (scheme !== undefined) return schemeCredentialsEnd(text, start + scheme[0].length, end);
    return unquotedTokenEnd(text, start, end);
  }

  function authorizationValueEnd(text: string, start: number, end: number): number {
    const value = text.slice(start, end);
    if (enclosingQuote(value) !== "") return end;
    const scheme = leadingSchemeWord(value);
    if (scheme === undefined) return end;
    return schemeCredentialsEnd(text, start + scheme[0].length, end);
  }

  function redactedHeaderValue(header: string, value: string): string | undefined {
    const quote = enclosingQuote(value);
    const inner = quote === "" ? value : value.slice(quote.length, value.length - quote.length);
    if (inner.startsWith(REDACTION_MARKER)) return undefined;
    if (AUTHORIZATION_HEADERS.has(header)) {
      const scheme = AUTH_SCHEME_PATTERN.exec(inner);
      if (scheme && AUTH_SCHEME_WORDS.has(scheme[1].toLowerCase())) {
        const credentials = inner.slice(scheme[0].length);
        if (credentials.length === 0) return undefined;
        const credentialQuote = enclosingQuote(credentials);
        if (credentials.slice(credentialQuote.length).startsWith(REDACTION_MARKER)) return undefined;
        return `${quote}${scheme[1]} ${credentialQuote}${REDACTION_MARKER}${credentialQuote}${quote}`;
      }
    }
    return `${quote}${REDACTION_MARKER}${quote}`;
  }

  function scrubHeaderLines(text: string): string {
    HEADER_LINE_PATTERN.lastIndex = 0;
    let out = "";
    let last = 0;
    let match: RegExpExecArray | null;
    while ((match = HEADER_LINE_PATTERN.exec(text)) !== null) {
      const header = match[1].toLowerCase();
      const start = match.index + match[0].length;
      const lineEnd = headerValueEnd(text, start);
      const end = LIST_VALUE_HEADERS.has(header) ? lineEnd : AUTHORIZATION_HEADERS.has(header) ? authorizationValueEnd(text, start, lineEnd) : singleTokenEnd(text, start, lineEnd);
      const value = text.slice(start, end);
      if (value.length === 0) continue;
      const replacement = redactedHeaderValue(header, value);
      if (replacement === undefined) continue;
      out += `${text.slice(last, start)}${replacement}`;
      last = end;
      HEADER_LINE_PATTERN.lastIndex = end;
    }
    return last === 0 ? text : `${out}${text.slice(last)}`;
  }

  function replaceCredentialAssignments(text: string): string {
    const fates = authParameterFates(text);
    ASSIGNMENT_KEY_PATTERN.lastIndex = 0;
    let out = "";
    let last = 0;
    let match: RegExpExecArray | null;
    while ((match = ASSIGNMENT_KEY_PATTERN.exec(text)) !== null) {
      const [whole, openingQuote, key, separator, operator] = match;
      if (operator === "=" && fates.get(match.index + openingQuote.length) === "challenge") continue;
      const spelledName = keyAfterEscape(text, match.index + openingQuote.length, key);
      const name = openingQuote === "" && spelledName.startsWith("D") && JAVA_PROPERTY_PREFIX_PATTERN.test(text.slice(Math.max(0, match.index - 2), match.index)) ? spelledName.slice(1) : spelledName;
      const valueStart = match.index + whole.length;
      if (isWebhookUrlKey(name)) {
        WEBHOOK_VALUE_PATTERN.lastIndex = valueStart;
        const url = WEBHOOK_VALUE_PATTERN.exec(text)?.[0];
        if (url === undefined) continue;
        out += `${text.slice(last, match.index)}${openingQuote}${key}${separator}${redactedWebhookUrl(url)}`;
        last = valueStart + url.length;
        ASSIGNMENT_KEY_PATTERN.lastIndex = last;
        continue;
      }
      if (!(operator === "=" ? isCredentialAssignmentKey(name) : isCredentialKey(name))) continue;
      const redactedScheme = REDACTED_SCHEME_VALUE_PATTERN.exec(text.slice(valueStart));
      if (redactedScheme !== null && AUTH_SCHEME_WORDS.has(redactedScheme[1].toLowerCase())) {
        if (AUTHORIZATION_HEADERS.has(name.toLowerCase())) continue;
        out += `${text.slice(last, match.index)}${openingQuote}${key}${separator}${redactedScheme[2]}${REDACTION_MARKER}`;
        last = valueStart + redactedScheme[0].length;
        ASSIGNMENT_KEY_PATTERN.lastIndex = last;
        continue;
      }
      const pathLabel = operator === ":" && text[match.index - 1] === "/" && text[match.index - 2] !== "\\";
      const valuePattern = operator === ":" && !pathLabel ? LINE_VALUE_PATTERN : DELIMITED_VALUE_PATTERN;
      valuePattern.lastIndex = valueStart;
      const value = valuePattern.exec(text)?.[0];
      if (value === undefined || STRUCTURAL_VALUE_PATTERN.test(value) || isCountValue(name, value)) continue;
      if (pathLabel && isPluralCredentialKey(name) && PROSE_CONTINUATION_PATTERN.test(text.slice(valueStart + value.length))) continue;
      out += `${text.slice(last, match.index)}${openingQuote}${key}${separator}${REDACTION_MARKER}`;
      last = valueStart + value.length;
      ASSIGNMENT_KEY_PATTERN.lastIndex = last;
    }
    return last === 0 ? text : `${out}${text.slice(last)}`;
  }

  function replaceFlagValues(text: string): string {
    return text.replace(FLAG_VALUE_PATTERN, (match, flag: string, space: string) => (isCredentialKey(flag) ? `--${flag}${space}${REDACTION_MARKER}` : match));
  }

  function quotedParameterValueEnd(text: string, valueStart: number, quote: string, limit: number): number {
    let index = valueStart + quote.length;
    while (index < limit) {
      const candidate = quoteTokenAt(text, index);
      if (candidate === undefined) {
        index += text[index] === "\\" ? backslashRun(text, index) : 1;
        continue;
      }
      if (midTokenQuoteAt(text, index, candidate.length)) {
        index += candidate.length;
        continue;
      }
      if (candidate === quote) return index + candidate.length;
      if (candidate.length < quote.length) return index;
      index += candidate.length;
    }
    return limit;
  }

  interface AuthParameter {
    name: string;
    nameStart: number;
    valueStart: number;
    valueEnd: number;
    quote: string | undefined;
  }

  type AuthParameterFate = "proof" | "challenge" | "other";

  function readAuthParameterList(text: string, start: number): { end: number; items: AuthParameter[] } | undefined {
    const limit = lineEndFrom(text, start);
    const items: AuthParameter[] = [];
    let index = start;
    while (index < limit) {
      AUTH_PARAM_ITEM_PATTERN.lastIndex = index;
      const item = AUTH_PARAM_ITEM_PATTERN.exec(text);
      if (item === null) break;
      const valueStart = index + item[0].length;
      const quote = quoteTokenAt(text, valueStart);
      let valueEnd: number;
      if (quote !== undefined) {
        valueEnd = quotedParameterValueEnd(text, valueStart, quote, limit);
      } else {
        AUTH_PARAM_BARE_VALUE_PATTERN.lastIndex = valueStart;
        const bare = AUTH_PARAM_BARE_VALUE_PATTERN.exec(text);
        if (bare === null) break;
        valueEnd = valueStart + bare[0].length;
      }
      items.push({ name: keyAfterEscape(text, index, item[1]), nameStart: index, valueStart, valueEnd, quote });
      AUTH_PARAM_SEPARATOR_PATTERN.lastIndex = valueEnd;
      const separator = AUTH_PARAM_SEPARATOR_PATTERN.exec(text);
      if (separator === null || separator[0].length === 0) break;
      index = valueEnd + separator[0].length;
    }
    const lastItem = items[items.length - 1];
    return lastItem === undefined ? undefined : { end: lastItem.valueEnd, items };
  }

  function authParameterFate(name: string): AuthParameterFate {
    const lower = name.toLowerCase();
    if (PROOF_PARAM_NAMES.has(lower)) return "proof";
    return CHALLENGE_PARAM_NAMES.has(lower) ? "challenge" : "other";
  }

  function isAuthParameterAnchor(name: string): boolean {
    const lower = name.toLowerCase();
    return (AUTH_PARAM_NAMES.has(lower) || CHALLENGE_PARAM_NAMES.has(lower)) && !PROOF_PARAM_NAMES.has(lower);
  }

  function authParameterFates(text: string): Map<number, AuthParameterFate> {
    const fates = new Map<number, AuthParameterFate>();
    AUTH_PARAMETER_LIST_OPENER_PATTERN.lastIndex = 0;
    let opener: RegExpExecArray | null;
    while ((opener = AUTH_PARAMETER_LIST_OPENER_PATTERN.exec(text)) !== null) {
      const list = readAuthParameterList(text, opener.index);
      if (list === undefined) continue;
      const schemeLed = SCHEME_LED_LIST_PATTERN.test(text.slice(Math.max(0, opener.index - 32), opener.index));
      if (schemeLed || (list.items.length > 1 && list.items.some((item) => isAuthParameterAnchor(item.name)))) {
        for (const item of list.items) fates.set(item.nameStart, authParameterFate(item.name));
      }
      AUTH_PARAMETER_LIST_OPENER_PATTERN.lastIndex = list.end;
    }
    return fates;
  }

  function replaceSchemeParameterLists(text: string): string {
    SCHEME_PARAMETER_LIST_PATTERN.lastIndex = 0;
    let out = "";
    let last = 0;
    let match: RegExpExecArray | null;
    while ((match = SCHEME_PARAMETER_LIST_PATTERN.exec(text)) !== null) {
      const list = readAuthParameterList(text, match.index + match[0].length);
      if (list === undefined || !list.items.some((item) => !CHALLENGE_PARAM_NAMES.has(item.name.toLowerCase()))) continue;
      out += `${text.slice(last, match.index)}${match[1]} ${REDACTION_MARKER}`;
      last = list.end;
      SCHEME_PARAMETER_LIST_PATTERN.lastIndex = last;
    }
    return last === 0 ? text : `${out}${text.slice(last)}`;
  }

  function replaceAuthParameterProofs(text: string): string {
    const proofs = [...authParameterFates(text).entries()].filter(([, fate]) => fate === "proof").map(([nameStart]) => nameStart);
    if (proofs.length === 0) return text;
    let out = "";
    let last = 0;
    for (const nameStart of proofs) {
      const list = readAuthParameterList(text, nameStart);
      const item = list?.items[0];
      if (item === undefined || item.nameStart !== nameStart) continue;
      const quote = item.quote ?? "";
      const closed = quote !== "" && item.valueEnd - quote.length > item.valueStart && text.startsWith(quote, item.valueEnd - quote.length);
      const value = text.slice(item.valueStart + quote.length, closed ? item.valueEnd - quote.length : item.valueEnd);
      if (value.length === 0 || value === REDACTION_MARKER) continue;
      out += `${text.slice(last, item.valueStart)}${quote}${REDACTION_MARKER}${closed ? quote : ""}`;
      last = item.valueEnd;
    }
    return last === 0 ? text : `${out}${text.slice(last)}`;
  }

  type QuotedValueRule = (key: string, value: string, redacted: () => string, webhook: (url: string) => string, match: string) => string;

  function replaceQuotedAttributes(text: string, quotedValue: QuotedValueRule): string {
    const fates = authParameterFates(text);
    return text.replace(QUOTED_ATTRIBUTE_PATTERN, (match, key: string, quote: string, value: string, offset: number) =>
      (fates.get(offset) === "challenge" ? match : quotedValue(keyAfterEscape(text, offset, key), value, () => `${key}=${quote}${REDACTION_MARKER}${quote}`, (url) => `${key}=${quote}${url}${quote}`, match)));
  }

  function scrubCarriers(text: string, pemScope: PemScope): string {
    const quotedValue = (key: string, value: string, redacted: () => string, webhook: (url: string) => string, match: string): string => {
      if (isWebhookUrlKey(key) && URL_VALUE_PATTERN.test(value)) return webhook(redactedWebhookUrl(value));
      return isCredentialKey(key) && !isCountValue(key, value) && !keepsSchemeWord(key, value) ? redacted() : match;
    };
    const carriers = scrubHeaderLines(scrubPem(text, pemScope))
      .replace(TOKEN_IN_PATH_WEBHOOK_PATTERN, `$1${REDACTION_MARKER}`)
      .replace(EMBEDDED_URL_PATTERN, scrubUrlUserinfo)
      .replace(SLASH_ESCAPED_URL_USERINFO_PATTERN, `$1${REDACTION_MARKER}@`)
      .replace(QUERY_PAIR_PATTERN, (match, separator: string, key: string, value: string) => (isCredentialAssignmentKey(key) || isTokenShapedValue(value) ? `${separator}${key}=${REDACTION_MARKER}` : match));
    const pairs = replaceAuthParameterProofs(replaceSchemeParameterLists(carriers))
      .replace(SCHEME_VALUE_PATTERN, (match, scheme: string, value: string) => (isSchemeProse(scheme, value) ? match : `${scheme} ${REDACTION_MARKER}`))
      .replace(JSON_QUOTED_PAIR_PATTERN, (match, key: string, separator: string, value: string) => quotedValue(key, value, () => `"${key}"${separator}"${REDACTION_MARKER}"`, (url) => `"${key}"${separator}"${url}"`, match))
      .replace(JSON_ESCAPED_PAIR_PATTERN, (match, run: string, key: string, separator: string, value: string) => quotedValue(key, value, () => `${run}"${key}${run}"${separator}${run}"${REDACTION_MARKER}${run}"`, (url) => `${run}"${key}${run}"${separator}${run}"${url}${run}"`, match));
    const scrubbed = replaceQuotedAttributes(pairs, quotedValue);
    return replaceCredentialAssignments(replaceFlagValues(scrubbed))
      .replace(JWT_PATTERN, REDACTION_MARKER)
      .replace(PANOS_API_KEY_PATTERN, REDACTION_MARKER)
      .replace(AWS_ACCESS_KEY_ID_PATTERN, REDACTION_MARKER)
      .replace(GITHUB_TOKEN_PATTERN, REDACTION_MARKER)
      .replace(STRIPE_KEY_PATTERN, REDACTION_MARKER)
      .replace(SLACK_TOKEN_PATTERN, REDACTION_MARKER);
  }

  function redactErrorText(text: string): string {
    return scrubCarriers(text, "all").replace(LONG_TOKEN_RUN_PATTERN, (run) => (looksLikeToken(run) ? REDACTION_MARKER : run));
  }

  function redactConfiguredSecrets(text: string, secrets: ReadonlyArray<string | undefined>): string {
    const values = secrets.filter((value): value is string => typeof value === "string" && value.length >= MIN_CONFIGURED_SECRET_LENGTH);
    if (values.length === 0) return text;
    return scrubSensitiveValues(text, values).split(REDACTED_VALUE).join(REDACTION_MARKER);
  }
  return { MIN_CONFIGURED_SECRET_LENGTH, LONG_TOKEN_MIN_LENGTH, URL_VALUE_PATTERN, SESSION_ID_PATTERN, isCredentialKey, isWebhookUrlKey, redactedWebhookUrl, scrubCarriers, redactErrorText, redactConfiguredSecrets };
}
