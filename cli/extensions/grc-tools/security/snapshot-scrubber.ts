/** Credential text and snapshot policy shared by the cloud/Ansible/Duo integrations.
 * Each factory invocation owns its configured-secret registry. */
export function createSnapshotCredentialScrubber() {
  const REDACTED_ERROR_VALUE = "[REDACTED]";
  const CONFIGURED_SECRETS = new Set<string>();
  const MIN_CONFIGURED_SECRET_LENGTH = 4;

  /**
   * The forms a configured secret can take inside an error string: plain, JSON-escaped, URL-encoded, base64,
   * and base64url (rule 9 scrub boundary: a configured secret is removed whatever its shape, in every form).
   */
  function configuredSecretForms(value: string): string[] {
    const forms = new Set<string>([
      value,
      JSON.stringify(value).slice(1, -1),
      encodeURIComponent(value),
      Buffer.from(value, "utf8").toString("base64"),
      Buffer.from(value, "utf8").toString("base64url"),
    ]);
    return [...forms].filter((form) => form.length >= MIN_CONFIGURED_SECRET_LENGTH);
  }

  /** Secrets the running client was configured with or obtained; every recorded error string is scrubbed of them in every form. */
  function registerConfiguredSecrets(...values: Array<string | undefined>): void {
    for (const value of values) {
      if (!value || value.length < MIN_CONFIGURED_SECRET_LENGTH) continue;
      for (const form of configuredSecretForms(value)) CONFIGURED_SECRETS.add(form);
    }
  }

  function escapeErrorRegExp(text: string): string {
    return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  /** Replaces every configured secret form wherever it appears; a form under eight characters only where it stands as a whole token. */
  function scrubConfiguredSecrets(text: string): string {
    let scrubbed = text;
    for (const secret of [...CONFIGURED_SECRETS].sort((left, right) => right.length - left.length)) {
      scrubbed = secret.length >= 8
        ? scrubbed.split(secret).join(REDACTED_ERROR_VALUE)
        : scrubbed.replace(new RegExp(`(?<![A-Za-z0-9])${escapeErrorRegExp(secret)}(?![A-Za-z0-9])`, "g"), REDACTED_ERROR_VALUE);
    }
    return scrubbed;
  }

  // The words that name a credential. A key ends in one of them; isCredentialNamedKey below decides how the word may
  // be attached to the rest of the key. `skey` and `ikey` are Duo's secret key and integration key (DUO_SKEY, DUO_IKEY),
  // both configured secrets of that integration; there is no bare `key`, so KmsKeyId, ssh_key_name, and the like stay
  // identifiers. The compound words (`session_token`, `client_secret`, `secret_access_key`, `secret_key`,
  // `connection_string`, `ssh_key_data`) are the members an SDK response or a credential store carries, so they count
  // in their PascalCase form too (`SessionToken`, `ClientSecret`, `SecretAccessKey`, `SecretKey`), where a PascalCase
  // error code that merely ends in `Token` (`ExpiredToken`) does not; see isCredentialNamedKey. The bearer ids are the
  // one override to the identifier suffix: a key ending in
  // `secret_id` (a Vault AppRole secret id) or `token_id` (a token id is the token), or in a session id (`session_id`,
  // `sid`, `sessid`, `jsessionid`, `PHPSESSID`), authenticates rather than identifies, so it is a credential key
  // despite ending in `id` and its value goes whatever its shape, UUID included, while `client_id`, `tenant_id`,
  // `access_key_id`, `key_id`, and `secret_name` keep theirs unless the value's own shape goes. A URL-valued webhook
  // key (`webhook`, `webhook_url`) carries its token in the path, so the whole value goes; `webhook_count` is a count.
  const ERROR_CREDENTIAL_WORDS =
    "token|secret[_.-]?id|token[_.-]?id|session[_.-]?token|access[_.-]?token|refresh[_.-]?token|id[_.-]?token|client[_.-]?secret|api[_.-]?secret|secret[_.-]?access[_.-]?key|secret[_.-]?key|secret|passw(?:or)?d|pwd|passphrase|api[_.-]?key|apikey|auth[_.-]?key|auth[_.-]?email|session(?:[_.-]?id)?|sessid|sid|cookie|csrftoken|authorization|auth|signature|sig|nonce|credentials?|access[_.-]?key|private[_.-]?key|ssh[_.-]?key[_.-]?data|skey|ikey|assertion|connection[_.-]?string|webhook(?:[_.-]?url)?";
  const ERROR_CREDENTIAL_KEY_PATTERN = `[A-Za-z0-9_.-]*(?:${ERROR_CREDENTIAL_WORDS})`;

  /**
   * Where a key may start: after a character that cannot be part of a key, or after a JSON escape (`\n`, `\t`,
   * `\u000a`) inside a serialized message, where the character before the key is the escape's last letter and
   * `\b` sees no boundary. Never right after a backslash, so the escape letter is not
   * read as the first letter of the key (`\nExpiredToken:` is the error code, not a key `nExpiredToken`).
   */
  const KEY_BOUNDARY_PATTERN = String.raw`(?:(?<![A-Za-z0-9_.\\-])|(?<=\\[nrtbfv])|(?<=\\u[0-9A-Fa-f]{4}))`;
  /** Where a header name or a scheme word may start: the same boundaries, allowing a `.` or `-` before the name. */
  const NAME_BOUNDARY_PATTERN = String.raw`(?:(?<![A-Za-z0-9_])|(?<=\\[nrtbfv])|(?<=\\u[0-9A-Fa-f]{4}))`;

  /**
   * The authorization scheme words, matched in any casing: the HTTP schemes, Okta's
   * SSWS, the Splunk and Snowflake header schemes, and SigV4. Under a credential-named key only an Authorization
   * header treats the word as a scheme in front of the value; under any other key the word is the value.
   */
  const ERROR_SCHEME_WORDS = "Bearer|Basic|Digest|Negotiate|NTLM|OAuth|SSWS|Token|ApiKey|Api-Key|Splunk|Snowflake|AWS4-HMAC-SHA256";
  const ERROR_SCHEME_PATTERN = `(?:${ERROR_SCHEME_WORDS})`;
  /**
   * key=value and key: value pairs whose key ends in a credential word, wherever the key stands: after a flag
   * prefix `--`, `-D`, a path segment `kv/`, a parenthesis, or a comma. The value runs to
   * whitespace, a quote, `&`, `;`, `,`, a closing bracket, an angle bracket, or a backslash (the compound-line
   * rule), so a pair inside a query string, a header list, a JSON fragment, or a parenthesis keeps the text after
   * it; a marker inside the value (a URL whose query was already removed) is part of it. A value that is already
   * the marker is not a value, so a second pass over a scrubbed message changes nothing; scrubCredentialPairs
   * decides whether the key names a credential.
   */
  const ERROR_CREDENTIAL_PAIR_PATTERN = new RegExp(
    `${KEY_BOUNDARY_PATTERN}(${ERROR_CREDENTIAL_KEY_PATTERN})((?:\\\\*["'])?\\s*[=:]\\s*["']?)((?:${ERROR_SCHEME_PATTERN}\\s+)?(?!\\[REDACTED\\])(?:\\[REDACTED\\]|[^\\s"'&;,<>)\\]}\\\\])+)`,
    "gi",
  );
  /** `--name value` in a CLI's stderr: the next token is the value. */
  const FLAG_CARRIER_PATTERN = new RegExp(`(?<![A-Za-z0-9_.-])--(${ERROR_CREDENTIAL_KEY_PATTERN})(\\s+)(?![-\\[])([^\\s"'&;,<>)\\]}\\\\]+)`, "gi");
  const TRAILING_PUNCTUATION_PATTERN = /[.!?:)]+$/;

  /**
   * A quoted value: the opening quote with the backslashes that escape it at its serialization depth (none when the
   * message is plain, one when it was serialized once, three when twice), the value up to the close quote at the
   * same depth (an escaped quote inside the value, `\"` inside `"..."`, is part of the value, as is a deeper
   * quote), and that close quote. Both patterns below place it after two capturing groups, so the backslashes are
   * group 4, the quote character group 5, the value group 6, and the close quote group 7.
   */
  const ERROR_QUOTED_VALUE_PATTERN = String.raw`(?<!\\)((\\*)(["']))((?:(?!(?<!\\)\4\5)[^\n])+)((?<!\\)\4\5)`;
  /**
   * A quoted credential value: `X-Api-Key: "value"`, `Cookie: sid='value'`, `Authorization: Bearer "value"`,
   * `\"X-Auth-Key\":\"value\"`: with or without spaces, single or double quotes, plain or JSON-escaped. The quotes
   * delimit the carrier, so the quoted value is removed whole whatever its shape; the pair rule above stops at the
   * opening quote and would judge a short or name-shaped value ("key", "prod-key") as prose. The header name, the
   * separator, the scheme, and the quotes stay so the message remains diagnosable.
   */
  const ERROR_QUOTED_CREDENTIAL_PATTERN = new RegExp(
    String.raw`${KEY_BOUNDARY_PATTERN}(${ERROR_CREDENTIAL_KEY_PATTERN})((?:\\*["'])?\s*[=:]\s*(?:${ERROR_SCHEME_PATTERN}\s*)?)${ERROR_QUOTED_VALUE_PATTERN}`,
    "gi",
  );
  // A scheme word that is itself quoted (`"Token":"..."`, a JSON key) or ends a compound key (`"x-api-key":`,
  // `"settings.token":`) is a pair the rule above already handled.
  const ERROR_QUOTED_SCHEME_PATTERN = new RegExp(String.raw`(?<!["'\\./-])\b(${ERROR_SCHEME_PATTERN})(\s*)${ERROR_QUOTED_VALUE_PATTERN}`, "gi");
  const QUOTED_VALUE_REPLACEMENT = `$1$2$3${REDACTED_ERROR_VALUE}$7`;
  /**
   * A quoted phrase that is a scheme word and one value (`"Bearer prod-token"`, `\"Token prod-key\"`, `'Basic abc'`):
   * the quotes delimit a header value, so the quoted name-shaped bearer goes whatever its shape, where the same
   * phrase bare in prose (`sent as Bearer prod-token`) is
   * judged by the scheme rule's shape test. A quoted phrase of several words after the scheme is prose and stays.
   */
  const ERROR_QUOTED_SCHEME_PHRASE_PATTERN = new RegExp(
    String.raw`(?<!\\)((\\*)(["']))(${ERROR_SCHEME_PATTERN})(\s+)((?:(?!(?<!\\)\2\3)[^\s"'\\])+)((?<!\\)\2\3)`,
    "gi",
  );
  const QUOTED_SCHEME_PHRASE_REPLACEMENT = `$1$4$5${REDACTED_ERROR_VALUE}$7`;

  const CREDENTIAL_KEY_WORD_PATTERN = new RegExp(`(?:${ERROR_CREDENTIAL_WORDS})$`, "i");
  // Credential words that end too many ordinary words to count when glued to a lowercase prefix (`oauth`, `ssid`).
  const WEAK_CREDENTIAL_WORD_PATTERN = /^(?:auth|sid|sig)$/i;
  const PAIR_VALUE_SCHEME_PATTERN = new RegExp(`^${ERROR_SCHEME_PATTERN}\\s+`, "i");
  const BARE_SCHEME_WORD_PATTERN = new RegExp(`^${ERROR_SCHEME_PATTERN}$`, "i");
  /** The keys whose value is `<scheme> <credential>`: Authorization and Proxy-Authorization. */
  const AUTHORIZATION_KEY_PATTERN = /authorization$/i;
  const SCHEME_PARAMETER_PATTERN = /^([A-Za-z][A-Za-z0-9_-]*)=(?!=)/;

  /**
   * Whether the value after a scheme word is a `name=value` parameter list (SigV4 `Credential=...`, `realm="api"`,
   * `OAuth oauth_consumer_key=...`) rather than one bearer credential: the name is shaped like a name segment by
   * segment (`oauth_consumer_key`, `x-amz-date`), and the `=` is followed by more text, or by the quote that opens
   * the parameter's value where the caller's value stopped (`uri="/dir"`, `Session="v"`: `quoteFollows`), or the
   * whole is not base64-length (`realm=` is a parameter; `cGFzc3dvcmQ=` is padding).
   */
  function isSchemeParameterList(value: string, quoteFollows = false): boolean {
    const parameter = SCHEME_PARAMETER_PATTERN.exec(value);
    if (parameter === null || !isParameterName(parameter[1])) return false;
    return parameter[0].length < value.length || quoteFollows || value.length % 4 !== 0;
  }

  /** A parameter name: `-` or `_` separated segments that are each shaped like part of a name (see isNameSegment). */
  function isParameterName(name: string): boolean {
    return name.split(/[-_]/).every((segment) => isNameSegment(segment));
  }

  /** Whether a quote, plain or behind the backslashes of its JSON escape, stands at `index` in `text`. */
  function quoteOpensAt(text: string, index: number): boolean {
    let cursor = index;
    while (text[cursor] === "\\") cursor += 1;
    return text[cursor] === '"' || text[cursor] === "'";
  }

  /**
   * Whether a key names a credential. It does when it is a credential word
   * (`password`, `Token`, `skey`, `SessionToken`), sets one off with `_`, `-`, or `.` (`DB_PASSWORD`,
   * `AZURE_CLIENT_SECRET`, `x-api-key`, `Proxy-Authorization`), or is a lowerCamelCase, lowercase, or uppercase
   * compound ending in one (`accessToken`, `clientSecret`, `dbpassword`, `ACCESSTOKEN`). A PascalCase identifier
   * that merely ends in the word (`InvalidAuthenticationToken`, `ExpiredToken`) is an error code or a type name,
   * and the text after its colon is prose. A key that names an identifier (`AWS_ACCESS_KEY_ID`, `AZURE_TENANT_ID`,
   * `CLOUDFLARE_EMAIL`) never ends in a credential word, so its value is judged by its own shape alone; the bearer
   * ids (`secret_id`, `token_id`, and the session ids, see ERROR_CREDENTIAL_WORDS) are credential words, so that
   * suffix test never reaches them.
   */
  function isCredentialNamedKey(key: string): boolean {
    const word = CREDENTIAL_KEY_WORD_PATTERN.exec(key)?.[0];
    if (word === undefined) return false;
    const prefix = key.slice(0, key.length - word.length);
    if (prefix.length === 0 || /[_.-]$/.test(prefix)) return true;
    if (/^[A-Z]/.test(prefix) && /[a-z]/.test(prefix)) return false;
    return !WEAK_CREDENTIAL_WORD_PATTERN.test(word);
  }

  /**
   * The value of a pair whose key names a credential is the credential and is removed whatever its shape and
   * length: `password=letmein`, `DB_PASSWORD=Sunshine`, `AZURE_CLIENT_SECRET: abc12`,
   * and `DUO_SKEY=p@ss` go the way `{"password":"letmein"}` already did. The key, the separator, and the sentence
   * punctuation after the value stay. Under an Authorization header a scheme word in front of the value stays
   * too, a scheme word standing alone ("sent as Authorization: Bearer") names the scheme and carries nothing, and
   * a parameter list after the scheme (SigV4 `Credential=..., SignedHeaders=..., Signature=...`) is judged pair by
   * pair so the region and the request scope stay (scrubAuthorizationParameters has already removed every
   * parameter value that is a proof, so this pass sees markers and the kept parameters). Under any other
   * credential key the scheme word is the value (`sslPassword=splunk rejected`,
   * `db_password: token`), and the prose after it stays. A `--name value` flag is a pair whose separator is the space.
   */
  function scrubCredentialPairs(text: string): string {
    const scrubbed = text.replace(ERROR_CREDENTIAL_PAIR_PATTERN, (match: string, key: string, separator: string, value: string, offset: number) => {
      if (!isCredentialNamedKey(key)) return match;
      const scheme = PAIR_VALUE_SCHEME_PATTERN.exec(value)?.[0] ?? "";
      const authorization = AUTHORIZATION_KEY_PATTERN.test(key);
      if (scheme.length > 0 && !authorization) {
        const word = scheme.trimEnd();
        return `${key}${separator}${REDACTED_ERROR_VALUE}${value.slice(word.length)}`;
      }
      const core = value.slice(scheme.length).replace(TRAILING_PUNCTUATION_PATTERN, "");
      if (core.length === 0) return match;
      const tail = value.slice(scheme.length + core.length);
      if (authorization) {
        if (BARE_SCHEME_WORD_PATTERN.test(core)) return match;
        if (isSchemeParameterList(core, quoteOpensAt(text, offset + match.length - tail.length))) {
          return `${key}${separator}${scheme}${scrubCredentialPairs(core)}${tail}`;
        }
      }
      return `${key}${separator}${scheme}${REDACTED_ERROR_VALUE}${tail}`;
    });
    return scrubbed.replace(FLAG_CARRIER_PATTERN, (match: string, key: string, space: string) =>
      isCredentialNamedKey(key) ? `--${key}${space}${REDACTED_ERROR_VALUE}` : match,
    );
  }

  /**
   * Header carriers whose value is free form: Cookie and Set-Cookie (session values with their attributes) and
   * Cloudflare's legacy X-Auth-Key / X-Auth-Email pair (the global API key and its account). The
   * value is removed whatever its shape. Where it ends follows the compound-line rule shared by every scrubber:
   * a quoted value (a plain or JSON-escaped quote) ends at its closing quote, so a closed value that holds `; Name:`
   * is one value and the quotes stay around the marker; an unquoted value, or a quoted one that is never closed,
   * ends at the `;` or `,` that introduces the next `Name:` header token on the line (a name may hold dots,
   * `X.Api.Key:`), at a `<` or `>` (the header quoted inside markup), at a `"` that closes the JSON string and
   * container that carried the line (`"}`, `"]`), at a JSON-escaped line break (`\n`, `\r`, `\u000a`, `\u000d` as
   * backslash text, the end of the line inside a serialized message), or at the end of the line, so the next
   * header keeps its name and gets its own carrier treatment. A value that is already the marker is left alone,
   * so a second pass over a scrubbed message leaves the text after the marker as it is.
   *
   * The header name counts as a carrier at a line start, after any character that is not part of a name, and
   * after a JSON escape: inside a serialized message the character before `Cookie`
   * is the escape's last letter (`\nCookie`, `\u000aCookie`), a word character to `\b`, and a boundary that
   * relied on `\b` left the free-form removal to the pair rule, which stops at the first `;` and judges every
   * later cookie pair on its own name and shape. After `--`, `.`, or `/` (plain or JSON-escaped) the name is a
   * flag, a property, or a path segment (`--x-auth-key=value -h db`, `-Dspring.datasource.x-auth-key=value`,
   * `kv/x-auth-key=value see log`), a pair whose value ends at the next space, so the pair rule takes it and the
   * text after the value stays.
   */
  const HEADER_CARRIER_PATTERN = new RegExp(`(?:(?<![A-Za-z0-9_./-])|(?<=\\\\[nrtbfv])|(?<=\\\\u[0-9A-Fa-f]{4}))(set-cookie|cookie|x-auth-key|x-auth-email)(\\s*[:=]\\s*)(?!\\s*\\[REDACTED\\])`, "gi");
  const HEADER_CARRIER_QUOTE_PATTERN = /^(\\*)(["'])/;
  const NEXT_HEADER_TOKEN_PATTERN = /[;,]\s*[A-Za-z][A-Za-z0-9.-]*\s*:/;
  const MARKUP_OR_JSON_CLOSE_PATTERN = /[<>]|"(?=\s*[}\]])/;
  const ESCAPED_LINE_BREAK_PATTERN = /\\(?:[nr]|u000[aAdD])/;

  /** The first occurrence of `quote` in `line` at or after `from` that is not escaped by a backslash before it, or -1. */
  function closingQuoteIndex(line: string, quote: string, from: number): number {
    for (let index = line.indexOf(quote, from); index !== -1; index = line.indexOf(quote, index + 1)) {
      if (index === 0 || line[index - 1] !== "\\") return index;
    }
    return -1;
  }

  /** The end of a free-form header value that starts at `start`, and the quote (plain or escaped) that encloses a closed quoted value. */
  function headerCarrierValueEnd(text: string, start: number): { end: number; quote?: string } {
    const newline = text.indexOf("\n", start);
    const line = text.slice(start, newline === -1 ? text.length : newline);
    const opening = HEADER_CARRIER_QUOTE_PATTERN.exec(line);
    if (opening) {
      const close = closingQuoteIndex(line, opening[0], opening[0].length);
      if (close !== -1) return { end: start + close + opening[0].length, quote: opening[0] };
    }
    // An unterminated quote is part of the value; the stops are searched after it.
    const skip = opening ? opening[0].length : 0;
    const rest = line.slice(skip);
    const stops = [MARKUP_OR_JSON_CLOSE_PATTERN.exec(rest)?.index, NEXT_HEADER_TOKEN_PATTERN.exec(rest)?.index, ESCAPED_LINE_BREAK_PATTERN.exec(rest)?.index].filter(
      (index): index is number => index !== undefined,
    );
    return { end: start + skip + (stops.length > 0 ? Math.min(...stops) : rest.length) };
  }

  function scrubHeaderCarriers(text: string): string {
    let scrubbed = "";
    let cursor = 0;
    for (const match of text.matchAll(HEADER_CARRIER_PATTERN)) {
      // A carrier name inside a value already consumed (`Cookie: "a; X-Auth-Key: b"`) is part of that value.
      if (match.index < cursor) continue;
      const valueStart = match.index + match[0].length;
      const { end, quote } = headerCarrierValueEnd(text, valueStart);
      if (end === valueStart) continue;
      scrubbed += text.slice(cursor, valueStart) + (quote === undefined ? REDACTED_ERROR_VALUE : `${quote}${REDACTED_ERROR_VALUE}${quote}`);
      cursor = end;
    }
    return scrubbed + text.slice(cursor);
  }

  /**
   * An Authorization or Proxy-Authorization header (any prefix the key rule accepts, any casing, plain or after a
   * JSON escape) whose value is a scheme word and a parameter list:
   * `Authorization: Snowflake Token="..."`, `Authorization: Digest username="...", realm="...", nonce="...",
   * uri="...", response="..."`, `Authorization: OAuth oauth_token="..."`, any `<Scheme> <name>="..."` shape. The
   * match ends after the space that follows the scheme word, where the first parameter's name starts, and
   * scrubSchemeParameterList walks the list. A header value quoted whole (`Authorization: "Digest ..."`, a JSON
   * header object) is not this shape: the quoted-value rule below removes it whole.
   */
  const AUTHORIZATION_PARAMETERS_PATTERN = new RegExp(
    String.raw`${KEY_BOUNDARY_PATTERN}([A-Za-z0-9_.-]*authorization)((?:\\*["'])?\s*[=:]\s*)(${ERROR_SCHEME_PATTERN})(\s+)(?=[A-Za-z])`,
    "gi",
  );
  /**
   * The parameters whose value describes the exchange rather than proves it, so they stay: Digest's `realm`,
   * `username`, `uri`, `qop`, `nc`, `algorithm`, `charset`, and `userhash` (RFC 7616), OAuth 1.0's consumer key (a
   * client identifier), signature method, timestamp, version, and callback (RFC 5849), and SigV4's `Credential`
   * (the access key id in front of the request scope, judged by the vendor prefix rule and the pair rule as before)
   * and `SignedHeaders`. Every other parameter is the proof or an opaque blob (`response`, `nonce`, `cnonce`,
   * `opaque`, `oauth_token`, `oauth_signature`, `oauth_nonce`, `Token`, `Session`, `value`) and its value becomes
   * the marker, quoted at any serialization depth or bare.
   */
  const KEPT_SCHEME_PARAMETER_PATTERN =
    /^(?:realm|username|uri|qop|nc|algorithm|charset|userhash|oauth_consumer_key|oauth_signature_method|oauth_timestamp|oauth_version|oauth_callback|credential|signedheaders)$/i;
  /**
   * The parameters whose name says the value is a proof wherever the list stands: Digest's `response`, a
   * `signature` or `sig`, OAuth 1.0's `oauth_signature`, and the MAC
   * scheme's `mac`. In a challenge (see CHALLENGE_PARAMETERS_PATTERN) only these go; under an Authorization header
   * every parameter that is not kept goes, so this list never widens what that header gives up.
   */
  const PROOF_SCHEME_PARAMETER_PATTERN = /^(?:response|signature|oauth_signature|mac|sig)$/i;
  const REALM_PARAMETER_PATTERN = /^realm$/i;
  /** Which values a parameter list gives up: every proof under an Authorization header, only the proof-named parameters in a challenge. */
  type SchemeParameterListKind = "authorization" | "challenge";
  const SCHEME_PARAMETER_NAME_PATTERN = /([A-Za-z][A-Za-z0-9_-]*)=(?!=)/y;
  const SCHEME_PARAMETER_BARE_VALUE_PATTERN = /(?:\[REDACTED\]|[^\s"'&;,<>)\]}\\])+/y;
  const SCHEME_PARAMETER_SEPARATOR_PATTERN = /\s*,\s*/y;

  /**
   * Where the parameter value that starts at `start` ends, and the quote (plain or JSON-escaped) that encloses a
   * quoted value: a quoted value runs to its closing quote at the same depth on the same line (an escaped quote
   * inside it is part of it), a bare value ends where the pair rule's value ends. An unterminated quote or an
   * empty bare value is not a parameter value, so the list ends before it.
   */
  function schemeParameterValueEnd(text: string, start: number): { end: number; quote?: string } | undefined {
    const newline = text.indexOf("\n", start);
    const line = text.slice(start, newline === -1 ? text.length : newline);
    const opening = HEADER_CARRIER_QUOTE_PATTERN.exec(line);
    if (opening) {
      const close = closingQuoteIndex(line, opening[0], opening[0].length);
      return close === -1 ? undefined : { end: start + close + opening[0].length, quote: opening[0] };
    }
    SCHEME_PARAMETER_BARE_VALUE_PATTERN.lastIndex = start;
    const bare = SCHEME_PARAMETER_BARE_VALUE_PATTERN.exec(text);
    return bare === null ? undefined : { end: start + bare[0].length };
  }

  /**
   * Walks the `name=value` parameter list that starts at `start`, the parameters separated by commas (RFC 7235),
   * each name shaped like a name (a base64 value with its padding, `cGFzc3dvcmQ=`, is no parameter). Under an
   * Authorization header a kept parameter passes whole and every other value becomes the marker; in a challenge
   * only a proof-named value does. The marker stands inside the value's own quotes, an empty value stays empty,
   * and a value that is already the marker is left as it is, so a second pass changes nothing. The list ends
   * before the first text that is not a parameter (prose, a `)`, the close of the JSON string that carried the
   * line, the `;` inside SigV4's `SignedHeaders=host;x-amz-date`), which the caller keeps; a separator with no
   * parameter after it is not consumed. Returns the end of the list, its scrubbed text, and whether a `realm`
   * parameter was among the parameters walked.
   */
  function scrubSchemeParameterList(text: string, start: number, kind: SchemeParameterListKind): { end: number; replacement: string; realm: boolean } {
    let end = start;
    let replacement = "";
    let pending = "";
    let cursor = start;
    let realm = false;
    for (;;) {
      SCHEME_PARAMETER_NAME_PATTERN.lastIndex = cursor;
      const name = SCHEME_PARAMETER_NAME_PATTERN.exec(text);
      if (name === null || !isParameterName(name[1])) break;
      const valueStart = cursor + name[0].length;
      const value = schemeParameterValueEnd(text, valueStart);
      if (value === undefined) break;
      const quote = value.quote ?? "";
      const content = text.slice(valueStart + quote.length, value.end - quote.length);
      const kept =
        content.length === 0 || (kind === "authorization" ? KEPT_SCHEME_PARAMETER_PATTERN.test(name[1]) : !PROOF_SCHEME_PARAMETER_PATTERN.test(name[1]));
      if (REALM_PARAMETER_PATTERN.test(name[1])) realm = true;
      replacement += `${pending}${name[0]}${quote}${kept ? content : REDACTED_ERROR_VALUE}${quote}`;
      end = cursor = value.end;
      SCHEME_PARAMETER_SEPARATOR_PATTERN.lastIndex = cursor;
      const separator = SCHEME_PARAMETER_SEPARATOR_PATTERN.exec(text);
      if (separator === null) break;
      pending = separator[0];
      cursor += separator[0].length;
    }
    return { end, replacement, realm };
  }

  /**
   * Removes the proofs from every Authorization parameter list in the text (see AUTHORIZATION_PARAMETERS_PATTERN),
   * the header name, the scheme word, the parameter names, the kept parameters, their quotes, and the text after
   * the list staying. Runs before the quoted-value and scheme rules, which then see the marker where a proof
   * stood; a header name inside a list already walked (`Authorization: Digest opaque="Authorization: ..."`) is part
   * of that value.
   */
  function scrubAuthorizationParameters(text: string): string {
    let scrubbed = "";
    let cursor = 0;
    for (const match of text.matchAll(AUTHORIZATION_PARAMETERS_PATTERN)) {
      if (match.index < cursor || !isCredentialNamedKey(match[1])) continue;
      const listStart = match.index + match[0].length;
      const { end, replacement } = scrubSchemeParameterList(text, listStart, "authorization");
      if (end === listStart) continue;
      scrubbed += text.slice(cursor, listStart) + replacement;
      cursor = end;
    }
    return scrubbed + text.slice(cursor);
  }

  /**
   * Where a parameter list that is not under an Authorization key may start: after a scheme word and its
   * whitespace when a parameter follows (a WWW-Authenticate or
   * Proxy-Authenticate challenge, `Digest realm="api", nonce="n", response="..."` in prose or in a JSON string, any
   * casing), or at a `realm` parameter or a proof-named parameter standing on its own (`realm="api", nonce="n",
   * response="..."` as a data value, `response="...", realm="api"`). A list shaped like a challenge is not exempt
   * from the proof rule because the challenge names it: scrubChallengeParameters removes the proof-named values and
   * keeps the rest, where a list under an Authorization key has already given up every proof.
   */
  const CHALLENGE_PARAMETERS_PATTERN = new RegExp(
    String.raw`(${NAME_BOUNDARY_PATTERN}(?:${ERROR_SCHEME_PATTERN})\s+)(?=[A-Za-z][A-Za-z0-9_-]*=(?!=))|${KEY_BOUNDARY_PATTERN}(?=(?:realm|response|signature|oauth_signature|mac|sig)=(?!=))`,
    "gi",
  );

  /**
   * Removes the proof-named values (see PROOF_SCHEME_PARAMETER_PATTERN) from every challenge-shaped parameter list in
   * the text: the list after a scheme word, whatever its parameters, and a bare list that holds a `realm` parameter,
   * before or after the proof. The scheme word, the parameter names, the other parameters (`realm`, `qop`,
   * `algorithm`, `opaque`, `error`, `error_description`), their quotes, and the text after the list stay, so
   * `WWW-Authenticate: Bearer realm="api"` and `Digest realm="api", qop="auth"` pass unchanged. A bare list with no
   * `realm` and no scheme word is data (`response="ok", status="done"`, `mac=aa:bb:cc:dd:ee:ff response=200`), as is
   * a `response` or `mac` field outside a parameter list (`"response": 403`). A list under an Authorization key has
   * already been walked by scrubAuthorizationParameters and holds markers where its proofs stood, which this pass
   * leaves as they are; a parameter name inside a value already walked is part of that value.
   */
  function scrubChallengeParameters(text: string): string {
    let scrubbed = "";
    let cursor = 0;
    for (const match of text.matchAll(CHALLENGE_PARAMETERS_PATTERN)) {
      if (match.index < cursor) continue;
      const scheme: string | undefined = match[1];
      const listStart = match.index + match[0].length;
      const { end, replacement, realm } = scrubSchemeParameterList(text, listStart, "challenge");
      if (end === listStart || (scheme === undefined && !realm)) continue;
      scrubbed += text.slice(cursor, listStart) + replacement;
      cursor = end;
    }
    return scrubbed + text.slice(cursor);
  }

  /**
   * Whether the token after a bare scheme word in prose is a credential: long, or carrying a digit or a base64
   * symbol (padding included), or changing case inside the word, so prose such as "Basic authentication" and
   * "Bearer token is missing" stays. A `name=value` parameter list after the scheme (`Bearer realm="api"`, SigV4
   * `Credential=...`, `OAuth oauth_consumer_key=...`), its first value quoted (`quoteFollows`) or bare, is judged
   * parameter by parameter by scrubAuthorizationParameters, scrubChallengeParameters, and the pair rule, not as one
   * bearer value.
   */
  function looksLikeSchemeCredential(value: string, quoteFollows = false): boolean {
    if (isSchemeParameterList(value, quoteFollows)) return false;
    return value.length >= 16 || /[\d+/=]/.test(value) || /[a-z][A-Z]/.test(value);
  }

  type QuotedCredentialReplacement = (
    match: string,
    key: string,
    separator: string,
    opening: string,
    backslashes: string,
    quote: string,
    content: string,
    closing: string,
  ) => string;
  type SchemeCredentialReplacement = (match: string, scheme: string, value: string, offset: number, text: string) => string;
  type TextRule = readonly [RegExp, string | QuotedCredentialReplacement | SchemeCredentialReplacement];

  function applyTextRule(text: string, [pattern, replacement]: TextRule): string {
    return typeof replacement === "string" ? text.replace(pattern, replacement) : text.replace(pattern, replacement);
  }

  /**
   * Carrier rules: a value is removed because of what carries it (a quoted header or pair value, an authorization
   * scheme, a vendor token prefix, a JWT or PEM shape), not because of its own shape. The free-form header carriers
   * (Cookie, Set-Cookie, X-Auth-Key, X-Auth-Email) run first in scrubHeaderCarriers, the Authorization parameter
   * lists in scrubAuthorizationParameters, and the challenge proofs in scrubChallengeParameters, so these only ever
   * see the marker.
   */
  const CARRIER_TEXT_PATTERNS: ReadonlyArray<TextRule> = [
    // Quoted header and pair values first, whatever their shape, so the scheme and pair rules see the marker. Under
    // an Authorization header a scheme word that opens the quoted value stays (`Authorization: "Bearer [REDACTED]"`).
    [
      ERROR_QUOTED_CREDENTIAL_PATTERN,
      (_match: string, key: string, separator: string, opening: string, _backslashes: string, _quote: string, content: string, closing: string) => {
        const scheme = AUTHORIZATION_KEY_PATTERN.test(key) ? PAIR_VALUE_SCHEME_PATTERN.exec(content)?.[0] ?? "" : "";
        return `${key}${separator}${opening}${scheme}${REDACTED_ERROR_VALUE}${closing}`;
      },
    ],
    [ERROR_QUOTED_SCHEME_PATTERN, QUOTED_VALUE_REPLACEMENT],
    [ERROR_QUOTED_SCHEME_PHRASE_PATTERN, QUOTED_SCHEME_PHRASE_REPLACEMENT],
    // Authorization scheme values wherever they appear (headers, cookies, HTML, JSON messages), in any casing of
    // the scheme word; looksLikeSchemeCredential keeps prose and parameter lists (a first parameter whose quoted
    // value follows the match included).
    [
      new RegExp(String.raw`${NAME_BOUNDARY_PATTERN}(${ERROR_SCHEME_PATTERN})\s+([A-Za-z0-9\-._~+/=:]{6,})`, "gi"),
      (match: string, scheme: string, value: string, offset: number, text: string) =>
        looksLikeSchemeCredential(value, quoteOpensAt(text, offset + match.length)) ? `${scheme} ${REDACTED_ERROR_VALUE}` : match,
    ],
    // Vendor token prefixes name the token type: AWS access key ids (long-term `AKIA`, temporary `ASIA`) and STS
    // bearer and context-specific credentials (`ABIA`, `ACCA`), Stripe secret and restricted keys, GitHub tokens,
    // Slack tokens. The prefix is the carrier, so these go from snapshots too (AWS evidence carries its access key
    // ids masked); the AWS unique ids of resources (roles, users, groups, policies) are bare shapes below.
    [/\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g, REDACTED_ERROR_VALUE],
    [/\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}/g, REDACTED_ERROR_VALUE],
    [/\b(?:gh[oprsu]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})/g, REDACTED_ERROR_VALUE],
    [/\bxox[abeoprs]-[A-Za-z0-9-]{10,}/g, REDACTED_ERROR_VALUE],
    // JWT-shaped strings.
    [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, REDACTED_ERROR_VALUE],
    // PEM blocks, whole or cut off.
    [/-----BEGIN [A-Z0-9 ]+-----[\s\S]*?(?:-----END [A-Z0-9 ]+-----|$)/g, REDACTED_ERROR_VALUE],
  ];

  /** Bare-shape rules: a value is removed for its own shape, wherever it stands. Error text only; a snapshot keeps its identifiers. */
  const BARE_SHAPE_PATTERNS: ReadonlyArray<TextRule> = [
    // AWS unique ids of roles, users, groups, managed policies, policy versions, and public keys: opaque
    // identifiers in error text, resource names in a snapshot (an assumed-role principal is `AROA...:session`).
    [/\b(?:AROA|AIDA|AGPA|ANPA|ANVA|APKA)[A-Z0-9]{16}\b/g, REDACTED_ERROR_VALUE],
    // 40-character secret access keys, long secret-shaped blobs, and hex digests.
    [/(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])/g, REDACTED_ERROR_VALUE],
    // Long blobs must carry a digit so camelCase identifiers survive.
    [/(?<![A-Za-z0-9+_=-])(?=[A-Za-z0-9+_-]*\d)[A-Za-z0-9+_-]{40,}={0,2}(?![A-Za-z0-9+_=-])/g, REDACTED_ERROR_VALUE],
    [/\b[a-f0-9]{32,}\b/gi, REDACTED_ERROR_VALUE],
  ];

  /**
   * URL userinfo, query, and fragment anywhere in the string, not only when the string starts with a URL: any
   * scheme (`https://`, `proxy://`), plain or with its slashes JSON-escaped (`https:\/\/`),
   * after a JSON escape as after any other boundary. The scheme, host, and path stay; the userinfo goes and the
   * query and the fragment each become the marker. The userinfo ends at the first `/`, `?`, or `#` as at
   * whitespace, so an `@` inside a query or a fragment is not a userinfo boundary when the
   * authority before it is a host: `https://h?e=a@x.com&token=v` is host `h` with a query, which becomes the
   * marker whole. When that authority is not `host[:port]` (`svc:secret`, a password read up to a raw `?` or `#`
   * inside it) and an `@` follows in the run, the run up to that `@` is userinfo after all (scrubUrlMatch).
   */
  const ERROR_URL_PATTERN = new RegExp(
    String.raw`(?:(?<![A-Za-z0-9+.\\-])|(?<=\\[nrtbfv])|(?<=\\u[0-9A-Fa-f]{4}))([A-Za-z][A-Za-z0-9+.-]*:(?:\/\/|\\\/\\\/))(?:[^\s\/?#@"'<>\\]+@)?((?:[^\s?#"'<>\\]|\\\/)+)(\?(?:[^\s#"'<>\\]|\\\/)*)?(#(?:[^\s"'<>\\]|\\\/)*)?`,
    "g",
  );
  /** A URL authority that is `host[:port]`: a name or address, or a bracketed IPv6 address, with at most a numeric port. */
  const HOST_AND_PORT_PATTERN = /^(?:\[[^\]\s]*\]|[^:\[\]@\\]+)(?::\d*)?$/;
  /** The first path separator of a host-and-path run, plain or JSON-escaped. */
  const PATH_START_PATTERN = /\\?\//;

  /**
   * Renders one URL match: the userinfo is gone (the pattern never captures it) and the query and the fragment
   * are the marker. An authority that is not `host[:port]` followed by an `@` later in the run is a userinfo
   * whose password carried a raw `?` or `#`, so everything up to that `@` goes and the URL after it is rendered
   * on its own; with a valid authority the `@` belongs to the query or the fragment.
   */
  function scrubUrlMatch(_match: string, scheme: string, hostPath: string, query?: string, fragment?: string): string {
    const pathStart = hostPath.search(PATH_START_PATTERN);
    const tail = `${query ?? ""}${fragment ?? ""}`;
    const at = tail.indexOf("@");
    if (pathStart === -1 && at !== -1 && !HOST_AND_PORT_PATTERN.test(hostPath)) {
      return `${scheme}${tail.slice(at + 1)}`.replace(ERROR_URL_PATTERN, scrubUrlMatch);
    }
    return `${scheme}${hostPath}${query ? `?${REDACTED_ERROR_VALUE}` : ""}${fragment ? `#${REDACTED_ERROR_VALUE}` : ""}`;
  }

  /**
   * Rule 9 scrub boundary for bare values. A run of 16 or more token characters is removed when it is shaped
   * like a token (base64 symbols, digits scattered through its letters, or casing that breaks into one- and
   * two-letter camelCase pieces) and kept when it is shaped like a name: "-" or "_" separated segments that are
   * each letters in any casing, digits alone, or letters with one digit group (`prod-us-east-2026`,
   * `AWSLambdaBasicExecutionRole`, `sha256`), an uppercase code, or a canonical UUID. "/", ".", ":", "@", and
   * whitespace end a run, so path segments, hostnames, ARNs, and emails are judged piece by piece. Opaque
   * identifiers whose shape is a token's are removed from error text as well; they travel in structured fields.
   */
  // Trailing "=" is base64 padding only when a delimiter follows it; before a marker (`API_KEY=[REDACTED]`), a quote
  // (`AWS_SECRET_ACCESS_KEY='[REDACTED]'`, `signature_method='ccg'`), an escape, or a path
  // (`AWS_SHARED_CREDENTIALS_FILE=/home/audit/.aws/credentials`) it is the pair's separator, so the key keeps its name.
  const LONG_TOKEN_RUN_PATTERN = /[A-Za-z0-9+_-]{16,}(?:={1,2}(?![A-Za-z0-9&[/"'\\<]))?/g;
  const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const UPPERCASE_CODE_PATTERN = /^[A-Z][A-Z_]*$|^[A-Z][A-Z0-9]*(?:[_-][A-Z0-9]+)+$/;
  const MIN_LETTERS_FOR_CASING = 6;

  const CAMEL_WORD_PATTERN = /[A-Z]+(?![a-z])|[A-Z]?[a-z]+/g;
  const MAX_SHORT_WORD_LENGTH = 2;

  /**
   * Token-shaped casing. Split at camelCase boundaries, a name is words and acronyms of three letters or more
   * (`GetAccessKeyLastUsed`, `AWSLambdaBasicExecutionRole`, `getHTTPSUrl`), while a random run breaks into
   * one- and two-letter pieces (`bPxRfiCYcanaryKEYqm`: b, Px, C, KE). Two or more such pieces making up at
   * least a third of the words is the token signal; one short word (`GetEbsEncryptionByDefault`) is a name.
   */
  function hasTokenCasing(letters: string): boolean {
    if (letters.length < MIN_LETTERS_FOR_CASING) return false;
    const words = letters.match(CAMEL_WORD_PATTERN) ?? [];
    const shortWords = words.filter((word) => word.length <= MAX_SHORT_WORD_LENGTH).length;
    return shortWords >= 2 && shortWords * 3 >= words.length;
  }

  /** A "-" or "_" separated segment shaped like part of a name: empty, digits alone, or letters with at most one digit group and no token casing. */
  function isNameSegment(segment: string): boolean {
    if (segment.length === 0 || /^\d+$/.test(segment)) return true;
    if (!/^[A-Za-z0-9]+$/.test(segment)) return false;
    if ((segment.match(/\d+/g) ?? []).length > 1) return false;
    return !hasTokenCasing(segment.replace(/\d+/g, ""));
  }

  function looksLikeToken(run: string): boolean {
    if (UUID_PATTERN.test(run) || UPPERCASE_CODE_PATTERN.test(run)) return false;
    if (/[+=]/.test(run)) return true;
    return run.split(/[-_]/).some((segment) => !isNameSegment(segment));
  }

  function scrubLongTokens(text: string): string {
    return text.replace(LONG_TOKEN_RUN_PATTERN, (run: string) => (looksLikeToken(run) ? REDACTED_ERROR_VALUE : run));
  }

  /**
   * Rule 9 sink for error text. describeError() (every attemptAwsRead failure and every access probe) and
   * errorMessage() (tool-level failures) are the only conversions from a thrown SDK error to recorded text,
   * and both run this pass, so no path can carry a credential echoed by a request context, a proxy body, or
   * a URL into findings, summaries, access checks, or the bundle.
   */
  function redactErrorText(text: string): string {
    let scrubbed = scrubCarriers(text);
    for (const rule of BARE_SHAPE_PATTERNS) scrubbed = applyTextRule(scrubbed, rule);
    scrubbed = scrubCredentialPairs(scrubbed);
    return scrubLongTokens(scrubbed);
  }

  /** The carrier passes shared by error text and snapshot strings: configured secrets, URL userinfo, query, and fragment, header carriers, Authorization parameter lists, challenge proofs, quoted values, schemes, vendor token prefixes, JWT and PEM shapes. */
  function scrubCarriers(text: string): string {
    let scrubbed = scrubConfiguredSecrets(text);
    scrubbed = scrubbed.replace(ERROR_URL_PATTERN, scrubUrlMatch);
    scrubbed = scrubHeaderCarriers(scrubbed);
    scrubbed = scrubAuthorizationParameters(scrubbed);
    scrubbed = scrubChallengeParameters(scrubbed);
    for (const rule of CARRIER_TEXT_PATTERNS) scrubbed = applyTextRule(scrubbed, rule);
    return scrubbed;
  }

  /**
   * Rule 9 data-side scrub for a string kept in a snapshot: the carrier rules of
   * redactErrorText (the configured secrets in every encoded form, URL userinfo, query, and fragment strings, the free-form
   * header carriers, the proofs in Authorization parameter lists and in challenges, quoted header and pair values,
   * authorization schemes, vendor token prefixes, JWT and PEM shapes, and credential-named pairs) without its
   * bare-shape rules, so a value is removed for what carries it and an identifier, a digest, or a key id that is
   * data stays data.
   */
  function redactCarrierText(text: string): string {
    return scrubCredentialPairs(scrubCarriers(text));
  }

  /** Nesting past which an object or array in a snapshot is replaced by the marker; the value handed to the walker is depth 1. */
  const SNAPSHOT_DEPTH_CAP = 32;
  /**
   * Field names whose value in API data is a secret whatever its shape. Exact names, not the suffix rule of the error
   * text pair rule: a snapshot's own keys name collections about credentials (`tokens`, `credentials`,
   * `passwordCredentials`, `webauthncredentials`, `hardtoken`) that carry metadata, and those stay. The URL-valued
   * webhook keys are here because the token travels in the URL's path.
   */
  const SNAPSHOT_SECRET_KEY_PATTERN =
    /^(?:secret[_-]?key|skey|secret|client[_-]?secret|api[_-]?secret|password|passwd|passphrase|private[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|secret[_-]?access[_-]?key|assertion|connection[_-]?string|authorization|cookie|set-cookie|x-auth-key|api[_-]?key|x-api-key|webhook(?:[_-]?url)?)$/i;
  /**
   * The bearer-id override for snapshot keys: a key ending in
   * `secret_id` or `token_id`, any prefix, casing, and separator (`secret_id`, `VAULT_SECRET_ID`, `role_secret_id`,
   * `roleSecretId`, `token_id`, `tokenId`), holds a Vault AppRole secret id or a token id, which authenticates rather
   * than identifies, so its value is the marker whatever its shape; an `_id` key that identifies (`client_id`,
   * `tenant_id`, `key_id`, `user_id`) is data and stays.
   */
  const SNAPSHOT_BEARER_ID_KEY_PATTERN = /(?:secret|token)[_-]?id$/i;

  /** The snapshot walk behind scrubSnapshotValue and the integration's own data walkers: one key rule, one string rule, one cap. */
  function scrubSnapshotTree(value: unknown, isSecretKey: (key: string) => boolean, depth: number): unknown {
    if (typeof value === "string") return redactCarrierText(value);
    if (value === null || typeof value !== "object") return value;
    if (value instanceof Date) return value;
    if (depth > SNAPSHOT_DEPTH_CAP) return REDACTED_ERROR_VALUE;
    if (Array.isArray(value)) return value.map((entry) => scrubSnapshotTree(entry, isSecretKey, depth + 1));
    const output: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
      output[key] = isSecretKey(key) ? snapshotMarkerFor(entry) : scrubSnapshotTree(entry, isSecretKey, depth + 1);
    }
    return output;
  }

  /** An absent or empty secret stays as it is (it reports that nothing was set); anything else is the marker. */
  function snapshotMarkerFor(entry: unknown): unknown {
    return entry === undefined || entry === null || entry === "" ? entry : REDACTED_ERROR_VALUE;
  }

  /**
   * Rule 9 walk over a value about to be written to a bundle file or returned as data. Every string at every depth
   * goes through redactCarrierText, so a carrier inside a benign-keyed string
   * (`detail: "Authorization: Bearer ..."`) is scrubbed in place with its siblings kept; a value under a secret
   * field name is the marker; an object or array nested past SNAPSHOT_DEPTH_CAP is the marker, so the depth of a
   * server-supplied tree bounds the work and nothing deeper than the cap is copied.
   */
  function scrubSnapshotValue(value: unknown): unknown {
    return scrubSnapshotTree(value, (key) => SNAPSHOT_SECRET_KEY_PATTERN.test(key) || SNAPSHOT_BEARER_ID_KEY_PATTERN.test(key), 1);
  }
  return { registerConfiguredSecrets, redactErrorText, redactCarrierText, scrubSnapshotTree, scrubSnapshotValue, SNAPSHOT_DEPTH_CAP };
}
