/**
 * Scrub boundary matrix (coordinator ruling on the scrub boundary).
 *
 * A bare value shaped like a name (words joined by hyphens or underscores with at most one numeric
 * segment, such as prod-us-east-2026) standing alone in prose is indistinguishable from a resource
 * name and stays. Two guards make that safe, and both are construction requirements for every
 * integration's redaction pass:
 *
 * 1. a value inside any carrier (Authorization, Cookie, Set-Cookie, x-api-key and similar headers;
 *    cookie or session assignments; URL userinfo and query pairs; the schemes Bearer, Basic, Digest,
 *    Token, ApiKey; credential-named key-value pairs; SOAP session elements) is removed whatever its
 *    shape, bare or quoted (`Cookie: sid="x"`, `X-Api-Key: 'x'`, `Authorization: Bearer "x"`, with any
 *    spacing and in JSON-escaped form), while a quoted non-credential header (`Content-Type:
 *    "application/json"`) stays; on a compound line a quoted value ends at its closing quote and an
 *    unquoted cookie or header value ends where the next `Name:` token begins, so the header that
 *    follows (`; X-Api-Key: "x"`, `; Content-Type: "application/json"`) keeps its name;
 * 2. a registered secret (KNOWN_SECRETS, that is the client's own credentials) is removed whatever
 *    its shape and in its base64, base64url, URL-encoded, and JSON-escaped forms.
 *
 * Real token shapes (16 or more characters with base64 symbols, scattered digits, or token casing,
 * hex digests, vendor prefixes, JWTs, PEM blocks) are still removed bare.
 *
 * A scheme word standing in prose is not a carrier: a lowercase scheme followed by a plain word, a
 * short acronym, or an environment variable name ("the bearer token is missing", "JWT bearer
 * (SF_CONSUMER_KEY,"), or a capitalized scheme followed by the capitalized next word of a title
 * ("Refresh Token Policy"), with punctuation around the word, stays; anything else after a scheme
 * word is its credential and goes.
 *
 * The matrix drives one integration's pass through `scrub(text)`; `registerSecret(secret)` registers
 * a credential through the integration's real path (constructing a client with it). The encoded
 * forms are computed here, independently of the implementation.
 */
import assert from "node:assert/strict";
import { assertFragmentsAbsent, shortestWindows } from "./planted-values.mjs";

export const REDACTED = "[REDACTED]";

/**
 * Name-shaped like the ruling's own example (sess-canary-COOKIE-31415926535897): three word segments
 * and one numeric segment, but random-looking so no 6-character window of it can coincide with a
 * carrier label or ordinary prose. Its removal from a carrier can only come from the carrier guard.
 */
export const NAME_SHAPED_CANARY = "vqzk-xwjr-HTBM-40928375611";

/**
 * Shaped like an environment variable name (upper-case segments joined by underscores). After a
 * lowercase scheme word it reads as prose ("JWT bearer (SF_CONSUMER_KEY,") and stays; after a
 * capitalized scheme it is the credential and goes, whatever its shape.
 */
export const UPPER_NAME_SHAPED_CANARY = "QXKV_JRWX_MBTH_58273940116";

/**
 * Too short for the bare token-run rule and token-cased with digits, so after a scheme word (even a
 * lowercase one in prose) only the scheme guard can remove it.
 */
export const SHORT_TOKEN_CANARY = "Xk9QzPw2Rt";

/**
 * A real token shape (20 characters, token casing, digits scattered through it): the bare token-run rule
 * removes it wherever it stands, so after a carrier label it is the shape whose removal proves least;
 * the escape-boundary rows run it anyway, since the rows audit the run rule's own lookbehind too.
 */
export const TOKEN_SHAPED_CANARY = "Qw7xKp2ZvN9tRb4Ym6Lc";

/**
 * Two secrets to register: one name-shaped, so its bare removal can only come from registration,
 * and one whose every encoded form differs from the raw form.
 */
export const REGISTERED_SECRETS = {
  nameShaped: "qhvz-wkxj-YRPL-7261",
  symbolic: 'Vq7@kZ+2/wP="9rT4x"',
};

/**
 * Literal JSON escapes as the two or six characters they are inside a doubly-encoded body (a gateway error
 * whose field holds serialized JSON): the client's parse hands the scrubber a backslash and an `n`, not a
 * newline. Every escape but `\/` and `\"` ends in a word character (`n`, `r`, `t`, `b`, `f`, a hex digit),
 * which is what a `\b` anchor or a "not preceded by a word character" lookbehind in front of a carrier
 * opener trips over (reviewer B round 4 verdict, N1). The reviewer's eleven plus `\b` and `\f`.
 */
export const JSON_ESCAPES = ["\\n", "\\r", "\\t", "\\b", "\\f", "\\r\\n", "\\u000a", "\\u0009", "\\u000d", "\\u000d\\u000a", "\\u0020", "\\/", '\\"'];

/** The decoded control characters the escapes stand for; a carrier after one of them was always removed and still must be. */
export const DECODED_CONTROLS = [["\n", "LF"], ["\t", "TAB"], ["\r\n", "CRLF"], [" ", "SPACE"]];

(() => {
  const owners = new Map();
  for (const [name, value] of [["NAME_SHAPED_CANARY", NAME_SHAPED_CANARY], ["UPPER_NAME_SHAPED_CANARY", UPPER_NAME_SHAPED_CANARY], ["SHORT_TOKEN_CANARY", SHORT_TOKEN_CANARY], ["TOKEN_SHAPED_CANARY", TOKEN_SHAPED_CANARY], ...Object.entries(REGISTERED_SECRETS)]) {
    for (const window of shortestWindows(value)) {
      const owner = owners.get(window);
      assert.equal(owner, undefined, `window ${window} appears in both ${owner} and ${name}`);
      owners.set(window, name);
      assert.equal(window.includes(REDACTED.slice(0, 3)), false, `window ${window} of ${name} overlaps the redaction marker`);
    }
  }
})();

/** Bare name-shaped values and ordinary operator prose that must come through verbatim. */
export const MUST_KEEP = [
  "Region prod-us-east-2026 rejected the request",
  "session sess-canary-COOKIE-31415926535897 closed",
  `session ${NAME_SHAPED_CANARY} closed`,
  "table sys_user_has_role and sys_user_grmember were read for Acme_Production_Org",
  "cipher TLS_AES_256_GCM_SHA384 on acme-corp-dev12345.example.com with oauth2-client-credentials",
  "content type application/x-www-form-urlencoded; the bearer token is missing; basic auth required; token request failed",
  "request failed (403) for /policy/combined/device-control/v1 and /fwmgr/queries/rule-groups/v1",
  "request failed (502 Bad Gateway) for /oauth/token: non-JSON body (text/html, 5120 bytes)",
  "Unable to read config file /tmp/grclanker-loader-Ab3dEf/nested-mapping.yaml (EISDIR)",
  "Unable to parse config file: invalid JSON in /tmp/grclanker-loader-x9Q2zR/credentials.json at line 3",
  "Metadata read of SecurityHealthCheckRisks and TwoFactorMethodsInfo failed",
  // Quoted non-credential headers, alone: the closing-quote rule takes only credential carriers.
  'Content-Type: "text/html; charset=utf-8"',
  'Date: "Mon, 22 Sep 2026 12:30:00 GMT"',
  // A credential word in a hyphenated name (access-token) or a lowercase scheme word before a lowercase word is prose, not a carrier.
  "Auth mode access-token against https://login.salesforce.com, instance https://acme.my.salesforce.com, API v64.0.",
  // camelCase identifiers may carry short acronyms and version suffixes.
  "CSRF flags enableCSRFOnGet and enableCSRFOnPost were not exposed by SecuritySettings; connectedAppOAuth and sessionTimeoutSAML were read",
  "None of the enabled prevention policies expose ScriptBasedExecutionMonitoring, InterpreterProtection, EngineProtectionV2",
  "OAuth token usage was not checked because the OauthToken read was forbidden; the bearer token was refreshed",
  // A scheme word in prose may be followed by a word wrapped in punctuation, an environment variable name, or the
  // capitalized next word of a title; none of those is its credential.
  "credentials are required: set the API key (account or user REST API key), the access token (OAuth bearer token), or the client id and secret (Scoped OAuth app credentials).",
  "JWT bearer (SF_CONSUMER_KEY, SF_USERNAME, SF_PRIVATE_KEY_FILE), username-password (SF_USERNAME, SF_PASSWORD), a refresh token, or an access token with SF_INSTANCE_URL.",
  "Pre-issued OAuth bearer token. Defaults to the ACCESS_TOKEN variable; PEM private key path for the JWT bearer flow.",
  "for each app record Permitted Users, IP Relaxation, Refresh Token Policy, and OAuth scopes; no refresh token expiry.",
  "Pre-issued access token (requires instance_url); rotation evidence derived from audit record token usage.",
  `JWT bearer (${UPPER_NAME_SHAPED_CANARY}, SF_USERNAME) reads as prose after a lowercase scheme`,
  // Non-credential assignments are worded without `=` so the credential pair rule cannot take them for a pair.
  "mutual TLS is not supported by this runtime; set the AUTH_METHOD variable to basic or oauth; the TLS probe connects with rejectUnauthorized set to false",
  // Quoted non-credential headers, in header-line, JSON, JSON-escaped, and assignment form, alone and in a sentence.
  'Content-Type: "application/json"',
  "Content-Type: 'text/html; charset=utf-8'",
  '"Content-Type": "application/json"',
  '\\"Content-Type\\":\\"application/json\\"',
  'Content-Type = "application/json"',
  'Accept: "application/vnd.pagerduty+json;version=2"',
  'User-Agent: "grclanker/1.0"',
  'Cache-Control: "no-store"',
  'Retry-After: "120"',
  'Content-Length: "5120"',
  'Location: "/api/now/table/sys_user"',
  'X-RateLimit-Remaining: "0"',
  'the proxy echoed Content-Type: "text/html" and Retry-After: "120" for prod-us-east-2026',
  // Several non-credential headers on one line stay whole, names included.
  'Content-Type: "application/json"; Accept: "application/json"',
  'Host: api.example.com; Content-Type: "application/json"',
  'Retry-After: "120", Content-Length: "5120"',
  'Content-Type: "application/json" Accept: "application/json"',
  ...escapedNonCredentialHeaderLines(),
];

/**
 * Controls for the escape-boundary rows: a non-credential header right after each literal escape, bare and
 * inside a JSON string member, stays whole, name and value (`\u0020Retry-After` is not a token run, and
 * `\nContent-Type` is not a carrier).
 */
export function escapedNonCredentialHeaderLines() {
  const lines = [];
  for (const escape of JSON_ESCAPES) {
    for (const [header, jsonMemberHeader] of [
      ['Content-Type: "application/json"', 'Content-Type: \\"application/json\\"'],
      ["Accept: text/html", "Accept: text/html"],
      ["Retry-After: 120", "Retry-After: 120"],
    ]) {
      lines.push(`upstream said 502${escape}${header}`, `{"message":"upstream said 502${escape}${jsonMemberHeader}"}`);
    }
  }
  return lines;
}

/**
 * The name-shaped canary inside every carrier the ruling names. `keeps` is the carrier's own label,
 * which must survive so the reader can still tell what was redacted.
 */
export function carrierCases(canary = NAME_SHAPED_CANARY) {
  return [
    { name: "Authorization Bearer header", text: `Authorization: Bearer ${canary}`, keeps: ["Authorization: "] },
    { name: "authorization Basic assignment", text: `authorization=Basic ${canary}`, keeps: ["authorization="] },
    // Inside a header the whole value is the credential, parameter names included.
    { name: "Authorization Digest parameters in JSON", text: `"Authorization": "Digest username=\\"svc\\", response=\\"${canary}\\""`, keeps: ["\"Authorization\": \""] },
    { name: "JSON-escaped Authorization header", text: `\\"Authorization\\":\\"Bearer ${canary}\\"`, keeps: ["Authorization"] },
    // An unknown scheme takes up to two tokens (`Scheme credential`), so the word after a bare credential goes with it.
    { name: "Proxy-Authorization without a scheme", text: `Proxy-Authorization: ${canary} trailing prose`, keeps: ["Proxy-Authorization: ", " prose"] },
    { name: "Authorization Token token= (PagerDuty scheme)", text: `Authorization: Token token=${canary}`, keeps: ["Authorization: "] },
    { name: "Authorization ApiKey", text: `Authorization: ApiKey ${canary}`, keeps: ["Authorization: "] },
    { name: "Cookie header", text: `Cookie: JSESSIONID=${canary}; theme=dark`, keeps: ["Cookie: "] },
    { name: "Set-Cookie header", text: `Set-Cookie: glide_session_store=${canary}; Path=/; HttpOnly`, keeps: ["Set-Cookie: "] },
    { name: "x-api-key header", text: `x-api-key: ${canary}`, keeps: ["x-api-key: "] },
    { name: "vendor api key header in JSON", text: `"x-sn-apikey": "${canary}"`, keeps: ["x-sn-apikey"] },
    { name: "X-Auth-Token assignment", text: `X-Auth-Token=${canary}`, keeps: ["X-Auth-Token="] },
    { name: "URL userinfo", text: `https://svc:${canary}@api.example.com/v1/x`, keeps: ["https://", "@api.example.com/v1/x"] },
    { name: "URL query pair mid-sentence", text: `see https://api.example.com/v1/x?token=${canary}&state=ok mid-sentence`, keeps: ["https://api.example.com/v1/x?", " mid-sentence"] },
    { name: "bare query pair", text: `bare query ?sid=${canary} pair`, keeps: ["?sid=", " pair"] },
    { name: "Bearer scheme in prose", text: `Bearer ${canary}`, keeps: ["Bearer "] },
    { name: "Basic scheme in prose", text: `Basic ${canary}`, keeps: ["Basic "] },
    { name: "Digest scheme in prose", text: `Digest ${canary}`, keeps: ["Digest "] },
    // A scheme standing in prose keeps its parameter names so the reader can tell which parameter was redacted.
    { name: "Digest parameters in prose", text: `Digest username="svc", response="${canary}"`, keeps: ["Digest username=", "response="] },
    { name: "Token scheme in prose", text: `Token ${canary}`, keeps: ["Token "] },
    { name: "ApiKey scheme in prose", text: `ApiKey ${canary}`, keeps: ["ApiKey "] },
    { name: "Token token= in prose", text: `Token token=${canary}`, keeps: ["Token token="] },
    { name: "lowercase bearer scheme", text: `bearer ${canary}`, keeps: ["bearer "] },
    // Punctuation around a credential does not turn it into prose, and after a capitalized scheme an
    // upper-case underscore value is the credential, not an environment variable name.
    { name: "Bearer scheme before a sentence end", text: `Bearer ${canary}.`, keeps: ["Bearer "] },
    { name: "Token scheme inside parentheses", text: `(Token ${canary})`, keeps: ["(Token "] },
    { name: "lowercase bearer scheme before a sentence end", text: `bearer ${canary}.`, keeps: ["bearer "] },
    { name: "Bearer scheme before an upper-case underscore value", text: `Bearer ${UPPER_NAME_SHAPED_CANARY}`, value: UPPER_NAME_SHAPED_CANARY, keeps: ["Bearer "] },
    { name: "lowercase bearer scheme before a short token-cased value", text: `the bearer ${SHORT_TOKEN_CANARY} was sent`, value: SHORT_TOKEN_CANARY, keeps: ["the bearer ", " was sent"] },
    { name: "lowercase token scheme before a short token-cased value in parentheses", text: `(token ${SHORT_TOKEN_CANARY}) expired`, value: SHORT_TOKEN_CANARY, keeps: ["(token ", " expired"] },
    { name: "Authorization Basic header with an upper-case underscore value", text: `Authorization: Basic ${UPPER_NAME_SHAPED_CANARY}`, value: UPPER_NAME_SHAPED_CANARY, keeps: ["Authorization: "] },
    { name: "client_secret assignment", text: `client_secret=${canary}`, keeps: ["client_secret="] },
    { name: "password field", text: `password: ${canary}`, keeps: ["password: "] },
    { name: "refresh_token JSON field", text: `"refresh_token": "${canary}"`, keeps: ["refresh_token"] },
    { name: "JSON-escaped access_token field", text: `\\"access_token\\":\\"${canary}\\"`, keeps: ["access_token"] },
    { name: "connect.sid cookie assignment", text: `connect.sid=${canary}`, keeps: ["connect.sid="] },
    { name: "PHPSESSID cookie assignment", text: `PHPSESSID=${canary}`, keeps: ["PHPSESSID="] },
    { name: "session assignment", text: `session=${canary}; other=1`, keeps: ["session="] },
    { name: "command-line password flag", text: `--password ${canary}`, keeps: ["--password "] },
    { name: "SOAP sessionId element", text: `<sessionId>${canary}</sessionId>`, keeps: ["<sessionId>", "</sessionId>"] },
    { name: "namespaced SOAP sessionId element", text: `<urn:sessionId>${canary}</urn:sessionId>`, keeps: ["<urn:sessionId>", "</urn:sessionId>"] },
    { name: "SOAP password element", text: `<password>${canary}</password>`, keeps: ["<password>", "</password>"] },
    ...quotedCarrierCases(canary),
    ...quotedCarrierCases(SHORT_TOKEN_CANARY).filter((item) => item.pinnedForShortToken).map((item) => ({ ...item, name: `${item.name} (short token)`, value: SHORT_TOKEN_CANARY })),
    ...escapeBoundaryCases(canary),
    ...escapeBoundaryCases(SHORT_TOKEN_CANARY),
    ...escapeBoundaryCases(TOKEN_SHAPED_CANARY),
    ...decodedControlCases(canary),
    ...escapedBareTokenCases(),
  ];
}

/**
 * The carriers a literal escape stands in front of inside a doubly-encoded body, with the label that must
 * survive after each: a cookie pair with a plain name (only the Cookie rule's opener can take it), a URL
 * with a userinfo password (only the URL rule's opener), a single-value credential header (the field rule's
 * lookbehind, which must also accept the `/` of `\/`), the Authorization header, and a scheme in prose.
 */
function escapeBoundaryCarriers(canary) {
  return [
    { carrier: "plain-name Cookie pair", text: `Cookie: theme=${canary}`, keeps: ["Cookie: "] },
    { carrier: "plain-name Set-Cookie pair with an attribute", text: `Set-Cookie: theme=${canary}; Secure`, keeps: ["Set-Cookie: "] },
    { carrier: "URL userinfo password", text: `https://alice:${canary}@host.example/path`, keeps: ["https://", "@host.example/path"] },
    { carrier: "X-Api-Key header", text: `X-Api-Key: ${canary}`, keeps: ["X-Api-Key: "] },
    { carrier: "Authorization Bearer header", text: `Authorization: Bearer ${canary}`, keeps: ["Authorization: "] },
    { carrier: "Bearer scheme in prose", text: `Bearer ${canary}`, keeps: ["Bearer "] },
  ];
}

/**
 * Escape-boundary rows (reviewer B round 4 verdict, N1): every carrier of `escapeBoundaryCarriers` right after
 * each literal JSON escape, bare (`upstream said 502\nCookie: theme=V`) and inside a JSON string member
 * (`{"message":"upstream said 502\nCookie: theme=V"}`). The escape and the carrier label must survive; the
 * value must not, in any 6-to-24-character window. Run with the name-shaped, the short token-cased, and the
 * token-shaped canary.
 */
export function escapeBoundaryCases(canary = NAME_SHAPED_CANARY) {
  const shape = canary === NAME_SHAPED_CANARY ? "name-shaped" : canary === SHORT_TOKEN_CANARY ? "short token" : "token-shaped";
  const cases = [];
  for (const escape of JSON_ESCAPES) {
    for (const { carrier, text, keeps } of escapeBoundaryCarriers(canary)) {
      const bare = `upstream said 502${escape}${text}`;
      cases.push({ name: `${carrier} after ${escape} (${shape})`, text: bare, value: canary, keeps: [`upstream said 502${escape}`, ...keeps] });
      cases.push({ name: `${carrier} after ${escape} inside a JSON string member (${shape})`, text: `{"message":"${bare}"}`, value: canary, keeps: [`{"message":"upstream said 502${escape}`, ...keeps, '"}'] });
    }
  }
  return cases;
}

/** The same carriers after the decoded control character the escapes stand for (a real newline, tab, CRLF, or space). */
export function decodedControlCases(canary = NAME_SHAPED_CANARY) {
  const cases = [];
  for (const [control, controlName] of DECODED_CONTROLS) {
    for (const { carrier, text, keeps } of escapeBoundaryCarriers(canary)) {
      cases.push({ name: `${carrier} after a decoded ${controlName}`, text: `upstream said 502${control}${text}`, value: canary, keeps: [`upstream said 502${control}`, ...keeps] });
    }
  }
  return cases;
}

/**
 * The bare token shapes right after each literal escape: the vendor-prefix, JWT, hex-digest, and token-run
 * rules open on the escape boundary too, and no token run starts inside the escape's own body.
 */
export function escapedBareTokenCases() {
  const cases = [];
  for (const escape of JSON_ESCAPES) {
    for (const token of BARE_TOKENS.filter((item) => !item.value.includes("\n"))) {
      cases.push({ name: `bare token ${token.name} after ${escape}`, text: `upstream said 502${escape}${token.value} seen`, value: token.value, keeps: [`upstream said 502${escape}`, " seen"] });
    }
  }
  return cases;
}

/**
 * Quoted header values (pinned carrier cases). Quotes around a credential belong to its carrier: the value
 * goes whole whatever its shape, in double or single quotes, with any spacing around the separator, and
 * in the JSON and JSON-escaped forms a headers object takes; the header after a Cookie or Authorization
 * header in the same JSON object stays. `pinnedForShortToken` marks the headline forms that are also run
 * with the short token-cased value, which no bare rule can remove.
 */
export function quotedCarrierCases(canary) {
  return [
    { name: "Cookie pair in double quotes", text: `Cookie: sid="${canary}"`, keeps: ["Cookie: "], pinnedForShortToken: true },
    { name: "Cookie pair in single quotes", text: `Cookie: sid='${canary}'`, keeps: ["Cookie: "] },
    { name: "Cookie pair with spaces around =", text: `Cookie: sid = "${canary}"`, keeps: ["Cookie: "] },
    { name: "Cookie pair without a space after the colon", text: `Cookie:sid="${canary}"`, keeps: ["Cookie:"] },
    { name: "Cookie whole value quoted", text: `Cookie: "sid=${canary}"`, keeps: ['Cookie: "'] },
    { name: "Cookie quoted pair followed by another pair", text: `Cookie: sid="${canary}"; theme=dark`, keeps: ["Cookie: "] },
    { name: "Set-Cookie quoted pair with attributes", text: `Set-Cookie: sid="${canary}"; Path=/; HttpOnly`, keeps: ["Set-Cookie: "] },
    { name: "Cookie in a JSON headers object with escaped inner quotes", text: `"Cookie": "sid=\\"${canary}\\"; theme=dark", "Accept": "application/json"`, keeps: ['"Cookie": "', '"Accept": "application/json"'] },
    { name: "Cookie in a JSON headers object before another header", text: `"Cookie": "sid=${canary}", "Content-Type": "application/json"`, keeps: ['"Cookie": "', '"Content-Type": "application/json"'] },
    { name: "JSON-escaped Cookie header", text: `\\"Cookie\\":\\"sid=${canary}\\"`, keeps: ["Cookie"] },
    { name: "X-Api-Key in double quotes", text: `X-Api-Key: "${canary}"`, keeps: ['X-Api-Key: "'], pinnedForShortToken: true },
    { name: "X-Api-Key in single quotes", text: `X-Api-Key: '${canary}'`, keeps: ["X-Api-Key: '"] },
    { name: "X-Api-Key without a space after the colon", text: `X-Api-Key:"${canary}"`, keeps: ['X-Api-Key:"'] },
    { name: "X-Api-Key with a space before the colon", text: `X-Api-Key : "${canary}"`, keeps: ['X-Api-Key : "'] },
    { name: "x-api-key quoted assignment", text: `x-api-key="${canary}"`, keeps: ["x-api-key="] },
    { name: "X-Api-Key in a JSON headers object", text: `"X-Api-Key": "${canary}"`, keeps: ["X-Api-Key"] },
    { name: "JSON-escaped X-Api-Key header", text: `\\"X-Api-Key\\":\\"${canary}\\"`, keeps: ["X-Api-Key"] },
    { name: "JSON-escaped X-Api-Key header with a space", text: `\\"X-Api-Key\\": \\"${canary}\\"`, keeps: ["X-Api-Key"] },
    { name: "Authorization Bearer with a double-quoted credential", text: `Authorization: Bearer "${canary}"`, keeps: ["Authorization: "], pinnedForShortToken: true },
    { name: "Authorization Bearer with a single-quoted credential", text: `Authorization: Bearer '${canary}'`, keeps: ["Authorization: "] },
    { name: "Authorization Basic with a double-quoted credential", text: `Authorization: Basic "${canary}"`, keeps: ["Authorization: "] },
    { name: "Authorization Bearer quoted without a space after the colon", text: `Authorization:Bearer "${canary}"`, keeps: ["Authorization:"] },
    { name: "Authorization whole value quoted", text: `Authorization: "Bearer ${canary}"`, keeps: ['Authorization: "'] },
    // The assignment rule folds the quoted marker left by the header rule, so the quotes go with the value.
    { name: "authorization assignment in single quotes", text: `authorization='Bearer ${canary}'`, keeps: ["authorization="] },
    { name: "Authorization Token token= with a quoted parameter", text: `Authorization: Token token="${canary}"`, keeps: ["Authorization: "] },
    { name: "Authorization Bearer quoted before trailing prose", text: `Authorization: Bearer "${canary}" for /api/now/table/sys_user`, keeps: ["Authorization: ", " for /api/now/table/sys_user"] },
    { name: "Authorization in a JSON headers object with escaped inner quotes", text: `"Authorization": "Bearer \\"${canary}\\"", "Content-Type": "application/json"`, keeps: ['"Authorization": "', '"Content-Type": "application/json"'] },
    { name: "JSON-escaped Authorization header with a space", text: `\\"Authorization\\": \\"Bearer ${canary}\\"`, keeps: ["Authorization"] },
    { name: "Bearer scheme in prose with a double-quoted credential", text: `Bearer "${canary}".`, keeps: ["Bearer "], pinnedForShortToken: true },
    { name: "Token scheme in prose with a single-quoted credential", text: `(Token '${canary}') expired`, keeps: ["(Token ", " expired"] },
    { name: "Digest parameters in single quotes", text: `Digest username='svc', response='${canary}'`, keeps: ["Digest username=", "response="] },
    { name: "client_secret quoted assignment", text: `client_secret="${canary}"`, keeps: ["client_secret="], pinnedForShortToken: true },
    { name: "client_secret assignment with spaces around =", text: `client_secret = ${canary} in prose`, keeps: ["client_secret = ", " in prose"] },
    { name: "password single-quoted assignment", text: `password='${canary}'; other=1`, keeps: ["password=", "; other=1"] },
    { name: "sid quoted assignment", text: `sid="${canary}"`, keeps: ["sid="] },
    { name: "JSON-escaped quoted assignment", text: `client_secret=\\"${canary}\\"`, keeps: ["client_secret="] },
    { name: "command-line token flag with a quoted value", text: `--token "${canary}" --org acme`, keeps: ["--token ", " --org acme"] },
    { name: "command-line password flag with a single-quoted value", text: `--password '${canary}'`, keeps: ["--password "] },
    ...compoundHeaderLineCases(canary),
  ];
}

/**
 * Compound header lines (pinned carrier cases, round 4 early signal). Header dumps and proxy error pages
 * put several headers on one `;`-, `,`-, or space-separated line. A quoted value ends at its closing
 * quote and an unquoted cookie or header value ends where the next `Name:` token begins, so the header
 * that follows a Cookie or another credential header keeps its name and gets its own carrier treatment:
 * a quoted name-shaped `X-Api-Key` value after a Cookie goes, and a following `Content-Type:
 * "application/json"` stays whole. The `ctl` cookie value is a position control, redacted with its
 * carrier; `keeps` names the following header so a swallowed name fails the case.
 */
export function compoundHeaderLineCases(canary) {
  const json = '"application/json"';
  const textHtml = '"text/html; charset=utf-8"';
  const date = 'Date: "Mon, 22 Sep 2026 12:30:00 GMT"';
  return [
    { name: "Cookie followed by a quoted X-Api-Key", text: `Cookie: sid="ctl"; X-Api-Key: "${canary}"`, keeps: ["Cookie: ", '; X-Api-Key: "'], pinnedForShortToken: true },
    { name: "Cookie followed by X-Api-Key with a space before the colon", text: `Cookie: sid="ctl"; X-Api-Key : "${canary}"`, keeps: ["Cookie: ", '; X-Api-Key : "'] },
    { name: "unquoted Cookie followed by a quoted X-Api-Key", text: `Cookie: sid=ctl; X-Api-Key: "${canary}"`, keeps: ["Cookie: ", '; X-Api-Key: "'] },
    { name: "single-quoted Cookie followed by X-Api-Key without a space", text: `Cookie: sid='ctl'; X-Api-Key:'${canary}'`, keeps: ["Cookie: ", "; X-Api-Key:'"] },
    { name: "Cookie followed by X-Api-Key after a comma", text: `Cookie: sid=ctl, X-Api-Key: "${canary}"`, keeps: ["Cookie: ", ', X-Api-Key: "'] },
    { name: "Cookie followed by X-Api-Key after a space", text: `Cookie: sid=ctl X-Api-Key: "${canary}"`, keeps: ["Cookie: ", ' X-Api-Key: "'] },
    { name: "Cookie followed by a quoted Authorization Bearer", text: `Cookie: sid="ctl"; Authorization: Bearer "${canary}"`, keeps: ["Cookie: ", "; Authorization: "] },
    { name: "Set-Cookie with attributes followed by Authorization", text: `Set-Cookie: session="ctl"; Path=/; Authorization: Bearer "${canary}"`, keeps: ["Set-Cookie: ", "; Authorization: "] },
    { name: "lowercase cookie pairs followed by lowercase authorization", text: `cookie: a=b; c=d; authorization: bearer "${canary}"`, keeps: ["cookie: ", "; authorization: "] },
    { name: "Cookie followed by Content-Type", text: `Cookie: sid=${canary}; Content-Type: ${json}`, keeps: ["Cookie: ", `; Content-Type: ${json}`], pinnedForShortToken: true },
    { name: "quoted Cookie followed by Content-Type and Accept", text: `Cookie: sid="${canary}"; Content-Type: ${json}; Accept: ${json}`, keeps: ["Cookie: ", `; Content-Type: ${json}; Accept: ${json}`] },
    { name: "Set-Cookie with an Expires date followed by X-Api-Key", text: `Set-Cookie: sid=${canary}; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Path=/; X-Api-Key: "ctl"`, keeps: ["Set-Cookie: ", '; X-Api-Key: "'] },
    { name: "two quoted headers, X-Api-Key then Authorization", text: `X-Api-Key: "ctl"; Authorization: Bearer "${canary}"`, keeps: ['X-Api-Key: "', "; Authorization: "] },
    { name: "two quoted headers, Authorization then X-Api-Key", text: `Authorization: Bearer "ctl"; X-Api-Key: "${canary}"`, keeps: ["Authorization: ", '; X-Api-Key: "'], pinnedForShortToken: true },
    { name: "two Set-Cookie headers on one line", text: `Set-Cookie: a=ctl; Secure; Set-Cookie: session="${canary}"; HttpOnly`, keeps: ["Set-Cookie: ", "; Set-Cookie: "] },
    { name: "Proxy-Authorization without a scheme followed by X-Api-Key after a space", text: `Proxy-Authorization: ctl X-Api-Key: "${canary}"`, keeps: ["Proxy-Authorization: ", ' X-Api-Key: "'] },
    { name: "Cookie followed by a JSON fragment", text: `Cookie: sid=ctl; {"X-Api-Key": "${canary}"}`, keeps: ["Cookie: ", '; {"X-Api-Key": "'] },
    { name: "quoted Cookie followed by a JSON fragment after a space", text: `Cookie: sid="ctl" {"api_key": "${canary}"}`, keeps: ["Cookie: ", '{"api_key": "'] },
    { name: "header dump with every credential header and Content-Type", text: `Headers presented: Authorization: Bearer "ctl"; Cookie: sid="ctl"; X-Api-Key: "${canary}"; Cookie: sid=prod-us-east-2026; Content-Type: ${json}`, keeps: ["Headers presented: Authorization: ", "; Cookie: ", '; X-Api-Key: "', `; Content-Type: ${json}`] },
    // Closing-quote refinement: a closed quoted value ends at its closing quote even with `; Name:` inside, so the
    // header start inside the quotes is part of the value; a quote followed by a value character closed nothing,
    // so that value is unterminated and the `Name:` cut applies to it, as it does to an unquoted value.
    { name: "closed quoted Cookie with a header start inside, then the Content-Type control", text: `Cookie: sid="${canary}; X-Api-Key: ctl"; Content-Type: ${textHtml}`, keeps: ["Cookie: ", `; Content-Type: ${textHtml}`] },
    { name: "closed quoted Bearer with a header start inside, then the Date control", text: `Authorization: Bearer "${canary}; X-Api-Key: ctl"; ${date}`, keeps: ["Authorization: ", `; ${date}`] },
    { name: "unterminated quoted Cookie then a quoted X-Api-Key carrying the value", text: `Cookie: sid="ctl; X-Api-Key: "${canary}"`, keeps: ["Cookie: ", '; X-Api-Key: "'] },
    { name: "unterminated quoted Cookie carrying the value, then a quoted X-Api-Key", text: `Cookie: sid="${canary}; X-Api-Key: "ctl"`, keeps: ["Cookie: ", '; X-Api-Key: "'] },
    { name: "unterminated quoted Cookie at the end of the line", text: `Cookie: sid="${canary}`, keeps: ["Cookie: "] },
    { name: "Cookie followed by the Content-Type control with a charset parameter", text: `Cookie: sid=${canary}; Content-Type: ${textHtml}`, keeps: ["Cookie: ", `; Content-Type: ${textHtml}`] },
    { name: "quoted Cookie followed by the Date control", text: `Cookie: sid="${canary}"; ${date}`, keeps: ["Cookie: ", `; ${date}`] },
  ];
}

/** Real token shapes that go even when bare. */
export const BARE_TOKENS = [
  { name: "base64 with padding", value: "dGhpcyBpcyBhIHRlc3QgdG9rZW4=" },
  { name: "base64 with plus and slash", value: "Zm9vYmFy+YmF6L3F1eA" },
  { name: "hex-suffixed vendor-style bearer", value: "cs-bearer-CANARY-9f8e7d6c5b4a3210" },
  { name: "scattered digits", value: "a1b2c3d4e5f6a7b8c9d0" },
  { name: "token casing", value: "NbAkKc66ryYTWUXYEuZqRt" },
  { name: "token casing with underscore", value: "y_NbAkKc66ryYTWUXYEu" },
  { name: "md5 hex digest", value: "9f8e7d6c5b4a32109f8e7d6c5b4a3210" },
  { name: "sha1 hex digest", value: "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
  { name: "AWS access key id", value: "AKIAIOSFODNN7EXAMPLE" },
  { name: "Slack bot token", value: "xoxb-1234567890-abcdefghijkl" },
  { name: "Stripe live key", value: "sk_live_4eC39HqLyjWDarjtT1zdp7dc" },
  { name: "GitHub personal access token", value: "ghp_16C7e42F292c6912E7710c838347Ae178B4a" },
  { name: "JWT", value: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkifQ.c2lnbmF0dXJl" },
  { name: "PEM block", value: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC\n-----END PRIVATE KEY-----" },
  { name: "alternating case run", value: "AbCdEfGhIjKlMnOpQr" },
];

/**
 * Path skeletons keep their word-like pieces. A canonical UUID (an Anypoint organization id, a Falcon
 * user uuid) is a vendor identifier and stays; a 32-hex sys_id is indistinguishable from an MD5 digest
 * and goes with the hex-digest rule.
 */
export const PATH_CASES = [
  { text: "for /accounts/api/organizations/550e8400-e29b-41d4-a716-446655440000/members", expected: "for /accounts/api/organizations/550e8400-e29b-41d4-a716-446655440000/members" },
  { text: "for /api/now/table/sys_user/6816f79cc0a8016401c5a33be04be441", expected: `for /api/now/table/sys_user/${REDACTED}` },
];

/** HTTP status lines as describeStatus and `${status} ${statusText}` render them; every integration's error strings carry them. */
export const HTTP_STATUS_TEXTS = [
  "200 OK",
  "400 Bad Request",
  "401 Unauthorized",
  "403 Forbidden",
  "404 Not Found",
  "429 Too Many Requests",
  "500 Internal Server Error",
  "502 Bad Gateway",
  "503 Service Unavailable",
  "504 Gateway Timeout",
];

/**
 * Addendum 7 must-keep table for one integration. Every entry is rendered by `keepTableLines` in isolation
 * and inside a realistic sentence of the kind the integration's error strings, inventories, and finding
 * summaries carry, and `assertScrubBoundary` asserts each line comes back verbatim.
 *
 * @typedef {object} KeepTable
 * @property {string[]} paths every endpoint path the integration requests
 * @property {string[]} tables every table, object, or dataset name the integration requests, as the inventories name them
 * @property {string[]} tenants tenant and org names with digits and hyphens
 * @property {string[]} principals principal identifiers in the vendor's shapes
 * @property {string[]} findingIds the integration's finding ids
 * @property {string[]} fixedTexts the standing fixed texts (loader, opaque-body, not requested, withheld, skipped, corollary wordings)
 * @property {string[]} [statusTexts] defaults to HTTP_STATUS_TEXTS
 */

/**
 * Renders each table entry in isolation and inside a realistic summary sentence: an endpoint path in
 * an error string, a table in an inventory state and a collection issue, a tenant in an access check
 * summary, a principal in a finding summary, a status text in an opaque-body note, a finding id in a
 * demotion summary, and a fixed text after a finding id and tenant.
 */
export function keepTableLines(table) {
  for (const key of ["paths", "tables", "tenants", "principals", "findingIds", "fixedTexts"]) {
    assert.ok(Array.isArray(table[key]) && table[key].length > 0, `keep table: ${key} lists at least one entry`);
  }
  const statusTexts = table.statusTexts ?? HTTP_STATUS_TEXTS;
  const [path] = table.paths;
  const [tenant] = table.tenants;
  const [principal] = table.principals;
  const [findingId] = table.findingIds;
  const lines = [];
  const add = (value, ...sentences) => {
    assert.equal(typeof value, "string", `keep table entry is a string: ${JSON.stringify(value)}`);
    assert.ok(value.length > 0, "keep table entry is not empty");
    for (const sentence of sentences) assert.ok(sentence.includes(value), `sentence embeds ${JSON.stringify(value)}: ${sentence}`);
    lines.push(value, ...sentences);
  };
  for (const item of table.paths) {
    add(
      item,
      `request failed (403 Forbidden) for ${item}: JSON body without documented error fields (application/json, 42 bytes)`,
      `${item} answered 200 OK on ${tenant}; 2 of 2 pages were read and the read was complete`,
    );
  }
  for (const item of table.tables) {
    add(
      item,
      `${item} read: complete (12 rows of 12)`,
      `${item} read: unread (request failed (403 Forbidden) for ${path}: Insufficient rights to query records)`,
      `the ${item} read was forbidden (403 Forbidden) on ${tenant}, so ${findingId} is manual and names ${item}`,
    );
  }
  for (const item of table.tenants) {
    add(item, `Connected to ${item} as ${principal}; every surface answered and ${path} was readable`);
  }
  for (const item of table.principals) {
    add(
      item,
      `Among the visible rows, ${item} holds an administrative role on ${tenant} and has not signed in for 90+ days`,
      `${findingId} names ${item} from a complete read of ${path}`,
    );
  }
  for (const item of statusTexts) {
    add(item, `request failed (${item}) for ${path}: non-JSON body (text/html, 5120 bytes)`);
  }
  for (const item of table.findingIds) {
    add(item, `${item} is manual because the ${path} read was forbidden (403 Forbidden) on ${tenant}; the verdict is capped and the inventory is named`);
  }
  for (const item of table.fixedTexts) {
    add(item, `${findingId} on ${tenant}: ${item}`);
  }
  return lines;
}

/** The raw, base64, base64url, URL-encoded (upper- and lowercase hex, `+` for space), and JSON-escaped forms, deduplicated. */
export function encodedForms(secret) {
  const bytes = Buffer.from(secret, "utf8");
  const urlEncoded = encodeURIComponent(secret);
  return [...new Set([
    secret,
    bytes.toString("base64"),
    bytes.toString("base64url"),
    urlEncoded,
    urlEncoded.replace(/%[0-9A-F]{2}/g, (escape) => escape.toLowerCase()),
    urlEncoded.replace(/%20/g, "+"),
    JSON.stringify(secret).slice(1, -1),
  ])];
}

(() => {
  const forms = encodedForms(REGISTERED_SECRETS.symbolic);
  assert.equal(forms.length, 6, "the symbolic secret has a distinct base64, base64url, URL-encoded (two cases), and JSON-escaped form");
  assert.equal(encodedForms(REGISTERED_SECRETS.nameShaped).length, 3, "the name-shaped secret has distinct base64 and base64url forms only");
})();

/** Removed means no substring of the value at lengths 6 through 24 survives and the marker took its place. */
function assertRemoved(output, value, label) {
  assertFragmentsAbsent(assert, output, [value], `${label}: output ${JSON.stringify(output)}`);
  assert.ok(output.includes(REDACTED), `${label}: no redaction marker: ${JSON.stringify(output)}`);
}

/**
 * Runs the matrix against one redaction surface.
 *
 * @param {object} options
 * @param {(text: string) => string} options.scrub the surface under test (an error constructor, an exported helper, a client's redact)
 * @param {((secret: string) => void) | undefined} options.registerSecret registers a credential through the integration's real
 *   path; when given, the name-shaped secret is first shown to survive bare (unregistered) before it is registered. Pass
 *   undefined for a second surface in the same file, where the secrets are already registered.
 * @param {string[]} [options.mustKeep] integration-specific prose that must come through verbatim
 * @param {KeepTable} [options.keepTable] the integration's addendum 7 must-keep table; every entry is asserted verbatim in
 *   isolation and inside a realistic summary sentence
 */
export function assertScrubBoundary({ scrub, registerSecret, mustKeep = [], keepTable }) {
  for (const keep of [...MUST_KEEP, ...mustKeep, ...(keepTable ? keepTableLines(keepTable) : [])]) {
    assert.equal(scrub(keep), keep, `bare name-shaped or ordinary prose must stay: ${JSON.stringify(keep)}`);
  }

  for (const item of carrierCases()) {
    const output = scrub(item.text);
    assertRemoved(output, item.value ?? NAME_SHAPED_CANARY, `carrier ${item.name}`);
    for (const kept of item.keeps) assert.ok(output.includes(kept), `carrier ${item.name}: label ${JSON.stringify(kept)} must stay: ${JSON.stringify(output)}`);
  }

  if (registerSecret !== undefined) {
    const bare = `echoed ${REGISTERED_SECRETS.nameShaped} in prose`;
    assert.equal(scrub(bare), bare, "positive control: the name-shaped secret survives bare before it is registered");
    registerSecret(REGISTERED_SECRETS.nameShaped);
    registerSecret(REGISTERED_SECRETS.symbolic);
  }
  for (const [label, secret] of Object.entries(REGISTERED_SECRETS)) {
    for (const form of encodedForms(secret)) {
      assertRemoved(scrub(`echoed ${form} in prose`), form, `registered ${label} secret, form ${JSON.stringify(form)}`);
    }
    assertRemoved(scrub(`Authorization: Basic ${Buffer.from(`svc:${secret}`).toString("base64")}`), Buffer.from(`svc:${secret}`).toString("base64"), `registered ${label} secret in a Basic credential`);
  }

  for (const token of BARE_TOKENS) {
    assertRemoved(scrub(`value ${token.value} seen`), token.value, `bare token ${token.name}`);
  }

  for (const item of PATH_CASES) {
    assert.equal(scrub(item.text), item.expected, `path skeleton: ${item.text}`);
  }
}
