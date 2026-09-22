/**
 * Canary fixtures for the rule 9 error-string class: a failing surface answers with a non-JSON
 * body (a proxy's 502 HTML page) that carries credential-shaped values, or with a JSON error whose
 * message embeds a URL with a token in its query string. No canary may survive into a tool result,
 * finding, summary, dataset error, access probe, bundle file, or inflated zip entry.
 */

export const CANARY = Object.freeze({
  bearer: "canary-bearer-TOKEN-0f9e8d7c6b5a4938",
  sessionCookie: "sess-canary-COOKIE-31415926535897",
  apiKey: "ak_canary_APIKEY_2718281828459045",
  urlToken: "CANARY-url-token-1618033988749",
  basic: "Y2FuYXJ5OnBhc3N3MHJkLTI3MTgyODE4Mjg=",
  jwt: "eyJhbGciOiJIUzI1NiJ9.eyJjYW5hcnkiOiJKV1QtNjAyMjE0MDc2In0.c2lnLWNhbmFyeS0xMDA0NTM0NTY3ODk",
  awsAccessKeyId: "AKIACANARY7EXAMPLE99",
  awsSecret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYcanaryKEY0",
});

export const CANARY_URL = `https://api.example.com/v1/x?token=${CANARY.urlToken}`;

/** Substrings that must never appear in any recorded output. */
export const CANARY_VALUES = Object.freeze([
  CANARY.bearer,
  CANARY.sessionCookie,
  CANARY.apiKey,
  CANARY.urlToken,
  `token=${CANARY.urlToken}`,
]);

/** A proxy error page with every canary embedded mid-sentence. */
export function htmlCanaryBody() {
  return [
    "<html><head><title>502 Bad Gateway</title></head><body>",
    `<p>The upstream rejected Authorization: Bearer ${CANARY.bearer} while replaying`,
    `Set-Cookie: session=${CANARY.sessionCookie}; Path=/; HttpOnly and x-api-key: ${CANARY.apiKey} for the caller;`,
    `retry the request at ${CANARY_URL} once the incident clears.</p>`,
    "</body></html>",
  ].join("\n");
}

/** A vendor-shaped error message that embeds the same URL mid-sentence. */
export function jsonCanaryMessage() {
  return `Access denied while fetching ${CANARY_URL} for the caller; retry after re-authenticating.`;
}

/** Matches the status-and-length note an integration must substitute for any non-JSON body. */
export const HTML_BODY_NOTE = /non-JSON body \(text\/html, \d+ bytes\)/;

/** Matches the redacted form of the canary URL: host and path kept, query replaced. */
export const REDACTED_CANARY_URL = /https:\/\/api\.example\.com\/v1\/x\?\[REDACTED\]/;

/**
 * The short-body class (rule 9, config loader errors): V8's JSON.parse quotes a 10-character window around the
 * failure and the whole source when the input is 21 characters or shorter, so a 200 answer whose body is a short
 * non-JSON text puts the entire body into the SyntaxError message. The only permitted record of such a body is
 * the status-and-length note.
 */
export const SHORT_BODY_CANARY = "<canary-abc123xyz>";
export const SHORT_BODY_CONTENT_TYPE = "text/plain";
export const SHORT_BODY_NOTE = new RegExp(`non-JSON body \\(${SHORT_BODY_CONTENT_TYPE}, ${Buffer.byteLength(SHORT_BODY_CANARY, "utf8")} bytes\\)`);

/** Wording from V8's SyntaxError messages; any of it in an output means a parser message was interpolated. */
export const PARSER_WORDING = /is not valid JSON|Unexpected token|Unexpected end of JSON|Unexpected non-whitespace|JSON at position|Expected property name|Bad control character/;

/** Positive control for the class: the parser's message really does carry the whole short body. */
export function parserMessageFor(body) {
  try {
    JSON.parse(body);
  } catch (error) {
    return error.message;
  }
  throw new Error(`${body} parsed as JSON; the fixture must be non-JSON`);
}

/** A 200 answer whose body is the short canary, served as the content type the note must name. */
export function shortBodyResponse(status = 200, statusText = "OK") {
  return new Response(SHORT_BODY_CANARY, { status, statusText, headers: { "content-type": SHORT_BODY_CONTENT_TYPE } });
}

/** Every window of `length` characters of the body; any longer leaked fragment contains one of them. */
export function bodyFragments(body = SHORT_BODY_CANARY, length = 8) {
  const fragments = [];
  for (let start = 0; start + length <= body.length; start += 1) fragments.push(body.slice(start, start + length));
  return fragments;
}

/** Asserts no 8-character fragment of the body and no parser wording reached the value, and that the note did. */
export function assertShortBodyRecordedAsNote(assert, value, label, body = SHORT_BODY_CANARY) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  for (const fragment of bodyFragments(body)) {
    assert.ok(!text.includes(fragment), `${label}: body fragment "${fragment}" leaked into ${text.slice(0, 400)}`);
  }
  assert.doesNotMatch(text, PARSER_WORDING, `${label}: parser wording leaked into ${text.slice(0, 400)}`);
  assert.match(text, SHORT_BODY_NOTE, `${label}: the non-JSON note is the record of the body: ${text.slice(0, 400)}`);
}

/** Same check for a body that must be absent without requiring the note (bundle files that do not record errors). */
export function assertNoShortBodyFragments(assert, value, label, body = SHORT_BODY_CANARY) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  for (const fragment of bodyFragments(body)) {
    assert.ok(!text.includes(fragment), `${label}: body fragment "${fragment}" leaked into ${text.slice(0, 400)}`);
  }
  assert.doesNotMatch(text, PARSER_WORDING, `${label}: parser wording leaked into ${text.slice(0, 400)}`);
}

export function assertNoCanaries(assert, value, label) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  for (const canary of CANARY_VALUES) {
    assert.ok(!text.includes(canary), `${label}: canary ${canary} leaked`);
  }
}

export function assertNoCanariesInFiles(assert, contents, label) {
  for (const [name, text] of contents) {
    assertNoCanaries(assert, text, `${label} ${name}`);
  }
}

/**
 * Cases every integration's redactErrorText must handle: the value that must disappear and, where
 * useful, what must survive so the message stays diagnosable.
 */
export const REDACTION_CASES = Object.freeze([
  {
    name: "bearer token mid-sentence",
    input: `upstream said Authorization: Bearer ${CANARY.bearer} was rejected`,
    absent: [CANARY.bearer],
    present: ["upstream said Authorization: Bearer [REDACTED] was rejected"],
  },
  {
    name: "basic credentials",
    input: `proxy replayed Basic ${CANARY.basic} and failed`,
    absent: [CANARY.basic],
    present: ["Basic [REDACTED]"],
  },
  {
    name: "session cookie",
    input: `Set-Cookie: session=${CANARY.sessionCookie}; Path=/ was echoed`,
    absent: [CANARY.sessionCookie],
  },
  {
    name: "api key pair",
    input: `header x-api-key: ${CANARY.apiKey} rejected; api_key=${CANARY.apiKey} too`,
    absent: [CANARY.apiKey],
  },
  {
    name: "jwt",
    input: `token ${CANARY.jwt} expired`,
    absent: [CANARY.jwt],
  },
  {
    name: "aws access key id and secret",
    input: `credentials ${CANARY.awsAccessKeyId} / ${CANARY.awsSecret} were rejected`,
    absent: [CANARY.awsAccessKeyId, CANARY.awsSecret],
  },
  {
    name: "url query and userinfo anywhere in the string",
    input: `see ${CANARY_URL} and https://user:${CANARY.sessionCookie}@api.example.com/v1/y?sig=${CANARY.apiKey} for details`,
    absent: [CANARY.urlToken, CANARY.sessionCookie, CANARY.apiKey, "user:"],
    present: ["https://api.example.com/v1/x?[REDACTED]", "https://api.example.com/v1/y?[REDACTED]", "for details"],
  },
  {
    name: "prose is left alone",
    input: "InvalidAuthenticationToken: Access token has expired. Basic authentication is disabled for this tenant.",
    absent: [],
    present: ["InvalidAuthenticationToken: Access token has expired.", "Basic authentication is disabled"],
  },
]);

export function assertRedactionCases(assert, redact) {
  for (const testCase of REDACTION_CASES) {
    const output = redact(testCase.input);
    for (const value of testCase.absent) {
      assert.ok(!output.includes(value), `${testCase.name}: ${value} survived in "${output}"`);
    }
    for (const value of testCase.present ?? []) {
      assert.ok(output.includes(value), `${testCase.name}: expected "${value}" in "${output}"`);
    }
  }
}
