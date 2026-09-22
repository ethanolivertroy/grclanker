/**
 * Canary fixtures for the rule 9 error-string class: a failing surface answers with a non-JSON
 * body (a proxy's 502 HTML page) that carries credential-shaped values, or with a JSON error whose
 * message embeds a URL with a token in its query string. No canary may survive into a tool result,
 * finding, summary, dataset error, access probe, bundle file, or inflated zip entry.
 *
 * Every canary is alphanumeric and random-looking (a JWT keeps its dot separators), so no window of
 * CANARY_WINDOW_MIN characters of any canary occurs in a fixture's legitimate values, and every leak
 * assertion checks every window of the canary from CANARY_WINDOW_MIN to CANARY_WINDOW_MAX characters
 * rather than the whole value: a partial echo (a JSON.parse window, a truncated token) cannot pass.
 */

export const CANARY = Object.freeze({
  bearer: "VFq5FSBbZgeS4UFPQzLp7ux43fPT8nzu",
  sessionCookie: "dJtCVy8yDXQmC7VJkqmKyeKc9PH8",
  apiKey: "z8MbGj5JMM5dyEKMYGUYcVkAFnv3",
  urlToken: "cPWqj5swNXPywURtfydcFhDW",
  basic: "ABc5e5LhrRjGmSFYasDXvAk6GwNwxH9S",
  jwt: "eyJhbGciOiJIUzI1NiIsImtpZCI6Ill0SzZrTUFQZ1haayJ9.eyJzdWIiOiJEY1J3OFJoZUViVEoifQ.hLyJhJZMRGcb3BUkmTgFbpjpjt6UvCJh",
  awsAccessKeyId: "AKIAT8Q56XX8D53AZ3JQ",
  awsSecret: "YWm6RTrMRVZq3cfs9sQG5ePFDTtHv5syKsSCRKv6",
});

export const CANARY_URL = `https://api.example.com/v1/x?token=${CANARY.urlToken}`;

/**
 * Values that must never appear in any recorded output. Checked window by window (see
 * assertNoCanaryWindows), so the `token=<urlToken>` compound of earlier revisions is covered by the
 * urlToken windows and is no longer listed: its own 6-character window "token=" is legitimate text.
 */
export const CANARY_VALUES = Object.freeze([
  CANARY.bearer,
  CANARY.sessionCookie,
  CANARY.apiKey,
  CANARY.urlToken,
  CANARY.basic,
  CANARY.jwt,
  CANARY.awsAccessKeyId,
  CANARY.awsSecret,
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
 * Sliding-window leak checks (rule 9, config loader errors, Qualys tightening). A leak assertion against a
 * planted credential checks every substring of the credential from CANARY_WINDOW_MIN to CANARY_WINDOW_MAX
 * characters, not the whole value and not one fixed width, so a partial echo such as JSON.parse's
 * 10-character window or a truncated token cannot pass. A value shorter than CANARY_WINDOW_MIN is checked
 * whole.
 */
export const CANARY_WINDOW_MIN = 6;
export const CANARY_WINDOW_MAX = 24;

/** Every substring of the value whose length lies in [minLength, maxLength], clamped to the value's length. */
export function canaryWindows(value, minLength = CANARY_WINDOW_MIN, maxLength = CANARY_WINDOW_MAX) {
  const shortest = Math.min(minLength, value.length);
  const longest = Math.min(maxLength, value.length);
  const windows = [];
  for (let length = shortest; length <= longest; length += 1) {
    for (let start = 0; start + length <= value.length; start += 1) windows.push(value.slice(start, start + length));
  }
  return windows;
}

/**
 * The longest window of the canary (lengths minLength..maxLength) that occurs in the text, or undefined when
 * none does. Every window of every length is covered: a text that contains any window of length L >=
 * minLength contains that window's first minLength characters, which is itself a minLength window, so the
 * minLength pass is the exhaustive test and the longer lengths only refine the report.
 */
export function leakedCanaryWindow(text, value, minLength = CANARY_WINDOW_MIN, maxLength = CANARY_WINDOW_MAX) {
  const shortest = Math.min(minLength, value.length);
  if (!canaryWindows(value, shortest, shortest).some((window) => text.includes(window))) return undefined;
  for (let length = Math.min(maxLength, value.length); length > shortest; length -= 1) {
    const window = canaryWindows(value, length, length).find((candidate) => text.includes(candidate));
    if (window) return window;
  }
  return canaryWindows(value, shortest, shortest).find((window) => text.includes(window));
}

function textOf(value) {
  return typeof value === "string" ? value : JSON.stringify(value);
}

/** Asserts no window of any canary occurs in the value (a string, or anything JSON.stringify renders). */
export function assertNoCanaryWindows(assert, value, canaries, label) {
  const text = textOf(value);
  for (const canary of canaries) {
    const window = leakedCanaryWindow(text, canary);
    assert.equal(window, undefined, `${label}: window "${window}" of canary ${canary} leaked into ${text.slice(0, 400)}`);
  }
}

/** Same check over a Map of file or zip-entry name to contents. */
export function assertNoCanaryWindowsInFiles(assert, contents, canaries, label) {
  for (const [name, text] of contents) assertNoCanaryWindows(assert, text, canaries, `${label} ${name}`);
}

/**
 * Fixture self-check. A canary is alphanumeric segments joined by dots (a JWT), long enough to carry several
 * windows, and random-looking (no character repeated three times in a row); no two canaries share a window,
 * and no window of any canary occurs in the fixture's legitimate values, so a windowed leak assertion can
 * fail only on a real echo of the planted value.
 */
export const CANARY_SHAPE = /^[A-Za-z0-9]+(?:\.[A-Za-z0-9_-]+)*$/;

export function assertCanaryShape(assert, value, label, { minLength = 12 } = {}) {
  assert.match(value, CANARY_SHAPE, `${label}: canary ${value} is not alphanumeric`);
  assert.ok(value.length >= minLength, `${label}: canary ${value} is shorter than ${minLength} characters`);
  assert.doesNotMatch(value, /(.)\1\1/, `${label}: canary ${value} repeats a character three times, which is not random-looking`);
}

export function assertCanariesDisjointFromFixture(assert, canaries, legitimateTexts, label) {
  const named = legitimateTexts instanceof Map ? [...legitimateTexts] : [...legitimateTexts].map((text, index) => [`#${index}`, text]);
  for (const [name, value] of named) {
    const text = textOf(value);
    for (const canary of canaries) {
      const window = leakedCanaryWindow(text, canary);
      assert.equal(window, undefined, `${label}: window "${window}" of canary ${canary} occurs in legitimate value ${name}`);
    }
  }
}

/** Runs the whole self-check: every canary's shape, pairwise disjointness, and disjointness from the fixture. */
export function assertCanaryFixture(assert, canaries, legitimateTexts, label, options = {}) {
  const unique = [...new Set(canaries)];
  for (const canary of unique) assertCanaryShape(assert, canary, label, options);
  for (const canary of unique) {
    for (const other of unique) {
      if (other === canary) continue;
      const window = leakedCanaryWindow(other, canary);
      assert.equal(window, undefined, `${label}: canaries ${canary} and ${other} share the window "${window}"`);
    }
  }
  assertCanariesDisjointFromFixture(assert, unique, legitimateTexts, label);
}

/**
 * The parser-snippet class (rule 9, config loader errors): V8's JSON.parse quotes a window of the source in
 * its SyntaxError message, so a transport that hands back a non-JSON body must never interpolate that message.
 */
export const PARSER_SNIPPET_CANARY = "A4wGMxZMnRHFb6PWdLT58NNw";

/** A non-JSON body with the parser-snippet canary at the position JSON.parse quotes. */
export function parserSnippetBody() {
  return `<html>${PARSER_SNIPPET_CANARY}</html>`;
}

/**
 * The short-body class (rule 9, config loader errors): V8's JSON.parse quotes a 10-character window around the
 * failure and the whole source when the input is 21 characters or shorter, so a 200 answer whose body is a short
 * non-JSON text puts the entire body into the SyntaxError message. The only permitted record of such a body is
 * the status-and-length note.
 */
export const SHORT_BODY_CANARY = "X3VHr2P9LeybLxNpqr";
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

/** Every window of the body from minLength to maxLength characters; any leaked fragment of that size is one of them. */
export function bodyFragments(body = SHORT_BODY_CANARY, minLength = CANARY_WINDOW_MIN, maxLength = CANARY_WINDOW_MAX) {
  return canaryWindows(body, minLength, maxLength);
}

/** Asserts no window of the body and no parser wording reached the value, and that the note did. */
export function assertShortBodyRecordedAsNote(assert, value, label, body = SHORT_BODY_CANARY) {
  const text = textOf(value);
  assertNoCanaryWindows(assert, text, [body], label);
  assert.doesNotMatch(text, PARSER_WORDING, `${label}: parser wording leaked into ${text.slice(0, 400)}`);
  assert.match(text, SHORT_BODY_NOTE, `${label}: the non-JSON note is the record of the body: ${text.slice(0, 400)}`);
}

/** Same check for a body that must be absent without requiring the note (bundle files that do not record errors). */
export function assertNoShortBodyFragments(assert, value, label, body = SHORT_BODY_CANARY) {
  const text = textOf(value);
  assertNoCanaryWindows(assert, text, [body], label);
  assert.doesNotMatch(text, PARSER_WORDING, `${label}: parser wording leaked into ${text.slice(0, 400)}`);
}

export function assertNoCanaries(assert, value, label) {
  assertNoCanaryWindows(assert, value, CANARY_VALUES, label);
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
  // Codex P1 (quoted header value): the quotes delimit the carrier, so the value is removed whole whatever its
  // shape; the header name, the scheme, and the quotes stay.
  {
    name: "quoted bearer token (Codex P1)",
    input: `upstream said Authorization: Bearer "${CANARY.bearer}" was rejected`,
    absent: [CANARY.bearer],
    present: ['upstream said Authorization: Bearer "[REDACTED]" was rejected'],
  },
  {
    name: "single-quoted bearer token without a space (Codex P1)",
    input: `Authorization:Bearer '${CANARY.bearer}' was rejected`,
    absent: [CANARY.bearer],
    present: ["Authorization:Bearer '[REDACTED]' was rejected"],
  },
  {
    name: "quoted X-Auth-Key header (Codex P1, round 4 item F)",
    input: `X-Auth-Key: "${CANARY.apiKey}" was invalid`,
    absent: [CANARY.apiKey],
    present: ["X-Auth-Key: [REDACTED]"],
  },
  {
    name: "bare X-Auth-Key and X-Auth-Email headers (round 4 item F)",
    input: `X-Auth-Key: ${CANARY.apiKey}\nX-Auth-Email: ${CANARY.sessionCookie} were rejected`,
    absent: [CANARY.apiKey, CANARY.sessionCookie],
    present: ["X-Auth-Key: [REDACTED]\nX-Auth-Email: [REDACTED]"],
  },
  {
    name: "quoted api key headers, single and double quotes (Codex P1)",
    input: `X-Api-Key: '${CANARY.apiKey}' rejected; x-api-key:"${CANARY.apiKey}" too`,
    absent: [CANARY.apiKey],
    present: ["X-Api-Key: '[REDACTED]' rejected", 'x-api-key:"[REDACTED]" too'],
  },
  {
    name: "quoted cookie attribute (Codex P1)",
    input: `Cookie: sid="${CANARY.sessionCookie}"; theme=dark was echoed`,
    absent: [CANARY.sessionCookie],
    present: ["Cookie: [REDACTED]"],
  },
  {
    name: "JSON-escaped quoted headers (Codex P1)",
    input: `body was {\\"X-Auth-Key\\":\\"${CANARY.apiKey}\\",\\"Authorization\\":\\"Bearer ${CANARY.bearer}\\",\\"password\\":\\"${CANARY.basic}\\"}`,
    absent: [CANARY.apiKey, CANARY.bearer, CANARY.basic],
    present: ['{\\"X-Auth-Key\\":\\"[REDACTED]\\",\\"Authorization\\":\\"[REDACTED]\\",\\"password\\":\\"[REDACTED]\\"}'],
  },
  {
    // One carrier per line: the cookie and X-Auth-Key rules consume through the end of their line.
    name: "name-shaped quoted values (the Codex P1 examples)",
    input: 'Cookie: sid="prod-cookie"\nX-Api-Key: "prod-key"\nX-Auth-Key: "prod-key"\nAuthorization: Bearer "prod-token"\nAuthorization: Bearer \'prod-token\'',
    absent: ["prod-cookie", "prod-key", "prod-token"],
    present: ['Cookie: [REDACTED]\nX-Api-Key: "[REDACTED]"\nX-Auth-Key: [REDACTED]\nAuthorization: Bearer "[REDACTED]"\nAuthorization: Bearer \'[REDACTED]\''],
  },
  {
    name: "quoted non-credential headers stay",
    input: 'Content-Type: "application/json" and Accept: \'application/json\' were sent; role "AWSLambdaBasicExecutionRole" was named',
    absent: [],
    present: ['Content-Type: "application/json"', "Accept: 'application/json'", 'role "AWSLambdaBasicExecutionRole"'],
  },
]);

/**
 * Quoted values that are not credentials (Codex P1 control): a quoted header value is removed only when the
 * header or pair names a credential or a scheme carries it, so these survive the scrub unchanged.
 */
export const QUOTED_NON_CREDENTIAL_TEXTS = Object.freeze([
  'Content-Type: "application/json"',
  "Accept: 'application/json'",
  'Content-Type:"text/html; charset=utf-8"',
  '{"displayName":"AWSLambdaBasicExecutionRole","role":"prod-us-east-2026"}',
  '{\\"@odata.type\\":\\"#microsoft.graph.conditionalAccessPolicy\\"}',
  'the header "X-Request-Id" was missing',
]);

/**
 * The absent values are checked window by window; the present values must survive whole; and a second pass over
 * the scrubbed output changes nothing, since error sinks scrub at more than one layer.
 */
export function assertRedactionCases(assert, redact) {
  for (const testCase of REDACTION_CASES) {
    const output = redact(testCase.input);
    assertNoCanaryWindows(assert, output, testCase.absent, testCase.name);
    for (const value of testCase.present ?? []) {
      assert.ok(output.includes(value), `${testCase.name}: expected "${value}" in "${output}"`);
    }
    assert.equal(redact(output), output, `${testCase.name}: a second pass over the scrubbed message changes nothing`);
  }
}

/**
 * Scrub boundary (coordinator ruling). A bare value shaped like a name, words joined by hyphens or underscores
 * with at most one numeric segment per word, is indistinguishable from a resource name and stays. Two guards
 * make that safe: a value inside any carrier is removed whatever its shape, and a configured secret is removed
 * whatever its shape and in its encoded forms. Real token shapes are removed bare.
 */
export const NAME_SHAPED_VALUES = Object.freeze([
  "prod-us-east-2026",
  "my-project-123456",
  "sess-canary-COOKIE-31415926535897",
  "AWSLambdaBasicExecutionRole",
  "identitySecurityDefaultsEnforcementPolicy",
  "Authorization_RequestDenied",
  "ACTIVITY_STREAM_ENABLED",
  "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "ec2-54-123-45-67",
  "arn:aws:iam::123456789012:role/AWSServiceRoleForConfig",
  "/subscriptions/3fa85f64-5717-4562-b3fc-2c963f66afa6/resourceGroups/rg-prod-2026",
]);

/** Values shaped like tokens: base64 symbols, digits scattered through letters, token casing, a hex digest, a JWT. */
export const TOKEN_SHAPED_VALUES = Object.freeze([
  CANARY.bearer,
  "0f9e8d7c6b5a4938a1b2c3d4",
  "Kq7Zx2Vw9Lm4Tp8R",
  "bPxRfiCYcanaryKEYqm",
  "dGhpcyBpcyBhIHNlY3JldA==",
  CANARY.jwt,
]);

/**
 * A configured secret with the characters the encoded forms change (space, quote, slash, plus, equals, at,
 * ampersand), so its JSON-escaped, URL-encoded, base64, and base64url forms all differ from the plain one.
 */
export const ENCODED_FORM_SECRET = 'p@ss "w0rd"/Zq7+Vx=Kn2&Rt9';

/** The plain, JSON-escaped, URL-encoded, base64, and base64url forms of a value. */
export function encodedFormsOf(value) {
  return [...new Set([
    value,
    JSON.stringify(value).slice(1, -1),
    encodeURIComponent(value),
    Buffer.from(value, "utf8").toString("base64"),
    Buffer.from(value, "utf8").toString("base64url"),
  ])];
}

/** Every carrier a value can ride in, with the text expected after the scrub. */
export function carrierCases(value) {
  return [
    ["Authorization header", `Authorization: Bearer ${value} was rejected`, "Authorization: Bearer [REDACTED] was rejected"],
    ["Basic scheme", `proxy replayed Basic ${value} upstream`, "proxy replayed Basic [REDACTED] upstream"],
    ["Token scheme", `Token ${value} expired`, "Token [REDACTED] expired"],
    ["ApiKey scheme", `ApiKey ${value} rejected`, "ApiKey [REDACTED] rejected"],
    ["Cookie header", `Cookie: session=${value}; theme=dark`, "Cookie: [REDACTED]"],
    ["Set-Cookie header", `Set-Cookie: sid=${value}; Path=/; HttpOnly`, "Set-Cookie: [REDACTED]"],
    ["x-api-key header", `x-api-key: ${value} was invalid`, "x-api-key: [REDACTED] was invalid"],
    ["session assignment", `session_id=${value} is stale`, "session_id=[REDACTED] is stale"],
    ["credential-named pair", `api_key=${value} too`, "api_key=[REDACTED] too"],
    ["quoted JSON pair", `{"client_secret":"${value}"}`, '{"client_secret":"[REDACTED]"}'],
    ["password pair", `password: ${value}.`, "password: [REDACTED]."],
    ["URL query pair", `see https://api.example.com/v1/x?token=${value} for details`, "see https://api.example.com/v1/x?[REDACTED] for details"],
    ["URL userinfo", `see https://auditor:${value}@api.example.com/v1/x for details`, "see https://api.example.com/v1/x for details"],
    // Codex P1 (quoted header value) and round 4 item F (X-Auth-Key / X-Auth-Email): quoted, single-quoted,
    // spaceless, and JSON-escaped forms; the X-Auth-* value is consumed through the end of the line like a cookie.
    ["quoted Authorization header", `Authorization: Bearer "${value}" was rejected`, 'Authorization: Bearer "[REDACTED]" was rejected'],
    ["single-quoted Authorization header", `Authorization: Bearer '${value}' was rejected`, "Authorization: Bearer '[REDACTED]' was rejected"],
    ["quoted Basic scheme", `WWW-Authenticate replayed Basic "${value}" upstream`, 'WWW-Authenticate replayed Basic "[REDACTED]" upstream'],
    ["quoted X-Auth-Key header", `X-Auth-Key: "${value}" was invalid`, "X-Auth-Key: [REDACTED]"],
    ["bare X-Auth-Key header", `X-Auth-Key: ${value} was invalid`, "X-Auth-Key: [REDACTED]"],
    ["bare X-Auth-Email header", `X-Auth-Email: ${value} was invalid`, "X-Auth-Email: [REDACTED]"],
    ["quoted x-api-key header without spaces", `x-api-key:"${value}" was invalid`, 'x-api-key:"[REDACTED]" was invalid'],
    ["single-quoted credential pair", `api_key='${value}' too`, "api_key='[REDACTED]' too"],
    ["quoted cookie attribute", `Cookie: sid="${value}"; theme=dark`, "Cookie: [REDACTED]"],
    ["JSON-escaped quoted header", `{\\"X-Auth-Key\\":\\"${value}\\"}`, '{\\"X-Auth-Key\\":\\"[REDACTED]\\"}'],
    ["JSON-escaped quoted Authorization", `{\\"Authorization\\":\\"Bearer ${value}\\"}`, '{\\"Authorization\\":\\"[REDACTED]\\"}'],
  ];
}

/**
 * Asserts the scrub boundary for one integration's redactErrorText: name-shaped values stay bare in prose,
 * a name-shaped value inside every carrier is removed, token-shaped values are removed bare, the configured
 * secret (registered by the caller before this runs) is removed in every encoded form, quoted non-credential
 * headers survive, and the integration's own fixed texts survive unchanged.
 */
export function assertScrubBoundary(assert, redact, { configuredSecret, mustKeep = [] } = {}) {
  for (const name of NAME_SHAPED_VALUES) {
    const text = `resource ${name} was not found`;
    assert.equal(redact(text), text, `name-shaped value stays bare: ${name}`);
  }
  for (const name of ["prod-us-east-2026", "sess-canary-COOKIE-31415926535897"]) {
    for (const [carrier, input, expected] of carrierCases(name)) {
      const output = redact(input);
      assert.equal(output, expected, `${carrier}: a name-shaped value inside a carrier is removed`);
      assertNoCanaryWindows(assert, output, [name], carrier);
      assert.equal(redact(`${output}) and retried`), `${output}) and retried`, `${carrier}: a second pass over the scrubbed carrier leaves the text after the marker alone`);
    }
  }
  for (const token of TOKEN_SHAPED_VALUES) {
    const output = redact(`rejected ${token} upstream`);
    assert.equal(output, "rejected [REDACTED] upstream", `token-shaped value is removed bare: ${token}`);
  }
  if (configuredSecret !== undefined) {
    const forms = encodedFormsOf(configuredSecret);
    assert.ok(forms.length >= 4, "the configured secret has distinct encoded forms");
    for (const form of forms) {
      const output = redact(`upstream echoed ${form} in its message`);
      assert.equal(output, "upstream echoed [REDACTED] in its message", `configured secret form is removed: ${form}`);
      assertNoCanaryWindows(assert, output, forms, `configured secret form ${form}`);
    }
  }
  for (const text of QUOTED_NON_CREDENTIAL_TEXTS) {
    assert.equal(redact(text), text, `quoted non-credential header survives the scrub: ${text}`);
  }
  for (const text of mustKeep) {
    assert.equal(redact(text), text, `fixed text survives the scrub: ${text}`);
  }
}
