import test from "node:test";
import assert from "node:assert/strict";

import {
  IntegrationError,
  REDACTED,
  describeErrorBody,
  describeFailedResponse,
  errorMessage,
  redactSecretValues,
  scrubDataText,
  scrubError,
  scrubErrorText,
} from "../dist/extensions/grc-tools/hardening/error-text.js";
import { NAME_SHAPED_VALUES, TOKEN_SHAPED_VALUES, assertCanariesDisjointFromFixture, assertCanaryFixture, assertNoCanaryWindows, leakedCanaryWindow } from "./helpers/error-canaries.mjs";
import { QUOTED_MUST_KEEP_HEADERS, countQuotedHeaderHits, quotedHeaderCases, unquotedControlCases } from "./helpers/quoted-header-matrix.mjs";

/**
 * The quoted carrier class (rule 9; Codex P1 "quoted header value" on #71, reviewer A's gap 26 on #70,
 * and the same class on main's shared scrubber at 9455b95): a quoted header or pair value is removed
 * whole up to its closing quote, whatever its shape and whatever it holds, in double or single quotes,
 * with or without spaces around the separator, and in JSON and JSON-escaped text at any depth. A
 * scrubber that stops at the opening quote leaves the value; one that stops at the first space inside
 * the quotes leaves the rest. Each row wraps a value and states the text expected once it is gone: the
 * quotes and the scheme word stay so the message still says what was replayed. The rows are the table
 * group A settled for its `credential-scrub.ts` (a053753), so both scrubbers agree row for row before
 * the batch 1 groups are rewired onto this library.
 */
const QUOTED_CARRIERS = Object.freeze([
  ["Cookie header, double-quoted pair value", (value) => `Cookie: sid="${value}"`, () => `Cookie: ${REDACTED}`],
  ["Cookie header, single-quoted pair value with attributes", (value) => `Cookie: sid='${value}'; Path=/; HttpOnly`, () => `Cookie: ${REDACTED}`],
  ["Cookie header, whole value quoted", (value) => `Cookie: "sid=${value}; Path=/"`, () => `Cookie: "${REDACTED}"`],
  ["Set-Cookie header, quoted pair value", (value) => `Set-Cookie: JSESSIONID="${value}"; Secure`, () => `Set-Cookie: ${REDACTED}`],
  ["Cookie JSON pair", (value) => `"Cookie": "sid=${value}"`, () => `"Cookie": "${REDACTED}"`],
  ["Cookie JSON pair, escaped", (value) => `\\"Cookie\\":\\"sid=${value}\\"`, () => `\\"Cookie\\":\\"${REDACTED}\\"`],
  ["X-Api-Key header, double quotes", (value) => `X-Api-Key: "${value}"`, () => `X-Api-Key: "${REDACTED}"`],
  ["X-Api-Key header, no spaces", (value) => `X-Api-Key:"${value}"`, () => `X-Api-Key:"${REDACTED}"`],
  ["X-Api-Key header, single quotes", (value) => `X-Api-Key: '${value}'`, () => `X-Api-Key: '${REDACTED}'`],
  ["X-Api-Key header, equals separator", (value) => `X-Api-Key = "${value}"`, () => `X-Api-Key = "${REDACTED}"`],
  ["X-Api-Key JSON pair", (value) => `"X-Api-Key": "${value}"`, () => `"X-Api-Key": "${REDACTED}"`],
  ["X-Api-Key JSON pair, escaped", (value) => `\\"X-Api-Key\\": \\"${value}\\"`, () => `\\"X-Api-Key\\": \\"${REDACTED}\\"`],
  ["X-Api-Key JSON pair, escaped twice", (value) => `\\\\\\"X-Api-Key\\\\\\": \\\\\\"${value}\\\\\\"`, () => `\\\\\\"X-Api-Key\\\\\\": \\\\\\"${REDACTED}\\\\\\"`],
  ["X-Auth-Token header, quoted", (value) => `X-Auth-Token: "${value}"`, () => `X-Auth-Token: "${REDACTED}"`],
  ["custom x- credential header, quoted", (value) => `X-Vendor-Session-Key: '${value}'`, () => `X-Vendor-Session-Key: '${REDACTED}'`],
  ["Authorization header, quoted value after the scheme", (value) => `Authorization: Bearer "${value}"`, () => `Authorization: Bearer "${REDACTED}"`],
  ["Authorization header, single-quoted value after the scheme", (value) => `Authorization: Bearer '${value}'`, () => `Authorization: Bearer '${REDACTED}'`],
  ["Authorization header, scheme inside the quotes", (value) => `Authorization: "Bearer ${value}"`, () => `Authorization: "Bearer ${REDACTED}"`],
  ["Authorization header, Basic quoted", (value) => `Authorization: Basic "${value}"`, () => `Authorization: Basic "${REDACTED}"`],
  ["Authorization JSON pair", (value) => `"Authorization": "Bearer ${value}"`, () => `"Authorization": "Bearer ${REDACTED}"`],
  ["Authorization JSON pair, escaped", (value) => `\\"Authorization\\": \\"Bearer ${value}\\"`, () => `\\"Authorization\\": \\"Bearer ${REDACTED}\\"`],
  ["Authorization JSON pair, escaped, no spaces", (value) => `\\"Authorization\\":\\"Bearer ${value}\\"`, () => `\\"Authorization\\":\\"Bearer ${REDACTED}\\"`],
  ["Proxy-Authorization header, quoted", (value) => `Proxy-Authorization: 'Basic ${value}'`, () => `Proxy-Authorization: 'Basic ${REDACTED}'`],
  ["Bearer scheme in prose, quoted", (value) => `upstream rejected Bearer "${value}" mid-sentence`, () => `upstream rejected Bearer "${REDACTED}" mid-sentence`],
  ["session assignment, quoted", (value) => `session_id: "${value}"`, () => `session_id: "${REDACTED}"`],
  ["sid JSON pair, escaped", (value) => `\\"sid\\": \\"${value}\\"`, () => `\\"sid\\": \\"${REDACTED}\\"`],
  ["password JSON pair holding spaces", (value) => `{"password": "${value} with spaces"}`, () => `{"password": "${REDACTED}"}`],
  ["token pair, escaped", (value) => `\\"token\\":\\"${value}\\"`, () => `\\"token\\":\\"${REDACTED}\\"`],
  ["unterminated quoted header value", (value) => `X-Api-Key: "${value}`, () => `X-Api-Key: "${REDACTED}`],
  [
    "request options echoed as JSON",
    (value) => `{"headers":{"Authorization":"Bearer ${value}","X-Api-Key":"${value}","Cookie":"sid=${value}","Accept":"application/json"}}`,
    () => `{"headers":{"Authorization":"Bearer ${REDACTED}","X-Api-Key":"${REDACTED}","Cookie":"${REDACTED}","Accept":"application/json"}}`,
  ],
]);

/** Random-looking values planted in the quoted carriers; the first is name-shaped and stays when it stands bare. */
const QUOTED_CANARIES = Object.freeze(["RulingNameShapedProbeZq", "BPt5mgDrRZ5YyLTHaQPepJUYQbGYRCjG"]);

/**
 * Quoted values under names that carry no credential, and the JSON case in which a scheme word closes
 * one string (`"Basic "`) and must not open a value in the next; every row comes back unchanged.
 */
const MUST_KEEP = Object.freeze([
  'Content-Type: "application/json"',
  '"Content-Type": "application/json"',
  '\\"Content-Type\\": \\"application/json\\"',
  "Accept: 'application/json'",
  'Content-Type: "text/html; charset=utf-8"',
  'User-Agent: "grclanker/1.0"',
  '"Content-Length": "5120"',
  'X-Request-Id: "req-2026-09-22-zq"',
  'X-Rate-Limit-Remaining: "0"',
  'X-Snowflake-Authorization-Token-Type: "KEYPAIR_JWT"',
  '{"headers":{"Accept":"application/json","Content-Type":"application/json"}}',
  "the Cookie header was rejected and the Authorization header was missing",
  '{"type": "Basic ", "scheme": "bearer"}',
  '{"type": "Bearer ", "note": "token authentication is required"}',
  'X-Api-Key: ""',
  "Authorization: Bearer",
  '"cookies": ["consent", "theme"]',
  "cookies: enabled",
  "Basic authentication is disabled for this deployment",
  "Bearer token authentication is required",
  "Bearer token-based auth is required",
  "third-party OAuth sign-in (codes 1, 11) and Zoom-held passwords",
  "the OAuth 2.0 device flow",
  'Bearer realm="api", error="invalid_token"',
  "InvalidAuthenticationToken: Access token has expired.",
  "access_tokens: seen 40 of 120",
  ...QUOTED_MUST_KEEP_HEADERS,
]);

/** Every scrub the library exposes for text, each returning the text it produces. */
const SCRUBS = Object.freeze([
  ["scrubErrorText", (text) => scrubErrorText(text)],
  ["scrubDataText", (text) => scrubDataText(text)],
  ["scrubError", (text) => scrubError(new Error(text)).message],
  ["errorMessage", (text) => errorMessage(new Error(text))],
  ["IntegrationError", (text) => new IntegrationError(text).message],
  ["redactSecretValues", (text) => redactSecretValues(text)],
]);

/** The scrubs that keep the text's own whitespace, so an exact expected output can be compared. */
const EXACT_SCRUBS = SCRUBS.filter(([name]) => name !== "errorMessage");

/**
 * The values planted in every row: the two canaries, group A's hyphenated name-shaped canary, and the
 * group D name- and token-shaped values that begin like a credential and share no 6-character window
 * with the carriers or the must-keep rows (`Authorization_RequestDenied` shares `Authori` with the
 * header name; a value opening with "/" is a path, which a quoted value after a bare scheme word in
 * prose never begins with), so a windowed leak assertion can fail only on a real echo.
 */
function plantedValues() {
  const groupD = [...NAME_SHAPED_VALUES, ...TOKEN_SHAPED_VALUES].filter((value) => /^[A-Za-z0-9]/.test(value) && value !== "Authorization_RequestDenied");
  return [...QUOTED_CANARIES, "canary-empty-team-zq", ...groupD];
}

test("quoted carriers fixture: the planted values look random and share no 6-character window with the carriers or the must-keep rows", () => {
  const legitimate = new Map([...QUOTED_CARRIERS.map(([label, carrier]) => [label, carrier("")]), ...MUST_KEEP.map((text, index) => [`must-keep ${index}`, text])]);
  assertCanaryFixture(assert, QUOTED_CANARIES, legitimate, "quoted carriers");
  assertCanariesDisjointFromFixture(assert, plantedValues(), legitimate, "quoted carriers, name-shaped values");
  assert.equal(QUOTED_CARRIERS.length, 30, "the table is group A's 30 rows");
  assert.ok(plantedValues().length >= 12, "several name-shaped values ride in every row");
});

test("quoted carriers: a quoted header or pair value is removed whole, in double or single quotes, with or without spaces, and JSON-escaped, through every scrub", () => {
  const [nameShapedCanary] = QUOTED_CANARIES;
  const bare = (value) => `the resource ${value} was not readable`;
  assert.equal(scrubDataText(bare(nameShapedCanary)), bare(nameShapedCanary), "the name-shaped canary stays bare in data text, so only the carrier can remove it there");
  assert.equal(scrubErrorText(bare("sess-canary-COOKIE-31415926535897")), bare("sess-canary-COOKIE-31415926535897"), "a name-shaped value stays bare in error text, so only the carrier can remove it there");
  for (const [label, carrier, expected] of QUOTED_CARRIERS) {
    for (const value of plantedValues()) {
      for (const [scrubName, scrub] of EXACT_SCRUBS) {
        const scrubbed = scrub(carrier(value));
        assert.equal(scrubbed, expected(), `${scrubName}: ${label} with ${value}`);
        assertNoCanaryWindows(assert, scrubbed, [value], `${scrubName}: ${label} with ${value}`);
        assert.equal(scrub(scrubbed), scrubbed, `${scrubName}: ${label} with ${value}: a second pass changed the text`);
      }
      assertNoCanaryWindows(assert, errorMessage(new Error(carrier(value))), [value], `errorMessage: ${label} with ${value}`);
    }
  }
});

test("quoted carriers: the reported forms, a plain word in quotes included, come out with the value gone and the quotes and scheme kept", () => {
  assert.equal(scrubErrorText('Cookie: sid="prod-cookie"'), `Cookie: ${REDACTED}`);
  assert.equal(scrubErrorText('X-Api-Key: "prod-key"'), `X-Api-Key: "${REDACTED}"`);
  assert.equal(scrubErrorText('X-Auth-Key: "prod-key"'), `X-Auth-Key: "${REDACTED}"`);
  assert.equal(scrubErrorText('Authorization: Bearer "token"'), `Authorization: Bearer "${REDACTED}"`);
  assert.equal(scrubErrorText("Authorization: Bearer 'token'"), `Authorization: Bearer '${REDACTED}'`);
  assert.equal(scrubErrorText('Authorization:"Bearer token"'), `Authorization:"Bearer ${REDACTED}"`);
  assert.equal(scrubErrorText('\\"Authorization\\": \\"Bearer token\\"'), `\\"Authorization\\": \\"Bearer ${REDACTED}\\"`);
  assert.equal(scrubErrorText('"password": "correct horse battery staple"'), `"password": "${REDACTED}"`);
  assert.equal(scrubErrorText('X-Api-Key: "a\\"b"'), `X-Api-Key: "${REDACTED}"`, "an escaped quote inside a plain quoted value is content");
  assert.equal(scrubErrorText('\\"X-Api-Key\\": \\"a\\\\\\"b\\"'), `\\"X-Api-Key\\": \\"${REDACTED}\\"`, "the JSON-escaped form of an escaped quote is content too");
  assert.equal(scrubErrorText('{"headers":{"X-Api-Key":"v\\"alue"},"status":401}'), `{"headers":{"X-Api-Key":"${REDACTED}"},"status":401}`, "the value ends at its own closing quote, not at the escaped one");
  assert.equal(scrubErrorText('{"detail":"header X-Api-Key: \\"pk\\" rejected"}'), `{"detail":"header X-Api-Key: \\"${REDACTED}\\" rejected"}`, "a quoted header inside a JSON string ends at the escaped closing quote, not at the string's own");
  assert.equal(scrubErrorText('X-Api-Key: "unterminated value with spaces\nnext line'), `X-Api-Key: "${REDACTED}\nnext line`, "an unterminated quote runs to the end of the line");
  assert.equal(scrubErrorText(`X-Api-Key: "${REDACTED}"`), `X-Api-Key: "${REDACTED}"`, "a marker inside the quotes is left alone");
});

test("quoted carriers: every must-keep row comes back unchanged from every scrub", () => {
  for (const text of MUST_KEEP) {
    for (const [scrubName, scrub] of EXACT_SCRUBS) {
      assert.equal(scrub(text), text, `${scrubName} changed ${JSON.stringify(text)}`);
    }
  }
});

test("quoted carriers: reviewer A's 1872-case matrix has no hit under any scrub, the must-keep headers stay, and the unquoted control holds", () => {
  const leaked = (output, value) => leakedCanaryWindow(typeof output === "string" ? output : JSON.stringify(output), value) !== undefined;
  const cases = quotedHeaderCases();
  assert.equal(cases.length, 1872);
  for (const [scrubName, scrub] of [
    ["scrubErrorText", (text) => scrubErrorText(text)],
    ["scrubDataText", (text) => scrubDataText(text)],
    ["redactSecretValues", (text) => redactSecretValues({ message: text, headers: [text] })],
  ]) {
    const summary = countQuotedHeaderHits(scrub, leaked);
    assert.equal(summary.cases, 1872, scrubName);
    assert.deepEqual({ hits: summary.hits, examples: summary.examples }, { hits: 0, examples: [] }, `${scrubName}: quoted header values leaked`);
    for (const header of QUOTED_MUST_KEEP_HEADERS) {
      const output = scrub(header);
      assert.equal(typeof output === "string" ? output : output.message, header, `${scrubName} changed a non-credential quoted header`);
    }
    for (const control of unquotedControlCases()) {
      assert.ok(!leaked(scrub(control.text), control.value), `${scrubName}: unquoted control leaked: ${control.label}`);
    }
  }
  for (const testCase of cases) {
    const once = scrubErrorText(testCase.text);
    assert.equal(scrubErrorText(once), once, `not idempotent: ${testCase.label}`);
    assert.ok(once.includes(REDACTED), `no marker written: ${testCase.label}`);
  }
});

/**
 * The compound-line rule (reviewer B's early signal on #62, reviewer A's gaps 27 and 28 on #70, the
 * sweep-wide rule with reviewer A's refinement), identical in every scrubber so they agree before the
 * batch 1 rewire: a quoted value ends at its closing quote; an unquoted cookie or header value, and a
 * quoted one that is never closed, ends at the `;` or `,` that introduces the next `Name:` token on the
 * line, or at the end of the line; the next header on the same line keeps its name and gets its own
 * carrier treatment. Each row plants two values (`a` in the first carrier, `b` in the second) and states
 * the exact text expected once both are gone, plus the following header names and values that must
 * survive. Group A's two edge shapes are the unterminated cookie quote that used to pair with the next
 * header's opening quote and the cookie attribute loop that used to swallow `; X-Api-Key: ...` as an
 * attribute; reviewer A's gap 28 is the closed quoted value that holds `; Name:` and is one value.
 */
const COMPOUND_LINES = Object.freeze([
  [
    "quoted cookie pair, quoted X-Api-Key, quoted Content-Type",
    (a, b) => `Cookie: sid="${a}"; X-Api-Key: "${b}"; Content-Type: "application/json"`,
    () => `Cookie: ${REDACTED}; X-Api-Key: "${REDACTED}"; Content-Type: "application/json"`,
    ["X-Api-Key:", 'Content-Type: "application/json"'],
  ],
  [
    "unquoted cookie pair, quoted X-Api-Key, quoted Content-Type",
    (a, b) => `Cookie: sid=${a}; X-Api-Key: "${b}"; Content-Type: "application/json"`,
    () => `Cookie: ${REDACTED}; X-Api-Key: "${REDACTED}"; Content-Type: "application/json"`,
    ["X-Api-Key:", 'Content-Type: "application/json"'],
  ],
  [
    "every value unquoted",
    (a, b) => `Cookie: sid=${a}; X-Api-Key: ${b}; Content-Type: application/json`,
    () => `Cookie: ${REDACTED}; X-Api-Key: ${REDACTED}; Content-Type: application/json`,
    ["X-Api-Key:", "Content-Type: application/json"],
  ],
  [
    "cookie with attributes, then quoted X-Api-Key and Content-Type (group A edge: the attribute loop)",
    (a, b) => `Cookie: sid=${a}; Path=/; HttpOnly; X-Api-Key: "${b}"; Content-Type: "application/json"`,
    () => `Cookie: ${REDACTED}; X-Api-Key: "${REDACTED}"; Content-Type: "application/json"`,
    ["X-Api-Key:", 'Content-Type: "application/json"'],
  ],
  [
    "cookie with attributes, comma before the next header",
    (a, b) => `Cookie: sid=${a}; Path=/, X-Api-Key: "${b}"`,
    () => `Cookie: ${REDACTED}, X-Api-Key: "${REDACTED}"`,
    ["X-Api-Key:"],
  ],
  [
    "two quoted headers on one line, comma-separated",
    (a, b) => `X-Api-Key: "${a}", Authorization: Bearer "${b}"`,
    () => `X-Api-Key: "${REDACTED}", Authorization: Bearer "${REDACTED}"`,
    ["Authorization: Bearer"],
  ],
  [
    "two quoted headers on one line, scheme inside the quotes",
    (a, b) => `Authorization: "Bearer ${a}"; X-Api-Key: "${b}"`,
    () => `Authorization: "Bearer ${REDACTED}"; X-Api-Key: "${REDACTED}"`,
    ["X-Api-Key:"],
  ],
  [
    "two quoted headers then a plain quoted header",
    (a, b) => `X-Auth-Token: '${a}'; Cookie: sid='${b}'; Accept: 'text/html'`,
    () => `X-Auth-Token: '${REDACTED}'; Cookie: ${REDACTED}; Accept: 'text/html'`,
    ["Cookie:", "Accept: 'text/html'"],
  ],
  [
    "quoted header followed by a JSON fragment",
    (a) => `X-Api-Key: "${a}" {"status":401,"error":"denied"}`,
    () => `X-Api-Key: "${REDACTED}" {"status":401,"error":"denied"}`,
    ['{"status":401,"error":"denied"}'],
  ],
  [
    "unquoted cookie followed by a JSON fragment",
    (a) => `Cookie: sid=${a} {"error":"invalid session"}`,
    () => `Cookie: ${REDACTED} {"error":"invalid session"}`,
    ['{"error":"invalid session"}'],
  ],
  [
    "unquoted header, comma, then a JSON fragment",
    (a) => `X-Api-Key: ${a}, {"Content-Type":"application/json"}`,
    () => `X-Api-Key: ${REDACTED}, {"Content-Type":"application/json"}`,
    ['{"Content-Type":"application/json"}'],
  ],
  [
    "JSON-escaped compound line inside a JSON string",
    (a, b) => `{"detail":"upstream sent Cookie: sid=\\"${a}\\"; X-Api-Key: \\"${b}\\"; Content-Type: \\"application/json\\""}`,
    () => `{"detail":"upstream sent Cookie: ${REDACTED}; X-Api-Key: \\"${REDACTED}\\"; Content-Type: \\"application/json\\""}`,
    ["X-Api-Key:", 'Content-Type: \\"application/json\\"'],
  ],
  [
    "JSON-escaped compound line, unquoted cookie value",
    (a, b) => `{"detail":"upstream sent Cookie: sid=${a}; X-Api-Key: \\"${b}\\"; Content-Type: \\"application/json\\""}`,
    () => `{"detail":"upstream sent Cookie: ${REDACTED}; X-Api-Key: \\"${REDACTED}\\"; Content-Type: \\"application/json\\""}`,
    ["X-Api-Key:", 'Content-Type: \\"application/json\\"'],
  ],
  [
    "unterminated cookie quote, then a quoted header (group A edge: the quote pairing)",
    (a, b) => `Cookie: sid="${a}; X-Api-Key: "${b}"`,
    () => `Cookie: ${REDACTED}; X-Api-Key: "${REDACTED}"`,
    ["X-Api-Key:"],
  ],
  [
    "unterminated cookie quote, a plain header, then a quoted header",
    (a, b) => `Cookie: sid="${a}; Content-Type: text; X-Api-Key: "${b}"`,
    () => `Cookie: ${REDACTED}; Content-Type: text; X-Api-Key: "${REDACTED}"`,
    ["Content-Type: text", "X-Api-Key:"],
  ],
  [
    "unterminated cookie quote, then a JSON-escaped quoted header",
    (a, b) => `Cookie: sid="${a}; X-Api-Key: \\"${b}\\"`,
    () => `Cookie: ${REDACTED}; X-Api-Key: \\"${REDACTED}\\"`,
    ["X-Api-Key:"],
  ],
  [
    "unterminated whole-quoted cookie, then a quoted header",
    (a, b) => `Cookie: "sid=${a}; X-Api-Key: "${b}"`,
    () => `Cookie: "${REDACTED}; X-Api-Key: "${REDACTED}"`,
    ["X-Api-Key:"],
  ],
  [
    "unterminated quoted header, then a quoted Authorization header",
    (a, b) => `X-Api-Key: "${a}; Authorization: "Bearer ${b}"`,
    () => `X-Api-Key: "${REDACTED}; Authorization: "Bearer ${REDACTED}"`,
    ["Authorization:"],
  ],
  [
    "closed quoted value holding `; Name:` is one value (reviewer A's gap 28)",
    (a, b) => `X-Api-Key: "${a}; note: ${b}" rejected`,
    () => `X-Api-Key: "${REDACTED}" rejected`,
    ["rejected"],
  ],
  [
    "closed quoted Content-Type holding `;` before a quoted header",
    (a) => `Content-Type: "text/html; charset=utf-8"; X-Api-Key: "${a}"`,
    () => `Content-Type: "text/html; charset=utf-8"; X-Api-Key: "${REDACTED}"`,
    ['Content-Type: "text/html; charset=utf-8"', "X-Api-Key:"],
  ],
]);

/** Pairs of planted values: each value rides in the first carrier once and in the second carrier once. */
function plantedPairs() {
  const values = plantedValues();
  return values.map((value, index) => [value, values[(index + 1) % values.length]]);
}

test("compound lines fixture: the rows share no 6-character window with the planted values", () => {
  const legitimate = new Map(COMPOUND_LINES.map(([label, line]) => [label, line("", "")]));
  assertCanariesDisjointFromFixture(assert, plantedValues(), legitimate, "compound lines");
  assert.equal(COMPOUND_LINES.length, 20);
});

test("compound lines: each credential value goes, the following header names and the Content-Type value stay, through every scrub, and a second pass is a no-op", () => {
  for (const [label, line, expected, keeps] of COMPOUND_LINES) {
    for (const [a, b] of plantedPairs()) {
      const input = line(a, b);
      const planted = [a, b].filter((value) => input.includes(value));
      for (const [scrubName, scrub] of EXACT_SCRUBS) {
        const output = scrub(input);
        assert.equal(output, expected(), `${scrubName}: ${label} with ${a} and ${b}`);
        for (const text of keeps) assert.ok(output.includes(text), `${scrubName}: ${label}: ${JSON.stringify(text)} did not survive in ${output}`);
        assertNoCanaryWindows(assert, output, planted, `${scrubName}: ${label}`);
        assert.equal(scrub(output), output, `${scrubName}: ${label}: a second pass changed the text`);
      }
      assertNoCanaryWindows(assert, errorMessage(new Error(input)), planted, `errorMessage: ${label}`);
    }
  }
});

test("compound lines: a documented message field of a 502 body carrying one comes out of describeFailedResponse and describeErrorBody with the same rendering", () => {
  for (const [label, line, expected] of COMPOUND_LINES) {
    for (const [a, b] of plantedPairs().slice(0, 4)) {
      const input = line(a, b);
      const body = JSON.stringify({ message: `upstream sent ${input}` });
      const note = describeErrorBody("application/json", body);
      assert.equal(note, `upstream sent ${expected()}`, `describeErrorBody: ${label}`);
      const described = describeFailedResponse({ method: "GET", endpoint: "/v1/users", status: 502, statusText: "Bad Gateway", contentType: "application/json", body });
      assert.equal(described, `GET /v1/users failed with 502 Bad Gateway: upstream sent ${expected()}`, `describeFailedResponse: ${label}`);
      assertNoCanaryWindows(assert, described, [a, b].filter((value) => input.includes(value)), `describeFailedResponse: ${label}`);
      assert.equal(scrubErrorText(described), described, `describeFailedResponse: ${label}: a further scrub changed the line`);
    }
  }
});
