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
  "Date: Mon, 22 Sep 2026 12:30:00 GMT",
  'Date: "Mon, 22 Sep 2026 12:30:00 GMT"',
  "Last-Modified: Mon, 22 Sep 2026 12:30:00 GMT; Content-Length: 512",
  'User-Agent: "grclanker/1.0"',
  '"Content-Length": "5120"',
  'X-Request-Id: "req-2026-09-22-zq"',
  'X-Rate-Limit-Remaining: "0"',
  '{"headers":{"Accept":"application/json","Content-Type":"application/json"}}',
  "the Cookie header was rejected and the Authorization header was missing",
  '{"type": "Basic ", "scheme": "bearer"}',
  '{"type": "Bearer ", "note": "token authentication is required"}',
  'X-Api-Key: ""',
  "Authorization: Bearer",
  '"cookies": ["consent", "theme"]',
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
  // A quoted or bare value under a header or key that `isCredentialKey` classifies is a carrier value
  // whatever its shape (review of #78, gap 1; main at 02967cc redacted this too).
  for (const [text, expected] of [["cookies: enabled", `cookies: ${REDACTED}`]]) {
    for (const [scrubName, scrub] of EXACT_SCRUBS) {
      assert.equal(scrub(text), expected, `${scrubName} on ${JSON.stringify(text)}`);
    }
  }
  // A header or key whose final segment is a setting suffix is a setting (coordinator ruling on the
  // settings reviewer A saw over-redacted): the descriptor value stays, quoted or bare, in every
  // scrub, and the same key with a token-shaped value loses only the token.
  for (const text of ['X-Snowflake-Authorization-Token-Type: "KEYPAIR_JWT"', "X-Snowflake-Authorization-Token-Type: KEYPAIR_JWT", 'x-auth-mode: "legacy"', "x-auth-mode: legacy"]) {
    for (const [scrubName, scrub] of EXACT_SCRUBS) {
      assert.equal(scrub(text), text, `${scrubName} on ${JSON.stringify(text)}`);
    }
  }
  assert.equal(scrubDataText('X-Snowflake-Authorization-Token-Type: "Kq7Zx2Vw9Lm4Tp8RwQ12"'), `X-Snowflake-Authorization-Token-Type: "${REDACTED}"`);
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
  [
    "unquoted cookie, then a Date header whose value holds a comma and colons, then a quoted header (control)",
    (a, b) => `Cookie: sid=${a}; Date: Mon, 22 Sep 2026 12:30:00 GMT; X-Api-Key: "${b}"`,
    () => `Cookie: ${REDACTED}; Date: Mon, 22 Sep 2026 12:30:00 GMT; X-Api-Key: "${REDACTED}"`,
    ["Date: Mon, 22 Sep 2026 12:30:00 GMT", "X-Api-Key:"],
  ],
  [
    "unterminated cookie quote, then a Date header, then a quoted header (control)",
    (a, b) => `Cookie: sid="${a}; Date: Mon, 22 Sep 2026 12:30:00 GMT; X-Api-Key: "${b}"`,
    () => `Cookie: ${REDACTED}; Date: Mon, 22 Sep 2026 12:30:00 GMT; X-Api-Key: "${REDACTED}"`,
    ["Date: Mon, 22 Sep 2026 12:30:00 GMT", "X-Api-Key:"],
  ],
  [
    "quoted Date header before a quoted Authorization header (control)",
    (a) => `Date: "Mon, 22 Sep 2026 12:30:00 GMT"; Authorization: Bearer "${a}"`,
    () => `Date: "Mon, 22 Sep 2026 12:30:00 GMT"; Authorization: Bearer "${REDACTED}"`,
    ['Date: "Mon, 22 Sep 2026 12:30:00 GMT"', "Authorization: Bearer"],
  ],
  [
    "unquoted header, comma, then a Date header with its own comma (control)",
    (a) => `X-Api-Key: ${a}, Date: Mon, 22 Sep 2026 12:30:00 GMT`,
    () => `X-Api-Key: ${REDACTED}, Date: Mon, 22 Sep 2026 12:30:00 GMT`,
    ["Date: Mon, 22 Sep 2026 12:30:00 GMT"],
  ],
  [
    // The Expires attribute's date holds a comma, which ends the cookie's attribute run under the rule; the remainder is a date, and the next header keeps its name.
    "Set-Cookie with an Expires date attribute before the next header",
    (a, b) => `Set-Cookie: session=${a}; Expires=Mon, 22 Sep 2026 12:30:00 GMT; Path=/; X-Api-Key: "${b}"`,
    () => `Set-Cookie: ${REDACTED}, 22 Sep 2026 12:30:00 GMT; Path=/; X-Api-Key: "${REDACTED}"`,
    ["22 Sep 2026 12:30:00 GMT; Path=/", "X-Api-Key:"],
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
  assert.equal(COMPOUND_LINES.length, 25);
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

/**
 * CodeRabbit (#78), discussion_r4076392614: the cookie attribute pattern allowed only `[A-Za-z0-9_-]`
 * in a later pair or attribute name, so `Cookie: theme=dark; my.sid=<v>` ended the scan at the `.`
 * and left `Cookie: [REDACTED].sid=<v>`, which no later rule removed. A cookie name may hold any RFC
 * 6265 token character (`!#$%&'*+-.^_` + "`|~" and alphanumerics; real names: `ASP.NET_SessionId`,
 * `.AspNetCore.Session`). The later-name class is now the first-pair-name class less `:`, so a
 * `; Name:` token still ends the value for the next header on a compound line. Each row plants the
 * first value in the cookie and, where a second header follows, the second value in that header.
 */
const RFC6265_COOKIE_NAME_ROWS = Object.freeze([
  ["dot in a later pair name", (a) => `Cookie: theme=dark; my.sid=${a}`, () => `Cookie: ${REDACTED}`, []],
  ["ASP.NET session name then an attribute", (a) => `Cookie: theme=dark; ASP.NET_SessionId=${a}; Path=/`, () => `Cookie: ${REDACTED}`, []],
  ["leading-dot ASP.NET Core name with attributes", (a) => `Set-Cookie: .AspNetCore.Session=${a}; HttpOnly; SameSite=Lax`, () => `Set-Cookie: ${REDACTED}`, []],
  ["leading-dot name as a later pair", (a) => `Cookie: theme=dark; .AspNetCore.Antiforgery.x9=${a}; lang=en`, () => `Cookie: ${REDACTED}`, []],
  ["every RFC 6265 token character in a name before the credential pair", (a) => `Cookie: a=b; x!y#z$w%u&t*s+r^q\`p|o~n=1; sid=${a}`, () => `Cookie: ${REDACTED}`, []],
  ["token-character name carrying the value", (a) => `Cookie: lang=en; ~sid!=${a}; Path=/`, () => `Cookie: ${REDACTED}`, []],
  ["dot name with a quoted value", (a) => `Cookie: theme=dark; my.sid="${a}"; Secure`, () => `Cookie: ${REDACTED}`, []],
  ["dot name in a Set-Cookie with spaced separators", (a) => `Set-Cookie: theme = dark; my.sid = ${a}; Path=/`, () => `Set-Cookie: ${REDACTED}`, []],
  ["dot name in a JSON pair", (a) => `"Cookie": "theme=dark; my.sid=${a}"`, () => `"Cookie": "${REDACTED}"`, []],
  ["dot name in a JSON-escaped pair", (a) => `\\"Cookie\\":\\"theme=dark; my.sid=${a}\\"`, () => `\\"Cookie\\":\\"${REDACTED}\\"`, []],
  [
    "compound control: dot name, then two headers keep their names",
    (a, b) => `Cookie: a=b; my.sid=${a}; X-Api-Key: ${b}; Content-Type: text/html`,
    () => `Cookie: ${REDACTED}; X-Api-Key: ${REDACTED}; Content-Type: text/html`,
    ["X-Api-Key:", "Content-Type: text/html"],
  ],
  [
    "compound control: token-character name, then a quoted header and a Date header",
    (a, b) => `Cookie: lang=en; ~sid!=${a}; X-Auth-Token: "${b}"; Date: Mon, 22 Sep 2026 12:30:00 GMT`,
    () => `Cookie: ${REDACTED}; X-Auth-Token: "${REDACTED}"; Date: Mon, 22 Sep 2026 12:30:00 GMT`,
    ["X-Auth-Token:", "Date: Mon, 22 Sep 2026 12:30:00 GMT"],
  ],
  [
    "compound control: ASP.NET name and attributes, then a Content-Type with a semicolon in quotes",
    (a) => `Set-Cookie: ASP.NET_SessionId=${a}; Path=/; HttpOnly; Content-Type: "text/html; charset=utf-8"`,
    () => `Set-Cookie: ${REDACTED}; Content-Type: "text/html; charset=utf-8"`,
    ['Content-Type: "text/html; charset=utf-8"'],
  ],
]);

test("CodeRabbit (#78): a later cookie name with a dot or any RFC 6265 token character keeps the scan going, so its value goes with the header, and the following header names still stay", () => {
  const legitimate = new Map(RFC6265_COOKIE_NAME_ROWS.map(([label, line]) => [label, line("", "")]));
  assertCanariesDisjointFromFixture(assert, plantedValues(), legitimate, "RFC 6265 cookie names");
  for (const [label, line, expected, keeps] of RFC6265_COOKIE_NAME_ROWS) {
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
      const body = JSON.stringify({ message: `upstream sent ${input}` });
      assert.equal(describeErrorBody("application/json", body), `upstream sent ${expected()}`, `describeErrorBody: ${label}`);
      const described = describeFailedResponse({ method: "GET", endpoint: "/v1/users", status: 502, statusText: "Bad Gateway", contentType: "application/json", body });
      assert.equal(described, `GET /v1/users failed with 502 Bad Gateway: upstream sent ${expected()}`, `describeFailedResponse: ${label}`);
      assertNoCanaryWindows(assert, described, planted, `describeFailedResponse: ${label}`);
    }
  }
  // The reported rendering, and the real names, with the literal value CodeRabbit used.
  assert.equal(scrubErrorText("Cookie: theme=dark; my.sid=hunter2"), `Cookie: ${REDACTED}`);
  assert.equal(scrubErrorText("Cookie: theme=dark; ASP.NET_SessionId=abc; Path=/"), `Cookie: ${REDACTED}`);
  assert.equal(scrubErrorText("Set-Cookie: .AspNetCore.Session=v; HttpOnly; SameSite=Lax"), `Set-Cookie: ${REDACTED}`);
  assert.equal(scrubErrorText("Cookie: a=b; my.sid=v; X-Api-Key: w; Content-Type: text/html"), `Cookie: ${REDACTED}; X-Api-Key: ${REDACTED}; Content-Type: text/html`);
  // A `; Name:` token after a dot-named pair is still the next header, not an attribute.
  assert.equal(scrubErrorText("Cookie: my.sid=v; X-Api-Key: w"), `Cookie: ${REDACTED}; X-Api-Key: ${REDACTED}`);
  assert.equal(scrubErrorText("Cookie: my.sid=v; Content-Type: text/html"), `Cookie: ${REDACTED}; Content-Type: text/html`);
});

/**
 * Leak-probe harness class 3 (apostrophe and dotted cookie names): `'` is an RFC 6265 token character,
 * so a cookie name or value may hold one (`my'pref`, `sid=O'<v>`, a name made of every token
 * character), and a scrubber whose classes leave it out ends the name or value at the apostrophe and
 * leaves the rest (`Cookie: [REDACTED]'<v>`). An apostrophe followed by another token character is
 * part of the name or value; one followed by a space, a bracket, sentence punctuation, or the end
 * closes a header line quoted whole in single quotes (see `SINGLE_QUOTED_HEADER_ROWS`). A following
 * header name may hold a `.` (`X.Api.Key:`), after a bare and after an unterminated quoted value; a
 * marker the query rule leaves under `&sid=` folds into the cookie's own marker.
 */
const APOSTROPHE_COOKIE_ROWS = Object.freeze([
  ["apostrophe in the first pair name, then the credential pair", (a) => `Cookie: my'pref=dark; sid=${a}`, () => `Cookie: ${REDACTED}`, []],
  ["apostrophe in a later pair name carrying the value", (a) => `Cookie: theme=dark; my'sid=${a}`, () => `Cookie: ${REDACTED}`, []],
  ["apostrophe inside the value", (a) => `Cookie: sid=O'${a}`, () => `Cookie: ${REDACTED}`, []],
  ["apostrophe inside the value, then attributes", (a) => `Cookie: sid=O'${a}; Path=/; HttpOnly`, () => `Cookie: ${REDACTED}`, []],
  ["apostrophe inside a Set-Cookie value with attributes", (a) => `Set-Cookie: sid=O'${a}; HttpOnly; SameSite=Lax`, () => `Set-Cookie: ${REDACTED}`, []],
  ["apostrophe inside an attribute value", (a) => `Set-Cookie: sid=${a}; Domain=o'reilly.example; Secure`, () => `Set-Cookie: ${REDACTED}`, []],
  ["apostrophe at the end of a name before =", (a) => `Cookie: sid'=${a}; Path=/`, () => `Cookie: ${REDACTED}`, []],
  ["every RFC 6265 token character, the apostrophe included, in the first name", (a, b) => `Cookie: !#$%&'*+^\`|~=${a}; X-Api-Key: ${b}`, () => `Cookie: ${REDACTED}; X-Api-Key: ${REDACTED}`, ["X-Api-Key:"]],
  ["every RFC 6265 token character, the apostrophe included, in a later name", (a) => `Cookie: theme=dark; a!b#c$d%e&f'g*h+i-j.k^l_m\`n|o~p=${a}`, () => `Cookie: ${REDACTED}`, []],
  ["query-rule marker under an ampersand name folded into one", (a) => `Cookie: &sid=${a}`, () => `Cookie: ${REDACTED}`, []],
  ["ampersand and hash names with JSON-escaped quoted values", (a, b) => `{"Cookie": "&sid=\\"${a}\\"; #tok=\\"${b}\\""}`, () => `{"Cookie": "${REDACTED}"}`, []],
  [
    "compound control: apostrophe value, then a dotted header and a Content-Type",
    (a, b) => `Cookie: sid=O'${a}; X.Api.Key: ${b}; Content-Type: text/html`,
    () => `Cookie: ${REDACTED}; X.Api.Key: ${REDACTED}; Content-Type: text/html`,
    ["X.Api.Key:", "Content-Type: text/html"],
  ],
  [
    "compound control: unterminated quoted value, then a dotted header and a Content-Type",
    (a, b) => `Cookie: sid="${a}; X.Api.Key: ${b}; Content-Type: text/html`,
    () => `Cookie: ${REDACTED}; X.Api.Key: ${REDACTED}; Content-Type: text/html`,
    ["X.Api.Key:", "Content-Type: text/html"],
  ],
  [
    "compound control: unterminated quoted header value, then a dotted header and a Date",
    (a, b) => `X-Api-Key: "${a}; X.Api.Key: ${b}; Date: Mon, 22 Sep 2026 12:30:00 GMT`,
    () => `X-Api-Key: "${REDACTED}; X.Api.Key: ${REDACTED}; Date: Mon, 22 Sep 2026 12:30:00 GMT`,
    ["X.Api.Key:", "Date: Mon, 22 Sep 2026 12:30:00 GMT"],
  ],
]);

test("leak-probe class 3: an apostrophe inside a cookie name or value is part of it, a name of every RFC 6265 token character carries its value, and a dotted following header keeps its name", () => {
  const legitimate = new Map(APOSTROPHE_COOKIE_ROWS.map(([label, line]) => [label, line("", "")]));
  assertCanariesDisjointFromFixture(assert, plantedValues(), legitimate, "apostrophe cookie rows");
  for (const [label, line, expected, keeps] of APOSTROPHE_COOKIE_ROWS) {
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
      const body = JSON.stringify({ message: `upstream sent ${input}` });
      assert.equal(describeErrorBody("application/json", body), `upstream sent ${expected()}`, `describeErrorBody: ${label}`);
      const described = describeFailedResponse({ method: "GET", endpoint: "/v1/users", status: 502, statusText: "Bad Gateway", contentType: "application/json", body });
      assert.equal(described, `GET /v1/users failed with 502 Bad Gateway: upstream sent ${expected()}`, `describeFailedResponse: ${label}`);
      assertNoCanaryWindows(assert, described, planted, `describeFailedResponse: ${label}`);
    }
  }
  // The literal renderings the class was reported with.
  assert.equal(scrubErrorText("Cookie: sid=O'hunter2"), `Cookie: ${REDACTED}`);
  assert.equal(scrubErrorText("Cookie: my'pref=dark; sid=hunter2"), `Cookie: ${REDACTED}`);
  assert.equal(scrubErrorText("Cookie: theme=dark; my'pref=hunter2"), `Cookie: ${REDACTED}`);
});

const REQUEST_ID_HEADER = "X-Request-Id: 5add72d1-b870-423d-a911-7f51772d8e6a";

/**
 * Review of #78 row E (CodeRabbit r4077655607 on `dd7426e`; leak-probe class 3): a cookie pair whose
 * name begins with "&" was matched by the query rule before the cookie reader ran, and the query
 * value took the ";" with it and ended the cookie there, so the later pair survived (`Cookie:
 * [REDACTED] pref=<v>`). The cookie reader now runs before the query rule and reads the pairs and
 * attributes whole, the ";" its boundary alone; a query value keeps running through ";" as on main
 * (Codex r4080768613 on #81, see the test after this one). A bare cookie run that ends in "="
 * (`theme=dark#sid=`, `theme=dark&sid=`) names one more pair whose JSON-escaped quoted value belongs
 * to it, so that value goes with the header rather than standing after the marker. The header after
 * the cookie keeps its name and value in every row.
 */
const AMPERSAND_COOKIE_ROWS = Object.freeze([
  ["ampersand name, then a later pair", (a, b) => `Cookie: &sid=${a}; pref=${b}`, () => `Cookie: ${REDACTED}`, []],
  ["ampersand name, then a later pair, then a header", (a, b) => `Cookie: &sid=${a}; pref=${b}; ${REQUEST_ID_HEADER}`, () => `Cookie: ${REDACTED}; ${REQUEST_ID_HEADER}`, [REQUEST_ID_HEADER]],
  ["hash name, then a later pair, then a header", (a, b) => `Cookie: #sid=${a}; pref=${b}; ${REQUEST_ID_HEADER}`, () => `Cookie: ${REDACTED}; ${REQUEST_ID_HEADER}`, [REQUEST_ID_HEADER]],
  ["ampersand name in Set-Cookie before attributes", (a) => `Set-Cookie: &sid=${a}; Path=/; HttpOnly`, () => `Set-Cookie: ${REDACTED}`, []],
  ["ampersand name in Set-Cookie before attributes and a header", (a) => `Set-Cookie: &sid=${a}; Path=/; HttpOnly; ${REQUEST_ID_HEADER}`, () => `Set-Cookie: ${REDACTED}; ${REQUEST_ID_HEADER}`, [REQUEST_ID_HEADER]],
  ["bare run ending in = after a hash, then a JSON-escaped quoted value", (a) => `Cookie: theme=dark#sid=\\"${a}\\"; ${REQUEST_ID_HEADER}`, () => `Cookie: ${REDACTED}; ${REQUEST_ID_HEADER}`, [REQUEST_ID_HEADER]],
  ["bare run ending in = after an ampersand, then a JSON-escaped quoted value", (a) => `Cookie: theme=dark&sid=\\"${a}\\"; ${REQUEST_ID_HEADER}`, () => `Cookie: ${REDACTED}; ${REQUEST_ID_HEADER}`, [REQUEST_ID_HEADER]],
  ["later ampersand name with a JSON-escaped quoted value", (a) => `Cookie: theme=dark; my&sid=\\"${a}\\"; ${REQUEST_ID_HEADER}`, () => `Cookie: ${REDACTED}; ${REQUEST_ID_HEADER}`, [REQUEST_ID_HEADER]],
  ["bare run ending in =, then a quoted value, then attributes", (a) => `Set-Cookie: theme=dark&sid="${a}"; Path=/; HttpOnly`, () => `Set-Cookie: ${REDACTED}`, []],
  ["ampersand name in a JSON-escaped header line", (a, b) => `{"detail":"Cookie: &sid=${a}; pref=${b}; ${REQUEST_ID_HEADER}"}`, () => `{"detail":"Cookie: ${REDACTED}; ${REQUEST_ID_HEADER}"}`, [REQUEST_ID_HEADER]],
  ["a query value runs through a semicolon, which is not a cookie separator there", (a) => `GET /v1/users?api_key=${a};x=1 failed`, () => `GET /v1/users?api_key=${REDACTED} failed`, [" failed"]],
]);

test("#78 row E: an ampersand or hash cookie name takes the whole header value with the pairs after it, a bare run ending in = owns the quoted value after it, and the following header stays", () => {
  const legitimate = new Map(AMPERSAND_COOKIE_ROWS.map(([label, line]) => [label, line("", "")]));
  assertCanariesDisjointFromFixture(assert, plantedValues(), legitimate, "ampersand cookie rows");
  for (const [label, line, expected, keeps] of AMPERSAND_COOKIE_ROWS) {
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
      const body = JSON.stringify({ message: `upstream sent ${input}` });
      assert.equal(describeErrorBody("application/json", body), `upstream sent ${expected()}`, `describeErrorBody: ${label}`);
      const described = describeFailedResponse({ method: "GET", endpoint: "/v1/users", status: 502, statusText: "Bad Gateway", contentType: "application/json", body });
      assert.equal(described, `GET /v1/users failed with 502 Bad Gateway: upstream sent ${expected()}`, `describeFailedResponse: ${label}`);
      assertNoCanaryWindows(assert, described, planted, `describeFailedResponse: ${label}`);
    }
  }
  // The renderings the review reported, with the literal values it used: the later pair survived.
  assert.equal(scrubErrorText("Cookie: &sid=hunter2; pref=dark"), `Cookie: ${REDACTED}`);
  assert.equal(scrubDataText("Cookie: theme=dark#sid=\\\"hunter2\\\"; X-Request-Id: 1"), `Cookie: ${REDACTED}; X-Request-Id: 1`);
  // A ";" does not end a bare query value: `URLSearchParams` reads it as part of the value.
  assert.equal(scrubErrorText("GET /v1/users?api_key=abcdef123456;page=2 failed"), `GET /v1/users?api_key=${REDACTED} failed`);
  // Base64 padding before the closing quote of a header line quoted whole: the quote after "==" runs
  // unterminated or encloses prose, so it ends the value rather than opening one.
  assert.equal(scrubErrorText("sent 'Cookie: sid=dGhpcyBpcyBhIHNlY3JldA==' then 'Accept: text/html'"), `sent 'Cookie: ${REDACTED}' then 'Accept: text/html'`);
  assert.equal(scrubErrorText("header -H 'Cookie: sid=dGhpcyBpcyBhIHNlY3JldA=='. Retry later"), `header -H 'Cookie: ${REDACTED}'. Retry later`);
  assert.equal(scrubErrorText('{"detail":"sent \\"Cookie: sid=dGhpcyBpcyBhIHNlY3JldA==\\", then \\"Accept: text/html\\""}'), `{"detail":"sent \\"Cookie: ${REDACTED}\\", then \\"Accept: text/html\\""}`);
  assert.equal(scrubErrorText('{"detail":"sent \\"Cookie: sid=dGhpcyBpcyBhIHNlY3JldA==\\" then \\"Accept: text/html\\""}'), `{"detail":"sent \\"Cookie: ${REDACTED}\\" then \\"Accept: text/html\\""}`);
});

/**
 * Codex r4080768613 on #81 (P1 at `5f75c90`): the ";" boundary row E gave the query value class
 * applied to every query pair, so `?token=<v>;<rest>` rendered `?token=[REDACTED];<rest>` and the tail
 * of the value survived, where `02967cc` and `b47f90d` redacted through the semicolon
 * (`URLSearchParams` reads ";" as part of the value). The value now goes whole again in the bare,
 * relative, absolute, slash-escaped, JSON, and JSON-escaped forms, and the cookie rows above keep
 * their rendering because the cookie reader owns the ";" and runs first. Mutation check (recorded in
 * the round 3 body): with ";" put back in the query value class every query row here renders
 * `[REDACTED];<rest>` and fails while the cookie rows still pass.
 */
const SEMICOLON_QUERY_ROWS = Object.freeze([
  ["bare query string", (value) => `?token=${value}`, () => `?token=${REDACTED}`],
  ["relative path", (value) => `GET /v1/x?token=${value} HTTP/1.1`, () => `GET /v1/x?token=${REDACTED} HTTP/1.1`],
  ["later pair on a relative path", (value) => `/v1/x?a=1&token=${value}&b=2`, () => `/v1/x?a=1&token=${REDACTED}&b=2`],
  ["bare later pair", (value) => `&api_key=${value}`, () => `&api_key=${REDACTED}`],
  ["absolute URL", (value) => `https://host/v1/x?token=${value}`, () => `https://host/v1/x?${REDACTED}`],
  ["absolute URL in a sentence", (value) => `GET https://host/v1/x?token=${value} failed with 401`, () => `GET https://host/v1/x?${REDACTED} failed with 401`],
  ["slash-escaped URL", (value) => `https:\\/\\/host\\/v1\\/x?token=${value}`, () => `https:\\/\\/host\\/v1\\/x?${REDACTED}`],
  ["relative path in a JSON string", (value) => `{"url":"/v1/x?token=${value}"}`, () => `{"url":"/v1/x?token=${REDACTED}"}`],
  ["absolute URL in a JSON string", (value) => `{"url":"https://host/v1/x?token=${value}"}`, () => `{"url":"https://host/v1/x?${REDACTED}"}`],
  ["relative path in a JSON-escaped string", (value) => `{\\"url\\":\\"/v1/x?token=${value}\\"}`, () => `{\\"url\\":\\"/v1/x?token=${REDACTED}\\"}`],
  ["slash-escaped URL in a JSON-escaped string", (value) => `{\\"url\\":\\"https:\\/\\/host\\/v1\\/x?token=${value}\\"}`, () => `{\\"url\\":\\"https:\\/\\/host\\/v1\\/x?${REDACTED}\\"}`],
]);

test("Codex r4080768613 on #81: a query value runs through a semicolon, so `?token=<v>;<rest>` loses the whole value in every URL form and sink, and the cookie rows keep their rendering", () => {
  const legitimate = new Map(SEMICOLON_QUERY_ROWS.map(([label, line]) => [label, line("")]));
  assertCanariesDisjointFromFixture(assert, plantedValues(), legitimate, "semicolon query rows");
  const valuePairs = [["hunter2", "restofsecret"], ...plantedPairs()];
  for (const [label, line, expected] of SEMICOLON_QUERY_ROWS) {
    for (const [head, tail] of valuePairs) {
      const input = line(`${head};${tail}`);
      for (const [scrubName, scrub] of EXACT_SCRUBS) {
        const output = scrub(input);
        assert.equal(output, expected(), `${scrubName}: ${label} with ${head};${tail}`);
        assertNoCanaryWindows(assert, output, [head, tail], `${scrubName}: ${label}`);
        assert.equal(scrub(output), output, `${scrubName}: ${label}: a second pass changed the text`);
      }
      assertNoCanaryWindows(assert, errorMessage(new Error(input)), [head, tail], `errorMessage: ${label}`);
    }
  }
  // The row as reported, through both scrubbers and a record under `redactSecretValues`.
  assert.equal(scrubErrorText("?token=hunter2;restofsecret"), `?token=${REDACTED}`);
  assert.equal(scrubDataText("?token=hunter2;restofsecret"), `?token=${REDACTED}`);
  assert.deepEqual(redactSecretValues({ request: "GET /v1/x?token=hunter2;restofsecret HTTP/1.1" }), { request: `GET /v1/x?token=${REDACTED} HTTP/1.1` });
  // The cookie rows the ";" boundary was added for keep their rendering: the boundary is the cookie reader's.
  for (const [text, expected] of [
    ["Cookie: &sid=a; pref=b", `Cookie: ${REDACTED}`],
    ["Cookie: &sid=hunter2; pref=dark", `Cookie: ${REDACTED}`],
    ["Cookie: #sid=hunter2; pref=dark; X-Request-Id: 1", `Cookie: ${REDACTED}; X-Request-Id: 1`],
    ["Cookie: sid=hunter2; Path=/; HttpOnly", `Cookie: ${REDACTED}`],
    ["Set-Cookie: &sid=hunter2; Path=/; HttpOnly", `Set-Cookie: ${REDACTED}`],
    ["Cookie: sid=hunter2; X-Request-Id: 1", `Cookie: ${REDACTED}; X-Request-Id: 1`],
    ["Cookie: return_to=https://x/y?token=hunter2;restofsecret; pref=dark", `Cookie: ${REDACTED}`],
  ]) {
    for (const [scrubName, scrub] of EXACT_SCRUBS) assert.equal(scrub(text), expected, `${scrubName}: ${text}`);
  }
});

/**
 * CodeRabbit r4081238237 on #81 (at `a377984`): `Authorization: Snowflake Token="<jwt>"` carries its
 * credential as a quoted auth-param (RFC 7235), the header reader's bare run stopped at the quote, and
 * the pair rule could not match `Token` after the marker, so the quoted value survived
 * (`Snowflake [REDACTED]"<jwt>"`); the same for the quoted params after `Digest` (`response`, `nonce`,
 * `cnonce`) and for any `<Scheme> <Key>="..."` shape. The reader now reads the auth-param list: one
 * quoted param keeps its label and quotes (`Snowflake Token="[REDACTED]"`), a list (Digest, OAuth 1,
 * SigV4) goes whole, a challenge's params (`realm="api"`) stay, and a scheme spelling that "=" follows
 * is a param name (`Authorization: Token="[REDACTED]"`). The fixed values in the Digest, SigV4, and
 * OAuth 1 rows are the RFC 7616, AWS, and RFC 5849 examples. Mutation check (recorded in the round 3
 * body): with the list reader returning null, 13 of the 15 rows fail and 10 leak the value through
 * every sink; the two rows inside a JSON string hold because the quoted header path takes the whole
 * string there.
 */
const AUTH_PARAM_ROWS = Object.freeze([
  ["bare header line", (value) => `Authorization: Snowflake Token="${value}"`, () => `Authorization: Snowflake Token="${REDACTED}"`],
  ["single-quoted header line", (value) => `Authorization: Snowflake Token='${value}'`, () => `Authorization: Snowflake Token='${REDACTED}'`],
  ["after a JSON escape", (value) => `request failed\\nAuthorization: Snowflake Token=\\"${value}\\"`, () => `request failed\\nAuthorization: Snowflake Token=\\"${REDACTED}\\"`],
  ["inside a JSON string", (value) => `{"headers":{"Authorization":"Snowflake Token=\\"${value}\\""}}`, () => `{"headers":{"Authorization":"Snowflake ${REDACTED}"}}`],
  ["header line inside a JSON string", (value) => `{"detail":"Authorization: Snowflake Token=\\"${value}\\""}`, () => `{"detail":"Authorization: Snowflake Token=\\"${REDACTED}\\""}`],
  ["compound line", (value) => `Authorization: Snowflake Token="${value}"; X-Request-Id: 1`, () => `Authorization: Snowflake Token="${REDACTED}"; X-Request-Id: 1`],
  ["Bearer with a quoted param", (value) => `Authorization: Bearer Token="${value}"`, () => `Authorization: Bearer Token="${REDACTED}"`],
  ["scheme spelling as the param name", (value) => `Authorization: Token="${value}"`, () => `Authorization: Token="${REDACTED}"`],
  ["generic credential header", (value) => `X-Api-Key: Token="${value}"`, () => `X-Api-Key: Token="${REDACTED}"`],
  ["scheme word in free text", (value) => `replayed Snowflake Token="${value}" upstream`, () => `replayed Snowflake Token="${REDACTED}" upstream`],
  ["credential-named pair", (value) => `password=Token="${value}"`, () => `password=${REDACTED}`],
  ["Digest auth-param list", (value) => `Authorization: Digest username="Mufasa", realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/dir/index.html", qop=auth, nc=00000001, cnonce="0a4f113b", response="${value}", opaque="5ccc069c403ebaf9f0171e9517f40e41"`, () => `Authorization: Digest ${REDACTED}`],
  ["Digest auth-param list inside a JSON string", (value) => `{"Authorization":"Digest username=\\"Mufasa\\", realm=\\"testrealm@host.com\\", nonce=\\"dcd98b7102dd2f0e8b11d0f600bfb0c093\\", response=\\"${value}\\", opaque=\\"5ccc069c403ebaf9f0171e9517f40e41\\""}`, () => `{"Authorization":"Digest ${REDACTED}"}`],
  ["SigV4 auth-param list", (value) => `Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260922/eu-north-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=${value}`, () => `Authorization: AWS4-HMAC-SHA256 ${REDACTED}`],
  ["OAuth 1 auth-param list", (value) => `Authorization: OAuth oauth_consumer_key="dpf43f3p2l4k3l03", oauth_token="${value}", oauth_signature_method="HMAC-SHA1", oauth_version="1.0"`, () => `Authorization: OAuth ${REDACTED}`],
]);

test("CodeRabbit r4081238237 on #81: a quoted auth-param after a scheme word goes with its label kept, a Digest, OAuth 1, or SigV4 list goes whole, and a challenge's params stay, through every sink", () => {
  const legitimate = new Map(AUTH_PARAM_ROWS.map(([label, line]) => [label, line("")]));
  assertCanariesDisjointFromFixture(assert, plantedValues(), legitimate, "auth-param rows");
  // "skvclmtirehs" is the value the review used.
  for (const [label, line, expected] of AUTH_PARAM_ROWS) {
    for (const value of ["skvclmtirehs", ...plantedValues()]) {
      const input = line(value);
      for (const [scrubName, scrub] of EXACT_SCRUBS) {
        const output = scrub(input);
        assert.equal(output, expected(), `${scrubName}: ${label} with ${value}`);
        assertNoCanaryWindows(assert, output, [value], `${scrubName}: ${label}`);
        assert.equal(scrub(output), output, `${scrubName}: ${label}: a second pass changed the text`);
      }
      assertNoCanaryWindows(assert, errorMessage(new Error(input)), [value], `errorMessage: ${label}`);
    }
  }
  // The row as reported, through both scrubbers and records under `redactSecretValues`.
  const reported = 'Authorization: Snowflake Token="skvclmtirehs"';
  assert.equal(scrubErrorText(reported), `Authorization: Snowflake Token="${REDACTED}"`);
  assert.equal(scrubDataText(reported), `Authorization: Snowflake Token="${REDACTED}"`);
  assert.equal(redactSecretValues(reported), `Authorization: Snowflake Token="${REDACTED}"`);
  assert.deepEqual(redactSecretValues({ detail: reported }), { detail: `Authorization: Snowflake Token="${REDACTED}"` });
  assert.deepEqual(redactSecretValues({ headers: { Authorization: 'Snowflake Token="skvclmtirehs"' } }), { headers: { Authorization: REDACTED } });
  // A challenge's params describe the server and stay, in a WWW-Authenticate header and in prose.
  for (const text of [
    'WWW-Authenticate: Bearer realm="api", error="invalid_token", error_description="The access token expired"',
    'WWW-Authenticate: Basic realm="WallyWorld"',
    'Bearer realm="api", error="invalid_token", error_description="The access token expired"',
    'Basic realm="WallyWorld"',
  ]) {
    for (const [scrubName, scrub] of EXACT_SCRUBS) assert.equal(scrub(text), text, `${scrubName}: ${text}`);
  }
  const digestChallenge = 'WWW-Authenticate: Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41"';
  for (const [scrubName, scrub] of EXACT_SCRUBS) {
    assert.ok(scrub(digestChallenge).startsWith('WWW-Authenticate: Digest realm="testrealm@host.com", qop="auth,auth-int", '), `${scrubName}: ${scrub(digestChallenge)}`);
  }
  // A bare run after the scheme word goes whole as before, and the renderings are fixed points.
  for (const [text, expected] of [
    ["Authorization: Snowflake Token=skvclmtirehs", `Authorization: Snowflake ${REDACTED}`],
    ['"Authorization": "Token=skvclmtirehs"', `"Authorization": "${REDACTED}"`],
    [`Authorization: Snowflake Token="${REDACTED}"`, `Authorization: Snowflake Token="${REDACTED}"`],
    [`Authorization: Token=${REDACTED}`, `Authorization: Token=${REDACTED}`],
    [`Authorization: Digest ${REDACTED}`, `Authorization: Digest ${REDACTED}`],
  ]) {
    for (const [scrubName, scrub] of EXACT_SCRUBS) assert.equal(scrub(text), expected, `${scrubName}: ${text}`);
  }
});

/**
 * A header line quoted whole in single quotes (a curl `-H` argument, a Python dict repr, a sentence
 * that ends after the quote) keeps its closing quote: the apostrophe that closes it is followed by a
 * space, a bracket, sentence punctuation, or the end, which is where a cookie name or value ends.
 * Each row plants the value in the cookie; the text after the closing quote must survive.
 */
const SINGLE_QUOTED_HEADER_ROWS = Object.freeze([
  ["curl argument then a URL", (a) => `curl -H 'Cookie: sid=${a}; HttpOnly' https://api.example.com`, () => `curl -H 'Cookie: ${REDACTED}' https://api.example.com`, ["' https://api.example.com"]],
  ["curl argument that ends a sentence", (a) => `header -H 'Cookie: sid=${a}; HttpOnly'. Retry later`, () => `header -H 'Cookie: ${REDACTED}'. Retry later`, ["'. Retry later"]],
  ["curl argument whose value ends the quote and the sentence", (a) => `header -H 'Cookie: sid=${a}'. Retry later`, () => `header -H 'Cookie: ${REDACTED}'. Retry later`, ["'. Retry later"]],
  ["curl argument whose value ends the quote before a comma", (a) => `sent 'Cookie: sid=${a}', then 'Accept: text/html'`, () => `sent 'Cookie: ${REDACTED}', then 'Accept: text/html'`, ["', then 'Accept: text/html'"]],
  ["Python dict repr with a quoted value", (a) => `headers={'Cookie': 'sid=${a}; Path=/'}`, () => `headers={'Cookie': '${REDACTED}'}`, ["'}"]],
  ["Set-Cookie with attributes inside single quotes", (a) => `sent 'Set-Cookie: sid=${a}; Path=/; HttpOnly' and failed`, () => `sent 'Set-Cookie: ${REDACTED}' and failed`, ["' and failed"]],
  ["later dot name inside single quotes", (a) => `sent 'Cookie: theme=dark; my.sid=${a}; Secure' and failed`, () => `sent 'Cookie: ${REDACTED}' and failed`, ["' and failed"]],
  ["apostrophe value inside single quotes", (a) => `sent 'Cookie: sid=O'${a}; Secure' and failed`, () => `sent 'Cookie: ${REDACTED}' and failed`, ["' and failed"]],
]);

test("a header line quoted whole in single quotes keeps its closing quote, which a space, a bracket, punctuation, or the end follows", () => {
  const legitimate = new Map(SINGLE_QUOTED_HEADER_ROWS.map(([label, line]) => [label, line("")]));
  assertCanariesDisjointFromFixture(assert, plantedValues(), legitimate, "single-quoted header lines");
  for (const [label, line, expected, keeps] of SINGLE_QUOTED_HEADER_ROWS) {
    for (const a of plantedValues()) {
      const input = line(a);
      for (const [scrubName, scrub] of EXACT_SCRUBS) {
        const output = scrub(input);
        assert.equal(output, expected(), `${scrubName}: ${label} with ${a}`);
        for (const text of keeps) assert.ok(output.includes(text), `${scrubName}: ${label}: ${JSON.stringify(text)} did not survive in ${output}`);
        assertNoCanaryWindows(assert, output, [a], `${scrubName}: ${label}`);
        assert.equal(scrub(output), output, `${scrubName}: ${label}: a second pass changed the text`);
      }
      assertNoCanaryWindows(assert, errorMessage(new Error(input)), [a], `errorMessage: ${label}`);
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
