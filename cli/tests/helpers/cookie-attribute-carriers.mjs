/**
 * The cookie attribute class (CodeRabbit on #78, r4076392614).
 *
 * A Cookie or Set-Cookie header value is `name=value` pairs and attributes separated by `;`. RFC 6265 lets a cookie
 * name hold any token character (`!#$%&'*+-.^_` plus "`|~" and alphanumerics), so `my.sid`, `ASP.NET_SessionId`,
 * `.AspNetCore.Session`, and `pref~v2` are all names. An attribute scan limited to letters, digits, "_", and "-"
 * stopped at the "." in `; my.sid=` and left that pair's value standing: `Cookie: theme=dark; my.sid=hunter2` came
 * out as `Cookie: [REDACTED].sid=hunter2`. These rows pin the widened class: every later pair goes with the header
 * value whatever its name, the scan still stops at the next header's `Name:` token on a compound line, and the
 * following header keeps its name and gets its own carrier treatment.
 *
 * Each row is `[label, carrier(value), expected(), controls]`: the text with the value planted, the exact text once
 * it is gone, and the fragments that must survive (the following header names). The helper runs every row through a
 * text scrubber with the supplied canaries, asserts the exact result, checks every 6-to-24-character window of the
 * canary is gone, checks the controls, and checks a second pass is a no-op.
 */
import { assertCanaryWindowsAbsent } from "./canary-windows.mjs";

/** The marker every scrubber writes; kept literal here so the helper does not depend on the built module. */
const REDACTED = "[REDACTED]";

/** Alphanumeric random-looking values planted in the rows; the first is name-shaped and would stay bare in prose. */
export const COOKIE_ATTRIBUTE_CANARIES = ["RulingNameShapedProbeZq", "BPt5mgDrRZ5YyLTHaQPepJUYQbGYRCjG"];

/** A cookie name built from every RFC 6265 token character other than letters and digits, plus a few of those. */
export const TOKEN_PUNCTUATION_COOKIE_NAME = "a!b#c$d%e&f*g+h-i.j^k_l`m|n~o";

export const COOKIE_ATTRIBUTE_CARRIERS = [
  ["later cookie whose name holds a dot", (value) => `Cookie: theme=dark; my.sid=${value}`, () => `Cookie: ${REDACTED}`],
  ["ASP.NET session cookie after a plain pair, with Path", (value) => `Cookie: theme=dark; ASP.NET_SessionId=${value}; Path=/`, () => `Cookie: ${REDACTED}`],
  ["Set-Cookie leading-dot name with HttpOnly and SameSite", (value) => `Set-Cookie: .AspNetCore.Session=${value}; HttpOnly; SameSite=Lax`, () => `Set-Cookie: ${REDACTED}`],
  ["every token character in a name before a credential pair", (value) => `Cookie: ${TOKEN_PUNCTUATION_COOKIE_NAME}=1; sid=${value}`, () => `Cookie: ${REDACTED}`],
  ["dotted and tilde names before a session_token pair", (value) => `Cookie: theme=dark; my.sid=${value}; pref~v2=1; session_token=${value}`, () => `Cookie: ${REDACTED}`],
  ["dotted name with a quoted value", (value) => `Cookie: theme=dark; my.sid="${value}"`, () => `Cookie: ${REDACTED}`],
  ["no space after the semicolons", (value) => `Cookie: theme=dark;my.sid=${value};Path=/`, () => `Cookie: ${REDACTED}`],
  ["apostrophe inside a name and a value", (value) => `Cookie: my'pref=1; sid=O'${value}`, () => `Cookie: ${REDACTED}`],
  ["ampersand and hash names with a JSON-escaped quoted value", (value) => `Cookie: a&b=x; c#d=\\"${value}\\"`, () => `Cookie: ${REDACTED}`],
  ["JSON pair", (value) => `"Cookie": "theme=dark; my.sid=${value}"`, () => `"Cookie": "${REDACTED}"`],
  ["JSON pair, escaped, ASP.NET name", (value) => `\\"Cookie\\": \\"theme=dark; ASP.NET_SessionId=${value}; Path=/\\"`, () => `\\"Cookie\\": \\"${REDACTED}\\"`],
  [
    "request options echoed as JSON",
    (value) => `{"headers":{"Cookie":"theme=dark; my.sid=${value}","Accept":"application/json"}}`,
    () => `{"headers":{"Cookie":"${REDACTED}","Accept":"application/json"}}`,
    ['"Accept":"application/json"'],
  ],
  [
    "header quoted whole in single quotes on a curl line",
    (value) => `-H 'Cookie: sid=${value}; HttpOnly' (retry 3)`,
    () => `-H 'Cookie: ${REDACTED}' (retry 3)`,
    ["-H 'Cookie: ", "' (retry 3)"],
  ],
  [
    "compound line, dotted cookie then quoted X-Api-Key then Content-Type",
    (value) => `Cookie: theme=dark; my.sid=${value}; X-Api-Key: "${value}"; Content-Type: application/json`,
    () => `Cookie: ${REDACTED}; X-Api-Key: "${REDACTED}"; Content-Type: application/json`,
    ['X-Api-Key: "', "Content-Type: application/json"],
  ],
  [
    "compound line, ASP.NET cookie with attributes then unquoted X-Api-Key then Content-Type",
    (value) => `Cookie: theme=dark; ASP.NET_SessionId=${value}; Path=/; HttpOnly; X-Api-Key: ${value}; Content-Type: application/json`,
    () => `Cookie: ${REDACTED}; X-Api-Key: ${REDACTED}; Content-Type: application/json`,
    ["X-Api-Key: ", "Content-Type: application/json"],
  ],
  [
    "compound line, Set-Cookie leading-dot name then a comma and Content-Type",
    (value) => `Set-Cookie: .AspNetCore.Session=${value}; HttpOnly, Content-Type: application/json`,
    () => `Set-Cookie: ${REDACTED}, Content-Type: application/json`,
    ["Content-Type: application/json"],
  ],
  [
    "compound line, token-character names with no spaces then a quoted X-Api-Key",
    (value) => `Cookie: ${TOKEN_PUNCTUATION_COOKIE_NAME}=1;sid=${value};X-Api-Key:"${value}"`,
    () => `Cookie: ${REDACTED};X-Api-Key:"${REDACTED}"`,
    ['X-Api-Key:"'],
  ],
  [
    "compound line, dotted header name after the cookie",
    (value) => `Cookie: theme=dark; my.sid=${value}; X.Api.Key: ${value}; Accept: application/json`,
    () => `Cookie: ${REDACTED}; X.Api.Key: ${REDACTED}; Accept: application/json`,
    ["X.Api.Key: ", "Accept: application/json"],
  ],
  [
    "compound line, bracketed dotted cookie then a JSON fragment",
    (value) => `(Cookie: my.sid=${value}) then {"token": "${value}", "env": "production"}`,
    () => `(Cookie: ${REDACTED}) then {"token": "${REDACTED}", "env": "production"}`,
    [") then {", '"env": "production"'],
  ],
  [
    "compound line, JSON-escaped dotted cookie then X-Api-Key then Content-Type",
    (value) => `\\"Cookie\\": \\"theme=dark; my.sid=${value}\\", \\"X-Api-Key\\": \\"${value}\\", \\"Content-Type\\": \\"application/json\\"`,
    () => `\\"Cookie\\": \\"${REDACTED}\\", \\"X-Api-Key\\": \\"${REDACTED}\\", \\"Content-Type\\": \\"application/json\\"`,
    ['\\"X-Api-Key\\": \\"', '\\"Content-Type\\": \\"application/json\\"'],
  ],
  [
    "compound line inside a 502 body note",
    (value) => `502 Bad Gateway: upstream echoed Cookie: theme=dark; ASP.NET_SessionId=${value}; Path=/; X-Api-Key: "${value}"; Content-Type: "application/json"`,
    () => `502 Bad Gateway: upstream echoed Cookie: ${REDACTED}; X-Api-Key: "${REDACTED}"; Content-Type: "application/json"`,
    ["502 Bad Gateway: upstream echoed Cookie: ", 'X-Api-Key: "', 'Content-Type: "application/json"'],
  ],
];

/** Every row's text with the canaries removed, for the fixture self-check against the planted values. */
export function cookieAttributeCarrierTexts() {
  return COOKIE_ATTRIBUTE_CARRIERS.map(([label, carrier]) => [label, carrier("")]);
}

/**
 * Runs every row through `scrub` (text to text) with each canary planted and asserts the exact expected text, the
 * absence of every canary window, the survival of the controls, and an idempotent second pass.
 */
export function assertCookieAttributeCarriersScrubbed(assert, scrub, label, canaries = COOKIE_ATTRIBUTE_CANARIES) {
  assert.ok(COOKIE_ATTRIBUTE_CARRIERS.length >= 16, `${label}: the cookie attribute rows are present`);
  for (const [rowLabel, carrier, expected, controls = []] of COOKIE_ATTRIBUTE_CARRIERS) {
    for (const value of canaries) {
      const scrubbed = scrub(carrier(value));
      assert.equal(scrubbed, expected(), `${label}: ${rowLabel} with ${value}`);
      assertCanaryWindowsAbsent(assert, scrubbed, [value], `${label}: ${rowLabel} with ${value}`);
      for (const control of controls) {
        assert.ok(scrubbed.includes(control), `${label}: ${rowLabel} with ${value}: the following text ${JSON.stringify(control)} did not survive: ${scrubbed}`);
      }
      assert.equal(scrub(scrubbed), scrubbed, `${label}: ${rowLabel} with ${value}: a second pass changed the text`);
    }
  }
}
