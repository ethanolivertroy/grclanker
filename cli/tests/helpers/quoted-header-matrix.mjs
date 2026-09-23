/**
 * Reviewer A's quoted header value matrix (Codex P1 on #70, gap 26), reproduced against the shared
 * scrubber: a credential header whose value is quoted must lose the value whole, in every quote style,
 * whatever the spacing around the separator and whatever frame the header line sits in, while a quoted
 * value under a header that is not a credential stays as written.
 *
 * 13 carriers, 4 values (two name-shaped, a 30-character token below no threshold, a 12-character token
 * below the 16-character long-token floor), 3 quote styles (double, single, JSON-escaped `\"v\"`),
 * 4 separator spacings, and 3 frames (a bare header line, a prose sentence, a JSON error body whose
 * encoder escapes the quotes again): 1872 cases per entry point. Each case is judged with every
 * 6-to-24-character window of the value, so a remainder such as `Cookie: [REDACTED]"v"` is a hit.
 */

/** The four values: name-shaped values a shape rule keeps, and two tokens either side of the long-token floor. */
export const QUOTED_HEADER_VALUES = Object.freeze([
  ["name-shaped short", "prod-us-east-2026"],
  ["name-shaped long", "svc-audit-reader-v2-blue"],
  ["token-shaped 30", "Vq4Hn8Zt2Kw6Rd9Xp3Jm7Cy5Bf1Lg0"],
  ["token-shaped 12", "X8cvDlJ1MxLX"],
]);

/** Double quotes, single quotes, and the JSON-escaped form a JSON string carries. */
export const QUOTE_STYLES = Object.freeze([
  ["double", (value) => `"${value}"`],
  ["single", (value) => `'${value}'`],
  ["json-escaped", (value) => `\\"${value}\\"`],
]);

/** Spacing around the header colon. */
export const SEPARATORS = Object.freeze([": ", ":", " : ", " :"]);

/**
 * The carriers. Each takes the quoted value, the separator, the plain value, and the quote function
 * (the whole-value carrier quotes `Bearer <value>` as one string).
 */
export const QUOTED_HEADER_CARRIERS = Object.freeze([
  ["Cookie: sid=Q", (quoted, separator) => `Cookie${separator}sid=${quoted}`],
  ["Cookie: sid = Q", (quoted, separator) => `Cookie${separator}sid = ${quoted}`],
  ["Cookie: prefs=Q", (quoted, separator) => `Cookie${separator}prefs=${quoted}`],
  ["Set-Cookie: sid=Q", (quoted, separator) => `Set-Cookie${separator}sid=${quoted}`],
  ["X-Api-Key: Q", (quoted, separator) => `X-Api-Key${separator}${quoted}`],
  ["X-Auth-Token: Q", (quoted, separator) => `X-Auth-Token${separator}${quoted}`],
  ["Authorization: Q", (quoted, separator) => `Authorization${separator}${quoted}`],
  ["Authorization: Bearer Q", (quoted, separator) => `Authorization${separator}Bearer ${quoted}`],
  ["Authorization: Basic Q", (quoted, separator) => `Authorization${separator}Basic ${quoted}`],
  ['Authorization: "Bearer V"', (quoted, separator, value, quote) => `Authorization${separator}${quote(`Bearer ${value}`)}`],
  ["Proxy-Authorization: Bearer Q", (quoted, separator) => `Proxy-Authorization${separator}Bearer ${quoted}`],
  ["DD-API-KEY: Q", (quoted, separator) => `DD-API-KEY${separator}${quoted}`],
  ["X-Phisher-Token: Q", (quoted, separator) => `X-Phisher-Token${separator}${quoted}`],
]);

/** A bare header line, the line inside a 401 prose message, and the line inside a JSON error body. */
export const FRAMES = Object.freeze([
  ["bare", (line) => line],
  ["prose", (line) => `Box returned 401 Unauthorized: the request header ${line} was refused by the upstream`],
  ["json-body", (line) => JSON.stringify({ type: "error", status: 401, message: `header ${line} rejected` })],
]);

/** Quoted values under headers that name no credential; every one must come back unchanged. */
export const QUOTED_MUST_KEEP_HEADERS = Object.freeze([
  'Content-Type: "application/json"',
  'Content-Type:"application/json; charset=utf-8"',
  "Accept: 'application/json'",
  'Content-Length: "42"',
  'X-Request-Id: "req-2026-09-22-0001"',
  'User-Agent: "grclanker-cli/0.4.1"',
  'Cache-Control: "no-store"',
  'Location: "/2.0/users/me"',
  '{"Content-Type":"application/json","Accept":"text/html"}',
]);

/** Every case of the matrix: `{ label, carrier, value, quote, separator, frame, text }`. */
export function quotedHeaderCases() {
  const cases = [];
  for (const [carrierName, carrier] of QUOTED_HEADER_CARRIERS) {
    for (const [valueName, value] of QUOTED_HEADER_VALUES) {
      for (const [quoteName, quote] of QUOTE_STYLES) {
        for (const separator of SEPARATORS) {
          const line = carrier(quote(value), separator, value, quote);
          for (const [frameName, frame] of FRAMES) {
            cases.push({
              label: `${carrierName} | ${valueName} | ${quoteName} | ${JSON.stringify(separator)} | ${frameName}`,
              carrier: carrierName,
              value,
              quote: quoteName,
              separator,
              frame: frameName,
              text: frame(line),
            });
          }
        }
      }
    }
  }
  return cases;
}

/** The control: the same carriers, values, separators, and frames with the value unquoted. */
export function unquotedControlCases() {
  const cases = [];
  const identity = (value) => value;
  for (const [carrierName, carrier] of QUOTED_HEADER_CARRIERS) {
    for (const [valueName, value] of QUOTED_HEADER_VALUES) {
      for (const separator of SEPARATORS) {
        const line = carrier(value, separator, value, identity);
        for (const [frameName, frame] of FRAMES) {
          cases.push({ label: `${carrierName} | ${valueName} | unquoted | ${JSON.stringify(separator)} | ${frameName}`, carrier: carrierName, value, frame: frameName, text: frame(line) });
        }
      }
    }
  }
  return cases;
}

/** Hit counts for one scrubber over the matrix: total, hits, and hits by carrier, quote style, frame, and value. */
export function countQuotedHeaderHits(scrub, leaked) {
  const summary = { cases: 0, hits: 0, byCarrier: {}, byQuote: {}, byFrame: {}, byValue: {}, examples: [] };
  for (const testCase of quotedHeaderCases()) {
    summary.cases += 1;
    const output = scrub(testCase.text);
    if (!leaked(output, testCase.value)) continue;
    summary.hits += 1;
    summary.byCarrier[testCase.carrier] = (summary.byCarrier[testCase.carrier] ?? 0) + 1;
    summary.byQuote[testCase.quote] = (summary.byQuote[testCase.quote] ?? 0) + 1;
    summary.byFrame[testCase.frame] = (summary.byFrame[testCase.frame] ?? 0) + 1;
    summary.byValue[testCase.value] = (summary.byValue[testCase.value] ?? 0) + 1;
    if (summary.examples.length < 12 && testCase.frame === "bare") summary.examples.push([testCase.text, output]);
  }
  return summary;
}
