import test from "node:test";
import assert from "node:assert/strict";

import { IntegrationError, describeErrorBody, redactSecretValues, scrubDataText, scrubErrorText } from "../dist/extensions/grc-tools/hardening/error-text.js";
import { leakedCanaryWindow } from "./helpers/error-canaries.mjs";

/**
 * The escaped-control matrix of the review of #78 (gap 2): every carrier class after the two-character
 * JSON escapes `\n`, `\r`, `\t` and after an escaped backslash, against three controls (a raw line
 * break, an escaped quote, a space), with token-shaped and prose-shaped values, through the text scrubs
 * and describeErrorBody's nested sink (where a raw control in the inner text is JSON-encoded to the
 * escape before the scrub reads it). The rule under test: an escape prefix leaks exactly what the space
 * control leaks, and that is only the scheme-prose row with a plain lowercase word (`Bearer <word> was
 * replayed`, the prose exemption after a scheme word, which main at 02967cc kept too).
 */

const VALUES = Object.freeze([
  ["token24", "Kq7Zx2Vw9Lm4Tp8RaB3cD5eF"],
  ["token12", "tnAki87T1HyQ"],
  ["lower11", "bvttcyphpdr"],
  ["lower16", "zbnrwypozxroedae"],
  ["digits7", "hunter2"],
]);

const CARRIERS = Object.freeze([
  ["pair eq", (value) => `api_key=${value}`],
  ["pair colon", (value) => `password: ${value}`],
  ["pair json-escaped", (value) => `\\"client_secret\\": \\"${value}\\"`],
  ["header X-Api-Key", (value) => `X-Api-Key: ${value}`],
  ["header Authorization Bearer", (value) => `Authorization: Bearer ${value}`],
  ["header quoted", (value) => `X-Auth-Token: \\"${value}\\"`],
  ["cookie", (value) => `Cookie: sid=${value}; Path=/`],
  ["set-cookie", (value) => `Set-Cookie: session=${value}; HttpOnly`],
  ["scheme prose", (value) => `Bearer ${value} was replayed`],
  ["query", (value) => `/v1/items?token=${value}&limit=5`],
  ["compound key", (value) => `client_token=${value}`],
  ["env upper", (value) => `GITHUB_TOKEN=${value}`],
]);

/** The prefixes as the scrub sees them; the nested sink decodes them into the inner text first. */
const ESCAPE_PREFIXES = Object.freeze([
  ["escaped newline", "request failed\\n"],
  ["escaped cr", "request failed\\r"],
  ["escaped tab", "request failed\\t"],
  ["escaped backspace", "request failed\\b"],
  ["escaped form feed", "request failed\\f"],
  ["escaped crlf", "request failed\\r\\n"],
  ["escaped backslash", "path C:\\\\"],
]);
const CONTROL_PREFIXES = Object.freeze([
  ["raw newline", "request failed\n"],
  ["escaped quote", 'said \\"'],
  ["space", "request failed "],
]);

function decodeForInnerText(text) {
  return text
    .replace(/\\n/g, "\n")
    .replace(/\\r/g, "\r")
    .replace(/\\t/g, "\t")
    .replace(/\\b/g, "\b")
    .replace(/\\f/g, "\f")
    .replace(/\\\\/g, "\\")
    .replace(/\\"/g, '"');
}

const SINKS = Object.freeze([
  ["scrubErrorText", (text) => scrubErrorText(text)],
  ["scrubDataText", (text) => scrubDataText(text)],
  ["redactSecretValues", (text) => redactSecretValues(text)],
  ["IntegrationError", (text) => new IntegrationError(text, {}).message],
  ["describeErrorBody nested", (text) => describeErrorBody("application/json", JSON.stringify({ error: { message: JSON.stringify({ detail: decodeForInnerText(text) }) } }))],
]);

/** The leaking rows of one prefix as `carrier|value|sink` strings. */
function leakingRows(prefix) {
  const rows = [];
  for (const [carrierName, carrier] of CARRIERS) {
    for (const [valueName, value] of VALUES) {
      const text = `${prefix}${carrier(value)} see the log`;
      for (const [sinkName, sink] of SINKS) {
        if (leakedCanaryWindow(sink(text), value) !== undefined) rows.push(`${carrierName}|${valueName}|${sinkName}`);
      }
    }
  }
  return rows;
}

test("escape boundaries: every escape prefix leaks exactly what the space control leaks, and that is only the scheme-prose plain-word row", () => {
  const trialsPerPrefix = CARRIERS.length * VALUES.length * SINKS.length;
  assert.equal(trialsPerPrefix, 300);
  const spaceRows = leakingRows(CONTROL_PREFIXES[2][1]).sort();
  // The one exemption in force under the control: a plain lowercase word after a scheme word in prose.
  const exemptRows = ["lower11", "lower16"].flatMap((valueName) => SINKS.map(([sinkName]) => `scheme prose|${valueName}|${sinkName}`)).sort();
  assert.deepEqual(spaceRows, exemptRows);
  for (const [prefixName, prefix] of [...ESCAPE_PREFIXES, ...CONTROL_PREFIXES]) {
    const rows = leakingRows(prefix);
    assert.deepEqual(rows.sort(), spaceRows, `${prefixName}: ${rows.length} leaking rows against the space control's ${spaceRows.length}`);
  }
});

test("escape boundaries: the escape letter is a boundary, not part of a name, and a following name that is not a carrier stays", () => {
  for (const text of [
    "request failed\\nnothing else",
    "request failed\\tterms accepted",
    "request failed\\rrate limited",
    "request failed\\bbackoff applied",
    "path C:\\\\temp\\\\token-store was read",
    "request failed\\napi_version=2 was sent",
  ]) {
    for (const [sinkName, sink] of SINKS.slice(0, 4)) {
      assert.equal(sink(text), text, `${sinkName} changed ${JSON.stringify(text)}`);
    }
  }
});
