import test from "node:test";
import assert from "node:assert/strict";

import { parseNextLinkHeader } from "../dist/extensions/grc-tools/hardening/link-header.js";

test("parseNextLinkHeader handles quoted commas, escaped quotes, and relation token lists", () => {
  assert.deepEqual(
    parseNextLinkHeader('<https://api.example.test/page2>; title="page one, continued"; rel="prev next"'),
    { kind: "next", target: "https://api.example.test/page2" },
  );
  assert.deepEqual(
    parseNextLinkHeader('<https://api.example.test/page1>; title="say \\"next, later\\""; rel=prev, <https://api.example.test/page2>; REL="NEXT LAST"; type="application/json"'),
    { kind: "next", target: "https://api.example.test/page2" },
  );
});

test("parseNextLinkHeader distinguishes exhaustion from malformed headers", () => {
  assert.deepEqual(parseNextLinkHeader(null), { kind: "absent" });
  assert.deepEqual(
    parseNextLinkHeader('<https://api.example.test/page1>; rel="prev last"'),
    { kind: "absent" },
  );
  for (const header of [
    "",
    '<https://api.example.test/page2>; title="unterminated; rel=next',
    "<https://api.example.test/page2; rel=next",
    "<https://api.example.test/page2>; rel",
    "<https://api.example.test/page2>; rel=",
    '<https://api.example.test/page2>; rel=""',
    '<https://api.example.test/page2>; title="missing relation"',
    '<https://api.example.test/page2>; rel="next",',
  ]) {
    assert.deepEqual(parseNextLinkHeader(header), { kind: "unparseable" }, header);
  }
});

test("parseNextLinkHeader ignores duplicate rel parameters after the first", () => {
  assert.deepEqual(
    parseNextLinkHeader("<https://api.example.test/page2>; rel=prev; rel=next"),
    { kind: "absent" },
  );
  assert.deepEqual(
    parseNextLinkHeader('<https://api.example.test/page2>; rel="next prev"; rel=last'),
    { kind: "next", target: "https://api.example.test/page2" },
  );
});
