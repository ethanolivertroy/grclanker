import test from "node:test";
import assert from "node:assert/strict";
import { assertCanaryWindowsAbsent, assertFixtureFreeOfCanaryWindows, canaryWindows, secretForms } from "./helpers/canary-windows.mjs";

test("the shared leak oracle detects every location and length of a planted fragment in text and bundle entries", () => {
  const canary = "Kq7Zx2Vw9Lm4Tp8RfiCY";
  for (let length = 6; length <= canary.length; length += 1) {
    for (let start = 0; start + length <= canary.length; start += 1) {
      const text = `prefix ${canary.slice(start, start + length)} suffix`;
      assert.throws(() => assertCanaryWindowsAbsent(assert, text, [canary], "text"));
      assert.throws(() => assertCanaryWindowsAbsent(assert, new Map([["evidence.json", text]]), [canary], "bundle"));
    }
  }
  assertCanaryWindowsAbsent(assert, "legitimate evidence with no credential", [canary], "control");
});

test("short credentials are checked whole, and custom window widths remain available", () => {
  assert.deepEqual(canaryWindows("abc"), ["abc"]);
  assert.throws(() => assertCanaryWindowsAbsent(assert, "abc", ["abc"], "short"));
  assert.deepEqual(canaryWindows("abcdef", { min: 3, max: 3 }), ["abc", "bcd", "cde", "def"]);
  assert.throws(() => assertCanaryWindowsAbsent(assert, "anything", [""], "empty"), /non-empty/);
});

test("fixture controls distinguish planted values from accidental collisions", () => {
  const canary = "Kq7Zx2Vw9Lm4Tp8RfiCY";
  assertFixtureFreeOfCanaryWindows(assert, `legitimate ${canary} data`, [canary], "control");
  assert.throws(() => assertFixtureFreeOfCanaryWindows(assert, `legitimate ${canary.slice(3, 10)} data`, [canary], "collision"));
  assert.equal(secretForms('p@ss"w/rd+2026').length, 5);
});
