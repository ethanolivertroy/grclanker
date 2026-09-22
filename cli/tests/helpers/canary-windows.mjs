/**
 * Sliding-window leak assertions for planted credentials.
 *
 * A whole-value check passes when a scrubber drops the value but lets a fragment through: a JSON.parse error quotes a
 * ten-character window of the source, a truncated error string keeps the head of a token, a URL decoder rewrites one
 * character. Checking every substring of the canary at lengths 6 through 24 catches each of those, so every assertion
 * that a planted credential is absent goes through `assertCanaryWindowsAbsent`.
 *
 * Canaries are alphanumeric and random-looking (`CANARY_SHAPE`) so that no 6-character window of one occurs in a
 * fixture's legitimate values; `assertCanaryFixture` is the self-check for that property.
 */

export const CANARY_WINDOW_MIN = 6;
export const CANARY_WINDOW_MAX = 24;

/**
 * Alphanumeric and at least one window long. Canaries are normally 32 characters so every length up to
 * CANARY_WINDOW_MAX is checked; the one exception is a JSON source that must stay at or under 21 characters for
 * JSON.parse to quote it whole, which caps that canary at 11 characters.
 */
export const CANARY_SHAPE = /^[A-Za-z0-9]{6,}$/;

/** Every distinct substring of `canary` at lengths `min` through `max` (capped at the canary's own length). */
export function canaryWindows(canary, { min = CANARY_WINDOW_MIN, max = CANARY_WINDOW_MAX } = {}) {
  const windows = new Set();
  const longest = Math.min(max, canary.length);
  for (let length = min; length <= longest; length += 1) {
    for (let index = 0; index + length <= canary.length; index += 1) {
      windows.add(canary.slice(index, index + length));
    }
  }
  return [...windows];
}

/** Normalizes a string, a Map of name to text, an array of [name, text] pairs, or an object to [name, text] pairs. */
function textEntries(contents) {
  if (typeof contents === "string") return [["text", contents]];
  if (contents instanceof Map) return [...contents.entries()].map(([name, text]) => [String(name), stringOf(text)]);
  if (Array.isArray(contents)) return contents.map((entry, index) => (Array.isArray(entry) ? [String(entry[0]), stringOf(entry[1])] : [String(index), stringOf(entry)]));
  return [["payload", stringOf(contents)]];
}

function stringOf(value) {
  return typeof value === "string" ? value : JSON.stringify(value) ?? String(value);
}

/**
 * Asserts, through the supplied assert module, that neither any canary nor any of its windows (lengths 6 through 24)
 * appears in any text of `contents`. The failure message names the file or payload, the canary, and the fragment.
 */
export function assertCanaryWindowsAbsent(assert, contents, canaries, label) {
  const entries = textEntries(contents);
  for (const canary of canaries) {
    if (typeof canary !== "string" || canary.length === 0) throw new TypeError(`${label}: canaries must be non-empty strings`);
    const windows = canaryWindows(canary);
    for (const [name, text] of entries) {
      assert.ok(!text.includes(canary), `${label}: planted canary ${canary} appears whole in ${name}`);
      for (const fragment of windows) {
        assert.ok(!text.includes(fragment), `${label}: fragment "${fragment}" (${fragment.length} of ${canary.length} characters) of planted canary ${canary} appears in ${name}`);
      }
    }
  }
}

/** Token-shaped canaries planted one per depth; each is distinct in every 6-character window from the others. */
const DEPTH_CANARIES = ["Kq7Zx2Vw9Lm4Tp8RfiCY", "bPxRfiCYwQmZkTnHvJdLsG", "Hn4Vq8Wz2Rt6Yp3LkMxSb", "Zt9Lm3Kp7Rx2Vw5QnHyGd"];

/**
 * A chain of nested records for the depth-cap pins: the record at nesting level k (the root is level 0) holds a fixed
 * `plain` string and a token-shaped `bare` canary, both at depth k + 1, and its `child` record at depth k + 1. The
 * canaries sit at depths cap - 1, cap, cap + 1, and cap + 2, in that order.
 */
export function depthCapChain(cap) {
  const canaryDepths = new Map([[cap - 1, DEPTH_CANARIES[0]], [cap, DEPTH_CANARIES[1]], [cap + 1, DEPTH_CANARIES[2]], [cap + 2, DEPTH_CANARIES[3]]]);
  const root = { plain: "depth-1-plain", bare: canaryDepths.get(1) ?? "bare-1" };
  let cursor = root;
  for (let level = 1; level <= cap + 2; level += 1) {
    const depth = level + 1;
    cursor.child = { plain: `depth-${depth}-plain`, bare: canaryDepths.get(depth) ?? `bare-${depth}` };
    cursor = cursor.child;
  }
  return { root, canaries: [...canaryDepths.values()] };
}

/**
 * Pins a data-side walker's depth cap: a string at depth cap - 1 and at depth cap is kept and still gets the pattern
 * pass (the token-shaped canary there becomes the marker), while a string and a container at depth cap + 1 become the
 * marker and nothing from depth cap + 2 survives in any window.
 */
export function assertDepthCapPins(assert, redact, cap, label) {
  const { root, canaries } = depthCapChain(cap);
  const out = redact(root);
  let record = out;
  for (let level = 1; level <= cap - 2; level += 1) record = record.child;
  // record is the level cap - 2 record: its strings sit at depth cap - 1, its child's strings at depth cap.
  assert.equal(record.plain, `depth-${cap - 1}-plain`, `${label}: a string at depth ${cap - 1} (cap - 1) is kept`);
  assert.equal(record.bare, "[REDACTED]", `${label}: a token-shaped string at depth ${cap - 1} still gets the pattern pass`);
  assert.equal(record.child.plain, `depth-${cap}-plain`, `${label}: a string at depth ${cap} (the cap) is kept`);
  assert.equal(record.child.bare, "[REDACTED]", `${label}: a token-shaped string at depth ${cap} still gets the pattern pass`);
  const atCap = record.child.child;
  assert.equal(atCap.plain, "[REDACTED]", `${label}: a string at depth ${cap + 1} (cap + 1) becomes the marker instead of being copied through`);
  assert.equal(atCap.bare, "[REDACTED]", `${label}: a canary at depth ${cap + 1} becomes the marker`);
  assert.equal(atCap.child, "[REDACTED]", `${label}: the container at depth ${cap + 1} becomes the marker, so depth ${cap + 2} is never copied`);
  assertCanaryWindowsAbsent(assert, JSON.stringify(out), canaries, `${label}: depth-cap canaries`);
  assert.ok(!JSON.stringify(out).includes(`depth-${cap + 1}-plain`) && !JSON.stringify(out).includes(`depth-${cap + 2}-plain`), `${label}: no string past the cap is copied through`);
}

/**
 * Fixture self-check: every canary has the alphanumeric random-looking shape, no 6-character window of one canary occurs
 * in another, and no 6-character window of any canary occurs in the fixture's legitimate values (`legitimate` takes the
 * same shapes as `assertCanaryWindowsAbsent`: the fixture records, the resolved config, a baseline run's output).
 */
export function assertCanaryFixture(assert, canaries, legitimate, label) {
  const list = [...canaries];
  assert.ok(list.length > 0, `${label}: at least one canary`);
  for (const canary of list) {
    assert.match(canary, CANARY_SHAPE, `${label}: canary ${canary} must be alphanumeric and at least ${CANARY_WINDOW_MIN} characters`);
    const classes = [/[a-z]/, /[A-Z]/, /[0-9]/].filter((pattern) => pattern.test(canary)).length;
    assert.ok(classes >= 2 && new Set(canary).size >= Math.min(12, canary.length - 2), `${label}: canary ${canary} must look random (letters and digits, few repeats)`);
  }
  const shortest = new Map();
  for (const canary of list) {
    for (const window of canaryWindows(canary, { min: CANARY_WINDOW_MIN, max: CANARY_WINDOW_MIN })) {
      const owner = shortest.get(window);
      assert.ok(owner === undefined || owner === canary, `${label}: window "${window}" occurs in both ${owner} and ${canary}`);
      shortest.set(window, canary);
    }
  }
  const entries = textEntries(legitimate);
  for (const [window, canary] of shortest) {
    for (const [name, text] of entries) {
      assert.ok(!text.includes(window), `${label}: window "${window}" of canary ${canary} occurs in legitimate value ${name}; choose a different canary`);
    }
  }
}
