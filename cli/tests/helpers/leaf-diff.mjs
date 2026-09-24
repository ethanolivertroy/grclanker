/**
 * Leaf diff for finding evidence (review round 2, SEND BACK 3).
 *
 * Compares one finding's evidence between a healthy baseline and a variant in which one source was
 * denied. A leaf derived from the denied source must render null in the variant: never 0, false,
 * "", [], {}, or a "none"-like string, because those read as a complete empty reading. The check has
 * two parts: the named leaves must be a reading in the baseline and null under the denial, and every
 * other leaf that changed between the two runs (or appeared) must be null or a non-empty value, so a
 * residual defaulted flag anywhere in the evidence fails the test rather than only the named paths.
 */
import { isDeepStrictEqual } from "node:util";

/** Flattens evidence to `path -> leaf`, treating empty arrays and objects as leaves. */
export function evidenceLeaves(value, path = "", out = new Map()) {
  if (Array.isArray(value)) {
    if (value.length === 0) {
      out.set(path, value);
      return out;
    }
    value.forEach((item, index) => evidenceLeaves(item, `${path}[${index}]`, out));
    return out;
  }
  if (value && typeof value === "object") {
    const keys = Object.keys(value);
    if (keys.length === 0) {
      out.set(path, value);
      return out;
    }
    for (const key of keys) evidenceLeaves(value[key], path ? `${path}.${key}` : key, out);
    return out;
  }
  out.set(path, value);
  return out;
}

/** A value that reads as a complete empty reading rather than an unread one. */
export function isEmptyReading(value) {
  if (value === 0 || value === false || value === "") return true;
  if (Array.isArray(value)) return value.length === 0;
  if (value && typeof value === "object") return Object.keys(value).length === 0;
  return typeof value === "string" && /^none$/i.test(value.trim());
}

/**
 * @param {import("node:assert")} assert
 * @param {object} options
 * @param {string} options.label names the denial in every message
 * @param {object} options.baseline the finding's evidence from the healthy run
 * @param {object} options.denied the same finding's evidence when the source was denied
 * @param {string[]} options.nullLeaves paths that are a reading in the baseline and must be null under the denial
 * @param {Array<string | RegExp>} [options.allow] paths whose value may legitimately change or appear (status text, causes)
 */
export function assertLeavesNullUnderDenial(assert, { label, baseline, denied, nullLeaves, allow = [] }) {
  const before = evidenceLeaves(baseline);
  const after = evidenceLeaves(denied);
  assert.ok(nullLeaves.length > 0, `${label}: names at least one leaf`);
  // A named path may be a non-empty list or object in the baseline (flattened to child leaves) and null under the denial.
  const isContainerPrefix = (leaves, path) => [...leaves.keys()].some((key) => key.startsWith(`${path}.`) || key.startsWith(`${path}[`));
  for (const path of nullLeaves) {
    assert.ok(before.has(path) || isContainerPrefix(before, path), `${label}: the baseline renders ${path} (have ${[...before.keys()].join(", ")})`);
    if (before.has(path)) assert.notEqual(before.get(path), null, `${label}: the baseline ${path} is a reading`);
    assert.ok(after.has(path), `${label}: the denied variant still renders ${path} (have ${[...after.keys()].join(", ")})`);
    assert.equal(after.get(path), null, `${label}: ${path} renders null under the denial, got ${JSON.stringify(after.get(path))}`);
  }
  const allowed = (path) => allow.some((rule) => (rule instanceof RegExp ? rule.test(path) : rule === path));
  for (const [path, value] of after) {
    if (allowed(path) || value === null) continue;
    if (!before.has(path)) {
      assert.equal(isEmptyReading(value), false, `${label}: ${path} appears under the denial as the empty reading ${JSON.stringify(value)}`);
      continue;
    }
    if (isDeepStrictEqual(before.get(path), value)) continue;
    assert.fail(`${label}: ${path} changed under the denial from ${JSON.stringify(before.get(path))} to ${JSON.stringify(value)}; a changed leaf must render null`);
  }
}
