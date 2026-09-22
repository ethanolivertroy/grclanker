/**
 * Fixed-text survival (round 7 note 1).
 *
 * Every fixed-text message an integration emits (the config loader read and parse messages, the
 * non-JSON and opaque-body notes, the `not requested:` and `principals_withheld` wordings, the
 * describeStatus and skipped texts, the corollary summary templates with their sample paths and
 * names) must come back from that integration's own redaction pass unchanged. A message built from
 * fixed text plus a path or a name must never be eaten by a carrier rule: the credential pair rule
 * once took the path in "Service account credentials: <path>" as the value of a credential-named key.
 *
 * Two sources feed the check: texts rendered by the real code paths (the loader on a failing file,
 * the error constructor on an opaque body, the assessments and the export on a fixture with denied
 * and skipped reads), harvested with `collectFixedTexts`, and the integration's standing fixed texts
 * listed with sample paths and names in the test file.
 */
import assert from "node:assert/strict";

/**
 * Keys whose string values, at any depth beneath them, carry fixed text: error strings, finding
 * summaries, inventory states, withheld notes, collection issues. Identifier-bearing fields (names,
 * ids, evidence values copied from records) are left out because their values are fixture data, not
 * fixed text.
 */
export const FIXED_TEXT_KEYS = new Set([
  "summary",
  "error",
  "detail",
  "message",
  "reason",
  "principals_withheld",
  "inventories",
  "unreadable_sources",
  "collection_issues",
  "issues",
  "errors",
  "skipped",
  "note",
  "notes",
  "evidence_to_collect",
  "manual_evidence",
]);

/** Collects every string found beneath a fixed-text key anywhere in `value`. */
export function collectFixedTexts(value, out = new Set(), inside = false) {
  if (typeof value === "string") {
    if (inside && value.length > 0) out.add(value);
  } else if (Array.isArray(value)) {
    for (const item of value) collectFixedTexts(item, out, inside);
  } else if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) collectFixedTexts(child, out, inside || FIXED_TEXT_KEYS.has(key));
  }
  return out;
}

/** Splits an `_errors.log` (or any line-oriented file) into its non-empty lines. */
export function logLines(text) {
  return (text ?? "").split("\n").map((line) => line.trim()).filter((line) => line.length > 0);
}

/**
 * Asserts every text comes back from `scrub` verbatim; the failure lists each eaten text next to
 * what the scrubber made of it. Returns the number of distinct texts checked.
 */
export function assertFixedTextsSurvive(scrub, texts, label) {
  const distinct = [...new Set([...texts].filter((text) => typeof text === "string" && text.length > 0))];
  assert.ok(distinct.length > 0, `${label}: at least one fixed text was rendered`);
  const eaten = [];
  for (const text of distinct) {
    const output = scrub(text);
    if (output !== text) eaten.push({ text, output });
  }
  assert.deepEqual(eaten, [], `${label}: ${eaten.length} of ${distinct.length} fixed texts changed under the scrubber`);
  return distinct.length;
}
