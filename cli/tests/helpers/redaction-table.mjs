/**
 * Must-keep and must-redact table for redactErrorText (addendum 7) and the fixed-text survival check (GWS
 * note 1). Kept apart from error-canaries.mjs, which PR #67 mirrors byte for byte; this file only imports it.
 *
 * Must-keep rows are the identifying strings an integration's summaries, markers, probes, and evidence rely
 * on: the endpoint paths and commands it requests, resource names, principals, status text, finding ids, and
 * every fixed-text message it emits. Each row is asserted unchanged in isolation and inside a realistic
 * summary sentence of its group. Must-redact rows are the shared canary set: each canary rides every carrier
 * beside a must-keep row inside one sentence, and the canary must vanish window by window while the row and
 * the rest of the sentence survive whole.
 */
import { CANARY_VALUES, QUOTED_NON_CREDENTIAL_TEXTS, assertNoCanaryWindows, carrierCases } from "./error-canaries.mjs";

/**
 * @typedef {object} MustKeepGroup
 * @property {string} label
 * @property {readonly string[]} values distinct must-keep rows
 * @property {(value: string) => string} sentence a realistic summary sentence that embeds one row
 */

/**
 * Must-keep group shared by every integration (Codex P1 control): quoted header and JSON values that name no
 * credential survive, while the quoted credential carriers in carrierCases are removed beside them.
 * @type {MustKeepGroup}
 */
export const QUOTED_NON_CREDENTIAL_GROUP = Object.freeze({
  label: "quoted non-credential headers (Codex P1 control)",
  values: QUOTED_NON_CREDENTIAL_TEXTS,
  sentence: (value) => `the 502 response carried ${value} and a non-JSON body (text/html, 5120 bytes)`,
});

/** Asserts each must-keep row survives the scrub unchanged, in isolation and inside its group's sentence. */
export function assertMustKeepRows(assert, redact, groups) {
  assert.ok(groups.length > 0, "the must-keep table has at least one group");
  for (const group of groups) {
    assert.ok(group.values.length > 0, `${group.label}: the group has rows`);
    assert.equal(new Set(group.values).size, group.values.length, `${group.label}: rows are distinct`);
    for (const value of group.values) {
      assert.equal(redact(value), value, `${group.label}: must-keep row survives in isolation: ${value}`);
      const sentence = group.sentence(value);
      assert.ok(sentence.includes(value), `${group.label}: the sentence embeds the row: ${value}`);
      assert.notEqual(sentence, value, `${group.label}: the sentence adds context around the row: ${value}`);
      assert.equal(redact(sentence), sentence, `${group.label}: must-keep row survives inside a summary sentence: ${sentence}`);
    }
  }
}

/**
 * Asserts each must-redact row (a canary inside a carrier) is removed while the must-keep row it shares a
 * sentence with survives, together with the rest of the sentence. Every canary rides every carrier and the
 * must-keep rows rotate through the pairs; the loop runs as long as the longer of the two lists, so every row
 * sits beside at least one redaction and every canary-carrier pair beside at least one row.
 */
export function assertMustRedactRowsBesideMustKeep(assert, redact, groups, canaries = CANARY_VALUES) {
  const rows = groups.flatMap((group) => group.values.map((value) => ({ group, value })));
  assert.ok(rows.length > 0, "the must-keep table has rows to pair with must-redact rows");
  const pairs = canaries.flatMap((canary) => carrierCases(canary).map((carrierCase) => ({ canary, carrierCase })));
  assert.ok(pairs.length > 0, "the must-redact table has canary-carrier pairs");
  const turns = Math.max(rows.length, pairs.length);
  for (let index = 0; index < turns; index += 1) {
    const { group, value } = rows[index % rows.length];
    const { canary, carrierCase: [carrier, carried, carriedAfter] } = pairs[index % pairs.length];
    const sentence = group.sentence(value);
    const output = redact(`${sentence} ${carried}`);
    assertNoCanaryWindows(assert, output, [canary], `${carrier} beside ${group.label} row ${value}`);
    assert.equal(
      output,
      `${sentence} ${carriedAfter}`,
      `${carrier} beside ${group.label} row ${value}: the row and its sentence survive and only the carried value is removed`,
    );
  }
}

/**
 * Asserts every fixed-text message an integration emits survives the scrub unchanged (GWS note 1). The list
 * is exported by the integration itself and rendered from the same constants and helpers its error sink
 * uses, so a reworded message is judged here without a test copy drifting from the source.
 */
export function assertFixedTextsSurvive(assert, redact, texts, { minimum = 1 } = {}) {
  assert.ok(texts.length >= minimum, `the fixed-text list has at least ${minimum} messages (${texts.length})`);
  assert.equal(new Set(texts).size, texts.length, "fixed texts are distinct");
  for (const text of texts) {
    assert.equal(typeof text, "string", `fixed text is a string: ${String(text)}`);
    assert.ok(text.trim().length > 0, "fixed text is not blank");
    assert.ok(!text.includes("[REDACTED]"), `a fixed text carries no redaction marker of its own: ${text}`);
    assert.equal(redact(text), text, `fixed text survives the scrub: ${text}`);
  }
}
