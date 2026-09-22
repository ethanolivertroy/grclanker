/**
 * Run-text survival sweeps for the credential scrubber.
 *
 * Every string a run records about legitimate data (finding summaries, manual-evidence instructions, inventory gaps,
 * request labels, bundle documents) must come back from the integration's scrubber unchanged; otherwise the scrubber
 * is rewriting evidence. `describeAlteration` renders the first place a scrubbed string differs from its source with
 * context on both sides, so a failing sweep names the rule that fired instead of the head of a long document.
 */

const CONTEXT_BEFORE = 60;
const CONTEXT_AFTER = 100;

/** Index of the first character at which `text` and `scrubbed` differ, or -1 when they are equal. */
export function firstDifference(text, scrubbed) {
  const shortest = Math.min(text.length, scrubbed.length);
  for (let index = 0; index < shortest; index += 1) {
    if (text[index] !== scrubbed[index]) return index;
  }
  return text.length === scrubbed.length ? -1 : shortest;
}

function window(value, from, to) {
  return JSON.stringify(value.slice(Math.max(0, from), to));
}

/** "<source window> -> <scrubbed window>" around the first difference, or an empty string when nothing changed. */
export function describeAlteration(text, scrubbed) {
  const index = firstDifference(text, scrubbed);
  if (index === -1) return "";
  return `${window(text, index - CONTEXT_BEFORE, index + CONTEXT_AFTER)} -> ${window(scrubbed, index - CONTEXT_BEFORE, index + CONTEXT_AFTER)}`;
}

/**
 * Runs every text through `scrub` and returns the distinct alterations, each rendered by `describeAlteration`. An
 * empty result means every string survived; the caller asserts on it and reports the list otherwise.
 */
export function scrubAlterations(texts, scrub) {
  const altered = new Set();
  for (const text of texts) {
    const scrubbed = scrub(text);
    if (scrubbed !== text) altered.add(describeAlteration(text, scrubbed));
  }
  return [...altered];
}
