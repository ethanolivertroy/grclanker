/**
 * Planted credentials and the fragment-window leak assertion (round 7, fragment windows).
 *
 * A leak assertion against a planted credential must not check only the whole value (a scrubber that
 * removes part of it would pass) nor fixed 8-character fragments (a 6- or 7-character survival would
 * pass): it checks every substring of the value at lengths 6 through 24. That is only sound when no
 * 6-character window of any planted value occurs in the fixture's legitimate values or in the prose
 * the integration generates, so planted values are alphanumeric and random-looking, and every fixture
 * asserts that property on itself through `assertPlantedValuesWellFormed`.
 */
export const FRAGMENT_WINDOW_MIN = 6;
export const FRAGMENT_WINDOW_MAX = 24;

/** Planted values: alphanumeric only, so no window can coincide with a carrier label or a path piece. */
export const PLANTED_VALUE_SHAPE = /^[A-Za-z0-9]+$/;

/**
 * Every substring of `value` at lengths 6 through 24 (or the whole value when it is shorter than 6),
 * deduplicated, longest first so a failure names the longest surviving fragment.
 */
export function fragmentWindows(value, min = FRAGMENT_WINDOW_MIN, max = FRAGMENT_WINDOW_MAX) {
  if (value.length <= min) return [value];
  const windows = new Set();
  for (let length = Math.min(max, value.length); length >= min; length -= 1) {
    for (let index = 0; index + length <= value.length; index += 1) windows.add(value.slice(index, index + length));
  }
  return [...windows];
}

/** The 6-character windows only, for the self-checks (distinctness and absence from legitimate text). */
export function shortestWindows(value) {
  return fragmentWindows(value, FRAGMENT_WINDOW_MIN, FRAGMENT_WINDOW_MIN);
}

/** Asserts through the supplied assert module that no window of any planted value appears in `text`. */
export function assertFragmentsAbsent(assert, text, values, label) {
  for (const value of values) {
    for (const window of fragmentWindows(value)) {
      assert.ok(!text.includes(window), `${label}: fragment ${JSON.stringify(window)} of planted value ${JSON.stringify(value)} appears`);
    }
  }
}

/** The bundle and zip variant: every file or inflated entry against every planted value's windows. */
export function assertSecretFragmentsAbsent(assert, contents, secrets, label) {
  for (const [name, text] of contents) assertFragmentsAbsent(assert, text, secrets, `${label}: ${name}`);
}

/**
 * The fixture self-check: every planted value is alphanumeric, at least 6 characters, its 6-character
 * windows are distinct from every other planted value's, and none of those windows occurs in any of the
 * `legitimateTexts` (the healthy fixture, the sample configuration, a healthy bundle's files).
 *
 * @param {object} assert the assert module
 * @param {Record<string, string> | string[]} values the planted values, keyed by name when possible
 * @param {Iterable<[string, string]> | string[]} legitimateTexts named legitimate texts (or bare strings)
 */
export function assertPlantedValuesWellFormed(assert, values, legitimateTexts = []) {
  const entries = Array.isArray(values) ? values.map((value, index) => [String(index), value]) : Object.entries(values);
  const texts = Array.isArray(legitimateTexts)
    ? legitimateTexts.map((text, index) => (Array.isArray(text) ? text : [String(index), text]))
    : [...legitimateTexts];
  const owners = new Map();
  for (const [name, value] of entries) {
    assert.equal(typeof value, "string", `planted value ${name} is a string`);
    assert.ok(value.length >= FRAGMENT_WINDOW_MIN, `planted value ${name} has at least ${FRAGMENT_WINDOW_MIN} characters`);
    assert.match(value, PLANTED_VALUE_SHAPE, `planted value ${name} is alphanumeric: ${value}`);
    for (const window of shortestWindows(value)) {
      const owner = owners.get(window);
      assert.equal(owner, undefined, `window ${window} appears in both planted values ${owner} and ${name}`);
      owners.set(window, name);
      for (const [textName, text] of texts) {
        assert.ok(!text.includes(window), `window ${window} of planted value ${name} occurs in legitimate text ${textName}`);
      }
    }
  }
}
