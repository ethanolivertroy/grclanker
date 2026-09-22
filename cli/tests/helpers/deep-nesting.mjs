/**
 * Over-depth containers (CodeRabbit on #62, second review, items 2 and 3).
 *
 * The data-side walker of each group B integration (`scrubDataStrings`; `redactSnapshot` in PagerDuty,
 * whose `capture` is the one choke point) rebuilds arrays and plain objects while scrubbing every string
 * leaf, but it must not pass a container nested deeper than MAX_REDACTION_DEPTH through unscrubbed: the
 * payload is server-controlled, so such a container is replaced by the marker instead.
 *
 * Each integration's test plants, in one record of one server payload the export keeps whole, three
 * fields whose leaf object sits at the maximum permitted depth (32: kept, its carrier values replaced in
 * place), one level past it (33: replaced whole), and two past it (34 = MAX + 2: replaced whole along with
 * its ancestor). PagerDuty's redactSnapshot checks the depth before the string branch, so at the maximum
 * depth it keeps the leaf's keys and replaces every value with the marker (stricter, not a leak); its test
 * asserts that shape through the `stringsPastDepth: "replaced"` option. The leaf carries a token-shaped and a name-shaped credential inside a free-text field's
 * carriers (`Authorization: Bearer`, `Cookie: sid=`); the over-depth leaves also carry them bare under
 * credential-named keys and bare in prose, which only the whole-container replacement can remove. A plain
 * marker string in each leaf shows whether the structure survived.
 *
 * Depth is counted from the walker's root (0). `deepFields(fieldDepth)` takes the depth the planted
 * fields' values will have (their parent container's depth plus one) and nests each leaf so it lands at
 * exactly 32, 33, and 34 levels from that root.
 */
import { assertFragmentsAbsent, assertPlantedValuesWellFormed, shortestWindows } from "./planted-values.mjs";

/** Mirrors MAX_REDACTION_DEPTH in the five integrations. */
export const MAX_REDACTION_DEPTH = 32;

/** The marker every integration writes for a redacted value. */
export const REDACTED = "[REDACTED]";

/**
 * Per planted depth: a token-shaped credential (random alphanumeric, distinct in every 6-character
 * window) and a name-shaped one (letter words joined by hyphens, the shape the scrub boundary keeps bare).
 */
export const DEEP_CANARY = Object.freeze({
  control: Object.freeze({ token: "7SL8bSc4vaQfeUevsHjnBuYu", name: "cfzbt-zkuvg-zpuwz" }),
  boundary: Object.freeze({ token: "YnNZJZhaMXkHLJhLNpaXBFGM", name: "ebpau-skzkr-qaerp" }),
  over: Object.freeze({ token: "sTwpLhNBeyQfbAQX2HADDhx3", name: "rnrnj-dfema-rpgpu" }),
});

/** The structure markers: present in an output only when the leaf that carries it survived. */
export const DEEP_MARKER = Object.freeze({
  control: "deep-control-structure-kept",
  boundary: "deep-boundary-structure",
  over: "deep-over-structure",
});

/** The field names planted on the record, so an output can show the record kept them. */
export const DEEP_FIELDS = Object.freeze(["deep_control", "deep_boundary", "deep_over"]);

/** The free-text carriers: a bearer scheme and a quoted cookie value on one compound line. */
export function carrierText({ token, name }) {
  return `Authorization: Bearer ${token}; Cookie: sid="${name}"`;
}

/** The key the control leaf carries its marker under; its survival shows the structure survived. */
export const CONTROL_MARKER_KEY = "deep_marker_key";

/** The leaf at the maximum permitted depth: a marker and the carriers in free text (structure kept, values replaced in place). */
export function controlLeaf() {
  return { [CONTROL_MARKER_KEY]: DEEP_MARKER.control, description: carrierText(DEEP_CANARY.control) };
}

/** An over-depth leaf: the marker, the carriers in free text, and the credentials bare under credential-named keys and in prose. */
export function overDepthLeaf(canary, marker) {
  return {
    marker,
    password: canary.token,
    client_secret: canary.name,
    description: carrierText(canary),
    note: `${canary.name} standing in prose beside ${canary.token}`,
  };
}

/** `leaf` wrapped in `levels` containers, alternating array and object so both walker branches are exercised. */
export function nest(leaf, levels) {
  let value = leaf;
  for (let level = 0; level < levels; level += 1) value = level % 2 === 0 ? [value] : { nested: value };
  return value;
}

/**
 * The three planted fields for a record whose field values sit at `fieldDepth` from the walker's root:
 * the control leaf lands at MAX_REDACTION_DEPTH, the boundary leaf one past it, the over leaf two past it.
 */
export function deepFields(fieldDepth) {
  return {
    deep_control: nest(controlLeaf(), MAX_REDACTION_DEPTH - fieldDepth),
    deep_boundary: nest(overDepthLeaf(DEEP_CANARY.boundary, DEEP_MARKER.boundary), MAX_REDACTION_DEPTH + 1 - fieldDepth),
    deep_over: nest(overDepthLeaf(DEEP_CANARY.over, DEEP_MARKER.over), MAX_REDACTION_DEPTH + 2 - fieldDepth),
  };
}

/** Every planted credential value, token and name shapes alike. */
export function plantedDeepValues() {
  return Object.values(DEEP_CANARY).flatMap(({ token, name }) => [token, name]);
}

/**
 * Wraps a fetch implementation so the JSON payload of every successful response whose URL satisfies
 * `matches` is passed through `plant` (which mutates and returns it); everything else passes through.
 */
export function plantingFetch(fetchImpl, matches, plant) {
  return async (input, init) => {
    const response = await fetchImpl(input, init);
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (!matches(url) || !response.ok || !/json/i.test(response.headers.get("content-type") ?? "")) return response;
    const text = await response.text();
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      return new Response(text, { status: response.status, statusText: response.statusText, headers: response.headers });
    }
    const headers = new Headers(response.headers);
    headers.delete("content-length");
    return new Response(JSON.stringify(plant(parsed, url)), { status: response.status, statusText: response.statusText, headers });
  };
}

/**
 * The fixture self-check for the planted values: the tokens are alphanumeric and distinct in every
 * 6-character window, and no 6-character window of any token or name occurs in the healthy outputs.
 */
export function assertDeepCanariesWellFormed(assert, healthyTexts) {
  const tokens = Object.fromEntries(Object.entries(DEEP_CANARY).map(([depth, { token }]) => [`${depth} token`, token]));
  assertPlantedValuesWellFormed(assert, tokens, healthyTexts);
  for (const [depth, { name }] of Object.entries(DEEP_CANARY)) {
    assert.match(name, /^[a-z]+(?:-[a-z]+)+$/, `${depth} name is name-shaped: ${name}`);
    for (const window of shortestWindows(name)) {
      for (const [label, text] of healthyTexts) assert.ok(!text.includes(window), `window ${window} of the ${depth} name occurs in legitimate text ${label}`);
    }
  }
}

/**
 * The assertion set over the harvested outputs (`texts`: named [label, text] pairs from the access check,
 * the assessments, the bundle files, and the zip entries):
 *  - no planted credential survives in any 6-to-24-character window anywhere;
 *  - the record kept the three planted fields (so a missing marker means replacement, not projection);
 *  - the control leaf at the maximum permitted depth reached an output with its keys (structure kept) and,
 *    with `stringsPastDepth: "scrubbed"` (scrubDataStrings), its marker intact and its carrier values
 *    replaced in place, or, with `"replaced"` (PagerDuty's redactSnapshot), every value the marker;
 *  - the boundary and over-depth leaves did not (replaced whole by the marker).
 */
export function assertDeepNesting(assert, texts, { stringsPastDepth = "scrubbed" } = {}) {
  const planted = plantedDeepValues();
  for (const [label, text] of texts) assertFragmentsAbsent(assert, text, planted, label);
  const joined = texts.map(([, text]) => text).join("\n");
  for (const field of DEEP_FIELDS) assert.ok(joined.includes(`"${field}"`), `the record kept the planted field ${field}`);
  const withControl = texts.filter(([, text]) => text.includes(`"${CONTROL_MARKER_KEY}"`));
  assert.ok(withControl.length > 0, "the control leaf at the maximum permitted depth reached an output with its structure kept");
  for (const [label, text] of withControl) {
    if (stringsPastDepth === "scrubbed") {
      assert.ok(text.includes(DEEP_MARKER.control), `${label}: the control's marker string is kept`);
      assert.ok(text.includes(`Authorization: ${REDACTED}`), `${label}: the control's bearer value is replaced in place`);
    } else {
      assert.ok(!text.includes(DEEP_MARKER.control), `${label}: every value of the control leaf is replaced`);
      assert.match(text, new RegExp(`"${CONTROL_MARKER_KEY}":\\s*"\\[REDACTED\\]"`), `${label}: the control's marker value is the redaction marker`);
    }
  }
  assert.ok(!joined.includes(DEEP_MARKER.boundary), "the leaf one level past the maximum depth is replaced whole");
  assert.ok(!joined.includes(DEEP_MARKER.over), "the leaf at MAX_REDACTION_DEPTH + 2 is replaced whole");
  assert.ok(joined.includes(REDACTED), "the over-depth containers are written as the marker");
}
