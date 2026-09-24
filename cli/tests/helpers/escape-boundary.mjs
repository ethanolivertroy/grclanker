/**
 * Escape-boundary canaries for the 502 tests (reviewer B round 4 verdict, N1).
 *
 * A gateway error whose JSON field holds serialized JSON is doubly encoded: `JSON.stringify` doubles the
 * backslash of every escape on the wire, the client's parse hands the scrubber the literal characters
 * (`\n` as a backslash and an `n`), and a carrier right after such an escape has a word character in front
 * of it. `escapeBoundaryTrace()` renders every literal escape before a cookie pair with a plain name, a
 * URL with a userinfo password, and an X-Api-Key header, carrying a token-shaped and a name-shaped canary,
 * bare and inside a JSON string member; an integration appends it to the message of its JSON canary
 * error body, adds `ESCAPE_CANARIES` to its leak assertion (every 6-to-24-character window), and adds
 * `ESCAPE_CANARY_PLANTED_VALUES` to its fixture self-check.
 */
import { JSON_ESCAPES } from "./scrub-boundary-matrix.mjs";

/**
 * Token-shaped: 18 characters of token casing with scattered digits, so the bare token-run rule would take it
 * standing alone. Name-shaped: three word segments and one numeric segment joined by hyphens, which no bare
 * rule takes, so its removal from a carrier after an escape can only come from the carrier rule's opener.
 */
export const ESCAPE_CANARIES = {
  token: "Hq4vZm8kTw2yXc7RbN",
  name: "kzwqvh-jxnpqv-RXNTWB-7291048536",
};

/** The alphanumeric pieces of the canaries, for `assertPlantedValuesWellFormed` (which requires alphanumeric values). */
export const ESCAPE_CANARY_PLANTED_VALUES = {
  "ESCAPE_CANARIES.token": ESCAPE_CANARIES.token,
  ...Object.fromEntries(ESCAPE_CANARIES.name.split("-").map((segment, index) => [`ESCAPE_CANARIES.name segment ${index + 1}`, segment])),
};

/** The three carriers the verdict names, around one value. */
export function escapeBoundaryCarriers(value) {
  return [`Cookie: theme=${value}`, `https://alice:${value}@host.example/path`, `X-Api-Key: ${value}`];
}

/**
 * The trace: for each literal escape, each carrier, and each canary, the carrier right after the escape, bare
 * and as the member of a serialized JSON object; the parts are single-quoted and comma-separated so each
 * value's carrier ends where the next part begins. Written as a JS string it holds one backslash per escape,
 * which `JSON.stringify` doubles on the wire and the client's parse restores.
 */
export function escapeBoundaryTrace() {
  const parts = [];
  for (const escape of JSON_ESCAPES) {
    for (const value of Object.values(ESCAPE_CANARIES)) {
      for (const carrier of escapeBoundaryCarriers(value)) {
        const bare = `upstream said 502${escape}${carrier}`;
        parts.push(`'${bare}'`, `'{"message":"${bare}"}'`);
      }
    }
  }
  return `the gateway logged ${parts.join(", ")}`;
}
