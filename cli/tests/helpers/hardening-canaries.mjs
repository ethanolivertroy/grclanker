/**
 * Canary fixtures and the fragment assertion for the shared hardening helper tests (rule 9).
 *
 * A leak assertion that looks for the whole planted value passes when only part of it is echoed:
 * `JSON.parse` quotes a 10-character window of the source, a truncated message keeps a prefix, a
 * base64 form loses its tail. `assertNoFragment` therefore checks every substring of the canary at
 * lengths 6 through 24. For that to be meaningful two properties must hold, and `assertCanaryFixture`
 * asserts both: no 6-character window of any canary occurs in a value the output is allowed to carry
 * (a path, a name, fixed text), so the canaries are random alphanumeric strings rather than words; and
 * no 8-character window is shared by two canaries (or repeated inside one), so a leak of one cannot
 * hide behind the absence of another.
 */
import assert from "node:assert/strict";
import { tmpdir } from "node:os";

/** Every substring of a planted value at these lengths must be absent from an output. */
export const FRAGMENT_LENGTHS = Object.freeze({ minLength: 6, maxLength: 24 });

/** The window length at which canaries must be pairwise distinct. */
export const DISTINCT_WINDOW_LENGTH = 8;

/** Values planted on the malformed line of each config-file fixture (coordinator addendum 6b). */
export const CONFIG_CANARY = Object.freeze({
  yamlNestedKey: "KsDA6SpXx5wofyiQ",
  yamlNestedBearer: "Ze7DQQs4s4UDSmrn",
  yamlAlias: "MK6ACAM3wnky25ae",
  yamlTag: "zHmiPLouHVj6Fs3x",
  jsonUnquoted: "hXphKgEwV78ZTrZ2",
  jsonShort: "Anj2cFQJnc",
  jsonTrailingComma: "iLFgRtS2gTAXKo9X",
  lockedFile: "M9JqgDdsH2uDry7e",
});

/**
 * Credential-shaped values for the error-text cases. Each is carried by the header, scheme, cookie,
 * key, or URL part its name says; the JWT is three alphanumeric segments behind the `eyJ` prefix and
 * the AWS key id sits behind `AKIA`, because those rules key on the prefix.
 */
export const ERROR_CANARY = Object.freeze({
  bearer: "WVW8uo3McYS3WA85V68gaMEq",
  basic: "FbhHryEVa6TqBEXUJ2gDGHaG",
  apiKey: "boLPh53qYQfSUibqxt8q8J9w",
  sessionCookie: "zuQ67vY4nN6orJvunrVvBhCi",
  urlToken: "3M8AvBLPJEefqBZVQSy3efNH",
  jwt: "eyJbykiSPLqArvPw4.ExXEN7i7m4FXoBgkSihy.x3eEbtebSBXxCMHhyF6M",
  awsAccessKeyId: "AKIA4TYT9MUPC7SKDHHG",
  awsSecret: "t4siE8a4gqtrY9p2LfZg3swBbeChGRBsAQnuNKWK",
  configured: "q4SX5siRZT6eH5uhk7uC",
});

/**
 * A configured secret with the characters the Flue encoded forms change (space, `+`, `/`, `=`, `@`,
 * `&`), so the URL-encoded and JSON-escaped forms differ from the plain one. Not alphanumeric by
 * design; it is checked against the legitimate values like every canary.
 */
export const ENCODED_FORM_SECRET = "p@ss w0rd/Zq7+Vx=Kn2&Rt9";

export const ERROR_CANARY_URL = `https://api.example.com/v1/x?token=${ERROR_CANARY.urlToken}`;

/** A proxy error page with every carrier embedded mid-sentence. */
export function htmlCanaryPage() {
  return [
    "<html><head><title>502 Bad Gateway</title></head><body>",
    `<p>The upstream rejected Authorization: Bearer ${ERROR_CANARY.bearer} while replaying`,
    `Set-Cookie: session=${ERROR_CANARY.sessionCookie}; Path=/; HttpOnly and x-api-key: ${ERROR_CANARY.apiKey} for the caller;`,
    `retry the request at ${ERROR_CANARY_URL} once the incident clears.</p>`,
    "</body></html>",
  ].join("\n");
}

/** A vendor-shaped error message that embeds the canary URL mid-sentence. */
export function jsonCanarySentence() {
  return `Access denied while fetching ${ERROR_CANARY_URL} for the caller; retry after re-authenticating.`;
}

/**
 * Text the outputs under test are allowed to carry: paths and names from the fixtures, the fixed
 * texts of the helpers, the prose of the cases, and the identifiers the must-keep tests preserve.
 * No 6-character window of a canary may occur in any of these.
 */
export const LEGITIMATE_VALUES = Object.freeze([
  // config-file fixtures and fixed texts
  "hardening-config-",
  "config.yaml",
  "config.json",
  "missing.yaml",
  "/tmp/config.yaml",
  "/tmp/config.json",
  "/etc/demo.yaml",
  "name: demo",
  "key",
  "token",
  "custom",
  "New Relic",
  "Zoom",
  "Unable to read config file",
  "Unable to parse config file: invalid YAML in",
  "Unable to parse config file: invalid JSON in",
  "invalid TOML in",
  "invalid config in",
  "at line",
  "column",
  "INVALID_YAML",
  "INVALID_JSON",
  "INVALID_TOML",
  "INVALID_CONFIG",
  "BLOCK_AS_IMPLICIT_KEY",
  "DUPLICATE_KEY",
  "TAB_AS_INDENT",
  "EISDIR",
  "EACCES",
  "ENOENT",
  "ENOTDIR",
  "ERR_FS_FILE_TOO_LARGE",
  "ERR_INVALID_ARG_TYPE",
  "Nested mappings are not allowed in compact mappings",
  "is not valid JSON",
  "Unexpected token",
  "Unresolved alias (the anchor must be set before the alias)",
  "illegal operation on a directory",
  "permission denied",
  "no such file or directory",
  // error-text fixed texts and names
  "[REDACTED]",
  "[truncated]",
  "non-JSON body",
  "malformed JSON body",
  "empty body",
  "JSON body without a documented message field",
  "bytes",
  "failed with",
  "Bad Gateway",
  "unknown status",
  "Request",
  "cause chain truncated",
  "Error without a message",
  "unknown error",
  "AggregateError",
  "IntegrationError",
  "DemoApiError",
  "AccessDeniedException",
  "E0000011",
  "text/html",
  "application/json",
  "application/problem+json",
  "text/plain",
  "text/json",
  "unknown",
  // URLs, paths, and headers the outputs keep
  "https://api.example.com/v1/x",
  "https://api.example.com/v1/y",
  "https://host.example/path/x",
  "https://docs.example.com/guide/setup",
  "/v1/users",
  "/v1/roles",
  "page=2",
  "api_key=",
  "sig=",
  "Authorization: Bearer",
  "Set-Cookie: session=",
  "Path=/; HttpOnly",
  "x-api-key:",
  "Basic",
  "Digest",
  "SSWS",
  // prose of the cases and the must-keep identifiers
  "The upstream rejected",
  "while replaying",
  "for the caller",
  "retry the request at",
  "once the incident clears",
  "Access denied while fetching",
  "retry after re-authenticating",
  "upstream said",
  "was rejected",
  "rejected",
  "proxy replayed",
  "and failed",
  "credentials",
  "were rejected",
  "for details",
  "GET failed:",
  "request failed",
  "denied",
  "missing",
  "several",
  "member",
  "and 2 more",
  "outer",
  "inner",
  "second",
  "invalid_client",
  "invalid_grant",
  "bad secret",
  "Forbidden",
  "Token",
  "expired",
  "cause one",
  "array root",
  "alice",
  "entity",
  "not found",
  "policy",
  "InvalidAuthenticationToken: Access token has expired. Basic authentication is disabled for this tenant.",
  "Bearer token-based auth is required",
  "the token authentication flow failed",
  "Digest access authentication",
  "4f3a9c1b7e2d8f6a0b5c4d3e2f1a0b9c",
  "123e4567-e89b-12d3-a456-426614174000",
  "ERR_FS_FILE_TOO_LARGE and BLOCK_AS_IMPLICIT_KEY returned",
  "InvalidAuthenticationTokenProvided by the caller",
  "count 12345678901234567890 exceeded",
  "the Content-Security-Policy-Report-Only header was set",
  "region us-east-1 and stage snake_case_identifier_here",
  "passcode",
  "cabbage stays",
  "nothing configured",
]);

/** Every substring of `canary` whose length lies in the range, longest first so a failure names the largest echo. */
export function fragmentsOf(canary, { minLength = FRAGMENT_LENGTHS.minLength, maxLength = FRAGMENT_LENGTHS.maxLength } = {}) {
  const fragments = [];
  const longest = Math.min(maxLength, canary.length);
  for (let length = longest; length >= minLength; length -= 1) {
    for (let index = 0; index + length <= canary.length; index += 1) fragments.push(canary.slice(index, index + length));
  }
  return fragments;
}

/** True when `text` carries any window of `canary` at the given length; the positive controls use it to prove the library echoed the value. */
export function carriesFragment(text, canary, length = DISTINCT_WINDOW_LENGTH) {
  return fragmentsOf(canary, { minLength: length, maxLength: length }).some((fragment) => text.includes(fragment));
}

/**
 * Asserts that no substring of `canary` at lengths `minLength` through `maxLength` (6 through 24 by
 * default) occurs in `output`, which may be a string or any value (serialised with `JSON.stringify`).
 */
export function assertNoFragment(output, canary, { minLength = FRAGMENT_LENGTHS.minLength, maxLength = FRAGMENT_LENGTHS.maxLength, label = "output" } = {}) {
  const text = typeof output === "string" ? output : JSON.stringify(output);
  assert.ok(typeof text === "string", `${label}: output did not serialise to text`);
  assert.ok(canary.length >= minLength, `${label}: canary ${JSON.stringify(canary)} is shorter than the ${minLength}-character minimum window`);
  for (const fragment of fragmentsOf(canary, { minLength, maxLength })) {
    assert.ok(!text.includes(fragment), `${label}: fragment ${JSON.stringify(fragment)} of canary ${JSON.stringify(canary)} leaked into ${JSON.stringify(text)}`);
  }
}

/** `assertNoFragment` over several canaries. */
export function assertNoFragments(output, canaries, options = {}) {
  for (const canary of canaries) assertNoFragment(output, canary, options);
}

/** Every canary the fixture plants, plus the encoded-form secret. */
export function allPlantedValues() {
  return [...Object.values(CONFIG_CANARY), ...Object.values(ERROR_CANARY), ENCODED_FORM_SECRET];
}

/**
 * Asserts that no 6-character window of any planted value occurs in `texts`, the values an output is
 * allowed to carry. A test with its own legitimate values (a must-keep table, sentence templates)
 * runs this over them so its negative assertions cannot fail on a coincidence.
 */
export function assertNoCanaryWindowIn(texts, planted = allPlantedValues()) {
  for (const value of planted) {
    for (const fragment of fragmentsOf(value, { minLength: FRAGMENT_LENGTHS.minLength, maxLength: FRAGMENT_LENGTHS.minLength })) {
      for (const text of texts) {
        assert.ok(!text.includes(fragment), `window ${JSON.stringify(fragment)} of planted value ${JSON.stringify(value)} occurs in legitimate value ${JSON.stringify(text)}`);
      }
    }
  }
}

/**
 * The fixture self-check: canaries are alphanumeric (the JWT is dot-joined alphanumeric segments),
 * pairwise distinct in every 8-character window with no window repeated inside one, and no
 * 6-character window of any planted value occurs in a legitimate value or in the temp directory path.
 */
export function assertCanaryFixture() {
  const canaries = [...Object.values(CONFIG_CANARY), ...Object.values(ERROR_CANARY)];
  for (const canary of canaries) {
    assert.match(canary, /^[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*$/, `canary ${canary} is not alphanumeric`);
    assert.ok(canary.length >= 10, `canary ${canary} is too short to carry distinct windows`);
  }
  const planted = allPlantedValues();
  const windows = planted.flatMap((value) => fragmentsOf(value, { minLength: DISTINCT_WINDOW_LENGTH, maxLength: DISTINCT_WINDOW_LENGTH }));
  assert.equal(new Set(windows).size, windows.length, `two planted values share a ${DISTINCT_WINDOW_LENGTH}-character window, or one repeats a window`);
  assertNoCanaryWindowIn([...LEGITIMATE_VALUES, tmpdir()], planted);
}
