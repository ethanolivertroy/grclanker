/**
 * Scrub boundary matrix (coordinator ruling on the scrub boundary).
 *
 * A bare value shaped like a name (words joined by hyphens or underscores with at most one numeric
 * segment, such as prod-us-east-2026) standing alone in prose is indistinguishable from a resource
 * name and stays. Two guards make that safe, and both are construction requirements for every
 * integration's redaction pass:
 *
 * 1. a value inside any carrier (Authorization, Cookie, Set-Cookie, x-api-key and similar headers;
 *    cookie or session assignments; URL userinfo and query pairs; the schemes Bearer, Basic, Digest,
 *    Token, ApiKey; credential-named key-value pairs; SOAP session elements) is removed whatever its
 *    shape;
 * 2. a registered secret (KNOWN_SECRETS, that is the client's own credentials) is removed whatever
 *    its shape and in its base64, base64url, URL-encoded, and JSON-escaped forms.
 *
 * Real token shapes (16 or more characters with base64 symbols, scattered digits, or token casing,
 * hex digests, vendor prefixes, JWTs, PEM blocks) are still removed bare.
 *
 * The matrix drives one integration's pass through `scrub(text)`; `registerSecret(secret)` registers
 * a credential through the integration's real path (constructing a client with it). The encoded
 * forms are computed here, independently of the implementation.
 */
import assert from "node:assert/strict";
import { assertFragmentsAbsent, shortestWindows } from "./planted-values.mjs";

export const REDACTED = "[REDACTED]";

/**
 * Name-shaped like the ruling's own example (sess-canary-COOKIE-31415926535897): three word segments
 * and one numeric segment, but random-looking so no 6-character window of it can coincide with a
 * carrier label or ordinary prose. Its removal from a carrier can only come from the carrier guard.
 */
export const NAME_SHAPED_CANARY = "vqzk-xwjr-HTBM-40928375611";

/**
 * Two secrets to register: one name-shaped, so its bare removal can only come from registration,
 * and one whose every encoded form differs from the raw form.
 */
export const REGISTERED_SECRETS = {
  nameShaped: "qhvz-wkxj-YRPL-7261",
  symbolic: 'Vq7@kZ+2/wP="9rT4x"',
};

(() => {
  const owners = new Map();
  for (const [name, value] of [["NAME_SHAPED_CANARY", NAME_SHAPED_CANARY], ...Object.entries(REGISTERED_SECRETS)]) {
    for (const window of shortestWindows(value)) {
      const owner = owners.get(window);
      assert.equal(owner, undefined, `window ${window} appears in both ${owner} and ${name}`);
      owners.set(window, name);
      assert.equal(window.includes(REDACTED.slice(0, 3)), false, `window ${window} of ${name} overlaps the redaction marker`);
    }
  }
})();

/** Bare name-shaped values and ordinary operator prose that must come through verbatim. */
export const MUST_KEEP = [
  "Region prod-us-east-2026 rejected the request",
  "session sess-canary-COOKIE-31415926535897 closed",
  `session ${NAME_SHAPED_CANARY} closed`,
  "table sys_user_has_role and sys_user_grmember were read for Acme_Production_Org",
  "cipher TLS_AES_256_GCM_SHA384 on acme-corp-dev12345.example.com with oauth2-client-credentials",
  "content type application/x-www-form-urlencoded; the bearer token is missing; basic auth required; token request failed",
  "request failed (403) for /policy/combined/device-control/v1 and /fwmgr/queries/rule-groups/v1",
  "request failed (502 Bad Gateway) for /oauth/token: non-JSON body (text/html, 5120 bytes)",
  "Unable to read config file /tmp/grclanker-loader-Ab3dEf/nested-mapping.yaml (EISDIR)",
  "Unable to parse config file: invalid JSON in /tmp/grclanker-loader-x9Q2zR/credentials.json at line 3",
  "Metadata read of SecurityHealthCheckRisks and TwoFactorMethodsInfo failed",
];

/**
 * The name-shaped canary inside every carrier the ruling names. `keeps` is the carrier's own label,
 * which must survive so the reader can still tell what was redacted.
 */
export function carrierCases(canary = NAME_SHAPED_CANARY) {
  return [
    { name: "Authorization Bearer header", text: `Authorization: Bearer ${canary}`, keeps: ["Authorization: "] },
    { name: "authorization Basic assignment", text: `authorization=Basic ${canary}`, keeps: ["authorization="] },
    // Inside a header the whole value is the credential, parameter names included.
    { name: "Authorization Digest parameters in JSON", text: `"Authorization": "Digest username=\\"svc\\", response=\\"${canary}\\""`, keeps: ["\"Authorization\": \""] },
    { name: "JSON-escaped Authorization header", text: `\\"Authorization\\":\\"Bearer ${canary}\\"`, keeps: ["Authorization"] },
    // An unknown scheme takes up to two tokens (`Scheme credential`), so the word after a bare credential goes with it.
    { name: "Proxy-Authorization without a scheme", text: `Proxy-Authorization: ${canary} trailing prose`, keeps: ["Proxy-Authorization: ", " prose"] },
    { name: "Authorization Token token= (PagerDuty scheme)", text: `Authorization: Token token=${canary}`, keeps: ["Authorization: "] },
    { name: "Authorization ApiKey", text: `Authorization: ApiKey ${canary}`, keeps: ["Authorization: "] },
    { name: "Cookie header", text: `Cookie: JSESSIONID=${canary}; theme=dark`, keeps: ["Cookie: "] },
    { name: "Set-Cookie header", text: `Set-Cookie: glide_session_store=${canary}; Path=/; HttpOnly`, keeps: ["Set-Cookie: "] },
    { name: "x-api-key header", text: `x-api-key: ${canary}`, keeps: ["x-api-key: "] },
    { name: "vendor api key header in JSON", text: `"x-sn-apikey": "${canary}"`, keeps: ["x-sn-apikey"] },
    { name: "X-Auth-Token assignment", text: `X-Auth-Token=${canary}`, keeps: ["X-Auth-Token="] },
    { name: "URL userinfo", text: `https://svc:${canary}@api.example.com/v1/x`, keeps: ["https://", "@api.example.com/v1/x"] },
    { name: "URL query pair mid-sentence", text: `see https://api.example.com/v1/x?token=${canary}&state=ok mid-sentence`, keeps: ["https://api.example.com/v1/x?", " mid-sentence"] },
    { name: "bare query pair", text: `bare query ?sid=${canary} pair`, keeps: ["?sid=", " pair"] },
    { name: "Bearer scheme in prose", text: `Bearer ${canary}`, keeps: ["Bearer "] },
    { name: "Basic scheme in prose", text: `Basic ${canary}`, keeps: ["Basic "] },
    { name: "Digest scheme in prose", text: `Digest ${canary}`, keeps: ["Digest "] },
    // A scheme standing in prose keeps its parameter names so the reader can tell which parameter was redacted.
    { name: "Digest parameters in prose", text: `Digest username="svc", response="${canary}"`, keeps: ["Digest username=", "response="] },
    { name: "Token scheme in prose", text: `Token ${canary}`, keeps: ["Token "] },
    { name: "ApiKey scheme in prose", text: `ApiKey ${canary}`, keeps: ["ApiKey "] },
    { name: "Token token= in prose", text: `Token token=${canary}`, keeps: ["Token token="] },
    { name: "lowercase bearer scheme", text: `bearer ${canary}`, keeps: ["bearer "] },
    { name: "client_secret assignment", text: `client_secret=${canary}`, keeps: ["client_secret="] },
    { name: "password field", text: `password: ${canary}`, keeps: ["password: "] },
    { name: "refresh_token JSON field", text: `"refresh_token": "${canary}"`, keeps: ["refresh_token"] },
    { name: "JSON-escaped access_token field", text: `\\"access_token\\":\\"${canary}\\"`, keeps: ["access_token"] },
    { name: "connect.sid cookie assignment", text: `connect.sid=${canary}`, keeps: ["connect.sid="] },
    { name: "PHPSESSID cookie assignment", text: `PHPSESSID=${canary}`, keeps: ["PHPSESSID="] },
    { name: "session assignment", text: `session=${canary}; other=1`, keeps: ["session="] },
    { name: "command-line password flag", text: `--password ${canary}`, keeps: ["--password "] },
    { name: "SOAP sessionId element", text: `<sessionId>${canary}</sessionId>`, keeps: ["<sessionId>", "</sessionId>"] },
    { name: "namespaced SOAP sessionId element", text: `<urn:sessionId>${canary}</urn:sessionId>`, keeps: ["<urn:sessionId>", "</urn:sessionId>"] },
    { name: "SOAP password element", text: `<password>${canary}</password>`, keeps: ["<password>", "</password>"] },
  ];
}

/** Real token shapes that go even when bare. */
export const BARE_TOKENS = [
  { name: "base64 with padding", value: "dGhpcyBpcyBhIHRlc3QgdG9rZW4=" },
  { name: "base64 with plus and slash", value: "Zm9vYmFy+YmF6L3F1eA" },
  { name: "hex-suffixed vendor-style bearer", value: "cs-bearer-CANARY-9f8e7d6c5b4a3210" },
  { name: "scattered digits", value: "a1b2c3d4e5f6a7b8c9d0" },
  { name: "token casing", value: "NbAkKc66ryYTWUXYEuZqRt" },
  { name: "token casing with underscore", value: "y_NbAkKc66ryYTWUXYEu" },
  { name: "md5 hex digest", value: "9f8e7d6c5b4a32109f8e7d6c5b4a3210" },
  { name: "sha1 hex digest", value: "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
  { name: "AWS access key id", value: "AKIAIOSFODNN7EXAMPLE" },
  { name: "Slack bot token", value: "xoxb-1234567890-abcdefghijkl" },
  { name: "Stripe live key", value: "sk_live_4eC39HqLyjWDarjtT1zdp7dc" },
  { name: "GitHub personal access token", value: "ghp_16C7e42F292c6912E7710c838347Ae178B4a" },
  { name: "JWT", value: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkifQ.c2lnbmF0dXJl" },
  { name: "PEM block", value: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC\n-----END PRIVATE KEY-----" },
  { name: "alternating case run", value: "AbCdEfGhIjKlMnOpQr" },
];

/** Path skeletons keep their word-like pieces; only the identifier piece goes. */
export const PATH_CASES = [
  { text: "for /accounts/api/organizations/550e8400-e29b-41d4-a716-446655440000/members", expected: `for /accounts/api/organizations/${REDACTED}/members` },
  { text: "for /api/now/table/sys_user/6816f79cc0a8016401c5a33be04be441", expected: `for /api/now/table/sys_user/${REDACTED}` },
];

/** The raw, base64, base64url, URL-encoded (upper- and lowercase hex, `+` for space), and JSON-escaped forms, deduplicated. */
export function encodedForms(secret) {
  const bytes = Buffer.from(secret, "utf8");
  const urlEncoded = encodeURIComponent(secret);
  return [...new Set([
    secret,
    bytes.toString("base64"),
    bytes.toString("base64url"),
    urlEncoded,
    urlEncoded.replace(/%[0-9A-F]{2}/g, (escape) => escape.toLowerCase()),
    urlEncoded.replace(/%20/g, "+"),
    JSON.stringify(secret).slice(1, -1),
  ])];
}

(() => {
  const forms = encodedForms(REGISTERED_SECRETS.symbolic);
  assert.equal(forms.length, 6, "the symbolic secret has a distinct base64, base64url, URL-encoded (two cases), and JSON-escaped form");
  assert.equal(encodedForms(REGISTERED_SECRETS.nameShaped).length, 3, "the name-shaped secret has distinct base64 and base64url forms only");
})();

/** Removed means no substring of the value at lengths 6 through 24 survives and the marker took its place. */
function assertRemoved(output, value, label) {
  assertFragmentsAbsent(assert, output, [value], `${label}: output ${JSON.stringify(output)}`);
  assert.ok(output.includes(REDACTED), `${label}: no redaction marker: ${JSON.stringify(output)}`);
}

/**
 * Runs the matrix against one redaction surface.
 *
 * @param {object} options
 * @param {(text: string) => string} options.scrub the surface under test (an error constructor, an exported helper, a client's redact)
 * @param {((secret: string) => void) | undefined} options.registerSecret registers a credential through the integration's real
 *   path; when given, the name-shaped secret is first shown to survive bare (unregistered) before it is registered. Pass
 *   undefined for a second surface in the same file, where the secrets are already registered.
 * @param {string[]} [options.mustKeep] integration-specific prose that must come through verbatim
 */
export function assertScrubBoundary({ scrub, registerSecret, mustKeep = [] }) {
  for (const keep of [...MUST_KEEP, ...mustKeep]) {
    assert.equal(scrub(keep), keep, `bare name-shaped or ordinary prose must stay: ${JSON.stringify(keep)}`);
  }

  for (const item of carrierCases()) {
    const output = scrub(item.text);
    assertRemoved(output, NAME_SHAPED_CANARY, `carrier ${item.name}`);
    for (const kept of item.keeps) assert.ok(output.includes(kept), `carrier ${item.name}: label ${JSON.stringify(kept)} must stay: ${JSON.stringify(output)}`);
  }

  if (registerSecret !== undefined) {
    const bare = `echoed ${REGISTERED_SECRETS.nameShaped} in prose`;
    assert.equal(scrub(bare), bare, "positive control: the name-shaped secret survives bare before it is registered");
    registerSecret(REGISTERED_SECRETS.nameShaped);
    registerSecret(REGISTERED_SECRETS.symbolic);
  }
  for (const [label, secret] of Object.entries(REGISTERED_SECRETS)) {
    for (const form of encodedForms(secret)) {
      assertRemoved(scrub(`echoed ${form} in prose`), form, `registered ${label} secret, form ${JSON.stringify(form)}`);
    }
    assertRemoved(scrub(`Authorization: Basic ${Buffer.from(`svc:${secret}`).toString("base64")}`), Buffer.from(`svc:${secret}`).toString("base64"), `registered ${label} secret in a Basic credential`);
  }

  for (const token of BARE_TOKENS) {
    assertRemoved(scrub(`value ${token.value} seen`), token.value, `bare token ${token.name}`);
  }

  for (const item of PATH_CASES) {
    assert.equal(scrub(item.text), item.expected, `path skeleton: ${item.text}`);
  }
}
