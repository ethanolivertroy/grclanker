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
  // A credential word in a hyphenated name (access-token) or a lowercase scheme word before a lowercase word is prose, not a carrier.
  "Auth mode access-token against https://login.salesforce.com, instance https://acme.my.salesforce.com, API v64.0.",
  // camelCase identifiers may carry short acronyms and version suffixes.
  "CSRF flags enableCSRFOnGet and enableCSRFOnPost were not exposed by SecuritySettings; connectedAppOAuth and sessionTimeoutSAML were read",
  "None of the enabled prevention policies expose ScriptBasedExecutionMonitoring, InterpreterProtection, EngineProtectionV2",
  "OAuth token usage was not checked because the OauthToken read was forbidden; the bearer token was refreshed",
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

/**
 * Path skeletons keep their word-like pieces. A canonical UUID (an Anypoint organization id, a Falcon
 * user uuid) is a vendor identifier and stays; a 32-hex sys_id is indistinguishable from an MD5 digest
 * and goes with the hex-digest rule.
 */
export const PATH_CASES = [
  { text: "for /accounts/api/organizations/550e8400-e29b-41d4-a716-446655440000/members", expected: "for /accounts/api/organizations/550e8400-e29b-41d4-a716-446655440000/members" },
  { text: "for /api/now/table/sys_user/6816f79cc0a8016401c5a33be04be441", expected: `for /api/now/table/sys_user/${REDACTED}` },
];

/** HTTP status lines as describeStatus and `${status} ${statusText}` render them; every integration's error strings carry them. */
export const HTTP_STATUS_TEXTS = [
  "200 OK",
  "400 Bad Request",
  "401 Unauthorized",
  "403 Forbidden",
  "404 Not Found",
  "429 Too Many Requests",
  "500 Internal Server Error",
  "502 Bad Gateway",
  "503 Service Unavailable",
  "504 Gateway Timeout",
];

/**
 * Addendum 7 must-keep table for one integration. Every entry is rendered by `keepTableLines` in isolation
 * and inside a realistic sentence of the kind the integration's error strings, inventories, and finding
 * summaries carry, and `assertScrubBoundary` asserts each line comes back verbatim.
 *
 * @typedef {object} KeepTable
 * @property {string[]} paths every endpoint path the integration requests
 * @property {string[]} tables every table, object, or dataset name the integration requests, as the inventories name them
 * @property {string[]} tenants tenant and org names with digits and hyphens
 * @property {string[]} principals principal identifiers in the vendor's shapes
 * @property {string[]} findingIds the integration's finding ids
 * @property {string[]} fixedTexts the standing fixed texts (loader, opaque-body, not requested, withheld, skipped, corollary wordings)
 * @property {string[]} [statusTexts] defaults to HTTP_STATUS_TEXTS
 */

/**
 * Renders each table entry in isolation and inside a realistic summary sentence: an endpoint path in
 * an error string, a table in an inventory state and a collection issue, a tenant in an access check
 * summary, a principal in a finding summary, a status text in an opaque-body note, a finding id in a
 * demotion summary, and a fixed text after a finding id and tenant.
 */
export function keepTableLines(table) {
  for (const key of ["paths", "tables", "tenants", "principals", "findingIds", "fixedTexts"]) {
    assert.ok(Array.isArray(table[key]) && table[key].length > 0, `keep table: ${key} lists at least one entry`);
  }
  const statusTexts = table.statusTexts ?? HTTP_STATUS_TEXTS;
  const [path] = table.paths;
  const [tenant] = table.tenants;
  const [principal] = table.principals;
  const [findingId] = table.findingIds;
  const lines = [];
  const add = (value, ...sentences) => {
    assert.equal(typeof value, "string", `keep table entry is a string: ${JSON.stringify(value)}`);
    assert.ok(value.length > 0, "keep table entry is not empty");
    for (const sentence of sentences) assert.ok(sentence.includes(value), `sentence embeds ${JSON.stringify(value)}: ${sentence}`);
    lines.push(value, ...sentences);
  };
  for (const item of table.paths) {
    add(
      item,
      `request failed (403 Forbidden) for ${item}: JSON body without documented error fields (application/json, 42 bytes)`,
      `${item} answered 200 OK on ${tenant}; 2 of 2 pages were read and the read was complete`,
    );
  }
  for (const item of table.tables) {
    add(
      item,
      `${item} read: complete (12 rows of 12)`,
      `${item} read: unread (request failed (403 Forbidden) for ${path}: Insufficient rights to query records)`,
      `the ${item} read was forbidden (403 Forbidden) on ${tenant}, so ${findingId} is manual and names ${item}`,
    );
  }
  for (const item of table.tenants) {
    add(item, `Connected to ${item} as ${principal}; every surface answered and ${path} was readable`);
  }
  for (const item of table.principals) {
    add(
      item,
      `Among the visible rows, ${item} holds an administrative role on ${tenant} and has not signed in for 90+ days`,
      `${findingId} names ${item} from a complete read of ${path}`,
    );
  }
  for (const item of statusTexts) {
    add(item, `request failed (${item}) for ${path}: non-JSON body (text/html, 5120 bytes)`);
  }
  for (const item of table.findingIds) {
    add(item, `${item} is manual because the ${path} read was forbidden (403 Forbidden) on ${tenant}; the verdict is capped and the inventory is named`);
  }
  for (const item of table.fixedTexts) {
    add(item, `${findingId} on ${tenant}: ${item}`);
  }
  return lines;
}

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
 * @param {KeepTable} [options.keepTable] the integration's addendum 7 must-keep table; every entry is asserted verbatim in
 *   isolation and inside a realistic summary sentence
 */
export function assertScrubBoundary({ scrub, registerSecret, mustKeep = [], keepTable }) {
  for (const keep of [...MUST_KEEP, ...mustKeep, ...(keepTable ? keepTableLines(keepTable) : [])]) {
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
