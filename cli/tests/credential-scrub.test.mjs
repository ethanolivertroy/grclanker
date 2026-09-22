import test from "node:test";
import assert from "node:assert/strict";
import {
  LONG_TOKEN_MIN_LENGTH,
  MIN_CONFIGURED_SECRET_LENGTH,
  REDACTED,
  createCredentialScrubber,
  isCredentialDataKey,
  isCredentialKey,
  looksLikeToken,
} from "../dist/extensions/grc-tools/credential-scrub.js";
import { assertCanaryFixture, assertCanaryWindowsAbsent } from "./helpers/canary-windows.mjs";
import { scrubAlterations } from "./helpers/scrub-survival.mjs";

// ---------------------------------------------------------------------------------------------------------------
// The coordinator's ruling on the scrub boundary. A bare value shaped like a name (words joined by hyphens or
// underscores with at most one numeric segment) standing alone in prose is indistinguishable from a resource name and
// stays. Two guards make that safe: a value inside any carrier is removed whatever its shape, and a configured secret
// is removed whatever its shape in every encoded form. Real token shapes are still removed bare.
// ---------------------------------------------------------------------------------------------------------------

/** Name-shaped values from the ruling: they stay bare and go inside every carrier. */
const NAME_SHAPED = ["prod-us-east-2026", "sess-canary-COOKIE-31415926535897", "canary-empty-team-zq", "CanaryRequireSsoChangeZq"];

/** Real token shapes: removed wherever they stand. */
const TOKEN_SHAPED = {
  scatteredDigits: "Kq7Zx2Vw9Lm4Tp8RfiCYcanaryKEY",
  hexSegment: "BEARER_CANARY_9f8e7d6c5b4a3210",
  tokenCasing: "bPxRfiCYwQmZkTnHvJdLsG",
  base64Padded: "QUJDREVGR0hJSktMTU5PUA==",
  base64Symbols: "QUJDR+VGR0hJSktMTU5PU/A",
  md5: "0f9e8d7c6b5a49380f9e8d7c6b5a4938",
  sha1: "abcdef0123456789abcdefabcdefabcdabcdef01",
  jwt: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkifQ.c2lnbmF0dXJlY2FuYXJ5",
  awsAccessKeyId: "AKIAIOSFODNN7EXAMPLE",
  awsSecret: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  slack: "xoxb-1234567890-abcdefghijklmnop",
  github: "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
  googleApiKey: "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q",
  stripe: "sk_live_abcdefghijklmnop1234",
  pem: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n-----END PRIVATE KEY-----",
};

/** Carriers from the ruling, each wrapping a value; the value must go whatever its shape. */
const CARRIERS = [
  ["Authorization header", (value) => `upstream sent Authorization: Bearer ${value}; retry later`],
  ["Authorization header, Basic", (value) => `Authorization: Basic ${value}`],
  ["Proxy-Authorization header", (value) => `Proxy-Authorization=Bearer ${value}`],
  ["Cookie header", (value) => `Cookie: sid=${value}; Path=/; HttpOnly`],
  ["Set-Cookie header", (value) => `Set-Cookie: JSESSIONID=${value}; Secure`],
  ["x-api-key header", (value) => `x-api-key: ${value}`],
  ["X-Auth-Token header", (value) => `X-Auth-Token: ${value}`],
  ["x-vault-token header", (value) => `x-vault-token=${value}`],
  ["custom x- credential header", (value) => `X-Canary-Session-Key: ${value}`],
  ["cookie assignment in text", (value) => `the response set session=${value} before failing`],
  ["session id assignment", (value) => `session_id: ${value}`],
  ["sid assignment", (value) => `sid=${value}`],
  ["csrf token assignment", (value) => `csrf_token="${value}"`],
  ["URL userinfo", (value) => `fetched https://user:${value}@api.example.com/v1/x mid-sentence`],
  ["URL query pair", (value) => `see https://api.example.com/v1/x?token=${value} for details`],
  ["URL fragment", (value) => `see https://api.example.com/v1/x#access_token=${value} for details`],
  ["relative query pair", (value) => `GET /api/v2/x?api_key=${value}&env=production`],
  ["relative query pair, later parameter", (value) => `GET /v1/users?page=2&sig=${value}`],
  ["Bearer scheme", (value) => `Bearer ${value}`],
  ["Basic scheme", (value) => `Basic ${value}`],
  ["Token scheme", (value) => `Token ${value}`],
  ["ApiKey scheme", (value) => `ApiKey ${value}`],
  ["token pair", (value) => `token=${value}`],
  ["password pair, JSON", (value) => `{"password": "${value}"}`],
  ["api_key pair", (value) => `api_key: ${value}`],
  ["client_secret pair", (value) => `client_secret=${value}`],
  ["secret pair", (value) => `secret: ${value}`],
  ["private_key pair", (value) => `private_key: ${value}`],
  ["access_token pair, quoted", (value) => `'access_token': '${value}'`],
  ["credentials pair", (value) => `credentials=${value}`],
  ["signature pair", (value) => `signature=${value}`],
  ["dd-api-key pair", (value) => `dd-api-key: ${value}`],
];

/**
 * The quoted carrier class (rule 9): a quoted header or pair value is removed whole up to its closing quote, whatever
 * its shape and whatever it holds, in double or single quotes, with or without spaces around the separator, and in
 * JSON and JSON-escaped text. A scrubber that stops at the opening quote leaves the value; one that stops at the first
 * space inside the quotes leaves the rest. Each row wraps a value and states the text expected once it is gone: the
 * quotes and the scheme word stay so the message still says what was replayed.
 */
const QUOTED_CARRIERS = [
  ["Cookie header, double-quoted pair value", (value) => `Cookie: sid="${value}"`, () => `Cookie: ${REDACTED}`],
  ["Cookie header, single-quoted pair value with attributes", (value) => `Cookie: sid='${value}'; Path=/; HttpOnly`, () => `Cookie: ${REDACTED}`],
  ["Cookie header, whole value quoted", (value) => `Cookie: "sid=${value}; Path=/"`, () => `Cookie: "${REDACTED}"`],
  ["Set-Cookie header, quoted pair value", (value) => `Set-Cookie: JSESSIONID="${value}"; Secure`, () => `Set-Cookie: ${REDACTED}`],
  ["Cookie JSON pair", (value) => `"Cookie": "sid=${value}"`, () => `"Cookie": "${REDACTED}"`],
  ["Cookie JSON pair, escaped", (value) => `\\"Cookie\\":\\"sid=${value}\\"`, () => `\\"Cookie\\":\\"${REDACTED}\\"`],
  ["X-Api-Key header, double quotes", (value) => `X-Api-Key: "${value}"`, () => `X-Api-Key: "${REDACTED}"`],
  ["X-Api-Key header, no spaces", (value) => `X-Api-Key:"${value}"`, () => `X-Api-Key:"${REDACTED}"`],
  ["X-Api-Key header, single quotes", (value) => `X-Api-Key: '${value}'`, () => `X-Api-Key: '${REDACTED}'`],
  ["X-Api-Key header, equals separator", (value) => `X-Api-Key = "${value}"`, () => `X-Api-Key = "${REDACTED}"`],
  ["X-Api-Key JSON pair", (value) => `"X-Api-Key": "${value}"`, () => `"X-Api-Key": "${REDACTED}"`],
  ["X-Api-Key JSON pair, escaped", (value) => `\\"X-Api-Key\\": \\"${value}\\"`, () => `\\"X-Api-Key\\": \\"${REDACTED}\\"`],
  ["X-Api-Key JSON pair, escaped twice", (value) => `\\\\\\"X-Api-Key\\\\\\": \\\\\\"${value}\\\\\\"`, () => `\\\\\\"X-Api-Key\\\\\\": \\\\\\"${REDACTED}\\\\\\"`],
  ["X-Auth-Token header, quoted", (value) => `X-Auth-Token: "${value}"`, () => `X-Auth-Token: "${REDACTED}"`],
  ["custom x- credential header, quoted", (value) => `X-Vendor-Session-Key: '${value}'`, () => `X-Vendor-Session-Key: '${REDACTED}'`],
  ["Authorization header, quoted value after the scheme", (value) => `Authorization: Bearer "${value}"`, () => `Authorization: Bearer "${REDACTED}"`],
  ["Authorization header, single-quoted value after the scheme", (value) => `Authorization: Bearer '${value}'`, () => `Authorization: Bearer '${REDACTED}'`],
  ["Authorization header, scheme inside the quotes", (value) => `Authorization: "Bearer ${value}"`, () => `Authorization: "Bearer ${REDACTED}"`],
  ["Authorization header, Basic quoted", (value) => `Authorization: Basic "${value}"`, () => `Authorization: Basic "${REDACTED}"`],
  ["Authorization JSON pair", (value) => `"Authorization": "Bearer ${value}"`, () => `"Authorization": "Bearer ${REDACTED}"`],
  ["Authorization JSON pair, escaped", (value) => `\\"Authorization\\": \\"Bearer ${value}\\"`, () => `\\"Authorization\\": \\"Bearer ${REDACTED}\\"`],
  ["Authorization JSON pair, escaped, no spaces", (value) => `\\"Authorization\\":\\"Bearer ${value}\\"`, () => `\\"Authorization\\":\\"Bearer ${REDACTED}\\"`],
  ["Proxy-Authorization header, quoted", (value) => `Proxy-Authorization: 'Basic ${value}'`, () => `Proxy-Authorization: 'Basic ${REDACTED}'`],
  ["Bearer scheme in prose, quoted", (value) => `upstream rejected Bearer "${value}" mid-sentence`, () => `upstream rejected Bearer "${REDACTED}" mid-sentence`],
  ["session assignment, quoted", (value) => `session_id: "${value}"`, () => `session_id: "${REDACTED}"`],
  ["sid JSON pair, escaped", (value) => `\\"sid\\": \\"${value}\\"`, () => `\\"sid\\": \\"${REDACTED}\\"`],
  ["password JSON pair holding spaces", (value) => `{"password": "${value} with spaces"}`, () => `{"password": "${REDACTED}"}`],
  ["token pair, escaped", (value) => `\\"token\\":\\"${value}\\"`, () => `\\"token\\":\\"${REDACTED}\\"`],
  ["unterminated quoted header value", (value) => `X-Api-Key: "${value}`, () => `X-Api-Key: "${REDACTED}`],
  [
    "request options echoed as JSON",
    (value) => `{"headers":{"Authorization":"Bearer ${value}","X-Api-Key":"${value}","Cookie":"sid=${value}","Accept":"application/json"}}`,
    () => `{"headers":{"Authorization":"Bearer ${REDACTED}","X-Api-Key":"${REDACTED}","Cookie":"${REDACTED}","Accept":"application/json"}}`,
  ],
  // Compound lines: a quoted value ends at its closing quote; an unquoted cookie or header value ends at `,`, at the
  // next header's `Name:` token, or at the line end; the header after it keeps its name and gets its own carrier
  // treatment. The fourth column lists the text that must survive as the following-header-name control.
  [
    "compound line, quoted cookie then quoted X-Api-Key then Content-Type",
    (value) => `Cookie: sid="${value}"; X-Api-Key: "${value}"; Content-Type: "application/json"`,
    () => `Cookie: ${REDACTED}; X-Api-Key: "${REDACTED}"; Content-Type: "application/json"`,
    ['X-Api-Key: "', 'Content-Type: "application/json"'],
  ],
  [
    "compound line, unquoted cookie then quoted X-Api-Key then Content-Type",
    (value) => `Cookie: sid=${value}; X-Api-Key: "${value}"; Content-Type: "application/json"`,
    () => `Cookie: ${REDACTED}; X-Api-Key: "${REDACTED}"; Content-Type: "application/json"`,
    ['X-Api-Key: "', 'Content-Type: "application/json"'],
  ],
  [
    "compound line, all unquoted",
    (value) => `Cookie: sid=${value}; X-Api-Key: ${value}; Content-Type: application/json`,
    () => `Cookie: ${REDACTED}; X-Api-Key: ${REDACTED}; Content-Type: application/json`,
    ["X-Api-Key: ", "Content-Type: application/json"],
  ],
  [
    "compound line, comma-separated",
    (value) => `Cookie: sid=${value}, X-Api-Key: "${value}", Content-Type: "application/json"`,
    () => `Cookie: ${REDACTED}, X-Api-Key: "${REDACTED}", Content-Type: "application/json"`,
    ['X-Api-Key: "', 'Content-Type: "application/json"'],
  ],
  [
    "compound line, no spaces",
    (value) => `Cookie: sid=${value};X-Api-Key:"${value}";Content-Type:"application/json"`,
    () => `Cookie: ${REDACTED};X-Api-Key:"${REDACTED}";Content-Type:"application/json"`,
    ['X-Api-Key:"', 'Content-Type:"application/json"'],
  ],
  [
    "compound line, cookie attributes before the next header",
    (value) => `Cookie: sid=${value}; Path=/; HttpOnly; X-Api-Key: "${value}"; Content-Type: "application/json"`,
    () => `Cookie: ${REDACTED}; X-Api-Key: "${REDACTED}"; Content-Type: "application/json"`,
    ['X-Api-Key: "', 'Content-Type: "application/json"'],
  ],
  [
    "compound line, Set-Cookie with attributes then a comma and Content-Type",
    (value) => `Set-Cookie: sid="${value}"; Path=/; Secure, Content-Type: "application/json"`,
    () => `Set-Cookie: ${REDACTED}, Content-Type: "application/json"`,
    ['Content-Type: "application/json"'],
  ],
  [
    "compound line, whole cookie value quoted then a quoted Content-Type holding a semicolon",
    (value) => `Cookie: "sid=${value}; Path=/"; Content-Type: "text/html; charset=utf-8"`,
    () => `Cookie: "${REDACTED}"; Content-Type: "text/html; charset=utf-8"`,
    ['Content-Type: "text/html; charset=utf-8"'],
  ],
  [
    "compound line, two quoted headers",
    (value) => `X-Api-Key: "${value}"; Authorization: Bearer "${value}"`,
    () => `X-Api-Key: "${REDACTED}"; Authorization: Bearer "${REDACTED}"`,
    ['Authorization: Bearer "'],
  ],
  [
    "compound line, two unquoted headers then Content-Type",
    (value) => `X-Api-Key: ${value}; Authorization: Bearer ${value}; Content-Type: application/json`,
    () => `X-Api-Key: ${REDACTED}; Authorization: Bearer ${REDACTED}; Content-Type: application/json`,
    ["Authorization: Bearer ", "Content-Type: application/json"],
  ],
  [
    "compound line, header then JSON fragment",
    (value) => `X-Api-Key: "${value}" {"token": "${value}", "env": "production"}`,
    () => `X-Api-Key: "${REDACTED}" {"token": "${REDACTED}", "env": "production"}`,
    ['"env": "production"'],
  ],
  [
    "compound line, JSON-escaped cookie then X-Api-Key then Content-Type",
    (value) => `\\"Cookie\\": \\"sid=${value}\\", \\"X-Api-Key\\": \\"${value}\\", \\"Content-Type\\": \\"application/json\\"`,
    () => `\\"Cookie\\": \\"${REDACTED}\\", \\"X-Api-Key\\": \\"${REDACTED}\\", \\"Content-Type\\": \\"application/json\\"`,
    ['\\"X-Api-Key\\": \\"', '\\"Content-Type\\": \\"application/json\\"'],
  ],
  [
    "compound line inside a 502 body note",
    (value) => `502 Bad Gateway: upstream echoed Cookie: sid=${value}; X-Api-Key: "${value}"; Content-Type: "application/json"`,
    () => `502 Bad Gateway: upstream echoed Cookie: ${REDACTED}; X-Api-Key: "${REDACTED}"; Content-Type: "application/json"`,
    ["502 Bad Gateway: upstream echoed Cookie: ", 'X-Api-Key: "', 'Content-Type: "application/json"'],
  ],
  [
    "compound line, unterminated quoted cookie value then a quoted X-Api-Key",
    (value) => `Cookie: sid="${value}; X-Api-Key: "${value}"; Content-Type: "application/json"`,
    () => `Cookie: ${REDACTED}; X-Api-Key: "${REDACTED}"; Content-Type: "application/json"`,
    ['X-Api-Key: "', 'Content-Type: "application/json"'],
  ],
  [
    "compound line, unterminated quoted header value then Content-Type",
    (value) => `X-Api-Key: "${value}; Content-Type: "application/json"`,
    () => `X-Api-Key: "${REDACTED}; Content-Type: "application/json"`,
    ['Content-Type: "application/json"'],
  ],
  [
    "compound line, a quoted Date holding commas and colons before a quoted X-Api-Key",
    (value) => `Date: "Mon, 22 Sep 2026 12:30:00 GMT"; X-Api-Key: "${value}"`,
    () => `Date: "Mon, 22 Sep 2026 12:30:00 GMT"; X-Api-Key: "${REDACTED}"`,
    ['Date: "Mon, 22 Sep 2026 12:30:00 GMT"; X-Api-Key: "'],
  ],
];

/** Alphanumeric random-looking values planted in the quoted carriers; the first is name-shaped and stays bare. */
const QUOTED_CANARIES = ["RulingNameShapedProbeZq", "BPt5mgDrRZ5YyLTHaQPepJUYQbGYRCjG"];

/** Fixed text every integration emits; the scrubber must return each string unchanged. */
const MUST_KEEP = [
  'Content-Type: "application/json"',
  '"Content-Type": "application/json"',
  '\\"Content-Type\\": \\"application/json\\"',
  "Accept: 'application/json'",
  'Content-Type: "text/html; charset=utf-8"',
  'User-Agent: "grclanker/1.0"',
  '"Content-Length": "5120"',
  'X-Request-Id: "req-2026-09-22-zq"',
  'X-Rate-Limit-Remaining: "0"',
  '{"headers":{"Accept":"application/json","Content-Type":"application/json"}}',
  "the Cookie header was rejected and the Authorization header was missing",
  '{"type": "Basic ", "scheme": "bearer"}',
  "403 Forbidden: non-JSON body (text/html, 47 bytes, not echoed)",
  "502 Bad Gateway: non-JSON body (text/html, 5120 bytes, not echoed)",
  "403 Forbidden: JSON body without a documented error field (64 bytes, not echoed)",
  "SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body",
  "Unreadable inventory: caller_identity (GET /api/v2/caller-identity: 403 Forbidden)",
  "api_keys (GET /_security/api_key: 403 Forbidden: security_exception)",
  "Unreadable inventory: sdk_keys for environment web/staging (GET /api/v2/projects/web/environments/staging/sdk-keys: LaunchDarkly request failed (403 Forbidden) for GET /api/v2/projects/web/environments/staging/sdk-keys: forbidden: Forbidden)",
  "access_tokens: LaunchDarkly request failed (403 Forbidden) for GET /api/v2/tokens?showAll=true: forbidden: Forbidden",
  "sdk_keys:web/production: LaunchDarkly request failed (403 Forbidden)",
  "GET /api/v2/auditlog?before=1758520000000&after=1755841600000",
  "GET /api/v2/teams?expand=members",
  "GET /api/v2/flags/web?env=production",
  "GET /api/v2/projects/web/environments/canary-open-prod-zq/sdk-keys",
  "GET /_cluster/settings?include_defaults=true&flat_settings=true",
  "GET /_security/api_key?with_limited_by=true",
  "GET /api/v2/current_user",
  "GET /v1/phishing/security_tests/12345/recipients?page=3&per_page=500",
  "GET /2.0/users?fields=id,login,status&limit=1000",
  "project prod-us-east-2026 environment sess-canary-COOKIE-31415926535897 was not readable",
  "team canary-empty-team-zq has no custom role; token canary-noexpiry-token-zq has no expiry",
  "Basic authentication is disabled for this deployment",
  "an Owner token for a complete inventory",
  "Bearer token authentication is required",
  "InvalidAuthenticationToken: Access token has expired.",
  "Config precedence resolved from: environment-token -> config-base-url -> config-file-present.",
  "Unable to read LaunchDarkly config file /tmp/grclanker-dogrc-dir-gCpdGy (EISDIR)",
  "Unable to parse KnowBe4 config file: invalid YAML in /home/runner/.knowbe4-inspector/config.yaml at line 3",
  "Unable to parse Elastic config file: invalid YAML in /tmp/elastic-malformed-config-SeSovG/config.yaml at line 1",
  "Unable to parse Box config file: invalid JSON in /tmp/box-jwt-a1B2c3/config.json at position 42",
  "role AWSLambdaBasicExecutionRole on arn:aws:iam::123456789012:role/service-role/name",
  "member 019c8f7e-3d2a-4b1c-9e8f-7a6b5c4d3e2f has no MFA",
  "CanaryRequireSsoChangeZq CanaryStaleSdkKeyZq getHTTPSUrl oauth2Client",
  "https://app.launchdarkly.com/settings/authorization",
  "https://api.us.knowbe4.com/v1/training/enrollments",
  "ECONNRESET while reading https://api.knowbe4.com/v1/users",
  "timed out after 30000 ms",
  "stale_token_days=90 max_keys=500 token_limit=10",
  "api_keys: 3 of 5 keys have no expiry; tokens: none are stale",
  "user-session: 3 active sessions",
  "x-ratelimit-reset: 1758520000",
  "Status 429 Too Many Requests retried 3 times",
  "sha256 digest mismatch for bundle export/grclanker-launchdarkly-2026-09-22",
  "cookie consent banner; the session ended",
  "version 2026.09.22-rc1 of the collector",
  "INVALID_JSON UNRESOLVED_ALIAS_SHAPE ERR_MODULE_NOT_FOUND",
  "Authorization > Access tokens: name, role or custom role, owner, expiry, and last used date of every token (showAll as an Owner or Admin)",
  "Organization settings > Security > SAML: Enable SSO and Require SSO are checked",
  JSON.stringify({ collected: false, status: "not-collected", endpoint: null, error: null, reason: "not_requested", truncated: null, seen: null, total: null, items: null }),
  JSON.stringify({ collected: false, status: 403, endpoint: "GET /api/v2/tokens?showAll=true", error: "LaunchDarkly request failed (403 Forbidden) for GET /api/v2/tokens?showAll=true: forbidden: access_denied", reason: "not_readable" }),
];

function eightCharacterWindows(text) {
  const windows = [];
  for (let index = 0; index + 8 <= text.length; index += 1) windows.push(text.slice(index, index + 8));
  return windows;
}

/** Asserts the value and every 8-character window of it are gone and the marker took its place. */
function assertRemoved(scrubbed, value, label) {
  assert.ok(!scrubbed.includes(value), `${label}: value survived: ${scrubbed}`);
  for (const fragment of eightCharacterWindows(value)) {
    assert.ok(!scrubbed.includes(fragment), `${label}: fragment "${fragment}" survived: ${scrubbed}`);
  }
  assert.ok(scrubbed.includes(REDACTED), `${label}: no marker written: ${scrubbed}`);
}

test("scrub boundary: name-shaped values standing bare in prose stay, and every must-keep string survives unchanged", () => {
  const scrubber = createCredentialScrubber();
  for (const value of NAME_SHAPED) {
    const text = `the resource ${value} was not readable`;
    assert.equal(scrubber.scrub(text), text, `bare name-shaped value altered: ${value}`);
  }
  assert.deepEqual(scrubAlterations(MUST_KEEP, scrubber.scrub), []);
});

test("scrub boundary guard 1: a value inside any carrier is removed whatever its shape", () => {
  const scrubber = createCredentialScrubber({ headers: ["dd-api-key"] });
  for (const [label, carrier] of CARRIERS) {
    for (const value of [...NAME_SHAPED, TOKEN_SHAPED.scatteredDigits, "short7"]) {
      const scrubbed = scrubber.scrub(carrier(value));
      assertRemoved(scrubbed, value, `${label} with ${value}`);
    }
  }
});

test("scrub boundary guard 1: carriers keep their name and scheme so the message still says what was replayed", () => {
  const scrubber = createCredentialScrubber();
  assert.equal(scrubber.scrub("Authorization: Bearer prod-us-east-2026"), `Authorization: Bearer ${REDACTED}`);
  assert.equal(scrubber.scrub("Cookie: sid=prod-us-east-2026; Path=/"), `Cookie: ${REDACTED}`);
  assert.equal(scrubber.scrub("see https://user:pw@api.example.com/v1/x?token=abc#f for details"), `see https://api.example.com/v1/x?${REDACTED} for details`);
  assert.equal(scrubber.scrub("GET /api/v2/x?token=prod-us-east-2026&env=production"), `GET /api/v2/x?token=${REDACTED}&env=production`);
  assert.equal(scrubber.scrub('{"token":"prod-us-east-2026","env":"production"}'), `{"token":"${REDACTED}","env":"production"}`);
  assert.equal(scrubber.scrub("api_key: prod-us-east-2026, env: production"), `api_key: ${REDACTED}, env: production`);
});

test("scrub boundary guard 1, quoted carriers: the planted values look random and share no 6-character window with the carriers or the must-keep rows", () => {
  const legitimate = [...QUOTED_CARRIERS.map(([label, carrier]) => [label, carrier("")]), ...MUST_KEEP.map((text, index) => [`must-keep ${index}`, text])];
  assertCanaryFixture(assert, QUOTED_CANARIES, legitimate, "quoted carriers");
});

test("scrub boundary guard 1, quoted carriers: a quoted header or pair value is removed whole, in double or single quotes, with or without spaces, and JSON-escaped", () => {
  const scrubber = createCredentialScrubber();
  const [nameShapedCanary] = QUOTED_CANARIES;
  const bare = `the resource ${nameShapedCanary} was not readable`;
  assert.equal(scrubber.scrub(bare), bare, "the name-shaped canary stays bare, so only the carrier can remove it");
  const values = [...QUOTED_CANARIES, ...NAME_SHAPED];
  for (const [label, carrier, expected, controls = []] of QUOTED_CARRIERS) {
    for (const value of values) {
      const scrubbed = scrubber.scrub(carrier(value));
      assert.equal(scrubbed, expected(), `${label} with ${value}`);
      assertCanaryWindowsAbsent(assert, scrubbed, [value], `${label} with ${value}`);
      for (const control of controls) {
        assert.ok(scrubbed.includes(control), `${label} with ${value}: the following header text ${JSON.stringify(control)} did not survive: ${scrubbed}`);
      }
      assert.equal(scrubber.scrub(scrubbed), scrubbed, `${label} with ${value}: a second pass changed the text`);
    }
  }
  assert.ok(QUOTED_CARRIERS.filter(([label]) => label.startsWith("compound line")).length >= 14, "the compound-line pins are present");
});

test("scrub boundary guard 1, quoted carriers: the reported forms, a plain word in quotes included, come out with the value gone and the quotes and scheme kept", () => {
  const scrubber = createCredentialScrubber();
  assert.equal(scrubber.scrub('Cookie: sid="prod-cookie"'), `Cookie: ${REDACTED}`);
  assert.equal(scrubber.scrub('X-Api-Key: "prod-key"'), `X-Api-Key: "${REDACTED}"`);
  assert.equal(scrubber.scrub('Authorization: Bearer "token"'), `Authorization: Bearer "${REDACTED}"`);
  assert.equal(scrubber.scrub("Authorization: Bearer 'token'"), `Authorization: Bearer '${REDACTED}'`);
  assert.equal(scrubber.scrub('Authorization:"Bearer token"'), `Authorization:"Bearer ${REDACTED}"`);
  assert.equal(scrubber.scrub('\\"Authorization\\": \\"Bearer token\\"'), `\\"Authorization\\": \\"Bearer ${REDACTED}\\"`);
  assert.equal(scrubber.scrub('X-Api-Key: ""'), 'X-Api-Key: ""', "an empty quoted value has nothing to remove");
  assert.equal(scrubber.scrub("Bearer token authentication is required"), "Bearer token authentication is required", "a bare plain word after a scheme word is still prose");
});

test("scrub boundary guard 2: a configured secret is removed whatever its shape and in its base64, base64url, URL-encoded, form-encoded, and JSON-escaped forms", () => {
  const scrubber = createCredentialScrubber();
  const secrets = ["prod-us-east-2026", "sess canary/COOKIE+31415926535897=", 'quote"me\\now'];
  scrubber.registerSecrets([...secrets, undefined, null, "abc"]);
  assert.deepEqual([...scrubber.secrets], secrets, "short, undefined, and null entries are ignored");
  for (const secret of secrets) {
    const bytes = Buffer.from(secret, "utf8");
    const base64 = bytes.toString("base64");
    const forms = {
      plain: secret,
      json: JSON.stringify(secret).slice(1, -1),
      uri: encodeURIComponent(secret),
      form: new URLSearchParams({ v: secret }).toString().slice(2),
      base64,
      base64Unpadded: base64.replace(/=+$/, ""),
      base64url: bytes.toString("base64url"),
      base64UrlEncoded: encodeURIComponent(base64),
    };
    for (const [form, value] of Object.entries(forms)) {
      const scrubbed = scrubber.scrub(`the value ${value} leaked bare in prose`);
      assert.ok(!scrubbed.includes(value), `${form} form of ${secret} survived: ${scrubbed}`);
      assert.ok(scrubbed.includes(REDACTED), `${form} form of ${secret}: no marker: ${scrubbed}`);
    }
  }
  assert.ok(MIN_CONFIGURED_SECRET_LENGTH >= 4, "a configured secret shorter than four characters would match ordinary prose");
});

test("scrub boundary guard 2: scrubbers built separately do not share configured secrets", () => {
  const first = createCredentialScrubber();
  const second = createCredentialScrubber();
  first.registerSecrets(["prod-us-east-2026"]);
  assert.equal(first.scrub("value prod-us-east-2026 here"), `value ${REDACTED} here`);
  assert.equal(second.scrub("value prod-us-east-2026 here"), "value prod-us-east-2026 here");
});

test("scrub boundary guard 3: real token shapes are removed bare wherever they stand", () => {
  const scrubber = createCredentialScrubber();
  for (const [label, value] of Object.entries(TOKEN_SHAPED)) {
    const scrubbed = scrubber.scrub(`observed ${value} in the response`);
    assertRemoved(scrubbed, value, label);
  }
  assert.equal(scrubber.scrub("key -----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7 truncated"), `key ${REDACTED}`, "an unterminated PEM header is redacted to the end of the text");
});

test("scrub boundary: vendor patterns and headers passed by an integration are honoured", () => {
  const scrubber = createCredentialScrubber({
    headers: ["x-phisher-token"],
    vendorPatterns: [/\b(?:api|sdk|mob|rel)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, /\bessu_[A-Za-z0-9+/=_-]{16,}/g],
  });
  assertRemoved(scrubber.scrub("X-Phisher-Token: prod-us-east-2026"), "prod-us-east-2026", "custom header");
  assertRemoved(scrubber.scrub("token api-deadbeef-cafe-babe-face-feedfacecafe rejected"), "api-deadbeef-cafe-babe-face-feedfacecafe", "vendor UUID key shape without a digit-scattered segment");
  assertRemoved(scrubber.scrub("sdk-0f9e8d7c-6b5a-4938-8c7d-1234567890ab"), "sdk-0f9e8d7c-6b5a-4938-8c7d-1234567890ab", "sdk key");
  assertRemoved(scrubber.scrub("cloud key essu_bXlrZXk6c2VjcmV0dmFsdWU"), "essu_bXlrZXk6c2VjcmV0dmFsdWU", "essu_ prefix");
});

test("scrub boundary: every replacement is idempotent and unanchored", () => {
  const scrubber = createCredentialScrubber({ headers: ["dd-api-key"] });
  scrubber.registerSecrets(["prod-us-east-2026"]);
  const texts = [
    ...CARRIERS.map(([, carrier]) => `prefix text; ${carrier("sess-canary-COOKIE-31415926535897")} suffix text.`),
    ...Object.values(TOKEN_SHAPED).map((value) => `prefix ${value} suffix`),
    "the configured prod-us-east-2026 and its base64 cHJvZC11cy1lYXN0LTIwMjY= and Authorization: Bearer x.y.z all mid-sentence",
  ];
  for (const text of texts) {
    const once = scrubber.scrub(text);
    assert.notEqual(once, text, `nothing scrubbed from: ${text}`);
    assert.equal(scrubber.scrub(once), once, `a second pass changed: ${once}`);
    assert.match(once, /^prefix|^the configured/, "text before the carrier is kept");
  }
});

test("scrub boundary: the ruling's consequence for tests, a name-shaped canary bare in prose is kept, in a carrier or registered it goes", () => {
  const canary = "sess-canary-COOKIE-31415926535897";
  const bare = createCredentialScrubber();
  assert.equal(bare.scrub(`the value ${canary} in prose`), `the value ${canary} in prose`);
  assert.equal(bare.scrub(`Set-Cookie: session=${canary}; HttpOnly`), `Set-Cookie: ${REDACTED}`);
  const registered = createCredentialScrubber();
  registered.registerSecrets([canary]);
  assertCanaryWindowsAbsent(assert, registered.scrub(`the value ${canary} in prose`), [canary], "registered canary");
});

test("looksLikeToken judges runs by base64 symbols, digit scatter, and token casing, never uppercase codes, digit strings, UUIDs, or names", () => {
  assert.ok(LONG_TOKEN_MIN_LENGTH === 16);
  for (const run of ["Kq7Zx2Vw9Lm4Tp8RfiCY", "bPxRfiCYwQmZkTnHvJdLsG", "QUJDREVGR0hJSktMTU5PUA==", "abc+defghi=jkl+mnop", "api-0f9e8d7c-6b5a-4938-8c7d-1234567890ab", "BEARER_CANARY_9f8e7d6c5b4a3210"]) {
    assert.ok(looksLikeToken(run), `expected token: ${run}`);
  }
  for (const run of [
    "prod-us-east-2026-configured",
    "sess-canary-COOKIE-31415926535897",
    "canary-empty-team-zq",
    "019c8f7e-3d2a-4b1c-9e8f-7a6b5c4d3e2f",
    "INVALID_JSON_DOCUMENT_SHAPE",
    "ERR_MODULE_NOT_FOUND",
    "17585200000001234567",
    "AWSLambdaBasicExecutionRole",
    "CanaryRequireSsoChangeZq",
    "grclanker-launchdarkly-2026-09-22",
    "elastic-malformed-config-SeSovG",
    "Proxy-Authorization=",
    "short-run",
  ]) {
    assert.ok(!looksLikeToken(run), `expected name: ${run}`);
  }
});

test("isCredentialKey covers the Flue heuristic plus bare and signed-URL names, and exempts thresholds, counts, and file references", () => {
  for (const key of ["token", "api_key", "apiKey", "client_secret", "password", "authorization", "cookie", "sid", "sig", "pwd", "session", "auth", "X-Amz-Signature", "oauth_token", "sdk_keys", "access_tokens"]) {
    assert.ok(isCredentialKey(key), `expected credential key: ${key}`);
  }
  for (const key of ["before", "after", "env", "expand", "limit", "offset", "page", "per_page", "fields", "include_defaults", "flat_settings", "with_limited_by", "stale_token_days", "max_keys", "token_limit", "credentials_file", "showAll", "status"]) {
    assert.ok(!isCredentialKey(key), `expected ordinary key: ${key}`);
  }
});

const DATA_CANARIES = {
  tokensEntry: "BPt5mgDrRZ5YyLTHaQPepJUYQbGYRCjG",
  credentialsValue: "zSVNdtuTMXK9T7qXe8CEDEYXmJ9K6vVL",
  headerValue: "QJGjPixxDSCkGNoArXMeL2USsBcdGfdd",
  noteToken: "PCWXTXXWpLrVFgXp2SPm7YQKZgcAgWUx",
  deepNote: "U7ktAa5zEHKELrac4CfrjWJF3zBQuiEx",
};

test("scrubData: the module key rule sees the enclosing key, pair values go by name, identifier keys keep their value, and containers and strings past the depth cap become the marker", () => {
  const scrubber = createCredentialScrubber();
  const deep = { level: 0 };
  let cursor = deep;
  for (let level = 1; level <= 12; level += 1) {
    cursor.child = { level, note: level === 9 ? DATA_CANARIES.deepNote : `depth-note-${level}` };
    cursor = cursor.child;
  }
  const record = {
    tokens: [DATA_CANARIES.tokensEntry],
    credentials: { value: DATA_CANARIES.credentialsValue },
    ssl: { key: "pem-body", certificate: "cert" },
    keystore: { key: "ks", path: "/etc/ks.p12" },
    headers: [{ name: "X-Api-Key", value: DATA_CANARIES.headerValue }, { name: "Accept", value: "application/json" }],
    id: "AaB6wvMiGMD7ReAp6tKkmeQD9QWYFmuM",
    note: `see token=${DATA_CANARIES.noteToken} and https://user:pw@h.example.com/a?token=x`,
    count: 3,
    password: 482913,
    enabled: true,
    none: null,
    deep,
  };
  // The module rule: the conservative record rule plus a bare `key` under ssl, tls, or keystore (the Elastic rule).
  const isModuleCredentialKey = (key, parentKey) => isCredentialDataKey(key) || (key === "key" && /^(ssl|tls|keystore)$/.test(parentKey ?? ""));
  const out = scrubber.scrubData(record, { isCredentialKey: isModuleCredentialKey, maxDepth: 10 });

  assert.equal(out.tokens, REDACTED, "an array under a credential key goes whole");
  assert.equal(out.credentials, REDACTED, "an object under a credential key goes whole");
  assert.equal(out.ssl.key, REDACTED, "the module rule receives the enclosing key");
  assert.equal(out.ssl.certificate, "cert");
  assert.equal(out.keystore.key, REDACTED);
  assert.equal(out.keystore.path, "/etc/ks.p12");
  assert.equal(out.headers[0].name, "X-Api-Key", "the pair keeps its name");
  assert.equal(out.headers[0].value, REDACTED, "a pair whose name is credential-shaped loses its value");
  assert.equal(out.headers[1].value, "application/json", "an ordinary pair keeps its value");
  assert.equal(out.id, record.id, "a value under an identifier key is not judged by shape");
  assert.match(out.note, /^see token=\[REDACTED\] and https:\/\/h\.example\.com\/a\?\[REDACTED\]$/, "free text gets the pattern pass");
  assert.equal(out.count, 3, "a number under an ordinary key passes through");
  assert.equal(out.password, REDACTED, "a number under a credential key is a PIN and goes");
  assert.equal(out.enabled, true);
  assert.equal(out.none, null);
  assert.equal(scrubber.scrubData({ ssl: { key: "pem-body" } }).ssl.key, "pem-body", "without a module rule a bare key under ssl is an identifier");

  // deep sits at depth 1, child level L at depth L + 1, and its note at depth L + 2: level 8's note (depth 10) is at the
  // cap and stays, level 9's note (depth 11) and level 9's child (depth 11) are past it and become the marker.
  let level = out.deep;
  for (let index = 1; index <= 8; index += 1) level = level.child;
  assert.equal(level.level, 8);
  assert.equal(level.note, "depth-note-8", "a string at the cap is kept");
  assert.equal(level.child.level, 9);
  assert.equal(level.child.note, REDACTED, "a string one level past the cap becomes the marker instead of skipping the pattern pass");
  assert.equal(level.child.child, REDACTED, "a container past the cap becomes the marker");
  assertCanaryWindowsAbsent(assert, JSON.stringify(out), Object.values(DATA_CANARIES), "scrubData output");
  assert.deepEqual(scrubber.scrubData(out, { isCredentialKey: isModuleCredentialKey, maxDepth: 10 }), out, "the data-side scrub is idempotent");
});
