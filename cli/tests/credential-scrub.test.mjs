import test from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_DATA_SCRUB_DEPTH,
  LONG_TOKEN_MIN_LENGTH,
  MIN_CONFIGURED_SECRET_LENGTH,
  REDACTED,
  createCredentialScrubber,
  isBearerIdKey,
  isCredentialDataKey,
  isCredentialKey,
  isIdentifierKey,
  isSettingKey,
  isWebhookKey,
  looksLikeToken,
} from "../dist/extensions/grc-tools/credential-scrub.js";
import { redactCredentialValues as redactBoxValues, scrubErrorText as scrubBoxErrorText } from "../dist/extensions/grc-tools/box.js";
import { redactCredentialValues as redactLaunchdarklyValues, scrubErrorText as scrubLaunchdarklyErrorText } from "../dist/extensions/grc-tools/launchdarkly.js";
import { redactCredentialValues as redactKnowbe4Values, scrubErrorText as scrubKnowbe4ErrorText } from "../dist/extensions/grc-tools/knowbe4.js";
import { redactCredentialValues as redactDatadogValues, scrubErrorText as scrubDatadogErrorText } from "../dist/extensions/grc-tools/datadog.js";
import { redactSensitiveValues as redactElasticValues, scrubErrorText as scrubElasticErrorText } from "../dist/extensions/grc-tools/elastic.js";
import { assertCanaryFixture, assertCanaryWindowsAbsent, assertDepthCapPins, canaryWindows } from "./helpers/canary-windows.mjs";
import { COOKIE_ATTRIBUTE_CANARIES, TOKEN_PUNCTUATION_COOKIE_NAME, assertCookieAttributeCarriersScrubbed, cookieAttributeCarrierTexts } from "./helpers/cookie-attribute-carriers.mjs";
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
  ["custom x- credential header", (value) => `X-Probe-Session-Key: ${value}`],
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

/** Asserts the value and every window of it at lengths 6 through 24 are gone and the marker took its place. */
function assertRemoved(scrubbed, value, label) {
  assert.ok(!scrubbed.includes(value), `${label}: value survived: ${scrubbed}`);
  for (const fragment of canaryWindows(value)) {
    assert.ok(!scrubbed.includes(fragment), `${label}: fragment "${fragment}" (${fragment.length} of ${value.length} characters) survived: ${scrubbed}`);
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

test("scrub boundary guard 1, quoted carriers: a closing quote on the line wins over the following-header cut, which applies only to a value left unterminated", () => {
  const scrubber = createCredentialScrubber();
  assert.equal(scrubber.scrub('X-Api-Key: "abc-def; Foo: ghi-jkl"'), `X-Api-Key: "${REDACTED}"`, "a terminated value holding `; Name:` is one value");
  assert.equal(scrubber.scrub('X-Api-Key: "abc-def, Foo: ghi-jkl" and more'), `X-Api-Key: "${REDACTED}" and more`, "a terminated value holding `, Name:` is one value");
  assert.equal(scrubber.scrub('X-Api-Key: "abc-def; Foo: ghi-jkl'), `X-Api-Key: "${REDACTED}; Foo: ghi-jkl`, "an unterminated value still stops at the next header's name");
  assert.equal(scrubber.scrub('X-Api-Key: "abc-def; Content-Type: application/json'), `X-Api-Key: "${REDACTED}; Content-Type: application/json`);
  assert.equal(
    scrubber.scrub('Authorization: \\"Bearer abc-def; Foo: ghi-jkl\\", Accept: \\"application/json\\"'),
    `Authorization: \\"Bearer ${REDACTED}\\", Accept: \\"application/json\\"`,
    "the same holds JSON-escaped",
  );
  const [canary] = QUOTED_CANARIES;
  const carriers = [
    ["terminated header value", `X-Api-Key: "${canary}; Foo: ghi-jkl"`, `X-Api-Key: "${REDACTED}"`, []],
    ["terminated header value, comma", `X-Api-Key: "${canary}, Foo: ghi-jkl" and more`, `X-Api-Key: "${REDACTED}" and more`, [" and more"]],
    ["unterminated header value", `X-Api-Key: "${canary}; Foo: ghi-jkl`, `X-Api-Key: "${REDACTED}; Foo: ghi-jkl`, ["Foo: ghi-jkl"]],
    ["terminated JSON pair", `{"X-Api-Key":"${canary}; Foo: ghi-jkl","Accept":"application/json"}`, `{"X-Api-Key":"${REDACTED}","Accept":"application/json"}`, ['"Accept":"application/json"']],
    ["unterminated value before a header whose value opens with a quote", `Cookie: sid="${canary}; X-Api-Key: "${canary}"; Accept: "application/json"`, `Cookie: ${REDACTED}; X-Api-Key: "${REDACTED}"; Accept: "application/json"`, ['X-Api-Key: "', 'Accept: "application/json"']],
    ["unterminated value before a header whose value opens with a single quote", `X-Api-Key: "${canary}; Authorization: 'Bearer ${canary}'`, `X-Api-Key: "${REDACTED}; Authorization: 'Bearer ${REDACTED}'`, ["Authorization: 'Bearer "]],
  ];
  for (const [entryPoint, scrub] of TEXT_ENTRY_POINTS) {
    for (const [label, text, expected, controls] of carriers) {
      const scrubbed = scrub(text);
      assert.equal(scrubbed, expected, `${entryPoint}: ${label}`);
      assertCanaryWindowsAbsent(assert, scrubbed, [canary], `${entryPoint}: ${label}`);
      for (const control of controls) assert.ok(scrubbed.includes(control), `${entryPoint}: ${label}: ${JSON.stringify(control)} did not survive`);
      assert.equal(scrub(scrubbed), scrubbed, `${entryPoint}: ${label}: a second pass changed the text`);
    }
  }
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
    "InvalidAuthenticationToken=",
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

// ---------------------------------------------------------------------------------------------------------------
// Row (a): a value under a credential-named key goes whatever its shape and length, through every entry point. The
// key rule sees a credential word anywhere in the name, so every vendor env name and every compound config key the
// five modules read is covered, and no shape gate applies to an assignment, a quoted value, or a `:` pair.
// ---------------------------------------------------------------------------------------------------------------

/** Every credential env name and config-file key the five modules read, plus group D's cross-check keys. */
const COMPOUND_CREDENTIAL_KEYS = [...new Set([
  "BOX_CLIENT_SECRET", "BOX_ACCESS_TOKEN", "BOX_REFRESH_TOKEN", "BOX_TOKEN", "BOX_DEVELOPER_TOKEN", "BOX_JWT_PASSPHRASE",
  "LAUNCHDARKLY_API_TOKEN", "LD_ACCESS_TOKEN",
  "DD_API_KEY", "DD_APP_KEY", "DD_APPLICATION_KEY", "DATADOG_API_KEY", "DATADOG_APP_KEY",
  "KNOWBE4_API_TOKEN", "KNOWBE4_PHISHER_API_TOKEN",
  "ELASTIC_API_KEY", "ELASTIC_CLOUD_API_KEY", "ELASTIC_PASSWORD", "ELASTIC_BEARER_TOKEN",
  "DB_PASSWORD", "password", "client_secret",
  "clientSecret", "access_token", "accessToken", "refresh_token", "refreshToken", "developer_token", "jwt_passphrase", "passphrase",
  "privateKey", "token", "secret", "api_key", "apikey",
  "api_token",
  "apiKey", "appKey", "appkey", "private_key",
  "apiToken", "phisher_api_token", "phisherApiToken",
  "api-key", "bearer_token", "bearer-token", "bearerToken", "cloud_api_key", "cloud-api-key", "cloudApiKey",
  // Webhook-prefixed credential keys (gap 39): the prefix does not make them URL keys.
  "webhook_secret", "WEBHOOK_SECRET", "webhookSecret", "webhook_token", "webhook_signing_key",
])];

/** Human-chosen values: the four that pass a digit, symbol, or length test and the eight a shape gate would keep. */
const WEAK_VALUES = ["hunter2", "Summer2026!", "letmein2024", "correcthorsebatterystaple", "letmein", "Sunshine", "abc12", "p@ss", "monkey", "qwerty", "iloveyou", "football"];

/** Every form a pair takes in an error body, a config echo, or a sentence. */
const PAIR_FORMS = [
  ["assignment", (key, value) => `${key}=${value}`],
  ["colon space", (key, value) => `${key}: ${value}`],
  ["colon tight", (key, value) => `${key}:${value}`],
  ["double quoted", (key, value) => `${key}="${value}"`],
  ["single quoted", (key, value) => `${key}='${value}'`],
  ["JSON", (key, value) => `{"${key}": "${value}"}`],
  ["JSON tight", (key, value) => `{"${key}":"${value}"}`],
  ["JSON escaped", (key, value) => `\\"${key}\\": \\"${value}\\"`],
  ["assignment in a sentence", (key, value) => `the upstream echoed ${key}=${value} back in its error body`],
  ["colon pair in a sentence", (key, value) => `the config line ${key}: ${value} was rejected by the loader`],
  ["spaced assignment on its own line", (key, value) => `[auth]\n${key} = ${value}\nregion = us`],
  ["YAML line", (key, value) => `region: us\n${key}: ${value}\nlimit: 10`],
];

/** The eleven entry points: the shared text and data scrubbers, each module's error text scrubber, each module's record walker. */
const ENTRY_POINTS = [
  ["shared scrub", (text) => createCredentialScrubber().scrub(text)],
  ["shared scrubData", (text) => JSON.stringify(createCredentialScrubber().scrubData({ note: text }))],
  ["box scrubErrorText", scrubBoxErrorText],
  ["launchdarkly scrubErrorText", scrubLaunchdarklyErrorText],
  ["knowbe4 scrubErrorText", scrubKnowbe4ErrorText],
  ["datadog scrubErrorText", scrubDatadogErrorText],
  ["elastic scrubErrorText", scrubElasticErrorText],
  ["box redactCredentialValues", (text) => JSON.stringify(redactBoxValues({ note: text }))],
  ["launchdarkly redactCredentialValues", (text) => JSON.stringify(redactLaunchdarklyValues({ note: text }))],
  ["knowbe4 redactCredentialValues", (text) => JSON.stringify(redactKnowbe4Values({ note: text }))],
  ["datadog redactCredentialValues", (text) => JSON.stringify(redactDatadogValues({ note: text }))],
  ["elastic redactSensitiveValues", (text) => JSON.stringify(redactElasticValues({ note: text }))],
];

/** Asserts the value is gone whole and in every 6-to-24 window, while the key survives and the marker was written. */
function assertPairValueGone(scrubbed, key, value, label) {
  assert.ok(!scrubbed.includes(value), `${label}: value survived: ${scrubbed}`);
  for (const fragment of canaryWindows(value)) assert.ok(!scrubbed.includes(fragment), `${label}: fragment "${fragment}" survived: ${scrubbed}`);
  assert.ok(scrubbed.includes(key), `${label}: key lost: ${scrubbed}`);
  assert.ok(scrubbed.includes(REDACTED), `${label}: no marker written: ${scrubbed}`);
}

test("row (a): every credential-named key the five modules read loses a human-chosen value whatever its shape, in every pair form, through every entry point", () => {
  assert.equal(COMPOUND_CREDENTIAL_KEYS.length, 55);
  for (const key of COMPOUND_CREDENTIAL_KEYS) assert.ok(isCredentialKey(key), `key rule misses ${key}`);
  let cells = 0;
  for (const [entryLabel, entry] of ENTRY_POINTS) {
    for (const key of COMPOUND_CREDENTIAL_KEYS) {
      for (const value of WEAK_VALUES) {
        for (const [formLabel, form] of PAIR_FORMS) {
          const scrubbed = entry(form(key, value));
          assertPairValueGone(scrubbed, key, value, `${entryLabel}, ${formLabel}, ${key}=${value}`);
          cells += 1;
        }
      }
    }
  }
  assert.equal(cells, ENTRY_POINTS.length * COMPOUND_CREDENTIAL_KEYS.length * WEAK_VALUES.length * PAIR_FORMS.length);
});

test("row (a): the key, separator, and quoting survive so the text still says which pair was replaced, and several pairs on one line each lose their own value", () => {
  const scrubber = createCredentialScrubber();
  assert.equal(scrubber.scrub("BOX_CLIENT_SECRET=football"), `BOX_CLIENT_SECRET=${REDACTED}`);
  assert.equal(scrubber.scrub("developer_token: letmein"), `developer_token: ${REDACTED}`);
  assert.equal(scrubber.scrub("cloud_api_key:p@ss"), `cloud_api_key:${REDACTED}`);
  assert.equal(scrubber.scrub('jwt_passphrase="Sunshine"'), `jwt_passphrase="${REDACTED}"`);
  assert.equal(scrubber.scrub("phisherApiToken='abc12'"), `phisherApiToken='${REDACTED}'`);
  assert.equal(scrubber.scrub('{"cloudApiKey": "monkey", "region": "us"}'), `{"cloudApiKey": "${REDACTED}", "region": "us"}`);
  assert.equal(scrubber.scrub('\\"DD_APP_KEY\\": \\"qwerty\\"'), `\\"DD_APP_KEY\\": \\"${REDACTED}\\"`);
  assert.equal(scrubber.scrub("the config line developer_token: letmein was rejected"), `the config line developer_token: ${REDACTED} was rejected`);
  assert.equal(
    scrubber.scrub("LAUNCHDARKLY_API_TOKEN=monkey LD_ACCESS_TOKEN=Sunshine DB_PASSWORD=letmein DD_APP_KEY=p@ss BOX_CLIENT_SECRET=football"),
    `LAUNCHDARKLY_API_TOKEN=${REDACTED} LD_ACCESS_TOKEN=${REDACTED} DB_PASSWORD=${REDACTED} DD_APP_KEY=${REDACTED} BOX_CLIENT_SECRET=${REDACTED}`,
  );
  assert.equal(scrubber.scrub("developer_token: hunter2, client_token: letmein; user_session: monkey"), `developer_token: ${REDACTED}, client_token: ${REDACTED}; user_session: ${REDACTED}`);
  assert.equal(scrubber.scrub("auth_header: Bearer letmein"), `auth_header: Bearer ${REDACTED}`);
  assert.equal(scrubber.scrub("developer_token: letmein."), `developer_token: ${REDACTED}.`);
});

test("row (a), identifiers and settings: a key whose final segment names a setting keeps a name-shaped value, a URL value still passes the URL rule, and only a token-shaped or registered value goes", () => {
  const kept = [
    "BOX_AUTH_METHOD=ccg",
    "BOX_TOKEN_URL=https://api.box.com/oauth2/token",
    "BOX_JWT_ALGORITHM=RS512",
    "BOX_JWT_AUDIENCE=https://api.box.com/oauth2/token",
    "LAUNCHDARKLY_KEY_SHAPE=sdk-uuid",
    "BOX_CLIENT_ID=acme-audit-app",
    "ELASTIC_USERNAME=elastic",
    "client_id: acme-audit-app",
    "token_type=Bearer",
    "grant_type=client_credentials",
    "auth_mode: oauth token_limit=10 max_keys=500 stale_token_days=90 key_name=deploy",
    "token_created_at: 2026-09-22T10:00:00Z key_expiry: 2027-01-01 token_inventory_scope: full caller_token_role: admin",
    'LAUNCHDARKLY_KEY_SHAPE: "sdk-uuid"',
    '{"BOX_AUTH_METHOD": "ccg", "BOX_TOKEN_URL": "https://api.box.com/oauth2/token"}',
    // The enterprise settings Box reports as words, as the analysis documents and finding evidence write them.
    '{"session_duration": "12 hours", "password_reset_frequency": "90 days", "previous_password_reuse_limit": "5"}',
    '"session_duration": "never"',
    "session_duration: 12 hours password_reset_frequency: 90 days key_rotation_interval=30d password_min_length=14",
  ];
  const scrubber = createCredentialScrubber();
  assert.deepEqual(scrubAlterations(kept, scrubber.scrub), []);
  for (const scrubErrorText of [scrubBoxErrorText, scrubLaunchdarklyErrorText, scrubKnowbe4ErrorText, scrubDatadogErrorText, scrubElasticErrorText]) {
    assert.deepEqual(scrubAlterations(kept, scrubErrorText), []);
  }
  for (const key of ["BOX_AUTH_METHOD", "BOX_TOKEN_URL", "BOX_JWT_ALGORITHM", "BOX_JWT_AUDIENCE", "LAUNCHDARKLY_KEY_SHAPE", "BOX_CLIENT_ID", "client_id", "token_type", "auth_mode", "key_name", "token_created_at", "maxKeys", "redirect_uri", "authorization_endpoint", "password_file", "private_key_path", "session_duration", "password_reset_frequency", "key_rotation_interval", "password_min_length"]) {
    assert.ok(isSettingKey(key) && !isCredentialKey(key), `expected a setting key: ${key}`);
  }
  // A duration or frequency key is a setting, not a spelling of the credential it qualifies.
  for (const key of ["session_token", "sessionToken", "password", "user_session"]) {
    assert.ok(isCredentialKey(key), `expected a credential key: ${key}`);
  }
  assert.equal(scrubber.scrub(`session_duration=${TOKEN_SHAPED.tokenCasing}`), `session_duration=${REDACTED}`, "a token-shaped value goes under a duration key as under any setting key");
  // The URL rule still applies to a setting's URL value: userinfo and query go, the path stays.
  assert.equal(scrubber.scrub("BOX_TOKEN_URL=https://svc:pw@api.box.com/oauth2/token?client_secret=football"), `BOX_TOKEN_URL=https://api.box.com/oauth2/token?${REDACTED}`);
  // Token-shaped and registered values go under a setting key as anywhere else.
  assert.equal(scrubber.scrub(`BOX_CLIENT_ID=${TOKEN_SHAPED.tokenCasing}`), `BOX_CLIENT_ID=${REDACTED}`);
  assert.equal(scrubber.scrub(`BOX_ENTERPRISE_ID=${TOKEN_SHAPED.md5}`), `BOX_ENTERPRISE_ID=${REDACTED}`);
  assert.equal(scrubber.scrub(`LAUNCHDARKLY_KEY_SHAPE=${TOKEN_SHAPED.scatteredDigits}`), `LAUNCHDARKLY_KEY_SHAPE=${REDACTED}`);
  const registered = createCredentialScrubber();
  registered.registerSecrets(["ccg-secret-value-zq"]);
  assert.equal(registered.scrub("BOX_AUTH_METHOD=ccg-secret-value-zq"), `BOX_AUTH_METHOD=${REDACTED}`);
  assert.equal(registered.scrub("BOX_TOKEN_URL=https://api.box.com/ccg-secret-value-zq/token"), `BOX_TOKEN_URL=https://api.box.com/${REDACTED}/token`);
});

test("row (a), webhooks: a webhook or callback URL key stays a credential key whatever its suffix and its value keeps only the origin, while a webhook's name is a name", () => {
  const scrubber = createCredentialScrubber();
  for (const key of ["webhook_url", "webhookUrl", "webhook", "webhooks", "slack_hook_url", "hook_url", "incomingHookUri", "callback_url", "callbackUrl"]) {
    assert.ok(isWebhookKey(key) && isCredentialKey(key), `expected a webhook key: ${key}`);
  }
  assert.equal(scrubber.scrub("webhook_url=https://hooks.example.com/services/foo/bar/abcdefghijkl"), `webhook_url=https://hooks.example.com/${REDACTED}`);
  assert.equal(scrubber.scrub('"webhookUrl": "https://hooks.example.com/services/foo/bar/abcdefghijkl"'), `"webhookUrl": "https://hooks.example.com/${REDACTED}"`);
  assert.equal(scrubber.scrub("slack_hook_url: https://hooks.slack.com/services/T000/B000/xyz"), `slack_hook_url: https://hooks.slack.com/${REDACTED}`);
  assert.equal(scrubber.scrub("callback_url=https://app.example.com/oauth/cb?code=abc&state=xyz"), `callback_url=https://app.example.com/${REDACTED}`);
  assert.equal(scrubber.scrub("see https://api.example.com/v1/x?webhook_url=https://hooks.example.com/services/a/b/c for details"), `see https://api.example.com/v1/x?${REDACTED} for details`);
  for (const text of ['"webhook": "canary-insecure-hook-zq"', "webhook_name: nightly-sync", "webhooks: 3 configured, 1 insecure"]) {
    assert.equal(scrubber.scrub(text), text, `a webhook name is not a URL and stays: ${text}`);
  }
  // On the data side the value is the origin alone, whatever the walker's own URL rule left of it: a rule that drops
  // only the query would keep the path, and a walker with no URL rule would keep both.
  const webhook = "https://svc:pw@hooks.example.com/services/T000/B000/abcdefghijkl?ts=1695000000&sig=mnopqrstuvwx";
  const queryOnly = (text) => text.replace(/\?.*$/, `?${REDACTED}`);
  const originOnly = (text) => (/^\s*https?:\/\//.test(text) ? `${new URL(text.trim()).protocol}//${new URL(text.trim()).host}` : text);
  for (const options of [{}, { transformString: queryOnly }, { transformString: originOnly }]) {
    const out = scrubber.scrubData({ id: "rec-4", webhook_url: webhook, name: "benign-sibling", hooks: [{ callbackUrl: ` ${webhook} ` }] }, options);
    assert.deepEqual(out, { id: "rec-4", webhook_url: "https://hooks.example.com", name: "benign-sibling", hooks: [{ callbackUrl: "https://hooks.example.com" }] });
  }
  assert.deepEqual(scrubber.scrubData({ webhook_url: "https://hooks.example.com" }), { webhook_url: "https://hooks.example.com" }, "an origin is already reduced");
  assert.deepEqual(scrubber.scrubData({ webhook_url: "https://[not a host/x" }), { webhook_url: REDACTED }, "a value that starts like a URL but does not parse becomes the marker");
  assert.deepEqual(
    scrubber.scrubData({ webhook_url: "hooks.example.com/services/T000/B000/abcdefghijkl", callbackUri: "/oauth/cb?code=abcdefghijkl", hook_url: "", webhook: "nightly-sync", webhooks: ["nightly-sync"] }),
    { webhook_url: REDACTED, callbackUri: REDACTED, hook_url: "", webhook: "nightly-sync", webhooks: ["nightly-sync"] },
    "a schemeless path under a URL-named webhook key becomes the marker, a blank stays blank, and a webhook name stays a name",
  );
});

// Gap 35: the application-key spellings a Datadog integration record carries (`appKey`, `application_key`, `DD_APP_KEY`)
// are credential keys on the data side in every walker, not only the shared one and Datadog's own.
const APPLICATION_KEY_SPELLINGS = ["appKey", "application_key", "DD_APP_KEY", "DD_APPLICATION_KEY", "DATADOG_APP_KEY", "appkey", "applicationKey", "app_key", "app-key", "applicationkeys"];

test("gap 35: every application-key spelling loses a human-chosen value in the shared record walker and every module walker, while the identifier and name beside it stay", () => {
  const walkers = [
    ["shared scrubData", (value) => createCredentialScrubber().scrubData(value)],
    ["box redactCredentialValues", redactBoxValues],
    ["launchdarkly redactCredentialValues", redactLaunchdarklyValues],
    ["knowbe4 redactCredentialValues", redactKnowbe4Values],
    ["datadog redactCredentialValues", redactDatadogValues],
    ["elastic redactSensitiveValues", redactElasticValues],
  ];
  for (const [label, walk] of walkers) {
    for (const value of WEAK_VALUES) {
      const record = { id: "int-1", name: "datadog-sync", ...Object.fromEntries(APPLICATION_KEY_SPELLINGS.map((key) => [key, value])) };
      const out = walk(record);
      for (const key of APPLICATION_KEY_SPELLINGS) assert.equal(out[key], REDACTED, `${label}: ${key}=${value} survived as ${JSON.stringify(out[key])}`);
      assert.equal(out.id, "int-1", `${label}: the identifier stays`);
      assert.equal(out.name, "datadog-sync", `${label}: the name stays`);
    }
    const nested = walk({ integrations: [{ kind: "datadog", config: { appKey: "monkey", region: "us1" } }] });
    assert.deepEqual(nested, { integrations: [{ kind: "datadog", config: { appKey: REDACTED, region: "us1" } }] }, `${label}: nested application key`);
  }
});

// Gap 39: a `webhook`-prefixed key whose last segment names a credential is a credential key, not a URL key, so its
// value goes whatever its shape in every carrier form; the URL keys and the bare webhook name keep their rulings.
const WEBHOOK_CREDENTIAL_KEYS = ["webhook_secret", "WEBHOOK_SECRET", "webhookSecret", "webhook_token", "webhook_signing_key"];
const WEBHOOK_CREDENTIAL_FORMS = [
  ["flag with a space", (key, value) => `--${key.replace(/_/g, "-")} ${value}`],
  ["flag with =", (key, value) => `--${key.replace(/_/g, "-")}=${value}`],
  ["Java property", (key, value) => `-D${key}=${value}`],
  ["path segment", (key, value) => `/api/v1/${key}=${value}`],
  ["scheme word first", (key, value) => `${key}=token ${value}`],
  ["scheme word first, colon", (key, value) => `${key}: bearer ${value}`],
  ["JSON with a URL sibling", (key, value) => `{"webhook_url": "https://hooks.example.com/services/T/B/x", "${key}": "${value}"}`],
];
const WEBHOOK_KEPT_TEXTS = [
  "webhook=nightly-sync",
  "webhooks: 3 configured",
  "webhook_name=nightly-sync",
  "webhook_id=123",
  "webhook_count: 3",
  "webhook_status: active",
  '"webhook": "canary-insecure-hook-zq"',
];

test("gap 39: a webhook-prefixed credential key loses a human-chosen value in the flag, Java property, path, scheme-first, and JSON forms through every entry point, while the webhook name and setting keys stay", () => {
  for (const key of WEBHOOK_CREDENTIAL_KEYS) assert.ok(!isWebhookKey(key) && isCredentialKey(key), `expected a credential key that is not a URL key: ${key}`);
  for (const key of ["webhook_name", "webhook_id", "webhook_count", "webhook_status"]) assert.ok(!isWebhookKey(key) && !isCredentialKey(key), `expected a setting: ${key}`);
  let cells = 0;
  for (const [entryLabel, entry] of ENTRY_POINTS) {
    for (const key of WEBHOOK_CREDENTIAL_KEYS) {
      for (const value of WEAK_VALUES) {
        for (const [formLabel, form] of WEBHOOK_CREDENTIAL_FORMS) {
          const scrubbed = entry(form(key, value));
          assertPairValueGone(scrubbed, formLabel.startsWith("flag") ? key.replace(/_/g, "-") : key, value, `${entryLabel}, ${formLabel}, ${key}=${value}`);
          if (formLabel.startsWith("scheme word first")) {
            assert.ok(!/[=:] ?(?:token|bearer)\b/i.test(scrubbed), `${entryLabel}, ${formLabel}, ${key}: the scheme word is the value's first word and goes: ${scrubbed}`);
          }
          if (formLabel === "JSON with a URL sibling") {
            assert.ok(scrubbed.includes("https://hooks.example.com/"), `${entryLabel}, ${key}: the sibling URL keeps its origin: ${scrubbed}`);
          }
          cells += 1;
        }
      }
    }
    for (const text of WEBHOOK_KEPT_TEXTS) {
      const output = entry(text);
      assert.ok(output.includes(text) || output.includes(JSON.stringify(text).slice(1, -1)), `${entryLabel}: a webhook name or setting changed: ${text} -> ${output}`);
    }
  }
  assert.equal(cells, ENTRY_POINTS.length * WEBHOOK_CREDENTIAL_KEYS.length * WEAK_VALUES.length * WEBHOOK_CREDENTIAL_FORMS.length);
  const scrubber = createCredentialScrubber();
  assert.equal(scrubber.scrub("webhook_secret=token rejected"), `webhook_secret=${REDACTED}`);
  assert.equal(scrubber.scrub("webhook_url=https://hooks.example.com/services/T/B/x webhook_secret=hunter2"), `webhook_url=https://hooks.example.com/${REDACTED} webhook_secret=${REDACTED}`);
  // A URL-named key's non-URL value becomes the marker on the text side too (a schemeless path would keep its token);
  // a clause after `webhook_url:` is prose and stays.
  assert.equal(scrubber.scrub("webhook_url=hooks.example.com/services/T/B/x"), `webhook_url=${REDACTED}`);
  assert.equal(scrubber.scrub('"webhook_url": "hooks.example.com/services/T/B/x"'), `"webhook_url": "${REDACTED}"`);
  assert.equal(scrubber.scrub("callback_url=hooks.example.com/services/T/B/x"), `callback_url=${REDACTED}`);
  assert.equal(scrubber.scrub("webhook_url: the endpoint was unreachable after 3 attempts"), "webhook_url: the endpoint was unreachable after 3 attempts");
  assert.equal(scrubber.scrub("webhook_url: https://hooks.example.com/services/T/B/x was unreachable"), `webhook_url: https://hooks.example.com/${REDACTED} was unreachable`);
});

// The (b) residual: a header-named key (`apiKey`, `x-api-key`, `x-auth-token`, `x-vault-token`) is read by the header
// carrier, which kept a leading scheme word for every header name; only the Authorization-style names keep it.
const HEADER_NAMED_KEYS = ["apiKey", "apikey", "api-key", "x-api-key", "X-Api-Key", "x-auth-token", "X-Auth-Token", "x-vault-token", "private-token", "x-access-token"];
const HEADER_SCHEME_WORDS = ["splunk", "token", "bearer", "Basic", "ApiKey", "OAuth", "Negotiate"];
const HEADER_SCHEME_FORMS = [
  ["NAME=<scheme> rejected", (key, scheme) => `${key}=${scheme} rejected`, (scheme) => `=${scheme}`],
  ["NAME=<scheme> <word>", (key, scheme) => `${key}=${scheme} ${NAME_SHAPED[0]}`, (scheme) => `=${scheme}`],
  ["NAME: <scheme>", (key, scheme) => `${key}: ${scheme}`, (scheme) => `: ${scheme}`],
  ["NAME: <scheme> rejected", (key, scheme) => `${key}: ${scheme} rejected`, (scheme) => `: ${scheme}`],
  ['NAME="<scheme> rejected"', (key, scheme) => `${key}="${scheme} rejected"`, (scheme) => `"${scheme}`],
  ['"NAME": "<scheme>"', (key, scheme) => `"${key}": "${scheme}"`, (scheme) => `"${scheme}"`],
];

test("header carrier: under an API-key or token header name a leading scheme word is the value's first word and goes with it, through every text entry point, while Authorization-style headers keep their scheme", () => {
  const textEntryPoints = ENTRY_POINTS.filter(([label]) => label.endsWith("scrub") || label.endsWith("scrubErrorText"));
  assert.equal(textEntryPoints.length, 6);
  let cells = 0;
  for (const [entryLabel, entry] of textEntryPoints) {
    for (const key of HEADER_NAMED_KEYS) {
      for (const scheme of HEADER_SCHEME_WORDS) {
        if (key.toLowerCase().includes(scheme.toLowerCase())) continue;
        for (const [formLabel, form, removed] of HEADER_SCHEME_FORMS) {
          const scrubbed = entry(form(key, scheme));
          const label = `${entryLabel}, ${formLabel}, ${key} / ${scheme}`;
          assert.ok(!scrubbed.includes(removed(scheme)), `${label}: the scheme word survived as the value: ${scrubbed}`);
          assert.ok(scrubbed.includes(key), `${label}: key lost: ${scrubbed}`);
          assert.ok(scrubbed.includes(REDACTED), `${label}: no marker written: ${scrubbed}`);
          assert.ok(!scrubbed.includes(NAME_SHAPED[0]), `${label}: the word after the scheme survived: ${scrubbed}`);
          cells += 1;
        }
      }
    }
    const kept = [
      `Authorization: Bearer ${REDACTED}`,
      `Authorization: ApiKey ${REDACTED}`,
      `Proxy-Authorization: Basic ${REDACTED}`,
      `authorization=Bearer ${REDACTED}`,
      'WWW-Authenticate: Bearer realm="api", error="invalid_token"',
      "X-Api-Key: [REDACTED]",
    ];
    assert.deepEqual(scrubAlterations(kept, entry), [], `${entryLabel}: an Authorization-style header lost its scheme or a fixed text changed`);
  }
  assert.ok(cells >= 6 * 9 * 6 * 6, `expected the full matrix, got ${cells}`);
  const scrubber = createCredentialScrubber({ headers: ["DD-API-KEY", "X-Phisher-Token"] });
  assert.equal(scrubber.scrub("X-Api-Key: token rejected"), `X-Api-Key: ${REDACTED}`);
  assert.equal(scrubber.scrub("apiKey=splunk rejected"), `apiKey=${REDACTED}`);
  assert.equal(scrubber.scrub("x-vault-token: splunk rejected"), `x-vault-token: ${REDACTED}`);
  assert.equal(scrubber.scrub("apiKey=token rejected value here"), `apiKey=${REDACTED} value here`);
  assert.equal(scrubber.scrub('X-Api-Key: Bearer "abcdefghijkl"'), `X-Api-Key: "${REDACTED}"`);
  assert.equal(scrubber.scrub("DD-API-KEY: token rejected"), `DD-API-KEY: ${REDACTED}`);
  assert.equal(scrubber.scrub("X-Phisher-Token: splunk rejected"), `X-Phisher-Token: ${REDACTED}`);
  assert.equal(scrubber.scrub("Authorization: Bearer abcdefghijkl"), `Authorization: Bearer ${REDACTED}`);
  assert.equal(scrubber.scrub('Authorization: Bearer "abcdefghijkl"'), `Authorization: Bearer "${REDACTED}"`);
  assert.equal(scrubber.scrub("Authorization: ApiKey abcdefghijkl"), `Authorization: ApiKey ${REDACTED}`);
  assert.equal(scrubber.scrub("Proxy-Authorization: Basic abcdefghijkl"), `Proxy-Authorization: Basic ${REDACTED}`);
});

// The bearer-id override (CodeRabbit on #78, r4077259415; `token_id` joined it in the 01:40 rulings, fail closed): a key
// ending in `secret_id` or `token_id`, in any prefix, casing, and separator, names a Vault AppRole secret id or a token
// id, which is a UUID the identifier rule would otherwise keep; they and the session-id keys are credential keys on
// both sides before the setting-suffix test. Every other `_id`, `_name`, and `_key_id` key the five modules read names
// a thing and keeps its value.
const BEARER_ID_KEYS = ["secret_id", "VAULT_SECRET_ID", "role_secret_id", "secretId", "roleSecretId", "vault.secret_id", "SECRETID", "token_id", "tokenId", "access_token_id", "session_id", "sessionId", "sid", "sessid", "JSESSIONID", "PHPSESSID", "ASP.NET_SessionId"];

/** The `_id`, `_name`, and `_key_id` keys the five modules read, config and vendor records included: all identifiers or settings. */
const IDENTIFIER_KEYS = [
  "client_id", "BOX_CLIENT_ID", "clientId", "enterprise_id", "BOX_ENTERPRISE_ID", "enterpriseId", "subject_id", "BOX_SUBJECT_ID", "publicKeyId", "public_key_id", "BOX_PUBLIC_KEY_ID",
  "key_id", "api_key_id", "access_key_id", "private_key_id", "secret_key_id", "tenant_id", "account_id", "org_id", "member_id", "_id", "id",
  "campaign_id", "group_id", "pst_id", "store_purchase_id", "user_id", "policy_id", "rule_id", "space_id", "event_id", "request_id",
];
const NAME_KEYS = ["secret_name", "tokenName", "token_name", "key_name", "role_name", "user_name", "policy_name", "space_name"];

const BEARER_ID_UUID = "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b";
const BEARER_ID_CANARY = "Hq4vT9mXcR2pLw8ZbN6kJd3sVf7yGa5e";

test("row (a), bearer ids: a key ending in secret_id or token_id or naming a session id is a credential key on both sides whatever its prefix, casing, and separator, before the setting-suffix test; every other _id, _name, and _key_id key stays an identifier or a setting", () => {
  for (const key of BEARER_ID_KEYS) {
    assert.ok(isBearerIdKey(key), `expected a bearer id: ${key}`);
    assert.ok(isCredentialKey(key) && isCredentialDataKey(key) && !isIdentifierKey(key), `expected a credential key on both sides: ${key}`);
  }
  assert.ok(isSettingKey("secret_id") && isSettingKey("VAULT_SECRET_ID") && isSettingKey("token_id"), "the id suffix still names a setting; the bearer-id override is checked first");
  for (const key of [...IDENTIFIER_KEYS, ...NAME_KEYS]) {
    assert.ok(!isBearerIdKey(key) && !isCredentialKey(key) && !isCredentialDataKey(key), `expected an identifier or setting, not a credential key: ${key}`);
  }
  for (const key of IDENTIFIER_KEYS) assert.ok(isIdentifierKey(key), `expected an identifier key: ${key}`);
  for (const key of NAME_KEYS) assert.ok(isSettingKey(key), `expected a setting key: ${key}`);
});

test("row (a), bearer ids: secret_id, VAULT_SECRET_ID, role_secret_id, and token_id lose a UUID, a random, and a human-chosen value in every pair form through every entry point, while client_id and the other identifiers keep a UUID", () => {
  const values = [BEARER_ID_UUID, BEARER_ID_CANARY, "hunter2"];
  const controls = ["client_id", "BOX_CLIENT_ID", "tenant_id", "enterprise_id", "key_id", "api_key_id", "account_id", "user_id"];
  let cells = 0;
  for (const [entryLabel, entry] of ENTRY_POINTS) {
    for (const [formLabel, form] of PAIR_FORMS) {
      for (const key of BEARER_ID_KEYS) {
        for (const value of values) {
          assertPairValueGone(entry(form(key, value)), key, value, `${entryLabel}, ${formLabel}, ${key}=${value}`);
          cells += 1;
        }
      }
      for (const key of controls) {
        const text = form(key, BEARER_ID_UUID);
        assert.ok(entry(text).includes(BEARER_ID_UUID), `${entryLabel}, ${formLabel}: the identifier ${key} lost its UUID: ${entry(text)}`);
      }
      for (const key of NAME_KEYS) {
        const text = form(key, "deploy-key-2026");
        assert.ok(entry(text).includes("deploy-key-2026"), `${entryLabel}, ${formLabel}: the setting ${key} lost its name: ${entry(text)}`);
      }
    }
  }
  assert.equal(cells, ENTRY_POINTS.length * PAIR_FORMS.length * BEARER_ID_KEYS.length * values.length);
  // The control and the bearer id side by side: only the secret id goes.
  const scrubber = createCredentialScrubber();
  assert.equal(scrubber.scrub(`client_id=${BEARER_ID_UUID}&secret_id=${BEARER_ID_UUID}`), `client_id=${BEARER_ID_UUID}&secret_id=${REDACTED}`);
  assert.equal(scrubber.scrub(`role_id: ${BEARER_ID_UUID}, VAULT_SECRET_ID: ${BEARER_ID_UUID}`), `role_id: ${BEARER_ID_UUID}, VAULT_SECRET_ID: ${REDACTED}`);
  assert.equal(scrubber.scrub(`{"role_id": "${BEARER_ID_UUID}", "role_secret_id": "${BEARER_ID_UUID}"}`), `{"role_id": "${BEARER_ID_UUID}", "role_secret_id": "${REDACTED}"}`);
});

test("row (a), bearer ids: the shared record walker and every module walker replace a secret_id or session id value whatever its shape and keep the identifier keys beside it", () => {
  const record = {
    secret_id: BEARER_ID_UUID,
    VAULT_SECRET_ID: BEARER_ID_CANARY,
    role_secret_id: "hunter2",
    session_id: BEARER_ID_UUID,
    sid: 48213,
    JSESSIONID: BEARER_ID_CANARY,
    client_id: BEARER_ID_UUID,
    tenant_id: BEARER_ID_UUID,
    enterprise_id: "12345678",
    key_id: "kid-2026",
    secret_name: "deploy-key-2026",
    nested: { auth: { secret_id: BEARER_ID_UUID, role_id: BEARER_ID_UUID } },
    list: [{ secret_id: BEARER_ID_CANARY, user_id: BEARER_ID_UUID }],
  };
  const walkers = [
    ["shared scrubData", (value) => createCredentialScrubber().scrubData(value)],
    ["box redactCredentialValues", redactBoxValues],
    ["launchdarkly redactCredentialValues", redactLaunchdarklyValues],
    ["knowbe4 redactCredentialValues", redactKnowbe4Values],
    ["datadog redactCredentialValues", redactDatadogValues],
    ["elastic redactSensitiveValues", redactElasticValues],
  ];
  for (const [label, walker] of walkers) {
    const out = walker(record);
    for (const key of ["secret_id", "VAULT_SECRET_ID", "role_secret_id", "session_id", "sid", "JSESSIONID"]) assert.equal(out[key], REDACTED, `${label}: ${key}`);
    assert.equal(out.nested.auth.secret_id, REDACTED, `${label}: nested secret_id`);
    assert.equal(out.list[0].secret_id, REDACTED, `${label}: secret_id in a list`);
    assert.equal(out.client_id, BEARER_ID_UUID, `${label}: client_id keeps its UUID`);
    assert.equal(out.tenant_id, BEARER_ID_UUID, `${label}: tenant_id keeps its UUID`);
    assert.equal(out.enterprise_id, "12345678", `${label}: enterprise_id`);
    assert.equal(out.key_id, "kid-2026", `${label}: key_id`);
    assert.equal(out.secret_name, "deploy-key-2026", `${label}: secret_name`);
    assert.equal(out.nested.auth.role_id, BEARER_ID_UUID, `${label}: role_id beside the secret id`);
    assert.equal(out.list[0].user_id, BEARER_ID_UUID, `${label}: user_id in a list`);
    assertCanaryWindowsAbsent(assert, JSON.stringify(out), [BEARER_ID_CANARY], `${label} output`);
    assert.deepEqual(walker(out), out, `${label}: the walker is idempotent`);
  }
});

test("row (a), prose: a plural inventory label or PascalCase code followed by a clause, an unquoted JSON literal, an unqualified key, and a spaced `=` in a syntax description all survive; the same spellings as assignments go", () => {
  const scrubber = createCredentialScrubber();
  const kept = [
    "InvalidAuthenticationToken: Access token has expired.",
    "access_tokens: LaunchDarkly request failed (403 Forbidden) for GET /api/v2/tokens?showAll=true: forbidden: Forbidden",
    "api_keys: 3 of 5 keys have no expiry; tokens: none are stale",
    "Authorization > Access tokens: name, role or custom role, owner, expiry, and last used date of every token",
    "sdk_keys:web/production: LaunchDarkly request failed (403 Forbidden)",
    "application_keys (GET /api/v2/application_keys, org_app_keys_read: Datadog request failed (403 Forbidden) GET /api/v2/application_keys: Forbidden)",
    "posture_findings_pass: Datadog request failed (403 Forbidden) GET /api/v2/posture_management/findings: Forbidden",
    "user-session: 3 active sessions",
    "- Pass: 7\n- Warn: 3\n- Fail: 7\n- Manual: 3",
    "Pass: 7, Warn: 3, Fail: 7, Manual: 3",
    "Invalid TOML at line 3: expected a comment, a [table] header, or a key = value pair",
    '"has_private_key": true, "api_keys_total": 2, "api_keys_complete": null, "authorization_realms": [], "enrollment_keys": 6',
    '"password_hashing_explicit": true, "token_service_enabled": false, "tokens_without_expiry": 1',
    '"integrationKey": "datadog", "key": "checkout-v2", "flagKey": "new-checkout", "projectKey": "web"',
    "key = value pair",
  ];
  assert.deepEqual(scrubAlterations(kept, scrubber.scrub), []);
  // The same spellings as assignments, quoted values, or under a qualified key go.
  assert.equal(scrubber.scrub("developer_token: Access was denied"), `developer_token: ${REDACTED} was denied`);
  assert.equal(scrubber.scrub("InvalidAuthenticationToken=Sunshine"), `InvalidAuthenticationToken=${REDACTED}`);
  assert.equal(scrubber.scrub('"access_tokens": "Sunshine"'), `"access_tokens": "${REDACTED}"`);
  assert.equal(scrubber.scrub("api_keys: Sunshine"), `api_keys: ${REDACTED}`);
  assert.equal(scrubber.scrub("api_keys: Sunshine; tokens: monkey"), `api_keys: ${REDACTED}; tokens: ${REDACTED}`);
  assert.equal(scrubber.scrub("org_app_keys_read: Sunshine"), `org_app_keys_read: ${REDACTED}`);
  assert.equal(scrubber.scrub("posture_findings_pass=Sunshine"), `posture_findings_pass=${REDACTED}`);
  assert.equal(scrubber.scrub("db_pass: Sunshine was rejected"), `db_pass: ${REDACTED} was rejected`);
  // A colon after the value chains labels only under a clause label; under a singular key it is an assignment.
  assert.equal(scrubber.scrub("developer_token: letmein2024: security_exception"), `developer_token: ${REDACTED}: security_exception`);
  assert.equal(scrubber.scrub("api_key: Sunshine:monkey"), `api_key: ${REDACTED}`);
  assert.equal(scrubber.scrub("sdk_keys:web/production: LaunchDarkly request failed (403 Forbidden)"), "sdk_keys:web/production: LaunchDarkly request failed (403 Forbidden)");
  assert.equal(scrubber.scrub('"has_private_key": "hunter2"'), `"has_private_key": "${REDACTED}"`);
  assert.equal(scrubber.scrub("has_private_key=true"), `has_private_key=${REDACTED}`);
  assert.equal(scrubber.scrub('"sdk_key": "letmein", "api_key": "hunter2"'), `"sdk_key": "${REDACTED}", "api_key": "${REDACTED}"`);
  assert.equal(scrubber.scrub(`"key": "${TOKEN_SHAPED.tokenCasing}"`), `"key": "${REDACTED}"`);
  assert.equal(scrubber.scrub("[auth]\ndeveloper_token = letmein\nregion = us"), `[auth]\ndeveloper_token = ${REDACTED}\nregion = us`);
});

// ---------------------------------------------------------------------------------------------------------------
// The cookie attribute class (CodeRabbit on #78, r4076392614): a later cookie whose name holds a "." or any other
// RFC 6265 token character goes with the header value, the scan still stops at the next header's `Name:` token, and
// the following header keeps its name. The rows live in helpers/cookie-attribute-carriers.mjs so each integration
// suite can run them too.
// ---------------------------------------------------------------------------------------------------------------

/** The same twelve entry points as text-to-text functions, so the rows' exact expected text can be asserted. */
const TEXT_ENTRY_POINTS = [
  ["shared scrub", (text) => createCredentialScrubber().scrub(text)],
  ["shared scrubData", (text) => createCredentialScrubber().scrubData({ note: text }).note],
  ["box scrubErrorText", scrubBoxErrorText],
  ["launchdarkly scrubErrorText", scrubLaunchdarklyErrorText],
  ["knowbe4 scrubErrorText", scrubKnowbe4ErrorText],
  ["datadog scrubErrorText", scrubDatadogErrorText],
  ["elastic scrubErrorText", scrubElasticErrorText],
  ["box redactCredentialValues", (text) => redactBoxValues({ note: text }).note],
  ["launchdarkly redactCredentialValues", (text) => redactLaunchdarklyValues({ note: text }).note],
  ["knowbe4 redactCredentialValues", (text) => redactKnowbe4Values({ note: text }).note],
  ["datadog redactCredentialValues", (text) => redactDatadogValues({ note: text }).note],
  ["elastic redactSensitiveValues", (text) => redactElasticValues({ note: text }).note],
];

test("cookie attribute class: the planted values look random and share no 6-character window with the rows or the must-keep strings, and the name row holds every token character", () => {
  const legitimate = [...cookieAttributeCarrierTexts(), ...MUST_KEEP.map((text, index) => [`must-keep ${index}`, text])];
  assertCanaryFixture(assert, COOKIE_ATTRIBUTE_CANARIES, legitimate, "cookie attribute rows");
  for (const character of "!#$%&*+-.^_`|~") assert.ok(TOKEN_PUNCTUATION_COOKIE_NAME.includes(character), `token character ${character} is in the name row`);
  assert.doesNotMatch(TOKEN_PUNCTUATION_COOKIE_NAME, /[\s;,="'<>()[\]{}\\]/, "the name row holds no cookie separator");
});

test("cookie attribute class: a later cookie whose name holds a dot or another token character goes with the header value through every entry point, and the following header names survive", () => {
  const values = [...COOKIE_ATTRIBUTE_CANARIES, ...NAME_SHAPED];
  for (const [label, entry] of TEXT_ENTRY_POINTS) assertCookieAttributeCarriersScrubbed(assert, entry, label, values);
  assert.equal(TEXT_ENTRY_POINTS.length, ENTRY_POINTS.length, "every entry point of the row (a) matrix runs the cookie rows");
  // With the value registered as a configured secret, the secret pass runs first and leaves its marker inside the
  // header value; the cookie reader steps over it so the attributes after it go with the header value.
  const registered = createCredentialScrubber();
  registered.registerSecrets(values);
  assertCookieAttributeCarriersScrubbed(assert, (text) => registered.scrub(text), "shared scrub, values registered as secrets", values);
});

test("cookie attribute class: the reported shapes come out with the whole header value gone and nothing of a later pair left behind", () => {
  const scrubber = createCredentialScrubber();
  assert.equal(scrubber.scrub("Cookie: theme=dark; my.sid=hunter2"), `Cookie: ${REDACTED}`);
  assert.equal(scrubber.scrub("Cookie: theme=dark; ASP.NET_SessionId=abc; Path=/"), `Cookie: ${REDACTED}`);
  assert.equal(scrubber.scrub("Set-Cookie: .AspNetCore.Session=v; HttpOnly; SameSite=Lax"), `Set-Cookie: ${REDACTED}`);
  assert.equal(scrubber.scrub("Cookie: theme=dark; my.sid=hunter2; Accept: application/json"), `Cookie: ${REDACTED}; Accept: application/json`);
  assert.equal(scrubber.scrub("Cookie: theme=dark; my.sid=hunter2; X.Api.Key: hunter2"), `Cookie: ${REDACTED}; X.Api.Key: ${REDACTED}`);
  assert.equal(scrubber.scrub("Cookie: a=1&sid=hunter2"), `Cookie: ${REDACTED}`, "a marker an earlier rule left at the end of the header value folds into the header's own");
  // A configured secret is replaced before the cookie reader runs; its marker inside the header value is stepped over
  // so the attributes after it go too, and the next header still ends the value.
  const registered = createCredentialScrubber();
  registered.registerSecrets(["hunter2-secret-zq"]);
  assert.equal(registered.scrub("Cookie: theme=dark; ASP.NET_SessionId=hunter2-secret-zq; Path=/; HttpOnly"), `Cookie: ${REDACTED}`);
  assert.equal(registered.scrub("Cookie: my'pref=1; sid=O'hunter2-secret-zq; Path=/"), `Cookie: ${REDACTED}`);
  assert.equal(registered.scrub("Cookie: theme=dark; ASP.NET_SessionId=hunter2-secret-zq; Path=/; X-Api-Key: hunter2-secret-zq"), `Cookie: ${REDACTED}; X-Api-Key: ${REDACTED}`);
  for (const text of ["the Cookie header was rejected", "Cookie: ", "Cookie: [REDACTED]", "cookie consent banner; the session ended"]) {
    assert.equal(scrubber.scrub(text), text, `nothing to remove: ${text}`);
  }
});

// ---------------------------------------------------------------------------------------------------------------
// Name boundary (coordinator rulings, rows A and D): a carrier fires after the letters of a JSON escape written into the
// text, after the dashes that open a command-line flag, and after a raw or escaped slash that ends a path segment;
// a name inside a request line or a URL, a hyphenated word, and a challenge's auth-param stay.
// ---------------------------------------------------------------------------------------------------------------

/** Random alphanumeric values planted in the boundary rows; the second is only ever planted after an escape. */
const BOUNDARY_CANARIES = ["VpUp1M1zy4myCidHiCobqUCXgAdEOzww", "AHc5hFZwLzYsazaf4xQ3O3mlLmhdDaby"];

/** [label, carrier(value), text that must survive around the marker]. */
const BOUNDARY_CARRIERS = [
  ["escape \\n before a pair", (value) => `request failed\\nsdk_key=${value} see the log`, ["request failed\\nsdk_key=", " see the log"]],
  ["escape \\t before a colon pair", (value) => `request failed\\tclient_token: ${value} see the log`, ["request failed\\tclient_token: ", " see the log"]],
  ["escape \\u000a before a pair", (value) => `request failed\\u000amobile_key=${value} see the log`, ["request failed\\u000amobile_key=", " see the log"]],
  ["escape \\u000a before an upper-case pair whose name carries digits", (value) => `request failed\\u000aKNOWBE4_API_TOKEN: ${value} see the log`, ["request failed\\u000aKNOWBE4_API_TOKEN: ", " see the log"]],
  ["escape \\r\\n before a scheme word", (value) => `request failed\\r\\nBearer ${value} see the log`, ["request failed\\r\\nBearer ", " see the log"]],
  ["escape \\r\\n before a header", (value) => `request failed\\r\\nAuthorization: Bearer ${value} see the log`, ["request failed\\r\\nAuthorization: Bearer ", " see the log"]],
  ["escape \\n before a pair inside a JSON string member", (value) => `{"detail":"request failed\\nsdk_key=${value} see the log"}`, ['{"detail":"request failed\\nsdk_key=', ' see the log"}']],
  ["escaped slash before a pair", (value) => `request failed\\/password=${value} see the log`, ["request failed\\/password=", " see the log"]],
  ["escaped slash after a path segment", (value) => `secret at path\\/password=${value} see the log`, ["secret at path\\/password=", " see the log"]],
  ["raw slash after a path segment, colon pair", (value) => `vault read kv/password: ${value} see the log`, ["vault read kv/password: ", " see the log"]],
  ["raw slash before a pair", (value) => `mount /password=${value} see the log`, ["mount /password=", " see the log"]],
  ["long flag", (value) => `mysql --password=${value} -h db.example.com`, ["mysql --password=", " -h db.example.com"]],
  ["short flag with a property key", (value) => `java -Dspring.datasource.password=${value} -jar app.jar`, ["java -Dspring.datasource.password=", " -jar app.jar"]],
  ["short flag with a bearer-id key", (value) => `java -Dsecret_id=${value} -jar app.jar`, ["java -Dsecret_id=", " -jar app.jar"]],
  ["short flag with a qualified key", (value) => `java -Dapi_key=${value} -jar app.jar`, ["java -Dapi_key=", " -jar app.jar"]],
  ["short flag with a hyphenated key", (value) => `java -Dprivate-key=${value} -jar app.jar`, ["java -Dprivate-key=", " -jar app.jar"]],
  ["short flag at line start", (value) => `-Dapi_key=${value}`, ["-Dapi_key="]],
  ["long flag with a hyphenated key", (value) => `vault login --vault-secret-id=${value} now`, ["vault login --vault-secret-id=", " now"]],
  ["backslash before a plain pair name", (value) => `note \\token=${value} end`, ["note \\token=", " end"]],
];

/** Text the boundary rules must leave unchanged: request lines, URLs, hyphenated words, and challenge auth-params. */
const BOUNDARY_KEPT = [
  "api_keys (GET /_security/api_key: 403 Forbidden: security_exception)",
  "POST /oauth2/token: invalid_grant",
  "GET /_security/api_key?with_limited_by=true",
  "user-session: 3 active sessions",
  "java -Duser.name=alice -Dtoken.file=/etc/app/token -jar app.jar",
  "Config precedence resolved from: environment-token -> config-base-url -> config-file-present.",
  'WWW-Authenticate: Bearer realm="api", error="invalid_token"',
  'WWW-Authenticate: Basic realm="Restricted"',
  "Bearer error_description=\"The access token expired\"",
];

/**
 * URL rows the boundary rules must leave unchanged. The LaunchDarkly data walker reduces a URL to its origin wherever
 * it stands by design (`reduceUrl`), so that entry point is not run on these rows; the Elastic walker reduces only a
 * value that is one URL (`reduceUrlValueToOrigin`) and runs on them.
 */
const URL_REDUCING_ENTRY_POINTS = new Set(["launchdarkly redactCredentialValues"]);
const BOUNDARY_KEPT_URLS = [
  "https://api.box.com/oauth2/token: 400 Bad Request",
  "GET https://es.example.com:9200/_security/api_key: 403 Forbidden",
  "https:\\/\\/es.example.com:9200\\/_security\\/api_key: 403 Forbidden",
  "java -Dtoken_url=https://auth.example.com/token -jar app.jar",
];

test("name boundary: the planted values look random and share no 6-character window with the boundary rows or the must-keep strings", () => {
  const legitimate = [
    ...BOUNDARY_CARRIERS.map(([label, carrier]) => [label, carrier("")]),
    ...BOUNDARY_KEPT.map((text, index) => [`kept ${index}`, text]),
    ...BOUNDARY_KEPT_URLS.map((text, index) => [`kept url ${index}`, text]),
    ...MUST_KEEP.map((text, index) => [`must-keep ${index}`, text]),
  ];
  assertCanaryFixture(assert, BOUNDARY_CANARIES, legitimate, "boundary rows");
});

test("name boundary rows A and D: a carrier fires after a JSON escape, after a flag's dashes, and after a path segment, through every entry point, and the escape, the flag, and the path stay", () => {
  const values = [...BOUNDARY_CANARIES, ...NAME_SHAPED];
  for (const [entryPoint, scrub] of TEXT_ENTRY_POINTS) {
    for (const [label, carrier, survivors] of BOUNDARY_CARRIERS) {
      for (const value of values) {
        const scrubbed = scrub(carrier(value));
        assertRemoved(scrubbed, value, `${entryPoint}: ${label} with ${value}`);
        for (const survivor of survivors) assert.ok(scrubbed.includes(survivor), `${entryPoint}: ${label} with ${value}: ${JSON.stringify(survivor)} did not survive: ${scrubbed}`);
        assert.equal(scrub(scrubbed), scrubbed, `${entryPoint}: ${label} with ${value}: a second pass changed the text`);
      }
    }
  }
  const scrubber = createCredentialScrubber();
  const [canary] = BOUNDARY_CANARIES;
  assert.equal(scrubber.scrub(`request failed\\nsdk_key=${canary} see the log`), `request failed\\nsdk_key=${REDACTED} see the log`);
  assert.equal(scrubber.scrub(`request failed\\u000aKNOWBE4_API_TOKEN: ${canary} see the log`), `request failed\\u000aKNOWBE4_API_TOKEN: ${REDACTED} see the log`, "the escape letters are not judged with the name they precede");
  assert.equal(scrubber.scrub(`request failed\\/password=${canary} see the log`), `request failed\\/password=${REDACTED} see the log`);
  assert.equal(scrubber.scrub(`mysql --password=${canary} -h db.example.com`), `mysql --password=${REDACTED} -h db.example.com`);
  assert.equal(scrubber.scrub(`java -Dspring.datasource.password=${canary} -jar app.jar`), `java -Dspring.datasource.password=${REDACTED} -jar app.jar`);
  for (const key of ["secret_id", "api_key", "private-key"]) {
    assert.equal(scrubber.scrub(`java -D${key}=${NAME_SHAPED[0]} -jar app.jar`), `java -D${key}=${REDACTED} -jar app.jar`, `the flag is -D and the key is ${key}, so a name-shaped value goes too`);
  }
  assert.equal(scrubber.scrub(`java --Dapi_key=${NAME_SHAPED[0]} -jar app.jar`), `java --Dapi_key=${NAME_SHAPED[0]} -jar app.jar`, "after two dashes the D belongs to the name, an unqualified key that keeps a name-shaped value");
  assert.equal(scrubber.scrub(`vault read kv/password: ${canary} see the log`), `vault read kv/password: ${REDACTED} see the log`);
  assert.equal(scrubber.scrub(`mysql --password=hunter2abcd -h db`), `mysql --password=${REDACTED} -h db`, "a short plain value after a flag goes too: the flag is an assignment");
});

test("name boundary: an escape glued to a bare token run is written back and only the run after it is judged", () => {
  const scrubber = createCredentialScrubber();
  const [, canary] = BOUNDARY_CANARIES;
  assert.equal(scrubber.scrub(`echoed\\u000a${canary} by the proxy`), `echoed\\u000a${REDACTED} by the proxy`);
  assert.equal(scrubber.scrub(`echoed\\n${canary} by the proxy`), `echoed\\n${REDACTED} by the proxy`);
  assert.equal(scrubber.scrub("request failed\\u000aKNOWBE4_PHISHER_API_TOKEN see the log"), "request failed\\u000aKNOWBE4_PHISHER_API_TOKEN see the log", "a name after an escape is a name, not a token with two digit groups");
  assert.equal(scrubber.scrub("request failed\\u000aKNOWBE4_REGION: us see the log"), "request failed\\u000aKNOWBE4_REGION: us see the log");
  for (const [entryPoint, scrub] of TEXT_ENTRY_POINTS) {
    const scrubbed = scrub(`echoed\\u000a${canary} by the proxy`);
    assertRemoved(scrubbed, canary, `${entryPoint}: escape glued to a token`);
    assert.ok(scrubbed.includes("echoed\\u000a"), `${entryPoint}: the escape survived: ${scrubbed}`);
  }
});

test("name boundary: request lines, URLs, hyphenated words, and challenge auth-params are kept unchanged through every entry point", () => {
  for (const [entryPoint, scrub] of TEXT_ENTRY_POINTS) {
    assert.deepEqual(scrubAlterations(BOUNDARY_KEPT, scrub), [], `${entryPoint}: a kept row was altered`);
    if (!URL_REDUCING_ENTRY_POINTS.has(entryPoint)) assert.deepEqual(scrubAlterations(BOUNDARY_KEPT_URLS, scrub), [], `${entryPoint}: a kept URL row was altered`);
  }
  const scrubber = createCredentialScrubber();
  assert.equal(scrubber.scrub('Bearer realm="api"'), 'Bearer realm="api"', "an auth-param after a scheme word is the challenge, not a credential");
  assert.equal(scrubber.scrub(`Bearer realm="api", access_token=${BOUNDARY_CANARIES[0]}`), `Bearer realm="api", access_token=${REDACTED}`, "a credential pair after the auth-param still goes");
});

test("URL rule: a URL written with JSON-escaped slashes loses its userinfo and query the same way and keeps its escaped form", () => {
  const [canary] = BOUNDARY_CANARIES;
  for (const [entryPoint, scrub] of TEXT_ENTRY_POINTS) {
    const scrubbed = scrub(`fetched https:\\/\\/svc:${canary}@api.example.com\\/v1 mid-sentence`);
    assertRemoved(scrubbed, canary, `${entryPoint}: escaped URL userinfo`);
    assert.ok(scrubbed.includes("https:\\/\\/api.example.com\\/v1"), `${entryPoint}: the escaped form survived: ${scrubbed}`);
    assert.equal(scrub(scrubbed), scrubbed, `${entryPoint}: a second pass changed the text`);
    const query = scrub(`{"url":"https:\\/\\/api.example.com\\/v1?token=${canary}"}`);
    assertRemoved(query, canary, `${entryPoint}: escaped URL query`);
    assert.ok(query.includes('{"url":"https:\\/\\/api.example.com\\/v1?'), `${entryPoint}: the escaped form survived: ${query}`);
  }
  const scrubber = createCredentialScrubber();
  assert.equal(scrubber.scrub(`fetched https:\\/\\/svc:${canary}@api.example.com\\/v1 mid-sentence`), `fetched https:\\/\\/api.example.com\\/v1?${REDACTED} mid-sentence`);
  assert.equal(scrubber.scrub(`{"url":"https:\\/\\/api.example.com\\/v1?token=${canary}"}`), `{"url":"https:\\/\\/api.example.com\\/v1?${REDACTED}"}`);
  assert.equal(scrubber.scrub('{"url":"https:\\/\\/api.example.com\\/v1"}'), '{"url":"https:\\/\\/api.example.com\\/v1"}', "an escaped URL with nothing to remove is unchanged");
});

const DATA_CANARIES = {
  tokensEntry: "BPt5mgDrRZ5YyLTHaQPepJUYQbGYRCjG",
  credentialsValue: "zSVNdtuTMXK9T7qXe8CEDEYXmJ9K6vVL",
  headerValue: "QJGjPixxDSCkGNoArXMeL2USsBcdGfdd",
  noteToken: "PCWXTXXWpLrVFgXp2SPm7YQKZgcAgWUx",
  deepNote: "U7ktAa5zEHKELrac4CfrjWJF3zBQuiEx",
};

test("scrubData: the module key rule sees the enclosing key, pair values go by name, identifier keys keep their value, a container past the depth cap becomes the marker, and the strings inside the deepest kept container are scrubbed rather than dropped", () => {
  const scrubber = createCredentialScrubber();
  const deep = { level: 0 };
  let cursor = deep;
  for (let level = 1; level <= 12; level += 1) {
    cursor.child = { level, label: `depth-label-${level}`, note: level === 9 ? DATA_CANARIES.deepNote : `depth-note-${level}` };
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

  // deep sits at depth 1, child level L at depth L + 1, and its strings at depth L + 2: level 9 (depth 10) is the deepest
  // kept container, so its strings (depth 11) are scrubbed and kept, and its child (depth 11) becomes the marker.
  let level = out.deep;
  for (let index = 1; index <= 8; index += 1) level = level.child;
  assert.equal(level.level, 8);
  assert.equal(level.note, "depth-note-8", "a string at the cap is kept");
  assert.equal(level.child.level, 9);
  assert.equal(level.child.label, "depth-label-9", "a string inside the deepest kept container is kept");
  assert.equal(level.child.note, REDACTED, "a token-shaped string inside the deepest kept container still gets the pattern pass");
  assert.equal(level.child.child, REDACTED, "a container past the cap becomes the marker, so nothing below it is copied");
  assert.ok(!JSON.stringify(out).includes("depth-label-10"), "no string below the masked container is copied");
  assertCanaryWindowsAbsent(assert, JSON.stringify(out), Object.values(DATA_CANARIES), "scrubData output");
  assert.deepEqual(scrubber.scrubData(out, { isCredentialKey: isModuleCredentialKey, maxDepth: 10 }), out, "the data-side scrub is idempotent");
});

test("gap 36: scrubData at the default cap of 24 keeps and scrubs every string down to depth 25 (inside the deepest kept container), masks the container at depth 25, copies nothing from depth 26, and the same pins hold at 32 and 64", () => {
  const scrubber = createCredentialScrubber();
  assertDepthCapPins(assert, (value) => scrubber.scrubData(value), DEFAULT_DATA_SCRUB_DEPTH, "shared scrubData, default cap");
  assert.equal(DEFAULT_DATA_SCRUB_DEPTH, 24);
  assertDepthCapPins(assert, (value) => scrubber.scrubData(value, { maxDepth: 32 }), 32, "shared scrubData, cap 32");
  assertDepthCapPins(assert, (value) => scrubber.scrubData(value, { maxDepth: 64 }), 64, "shared scrubData, cap 64");
});
