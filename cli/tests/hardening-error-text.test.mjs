import test from "node:test";
import assert from "node:assert/strict";

import {
  IntegrationError,
  LONG_TOKEN_MIN_LENGTH,
  MAX_ERROR_MESSAGE_LENGTH,
  MAX_VENDOR_MESSAGE_LENGTH,
  MIN_CONFIGURED_SECRET_LENGTH,
  REDACTED,
  describeErrorBody,
  describeFailedResponse,
  errorMessage,
  isCredentialKey,
  mediaTypeOf,
  redactSecretValues,
  scrubDataText,
  scrubError,
  scrubErrorText,
} from "../dist/extensions/grc-tools/hardening/error-text.js";
import {
  CANARY,
  CANARY_URL,
  HTML_BODY_NOTE,
  REDACTED_CANARY_URL,
  REDACTION_CASES,
  assertNoCanaries,
  assertRedactionCases,
  carrierCases,
  htmlCanaryBody,
  jsonCanaryMessage,
} from "./helpers/error-canaries.mjs";
import {
  ENCODED_FORM_SECRET,
  ERROR_CANARY,
  ERROR_CANARY_URL,
  assertCanaryFixture,
  assertNoFragment,
  assertNoFragments,
  htmlCanaryPage,
  jsonCanarySentence,
} from "./helpers/hardening-canaries.mjs";

const HEX_DIGEST = "4f3a9c1b7e2d8f6a0b5c4d3e2f1a0b9c";
const UUID = "123e4567-e89b-12d3-a456-426614174000";
const CONFIGURED_SECRET = "s3cr3t-Value-With-Case-42";
/**
 * The shared group D contract (whole-value absence of every planted canary; those canaries are
 * readable words, so only the whole value is checked) plus the fragment rule for the random-looking
 * `ERROR_CANARY` set: no 6- to 24-character window may remain, so a partial echo (a truncated message,
 * a base64 tail, a `JSON.parse` window) cannot pass.
 */
function assertNoCanaryValues(value, label) {
  assertNoCanaries(assert, value, label);
  const text = typeof value === "string" ? value : JSON.stringify(value);
  for (const canary of [CANARY.basic, CANARY.jwt, CANARY.awsAccessKeyId, CANARY.awsSecret]) {
    assert.ok(!text.includes(canary), `${label}: canary ${canary} leaked`);
  }
  assertNoFragments(value, Object.values(ERROR_CANARY), { label });
}

/**
 * Every carrier of the `ERROR_CANARY` set: header lines, a cookie, a key pair, a URL query, a JWT, the
 * AWS pair in prose, and the AWS secret glued to `=` after a key that does not name a credential (a
 * bare `x=` and an env-style `NAME=`), where only the secret's own shape can catch it.
 */
function errorCanaryCarriers() {
  return [
    `Authorization: Bearer ${ERROR_CANARY.bearer} was rejected`,
    `proxy replayed Basic ${ERROR_CANARY.basic} and failed`,
    `Set-Cookie: session=${ERROR_CANARY.sessionCookie}; Path=/; HttpOnly`,
    `x-api-key: ${ERROR_CANARY.apiKey} for the caller`,
    `api_key=${ERROR_CANARY.apiKey}&page=2`,
    `retry the request at ${ERROR_CANARY_URL} once the incident clears`,
    `token ${ERROR_CANARY.jwt} expired`,
    `credentials ${ERROR_CANARY.awsAccessKeyId} ${ERROR_CANARY.awsSecret} were rejected`,
    `x=${ERROR_CANARY.awsSecret}`,
    `ENV_VALUE=${ERROR_CANARY.awsSecret} was rejected`,
    `key ${ERROR_CANARY.configured} rejected`,
    htmlCanaryPage(),
    jsonCanarySentence(),
  ];
}

test("scrubErrorText handles every shared redaction case and is idempotent", () => {
  assertRedactionCases(assert, scrubErrorText);
  for (const { input } of [...REDACTION_CASES, { input: htmlCanaryBody() }, { input: jsonCanaryMessage() }]) {
    const once = scrubErrorText(input);
    assert.equal(scrubErrorText(once), once, `not idempotent for ${JSON.stringify(input)}`);
    assertNoCanaryValues(once, "scrubbed text");
  }
  assert.equal(scrubErrorText(""), "");
});

test("the random-looking canary set leaves no 6- to 24-character fragment through any surface, with a fixture self-check", () => {
  assertCanaryFixture();
  const carriers = errorCanaryCarriers();
  const secrets = [ERROR_CANARY.configured];
  for (const carrier of carriers) {
    for (const [surface, output] of [
      ["scrubErrorText", scrubErrorText(carrier, { secrets })],
      ["scrubDataText", scrubDataText(carrier, { secrets })],
      ["errorMessage", errorMessage(new Error(carrier), { secrets })],
      ["scrubError", scrubError(new Error("outer", { cause: new Error(carrier) }), { secrets })],
      ["IntegrationError", new IntegrationError(carrier, { endpoint: ERROR_CANARY_URL }, { secrets })],
      ["redactSecretValues", redactSecretValues({ message: carrier, token: carrier, list: [carrier] }, { secrets })],
      ["describeErrorBody text/html", describeErrorBody("text/html", carrier, { secrets })],
      ["describeErrorBody json message", describeErrorBody("application/json", JSON.stringify({ message: carrier }), { secrets })],
      ["describeErrorBody json undocumented", describeErrorBody("application/json", JSON.stringify({ debug: carrier }), { secrets })],
      ["describeErrorBody malformed", describeErrorBody("application/json", carrier, { secrets })],
      ["describeFailedResponse", describeFailedResponse({ method: "GET", endpoint: ERROR_CANARY_URL, status: 502, statusText: carrier, contentType: "text/html", body: carrier }, { secrets })],
    ]) {
      const serialised = output instanceof Error ? { name: output.name, message: output.message, endpoint: output.endpoint, folded: errorMessage(output, { secrets }) } : output;
      assertNoFragments(serialised, Object.values(ERROR_CANARY), { label: `${surface} of ${carrier.slice(0, 40)}` });
    }
  }
  assert.equal(scrubErrorText(`Authorization: Bearer ${ERROR_CANARY.bearer} was rejected`), `Authorization: Bearer ${REDACTED} was rejected`);
  for (const scrub of [scrubErrorText, scrubDataText]) {
    assert.equal(scrub(`x=${ERROR_CANARY.awsSecret}`), `x=${REDACTED}`, "an AWS secret after a non-credential key= is caught by its shape");
    assert.equal(scrub(`ENV_VALUE=${ERROR_CANARY.awsSecret} was rejected`), `ENV_VALUE=${REDACTED} was rejected`);
    assert.equal(scrub(`secret_access_key=${ERROR_CANARY.awsSecret}`), `secret_access_key=${REDACTED}`, "a long credential key keeps its name in front of one marker");
  }
  assert.equal(scrubErrorText(jsonCanarySentence()), `Access denied while fetching https://api.example.com/v1/x?${REDACTED} for the caller; retry after re-authenticating.`);
  assertNoFragment(scrubErrorText(`key ${ENCODED_FORM_SECRET} rejected`, { secrets: [ENCODED_FORM_SECRET] }), ENCODED_FORM_SECRET);
});

test("configured secrets are removed in every encoded form with one marker", () => {
  const forms = [
    CONFIGURED_SECRET,
    Buffer.from(CONFIGURED_SECRET, "utf8").toString("base64"),
    Buffer.from(CONFIGURED_SECRET, "utf8").toString("base64url"),
    encodeURIComponent(CONFIGURED_SECRET),
    JSON.stringify(CONFIGURED_SECRET).slice(1, -1),
  ];
  const text = `rejected: ${forms.join(" / ")} by the proxy`;
  const scrubbed = scrubErrorText(text, { secrets: [CONFIGURED_SECRET, undefined, null, "ab"] });
  for (const form of forms) assert.ok(!scrubbed.includes(form), `${form} survived in "${scrubbed}"`);
  assert.ok(scrubbed.includes(REDACTED));
  assert.ok(!scrubbed.includes("[redacted]"), "the Flue marker must be folded into the shared one");
  assert.ok(scrubbed.startsWith("rejected: "));
  assert.ok(scrubbed.endsWith(" by the proxy"));

  assert.equal(scrubErrorText("cabbage stays", { secrets: ["ab"] }), "cabbage stays", `values shorter than ${MIN_CONFIGURED_SECRET_LENGTH} are not scrubbed`);
  assert.equal(scrubErrorText("passcode 4711 rejected, 47110 stays", { secrets: ["4711"] }), `passcode ${REDACTED} rejected, 47110 stays`);
  assert.equal(scrubErrorText("nothing configured"), "nothing configured");
});

test("PEM blocks and unterminated PEM headers are removed whole", () => {
  const block = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7canaryKEYbody\nsecondLINE0f1t\n-----END RSA PRIVATE KEY-----";
  assert.equal(scrubErrorText(`key ${block} rejected`), `key ${REDACTED} rejected`);
  const open = scrubErrorText("failed: -----BEGIN PRIVATE KEY-----\nMIIEowIBAAKCAQEA7canaryKEYbody and everything after");
  assert.equal(open, `failed: ${REDACTED}`);
});

test("the long-token rule removes bare token runs from error text and leaves identifiers, data text, and codes alone", () => {
  assert.equal(scrubErrorText(`entity ${HEX_DIGEST} not found`), `entity ${REDACTED} not found`);
  assert.equal(scrubErrorText(`entity ${HEX_DIGEST} not found`, { longTokens: false }), `entity ${HEX_DIGEST} not found`);
  assert.equal(scrubDataText(`entity ${HEX_DIGEST} not found`), `entity ${HEX_DIGEST} not found`);

  const identifiers = [
    `policy ${UUID} missing`,
    "code ERR_FS_FILE_TOO_LARGE and BLOCK_AS_IMPLICIT_KEY returned",
    "InvalidAuthenticationTokenProvided by the caller",
    "count 12345678901234567890 exceeded",
    "the Content-Security-Policy-Report-Only header was set",
    "region us-east-1 and stage snake_case_identifier_here",
  ];
  for (const text of identifiers) assert.equal(scrubErrorText(text), text);
  assert.ok(HEX_DIGEST.length >= LONG_TOKEN_MIN_LENGTH);

  const shortRun = `id ${"aB3".repeat(5)} ok`;
  assert.equal(shortRun.length > 0 && "aB3".repeat(5).length < LONG_TOKEN_MIN_LENGTH, true);
  assert.equal(scrubErrorText(shortRun), shortRun, "runs shorter than the minimum are not judged");
});

test("vendor token prefixes are removed even when the long-token rule is off", () => {
  const tokens = [
    "xoxb-1234567890-abcdefghijklmnop",
    "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
    "github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
    "glpat-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "AIzaSyA1234567890abcdefghijklmnopqrstuv",
    "ya29.A0ARrdaM-abcdefghijklmnopqrstuvwxyz",
    "NRAK-ABCDEFGHIJKLMNOP",
    "sk_live_abcdefghijklmnop",
    "SG.abcdefghijklmnopqrst.abcdefghijklmnopqrstuvwxyz",
  ];
  for (const token of tokens) {
    const scrubbed = scrubDataText(`token ${token} rejected`);
    assert.ok(!scrubbed.includes(token), `${token} survived in "${scrubbed}"`);
    assert.equal(scrubbed, `token ${REDACTED} rejected`);
  }
});

test("scheme-carried values are removed whatever their casing or entropy; the prose exemption is one plain word, a lowercase compound, a dotted version, or an auth-param", () => {
  assert.equal(scrubDataText(`Authorization: Bearer ${CANARY.bearer} rejected`), `Authorization: Bearer ${REDACTED} rejected`, "a lowercase word that continues into a token is a token");
  assert.equal(scrubDataText(`proxy replayed Basic ${CANARY.basic}`), `proxy replayed Basic ${REDACTED}`);
  assert.equal(scrubDataText("SSWS 00abcDEF123ghiJKL456 rejected"), `SSWS ${REDACTED} rejected`);
  // Codex P2 (scheme-carried lowercase opaque): under a header carrier the value goes whatever its shape, a plain word included.
  for (const opaque of ["abcdefghijkl", "qwertyuiopasdfghjklzxcvbnm", "token", "abc123", "AbCdEfGh", "x9y8z7"]) {
    for (const scrub of [scrubErrorText, scrubDataText]) {
      assert.equal(scrub(`Authorization: Bearer ${opaque} rejected`), `Authorization: Bearer ${REDACTED} rejected`, `header carrier with ${opaque}`);
      assert.equal(scrub(`"Authorization": "Bearer ${opaque}"`), `"Authorization": "Bearer ${REDACTED}"`, `JSON header carrier with ${opaque}`);
      assert.equal(scrub(`Proxy-Authorization: Basic ${opaque}`), `Proxy-Authorization: Basic ${REDACTED}`, `proxy header carrier with ${opaque}`);
    }
  }
  // In free text the value goes unless it is one of the fixed-text shapes: a digit, a symbol, mixed casing inside a word, or 20 or more letters is never prose.
  for (const opaque of ["abc123", "x9y8z7", "AbCdEfGh", "abcdefghijklmnopqrstu", "abcd_efgh", "abcd.efgh", "dXNlcjpwYXNz", "00abcDEF", "Kq7Zx2Vw9Lm4Tp8R", "12345", "sk-live-9x"]) {
    for (const [scheme, tail] of [["Bearer", " was rejected"], ["Basic", " upstream"], ["Token", " expired"], ["SSWS", " rejected"], ["ApiKey", ""], ["Splunk", "."]]) {
      const text = `replayed ${scheme} ${opaque}${tail}`;
      assert.equal(scrubDataText(text), `replayed ${scheme} ${REDACTED}${tail}`, text);
      assert.equal(scrubErrorText(text), `replayed ${scheme} ${REDACTED}${tail}`, text);
    }
  }
  // The prose exemption, derived from the 121 distinct continuations the integrations' fixed texts put after a scheme word.
  for (const prose of [
    "Basic authentication is disabled for this tenant.",
    "Bearer token-based auth is required",
    "Bearer token authentication is required",
    "the token authentication flow failed",
    "Digest access authentication",
    "third-party OAuth sign-in (codes 1, 11) and Zoom-held passwords",
    "Optional Okta OAuth service-app client ID. Used with PrivateKey auth mode.",
    "the OAuth 2.0 device flow and Splunk Enterprise 9.1.2",
    "Splunk Cloud, Splunk Enterprise, SSWS API tokens, SSWS or OAuth",
    'Bearer realm="api", error="invalid_token", error_description="The access token expired"',
    "Token inventory: 3 of 5 keys have no expiry",
    "Authorization: Bearer",
    "Authorization: Bearer\nnext line starts here",
    "Basic (deprecated) and Basic (full access) modes",
  ]) {
    assert.equal(scrubErrorText(prose), prose);
    assert.equal(scrubDataText(prose), prose);
  }
});

test("credential-named pairs lose any nonempty value whatever its shape, compound and env-style keys included; the one exemption is a word that continues as prose", () => {
  // Codex P2 (credential-labelled pair with a short lowercase word value): guard 1 as written, no shape gate.
  for (const [text, expected] of [
    ["password: hunter2xyz", `password: ${REDACTED}`],
    ["password: hunter", `password: ${REDACTED}`],
    ["token=abcdefgh", `token=${REDACTED}`],
    ["api_key: short", `api_key: ${REDACTED}`],
    ["secret: word.", `secret: ${REDACTED}.`],
    ["the credentials: seen 40 of 120", `the credentials: ${REDACTED} 40 of 120`],
    ['{"password": "correct horse battery staple"}', `{"password": "${REDACTED}"}`],
    ["session_id=abc is stale", `session_id=${REDACTED} is stale`],
    ["sid: x1", `sid: ${REDACTED}`],
    ["passphrase: 'open sesame'", `passphrase: '${REDACTED}'`],
    ["client_secret = s3", `client_secret = ${REDACTED}`],
    ["Api-Key: prod-us-east-2026, env: production", `Api-Key: ${REDACTED}, env: production`],
    ["x-amz-signature=abcdef&x-amz-date=20260922", `x-amz-signature=${REDACTED}&x-amz-date=20260922`],
    [`token=${REDACTED} already scrubbed`, `token=${REDACTED} already scrubbed`],
    ['"token": null, "otp": true', '"token": null, "otp": true'],
    ["token: ", "token: "],
  ]) {
    assert.equal(scrubErrorText(text), expected, text);
    assert.equal(scrubDataText(text), expected, text);
    assert.equal(redactSecretValues(text), expected, text);
  }
  // A compound or env-style key the Flue heuristic classifies is a carrier like the credential words
  // themselves (review of #78, gap 1): the value goes whatever its shape, a human-chosen password
  // included, in every separator and quoting form.
  for (const [text, expected] of [
    ["DB_PASSWORD=hunter2", `DB_PASSWORD=${REDACTED}`],
    ["SPLUNK_PASSWORD=Summer2026!", `SPLUNK_PASSWORD=${REDACTED}`],
    ["admin_password=correcthorsebatterystaple", `admin_password=${REDACTED}`],
    ["GITHUB_TOKEN=letmein2024", `GITHUB_TOKEN=${REDACTED}`],
    ["client_token=voxkqrrijhpp", `client_token=${REDACTED}`],
    ["ZIA_PASSWORD=changeme", `ZIA_PASSWORD=${REDACTED}`],
    ["DB_PASSWORD: P@ssw0rd", `DB_PASSWORD: ${REDACTED}`],
    ["DB_PASSWORD=abc12", `DB_PASSWORD=${REDACTED}`],
    ['{"client_token":"letmein2024"}', `{"client_token":"${REDACTED}"}`],
    ['{"client_token":"expired"}', `{"client_token":"${REDACTED}"}`],
    ['\\"clientToken\\": \\"hunter2\\"', `\\"clientToken\\": \\"${REDACTED}\\"`],
    ["client-token='changeme'", `client-token='${REDACTED}'`],
    ["client_token: expired", `client_token: ${REDACTED}`],
    ["client_token: expired.", `client_token: ${REDACTED}.`],
    ["client_token: expired, retry later", `client_token: ${REDACTED}, retry later`],
    ["client_token=expired and more", `client_token=${REDACTED} and more`],
    ["environment-token: present", `environment-token: ${REDACTED}`],
    ["settings.token: enabled", `settings.token: ${REDACTED}`],
    ["secrets: truncated", `secrets: ${REDACTED}`],
    ["x-auth-mode: legacy", `x-auth-mode: ${REDACTED}`],
    ["client_token: Bearer abcdef", `client_token: Bearer ${REDACTED}`],
    ["client_token: Kq7Zx2Vw9Lm4Tp8R rejected", `client_token: ${REDACTED} rejected`],
    ["user_session: 0f9e8d7c6b5a4938 rejected", `user_session: ${REDACTED} rejected`],
    ["access_tokens: dGhpcyBpcyBh== rejected", `access_tokens: ${REDACTED} rejected`],
    ["X-Vendor-Auth: a1b2c3d4e5f6 rejected", `X-Vendor-Auth: ${REDACTED} rejected`],
    // The shapes main's rule at 02967cc redacted (a digit, a symbol, a case change, twelve characters) go here too.
    ["client_token: LaunchDarkly request failed", `client_token: ${REDACTED} request failed`],
    ["Authorization_RequestDenied: Insufficient privileges to complete the operation.", `Authorization_RequestDenied: ${REDACTED} privileges to complete the operation.`],
    ["client_token: expired2 now", `client_token: ${REDACTED} now`],
    ["client_token: OPENSESAME now", `client_token: ${REDACTED} now`],
  ]) {
    assert.equal(scrubErrorText(text), expected, text);
    assert.equal(scrubDataText(text), expected, text);
    assert.equal(redactSecretValues(text), expected, text);
  }
  // The one exemption: after `Key: `, one plain word (or a count under six digits) that another word,
  // number, or parenthesis follows on the same line is prose. Its shape is no wider than main's at
  // 02967cc (under six characters, or letters only under twelve with no case change inside the
  // word); the continuation requirement is new. Each exempted phrase is pinned again in
  // hardening-fixed-text.test.mjs.
  for (const prose of [
    "InvalidAuthenticationToken: Access token has expired.",
    "TokenExpired: The token has expired",
    "access_tokens: seen 40 of 120",
    "tokens: 3 of 5 rotated",
    "tokens: none are stale",
    "user_session: 3 active sessions",
    "token_type: Bearer token expected",
    "secrets: unreadable (GET /v1/secrets failed with 403 Forbidden)",
    "secrets: not collected",
    "sdk-keys: 3 of 5 rotated",
    "DB_PASSWORD: admin was rejected",
  ]) {
    assert.equal(scrubErrorText(prose), prose);
    assert.equal(scrubDataText(prose), prose);
  }
  // A scheme word standing alone after such a key is the whole value and stays (`token_type: Bearer`).
  for (const text of ["token_type: Bearer", '{"access_token":"abc","token_type":"Bearer","expires_in":3600}', "X-Token-Type: Bearer"]) {
    assert.equal(scrubErrorText(text), text.replace('"abc"', `"${REDACTED}"`), text);
  }
  // A credential word inside a longer name, a path, or a dotted key is not one of the credential words
  // (`NAME_START`), so the explicit pair rule leaves it to the generic rule, whose value is a status
  // line here; a credential word after an article is the explicit pair.
  for (const [text, expected] of [
    ["GET /_security/api_key: 403 Forbidden", "GET /_security/api_key: 403 Forbidden"],
    ["the token: yes, but not this one", `the token: ${REDACTED}, but not this one`],
  ]) {
    assert.equal(scrubErrorText(text), expected, text);
  }
});

test("URL scrubbing is idempotent for query-only, fragment-only, and mixed URLs, and every entry point is idempotent over the carrier corpus", () => {
  // Codex finding: a fragment-only URL came back as `#[REDACTED][REDACTED]` on a second pass.
  for (const [text, expected] of [
    ["see https://docs.example.com/guide#section-2 for details", `see https://docs.example.com/guide#${REDACTED} for details`],
    ["see https://api.example.com/v1/x?page=2#top.", `see https://api.example.com/v1/x?${REDACTED}#${REDACTED}.`],
    [`see https://api.example.com/v1/x?${REDACTED}#${REDACTED} for details`, `see https://api.example.com/v1/x?${REDACTED}#${REDACTED} for details`],
    [`see https://api.example.com/v1/x#${REDACTED}`, `see https://api.example.com/v1/x#${REDACTED}`],
    ['{"url":"https://api.example.com/v1/x?token=abc#frag"}', `{"url":"https://api.example.com/v1/x?${REDACTED}#${REDACTED}"}`],
    ['"url":"https://api.example.com/v1/x?token=abc\\"}', `"url":"https://api.example.com/v1/x?${REDACTED}\\"}`],
  ]) {
    for (const scrub of [scrubErrorText, scrubDataText]) {
      const once = scrub(text);
      assert.equal(once, expected, text);
      assert.equal(scrub(once), once, `second pass changed ${JSON.stringify(once)}`);
    }
  }
  const corpus = [
    ...REDACTION_CASES.map(({ input }) => input),
    ...errorCanaryCarriers(),
    ...["prod-us-east-2026", ERROR_CANARY.bearer].flatMap((value) => carrierCases(value).map(([, input]) => input)),
    "see https://docs.example.com/guide#section-2 and https://h.example/p?x=1#y",
    `Set-Cookie: sid="${ERROR_CANARY.sessionCookie}"; Path=/; HttpOnly`,
    `{"headers":{"Authorization":"Bearer ${ERROR_CANARY.bearer}","X-Api-Key":"${ERROR_CANARY.apiKey}"}}`,
    "-----BEGIN PRIVATE KEY-----\nMIIEowIBAAKCAQEA7canaryKEYbody\n-----END PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----\nMIIEowIBAAKCAQEA7canaryKEYbody unterminated",
  ];
  const secrets = [ERROR_CANARY.configured];
  const entryPoints = [
    ["scrubErrorText", (text) => scrubErrorText(text, { secrets })],
    ["scrubDataText", (text) => scrubDataText(text, { secrets })],
    ["errorMessage", (text) => errorMessage(new Error(text), { secrets })],
    ["scrubError", (text) => scrubError(new Error(text), { secrets }).message],
    ["IntegrationError", (text) => new IntegrationError(text, {}, { secrets }).message],
    ["redactSecretValues", (text) => redactSecretValues(text, { secrets })],
    ["describeErrorBody", (text) => describeErrorBody("application/json", JSON.stringify({ message: text }), { secrets })],
  ];
  for (const text of corpus) {
    for (const [name, scrub] of entryPoints) {
      const once = scrub(text);
      assert.equal(scrub(once), once, `${name} is not idempotent for ${JSON.stringify(text)}: ${JSON.stringify(once)}`);
      assert.equal(scrub(scrub(once)), once, `${name} is not idempotent on the third pass for ${JSON.stringify(text)}`);
      // Normal composition scrubs twice (a body note inside a response line): every output is a fixed point of both text scrubs.
      assert.equal(scrubErrorText(once, { secrets }), once, `${name}: scrubErrorText changed its output for ${JSON.stringify(text)}`);
      assert.equal(scrubDataText(once, { secrets }), once, `${name}: scrubDataText changed its output for ${JSON.stringify(text)}`);
    }
  }
  // describeFailedResponse composes describeErrorBody and scrubErrorText: describing a line it already
  // produced adds only the fixed prefix, and the line is a fixed point of both text scrubs.
  const prefix = "GET /v1/users failed with 502 Bad Gateway: ";
  const describe = (text) =>
    describeFailedResponse({ method: "GET", endpoint: "/v1/users", status: 502, statusText: "Bad Gateway", contentType: "application/json", body: JSON.stringify({ message: text }) }, { secrets });
  for (const text of corpus) {
    const once = describe(text);
    assert.ok(once.startsWith(prefix), `describeFailedResponse for ${JSON.stringify(text)}: ${once}`);
    const asMessage = once.length <= MAX_VENDOR_MESSAGE_LENGTH ? once : `${once.slice(0, MAX_VENDOR_MESSAGE_LENGTH)} [truncated]`;
    assert.equal(describe(once), `${prefix}${asMessage}`, `describeFailedResponse changed its own output for ${JSON.stringify(text)}`);
    assert.equal(scrubErrorText(once, { secrets }), once, `describeFailedResponse: scrubErrorText changed its output for ${JSON.stringify(text)}`);
    assert.equal(scrubDataText(once, { secrets }), once, `describeFailedResponse: scrubDataText changed its output for ${JSON.stringify(text)}`);
  }
});

test("scrubError reads every property under a guard, so a throwing getter, a hostile Proxy, or a revoked Proxy cannot replace the failure being recorded", () => {
  const trap = () => {
    throw new Error(`trap fired with ${CANARY.bearer}`);
  };
  const hostile = new Proxy({}, { get: trap, has: trap, ownKeys: trap, getOwnPropertyDescriptor: trap, getPrototypeOf: trap });
  assert.deepEqual(scrubError(hostile), { name: "Error", message: "Error without a message" });
  assert.equal(errorMessage(hostile), "Error without a message");

  class ThrowingAccessors extends Error {
    name = "ThrowingAccessors";
    get code() {
      return trap();
    }
    get status() {
      return trap();
    }
    get cause() {
      return trap();
    }
    get errors() {
      return trap();
    }
    get response() {
      return trap();
    }
    get request() {
      return trap();
    }
    get endpoint() {
      return trap();
    }
  }
  const accessors = new ThrowingAccessors(`request failed: Authorization: Bearer ${CANARY.bearer}`);
  assert.deepEqual(scrubError(accessors), { name: "ThrowingAccessors", message: `request failed: Authorization: Bearer ${REDACTED}` });

  const throwingName = Object.create(Error.prototype, { name: { get: trap }, message: { value: "named badly", enumerable: true } });
  assert.deepEqual(scrubError(throwingName), { name: "Error", message: "named badly" });

  const membersProxy = new Proxy([new Error("member one")], { get: (target, key) => (key === "length" ? trap() : target[key]) });
  assert.deepEqual(scrubError({ message: "aggregate", errors: membersProxy }), { name: "Error", message: "aggregate" });
  const memberTrap = new Proxy([new Error("member one")], { get: (target, key) => (key === "0" ? trap() : target[key]) });
  assert.deepEqual(scrubError({ message: "aggregate", errors: memberTrap }), { name: "Error", message: "aggregate" });

  const { proxy: revoked, revoke } = Proxy.revocable({ message: "gone" }, {});
  revoke();
  assert.deepEqual(scrubError(revoked), { name: "Error", message: "Error without a message" });
  assert.deepEqual(scrubError({ message: "outer", cause: revoked, $metadata: revoked, request: revoked, errors: revoked }), { name: "Error", message: "outer (cause: Error without a message)" });

  const folded = new IntegrationError("collector failed", { cause: hostile, status: 502 });
  assert.equal(folded.message, "collector failed");
  assert.equal(errorMessage(folded), "collector failed (cause: Error without a message)");
  for (const value of [hostile, accessors, throwingName, revoked]) assertNoCanaryValues(scrubError(value), "hostile thrown value");
});

test("URLs keep scheme, host, and path and lose userinfo, query, and fragment; bare query pairs keep their names", () => {
  assert.equal(
    scrubErrorText(`see https://alice:${CANARY.sessionCookie}@host.example/path/x?token=${CANARY.urlToken}#frag.`),
    `see https://host.example/path/x?${REDACTED}#${REDACTED}.`,
  );
  assert.equal(scrubErrorText("GET /v1/users?api_key=abcdef123456&page=2&sig=zzzz9999 failed"), `GET /v1/users?api_key=${REDACTED}&page=2&sig=${REDACTED} failed`);
  assert.equal(scrubErrorText("open https://docs.example.com/guide/setup for details"), "open https://docs.example.com/guide/setup for details");
});

test("describeErrorBody never echoes a body and keeps only documented message fields", () => {
  const html = describeErrorBody("text/html; charset=utf-8", htmlCanaryBody());
  assert.match(html, HTML_BODY_NOTE);
  assert.ok(!html.includes("<html"));
  assertNoCanaryValues(html, "html body note");

  const json = describeErrorBody("application/json", JSON.stringify({ message: jsonCanaryMessage() }));
  assert.match(json, REDACTED_CANARY_URL);
  assert.ok(json.includes("Access denied while fetching"));
  assertNoCanaryValues(json, "json message");

  const undocumented = describeErrorBody("application/json", JSON.stringify({ debug: CANARY.bearer, trace: { token: CANARY.apiKey } }));
  assert.match(undocumented, /^JSON body without a documented message field \(\d+ bytes\)$/);
  assertNoCanaryValues(undocumented, "undocumented json fields");

  assert.equal(describeErrorBody("application/json", `<html>${CANARY.bearer}</html>`), `malformed JSON body (application/json, ${13 + CANARY.bearer.length} bytes)`);
  assert.equal(describeErrorBody("application/json", ""), "empty body");
  assert.equal(describeErrorBody(null, "plain text with Bearer " + CANARY.bearer), `non-JSON body (unknown, ${23 + CANARY.bearer.length} bytes)`);
  assert.equal(describeErrorBody("text/plain", "denied"), "non-JSON body (text/plain, 6 bytes)");

  assert.equal(describeErrorBody("application/problem+json", JSON.stringify({ title: "Forbidden", detail: `Token ${CANARY.jwt} expired` })), `Forbidden; Token ${REDACTED} expired`);
  assert.equal(describeErrorBody("text/json", JSON.stringify({ error: { message: "outer", errors: [{ message: "inner" }, "second"] } })), "outer; inner; second");
  assert.equal(describeErrorBody("application/json", JSON.stringify({ error: "invalid_client", error_description: "bad secret" })), "bad secret; invalid_client");
  assert.equal(describeErrorBody("application/json", JSON.stringify({ errorCauses: [{ errorSummary: "cause one" }], errorSummary: "top" })), "top; cause one");
  assert.equal(describeErrorBody("application/json", JSON.stringify([{ message: "array root" }])), "JSON body without a documented message field (26 bytes)");

  const long = describeErrorBody("application/json", JSON.stringify({ message: "m".repeat(MAX_VENDOR_MESSAGE_LENGTH + 50) }));
  assert.ok(long.startsWith("m".repeat(MAX_VENDOR_MESSAGE_LENGTH)));
  assert.ok(long.endsWith(" [truncated]"));
  assert.equal(long.length, MAX_VENDOR_MESSAGE_LENGTH + " [truncated]".length);

  const configured = describeErrorBody("application/json", JSON.stringify({ message: `key ${CONFIGURED_SECRET} rejected` }), { secrets: [CONFIGURED_SECRET] });
  assert.equal(configured, `key ${REDACTED} rejected`);
});

test("describeFailedResponse builds the standard line from validated parts", () => {
  const line = describeFailedResponse({
    method: "GET",
    endpoint: `/v1/users?token=${CANARY.urlToken}&page=2`,
    status: 502,
    statusText: "Bad Gateway",
    contentType: "text/html",
    body: htmlCanaryBody(),
  });
  assert.match(line, /^GET \/v1\/users\?token=\[REDACTED\]&page=2 failed with 502 Bad Gateway: non-JSON body \(text\/html, \d+ bytes\)$/);
  assertNoCanaryValues(line, "failed response line");

  const odd = describeFailedResponse({ method: "get", endpoint: "/x", status: 999, statusText: "<script>alert(1)</script>", contentType: "application/json", body: "" });
  assert.equal(odd, "Request /x failed with unknown status: empty body");
  assert.equal(describeFailedResponse({ method: "POST", endpoint: "/y", status: 401, body: "{}", contentType: "application/json" }), "POST /y failed with 401: JSON body without a documented message field (2 bytes)");
});

test("scrubError reduces thrown values to fixed fields and reads no body or toString", () => {
  const nested = new Error("request failed", { cause: new Error(`Authorization: Bearer ${CANARY.bearer} rejected`) });
  const scrubbed = scrubError(nested);
  assert.deepEqual(scrubbed, { name: "Error", message: `request failed (cause: Authorization: Bearer ${REDACTED} rejected)` });

  const awsShaped = {
    name: "AccessDeniedException",
    message: "denied",
    $metadata: { httpStatusCode: 403 },
    $responseBodyText: `{"token":"${CANARY.apiKey}"}`,
    toString() {
      return CANARY.sessionCookie;
    },
  };
  assert.deepEqual(scrubError(awsShaped), { name: "AccessDeniedException", message: "denied", status: 403 });

  const withRequest = { code: 404, statusCode: 404, message: "missing", request: { url: CANARY_URL } };
  assert.deepEqual(scrubError(withRequest), { name: "Error", message: "missing", code: "404", status: 404, endpoint: "https://api.example.com/v1/x?[REDACTED]" });

  const members = Array.from({ length: 5 }, (_, index) => Object.assign(new Error(`member ${index} Bearer ${CANARY.bearer}`), { code: index === 2 ? "E0000011" : "not a code!" }));
  const aggregate = scrubError(new AggregateError(members, "several"));
  assert.equal(aggregate.message, `several (5 errors: member 0 Bearer ${REDACTED}; member 1 Bearer ${REDACTED}; member 2 Bearer ${REDACTED}; and 2 more)`);
  assert.equal(aggregate.code, "E0000011");
  assert.equal(aggregate.name, "AggregateError");

  const loop = new Error("loop");
  loop.cause = loop;
  assert.equal(scrubError(loop).message, "loop (cause: cause chain truncated)");

  assert.deepEqual(scrubError(`Basic ${CANARY.basic}`), { name: "Error", message: `Basic ${REDACTED}` });
  assert.deepEqual(scrubError(null), { name: "Error", message: "unknown error" });
  assert.deepEqual(scrubError(undefined), { name: "Error", message: "unknown error" });
  assert.deepEqual(scrubError(42), { name: "Error", message: "42" });
  assert.deepEqual(scrubError({ name: "Weird Name!", message: 7 }), { name: "Error", message: "Error without a message" });
  assert.deepEqual(scrubError({ error: "invalid_grant", error_description: "ignored when error is a string" }), { name: "Error", message: "invalid_grant" });
  assert.equal(scrubError({ message: "x", endpoint: "/v".repeat(400) }).endpoint, undefined, "an overlong endpoint is dropped");

  const long = scrubError(new Error("x".repeat(MAX_ERROR_MESSAGE_LENGTH + 100)));
  assert.equal(long.message.length, MAX_ERROR_MESSAGE_LENGTH + " [truncated]".length);

  for (const value of [nested, awsShaped, withRequest, aggregate]) assertNoCanaryValues(scrubError(value), "scrubError output");
});

test("errorMessage is the one-line form", () => {
  assert.equal(errorMessage(new Error("first line\n\n   second\tline")), "first line second line");
  assert.equal(errorMessage(new Error("outer", { cause: `token ${CANARY.jwt}` })), `outer (cause: token ${REDACTED})`);
  assert.equal(errorMessage(`key ${CONFIGURED_SECRET} rejected`, { secrets: [CONFIGURED_SECRET] }), `key ${REDACTED} rejected`);
});

test("IntegrationError scrubs its own message and validates its fields; subclasses keep their name", () => {
  class DemoApiError extends IntegrationError {}
  const cause = new Error(`Basic ${CANARY.basic} rejected`);
  const error = new DemoApiError(`GET failed: Authorization: Bearer ${CANARY.bearer} rejected`, { status: 401, endpoint: CANARY_URL, code: "E0000011", cause });

  assert.ok(error instanceof Error);
  assert.ok(error instanceof IntegrationError);
  assert.ok(error instanceof DemoApiError);
  assert.equal(error.name, "DemoApiError");
  assert.equal(error.message, `GET failed: Authorization: Bearer ${REDACTED} rejected`);
  assert.equal(error.status, 401);
  assert.match(error.endpoint, REDACTED_CANARY_URL);
  assert.equal(error.code, "E0000011");
  assert.equal(error.cause, cause);
  assert.equal(errorMessage(error), `GET failed: Authorization: Bearer ${REDACTED} rejected (cause: Basic ${REDACTED} rejected)`);
  assertNoCanaryValues({ message: error.message, endpoint: error.endpoint, folded: errorMessage(error), scrubbed: scrubError(error) }, "IntegrationError");

  const bare = new IntegrationError(`key ${CONFIGURED_SECRET} rejected`, { status: 600, code: "has spaces in it" }, { secrets: [CONFIGURED_SECRET] });
  assert.equal(bare.name, "IntegrationError");
  assert.equal(bare.message, `key ${REDACTED} rejected`);
  assert.equal(bare.status, undefined);
  assert.equal(bare.code, undefined);
  assert.equal(bare.endpoint, undefined);
  assert.equal(bare.cause, undefined);
  assert.deepEqual(scrubError(bare), { name: "IntegrationError", message: `key ${REDACTED} rejected` });
});

test("redactSecretValues replaces credential entries, scrubs strings as data, and copies without mutating", () => {
  const input = {
    user: "alice",
    password: "pw-123456",
    nested: { api_key: "k", flags: { password_required: true, token: null, secret: undefined } },
    list: [{ client_secret: "s" }, `Bearer ${CANARY.bearer}`, 3],
    hash: HEX_DIGEST,
    when: new Date(0),
    passwordPolicy: { minLength: 8 },
  };
  const snapshot = JSON.stringify(input);
  const output = redactSecretValues(input);
  assert.equal(JSON.stringify(input), snapshot, "input must not be mutated");
  assert.notEqual(output, input);
  assert.equal(output.user, "alice");
  assert.equal(output.password, REDACTED);
  assert.equal(output.nested.api_key, REDACTED);
  assert.equal(output.nested.flags.password_required, true);
  assert.equal(output.nested.flags.token, null);
  assert.equal(output.nested.flags.secret, undefined);
  assert.equal(output.list[0].client_secret, REDACTED);
  assert.equal(output.list[1], `Bearer ${REDACTED}`);
  assert.equal(output.list[2], 3);
  assert.equal(output.hash, HEX_DIGEST, "data values keep opaque identifiers");
  assert.equal(output.when, input.when, "non-plain objects are returned as they are");
  assert.equal(output.passwordPolicy, REDACTED);

  const preserved = redactSecretValues(input, { preserveKey: (key) => key === "passwordPolicy" });
  assert.deepEqual(preserved.passwordPolicy, { minLength: 8 });
  assert.equal(preserved.password, REDACTED);

  assert.equal(redactSecretValues(`x ${HEX_DIGEST}`), `x ${HEX_DIGEST}`);
  assert.equal(redactSecretValues(`x ${CANARY.jwt}`), `x ${REDACTED}`);
  assert.deepEqual(redactSecretValues([`token=${CANARY.apiKey}`]), [`token=${REDACTED}`]);
  assert.equal(redactSecretValues(7), 7);
  assert.equal(redactSecretValues(null), null);
  assertNoCanaryValues(output, "redacted record");
});

test("isCredentialKey covers the Flue heuristic plus bare and signed-URL names", () => {
  for (const key of ["token", "client_secret", "Authorization", "x-api-key", "sid", "sig", "X-Amz-Signature", "Proxy-Authorization", "session", "oauth_token", "pwd", "sessid", "cookie", "private_key"]) {
    assert.ok(isCredentialKey(key), `${key} names a credential`);
  }
  for (const key of ["username", "max_tokens", "token_limit", "keyword", "page", "region", "credentials_file", "session_count", "monkey", "signal"]) {
    assert.ok(!isCredentialKey(key), `${key} does not name a credential`);
  }
});

test("mediaTypeOf lowercases and strips parameters, and answers unknown for anything malformed", () => {
  assert.equal(mediaTypeOf("Application/JSON; charset=utf-8"), "application/json");
  assert.equal(mediaTypeOf("application/problem+json"), "application/problem+json");
  assert.equal(mediaTypeOf(null), "unknown");
  assert.equal(mediaTypeOf(undefined), "unknown");
  assert.equal(mediaTypeOf(""), "unknown");
  assert.equal(mediaTypeOf("nonsense"), "unknown");
  assert.equal(mediaTypeOf("text/html <script>"), "unknown");
});
