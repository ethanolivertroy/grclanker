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
  htmlCanaryBody,
  jsonCanaryMessage,
} from "./helpers/error-canaries.mjs";

const HEX_DIGEST = "4f3a9c1b7e2d8f6a0b5c4d3e2f1a0b9c";
const UUID = "123e4567-e89b-12d3-a456-426614174000";
const CONFIGURED_SECRET = "s3cr3t-Value-With-Case-42";

function assertNoCanaryValues(value, label) {
  assertNoCanaries(assert, value, label);
  const text = typeof value === "string" ? value : JSON.stringify(value);
  for (const canary of [CANARY.basic, CANARY.jwt, CANARY.awsAccessKeyId, CANARY.awsSecret]) {
    assert.ok(!text.includes(canary), `${label}: canary ${canary} leaked`);
  }
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

test("authorization scheme values are removed unless the value is one plain lowercase word", () => {
  assert.equal(scrubDataText(`Authorization: Bearer ${CANARY.bearer} rejected`), `Authorization: Bearer ${REDACTED} rejected`, "a lowercase word that continues into a token is a token");
  assert.equal(scrubDataText(`proxy replayed Basic ${CANARY.basic}`), `proxy replayed Basic ${REDACTED}`);
  assert.equal(scrubDataText("SSWS 00abcDEF123ghiJKL456 rejected"), `SSWS ${REDACTED} rejected`);
  for (const prose of ["Basic authentication is disabled for this tenant.", "Bearer token-based auth is required", "the token authentication flow failed", "Digest access authentication"]) {
    assert.equal(scrubErrorText(prose), prose);
  }
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
