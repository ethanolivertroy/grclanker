/**
 * The two boundary guards of the coordinator's addendum 7 ruling, as the independent review of #67
 * measured them (check 11 at 3ae4f7f: 29,368 carrier trials and 6,220 configured-secret trials with
 * zero leaks), ported so every later change to the scrub is measured the same way.
 *
 * Guard 1: any value inside a carrier is removed whatever its shape. Every canary the batch 1 and
 * batch 2 sweeps plant, the vendor token shapes, the digest, base64, and PEM shapes, and the
 * name-shaped values the must-keep table protects when bare ride in every carrier (header, scheme,
 * cookie, URL userinfo and query, bare query pair, credential pair in prose and JSON) through every
 * sink (both text scrubs, scrubError over a message, a vendor `error` field, an `error_description`,
 * and a cause, errorMessage, IntegrationError and a subclass, redactSecretValues over an object, and
 * the endpoint sinks) and no 6-to-24 window survives.
 *
 * Guard 2: a configured secret is removed whatever its shape, in every encoded form (plain, base64,
 * base64url, URL-encoded, JSON-escaped, and a reflowed PEM), bare, embedded inside a longer token, and
 * inside the carriers, down to MIN_CONFIGURED_SECRET_LENGTH; a shorter secret is ignored, as documented.
 *
 * Bare values are the ruled behaviour, not a guard: a real token shape must go bare under the error-text
 * sinks; a name-shaped value may stay bare, which the must-keep table asserts.
 */
import test from "node:test";
import assert from "node:assert/strict";

import {
  IntegrationError,
  MIN_CONFIGURED_SECRET_LENGTH,
  errorMessage,
  redactSecretValues,
  scrubDataText,
  scrubError,
  scrubErrorText,
} from "../dist/extensions/grc-tools/hardening/error-text.js";
import { CANARY as GROUP_D_CANARY } from "./helpers/error-canaries.mjs";
import { CONFIG_CANARY, ENCODED_FORM_SECRET, ERROR_CANARY, fragmentsOf } from "./helpers/hardening-canaries.mjs";

const PEM = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCq7Zx1Vb3Nm5Kp\nRt9Ws2Yu4Io6Pa8Sd0Fg1Hj3Kl5Zx7Cv9Bn2Mq4We6Rt8Yu0Io2Pa4Sd6Fg8Hj0K\n-----END PRIVATE KEY-----";

/** Whether a value must go bare under the error-text sinks (`token`), may stay bare (`name`), or is under the 16-character floor (`short`). */
function bareExpectation(value) {
  return /^[A-Za-z]+(?:[-_][A-Za-z]+)*[-_]\d+$/.test(value) ? "name" : value.length >= 16 ? "token" : "short";
}

/** name: [value, bare expectation]. */
const CANARIES = Object.freeze({
  ...Object.fromEntries(Object.entries(GROUP_D_CANARY).map(([key, value]) => [`groupD_${key}`, [value, bareExpectation(value)]])),
  nameShaped_sessionCookie: ["sess-canary-COOKIE-31415926535897", "name"],
  nameShaped_apiKey: ["ak_canary_APIKEY_2718281828459045", "name"],
  nameShaped_urlToken: ["CANARY-url-token-1618033988749", "name"],
  ...Object.fromEntries(Object.entries(ERROR_CANARY).map(([key, value]) => [`errorCanary_${key}`, [value, "token"]])),
  ...Object.fromEntries(Object.entries(CONFIG_CANARY).map(([key, value]) => [`configCanary_${key}`, [value, value.length >= 16 ? "token" : "short"]])),
  zscaler_webex_apiKey: ["TOKCANARYqz8m2v4x7k1p3w5n9r", "token"],
  zscaler_webex_bearer: ["BRCANARYh6j2f8d4s0a1g3l5", "token"],
  zscaler_webex_alias: ["ALCANARYu3y7e1t9r5w", "token"],
  webex_zoom_json: ["JSCANARYb2n4m6v8c0x1z3l5k7", "token"],
  zoom_clientId: ["IDCANARYe9f8g7h6j5k4l3m2", "token"],
  zoom_short: ["SHCANARY4x2", "short"],
  zoom_bearer: ["CANARY-BEARER-7f3a9c1d", "token"],
  slack_session5: ["CANARY-SESSION-5", "name"],
  slack_apikey2: ["CANARY-APIKEY-2", "short"],
  slack_urltoken2: ["CANARY-URLTOKEN-2", "name"],
  slack_xoxp_config: ["xoxp-CANARY-CONFIG-1", "token"],
  qualys_platform: ["qk_live_LEAKPLATFORMCANARY7f3a9c1d", "token"],
  github_keyBody: ["LEAKKEYBODYCANARY0123456789abcdef", "name"],
  github_bearer: ["LEAKBEARERCANARY9876543210fedcba", "name"],
  gcp_bearer: ["ya29.a0CANARYBEARER7f3a9c1d7f3a9c1d7f3a9c1d", "token"],
  gcp_session: ["CANARYSESSION7f3a9c1d7f3a9c1d", "token"],
  gcp_apiKey: ["AIzaSyCANARYAPIKEY7f3a9c1d000000000000", "token"],
  gcp_urlToken: ["CANARYURLTOKEN7f3a9c1d7f3a9c1d", "token"],
  gcp_clientSecret: ["GOCSPX-CANARYCLIENTSECRET7f3a9c1d", "token"],
  gcp_refreshToken: ["1//0gCANARYREFRESH7f3a9c1d-7f3a9c1d", "token"],
  newrelic_key: ["NRAK-LEAKCANARY1234567890ABCDEF", "token"],
  newrelic_bearer: ["LEAKBEARERCANARY7f3a9c1d2e4b", "token"],
  newrelic_apiKey: ["CANARYAPIKEY7f3a9c1d", "token"],
  newrelic_idToken: ["CANARYIDTOKEN7f3a9c1d", "token"],
  newrelic_secret: ["CANARYSECRET7f3a9c1d", "token"],
  vendor_slack_xoxb: ["xoxb-1234567890-Ab3Cd5Ef7Gh9Ij1Kl3Mn5", "token"],
  vendor_github_ghp: ["ghp_Ab3Cd5Ef7Gh9Ij1Kl3Mn5Op7Qr9St1Uv3Wx5", "token"],
  vendor_github_pat: ["github_pat_11ABCDEFG0Ab3Cd5Ef7Gh9Ij1Kl3Mn5Op7", "token"],
  vendor_gitlab: ["glpat-Zx9Cv7Bn5Mq3We1Rt8Yu6Io", "token"],
  vendor_google_aiza: ["AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q", "token"],
  vendor_google_ya29: ["ya29.a0AfH6SMBx1Yz2Wv3Ut4Sr5Qp6On7Ml8Kj", "token"],
  vendor_newrelic: ["NRAK-ABC123DEF456GHI789JKL", "token"],
  vendor_stripe: ["sk_live_Ab3Cd5Ef7Gh9Ij1Kl3Mn5Op", "token"],
  vendor_sendgrid: ["SG.Ab3Cd5Ef7Gh9Ij1Kl3Mn5Op7.Qr9St1Uv3Wx5Yz7Ab9Cd1Ef3", "token"],
  shape_hexDigest: ["0f9e8d7c6b5a49382716a5b4c3d2e1f0", "token"],
  shape_sha256: ["9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "token"],
  shape_base64: ["Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA==", "token"],
  shape_scatteredDigits: ["Kq7Zx2Vw9Lm4Tp8Rn3Yb6", "token"],
  shape_tokenCasing: ["bPxRfiCYcanaryKEYqWeRtY", "token"],
  shape_pem: [PEM, "token"],
});

/** Guard 1 carriers; each embeds the value mid-sentence. */
const CARRIERS = Object.freeze({
  authBearer: (v) => `upstream said Authorization: Bearer ${v} was rejected while replaying`,
  authBasic: (v) => `upstream said Authorization: Basic ${v} was rejected while replaying`,
  authSSWS: (v) => `upstream said Authorization: SSWS ${v} was rejected while replaying`,
  authToken: (v) => `upstream said Authorization: Token ${v} was rejected while replaying`,
  authApiKey: (v) => `upstream said Authorization: ApiKey ${v} was rejected while replaying`,
  schemeBearer: (v) => `the proxy replayed Bearer ${v} and failed`,
  schemeBasic: (v) => `the proxy replayed Basic ${v} and failed`,
  schemeSSWS: (v) => `the proxy replayed SSWS ${v} and failed`,
  schemeToken: (v) => `the proxy replayed Token ${v} and failed`,
  schemeApiKey: (v) => `the proxy replayed ApiKey ${v} and failed`,
  cookieHeaderPair: (v) => `Cookie: session=${v}; other=1 was sent`,
  cookieHeaderWhole: (v) => `Cookie: ${v} was sent`,
  setCookie: (v) => `Set-Cookie: session=${v}; Path=/; HttpOnly was echoed`,
  setCookieNamed: (v) => `Set-Cookie: JSESSIONID=${v}; Secure was echoed`,
  xApiKey: (v) => `header x-api-key: ${v} rejected`,
  xApiKeyCased: (v) => `header X-Api-Key: ${v} rejected`,
  xAuthToken: (v) => `header X-Auth-Token: ${v} rejected`,
  apiKeyHeader: (v) => `header Api-Key: ${v} rejected`,
  amzSecurityToken: (v) => `header X-Amz-Security-Token: ${v} rejected`,
  proxyAuthorization: (v) => `header Proxy-Authorization: ${v} rejected`,
  sessionAssign: (v) => `login returned session=${v} for the caller`,
  sessidAssign: (v) => `login returned sessid=${v} for the caller`,
  sidAssign: (v) => `login returned sid=${v} for the caller`,
  cookieAssign: (v) => `login returned cookie=${v} for the caller`,
  sessionColon: (v) => `login returned session: ${v} for the caller`,
  urlUserinfoPassword: (v) => `see https://user:${v}@api.example.com/v1/y for details`,
  urlUserinfoBare: (v) => `see https://${v}@api.example.com/v1/y for details`,
  urlQueryToken: (v) => `see https://api.example.com/v1/x?token=${v} for details`,
  urlQueryApiKeyMid: (v) => `see https://api.example.com/v1/x?page=2&api_key=${v}&limit=5 for details`,
  urlQuerySig: (v) => `see https://storage.example.com/o/x?sig=${v} for details`,
  urlQueryAccessToken: (v) => `redirected to https://example.invalid/cb?access_token=${v}&state=x.`,
  bareQueryToken: (v) => `request /v1/items?token=${v}&limit=5 failed`,
  bareQueryPassword: (v) => `request /login?user=bob&password=${v} failed`,
  pairApiKeyEq: (v) => `retry with api_key=${v} later`,
  pairPasswordColon: (v) => `config password: ${v} rejected`,
  pairSecretJson: (v) => `body {"secret":"${v}","status":403} rejected`,
  pairClientSecretEq: (v) => `client_secret=${v} rejected`,
  pairAccessTokenColon: (v) => `access_token: ${v} expired`,
  pairApiKeyCamel: (v) => `apiKey: ${v} rejected`,
  pairTokenEq: (v) => `token=${v} rejected`,
  pairPasswordJson: (v) => `body {"password": "${v}"} rejected`,
  pairRefreshTokenEq: (v) => `refresh_token=${v} expired`,
  pairPrivateKeyColon: (v) => `private_key: ${v} rejected`,
  pairAuthorizationJson: (v) => `headers {"Authorization":"${v}"} were logged`,
  quotedCookiePair: (v) => `Cookie: sid="${v}"; X-Api-Key: "${v}"; Content-Type: "application/json" was sent`,
  quotedHeaderSingle: (v) => `Set-Cookie: session='${v}' was echoed`,
  quotedBearer: (v) => `Authorization: Bearer "${v}" was rejected`,
  jsonEscapedHeaders: (v) => `{"detail":"upstream sent Cookie: sid=\\"${v}\\"; X-Api-Key: \\"${v}\\""}`,
});
const BARE = (v) => `saw ${v} in the output while listing roles`;

/** Text a sink may return: a string or a value serialised with the undefined marker the review used. */
function textOf(value) {
  if (typeof value === "string") return value;
  return JSON.stringify(value, (_key, entry) => (entry === undefined ? "__undefined__" : entry)) ?? String(value);
}

const SINKS = Object.freeze({
  scrubErrorText: (text, options) => scrubErrorText(text, options),
  scrubDataText: (text, options) => scrubDataText(text, options),
  scrubError_message: (text, options) => scrubError(new Error(text), options).message,
  scrubError_errorField: (text, options) => scrubError({ name: "VendorError", error: text }, options).message,
  scrubError_errorDescription: (text, options) => scrubError({ error_description: text }, options).message,
  scrubError_cause: (text, options) => scrubError(new Error("outer", { cause: new Error(text) }), options).message,
  errorMessage: (text, options) => errorMessage(new Error(text), options),
  IntegrationError_message: (text, options) => new IntegrationError(text, {}, options).message,
  IntegrationError_subclass: (text, options) => new (class ZoomApiError extends IntegrationError {})(text, { status: 401 }, options).message,
  redactSecretValues_string: (text, options) => textOf(redactSecretValues({ note: text, nested: [{ detail: text }] }, options)),
});
/** The sinks built on scrubErrorText, under which a real token shape must go even bare. */
const ERROR_TEXT_SINKS = Object.freeze(["scrubErrorText", "scrubError_message", "errorMessage", "IntegrationError_message", "IntegrationError_subclass"]);

/** Endpoint sinks take a URL-shaped carrier only. */
const ENDPOINT_SINKS = Object.freeze({
  scrubError_endpoint: (url, options) => scrubError(Object.assign(new Error("m"), { endpoint: url }), options).endpoint ?? "",
  scrubError_requestUrl: (url, options) => scrubError(Object.assign(new Error("m"), { request: { url } }), options).endpoint ?? "",
  IntegrationError_endpoint: (url, options) => new IntegrationError("m", { endpoint: url }, options).endpoint ?? "",
});
const ENDPOINT_CARRIERS = Object.freeze({
  userinfo: (v) => `https://user:${v}@api.example.com/v1/y`,
  queryToken: (v) => `https://api.example.com/v1/x?token=${v}&page=2`,
  bareQueryApiKey: (v) => `/v1/items?api_key=${v}&limit=5`,
  querySig: (v) => `/o/x?sig=${v}`,
});

/** The 6-to-24 windows of `value` present in `output`; a value shorter than 6 is judged whole. */
function leakedWindows(output, value) {
  const text = textOf(output);
  const fragments = value.length >= 6 ? fragmentsOf(value) : [value];
  return fragments.filter((fragment) => text.includes(fragment));
}

function isUrlHostile(value) {
  return /[/@?#&\s]/.test(value);
}

test("guard 1: every canary shape inside every carrier is removed through every sink, with no 6-to-24 window left, and the text sinks are idempotent", (t) => {
  const leaks = [];
  let trials = 0;
  let idempotenceChecks = 0;
  for (const [name, [value]] of Object.entries(CANARIES)) {
    const hostile = isUrlHostile(value);
    for (const [carrierName, carrier] of Object.entries(CARRIERS)) {
      const isUrlCarrier = /^url|^bareQuery/.test(carrierName);
      // A raw "/" or "@" inside userinfo or a query value makes the URL malformed; the value rides URL-encoded there, as a client would send it.
      const planted = isUrlCarrier && hostile ? encodeURIComponent(value) : value;
      const text = carrier(planted);
      for (const [sinkName, sink] of Object.entries(SINKS)) {
        trials += 1;
        const out = sink(text, {});
        const leaked = leakedWindows(out, planted);
        if (leaked.length > 0) leaks.push(`${name} in ${carrierName} via ${sinkName}: window ${JSON.stringify(leaked[0])} in ${textOf(out).slice(0, 200)}`);
        if (sinkName === "scrubErrorText" || sinkName === "scrubDataText") {
          idempotenceChecks += 1;
          assert.equal(sink(out, {}), out, `${sinkName} is not idempotent over ${name} in ${carrierName}`);
        }
      }
    }
    if (!/\s/.test(value)) {
      const planted = hostile ? encodeURIComponent(value) : value;
      for (const [carrierName, carrier] of Object.entries(ENDPOINT_CARRIERS)) {
        const url = carrier(planted);
        for (const [sinkName, sink] of Object.entries(ENDPOINT_SINKS)) {
          trials += 1;
          const out = sink(url, {});
          const leaked = leakedWindows(out, planted);
          if (leaked.length > 0) leaks.push(`${name} in endpoint:${carrierName} via ${sinkName}: window ${JSON.stringify(leaked[0])} in ${textOf(out).slice(0, 200)}`);
        }
      }
    }
  }
  t.diagnostic(`guard 1: ${trials} carrier trials over ${Object.keys(CANARIES).length} canaries, ${Object.keys(CARRIERS).length + Object.keys(ENDPOINT_CARRIERS).length} carriers, ${Object.keys(SINKS).length + Object.keys(ENDPOINT_SINKS).length} sinks; ${idempotenceChecks} idempotence checks; ${leaks.length} leaks`);
  assert.ok(trials >= 29000, `expected the review's trial volume, ran ${trials}`);
  assert.deepEqual(leaks, [], `${leaks.length} guard 1 leaks, first: ${leaks[0]}`);
});

test("bare values: a real token shape goes bare under every error-text sink; a name-shaped value is the ruled must-keep case", () => {
  const failures = [];
  for (const [name, [value, expectation]] of Object.entries(CANARIES)) {
    if (expectation !== "token") continue;
    for (const sinkName of ERROR_TEXT_SINKS) {
      const leaked = leakedWindows(SINKS[sinkName](BARE(value), {}), value);
      if (leaked.length > 0) failures.push(`${name} via ${sinkName}: ${leaked.length} windows, first ${JSON.stringify(leaked[0])}`);
    }
  }
  assert.deepEqual(failures, [], `${failures.length} bare token shapes survived an error-text sink, first: ${failures[0]}`);
  for (const [name, [value, expectation]] of Object.entries(CANARIES)) {
    if (expectation !== "name") continue;
    assert.equal(scrubErrorText(BARE(value)), BARE(value), `${name}: a bare name-shaped value stays under scrubErrorText (the must-keep ruling)`);
  }
});

/** Every encoded form a configured secret may take in a body or a log line. */
function forms(secret) {
  const out = {
    plain: secret,
    base64: Buffer.from(secret).toString("base64"),
    base64url: Buffer.from(secret).toString("base64url"),
    urlEncoded: encodeURIComponent(secret),
    jsonEscaped: JSON.stringify(secret).slice(1, -1),
  };
  if (secret.includes("\n")) out.reflowed = secret.split("\n").slice(1, -1).join(" ");
  return out;
}

const SECRETS = Object.freeze({
  len3_ignored: "Ab1",
  len4: "Gy4T",
  len5: "Gy4Tz",
  len6: "Hq7Wz3",
  len7: "Hq7Wz3M",
  len8: "Jk8Rv2Np",
  len12: "Lm4Qs9Tv1Xw7",
  len20_random: ERROR_CANARY.configured,
  len24_random: "Qp7Zr2Vx9Lk4Wm1Nt6Hs3Jd5",
  nameShaped: "my-secret-name-2026",
  nameShapedUnderscore: "prod_db_replica_2026",
  plainWord: "swordfish",
  plainPhrase: "correcthorsebatterystaple",
  digitsOnly: "8675309124",
  uppercaseCode: "SUPERSECRETCODE",
  encodedFormChars: ENCODED_FORM_SECRET,
  quotesAndBackslash: 'pa"ss\\wo/rd+9<x>',
  unicode: "pässwörd-ünïcode-9",
  pem: PEM,
});

test("guard 2: a configured secret of every shape and length is removed in every encoded form, bare, embedded, and inside the carriers, through every sink, down to the documented floor", (t) => {
  const leaks = [];
  let trials = 0;
  let ignoredShortForms = 0;
  for (const [name, secret] of Object.entries(SECRETS)) {
    const options = { secrets: [secret, undefined, null] };
    const shortSecret = secret.length < 8;
    const ignored = secret.length < MIN_CONFIGURED_SECRET_LENGTH;
    for (const [formName, form] of Object.entries(forms(secret))) {
      if (form.length === 0) continue;
      const placements = { whole: `pin ${form} rejected` };
      if (!shortSecret) placements.embedded = `pin x${form}y rejected`;
      if (!/\s/.test(form)) {
        placements.authBearer = CARRIERS.authBearer(form);
        placements.setCookie = CARRIERS.setCookie(form);
        placements.xApiKey = CARRIERS.xApiKey(form);
        placements.pairPasswordColon = CARRIERS.pairPasswordColon(form);
        placements.urlQueryToken = CARRIERS.urlQueryToken(form);
        placements.quotedCookiePair = CARRIERS.quotedCookiePair(form);
      }
      for (const [placementName, text] of Object.entries(placements)) {
        for (const [sinkName, sink] of Object.entries(SINKS)) {
          trials += 1;
          const outText = textOf(sink(text, options));
          const leaked = form.length >= 6 ? fragmentsOf(form).filter((fragment) => outText.includes(fragment)) : outText.includes(form) ? [form] : [];
          if (leaked.length === 0) continue;
          if (ignored) {
            ignoredShortForms += 1;
            continue;
          }
          leaks.push(`secret ${name} form ${formName} placement ${placementName} via ${sinkName}: window ${JSON.stringify(leaked[0])} in ${outText.slice(0, 200)}`);
        }
      }
    }
  }
  t.diagnostic(`guard 2: ${trials} configured-secret trials over ${Object.keys(SECRETS).length} secrets; ${leaks.length} leaks; ${ignoredShortForms} kept forms of the ignored ${MIN_CONFIGURED_SECRET_LENGTH - 1}-character secret`);
  assert.ok(trials >= 6000, `expected the review's trial volume, ran ${trials}`);
  assert.deepEqual(leaks, [], `${leaks.length} guard 2 leaks, first: ${leaks[0]}`);
  assert.equal(scrubErrorText("pin Ab1 rejected", { secrets: ["Ab1"] }), "pin Ab1 rejected", "a secret under the floor is ignored, as documented");
  assert.ok(ignoredShortForms > 0, "the ignored short secret was seen kept in at least one form");
});
