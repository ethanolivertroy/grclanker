/**
 * The data-side carrier class (round 4 item 2): a credential carried inside a free-text field of an API
 * response (a description, a note, a name, a policy comment) must not reach a snapshot, an evidence
 * list, a summary, a bundle file, or a zip entry, while the identifiers that live in the same fields
 * (hostnames, table names, UUIDs, quoted non-credential headers, prose using scheme words) must.
 *
 * `injectingFetch` wraps an integration's healthy fixture: every JSON response has the planted text
 * appended to every text-like string field, so every collector sees every form. The planted text is
 * the fifteen carrier forms reviewer B's `text-field-carriers` probe plants (each with its own random
 * alphanumeric token or a name-shaped value no shape rule removes), the vendor-prefixed token shapes,
 * a JWT, and a PEM block bare in prose (ruling 6: unambiguous credential shapes go on the data side too),
 * the integration's configured secrets bare in prose (a remembered secret goes whatever its shape), the
 * must-survive controls, and a bare token that documents the ruling: the generic bare-run rule does not
 * run on the data side, so it stays.
 *
 * Leak assertions check every window of every planted value at lengths 6 through 24
 * (`assertFragmentsAbsent`); the fixture self-check proves no window occurs in the healthy outputs.
 */
import { assertFragmentsAbsent, shortestWindows } from "./planted-values.mjs";

/** Keys whose string values are free text a vendor UI shows and an auditor reads. */
export const TEXT_FIELD_KEY = /(desc|description|comment|content|message|title|summary|note|notes|detail|body|text|reason|justification|display|label|name|subject)/i;

/** Name-shaped values (hyphenated lowercase syllables): no token heuristic removes them, only the carrier can. */
export const CARRIER_NAMES = Object.freeze({
  bearer: "harvel-domire-quist",
  cookie: "selwyn-torbane-ulk",
  setCookie: "morrow-fendlish-ava",
  userinfo: "castel-birrow-nyme",
  query: "ondrel-vastique-por",
  secret: "lumire-gaskell-tob",
});

/** One random alphanumeric token per carrier form; no 6-character window is shared between any two. */
export const CARRIER_TOKENS = Object.freeze([
  "GGgs8pptyZJQXN3njFaphGCd",
  "gkcUqgcVkscgzGSsJkqDVghC",
  "LKscMXL8aqGFseqWjA4cfDjt",
  "kSyRGgrc5AMqrsEmUKbnNzHY",
  "7Q4pmryB2aEWdvR3WELNEKLh",
  "csRnfbwVVFyfdSbSxb972KqE",
  "vt7DFDJC2NMuNU47zaC4Bced",
  "NkqPskvK2FQ5fAtCHkWAYVCd",
  "qYHshVhZLbggXgYBZUaejfmg",
  "6vNFfdczJrBHe9a8hqDuUAKJ",
  "XjPQbJPUG4GrZPUmhdckambV",
  "6DA5tUYMe7Bwsv7dUq47HjzC",
  "w9UV8QLQ2nB7zVKxKbWajNAE",
  "r6kUXg8VEkxK5frVWK66SMMm",
  "ahqK8DwPpep9bH5VByeAWWqp",
]);

/** The bare token the ruling keeps on the data side (informational control: it must survive). */
export const BARE_TOKEN_CONTROL = "wwajkCRRybmRR5pnM9XsZv8c";

/**
 * Ruling 6 (reviewer B round 4 verdict): vendor-prefixed token shapes, JWTs, and PEM blocks are unambiguous
 * credential shapes with no identifier collision, so the data side removes them bare too, while the generic
 * bare-run rule stays off it (BARE_TOKEN_CONTROL survives). One random value per shape; the PEM block plants
 * its body line, the whole block goes with it.
 */
export const VENDOR_TOKEN_CANARIES = Object.freeze({
  stripeLiveKey: "sk_live_Vb3RqZ8mKp2WxT9nJc4LyH7d",
  githubToken: "ghp_Xq7Lm2Nv9Rt4Wy6Zb8Kc3Fh5Jd1PgSaUe",
  awsAccessKeyId: "AKIAQ7X2M9V4R6T8W3Y5",
  slackBotToken: "xoxb-4827391056-Zk9Qm2Pv7Rt4Wy6B",
  jwt: "eyJXq7Lm2Nv9Rt4Wy6Zb8.eyJKc3Fh5Jd1PgSaUeQm7Z.x3Kp9Wm2Rt5Yv8Nb4Lc6Hd",
  pemBody: "Qm7Zx3Kp9Wm2Rt5Yv8Nb4Lc6HdJf1Gs0TwVy2Xz",
});

/** The vendor shapes bare in prose: [form, text, planted values]. */
export function vendorTokenForms() {
  return [
    ["bare Stripe live key", `key ${VENDOR_TOKEN_CANARIES.stripeLiveKey} end`, [VENDOR_TOKEN_CANARIES.stripeLiveKey]],
    ["bare GitHub token", `pat ${VENDOR_TOKEN_CANARIES.githubToken} end`, [VENDOR_TOKEN_CANARIES.githubToken]],
    ["bare AWS access key id", `id ${VENDOR_TOKEN_CANARIES.awsAccessKeyId} end`, [VENDOR_TOKEN_CANARIES.awsAccessKeyId]],
    ["bare Slack bot token", `bot ${VENDOR_TOKEN_CANARIES.slackBotToken} end`, [VENDOR_TOKEN_CANARIES.slackBotToken]],
    ["bare JWT", `jwt ${VENDOR_TOKEN_CANARIES.jwt} end`, [VENDOR_TOKEN_CANARIES.jwt]],
    ["PEM block", `-----BEGIN PRIVATE KEY-----\n${VENDOR_TOKEN_CANARIES.pemBody}\n-----END PRIVATE KEY-----`, [VENDOR_TOKEN_CANARIES.pemBody]],
  ];
}

/** Configured-secret canaries for the clients under test; no 6-character window is shared with any token above. */
export const CONFIGURED_SECRET_CANARIES = Object.freeze({
  crowdstrikeClientSecret: "xbUwCYyjakswBppyDyj5",
  mulesoftClientSecret: "XmBeZZK7anrEJz3HCgNd",
  pagerdutyApiToken: "Gswy3m37CC2cvVnfrvdM",
  salesforcePassword: "84fjUKdKfKEsCzNAJTqB",
  salesforceSecurityToken: "5UprSzzyDjMVfQaARQa7",
  salesforceConsumerSecret: "pVwcmY4sUt7LQawUnZQq",
  servicenowPassword: "ULkfBn4fyTY87d2AkJxB",
  servicenowRefreshToken: "RdX7eg7JnYGxcvpJ968M",
});

/** Must survive verbatim somewhere in the outputs: proves the text reached them and identifiers are kept. */
export const MUST_SURVIVE = Object.freeze([
  "prod-us-east-2026",
  "sys_user_has_role",
  "6f1c1e2a-4b6d-4e0a-9c3f-2d7a8b9c0d1e",
  'Content-Type: "application/json"',
  "bearer of record",
]);

/** The fifteen carrier forms: [form, text, planted values]. */
export function carrierForms() {
  const token = (index) => CARRIER_TOKENS[index];
  return [
    ["header Authorization: Bearer <token>", `Authorization: Bearer ${token(0)}`, [token(0)]],
    ['header Authorization: Bearer "<name>"', `Authorization: Bearer "${CARRIER_NAMES.bearer}"`, [CARRIER_NAMES.bearer]],
    ["header Cookie: sid=<token>", `Cookie: sid=${token(2)}`, [token(2)]],
    ['header Cookie: sid="<name>"', `Cookie: sid="${CARRIER_NAMES.cookie}"`, [CARRIER_NAMES.cookie]],
    ["header Set-Cookie: session='<name>'; Secure", `Set-Cookie: session='${CARRIER_NAMES.setCookie}'; Secure`, [CARRIER_NAMES.setCookie]],
    ["header X-Api-Key: <token>", `X-Api-Key: ${token(5)}`, [token(5)]],
    ['header X-Api-Key: "<token>"', `X-Api-Key: "${token(6)}"`, [token(6)]],
    ["URL userinfo (token)", `https://svc:${token(7)}@api.example.test/v1/x`, [token(7)]],
    ["URL userinfo (name)", `https://deploy:${CARRIER_NAMES.userinfo}@git.example.test/repo.git`, [CARRIER_NAMES.userinfo]],
    ["URL query ?token=<token>", `https://hooks.example.test/h?token=${token(9)}`, [token(9)]],
    ["URL query ?sig=<name>", `https://hooks.example.test/h?sig=${CARRIER_NAMES.query}`, [CARRIER_NAMES.query]],
    ["assignment password=<token>", `password=${token(11)}`, [token(11)]],
    ['field client_secret: "<name>"', `client_secret: "${CARRIER_NAMES.secret}"`, [CARRIER_NAMES.secret]],
    ["flag --token <token>", `--token ${token(13)}`, [token(13)]],
    ['JSON field {"api_key":"<token>"}', JSON.stringify({ api_key: token(14) }), [token(14)]],
  ];
}

/** Every value that must vanish: the fifteen forms' values, the vendor shapes, and the integration's configured secrets. */
export function plantedCarrierValues(configuredSecrets = []) {
  return [...carrierForms().flatMap(([, , values]) => values), ...vendorTokenForms().flatMap(([, , values]) => values), ...configuredSecrets];
}

/** The text appended to every text-like field: the forms, the vendor shapes, the configured secrets bare in prose, the controls, and the bare token. */
export function carrierSuffix(configuredSecrets = []) {
  return [
    ...carrierForms().map(([, text]) => text),
    ...vendorTokenForms().map(([, text]) => text),
    ...configuredSecrets.map((secret) => `configured ${secret} in prose`),
    ...MUST_SURVIVE,
    BARE_TOKEN_CONTROL,
  ].join(" | ");
}

/** A deep copy of `value` with `suffix` appended to every string under a text-like key. */
export function injectTextFields(value, suffix, key = "") {
  if (Array.isArray(value)) return value.map((item) => injectTextFields(item, suffix, key));
  if (value !== null && typeof value === "object") {
    const output = {};
    for (const [childKey, child] of Object.entries(value)) output[childKey] = injectTextFields(child, suffix, childKey);
    return output;
  }
  if (typeof value === "string" && TEXT_FIELD_KEY.test(key)) return `${value} ${suffix}`;
  return value;
}

/**
 * Wraps a fetch implementation so every successful JSON response carries `suffix` in each text-like
 * field; non-JSON and error responses pass through untouched.
 */
export function injectingFetch(fetchImpl, suffix) {
  return async (input, init) => {
    const response = await fetchImpl(input, init);
    const contentType = response.headers.get("content-type") ?? "";
    if (!response.ok || !/json/i.test(contentType)) return response;
    const text = await response.text();
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      return new Response(text, { status: response.status, statusText: response.statusText, headers: response.headers });
    }
    const headers = new Headers(response.headers);
    headers.delete("content-length");
    return new Response(JSON.stringify(injectTextFields(parsed, suffix)), { status: response.status, statusText: response.statusText, headers });
  };
}

/** Every string leaf of a value, for the survival checks. */
export function collectStrings(value, output = []) {
  if (typeof value === "string") output.push(value);
  else if (Array.isArray(value)) for (const item of value) collectStrings(item, output);
  else if (value !== null && typeof value === "object") for (const item of Object.values(value)) collectStrings(item, output);
  return output;
}

/**
 * The full assertion set over the harvested outputs (`texts`: named [label, text] pairs from the access
 * check, the assessments, the bundle files, and the zip entries): no planted value survives in any
 * 6-to-24-character window, every must-survive control and the bare token appear somewhere, and, given
 * `healthyTexts` from the same run without injection, no 6-character window of any planted value occurs
 * in the fixture's legitimate outputs (the self-check that makes the window assertion sound).
 */
export function assertTextFieldCarriers(assert, texts, { configuredSecrets = [], healthyTexts = [] } = {}) {
  const planted = plantedCarrierValues(configuredSecrets);
  for (const [label, text] of texts) assertFragmentsAbsent(assert, text, planted, label);
  const joined = texts.map(([, text]) => text).join("\n");
  for (const control of MUST_SURVIVE) assert.ok(joined.includes(control), `must-survive control ${JSON.stringify(control)} reached the outputs`);
  assert.ok(joined.includes(BARE_TOKEN_CONTROL), "the bare token stays on the data side (no bare-token rule runs there)");
  const healthy = healthyTexts.map(([, text]) => text).join("\n");
  for (const value of planted) {
    for (const window of shortestWindows(value)) {
      assert.ok(!healthy.includes(window), `window ${window} of planted value ${value} occurs in the healthy fixture outputs`);
    }
  }
}
