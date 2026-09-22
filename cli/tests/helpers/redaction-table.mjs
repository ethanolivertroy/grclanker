/**
 * Must-keep and must-redact table for redactErrorText (addendum 7) and the fixed-text survival check (GWS
 * note 1). Kept apart from error-canaries.mjs, which PR #67 mirrors byte for byte; this file only imports it.
 *
 * Must-keep rows are the identifying strings an integration's summaries, markers, probes, and evidence rely
 * on: the endpoint paths and commands it requests, resource names, principals, status text, finding ids, and
 * every fixed-text message it emits. Each row is asserted unchanged in isolation and inside a realistic
 * summary sentence of its group. Must-redact rows are the shared canary set: each canary rides every carrier
 * beside a must-keep row inside one sentence, and the canary must vanish window by window while the row and
 * the rest of the sentence survive whole.
 */
import { CANARY_VALUES, QUOTED_NON_CREDENTIAL_TEXTS, assertNoCanaryWindows, carrierCases } from "./error-canaries.mjs";

/**
 * @typedef {object} MustKeepGroup
 * @property {string} label
 * @property {readonly string[]} values distinct must-keep rows
 * @property {(value: string) => string} sentence a realistic summary sentence that embeds one row
 */

/**
 * Must-keep group shared by every integration (Codex P1 control): quoted header and JSON values that name no
 * credential survive, while the quoted credential carriers in carrierCases are removed beside them.
 * @type {MustKeepGroup}
 */
export const QUOTED_NON_CREDENTIAL_GROUP = Object.freeze({
  label: "quoted non-credential headers (Codex P1 control)",
  values: QUOTED_NON_CREDENTIAL_TEXTS,
  sentence: (value) => `the 502 response carried ${value} and a non-JSON body (text/html, 5120 bytes)`,
});

/** Asserts each must-keep row survives the scrub unchanged, in isolation and inside its group's sentence. */
export function assertMustKeepRows(assert, redact, groups) {
  assert.ok(groups.length > 0, "the must-keep table has at least one group");
  for (const group of groups) {
    assert.ok(group.values.length > 0, `${group.label}: the group has rows`);
    assert.equal(new Set(group.values).size, group.values.length, `${group.label}: rows are distinct`);
    for (const value of group.values) {
      assert.equal(redact(value), value, `${group.label}: must-keep row survives in isolation: ${value}`);
      const sentence = group.sentence(value);
      assert.ok(sentence.includes(value), `${group.label}: the sentence embeds the row: ${value}`);
      assert.notEqual(sentence, value, `${group.label}: the sentence adds context around the row: ${value}`);
      assert.equal(redact(sentence), sentence, `${group.label}: must-keep row survives inside a summary sentence: ${sentence}`);
    }
  }
}

/**
 * Asserts each must-redact row (a canary inside a carrier) is removed while the must-keep row it shares a
 * sentence with survives, together with the rest of the sentence. Every canary rides every carrier and the
 * must-keep rows rotate through the pairs; the loop runs as long as the longer of the two lists, so every row
 * sits beside at least one redaction and every canary-carrier pair beside at least one row.
 */
export function assertMustRedactRowsBesideMustKeep(assert, redact, groups, canaries = CANARY_VALUES) {
  const rows = groups.flatMap((group) => group.values.map((value) => ({ group, value })));
  assert.ok(rows.length > 0, "the must-keep table has rows to pair with must-redact rows");
  const pairs = canaries.flatMap((canary) => carrierCases(canary).map((carrierCase) => ({ canary, carrierCase })));
  assert.ok(pairs.length > 0, "the must-redact table has canary-carrier pairs");
  const turns = Math.max(rows.length, pairs.length);
  for (let index = 0; index < turns; index += 1) {
    const { group, value } = rows[index % rows.length];
    const { canary, carrierCase: [carrier, carried, carriedAfter] } = pairs[index % pairs.length];
    const sentence = group.sentence(value);
    const output = redact(`${sentence} ${carried}`);
    assertNoCanaryWindows(assert, output, [canary], `${carrier} beside ${group.label} row ${value}`);
    assert.equal(
      output,
      `${sentence} ${carriedAfter}`,
      `${carrier} beside ${group.label} row ${value}: the row and its sentence survive and only the carried value is removed`,
    );
  }
}

/**
 * Reviewer D round 5 baseline: a value under a credential-named key is a carrier and is removed whatever its
 * shape and length, unquoted as well as quoted. The keys are the credential env names and config keys the five
 * integrations read (the AWS pair through the SDK chain) beside the generic keys reviewer D probed and one
 * lowerCamelCase, one header, and one dotted compound. DUO_IKEY and ikey are the keys the word list had no word
 * for until reviewer D's round 5 baseline (the pattern named skey but not ikey).
 */
export const CREDENTIAL_NAMED_KEYS = Object.freeze([
  "password",
  "DB_PASSWORD",
  "AAP_PASSWORD",
  "admin_password",
  "client_token",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "AZURE_CLIENT_SECRET",
  "AZURE_ACCESS_TOKEN",
  "AZURE_GRAPH_TOKEN",
  "AZURE_MANAGEMENT_TOKEN",
  "CLOUDFLARE_API_TOKEN",
  "CLOUDFLARE_API_KEY",
  "DUO_SKEY",
  "DUO_IKEY",
  "skey",
  "ikey",
  "AAP_TOKEN",
  "accessToken",
  "x-api-key",
  "Proxy-Authorization",
  "settings.token",
]);

/**
 * Reviewer D's value-shape matrix: the values the retired shape test kept. Alphabetic words of 6 to 11
 * characters, values under 6 characters, and the listed passwords (the ones with a digit were already removed;
 * they stay as controls). Every value is chosen so that none of its 6-to-24 windows, or the whole value when
 * shorter, occurs in any key, separator, or sentence of the forms below.
 */
export const CREDENTIAL_VALUE_SHAPES = Object.freeze({
  alphabetic: Object.freeze(["letmein", "monkey", "qwerty", "dragon", "Sunshine", "iloveyou", "football", "baseball", "abcdefghijk"]),
  short: Object.freeze(["abc12", "p@ss", "Zq7", "1a"]),
  listed: Object.freeze(["hunter2", "Summer2026!", "correcthorsebatterystaple", "letmein2024", "trustno1"]),
});
export const CREDENTIAL_VALUE_MATRIX = Object.freeze(Object.values(CREDENTIAL_VALUE_SHAPES).flat());

const TRAILING_SENTENCE_PUNCTUATION = /[.!?:)]+$/;

/**
 * The unquoted and quoted forms a key-value pair takes in error text, each with the exact text expected after
 * the scrub: the key, the separator, the quotes, the surrounding text, and any sentence punctuation the value
 * itself ends with stay, and only the value becomes the marker. The compound forms end the value at a closing
 * bracket, a `;`, an `&`, or the end of a sentence, so the next header or query pair keeps its name and value.
 */
export function credentialPairForms(key, value) {
  const marker = "[REDACTED]";
  const tail = TRAILING_SENTENCE_PUNCTUATION.exec(value)?.[0] ?? "";
  return [
    [`${key}=${value}`, `${key}=${marker}${tail}`],
    [`${key}: ${value}`, `${key}: ${marker}${tail}`],
    [`${key}:${value}`, `${key}:${marker}${tail}`],
    [`{"${key}":"${value}"}`, `{"${key}":"${marker}"}`],
    [`"${key}": "${value}"`, `"${key}": "${marker}"`],
    [`request failed (${key}=${value}) at 12:00`, `request failed (${key}=${marker}${tail}) at 12:00`],
    [`${key}=${value}; Content-Type: application/json`, `${key}=${marker}${tail}; Content-Type: application/json`],
    [`a=1&${key}=${value}&b=2`, `a=1&${key}=${marker}${tail}&b=2`],
    [`[${key}=${value}]`, `[${key}=${marker}${tail}]`],
    [`the upstream echoed ${key}: ${value}.`, `the upstream echoed ${key}: ${marker}${tail}.`],
    [`${key}=${value}\n${key}: ${value}`, `${key}=${marker}${tail}\n${key}: ${marker}${tail}`],
  ];
}

/**
 * Asserts every value of the shape matrix is removed under every credential-named key in every form, that only
 * the value is removed, and that a second pass over the scrubbed text changes nothing (reviewer D round 5
 * baseline). A value shorter than the window minimum is checked whole.
 */
export function assertCredentialPairValuesRemoved(assert, redact, { keys = CREDENTIAL_NAMED_KEYS, values = CREDENTIAL_VALUE_MATRIX } = {}) {
  assert.ok(keys.length > 0 && values.length > 0, "the credential pair matrix has keys and values");
  for (const key of keys) {
    for (const value of values) {
      for (const [text, expected] of credentialPairForms(key, value)) {
        const output = redact(text);
        assertNoCanaryWindows(assert, output, [value], `credential pair ${JSON.stringify(text)}`);
        assert.equal(output, expected, `only the value under ${key} is removed: ${JSON.stringify(text)}`);
        assert.equal(redact(output), output, `a second pass over ${JSON.stringify(output)} changes nothing`);
      }
    }
  }
}

/**
 * Reviewer D round 5 ruling on identifier-named keys: AWS_ACCESS_KEY_ID, CLOUDFLARE_EMAIL, AAP_USERNAME,
 * AZURE_CLIENT_ID, AZURE_TENANT_ID, and CLOUDFLARE_ACCOUNT_ID name identifiers, not credentials, so their
 * values are judged by their own shape alone: an access key id is removed by the bare AWS key-id rule and a
 * 32-hex account id by the hex rule (masked in prose, kept in structured fields), whatever the key; a UUID, an
 * email, a user name, a profile name, and a file path stay. The key and its separator survive in every case.
 */
export const IDENTIFIER_KEY_ROWS = Object.freeze([
  ["AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY_ID=[REDACTED]"],
  ['{"AWS_ACCESS_KEY_ID":"AKIAIOSFODNN7EXAMPLE"}', '{"AWS_ACCESS_KEY_ID":"[REDACTED]"}'],
  ["CLOUDFLARE_ACCOUNT_ID=023e105f4ecef8ad9ca31a8372d0c353", "CLOUDFLARE_ACCOUNT_ID=[REDACTED]"],
  ["AZURE_TENANT_ID=3f2504e0-4f89-11d3-9a0c-0305e82c3301", "AZURE_TENANT_ID=3f2504e0-4f89-11d3-9a0c-0305e82c3301"],
  ['"AZURE_TENANT_ID": "3f2504e0-4f89-11d3-9a0c-0305e82c3301"', '"AZURE_TENANT_ID": "3f2504e0-4f89-11d3-9a0c-0305e82c3301"'],
  ["AZURE_CLIENT_ID: 6ba7b810-9dad-11d1-80b4-00c04fd430c8", "AZURE_CLIENT_ID: 6ba7b810-9dad-11d1-80b4-00c04fd430c8"],
  ["CLOUDFLARE_EMAIL=ops@example.com", "CLOUDFLARE_EMAIL=ops@example.com"],
  ["AAP_USERNAME=auditor", "AAP_USERNAME=auditor"],
  ["AWS_PROFILE=audit", "AWS_PROFILE=audit"],
  ["AWS_SHARED_CREDENTIALS_FILE=/home/audit/.aws/credentials", "AWS_SHARED_CREDENTIALS_FILE=/home/audit/.aws/credentials"],
  ["AZURE_CLIENT_CERTIFICATE_PATH=/etc/azure/audit.pem", "AZURE_CLIENT_CERTIFICATE_PATH=/etc/azure/audit.pem"],
  ["KmsKeyId: alias/aws/ebs", "KmsKeyId: alias/aws/ebs"],
]);

/** Asserts each identifier-named row scrubs to exactly its expected text, in isolation and inside a sentence. */
export function assertIdentifierKeyRows(assert, redact, rows = IDENTIFIER_KEY_ROWS) {
  for (const [text, expected] of rows) {
    assert.equal(redact(text), expected, `identifier-named key: ${text}`);
    const sentence = `the resolver read ${text} from the environment`;
    assert.equal(redact(sentence), `the resolver read ${expected} from the environment`, `identifier-named key inside a sentence: ${text}`);
  }
}

/**
 * reviewer D round 5 escapes. Inside a serialized message a header line follows a JSON escape rather than a
 * real line break: `\n`, `\t`, `\r\n` (two characters each) or `\u000a`, `\u0009`, `\u000d\u000a` (six), as
 * backslash text. The character before the header name is then the escape's last letter, a word character to
 * `\b`, so a carrier rule that relied on `\b` never fired and left the line to the pair rule, which stops at the
 * first `;`: `\nCookie: theme=dark; my.tracker=hunter2` came back `Cookie: [REDACTED]; my.tracker=hunter2`, the
 * later pair judged on its own name and shape, and `\nX-Auth-Key: prodkey` lost the whatever-the-shape rule.
 */
export const JSON_ESCAPES = Object.freeze(["\\n", "\\t", "\\r\\n", "\\u000a", "\\u0009", "\\u000d\\u000a"]);

/** The escaped line break, in the escape's own style, that separates a header line from the next one inside a serialized message. */
export function escapedLineBreakFor(escape) {
  return escape.includes("\\u") ? "\\u000d\\u000a" : "\\r\\n";
}

const CLOUDFLARE_GLOBAL_KEY = "c2547eb745079dac9320b638f5e225cf483cc";
const SIGV4_KEY_ID = "AKIAQ7RZ3M5XK2VJ8N4W";
const SIGV4_SIGNATURE = "3f2a9c8e7b6d5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f";
const SESSION_TOKEN = "FwoGZXIvYXdzEBYaDHt4Q2kzR2xNbVpqNXo5Y3VkbXM2Kq3Ht8Wz";
const CSRF_TOKEN = "Xh4Kq9Lm2Tz7Bv5Rn8Wc3Yp6Fd1Gs0J";
const SESSION_ID = "8m2kq4r7v9x1z3c5b6n0p2t4";
const CSRF_COOKIE = "Wq3Er5Ty7Ui9Op1As2Df4Gh6";
const BASIC_CREDENTIAL = Buffer.from("DIQ7RZ3M5XK2VJ8N4WPL:Zk8qLm3nRt7vWx2yPa5cB9dQf4Hs6Jt1", "utf8").toString("base64");

/**
 * The nineteen header lines the five integrations send, each with the values it carries (judged by 6-to-24
 * windows; a whole pair when its value is under six characters) and the text that must stay. `X-Auth-Key`
 * and `X-Auth-Email` (Cloudflare's global key pair), `Authorization: Bearer` (Azure, Cloudflare, Ansible),
 * `Authorization: Basic` (Duo, Ansible), the SigV4 `Authorization` and `X-Amz-Security-Token` (AWS),
 * `X-CSRFToken` and the session cookie (Ansible session mode), and the cookie shapes whose later pair carries
 * no credential word (`my.tracker`, `ASP.NET_Tracker`) or a short value (`SessionId=abc`, `Session=v`).
 */
export const ESCAPED_HEADER_LINES = Object.freeze([
  Object.freeze({ label: "X-Auth-Key hex global key", line: `X-Auth-Key: ${CLOUDFLARE_GLOBAL_KEY}`, values: [CLOUDFLARE_GLOBAL_KEY], name: "X-Auth-Key" }),
  Object.freeze({ label: "X-Auth-Key name-shaped", line: "X-Auth-Key: prod-key", values: ["prod-key"], name: "X-Auth-Key" }),
  Object.freeze({ label: "X-Auth-Key hunter2", line: "X-Auth-Key: hunter2", values: ["hunter2"], name: "X-Auth-Key" }),
  Object.freeze({ label: "X-Auth-Key alphabetic seven", line: "X-Auth-Key: prodkey", values: ["prodkey"], name: "X-Auth-Key" }),
  Object.freeze({ label: "X-Auth-Email", line: "X-Auth-Email: qz7auditor.rk3@corp.test", values: ["qz7auditor.rk3"], name: "X-Auth-Email" }),
  Object.freeze({ label: "Bearer 23-character token", line: "Authorization: Bearer Zk8qLm3nRt7vWx2yPa5cB9d", values: ["Zk8qLm3nRt7vWx2yPa5cB9d"], name: "Authorization" }),
  Object.freeze({ label: "Bearer name-shaped", line: "Authorization: Bearer prod-token", values: ["prod-token"], name: "Authorization" }),
  Object.freeze({ label: "Bearer hunter2", line: "Authorization: Bearer hunter2", values: ["hunter2"], name: "Authorization" }),
  Object.freeze({ label: "Basic ikey:signature", line: `Authorization: Basic ${BASIC_CREDENTIAL}`, values: [BASIC_CREDENTIAL], name: "Authorization" }),
  Object.freeze({
    label: "SigV4 Authorization",
    line: `Authorization: AWS4-HMAC-SHA256 Credential=${SIGV4_KEY_ID}/20260922/us-east-1/sts/aws4_request, SignedHeaders=host;x-amz-date, Signature=${SIGV4_SIGNATURE}`,
    values: [SIGV4_KEY_ID, SIGV4_SIGNATURE],
    name: "Authorization",
    keep: ["us-east-1", "aws4_request", "SignedHeaders=host;x-amz-date"],
  }),
  Object.freeze({ label: "X-Amz-Security-Token", line: `X-Amz-Security-Token: ${SESSION_TOKEN}`, values: [SESSION_TOKEN], name: "X-Amz-Security-Token" }),
  Object.freeze({ label: "X-CSRFToken", line: `X-CSRFToken: ${CSRF_TOKEN}`, values: [CSRF_TOKEN], name: "X-CSRFToken" }),
  Object.freeze({ label: "AAP session cookie", line: `Cookie: sessionid=${SESSION_ID}; csrftoken=${CSRF_COOKIE}`, values: [SESSION_ID, CSRF_COOKIE], name: "Cookie" }),
  Object.freeze({ label: "cookie with a dotted credential pair", line: "Cookie: theme=dark; my.sid=hunter2", values: ["hunter2"], name: "Cookie" }),
  Object.freeze({ label: "cookie with a later pair carrying no credential word", line: "Cookie: theme=dark; my.tracker=hunter2", values: ["hunter2"], name: "Cookie" }),
  Object.freeze({ label: "cookie with a dotted later pair carrying no credential word", line: "Cookie: theme=dark; ASP.NET_Tracker=hunter2", values: ["hunter2"], name: "Cookie" }),
  Object.freeze({ label: "cookie with a later short credential value", line: "Cookie: theme=dark; ASP.NET_SessionId=abc", values: ["ASP.NET_SessionId=abc"], name: "Cookie" }),
  Object.freeze({ label: "Set-Cookie with a dotted short session value", line: "Set-Cookie: .AspNetCore.Session=v; HttpOnly", values: [".AspNetCore.Session=v"], name: "Set-Cookie" }),
  Object.freeze({ label: "Set-Cookie with attributes", line: "Set-Cookie: session=Vb7Nq2Xz9Lk4Rm6Tp1Wc8; Path=/; HttpOnly; Secure", values: ["Vb7Nq2Xz9Lk4Rm6Tp1Wc8"], name: "Set-Cookie" }),
]);

const FOLLOWING_HEADER = "Content-Type: application/json";

/**
 * The forms one header line takes after one escape: at the start of the text, after prose, as the tail of a JSON
 * string member, followed by the next header on the same line after `;`, and followed by the next header after an
 * escaped line break. Each row is [label, text, expected output], the expectation built from the scrub of the
 * plain line so the rule is "an escape changes nothing"; the JSON member form is judged by windows and by the
 * string's close surviving instead.
 */
export function escapedHeaderForms(line, escape, plainOutput) {
  const lineBreak = escapedLineBreakFor(escape);
  return [
    ["leading", `${escape}${line}`, `${escape}${plainOutput}`],
    ["after prose", `request failed${escape}${line}`, `request failed${escape}${plainOutput}`],
    ["JSON member", `{"error":"request failed${escape}${line}"}`, undefined],
    ["followed by a header after ;", `${escape}${line}; ${FOLLOWING_HEADER}`, `${escape}${plainOutput}; ${FOLLOWING_HEADER}`],
    ["followed by a header after an escaped line break", `${escape}${line}${lineBreak}${FOLLOWING_HEADER}`, `${escape}${plainOutput}${lineBreak}${FOLLOWING_HEADER}`],
  ];
}

/**
 * Asserts the escape rule for one redactErrorText over every header line, escape, and form: the plain line's
 * values are removed (positive control) with its must-keep text kept, and after any escape the output is the
 * escape plus the plain output (the header name kept, the following header kept whole), no 6-to-24 window of
 * any planted value survives, and a second pass changes nothing. Returns the number of escaped texts judged.
 */
export function assertEscapedHeaderCarriers(assert, redact, { lines = ESCAPED_HEADER_LINES, escapes = JSON_ESCAPES } = {}) {
  let judged = 0;
  for (const { label, line, values, name, keep = [] } of lines) {
    const plainOutput = redact(line);
    assert.notEqual(plainOutput, line, `${label}: positive control, the plain line is scrubbed`);
    assertNoCanaryWindows(assert, plainOutput, values, `${label}: plain line`);
    assert.ok(plainOutput.startsWith(`${name}:`), `${label}: the plain line keeps its header name: ${plainOutput}`);
    for (const text of keep) assert.ok(plainOutput.includes(text), `${label}: the plain line keeps ${text}: ${plainOutput}`);
    for (const escape of escapes) {
      for (const [form, text, expected] of escapedHeaderForms(line, escape, plainOutput)) {
        const output = redact(text);
        judged += 1;
        assertNoCanaryWindows(assert, output, values, `${label} after ${JSON.stringify(escape)}, ${form}: ${text}`);
        if (expected === undefined) {
          assert.ok(output.includes(`${escape}${name}:`), `${label} after ${JSON.stringify(escape)}, ${form}: the header name survives: ${output}`);
          assert.ok(output.endsWith('"}'), `${label} after ${JSON.stringify(escape)}, ${form}: the JSON string's close survives: ${output}`);
          for (const kept of keep) assert.ok(output.includes(kept), `${label} after ${JSON.stringify(escape)}, ${form}: keeps ${kept}: ${output}`);
        } else {
          assert.equal(output, expected, `${label} after ${JSON.stringify(escape)}, ${form}: the escape changes nothing: ${text}`);
        }
        assert.equal(redact(output), output, `${label} after ${JSON.stringify(escape)}, ${form}: a second pass changes nothing`);
      }
    }
  }
  return judged;
}

/**
 * Round 4 open ruling on server-assigned 32-hex ids, resolved as: masked in sentences, kept whole in structured
 * fields. A GuardDuty detector id and a Cloudflare account, zone, or token id are 32 hex characters, a hex
 * digest to the scrub, so error text removes them bare and they travel whole in the structured fields
 * (`detectors_unreadable`, `accountId`, `endpoint`, `account_id`, record ids); a sentence the integration
 * composes that names one (a read label, an endpoint in a summary, an access note, an errors line) masks it
 * to its first and last four characters, so the line still names the resource instead of reading as though
 * a secret had been recorded. The placeholders the fixtures use elsewhere (`detector-1`, `acc-123`, `zone-1`,
 * `tok-current`) are name-shaped and stay, which is why they never exercised the real shape.
 */
export const SERVER_ASSIGNED_HEX_IDS = Object.freeze([
  Object.freeze({ label: "GuardDuty detector id", id: "12abc34d567e8fa901bc2d34e56789f0", masked: "12ab****89f0", sentence: (value) => `guardduty:GetDetector ${value}: AccessDenied (User is not authorized to perform this operation)` }),
  Object.freeze({ label: "Cloudflare account id", id: "023e105f4ecef8ad9ca31a8372d0c353", masked: "023e****c353", sentence: (value) => `Cloudflare request failed for /accounts/${value}/members (403 Forbidden): Authentication error` }),
  Object.freeze({ label: "Cloudflare zone id", id: "9a7806061c88ada191ed06f989cc3dac", masked: "9a78****3dac", sentence: (value) => `Manual review required: /zones/${value}/dnssec could not be read (403 Forbidden). Grant Zone: Read to the audit token, or collect the DNSSEC status manually.` }),
  Object.freeze({ label: "Cloudflare token id", id: "ed17574386854bf78a67040be0a770b0", masked: "ed17****70b0", sentence: (value) => `/user/tokens/${value}: Cloudflare request failed for /user/tokens/${value} (403 Forbidden): Authentication error` }),
]);

/** The name-shaped placeholders the group D fixtures use for the same ids; no rule touches them. */
export const HEX_ID_PLACEHOLDERS = Object.freeze(["detector-1", "acc-123", "zone-1", "tok-current"]);

/**
 * Must-keep group for the integrations whose sentences name a 32-hex id: the masked forms survive the scrub
 * alone and inside the sentence that names the resource, beside every canary carrier.
 * @type {MustKeepGroup}
 */
export const MASKED_HEX_ID_GROUP = Object.freeze({
  label: "masked 32-hex ids (round 4 open ruling)",
  values: SERVER_ASSIGNED_HEX_IDS.map((entry) => entry.masked),
  sentence: (value) => SERVER_ASSIGNED_HEX_IDS.find((entry) => entry.masked === value).sentence(value),
});

/**
 * Asserts the scrub side of the 32-hex policy for one redactErrorText: the real id is removed bare and inside
 * the sentence that names its endpoint (no 6-to-24 window survives, and nothing else in the sentence changes),
 * the masked form survives bare and inside the same sentence, and the placeholders survive. `mask`, when given,
 * is the integration's labelIdentifier: it must produce the masked form for the real id, return a placeholder
 * unchanged, and its output must survive the scrub.
 */
export function assertHexIdentifierPolicy(assert, redact, { mask } = {}) {
  for (const { label, id, masked, sentence } of SERVER_ASSIGNED_HEX_IDS) {
    assert.match(id, /^[0-9a-f]{32}$/, `${label}: the fixture id has the real 32-hex shape`);
    assert.equal(redact(id), "[REDACTED]", `${label}: the bare 32-hex id is a hex digest to the scrub`);
    const output = redact(sentence(id));
    assertNoCanaryWindows(assert, output, [id], `${label} inside ${sentence(id)}`);
    assert.equal(output, sentence("[REDACTED]"), `${label}: only the id is removed from the sentence that names it`);
    assert.equal(redact(masked), masked, `${label}: the masked form survives the scrub bare`);
    assert.equal(redact(sentence(masked)), sentence(masked), `${label}: the masked form survives inside the sentence`);
    if (mask) {
      assert.equal(mask(id), masked, `${label}: labelIdentifier masks the real id to its first and last four characters`);
      assert.equal(redact(mask(id)), mask(id), `${label}: the label survives the scrub`);
    }
  }
  for (const placeholder of HEX_ID_PLACEHOLDERS) {
    assert.equal(redact(placeholder), placeholder, `placeholder ${placeholder} is name-shaped and stays`);
    if (mask) assert.equal(mask(placeholder), placeholder, `labelIdentifier keeps the placeholder ${placeholder} whole`);
  }
}

/**
 * Asserts every fixed-text message an integration emits survives the scrub unchanged (GWS note 1). The list
 * is exported by the integration itself and rendered from the same constants and helpers its error sink
 * uses, so a reworded message is judged here without a test copy drifting from the source.
 */
export function assertFixedTextsSurvive(assert, redact, texts, { minimum = 1 } = {}) {
  assert.ok(texts.length >= minimum, `the fixed-text list has at least ${minimum} messages (${texts.length})`);
  assert.equal(new Set(texts).size, texts.length, "fixed texts are distinct");
  for (const text of texts) {
    assert.equal(typeof text, "string", `fixed text is a string: ${String(text)}`);
    assert.ok(text.trim().length > 0, "fixed text is not blank");
    assert.ok(!text.includes("[REDACTED]"), `a fixed text carries no redaction marker of its own: ${text}`);
    assert.equal(redact(text), text, `fixed text survives the scrub: ${text}`);
  }
}
