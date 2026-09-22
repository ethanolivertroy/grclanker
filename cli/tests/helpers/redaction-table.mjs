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
