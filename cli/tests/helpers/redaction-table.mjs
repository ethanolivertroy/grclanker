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
 * Flag and path position (harness revision 3, reviewer #78 row D): a credential-named segment followed by `=` is a
 * pair whatever precedes it (a `--flag`, a `-D` property, a `kv/` path segment, a parenthesis, a comma), `--name
 * value` is a pair whose separator is the space, and `:` after a path segment removes the single-token value,
 * so an endpoint path that ends in a credential word loses the token after its colon (a status code included:
 * the modules join a status to such a path with "returned" or parentheses instead). The text after the value
 * stays in every form. A path segment that is not a credential word (`api-tokens`) and a `--` or `-D` flag whose
 * name is not one (`--timeout`) keep their values. Each row is `[text, expected]`.
 */
export const FLAG_AND_PATH_PAIR_ROWS = Object.freeze([
  ["mysql --password=Sunshine -h db", "mysql --password=[REDACTED] -h db"],
  ["psql --password Sunshine -h db", "psql --password [REDACTED] -h db"],
  ["curl --api-key=prod-key-2026 https://api.example.com/v1", "curl --api-key=[REDACTED] https://api.example.com/v1"],
  ["java -Dspring.datasource.password=Sunshine -jar app.jar", "java -Dspring.datasource.password=[REDACTED] -jar app.jar"],
  ["java -DDB_PASSWORD=Sunshine -jar app.jar", "java -DDB_PASSWORD=[REDACTED] -jar app.jar"],
  ["kv/password: Sunshine", "kv/password: [REDACTED]"],
  ["path/x-auth-key=prod-key-2026 see log", "path/x-auth-key=[REDACTED] see log"],
  ["/client_secret=prod-key-2026", "/client_secret=[REDACTED]"],
  ["GET /_security/api_key: 403 Forbidden", "GET /_security/api_key: [REDACTED] Forbidden"],
  ["POST /tenant/oauth2/v2.0/token: 401 Unauthorized", "POST /tenant/oauth2/v2.0/token: [REDACTED] Unauthorized"],
  ["helm --set db.password=Sunshine upgrade", "helm --set db.password=[REDACTED] upgrade"],
  ["(password=Sunshine)", "(password=[REDACTED])"],
  ["a,password=Sunshine", "a,password=[REDACTED]"],
  ["/api/v1/api-tokens: request failed with 403", "/api/v1/api-tokens: request failed with 403"],
  ["psql --timeout 30 -h db", "psql --timeout 30 -h db"],
  ["java -Dspring.datasource.url=jdbc:postgresql://db/app -jar app.jar", "java -Dspring.datasource.url=jdbc:postgresql://db/app -jar app.jar"],
]);

/** Asserts each flag and path row scrubs to exactly its expected text and that a second pass changes nothing. */
export function assertFlagAndPathPairRows(assert, redact, rows = FLAG_AND_PATH_PAIR_ROWS) {
  for (const [text, expected] of rows) {
    const output = redact(text);
    assert.equal(output, expected, `flag or path pair: ${text}`);
    assert.equal(redact(output), output, `a second pass over ${JSON.stringify(output)} changes nothing`);
  }
}

/**
 * URL userinfo boundary (CodeRabbit on #76 at b0ef16f): the userinfo of the URL rule ends at the first `/`, `?`,
 * or `#` as at whitespace, so an `@` inside a query or a fragment is not a userinfo boundary. Before the fix
 * `https://h?e=a@x.com&token=s3cr3t` read as userinfo `h?e=a@` and host `x.com&token=s3cr3t`, so the query rule
 * never saw the token: the pair rule removed `token=s3cr3t` on its own, while the same query under a benign key
 * (`&v=s3cr3t`, the third row) reached the output whole, and `https://h#f@x.com` read as userinfo `h#f@` and host
 * `x.com`. Each row is `[text, expected]`: the host `h` stays, a query becomes the marker whole, and a fragment
 * is kept. The rows hold for the error sink, the data-string sink, and a snapshot string alike.
 */
export const URL_USERINFO_BOUNDARY_ROWS = Object.freeze([
  ["https://h?e=a@x.com&token=s3cr3t", "https://h?[REDACTED]"],
  ["https://h#f@x.com", "https://h#f@x.com"],
  ["https://h?e=a@x.com&v=s3cr3t", "https://h?[REDACTED]"],
]);

/**
 * Asserts each URL userinfo boundary row scrubs to exactly its expected text, bare and inside a sentence, that a
 * second pass changes nothing, and that no window of the query value survives in any output.
 */
export function assertUrlUserinfoBoundaryRows(assert, redact, { label = "redact", rows = URL_USERINFO_BOUNDARY_ROWS } = {}) {
  const outputs = [];
  for (const [text, expected] of rows) {
    const output = redact(text);
    assert.equal(output, expected, `${label} URL userinfo boundary: ${text}`);
    assert.equal(redact(output), output, `${label}: a second pass over ${JSON.stringify(output)} changes nothing`);
    const sentence = redact(`upstream ${text} rejected the request`);
    assert.equal(sentence, `upstream ${expected} rejected the request`, `${label} URL userinfo boundary inside a sentence: ${text}`);
    outputs.push(output, sentence);
  }
  assertNoCanaryWindows(assert, outputs.join("\n"), ["s3cr3t"], `${label} URL userinfo boundary rows`);
}

/**
 * The bearer-id override to the identifier ruling above (CodeRabbit r4077259415 on #78): a key ending in `secret_id`
 * or `token_id`, any prefix, casing, and separator, holds a Vault AppRole secret id or a token id that is itself the
 * bearer, and a session-id key holds a session token; each authenticates rather than identifies, so it is a
 * credential key despite its `id` suffix and its value is removed whatever its shape, a UUID included. Every key
 * rides every form of credentialPairForms with a UUID, a random, and a name-shaped value; none of the values'
 * 6-to-24 windows occurs in any key, form, or sentence. The `token_id` keys pin the row the modules already
 * implemented (SNAPSHOT_BEARER_ID_KEY_PATTERN and ERROR_CREDENTIAL_WORDS name both suffixes; CodeRabbit on #76).
 */
export const BEARER_ID_KEYS = Object.freeze([
  "secret_id",
  "SECRET_ID",
  "secret-id",
  "VAULT_SECRET_ID",
  "role_secret_id",
  "roleSecretId",
  "vault.secret_id",
  "token_id",
  "TOKEN_ID",
  "tokenId",
  "session_id",
  "sid",
  "sessid",
  "jsessionid",
  "JSESSIONID",
  "PHPSESSID",
]);
export const BEARER_ID_VALUES = Object.freeze(["9b2f6c1e-3d4a-4e5f-8a7b-1c2d3e4f5a6b", "Qv7Lx2Zm9Kp4Rt8W", "prod-approle-2026"]);

/**
 * Controls beside the override: the identifier keys with the same suffixes keep a UUID or a plain value and lose
 * only a value the bare-shape rules remove (an AKIA access key id), `role_id` (the public half of an AppRole) and
 * `secret_name` stay identifiers, and `ssid` is a network name, not a session id.
 */
export const BEARER_ID_CONTROL_ROWS = Object.freeze([
  ["AZURE_TENANT_ID=9b2f6c1e-3d4a-4e5f-8a7b-1c2d3e4f5a6b", "AZURE_TENANT_ID=9b2f6c1e-3d4a-4e5f-8a7b-1c2d3e4f5a6b"],
  ['"AZURE_TENANT_ID": "9b2f6c1e-3d4a-4e5f-8a7b-1c2d3e4f5a6b"', '"AZURE_TENANT_ID": "9b2f6c1e-3d4a-4e5f-8a7b-1c2d3e4f5a6b"'],
  ["client_id=9b2f6c1e-3d4a-4e5f-8a7b-1c2d3e4f5a6b", "client_id=9b2f6c1e-3d4a-4e5f-8a7b-1c2d3e4f5a6b"],
  ["tenant_id: 9b2f6c1e-3d4a-4e5f-8a7b-1c2d3e4f5a6b", "tenant_id: 9b2f6c1e-3d4a-4e5f-8a7b-1c2d3e4f5a6b"],
  ['{"role_id":"9b2f6c1e-3d4a-4e5f-8a7b-1c2d3e4f5a6b"}', '{"role_id":"9b2f6c1e-3d4a-4e5f-8a7b-1c2d3e4f5a6b"}'],
  ["access_key_id=audit-2026", "access_key_id=audit-2026"],
  ["access_key_id=AKIAIOSFODNN7EXAMPLE", "access_key_id=[REDACTED]"],
  ["key_id=alias/aws/ebs", "key_id=alias/aws/ebs"],
  ["secret_name=my-secret", "secret_name=my-secret"],
  ["VAULT_SECRET_NAME=prod-approle-2026", "VAULT_SECRET_NAME=prod-approle-2026"],
  ["ssid=corp-wifi-2026", "ssid=corp-wifi-2026"],
]);
/** The controls a data-string scrub (carriers only, no bare-shape rules) must keep: every row above whose value stays. */
export const BEARER_ID_CARRIER_CONTROL_ROWS = Object.freeze(BEARER_ID_CONTROL_ROWS.filter(([text, expected]) => text === expected));

/**
 * Asserts the bearer-id override on one text scrub: every bearer-id key loses its value in every form whatever
 * the value's shape (through assertCredentialPairValuesRemoved, so only the value goes and a second pass changes
 * nothing), and every control row scrubs to exactly its expected text. A data-string scrub passes
 * BEARER_ID_CARRIER_CONTROL_ROWS as its controls, since it has no bare-shape rule to remove an access key id.
 */
export function assertBearerIdKeyRows(assert, redact, { keys = BEARER_ID_KEYS, values = BEARER_ID_VALUES, controls = BEARER_ID_CONTROL_ROWS } = {}) {
  assertCredentialPairValuesRemoved(assert, redact, { keys, values });
  assertIdentifierKeyRows(assert, redact, controls);
}

/**
 * Asserts the bearer-id override on a snapshot walker: a value under a key ending in `secret_id` or `token_id` is
 * the marker at the top level and nested, while the identifier keys beside it keep their values, whatever the
 * shape of either.
 */
export function assertBearerIdSnapshotKeys(assert, scrubSnapshot, values = BEARER_ID_VALUES) {
  for (const value of values) {
    const identifiers = { AZURE_TENANT_ID: value, client_id: value, tenant_id: value, role_id: value, access_key_id: value, key_id: value, secret_name: value, user_id: value };
    const bearers = { secret_id: value, SECRET_ID: value, VAULT_SECRET_ID: value, role_secret_id: value, roleSecretId: value, token_id: value, TOKEN_ID: value, tokenId: value };
    const output = scrubSnapshot({ ...identifiers, ...bearers, nested: { approle: { ...identifiers, ...bearers } }, list: [{ ...bearers }] });
    for (const record of [output, output.nested.approle, output.list[0]]) {
      for (const key of Object.keys(bearers)) assert.equal(record[key], "[REDACTED]", `snapshot key ${key} holds the marker for ${value}`);
    }
    for (const record of [output, output.nested.approle]) {
      for (const key of Object.keys(identifiers)) assert.equal(record[key], value, `snapshot key ${key} keeps ${value}`);
    }
    assertNoCanaryWindows(assert, JSON.stringify({ bearers: [output.secret_id, output.nested.approle.roleSecretId, output.list[0].VAULT_SECRET_ID] }), [value], `snapshot bearer ids for ${value}`);
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

/** The proofs planted in AUTHORIZATION_PARAMETER_ROWS: lowercase letters only, so only a carrier rule can remove them, and one hex digest. */
const AUTHORIZATION_PROOFS = Object.freeze({
  codeRabbit: "skvclmtirehs",
  snowflake: "pvbxrqzmwltn",
  value: "zrqmxvwbtpln",
  key: "wtqzvxrmblpn",
  response: "wrqzvbnxmlpt",
  nonce: "qxzmvrwbplnt",
  cnonce: "mzvqwrtxbpln",
  opaque: "bnzxqvmrwtlp",
  hexResponse: "4f1c9e2a7b3d8f6e5a0c1b2d3e4f5a6b",
  oauthToken: "vqzxrwmbntlp",
  oauthSignature: "xzqvrmwbltpn",
  oauthNonce: "rwmbqzxvtlpn",
});
const DIGEST_HEAD = 'Authorization: Digest username="Mufasa", realm="testrealm@host.com"';
const OAUTH_HEAD = 'Authorization: OAuth oauth_consumer_key="audit-client"';
const DIGEST_TAIL = 'uri="/dir/index.html", qop=auth, nc=00000001';
const OAUTH_TAIL = 'oauth_signature_method="HMAC-SHA1", oauth_version="1.0"';

/**
 * Authorization parameter lists (CodeRabbit on #81, discussion_r4081238237, probed on #76): under an Authorization
 * or Proxy-Authorization header a scheme word may be followed by `name=value` parameters, and the value of every
 * parameter that is a proof is removed whatever its name, quoted or bare: `Snowflake Token="..."`, any `<Scheme>
 * <name>="..."` shape, Digest's `response`, `nonce`, `cnonce`, and `opaque`, OAuth 1.0's `oauth_token`,
 * `oauth_signature`, and `oauth_nonce`. The parameters that describe the exchange stay: `realm`, `username`, `uri`,
 * `qop`, `nc`, `algorithm`, `oauth_consumer_key` (a client identifier, judged by its own shape like `client_id`),
 * `oauth_signature_method`, `oauth_version`, and SigV4's scope and signed headers. A WWW-Authenticate challenge is
 * not an Authorization header, so its `realm="api"` stays with the rest of it, as does `Bearer realm="api"` in prose;
 * a header value quoted whole (a JSON header object) is removed whole by the quoted-value rule as before. Before the
 * fix a quoted value under a parameter name that is no credential word (`response`, `value`) survived on every sink,
 * and a `name=` of four or eight characters (`key=`, `uri=`) read as base64 padding, so the marker replaced the name
 * and the quoted value survived. Each row is `[text, expected]`; the rows hold for the error sink, the data-string
 * sink, and a snapshot string alike, bare, inside a sentence, after a JSON escape, and inside a JSON string.
 */
export const AUTHORIZATION_PARAMETER_ROWS = Object.freeze([
  [`Authorization: Snowflake Token="${AUTHORIZATION_PROOFS.codeRabbit}"`, 'Authorization: Snowflake Token="[REDACTED]"'],
  [`proxy-authorization: snowflake token='${AUTHORIZATION_PROOFS.snowflake}'`, "proxy-authorization: snowflake token='[REDACTED]'"],
  [`Authorization: Bearer value="${AUTHORIZATION_PROOFS.value}"`, 'Authorization: Bearer value="[REDACTED]"'],
  [`Authorization: Bearer key="${AUTHORIZATION_PROOFS.key}"`, 'Authorization: Bearer key="[REDACTED]"'],
  [`Authorization: Digest response=${AUTHORIZATION_PROOFS.response}`, "Authorization: Digest response=[REDACTED]"],
  [`Authorization: Digest response="${AUTHORIZATION_PROOFS.response}"`, 'Authorization: Digest response="[REDACTED]"'],
  [`Authorization: Digest nonce="${AUTHORIZATION_PROOFS.nonce}"`, 'Authorization: Digest nonce="[REDACTED]"'],
  [
    `${DIGEST_HEAD}, nonce="${AUTHORIZATION_PROOFS.nonce}", ${DIGEST_TAIL}, cnonce="${AUTHORIZATION_PROOFS.cnonce}", response="${AUTHORIZATION_PROOFS.response}", opaque="${AUTHORIZATION_PROOFS.opaque}"`,
    `${DIGEST_HEAD}, nonce="[REDACTED]", ${DIGEST_TAIL}, cnonce="[REDACTED]", response="[REDACTED]", opaque="[REDACTED]"`,
  ],
  [`${DIGEST_HEAD}, uri="/dir/index.html", response="${AUTHORIZATION_PROOFS.hexResponse}"`, `${DIGEST_HEAD}, uri="/dir/index.html", response="[REDACTED]"`],
  [
    `${OAUTH_HEAD}, oauth_token="${AUTHORIZATION_PROOFS.oauthToken}", ${OAUTH_TAIL}, oauth_signature="${AUTHORIZATION_PROOFS.oauthSignature}", oauth_nonce="${AUTHORIZATION_PROOFS.oauthNonce}"`,
    `${OAUTH_HEAD}, oauth_token="[REDACTED]", ${OAUTH_TAIL}, oauth_signature="[REDACTED]", oauth_nonce="[REDACTED]"`,
  ],
  [
    `Authorization: AWS4-HMAC-SHA256 Credential=${SIGV4_KEY_ID}/20260922/us-east-1/sts/aws4_request, SignedHeaders=host;x-amz-date, Signature=${SIGV4_SIGNATURE}`,
    "Authorization: AWS4-HMAC-SHA256 Credential=[REDACTED]/20260922/us-east-1/sts/aws4_request, SignedHeaders=host;x-amz-date, Signature=[REDACTED]",
  ],
  [JSON.stringify({ headers: { Authorization: `Digest response="${AUTHORIZATION_PROOFS.response}"` } }), '{"headers":{"Authorization":"Digest [REDACTED]"}}'],
  ['WWW-Authenticate: Bearer realm="api", error="invalid_token", error_description="The access token expired"', 'WWW-Authenticate: Bearer realm="api", error="invalid_token", error_description="The access token expired"'],
  ['WWW-Authenticate: Digest realm="api", qop="auth", algorithm=SHA-256', 'WWW-Authenticate: Digest realm="api", qop="auth", algorithm=SHA-256'],
  ['The server answered 401 with Bearer realm="api" and no token.', 'The server answered 401 with Bearer realm="api" and no token.'],
]);

/** The values that must not survive any AUTHORIZATION_PARAMETER_ROWS output, by 6-to-24 windows. */
export const AUTHORIZATION_PROOF_VALUES = Object.freeze([...Object.values(AUTHORIZATION_PROOFS), SIGV4_KEY_ID, SIGV4_SIGNATURE]);

/** The proofs planted in CHALLENGE_PROOF_ROWS: non-hex and name-shaped (lowercase letters, one hyphenated), so only a carrier rule can remove them. */
const CHALLENGE_PROOFS = Object.freeze({
  challenge: "hwzqtnvxrblm",
  data: "ltrqzvwmbxnp",
  prose: "vbnqxzrwtlmp",
  sig: "ptzrqwvxnbml",
  signature: "nxqvzrltwbmp",
  oauthSignature: "rzqvtwxnblmp",
  mac: "wxzqrtvnblpm",
  macScheme: "zqvnrtwxlbmp",
  unquoted: "bqzrvtwxnlmp",
  singleQuoted: "mxzqrvtwnblp",
  first: "qwzrvtxnblmp",
  hyphenated: "rzqwt-vxnbl-mpqz",
  token: "xzqrvwtnblmp",
  header: "tzqrvwxnblmp",
});

/**
 * Challenge proofs (CodeRabbit on #81, discussion_r4081776771, probed on #76): a parameter list that is not under an
 * Authorization key, a WWW-Authenticate or Proxy-Authenticate challenge, a scheme word and its parameters in prose,
 * or a bare realm-led data value such as `realm="api", nonce="n", response="..."`, is not exempt from the proof
 * rule because it is shaped like a challenge: the value of a parameter named as a proof (`response`, `signature`,
 * `oauth_signature`, `mac`, `sig`) goes, quoted at any depth or bare, before or after the `realm`, while the
 * parameters that describe the challenge (`realm`, `qop`, `algorithm`, `error`, `error_description`, `id`, `ts`)
 * keep their values, so a proof-free challenge passes unchanged. A `nonce` is a credential word since #64, so
 * `nonce="n"` reads `nonce="[REDACTED]"` in a challenge as in an Authorization header; the rows pin that rendering
 * as it stands. A list with neither a `realm` nor a scheme word before it is data (`response="ok", status="done"`),
 * as is a `response` or `mac` field outside a parameter list (`"response": 403`, `mac=aa:bb:cc:dd:ee:ff`). Before
 * the fix the `response` and `mac` values survived on every sink in every form (`sig`, `signature`, and
 * `oauth_signature` are credential words and went already). Each row is `[text, expected]`; the rows hold for the
 * error sink, the data-string sink, and a snapshot string alike, bare, inside a sentence, after a JSON escape, and
 * inside a JSON string.
 */
export const CHALLENGE_PROOF_ROWS = Object.freeze([
  [`WWW-Authenticate: Digest realm="api", nonce="n", response="${CHALLENGE_PROOFS.challenge}"`, 'WWW-Authenticate: Digest realm="api", nonce="[REDACTED]", response="[REDACTED]"'],
  [`realm="api", nonce="n", response="${CHALLENGE_PROOFS.data}"`, 'realm="api", nonce="[REDACTED]", response="[REDACTED]"'],
  [`Digest realm="api", nonce="n", response="${CHALLENGE_PROOFS.prose}"`, 'Digest realm="api", nonce="[REDACTED]", response="[REDACTED]"'],
  [`realm="api", sig="${CHALLENGE_PROOFS.sig}"`, 'realm="api", sig="[REDACTED]"'],
  [`realm="api", signature="${CHALLENGE_PROOFS.signature}"`, 'realm="api", signature="[REDACTED]"'],
  [`realm="api", oauth_signature="${CHALLENGE_PROOFS.oauthSignature}"`, 'realm="api", oauth_signature="[REDACTED]"'],
  [`realm="api", mac="${CHALLENGE_PROOFS.mac}"`, 'realm="api", mac="[REDACTED]"'],
  [
    `WWW-Authenticate: MAC realm="api", id="h480djs93hd8", ts="1336363200", mac="${CHALLENGE_PROOFS.macScheme}"`,
    'WWW-Authenticate: MAC realm="api", id="h480djs93hd8", ts="1336363200", mac="[REDACTED]"',
  ],
  [`WWW-Authenticate: Digest realm=api, nonce=n, response=${CHALLENGE_PROOFS.unquoted}`, "WWW-Authenticate: Digest realm=api, nonce=[REDACTED], response=[REDACTED]"],
  [`WWW-Authenticate: Digest realm='api', response='${CHALLENGE_PROOFS.singleQuoted}'`, "WWW-Authenticate: Digest realm='api', response='[REDACTED]'"],
  [`WWW-Authenticate: Digest realm="api", response="${CHALLENGE_PROOFS.hyphenated}"`, 'WWW-Authenticate: Digest realm="api", response="[REDACTED]"'],
  [JSON.stringify({ "WWW-Authenticate": `Digest realm="api", response="${CHALLENGE_PROOFS.header}"` }), '{"WWW-Authenticate":"Digest realm=\\"api\\", response=\\"[REDACTED]\\""}'],
  [`response="${CHALLENGE_PROOFS.first}", realm="api"`, 'response="[REDACTED]", realm="api"'],
  [`Token realm="api", response="${CHALLENGE_PROOFS.token}"`, 'Token realm="api", response="[REDACTED]"'],
  [
    `WWW-Authenticate: Bearer realm="api", error="invalid_token", signature="${CHALLENGE_PROOFS.signature}"`,
    'WWW-Authenticate: Bearer realm="api", error="invalid_token", signature="[REDACTED]"',
  ],
  ['WWW-Authenticate: Bearer realm="api"', 'WWW-Authenticate: Bearer realm="api"'],
  ['Digest realm="api", qop="auth", nonce="n"', 'Digest realm="api", qop="auth", nonce="[REDACTED]"'],
  [
    'WWW-Authenticate: Bearer realm="api", error_description="the response signature did not verify"',
    'WWW-Authenticate: Bearer realm="api", error_description="the response signature did not verify"',
  ],
  ['WWW-Authenticate: OAuth realm="api", oauth_problem="signature_invalid"', 'WWW-Authenticate: OAuth realm="api", oauth_problem="signature_invalid"'],
  ['{"response": 403, "mac": "aa:bb:cc:dd:ee:ff"}', '{"response": 403, "mac": "aa:bb:cc:dd:ee:ff"}'],
  ["interface eth0 mac=aa:bb:cc:dd:ee:ff response=200 in 12ms", "interface eth0 mac=aa:bb:cc:dd:ee:ff response=200 in 12ms"],
  ['response="ok", status="done"', 'response="ok", status="done"'],
  ['realm="api" was offered; the response body follows', 'realm="api" was offered; the response body follows'],
]);

/** The values that must not survive any CHALLENGE_PROOF_ROWS output, by 6-to-24 windows. */
export const CHALLENGE_PROOF_VALUES = Object.freeze(Object.values(CHALLENGE_PROOFS));

/** One JSON escape of `text` without the enclosing quotes, so a header line reads as the tail of a serialized message. */
function jsonEscaped(text) {
  return JSON.stringify(text).slice(1, -1);
}

/**
 * Asserts each `[text, expected]` row scrubs to exactly its expected text bare, inside a sentence with a
 * parenthesis after it, after a JSON escape, and inside a JSON string (the expectation is the escape or the
 * serialization of the plain expectation, so the form changes nothing), that a second pass over every output
 * changes nothing, and that no window of any planted proof survives in any output.
 */
function assertParameterRows(assert, redact, { label, rows, subject, rowsLabel, proofValues }) {
  const outputs = [];
  for (const [text, expected] of rows) {
    const forms = [
      ["bare", text, expected],
      ["inside a sentence", `upstream rejected the request (${text}) and returned 401 Unauthorized`, `upstream rejected the request (${expected}) and returned 401 Unauthorized`],
      ["after a JSON escape", `Request failed\\n${jsonEscaped(text)}\\nRetry later`, `Request failed\\n${jsonEscaped(expected)}\\nRetry later`],
      ["inside a JSON string", JSON.stringify({ code: "Unauthorized", message: `rejected ${text}` }), JSON.stringify({ code: "Unauthorized", message: `rejected ${expected}` })],
    ];
    for (const [form, input, expectedOutput] of forms) {
      const output = redact(input);
      assert.equal(output, expectedOutput, `${label} ${subject}, ${form}: ${text}`);
      assert.equal(redact(output), output, `${label}, ${form}: a second pass over ${JSON.stringify(output)} changes nothing`);
      outputs.push(output);
    }
  }
  assertNoCanaryWindows(assert, outputs.join("\n"), proofValues, `${label} ${rowsLabel}`);
}

/** The Authorization parameter rows (AUTHORIZATION_PARAMETER_ROWS) through assertParameterRows. */
export function assertAuthorizationParameterRows(assert, redact, { label = "redact", rows = AUTHORIZATION_PARAMETER_ROWS } = {}) {
  assertParameterRows(assert, redact, { label, rows, subject: "Authorization parameters", rowsLabel: "Authorization parameter rows", proofValues: AUTHORIZATION_PROOF_VALUES });
}

/** The challenge proof rows (CHALLENGE_PROOF_ROWS) through assertParameterRows. */
export function assertChallengeProofRows(assert, redact, { label = "redact", rows = CHALLENGE_PROOF_ROWS } = {}) {
  assertParameterRows(assert, redact, { label, rows, subject: "challenge parameters", rowsLabel: "challenge proof rows", proofValues: CHALLENGE_PROOF_VALUES });
}

/**
 * reviewer D round 5 depth control. The data walkers removed a credential-keyed value at every depth but left a
 * carrier inside a benign-keyed string untouched at every depth, and the AAP settings API returns arbitrary
 * nested values, so a bearer inside a nested setting reached core_data. The rule has two halves: every string a
 * snapshot keeps passes the data-side carrier scrub at every depth, in place, with its siblings kept; and an
 * object or array nested past the cap becomes the marker. The canaries' 6-windows occur in no fixture.
 */
export const DEPTH_CONTROL = Object.freeze({
  cap: 32,
  levels: 40,
  keyedCanary: "Qv7Tz3Km9Rb2Wn5Xp8Lc4Hd6Jf1Gs",
  carrierCanary: "Yt3Rq8Zm2Vk7Lp4Nx9Wc6Hb1Jd5Fs",
});

/**
 * Reviewer D's 40-deep tree: each level `{ level, note, secret_key, detail, quoted, child }`, the keyed value
 * under `secret_key`, a bearer carrier under the benign key `detail`, and the quoted name-shaped bearer under
 * `quoted`. Level 1 is the value returned; level k sits k - 1 containers below it.
 */
export function deepProbeTree({ levels = DEPTH_CONTROL.levels, keyedCanary = DEPTH_CONTROL.keyedCanary, carrierCanary = DEPTH_CONTROL.carrierCanary } = {}) {
  let child;
  for (let level = levels; level >= 1; level -= 1) {
    child = {
      level,
      note: `benign-note-${level}`,
      secret_key: `SK_${keyedCanary}`,
      detail: `Authorization: Bearer ${carrierCanary}`,
      quoted: 'token was "Bearer prod-token"',
      ...(child === undefined ? {} : { child }),
    };
  }
  return child;
}

/** The canaries the depth tree plants, for a windowed scan of any output that might carry it. */
export const DEPTH_CONTROL_CANARIES = Object.freeze([DEPTH_CONTROL.keyedCanary, DEPTH_CONTROL.carrierCanary]);

/**
 * Asserts both halves on one walker: `walk(tree)` returns the tree as the walker leaves it. `rootDepth` is the
 * depth the walker assigns to level 1 (1 when the tree is the value handed to it, 2 when it is wrapped in a list
 * or a record first). At every level up to the cap the container keeps its shape and its benign sibling, the
 * credential-keyed value is the marker in place, and both carrier strings are scrubbed in place; the first level
 * past the cap is the marker; no 6-to-24 window of either canary survives anywhere in the output. Returns the
 * number of levels found in place.
 */
export function assertDepthControl(assert, walk, { label, rootDepth = 1, cap = DEPTH_CONTROL.cap, levels = DEPTH_CONTROL.levels, marker = "[REDACTED]" } = {}) {
  return assertWalkedTree(assert, walk(deepProbeTree({ levels })), { label, rootDepth, cap, levels, marker });
}

/**
 * Asserts both halves on a walked tree whose level 1 sits at `rootDepth`: every level up to the cap is in place
 * (shape, benign sibling, keyed value the marker, both carriers scrubbed, exactly its keys), the first level past
 * the cap is the marker, and no 6-to-24 window of either canary survives. Returns the number of levels in place.
 */
export function assertWalkedTree(assert, output, { label, rootDepth = 1, cap = DEPTH_CONTROL.cap, levels = DEPTH_CONTROL.levels, marker = "[REDACTED]" }) {
  const inPlace = cap - rootDepth + 1;
  assert.ok(inPlace >= 1 && inPlace < levels, `${label}: the tree reaches past the cap (${inPlace} levels in place from depth ${rootDepth})`);
  let node = output;
  for (let level = 1; level <= inPlace; level += 1) {
    assert.equal(typeof node, "object", `${label}: level ${level} (depth ${level + rootDepth - 1}) keeps its shape`);
    assert.equal(node.level, level, `${label}: level ${level} is the level it was`);
    assert.equal(node.note, `benign-note-${level}`, `${label}: level ${level} keeps its benign sibling`);
    assert.equal(node.secret_key, marker, `${label}: level ${level} removes the credential-keyed value in place`);
    assert.equal(node.detail, "Authorization: Bearer [REDACTED]", `${label}: level ${level} scrubs the bearer carrier in the benign-keyed string in place`);
    assert.equal(node.quoted, 'token was "Bearer [REDACTED]"', `${label}: level ${level} scrubs the quoted name-shaped bearer in place`);
    assert.deepEqual(Object.keys(node).sort(), ["child", "detail", "level", "note", "quoted", "secret_key"], `${label}: level ${level} keeps exactly its keys`);
    node = node.child;
  }
  assert.equal(node, marker, `${label}: level ${inPlace + 1} (depth ${cap + 1}, past the cap) is the marker`);
  assertNoCanaryWindows(assert, JSON.stringify(output), DEPTH_CONTROL_CANARIES, `${label}: the walked tree`);
  return inPlace;
}

/** Every planted tree in a parsed document with the depth of its level 1 (the document's root is depth 1) and its path. */
export function findPlantedTrees(value, key = "x_deep_probe", depth = 1, path = "$") {
  if (value === null || typeof value !== "object") return [];
  if (Array.isArray(value)) return value.flatMap((entry, index) => findPlantedTrees(entry, key, depth + 1, `${path}[${index}]`));
  const found = [];
  for (const [name, entry] of Object.entries(value)) {
    if (name === key) found.push({ path: `${path}.${name}`, depth: depth + 1, tree: entry });
    else found.push(...findPlantedTrees(entry, key, depth + 1, `${path}.${name}`));
  }
  return found;
}

/**
 * Identifier shapes a snapshot names its resources by; the data-side scrub keeps every one bare and beside a label.
 * An AWS role unique id (`AROA...`) is a resource identifier and stays; an access key id (`AKIA...`) is a
 * credential's own id and goes (SNAPSHOT_VENDOR_TOKEN_ROWS).
 */
export const SNAPSHOT_IDENTIFIER_ROWS = Object.freeze([
  "4f1c2f7a9b3d4e5f8a7b6c5d4e3f2a1b",
  "62e90394-69f5-4237-9190-012177145e10",
  "arn:aws:iam::123456789012:role/Deploy",
  "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "AROAEXAMPLE000000001:session-name",
  "AIDAEXAMPLE000000001",
  "https://aap.example.com/api/v2/hosts/",
]);

/**
 * Vendor-prefixed token shapes (harness revision 3, class 6): the prefix names the token type, so the value goes
 * from a snapshot string as from error text, whatever key carries it. Each is `[text, expected]`; the AWS
 * access key id is the fixture id AWS evidence masks.
 */
export const SNAPSHOT_VENDOR_TOKEN_ROWS = Object.freeze([
  ["AKIAEXAMPLE000000001", "[REDACTED]"],
  ["ASIAEXAMPLE000000001", "[REDACTED]"],
  ["sk_live_EXAMPLE0000000000000001", "[REDACTED]"],
  ["ghp_EXAMPLE00000000000000000000000001", "[REDACTED]"],
  ["xoxb-1234567890-1234567890123-EXAMPLE0000000001", "[REDACTED]"],
]);

/**
 * The data-side string scrub (redactCarrierText): a value is removed for what carries it, an identifier stays for
 * what it is. Carriers: a header line, an authorization scheme, a cookie, URL userinfo and query, a credential-named
 * pair, a quoted scheme phrase, and the configured secret when one is given. Kept: the identifier rows above, since
 * a snapshot names its resources by them and the bare-shape rules belong to error text only.
 */
export function assertCarrierTextScrub(assert, redact, { label = "redactCarrierText", configuredSecret } = {}) {
  const canary = DEPTH_CONTROL.carrierCanary;
  const cases = [
    [`Authorization: Bearer ${canary}`, "Authorization: Bearer [REDACTED]"],
    [`X-Auth-Key: ${canary}`, "X-Auth-Key: [REDACTED]"],
    [`Cookie: sid=${canary}; theme=dark`, "Cookie: [REDACTED]"],
    [`https://user:${canary}@example.com/api/?token=${canary}`, "https://example.com/api/?[REDACTED]"],
    [`password=${canary}`, "password=[REDACTED]"],
    [`"api_key": "${canary}"`, '"api_key": "[REDACTED]"'],
    ['token was "Bearer prod-token"', 'token was "Bearer [REDACTED]"'],
    [`Basic ${canary}==`, "Basic [REDACTED]"],
    ...(configuredSecret ? [[`note: ${configuredSecret}`, "note: [REDACTED]"]] : []),
  ];
  for (const [text, expected] of cases) {
    assert.equal(redact(text), expected, `${label} removes the carried value: ${text}`);
    assert.equal(redact(expected), expected, `${label} is idempotent: ${expected}`);
  }
  for (const row of SNAPSHOT_IDENTIFIER_ROWS) {
    assert.equal(redact(row), row, `${label} keeps the identifier bare: ${row}`);
    assert.equal(redact(`resource ${row} read`), `resource ${row} read`, `${label} keeps the identifier in a sentence: ${row}`);
  }
  for (const [text, expected] of SNAPSHOT_VENDOR_TOKEN_ROWS) {
    assert.equal(redact(text), expected, `${label} removes the vendor-prefixed token bare: ${text}`);
    assert.equal(redact(`note: key ${text} end`), `note: key ${expected} end`, `${label} removes the vendor-prefixed token in a sentence: ${text}`);
  }
  assertNoCanaryWindows(assert, cases.map(([text]) => redact(text)).join("\n"), [canary], `${label} cases`);
}

/**
 * Plants the depth tree as `key` on an object and on every object nested up to `maxDepth` containers below it (a
 * page's records and their nested records), the way reviewer D's probe plants it, in place; returns the number of
 * objects planted into. The tree itself is never planted into.
 */
export function plantDeepProbe(container, { key = "x_deep_probe", depth = 0, maxDepth = 3 } = {}) {
  if (depth > maxDepth || container === null || typeof container !== "object") return 0;
  if (Array.isArray(container)) return container.reduce((count, entry) => count + plantDeepProbe(entry, { key, depth: depth + 1, maxDepth }), 0);
  let count = 1;
  for (const value of Object.values(container)) count += plantDeepProbe(value, { key, depth: depth + 1, maxDepth });
  container[key] = deepProbeTree();
  return count;
}

/**
 * Wraps a fixture's routes so every JSON response carries the depth tree on its body and in every record and
 * nested record (plantDeepProbe); `skip` lists paths left alone (a token endpoint). Non-JSON responses pass
 * through. `planted` counts the objects planted into, so a test can prove the fixture carried the tree.
 */
export function withPlantedRoutes(routes, { key = "x_deep_probe", skip = [], planted = { count: 0 } } = {}) {
  const wrapped = {};
  for (const [path, route] of Object.entries(routes)) {
    wrapped[path] = skip.includes(path)
      ? route
      : async (...args) => {
          const response = await route(...args);
          const text = await response.text();
          const init = { status: response.status, statusText: response.statusText, headers: response.headers };
          let body;
          try {
            body = JSON.parse(text);
          } catch {
            return new Response(text, init);
          }
          planted.count += plantDeepProbe(body, { key });
          return new Response(JSON.stringify(body), init);
        };
  }
  return wrapped;
}

/**
 * AWS: an unknown output member is dropped by the SDK's typed deserializer, so the tree travels inside the two
 * policy documents the code parses (iam:GetPolicyVersion `Document`, URL-encoded, and s3:GetBucketPolicy
 * `Policy`) as a statement whose `Sid` carries the bearer, whose `Condition` carries the quoted name-shaped bearer
 * and the tree, both real string positions in a policy. Returns the document text with the statement added.
 */
export function plantDeepProbeInPolicyDocument(text, { encoded = false } = {}) {
  const document = JSON.parse(encoded ? decodeURIComponent(text) : text);
  const statements = Array.isArray(document.Statement) ? document.Statement : document.Statement === undefined ? [] : [document.Statement];
  statements.push({
    Sid: `Authorization: Bearer ${DEPTH_CONTROL.carrierCanary}`,
    Effect: "Deny",
    Action: "s3:DeleteBucket",
    Resource: "*",
    Condition: { StringEquals: { "aws:PrincipalTag/note": 'token was "Bearer prod-token"', x_deep_probe: deepProbeTree() } },
  });
  const planted = JSON.stringify({ ...document, Statement: statements });
  return encoded ? encodeURIComponent(planted) : planted;
}

/**
 * Asserts the end-to-end half on a bundle: no 6-to-24 window of either depth canary in any file, zip entry, or
 * serialized output, and no name-shaped bearer either. With `treeExpected` false, no trace of the planted tree
 * (`benign-note-`) anywhere, since the integration's documented-field projection drops an unknown member before it
 * is written. With `treeExpected` true, every planted tree in every JSON file and zip entry is judged where it
 * stands: the file's root is depth 1, so a tree whose level 1 sits at depth d keeps levels 1 to cap - d + 1 in
 * place (note kept, keyed value the marker, both carriers scrubbed) and its next level is the marker. Returns
 * the names of the files and zip entries carrying the tree.
 */
export function assertDepthControlOutputs(assert, { files, zipEntries, outputs = [] }, { label, treeExpected, cap = DEPTH_CONTROL.cap, marker = "[REDACTED]", key = "x_deep_probe" }) {
  assertNoCanaryWindows(assert, [...files.values()].join("\n"), DEPTH_CONTROL_CANARIES, `${label} bundle files`);
  assertNoCanaryWindows(assert, [...zipEntries.values()].join("\n"), DEPTH_CONTROL_CANARIES, `${label} zip entries`);
  for (const output of outputs) assertNoCanaryWindows(assert, JSON.stringify(output), DEPTH_CONTROL_CANARIES, `${label} output`);
  const everything = [...[...files].map(([name, text]) => [`file ${name}`, text]), ...[...zipEntries].map(([name, text]) => [`zip ${name}`, text])];
  for (const [name, text] of everything) assert.ok(!text.includes("Bearer prod-token"), `${label}: ${name} carries no quoted name-shaped bearer`);
  for (const output of outputs) assert.ok(!JSON.stringify(output).includes("Bearer prod-token"), `${label}: no output carries the quoted name-shaped bearer`);
  if (!treeExpected) {
    for (const [name, text] of everything) assert.ok(!text.includes("benign-note-"), `${label}: ${name} carries no trace of the planted tree (dropped by projection)`);
    for (const output of outputs) assert.ok(!JSON.stringify(output).includes("benign-note-"), `${label}: no output carries the planted tree`);
    return [];
  }
  const carrying = [];
  for (const [name, text] of everything) {
    if (!text.includes("benign-note-")) continue;
    let document;
    try {
      document = JSON.parse(text);
    } catch {
      assert.fail(`${label}: ${name} carries the planted tree but is not a JSON document`);
    }
    const trees = findPlantedTrees(document, key);
    assert.ok(trees.length > 0, `${label}: ${name} carries the tree under its planted key`);
    for (const { path, depth, tree } of trees) assertWalkedTree(assert, tree, { label: `${label} ${name} at ${path}`, rootDepth: depth, cap, marker });
    carrying.push(name);
  }
  assert.ok(carrying.length > 0, `${label}: at least one written file carries the planted tree`);
  return carrying;
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
