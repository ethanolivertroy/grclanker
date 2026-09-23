import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  IntegrationError,
  describeErrorBody,
  describeFailedResponse,
  errorMessage,
  redactSecretValues,
  scrubDataText,
  scrubError,
  scrubErrorText,
} from "../dist/extensions/grc-tools/hardening/error-text.js";
import { NextLinkError, nextLinkStop, resolveSameOriginUrl } from "../dist/extensions/grc-tools/hardening/next-link.js";
import { describePagination } from "../dist/extensions/grc-tools/hardening/pagination.js";
import { datasetState, derived, gatedPrincipals, isComplete, isReadable, readDataset, seenVersusTotal, unreadableDataset } from "../dist/extensions/grc-tools/hardening/collection-status.js";
import {
  BEARER_ID_KEYS,
  FIXED_PASSWORDS,
  FIXED_SCHEME_WORDS,
  GENERIC_CREDENTIAL_KEYS,
  INFORMATIONAL_ESCAPE_FORMS,
  LEAK_CLASSES,
  SESSION_ID_KEYS,
  SETTING_SUFFIX_CONTROLS,
  SETTING_SUFFIX_UUID_CONTROL_KEYS,
  VENDOR_ENV_KEYS,
  assertCanariesDisjoint,
  assertNoLeaks,
  leakedWindow,
  makeCanaries,
  recordingFetch,
  runLeakProbe,
} from "./helpers/leak-probe-harness.mjs";

/**
 * The shared leak-probe harness (method change of 22:25 UTC): its self-tests, and its first
 * adopter, the shared `hardening/` library. The self-tests pin that every row detects its planted
 * value against an identity scrubber, that every must-keep row passes an identity scrubber, that
 * the canary self-check rejects a colliding canary, that the runner classes catch a follower, a
 * flipping collector, and a raw-writing export, and that the class 1 bearer-id row detects the
 * setting-suffix exemption without its override (CodeRabbit r4077259415 on #78 `e848385`), and that
 * the informational rows (percent-encoded and JavaScript hex line breaks, non-gating by the
 * principal's ruling) are counted in the report without ever failing `assertNoLeaks`, and that
 * class 8 flags a userinfo-bearing request on the configured origin, an unparseable request, and a
 * userinfo-stripped follow of a rejected link (CodeRabbit 5286122785 on #78 `8b92f20`), wants the
 * rejected origin named in a refusal note, and catches an uppercase-scheme link fetched as a relative
 * path (group D self-check, revision 3). The library run wires every entry point the library exposes
 * and must report zero leaks.
 */

const identity = (text) => text;
const IDENTITY_SINKS = Object.freeze({ error: [{ name: "identity", fn: identity }], data: [{ name: "identity-data", fn: identity }] });

const USERS = Object.freeze([
  Object.freeze({ name: "ursula.quill", mfa: true }),
  Object.freeze({ name: "umberto.reyes", mfa: true }),
  Object.freeze({ name: "ulrich.stone", mfa: false }),
]);
const ROLES = Object.freeze([
  Object.freeze({ name: "rhea.adminson", role: "admin" }),
  Object.freeze({ name: "rowan.operator", role: "operator" }),
]);
const MODEL_INVENTORIES = Object.freeze(["users", "roles"]);

function datasetFor(records, inventory, target, mode, endpoint) {
  if (inventory !== target || mode === "baseline") return readDataset([...records], { total: records.length, status: 200, endpoint });
  switch (mode) {
    case "zero-rows-truncated":
      return readDataset([], { truncated: true, total: records.length, status: 200, endpoint });
    case "capped":
      return readDataset(records.slice(0, 1), { truncated: true, total: records.length, status: 200, endpoint });
    case "denied":
      return unreadableDataset(scrubErrorText(`GET ${endpoint} failed with 403 Forbidden: JSON body without a documented message field (42 bytes)`), { status: 403, endpoint });
    default:
      throw new Error(`unknown mode ${mode}`);
  }
}

function summaryOf(dataset) {
  return {
    state: datasetState(dataset),
    count: derived(dataset.items.length, dataset),
    seen: isReadable(dataset) && !isComplete(dataset) ? seenVersusTotal(dataset.items.length, dataset.total) : null,
    status: dataset.status,
    error: dataset.error,
  };
}

/** A collector built on the collection-status helpers: the shape every integration's findings must take under a partial read. */
function modelTruncationRunner({ inventory, mode }) {
  const users = datasetFor(USERS, inventory, "users", mode, "/api/v2/users");
  const roles = datasetFor(ROLES, inventory, "roles", mode, "/api/v2/roles");
  const withoutMfa = users.items.filter((user) => !user.mfa);
  const admins = roles.items.filter((role) => role.role === "admin");
  const findings = [
    {
      id: "USERS-MFA",
      status: isComplete(users) ? (withoutMfa.length === 0 ? "pass" : "fail") : "not_evaluated",
      summary: isComplete(users) ? `${withoutMfa.length} of ${users.items.length} users lack MFA` : `users inventory ${datasetState(users)}: ${users.error ?? seenVersusTotal(users.items.length, users.total)}`,
      evidence: {
        users_total: derived(users.items.length, users),
        without_mfa: derived(withoutMfa.length, users),
        ...gatedPrincipals({ users_without_mfa: withoutMfa.map((user) => user.name) }, isComplete(users), [`users ${datasetState(users)}`]),
      },
    },
    {
      id: "ROLES-ADMIN",
      status: isComplete(roles) ? (admins.length <= 1 ? "pass" : "fail") : "not_evaluated",
      summary: isComplete(roles) ? `${admins.length} admin role holders` : `roles inventory ${datasetState(roles)}: ${roles.error ?? seenVersusTotal(roles.items.length, roles.total)}`,
      evidence: {
        admins: derived(admins.length, roles),
        ...gatedPrincipals({ admin_principals: admins.map((role) => role.name) }, isComplete(roles), [`roles ${datasetState(roles)}`]),
      },
    },
    { id: "STATIC-01", status: "pass", summary: "the static control reads no inventory", evidence: {} },
  ];
  const summaries = { users: summaryOf(users), roles: summaryOf(roles) };
  const principals = inventory === "users" ? USERS.map((user) => user.name) : inventory === "roles" ? ROLES.map((role) => role.name) : [];
  return { findings, summaries, principals };
}

/** The same collector without the helpers: statuses and counts computed from whatever rows arrived. */
function flawedTruncationRunner({ inventory, mode }) {
  const users = datasetFor(USERS, inventory, "users", mode, "/api/v2/users");
  const roles = datasetFor(ROLES, inventory, "roles", mode, "/api/v2/roles");
  const withoutMfa = users.items.filter((user) => !user.mfa);
  const admins = roles.items.filter((role) => role.role === "admin");
  const findings = [
    { id: "USERS-MFA", status: withoutMfa.length === 0 ? "pass" : "fail", summary: `${withoutMfa.length} users lack MFA`, evidence: { users_total: users.items.length, users_without_mfa: withoutMfa.map((user) => user.name) } },
    { id: "USERS-COUNT", status: users.items.length >= 3 ? "pass" : "fail", summary: `${users.items.length} users`, evidence: { complete: users.items.length >= 3 } },
    { id: "ROLES-ADMIN", status: admins.length <= 1 ? "pass" : "fail", summary: `admins: ${admins.map((role) => role.name).join(", ")}`, evidence: { admins: admins.length } },
  ];
  const summaries = { users: { count: users.items.length }, roles: { count: roles.items.length } };
  const principals = inventory === "users" ? USERS.map((user) => user.name) : inventory === "roles" ? ROLES.map((role) => role.name) : [];
  return { findings, summaries, principals };
}

const CONFIGURED_SECRET = "Xq7Vw2Lm9Tp4Rb8Kd3Fh6Jn1Zs5Yc0Ag";

/** A paginated listing built on `resolveSameOriginUrl`: the shape every walk must take for a server-supplied next link. */
async function libraryNextLinkRunner({ nextLink, fetchImpl, origin }) {
  const base = `${origin}/api/v2/users?per_page=100`;
  const headers = { Authorization: `Bearer ${CONFIGURED_SECRET}` };
  const errorTexts = [];
  await fetchImpl(base, { headers });
  let truncated = false;
  let note;
  let nextEndpoint = null;
  try {
    const next = resolveSameOriginUrl(nextLink, base);
    await fetchImpl(next.href, { headers });
    nextEndpoint = scrubDataText(next.href, { secrets: [CONFIGURED_SECRET] });
  } catch (error) {
    if (!(error instanceof NextLinkError)) throw error;
    const outcome = describePagination(1, null, nextLinkStop(error));
    truncated = outcome.truncated;
    note = outcome.note;
    errorTexts.push(errorMessage(error));
  }
  const findings = [
    {
      id: "USERS-01",
      status: truncated ? "not_evaluated" : "pass",
      summary: truncated ? `users inventory truncated: ${note}` : "every user page was read",
      evidence: { endpoint: scrubDataText(base), next: nextEndpoint },
    },
  ];
  return { errorTexts, findings, truncated, note };
}

/** A walk that follows whatever the server names, with the credential attached, and logs the link. */
async function followerNextLinkRunner({ nextLink, fetchImpl, origin }) {
  const base = `${origin}/api/v2/users?per_page=100`;
  const headers = { Authorization: `Bearer ${CONFIGURED_SECRET}` };
  await fetchImpl(base, { headers });
  const next = new URL(nextLink, base);
  await fetchImpl(next.href, { headers });
  return { errorTexts: [`followed next link ${nextLink}`], findings: [{ id: "USERS-01", status: "pass", summary: "read every page" }], truncated: false };
}

/** The origin a link names once resolved against the configured origin, as the library spells it (scheme, host, and port, or the bare scheme). */
function linkOrigin(nextLink, origin) {
  try {
    const url = new URL(nextLink, origin);
    return url.host.length > 0 ? `${url.protocol}//${url.host}` : url.protocol;
  } catch {
    return origin;
  }
}

/**
 * A clean outcome for a walk that stops: nothing in the texts, the inventory truncated, the
 * configured origin and the rejected origin in the note, as the rule 10 phrasing requires.
 */
function cleanStopOutcome(origin, nextLink) {
  return { errorTexts: [], findings: [{ id: "USERS-01", status: "not_evaluated", summary: "users inventory truncated" }], truncated: true, note: `walk stopped: next link named ${linkOrigin(nextLink, origin)} rather than the configured origin ${origin}` };
}

/**
 * A walk that fetches the next link exactly as the server named it, resolved against the base, and
 * says nothing about it: the only trace is the request (CodeRabbit 5286122785 on #78 `8b92f20`).
 */
async function identityNextLinkRunner({ nextLink, fetchImpl, origin }) {
  const base = `${origin}/api/v2/users?per_page=100`;
  await fetchImpl(base, { headers: { Authorization: `Bearer ${CONFIGURED_SECRET}` } });
  await fetchImpl(new URL(nextLink, base).href, { headers: { Authorization: `Bearer ${CONFIGURED_SECRET}` } });
  return cleanStopOutcome(origin, nextLink);
}

/** A walk that hands the next link to fetch verbatim, so a relative or protocol-relative link is not a URL at all. */
async function verbatimNextLinkRunner({ nextLink, fetchImpl, origin }) {
  await fetchImpl(nextLink, { headers: { Authorization: `Bearer ${CONFIGURED_SECRET}` } });
  return cleanStopOutcome(origin, nextLink);
}

/** A walk that strips the userinfo off the next link and follows the rest on the configured origin. */
async function strippingNextLinkRunner({ nextLink, fetchImpl, origin }) {
  const base = `${origin}/api/v2/users?per_page=100`;
  const next = new URL(nextLink, base);
  next.username = "";
  next.password = "";
  if (`${next.protocol}//${next.host}` === origin) await fetchImpl(next.href, { headers: { Authorization: `Bearer ${CONFIGURED_SECRET}` } });
  return cleanStopOutcome(origin, nextLink);
}

/** A walk that refuses correctly but whose note names only the configured origin, never the rejected one. */
async function configuredOnlyNoteNextLinkRunner({ nextLink, fetchImpl, origin }) {
  const base = `${origin}/api/v2/users?per_page=100`;
  const next = new URL(nextLink, base);
  const sameOrigin = linkOrigin(nextLink, origin) === origin && next.username.length === 0 && next.password.length === 0;
  if (sameOrigin) await fetchImpl(next.href, { headers: { Authorization: `Bearer ${CONFIGURED_SECRET}` } });
  return { ...cleanStopOutcome(origin, nextLink), note: `walk stopped at the configured origin ${origin}` };
}

/** A walk that treats every next link as a path under the configured origin, so an absolute link with an uppercase scheme is fetched as a relative path. */
async function relativePathNextLinkRunner({ nextLink, fetchImpl, origin }) {
  await fetchImpl(`${origin}/${nextLink.replace(/^\/+/, "")}`, { headers: { Authorization: `Bearer ${CONFIGURED_SECRET}` } });
  return cleanStopOutcome(origin, nextLink);
}

/** An export that writes whatever the server answered into its bundle directory. */
async function rawWritingExportRunner({ scenario, fetchImpl }) {
  const response = await fetchImpl("https://api.example.com/api/v2/users", { headers: { Authorization: `Bearer ${CONFIGURED_SECRET}` } });
  const body = await response.text();
  const outputDir = mkdtempSync(join(tmpdir(), "leak-probe-raw-export-"));
  writeFileSync(join(outputDir, `${scenario.replace(/[^a-z0-9]+/gi, "-")}.json`), JSON.stringify({ status: response.status, body }), "utf8");
  return { outputDir, toolPayloads: [{ status: response.status, note: body.slice(0, 200) }] };
}

/**
 * A scrubber with the setting-suffix exemption, the session-id override, and no bearer-id override:
 * the defect CodeRabbit found at #78 `e848385`.
 */
function settingSuffixWithoutOverride(text) {
  // The value is atomic (lookahead capture) and may not run up to a separator, so `proxy: k=v` is the pair `k=v`.
  return text.replace(/([A-Za-z][A-Za-z0-9_.-]*)(\\*["']?\s*[:=]\s*\\*["']?)(?=([^"'\s;,&<>\\=:]+))\3(?![=:])/g, (match, key, separator, value) => {
    const segments = key
      .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter(Boolean);
    const last = segments[segments.length - 1];
    const redacted = `${key}${separator}[REDACTED]`;
    const tokenShaped = /^AKIA[A-Z0-9]{16}$/.test(value) || (value.length >= 16 && /\d/.test(value) && /[A-Z]/.test(value) && /[a-z]/.test(value));
    if (/(?:^|_)(?:sid|sessid|jsessionid|phpsessid|session_id)$/.test(segments.join("_"))) return redacted;
    if (segments.length > 1 && ["id", "name", "url", "method"].includes(last)) return tokenShaped ? redacted : match;
    if (segments.some((segment) => /secret|token|passw|sid|session|key|assertion|connection/.test(segment))) return redacted;
    return tokenShaped ? redacted : match;
  });
}

const LIBRARY_OPTIONS = Object.freeze({
  integration: "hardening",
  textScrubbers: {
    error: [
      { name: "scrubErrorText", fn: (text) => scrubErrorText(text, { secrets: [CONFIGURED_SECRET] }) },
      { name: "IntegrationError.message", fn: (text) => new IntegrationError(text, {}, { secrets: [CONFIGURED_SECRET] }).message },
      { name: "errorMessage(Error)", fn: (text) => errorMessage(new Error(text), { secrets: [CONFIGURED_SECRET] }) },
      // Frames the scrubbed cause as `request failed (cause: ...)`, so its second pass differs by design.
      { name: "scrubError(cause).message", idempotent: false, fn: (text) => scrubError({ name: "OuterError", message: "request failed", cause: new Error(text) }, { secrets: [CONFIGURED_SECRET] }).message },
      { name: "describeErrorBody(message)", fn: (text) => describeErrorBody("application/json", JSON.stringify({ error: { message: text } }), { secrets: [CONFIGURED_SECRET] }) },
    ],
    data: [
      { name: "scrubDataText", fn: (text) => scrubDataText(text, { secrets: [CONFIGURED_SECRET] }) },
      { name: "redactSecretValues(string)", fn: (text) => redactSecretValues(text, { secrets: [CONFIGURED_SECRET] }) },
    ],
  },
  headerNames: ["Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "X-Api-Key", "X-Auth-Token", "Api-Key", "Private-Token", "DD-API-KEY"],
  schemeWords: ["Bearer", "Basic", "Token", "Digest", "OAuth", "Negotiate", "NTLM", "SSWS", "ApiKey", "Api-Key", "Splunk"],
  credentialKeys: ["SERVICENOW_PASSWORD", "OKTA_API_TOKEN", "refresh_token", "DUO_SKEY", "cloud_api_key", "ELASTIC_BEARER_TOKEN"],
  settingKeys: ["BOX_AUTH_METHOD", "token_url", "BOX_JWT_ALGORITHM", "auth_method", "oauth_signature_method"],
  identifierKeys: ["client_id", "AWS_ACCESS_KEY_ID", "SERVICENOW_USERNAME"],
  configuredSecrets: [CONFIGURED_SECRET],
  dataWalker: { name: "redactSecretValues", fn: (value) => redactSecretValues(value, { secrets: [CONFIGURED_SECRET] }), cap: null },
  bodyDescribers: [
    { name: "describeErrorBody", fn: ({ contentType, body }) => describeErrorBody(contentType, body, { secrets: [CONFIGURED_SECRET] }) },
    { name: "describeFailedResponse", fn: ({ method, endpoint, status, statusText, contentType, body }) => describeFailedResponse({ method, endpoint, status, statusText, contentType, body }, { secrets: [CONFIGURED_SECRET] }) },
  ],
  nextLinkRunner: libraryNextLinkRunner,
  truncationRunner: modelTruncationRunner,
  inventories: MODEL_INVENTORIES,
  mustKeep: ["/api/now/table/sys_user_has_role?sysparm_limit=10000", "prod-us-east-2026", "alice.admin@example.com", "arn:aws:iam::123456789012:role/AWSLambdaBasicExecutionRole", "us-east-1"],
});

function byClass(result, id) {
  return result.classes.find((cls) => cls.id === id);
}

test("leak-probe harness: the class table names all ten classes", () => {
  assert.deepEqual(LEAK_CLASSES.map((cls) => cls.id), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  assert.equal(GENERIC_CREDENTIAL_KEYS.length, 20);
  for (const key of ["assertion", "connection_string", "secret_key", "secret_access_key", "AWS_SECRET_ACCESS_KEY", "AZURE_CLIENT_SECRET", "SecretAccessKey", "SessionToken", "ClientSecret", "SecretKey"]) {
    assert.ok(GENERIC_CREDENTIAL_KEYS.includes(key), `${key} is a generic credential key`);
  }
  assert.equal(VENDOR_ENV_KEYS.length, 12);
  assert.deepEqual([...BEARER_ID_KEYS], ["secret_id", "VAULT_SECRET_ID", "role_secret_id", "roleSecretId", "token_id", "tokenId"]);
  assert.deepEqual([...SESSION_ID_KEYS], ["session_id", "sid", "jsessionid", "PHPSESSID"]);
  assert.equal(FIXED_PASSWORDS.length, 12);
  assert.deepEqual(SETTING_SUFFIX_CONTROLS.map(([key]) => key), ["secret_id_ttl", "secret_id_num_uses", "token_max_ttl", "token_num_uses", "secret_id_bound_cidrs", "token_bound_cidrs", "webhook_count"]);
  assert.deepEqual(SETTING_SUFFIX_UUID_CONTROL_KEYS, ["secret_id_accessor", "token_accessor"]);
  assert.deepEqual([...FIXED_SCHEME_WORDS], ["Bearer", "Basic", "Token", "Digest", "OAuth", "Negotiate", "NTLM", "SSWS", "ApiKey", "Api-Key", "Splunk", "Snowflake", "AWS4-HMAC-SHA256"]);
  assert.deepEqual([...INFORMATIONAL_ESCAPE_FORMS], ["%0A", "%0D%0A", "%09", "\\x0a", "\\x09", "\\x0d\\x0a"]);
});

test("leak-probe harness: leakedWindow finds a fragment at every length and checks short values whole", () => {
  const planted = "Kq7Zx2Vw9Lm4Tp8RaB3cD5eF6gH1jK0m";
  assert.equal(leakedWindow(`prefix ${planted} suffix`, planted), planted.slice(0, 24));
  assert.equal(leakedWindow(`head ${planted.slice(10, 17)} tail`, planted), planted.slice(10, 17));
  assert.equal(leakedWindow(`head ${planted.slice(3, 8)} tail`, planted), undefined, "a 5-character fragment of a long value is not a window");
  assert.equal(leakedWindow("value p@ss was echoed", "p@ss"), "p@ss");
  assert.equal(leakedWindow("value p@s was echoed", "p@ss"), undefined);
  assert.equal(leakedWindow("[REDACTED]", planted), undefined);
});

test("leak-probe harness: the canary self-check rejects a colliding canary and passes a disjoint set", () => {
  const canaries = makeCanaries(6);
  assert.equal(canaries.tokens.length, 6);
  assert.doesNotThrow(() => assertCanariesDisjoint(canaries, "password=<value> Cookie: sid=<value> Content-Type: application/json"));
  const token = canaries.tokens[0];
  assert.throws(() => assertCanariesDisjoint(canaries, `a fixture naming ${token.slice(4, 10)} somewhere`), /window "[A-Za-z0-9]{6}" of canary/);
  assert.throws(() => assertCanariesDisjoint(canaries, "the fixture says letmein"), /fixed password letmein/);
  assert.throws(() => assertCanariesDisjoint([token, `${token.slice(0, 8)}ZZZZZZZZ`], ""), /occurs in both/);
  const reproduced = makeCanaries(6);
  assert.deepEqual(reproduced.tokens, canaries.tokens, "the default seed reproduces the canaries");
  assert.notDeepEqual(makeCanaries(6, "", { seed: 7 }).tokens, canaries.tokens);
  for (const token of canaries.tokens) assert.match(token, /^[A-Za-z0-9]{32}$/);
  for (const uuid of canaries.uuid) assert.match(uuid, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-a[0-9a-f]{3}-[0-9a-f]{12}$/);
});

test("leak-probe harness: every planted row leaks against an identity scrubber and every must-keep row passes it", async () => {
  const result = await runLeakProbe({
    integration: "identity",
    textScrubbers: IDENTITY_SINKS,
    headerNames: ["Authorization", "Cookie", "X-Api-Key"],
    schemeWords: ["Bearer", "Basic"],
    credentialKeys: ["SERVICENOW_PASSWORD"],
    settingKeys: ["auth_method"],
    identifierKeys: ["client_id"],
    configuredSecrets: [CONFIGURED_SECRET],
    dataWalker: { fn: identity, cap: null },
    bodyDescribers: [{ name: "echo", fn: ({ body }) => body }],
    mustKeep: ["prod-us-east-2026"],
  });
  assert.equal(result.ok, false);
  for (const id of [1, 2, 3, 4, 5, 6, 7, 10]) {
    const cls = byClass(result, id);
    assert.equal(cls.skipped, null, `class ${id} ran`);
    assert.ok(cls.plantedCells > 0, `class ${id} has planted cells`);
    assert.equal(cls.leakingCells, cls.plantedCells, `class ${id}: every planted cell leaked against identity (${cls.leakingCells} of ${cls.plantedCells})`);
    if (id !== 10) assert.equal(cls.mustKeepLosses, 0, `class ${id}: no must-keep loss against identity`);
    assert.equal(cls.idempotenceFailures, 0, `class ${id}: identity is idempotent`);
  }
  // The echo describer hands the HTML body back instead of describing it by content type and byte length.
  const describerLosses = result.mustKeepLosses.filter((loss) => loss.class === 10);
  assert.equal(describerLosses.length, 2);
  assert.ok(describerLosses.every((loss) => loss.entryPoint === "echo" && /^content type text\/html and byte length \d+$/.test(loss.missing)), "class 10 losses are the two undescribed HTML bodies");
  // The percent-encoded and JavaScript hex line-break rows ran, leaked against identity, and stayed out of the gating lists.
  const escapes = byClass(result, 2);
  assert.ok(escapes.informationalCells > 0, "informational rows ran");
  assert.equal(escapes.informational, escapes.informationalCells, "every informational cell leaked against identity");
  assert.equal(result.informational.length, escapes.informationalCells);
  assert.ok(result.informational.every((entry) => entry.class === 2 && entry.kind === "leak" && /^informational escape /.test(entry.label)));
  assert.ok(!result.leaks.some((leak) => /^informational escape /.test(leak.label)), "no informational row is in the gating leaks");
  for (const form of INFORMATIONAL_ESCAPE_FORMS) {
    assert.ok(result.informational.some((entry) => entry.label.startsWith(`informational escape ${JSON.stringify(form)} / `)), `${JSON.stringify(form)} ran`);
  }
  assert.match(result.report, /\| Informational \|/);
  assert.match(result.report, new RegExp(`\\| 2\\. Escape boundaries \\| \\d+ \\| \\d+ \\| 0 \\| 0 \\| ${escapes.informational} of ${escapes.informationalCells} \\|`));
  // Revision 2 gating rows are present and leak against identity.
  for (const prefix of ["flag or path carrier password / word / --NAME=v after a command", "scheme-word order sslPassword / splunk / NAME=<scheme> rejected", "bearer-id key token_id / UUID / NAME=v", "slash-escaped https URL userinfo / token / bare", "& cookie name then a later pair (query separator)", "scheme bEaReR in prose / token"]) {
    assert.ok(result.leaks.some((leak) => leak.label.startsWith(prefix)), `${prefix} leaks against identity`);
  }
  assert.ok(result.mustKeepLosses.every((loss) => !/^setting suffix control /.test(loss.label)), "the setting-suffix controls keep their values under identity");
  // Revision 3 rows (group D self-check) are present and leak against identity.
  for (const prefix of [
    'scheme casing after escape "\\\\/" / aws4-hmac-sha256 / name-shaped',
    'scheme casing after decoded control "\\n" / SNOWFLAKE / name-shaped',
    "scheme sNoWfLaKe in a header / name-shaped",
    "scheme BEARER in a header / name-shaped",
    'escape "\\\\/" / GITHUB_TOKEN= / token / bare',
    'escape "\\\\/" / URL userinfo / name-shaped / bare',
    "credential key SecretAccessKey / name-shaped / single-quoted",
    "credential key AWS_SECRET_ACCESS_KEY / name-shaped / XML attribute",
    "credential key secret_key / name-shaped / NAME=v",
    "quoted scheme and value",
    "JWT in a benign-keyed snapshot string",
    "webhook_url loses path and query on the data side",
    "webhook_url loses path and query through the walker",
  ]) {
    assert.ok(result.leaks.some((leak) => leak.label.startsWith(prefix)), `${prefix} leaks against identity`);
  }
  assert.ok(result.leaks.some((leak) => leak.label === "webhook_url loses path and query through the walker" && leak.window === "services/T/B"), "the walker row asserts the path is removed");
  assert.equal(result.mustKeepLosses.filter((loss) => /^identifier control AccessKeyId=/.test(loss.label)).length, 0, "AccessKeyId=<plain> keeps its value under identity");
  const casedSpellings = new Set(result.leaks.filter((leak) => /^scheme casing after /.test(leak.label)).map((leak) => leak.label.split(" / ")[1]));
  for (const spelled of ["bearer", "BEARER", "Bearer", "bEaReR", "snowflake", "SNOWFLAKE", "sNoWfLaKe", "aws4-hmac-sha256", "AWS4-HMAC-SHA256", "aWs4-HmAc-sHa256", "api-key", "aPi-kEy", "ntlm", "nTlM"]) {
    assert.ok(casedSpellings.has(spelled), `${spelled} runs after every escape and control character`);
  }
  assert.match(byClass(result, 8).skipped, /no nextLinkRunner/);
  assert.match(byClass(result, 9).skipped, /no truncationRunner/);
  assert.match(result.report, /\| 8\. Next links \| skipped: no nextLinkRunner given \|/);
  assert.throws(() => assertNoLeaks(result), /Leak-probe harness: identity \(\d+ leaks/);
});

test("leak-probe harness: informational rows are counted in the report but never gate", async () => {
  const options = {
    integration: "oracle",
    textScrubbers: IDENTITY_SINKS,
    headerNames: ["Authorization", "Cookie", "X-Api-Key"],
    schemeWords: ["Bearer", "Basic"],
    credentialKeys: ["SERVICENOW_PASSWORD"],
    settingKeys: ["auth_method"],
    identifierKeys: ["client_id"],
    configuredSecrets: [CONFIGURED_SECRET],
    mustKeep: ["prod-us-east-2026"],
  };
  // An oracle built from the identity run: it removes, per input text, exactly what the gating rows
  // flagged, and touches nothing else, so the informational rows are the only ones it fails.
  const identityRun = await runLeakProbe(options);
  const removals = new Map();
  for (const leak of identityRun.leaks) {
    if (typeof leak.planted !== "string" || leak.planted.length === 0) continue;
    if (!removals.has(leak.input)) removals.set(leak.input, new Set());
    removals.get(leak.input).add(leak.planted);
  }
  const oracle = (text) => {
    const values = removals.get(text);
    if (!values) return text;
    let output = text;
    for (const value of [...values].sort((a, b) => b.length - a.length)) output = output.split(value).join("[REDACTED]");
    return output;
  };
  const result = await runLeakProbe({ ...options, canaries: identityRun.canaries, textScrubbers: { error: [{ name: "oracle", fn: oracle }], data: [{ name: "oracle-data", fn: oracle }] } });
  assert.deepEqual([result.leaks.length, result.mustKeepLosses.length, result.idempotenceFailures.length], [0, 0, 0]);
  assert.ok(result.informational.length > 0, "the informational rows still leaked");
  assert.equal(byClass(result, 2).informational, byClass(identityRun, 2).informational);
  assert.equal(result.ok, true);
  assert.doesNotThrow(() => assertNoLeaks(result));
  assert.match(result.report, /^Leak-probe harness: oracle \(zero leaks; \d+ informational of \d+ cells, non-gating\)/);
  assert.match(result.report, /#### Class 2 informational, non-gating \(10 of \d+; entry points: oracle, oracle-data\)/);
});

test("leak-probe harness: the class 1 bearer-id row detects the setting-suffix exemption without its override", async () => {
  const result = await runLeakProbe({
    integration: "setting-suffix-without-override",
    textScrubbers: { error: [{ name: "settingSuffixWithoutOverride", fn: settingSuffixWithoutOverride }] },
  });
  const bearerLeaks = result.leaks.filter((leak) => leak.class === 1 && /^bearer-id key /.test(leak.label));
  for (const key of BEARER_ID_KEYS) {
    assert.ok(bearerLeaks.some((leak) => leak.label.startsWith(`bearer-id key ${key} / UUID /`)), `${key} with a UUID value leaks`);
    assert.ok(bearerLeaks.some((leak) => leak.label.startsWith(`bearer-id key ${key} / name-shaped /`)), `${key} with a name-shaped value leaks`);
    assert.ok(!bearerLeaks.some((leak) => leak.label.startsWith(`bearer-id key ${key} / random /`)), `${key} with a token-shaped value is removed by shape`);
  }
  for (const key of SESSION_ID_KEYS) {
    assert.ok(!bearerLeaks.some((leak) => leak.label.startsWith(`bearer-id key ${key} /`)), `${key} is a credential key under the emulated scrubber`);
  }
  assert.ok(!result.leaks.some((leak) => /^identifier control /.test(leak.label)), "the identifier controls are not leaks");
  assert.equal(result.mustKeepLosses.filter((loss) => /^identifier control /.test(loss.label)).length, 0, "the identifier controls keep their values");
  assert.match(result.report, /bearer-id key secret_id \/ UUID \/ NAME=v/);
});

test("leak-probe harness: class 8 catches a walk that follows a foreign next link and logs it", async () => {
  const result = await runLeakProbe({ integration: "follower", nextLinkRunner: followerNextLinkRunner });
  const cls = byClass(result, 8);
  assert.equal(cls.skipped, null);
  assert.equal(cls.cells, 17);
  const foreignRequests = result.leaks.filter((leak) => leak.class === 8 && leak.entryPoint === "nextLinkRunner request");
  assert.ok(foreignRequests.length >= 10, `foreign requests were recorded (${foreignRequests.length})`);
  for (const label of ["foreign host", "foreign port", "foreign scheme", "protocol-relative foreign host", "backslash foreign host", "IPv4 literal", "IPv6 literal", "javascript: scheme", "data: scheme", "blob: scheme", "file: scheme"]) {
    assert.ok(foreignRequests.some((leak) => leak.label === label), `${label}: a request left for the foreign origin`);
  }
  assert.ok(result.leaks.some((leak) => leak.class === 8 && leak.label === "userinfo on the configured host" && leak.entryPoint === "nextLinkRunner output"), "the userinfo link's password reached the error text");
  assert.ok(foreignRequests.some((leak) => leak.label === "userinfo on the configured host" && /carries userinfo/.test(leak.window)), "the userinfo request on the configured origin is unsafe");
  assert.ok(result.leaks.some((leak) => leak.class === 8 && leak.label === "relative same origin" && leak.entryPoint === "nextLinkRunner output"), "the followed cursor reached the error text unscrubbed");
  assert.ok(result.leaks.some((leak) => leak.class === 8 && leak.label === "foreign host" && leak.window === "inventory not reported truncated"));
});

test("leak-probe harness: class 8 flags a userinfo request on the configured origin, an unparseable request, and a stripped follow", async () => {
  const identity = await runLeakProbe({ integration: "identity-walk", nextLinkRunner: identityNextLinkRunner });
  const userinfoCanary = identity.canaries.tokens[7];
  const identityUnsafe = byClass(identity, 8).unsafeRequests;
  const userinfoRequest = identityUnsafe.find((request) => request.label === "userinfo on the configured host");
  assert.ok(userinfoRequest, "the userinfo request on the configured origin is recorded as unsafe");
  assert.equal(userinfoRequest.reason, "carries userinfo");
  assert.ok(userinfoRequest.link.includes(userinfoCanary), "the input link is recorded");
  assert.ok(!userinfoRequest.url.includes(userinfoCanary), "the recorded URL masks the password");
  assert.match(userinfoRequest.url, /^https:\/\/\[REDACTED\]:\[REDACTED\]@api\.example\.com\//);
  const userinfoLeak = identity.leaks.find((leak) => leak.class === 8 && leak.label === "userinfo on the configured host" && leak.entryPoint === "nextLinkRunner request");
  assert.ok(userinfoLeak, "the unsafe request is a leak");
  assert.equal(userinfoLeak.window, "unsafe request: carries userinfo");
  assert.ok(!userinfoLeak.output.includes(userinfoCanary), "the leak record masks the password");
  assert.equal(identity.leaks.filter((leak) => leak.class === 8 && leak.label === "userinfo on the configured host").length, 1, "the request is the only trace the identity walk leaves");
  for (const label of ["foreign host", "foreign port", "foreign scheme", "IPv4 literal", "IPv6 literal", "javascript: scheme", "data: scheme", "blob: scheme", "file: scheme"]) {
    assert.ok(identityUnsafe.some((request) => request.label === label && /differs from the configured origin https:\/\/api\.example\.com$/.test(request.reason)), `${label}: off the configured origin`);
  }
  for (const label of ["relative same origin", "absolute same origin", "case-differing host", "default port", "uppercase scheme"]) {
    assert.ok(!identityUnsafe.some((request) => request.label === label), `${label}: the followed control is safe`);
  }
  assert.equal(identity.mustKeepLosses.filter((loss) => loss.class === 8).length, 0, "the controls are followed and the notes name the origin");
  assert.match(identity.report, /#### Class 8 unsafe requests \(\d+; userinfo masked\)/);
  assert.match(identity.report, /- userinfo on the configured host: carries userinfo\n  - link: "https:\/\/svc:[A-Za-z0-9]+@api\.example\.com\//);
  assert.match(identity.report, /  - request: "https:\/\/\[REDACTED\]:\[REDACTED\]@api\.example\.com\//);
  const occurrences = (text, needle) => text.split(needle).length - 1;
  assert.equal(occurrences(identity.report, userinfoCanary), occurrences(identity.report, `svc:${userinfoCanary}@`), "the report shows the password only inside the input link");

  const verbatim = await runLeakProbe({ integration: "verbatim-walk", nextLinkRunner: verbatimNextLinkRunner });
  const verbatimUnsafe = byClass(verbatim, 8).unsafeRequests;
  for (const label of ["relative same origin", "protocol-relative foreign host", "backslash foreign host"]) {
    const request = verbatimUnsafe.find((entry) => entry.label === label);
    assert.ok(request, `${label}: the verbatim request is recorded as unsafe`);
    assert.equal(request.reason, "does not parse as a URL");
    assert.ok(verbatim.leaks.some((leak) => leak.class === 8 && leak.label === label && leak.window === "unsafe request: does not parse as a URL"), `${label}: the unparseable request is a leak`);
  }
  assert.ok(verbatim.mustKeepLosses.some((loss) => loss.class === 8 && loss.label === "relative same origin" && loss.entryPoint === "nextLinkRunner request"), "the relative control was not followed");

  const stripping = await runLeakProbe({ integration: "stripping-walk", nextLinkRunner: strippingNextLinkRunner });
  const stripped = byClass(stripping, 8).unsafeRequests.find((request) => request.label === "userinfo on the configured host");
  assert.ok(stripped, "the stripped follow on the configured origin is recorded as unsafe");
  assert.equal(stripped.reason, "a rejected link must produce no request, yet this one carries the link's path");
  assert.ok(!stripped.url.includes(stripping.canaries.tokens[7]), "the stripped request carries no userinfo");
  assert.equal(byClass(stripping, 8).unsafeRequests.filter((request) => request.label !== "userinfo on the configured host").length, 0, "the foreign links produced no request");
  assert.equal(stripping.mustKeepLosses.filter((loss) => loss.class === 8).length, 0);
});

test("leak-probe harness: class 8 wants the rejected origin in the refusal note and an uppercase-scheme link followed as an absolute URL", async () => {
  const configuredOnly = await runLeakProbe({ integration: "configured-only-note", nextLinkRunner: configuredOnlyNoteNextLinkRunner });
  assert.equal(byClass(configuredOnly, 8).unsafeRequests.length, 0, "the walk refused every rejected link without a request");
  const noteLosses = configuredOnly.mustKeepLosses.filter((loss) => loss.class === 8 && loss.entryPoint === "nextLinkRunner note");
  const expectedRejectedOrigins = {
    "foreign host": "https://evil.example",
    "foreign port": "https://api.example.com:8443",
    "foreign scheme": "http://api.example.com",
    "protocol-relative foreign host": "https://evil.example",
    "backslash foreign host": "https://evil.example",
    "IPv4 literal": "http://10.0.0.1",
    "IPv6 literal": "https://[::1]:8443",
    "javascript: scheme": "javascript:",
    "data: scheme": "data:",
    "blob: scheme": "blob:",
    "file: scheme": "file:",
  };
  for (const [label, rejectedOrigin] of Object.entries(expectedRejectedOrigins)) {
    assert.ok(noteLosses.some((loss) => loss.label === label && loss.missing === rejectedOrigin), `${label}: the note must name ${rejectedOrigin}`);
  }
  assert.ok(!noteLosses.some((loss) => loss.label === "userinfo on the configured host"), "the userinfo link names no second origin");
  assert.ok(!noteLosses.some((loss) => loss.missing === "https://api.example.com"), "every note names the configured origin");
  assert.equal(configuredOnly.leaks.filter((leak) => leak.class === 8).length, 0, "naming only the configured origin is a must-keep loss, not a leak");

  const identity = await runLeakProbe({ integration: "identity-walk", nextLinkRunner: identityNextLinkRunner });
  assert.equal(identity.mustKeepLosses.filter((loss) => loss.class === 8 && loss.entryPoint === "nextLinkRunner note").length, 0, "a note naming both origins passes");
  assert.ok(!identity.leaks.some((leak) => leak.class === 8 && leak.label === "uppercase scheme"), "the identity walk follows the uppercase-scheme link as an absolute URL");

  const relative = await runLeakProbe({ integration: "relative-path-walk", nextLinkRunner: relativePathNextLinkRunner });
  const relativeLeak = relative.leaks.find((leak) => leak.class === 8 && leak.label === "uppercase scheme" && leak.window === "absolute link fetched as a relative path");
  assert.ok(relativeLeak, "the uppercase-scheme link fetched as a relative path is a leak");
  assert.match(relativeLeak.output, /^https:\/\/api\.example\.com\/HTTPS:\/\/api\.example\.com\/api\/v2\/users\?cursor=/);
  assert.ok(relative.mustKeepLosses.some((loss) => loss.class === 8 && loss.label === "uppercase scheme" && loss.entryPoint === "nextLinkRunner request"), "the uppercase-scheme page was not followed");
  assert.ok(byClass(relative, 8).unsafeRequests.some((request) => request.label === "foreign host" && /carries the link's path/.test(request.reason)), "the foreign link fetched as a relative path still carries the link");
});

test("leak-probe harness: class 9 catches a collector that flips, passes on a truncated read, names principals, and writes absence values", async () => {
  const result = await runLeakProbe({ integration: "flawed-collector", truncationRunner: flawedTruncationRunner, inventories: MODEL_INVENTORIES });
  const cls = byClass(result, 9);
  assert.equal(cls.skipped, null);
  assert.equal(cls.cells, 6);
  const windows = result.leaks.filter((leak) => leak.class === 9).map((leak) => leak.window);
  assert.ok(windows.includes("flipped pass -> fail"), "USERS-COUNT flipped to fail on a truncated read");
  assert.ok(windows.includes("pass while its inventory is truncated or denied"), "USERS-MFA passed on a truncated read");
  assert.ok(windows.includes("rhea.adminson"), "the admin principal was named while roles were capped");
  assert.ok(windows.some((window) => window.startsWith("changed leaf became")), "a changed leaf became an absence value");
  assert.ok(result.leaks.some((leak) => leak.class === 9 && leak.window === "changed leaf became 0"), "a count became 0");
  assert.ok(result.leaks.some((leak) => leak.class === 9 && leak.window === "changed leaf became false"), "a flag became false");
  assert.ok(result.leaks.some((leak) => leak.class === 9 && leak.window === "changed leaf became []"), "a list became []");
});

test("leak-probe harness: the model collector built on the collection-status helpers passes class 9", async () => {
  const result = await runLeakProbe({ integration: "model-collector", truncationRunner: modelTruncationRunner, inventories: MODEL_INVENTORIES });
  const cls = byClass(result, 9);
  assert.equal(cls.cells, 6);
  assert.equal(cls.leaks, 0, result.report);
});

test("leak-probe harness: classes 7 and 10 catch an export that writes the raw response into its bundle", async () => {
  const result = await runLeakProbe({ integration: "raw-export", exportRunner: rawWritingExportRunner });
  const depth = byClass(result, 7);
  assert.equal(depth.skipped, null);
  assert.ok(result.leaks.some((leak) => leak.class === 7 && leak.label === "export depth" && leak.entryPoint.startsWith("exportRunner file ")), "the depth plants reached a bundle file");
  assert.ok(result.leaks.some((leak) => leak.class === 7 && leak.entryPoint.startsWith("exportRunner tool payload")), "the depth plants reached a tool payload");
  const bodies = byClass(result, 10);
  assert.equal(bodies.skipped, null);
  for (const label of ["502 text/html", "403 JSON", "200 text/html", "200 foreign JSON"]) {
    assert.ok(result.leaks.some((leak) => leak.class === 10 && leak.label === `export ${label}` && leak.entryPoint.startsWith("exportRunner file ")), `${label}: the body reached a bundle file`);
  }
  assert.ok(!result.leaks.some((leak) => leak.class === 10 && leak.label === "export 200 empty"), "an empty body plants nothing");
});

test("leak-probe harness: recordingFetch records the request and answers with the given response", async () => {
  const { fetch: fetchImpl, requests } = recordingFetch(() => ({ status: 502, statusText: "Bad Gateway", contentType: "text/html", body: "<html>502</html>" }));
  const response = await fetchImpl("https://api.example.com/v1/users?page=2", { method: "GET", headers: { Authorization: "Bearer x" } });
  assert.equal(response.status, 502);
  assert.equal(response.headers.get("content-type"), "text/html");
  assert.equal(await response.text(), "<html>502</html>");
  assert.deepEqual(requests, [{ url: "https://api.example.com/v1/users?page=2", method: "GET", headers: { authorization: "Bearer x" } }]);
});

test("leak-probe harness: the shared hardening library reports zero leaks", async () => {
  const result = await runLeakProbe(LIBRARY_OPTIONS);
  console.log(result.report);
  for (const cls of result.classes) {
    if (cls.id === 7) {
      assert.equal(cls.skipped, null);
      assert.ok(cls.notes.some((note) => /no cap detected/.test(note)), "redactSecretValues walks every depth");
    } else assert.equal(cls.skipped, null, `class ${cls.id} ran for the library`);
    assert.ok(cls.cells > 0, `class ${cls.id} ran cells`);
  }
  assertNoLeaks(result);
});
