/**
 * Shared leak-probe harness for the batch 1 hardening PRs.
 *
 * One harness encodes every leak class the reviews found (credential pairs without a shape gate,
 * escape boundaries, cookie and header names, quoted and compound headers, scheme casing, data-side
 * token shapes, depth caps, foreign next links, truncated-page and denial flips, error bodies), so
 * every worker runs the same rows against its own integration before a final head and every
 * reviewer runs them again and returns one verdict per head. Integrations pass the entry points and
 * runners they have; a missing runner skips its class and the report says so.
 *
 * Every leak check tests every window of the planted value at lengths 6 through 24 (a value under 6
 * characters is checked whole): a scrubber that drops the value but lets a fragment through fails
 * the same as one that keeps it. Every text row runs twice through each scrubber, and the second
 * pass must change nothing. Canaries are random-looking alphanumeric values from a seeded generator,
 * checked against the harness vocabulary so no 6-character window of one occurs in a value the
 * output may keep.
 *
 * Revision 2 (01:40 rulings) adds the bearer-id `token_id`, the setting suffixes `ttl`, `max_ttl`,
 * `num_uses`, `bound_cidrs`, `accessor` and the URL-only webhook exception, flag and path carriers,
 * the scheme-word-order row, slash-escaped URLs, the query-separator cookie row, and any-casing
 * scheme words. Percent-encoded and JavaScript hex line breaks run as informational rows: counted
 * in the report, never a leak in the gating totals, never a throw from `assertNoLeaks`. Class 8
 * classifies every request the runner made (CodeRabbit 5286122785 on #78 `8b92f20`): a request is
 * unsafe when it does not parse as a URL, when its username or password is non-empty, or when its
 * origin differs from the configured origin; each unsafe request is a leak and is listed on the
 * class 8 result with its userinfo masked.
 *
 * Depends only on `node:` modules and `./bundle-contents.mjs`; runs on Node 22.19 or newer.
 */
import { readBundleFiles, readZipEntries } from "./bundle-contents.mjs";

export const WINDOW_MIN = 6;
export const WINDOW_MAX = 24;
export const DISTINCT_WINDOW = 8;
const MAX_EXAMPLES_PER_CLASS = 20;
const MAX_INFORMATIONAL_EXAMPLES = 10;
const MAX_DEPTH_PROBE = 80;
const DEFAULT_SEED = 0x5eed2026;
const DEFAULT_ORIGIN = "https://api.example.com";
const MARKER_PATTERN = /\[REDACTED\]|\[redacted\]|not collected|not requested|not readable|unreadable|truncated|denied|withheld|partial|incomplete|unknown|\bseen\b|\bof \d+\b/i;

export const LEAK_CLASSES = Object.freeze([
  Object.freeze({ id: 1, key: "credential-pairs", name: "Credential pairs, no shape gate" }),
  Object.freeze({ id: 2, key: "escape-boundaries", name: "Escape boundaries" }),
  Object.freeze({ id: 3, key: "cookie-header-names", name: "Cookie and header names" }),
  Object.freeze({ id: 4, key: "quoted-compound-headers", name: "Quoted and compound headers" }),
  Object.freeze({ id: 5, key: "scheme-casing", name: "Scheme casing and prose" }),
  Object.freeze({ id: 6, key: "data-shapes", name: "Data-side shapes" }),
  Object.freeze({ id: 7, key: "depth", name: "Depth" }),
  Object.freeze({ id: 8, key: "next-links", name: "Next links" }),
  Object.freeze({ id: 9, key: "truncation-flips", name: "Truncated-page and denial flips" }),
  Object.freeze({ id: 10, key: "error-bodies", name: "Error bodies" }),
]);

/** The generic credential keys every integration's scrubber must classify (class 1). */
export const GENERIC_CREDENTIAL_KEYS = Object.freeze([
  "password",
  "passwd",
  "secret",
  "token",
  "api_key",
  "client_secret",
  "assertion",
  "connection_string",
  "private_key",
  "DB_PASSWORD",
  "admin_password",
  "client_token",
]);

/**
 * Keys that end in an identifier suffix but carry a bearer credential: a Vault AppRole secret id is a
 * UUID, a token id is the token, and a session id is the session, so their values go whatever the
 * shape (CodeRabbit r4077259415 on #78 `e848385`; the bearer-id override is checked before the
 * setting-suffix test; `token_id` joined it in the 01:40 rulings, fail closed).
 */
export const BEARER_ID_KEYS = Object.freeze(["secret_id", "VAULT_SECRET_ID", "role_secret_id", "roleSecretId", "token_id", "tokenId"]);
export const SESSION_ID_KEYS = Object.freeze(["session_id", "sid", "jsessionid", "PHPSESSID"]);

/**
 * Setting keys whose final segment the 01:40 rulings added to the setting suffixes (`ttl`, `max_ttl`,
 * `num_uses`, `bound_cidrs`, `accessor`: the AppRole settings an assessment reports) and the webhook
 * exception narrowed to URL-valued keys (`webhook_count` keeps its value). Each is `[key, value]`;
 * every value must survive every scrub.
 */
export const SETTING_SUFFIX_CONTROLS = Object.freeze([
  Object.freeze(["secret_id_ttl", "3600"]),
  Object.freeze(["secret_id_num_uses", "5"]),
  Object.freeze(["token_max_ttl", "7200"]),
  Object.freeze(["token_num_uses", "0"]),
  Object.freeze(["secret_id_bound_cidrs", "10.0.0.0/8"]),
  Object.freeze(["token_bound_cidrs", "10.0.0.0/8"]),
  Object.freeze(["webhook_count", "3"]),
]);

/**
 * Setting keys ending in `accessor` (a Vault accessor is a UUID); their value is a UUID canary and
 * must survive every scrub, so it lives beside the identifier controls rather than in the fixed list.
 */
export const SETTING_SUFFIX_UUID_CONTROL_KEYS = Object.freeze(["secret_id_accessor", "token_accessor"]);

/**
 * Scheme words every scrubber recognises in any casing on both sides (01:40 ruling, row B); an
 * integration's own `schemeWords` are added to these.
 */
export const FIXED_SCHEME_WORDS = Object.freeze(["Bearer", "Basic", "Token", "Digest", "OAuth", "Negotiate", "NTLM", "SSWS", "ApiKey", "Api-Key", "Splunk"]);

/**
 * Credential names probed in flag and path position (reviewer #78 row D): `=` after a
 * credential-named segment is a pair whatever precedes the name, `--name=v`, `--name v`, `-Dname=v`,
 * and `-Dprefix.name=v` are carriers, and `:` after a path segment removes a single-token value.
 */
const FLAG_PATH_KEYS = Object.freeze(["password", "api_key", "api-key", "client_secret", "client-secret", "token", "access_token", "secret_id", "DB_PASSWORD", "X-Api-Key", "private-key"]);

/**
 * Line-break encodings the principal ruled NON-GATING for every PR in this effort: percent-encoded
 * and JavaScript hex line breaks before a carrier opener run as informational rows (counted in the
 * report, never a leak in the gating totals, never a throw from `assertNoLeaks`).
 */
export const INFORMATIONAL_ESCAPE_FORMS = Object.freeze(["%0A", "%0D%0A", "%09", "\\x0a", "\\x09", "\\x0d\\x0a"]);

/** Human-chosen password shapes the shape gate let through (reviewer D round 5 baseline). */
export const FIXED_PASSWORDS = Object.freeze([
  "letmein",
  "Sunshine",
  "monkey",
  "qwerty",
  "iloveyou",
  "football",
  "hunter2",
  "Summer2026!",
  "letmein2024",
  "correcthorsebatterystaple",
  "abc12",
  "p@ss",
]);

const RFC6265_TOKEN_SYMBOLS = Object.freeze(["!", "#", "$", "%", "&", "'", "*", "+", "-", ".", "^", "_", "`", "|", "~"]);

/**
 * Every escape form as the literal characters a JSON-encoded text carries (`\n` is a backslash and
 * an `n`), and the decoded control characters that stand as controls: a carrier after a raw line
 * break, tab, or space must be caught the same way, so the escaped form must be caught too.
 */
const ESCAPE_FORMS = Object.freeze(["\\n", "\\r", "\\t", "\\b", "\\f", "\\/", '\\"', "\\u000a", "\\u0009", "\\u000d\\u000a", "\\u0020"]);
const DECODED_CONTROLS = Object.freeze(["\n", "\r", "\t", "\b", "\f", "\r\n", " "]);

const CONTROL_HEADER_LINES = Object.freeze(['Content-Type: "text/html; charset=utf-8"', "Date: Mon, 22 Sep 2026 12:30:00 GMT"]);
const PLAIN_SETTING_VALUES = Object.freeze(["ccg", "RS256", "https://api.example.com/oauth2/token"]);
const IDENTIFIER_PLAIN_VALUES = Object.freeze(["svc-reporting-2026", "alice.admin"]);
const NAME_SHAPED_DATA_VALUE = "prod-us-east-2026-cluster";

/** Fixed fragments the rows are built from; canaries must not share a 6-character window with any of them. */
const VOCABULARY = Object.freeze([
  ...GENERIC_CREDENTIAL_KEYS,
  ...BEARER_ID_KEYS,
  ...SESSION_ID_KEYS,
  ...CONTROL_HEADER_LINES,
  ...PLAIN_SETTING_VALUES,
  ...IDENTIFIER_PLAIN_VALUES,
  ...SETTING_SUFFIX_CONTROLS.flat(),
  ...SETTING_SUFFIX_UUID_CONTROL_KEYS,
  ...FIXED_SCHEME_WORDS,
  ...FLAG_PATH_KEYS,
  ...INFORMATIONAL_ESCAPE_FORMS,
  NAME_SHAPED_DATA_VALUE,
  "mysql",
  "psql",
  "curl",
  "java",
  "-h db",
  "-jar app.jar",
  "spring.datasource",
  "path/",
  "see log",
  "kv/",
  "/api/v1/api-tokens: request failed with 403",
  "helm --set db.password",
  "upgrade",
  "x_password",
  "(password",
  "a,password",
  "sslPassword",
  "db_password",
  "rejected",
  "pref",
  "webhook",
  "proxy.example.com",
  "api.example.com",
  "upstream",
  "refused",
  "request url",
  "client_id",
  "tenant_id",
  "access_key_id",
  "key_id",
  "secret_name",
  "my-secret",
  "key-2026-primary",
  "primary-signing-key",
  "webhook_url",
  "https://hooks.example.com/services/T/B/",
  "export",
  "config",
  "upstream echoed",
  "before closing",
  "proxy",
  "detail",
  "upstream sent",
  "request failed",
  "request headers",
  "see the log",
  "Content-Type: application/json",
  "X-Request-Id",
  "theme=dark",
  "Path=/",
  "HttpOnly",
  "Expires=Wed, 21 Oct 2026 07:28:00 GMT",
  "ASP.NET_SessionId",
  ".AspNetCore.Session",
  "my.sid",
  "my'pref",
  "X.Api.Key",
  "text/plain",
  "application/json",
  "text/html",
  '{"status":"denied"}',
  "Cookie",
  "Set-Cookie",
  "X-Api-Key",
  "Authorization",
  "Proxy-Authorization",
  "X-Auth-Token",
  "Bearer",
  "Basic",
  "Token",
  "replayed",
  "upstream",
  "Bearer token is missing",
  'Bearer realm="api"',
  "502 Bad Gateway",
  "upstream replied with",
  "Access denied",
  "benign-sibling",
  "level",
  "description",
  "notes",
  "settings",
  "record",
  "users",
  "cursor",
  "per_page",
  "api.example.com",
  "evil.example",
  "10.0.0.1",
  "svc",
  "items",
  "sk_live_",
  "xoxb-",
  "ghp_",
  "AKIA",
  "-----BEGIN PRIVATE KEY-----",
  "-----END PRIVATE KEY-----",
  "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
]);

// ---------------------------------------------------------------------------------------------
// Canaries
// ---------------------------------------------------------------------------------------------

const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS = "0123456789";
const ALNUM = `${LOWER}${UPPER}${DIGITS}`;
const HEX = "0123456789abcdef";

function makeRandom(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function pick(random, alphabet, length) {
  let out = "";
  for (let index = 0; index < length; index += 1) out += alphabet[Math.floor(random() * alphabet.length)];
  return out;
}

/** Mixed case with at least four digits standing between letters, so every token-shape rule sees a token. */
function isTokenShaped(value) {
  if (!/[a-z]/.test(value) || !/[A-Z]/.test(value)) return false;
  const scattered = [...value.matchAll(/[A-Za-z]\d[A-Za-z]/g)].length;
  return scattered >= 4 && (value.match(/\d/g) ?? []).length >= 4;
}

/** Every distinct substring of `value` at `length` characters (the whole value when it is shorter). */
export function windowsOf(value, length = WINDOW_MIN) {
  if (value.length <= length) return [value];
  const windows = new Set();
  for (let index = 0; index + length <= value.length; index += 1) windows.add(value.slice(index, index + length));
  return [...windows];
}

/**
 * The longest window (6 to 24 characters, or the whole of a value under 6) of `planted` that occurs
 * in `text`, or undefined when none does. Any longer window contains a 6-character one, so the short
 * windows decide and the longest is found only for the report.
 */
export function leakedWindow(text, planted) {
  if (typeof text !== "string" || typeof planted !== "string" || planted.length === 0) return undefined;
  if (planted.length <= WINDOW_MIN) return text.includes(planted) ? planted : undefined;
  const shortest = windowsOf(planted, WINDOW_MIN).find((window) => text.includes(window));
  if (shortest === undefined) return undefined;
  for (let length = Math.min(WINDOW_MAX, planted.length); length > WINDOW_MIN; length -= 1) {
    const found = windowsOf(planted, length).find((window) => text.includes(window));
    if (found !== undefined) return found;
  }
  return shortest;
}

function collidingWindow(value, fixtureText) {
  return windowsOf(value, WINDOW_MIN).find((window) => fixtureText.includes(window));
}

/**
 * Random-looking values of the shapes every class needs: `n` token-shaped canaries (32 characters,
 * mixed case, digits scattered), name-shaped lowercase words of 12, alphabetic values of 6 to 11,
 * values under 6, one-digit-group values, values of 12 or more letters, UUIDs, base64-looking opaque
 * values, and the fixed passwords. No 6-character window of a random canary occurs in `fixtureText`
 * or in the harness vocabulary, and no two random canaries share an 8-character window; the seed
 * makes a run reproducible.
 */
export function makeCanaries(n = 8, fixtureText = "", { seed = DEFAULT_SEED } = {}) {
  const random = makeRandom(seed);
  // A random canary must not share a window with the fixed passwords either: both are planted values.
  const fixture = `${fixtureText}\n${VOCABULARY.join("\n")}\n${FIXED_PASSWORDS.join("\n")}`;
  const taken = new Set();
  const randomValues = [];
  const fresh = (generate, shape) => {
    for (let attempt = 0; attempt < 500; attempt += 1) {
      const value = generate();
      if (shape && !shape(value)) continue;
      if (collidingWindow(value, fixture) !== undefined) continue;
      const long = windowsOf(value, DISTINCT_WINDOW);
      if (value.length >= DISTINCT_WINDOW && long.some((window) => taken.has(window))) continue;
      for (const window of long) taken.add(window);
      randomValues.push(value);
      return value;
    }
    throw new Error("makeCanaries: could not find a canary disjoint from the fixture text");
  };
  const many = (count, generate, shape) => Array.from({ length: count }, () => fresh(generate, shape));
  const tokens = many(Math.max(n, 4), () => pick(random, ALNUM, 32), isTokenShaped);
  const nameShaped = many(5, () => pick(random, LOWER, 12));
  const alphabetic = many(3, () => pick(random, LOWER, 9));
  const short = many(3, () => `${pick(random, LOWER, 3)}${pick(random, DIGITS, 2)}`);
  const digitGroup = many(3, () => `${pick(random, LOWER, 7)}${pick(random, DIGITS, 4)}`);
  const long = many(3, () => pick(random, LOWER, 20));
  const uuid = many(2, () => `${pick(random, HEX, 8)}-${pick(random, HEX, 4)}-4${pick(random, HEX, 3)}-a${pick(random, HEX, 3)}-${pick(random, HEX, 12)}`);
  const opaque = many(2, () => Buffer.from(`svc:${pick(random, LOWER, 9)}`).toString("base64").replace(/[+/=]/g, "A"), (value) => value.length >= 12 && /[a-z]/.test(value) && /[A-Z]/.test(value));
  const upperKey = many(2, () => pick(random, `${UPPER}234567`, 16), (value) => /\d/.test(value) && /[A-Z]/.test(value));
  return Object.freeze({
    tokens,
    nameShaped,
    alphabetic,
    short,
    digitGroup,
    long,
    uuid,
    opaque,
    upperKey,
    passwords: FIXED_PASSWORDS,
    random: Object.freeze([...randomValues]),
    seed,
  });
}

/**
 * Fails when any 6-character window of a random canary occurs in `fixtureText`, when a fixed
 * password occurs whole in it, or when two random canaries share an 8-character window. `canaries`
 * is the object `makeCanaries` returns or an array of values (all treated as random).
 */
export function assertCanariesDisjoint(canaries, fixtureText) {
  const randomValues = Array.isArray(canaries) ? canaries : canaries.random;
  const fixed = Array.isArray(canaries) ? [] : canaries.passwords;
  const problems = [];
  for (const value of randomValues) {
    const window = collidingWindow(value, fixtureText);
    if (window !== undefined) problems.push(`window "${window}" of canary ${value} occurs in the fixture text`);
  }
  for (const value of fixed) {
    if (fixtureText.includes(value)) problems.push(`fixed password ${value} occurs in the fixture text`);
  }
  const owners = new Map();
  for (const value of randomValues) {
    if (value.length < DISTINCT_WINDOW) continue;
    for (const window of windowsOf(value, DISTINCT_WINDOW)) {
      const owner = owners.get(window);
      if (owner !== undefined && owner !== value) problems.push(`window "${window}" occurs in both ${owner} and ${value}`);
      owners.set(window, value);
    }
  }
  if (problems.length > 0) throw new Error(`canaries collide with the fixture:\n- ${problems.join("\n- ")}`);
}

// ---------------------------------------------------------------------------------------------
// Row builders. A text cell is `{ label, input, planted, mustKeep, mustRemove, sinks }`: `planted`
// values must be absent from the output down to their windows, `mustRemove` strings absent whole,
// `mustKeep` strings present whole; `sinks` names the scrubber set ("error", "data", or "all").
// ---------------------------------------------------------------------------------------------

function cell(label, input, { planted = [], mustKeep = [], mustRemove = [], sinks = "all", informational = false } = {}) {
  return { label, input, planted: planted.filter(Boolean), mustKeep: mustKeep.filter(Boolean), mustRemove: mustRemove.filter(Boolean), sinks, informational };
}

/** A token index that stays inside the canary set an integration may have sized itself. */
function tokenAt(canaries, index) {
  return canaries.tokens[index % canaries.tokens.length];
}

function nameShapedAt(canaries, index) {
  return canaries.nameShaped[index % canaries.nameShaped.length];
}

function alternateCase(word) {
  return [...word].map((character, index) => (index % 2 === 0 ? character.toLowerCase() : character.toUpperCase())).join("");
}

const PAIR_FORMS = Object.freeze([
  ["NAME=v", (key, value) => `${key}=${value}`],
  ["NAME: v", (key, value) => `${key}: ${value}`],
  ["NAME:v", (key, value) => `${key}:${value}`],
  ['"NAME": "v"', (key, value) => `"${key}": "${value}"`],
  ['{"NAME":"v"}', (key, value) => `{"${key}":"${value}"}`],
  ["JSON-escaped member", (key, value) => `\\"${key}\\": \\"${value}\\"`],
  ["single-quoted", (key, value) => `${key}='${value}'`],
  ["double-quoted", (key, value) => `${key}="${value}"`],
  ["export NAME=v", (key, value) => `export ${key}=${value}`],
  ['YAML NAME: "v"', (key, value) => `${key}: "${value}"`],
  ["XML attribute", (key, value) => `<config ${key}="${value}" />`],
  ["in prose", (key, value) => `upstream echoed ${key}=${value} before closing`],
  ["after a colon-terminated word", (key, value) => `proxy: ${key}=${value}`],
  ["inside a JSON string member", (key, value) => `{"detail":"upstream sent ${key}=${value}"}`],
]);

function unique(values) {
  return [...new Set(values.filter((value) => typeof value === "string" && value.length > 0))];
}

function credentialValueSet(canaries) {
  return [
    ["token", canaries.tokens[0]],
    ["name-shaped", canaries.nameShaped[0]],
    ["alphabetic 6-11", canaries.alphabetic[0]],
    ["under 6", canaries.short[0]],
    ["one digit group", canaries.digitGroup[0]],
    ["12 or more", canaries.long[0]],
    ...canaries.passwords.map((password) => [`password ${password}`, password]),
  ];
}

function credentialPairCells(options, canaries) {
  const cells = [];
  const keys = unique([...(options.credentialKeys ?? []), ...GENERIC_CREDENTIAL_KEYS]);
  const values = credentialValueSet(canaries);
  for (const key of keys) {
    for (const [valueName, value] of values) {
      for (const [formName, form] of PAIR_FORMS) {
        cells.push(cell(`credential key ${key} / ${valueName} / ${formName}`, form(key, value), { planted: [value], mustKeep: [key] }));
      }
    }
  }
  const bearerValues = [
    ["UUID", canaries.uuid[0]],
    ["random", canaries.tokens[1]],
    ["name-shaped", canaries.nameShaped[1]],
  ];
  for (const key of [...BEARER_ID_KEYS, ...SESSION_ID_KEYS]) {
    for (const [valueName, value] of bearerValues) {
      for (const [formName, form] of PAIR_FORMS) {
        cells.push(cell(`bearer-id key ${key} / ${valueName} / ${formName}`, form(key, value), { planted: [value], mustKeep: [key] }));
      }
    }
  }
  const controls = [
    ["client_id", canaries.uuid[1]],
    ["tenant_id", canaries.uuid[1]],
    ["access_key_id", "key-2026-primary"],
    ["key_id", "primary-signing-key"],
    ["secret_name", "my-secret"],
  ];
  for (const [key, value] of controls) {
    for (const [formName, form] of PAIR_FORMS) {
      cells.push(cell(`identifier control ${key}=<${value === canaries.uuid[1] ? "uuid" : "plain"}> / ${formName}`, form(key, value), { mustKeep: [key, value] }));
    }
  }
  const awsKeyId = `AKIA${canaries.upperKey[0]}`;
  for (const [formName, form] of PAIR_FORMS) {
    cells.push(cell(`identifier control access_key_id=AKIA<16> removed by shape / ${formName}`, form("access_key_id", awsKeyId), { planted: [awsKeyId], mustKeep: ["access_key_id"] }));
  }
  for (const key of unique(options.settingKeys ?? [])) {
    for (const value of PLAIN_SETTING_VALUES) {
      for (const [formName, form] of PAIR_FORMS) {
        cells.push(cell(`setting key ${key}=${value} / ${formName}`, form(key, value), { mustKeep: [key, value] }));
      }
    }
  }
  const webhook = `https://hooks.example.com/services/T/B/${canaries.tokens[2]}`;
  for (const [formName, form] of PAIR_FORMS) {
    cells.push(cell(`webhook_url loses path and query / ${formName}`, form("webhook_url", webhook), { planted: [canaries.tokens[2]], mustRemove: ["services/T/B"], mustKeep: ["webhook_url"] }));
    cells.push(cell(`bare webhook loses path and query / ${formName}`, form("webhook", webhook), { planted: [canaries.tokens[2]], mustRemove: ["services/T/B"], mustKeep: ["webhook"] }));
  }
  for (const [key, value] of SETTING_SUFFIX_CONTROLS) {
    for (const [formName, form] of PAIR_FORMS) {
      cells.push(cell(`setting suffix control ${key}=${value} / ${formName}`, form(key, value), { mustKeep: [key, value] }));
    }
  }
  for (const key of SETTING_SUFFIX_UUID_CONTROL_KEYS) {
    for (const [formName, form] of PAIR_FORMS) {
      cells.push(cell(`setting suffix control ${key}=<uuid> / ${formName}`, form(key, canaries.uuid[1]), { mustKeep: [key, canaries.uuid[1]] }));
    }
  }
  cells.push(...flagAndPathCarrierCells(options, canaries));
  cells.push(...schemeWordOrderCells(options, canaries));
  for (const key of unique(options.identifierKeys ?? [])) {
    for (const value of IDENTIFIER_PLAIN_VALUES) {
      for (const [formName, form] of PAIR_FORMS) {
        cells.push(cell(`identifier key ${key}=<plain ${value}> / ${formName}`, form(key, value), { mustKeep: [key, value] }));
      }
    }
    for (const [formName, form] of PAIR_FORMS) {
      cells.push(cell(`identifier key ${key}=<token> lost by shape / ${formName}`, form(key, canaries.tokens[3]), { planted: [canaries.tokens[3]], mustKeep: [key], sinks: "error" }));
    }
  }
  for (const secret of unique(options.configuredSecrets ?? [])) {
    cells.push(cell("configured secret in prose", `the value ${secret} was echoed by the proxy`, { planted: [secret], mustKeep: ["echoed by the proxy"] }));
    cells.push(cell("configured secret under a setting key", `auth_method=${secret}`, { planted: [secret], mustKeep: ["auth_method"] }));
    cells.push(cell("configured secret in a JSON member", `{"detail":"${secret}"}`, { planted: [secret], mustKeep: ["detail"] }));
  }
  return cells;
}

/**
 * Reviewer #78 row D: a credential name after `--`, `-D`, or `/` is a carrier (CLI flags echoed in a
 * spawned CLI's stderr, path segments), with the controls the ruling keeps (a bare path label whose
 * `:` continues as prose) and the pair positions main already handled.
 */
function flagAndPathCarrierCells(options, canaries) {
  const cells = [];
  const keys = unique([...FLAG_PATH_KEYS, ...(options.credentialKeys ?? [])]);
  const values = [
    ["word", nameShapedAt(canaries, 3)],
    ["token", tokenAt(canaries, 8)],
  ];
  const forms = [
    ["--NAME=v after a command", (key, value) => `mysql --${key}=${value} -h db`, (key) => [`mysql --${key}`, "-h db"]],
    ["--NAME v after a command", (key, value) => `psql --${key} ${value} -h db`, (key) => [`psql --${key}`, "-h db"]],
    ["--NAME=v at line start", (key, value) => `--${key}=${value}`, (key) => [`--${key}`]],
    ["--NAME=v before a URL", (key, value) => `curl --${key}=${value} https://api.example.com/v1`, (key) => [`curl --${key}`, "https://api.example.com/v1"]],
    ["-DNAME=v", (key, value) => `java -D${key}=${value} -jar app.jar`, (key) => [`java -D${key}`, "-jar app.jar"]],
    ["-Dprefix.NAME=v", (key, value) => `java -Dspring.datasource.${key}=${value} -jar app.jar`, (key) => [`java -Dspring.datasource.${key}`, "-jar app.jar"]],
    ["path/NAME=v", (key, value) => `path/${key}=${value} see log`, (key) => [`path/${key}`, "see log"]],
    ["/NAME=v at line start", (key, value) => `/${key}=${value}`, (key) => [`/${key}`]],
    ["kv/NAME: v (single token)", (key, value) => `kv/${key}: ${value}`, (key) => [`kv/${key}`]],
  ];
  for (const key of keys) {
    for (const [valueName, value] of values) {
      for (const [formName, form, keep] of forms) {
        cells.push(cell(`flag or path carrier ${key} / ${valueName} / ${formName}`, form(key, value), { planted: [value], mustKeep: keep(key) }));
      }
    }
  }
  cells.push(cell("path label control: /api/v1/api-tokens: prose continuation", "/api/v1/api-tokens: request failed with 403", { mustKeep: ["/api/v1/api-tokens: request failed with 403"] }));
  for (const [valueName, value] of values) {
    cells.push(cell(`flag control --set db.password=v / ${valueName}`, `helm --set db.password=${value} upgrade`, { planted: [value], mustKeep: ["helm --set db.password", "upgrade"] }));
    cells.push(cell(`compound control x_password=v / ${valueName}`, `x_password=${value}`, { planted: [value], mustKeep: ["x_password"] }));
    cells.push(cell(`parenthesis control (password=v) / ${valueName}`, `(password=${value})`, { planted: [value], mustKeep: ["(password"] }));
    cells.push(cell(`comma control a,password=v / ${valueName}`, `a,password=${value}`, { planted: [value], mustKeep: ["a,password"] }));
  }
  return cells;
}

/**
 * CodeRabbit r4078025849 on #63: a credential-named key whose value starts with a scheme word is
 * redacted unconditionally (`sslPassword=splunk rejected`, `db_password: token`); the scheme-word
 * branches apply only to Authorization-style keys and bare scheme words in prose. The scheme word is
 * the value, so it must go; a prose continuation after it may stay. Keys that contain the scheme word
 * themselves are left out of that scheme's rows so the key cannot be read as the surviving value.
 */
function schemeWordOrderCells(options, canaries) {
  const cells = [];
  const keys = unique(["sslPassword", "db_password", ...GENERIC_CREDENTIAL_KEYS, ...(options.credentialKeys ?? [])]);
  const schemes = unique(["splunk", "token", "bearer", "Basic", ...(options.schemeWords ?? [])]);
  const forms = [
    ["NAME=<scheme> rejected", (key, scheme) => `${key}=${scheme} rejected`, (scheme) => [`=${scheme}`]],
    ["NAME: <scheme>", (key, scheme) => `${key}: ${scheme}`, (scheme) => [`: ${scheme}`]],
    ['NAME="<scheme> rejected"', (key, scheme) => `${key}="${scheme} rejected"`, (scheme) => [`"${scheme}`]],
    ['"NAME": "<scheme>"', (key, scheme) => `"${key}": "${scheme}"`, (scheme) => [`"${scheme}"`]],
  ];
  const continuation = nameShapedAt(canaries, 4);
  for (const key of keys) {
    for (const scheme of schemes) {
      if (key.toLowerCase().includes(scheme.toLowerCase())) continue;
      for (const [formName, form, remove] of forms) {
        cells.push(cell(`scheme-word order ${key} / ${scheme} / ${formName}`, form(key, scheme), { mustRemove: remove(scheme), mustKeep: [key] }));
      }
      cells.push(cell(`scheme-word order ${key} / ${scheme} / NAME=<scheme> <word>`, `${key}=${scheme} ${continuation}`, { mustRemove: [`=${scheme}`], mustKeep: [key] }));
    }
  }
  return cells;
}

function headerCarrierLines(options, value) {
  const lines = [];
  const schemes = unique([...(options.schemeWords ?? []), "Bearer"]);
  for (const header of unique([...(options.headerNames ?? []), "Authorization", "Cookie", "X-Api-Key"])) {
    const lower = header.toLowerCase();
    if (lower === "authorization" || lower === "proxy-authorization") {
      for (const scheme of schemes) lines.push([`${header}: ${scheme}`, `${header}: ${scheme} ${value}`, [header, scheme]]);
    } else if (lower === "cookie" || lower === "set-cookie") {
      lines.push([`${header}: sid=`, `${header}: sid=${value}`, [header]]);
    } else {
      lines.push([`${header}:`, `${header}: ${value}`, [header]]);
    }
  }
  return lines;
}

function escapeBoundaryCells(options, canaries) {
  const cells = [];
  const values = [
    ["token", canaries.tokens[4]],
    ["name-shaped", canaries.nameShaped[2]],
  ];
  const pairKeys = unique([...(options.credentialKeys ?? []), "api_key", "password", "client_token"]);
  const contexts = [
    ["bare", (escape, carrier) => `request failed${escape}${carrier} see the log`, ["failed"]],
    ["inside a JSON string member", (escape, carrier) => `{"detail":"request failed${escape}${carrier} see the log"}`, ["failed", "detail"]],
    ["after a colon-terminated word", (escape, carrier) => `request headers:${escape}${carrier} see the log`, ["headers"]],
  ];
  const carriersFor = (value) => [
    ...headerCarrierLines(options, value),
    ...pairKeys.flatMap((key) => [
      [`${key}=`, `${key}=${value}`, [key]],
      [`${key}: `, `${key}: ${value}`, [key]],
    ]),
    ["URL userinfo", `https://svc:${value}@api.example.com/v1/items`, ["api.example.com"]],
    ["Cookie: theme=", `Cookie: theme=${value}`, ["Cookie"]],
  ];
  const prefixes = [...ESCAPE_FORMS.map((literal) => [`escape ${JSON.stringify(literal)}`, literal]), ...DECODED_CONTROLS.map((decoded) => [`decoded control ${JSON.stringify(decoded)}`, decoded])];
  for (const [prefixName, escape] of prefixes) {
    for (const [valueName, value] of values) {
      for (const [carrierName, carrier, keep] of carriersFor(value)) {
        for (const [contextName, context, contextKeep] of contexts) {
          cells.push(cell(`${prefixName} / ${carrierName} / ${valueName} / ${contextName}`, context(escape, carrier), { planted: [value], mustKeep: [...keep, ...contextKeep] }));
        }
      }
    }
    for (const [contextName, context, contextKeep] of contexts) {
      cells.push(cell(`${prefixName} / control Content-Type / ${contextName}`, context(escape, "Content-Type: application/json"), { mustKeep: ["Content-Type: application/json", ...contextKeep] }));
      cells.push(cell(`${prefixName} / control X-Request-Id / ${contextName}`, context(escape, `X-Request-Id: ${canaries.uuid[1]}`), { mustKeep: [`X-Request-Id: ${canaries.uuid[1]}`, ...contextKeep] }));
    }
  }
  // Percent-encoded and JavaScript hex line breaks: the same rows, informational by the principal's ruling.
  for (const literal of INFORMATIONAL_ESCAPE_FORMS) {
    for (const [valueName, value] of values) {
      for (const [carrierName, carrier, keep] of carriersFor(value)) {
        for (const [contextName, context, contextKeep] of contexts) {
          cells.push(cell(`informational escape ${JSON.stringify(literal)} / ${carrierName} / ${valueName} / ${contextName}`, context(literal, carrier), { planted: [value], mustKeep: [...keep, ...contextKeep], informational: true }));
        }
      }
    }
  }
  // Slash-escaped URLs (reviewer #78 row C): `:\/\/` is a URL like `://`, losing userinfo and query.
  const urlContexts = [
    ["bare", (url) => `upstream ${url} refused`, ["upstream", "refused"]],
    ["inside a JSON string member", (url) => `{"detail":"upstream ${url} refused"}`, ["upstream", "refused", "detail"]],
    ["after a colon-terminated word", (url) => `request url: ${url}`, ["request url"]],
  ];
  for (const [valueName, value] of values) {
    const urls = [
      ["slash-escaped https URL userinfo", `https:\\/\\/svc:${value}@api.example.com\\/v1\\/items`, ["api.example.com"]],
      ["slash-escaped proxy URL userinfo", `proxy:\\/\\/svc:${value}@proxy.example.com:8080`, ["proxy.example.com"]],
      ["slash-escaped https URL query", `https:\\/\\/api.example.com\\/v1\\/items?token=${value}&x=1`, ["api.example.com"]],
    ];
    for (const [urlName, url, keep] of urls) {
      for (const [contextName, context, contextKeep] of urlContexts) {
        cells.push(cell(`${urlName} / ${valueName} / ${contextName}`, context(url), { planted: [value], mustKeep: [...keep, ...contextKeep] }));
      }
    }
  }
  return cells;
}

function cookieHeaderNameCells(canaries) {
  const cells = [];
  const value = canaries.tokens[5];
  const second = canaries.tokens[6];
  const uuid = canaries.uuid[1];
  const followingKeep = [...CONTROL_HEADER_LINES, `X-Request-Id: ${uuid}`];
  const following = followingKeep.join("; ");
  for (const name of ["my.sid", "ASP.NET_SessionId", ".AspNetCore.Session", "my'pref"]) {
    cells.push(cell(`later cookie pair name ${name}`, `Cookie: theme=dark; ${name}=${value}`, { planted: [value], mustKeep: ["Cookie"] }));
    cells.push(cell(`later cookie pair name ${name} before headers`, `Cookie: theme=dark; ${name}=${value}; ${following}`, { planted: [value], mustKeep: ["Cookie", ...followingKeep] }));
  }
  cells.push(cell("apostrophe inside a cookie value", `Cookie: sid=O'${value}`, { planted: [value], mustKeep: ["Cookie"] }));
  cells.push(cell("apostrophe inside a cookie value before headers", `Cookie: sid=O'${value}; ${following}`, { planted: [value], mustKeep: ["Cookie", ...followingKeep] }));
  for (const symbol of RFC6265_TOKEN_SYMBOLS) {
    cells.push(cell(`RFC 6265 token character ${JSON.stringify(symbol)} in a later cookie name`, `Cookie: theme=dark; my${symbol}sid=${value}; ${following}`, { planted: [value], mustKeep: ["Cookie", ...followingKeep] }));
  }
  for (const symbol of ["&", "#"]) {
    cells.push(cell(`${symbol} cookie name with a JSON-escaped quoted value`, `Cookie: theme=dark; my${symbol}sid=\\"${value}\\"; X-Request-Id: ${uuid}`, { planted: [value], mustKeep: ["Cookie", `X-Request-Id: ${uuid}`] }));
    cells.push(cell(`${symbol} credential-worded cookie name with a JSON-escaped quoted value`, `Cookie: theme=dark${symbol}sid=\\"${value}\\"; X-Request-Id: ${uuid}`, { planted: [value], mustKeep: ["Cookie", `X-Request-Id: ${uuid}`] }));
  }
  for (const separator of ["; ", ", "]) {
    const attributes = `Set-Cookie: session=${value}; Path=/; HttpOnly; Expires=Wed, 21 Oct 2026 07:28:00 GMT${separator}${followingKeep.join(separator)}`;
    cells.push(cell(`cookie attributes before the next header (${JSON.stringify(separator.trim())})`, attributes, { planted: [value], mustKeep: ["Set-Cookie", ...followingKeep] }));
  }
  // CodeRabbit r4077655607 on `dd7426e`: a query-pair value that may hold `;` consumes the cookie
  // separator before the cookie reader runs and the later pair survives; expected `Cookie: [REDACTED]`.
  const later = nameShapedAt(canaries, 4);
  for (const symbol of ["&", "#"]) {
    cells.push(cell(`${symbol} cookie name then a later pair (query separator)`, `Cookie: ${symbol}sid=${value}; pref=${later}`, { planted: [value, later], mustKeep: ["Cookie"] }));
    cells.push(cell(`${symbol} cookie name then a later pair before a header`, `Cookie: ${symbol}sid=${value}; pref=${later}; X-Request-Id: ${uuid}`, { planted: [value, later], mustKeep: ["Cookie", `X-Request-Id: ${uuid}`] }));
  }
  cells.push(cell("& cookie name in Set-Cookie before attributes", `Set-Cookie: &sid=${value}; Path=/; HttpOnly`, { planted: [value], mustKeep: ["Set-Cookie"] }));
  cells.push(cell("following header whose name holds a dot", `Cookie: sid=${value}; X.Api.Key: ${second}; Content-Type: text/plain`, { planted: [value, second], mustKeep: ["Cookie", "X.Api.Key", "Content-Type: text/plain"] }));
  cells.push(cell("controls after a cookie value", `Cookie: sid=${value}; ${following}`, { planted: [value], mustKeep: ["Cookie", ...followingKeep] }));
  return cells;
}

function quotedCompoundHeaderCells(canaries) {
  const rows = [];
  const first = canaries.tokens[6];
  const second = canaries.tokens[7];
  const date = "Date: Mon, 22 Sep 2026 12:30:00 GMT";
  rows.push(["double-quoted X-Api-Key", `X-Api-Key: "${first}"`, [first], ["X-Api-Key", '"']]);
  rows.push(["single-quoted X-Api-Key", `X-Api-Key: '${first}'`, [first], ["X-Api-Key", "'"]]);
  rows.push(["JSON-escaped quoted X-Api-Key (depth 1)", `X-Api-Key: \\"${first}\\"`, [first], ["X-Api-Key", '\\"']]);
  rows.push(["JSON-escaped quoted X-Api-Key (depth 2)", `X-Api-Key: \\\\\\"${first}\\\\\\"`, [first], ["X-Api-Key"]]);
  rows.push(["quoted cookie pair", `Cookie: sid="${first}"`, [first], ["Cookie"]]);
  rows.push(["quoted bearer value", `Authorization: Bearer "${first}"`, [first], ["Authorization", "Bearer"]]);
  rows.push(["compound unquoted", `Cookie: sid=${first}; X-Api-Key: ${second}; Content-Type: application/json`, [first, second], ["Cookie", "X-Api-Key", "Content-Type: application/json"]]);
  rows.push(["compound quoted", `Cookie: sid="${first}"; X-Api-Key: "${second}"; Content-Type: "application/json"`, [first, second], ["Cookie", "X-Api-Key", 'Content-Type: "application/json"']]);
  rows.push(["compound all bare", `Cookie: ${first}; X-Api-Key: ${second}; Content-Type: application/json`, [first, second], ["Cookie", "X-Api-Key", "Content-Type: application/json"]]);
  rows.push(["closed quoted value holding ; Name:", `X-Api-Key: "${first}; Content-Type: text/html"; ${date}`, [first], ["X-Api-Key", date]]);
  rows.push(["unterminated quoted value before the next header", `X-Api-Key: "${first}; Content-Type: application/json`, [first], ["X-Api-Key", "Content-Type: application/json"]]);
  rows.push(["two quoted headers on one line", `X-Api-Key: "${first}", Authorization: "Bearer ${second}"`, [first, second], ["X-Api-Key", "Authorization", "Bearer"]]);
  rows.push(["header then JSON fragment", `X-Api-Key: ${first} {"status":"denied"}`, [first], ["X-Api-Key", '{"status":"denied"}']]);
  rows.push(["JSON-object headers with escaped inner quotes", `{"Cookie": "sid=\\"${first}\\"", "X-Api-Key": "${second}"}`, [first, second], ['"Cookie"', '"X-Api-Key"']]);
  rows.push(["double-escaped raw JSON string", `"{\\"Cookie\\": \\"sid=\\\\\\"${first}\\\\\\"\\", \\"Content-Type\\": \\"application/json\\"}"`, [first], ["Cookie", "Content-Type"]]);
  const cells = [];
  for (const [label, line, planted, keep] of rows) {
    cells.push(cell(label, line, { planted, mustKeep: keep }));
    cells.push(cell(`${label} inside a 502 body`, `<html><head><title>502 Bad Gateway</title></head><body><p>upstream replied with ${line}</p></body></html>`, { planted, mustKeep: [...keep, "502 Bad Gateway", "upstream replied with"] }));
  }
  return cells;
}

function schemeCasingCells(options, canaries) {
  const cells = [];
  const schemes = unique([...FIXED_SCHEME_WORDS, ...(options.schemeWords ?? [])]);
  const values = [
    ["token", canaries.tokens[7]],
    ["opaque", canaries.opaque[0]],
  ];
  for (const scheme of schemes) {
    // Lower, upper, the given spelling, and an alternating one: any casing matches (01:40 ruling).
    const casings = unique([scheme.toLowerCase(), scheme.toUpperCase(), scheme, alternateCase(scheme)]);
    for (const spelled of casings) {
      for (const [valueName, value] of values) {
        cells.push(cell(`scheme ${spelled} in a header / ${valueName}`, `Authorization: ${spelled} ${value}`, { planted: [value], mustKeep: ["Authorization", spelled] }));
        cells.push(cell(`scheme ${spelled} in prose / ${valueName}`, `replayed ${spelled} ${value} upstream`, { planted: [value], mustKeep: ["replayed", spelled, "upstream"] }));
      }
    }
  }
  cells.push(cell("fixed prose Bearer token is missing", "Bearer token is missing", { mustKeep: ["Bearer token is missing"] }));
  cells.push(cell('fixed prose Bearer realm="api"', 'Bearer realm="api"', { mustKeep: ['Bearer realm="api"'] }));
  return cells;
}

/** The unambiguous data-side token shapes; each entry is `[label, text, plantedWindows]`. */
function dataShapeValues(canaries) {
  const pem = `-----BEGIN PRIVATE KEY-----\n${canaries.tokens[0]}${canaries.tokens[1]}\n${canaries.tokens[2]}${canaries.tokens[3]}\n-----END PRIVATE KEY-----`;
  const jwt = `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.${canaries.tokens[4]}.${canaries.tokens[5]}`;
  return [
    ["sk_live_<24>", `sk_live_${canaries.tokens[6].slice(0, 24)}`, [canaries.tokens[6].slice(0, 24)]],
    ["xoxb-<...>", `xoxb-${canaries.digitGroup[1].slice(-4)}12345678-${canaries.digitGroup[2].slice(-4)}123456789-${canaries.tokens[7].slice(0, 24)}`, [canaries.tokens[7].slice(0, 24)]],
    ["ghp_<36>", `ghp_${canaries.tokens[0]}${canaries.tokens[1].slice(0, 4)}`, [canaries.tokens[0]]],
    ["AKIA<16>", `AKIA${canaries.upperKey[1]}`, [`AKIA${canaries.upperKey[1]}`]],
    ["JWT", jwt, [canaries.tokens[4], canaries.tokens[5]]],
    ["PEM block", pem, [canaries.tokens[0], canaries.tokens[1], canaries.tokens[2], canaries.tokens[3]]],
    ["carrier line", `Authorization: Bearer ${canaries.tokens[2]}`, [canaries.tokens[2]]],
  ];
}

function dataShapeTextCells(canaries) {
  const cells = [];
  for (const [label, text, planted] of dataShapeValues(canaries)) {
    cells.push(cell(`${label} in a free-text field`, `note: key ${text} end`, { planted, mustKeep: ["note: key", "end"], sinks: "data" }));
  }
  cells.push(cell("name-shaped 16+ run stays on the data side", `cluster ${NAME_SHAPED_DATA_VALUE} was read`, { mustKeep: [NAME_SHAPED_DATA_VALUE], sinks: "data" }));
  return cells;
}

/** Walker cells: `{ label, value, planted, mustKeep }`; the walker's output is stringified and scanned. */
function dataShapeWalkerCells(canaries) {
  const cells = [];
  for (const [label, text, planted] of dataShapeValues(canaries)) {
    cells.push({ label: `${label} in a benign-keyed field`, value: { id: "rec-1", description: `note: key ${text} end`, tags: [{ notes: [`also ${text}`] }] }, planted, mustKeep: ["rec-1", "note: key"] });
  }
  cells.push({ label: "name-shaped 16+ run stays in a benign-keyed field", value: { id: "rec-2", description: `cluster ${NAME_SHAPED_DATA_VALUE} was read` }, planted: [], mustKeep: [NAME_SHAPED_DATA_VALUE] });
  return cells;
}

/** `{ level_1: [ { level_2: ... leaf } ] }` with an array every third level, `depth` containers deep. */
function nest(depth, leaf) {
  let value = leaf;
  for (let level = depth; level >= 1; level -= 1) {
    value = level % 3 === 0 ? [value] : { [`level_${level}`]: value };
  }
  return value;
}

function depthPlants(depth, canaries, sibling) {
  return {
    credential: nest(depth, { password: canaries.tokens[0], api_key: canaries.tokens[1], name: sibling }),
    carrier: nest(depth, { description: `Authorization: Bearer ${canaries.tokens[2]}`, name: sibling }),
  };
}

function isContainer(value) {
  return value !== null && typeof value === "object";
}

/** The leaf of `nest(depth, leaf)` inside a walker's output, or undefined when a container on the way was replaced. */
function leafAt(output, depth) {
  let cursor = output;
  for (let level = 1; level <= depth; level += 1) {
    if (!isContainer(cursor)) return undefined;
    cursor = Array.isArray(cursor) ? cursor[0] : cursor[`level_${level}`];
  }
  return cursor;
}

/** The deepest nesting at which `walker` still keeps containers (the cap), or null when it keeps them up to MAX_DEPTH_PROBE. */
async function detectCap(walker) {
  for (let depth = 1; depth <= MAX_DEPTH_PROBE; depth += 1) {
    const output = await walker(structuredClone(nest(depth, { name: `benign-sibling-${depth}` })));
    if (!isContainer(leafAt(output, depth))) return depth - 1;
  }
  return null;
}

function depthsFor(cap) {
  if (cap === null) return [1, 8, 33, 34, 65, MAX_DEPTH_PROBE];
  return [...new Set([1, cap - 1, cap, cap + 1, cap + 2].filter((depth) => depth >= 1))];
}

// ---------------------------------------------------------------------------------------------
// Runner support
// ---------------------------------------------------------------------------------------------

/**
 * A `fetch` that records every request and answers each with `respond(url, init)` (a plain
 * `{ status, statusText, contentType, headers, body }` or a `Response`). Returns `{ fetch, requests }`;
 * each request is `{ url, method, headers }` with the header names lowercased.
 */
export function recordingFetch(respond) {
  const requests = [];
  const fetchImpl = async (input, init = {}) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const headers = {};
    const source = init.headers ?? (typeof input === "object" && input !== null && "headers" in input ? input.headers : undefined);
    if (source) {
      const entries = typeof source.entries === "function" ? [...source.entries()] : Object.entries(source);
      for (const [name, value] of entries) headers[String(name).toLowerCase()] = String(value);
    }
    requests.push({ url, method: init.method ?? "GET", headers });
    const answer = await respond(url, init);
    if (answer instanceof Response) return answer;
    const responseHeaders = { ...(answer.headers ?? {}) };
    if (answer.contentType !== undefined && answer.contentType !== null) responseHeaders["content-type"] = answer.contentType;
    return new Response(answer.body ?? "", { status: answer.status ?? 200, statusText: answer.statusText ?? "", headers: responseHeaders });
  };
  return { fetch: fetchImpl, requests };
}

function stringify(value) {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}

function originOfParsedUrl(parsed) {
  return parsed.host.length > 0 ? `${parsed.protocol}//${parsed.host}` : parsed.protocol;
}

/** The URL with its username and password replaced by `[REDACTED]`; an unparseable string is masked by pattern. */
function maskUserinfo(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return String(url).replace(/^([A-Za-z][A-Za-z0-9+.-]*:)?(\/\/|\\\\)[^/\\?#@\s]*@/, "$1$2[REDACTED]@");
  }
  if (parsed.username.length === 0 && parsed.password.length === 0) return parsed.href;
  const userinfo = `${parsed.username.length > 0 ? "[REDACTED]" : ""}${parsed.password.length > 0 ? ":[REDACTED]" : ""}`;
  return `${parsed.protocol}//${userinfo}@${parsed.host}${parsed.pathname}${parsed.search}${parsed.hash}`;
}

/**
 * Classifies a request the runner made (CodeRabbit 5286122785 on #78 `8b92f20`: the origin test alone
 * let a userinfo-bearing request on the configured origin pass). Unsafe when the URL does not parse,
 * when its username or password is non-empty, or when its origin differs from the configured origin;
 * returns `{ reason, url }` with the userinfo masked, or `undefined` for a safe request.
 */
export function classifyRequest(url, configuredOrigin) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { reason: "does not parse as a URL", url: maskUserinfo(url) };
  }
  const masked = maskUserinfo(url);
  if (parsed.username.length > 0 || parsed.password.length > 0) return { reason: "carries userinfo", url: masked };
  const origin = originOfParsedUrl(parsed);
  if (origin !== configuredOrigin) return { reason: `origin ${origin} differs from the configured origin ${configuredOrigin}`, url: masked };
  return undefined;
}

/** Leaves of a JSON value, each with its path; an empty array or object is a leaf at its own path. */
function leaves(value, path = "$", out = []) {
  if (Array.isArray(value)) {
    if (value.length === 0) out.push([path, value]);
    else value.forEach((item, index) => leaves(item, `${path}[${index}]`, out));
  } else if (isContainer(value)) {
    const entries = Object.entries(value);
    if (entries.length === 0) out.push([path, value]);
    else for (const [key, item] of entries) leaves(item, `${path}.${key}`, out);
  } else out.push([path, value]);
  return out;
}

function findingId(finding, index) {
  if (!isContainer(finding)) return `#${index}`;
  return String(finding.id ?? finding.control_id ?? finding.controlId ?? finding.control ?? finding.rule ?? finding.check ?? finding.name ?? finding.title ?? `#${index}`);
}

function findingStatus(finding) {
  if (!isContainer(finding)) return undefined;
  const status = finding.status ?? finding.result ?? finding.verdict ?? finding.outcome ?? finding.state;
  return typeof status === "string" ? status.toLowerCase() : status;
}

function findingsById(findings) {
  const map = new Map();
  (Array.isArray(findings) ? findings : []).forEach((finding, index) => map.set(findingId(finding, index), finding));
  return map;
}

function isAbsenceLeaf(value) {
  return value === 0 || value === false || (Array.isArray(value) && value.length === 0) || (isContainer(value) && !Array.isArray(value) && Object.keys(value).length === 0);
}

/** Leaves whose value changed (or appeared) between `before` and `after`, as `[path, before, after]`. */
function changedLeaves(before, after) {
  const beforeMap = new Map(leaves(before));
  const changes = [];
  for (const [path, value] of leaves(after)) {
    const previous = beforeMap.get(path);
    const same = beforeMap.has(path) && (previous === value || (isContainer(previous) && isContainer(value) && stringify(previous) === stringify(value)));
    if (!same) changes.push([path, previous, value]);
  }
  return changes;
}

// ---------------------------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------------------------

/**
 * A sink is `{ name, fn, idempotent }`. `idempotent: false` marks a wrapping entry point (one that
 * frames its input, such as the message of an error built over a cause) whose second pass legitimately
 * differs from its first; the harness still scans that second pass for the planted values.
 */
function normalizeSinks(list, fallbackPrefix) {
  return (list ?? []).map((entry, index) => {
    if (typeof entry === "function") return { name: entry.name || `${fallbackPrefix}[${index}]`, fn: entry, idempotent: true };
    return { name: entry.name ?? `${fallbackPrefix}[${index}]`, fn: entry.fn, idempotent: entry.idempotent !== false };
  });
}

class ClassResult {
  constructor(definition) {
    this.id = definition.id;
    this.key = definition.key;
    this.name = definition.name;
    this.cells = 0;
    this.plantedCells = 0;
    this.leakingCells = 0;
    this.leaks = 0;
    this.mustKeepLosses = 0;
    this.idempotenceFailures = 0;
    this.entryPoints = new Set();
    this.examples = [];
    // Informational rows: run and counted, never part of the gating totals.
    this.informationalCells = 0;
    this.informational = 0;
    this.informationalEntryPoints = new Set();
    this.informationalExamples = [];
    // Class 8: every request the runner made that was unsafe, `{ label, link, url, reason }` with the userinfo masked.
    this.unsafeRequests = [];
    this.skipped = null;
    this.notes = [];
  }

  example(kind, detail) {
    if (this.examples.length < MAX_EXAMPLES_PER_CLASS) this.examples.push({ kind, ...detail });
  }

  informationalExample(kind, detail) {
    if (this.informationalExamples.length < MAX_INFORMATIONAL_EXAMPLES) this.informationalExamples.push({ kind, ...detail });
  }
}

function fixtureTextOf(options) {
  return [
    ...(options.headerNames ?? []),
    ...(options.schemeWords ?? []),
    ...(options.credentialKeys ?? []),
    ...(options.settingKeys ?? []),
    ...(options.identifierKeys ?? []),
    ...(options.inventories ?? []).map(String),
    ...(options.mustKeep ?? []),
    ...VOCABULARY,
  ].join("\n");
}

/**
 * Runs every class the integration wires and returns `{ integration, classes, leaks, mustKeepLosses,
 * idempotenceFailures, informational, report, ok, canaries }`. Every option is optional except
 * `integration`; a class whose runner is missing is skipped and the report says so. `ok` and
 * `assertNoLeaks` read the three gating lists; `informational` holds the observations on the
 * non-gating rows (per class: `informationalCells`, `informational`, `informationalEntryPoints`).
 *
 * - `textScrubbers: { error: [sink], data: [sink] }`, a sink being a function or
 *   `{ name, fn(text), idempotent }`; `idempotent: false` marks a wrapping entry point whose second
 *   pass differs by design (it is still scanned for the planted values). Classes 1 to 5 run their
 *   rows through both sets (shape-only rows through the error sinks), class 6 through the data sinks,
 *   class 10 through the error sinks.
 * - `headerNames`, `schemeWords`, `credentialKeys`, `settingKeys`, `identifierKeys`: the
 *   integration's own names, added to the fixed rows; `configuredSecrets`: values registered with the
 *   scrubbers, planted as such.
 * - `dataWalker: { name, fn(value), cap }` (class 6 and 7; `cap: null` detects the depth cap).
 * - `exportRunner({ scenario, plantedPayload, response, fetchImpl, requests, canaries })` returning
 *   `{ outputDir, zipPath, toolPayloads }` (classes 7 and 10, end to end, bundle and zip scanned).
 * - `nextLinkRunner({ nextLink, fetchImpl, requests, origin, canaries })` returning
 *   `{ requests, errorTexts, findings, truncated, note }` (class 8); `origin` sets the configured origin.
 *   Every request the runner made is classified (`classifyRequest`); each unsafe one is a leak and is
 *   listed on the class result as `unsafeRequests: [{ label, link, url, reason }]`, userinfo masked.
 * - `truncationRunner({ inventory, mode })` for `mode` in `baseline`, `zero-rows-truncated`,
 *   `capped`, `denied`, returning `{ findings, summaries, principals, readers }`, with `inventories`
 *   naming the sets (class 9).
 * - `bodyDescribers: [{ name, fn({ status, statusText, contentType, body, method, endpoint }) }]`
 *   (class 10); `mustKeep`: strings that must survive every scrub; `canaries` or `seed`.
 */
export async function runLeakProbe(options) {
  if (!options || typeof options.integration !== "string") throw new TypeError("runLeakProbe: options.integration is required");
  const fixtureText = fixtureTextOf(options);
  const canaries = options.canaries ?? makeCanaries(10, fixtureText, { seed: options.seed ?? DEFAULT_SEED });
  assertCanariesDisjoint(canaries, fixtureText);
  const errorSinks = normalizeSinks(options.textScrubbers?.error, "error");
  const dataSinks = normalizeSinks(options.textScrubbers?.data, "data");
  const allSinks = [...errorSinks, ...dataSinks];
  const sinksFor = (set) => (set === "error" ? errorSinks : set === "data" ? dataSinks : allSinks);
  const results = LEAK_CLASSES.map((definition) => new ClassResult(definition));
  const byId = (id) => results[id - 1];
  const leaks = [];
  const mustKeepLosses = [];
  const idempotenceFailures = [];
  const informational = [];

  // An observation on an informational row is counted and shown, never gated on.
  const recordInformational = (cls, kind, detail) => {
    cls.informational += 1;
    cls.informationalEntryPoints.add(detail.entryPoint);
    cls.informationalExample(kind, detail);
    informational.push({ class: cls.id, kind, ...detail });
  };
  const recordLeak = (cls, detail) => {
    if (detail.informational) return recordInformational(cls, "leak", detail);
    cls.leaks += 1;
    cls.entryPoints.add(detail.entryPoint);
    cls.example("leak", detail);
    leaks.push({ class: cls.id, ...detail });
  };
  const recordLoss = (cls, detail) => {
    if (detail.informational) return recordInformational(cls, "must-keep loss", detail);
    cls.mustKeepLosses += 1;
    cls.entryPoints.add(detail.entryPoint);
    cls.example("must-keep loss", detail);
    mustKeepLosses.push({ class: cls.id, ...detail });
  };
  const recordIdempotence = (cls, detail) => {
    if (detail.informational) return recordInformational(cls, "idempotence", detail);
    cls.idempotenceFailures += 1;
    cls.entryPoints.add(detail.entryPoint);
    cls.example("idempotence", detail);
    idempotenceFailures.push({ class: cls.id, ...detail });
  };

  const scanText = (cls, label, entryPoint, input, output, planted, mustKeep = [], mustRemove = [], informationalRow = false) => {
    const base = informationalRow ? { label, entryPoint, input, output, informational: true } : { label, entryPoint, input, output };
    for (const value of planted) {
      const window = leakedWindow(output, value);
      if (window !== undefined) recordLeak(cls, { ...base, planted: value, window });
    }
    for (const value of mustRemove) {
      if (output.includes(value)) recordLeak(cls, { ...base, planted: value, window: value });
    }
    for (const value of mustKeep) {
      if (!output.includes(value)) recordLoss(cls, { ...base, missing: value });
    }
  };

  const runTextCells = async (cls, cells) => {
    for (const row of cells) {
      const sinks = sinksFor(row.sinks);
      if (sinks.length === 0) continue;
      const informationalRow = row.informational === true;
      const flag = informationalRow ? { informational: true } : {};
      for (const sink of sinks) {
        if (informationalRow) cls.informationalCells += 1;
        else {
          cls.cells += 1;
          if (row.planted.length > 0 || row.mustRemove.length > 0) cls.plantedCells += 1;
        }
        const leaksBefore = cls.leaks;
        let first;
        let second;
        try {
          first = String(await sink.fn(row.input));
          second = String(await sink.fn(first));
        } catch (error) {
          recordLeak(cls, { ...flag, label: row.label, entryPoint: sink.name, input: row.input, output: `threw ${error instanceof Error ? error.message : String(error)}`, planted: row.planted[0] ?? "", window: "(scrubber threw)" });
          if (!informationalRow) cls.leakingCells += 1;
          continue;
        }
        scanText(cls, row.label, sink.name, row.input, first, row.planted, row.mustKeep, row.mustRemove, informationalRow);
        if (sink.idempotent && second !== first) recordIdempotence(cls, { ...flag, label: row.label, entryPoint: sink.name, input: row.input, output: first, second });
        else {
          for (const value of row.planted) {
            const window = leakedWindow(second, value);
            if (window !== undefined && leakedWindow(first, value) === undefined) recordLeak(cls, { ...flag, label: row.label, entryPoint: sink.name, input: row.input, output: second, planted: value, window });
          }
        }
        if (cls.leaks > leaksBefore) cls.leakingCells += 1;
      }
    }
  };

  const walker = options.dataWalker && typeof options.dataWalker.fn === "function" ? options.dataWalker : options.dataWalker && typeof options.dataWalker === "function" ? { fn: options.dataWalker, cap: null } : null;
  const walkerName = walker ? walker.name ?? walker.fn.name ?? "dataWalker" : null;

  const runWalkerCell = async (cls, row) => {
    cls.cells += 1;
    if (row.planted.length > 0) cls.plantedCells += 1;
    const leaksBefore = cls.leaks;
    let output;
    let again;
    try {
      output = await walker.fn(structuredClone(row.value));
      again = await walker.fn(structuredClone(output));
    } catch (error) {
      recordLeak(cls, { label: row.label, entryPoint: walkerName, input: stringify(row.value), output: `threw ${error instanceof Error ? error.message : String(error)}`, planted: row.planted[0] ?? "", window: "(walker threw)" });
      cls.leakingCells += 1;
      return undefined;
    }
    const text = stringify(output);
    scanText(cls, row.label, walkerName, stringify(row.value), text, row.planted, row.mustKeep ?? []);
    if (stringify(again) !== text) recordIdempotence(cls, { label: row.label, entryPoint: walkerName, input: stringify(row.value), output: text, second: stringify(again) });
    if (cls.leaks > leaksBefore) cls.leakingCells += 1;
    return output;
  };

  // Classes 1 to 5: text rows through every scrubber.
  if (allSinks.length === 0) {
    for (const id of [1, 2, 3, 4, 5]) byId(id).skipped = "no text scrubbers given";
  } else {
    await runTextCells(byId(1), credentialPairCells(options, canaries));
    await runTextCells(byId(2), escapeBoundaryCells(options, canaries));
    await runTextCells(byId(3), cookieHeaderNameCells(canaries));
    await runTextCells(byId(4), quotedCompoundHeaderCells(canaries));
    await runTextCells(byId(5), schemeCasingCells(options, canaries));
    const mustKeepRows = unique(options.mustKeep ?? []).flatMap((value) => [
      cell(`must-keep ${JSON.stringify(value)} alone`, value, { mustKeep: [value] }),
      cell(`must-keep ${JSON.stringify(value)} in a summary`, `GET /v1/items for ${value} failed with 403: access denied`, { mustKeep: [value] }),
    ]);
    await runTextCells(byId(1), mustKeepRows);
  }

  // Class 6: data-side shapes through the data scrubbers and the walker.
  {
    const cls = byId(6);
    if (dataSinks.length === 0 && !walker) cls.skipped = "no data scrubbers or dataWalker given";
    else {
      if (dataSinks.length > 0) await runTextCells(cls, dataShapeTextCells(canaries));
      else cls.notes.push("no data scrubbers given; walker only");
      if (walker) for (const row of dataShapeWalkerCells(canaries)) await runWalkerCell(cls, row);
      else cls.notes.push("no dataWalker given; data scrubbers only");
    }
  }

  // Class 7: depth through the walker and, when given, end to end through the export.
  {
    const cls = byId(7);
    if (!walker && !options.exportRunner) cls.skipped = "no dataWalker or exportRunner given";
    else {
      let cap = walker ? (walker.cap ?? null) : null;
      if (walker) {
        if (cap === null) {
          cap = await detectCap(walker.fn);
          cls.notes.push(cap === null ? `no cap detected up to depth ${MAX_DEPTH_PROBE}; containers are kept at every depth` : `cap detected at depth ${cap}`);
        } else cls.notes.push(`cap ${cap} given`);
        for (const depth of depthsFor(cap)) {
          const sibling = `benign-sibling-${depth}`;
          const plants = depthPlants(depth, canaries, sibling);
          const pastCap = cap !== null && depth > cap;
          const keepSibling = pastCap ? [] : [sibling];
          const credentialOutput = await runWalkerCell(cls, { label: `credential-keyed values at depth ${depth}`, value: { id: "rec-1", settings: plants.credential }, planted: [canaries.tokens[0], canaries.tokens[1]], mustKeep: ["rec-1", ...keepSibling] });
          await runWalkerCell(cls, { label: `benign-keyed carrier at depth ${depth}`, value: { id: "rec-1", settings: plants.carrier }, planted: [canaries.tokens[2]], mustKeep: ["rec-1", ...keepSibling] });
          if (pastCap && credentialOutput !== undefined) {
            const leaf = leafAt(credentialOutput.settings, depth);
            cls.notes.push(isContainer(leaf) ? `depth ${depth} (past the cap): the container was scrubbed in place` : `depth ${depth} (past the cap): the container was replaced by a marker`);
          }
        }
      }
      if (options.exportRunner) {
        const depths = depthsFor(cap);
        const settings = {};
        for (const depth of depths) settings[`depth_${depth}`] = depthPlants(depth, canaries, `benign-sibling-${depth}`);
        const plantedPayload = { id: "rec-1", name: "planted record", settings };
        await runExportScenario(cls, "depth", plantedPayload, { status: 200, contentType: "application/json", body: JSON.stringify(plantedPayload) }, [canaries.tokens[0], canaries.tokens[1], canaries.tokens[2]]);
      } else cls.notes.push("no exportRunner given; walker only");
    }
  }

  async function runExportScenario(cls, scenario, plantedPayload, response, planted) {
    cls.cells += 1;
    if (planted.length > 0) cls.plantedCells += 1;
    const leaksBefore = cls.leaks;
    const recorder = recordingFetch(() => response);
    let outcome;
    try {
      outcome = await options.exportRunner({ scenario, plantedPayload, response, fetchImpl: recorder.fetch, requests: recorder.requests, canaries });
    } catch (error) {
      recordLeak(cls, { label: `export ${scenario}`, entryPoint: "exportRunner", input: scenario, output: `threw ${error instanceof Error ? error.message : String(error)}`, planted: planted[0] ?? "", window: "(exportRunner threw)" });
      cls.leakingCells += 1;
      return;
    }
    const contents = new Map();
    if (outcome?.outputDir) for (const [name, text] of readBundleFiles(outcome.outputDir)) contents.set(`file ${name}`, text);
    if (outcome?.zipPath) for (const [name, text] of readZipEntries(outcome.zipPath)) contents.set(`zip ${name}`, text);
    (outcome?.toolPayloads ?? []).forEach((payload, index) => contents.set(`tool payload ${index}`, stringify(payload)));
    if (contents.size === 0) cls.notes.push(`export ${scenario}: the runner returned nothing to scan`);
    for (const [name, text] of contents) {
      for (const value of planted) {
        const window = leakedWindow(text, value);
        if (window !== undefined) recordLeak(cls, { label: `export ${scenario}`, entryPoint: `exportRunner ${name}`, input: scenario, output: text.length > 400 ? `${text.slice(0, 400)}...` : text, planted: value, window });
      }
    }
    if (cls.leaks > leaksBefore) cls.leakingCells += 1;
  }

  // Class 8: next links through the runner.
  {
    const cls = byId(8);
    if (typeof options.nextLinkRunner !== "function") cls.skipped = "no nextLinkRunner given";
    else {
      const origin = options.origin ?? DEFAULT_ORIGIN;
      const originUrl = new URL(origin);
      const configuredOrigin = `${originUrl.protocol}//${originUrl.host}`;
      const host = originUrl.host;
      const [pathCanary, queryCanary, fragmentCanary, userinfoCanary] = [canaries.tokens[4], canaries.tokens[5], canaries.tokens[6], canaries.tokens[7]];
      const tail = `/${pathCanary}/users?cursor=${queryCanary}#${fragmentCanary}`;
      const linkCanaries = [pathCanary, queryCanary, fragmentCanary, userinfoCanary];
      const linkParts = [["path", pathCanary], ["query", queryCanary], ["fragment", fragmentCanary], ["userinfo", userinfoCanary]];
      const otherScheme = originUrl.protocol === "https:" ? "http:" : "https:";
      const rejected = [
        ["foreign host", `https://evil.example${tail}`],
        ["foreign port", `${originUrl.protocol}//${originUrl.hostname}:8443${tail}`],
        ["foreign scheme", `${otherScheme}//${host}${tail}`],
        ["userinfo on the configured host", `${originUrl.protocol}//svc:${userinfoCanary}@${host}${tail}`],
        ["protocol-relative foreign host", `//evil.example${tail}`],
        ["backslash foreign host", `\\\\evil.example${tail}`],
        ["IPv4 literal", `http://10.0.0.1${tail}`],
        ["IPv6 literal", `https://[::1]:8443${tail}`],
        ["javascript: scheme", `javascript:alert('${pathCanary}')`],
        ["data: scheme", `data:text/plain,${pathCanary}`],
        ["blob: scheme", `blob:https://evil.example/${pathCanary}`],
        ["file: scheme", `file:///etc/${pathCanary}`],
      ];
      const controls = [
        ["relative same origin", `/api/v2/users?cursor=${queryCanary}`],
        ["absolute same origin", `${configuredOrigin}/api/v2/users?cursor=${queryCanary}`],
        ["case-differing host", `${originUrl.protocol.toUpperCase()}//${host.toUpperCase()}/api/v2/users?cursor=${queryCanary}`],
        ["default port", `${originUrl.protocol}//${originUrl.hostname}:${originUrl.protocol === "https:" ? 443 : 80}/api/v2/users?cursor=${queryCanary}`],
      ];
      const runLink = async (label, nextLink, expectFollowed) => {
        cls.cells += 1;
        cls.plantedCells += 1;
        const leaksBefore = cls.leaks;
        const recorder = recordingFetch(() => ({ status: 200, contentType: "application/json", body: JSON.stringify({ items: [], next: null }) }));
        let outcome;
        try {
          outcome = await options.nextLinkRunner({ nextLink, fetchImpl: recorder.fetch, requests: recorder.requests, origin: configuredOrigin, canaries });
        } catch (error) {
          recordLeak(cls, { label, entryPoint: "nextLinkRunner", input: nextLink, output: `threw ${error instanceof Error ? error.message : String(error)}`, planted: pathCanary, window: "(nextLinkRunner threw)" });
          cls.leakingCells += 1;
          return;
        }
        const requests = [...recorder.requests, ...(outcome?.requests ?? []).map((request) => (typeof request === "string" ? { url: request, headers: {} } : request))];
        // Every request is classified: unparseable, userinfo-bearing, or off the configured origin is
        // unsafe (CodeRabbit 5286122785 on #78 `8b92f20`). A rejected link must produce no request at
        // all, so on a rejected row a safe-looking request that carries any part of the link followed it.
        const recordUnsafe = (verdict) => {
          cls.unsafeRequests.push({ label, link: nextLink, url: verdict.url, reason: verdict.reason });
          recordLeak(cls, { label, entryPoint: "nextLinkRunner request", input: nextLink, output: verdict.url, planted: verdict.url, window: `unsafe request: ${verdict.reason}` });
        };
        for (const request of requests) {
          const url = String(request.url);
          const verdict = classifyRequest(url, configuredOrigin);
          if (verdict !== undefined) recordUnsafe(verdict);
          else if (!expectFollowed) {
            const carried = linkParts.find(([, value]) => url.includes(value));
            if (carried) recordUnsafe({ reason: `a rejected link must produce no request, yet this one carries the link's ${carried[0]}`, url });
          }
        }
        if (!expectFollowed) {
          if (outcome && "truncated" in outcome && outcome.truncated !== true) recordLeak(cls, { label, entryPoint: "nextLinkRunner truncated", input: nextLink, output: stringify(outcome.truncated), planted: "truncated", window: "inventory not reported truncated" });
          // The reason the operator reads is the note plus whatever error text the runner surfaced
          // (a library may name the configured origin in the error and the rejected origin in the note).
          const reasonTexts = [outcome?.note ?? outcome?.reason, ...(outcome?.errorTexts ?? [])].filter((text) => typeof text === "string");
          if (reasonTexts.length > 0 && !reasonTexts.some((text) => text.includes(configuredOrigin))) recordLoss(cls, { label, entryPoint: "nextLinkRunner note", input: nextLink, output: reasonTexts.join(" | "), missing: configuredOrigin });
        } else {
          const followed = requests.some((request) => {
            try {
              const url = new URL(request.url);
              return url.pathname === "/api/v2/users" && url.searchParams.get("cursor") === queryCanary;
            } catch {
              return false;
            }
          });
          if (!followed) recordLoss(cls, { label, entryPoint: "nextLinkRunner request", input: nextLink, output: stringify(requests.map((request) => request.url)), missing: "a request for the same-origin next page" });
        }
        const texts = [...(outcome?.errorTexts ?? []).map(stringify), stringify(outcome?.findings ?? []), typeof outcome?.note === "string" ? outcome.note : "", typeof outcome?.reason === "string" ? outcome.reason : ""];
        for (const text of texts) {
          for (const value of linkCanaries) {
            const window = leakedWindow(text, value);
            if (window !== undefined) recordLeak(cls, { label, entryPoint: "nextLinkRunner output", input: nextLink, output: text, planted: value, window });
          }
        }
        if (cls.leaks > leaksBefore) cls.leakingCells += 1;
      };
      for (const [label, link] of rejected) await runLink(label, link, false);
      for (const [label, link] of controls) await runLink(label, link, true);
    }
  }

  // Class 9: truncated-page and denial flips through the runner.
  {
    const cls = byId(9);
    if (typeof options.truncationRunner !== "function") cls.skipped = "no truncationRunner given";
    else if (!(options.inventories ?? []).length) cls.skipped = "no inventories given";
    else {
      let baseline;
      try {
        baseline = await options.truncationRunner({ inventory: null, mode: "baseline" });
      } catch (error) {
        cls.skipped = `baseline run threw ${error instanceof Error ? error.message : String(error)}`;
      }
      if (baseline) {
        const baseFindings = findingsById(baseline.findings);
        for (const inventory of options.inventories) {
          const name = typeof inventory === "string" ? inventory : inventory.name;
          for (const mode of ["zero-rows-truncated", "capped", "denied"]) {
            cls.cells += 1;
            cls.plantedCells += 1;
            const leaksBefore = cls.leaks;
            const label = `${name} / ${mode}`;
            let outcome;
            try {
              outcome = await options.truncationRunner({ inventory: name, mode });
            } catch (error) {
              recordLeak(cls, { label, entryPoint: "truncationRunner", input: label, output: `threw ${error instanceof Error ? error.message : String(error)}`, planted: name, window: "(truncationRunner threw)" });
              cls.leakingCells += 1;
              continue;
            }
            const findings = findingsById(outcome?.findings);
            const declaredReaders = new Set([...(outcome?.readers ?? []), ...((typeof inventory === "object" && inventory.findings) || [])].map(String));
            for (const [id, finding] of findings) {
              const before = baseFindings.get(id);
              const beforeStatus = findingStatus(before);
              const afterStatus = findingStatus(finding);
              const changed = before === undefined || stringify(before) !== stringify(finding);
              if (beforeStatus === "pass" && afterStatus === "fail") recordLeak(cls, { label, entryPoint: `finding ${id}`, input: label, output: stringify(finding), planted: "pass", window: "flipped pass -> fail" });
              if (afterStatus === "pass" && (changed || declaredReaders.has(id))) recordLeak(cls, { label, entryPoint: `finding ${id}`, input: label, output: stringify(finding), planted: "pass", window: "pass while its inventory is truncated or denied" });
            }
            const principals = unique([...(outcome?.principals ?? []), ...((typeof inventory === "object" && inventory.principals) || [])]);
            if (principals.length === 0) cls.notes.push(`${label}: no principals declared; the named-principal check did not run`);
            for (const [id, finding] of findings) {
              const text = stringify(finding);
              for (const principal of principals) {
                if (text.includes(principal)) recordLeak(cls, { label, entryPoint: `finding ${id}`, input: label, output: text, planted: principal, window: principal });
              }
            }
            const changes = changedLeaves(
              { findings: Object.fromEntries(baseFindings), summaries: baseline.summaries ?? null },
              { findings: Object.fromEntries(findings), summaries: outcome?.summaries ?? null },
            );
            for (const [path, before, after] of changes) {
              if (isAbsenceLeaf(after)) recordLeak(cls, { label, entryPoint: path, input: label, output: `${stringify(before)} -> ${stringify(after)}`, planted: stringify(after), window: `changed leaf became ${stringify(after)}` });
              else if (typeof after === "string" && before !== undefined && typeof before !== "string" && !MARKER_PATTERN.test(after)) cls.notes.push(`${label}: ${path} became the string ${JSON.stringify(after)}`);
            }
            if (cls.leaks > leaksBefore) cls.leakingCells += 1;
          }
        }
      }
    }
  }

  // Class 10: error bodies through the error scrubbers, the body describers, and the export.
  {
    const cls = byId(10);
    const describers = normalizeSinks(options.bodyDescribers, "bodyDescriber");
    if (errorSinks.length === 0 && describers.length === 0 && !options.exportRunner) cls.skipped = "no error scrubbers, bodyDescribers, or exportRunner given";
    else {
      const bodyCanary = canaries.tokens[8];
      const lines = [
        `password=${canaries.passwords[0]}`,
        `client_token=${canaries.nameShaped[0]}`,
        `\\nX-Api-Key: ${canaries.tokens[0]}`,
        `Cookie: theme=dark; my.sid=${canaries.tokens[1]}`,
        `X-Api-Key: "${canaries.tokens[2]}"; Content-Type: application/json`,
        `replayed basic ${canaries.opaque[0]} upstream`,
        `Authorization: Bearer ${bodyCanary}`,
      ];
      const planted = [canaries.passwords[0], canaries.nameShaped[0], canaries.tokens[0], canaries.tokens[1], canaries.tokens[2], canaries.opaque[0], bodyCanary];
      const html = `<html><head><title>502 Bad Gateway</title></head><body><p>upstream said: ${lines.join(" ")}</p></body></html>`;
      const json403 = JSON.stringify({ error: { message: `Access denied: ${lines.join(" ")}`, code: "forbidden" }, details: { password: bodyCanary } });
      const foreignJson = JSON.stringify({ foo: bodyCanary, items: [{ password: bodyCanary, description: `Authorization: Bearer ${canaries.tokens[0]}` }] });
      const scenarios = [
        ["502 text/html", { status: 502, statusText: "Bad Gateway", contentType: "text/html", body: html }, planted],
        ["403 JSON", { status: 403, statusText: "Forbidden", contentType: "application/json", body: json403 }, planted],
        ["200 text/html", { status: 200, statusText: "OK", contentType: "text/html", body: html }, planted],
        ["200 empty", { status: 200, statusText: "OK", contentType: "application/json", body: "" }, []],
        ["200 foreign JSON", { status: 200, statusText: "OK", contentType: "application/json", body: foreignJson }, [bodyCanary, canaries.tokens[0]]],
      ];
      if (errorSinks.length > 0) {
        await runTextCells(cls, scenarios.filter(([, response]) => response.body.length > 0).map(([label, response, values]) => cell(`${label} body as error text`, response.body, { planted: values, sinks: "error" })));
      }
      for (const describer of describers) {
        for (const [label, response, values] of scenarios) {
          cls.cells += 1;
          if (values.length > 0) cls.plantedCells += 1;
          const leaksBefore = cls.leaks;
          let output;
          try {
            output = String(await describer.fn({ ...response, method: "GET", endpoint: "/v1/users" }));
          } catch (error) {
            recordLeak(cls, { label, entryPoint: describer.name, input: label, output: `threw ${error instanceof Error ? error.message : String(error)}`, planted: values[0] ?? "", window: "(describer threw)" });
            cls.leakingCells += 1;
            continue;
          }
          scanText(cls, `${label} described`, describer.name, response.body, output, values);
          const bytes = Buffer.byteLength(response.body, "utf8");
          if (response.contentType === "text/html" && (!output.includes("text/html") || !output.includes(String(bytes)))) recordLoss(cls, { label: `${label} described`, entryPoint: describer.name, input: response.body, output, missing: `content type text/html and byte length ${bytes}` });
          if (cls.leaks > leaksBefore) cls.leakingCells += 1;
        }
      }
      if (options.exportRunner) {
        for (const [label, response, values] of scenarios) await runExportScenario(cls, label, null, response, values);
      } else cls.notes.push("no exportRunner given; scrubbers and describers only");
    }
  }

  const summary = {
    integration: options.integration,
    canaries,
    classes: results.map((cls) => ({
      id: cls.id,
      key: cls.key,
      name: cls.name,
      cells: cls.cells,
      plantedCells: cls.plantedCells,
      leakingCells: cls.leakingCells,
      leaks: cls.leaks,
      mustKeepLosses: cls.mustKeepLosses,
      idempotenceFailures: cls.idempotenceFailures,
      entryPoints: [...cls.entryPoints].sort(),
      examples: cls.examples,
      informationalCells: cls.informationalCells,
      informational: cls.informational,
      informationalEntryPoints: [...cls.informationalEntryPoints].sort(),
      informationalExamples: cls.informationalExamples,
      unsafeRequests: cls.unsafeRequests,
      skipped: cls.skipped,
      notes: cls.notes,
    })),
    leaks,
    mustKeepLosses,
    idempotenceFailures,
    informational,
  };
  // Informational rows never gate: `ok` reads the three gating totals only.
  summary.ok = leaks.length === 0 && mustKeepLosses.length === 0 && idempotenceFailures.length === 0;
  summary.report = renderReport(summary);
  return summary;
}

function clip(text, limit = 160) {
  const flat = String(text).replace(/\s+/g, " ");
  return flat.length > limit ? `${flat.slice(0, limit)}...` : flat;
}

function exampleLines(example) {
  const detail = example.kind === "leak" ? `window ${JSON.stringify(example.window)} of ${JSON.stringify(clip(example.planted, 40))}` : example.kind === "must-keep loss" ? `lost ${JSON.stringify(clip(example.missing, 80))}` : `second pass changed the text`;
  return [`- ${example.kind} / ${clip(example.label, 100)} / ${example.entryPoint}: ${detail}`, `  - input: ${JSON.stringify(clip(example.input))}`, `  - output: ${JSON.stringify(clip(example.output))}`];
}

function renderReport(summary) {
  const gating = summary.ok ? "zero leaks" : `${summary.leaks.length} leaks, ${summary.mustKeepLosses.length} must-keep losses, ${summary.idempotenceFailures.length} idempotence failures`;
  const informationalCells = summary.classes.reduce((total, cls) => total + cls.informationalCells, 0);
  const informationalNote = informationalCells > 0 ? `; ${summary.informational.length} informational of ${informationalCells} cells, non-gating` : "";
  const lines = [
    `Leak-probe harness: ${summary.integration} (${gating}${informationalNote})`,
    "",
    "| Class | Cells | Leaks | Must-keep losses | Idempotence failures | Informational | Leaking entry points |",
    "| --- | ---: | ---: | ---: | ---: | ---: | --- |",
  ];
  for (const cls of summary.classes) {
    const cellsText = cls.skipped ? `skipped: ${cls.skipped}` : String(cls.cells);
    const entryPoints = cls.entryPoints.length > 0 ? cls.entryPoints.join(", ") : "-";
    const informationalText = cls.informationalCells > 0 ? `${cls.informational} of ${cls.informationalCells}` : "-";
    lines.push(`| ${cls.id}. ${cls.name} | ${cellsText} | ${cls.leaks} | ${cls.mustKeepLosses} | ${cls.idempotenceFailures} | ${informationalText} | ${entryPoints} |`);
  }
  for (const cls of summary.classes) {
    if (cls.notes.length > 0) lines.push("", `Notes, class ${cls.id}: ${unique(cls.notes).join("; ")}`);
  }
  for (const cls of summary.classes) {
    if (cls.examples.length === 0) continue;
    lines.push("", `#### Class ${cls.id} examples (${cls.examples.length} of ${cls.leaks + cls.mustKeepLosses + cls.idempotenceFailures})`);
    for (const example of cls.examples) lines.push(...exampleLines(example));
  }
  for (const cls of summary.classes) {
    if (cls.unsafeRequests.length === 0) continue;
    lines.push("", `#### Class ${cls.id} unsafe requests (${cls.unsafeRequests.length}; userinfo masked)`);
    for (const request of cls.unsafeRequests.slice(0, MAX_EXAMPLES_PER_CLASS)) lines.push(`- ${clip(request.label, 100)}: ${request.reason}`, `  - link: ${JSON.stringify(clip(request.link))}`, `  - request: ${JSON.stringify(clip(request.url))}`);
    if (cls.unsafeRequests.length > MAX_EXAMPLES_PER_CLASS) lines.push(`- ... ${cls.unsafeRequests.length - MAX_EXAMPLES_PER_CLASS} more`);
  }
  for (const cls of summary.classes) {
    if (cls.informationalExamples.length === 0) continue;
    lines.push("", `#### Class ${cls.id} informational, non-gating (${cls.informationalExamples.length} of ${cls.informational}; entry points: ${cls.informationalEntryPoints.join(", ")})`);
    for (const example of cls.informationalExamples) lines.push(...exampleLines(example));
  }
  return lines.join("\n");
}

/**
 * Throws with the per-class table when the run recorded any leak, must-keep loss, or idempotence
 * failure. Informational rows never throw.
 */
export function assertNoLeaks(result) {
  if (!result || !Array.isArray(result.classes)) throw new TypeError("assertNoLeaks: expected the result of runLeakProbe");
  if (result.ok) return;
  throw new Error(result.report);
}
