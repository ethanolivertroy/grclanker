import test from "node:test";
import assert from "node:assert/strict";

import {
  IntegrationError,
  REDACTED,
  describeErrorBody,
  describeFailedResponse,
  errorMessage,
  isCredentialKey,
  redactSecretValues,
  scrubDataText,
  scrubErrorText,
} from "../dist/extensions/grc-tools/hardening/error-text.js";
import { isSensitiveArgumentKey } from "../dist/flue/redact.js";
import { leakedCanaryWindow } from "./helpers/error-canaries.mjs";

/**
 * The compound and env-style credential keys of the review of #78 (gap 1): a value under any key
 * `isCredentialKey` classifies is a carrier and goes whatever its shape, the human-chosen password
 * shapes main's rule at 02967cc redacted included. The matrices here reproduce the reviewer's
 * counts in the suite: the 32 credential environment names the integrations read by the password
 * shapes in `=`, `: `, JSON, JSON-escaped, and quoted-assignment forms (the 160-pair matrix and its
 * wider forms), the 45-key probe over nine sinks (probe 1c), and the differential against main's
 * shape rule (probe 1b: every value main redacted under a compound key is redacted here).
 */

/** Credential environment names read by `cli/extensions/grc-tools/**\/*.ts` (`*_PASSWORD`, `*_TOKEN`, `*_API_KEY`, `*_KEY`). */
const ENV_CREDENTIAL_NAMES = Object.freeze([
  "AAP_PASSWORD",
  "AAP_TOKEN",
  "ANYPOINT_PASSWORD",
  "ANYPOINT_TOKEN",
  "BOX_TOKEN",
  "CLOUDFLARE_API_KEY",
  "DATADOG_API_KEY",
  "DD_API_KEY",
  "DUPLICATE_KEY",
  "ELASTIC_API_KEY",
  "ELASTIC_PASSWORD",
  "GH_TOKEN",
  "GITHUB_TOKEN",
  "HAS_PASSWORD",
  "PAGERDUTY_API_KEY",
  "PAGERDUTY_TOKEN",
  "PANOS_API_KEY",
  "PANOS_PASSWORD",
  "PD_API_KEY",
  "QUALYS_PASSWORD",
  "QUALYS_TOKEN",
  "SERVICENOW_PASSWORD",
  "SERVICENOW_TOKEN",
  "SF_PASSWORD",
  "SLACK_TOKEN",
  "SNOWFLAKE_TOKEN",
  "SPLUNK_PASSWORD",
  "SPLUNK_TOKEN",
  "WEBEX_TOKEN",
  "ZIA_API_KEY",
  "ZIA_PASSWORD",
  "ZOOM_TOKEN",
]);

/** The five ordinary password shapes of the 160-pair matrix. */
const ORDINARY_PASSWORDS = Object.freeze(["hunter2", "changeme", "Summer2026!", "correcthorsebatterystaple", "P@ssw0rd"]);

/** The fifteen password and passphrase shapes of probe 1c. */
const PASSWORD_SHAPES = Object.freeze([
  "hunter2",
  "changeme",
  "welcome123",
  "qwerty12345",
  "Summer2026!",
  "P@ssw0rd",
  "Tr0ub4dor&3",
  "MyDogRex2019",
  "correcthorsebatterystaple",
  "admin123!",
  "letmein2024",
  "voxkqrrijhpp",
  "prod-us-east-2026",
  "CorrectHorse",
  "ABCD-EFGH-IJKL",
]);

/** The 45 keys of probe 1c by form; every one is classified by `isCredentialKey`. */
const PROBE_KEYS = Object.freeze({
  env: ["DB_PASSWORD", "MYSQL_ROOT_PASSWORD", "POSTGRES_PASSWORD", "SMTP_PASSWORD", "LDAP_BIND_PASSWORD", "ADMIN_PASSWORD", "GITHUB_TOKEN", "SLACK_BOT_TOKEN", "DD_API_KEY", "NEW_RELIC_API_KEY", "VAULT_TOKEN", "OKTA_API_TOKEN", "JIRA_API_TOKEN", "SNOWFLAKE_PASSWORD"],
  snake: ["db_password", "admin_password", "bind_password", "client_token", "service_token", "signing_key", "license_key", "api_secret", "encryption_key", "master_key"],
  camel: ["dbPassword", "adminPassword", "clientToken", "signingKey", "licenseKey", "bindPassword"],
  kebab: ["db-password", "admin-password", "client-token", "license-key"],
  header: ["X-Vault-Token", "X-Client-Token", "X-Admin-Password", "X-License-Key", "X-Signing-Key"],
  tier1: ["password", "token", "secret", "api_key", "client_secret", "access_token"],
});

/** The forms a pair is written in: `=`, `: `, JSON, JSON-escaped, and a quoted assignment. */
const FORMS = Object.freeze([
  ["eq", (key, value) => `${key}=${value}`],
  ["colon_space", (key, value) => `${key}: ${value}`],
  ["json", (key, value) => JSON.stringify({ [key]: value })],
  ["json_escaped", (key, value) => JSON.stringify(JSON.stringify({ [key]: value })).slice(1, -1)],
  ["eq_quoted", (key, value) => `${key}="${value}"`],
]);

/** The frames of probe 1b. */
const FRAMES = Object.freeze([
  ["bare", (pair) => pair],
  ["sentence", (pair) => `the upstream rejected the request with ${pair} and closed the connection`],
  ["json_object", (pair) => `{"status": 401, ${pair}, "retry": false}`],
  ["env_dump", (pair) => `environment: PATH=/usr/bin ${pair} HOME=/root`],
  ["multiline", (pair) => `request failed\n${pair}\nsee the log`],
]);

class VendorApiError extends IntegrationError {}

/** The nine sinks of probe 1c, each taking the pair text. */
const SINKS = Object.freeze([
  ["scrubErrorText", (text) => scrubErrorText(text)],
  ["scrubDataText", (text) => scrubDataText(text)],
  ["redactSecretValues", (text) => redactSecretValues({ message: text, notes: [text] })],
  ["IntegrationError", (text) => new IntegrationError(`config rejected: ${text}`, { code: "X" }).message],
  ["IntegrationError subclass", (text) => new VendorApiError(text, { status: 401 }).message],
  ["errorMessage", (text) => errorMessage(new Error(`upstream said ${text}`))],
  ["describeErrorBody message", (text) => describeErrorBody("application/json", JSON.stringify({ message: text }))],
  ["describeErrorBody nested", (text) => describeErrorBody("application/json", JSON.stringify({ error: { message: JSON.stringify({ detail: text }) } }))],
  ["describeFailedResponse", (text) => describeFailedResponse({ method: "GET", endpoint: "/v1/users", status: 502, statusText: "Bad Gateway", contentType: "application/json", body: JSON.stringify({ message: text }) })],
]);

function leaked(output, value) {
  return leakedCanaryWindow(typeof output === "string" ? output : JSON.stringify(output), value) !== undefined;
}

test("credential pairs: the 32 credential environment names by five ordinary passwords through scrubErrorText (the 160-pair matrix) leak nothing", () => {
  let trials = 0;
  for (const name of ENV_CREDENTIAL_NAMES) {
    assert.ok(isCredentialKey(name), `${name} is classified`);
    for (const password of ORDINARY_PASSWORDS) {
      const text = `${name}=${password}`;
      assert.equal(scrubErrorText(text), `${name}=${REDACTED}`, text);
      trials += 1;
    }
  }
  assert.equal(trials, 160);
});

test("credential pairs: the 32 environment names by fifteen password shapes in every written form leak nothing through any sink", () => {
  let trials = 0;
  const leaks = [];
  for (const name of ENV_CREDENTIAL_NAMES) {
    for (const password of PASSWORD_SHAPES) {
      for (const [formName, form] of FORMS) {
        const text = form(name, password);
        for (const [sinkName, sink] of SINKS) {
          trials += 1;
          if (leaked(sink(text), password)) leaks.push(`${name} ${formName} ${sinkName}: ${JSON.stringify(text)}`);
        }
      }
    }
  }
  assert.equal(trials, ENV_CREDENTIAL_NAMES.length * PASSWORD_SHAPES.length * FORMS.length * SINKS.length);
  assert.deepEqual(leaks, []);
});

test("credential pairs: probe 1c, 45 keys by fifteen password shapes through nine sinks, leaks nothing in any key form", () => {
  const keys = Object.values(PROBE_KEYS).flat();
  assert.equal(keys.length, 45);
  const leaksByForm = {};
  let trials = 0;
  for (const [formName, formKeys] of Object.entries(PROBE_KEYS)) {
    leaksByForm[formName] = 0;
    for (const key of formKeys) {
      assert.ok(isCredentialKey(key), `${key} is classified`);
      for (const password of PASSWORD_SHAPES) {
        for (const [, form] of FORMS.slice(0, 3)) {
          const text = form(key, password);
          for (const [, sink] of SINKS) {
            trials += 1;
            if (leaked(sink(text), password)) leaksByForm[formName] += 1;
          }
        }
      }
    }
  }
  assert.equal(trials, 45 * PASSWORD_SHAPES.length * 3 * SINKS.length);
  assert.deepEqual(leaksByForm, { env: 0, snake: 0, camel: 0, kebab: 0, header: 0, tier1: 0 });
});

/**
 * Main's value rule at 02967cc (`looksLikeCredentialValue`): a value of six characters or more with a
 * digit, a symbol, or a case change inside the word, or of twelve characters or more, is redacted. The
 * head redacts everything main redacted; this is probe 1b's "regressions" count, which must be zero.
 */
function mainRedacted(value) {
  if (value.length < 6) return false;
  if (/\d/.test(value) || value.length >= 12) return true;
  if (/[^A-Za-z]/.test(value)) return true;
  return /[a-z][A-Z]/.test(value);
}

const PROBE_1B_KEYS = Object.freeze([
  "client_token",
  "admin_password",
  "db_passwd",
  "signing_key",
  "license_key",
  "encryption_key",
  "master_key",
  "service_account_key",
  "api_secret",
  "vendor_secret",
  "hmac_key",
  "clientToken",
  "adminPassword",
  "signingKey",
  "licenseKey",
  "client-token",
  "admin-password",
  "DD_API_KEY",
  "NEW_RELIC_API_KEY",
  "SLACK_BOT_TOKEN",
  "GITHUB_TOKEN",
  "DB_PASSWORD",
  "HTTP_X_API_KEY",
  "CLIENT_TOKEN",
  "apikey",
  "privatekey",
  "sessionid",
  "tokens",
  "secrets",
  "passwords",
  "keys",
]);
const PROBE_1B_VALUES = Object.freeze([
  "hunter",
  "abcdefghijk",
  "vexenmbyipgq",
  "oijcysffpyhthekp",
  "snqsuhxcnlicusatxupd",
  "correcthorsebatterystaple",
  "hunter2",
  "letmein2024",
  "abc123",
  "CorrectHorse",
  "Swordfish",
  "OPENSESAME",
  "ABCD-EFGH-IJKL",
  "tnAki87T1HyQ",
  "Kq7Zx2Vw9Lm4Tp8RaB3cD5eF",
  "9f8e7d6c5b4a39281706f5e4d3c2b1a0",
  "p@ssw0rd!x",
]);

test("credential pairs: probe 1b, no value main's rule redacted under a compound key survives in any separator or frame (zero regressions), and bare values of every shape go", () => {
  const regressions = [];
  const bareLeaks = [];
  let trials = 0;
  for (const key of PROBE_1B_KEYS) {
    for (const value of PROBE_1B_VALUES) {
      for (const [formName, form] of FORMS) {
        for (const [frameName, frame] of FRAMES) {
          const text = frame(form(key, value));
          for (const [sinkName, sink] of [SINKS[0], SINKS[1]]) {
            trials += 1;
            const hit = leaked(sink(text), value);
            if (hit && mainRedacted(value)) regressions.push(`${key} ${value} ${formName} ${frameName} ${sinkName}`);
            if (hit && frameName === "bare") bareLeaks.push(`${key} ${value} ${formName} ${sinkName}`);
          }
        }
      }
    }
  }
  assert.equal(trials, PROBE_1B_KEYS.length * PROBE_1B_VALUES.length * FORMS.length * FRAMES.length * 2);
  assert.deepEqual(regressions, []);
  assert.deepEqual(bareLeaks, []);
});

test("credential pairs: the prose exemption is the only way a value under a compound key survives, and it needs `Key: ` and a continuation", () => {
  // The exemption in force: a plain word after `Key: ` followed by another word.
  assert.equal(scrubErrorText("client_token: expired at noon"), "client_token: expired at noon");
  // Withdrawn by the separator, the shape, the length, or a missing continuation.
  for (const [text, expected] of [
    ["client_token=expired at noon", `client_token=${REDACTED} at noon`],
    ["client_token:expired at noon", `client_token:${REDACTED} at noon`],
    ['client_token: "expired" at noon', `client_token: "${REDACTED}" at noon`],
    ["client_token: expired", `client_token: ${REDACTED}`],
    ["client_token: expired2 at noon", `client_token: ${REDACTED} at noon`],
    ["client_token: exPired at noon", `client_token: ${REDACTED} at noon`],
    ["client_token: expiredtoday at noon", `client_token: ${REDACTED} at noon`],
    ["client_token: expired\nat noon", `client_token: ${REDACTED}\nat noon`],
    ["client_token: expired\\nat noon", `client_token: ${REDACTED}\\nat noon`],
  ]) {
    assert.equal(scrubErrorText(text), expected, text);
    assert.equal(scrubDataText(text), expected, text);
  }
});

/**
 * Coordinator ruling on the settings reviewer A saw over-redacted in group A: a key whose final
 * segment is a setting suffix (`url`, `uri`, `endpoint`, `method`, `algorithm`, `audience`, `issuer`,
 * `shape`, `type`, `mode`, `path`, `file`, `dir`, `limit`, `count`, `id`, `name`) is a setting, not a
 * credential key, even when an earlier segment is a credential word. Its value stays unless it is
 * token-shaped or a registered secret, and a URL value passes the URL rule. Main at 02967cc classified
 * these keys by the Flue heuristic alone and redacted the value under `mainRedacted`, so the rows
 * `MAIN_REDACTED_SETTINGS` lists are the ones main redacted and the head keeps by design: they are
 * not leaks and are reported separately from the probe 1b regressions (which stay zero).
 */
const SETTING_ROWS = Object.freeze([
  ["BOX_AUTH_METHOD", "ccg"],
  ["BOX_TOKEN_URL", "https://api.box.com/oauth2/token"],
  ["BOX_JWT_ALGORITHM", "RS256"],
  ["auth_method", "client_secret"],
  ["token_endpoint", "https://login.microsoftonline.com/common/oauth2/v2.0/token"],
  ["token_uri", "https://oauth2.googleapis.com/token"],
  ["tokenUrl", "https://api.box.com/oauth2/token"],
  ["token_type", "Bearer"],
  ["auth_mode", "basic"],
  ["oauth_signature_method", "HMAC-SHA1"],
  ["token_audience", "https://api.example.com"],
  ["jwt_issuer", "https://issuer.example.com/oauth2/default"],
  ["token_shape", "jwt"],
  ["private_key_path", "/etc/grclanker/box-private.pem"],
  ["credentials_file", "./credentials.json"],
  ["token_dir", "/var/lib/grclanker/tokens"],
  ["token_limit", "5"],
  ["session_count", "3"],
  ["secret_name", "prod/grclanker/box"],
  ["key_name", "signing-2026"],
  ["key_id", "signing-2026"],
  ["api_key_id", "signing-2026"],
  ["client_id", "my-app-2026"],
  ["tenant_id", "2f3c1a9e-7b6d-4c5e-8f9a-0b1c2d3e4f5a"],
  ["user_name", "svc-backup-2026"],
  // Review of #78 (01:40 rulings): the Vault AppRole settings and a webhook setting that is not the URL.
  ["secret_id_ttl", "3600"],
  ["token_max_ttl", "7200"],
  ["secret_id_num_uses", "5"],
  ["token_num_uses", "0"],
  ["secret_id_bound_cidrs", "10.0.0.0/8"],
  ["token_bound_cidrs", "10.0.0.0/8"],
  ["secret_id_accessor", "6b1f4c2e-9d3a-4f7b-8c5e-2a1d0e9f8b7c"],
  ["token_accessor", "6b1f4c2e-9d3a-4f7b-8c5e-2a1d0e9f8b7c"],
  ["webhook_count", "3"],
]);

/**
 * Main's key rule at 02967cc (`isCredentialKey`): the Flue heuristic, then the safe-shape exemption
 * (`max_`, `min_`, `_limit`, `_days`, `_hours`, `_minutes`, `_seconds`, `_count`, `_path`, `_file`,
 * `_dir`), then the extra bare segments.
 */
function mainCredentialKey(key) {
  if (isSensitiveArgumentKey(key)) return true;
  if (/^(?:max|min)[_-]|[_-](?:limit|days|hours|minutes|seconds|count|path|file|dir)$/i.test(key)) return false;
  const segments = key.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  return segments.some((segment) => ["sid", "sig", "pwd", "passwd", "pass", "session", "sessid", "auth", "nonce", "sas"].includes(segment));
}

/** The setting rows main at 02967cc redacted in its text scrubs (main's key rule, main's value rule) and the head keeps. */
const MAIN_REDACTED_SETTINGS = Object.freeze([
  "BOX_TOKEN_URL",
  "auth_method",
  "token_endpoint",
  "token_uri",
  "tokenUrl",
  "oauth_signature_method",
  "token_audience",
  "jwt_issuer",
  "secret_name",
  "key_name",
  "key_id",
  "api_key_id",
  "secret_id_bound_cidrs",
  "token_bound_cidrs",
  "secret_id_accessor",
  "token_accessor",
]);

/** The setting rows main redacted in `redactSecretValues` over an object (every key main classified, whatever the value). */
const MAIN_REDACTED_SETTING_ENTRIES = Object.freeze([
  ...MAIN_REDACTED_SETTINGS,
  "BOX_AUTH_METHOD",
  "BOX_JWT_ALGORITHM",
  "token_type",
  "auth_mode",
  "token_shape",
  "secret_id_ttl",
  "token_max_ttl",
  "secret_id_num_uses",
  "token_num_uses",
]);

test("settings: a key whose final segment is a setting suffix keeps its value in every form, frame, and sink, and the rows main redacted are exactly the documented list", () => {
  let trials = 0;
  for (const [key, value] of SETTING_ROWS) {
    assert.ok(!isCredentialKey(key), `${key} is a setting`);
    for (const [formName, form] of FORMS) {
      for (const [frameName, frame] of FRAMES) {
        const text = frame(form(key, value));
        for (const [sinkName, sink] of SINKS) {
          trials += 1;
          const output = sink(text);
          const rendered = typeof output === "string" ? output : JSON.stringify(output);
          assert.ok(rendered.includes(value) || rendered.includes(JSON.stringify(value).slice(1, -1)), `${key}=${value} must survive ${formName} ${frameName} through ${sinkName}: ${rendered}`);
        }
      }
    }
    assert.deepEqual(redactSecretValues({ [key]: value }), { [key]: value }, `${key} as a record entry`);
  }
  assert.equal(trials, SETTING_ROWS.length * FORMS.length * FRAMES.length * SINKS.length);
  assert.deepEqual(
    SETTING_ROWS.filter(([key, value]) => mainCredentialKey(key) && mainRedacted(value)).map(([key]) => key),
    [...MAIN_REDACTED_SETTINGS],
  );
  assert.deepEqual(
    SETTING_ROWS.filter(([key]) => mainCredentialKey(key)).map(([key]) => key).sort(),
    [...MAIN_REDACTED_SETTING_ENTRIES].sort(),
  );
});

test("settings: the exceptions stay credential keys whatever their suffix and lose any value in every form, frame, and sink", () => {
  const rows = [
    ["webhook_url", "https://hooks.example.com/services/foo/bar/abcdefghijkl"],
    ["WEBHOOK_URL", "https://hooks.slack.com/services/T000/B000/abcdefghijkl"],
    ["webhookUrl", "https://hooks.example.com/services/abcdefghijkl"],
    ["slack_hook_url", "https://hooks.slack.com/services/abcdefghijkl"],
    ["callback_url", "https://app.example.com/oauth/return"],
    ["webhook", "https://hooks.example.com/services/foo/bar/abcdefghijkl"],
    ["webhook_path", "/services/foo/bar/abcdefghijkl"],
    ["token_id", "abcdefghijkl"],
    ["tokenId", "abcdefghijkl"],
    ["session_id", "abcdefghijkl"],
    ["user_session_id", "abcdefghijkl"],
    ["PHPSESSID", "abcdefghijkl"],
    ["ASP.NET_SessionId", "abcdefghijkl"],
  ];
  for (const [key, value] of rows) {
    assert.ok(isCredentialKey(key), `${key} stays a credential key`);
    for (const [formName, form] of FORMS) {
      for (const [frameName, frame] of FRAMES) {
        const text = frame(form(key, value));
        for (const [sinkName, sink] of SINKS) {
          assert.ok(!leaked(sink(text), value), `${key} ${formName} ${frameName} leaked through ${sinkName}`);
        }
      }
    }
    assert.deepEqual(redactSecretValues({ [key]: value }), { [key]: REDACTED }, `${key} as a record entry`);
  }
});

/**
 * CodeRabbit (#78) secret_id: the Vault AppRole secret id is a bearer credential with an identifier
 * suffix, and its UUID shape keeps it off the long-token rule, so the setting-suffix ruling had turned
 * `secret_id`, `VAULT_SECRET_ID`, and `role_secret_id` into settings whose UUID value passed every
 * scrub where main at 02967cc redacted it through the `secret` word. A key ending in `secret_id` is a
 * credential key again whatever its prefix, casing, or separator, and an explicit credential pair name
 * like the session names, so even a plain word under `Key: ` that continues as prose goes; the
 * identifier half of the pair (`role_id`) and the other identifier keys keep a UUID.
 */
const SECRET_ID_ROWS = Object.freeze([
  ["secret_id", "3f6c1e2a-8b4d-4c7e-9a1f-2d5e6b7c8d9e"],
  ["secret_id", "k7Qm2xZp9vLw4nRt8sYb"],
  ["secret_id", "x7Kp2q"],
  ["secret_id", "qzvkwpmtr"],
  ["VAULT_SECRET_ID", "9B2E4F6A-1C3D-4E5F-8A9B-0C1D2E3F4A5B"],
  ["VAULT_SECRET_ID", "k7Qm2xZp9vLw4nRt8sYb"],
  ["VAULT_SECRET_ID", "x7Kp2q"],
  ["VAULT_SECRET_ID", "qzvkwpmtr"],
  ["role_secret_id", "3f6c1e2a-8b4d-4c7e-9a1f-2d5e6b7c8d9e"],
  ["role_secret_id", "k7Qm2xZp9vLw4nRt8sYb"],
  ["role_secret_id", "x7Kp2q"],
  ["role_secret_id", "qzvkwpmtr"],
  ["secretId", "3f6c1e2a-8b4d-4c7e-9a1f-2d5e6b7c8d9e"],
  ["secret-id", "3f6c1e2a-8b4d-4c7e-9a1f-2d5e6b7c8d9e"],
  ["roleSecretId", "9B2E4F6A-1C3D-4E5F-8A9B-0C1D2E3F4A5B"],
]);

const IDENTIFIER_UUID_CONTROLS = Object.freeze([
  ["client_id", "123e4567-e89b-12d3-a456-426614174000"],
  ["tenant_id", "2f3c1a9e-7b6d-4c5e-8f9a-0b1c2d3e4f5a"],
  ["role_id", "5d1a2b3c-4e5f-4a6b-8c7d-9e0f1a2b3c4d"],
  ["VAULT_ROLE_ID", "5d1a2b3c-4e5f-4a6b-8c7d-9e0f1a2b3c4d"],
]);

test("CodeRabbit (#78) secret_id: a key ending in secret_id loses a UUID, random, or plain-word value in every form, frame, and sink, main classified every such key too, and client_id and tenant_id UUIDs stay", () => {
  let trials = 0;
  for (const [key, value] of SECRET_ID_ROWS) {
    assert.ok(isCredentialKey(key), `${key} is the bearer secret id`);
    assert.ok(mainCredentialKey(key), `${key}: main at 02967cc classified it too, so redacting it narrows nothing`);
    for (const [formName, form] of FORMS) {
      for (const [frameName, frame] of FRAMES) {
        const text = frame(form(key, value));
        for (const [sinkName, sink] of SINKS) {
          trials += 1;
          const output = sink(text);
          assert.ok(!leaked(output, value), `${key}=${value} ${formName} ${frameName} leaked through ${sinkName}`);
          const rendered = typeof output === "string" ? output : JSON.stringify(output);
          assert.ok(rendered.includes(REDACTED), `${key}=${value} ${formName} ${frameName} left no marker through ${sinkName}: ${rendered}`);
        }
      }
    }
    assert.deepEqual(redactSecretValues({ [key]: value }), { [key]: REDACTED }, `${key} as a record entry`);
  }
  assert.equal(trials, SECRET_ID_ROWS.length * FORMS.length * FRAMES.length * SINKS.length);
  for (const [key, value] of IDENTIFIER_UUID_CONTROLS) {
    assert.ok(!isCredentialKey(key), `${key} is an identifier`);
    for (const [formName, form] of FORMS) {
      for (const [frameName, frame] of FRAMES) {
        const text = frame(form(key, value));
        for (const [sinkName, sink] of SINKS) {
          const output = sink(text);
          const rendered = typeof output === "string" ? output : JSON.stringify(output);
          assert.ok(rendered.includes(value), `${key}=${value} must survive ${formName} ${frameName} through ${sinkName}: ${rendered}`);
        }
      }
    }
    assert.deepEqual(redactSecretValues({ [key]: value }), { [key]: value }, `${key} as a record entry`);
  }
  // The pair as a Vault client logs it: the identifier half stays beside the marker.
  const [[, roleId]] = IDENTIFIER_UUID_CONTROLS.slice(2);
  const [[, secretId]] = SECRET_ID_ROWS;
  assert.equal(scrubErrorText(`{"role_id":"${roleId}","secret_id":"${secretId}"}`), `{"role_id":"${roleId}","secret_id":"${REDACTED}"}`);
  assert.equal(scrubDataText(`VAULT_ROLE_ID=${roleId} VAULT_SECRET_ID=${secretId}`), `VAULT_ROLE_ID=${roleId} VAULT_SECRET_ID=${REDACTED}`);
  assert.deepEqual(redactSecretValues({ role_id: roleId, secret_id: secretId }), { role_id: roleId, secret_id: REDACTED });
});

test("settings: a token-shaped value under a setting key beside a credential word goes by shape through every sink, the data scrubs included, and only that run goes", () => {
  for (const value of ["Kq7Zx2Vw9Lm4Tp8RwQ12", "0f9e8d7c6b5a49382716f5e4d3c2b1a09f8e7d6c", "tnAki87T1HyQxV2b"]) {
    for (const [key, prefix] of [
      ["auth_method", ""],
      ["private_key_id", ""],
      ["api_key_id", ""],
      ["BOX_TOKEN_URL", "https://api.box.com/oauth2/"],
      ["tokenUrl", "https://api.box.com/oauth2/"],
    ]) {
      for (const [formName, form] of FORMS) {
        for (const [frameName, frame] of FRAMES) {
          const text = frame(form(key, `${prefix}${value}`));
          for (const [sinkName, sink] of SINKS) {
            const output = sink(text);
            assert.ok(!leaked(output, value), `${key} ${formName} ${frameName} leaked through ${sinkName}`);
            const rendered = typeof output === "string" ? output : JSON.stringify(output);
            if (prefix) assert.ok(rendered.includes(prefix), `${key}: the path in front of the token stays: ${rendered}`);
          }
        }
      }
      assert.deepEqual(redactSecretValues({ [key]: `${prefix}${value}` }), { [key]: `${prefix}${REDACTED}` }, `${key} as a record entry`);
    }
  }
});

test("#78 row D: a credential name after --, -D, -Dprefix., or a path segment is a carrier in every sink, and the path label control keeps its prose", () => {
  // Regression from main at 02967cc: `NAME_START` forbade "-" and "/" before a name, so the flags a
  // spawned CLI echoes (`mysql --password=<v>`, `java -Dpassword=<v>`) and a pair after a path segment
  // (`kv/password: <v>`) passed every scrub. The generic pair rule now starts a key after "-" or "/"
  // (`PAIR_KEY_START`), and `--name <value>` with a space is its own carrier (`FLAG_ARGUMENT_PATTERN`).
  const word = "skvclmtirehs";
  const token = "yln2bVNl4tE9Cyp1B18V2mX7CVud5LhW";
  const keys = ["password", "api_key", "api-key", "client_secret", "client-secret", "token", "access_token", "secret_id", "DB_PASSWORD", "X-Api-Key", "private-key", "SERVICENOW_PASSWORD", "DUO_SKEY", "refresh_token"];
  const forms = [
    [(key, value) => `mysql --${key}=${value} -h db`, (key) => [`mysql --${key}=`, " -h db"]],
    [(key, value) => `psql --${key} ${value} -h db`, (key) => [`psql --${key} `, " -h db"]],
    [(key, value) => `--${key}=${value}`, (key) => [`--${key}=`]],
    [(key, value) => `curl --${key}=${value} https://api.example.com/v1`, (key) => [`curl --${key}=`, " https://api.example.com/v1"]],
    [(key, value) => `java -D${key}=${value} -jar app.jar`, (key) => [`java -D${key}=`, " -jar app.jar"]],
    [(key, value) => `java -Dspring.datasource.${key}=${value} -jar app.jar`, (key) => [`java -Dspring.datasource.${key}=`, " -jar app.jar"]],
    [(key, value) => `path/${key}=${value} see log`, (key) => [`path/${key}=`, " see log"]],
    [(key, value) => `/${key}=${value}`, (key) => [`/${key}=`]],
    [(key, value) => `kv/${key}: ${value}`, (key) => [`kv/${key}: `]],
  ];
  let trials = 0;
  for (const key of keys) {
    for (const value of [word, token]) {
      for (const [form, keep] of forms) {
        const text = form(key, value);
        for (const [sinkName, sink] of SINKS) {
          trials += 1;
          const output = sink(text);
          assert.ok(!leaked(output, value), `${JSON.stringify(text)} leaked through ${sinkName}: ${JSON.stringify(output)}`);
          const rendered = typeof output === "string" ? output : JSON.stringify(output);
          for (const fragment of keep(key)) assert.ok(rendered.includes(fragment), `${JSON.stringify(text)} lost ${JSON.stringify(fragment)} through ${sinkName}: ${rendered}`);
        }
      }
    }
  }
  assert.equal(trials, keys.length * 2 * forms.length * SINKS.length);
  for (const [text, expected] of [
    [`mysql --password=${word} -h db`, `mysql --password=${REDACTED} -h db`],
    [`psql --password ${word} -h db`, `psql --password ${REDACTED} -h db`],
    [`psql --password '${word}' -h db`, `psql --password '${REDACTED}' -h db`],
    [`java -Dspring.datasource.password=${word} -jar app.jar`, `java -Dspring.datasource.password=${REDACTED} -jar app.jar`],
    [`kv/password: ${word}`, `kv/password: ${REDACTED}`],
    [`/password=${word}`, `/password=${REDACTED}`],
    // The controls the ruling keeps: a path label whose `:` continues as prose, the flag forms main
    // already handled, a setting flag, a flag with no argument, and the prose the sources emit.
    ["/api/v1/api-tokens: request failed with 403", "/api/v1/api-tokens: request failed with 403"],
    ["GET /_security/api_key: 403 Forbidden", "GET /_security/api_key: 403 Forbidden"],
    [`helm --set db.password=${word} upgrade`, `helm --set db.password=${REDACTED} upgrade`],
    ["--token-url https://api.example.com/oauth2/token", "--token-url https://api.example.com/oauth2/token"],
    ["--password --verbose", "--password --verbose"],
    ["sdk-keys: 3 of 5 rotated", "sdk-keys: 3 of 5 rotated"],
    ["Content-Type: application/json", "Content-Type: application/json"],
  ]) {
    assert.equal(scrubErrorText(text), expected, text);
    assert.equal(scrubDataText(text), expected, text);
    assert.equal(redactSecretValues(text), expected, text);
    assert.equal(scrubErrorText(expected), expected, `idempotent: ${text}`);
  }
});
