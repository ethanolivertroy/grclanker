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
