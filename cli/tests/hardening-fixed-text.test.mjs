import test from "node:test";
import assert from "node:assert/strict";

import { ConfigFileError } from "../dist/extensions/grc-tools/hardening/config-file.js";
import {
  IntegrationError,
  REDACTED,
  describeErrorBody,
  describeFailedResponse,
  errorMessage,
  scrubDataText,
  scrubErrorText,
} from "../dist/extensions/grc-tools/hardening/error-text.js";
import {
  coreDataValue,
  gatedPrincipals,
  notCollected,
  notRequested,
  notRequestedDataset,
  seenVersusTotal,
  unreadableDataset,
} from "../dist/extensions/grc-tools/hardening/collection-status.js";
import { describePagination } from "../dist/extensions/grc-tools/hardening/pagination.js";
import { NextLinkError, nextLinkStop, originOf, resolveSameOriginUrl } from "../dist/extensions/grc-tools/hardening/next-link.js";

/**
 * Every fixed-text message the library renders must come back from the library's own scrub
 * unchanged: the credential-pair rule eats `<credential word>: <value>` (the GWS round 7 case,
 * `Service account credentials: <path>`), and the long-token rule eats a 16-character run with a
 * digit or mixed case. Fixed wording and the placement of the path are chosen so neither applies.
 */
function assertSurvivesScrub(message, label) {
  assert.equal(typeof message, "string", `${label}: not a string`);
  assert.equal(scrubErrorText(message), message, `${label}: scrubErrorText changed the fixed text`);
  assert.equal(scrubDataText(message), message, `${label}: scrubDataText changed the fixed text`);
  assert.ok(!message.includes(REDACTED), `${label}: fixed text must not carry the marker`);
}

/** Realistic operator paths, including directories and files named for the credentials they hold. */
const PATHS = Object.freeze([
  "/home/user/.config/tool/credentials.json",
  "/home/user/.config/tool/config.yaml",
  "/home/user/secrets/tool.yaml",
  "/etc/tool/credentials/service-account.json",
  "/var/lib/tool/.secrets/api_keys.yaml",
  "/opt/tool/conf/token-store/config.json",
  "/Users/user/Library/Application Support/tool/credentials.yaml",
  "C:\\Users\\user\\AppData\\Roaming\\tool\\credentials.json",
  "./config/credentials.yaml",
  "~/.okta.yaml",
  "/home/user/.config/gcloud/application_default_credentials.json",
  "/home/user/.aws/credentials",
]);

const LABELS = Object.freeze([undefined, "New Relic", "Google Workspace", "Okta", "HashiCorp Vault", "1Password", "Zoom"]);
const READ_CODES = Object.freeze([undefined, "EACCES", "EISDIR", "ENOTDIR", "ELOOP", "EMFILE", "ERR_FS_FILE_TOO_LARGE"]);
const PARSE_CASES = Object.freeze([
  { format: "YAML", code: undefined },
  { format: "YAML", code: "BLOCK_AS_IMPLICIT_KEY" },
  { format: "YAML", code: "DUPLICATE_KEY" },
  { format: "YAML", code: "TAB_AS_INDENT" },
  { format: "YAML", code: "MULTILINE_IMPLICIT_KEY" },
  { format: "YAML", code: "KEY_OVER_1024_CHARS" },
  { format: "JSON", code: undefined },
  { format: "TOML", code: undefined },
  { format: "INI", code: undefined },
  { format: undefined, code: undefined },
]);
const POSITIONS = Object.freeze([{}, { line: 2 }, { line: 2, column: 6 }, { line: 1284, column: 19 }]);

const MEDIA_TYPES = Object.freeze([
  null,
  undefined,
  "",
  "text/html",
  "text/html; charset=utf-8",
  "text/plain",
  "application/xml",
  "application/x-www-form-urlencoded",
  "application/octet-stream",
  "application/x-ndjson",
  "image/svg+xml",
]);
const JSON_MEDIA_TYPES = Object.freeze(["application/json", "application/json; charset=utf-8", "application/problem+json", "application/vnd.api+json", "text/json"]);

const METHODS = Object.freeze(["GET", "POST", "PUT", "PATCH", "DELETE"]);
const ENDPOINTS = Object.freeze([
  "/v1/users",
  "/v1/credentials/rotate",
  "/oauth2/v1/token",
  "/api/v2/secrets",
  "/api/v1/apikey",
  "/admin/v1/sessions",
  "/v1/users?page=2&per_page=100",
  "https://api.example.com/v1/users",
  "https://graph.microsoft.com/v1.0/users",
  "https://login.microsoftonline.com/common/oauth2/v2.0/token",
]);
const STATUSES = Object.freeze([
  [400, "Bad Request"],
  [401, "Unauthorized"],
  [403, "Forbidden"],
  [404, "Not Found"],
  [429, "Too Many Requests"],
  [500, "Internal Server Error"],
  [502, "Bad Gateway"],
  [503, "Service Unavailable"],
  [401, null],
  [502, undefined],
]);

const DATASET_LABELS = Object.freeze(["roles", "users", "credentials", "secrets", "tokens", "api keys", "service account keys", "sessions", "OAuth clients", "password policies", "signing keys"]);
/**
 * Labels that are themselves a credential-named pair key (`credentials`, and any other word of the
 * scrub's `CREDENTIAL_PAIR_NAMES`) cannot stand in front of a colon in a note: the pair rule takes
 * whatever follows as the value whatever its shape (coordinator ruling on the Codex P2). A plural or
 * compound label (`secrets`, `tokens`, `api keys`, `sessions`) is not such a key and survives.
 */
const PAIR_KEY_LABELS = Object.freeze(["credentials"]);

function bodyNotes() {
  const notes = [];
  for (const mediaType of MEDIA_TYPES) {
    notes.push([`non-JSON body (${mediaType})`, describeErrorBody(mediaType, "<html><body>502</body></html>")]);
    notes.push([`empty body (${mediaType})`, describeErrorBody(mediaType, "")]);
  }
  for (const mediaType of JSON_MEDIA_TYPES) {
    notes.push([`malformed JSON (${mediaType})`, describeErrorBody(mediaType, "<html>oops</html>")]);
    notes.push([`undocumented field (${mediaType})`, describeErrorBody(mediaType, JSON.stringify({ trace_id: "abc", debug: { level: 3 } }))]);
    notes.push([`empty body (${mediaType})`, describeErrorBody(mediaType, "")]);
    notes.push([`array root (${mediaType})`, describeErrorBody(mediaType, "[]")]);
  }
  return notes;
}

function failedResponseLines() {
  const lines = [];
  for (const method of METHODS) {
    for (const endpoint of ENDPOINTS) {
      for (const [status, statusText] of STATUSES) {
        const body = { contentType: "text/html", body: "<html>denied</html>" };
        const line = describeFailedResponse({ method, endpoint, status, statusText, ...body });
        const expected = `${method} ${endpoint} failed with ${status}${statusText ? ` ${statusText}` : ""}: non-JSON body (text/html, 19 bytes)`;
        lines.push([`${method} ${endpoint} ${status}`, line, expected]);
      }
    }
  }
  lines.push(["empty body", describeFailedResponse({ method: "GET", endpoint: "/v1/users", status: 401, statusText: "Unauthorized", contentType: "application/json", body: "" }), "GET /v1/users failed with 401 Unauthorized: empty body"]);
  lines.push(["malformed", describeFailedResponse({ method: "GET", endpoint: "/v1/users", status: 500, contentType: "application/json", body: "<html>" }), "GET /v1/users failed with 500: malformed JSON body (application/json, 6 bytes)"]);
  lines.push(["undocumented", describeFailedResponse({ method: "POST", endpoint: "/oauth2/v1/token", status: 400, statusText: "Bad Request", contentType: "application/json", body: "{}" }), "POST /oauth2/v1/token failed with 400 Bad Request: JSON body without a documented message field (2 bytes)"]);
  return lines;
}

test("every ConfigFileError message survives the scrub for every kind, format, code, position, label, and realistic path", () => {
  let rendered = 0;
  for (const path of PATHS) {
    for (const label of LABELS) {
      for (const code of READ_CODES) {
        const message = new ConfigFileError({ kind: "read", path, code, label }).message;
        assert.ok(message.includes(path), `read message must carry the path: ${message}`);
        assertSurvivesScrub(message, `read ${path} ${label} ${code}`);
        rendered += 1;
      }
      for (const { format, code } of PARSE_CASES) {
        for (const position of POSITIONS) {
          const message = new ConfigFileError({ kind: "parse", path, format, code, label, ...position }).message;
          assert.ok(message.includes(path), `parse message must carry the path: ${message}`);
          assertSurvivesScrub(message, `parse ${path} ${label} ${format} ${code} ${JSON.stringify(position)}`);
          rendered += 1;
        }
      }
    }
  }
  assert.ok(rendered > 3000, `expected a full matrix, rendered ${rendered}`);
});

test("every describeErrorBody note survives the scrub", () => {
  for (const [label, note] of bodyNotes()) {
    assertSurvivesScrub(note, label);
    assert.match(note, /^(?:non-JSON body \((?:[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+|unknown), \d+ bytes\)|malformed JSON body \([a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+, \d+ bytes\)|JSON body without a documented message field \(\d+ bytes\)|empty body)$/, label);
  }
});

test("every describeFailedResponse line is rendered as written and survives a second scrub", () => {
  for (const [label, line, expected] of failedResponseLines()) {
    assert.equal(line, expected, `${label}: the constructor's own scrub changed the fixed text`);
    assertSurvivesScrub(line, label);
  }
});

test("IntegrationError messages built from the fixed texts survive, with and without a cause", () => {
  class DemoApiError extends IntegrationError {}
  for (const [label, line] of failedResponseLines().slice(0, 40)) {
    const error = new DemoApiError(line, { status: 403, endpoint: "/v1/users" });
    assert.equal(error.message, line, `${label}: IntegrationError changed the fixed text`);
    assertSurvivesScrub(error.message, label);
    assertSurvivesScrub(errorMessage(error), `${label} folded`);
  }
  for (const path of PATHS) {
    const cause = new ConfigFileError({ kind: "parse", path, format: "YAML", code: "BLOCK_AS_IMPLICIT_KEY", line: 2, column: 6, label: "Google Workspace" });
    const error = new IntegrationError(`Unable to resolve configuration for the audit`, { cause });
    const folded = errorMessage(error);
    assert.equal(folded, `Unable to resolve configuration for the audit (cause: ${cause.message})`);
    assertSurvivesScrub(folded, `cause ${path}`);
  }
  for (const endpoint of ENDPOINTS) {
    const error = new IntegrationError(`GET ${endpoint} failed with 403 Forbidden: non-JSON body (text/html, 512 bytes)`, { status: 403, endpoint });
    if (!endpoint.includes("?")) assert.equal(error.endpoint, endpoint, "a benign endpoint is stored as written");
    assertSurvivesScrub(error.message, `endpoint ${endpoint}`);
  }
});

test("every pagination note survives the scrub", () => {
  const stops = [
    { kind: "exhausted" },
    { kind: "limit", limit: 500 },
    { kind: "page_cap", pages: 20 },
    { kind: "repeated_cursor" },
    { kind: "empty_page_with_cursor" },
    { kind: "time_budget", budgetMs: 30000 },
    { kind: "missing_total" },
    { kind: "rejected_next_link", reason: "foreign_origin", origin: "https://evil.example" },
    { kind: "rejected_next_link", reason: "foreign_origin" },
    { kind: "rejected_next_link", reason: "userinfo" },
    { kind: "rejected_next_link", reason: "unparseable" },
  ];
  for (const stop of stops) {
    for (const [seen, total] of [[0, null], [40, 120], [500, 1200], [1000, undefined], [40, 0]]) {
      const outcome = describePagination(seen, total, stop);
      if (outcome.note !== undefined) assertSurvivesScrub(outcome.note, `${stop.kind} ${seen}/${total}`);
    }
  }
  assertSurvivesScrub(seenVersusTotal(40, 120), "seen of total");
  assertSurvivesScrub(seenVersusTotal(40, null), "seen, total unknown");
});

/** Configured origins in the shapes the integrations use: vendor hosts, tenant subdomains, ports, and IP literals. */
const CONFIGURED_ORIGINS = Object.freeze([
  "https://api.example.com",
  "https://acme.okta.com",
  "https://acme-admin.zscaler.net",
  "https://graph.microsoft.com",
  "https://api.us.onelogin.com",
  "https://dev123456.service-now.com",
  "https://api.eu1.qualys.com:443",
  "https://vault.internal.example:8200",
  "http://10.0.0.1:8080",
  "https://[2001:db8::1]:8443",
]);
/** Rejected origins: other hosts, other schemes, other ports, IP literals, and non-hierarchical schemes. */
const REJECTED_ORIGINS = Object.freeze([
  "https://evil.example",
  "https://collector.attacker.example",
  "http://api.example.com",
  "https://api.example.com:8443",
  "http://169.254.169.254",
  "http://127.0.0.1:9000",
  "https://[::1]",
  "https://xn--80ak6aa92e.com",
  "javascript:",
  "data:",
]);

test("every NextLinkError message and next-link pagination note survives the scrub for every configured and rejected origin", () => {
  let rendered = 0;
  for (const configuredAsWritten of CONFIGURED_ORIGINS) {
    const base = `${configuredAsWritten}/api/v2/users?per_page=100`;
    // A default port written in the configuration (`:443`) is not part of the origin the URL parser reports.
    const configured = originOf(new URL(base));
    for (const rejected of REJECTED_ORIGINS) {
      const link = rejected.endsWith(":") ? `${rejected}payload` : `${rejected}/collect?token=abc`;
      let error;
      try {
        resolveSameOriginUrl(link, base);
      } catch (thrown) {
        error = thrown;
      }
      if (error === undefined) continue; // the rejected origin equals this configured origin
      assert.ok(error instanceof NextLinkError, `${configured} <- ${rejected}`);
      assert.equal(error.message, `next link to ${rejected} was not followed because it does not share the configured origin ${configured}`);
      assertSurvivesScrub(error.message, `foreign ${configured} <- ${rejected}`);
      assertSurvivesScrub(errorMessage(error), `foreign ${configured} <- ${rejected} folded`);
      const note = describePagination(40, 120, nextLinkStop(error)).note;
      assertSurvivesScrub(note, `foreign note ${configured} <- ${rejected}`);
      rendered += 1;
    }
    for (const [reason, link] of [["userinfo", `${configured.replace("://", "://user:pw@")}/api/v2/users?page=2`], ["unparseable", "http://[bad"]]) {
      let error;
      try {
        resolveSameOriginUrl(link, base);
      } catch (thrown) {
        error = thrown;
      }
      assert.ok(error instanceof NextLinkError && error.reason === reason, `${configured} ${reason}`);
      assertSurvivesScrub(error.message, `${reason} ${configured}`);
      assertSurvivesScrub(errorMessage(error), `${reason} ${configured} folded`);
      assertSurvivesScrub(describePagination(40, 120, nextLinkStop(error)).note, `${reason} note ${configured}`);
      rendered += 1;
    }
  }
  assert.ok(rendered >= 100, `expected the full matrix, rendered ${rendered}`);
});

test("marker error text survives the scrub for every inventory label, including credential-named inventories", () => {
  const line = describeFailedResponse({ method: "GET", endpoint: "/v1/roles", status: 403, statusText: "Forbidden", contentType: "text/html", body: "<html>denied</html>" });
  for (const label of DATASET_LABELS) {
    const endpoint = `/v1/${label.replace(/ /g, "-").toLowerCase()}`;
    const parentLine = describeFailedResponse({ method: "GET", endpoint, status: 403, statusText: "Forbidden", contentType: "text/html", body: "<html>denied</html>" });
    assertSurvivesScrub(parentLine, `${label} parent line`);
    assertSurvivesScrub(notCollected(parentLine, 403, endpoint).error, `${label} not collected`);
    assertSurvivesScrub(notRequested(label, parentLine).error, `${label} not requested with parent error`);
    assertSurvivesScrub(notRequested(label).error, `${label} not requested`);
    assertSurvivesScrub(coreDataValue(notRequestedDataset(label, parentLine)).error, `${label} not requested dataset`);
    assertSurvivesScrub(coreDataValue(unreadableDataset(parentLine, { status: 403, endpoint })).error, `${label} unreadable dataset`);

    const notes = [
      `${label}: ${seenVersusTotal(40, 120)}`,
      `${label}: ${seenVersusTotal(40, null)}`,
      `${label}: unreadable (${parentLine})`,
      `${label}: not collected`,
      `${label}: truncated`,
    ];
    const gated = gatedPrincipals({ admins_without_mfa: ["alice"], admin_count: 1 }, false, notes);
    if (PAIR_KEY_LABELS.includes(label)) {
      // The caller's note, not the library's: a credential pair key before a colon loses the word after it, so such a label is written without the colon.
      assert.equal(scrubErrorText(gated.principals_withheld), notes.map((note) => note.replace(/^credentials: \S+/, `credentials: ${REDACTED}`)).join("; "), `${label} principals_withheld with a colon`);
      const withoutColon = notes.map((note) => note.replace(`${label}: `, `${label} `));
      assertSurvivesScrub(gatedPrincipals({ admin_count: 1 }, false, withoutColon).principals_withheld, `${label} principals_withheld without a colon`);
      assertSurvivesScrub(gatedPrincipals({ admin_count: 1 }, false, notes.map((note) => note.replace(`${label}: `, `${label} inventory: `))).principals_withheld, `${label} principals_withheld with a compound label`);
      continue;
    }
    assertSurvivesScrub(gated.principals_withheld, `${label} principals_withheld`);
  }
  assertSurvivesScrub(notCollected(line).error, "not collected without status");
});

test("a path rendered as the value of a credential-named pair is eaten, which is why no fixed text renders one that way", () => {
  const path = "/home/user/.config/tool/credentials.json";
  assert.equal(scrubErrorText(`Service account credentials: ${path}`), `Service account credentials: ${REDACTED}`);
  assert.equal(scrubDataText(`credentials=${path}`), `credentials=${REDACTED}`);
  assert.equal(scrubErrorText(`Service account credentials file ${path} could not be read`), `Service account credentials file ${path} could not be read`);
  assert.equal(scrubErrorText(`Unable to read config file ${path} (EACCES)`), `Unable to read config file ${path} (EACCES)`);
});
