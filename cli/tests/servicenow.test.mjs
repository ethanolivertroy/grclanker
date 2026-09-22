import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

import {
  ServicenowApiClient,
  ServicenowApiError,
  assessServicenowAccessControl,
  assessServicenowIdentityAccess,
  assessServicenowOperationsGovernance,
  assessServicenowPlatformHardening,
  buildSensitiveAclQuery,
  checkServicenowAccess,
  exportServicenowAuditBundle,
  listServicenowControls,
  mappingsForControl,
  parseLinkNext,
  projectAclRow,
  projectRows,
  redactSecrets,
  registerServicenowTools,
  resolveSecureOutputPath,
  resolveServicenowConfiguration,
} from "../dist/extensions/grc-tools/servicenow.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";
import { assertSecretFragmentsAbsent, readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";
import { CONFIG_CANARIES, assertConfigLoaderMatrix, configLoaderCases } from "./helpers/config-loader-matrix.mjs";
import { assertFixedTextsSurvive, collectFixedTexts, collectThrownMessage, collectToolTexts, logLines } from "./helpers/fixed-text-survival.mjs";
import { assertFragmentsAbsent, assertPlantedValuesWellFormed } from "./helpers/planted-values.mjs";
import { assertScrubBoundary } from "./helpers/scrub-boundary-matrix.mjs";

const FIXED_NOW = new Date("2026-09-21T00:00:00Z");
const RECENT_LOGIN = "2026-09-20 08:15:00";
const STALE_LOGIN = "2026-01-05 08:15:00";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

/** The configured basic-auth password: a planted credential, so random-looking (see the planted-values self-check). */
const SAMPLE_PASSWORD = "Ka4pnBxqUxmU8PgZhf";

function sampleConfig(overrides = {}) {
  return {
    instanceUrl: "https://dev12345.service-now.com",
    instanceName: "dev12345",
    authMode: "basic",
    username: "audit.reader",
    password: SAMPLE_PASSWORD,
    timeoutMs: 30000,
    maxRetries: 3,
    pageSize: 500,
    sourceChain: ["tests"],
    ...overrides,
  };
}

const REASON_PHRASES = { 200: "OK", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 429: "Too Many Requests", 500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable" };

function jsonResponse(value, options = {}) {
  return new Response(JSON.stringify(value), {
    status: options.status ?? 200,
    statusText: options.statusText ?? REASON_PHRASES[options.status ?? 200] ?? "",
    headers: {
      "content-type": "application/json",
      ...(options.headers ?? {}),
    },
  });
}

function forbiddenResponse() {
  return jsonResponse({ error: { message: "Insufficient rights to query records", detail: "Field(s) present in the query do not have permission to be read" }, status: "failure" }, { status: 403 });
}

/** Random-looking alphanumeric canaries; the leak assertions check every substring of them at lengths 6 through 24. */
const SNOW_CANARY = {
  bearer: "mfuQzWnTyV9scxqkWy",
  session: "UJg6tnwe5nP7EwdYya",
  apiKey: "jG9FmV3axD4A7pcZdp",
  urlToken: "bGnrbF6YU5UQUxDu2u",
  password: "CFe6ahZBmU4AsbZt4J",
  clientSecret: "gjbPA9KryHPaZwmf9C",
  accessToken: "QAK8MsfbqRnUyzYNfP",
};
const SNOW_CANARY_URL = `https://api.example.com/v1/x?token=${SNOW_CANARY.urlToken}`;

/** Planted in every fixture column that can carry a secret on a real instance (secretLadenFixture). */
const FAKE_SNOW_SECRETS = {
  passwordHash: "vdKjWDw6FPzcNrMpAF",
  secretToken1: "pSxb8eQAKJZumEpGEB",
  secretToken2: "vUySfhtReYjPs6gxE5",
  privateKey: "hLWJHSGAZrhB4j8z7e",
  scriptLiteral: "7CKYRgHmrmuQhNJsdp",
};

/**
 * `fail` serves one table (Table API and Aggregate API) or one path with a body that must never be
 * echoed: html is a 502 proxy page carrying the canaries; json is a 403 ServiceNow error object whose
 * documented message and detail fields embed the canary URL mid-sentence and a bearer value.
 */
function snowCanaryResponse(flavor) {
  if (flavor === "html") {
    const page = [
      "<html><head><title>502 Bad Gateway</title></head><body>",
      `<p>The upstream request carried Authorization: Bearer ${SNOW_CANARY.bearer} and Set-Cookie: JSESSIONID=${SNOW_CANARY.session}.</p>`,
      `<p>Retry with x-api-key: ${SNOW_CANARY.apiKey}; the incident is tracked at ${SNOW_CANARY_URL} until resolved.</p>`,
      "</body></html>",
    ].join("");
    return new Response(page, { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html; charset=utf-8" } });
  }
  return jsonResponse({
    error: {
      message: `Insufficient rights; the request was logged at ${SNOW_CANARY_URL} for review`,
      detail: `Presented Authorization: Bearer ${SNOW_CANARY.bearer}; see ${SNOW_CANARY_URL} for the ACL decision`,
    },
    error_description: `Token exchange refused; retry at ${SNOW_CANARY_URL}`,
    status: "failure",
  }, { status: 403 });
}

function parseConditionGroups(query) {
  if (!query) return [];
  const groups = [];
  for (const part of query.split("^")) {
    if (part.startsWith("OR") && groups.length > 0) {
      groups[groups.length - 1].push(part.slice(2));
    } else {
      groups.push([part]);
    }
  }
  return groups;
}

function matchesCondition(row, condition, fixture) {
  for (const operator of ["STARTSWITH", "LIKE", "IN", ">=", "="]) {
    const index = condition.indexOf(operator);
    if (index <= 0) continue;
    const field = condition.slice(0, index);
    const value = condition.slice(index + operator.length);
    const actual = row[field] === undefined || row[field] === null ? "" : String(row[field]);
    if (value.startsWith("javascript:")) {
      if (value.includes("getUserID")) return row.user_name === fixture.identity;
      return true;
    }
    switch (operator) {
      case "STARTSWITH":
        return actual.startsWith(value);
      case "LIKE":
        return actual.includes(value);
      case "IN":
        return value.split(",").includes(actual);
      case ">=":
        return actual >= value;
      default:
        return actual === value;
    }
  }
  return true;
}

function matchesQuery(row, query, fixture) {
  const groups = parseConditionGroups(query);
  return groups.every((group) => group.some((condition) => matchesCondition(row, condition, fixture)));
}

function filterRows(rows, query, fixture) {
  const alternatives = query ? query.split("^NQ") : [""];
  return rows.filter((row) => alternatives.some((alternative) => matchesQuery(row, alternative, fixture)));
}

function fixtureFetch(fixture, options = {}) {
  const calls = [];
  // Every served response is logged with its status so tests can prove that each status code and
  // endpoint named anywhere in the output corresponds to a request the run made.
  const requests = [];
  const forbidden = new Set(options.forbiddenTables ?? []);
  const forbiddenCounts = new Set(options.forbiddenCounts ?? []);
  const forbiddenQueries = options.forbiddenQueries ?? [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(String(input));
    calls.push({ url, init });
    const respond = (response) => {
      requests.push({ method: init.method ?? "GET", url: url.toString(), path: url.pathname, status: response.status });
      return response;
    };
    const tableMatch = url.pathname.match(/^\/api\/now\/table\/([^/]+)$/);
    const statsMatch = url.pathname.match(/^\/api\/now\/stats\/([^/]+)$/);
    const table = tableMatch?.[1] ?? statsMatch?.[1];
    if (options.fail && ((options.fail.table !== undefined && table === options.fail.table) || (options.fail.path !== undefined && url.pathname === options.fail.path))) {
      return respond(snowCanaryResponse(options.fail.flavor));
    }
    if (options.oauthToken && url.pathname === "/oauth_token.do") {
      return respond(jsonResponse({ access_token: options.oauthToken, expires_in: 1799, token_type: "Bearer" }));
    }
    if (options.forbidAll || (table && forbidden.has(table))) return respond(forbiddenResponse());
    if (statsMatch && forbiddenCounts.has(table)) return respond(forbiddenResponse());
    if (tableMatch && forbiddenQueries.some((rule) => rule.table === table && (url.searchParams.get("sysparm_query") ?? "").includes(rule.queryIncludes))) {
      return respond(forbiddenResponse());
    }
    const inflate = options.inflateTotals?.[table] ?? options.inflateTotal ?? 0;
    if (tableMatch) {
      const rows = fixture.tables[table];
      if (rows === undefined) return respond(jsonResponse({ error: { message: `Invalid table ${table}` } }, { status: 400 }));
      const query = url.searchParams.get("sysparm_query") ?? "";
      const matched = filterRows(rows, query, fixture);
      const limit = Number(url.searchParams.get("sysparm_limit") ?? "500");
      const offset = Number(url.searchParams.get("sysparm_offset") ?? "0");
      const page = matched.slice(offset, offset + limit);
      const headers = options.omitTotalCount ? {} : { "X-Total-Count": String(matched.length + inflate) };
      if (offset + limit < matched.length) {
        const nextUrl = new URL(url);
        nextUrl.searchParams.set("sysparm_offset", String(offset + limit));
        headers.Link = `<${nextUrl.toString()}>;rel="next"`;
      }
      return respond(jsonResponse({ result: page }, { headers }));
    }
    if (statsMatch) {
      const explicit = fixture.counts?.[table];
      if (explicit !== undefined) {
        return respond(jsonResponse({ result: { stats: { count: String(explicit) } } }));
      }
      const rows = fixture.tables[table];
      if (rows === undefined) return respond(jsonResponse({ error: { message: `Invalid table ${table}` } }, { status: 400 }));
      const query = url.searchParams.get("sysparm_query") ?? "";
      return respond(jsonResponse({ result: { stats: { count: String(filterRows(rows, query, fixture).length + inflate) } } }));
    }
    return respond(jsonResponse({ error: { message: "not found" } }, { status: 404 }));
  };
  return { fetchImpl, calls, requests };
}

function createClient(fetchImpl, overrides = {}, sleeps = []) {
  return new ServicenowApiClient(sampleConfig(overrides), {
    fetchImpl,
    sleep: async (ms) => {
      sleeps.push(ms);
    },
    now: () => FIXED_NOW,
  });
}

function property(name, value) {
  return { sys_id: `prop-${name}`, name, value, type: "string", sys_updated_on: "2026-06-01 00:00:00" };
}

function user(sysId, userName, overrides = {}) {
  return {
    sys_id: sysId,
    user_name: userName,
    name: userName,
    email: `${userName}@example.com`,
    active: "true",
    locked_out: "false",
    last_login_time: RECENT_LOGIN,
    web_service_access_only: "false",
    internal_integration_user: "false",
    enable_multifactor_authn: "false",
    sys_created_on: "2025-01-01 00:00:00",
    ...overrides,
  };
}

function roleAssignment(sysId, userRow, roleName, overrides = {}) {
  return {
    sys_id: sysId,
    user: userRow.sys_id,
    "user.user_name": userRow.user_name,
    "user.active": userRow.active,
    "user.web_service_access_only": userRow.web_service_access_only,
    "user.internal_integration_user": userRow.internal_integration_user,
    "user.last_login_time": userRow.last_login_time,
    role: `role-${roleName}`,
    "role.name": roleName,
    inherited: "false",
    state: "active",
    ...overrides,
  };
}

const SENSITIVE_TABLES = ["sys_user", "sys_user_has_role", "sys_user_role", "sys_properties", "sys_script", "sys_security_acl", "syslog", "sys_audit"];

function sensitiveAcls(options = {}) {
  const acls = [];
  const aclRoles = [];
  for (const table of SENSITIVE_TABLES) {
    for (const operation of ["read", "write", "delete"]) {
      const sysId = `acl-${table}-${operation}`;
      acls.push({ sys_id: sysId, name: table, operation, type: "record", active: "true", admin_overrides: "true", condition: "", script: "", advanced: "false", description: "" });
      if (!(options.unrestricted ?? []).includes(sysId)) {
        aclRoles.push({ sys_id: `aclrole-${sysId}`, sys_security_acl: sysId, "sys_security_acl.name": table, sys_user_role: "role-admin", "sys_user_role.name": "admin" });
      }
    }
  }
  return { acls, aclRoles };
}

function healthyProperties() {
  return [
    property("glide.enable.password_policy", "true"),
    property("glide.apply.password_policy.on_login", "true"),
    property("glide.login.no_blank_password", "true"),
    property("glide.authenticate.multifactor", "true"),
    property("glide.authenticate.multifactor.email.otp.enabled", "false"),
    property("glide.authenticate.multisso.enabled", "true"),
    property("glide.authenticate.sso.redirect.idp", "sso-okta"),
    property("glide.sso.acr.enabled", "true"),
    property("glide.security.use_csrf_token", "true"),
    property("glide.security.csrf.strict.validation.mode", "true"),
    property("glide.security.file.mime_type.validation", "true"),
    property("glide.security.diag_txns_acl", "true"),
    property("glide.security.strict.user_image_upload", "true"),
    property("glide.script.use.sandbox", "true"),
    property("glide.script.allow.ajaxevaluate", "false"),
    property("glide.script.secure.ajaxgliderecord", "true"),
    property("glide.script.ccsi.ispublic", "false"),
    property("glide.security.strict.updates", "true"),
    property("glide.security.strict.actions", "true"),
    property("glide.ui.escape_html_list_field", "true"),
    property("glide.ui.escape_all_script", "true"),
    property("glide.html.escape_script", "true"),
    property("glide.html.sanitize_all_fields", "true"),
    property("glide.ui.security.allow_codetag", "false"),
    property("glide.ui.security.codetag.allow_script", "false"),
    property("glide.set_x_frame_options", "true"),
    property("glide.ui.secure_cookies", "true"),
    property("glide.cookies.http_only", "true"),
    property("glide.ui.session_timeout", "30"),
    property("glide.ui.rotate_sessions", "true"),
    property("glide.ui.user_cookie.max_life_span_in_days", "1"),
    property("glide.ip.authenticate.strict", "true"),
    property("glide.smtp.auth", "true"),
    property("glide.email.email_with_no_target_visible_to_all", "false"),
    property("glide.debug.ui", "false"),
  ];
}

function healthyFixture() {
  const alice = user("u-alice", "alice.admin", { enable_multifactor_authn: "true" });
  const bob = user("u-bob", "bob.user");
  const svc = user("u-svc", "svc.integration", { web_service_access_only: "true" });
  const reader = user("u-reader", "audit.reader", { enable_multifactor_authn: "true" });
  const { acls, aclRoles } = sensitiveAcls();
  return {
    identity: "audit.reader",
    tables: {
      sys_user: [alice, bob, svc, reader],
      sys_user_has_role: [roleAssignment("uhr-1", alice, "admin")],
      sys_user_role: [{ sys_id: "role-admin", name: "admin" }, { sys_id: "role-itil", name: "itil" }],
      sys_user_role_contains: [
        { sys_id: "rc-1", role: "role-itil_admin", "role.name": "itil_admin", contains: "role-itil", "contains.name": "itil" },
        { sys_id: "rc-2", role: "role-catalog_admin", "role.name": "catalog_admin", contains: "role-catalog", "contains.name": "catalog" },
      ],
      sys_properties: healthyProperties(),
      password_policy: [{ sys_id: "pp-default", name: "Default", minimum_password_length: "14", maximum_password_length: "72", require_uppercase: "true", require_lowercase: "true", require_digit: "true", require_special: "true" }],
      sso_properties: [{ sys_id: "sso-okta", name: "Okta", active: "true", default: "true", auto_redirect_idp: "true", sys_updated_on: "2026-01-01 00:00:00" }],
      ldap_server_config: [],
      sys_certificate: [{ sys_id: "cert-1", name: "Okta signing certificate", type: "cert", expires: "2027-06-01 00:00:00", active: "true" }],
      oauth_entity: [{ sys_id: "oauth-1", name: "Integration app", type: "client", active: "true", client_id: "abc123" }],
      multi_factor_criteria: [
        { sys_id: "d427668b73003300fdbd04fbc4f6a7b6", name: "Role-based multi-factor authentication", active: "true", roles: "admin, security_admin" },
        { sys_id: "mfc-user", name: "User-based multi-factor authentication", active: "true" },
      ],
      sys_security_acl: acls,
      sys_security_acl_role: aclRoles,
      sys_public: [],
      sys_script: [{ sys_id: "br-1", name: "Set assignment", collection: "incident", active: "true", script: "current.assigned_to = gs.getUserID();" }],
      ip_access: [{ sys_id: "ip-1", type: "allow", direction: "inbound", active: "true", range_start: "10.0.0.0", range_end: "10.0.255.255", description: "Corporate VPN" }],
      sys_email_account: [{ sys_id: "email-1", name: "Outbound SMTP", type: "SMTP", active: "true", connection_security: "SSL/TLS", authentication: "Password", server: "smtp.example.com", port: "465" }],
      sys_encryption_context: [],
      sys_kmf_crypto_module: [],
      sys_dictionary: [
        { sys_id: "dict-user", name: "sys_user", internal_type: "collection", audit: "true", attributes: "" },
        { sys_id: "dict-uhr", name: "sys_user_has_role", internal_type: "collection", audit: "true", attributes: "" },
        { sys_id: "dict-role", name: "sys_user_role", internal_type: "collection", audit: "true", attributes: "" },
        { sys_id: "dict-acl", name: "sys_security_acl", internal_type: "collection", audit: "true", attributes: "" },
        { sys_id: "dict-props", name: "sys_properties", internal_type: "collection", audit: "true", attributes: "" },
      ],
      sys_audit: [{ sys_id: "audit-1" }],
      syslog_transaction: [{ sys_id: "txn-1" }],
      sys_update_set: [{ sys_id: "us-default", name: "Default", state: "complete", application: "global", sys_created_by: "admin" }],
      sys_update_xml: [],
      sys_user_session: [{ sys_id: "session-1" }],
      ecc_agent: [{ sys_id: "mid-1", name: "mid01", status: "Up", validated: "true", version: "yokohama-01-01-2026", host_name: "mid01.example.com" }],
      sys_plugins: [
        { sys_id: "plg-1", name: "High Security Settings", source: "com.glide.high_security", active: "active", version: "1.0" },
        { sys_id: "plg-2", name: "Contextual Security: Role Management V2", source: "com.glide.role_management.v2", active: "active", version: "1.0" },
        { sys_id: "plg-3", name: "Security Jump Start (ACL Rules)", source: "com.snc.security_jump_start", active: "active", version: "1.0" },
        { sys_id: "plg-4", name: "Instance Security Center", source: "com.glide.security_center", active: "active", version: "1.0" },
        { sys_id: "plg-5", name: "IP Range Based Authentication", source: "com.snc.ipauthenticator", active: "active", version: "1.0" },
      ],
    },
    counts: {
      sys_audit: 1200,
      syslog_transaction: 50000,
    },
  };
}

function emptyFixture() {
  const healthy = healthyFixture();
  const tables = Object.fromEntries(Object.keys(healthy.tables).map((table) => [table, []]));
  return { identity: "audit.reader", tables, counts: { sys_audit: 0, syslog_transaction: 0 } };
}

function failingFixture() {
  const fixture = healthyFixture();
  const alice = user("u-alice", "alice.admin", { last_login_time: STALE_LOGIN });
  const nolog = user("u-nolog", "never.logged", { last_login_time: "" });
  const svc = user("u-svc", "svc.integration", { web_service_access_only: "true" });
  const reader = user("u-reader", "audit.reader");
  fixture.tables.sys_user = [alice, nolog, svc, reader];
  fixture.tables.sys_user_has_role = [
    roleAssignment("uhr-1", alice, "admin"),
    roleAssignment("uhr-2", alice, "security_admin"),
    roleAssignment("uhr-3", svc, "admin"),
  ];
  fixture.tables.sys_user_role_contains.push({ sys_id: "rc-3", role: "role-itil_admin", "role.name": "itil_admin", contains: "role-admin", "contains.name": "admin" });
  const override = new Map([
    ["glide.authenticate.multifactor", "false"],
    ["glide.security.use_csrf_token", "false"],
    ["glide.script.allow.ajaxevaluate", "true"],
    ["glide.ui.escape_all_script", "false"],
    ["glide.ui.session_timeout", "120"],
    ["glide.ip.authenticate.strict", "false"],
    ["glide.debug.ui", "true"],
  ]);
  fixture.tables.sys_properties = fixture.tables.sys_properties.map((row) => (override.has(row.name) ? { ...row, value: override.get(row.name) } : row));
  fixture.tables.password_policy = [{ sys_id: "pp-default", name: "Default", minimum_password_length: "6", require_uppercase: "false", require_lowercase: "true", require_digit: "false" }];
  fixture.tables.sso_properties = [];
  fixture.tables.sys_certificate = [{ sys_id: "cert-1", name: "Expired signing certificate", type: "cert", expires: "2026-01-01 00:00:00", active: "true" }];
  const { acls, aclRoles } = sensitiveAcls({ unrestricted: ["acl-sys_user-read"] });
  fixture.tables.sys_security_acl = acls.filter((row) => row.name !== "syslog");
  fixture.tables.sys_security_acl_role = aclRoles;
  fixture.tables.sys_public = [{ sys_id: "pub-1", page: "custom_status", active: "true" }];
  fixture.tables.sys_script.push({ sys_id: "br-2", name: "Dynamic eval", collection: "incident", active: "true", script: "eval(current.script);" });
  fixture.tables.ip_access = [];
  fixture.tables.sys_email_account = [{ sys_id: "email-1", name: "Outbound SMTP", type: "SMTP", active: "true", connection_security: "None", server: "smtp.example.com", port: "25" }];
  fixture.tables.sys_dictionary = fixture.tables.sys_dictionary.map((row) => (row.name === "sys_user" ? { ...row, audit: "false" } : row));
  fixture.tables.sys_update_set.push({ sys_id: "us-open", name: "Security tweaks", state: "in progress", application: "global", sys_created_by: "dev" });
  fixture.tables.sys_update_xml = [{ sys_id: "ux-1", name: "sys_security_acl_abc", type: "Access Control", target_name: "sys_user.read", action: "INSERT_OR_UPDATE", update_set: "us-open", "update_set.name": "Security tweaks", "update_set.state": "in progress" }];
  fixture.tables.ecc_agent = [{ sys_id: "mid-1", name: "mid01", status: "Down", validated: "false", version: "old" }];
  fixture.tables.sys_plugins = fixture.tables.sys_plugins.map((row) => (row.name === "High Security Settings" ? { ...row, active: "inactive" } : row));
  return fixture;
}

function findingsById(result) {
  return new Map(result.findings.map((item) => [item.id, item]));
}

function assertNoPass(result, label) {
  const passing = result.findings.filter((item) => item.status === "pass").map((item) => item.id);
  assert.deepEqual(passing, [], `${label}: expected no passing findings but saw ${passing.join(", ")}`);
}

async function runAllAssessments(client) {
  return {
    identity: await assessServicenowIdentityAccess(client),
    hardening: await assessServicenowPlatformHardening(client),
    accessControl: await assessServicenowAccessControl(client),
    operations: await assessServicenowOperationsGovernance(client),
  };
}

test("resolveServicenowConfiguration applies args over env over config file", () => {
  const base = createTempBase("servicenow-config-");
  const configPath = join(base, "config.yaml");
  writeFileSync(configPath, [
    "servicenow:",
    "  instance: filesnow",
    "  username: file.user",
    "  password: file-password",
    "  timeout_seconds: 12",
    "",
  ].join("\n"));

  const resolved = resolveServicenowConfiguration(
    { username: "arg.user", config_file: configPath },
    { SERVICENOW_USERNAME: "env.user", SERVICENOW_MAX_RETRIES: "5" },
    { cwd: base, homeDir: base },
  );

  assert.equal(resolved.instanceUrl, "https://filesnow.service-now.com");
  assert.equal(resolved.instanceName, "filesnow");
  assert.equal(resolved.username, "arg.user");
  assert.equal(resolved.password, "file-password");
  assert.equal(resolved.authMode, "basic");
  assert.equal(resolved.timeoutMs, 12000);
  assert.equal(resolved.maxRetries, 5);
  assert.deepEqual(resolved.sourceChain, [`config-file:${configPath}`, "environment", "arguments"]);
});

test("resolveServicenowConfiguration infers OAuth from client credentials and tokens", () => {
  const oauth = resolveServicenowConfiguration({}, {
    SERVICENOW_URL: "https://acme.service-now.com/",
    SERVICENOW_CLIENT_ID: "client-id",
    SERVICENOW_CLIENT_SECRET: "client-secret",
  }, { cwd: createTempBase("servicenow-empty-"), homeDir: createTempBase("servicenow-home-") });
  assert.equal(oauth.authMode, "oauth");
  assert.equal(oauth.instanceUrl, "https://acme.service-now.com");
  assert.equal(oauth.instanceName, "acme");

  const token = resolveServicenowConfiguration({ instance: "acme", access_token: "pre-issued-token" }, {}, { cwd: createTempBase("servicenow-empty-"), homeDir: createTempBase("servicenow-home-") });
  assert.equal(token.authMode, "oauth");
  assert.equal(token.accessToken, "pre-issued-token");

  const explicit = resolveServicenowConfiguration({ instance: "acme", auth_method: "oauth2", client_id: "id", client_secret: "secret", username: "svc", password: "pw" }, {}, { cwd: createTempBase("servicenow-empty-"), homeDir: createTempBase("servicenow-home-") });
  assert.equal(explicit.authMode, "oauth");
});

test("resolveServicenowConfiguration rejects missing credentials, missing config files, and mTLS", () => {
  const scratch = { cwd: createTempBase("servicenow-empty-"), homeDir: createTempBase("servicenow-home-") };
  assert.throws(() => resolveServicenowConfiguration({ instance: "acme" }, {}, scratch), /credentials are required/);
  assert.throws(() => resolveServicenowConfiguration({}, { SERVICENOW_USERNAME: "u", SERVICENOW_PASSWORD: "p" }, scratch), /SERVICENOW_URL or SERVICENOW_INSTANCE/);
  assert.throws(() => resolveServicenowConfiguration({ instance: "acme", config_file: join(scratch.cwd, "missing.yaml") }, {}, scratch), (error) => {
    assert.equal(error.message, `Unable to read ServiceNow config file ${join(scratch.cwd, "missing.yaml")} (ENOENT)`);
    assert.equal(error.code, "ENOENT");
    return true;
  });
  assert.throws(() => resolveServicenowConfiguration({ instance: "acme", auth_method: "mtls" }, {}, scratch), /mutual TLS/);
  assert.throws(() => resolveServicenowConfiguration({ instance: "acme", auth_method: "basic", username: "u" }, {}, scratch), /basic auth requires/);
});

test("addendum 6b: the YAML config loader reports read and parse failures with fixed text and never quotes the file, the yaml package, or the fs error", async () => {
  const scratch = { cwd: createTempBase("servicenow-loader-cwd-"), homeDir: createTempBase("servicenow-loader-home-") };
  const cases = configLoaderCases({ format: "yaml", displayName: "ServiceNow", fileNoun: "config file", extension: ".yaml" });
  assert.deepEqual(cases.map((item) => item.name), ["yaml nested mapping", "yaml unresolved alias", "EISDIR", "EACCES", "ENOENT on an explicit path"]);
  const registered = [];
  registerServicenowTools({ registerTool: (tool) => registered.push(tool) });
  const checkAccess = registered.find((tool) => tool.name === "servicenow_check_access");
  await assertConfigLoaderMatrix(cases, {
    resolve: (path) => resolveServicenowConfiguration({ instance: "acme", config_file: path }, {}, scratch),
    checkAccess: (path) => checkAccess.execute("call-config", checkAccess.prepareArguments({ instance: "acme", config_file: path })),
  });
  // The same file at the default location is a parse failure too, not a silent skip.
  const defaultPath = join(scratch.cwd, ".servicenow.yaml");
  writeFileSync(defaultPath, "servicenow:\n  token: *QWJHXVZPKMTRYU1\n");
  assert.throws(() => resolveServicenowConfiguration({ instance: "acme" }, {}, scratch), (error) => {
    assert.equal(error.message, `Unable to parse ServiceNow config file: invalid YAML in ${defaultPath}`);
    assert.equal(error.code, "INVALID_YAML");
    return true;
  });
});

test("ServicenowApiClient shapes Table API queries with basic auth and follows Link pagination to completion", async () => {
  const fixture = healthyFixture();
  fixture.tables.sys_user = Array.from({ length: 5 }, (_, index) => user(`u-${index}`, `user${index}`));
  const { fetchImpl, calls } = fixtureFetch(fixture);
  const client = createClient(fetchImpl, { pageSize: 2 });

  const snapshot = await client.queryTable("sys_user", { query: "active=true", fields: ["sys_id", "user_name"], limit: 100 });

  assert.equal(snapshot.rows.length, 5);
  assert.equal(snapshot.total, 5);
  assert.equal(snapshot.pages, 3);
  assert.equal(snapshot.truncated, false);
  assert.equal(snapshot.partial, false);
  assert.equal(snapshot.error, undefined);
  assert.deepEqual(calls.map((call) => call.url.searchParams.get("sysparm_offset")), ["0", "2", "4"]);
  const first = calls[0].url;
  assert.equal(first.pathname, "/api/now/table/sys_user");
  assert.equal(first.searchParams.get("sysparm_query"), "active=true");
  assert.equal(first.searchParams.get("sysparm_fields"), "sys_id,user_name");
  assert.equal(first.searchParams.get("sysparm_limit"), "2");
  assert.equal(first.searchParams.get("sysparm_exclude_reference_link"), "true");
  const expectedAuth = `Basic ${Buffer.from(`audit.reader:${SAMPLE_PASSWORD}`).toString("base64")}`;
  for (const call of calls) {
    assert.equal(call.init.headers.get("authorization"), expectedAuth);
    assert.equal(call.init.headers.get("accept"), "application/json");
  }
});

test("ServicenowApiClient records truncation when the record limit stops pagination", async () => {
  const fixture = healthyFixture();
  fixture.tables.sys_user = Array.from({ length: 6 }, (_, index) => user(`u-${index}`, `user${index}`));
  const { fetchImpl, calls } = fixtureFetch(fixture);
  const client = createClient(fetchImpl, { pageSize: 2 });

  const snapshot = await client.queryTable("sys_user", { limit: 4 });

  assert.equal(snapshot.rows.length, 4);
  assert.equal(snapshot.total, 6);
  assert.equal(snapshot.truncated, true);
  assert.equal(snapshot.partial, true);
  assert.equal(calls.length, 2);
});

test("ServicenowApiClient flags ACL-hidden rows when X-Total-Count exceeds the returned rows", async () => {
  const { fetchImpl } = fixtureFetch(healthyFixture(), { inflateTotal: 7 });
  const snapshot = await createClient(fetchImpl).queryTable("sys_user_role");
  assert.equal(snapshot.rows.length, 2);
  assert.equal(snapshot.total, 9);
  assert.equal(snapshot.truncated, false);
  assert.equal(snapshot.partial, true);
});

test("ServicenowApiClient reads Aggregate API counts and captures count failures", async () => {
  const { fetchImpl, calls } = fixtureFetch(healthyFixture(), { forbiddenTables: ["sys_update_set"] });
  const client = createClient(fetchImpl);

  const audit = await client.countRecords("sys_audit", "sys_created_on>=javascript:gs.daysAgoStart(7)");
  assert.equal(audit.count, 1200);
  assert.equal(calls[0].url.pathname, "/api/now/stats/sys_audit");
  assert.equal(calls[0].url.searchParams.get("sysparm_count"), "true");
  assert.equal(calls[0].url.searchParams.get("sysparm_query"), "sys_created_on>=javascript:gs.daysAgoStart(7)");

  const denied = await client.countRecords("sys_update_set");
  assert.equal(denied.count, undefined);
  assert.equal(denied.statusCode, 403);
  assert.match(denied.error, /403/);
});

test("ServicenowApiClient exchanges OAuth client credentials at /oauth_token.do and sends a bearer token", async () => {
  const fixture = healthyFixture();
  const inner = fixtureFetch(fixture);
  const tokenCalls = [];
  const fetchImpl = async (input, init) => {
    const url = new URL(String(input));
    if (url.pathname === "/oauth_token.do") {
      tokenCalls.push({ url, init });
      return jsonResponse({ access_token: "oauth-access-token", expires_in: 1799, token_type: "Bearer" });
    }
    return inner.fetchImpl(input, init);
  };
  const client = createClient(fetchImpl, { authMode: "oauth", username: undefined, password: undefined, clientId: "client-id", clientSecret: "client-secret" });

  const snapshot = await client.queryTable("sys_user_role");
  assert.equal(snapshot.rows.length, 2);
  assert.equal(tokenCalls.length, 1);
  assert.equal(tokenCalls[0].init.method, "POST");
  const body = new URLSearchParams(tokenCalls[0].init.body);
  assert.equal(body.get("grant_type"), "client_credentials");
  assert.equal(body.get("client_id"), "client-id");
  assert.equal(body.get("client_secret"), "client-secret");
  assert.equal(inner.calls[0].init.headers.get("authorization"), "Bearer oauth-access-token");

  await client.queryTable("sys_user_role");
  assert.equal(tokenCalls.length, 1, "token is cached until it expires");
});

test("ServicenowApiClient uses the OAuth password grant when a user credential is present", async () => {
  const inner = fixtureFetch(healthyFixture());
  const tokenCalls = [];
  const fetchImpl = async (input, init) => {
    const url = new URL(String(input));
    if (url.pathname === "/oauth_token.do") {
      tokenCalls.push(new URLSearchParams(init.body));
      return jsonResponse({ access_token: "password-grant-token", expires_in: 1799, refresh_token: "refresh-me" });
    }
    return inner.fetchImpl(input, init);
  };
  const client = createClient(fetchImpl, { authMode: "oauth", clientId: "client-id", clientSecret: "client-secret" });

  await client.queryTable("sys_user_role");
  assert.equal(tokenCalls[0].get("grant_type"), "password");
  assert.equal(tokenCalls[0].get("username"), "audit.reader");
  assert.equal(tokenCalls[0].get("password"), SAMPLE_PASSWORD);
  assert.equal(inner.calls[0].init.headers.get("authorization"), "Bearer password-grant-token");
});

test("ServicenowApiClient retries 429 and 5xx responses with backoff and honors Retry-After", async () => {
  const inner = fixtureFetch(healthyFixture());
  const responses = [
    () => jsonResponse({ error: { message: "Rate limit" } }, { status: 429, headers: { "Retry-After": "2" } }),
    () => jsonResponse({ error: { message: "Service unavailable" } }, { status: 503 }),
  ];
  const fetchImpl = async (input, init) => {
    const next = responses.shift();
    return next ? next() : inner.fetchImpl(input, init);
  };
  const sleeps = [];
  const snapshot = await createClient(fetchImpl, {}, sleeps).queryTable("sys_user_role");

  assert.equal(snapshot.error, undefined);
  assert.equal(snapshot.rows.length, 2);
  assert.deepEqual(sleeps, [2000, 1000]);
});

test("ServicenowApiClient gives up after max retries and reports the failing status", async () => {
  let attempts = 0;
  const fetchImpl = async () => {
    attempts += 1;
    return jsonResponse({ error: { message: "Internal error" } }, { status: 500 });
  };
  const sleeps = [];
  const snapshot = await createClient(fetchImpl, { maxRetries: 2 }, sleeps).queryTable("sys_user");
  assert.equal(attempts, 3);
  assert.equal(sleeps.length, 2);
  assert.equal(snapshot.statusCode, 500);
  assert.equal(snapshot.rows.length, 0);
  assert.match(snapshot.error, /500/);
});

test("ServicenowApiClient redacts credentials from error messages", async () => {
  const fetchImpl = async () => jsonResponse({ error: { message: `Bad credential ${SAMPLE_PASSWORD} for audit.reader` } }, { status: 400 });
  const snapshot = await createClient(fetchImpl).queryTable("sys_user");
  assert.match(snapshot.error, /\[REDACTED\]/);
  assertFragmentsAbsent(assert, snapshot.error, [SAMPLE_PASSWORD], "error string from a body echoing the password");
  assert.equal(redactSecrets("token abc123def", ["abc123def", undefined, "ab"]), "token [REDACTED]");
});

test("parseLinkNext extracts only the rel=next link", () => {
  const header = '<https://dev.service-now.com/api/now/table/sys_user?sysparm_offset=0>;rel="first",<https://dev.service-now.com/api/now/table/sys_user?sysparm_offset=500>;rel="next",<https://dev.service-now.com/api/now/table/sys_user?sysparm_offset=1500>;rel="last"';
  assert.equal(parseLinkNext(header), "https://dev.service-now.com/api/now/table/sys_user?sysparm_offset=500");
  assert.equal(parseLinkNext('<https://dev.service-now.com/x?sysparm_offset=0>;rel="first"'), undefined);
  assert.equal(parseLinkNext(null), undefined);
});

test("checkServicenowAccess reports a healthy instance with the authenticated identity", async () => {
  const { fetchImpl } = fixtureFetch(healthyFixture());
  const result = await checkServicenowAccess(createClient(fetchImpl));

  assert.equal(result.status, "healthy");
  assert.equal(result.identity, "audit.reader");
  assert.equal(result.authMode, "basic");
  assert.equal(result.surfaces.length, 27);
  assert.ok(result.surfaces.every((surface) => surface.status === "readable"));
  const audit = result.surfaces.find((surface) => surface.table === "sys_audit");
  assert.equal(audit.total, 1200);
  assert.match(result.recommendedNextStep, /servicenow_assess_identity_access/);
});

test("checkServicenowAccess reports forbidden and ACL-filtered tables as limited", async () => {
  const fixture = healthyFixture();
  fixture.tables.sys_audit = [];
  const { fetchImpl } = fixtureFetch(fixture, { forbiddenTables: ["sys_properties"] });
  const result = await checkServicenowAccess(createClient(fetchImpl));

  assert.equal(result.status, "limited");
  const properties = result.surfaces.find((surface) => surface.table === "sys_properties");
  assert.equal(properties.status, "forbidden");
  assert.match(properties.error, /403/);
  const audit = result.surfaces.find((surface) => surface.table === "sys_audit");
  assert.equal(audit.status, "acl_filtered");
  assert.equal(audit.visible, 0);
  assert.equal(audit.total, 1200);
  assert.ok(result.notes.some((note) => note.includes("Degraded")));
  assert.match(result.recommendedNextStep, /scoped read role/);
});

test("assessServicenowIdentityAccess passes a healthy identity fixture with framework mappings", async () => {
  const { fetchImpl } = fixtureFetch(healthyFixture());
  const result = await assessServicenowIdentityAccess(createClient(fetchImpl));
  const byId = findingsById(result);

  assert.equal(result.area, "identity_access");
  assert.deepEqual([...byId.keys()].sort(), ["SNOW-03", "SNOW-04", "SNOW-06", "SNOW-07", "SNOW-08", "SNOW-14"]);
  for (const id of byId.keys()) {
    assert.equal(byId.get(id).status, "pass", `${id}: ${byId.get(id).summary}`);
    assert.equal(byId.get(id).mappings.length, 8);
  }
  assert.deepEqual(byId.get("SNOW-07").mappings, mappingsForControl(7));
  assert.ok(byId.get("SNOW-07").mappings.includes("FedRAMP IA-2(1)"));
  assert.ok(byId.get("SNOW-07").mappings.includes("PCI-DSS 8.4.2"));
  assert.deepEqual(result.errors, []);
  assert.equal(result.summary.admin_users, 1);
});

test("assessServicenowIdentityAccess fails weak identity controls and buckets users without login dates", async () => {
  const { fetchImpl } = fixtureFetch(failingFixture());
  const result = await assessServicenowIdentityAccess(createClient(fetchImpl));
  const byId = findingsById(result);

  assert.equal(byId.get("SNOW-03").status, "warn");
  assert.match(byId.get("SNOW-03").summary, /inheritance/);
  assert.equal(byId.get("SNOW-04").status, "fail");
  assert.match(byId.get("SNOW-04").summary, /1 admins have not logged in/);
  assert.deepEqual(byId.get("SNOW-04").evidence.users_without_last_login, ["never.logged"]);
  assert.match(byId.get("SNOW-04").summary, /not counted as active/);
  assert.equal(byId.get("SNOW-06").status, "fail");
  assert.match(byId.get("SNOW-06").summary, /min 6/);
  assert.equal(byId.get("SNOW-07").status, "fail");
  assert.match(byId.get("SNOW-07").summary, /glide.authenticate.multifactor is false/);
  assert.equal(byId.get("SNOW-08").status, "fail");
  assert.equal(byId.get("SNOW-14").status, "fail");
  assert.match(byId.get("SNOW-14").summary, /svc.integration/);
});

test("assessServicenowIdentityAccess never counts users without a last login date as active (rule 4)", async () => {
  const fixture = healthyFixture();
  fixture.tables.sys_user.push(user("u-ghost", "ghost.user", { last_login_time: "" }));
  const { fetchImpl } = fixtureFetch(fixture);
  const result = await assessServicenowIdentityAccess(createClient(fetchImpl));
  const review = findingsById(result).get("SNOW-04");

  assert.equal(review.status, "warn");
  assert.deepEqual(review.evidence.users_without_last_login, ["ghost.user"]);
  assert.equal(review.evidence.inactive_user_count, 0);
});

test("assessServicenowIdentityAccess treats an absent MFA property as disabled, not as compliant (rule 6)", async () => {
  const fixture = healthyFixture();
  fixture.tables.sys_properties = fixture.tables.sys_properties.filter((row) => row.name !== "glide.authenticate.multifactor");
  const { fetchImpl } = fixtureFetch(fixture);
  const mfa = findingsById(await assessServicenowIdentityAccess(createClient(fetchImpl))).get("SNOW-07");

  assert.equal(mfa.status, "fail");
  assert.match(mfa.summary, /no sys_properties row; the documented default is false/);
});

test("SNOW-07 reads multi_factor_criteria and passes only when the role-based record is active and covers admin roles", async () => {
  const { fetchImpl, calls } = fixtureFetch(healthyFixture());
  const mfa = findingsById(await assessServicenowIdentityAccess(createClient(fetchImpl))).get("SNOW-07");

  assert.equal(mfa.status, "pass", mfa.summary);
  assert.match(mfa.summary, /Role-based multi-factor authentication criteria record is active and covers admin and security_admin/);
  assert.equal(mfa.evidence.role_based_criteria_active, true);
  assert.deepEqual(mfa.evidence.elevated_roles_covered_by_criteria, ["admin", "security_admin"]);
  assert.equal(mfa.manualEvidence, undefined);
  const criteriaCall = calls.find((call) => call.url.pathname === "/api/now/table/multi_factor_criteria");
  assert.ok(criteriaCall, "the enforcement criteria table is read");
  assert.equal(criteriaCall.url.searchParams.get("sysparm_display_value"), "true");
});

test("SNOW-07 fails when the role-based criteria record is inactive and admins lack the per-user flag", async () => {
  const fixture = healthyFixture();
  fixture.tables.multi_factor_criteria = fixture.tables.multi_factor_criteria.map((row) => (/Role-based/.test(row.name) ? { ...row, active: "false" } : row));
  fixture.tables.sys_user = fixture.tables.sys_user.map((row) => (row.user_name === "alice.admin" ? { ...row, enable_multifactor_authn: "false" } : row));
  const mfa = findingsById(await assessServicenowIdentityAccess(createClient(fixtureFetch(fixture).fetchImpl))).get("SNOW-07");

  assert.equal(mfa.status, "fail");
  assert.match(mfa.summary, /criteria record is inactive and 1\/1 admin users do not carry enable_multifactor_authn/);
});

test("SNOW-07 warns when the active role-based criteria omit admin roles or when only per-user flags enforce MFA", async () => {
  const partialRoles = healthyFixture();
  partialRoles.tables.multi_factor_criteria = partialRoles.tables.multi_factor_criteria.map((row) => (/Role-based/.test(row.name) ? { ...row, roles: "itil" } : row));
  partialRoles.tables.sys_user = partialRoles.tables.sys_user.map((row) => (row.user_name === "alice.admin" ? { ...row, enable_multifactor_authn: "false" } : row));
  const uncovered = findingsById(await assessServicenowIdentityAccess(createClient(fixtureFetch(partialRoles).fetchImpl))).get("SNOW-07");
  assert.equal(uncovered.status, "warn");
  assert.match(uncovered.summary, /Multi-factor Roles list \(itil\) does not include admin and security_admin/);

  const inactiveRoleBased = healthyFixture();
  inactiveRoleBased.tables.multi_factor_criteria = inactiveRoleBased.tables.multi_factor_criteria.map((row) => (/Role-based/.test(row.name) ? { ...row, active: "false" } : row));
  const perUserOnly = findingsById(await assessServicenowIdentityAccess(createClient(fixtureFetch(inactiveRoleBased).fetchImpl))).get("SNOW-07");
  assert.equal(perUserOnly.status, "warn");
  assert.match(perUserOnly.summary, /criteria record is inactive, so newly granted administrators are not enforced automatically/);

  const rolesNotExposed = healthyFixture();
  rolesNotExposed.tables.multi_factor_criteria = rolesNotExposed.tables.multi_factor_criteria.map((row) => (/Role-based/.test(row.name) ? { sys_id: row.sys_id, name: row.name, active: row.active } : row));
  const flaggedAdmins = findingsById(await assessServicenowIdentityAccess(createClient(fixtureFetch(rolesNotExposed).fetchImpl))).get("SNOW-07");
  assert.equal(flaggedAdmins.status, "pass", "an active role-based record plus every admin carrying the per-user flag is enforcement");
  assert.match(flaggedAdmins.summary, /all 1 admin users also carry enable_multifactor_authn/);
});

test("SNOW-07 is manual, never pass, when multi_factor_criteria is forbidden or returns no rows (rules 1 and 2)", async () => {
  const forbidden = fixtureFetch(healthyFixture(), { forbiddenTables: ["multi_factor_criteria"] });
  const gatedResult = await assessServicenowIdentityAccess(createClient(forbidden.fetchImpl));
  const gated = findingsById(gatedResult).get("SNOW-07");
  assert.equal(gated.status, "manual");
  assert.match(gated.summary, /multi_factor_criteria read was forbidden \(403\)/);
  assert.equal(findingsById(gatedResult).get("SNOW-04").status, "pass", "the criteria read only gates the MFA finding");

  const empty = healthyFixture();
  empty.tables.multi_factor_criteria = [];
  const unreadable = findingsById(await assessServicenowIdentityAccess(createClient(fixtureFetch(empty).fetchImpl))).get("SNOW-07");
  assert.equal(unreadable.status, "manual");
  assert.match(unreadable.summary, /baseline Role-based multi-factor authentication record always exists/);
});

test("SNOW-07 warns on the documented email OTP property glide.authenticate.multifactor.email.otp.enabled", async () => {
  const fixture = healthyFixture();
  fixture.tables.sys_properties = fixture.tables.sys_properties.map((row) => (row.name === "glide.authenticate.multifactor.email.otp.enabled" ? { ...row, value: "true" } : row));
  const { fetchImpl, calls } = fixtureFetch(fixture);
  const mfa = findingsById(await assessServicenowIdentityAccess(createClient(fetchImpl))).get("SNOW-07");

  assert.equal(mfa.status, "warn");
  assert.match(mfa.summary, /email OTP is enabled as a factor/);
  assert.equal(mfa.evidence.email_otp_enabled, "true");
  const propertyCall = calls.find((call) => call.url.pathname === "/api/now/table/sys_properties");
  const requested = propertyCall.url.searchParams.get("sysparm_query").replace("nameIN", "").split(",");
  assert.ok(requested.includes("glide.authenticate.multifactor.email.otp.enabled"));
  assert.equal(requested.includes("glide.authenticate.multifactor.email.otp.enable"), false);
});

test("assessServicenowPlatformHardening passes a hardened fixture and keeps email security manual", async () => {
  const { fetchImpl } = fixtureFetch(healthyFixture());
  const result = await assessServicenowPlatformHardening(createClient(fetchImpl));
  const byId = findingsById(result);

  assert.deepEqual([...byId.keys()].sort(), ["SNOW-01", "SNOW-05", "SNOW-12", "SNOW-13", "SNOW-16", "SNOW-17", "SNOW-18"]);
  for (const id of ["SNOW-01", "SNOW-05", "SNOW-12", "SNOW-13", "SNOW-16", "SNOW-17"]) {
    assert.equal(byId.get(id).status, "pass", `${id}: ${byId.get(id).summary}`);
  }
  assert.equal(byId.get("SNOW-18").status, "manual");
  assert.match(byId.get("SNOW-18").summary, /DKIM/);
  assert.match(byId.get("SNOW-18").manualEvidence, /Email Accounts/);
  assert.deepEqual(result.errors, []);
});

test("assessServicenowPlatformHardening fails weak properties, eval usage, debug flags, and missing IP rules", async () => {
  const { fetchImpl } = fixtureFetch(failingFixture());
  const byId = findingsById(await assessServicenowPlatformHardening(createClient(fetchImpl)));

  assert.equal(byId.get("SNOW-01").status, "fail");
  assert.match(byId.get("SNOW-01").summary, /glide.security.use_csrf_token is false/);
  assert.equal(byId.get("SNOW-05").status, "fail");
  assert.match(byId.get("SNOW-05").summary, /120/);
  assert.equal(byId.get("SNOW-12").status, "fail");
  assert.match(byId.get("SNOW-12").summary, /eval\(\)/);
  assert.equal(byId.get("SNOW-13").status, "fail");
  assert.equal(byId.get("SNOW-16").status, "fail");
  assert.match(byId.get("SNOW-16").summary, /glide.debug.ui/);
  assert.equal(byId.get("SNOW-17").status, "fail");
  assert.equal(byId.get("SNOW-18").status, "fail");
  assert.match(byId.get("SNOW-18").summary, /Connection Security = None \(Outbound SMTP\)/);
});

test("SNOW-18 reads the documented Connection Security field with display values and grades None, STARTTLS, and SSL/TLS", async () => {
  const healthy = fixtureFetch(healthyFixture());
  const secure = findingsById(await assessServicenowPlatformHardening(createClient(healthy.fetchImpl))).get("SNOW-18");
  assert.equal(secure.status, "manual");
  assert.match(secure.summary, /All 1 active SMTP accounts use Connection Security = SSL\/TLS/);
  assert.deepEqual(secure.evidence.smtp_accounts_ssl_tls, ["Outbound SMTP"]);
  const emailCall = healthy.calls.find((call) => call.url.pathname === "/api/now/table/sys_email_account");
  assert.ok(emailCall.url.searchParams.get("sysparm_fields").split(",").includes("connection_security"));
  assert.equal(emailCall.url.searchParams.get("sysparm_fields").includes("enable_tls,server"), false, "the undocumented flag is no longer the primary field");
  assert.equal(emailCall.url.searchParams.get("sysparm_display_value"), "true");

  const starttls = healthyFixture();
  starttls.tables.sys_email_account = [{ sys_id: "email-1", name: "Outbound SMTP", type: "SMTP", active: "true", connection_security: "STARTTLS", server: "smtp.example.com", port: "587" }];
  const opportunistic = findingsById(await assessServicenowPlatformHardening(createClient(fixtureFetch(starttls).fetchImpl))).get("SNOW-18");
  assert.equal(opportunistic.status, "warn");
  assert.match(opportunistic.summary, /use STARTTLS \(Outbound SMTP\); ServiceNow warns/);

  const legacy = healthyFixture();
  legacy.tables.sys_email_account = [{ sys_id: "email-1", name: "Legacy SMTP", type: "SMTP", active: "true", enable_ssl: "true", enable_tls: "false", server: "smtp.example.com", port: "465" }];
  const legacyFinding = findingsById(await assessServicenowPlatformHardening(createClient(fixtureFetch(legacy).fetchImpl))).get("SNOW-18");
  assert.equal(legacyFinding.status, "manual");
  assert.deepEqual(legacyFinding.evidence.smtp_connection_security, [{ name: "Legacy SMTP", connection_security: "enable_ssl=true", level: "ssl_tls", source: "legacy_flags" }]);
});

test("SNOW-18 treats an absent Connection Security value as unverifiable rather than as a failure (rule 6)", async () => {
  const fixture = healthyFixture();
  fixture.tables.sys_email_account = [{ sys_id: "email-1", name: "Outbound SMTP", type: "SMTP", active: "true", server: "smtp.example.com", port: "587" }];
  const email = findingsById(await assessServicenowPlatformHardening(createClient(fixtureFetch(fixture).fetchImpl))).get("SNOW-18");

  assert.equal(email.status, "manual");
  assert.match(email.summary, /Connection Security could not be read for 1\/1 active SMTP accounts \(Outbound SMTP\)/);
  assert.match(email.summary, /neither assumed secure nor insecure/);
  assert.deepEqual(email.evidence.smtp_accounts_unverified, ["Outbound SMTP"]);
  assert.deepEqual(email.evidence.smtp_accounts_none, []);
});

test("assessServicenowPlatformHardening warns instead of assuming defaults for absent properties (rule 6)", async () => {
  const fixture = healthyFixture();
  fixture.tables.sys_properties = fixture.tables.sys_properties.filter((row) => !["glide.ui.session_timeout", "glide.security.diag_txns_acl"].includes(row.name));
  const { fetchImpl } = fixtureFetch(fixture);
  const byId = findingsById(await assessServicenowPlatformHardening(createClient(fetchImpl)));

  assert.equal(byId.get("SNOW-05").status, "warn");
  assert.match(byId.get("SNOW-05").summary, /not assumed/);
  assert.equal(byId.get("SNOW-01").status, "warn");
  assert.match(byId.get("SNOW-01").summary, /glide.security.diag_txns_acl/);
});

test("SNOW-17 reads the documented ip_access table and the com.snc.ipauthenticator plugin row", async () => {
  const { fetchImpl, calls } = fixtureFetch(healthyFixture());
  const ipAccess = findingsById(await assessServicenowPlatformHardening(createClient(fetchImpl))).get("SNOW-17");

  assert.equal(ipAccess.status, "pass", ipAccess.summary);
  assert.match(ipAccess.summary, /com.snc.ipauthenticator is active, 1 active ip_access rules/);
  assert.equal(ipAccess.evidence.ip_authenticator_plugin_active, true);
  assert.deepEqual(ipAccess.evidence.active_rules, ["allow inbound 10.0.0.0-10.0.255.255"]);
  const tables = calls.map((call) => call.url.pathname.replace("/api/now/table/", ""));
  assert.ok(tables.includes("ip_access"));
  assert.equal(tables.includes("sys_ip_address_access"), false);
  const pluginCall = calls.find((call) => call.url.pathname === "/api/now/table/sys_plugins");
  assert.equal(pluginCall.url.searchParams.get("sysparm_query"), "source=com.snc.ipauthenticator");
});

test("SNOW-17 fails when the IP authenticator plugin is inactive or absent, even when the table is missing", async () => {
  const inactive = healthyFixture();
  inactive.tables.sys_plugins = inactive.tables.sys_plugins.map((row) => (row.source === "com.snc.ipauthenticator" ? { ...row, active: "inactive" } : row));
  const inactiveFinding = findingsById(await assessServicenowPlatformHardening(createClient(fixtureFetch(inactive).fetchImpl))).get("SNOW-17");
  assert.equal(inactiveFinding.status, "fail");
  assert.match(inactiveFinding.summary, /com.snc.ipauthenticator\) is inactive in sys_plugins/);

  const notInstalled = healthyFixture();
  notInstalled.tables.sys_plugins = notInstalled.tables.sys_plugins.filter((row) => row.source !== "com.snc.ipauthenticator");
  delete notInstalled.tables.ip_access;
  const result = await assessServicenowPlatformHardening(createClient(fixtureFetch(notInstalled).fetchImpl));
  const missing = findingsById(result).get("SNOW-17");
  assert.equal(missing.status, "fail", missing.summary);
  assert.match(missing.summary, /has no row in sys_plugins and the ip_access table does not exist/);
  assert.equal(missing.evidence.ip_access_table_available, false);
  assert.equal(result.errors.some((issue) => /ip_access read failed/.test(issue)), false, "a missing plugin table is a documented state, not a collection error");
});

test("SNOW-17 stays manual when the plugin inventory is forbidden and warns when only the rules are visible", async () => {
  const forbidden = fixtureFetch(healthyFixture(), { forbiddenTables: ["sys_plugins"] });
  const gated = findingsById(await assessServicenowPlatformHardening(createClient(forbidden.fetchImpl))).get("SNOW-17");
  assert.equal(gated.status, "manual");
  assert.match(gated.summary, /sys_plugins read was forbidden \(403\)/);

  const filtered = healthyFixture();
  filtered.tables.sys_plugins = filtered.tables.sys_plugins.filter((row) => row.source !== "com.snc.ipauthenticator");
  const partial = findingsById(await assessServicenowPlatformHardening(createClient(fixtureFetch(filtered).fetchImpl))).get("SNOW-17");
  assert.equal(partial.status, "warn");
  assert.match(partial.summary, /plugin activation could not be confirmed/);
});

test("assessServicenowAccessControl passes complete role-protected ACL coverage", async () => {
  const { fetchImpl } = fixtureFetch(healthyFixture());
  const result = await assessServicenowAccessControl(createClient(fetchImpl));
  const byId = findingsById(result);

  assert.deepEqual([...byId.keys()].sort(), ["SNOW-02", "SNOW-11"]);
  assert.equal(byId.get("SNOW-02").status, "pass", byId.get("SNOW-02").summary);
  assert.equal(byId.get("SNOW-11").status, "pass", byId.get("SNOW-11").summary);
  assert.equal(result.summary.record_acl_total, 24);
  assert.deepEqual(result.errors, []);
});

test("buildSensitiveAclQuery ANDs the name filter with active=true^type=record through ^NQ groups", async () => {
  const base = "active=true^type=record";
  const names = ["*", "sys_user", "sys_user_has_role", "sys_user_role", "sys_properties", "sys_script", "sys_security_acl", "syslog", "sys_audit"];
  const expected = [
    `${base}^nameIN${names.join(",")}`,
    ...names.map((name) => `${base}^nameSTARTSWITH${name}.`),
  ].join("^NQ");
  assert.equal(buildSensitiveAclQuery(), expected);
  assert.equal(buildSensitiveAclQuery().includes("^OR"), false, "^OR binds to the adjacent condition only and must not be used for the name group");
  for (const group of buildSensitiveAclQuery().split("^NQ")) {
    assert.ok(group.startsWith(`${base}^name`), `every group repeats the active and type conditions: ${group}`);
  }

  const fixture = healthyFixture();
  fixture.tables.sys_security_acl.push(
    { sys_id: "acl-incident-read", name: "incident", operation: "read", type: "record", active: "true", admin_overrides: "true", condition: "", script: "", advanced: "false", description: "" },
    { sys_id: "acl-ui-sys_user", name: "sys_user", operation: "read", type: "ui_page", active: "true", admin_overrides: "true", condition: "", script: "", advanced: "false", description: "" },
    { sys_id: "acl-inactive-sys_user", name: "sys_user", operation: "read", type: "record", active: "false", admin_overrides: "true", condition: "", script: "", advanced: "false", description: "" },
    { sys_id: "acl-sys_user-field", name: "sys_user.password", operation: "read", type: "record", active: "true", admin_overrides: "true", condition: "", script: "", advanced: "false", description: "" },
  );
  fixture.tables.sys_security_acl_role.push({ sys_id: "aclrole-field", sys_security_acl: "acl-sys_user-field", "sys_security_acl.name": "sys_user.password", sys_user_role: "role-admin", "sys_user_role.name": "admin" });
  const { fetchImpl, calls } = fixtureFetch(fixture);
  const result = await assessServicenowAccessControl(createClient(fetchImpl));
  const aclCall = calls.find((call) => call.url.pathname === "/api/now/table/sys_security_acl");
  assert.equal(aclCall.url.searchParams.get("sysparm_query"), expected);
  assert.equal(result.summary.sensitive_acls_visible, 25, "only active record ACLs on sensitive or wildcard tables (including field-level rules) are fetched");
  assert.equal(findingsById(result).get("SNOW-11").status, "pass");
});

test("assessServicenowAccessControl fails unrestricted ACLs and uncovered sensitive tables", async () => {
  const { fetchImpl } = fixtureFetch(failingFixture());
  const byId = findingsById(await assessServicenowAccessControl(createClient(fetchImpl)));

  assert.equal(byId.get("SNOW-02").status, "fail");
  assert.match(byId.get("SNOW-02").summary, /sys_user:read/);
  assert.equal(byId.get("SNOW-11").status, "fail");
  assert.match(byId.get("SNOW-11").summary, /syslog/);
});

test("assessServicenowOperationsGovernance keeps API-unverifiable controls manual and passes clean update sets", async () => {
  const { fetchImpl } = fixtureFetch(healthyFixture());
  const result = await assessServicenowOperationsGovernance(createClient(fetchImpl));
  const byId = findingsById(result);

  assert.deepEqual([...byId.keys()].sort(), ["SNOW-09", "SNOW-10", "SNOW-15", "SNOW-19", "SNOW-20"]);
  assert.equal(byId.get("SNOW-09").status, "manual");
  assert.match(byId.get("SNOW-09").summary, /column-level encryption is not in use/);
  assert.equal(byId.get("SNOW-10").status, "manual");
  assert.match(byId.get("SNOW-10").summary, /1200 rows/);
  assert.match(byId.get("SNOW-10").summary, /retention period is not exposed/);
  assert.equal(byId.get("SNOW-15").status, "pass", byId.get("SNOW-15").summary);
  assert.equal(byId.get("SNOW-19").status, "manual");
  assert.match(byId.get("SNOW-19").summary, /mutual authentication/);
  assert.equal(byId.get("SNOW-20").status, "manual");
  assert.match(byId.get("SNOW-20").summary, /3 baseline security plugins are active/);
  for (const item of result.findings) {
    if (item.status === "manual") assert.ok(item.manualEvidence, `${item.id} must state the manual evidence`);
  }
});

test("assessServicenowOperationsGovernance fails unaudited tables, unvalidated MID Servers, and inactive security plugins", async () => {
  const { fetchImpl } = fixtureFetch(failingFixture());
  const byId = findingsById(await assessServicenowOperationsGovernance(createClient(fetchImpl)));

  assert.equal(byId.get("SNOW-10").status, "fail");
  assert.match(byId.get("SNOW-10").summary, /sys_user/);
  assert.equal(byId.get("SNOW-15").status, "warn");
  assert.match(byId.get("SNOW-15").summary, /Security tweaks/);
  assert.equal(byId.get("SNOW-19").status, "fail");
  assert.match(byId.get("SNOW-19").summary, /not validated/);
  assert.equal(byId.get("SNOW-20").status, "fail");
  assert.match(byId.get("SNOW-20").summary, /High Security Settings/);
});

test("SNOW-09 inventories KMF cryptographic modules and treats a missing legacy context table as absent, not as an error", async () => {
  const withModules = healthyFixture();
  withModules.tables.sys_kmf_crypto_module = [{ sys_id: "kmf-1", name: "global.pii_module", module_name: "pii_module", state: "Published" }];
  delete withModules.tables.sys_encryption_context;
  const { fetchImpl, calls } = fixtureFetch(withModules);
  const result = await assessServicenowOperationsGovernance(createClient(fetchImpl));
  const encryption = findingsById(result).get("SNOW-09");

  assert.equal(encryption.status, "manual");
  assert.match(encryption.summary, /1 KMF cryptographic modules, 0 legacy encryption contexts, and 0 encrypted dictionary fields/);
  assert.deepEqual(encryption.evidence.crypto_modules, ["global.pii_module"]);
  assert.equal(encryption.evidence.legacy_context_table_available, false);
  assert.ok(calls.some((call) => call.url.pathname === "/api/now/table/sys_kmf_crypto_module"));
  assert.equal(result.errors.some((issue) => /sys_encryption_context read failed/.test(issue)), false);

  const none = findingsById(await assessServicenowOperationsGovernance(createClient(fixtureFetch(withModules, { forbiddenTables: ["sys_kmf_crypto_module"] }).fetchImpl))).get("SNOW-09");
  assert.equal(none.status, "manual");
  assert.match(none.summary, /sys_kmf_crypto_module read was forbidden \(403\)/);
});

test("SNOW-04 surfaces locked-out accounts and flags locked administrators", async () => {
  const fixture = healthyFixture();
  fixture.tables.sys_user = fixture.tables.sys_user.map((row) => (row.user_name === "bob.user" ? { ...row, locked_out: "true" } : row));
  const review = findingsById(await assessServicenowIdentityAccess(createClient(fixtureFetch(fixture).fetchImpl))).get("SNOW-04");

  assert.equal(review.status, "warn");
  assert.match(review.summary, /1 active accounts are locked out \(0 admins; review or deactivate them\)/);
  assert.deepEqual(review.evidence.locked_out_users, ["bob.user"]);
  assert.equal(review.evidence.locked_out_user_count, 1);
  assert.deepEqual(review.evidence.locked_out_admins, []);

  const lockedAdmin = healthyFixture();
  lockedAdmin.tables.sys_user = lockedAdmin.tables.sys_user.map((row) => (row.user_name === "alice.admin" ? { ...row, locked_out: "true" } : row));
  const adminReview = findingsById(await assessServicenowIdentityAccess(createClient(fixtureFetch(lockedAdmin).fetchImpl))).get("SNOW-04");
  assert.equal(adminReview.status, "warn");
  assert.deepEqual(adminReview.evidence.locked_out_admins, ["alice.admin"]);

  const clean = findingsById(await assessServicenowIdentityAccess(createClient(fixtureFetch(healthyFixture()).fetchImpl))).get("SNOW-04");
  assert.equal(clean.status, "pass");
  assert.match(clean.summary, /no active account is locked out/);
  assert.equal(clean.evidence.locked_out_user_count, 0);
});

test("assessServicenowOperationsGovernance fails audited tables that produce zero audit rows (rule 2)", async () => {
  const fixture = healthyFixture();
  fixture.counts.sys_audit = 0;
  const { fetchImpl } = fixtureFetch(fixture);
  const audit = findingsById(await assessServicenowOperationsGovernance(createClient(fetchImpl))).get("SNOW-10");
  assert.equal(audit.status, "fail");
  assert.match(audit.summary, /zero rows/);
});

test("self-check (a): every endpoint forbidden yields manual verdicts that name the cause (rule 1)", async () => {
  const { fetchImpl } = fixtureFetch(healthyFixture(), { forbidAll: true });
  const results = await runAllAssessments(createClient(fetchImpl));

  const findings = Object.values(results).flatMap((result) => result.findings);
  assert.equal(findings.length, 20);
  for (const [label, result] of Object.entries(results)) {
    assertNoPass(result, `forbidden/${label}`);
    assert.ok(result.errors.length > 0, `${label} should record collection issues`);
  }
  for (const item of findings) {
    assert.equal(item.status, "manual", `${item.id} should be manual when forbidden: ${item.summary}`);
    assert.match(item.summary, /forbidden \(403\)/);
    assert.ok(item.manualEvidence, `${item.id} must state the evidence to collect`);
  }
});

test("self-check (b): empty inventories never pass and each summary states fail or manual intent (rule 2)", async () => {
  const { fetchImpl } = fixtureFetch(emptyFixture());
  const results = await runAllAssessments(createClient(fetchImpl));

  const findings = Object.values(results).flatMap((result) => result.findings);
  assert.equal(findings.length, 20);
  for (const [label, result] of Object.entries(results)) {
    assertNoPass(result, `empty/${label}`);
  }
  const statusById = new Map(findings.map((item) => [item.id, item.status]));
  assert.equal(statusById.get("SNOW-03"), "manual");
  assert.equal(statusById.get("SNOW-04"), "manual");
  assert.equal(statusById.get("SNOW-06"), "fail");
  assert.equal(statusById.get("SNOW-07"), "fail");
  assert.equal(statusById.get("SNOW-08"), "fail");
  assert.equal(statusById.get("SNOW-14"), "manual");
  assert.equal(statusById.get("SNOW-02"), "manual");
  assert.equal(statusById.get("SNOW-11"), "manual");
  assert.equal(statusById.get("SNOW-17"), "fail");
  assert.equal(statusById.get("SNOW-16"), "manual");
  assert.equal(statusById.get("SNOW-15"), "manual");
  assert.equal(statusById.get("SNOW-19"), "manual");
  assert.equal(statusById.get("SNOW-20"), "manual");
  assert.match(findings.find((item) => item.id === "SNOW-19").summary, /Not applicable as observed/);
  assert.match(findings.find((item) => item.id === "SNOW-15").summary, /cannot be trusted/);
});

test("self-check (c): partial inventories with X-Total-Count above the returned rows never pass (rules 5 and 7)", async () => {
  const { fetchImpl } = fixtureFetch(healthyFixture(), { inflateTotal: 3 });
  const results = await runAllAssessments(createClient(fetchImpl));

  const findings = Object.values(results).flatMap((result) => result.findings);
  assert.equal(findings.length, 20);
  for (const [label, result] of Object.entries(results)) {
    assertNoPass(result, `partial/${label}`);
    assert.ok(result.errors.some((issue) => /ACL-filtered or hidden rows/.test(issue)), `${label} should report the partial view`);
  }
  const downgraded = findings.filter((item) => /Partial view:/.test(item.summary));
  assert.ok(downgraded.length >= 15, `expected most findings to carry the partial-view note, saw ${downgraded.length}`);
  const review = findings.find((item) => item.id === "SNOW-04");
  assert.equal(review.status, "warn");
  assert.match(review.summary, /returned 4 of 7 rows/);
});

test("self-check (c): zero rows without an X-Total-Count header never pass on an aggregate count alone (rule 5)", async () => {
  const { fetchImpl } = fixtureFetch(healthyFixture(), { omitTotalCount: true });
  const results = await runAllAssessments(createClient(fetchImpl));
  const findings = Object.values(results).flatMap((result) => result.findings);
  const byId = new Map(findings.map((item) => [item.id, item]));

  const roleHierarchy = byId.get("SNOW-03");
  assert.equal(roleHierarchy.status, "manual");
  assert.match(roleHierarchy.summary, /no rows and no X-Total-Count header/);
  assert.match(roleHierarchy.summary, /holds 2 rows in aggregate/);
  assert.equal(roleHierarchy.evidence.x_total_count_present, false);

  const updateSets = byId.get("SNOW-15");
  assert.equal(updateSets.status, "manual");
  assert.match(updateSets.summary, /no rows and no X-Total-Count header/);
  assert.match(updateSets.summary, /holds 1 rows in aggregate/);

  const debug = byId.get("SNOW-16");
  assert.notEqual(debug.status, "pass");
  assert.match(debug.summary, /returned 0 rows without an X-Total-Count header \(visibility unproven\)/);
  for (const item of findings) {
    if (/\(visibility unproven\)/.test(item.summary)) assert.notEqual(item.status, "pass", `${item.id} passed on an unproven empty read`);
  }

  const withHeader = await runAllAssessments(createClient(fixtureFetch(healthyFixture()).fetchImpl));
  const healthyById = new Map(Object.values(withHeader).flatMap((result) => result.findings).map((item) => [item.id, item.status]));
  assert.equal(healthyById.get("SNOW-03"), "pass");
  assert.equal(healthyById.get("SNOW-15"), "pass");
  assert.equal(healthyById.get("SNOW-16"), "pass");
});

test("self-check (c): a truncated first page with an unfollowed Link rel=next never passes (rule 7)", async () => {
  const fixture = healthyFixture();
  fixture.tables.sys_user = [...fixture.tables.sys_user, user("u-extra", "extra.user"), user("u-more", "more.user")];
  const { fetchImpl } = fixtureFetch(fixture);
  const result = await assessServicenowIdentityAccess(createClient(fetchImpl, { pageSize: 2 }), { recordLimit: 4 });
  const review = findingsById(result).get("SNOW-04");

  assert.equal(review.status, "warn");
  assert.match(review.summary, /truncated at 4 of 6 rows/);
  assert.ok(result.errors.some((issue) => /record limit reached/.test(issue)));
});

test("mappingsForControl and listServicenowControls cover all twenty controls across four areas", () => {
  const controls = listServicenowControls();
  assert.equal(controls.length, 20);
  assert.deepEqual(controls.map((item) => item.control).sort((left, right) => left - right), Array.from({ length: 20 }, (_, index) => index + 1));
  assert.deepEqual([...new Set(controls.map((item) => item.area))].sort(), ["access_control", "identity_access", "operations_governance", "platform_hardening"]);
  for (const item of controls) {
    const mappings = mappingsForControl(item.control);
    assert.equal(mappings.length, 8, `${item.id} should map to eight frameworks`);
    assert.ok(mappings.some((mapping) => mapping.startsWith("FedRAMP ")));
    assert.ok(mappings.some((mapping) => mapping.startsWith("ISMAP ")));
  }
  assert.deepEqual(mappingsForControl(99), []);
});

test("exportServicenowAuditBundle writes core data, analysis, compliance reports, and a paired zip", async () => {
  const base = createTempBase("servicenow-bundle-");
  const { fetchImpl } = fixtureFetch(healthyFixture());
  const config = sampleConfig();
  const result = await exportServicenowAuditBundle(createClient(fetchImpl), config, base);

  assert.equal(basename(result.outputDir), "dev12345-audit-bundle");
  assert.equal(result.zipPath, join(base, "dev12345-audit-bundle.zip"));
  assert.ok(existsSync(result.zipPath));
  assert.equal(result.findingCount, 20);
  assert.equal(result.errorCount, 0);
  assert.equal(existsSync(join(result.outputDir, "_errors.log")), false);
  for (const relativePath of [
    "core_data/access_check.json",
    "core_data/sys_user.json",
    "core_data/sys_properties_hardening.json",
    "core_data/sys_security_acl.json",
    "core_data/sys_audit_count.json",
    "core_data/sys_plugins.json",
    "core_data/ip_access.json",
    "core_data/sys_plugins_ip_authenticator.json",
    "core_data/multi_factor_criteria.json",
    "core_data/sys_kmf_crypto_module.json",
    "analysis/findings.json",
    "analysis/summary.json",
    "analysis/identity_access.json",
    "analysis/platform_hardening.json",
    "analysis/access_control.json",
    "analysis/operations_governance.json",
    "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md",
    "compliance/fedramp/fedramp_compliance_report.md",
    "compliance/cmmc/cmmc_compliance_report.md",
    "compliance/soc2/soc2_compliance_report.md",
    "compliance/cis/cis_compliance_report.md",
    "compliance/pci_dss/pci_dss_compliance_report.md",
    "compliance/disa_stig/stig_compliance_checklist.md",
    "compliance/irap/irap_compliance_report.md",
    "compliance/ismap/ismap_compliance_report.md",
    "QUICK_REFERENCE.md",
    "metadata.json",
  ]) {
    assert.ok(existsSync(join(result.outputDir, relativePath)), `missing ${relativePath}`);
  }
  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis/findings.json"), "utf8"));
  assert.equal(findings.length, 20);
  assert.deepEqual([...new Set(findings.map((item) => item.id))].length, 20);
  const matrix = readFileSync(join(result.outputDir, "compliance/unified_compliance_matrix.md"), "utf8");
  assert.match(matrix, /SNOW-07/);
  assert.match(matrix, /IA-2\(1\)/);
  const metadata = JSON.parse(readFileSync(join(result.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.instance_url, config.instanceUrl);
  assert.equal(JSON.stringify(findings).includes(config.password), false);
});

test("exportServicenowAuditBundle never overwrites a prior bundle on rerun (rule 8)", async () => {
  const base = createTempBase("servicenow-bundle-rerun-");
  const config = sampleConfig();
  const first = await exportServicenowAuditBundle(createClient(fixtureFetch(healthyFixture()).fetchImpl), config, base);
  const second = await exportServicenowAuditBundle(createClient(fixtureFetch(healthyFixture()).fetchImpl), config, base);

  assert.notEqual(first.outputDir, second.outputDir);
  assert.notEqual(first.zipPath, second.zipPath);
  assert.equal(basename(second.outputDir), "dev12345-audit-bundle-2");
  assert.equal(basename(second.zipPath), "dev12345-audit-bundle-2.zip");
  assert.ok(existsSync(first.zipPath));
  assert.ok(existsSync(second.zipPath));
});

test("exportServicenowAuditBundle records partial collection failures in _errors.log", async () => {
  const base = createTempBase("servicenow-bundle-errors-");
  const { fetchImpl } = fixtureFetch(healthyFixture(), { forbiddenTables: ["sys_properties", "sys_audit"] });
  const result = await exportServicenowAuditBundle(createClient(fetchImpl), sampleConfig(), base);

  assert.ok(result.errorCount > 0);
  const errorLog = readFileSync(join(result.outputDir, "_errors.log"), "utf8");
  assert.match(errorLog, /sys_properties read was forbidden \(403\)/);
  assert.match(errorLog, /aggregate count failed/);
  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis/findings.json"), "utf8"));
  const hardening = findings.filter((item) => ["SNOW-01", "SNOW-05", "SNOW-13"].includes(item.id));
  assert.ok(hardening.every((item) => item.status === "manual"));
  const executive = readFileSync(join(result.outputDir, "compliance/executive_summary.md"), "utf8");
  assert.match(executive, /Manual Evidence To Collect/);
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("servicenow-secure-");
  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "/etc/passwd"), /Refusing to write outside/);

  const target = createTempBase("servicenow-secure-target-");
  const linkPath = join(base, "linked");
  symlinkSync(target, linkPath, "dir");
  assert.throws(() => resolveSecureOutputPath(base, "linked/bundle"), /symlinked parent/);

  const resolved = resolveSecureOutputPath(base, "nested/bundle.zip");
  assert.equal(resolved, join(base, "nested/bundle.zip"));
});

test("ServiceNow tools are registered in the tool catalog under the ServiceNow group", () => {
  const tools = getRegisteredToolSummaries().filter((tool) => tool.name.startsWith("servicenow_"));
  assert.deepEqual(tools.map((tool) => tool.name).sort(), [
    "servicenow_assess_access_control",
    "servicenow_assess_identity_access",
    "servicenow_assess_operations_governance",
    "servicenow_assess_platform_hardening",
    "servicenow_check_access",
    "servicenow_export_audit_bundle",
  ]);
  assert.ok(tools.every((tool) => tool.group === "ServiceNow"));
});

const FAKE_SECRETS = Object.values(FAKE_SNOW_SECRETS);

/**
 * The healthy fixture with a distinctive fake secret planted in every column
 * that can carry one on a real instance (password hashes, client secrets,
 * bind and mailbox passwords, keystore material, encryption keys, update XML
 * payloads, script bodies) plus extra columns on the two tables that used to
 * be read whole. The fake server ignores sysparm_fields, so only client-side
 * projection keeps these out of the bundle.
 */
function secretLadenFixture() {
  const fixture = healthyFixture();
  fixture.tables.sys_user = fixture.tables.sys_user.map((row) => ({ ...row, user_password: FAKE_SNOW_SECRETS.passwordHash, password_needs_reset: "false" }));
  fixture.tables.sys_user_has_role = fixture.tables.sys_user_has_role.map((row) => ({ ...row, "user.user_password": FAKE_SNOW_SECRETS.passwordHash }));
  fixture.tables.sys_properties = [
    ...fixture.tables.sys_properties.map((row) => ({ ...row, description: `Rotated with ${FAKE_SNOW_SECRETS.secretToken2} on ${row.sys_updated_on}` })),
    property("my.integration.api_token", FAKE_SNOW_SECRETS.secretToken2),
  ];
  fixture.tables.password_policy = fixture.tables.password_policy.map((row) => ({ ...row, description: `Seeded via ${FAKE_SNOW_SECRETS.secretToken1}`, lockout_message: `Call the helpdesk quoting ${FAKE_SNOW_SECRETS.secretToken1}` }));
  fixture.tables.multi_factor_criteria = fixture.tables.multi_factor_criteria.map((row) => ({ ...row, description: `Bootstrap secret ${FAKE_SNOW_SECRETS.secretToken1}`, condition: `gs.getProperty('mfa.seed') == '${FAKE_SNOW_SECRETS.secretToken1}'` }));
  fixture.tables.ldap_server_config = [{ sys_id: "ldap-1", name: "Corporate LDAP", active: "true", server_url: "ldaps://ldap.example.com", rdn: "cn=bind,dc=example,dc=com", password: FAKE_SNOW_SECRETS.secretToken1, sys_updated_on: "2026-01-01 00:00:00" }];
  fixture.tables.sys_certificate = fixture.tables.sys_certificate.map((row) => ({ ...row, key_store_password: FAKE_SNOW_SECRETS.secretToken1, pem_certificate: `-----BEGIN PRIVATE KEY-----\n${FAKE_SNOW_SECRETS.privateKey}\n-----END PRIVATE KEY-----` }));
  fixture.tables.oauth_entity = fixture.tables.oauth_entity.map((row) => ({ ...row, client_secret: FAKE_SNOW_SECRETS.secretToken1, redirect_url: `https://app.example.com/callback?state=${FAKE_SNOW_SECRETS.secretToken1}` }));
  fixture.tables.sys_email_account = fixture.tables.sys_email_account.map((row) => ({ ...row, user_name: "smtp-relay", password: FAKE_SNOW_SECRETS.secretToken1 }));
  fixture.tables.sys_encryption_context = [{ sys_id: "ctx-1", name: "PII context", type: "AES256", encryption_key: FAKE_SNOW_SECRETS.secretToken1, sys_updated_on: "2026-01-01 00:00:00" }];
  fixture.tables.sys_update_xml = [{
    sys_id: "ux-1",
    name: "sys_properties_abc",
    type: "System Property",
    target_name: "my.integration.api_token",
    action: "INSERT_OR_UPDATE",
    update_set: "us-open",
    "update_set.name": "Security tweaks",
    "update_set.state": "in progress",
    payload: `<record_update><sys_properties><value>${FAKE_SNOW_SECRETS.secretToken1}</value></sys_properties></record_update>`,
  }];
  fixture.tables.sys_script = [
    ...fixture.tables.sys_script,
    { sys_id: "br-2", name: "Dynamic eval", collection: "incident", active: "true", script: `eval(current.script); var key = '${FAKE_SNOW_SECRETS.scriptLiteral}';` },
  ];
  fixture.tables.sys_security_acl = fixture.tables.sys_security_acl.map((row) => (row.operation === "read"
    ? { ...row, condition: `gs.getProperty('acl.seed') == '${FAKE_SNOW_SECRETS.scriptLiteral}'`, script: `answer = current.token == '${FAKE_SNOW_SECRETS.scriptLiteral}';` }
    : row));
  fixture.tables.ecc_agent = fixture.tables.ecc_agent.map((row) => ({ ...row, mid_credential: FAKE_SNOW_SECRETS.secretToken1 }));
  return fixture;
}

test("ServicenowApiClient projects rows to the requested fields even when the server ignores sysparm_fields (rule 9)", async () => {
  const fixture = healthyFixture();
  fixture.tables.sys_user = fixture.tables.sys_user.map((row) => ({ ...row, user_password: FAKE_SNOW_SECRETS.passwordHash }));
  const { fetchImpl, calls } = fixtureFetch(fixture);

  const projected = await createClient(fetchImpl).queryTable("sys_user", { fields: ["sys_id", "user_name"] });
  assert.equal(projected.rows.length, 4);
  for (const row of projected.rows) assert.deepEqual(Object.keys(row).sort(), ["sys_id", "user_name"]);
  assert.equal(calls[0].url.searchParams.get("sysparm_fields"), "sys_id,user_name");
  assert.equal(JSON.stringify(projected).includes(FAKE_SNOW_SECRETS.passwordHash), false);

  const dotted = await createClient(fetchImpl).queryTable("sys_user_has_role", { fields: ["sys_id", "user.user_name", "role.name"] });
  assert.deepEqual(Object.keys(dotted.rows[0]).sort(), ["role.name", "sys_id", "user.user_name"], "dot-walked columns are kept under their dotted key");

  assert.deepEqual(projectRows([{ a: 1, b: 2 }], ["a"]), [{ a: 1 }]);
  assert.deepEqual(projectRows([{ a: 1, b: 2 }], undefined), [{ a: 1, b: 2 }], "no fields list means the caller asked for whole rows");
  assert.deepEqual(projectRows([{ a: 1 }], []), [{ a: 1 }]);
  assert.deepEqual(
    projectAclRow({ sys_id: "acl-1", name: "sys_user", operation: "read", condition: "gs.hasRole('admin')", script: "" }),
    { sys_id: "acl-1", name: "sys_user", operation: "read", has_condition: true, has_script: false },
  );
});

test("exportServicenowAuditBundle never writes planted secrets to any bundle file or zip entry (rule 9)", async () => {
  const base = createTempBase("servicenow-bundle-secrets-");
  const fixture = secretLadenFixture();
  const result = await exportServicenowAuditBundle(createClient(fixtureFetch(fixture).fetchImpl), sampleConfig(), base);

  const files = readBundleFiles(result.outputDir);
  assert.ok(files.size >= 40, `expected a full bundle, saw ${files.size} files`);
  assert.ok(files.has("core_data/sys_user.json"));
  assert.ok(files.has("core_data/sys_security_acl.json"));
  assert.ok(files.has("core_data/sys_update_xml_sensitive.json"));
  assert.ok(files.has("core_data/sys_encryption_context.json"));
  assert.ok(files.has("core_data/ldap_server_config.json"));
  assert.ok(files.has("core_data/access_check.json"));
  assertSecretFragmentsAbsent(assert, files, [...FAKE_SECRETS, sampleConfig().password], "bundle directory");
  const entries = readZipEntries(result.zipPath);
  assert.equal(entries.size, files.size, "the zip carries every bundle file");
  assertSecretFragmentsAbsent(assert, entries, [...FAKE_SECRETS, sampleConfig().password], "zip archive");

  const rows = (relativePath) => JSON.parse(files.get(relativePath)).rows;
  const users = rows("core_data/sys_user.json");
  assert.equal(users.length, 4);
  assert.ok(users.every((row) => !("user_password" in row) && !("password_needs_reset" in row) && typeof row.user_name === "string"));
  assert.ok(rows("core_data/sys_user_has_role_privileged.json").every((row) => !("user.user_password" in row) && row["role.name"] === "admin"));
  assert.ok(rows("core_data/sys_properties_identity.json").every((row) => !("description" in row) && row.name.startsWith("glide.")));
  const policies = rows("core_data/password_policy.json");
  assert.equal(policies.length, 1);
  assert.deepEqual(Object.keys(policies[0]).sort(), ["maximum_password_length", "minimum_password_length", "name", "require_digit", "require_lowercase", "require_special", "require_uppercase", "sys_id"]);
  const criteria = rows("core_data/multi_factor_criteria.json");
  assert.deepEqual(criteria.map((row) => Object.keys(row).sort()), [["active", "name", "roles", "sys_id"], ["active", "name", "sys_id"]]);
  assert.ok(rows("core_data/ldap_server_config.json").every((row) => !("password" in row) && !("rdn" in row) && !("server_url" in row) && row.name === "Corporate LDAP"));
  assert.ok(rows("core_data/sys_certificate.json").every((row) => !("key_store_password" in row) && !("pem_certificate" in row) && typeof row.expires === "string"));
  assert.ok(rows("core_data/oauth_entity.json").every((row) => !("client_secret" in row) && !("redirect_url" in row) && row.client_id === "abc123"));
  assert.ok(rows("core_data/sys_email_account.json").every((row) => !("password" in row) && !("user_name" in row) && row.connection_security === "SSL/TLS"));
  assert.ok(rows("core_data/sys_encryption_context.json").every((row) => !("encryption_key" in row) && row.name === "PII context"));
  const updateXml = rows("core_data/sys_update_xml_sensitive.json");
  assert.equal(updateXml.length, 1);
  assert.ok(!("payload" in updateXml[0]) && updateXml[0].target_name === "my.integration.api_token");
  const evalRules = rows("core_data/sys_script_eval.json");
  assert.equal(evalRules.length, 1);
  assert.deepEqual(Object.keys(evalRules[0]).sort(), ["collection", "name", "sys_id"]);
  const acls = rows("core_data/sys_security_acl.json");
  assert.ok(acls.length > 0);
  for (const acl of acls) {
    assert.ok(!("condition" in acl) && !("script" in acl), `${acl.sys_id} still carries code bodies`);
    assert.equal(acl.has_condition, acl.operation === "read");
    assert.equal(acl.has_script, acl.operation === "read");
  }
  assert.ok(rows("core_data/ecc_agent.json").every((row) => !("mid_credential" in row) && row.validated === "true"));
  const accessCheck = JSON.parse(files.get("core_data/access_check.json"));
  assert.equal(accessCheck.identity, "audit.reader", "the whoami row is projected to user_name and name");

  const findings = new Map(JSON.parse(files.get("analysis/findings.json")).map((item) => [item.id, item]));
  for (const id of ["SNOW-02", "SNOW-04", "SNOW-06", "SNOW-07", "SNOW-08", "SNOW-11", "SNOW-14"]) {
    assert.equal(findings.get(id).status, "pass", `${id} must still pass on the projected columns: ${findings.get(id).summary}`);
  }
  assert.match(findings.get("SNOW-06").summary, /all 1 password policies meet the threshold/);
  assert.match(findings.get("SNOW-07").summary, /covers admin and security_admin/);
  assert.match(findings.get("SNOW-08").summary, /1 active LDAP servers/);
  assert.equal(findings.get("SNOW-12").status, "fail", "the eval() rule is still detected without its script body");
  assert.match(findings.get("SNOW-12").summary, /Dynamic eval \(incident\)/);
});

test("ServicenowApiClient describes non-JSON error bodies by shape and logs only the pathname on timeout (rule 9)", async () => {
  const gatewayPage = `<html><body>502 upstream; request headers: authorization: Basic ${FAKE_SNOW_SECRETS.secretToken1}</body></html>`;
  const gatewayFetch = async () => new Response(gatewayPage, { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html" } });
  const snapshot = await createClient(gatewayFetch, { maxRetries: 0 }).queryTable("sys_user", { query: "active=true", fields: ["sys_id"] });
  assert.equal(snapshot.statusCode, 502);
  assert.match(snapshot.error, /502 Bad Gateway\) for \/api\/now\/table\/sys_user: non-JSON body \(text\/html, \d+ bytes\)$/);
  assertFragmentsAbsent(assert, snapshot.error, [FAKE_SNOW_SECRETS.secretToken1], "502 HTML error string");
  assert.equal(snapshot.error.includes("<html>"), false);

  const tokenFetch = async (input) => {
    assert.equal(new URL(String(input)).pathname, "/oauth_token.do");
    return new Response(gatewayPage, { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html" } });
  };
  const oauth = createClient(tokenFetch, { authMode: "oauth", username: undefined, password: undefined, clientId: "client-id", clientSecret: "client-secret" });
  const tokenFailure = await oauth.queryTable("sys_user", { fields: ["sys_id"] });
  assert.match(tokenFailure.error, /OAuth token request failed \(502 Bad Gateway\) for \/oauth_token\.do: non-JSON body \(text\/html, \d+ bytes\)$/);
  assertFragmentsAbsent(assert, tokenFailure.error, [FAKE_SNOW_SECRETS.secretToken1], "token endpoint 502 HTML error string");

  const hangingFetch = (input, init) => new Promise((_, reject) => {
    init.signal.addEventListener("abort", () => reject(new Error("aborted")));
  });
  const timedOut = await createClient(hangingFetch, { timeoutMs: 5 }).queryTable("sys_user", { query: "user_name=alice.admin", fields: ["sys_id"] });
  assert.match(timedOut.error, /timed out after 5ms: \/api\/now\/table\/sys_user$/);
  assert.equal(timedOut.error.includes("sysparm_query"), false);
  assert.equal(timedOut.error.includes("alice.admin"), false);
});

function overrideTablePage(inner, table, respond) {
  return async (input, init) => {
    const url = new URL(String(input));
    if (url.pathname === `/api/now/table/${table}`) {
      const response = respond(url);
      if (response) return response;
    }
    return inner.fetchImpl(input, init);
  };
}

test("ServicenowApiClient reports an empty page that still carries a Link rel=next as truncated with an unknown total (rule 10)", async () => {
  const fixture = healthyFixture();
  fixture.tables.sys_user = Array.from({ length: 6 }, (_, index) => user(`u-${index}`, `user${index}`));
  const inner = fixtureFetch(fixture, { omitTotalCount: true });
  const fetchImpl = overrideTablePage(inner, "sys_user", (url) => {
    if (url.searchParams.get("sysparm_offset") !== "2") return undefined;
    const next = new URL(url);
    next.searchParams.set("sysparm_offset", "4");
    return jsonResponse({ result: [] }, { headers: { Link: `<${next.toString()}>;rel="next"` } });
  });

  const snapshot = await createClient(fetchImpl, { pageSize: 2 }).queryTable("sys_user", { query: "active=true", fields: ["sys_id", "user_name", "last_login_time"], limit: 100 });
  assert.equal(snapshot.rows.length, 2);
  assert.equal(snapshot.pages, 2);
  assert.equal(snapshot.total, undefined);
  assert.equal(snapshot.truncated, true);
  assert.equal(snapshot.partial, true);
  assert.equal(snapshot.truncationReason, "empty page returned with a Link rel=next");

  const review = findingsById(await assessServicenowIdentityAccess(createClient(fetchImpl, { pageSize: 2 }))).get("SNOW-04");
  assert.equal(review.status, "warn");
  assert.match(review.summary, /sys_user was truncated at 2 of unknown rows \(empty page returned with a Link rel=next\)/);
  assert.equal(review.evidence.inputs[0].truncation_reason, "empty page returned with a Link rel=next");
});

test("ServicenowApiClient stops on a Link rel=next whose offset does not advance and reports truncation without duplicating rows (rule 10)", async () => {
  const fixture = healthyFixture();
  fixture.tables.sys_user = Array.from({ length: 6 }, (_, index) => user(`u-${index}`, `user${index}`));
  const inner = fixtureFetch(fixture);
  let userCalls = 0;
  const fetchImpl = overrideTablePage(inner, "sys_user", (url) => {
    userCalls += 1;
    return jsonResponse({ result: fixture.tables.sys_user.slice(0, 2) }, { headers: { "X-Total-Count": "6", Link: `<${url.toString()}>;rel="next"` } });
  });

  const snapshot = await createClient(fetchImpl, { pageSize: 2 }).queryTable("sys_user", { fields: ["sys_id", "user_name"], limit: 100 });
  assert.equal(userCalls, 1, "the stuck cursor is not re-read");
  assert.equal(snapshot.rows.length, 2);
  assert.equal(snapshot.total, 6);
  assert.equal(snapshot.truncated, true);
  assert.equal(snapshot.truncationReason, "Link rel=next offset did not advance");

  const result = await assessServicenowIdentityAccess(createClient(fetchImpl, { pageSize: 2 }));
  const review = findingsById(result).get("SNOW-04");
  assert.equal(review.status, "warn");
  assert.match(review.summary, /sys_user was truncated at 2 of 6 rows \(Link rel=next offset did not advance\)/);
  assert.equal(review.evidence.active_users, 2, "seen counts are not inflated by the repeated page");
  assert.ok(result.errors.some((issue) => /offset did not advance/.test(issue)));
});

test("ServicenowApiClient marks a non-empty read without X-Total-Count as total unknown so dependent findings cannot pass (rule 10)", async () => {
  const { fetchImpl } = fixtureFetch(healthyFixture(), { omitTotalCount: true });
  const snapshot = await createClient(fetchImpl).queryTable("sys_user", { query: "active=true", fields: ["sys_id", "user_name"] });
  assert.equal(snapshot.rows.length, 4);
  assert.equal(snapshot.total, undefined);
  assert.equal(snapshot.totalUnknown, true);
  assert.equal(snapshot.truncated, false);
  assert.equal(snapshot.partial, true);

  const results = await runAllAssessments(createClient(fetchImpl));
  for (const [label, result] of Object.entries(results)) {
    assertNoPass(result, `total-unknown/${label}`);
  }
  const review = findingsById(results.identity).get("SNOW-04");
  assert.equal(review.status, "warn");
  assert.match(review.summary, /sys_user returned 4 rows without an X-Total-Count header \(total unknown\)/);
  assert.equal(review.evidence.inputs[0].total_unknown, true);
  assert.ok(results.identity.errors.some((issue) => /\(total unknown\)/.test(issue)));

  const withHeader = findingsById(await assessServicenowIdentityAccess(createClient(fixtureFetch(healthyFixture()).fetchImpl))).get("SNOW-04");
  assert.equal(withHeader.status, "pass");
  assert.equal(withHeader.evidence.inputs[0].total_unknown, false);
});

/**
 * Every finding whose verdict reads two or more collected datasets, with the
 * dataset treated as primary and each secondary the test forbids in turn.
 * "count" secondaries are Aggregate API reads; "query" secondaries are a
 * second query against a table the finding also reads through another query.
 */
const MULTI_INVENTORY_FINDINGS = [
  { id: "SNOW-02", assess: assessServicenowAccessControl, primary: "sys_security_acl", secondaries: [{ table: "sys_security_acl_role" }, { table: "sys_public" }, { count: "sys_security_acl" }] },
  { id: "SNOW-03", assess: assessServicenowIdentityAccess, primary: "sys_user_role_contains", secondaries: [{ count: "sys_user_role_contains" }] },
  { id: "SNOW-04", assess: assessServicenowIdentityAccess, primary: "sys_user", secondaries: [{ table: "sys_user_has_role" }] },
  { id: "SNOW-06", assess: assessServicenowIdentityAccess, primary: "password_policy", secondaries: [{ table: "sys_properties" }] },
  { id: "SNOW-07", assess: assessServicenowIdentityAccess, primary: "sys_properties", secondaries: [{ table: "sys_user" }, { table: "sys_user_has_role" }, { table: "multi_factor_criteria" }] },
  { id: "SNOW-08", assess: assessServicenowIdentityAccess, primary: "sso_properties", secondaries: [{ table: "ldap_server_config" }, { table: "sys_properties" }, { table: "sys_certificate" }] },
  { id: "SNOW-09", assess: assessServicenowOperationsGovernance, primary: "sys_kmf_crypto_module", secondaries: [{ table: "sys_encryption_context" }, { table: "sys_dictionary" }], baseline: "manual" },
  { id: "SNOW-10", assess: assessServicenowOperationsGovernance, primary: "sys_dictionary", secondaries: [{ count: "sys_audit" }], baseline: "manual" },
  { id: "SNOW-11", assess: assessServicenowAccessControl, primary: "sys_security_acl", secondaries: [{ table: "sys_security_acl_role" }, { count: "sys_security_acl" }] },
  { id: "SNOW-12", assess: assessServicenowPlatformHardening, primary: "sys_properties", secondaries: [{ table: "sys_script" }] },
  { id: "SNOW-14", assess: assessServicenowIdentityAccess, primary: "sys_user", secondaries: [{ table: "sys_user_has_role" }, { table: "oauth_entity" }] },
  { id: "SNOW-15", assess: assessServicenowOperationsGovernance, primary: "sys_update_set", secondaries: [{ table: "sys_update_xml" }, { count: "sys_update_set" }] },
  { id: "SNOW-16", assess: assessServicenowPlatformHardening, primary: "sys_properties", secondaries: [{ query: { table: "sys_properties", queryIncludes: "nameLIKEdebug" } }, { query: { table: "sys_properties", queryIncludes: "glide.security.use_csrf_token" } }] },
  { id: "SNOW-17", assess: assessServicenowPlatformHardening, primary: "sys_properties", secondaries: [{ table: "ip_access" }, { table: "sys_plugins" }] },
  { id: "SNOW-18", assess: assessServicenowPlatformHardening, primary: "sys_email_account", secondaries: [{ table: "sys_properties" }], baseline: "manual" },
  { id: "SNOW-19", assess: assessServicenowOperationsGovernance, primary: "ecc_agent", secondaries: [{ table: "sys_properties" }], baseline: "manual" },
];

test("rule 1 corollary: every multi-inventory finding demotes and names the inventory when one secondary read is forbidden", async () => {
  let checked = 0;
  for (const definition of MULTI_INVENTORY_FINDINGS) {
    const baseline = findingsById(await definition.assess(createClient(fixtureFetch(healthyFixture()).fetchImpl))).get(definition.id);
    assert.equal(baseline.status, definition.baseline ?? "pass", `${definition.id} baseline: ${baseline.summary}`);

    for (const secondary of definition.secondaries) {
      const table = secondary.table ?? secondary.count ?? secondary.query.table;
      const options = secondary.table
        ? { forbiddenTables: [secondary.table] }
        : secondary.count
          ? { forbiddenCounts: [secondary.count] }
          : { forbiddenQueries: [secondary.query] };
      const label = `${definition.id} with ${secondary.count ? `count(${table})` : secondary.query ? `${table}[${secondary.query.queryIncludes}]` : table} forbidden`;
      const result = await definition.assess(createClient(fixtureFetch(healthyFixture(), options).fetchImpl));
      const item = findingsById(result).get(definition.id);

      assert.notEqual(item.status, "pass", `${label}: ${item.summary}`);
      assert.ok(["manual", "warn"].includes(item.status), `${label}: expected manual or warn, saw ${item.status}`);
      assert.ok(item.summary.includes(table), `${label}: summary must name the unreadable inventory: ${item.summary}`);
      assert.ok(item.manualEvidence, `${label}: must state the evidence a human collects`);
      assert.ok(result.errors.some((issue) => issue.includes(table) && /403|forbidden/i.test(issue)), `${label}: errors must disclose the forbidden read`);
      checked += 1;
    }
  }
  assert.equal(checked, 28, "every secondary inventory of every multi-inventory finding was exercised");
});

/** core_data files written from each Table API dataset, keyed by the table the request reads. */
const SERVICENOW_TABLE_FILES = {
  sys_user: ["core_data/sys_user.json"],
  sys_user_has_role: ["core_data/sys_user_has_role_privileged.json"],
  sys_user_role_contains: ["core_data/sys_user_role_contains.json"],
  sys_properties: ["core_data/sys_properties_identity.json", "core_data/sys_properties_hardening.json", "core_data/sys_properties_debug.json", "core_data/sys_properties_mid.json"],
  password_policy: ["core_data/password_policy.json"],
  sso_properties: ["core_data/sso_properties.json"],
  ldap_server_config: ["core_data/ldap_server_config.json"],
  sys_certificate: ["core_data/sys_certificate.json"],
  oauth_entity: ["core_data/oauth_entity.json"],
  multi_factor_criteria: ["core_data/multi_factor_criteria.json"],
  sys_script: ["core_data/sys_script_eval.json"],
  ip_access: ["core_data/ip_access.json"],
  sys_plugins: ["core_data/sys_plugins_ip_authenticator.json", "core_data/sys_plugins.json"],
  sys_email_account: ["core_data/sys_email_account.json"],
  sys_security_acl: ["core_data/sys_security_acl.json"],
  sys_security_acl_role: ["core_data/sys_security_acl_role.json"],
  sys_public: ["core_data/sys_public.json"],
  sys_encryption_context: ["core_data/sys_encryption_context.json"],
  sys_kmf_crypto_module: ["core_data/sys_kmf_crypto_module.json"],
  sys_dictionary: ["core_data/sys_dictionary_encrypted.json", "core_data/sys_dictionary_audit.json"],
  sys_update_set: ["core_data/sys_update_set_in_progress.json"],
  sys_update_xml: ["core_data/sys_update_xml_sensitive.json"],
  ecc_agent: ["core_data/ecc_agent.json"],
};

/** core_data files written from each Aggregate API count, keyed by table. */
const SERVICENOW_COUNT_FILES = {
  sys_user_role_contains: "core_data/sys_user_role_contains_count.json",
  sys_security_acl: "core_data/sys_security_acl_count.json",
  sys_audit: "core_data/sys_audit_count.json",
  syslog_transaction: "core_data/syslog_transaction_count.json",
  sys_update_set: "core_data/sys_update_set_count.json",
};

const SERVICENOW_AREAS = ["identity_access", "platform_hardening", "access_control", "operations_governance"];

function isAbsenceValue(value) {
  if (value === 0 || value === false) return true;
  if (Array.isArray(value)) return value.length === 0;
  if (value !== null && typeof value === "object") return Object.keys(value).length === 0;
  return false;
}

// Objects and arrays of objects are descended so that a per-input or per-table record contributes
// one leaf per field; arrays of scalars stay leaves.
function fieldLeaves(value, path, out) {
  if (Array.isArray(value) && value.length > 0 && value.every((item) => item !== null && typeof item === "object" && !Array.isArray(item))) {
    value.forEach((item, index) => fieldLeaves(item, `${path}.${index}`, out));
    return out;
  }
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    out.set(path, value);
    return out;
  }
  for (const [key, child] of Object.entries(value)) fieldLeaves(child, `${path}.${key}`, out);
  return out;
}

function assessmentLeaves(result) {
  const out = new Map();
  fieldLeaves(result.summary, `${result.area}.summary`, out);
  for (const item of result.findings) {
    out.set(`${item.id}.status`, item.status);
    out.set(`${item.id}.summary`, item.summary);
    fieldLeaves(item.evidence ?? {}, `${item.id}.evidence`, out);
  }
  return out;
}

const STATUS_COUNT_KEYS = new Set(["pass", "warn", "fail", "manual"]);

// Every leaf that carried a value in the all-readable baseline must, under a single denial, keep that
// value, render null, or (for prose) change text. It must never fall to 0, [], {}, or false. A leaf may
// disappear only when its finding was withheld whole because an input was unread.
function assertNoDefaultedLeaves(baseline, current, label) {
  for (const [path, base] of baseline) {
    const [owner] = path.split(".");
    if (STATUS_COUNT_KEYS.has(path.split(".").at(-1)) && path.includes(".summary.")) continue;
    if (!current.has(path)) {
      const withheld = current.get(`${owner}.status`) === "manual" && /^Verdict unknown:/.test(current.get(`${owner}.summary`) ?? "");
      assert.ok(withheld, `${label}: leaf ${path} disappeared although ${owner} was not withheld as unread`);
      continue;
    }
    const value = current.get(path);
    if (base === null || isAbsenceValue(base)) continue;
    if (typeof base === "string") continue;
    if (value === null) continue;
    assert.ok(!isAbsenceValue(value), `${label}: leaf ${path} defaulted from ${JSON.stringify(base)} to ${JSON.stringify(value)}`);
    assert.deepEqual(value, base, `${label}: leaf ${path} changed from ${JSON.stringify(base)} to ${JSON.stringify(value)} instead of rendering null`);
  }
}

function collectStrings(value, out = []) {
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) for (const item of value) collectStrings(item, out);
  else if (value && typeof value === "object") for (const item of Object.values(value)) collectStrings(item, out);
  return out;
}

function collectStatusFields(value, out = []) {
  if (Array.isArray(value)) for (const item of value) collectStatusFields(item, out);
  else if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      if (["status", "status_code", "http_status"].includes(key) && typeof child === "number") out.push(child);
      collectStatusFields(child, out);
    }
  }
  return out;
}

// Status codes appear in output as "(403 Forbidden)" or "forbidden (403)"; endpoints as Table API or
// Aggregate API paths; tables named as failed reads appear as "<table> read was forbidden" or "<table> read failed".
function mentionedStatusCodes(text) {
  return [...text.matchAll(/\((\d{3})(?: [A-Za-z]|\))/g)].map((match) => Number(match[1]));
}

function mentionedEndpoints(text) {
  return [...text.matchAll(/\/api\/now\/(?:table|stats)\/[A-Za-z0-9_]+/g)].map((match) => match[0]);
}

function mentionedFailedTables(text) {
  return [...text.matchAll(/\b([a-z][a-z0-9_]+) read (?:was forbidden|failed)\b/g)].map((match) => match[1]);
}

function assertMentionsMatchRequests(outputs, requests, label) {
  const loggedStatuses = new Set(requests.map((request) => request.status));
  const loggedPaths = new Set(requests.map((request) => request.path));
  for (const code of collectStatusFields(outputs)) {
    assert.ok(loggedStatuses.has(code), `${label}: a status field carries HTTP ${code} but no request returned it`);
  }
  for (const text of collectStrings(outputs)) {
    for (const code of mentionedStatusCodes(text)) {
      assert.ok(loggedStatuses.has(code), `${label}: output names HTTP ${code} but no request returned it: ${text}`);
    }
    for (const endpoint of mentionedEndpoints(text)) {
      assert.ok(loggedPaths.has(endpoint), `${label}: output names ${endpoint} but no request was made to it: ${text}`);
    }
    for (const table of mentionedFailedTables(text)) {
      assert.ok(loggedPaths.has(`/api/now/table/${table}`), `${label}: output names a failed read of ${table} but no request was made to it: ${text}`);
    }
  }
}

function fixtureUserNames(fixture) {
  return fixture.tables.sys_user.map((row) => row.user_name);
}

async function exportWithFixture(options = {}, fixture = healthyFixture()) {
  const base = createTempBase("servicenow-sweep-");
  const { fetchImpl, requests } = fixtureFetch(fixture, options);
  const client = createClient(fetchImpl);
  const result = await exportServicenowAuditBundle(client, sampleConfig(), base);
  const files = readBundleFiles(result.outputDir);
  const analysis = SERVICENOW_AREAS.map((area) => JSON.parse(files.get(`analysis/${area}.json`)));
  const accessCheck = JSON.parse(files.get("core_data/access_check.json"));
  const payloads = [await checkServicenowAccess(client), ...Object.values(await runAllAssessments(client))];
  return {
    result,
    files,
    analysis,
    accessCheck,
    payloads,
    requests,
    fixture,
    errors: files.get("_errors.log") ?? "",
    executive: files.get("compliance/executive_summary.md"),
  };
}

function assertTableMarker(marker, table, label) {
  assert.equal(marker.collected, false, `${label}: core_data carries the not-collected marker`);
  assert.equal(marker.table, table, label);
  assert.equal(marker.status, 403, `${label}: the marker status is the observed status`);
  assert.equal(marker.endpoint, `/api/now/table/${table}`, `${label}: the marker endpoint is the requested path`);
  assert.match(marker.error, /\(403 Forbidden\) for \/api\/now\/table\//, label);
  assert.ok(!("rows" in marker), `${label}: a denied dataset is never written as a row list`);
  assert.ok(!("truncated" in marker) && !("partial" in marker), `${label}: a denied dataset carries no collection flags`);
}

function assertCountMarker(marker, table, label) {
  assert.equal(marker.collected, false, `${label}: the count file carries the not-collected marker`);
  assert.equal(marker.status, 403, label);
  assert.equal(marker.endpoint, `/api/now/stats/${table}`, label);
  assert.match(marker.error, /\(403 Forbidden\) for \/api\/now\/stats\//, label);
  assert.ok(!("count" in marker), `${label}: a denied count never carries a count`);
}

test("collection status, request matching, and denied-list markers: each table and aggregate denied one at a time writes a marker, renders dependent counts null, names no principal from the denied set, and mentions only observed statuses, endpoints, and tables", async () => {
  const baseline = await exportWithFixture();
  assert.equal(baseline.result.errorCount, 0);
  assert.equal(baseline.accessCheck.status, "healthy");
  for (const item of baseline.analysis) {
    for (const [name, state] of Object.entries(item.summary.inventories)) {
      assert.match(state, /: complete \(/, `${item.area}.inventories.${name} must be complete in the baseline: ${state}`);
    }
  }
  for (const [table, files] of Object.entries(SERVICENOW_TABLE_FILES)) {
    for (const file of files) {
      const snapshot = JSON.parse(baseline.files.get(file));
      assert.notEqual(snapshot.collected, false, `${file} is collected in the baseline`);
      assert.equal(snapshot.table, table);
      assert.ok(Array.isArray(snapshot.rows), `${file} carries a row list in the baseline`);
    }
  }
  // ldap_server_config and sys_public are served readable but empty, so every run carries datasets that must stay [].
  assert.deepEqual(JSON.parse(baseline.files.get("core_data/ldap_server_config.json")).rows, []);
  assert.deepEqual(JSON.parse(baseline.files.get("core_data/sys_public.json")).rows, []);
  assertMentionsMatchRequests([baseline.analysis, baseline.accessCheck, baseline.payloads, baseline.executive], baseline.requests, "baseline");
  const baselineLeaves = new Map(baseline.analysis.flatMap((item) => [...assessmentLeaves(item)]));
  const userNames = fixtureUserNames(baseline.fixture);

  const tables = Object.keys(baseline.fixture.tables);
  const denials = [
    ...tables.map((table) => ({ label: `deny table ${table}`, table, options: { forbiddenTables: [table] }, tableDenied: true })),
    ...Object.keys(SERVICENOW_COUNT_FILES).map((table) => ({ label: `deny count ${table}`, table, options: { forbiddenCounts: [table] }, tableDenied: false })),
  ];
  for (const { label, table, options, tableDenied } of denials) {
    const run = await exportWithFixture(options);
    const deniedPaths = tableDenied ? [`/api/now/table/${table}`, `/api/now/stats/${table}`] : [`/api/now/stats/${table}`];
    const denied = run.requests.filter((request) => deniedPaths.includes(request.path));
    assert.ok(denied.length > 0 && denied.every((request) => request.status === 403), `${label}: the fixture served 403 for the denied requests`);

    if (tableDenied) {
      for (const file of SERVICENOW_TABLE_FILES[table] ?? []) assertTableMarker(JSON.parse(run.files.get(file)), table, `${label} (${file})`);
      if (SERVICENOW_COUNT_FILES[table]) assertCountMarker(JSON.parse(run.files.get(SERVICENOW_COUNT_FILES[table])), table, label);
    } else {
      assertCountMarker(JSON.parse(run.files.get(SERVICENOW_COUNT_FILES[table])), table, label);
      for (const file of SERVICENOW_TABLE_FILES[table] ?? []) {
        assert.ok(Array.isArray(JSON.parse(run.files.get(file)).rows), `${label}: the table read stays a row list when only the aggregate is denied`);
      }
    }
    for (const [otherTable, files] of Object.entries(SERVICENOW_TABLE_FILES)) {
      if (otherTable === table || (table === "sys_security_acl" && otherTable === "sys_security_acl_role")) continue;
      for (const file of files) {
        const snapshot = JSON.parse(run.files.get(file));
        assert.notEqual(snapshot.collected, false, `${label}: ${file} stays collected`);
        assert.ok(Array.isArray(snapshot.rows), `${label}: ${file} keeps its row list`);
      }
    }
    if (table !== "ldap_server_config") assert.deepEqual(JSON.parse(run.files.get("core_data/ldap_server_config.json")).rows, [], `${label}: a readable-but-empty dataset keeps []`);
    if (table !== "sys_public") assert.deepEqual(JSON.parse(run.files.get("core_data/sys_public.json")).rows, [], `${label}: a readable-but-empty dataset keeps []`);
    if (tableDenied && table === "sys_security_acl") {
      // No ACL ids were read, so no role lookup was issued: the marker says so and borrows no status code.
      const roles = JSON.parse(run.files.get("core_data/sys_security_acl_role.json"));
      assert.equal(roles.collected, false, label);
      assert.equal(roles.status, null, `${label}: a request that was never made has no status`);
      assert.equal(roles.endpoint, null, `${label}: a request that was never made has no endpoint`);
      assert.match(roles.error, /^not requested: the sys_security_acl read failed/);
      assert.ok(!("pages" in roles));
      const accessControl = run.analysis.find((item) => item.area === "access_control");
      assert.match(accessControl.summary.inventories.acl_roles, /^sys_security_acl_role read: not requested \(/);
      const roleInput = findingsById(accessControl).get("SNOW-02").evidence.inputs.find((input) => input.table === "sys_security_acl_role");
      assert.equal(roleInput.state, "not_requested");
      assert.equal(roleInput.status_code, null);
      assert.equal(roleInput.pages, null);
      assert.ok(run.errors.includes("sys_security_acl_role was not requested"), `${label}: _errors.log states that the lookup was not issued`);
    }

    const currentLeaves = new Map(run.analysis.flatMap((item) => [...assessmentLeaves(item)]));
    assertNoDefaultedLeaves(baselineLeaves, currentLeaves, label);
    const states = run.analysis.flatMap((item) => Object.values(item.summary.inventories));
    const unread = states.filter((state) => /: unread \(/.test(state));
    if (tableDenied && SERVICENOW_TABLE_FILES[table]) {
      assert.ok(unread.some((state) => state.startsWith(`${table} read: unread (`)), `${label}: an assessment summary names the unread table`);
    }
    if (!tableDenied || SERVICENOW_COUNT_FILES[table]) {
      assert.ok(unread.some((state) => state.startsWith(`${table} aggregate: unread (`)), `${label}: an assessment summary names the unread aggregate`);
    }
    for (const state of unread) assert.match(state, /\(403 Forbidden\) for \/api\/now\//, `${label}: the unread state carries the observed failure`);
    if (SERVICENOW_TABLE_FILES[table] || SERVICENOW_COUNT_FILES[table]) {
      assert.match(run.errors, /\(403( Forbidden)?\)/, `${label}: _errors.log names the observed status`);
      assert.ok(run.errors.includes(table), `${label}: _errors.log names the denied table`);
      const text = collectStrings([run.analysis, run.errors]);
      assert.ok(text.flatMap(mentionedStatusCodes).includes(403), `${label}: the scanner sees the 403 the output names`);
      assert.ok(text.flatMap(mentionedEndpoints).some((endpoint) => deniedPaths.includes(endpoint)), `${label}: the scanner sees the denied path the output names`);
    }
    assertMentionsMatchRequests([run.analysis, run.accessCheck, run.payloads, run.errors, run.executive], run.requests, label);

    for (const item of run.analysis) {
      for (const finding of item.findings) {
        for (const input of finding.evidence.inputs) {
          if (input.state === "complete") continue;
          for (const key of ["visible_rows", "total_rows", "truncated", "partial", "total_unknown"]) {
            if (input.state === "partial") continue;
            assert.equal(input[key], null, `${label}: ${finding.id} input ${input.table} (${input.state}) renders ${key} null`);
          }
        }
      }
    }

    const surface = run.accessCheck.surfaces.find((item) => item.table === table);
    assert.ok(surface, `${label}: the access check probes ${table}`);
    if (tableDenied) {
      assert.equal(surface.status, "forbidden", label);
      assert.equal(surface.http_status, 403, label);
      assert.ok(!("visible" in surface), `${label}: a forbidden surface carries no visible count`);
      assert.ok(!("total" in surface), `${label}: a forbidden surface with a failed aggregate carries no total`);
      assert.match(surface.error, /aggregate count also failed \(ServiceNow request failed \(403 Forbidden\) for \/api\/now\/stats\//);
    } else {
      assert.equal(surface.status, "readable", label);
      assert.ok(!("http_status" in surface), label);
    }

    if (tableDenied && (table === "sys_user" || table === "sys_user_has_role")) {
      const text = JSON.stringify([run.analysis, run.payloads.slice(1)]);
      for (const name of userNames) assert.ok(!text.includes(name), `${label}: ${name} must not be named from the denied inventory`);
      const identity = run.analysis.find((item) => item.area === "identity_access");
      assert.equal(identity.summary.admin_users, null, `${label}: summary admin_users renders null`);
      for (const id of ["SNOW-04", "SNOW-07", "SNOW-14"]) {
        const finding = findingsById(identity).get(id);
        assert.equal(finding.status, "manual", label);
        assert.ok(!("admin_user_names" in finding.evidence) && !("integration_user_names" in finding.evidence), `${label}: ${id} withholds its principal lists`);
        assert.ok(finding.summary.includes(table), `${label}: ${id} names the unread inventory`);
      }
      if (table === "sys_user") {
        assert.equal(identity.summary.active_users_visible, null);
        assert.equal(identity.summary.active_users_total, null);
        assert.equal(run.accessCheck.identity, undefined, `${label}: no identity is claimed when sys_user cannot be read`);
      } else {
        assert.equal(identity.summary.active_users_visible, 4);
        assert.equal(identity.summary.privileged_assignments_visible, null);
      }
    }
    if (tableDenied && table === "sys_properties") {
      const hardening = run.analysis.find((item) => item.area === "platform_hardening");
      assert.equal(hardening.summary.hardening_properties_visible, null);
      assert.equal(hardening.summary.enabled_debug_properties, null, `${label}: a debug property count from a denied read renders null`);
      assert.ok(hardening.findings.every((finding) => finding.status === "manual"), label);
    }
    if (tableDenied && table === "sys_plugins") {
      const hardening = run.analysis.find((item) => item.area === "platform_hardening");
      assert.equal(hardening.summary.ip_authenticator_plugin_active, null, `${label}: a plugin flag never defaults to false on a denied read`);
      assert.equal(run.analysis.find((item) => item.area === "operations_governance").summary.plugins_visible, null);
    }
    if (tableDenied && table === "sys_security_acl") {
      const accessControl = run.analysis.find((item) => item.area === "access_control");
      for (const key of ["sensitive_acls_visible", "wildcard_acls", "unrestricted_acls"]) {
        assert.equal(accessControl.summary[key], null, `${label}: summary ${key} renders null`);
      }
      assert.equal(accessControl.summary.record_acl_total, null);
      assert.equal(accessControl.summary.public_pages, 0, `${label}: a readable-but-empty count stays 0`);
    }
    if (!tableDenied && table === "sys_audit") {
      const operations = run.analysis.find((item) => item.area === "operations_governance");
      assert.equal(operations.summary.audit_rows_last_7_days, null);
      const audit = findingsById(operations).get("SNOW-10");
      assert.equal(audit.evidence.audit_rows_last_7_days, null);
      assert.match(audit.evidence.audit_count_error, /\(403 Forbidden\) for \/api\/now\/stats\/sys_audit/);
    }
  }
});

test("collection status: a partially visible user directory keeps seen and total counts, renders principal counts and lists null, and names no user from the partial set", async () => {
  const run = await exportWithFixture({ inflateTotals: { sys_user: 2000 } });
  const users = JSON.parse(run.files.get("core_data/sys_user.json"));
  assert.equal(users.partial, true);
  assert.equal(users.total, 2004);
  assert.equal(users.rows.length, 4);
  const identity = run.analysis.find((item) => item.area === "identity_access");
  assert.equal(identity.summary.active_users_visible, 4);
  assert.equal(identity.summary.active_users_total, 2004);
  assert.equal(identity.summary.admin_users, null);
  assert.match(identity.summary.inventories.users, /^sys_user read: partial \(sys_user returned 4 of 2004 rows/);
  const text = JSON.stringify([identity, run.payloads.slice(1)]);
  for (const name of fixtureUserNames(run.fixture)) assert.ok(!text.includes(name), `${name} must not be named from a partly read directory`);
  for (const id of ["SNOW-04", "SNOW-07", "SNOW-14"]) {
    const finding = findingsById(identity).get(id);
    assert.notEqual(finding.status, "pass", `${id} cannot pass on a partial directory`);
    assert.match(finding.evidence.principals_withheld, /^sys_user returned 4 of 2004 rows/);
    assert.match(finding.summary, /withheld because the user (or role )?inventory was not fully read|Partial view/);
  }
  const review = findingsById(identity).get("SNOW-04");
  for (const key of ["admin_users", "admin_user_names", "inactive_users", "inactive_user_count", "locked_out_users", "multi_privileged_users"]) {
    assert.equal(review.evidence[key], null, `SNOW-04 ${key} renders null on a partial directory`);
  }
  assert.equal(review.evidence.active_users, 4, "the seen count stays real");
  assert.equal(review.evidence.max_admins, 10, "thresholds are never gated");
  assert.equal(findingsById(identity).get("SNOW-07").evidence.admins_without_user_mfa_flag, null);
  assert.equal(findingsById(identity).get("SNOW-14").evidence.integration_users, null);
  assertMentionsMatchRequests([run.analysis, run.accessCheck, run.payloads, run.errors, run.executive], run.requests, "partial users");
});

test("review round item 13: absence-driven fails on a partial ACL, plugin, or property read cap at manual and name nothing they did not see", async () => {
  const withoutAcls = healthyFixture();
  withoutAcls.tables.sys_security_acl = withoutAcls.tables.sys_security_acl.filter((row) => row.name !== "sys_audit" && row.name !== "syslog");
  const partialAcls = await assessServicenowAccessControl(createClient(fixtureFetch(withoutAcls, { inflateTotals: { sys_security_acl: 60 } }).fetchImpl));
  const tableLevel = findingsById(partialAcls).get("SNOW-11");
  assert.equal(tableLevel.status, "manual");
  assert.match(tableLevel.summary, /read was partial, so the unread rows could hold them; table names and counts are withheld/);
  assert.doesNotMatch(tableLevel.summary, /sys_audit|syslog|\d+ sensitive tables have no/);
  for (const row of tableLevel.evidence.sensitive_table_coverage) {
    if (row.table === "sys_audit" || row.table === "syslog") {
      assert.equal(row.acls, null, `${row.table} acls render null on a partial ACL read`);
      assert.equal(row.missing_operations, null);
    }
  }
  const completeAcls = await assessServicenowAccessControl(createClient(fixtureFetch(withoutAcls).fetchImpl));
  assert.equal(findingsById(completeAcls).get("SNOW-11").status, "fail");
  assert.match(findingsById(completeAcls).get("SNOW-11").summary, /2 sensitive tables have no visible active record ACL: syslog, sys_audit/);

  const withoutPlugins = healthyFixture();
  withoutPlugins.tables.sys_plugins = withoutPlugins.tables.sys_plugins.filter((row) => !/Role Management V2|Security Jump Start/.test(row.name));
  const partialPlugins = await assessServicenowOperationsGovernance(createClient(fixtureFetch(withoutPlugins, { inflateTotals: { sys_plugins: 40 } }).fetchImpl));
  const plugins = findingsById(partialPlugins).get("SNOW-20");
  assert.equal(plugins.status, "manual");
  assert.match(plugins.summary, /2 baseline security plugins were not among the visible sys_plugins rows and that read was partial/);
  assert.doesNotMatch(plugins.summary, /Role Management V2|Security Jump Start/);
  for (const item of plugins.evidence.required_security_plugins) {
    if (/Role Management V2|Security Jump Start/.test(item.label)) assert.equal(item.present, null, `${item.label} presence is unknown on a partial read`);
    else assert.equal(item.present, true);
  }
  const completePlugins = await assessServicenowOperationsGovernance(createClient(fixtureFetch(withoutPlugins).fetchImpl));
  assert.equal(findingsById(completePlugins).get("SNOW-20").status, "fail");
  assert.match(findingsById(completePlugins).get("SNOW-20").summary, /2 baseline security plugins are not active: Contextual Security: Role Management V2, Security Jump Start \(ACL Rules\)/);
  const inactivePlugins = healthyFixture();
  inactivePlugins.tables.sys_plugins = inactivePlugins.tables.sys_plugins.map((row) => (/Security Jump Start/.test(row.name) ? { ...row, active: "inactive" } : row));
  const observedInactive = await assessServicenowOperationsGovernance(createClient(fixtureFetch(inactivePlugins, { inflateTotals: { sys_plugins: 40 } }).fetchImpl));
  assert.equal(findingsById(observedInactive).get("SNOW-20").status, "fail", "a plugin observed inactive is a real observation even on a partial read");
  assert.match(findingsById(observedInactive).get("SNOW-20").summary, /1 baseline security plugins are present but not active: Security Jump Start \(ACL Rules\)/);

  const withoutMfaProperty = healthyFixture();
  withoutMfaProperty.tables.sys_properties = withoutMfaProperty.tables.sys_properties.filter((row) => row.name !== "glide.authenticate.multifactor");
  const partialProperties = await assessServicenowIdentityAccess(createClient(fixtureFetch(withoutMfaProperty, { inflateTotals: { sys_properties: 40 } }).fetchImpl));
  const mfa = findingsById(partialProperties).get("SNOW-07");
  assert.equal(mfa.status, "manual");
  assert.match(mfa.summary, /glide\.authenticate\.multifactor was not among the visible sys_properties rows and that read was partial/);
  assert.doesNotMatch(mfa.summary, /documented default is false/);
  assert.equal(mfa.evidence.glide_authenticate_multifactor, null);
  const completeProperties = await assessServicenowIdentityAccess(createClient(fixtureFetch(withoutMfaProperty).fetchImpl));
  assert.equal(findingsById(completeProperties).get("SNOW-07").status, "fail");
  assert.match(findingsById(completeProperties).get("SNOW-07").summary, /has no sys_properties row; the documented default is false/);
});

/** No canary survives in any substring at lengths 6 through 24, and no HTML body was echoed. */
function assertSnowCanariesAbsent(text, context) {
  assertFragmentsAbsent(assert, text, Object.values(SNOW_CANARY), context);
  assert.ok(!text.includes("<html>"), `${context}: an HTML body was echoed`);
}

/** Every table the healthy run reads through the Table API or the Aggregate API, in first-request order. */
async function snowCanaryTables() {
  const { fetchImpl, requests } = fixtureFetch(healthyFixture());
  const client = createClient(fetchImpl);
  await checkServicenowAccess(client);
  await exportServicenowAuditBundle(client, sampleConfig(), createTempBase("grclanker-snow-surfaces-"));
  const tables = [];
  for (const request of requests) {
    const table = request.path.match(/^\/api\/now\/(?:table|stats)\/([^/]+)$/)?.[1];
    if (table && !tables.includes(table)) tables.push(table);
  }
  return tables;
}

/**
 * Runs the access check, all four assessments, and the export against a fixture where one surface
 * answers with the canary body, and asserts no canary reaches any result, bundle file, or zip entry,
 * and that every error string naming the failing surface carries the status-and-length note (html)
 * or the redacted URL (json).
 */
async function snowCanaryRun(configOverrides, fail, fixtureOptions = {}) {
  const base = createTempBase("grclanker-snow-canary-");
  const { fetchImpl, requests } = fixtureFetch(healthyFixture(), { ...fixtureOptions, fail });
  const config = sampleConfig(configOverrides);
  const client = new ServicenowApiClient(config, { fetchImpl, sleep: async () => {}, now: () => FIXED_NOW });
  const context = `${fail.table ?? fail.path} (${fail.flavor})`;
  const access = await checkServicenowAccess(client);
  const assessments = await Promise.all([
    assessServicenowIdentityAccess(client),
    assessServicenowPlatformHardening(client),
    assessServicenowAccessControl(client),
    assessServicenowOperationsGovernance(client),
  ]);
  const result = await exportServicenowAuditBundle(client, config, base);
  const files = readBundleFiles(result.outputDir);
  const zipEntries = readZipEntries(result.zipPath);
  const failingPaths = fail.table ? [`/api/now/table/${fail.table}`, `/api/now/stats/${fail.table}`] : [fail.path];
  assert.ok(requests.some((request) => failingPaths.includes(request.path)), `${context}: the failing surface was requested`);

  assertSnowCanariesAbsent(JSON.stringify(access), `${context} check_access`);
  assertSnowCanariesAbsent(JSON.stringify(assessments), `${context} assessments`);
  for (const [name, content] of files) assertSnowCanariesAbsent(content, `${context} bundle ${name}`);
  for (const [name, content] of zipEntries) assertSnowCanariesAbsent(content, `${context} zip ${name}`);

  const errorStrings = [
    ...access.surfaces.map((surface) => surface.error).filter(Boolean),
    ...access.notes.filter((note) => /identity lookup failed/.test(note)),
    ...assessments.flatMap((assessment) => assessment.errors),
    ...(files.get("_errors.log") ?? "").split("\n").filter(Boolean),
  ].filter((text) => failingPaths.some((path) => text.includes(path)));
  assert.ok(errorStrings.length > 0, `${context}: the failing surface must be recorded by the access check, an assessment, or the export`);
  for (const errorString of errorStrings) {
    if (fail.flavor === "html") {
      assert.match(errorString, /\(502 Bad Gateway\) for \/[^\s:]+: non-JSON body \(text\/html, \d+ bytes\)/, `${context}: ${errorString}`);
    } else {
      assert.match(errorString, /\(403 Forbidden\) for \/[^\s:]+: [^\n]*https:\/\/api\.example\.com\/v1\/x\?\[REDACTED\]/, `${context}: ${errorString}`);
      assert.ok(!errorString.includes("token="), `${context}: ${errorString}`);
      assertFragmentsAbsent(assert, errorString, [SNOW_CANARY.bearer], `${context}: bearer in the JSON detail field`);
    }
  }
  return { access, assessments, files, requests };
}

test("addendum 4: on every ServiceNow table a 502 HTML body or a JSON error embedding a credential URL never reaches results or the bundle, and the recorded error carries a status-and-length note or the redacted URL", async () => {
  const tables = await snowCanaryTables();
  assert.ok(tables.length >= 15, `the healthy run reads ${tables.length} tables`);
  assert.ok(tables.includes("sys_user") && tables.includes("sys_properties") && tables.includes("sys_plugins") && tables.includes("sys_security_acl"));
  let runs = 0;
  for (const table of tables) {
    for (const flavor of ["html", "json"]) {
      const run = await snowCanaryRun({ password: SNOW_CANARY.password }, { table, flavor });
      if (table === "sys_user") {
        const identityNote = run.access.notes.find((note) => /identity lookup failed/.test(note));
        assert.match(identityNote, flavor === "html" ? /non-JSON body \(text\/html, \d+ bytes\)/ : /\?\[REDACTED\]/);
      }
      runs += 1;
    }
  }
  assert.equal(runs, tables.length * 2);
});

test("addendum 4: an OAuth token endpoint that answers with a 502 HTML page or a JSON error embedding a credential URL never echoes the body, and the obtained bearer token is redacted from every later error string", async () => {
  const oauth = { authMode: "oauth", username: undefined, password: undefined, clientId: "client-id", clientSecret: SNOW_CANARY.clientSecret };
  for (const flavor of ["html", "json"]) {
    const run = await snowCanaryRun(oauth, { path: "/oauth_token.do", flavor });
    for (const surface of run.access.surfaces) {
      assert.equal(surface.status, flavor === "html" ? "not_readable" : "forbidden");
      assert.equal(surface.http_status, flavor === "html" ? 502 : 403);
      assert.match(surface.error, /^ServiceNow OAuth token request failed \((502 Bad Gateway|403 Forbidden)\) for \/oauth_token\.do: /);
    }
    assert.ok(run.requests.every((request) => request.path === "/oauth_token.do"), `${flavor}: no Table API request is issued without a bearer token`);
  }

  // With the token endpoint healthy, the bearer it returns is remembered and redacted from a later error,
  // and the configured client secret never appears either.
  const { fetchImpl } = fixtureFetch(healthyFixture(), { oauthToken: SNOW_CANARY.accessToken, fail: { table: "sys_user", flavor: "json" } });
  const client = new ServicenowApiClient(sampleConfig(oauth), { fetchImpl, sleep: async () => {}, now: () => FIXED_NOW });
  const snapshot = await client.queryTable("sys_user", { fields: ["sys_id"] });
  assert.equal(snapshot.statusCode, 403);
  assertSnowCanariesAbsent(snapshot.error, "post-exchange error");
  assertFragmentsAbsent(assert, client.redact(`Authorization: Bearer ${SNOW_CANARY.accessToken}; client_secret=${SNOW_CANARY.clientSecret}; ${SNOW_CANARY_URL}`), [SNOW_CANARY.accessToken, SNOW_CANARY.clientSecret, SNOW_CANARY.urlToken], "client.redact over the obtained bearer, the client secret, and the canary URL");
  assert.equal(redactSecrets(`header Bearer ${SNOW_CANARY.bearer}, cookie JSESSIONID=${SNOW_CANARY.session}, at https://u:p@example.com/a?sid=1#frag`, []), "header Bearer [REDACTED], cookie JSESSIONID=[REDACTED], at https://[REDACTED]@example.com/a?[REDACTED]#[REDACTED]");
  assert.match(redactSecrets("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl", []), /^Authorization: \[REDACTED\]/);
});

test("planted values self-check: every canary and planted secret is alphanumeric, distinct in every 6-character window, and no window occurs in the healthy fixture, the sample configuration, or a healthy bundle", async () => {
  const healthy = await exportWithFixture();
  assert.equal(healthy.result.errorCount, 0);
  assertPlantedValuesWellFormed(assert, {
    ...Object.fromEntries(Object.entries(SNOW_CANARY).map(([name, value]) => [`SNOW_CANARY.${name}`, value])),
    ...Object.fromEntries(Object.entries(FAKE_SNOW_SECRETS).map(([name, value]) => [`FAKE_SNOW_SECRETS.${name}`, value])),
    ...Object.fromEntries(Object.entries(CONFIG_CANARIES).map(([name, value]) => [`CONFIG_CANARIES.${name}`, value])),
    SAMPLE_PASSWORD,
  }, [
    ["healthy fixture", JSON.stringify(healthyFixture())],
    ["sample configuration", JSON.stringify({ ...sampleConfig(), password: null })],
    ["healthy tool payloads", JSON.stringify(healthy.payloads)],
    ...[...healthy.files].map(([name, content]) => [`healthy bundle ${name}`, content]),
  ]);
});

/**
 * The standing fixed texts ServiceNow emits, rendered with sample paths and names: the config loader
 * read and parse messages, the non-JSON and opaque-body notes, the timeout, the `not requested:` and
 * skipped wordings, the inventory states, the withheld notes, and the corollary summary templates.
 */
const SERVICENOW_FIXED_TEXTS = [
  // The resolver's own messages, which reach check_access, assess, and export results live.
  "SERVICENOW_URL or SERVICENOW_INSTANCE (or an instance_url / instance argument) is required.",
  "ServiceNow credentials are required. Set SERVICENOW_USERNAME plus SERVICENOW_PASSWORD for basic auth, SERVICENOW_CLIENT_ID plus SERVICENOW_CLIENT_SECRET (optionally with username and password for the password grant) for OAuth, or SERVICENOW_ACCESS_TOKEN for a pre-issued bearer token.",
  "ServiceNow basic auth requires SERVICENOW_USERNAME and SERVICENOW_PASSWORD.",
  "ServiceNow OAuth requires SERVICENOW_CLIENT_ID and SERVICENOW_CLIENT_SECRET (or SERVICENOW_ACCESS_TOKEN).",
  "ServiceNow mutual TLS is recognized but not supported by this runtime's fetch client; set SERVICENOW_AUTH_METHOD to basic or oauth.",
  "Pre-issued OAuth bearer token. Defaults to SERVICENOW_ACCESS_TOKEN.",
  "Unable to read ServiceNow config file /home/svc/.servicenow.yaml (ENOENT)",
  "Unable to read ServiceNow config file /tmp/grclanker-servicenow-loader-Ab3dEf/directory.yaml (EISDIR)",
  "Unable to read ServiceNow config file /tmp/grclanker-servicenow-loader-Ab3dEf/locked.yaml (EACCES)",
  "Unable to parse ServiceNow config file: invalid YAML in /tmp/grclanker-servicenow-loader-Ab3dEf/alias.yaml",
  "Unable to parse ServiceNow config file: invalid YAML in /tmp/grclanker-servicenow-loader-Ab3dEf/nested-mapping.yaml at line 2",
  "Unable to parse ServiceNow config file: /home/svc/.servicenow-sec-inspector/config.yaml must contain a YAML mapping",
  "ServiceNow request failed (502 Bad Gateway) for /api/now/table/sys_user: non-JSON body (text/html, 5120 bytes)",
  "ServiceNow request failed (403 Forbidden) for /api/now/table/sys_user_has_role: JSON body without documented error fields (application/json, 42 bytes)",
  "ServiceNow request failed (403 Forbidden) for /api/now/table/password_policy: Insufficient rights to query records",
  "ServiceNow request failed (429 Too Many Requests) for /api/now/stats/sys_audit: non-JSON body (text/plain, 12 bytes)",
  "ServiceNow OAuth token request failed (502 Bad Gateway) for /oauth_token.do: non-JSON body (text/html, 5120 bytes)",
  "ServiceNow request timed out after 30000ms: /api/now/table/sys_user",
  "not requested: the sys_security_acl read failed, so there were no ACL ids to look up",
  "sys_security_acl_role was not requested (the sys_security_acl read returned no rows, so there were no ACL ids to look up)",
  "sys_user read was forbidden (403)",
  "password_policy read failed (ServiceNow request timed out after 30000ms: /api/now/table/password_policy)",
  "sys_user was truncated at 500 of 2004 rows (record limit reached)",
  "sys_user returned 4 of 2004 rows (ACL-filtered or hidden rows)",
  "sys_public returned 0 rows without an X-Total-Count header (visibility unproven)",
  "sys_user read: complete (12 rows of 12)",
  "sys_user read: partial (sys_user returned 4 of 2004 rows (ACL-filtered or hidden rows))",
  "sys_user read: unread (ServiceNow request failed (403 Forbidden) for /api/now/table/sys_user: Insufficient rights to query records)",
  "password_policy read: complete (1 row)",
  "password_policy read: unread (ServiceNow request failed (403 Forbidden) for /api/now/table/password_policy: Insufficient rights to query records)",
  "sys_security_acl_role read: not requested (the sys_security_acl read failed, so there were no ACL ids to look up)",
  "sys_encryption_context read: unavailable (sys_encryption_context (legacy Column Level Encryption contexts) does not exist on this instance (ServiceNow request failed (400 Bad Request) for /api/now/table/sys_encryption_context: Invalid table sys_encryption_context))",
  "ip_access read: unavailable (ip_access does not exist on this instance; the com.glide.ip_authenticator plugin creates it when activated (ServiceNow request failed (400 Bad Request) for /api/now/table/ip_access: Invalid table ip_access))",
  "sys_security_acl aggregate: unread (ServiceNow request failed (403 Forbidden) for /api/now/stats/sys_security_acl: Insufficient rights to query records)",
  "sys_audit aggregate: unread (no count returned)",
  "sys_audit aggregate: complete (120533)",
  "users: sys_user read was forbidden (403)",
  "acl roles: sys_security_acl_role was not requested (the sys_security_acl read failed, so there were no ACL ids to look up)",
  "role inheritance: aggregate count failed (ServiceNow request failed (403 Forbidden) for /api/now/stats/sys_user_role_contains: Insufficient rights to query records)",
  "exact counts and names are withheld because the user inventory was not fully read",
  "counts and names are withheld because the user or role inventory was not fully read",
  "Among the visible rows, an admin or security_admin holder has not logged in for 90+ days; exact counts and names are withheld because the user inventory was not fully read.",
  "visible admin users without enable_multifactor_authn were observed (counts withheld because the user inventory was not fully read)",
  "glide.authenticate.multifactor was not among the visible sys_properties rows and that read was partial, so the unread rows could hold it; platform MFA enablement is unknown.",
  "Open System Security > Access Control (ACL) and confirm read, write, and delete record ACLs with roles exist for sys_user, sys_user_has_role, sys_user_role, sys_properties, sys_script, sys_security_acl, syslog, sys_audit.",
  "Connection Security could not be read for 1/2 active SMTP accounts (Corporate SMTP): the connection_security column and the legacy enable_ssl and enable_tls booleans were all unreadable.",
];

/** Addendum 7 must-keep table for ServiceNow: paths and tables, tenants, principals, finding ids, and the standing fixed texts. */
function servicenowKeepTable() {
  const tables = Object.keys(SERVICENOW_TABLE_FILES);
  const counts = Object.keys(SERVICENOW_COUNT_FILES);
  return {
    paths: [
      "/oauth_token.do",
      ...tables.map((table) => `/api/now/table/${table}`),
      ...counts.map((table) => `/api/now/stats/${table}`),
    ],
    tables: [...new Set([...tables, ...counts, "sys_user_has_role", "sys_user_grmember", "sys_user_role", "sys_audit", "syslog", "syslog_transaction"])],
    tenants: [
      "dev12345.service-now.com",
      "https://dev12345.service-now.com",
      "acme-prod-2026.service-now.com",
      "acme-prod-2026",
      "prod-us-east-2026",
      "Acme_Production_Org",
    ],
    principals: [
      "bob.user",
      "bob.user@acme.example",
      "audit.reader",
      "svc_integration_2026",
      "abel.tuter",
      "ITIL_User1",
      "admin",
      "security_admin",
      "x_acme_app.integration_user",
    ],
    findingIds: listServicenowControls().map((control) => control.id),
    fixedTexts: SERVICENOW_FIXED_TEXTS,
  };
}

test("scrub boundary: bare name-shaped values stay, carriers and registered secrets (in every encoded form) and real token shapes go, on redactSecrets and in ServicenowApiError; the addendum 7 must-keep table survives in isolation and in sentences", () => {
  const fetchImpl = async () => jsonResponse({});
  const mustKeep = [
    "ServiceNow OAuth token request failed (502 Bad Gateway) for /oauth_token.do: non-JSON body (text/html, 5120 bytes)",
    "ServiceNow request failed (403 Forbidden) for /api/now/table/sys_user_has_role: JSON body without documented error fields (application/json, 42 bytes)",
    "Unable to read ServiceNow config file /home/svc/.servicenow.yaml (ENOENT)",
    "Unable to parse ServiceNow config file: invalid YAML in /tmp/grclanker-servicenow-loader-Ab3dEf/alias.yaml",
  ];
  const keepTable = servicenowKeepTable();
  assert.equal(keepTable.findingIds.length, 20, "every ServiceNow finding id is in the table");
  assert.ok(keepTable.findingIds.includes("SNOW-11"));
  // The client constructor is the registration path (rememberSecrets on the configured password).
  assertScrubBoundary({
    scrub: (text) => redactSecrets(text, []),
    registerSecret: (secret) => new ServicenowApiClient(sampleConfig({ password: secret }), { fetchImpl }),
    mustKeep,
    keepTable,
  });
  // The error constructor applies the same pass to the message and the detail field; the secrets are registered by now.
  assertScrubBoundary({ scrub: (text) => new ServicenowApiError(text, 502).message, mustKeep, keepTable });
  assertScrubBoundary({ scrub: (text) => new ServicenowApiError("request failed", 502, text).detail, mustKeep, keepTable });
});

test("round 7 note 1: every fixed-text message ServiceNow emits (loader, opaque body, timeout, not requested, withheld, inventory states, corollary summaries) comes back from redactSecrets unchanged", async () => {
  const texts = new Set(SERVICENOW_FIXED_TEXTS);

  // The loader's own read and parse messages on real failing files.
  const scratch = { cwd: createTempBase("servicenow-fixed-cwd-"), homeDir: createTempBase("servicenow-fixed-home-") };
  for (const item of configLoaderCases({ format: "yaml", displayName: "ServiceNow", fileNoun: "config file", extension: ".yaml" })) {
    if (item.skip) continue;
    assert.throws(() => resolveServicenowConfiguration({ instance: "acme", config_file: item.path }, {}, scratch), (error) => {
      texts.add(error.message);
      return true;
    });
  }

  // The resolver's own messages on the real path, with an empty environment and no config file: no
  // instance, no credentials, and each auth method named without its credentials (mTLS included).
  const resolverMessages = [
    collectThrownMessage(texts, () => resolveServicenowConfiguration({}, {}, scratch), "no instance"),
    collectThrownMessage(texts, () => resolveServicenowConfiguration({ instance: "acme" }, {}, scratch), "no credentials"),
    collectThrownMessage(texts, () => resolveServicenowConfiguration({ instance: "acme", auth_method: "basic" }, {}, scratch), "basic without credentials"),
    collectThrownMessage(texts, () => resolveServicenowConfiguration({ instance: "acme", auth_method: "oauth" }, {}, scratch), "oauth without credentials"),
    collectThrownMessage(texts, () => resolveServicenowConfiguration({ instance: "acme", auth_method: "mtls" }, {}, scratch), "mtls"),
  ];
  assert.ok(resolverMessages.some((message) => /credentials are required/.test(message)), "the resolver rendered its credentials-required message");
  assert.ok(resolverMessages.some((message) => /mutual TLS/.test(message)), "the resolver rendered its mTLS message");

  // Every tool label, description, and argument description the integration registers.
  const registered = [];
  registerServicenowTools({ registerTool: (tool) => registered.push(tool) });
  const toolTexts = collectToolTexts(registered);
  assert.ok([...toolTexts].some((text) => /bearer token/.test(text)), "the tool schemas carry the bearer token argument description");
  for (const text of toolTexts) texts.add(text);

  // The error constructor's opaque-body notes and describeStatus text on real responses.
  const opaque = createClient(async (input) => {
    const pathname = new URL(String(input)).pathname;
    if (pathname.endsWith("/sys_user")) return new Response("<html><body>Bad Gateway</body></html>", { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html" } });
    if (pathname.endsWith("/sys_properties")) return jsonResponse({ unexpected: { shape: true } }, { status: 403 });
    return new Response("upstream request timeout", { status: 504, statusText: "Gateway Timeout", headers: { "content-type": "text/plain" } });
  });
  for (const table of ["sys_user", "sys_properties", "sys_audit"]) {
    const snapshot = await opaque.queryTable(table);
    assert.ok(snapshot.error, `${table} read is unread`);
    texts.add(snapshot.error);
    const count = await opaque.countRecords(table);
    assert.ok(count.error, `${table} count is unread`);
    texts.add(count.error);
  }
  await assert.rejects(opaque.requestJson(`${sampleConfig().instanceUrl}/api/now/table/sys_user`), (error) => {
    assert.ok(error instanceof ServicenowApiError, `requestJson throws the client's error class: ${error}`);
    texts.add(error.message);
    if (error.detail) texts.add(error.detail);
    return true;
  });

  // Every assessment, the access check, and the bundle on a healthy fixture, on every table denied, on a
  // dependent read skipped behind its failed parent, and on a partial read: summaries, inventory states,
  // principals_withheld, collection issues, dataset errors, and the error log.
  const runs = [
    await exportWithFixture(),
    await exportWithFixture({ forbidAll: true }),
    await exportWithFixture({ forbiddenTables: ["sys_security_acl", "sys_user", "password_policy"], forbiddenCounts: ["sys_user_role_contains", "sys_security_acl"] }),
    await exportWithFixture({ inflateTotal: 2000 }),
    await exportWithFixture({ omitTotalCount: true }),
  ];
  for (const run of runs) {
    collectFixedTexts([run.analysis, run.accessCheck, run.payloads], texts);
    for (const line of logLines(run.errors)) texts.add(line);
    for (const [name, content] of run.files) {
      if (name.startsWith("core_data/")) collectFixedTexts(JSON.parse(content), texts);
    }
  }

  const checked = assertFixedTextsSurvive((text) => redactSecrets(text, []), texts, "ServiceNow fixed texts");
  assert.ok(checked >= SERVICENOW_FIXED_TEXTS.length + 40, `the harvest rendered texts beyond the standing list (${checked})`);
  assert.ok([...texts].some((text) => /read: not requested \(/.test(text)), "the harvest rendered a not requested inventory state");
  assert.ok([...texts].some((text) => /^not requested: /.test(text)), "the harvest rendered a not requested dataset error");
  assert.ok([...texts].some((text) => /withheld because the user inventory was not fully read/.test(text)), "the harvest rendered a principals_withheld note");
  assert.ok([...texts].some((text) => /non-JSON body \(text\/html, \d+ bytes\)/.test(text)), "the harvest rendered a status-and-length note");
});

test("round 7 note 2: credentials and the config file path set through the environment survive an unrelated argument, and the source chain names the environment", () => {
  const base = createTempBase("servicenow-env-survives-");
  const configPath = join(base, "servicenow.yaml");
  writeFileSync(configPath, ["servicenow:", "  instance: fileinstance", "  timeout_seconds: 12", ""].join("\n"));
  const env = {
    SERVICENOW_CONFIG_FILE: configPath,
    SERVICENOW_INSTANCE: "envinstance",
    SERVICENOW_USERNAME: "env.user",
    SERVICENOW_PASSWORD: "env-password-value",
  };
  for (const [label, unrelated] of [
    ["page_size", { page_size: 100 }],
    ["max_retries", { max_retries: 2 }],
    ["auth_method basic", { auth_method: "basic" }],
  ]) {
    const resolved = resolveServicenowConfiguration(unrelated, env, { cwd: base, homeDir: base });
    assert.equal(resolved.username, "env.user", `${label}: the environment username resolves`);
    assert.equal(resolved.password, "env-password-value", `${label}: the environment password resolves`);
    assert.equal(resolved.instanceName, "envinstance", `${label}: the environment instance overrides the file`);
    assert.equal(resolved.instanceUrl, "https://envinstance.service-now.com", label);
    assert.equal(resolved.timeoutMs, 12000, `${label}: the file value not set elsewhere still applies`);
    assert.ok(resolved.sourceChain.includes("environment"), `${label}: the source chain names the environment: ${JSON.stringify(resolved.sourceChain)}`);
    assert.ok(resolved.sourceChain.includes(`config-file:${configPath}`), `${label}: the source chain names the config file from the environment`);
    assert.deepEqual(resolved.sourceChain, [`config-file:${configPath}`, "environment", "arguments"], label);
  }
  // An argument object whose credential keys are present but undefined must not shadow the environment.
  const shadowed = resolveServicenowConfiguration({ username: undefined, password: undefined, page_size: 50 }, env, { cwd: base, homeDir: base });
  assert.equal(shadowed.username, "env.user");
  assert.equal(shadowed.password, "env-password-value");
  assert.deepEqual(shadowed.sourceChain, [`config-file:${configPath}`, "environment", "arguments"]);
});

test("review round item 13, extended: SNOW-08 and SNOW-17 do not assert the absence of a provider, plugin, or rule from a partial read", async () => {
  const inactiveProviders = healthyFixture();
  inactiveProviders.tables.sso_properties = inactiveProviders.tables.sso_properties.map((row) => ({ ...row, active: "false" }));
  const partialProviders = await assessServicenowIdentityAccess(createClient(fixtureFetch(inactiveProviders, { inflateTotals: { sso_properties: 40 } }).fetchImpl));
  const sso = findingsById(partialProviders).get("SNOW-08");
  assert.equal(sso.status, "manual");
  assert.match(sso.summary, /was among the visible rows, and at least one of those reads was partial/);
  const completeProviders = await assessServicenowIdentityAccess(createClient(fixtureFetch(inactiveProviders).fetchImpl));
  assert.equal(findingsById(completeProviders).get("SNOW-08").status, "fail");

  const inactiveRules = healthyFixture();
  inactiveRules.tables.ip_access = inactiveRules.tables.ip_access.map((row) => ({ ...row, active: "false" }));
  const partialRules = await assessServicenowPlatformHardening(createClient(fixtureFetch(inactiveRules, { inflateTotals: { ip_access: 40 } }).fetchImpl));
  const rules = findingsById(partialRules).get("SNOW-17");
  assert.equal(rules.status, "manual");
  assert.match(rules.summary, /none of the visible ip_access rows is active, but that read was partial/);
  const completeRules = await assessServicenowPlatformHardening(createClient(fixtureFetch(inactiveRules).fetchImpl));
  assert.equal(findingsById(completeRules).get("SNOW-17").status, "fail");

  // With active rules visible, a missing plugin row already stops at warn ("could not be confirmed"); the
  // absence claim only fires when no active rule is visible either, so that is the path gated here.
  const withoutPlugin = healthyFixture();
  withoutPlugin.tables.sys_plugins = withoutPlugin.tables.sys_plugins.filter((row) => row.source !== "com.snc.ipauthenticator");
  withoutPlugin.tables.ip_access = withoutPlugin.tables.ip_access.map((row) => ({ ...row, active: "false" }));
  const partialPlugins = await assessServicenowPlatformHardening(createClient(fixtureFetch(withoutPlugin, { inflateTotals: { sys_plugins: 40 } }).fetchImpl));
  const plugin = findingsById(partialPlugins).get("SNOW-17");
  assert.equal(plugin.status, "manual");
  assert.match(plugin.summary, /was not among the visible sys_plugins rows and that read was partial/);
  const completePlugins = await assessServicenowPlatformHardening(createClient(fixtureFetch(withoutPlugin).fetchImpl));
  assert.equal(findingsById(completePlugins).get("SNOW-17").status, "fail");
  assert.match(findingsById(completePlugins).get("SNOW-17").summary, /has no row in sys_plugins/);
});
