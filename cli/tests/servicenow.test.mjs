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
  redactSecrets,
  resolveSecureOutputPath,
  resolveServicenowConfiguration,
} from "../dist/extensions/grc-tools/servicenow.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";

const FIXED_NOW = new Date("2026-09-21T00:00:00Z");
const RECENT_LOGIN = "2026-09-20 08:15:00";
const STALE_LOGIN = "2026-01-05 08:15:00";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function sampleConfig(overrides = {}) {
  return {
    instanceUrl: "https://dev12345.service-now.com",
    instanceName: "dev12345",
    authMode: "basic",
    username: "audit.reader",
    password: "s3cret-pass-word",
    timeoutMs: 30000,
    maxRetries: 3,
    pageSize: 500,
    sourceChain: ["tests"],
    ...overrides,
  };
}

function jsonResponse(value, options = {}) {
  return new Response(JSON.stringify(value), {
    status: options.status ?? 200,
    headers: {
      "content-type": "application/json",
      ...(options.headers ?? {}),
    },
  });
}

function forbiddenResponse() {
  return jsonResponse({ error: { message: "Insufficient rights to query records", detail: "Field(s) present in the query do not have permission to be read" }, status: "failure" }, { status: 403 });
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
  const forbidden = new Set(options.forbiddenTables ?? []);
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(String(input));
    calls.push({ url, init });
    const tableMatch = url.pathname.match(/^\/api\/now\/table\/([^/]+)$/);
    const statsMatch = url.pathname.match(/^\/api\/now\/stats\/([^/]+)$/);
    const table = tableMatch?.[1] ?? statsMatch?.[1];
    if (options.forbidAll || (table && forbidden.has(table))) return forbiddenResponse();
    if (tableMatch) {
      const rows = fixture.tables[table];
      if (rows === undefined) return jsonResponse({ error: { message: `Invalid table ${table}` } }, { status: 400 });
      const query = url.searchParams.get("sysparm_query") ?? "";
      const matched = filterRows(rows, query, fixture);
      const limit = Number(url.searchParams.get("sysparm_limit") ?? "500");
      const offset = Number(url.searchParams.get("sysparm_offset") ?? "0");
      const page = matched.slice(offset, offset + limit);
      const headers = options.omitTotalCount ? {} : { "X-Total-Count": String(matched.length + (options.inflateTotal ?? 0)) };
      if (offset + limit < matched.length) {
        const nextUrl = new URL(url);
        nextUrl.searchParams.set("sysparm_offset", String(offset + limit));
        headers.Link = `<${nextUrl.toString()}>;rel="next"`;
      }
      return jsonResponse({ result: page }, { headers });
    }
    if (statsMatch) {
      const explicit = fixture.counts?.[table];
      if (explicit !== undefined) {
        return jsonResponse({ result: { stats: { count: String(explicit) } } });
      }
      const rows = fixture.tables[table];
      if (rows === undefined) return jsonResponse({ error: { message: `Invalid table ${table}` } }, { status: 400 });
      const query = url.searchParams.get("sysparm_query") ?? "";
      return jsonResponse({ result: { stats: { count: String(filterRows(rows, query, fixture).length + (options.inflateTotal ?? 0)) } } });
    }
    return jsonResponse({ error: { message: "not found" } }, { status: 404 });
  };
  return { fetchImpl, calls };
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
  assert.throws(() => resolveServicenowConfiguration({ instance: "acme", config_file: join(scratch.cwd, "missing.yaml") }, {}, scratch), /config file was not found/);
  assert.throws(() => resolveServicenowConfiguration({ instance: "acme", auth_method: "mtls" }, {}, scratch), /mutual TLS/);
  assert.throws(() => resolveServicenowConfiguration({ instance: "acme", auth_method: "basic", username: "u" }, {}, scratch), /basic auth requires/);
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
  const expectedAuth = `Basic ${Buffer.from("audit.reader:s3cret-pass-word").toString("base64")}`;
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
  assert.equal(tokenCalls[0].get("password"), "s3cret-pass-word");
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
  const fetchImpl = async () => jsonResponse({ error: { message: "Bad credential s3cret-pass-word for audit.reader" } }, { status: 400 });
  const snapshot = await createClient(fetchImpl).queryTable("sys_user");
  assert.match(snapshot.error, /\[REDACTED\]/);
  assert.equal(snapshot.error.includes("s3cret-pass-word"), false);
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
  assert.match(byId.get("SNOW-07").summary, /glide.authenticate.multifactor=false/);
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
  assert.match(byId.get("SNOW-01").summary, /glide.security.use_csrf_token=false/);
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
