import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";

import {
  assessTenableAccessControl,
  assessTenableScanProgram,
  assessTenableSensorCoverage,
  assessTenableVulnerabilityManagement,
  checkTenableAccess,
  collectTenableAccessControlData,
  collectTenableScanProgramData,
  collectTenableSensorCoverageData,
  collectTenableVulnerabilityData,
  createTenableClients,
  exportTenableAuditBundle,
  registerTenableTools,
  resolveSecureOutputPath,
  resolveTenableConfiguration,
} from "../dist/extensions/grc-tools/tenable.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";
import { assertSecretsAbsent, readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";

const NOW = Date.parse("2026-09-21T12:00:00Z");
const RECENT_SECONDS = Math.floor((NOW - 2 * 86_400_000) / 1000);
const RECENT_ISO = new Date(NOW - 2 * 86_400_000).toISOString();
const RECENT_PLUGIN_SET = "202609211000";
const EMPTY_ENV = { HOME: "/nonexistent-home-for-tests" };
// An explicitly named config file must exist (a missing one is an ENOENT error), so
// fixtures that want "no file settings" point at a real empty YAML file instead of
// the developer's ~/.tenable/config.yaml.
const EMPTY_CONFIG_FILE = join(mkdtempSync(join(tmpdir(), "tenable-empty-config-")), "tenable.yaml");
writeFileSync(EMPTY_CONFIG_FILE, "");

function jsonResponse(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}

function vmConfig(extra = {}) {
  return resolveTenableConfiguration({ access_key: "access-key-123456", secret_key: "secret-key-654321", config_file: EMPTY_CONFIG_FILE, ...extra }, EMPTY_ENV);
}

function healthyUsers() {
  return [
    { id: 1, uuid: "u-1", username: "admin@example.com", email: "admin@example.com", permissions: 64, enabled: true, ui_permitted: true, two_factor: { sms_enabled: 1 }, ui_saml_only: false, lastlogin: NOW - 86_400_000, login_fail_count: 0, locked: false, role: { name: "Administrator" }, last_apikey_access: NOW - 3_600_000 },
    { id: 2, uuid: "u-2", username: "scanner@example.com", email: "scanner@example.com", permissions: 40, enabled: true, ui_permitted: true, two_factor: { sms_enabled: 1 }, lastlogin: NOW - 5 * 86_400_000, login_fail_count: 0, locked: false, role: { name: "Scan Manager" } },
  ];
}

function healthyAssets() {
  return [
    { id: "a-1", has_agent: true, last_authentication_scan_status: "Success", last_seen: RECENT_ISO, network_id: "net-1", network_name: "Default", tags: [{ key: "Environment", value: "prod" }], sources: [{ name: "NESSUS_AGENT" }] },
    { id: "a-2", has_agent: false, last_authentication_scan_status: "Success", last_seen: RECENT_ISO, network_id: "net-1", network_name: "Default", tags: [{ key: "Environment", value: "prod" }], sources: [{ name: "NESSUS_SCAN" }] },
  ];
}

function healthyPolicyDetails(overrides = {}) {
  return {
    uuid: "tmpl-basic",
    settings: { safe_checks: "yes", portscan_range: "default", thorough_tests: "no", max_hosts_per_scan: "80", max_checks_per_host: "5", report_paranoia: "Normal", ...(overrides.settings ?? {}) },
    plugins: overrides.plugins ?? { "Windows": { status: "enabled" }, "Web Servers": { status: "enabled" }, "Denial of Service": { status: "disabled" } },
    credentials: {},
    audits: {},
    scap: {},
  };
}

function externalExportJob(uuid, createdMs, extra = {}) {
  return { uuid, status: "FINISHED", created: createdMs, num_assets_per_chunk: 50, filters: { state: ["OPEN", "REOPENED"] }, total_chunks: 1, finished_chunks: 1, ...extra };
}

function healthyVulns() {
  return [
    { severity: "critical", state: "OPEN", first_found: RECENT_ISO, last_found: RECENT_ISO, plugin: { id: 1, vpr: { score: 9.3 }, cvss3_base_score: 9.8 } },
    { severity: "high", state: "FIXED", first_found: RECENT_ISO, last_fixed: RECENT_ISO, time_taken_to_fix: 2 * 86_400, plugin: { id: 2, vpr: { score: 7.1 }, cvss3_base_score: 8.1 } },
  ];
}

function healthyRoutes() {
  return {
    "GET /users": { users: healthyUsers() },
    "GET /scans": {
      scans: [
        { id: 10, uuid: "s-10", name: "Weekly Prod", enabled: true, rrules: "FREQ=WEEKLY;INTERVAL=1", status: "completed", type: "remote", policy_id: 1, last_modification_date: RECENT_SECONDS, wizard_uuid: "tmpl-basic", template_uuid: "tmpl-basic" },
        { id: 11, uuid: "s-11", name: "PCI Quarterly", enabled: true, rrules: "FREQ=MONTHLY;INTERVAL=3", status: "completed", type: "remote", policy_id: 2, last_modification_date: RECENT_SECONDS, wizard_uuid: "tmpl-pci", template_uuid: "tmpl-pci" },
      ],
    },
    "GET /policies": { policies: [{ id: 1, name: "Prod policy", template_uuid: "tmpl-basic" }, { id: 2, name: "PCI policy", template_uuid: "tmpl-pci" }] },
    "GET /policies/1": healthyPolicyDetails(),
    "GET /policies/2": healthyPolicyDetails(),
    "GET /editor/scan/templates": {
      templates: [
        { uuid: "tmpl-basic", name: "basic", title: "Basic Network Scan" },
        { uuid: "tmpl-pci", name: "pci", title: "PCI Quarterly External Scan" },
        { uuid: "tmpl-disc", name: "discovery", title: "Host Discovery" },
      ],
    },
    "GET /exclusions": { exclusions: [{ id: 1, name: "Maintenance window", description: "CHG-1234", members: "10.0.0.5", schedule: { enabled: true, rrules: "FREQ=WEEKLY" } }], pagination: { total: 1 } },
    "GET /target-groups": { target_groups: [] },
    "GET /server/properties": { loaded_plugin_set: RECENT_PLUGIN_SET, nessus_ui_version: "10.8.0", plugin_set: RECENT_PLUGIN_SET },
    "GET /scanners": { scanners: [{ id: 1, name: "US Cloud Scanner", status: "on", linked: 1, type: "managed", loaded_plugin_set: RECENT_PLUGIN_SET, ui_version: "10.8.0", last_connect: RECENT_SECONDS, group: false, pool: false }] },
    "GET /scanners/null/agents": { agents: [{ id: 1, uuid: "ag-1", name: "host-1", status: "on", last_connect: RECENT_SECONDS, core_version: "10.8.0", plugin_feed_id: RECENT_PLUGIN_SET, groups: [{ id: 1, name: "prod" }] }], pagination: { total: 1 } },
    "GET /scanners/null/agent-groups": { groups: [{ id: 1, name: "prod", agents_count: 1 }] },
    "GET /networks": { networks: [{ uuid: "net-1", name: "Default", is_default: true, scanner_count: 1, assets_ttl_days: 90 }], pagination: { total: 1 } },
    "GET /tags/categories": { categories: [{ uuid: "c-1", name: "Environment" }], pagination: { total: 1 } },
    "GET /tags/values": { values: [{ uuid: "v-1", category_name: "Environment", value: "prod" }], pagination: { total: 1 } },
    "GET /groups": { groups: [{ id: 1, name: "Administrators" }] },
    "GET /access-control/v1/roles": [{ id: "r-1", name: "Administrator", type: "system" }],
    "GET /api/v3/access-control/permissions": { permissions: [{ uuid: "p-1", name: "Prod assets", actions: ["CanView"], objects: [{ type: "Tag", name: "Environment:prod" }], subjects: [{ type: "Group", name: "Analysts" }], created_by: "admin" }] },
    "GET /v2/access-groups": { access_groups: [], pagination: { total: 0 } },
    "GET /credentials": { credentials: [{ uuid: "c-1", name: "Linux SSH", type: { id: "ssh", name: "SSH" }, created_date: RECENT_SECONDS, last_used_by: { name: "Weekly Prod" } }], pagination: { total: 1 } },
    "GET /audit-log/v1/events": { events: [{ id: "e-1", action: "user.login", crud: "r", is_failure: false, received: RECENT_ISO, actor: { id: "u-1", name: "admin" }, target: { id: "u-1", type: "User" } }], pagination: { total: 1 } },
    "GET /vulns/export/status": { exports: [externalExportJob("vx-1", NOW - 86_400_000), externalExportJob("vx-2", NOW - 2 * 86_400_000)] },
    "GET /assets/export/status": { exports: [externalExportJob("ax-1", NOW - 86_400_000, { filters: { has_plugin_results: true } })] },
    "POST /assets/export": { export_uuid: "asset-export-1" },
    "GET /assets/export/asset-export-1/status": { status: "FINISHED", chunks_available: [1], chunks_failed: [], total_chunks: 1 },
    "GET /assets/export/asset-export-1/chunks/1": healthyAssets(),
    "POST /vulns/export": { export_uuid: "vuln-export-1" },
    "GET /vulns/export/vuln-export-1/status": { status: "FINISHED", chunks_available: [1], chunks_failed: [], total_chunks: 1 },
    "GET /vulns/export/vuln-export-1/chunks/1": healthyVulns(),
  };
}

function emptyRoutes() {
  const routes = healthyRoutes();
  for (const key of Object.keys(routes)) {
    const value = routes[key];
    if (Array.isArray(value)) {
      routes[key] = [];
      continue;
    }
    if (key.endsWith("/status") && "chunks_available" in value) {
      routes[key] = { status: "FINISHED", chunks_available: [], chunks_failed: [], total_chunks: 0 };
      continue;
    }
    if (key.startsWith("POST")) continue;
    const copy = {};
    for (const [field, fieldValue] of Object.entries(value)) {
      copy[field] = Array.isArray(fieldValue) ? [] : field === "pagination" ? { total: 0 } : fieldValue;
    }
    routes[key] = copy;
  }
  return routes;
}

function partialRoutes() {
  const routes = healthyRoutes();
  routes["GET /users"] = { users: healthyUsers().map(({ id, uuid, username, email }) => ({ id, uuid, username, email })) };
  for (const key of Object.keys(routes)) {
    const value = routes[key];
    if (value && typeof value === "object" && !Array.isArray(value) && value.pagination) {
      routes[key] = { ...value, pagination: { total: 250 } };
    }
  }
  routes["GET /assets/export/asset-export-1/status"] = { status: "FINISHED", chunks_available: [1, 2, 3], chunks_failed: [], total_chunks: 3 };
  routes["GET /vulns/export/vuln-export-1/status"] = { status: "FINISHED", chunks_available: [1, 2, 3], chunks_failed: [], total_chunks: 3 };
  return routes;
}

function routerFetch(routes, { status = 200, log } = {}) {
  return async (url, init = {}) => {
    const parsed = new URL(url);
    const method = (init.method ?? "GET").toUpperCase();
    const key = `${method} ${parsed.pathname}`;
    log?.push({ key, url: parsed.toString(), headers: init.headers, body: init.body });
    if (status !== 200) return jsonResponse({ error: "forbidden" }, status);
    if (!(key in routes)) return jsonResponse({ error: `unrouted ${key}` }, 404);
    const value = routes[key];
    if (value && typeof value === "object" && "__status" in value) return jsonResponse({ error: "forbidden" }, value.__status);
    const offset = Number(parsed.searchParams.get("offset") ?? "0");
    if (offset > 0 && value && typeof value === "object" && !Array.isArray(value)) {
      const paged = {};
      for (const [field, fieldValue] of Object.entries(value)) paged[field] = Array.isArray(fieldValue) ? [] : fieldValue;
      return jsonResponse(paged);
    }
    return jsonResponse(value);
  };
}

function clientsFor(routes, options = {}) {
  return createTenableClients(vmConfig(options.configExtra), {
    fetchImpl: routerFetch(routes, options),
    sleepImpl: async () => {},
    exportPollMs: 0,
    exportTimeoutMs: 5_000,
  });
}

async function runAll(clients, options = {}) {
  const assessOptions = { now: NOW, ...options };
  const [scan, sensor, access, vuln] = await Promise.all([
    collectTenableScanProgramData(clients, assessOptions),
    collectTenableSensorCoverageData(clients, assessOptions),
    collectTenableAccessControlData(clients, assessOptions),
    collectTenableVulnerabilityData(clients, assessOptions),
  ]);
  return [
    assessTenableScanProgram(scan, assessOptions),
    assessTenableSensorCoverage(sensor, assessOptions),
    assessTenableAccessControl(access, assessOptions),
    assessTenableVulnerabilityManagement(vuln, assessOptions),
  ];
}

function allFindings(results) {
  return results.flatMap((result) => result.findings);
}

function byId(results, id) {
  const match = allFindings(results).find((item) => item.id === id);
  assert.ok(match, `expected finding ${id}`);
  return match;
}

test("resolveTenableConfiguration prefers arguments over environment over config file", () => {
  const dir = mkdtempSync(join(tmpdir(), "tenable-config-"));
  const configPath = join(dir, "config.yaml");
  writeFileSync(configPath, "access_key: file-access-key\nsecret_key: file-secret-key\nurl: https://fedcloud.tenable.com\n");

  const fromFile = resolveTenableConfiguration({ config_file: configPath }, EMPTY_ENV);
  assert.equal(fromFile.vm.accessKey, "file-access-key");
  assert.equal(fromFile.vm.baseUrl, "https://fedcloud.tenable.com");
  assert.equal(fromFile.vm.fedramp, true);
  assert.ok(fromFile.sourceChain.some((item) => item.startsWith("config:")));

  const fromEnv = resolveTenableConfiguration({ config_file: configPath }, { ...EMPTY_ENV, TENABLE_ACCESS_KEY: "env-access-key", TENABLE_SECRET_KEY: "env-secret-key", TENABLE_URL: "https://cloud.tenable.com" });
  assert.equal(fromEnv.vm.accessKey, "env-access-key");
  assert.equal(fromEnv.vm.baseUrl, "https://cloud.tenable.com");
  assert.equal(fromEnv.vm.fedramp, false);

  const fromArgs = resolveTenableConfiguration({ config_file: configPath, access_key: "arg-access-key", secret_key: "arg-secret-key", url: "cloud.tenable.com/" }, { ...EMPTY_ENV, TENABLE_ACCESS_KEY: "env-access-key", TENABLE_SECRET_KEY: "env-secret-key" });
  assert.equal(fromArgs.vm.accessKey, "arg-access-key");
  assert.equal(fromArgs.vm.baseUrl, "https://cloud.tenable.com");
  assert.equal(fromArgs.platform, "vm");
  assert.equal(fromArgs.securityCenter, undefined);
});

test("resolveTenableConfiguration treats non-cloud URLs as Tenable Security Center and requires keys", () => {
  const sc = resolveTenableConfiguration({ url: "https://sc.example.internal", access_key: "sc-access-key", secret_key: "sc-secret-key", config_file: EMPTY_CONFIG_FILE }, EMPTY_ENV);
  assert.equal(sc.platform, "sc");
  assert.equal(sc.vm, undefined);
  assert.equal(sc.securityCenter.baseUrl, "https://sc.example.internal");
  assert.equal(sc.securityCenter.accessKey, "sc-access-key");

  const both = resolveTenableConfiguration({ config_file: EMPTY_CONFIG_FILE }, { ...EMPTY_ENV, TENABLE_ACCESS_KEY: "a-key-123456", TENABLE_SECRET_KEY: "s-key-123456", TENABLE_SC_URL: "https://sc.example.internal", TENABLE_SC_ACCESS_KEY: "sc-a", TENABLE_SC_SECRET_KEY: "sc-s" });
  assert.equal(both.platform, "vm");
  assert.equal(both.vm.baseUrl, "https://cloud.tenable.com");
  assert.equal(both.securityCenter.baseUrl, "https://sc.example.internal");

  assert.throws(() => resolveTenableConfiguration({ config_file: EMPTY_CONFIG_FILE }, EMPTY_ENV), /TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY/);
  assert.throws(() => resolveTenableConfiguration({ url: "https://sc.example.internal", config_file: EMPTY_CONFIG_FILE }, EMPTY_ENV), /needs API keys/);
});

// Config loader canaries: no two share an 8-character window, so any fragment a parser
// quotes from the file is attributable to one fixture. The short canary keeps the JSON
// short file at 20 characters, within the size at which JSON.parse quotes the whole source.
const LOADER_CANARIES = {
  yamlNestedKey: "cnrA1qz8Xw4LpT9vK2mD",
  yamlNestedBearer: "cnrB5hj3Yn7GsW2rQ8kF",
  yamlAlias: "cnrC9tb6Um1JdX3eN7wP",
  jsonUnquoted: "cnrD2vf7Zk5HcR8sL4yG",
  jsonShort: "cnrE6pm4Qa",
  jsonMultiline: "cnrF3gk8Wd2ZnT6iM9oJ",
};
const LIBRARY_ERROR_WORDING = ["Nested mappings", "is not valid JSON", "Unresolved alias", "illegal operation", "permission denied", "Unexpected token", "Expected ',' or '}'"];

function assertNoLoaderLeak(text, canaries, label) {
  for (const canary of canaries) {
    assert.ok(!text.includes(canary), `${label}: canary ${canary} leaked into: ${text}`);
    for (let index = 0; index + 8 <= canary.length; index += 1) {
      const fragment = canary.slice(index, index + 8);
      assert.ok(!text.includes(fragment), `${label}: canary fragment ${fragment} leaked into: ${text}`);
    }
  }
  for (const wording of LIBRARY_ERROR_WORDING) {
    assert.ok(!text.includes(wording), `${label}: library wording "${wording}" leaked into: ${text}`);
  }
}

test("config loader errors carry fixed text, the path, a validated code, and a structured line, never the file contents or library wording", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tenable-loader-errors-"));
  const write = (name, text) => {
    const pathname = join(dir, name);
    writeFileSync(pathname, text);
    return pathname;
  };
  const registered = [];
  registerTenableTools({ registerTool: (tool) => registered.push(tool) });
  const check = registered.find((tool) => tool.name === "tenable_check_access");
  const checkAccessText = async (configFile) => JSON.stringify(await check.execute("call-loader", check.prepareArguments({ config_file: configFile, url: "https://cloud.tenable.com" })));

  const cases = [
    {
      label: "YAML nested mapping",
      file: write("nested.yaml", `key: ${LOADER_CANARIES.yamlNestedKey}: Bearer ${LOADER_CANARIES.yamlNestedBearer}\n`),
      canaries: [LOADER_CANARIES.yamlNestedKey, LOADER_CANARIES.yamlNestedBearer],
      libraryThrows: true,
      libraryCarriesCanary: true,
      expected: (pathname) => `Unable to parse Tenable config file: invalid YAML in ${pathname} at line 1 (INVALID_YAML)`,
    },
    {
      label: "YAML alias",
      file: write("alias.yaml", `key: *${LOADER_CANARIES.yamlAlias}\n`),
      canaries: [LOADER_CANARIES.yamlAlias],
      libraryThrows: true,
      libraryCarriesCanary: true,
      // A ReferenceError, not a YAMLError: no linePos, so no line is claimed.
      expected: (pathname) => `Unable to parse Tenable config file: invalid YAML in ${pathname} (INVALID_YAML)`,
    },
    {
      label: "JSON unquoted value",
      file: write("unquoted.json", `{"token": ${LOADER_CANARIES.jsonUnquoted}}\n`),
      canaries: [LOADER_CANARIES.jsonUnquoted],
      // A JSON flow mapping with a bare scalar is valid YAML, so the loader reads it as a
      // setting and the resolver fails later on the missing keys without echoing anything.
      // JSON.parse is the positive control here: its message quotes a window of the source.
      libraryThrows: false,
      jsonParseCarriesFragment: true,
      expected: () => "TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY (or access_key and secret_key arguments) are required for Tenable Vulnerability Management.",
    },
    {
      label: "JSON short file",
      file: write("short.json", `{"token":${LOADER_CANARIES.jsonShort}}`),
      canaries: [LOADER_CANARIES.jsonShort],
      libraryThrows: false,
      jsonParseCarriesCanary: true,
      expected: () => "TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY (or access_key and secret_key arguments) are required for Tenable Vulnerability Management.",
    },
    {
      label: "EISDIR",
      file: (() => {
        const pathname = join(dir, "config-dir.yaml");
        mkdirSync(pathname);
        return pathname;
      })(),
      canaries: [],
      libraryThrows: false,
      expected: (pathname) => `Unable to read Tenable config file ${pathname} (EISDIR)`,
    },
    {
      label: "ENOENT",
      file: join(dir, "missing.yaml"),
      canaries: [],
      libraryThrows: false,
      expected: (pathname) => `Unable to read Tenable config file ${pathname} (ENOENT)`,
    },
    ...(process.getuid?.() === 0 ? [] : [{
      label: "EACCES",
      file: (() => {
        const pathname = write("unreadable.yaml", `access_key: ${LOADER_CANARIES.jsonMultiline}\n`);
        chmodSync(pathname, 0o000);
        return pathname;
      })(),
      canaries: [LOADER_CANARIES.jsonMultiline],
      libraryThrows: false,
      expected: (pathname) => `Unable to read Tenable config file ${pathname} (EACCES)`,
    }]),
  ];
  assert.ok(readFileSync(cases[3].file, "utf8").length <= 20, "the short JSON fixture stays within the size JSON.parse quotes whole");

  for (const entry of cases) {
    if (entry.libraryThrows) {
      // Positive control: the parser's own message quotes the file contents.
      assert.throws(() => parseYaml(readFileSync(entry.file, "utf8")), (error) => {
        assert.ok(entry.canaries.some((canary) => error.message.includes(canary)), `${entry.label}: positive control expected the library message to carry a canary: ${error.message}`);
        return true;
      });
    }
    if (entry.jsonParseCarriesFragment || entry.jsonParseCarriesCanary) {
      // Positive control for the JSON shapes: JSON.parse quotes a 10-character window
      // around the failure, or the whole source of a file this short.
      assert.throws(() => JSON.parse(readFileSync(entry.file, "utf8")), (error) => {
        if (entry.jsonParseCarriesCanary) assert.ok(error.message.includes(entry.canaries[0]), `${entry.label}: positive control expected the whole canary: ${error.message}`);
        if (entry.jsonParseCarriesFragment) assert.ok(error.message.includes(entry.canaries[0].slice(0, 8)), `${entry.label}: positive control expected a canary fragment: ${error.message}`);
        return true;
      });
    }
    assert.throws(() => resolveTenableConfiguration({ config_file: entry.file, url: "https://cloud.tenable.com" }, EMPTY_ENV), (error) => {
      assert.equal(error.message, entry.expected(entry.file), `${entry.label}: resolver message`);
      assertNoLoaderLeak(error.message, entry.canaries, `${entry.label} resolver`);
      return true;
    });
    const toolText = await checkAccessText(entry.file);
    assertNoLoaderLeak(toolText, entry.canaries, `${entry.label} check_access`);
    assert.ok(toolText.includes(entry.expected(entry.file)), `${entry.label}: check_access carries the fixed loader text: ${toolText}`);
  }

  // A key on a scrub list does not rescue a message that quotes the source: the fixed
  // text never depends on which key the file used.
  const bearerLine = write("bearer.yaml", `secret_key: ${LOADER_CANARIES.yamlNestedKey}: Bearer ${LOADER_CANARIES.yamlNestedBearer}\n`);
  assert.throws(() => resolveTenableConfiguration({ config_file: bearerLine }, EMPTY_ENV), (error) => {
    assert.equal(error.message, `Unable to parse Tenable config file: invalid YAML in ${bearerLine} at line 1 (INVALID_YAML)`);
    return true;
  });
  const shape = write("list.yaml", "- just\n- a list\n");
  assert.throws(() => resolveTenableConfiguration({ config_file: shape }, EMPTY_ENV), new RegExp(`Unable to parse Tenable config file: .* must contain a YAML mapping of settings \\(INVALID_CONFIG_SHAPE\\)`));
});

test("TenableApiClient sends the X-ApiKeys header, walks pagination, and redacts keys from errors", async () => {
  const log = [];
  const routes = healthyRoutes();
  routes["GET /exclusions"] = { exclusions: [{ id: 1, name: "one" }, { id: 2, name: "two" }], pagination: { total: 3 } };
  const clients = clientsFor(routes, { log });
  const page = await clients.vm.listExclusions();
  assert.equal(page.items.length, 2);
  assert.equal(page.total, 3);
  assert.equal(page.truncated, true);
  assert.equal(log[0].headers["X-ApiKeys"], "accessKey=access-key-123456;secretKey=secret-key-654321");
  assert.ok(log[0].url.includes("limit=200"), log[0].url);
  assert.ok(log.some((entry) => entry.url.includes("offset=2")), "second page requested");

  const failing = createTenableClients(vmConfig(), {
    fetchImpl: async () => new Response("denied for accessKey=access-key-123456;secretKey=secret-key-654321", { status: 403 }),
    sleepImpl: async () => {},
  });
  await assert.rejects(() => failing.vm.listScans(), (error) => {
    assert.equal(error.status, 403);
    assert.ok(!error.message.includes("secret-key-654321"), error.message);
    assert.ok(!error.message.includes("denied for"), `non-JSON bodies are never echoed: ${error.message}`);
    assert.match(error.message, /403[^;]*; non-JSON text\/plain response body \(66 bytes, not echoed\)/);
    return true;
  });

  const jsonFailure = createTenableClients(vmConfig(), {
    fetchImpl: async () => jsonResponse({ error: "invalid credentials accessKey=access-key-123456;secretKey=secret-key-654321" }, 401),
    sleepImpl: async () => {},
  });
  await assert.rejects(() => jsonFailure.vm.listScans(), (error) => {
    assert.equal(error.status, 401);
    assert.ok(error.message.includes("invalid credentials"), "documented JSON error fields are kept");
    assert.ok(!error.message.includes("secret-key-654321"), error.message);
    assert.ok(error.message.includes("[REDACTED]"), error.message);
    return true;
  });
});

function fullPageFetch(collectionKey, pageLimit, options = {}) {
  const { shortPageAt, total } = options;
  return async (url) => {
    const parsed = new URL(url);
    const offset = Number(parsed.searchParams.get("offset") ?? "0");
    const page = offset / pageLimit;
    const count = shortPageAt !== undefined && page >= shortPageAt ? 1 : pageLimit;
    const items = Array.from({ length: count }, (_, index) => ({ uuid: `${collectionKey}-${offset + index}`, name: `${collectionKey} ${offset + index}`, scanner_count: 1 }));
    return jsonResponse(total === undefined ? { [collectionKey]: items } : { [collectionKey]: items, pagination: { total } });
  };
}

test("listPaginated marks a walk that exhausts maxPages on full pages without pagination.total as truncated", async () => {
  const capped = createTenableClients(vmConfig(), { fetchImpl: fullPageFetch("networks", 2), sleepImpl: async () => {} });
  const cappedPage = await capped.vm.listPaginated("/networks", "networks", {}, { pageLimit: 2, maxPages: 3 });
  assert.equal(cappedPage.items.length, 6, "every permitted page was fetched");
  assert.equal(cappedPage.total, null, "no total was reported, so the page carries null rather than a number");
  assert.equal(cappedPage.truncated, true, "leaving the loop at the page cap is a partial inventory");
  assert.match(cappedPage.reason, /stopped at the 3-page cap/);

  const short = createTenableClients(vmConfig(), { fetchImpl: fullPageFetch("networks", 2, { shortPageAt: 2 }), sleepImpl: async () => {} });
  const shortPage = await short.vm.listPaginated("/networks", "networks", {}, { pageLimit: 2, maxPages: 3 });
  assert.equal(shortPage.items.length, 5);
  assert.equal(shortPage.truncated, false, "a short page ends the collection");

  const totalled = createTenableClients(vmConfig(), { fetchImpl: fullPageFetch("networks", 2, { total: 6 }), sleepImpl: async () => {} });
  const totalledPage = await totalled.vm.listPaginated("/networks", "networks", {}, { pageLimit: 2, maxPages: 3 });
  assert.equal(totalledPage.items.length, 6);
  assert.equal(totalledPage.total, 6);
  assert.equal(totalledPage.truncated, false, "reaching the reported total on the last permitted page is complete");
});

test("a page-capped inventory without pagination.total demotes the finding instead of passing", async () => {
  const routes = healthyRoutes();
  const fallback = routerFetch(routes);
  const networksFetch = fullPageFetch("networks", 50);
  const clients = createTenableClients(vmConfig(), {
    fetchImpl: async (url, init) => (new URL(url).pathname === "/networks" ? networksFetch(url) : fallback(url, init)),
    sleepImpl: async () => {},
    exportPollMs: 0,
    exportTimeoutMs: 5_000,
  });
  const data = await collectTenableSensorCoverageData(clients, { now: NOW });
  assert.equal(data.networks.status, "ok");
  assert.equal(data.networks.truncated, true);
  assert.equal(data.networks.seen, 200 * 50, "the walk stopped at the default page cap");
  assert.equal(data.networks.total, null, "no total was reported, so none is invented");

  const result = assessTenableSensorCoverage(data, { now: NOW });
  const networks = result.findings.find((item) => item.id === "TENABLE-09");
  assert.equal(networks.status, "warn", networks.summary);
  assert.match(networks.summary, /Only 10000 of unknown records were retrieved \(the walk stopped at the 200-page cap\), so the verdict is capped at warn/);
  assert.ok(result.errors.some((error) => error.includes("partial view (10000 of unknown records retrieved; the walk stopped at the 200-page cap)")), JSON.stringify(result.errors));
});

test("TenableApiClient retries 429 and 5xx responses honoring retry-after", async () => {
  let calls = 0;
  const delays = [];
  const clients = createTenableClients(vmConfig(), {
    fetchImpl: async () => {
      calls += 1;
      if (calls === 1) return jsonResponse({ error: "slow down" }, 429, { "retry-after": "1" });
      if (calls === 2) return jsonResponse({ error: "upstream" }, 503);
      return jsonResponse({ scans: [{ id: 1, name: "ok" }] });
    },
    sleepImpl: async (ms) => { delays.push(ms); },
  });
  const scans = await clients.vm.listScans();
  assert.equal(scans.length, 1);
  assert.equal(calls, 3);
  assert.equal(delays[0], 1000);
  assert.equal(delays.length, 2);

  const exhausted = createTenableClients(vmConfig(), {
    fetchImpl: async () => jsonResponse({ error: "down" }, 502),
    sleepImpl: async () => {},
    retryLimit: 1,
  });
  await assert.rejects(() => exhausted.vm.listScans(), /502/);
});

test("TenableApiClient runs the export workflow: request, poll status, download every chunk", async () => {
  const log = [];
  const routes = healthyRoutes();
  let polls = 0;
  const clients = createTenableClients(vmConfig(), {
    fetchImpl: async (url, init) => {
      const parsed = new URL(url);
      const key = `${(init?.method ?? "GET").toUpperCase()} ${parsed.pathname}`;
      log.push(key);
      if (key === "GET /assets/export/asset-export-1/status") {
        polls += 1;
        if (polls === 1) return jsonResponse({ status: "PROCESSING", chunks_available: [] });
        return jsonResponse({ status: "FINISHED", chunks_available: [1, 2], chunks_failed: [], total_chunks: 2 });
      }
      if (key === "GET /assets/export/asset-export-1/chunks/2") return jsonResponse([{ id: "a-3" }]);
      return routerFetch(routes)(url, init);
    },
    sleepImpl: async () => {},
    exportPollMs: 0,
  });
  const result = await clients.vm.exportAssets();
  assert.equal(result.status, "FINISHED");
  assert.equal(result.records.length, 3);
  assert.equal(result.fetchedChunks, 2);
  assert.equal(result.truncated, false);
  assert.equal(log[0], "POST /assets/export");
  assert.equal(polls, 2);

  const capped = await clientsFor(partialRoutes()).vm.exportAssets(1);
  assert.equal(capped.fetchedChunks, 1);
  assert.equal(capped.totalChunks, 3);
  assert.equal(capped.truncated, true);
});

test("checkTenableAccess reports healthy when every surface is readable by an Administrator key", async () => {
  const result = await checkTenableAccess(clientsFor(healthyRoutes()));
  assert.equal(result.status, "healthy");
  assert.equal(result.callerIsAdministrator, true);
  assert.ok(result.platform.includes("cloud.tenable.com"));
  const configured = result.surfaces.filter((surface) => surface.status !== "not_configured");
  assert.ok(configured.every((surface) => surface.status === "readable"));
  assert.ok(result.surfaces.some((surface) => surface.name === "sc_scans" && surface.status === "not_configured"));
});

test("checkTenableAccess reports limited access and names the missing role when surfaces are forbidden", async () => {
  const routes = healthyRoutes();
  routes["GET /users"] = { users: healthyUsers().map(({ id, uuid, username, email }) => ({ id, uuid, username, email })) };
  const clients = createTenableClients(vmConfig(), {
    fetchImpl: async (url, init) => {
      const parsed = new URL(url);
      if (parsed.pathname === "/audit-log/v1/events" || parsed.pathname === "/access-control/v1/roles") return jsonResponse({ error: "forbidden" }, 403);
      return routerFetch(routes)(url, init);
    },
    sleepImpl: async () => {},
  });
  const result = await checkTenableAccess(clients);
  assert.equal(result.status, "limited");
  assert.equal(result.callerIsAdministrator, false);
  const auditLog = result.surfaces.find((surface) => surface.name === "audit_log");
  assert.equal(auditLog.status, "forbidden");
  assert.ok(result.notes.some((note) => note.includes("audit_log needs the Administrator role")));
  assert.ok(result.recommendedNextStep.includes("Administrator"));
});

test("healthy fixture yields passing verdicts and every control carries framework mappings", async () => {
  const results = await runAll(clientsFor(healthyRoutes()), { expectedAssetCount: 2 });
  const findings = allFindings(results);
  const ids = new Set(findings.map((item) => item.id.slice(0, 10)));
  for (let control = 1; control <= 20; control += 1) {
    assert.ok(ids.has(`TENABLE-${String(control).padStart(2, "0")}`), `control ${control} missing`);
  }
  for (const item of findings) {
    assert.ok(item.mappings.length >= 7, `${item.id} mappings`);
    assert.ok(item.mappings.some((mapping) => mapping.startsWith("FedRAMP")), `${item.id} FedRAMP mapping`);
    assert.ok(["pass", "warn", "fail", "manual"].includes(item.status));
    assert.ok(["critical", "high", "medium", "low", "info"].includes(item.severity));
    if (!item.id.endsWith("-SC")) assert.ok(!item.summary.includes("could not be read"), `${item.id}: ${item.summary}`);
  }
  for (const result of results) assert.deepEqual(result.errors, [], `${result.category} errors`);
  assert.equal(byId(results, "TENABLE-02").status, "pass");
  assert.equal(byId(results, "TENABLE-04").status, "pass");
  assert.equal(byId(results, "TENABLE-13").status, "pass");
  assert.equal(byId(results, "TENABLE-17").status, "pass");
  assert.equal(byId(results, "TENABLE-01").status, "pass");
  assert.equal(byId(results, "TENABLE-08").status, "pass");
  assert.equal(byId(results, "TENABLE-10").status, "pass");
  assert.equal(byId(results, "TENABLE-11").status, "pass");
  assert.equal(byId(results, "TENABLE-19").status, "pass");
  assert.ok(findings.filter((item) => item.status === "pass").length >= 8, JSON.stringify(findings.map((item) => [item.id, item.status])));
  for (const item of findings.filter((entry) => entry.id.endsWith("-SC"))) {
    assert.equal(item.status, "manual");
    assert.ok(item.summary.includes("not configured"), item.summary);
  }
});

test("failing fixture: stale schedules, disabled MFA, and SLA breaches fail", async () => {
  const routes = healthyRoutes();
  const oldSeconds = Math.floor((NOW - 120 * 86_400_000) / 1000);
  routes["GET /scans"] = { scans: [{ id: 10, name: "Stale", enabled: true, rrules: "FREQ=WEEKLY", status: "completed", last_modification_date: oldSeconds, wizard_uuid: "tmpl-basic" }] };
  routes["GET /users"] = { users: healthyUsers().map((user) => ({ ...user, two_factor: { sms_enabled: 0 }, ui_saml_only: false })) };
  routes["GET /vulns/export/vuln-export-1/chunks/1"] = [{ severity: "critical", state: "OPEN", first_found: new Date(NOW - 60 * 86_400_000).toISOString(), plugin: { id: 1, vpr: { score: 9.5 } } }];
  const results = await runAll(clientsFor(routes));
  assert.equal(byId(results, "TENABLE-02").status, "fail");
  assert.equal(byId(results, "TENABLE-10").status, "fail");
  assert.equal(byId(results, "TENABLE-15").status, "fail");
});

test("false-pass self-check (a): every endpoint forbidden yields only manual verdicts naming the cause", async () => {
  const results = await runAll(clientsFor(healthyRoutes(), { status: 403 }));
  const findings = allFindings(results);
  assert.ok(findings.length >= 20);
  for (const item of findings) {
    assert.notEqual(item.status, "pass", `${item.id} passed on forbidden data`);
    assert.equal(item.status, "manual", `${item.id} should be manual: ${item.summary}`);
    assert.ok(/could not be read|not configured/.test(item.summary), item.summary);
    assert.ok(/A human must collect|not configured/.test(item.summary), item.summary);
  }
  for (const result of results) assert.ok(result.errors.length > 0, `${result.category} should record errors`);
});

test("false-pass self-check (b): empty inventories never pass except where emptiness is compliant", async () => {
  const results = await runAll(clientsFor(emptyRoutes()));
  const findings = allFindings(results);
  const passing = findings.filter((item) => item.status === "pass").map((item) => item.id).sort();
  assert.deepEqual(passing, ["TENABLE-13"], JSON.stringify(findings.map((item) => [item.id, item.status, item.summary])));
  assert.ok(byId(results, "TENABLE-13").summary.includes("emptiness is compliant"));
  assert.equal(byId(results, "TENABLE-20").status, "warn");
  assert.ok(byId(results, "TENABLE-20").summary.includes("not confirmed as Administrator"));
  assert.ok(byId(results, "TENABLE-08").summary.includes("returned zero scanners"));
  assert.ok(byId(results, "TENABLE-19").summary.includes("not evident in the observable window"));
  for (const id of ["TENABLE-01", "TENABLE-02", "TENABLE-03", "TENABLE-17"]) {
    assert.equal(byId(results, id).status, "fail", `${id} should fail on emptiness`);
  }
  for (const id of ["TENABLE-04", "TENABLE-05", "TENABLE-07", "TENABLE-08", "TENABLE-10", "TENABLE-14", "TENABLE-15", "TENABLE-19"]) {
    assert.equal(byId(results, id).status, "manual", `${id} should be manual on emptiness`);
  }
});

test("false-pass self-check (c): partial inventories and a non-Administrator key never pass", async () => {
  const results = await runAll(clientsFor(partialRoutes()), { maxChunks: 1, expectedAssetCount: 2 });
  const findings = allFindings(results);
  for (const item of findings) {
    assert.notEqual(item.status, "pass", `${item.id} passed on partial data: ${item.summary}`);
  }
  const exclusions = byId(results, "TENABLE-13");
  assert.equal(exclusions.status, "warn");
  assert.ok(exclusions.summary.includes("1 of 250"), exclusions.summary);
  const credentialed = byId(results, "TENABLE-04");
  assert.ok(["warn", "manual"].includes(credentialed.status));
  assert.ok(credentialed.evidence.chunks_fetched === "1/3", JSON.stringify(credentialed.evidence));
  const vpr = byId(results, "TENABLE-14");
  assert.ok(vpr.summary.includes("1 of 3 chunks"), vpr.summary);
  assert.ok(results.some((result) => result.errors.some((error) => error.includes("partial view"))));
});

test("undated items are never counted as fresh and cap the verdict at warn", async () => {
  const routes = healthyRoutes();
  routes["GET /scans"] = { scans: [{ id: 10, name: "Undated", enabled: true, rrules: "FREQ=WEEKLY", status: "completed", wizard_uuid: "tmpl-basic" }] };
  routes["GET /scanners/null/agents"] = { agents: [{ id: 1, uuid: "ag-1", name: "host-1", status: "on", core_version: "10.8.0", plugin_feed_id: RECENT_PLUGIN_SET, groups: [{ name: "prod" }] }], pagination: { total: 1 } };
  const results = await runAll(clientsFor(routes));
  const schedule = byId(results, "TENABLE-02");
  assert.equal(schedule.status, "warn");
  assert.ok(schedule.summary.includes("never run or expose no launch date"), schedule.summary);
  const agents = byId(results, "TENABLE-05");
  assert.notEqual(agents.status, "pass");
});

test("disabled enabling flags do not support pass", async () => {
  const routes = healthyRoutes();
  routes["GET /scans"] = { scans: [{ id: 10, name: "Disabled", enabled: false, rrules: "FREQ=WEEKLY", status: "completed", last_modification_date: RECENT_SECONDS, wizard_uuid: "tmpl-pci" }] };
  routes["GET /exclusions"] = { exclusions: [{ id: 1, name: "Forever", description: "x", members: "10.0.0.5", schedule: { enabled: false } }], pagination: { total: 1 } };
  const results = await runAll(clientsFor(routes));
  assert.equal(byId(results, "TENABLE-02").status, "fail");
  assert.equal(byId(results, "TENABLE-17").status, "fail");
  assert.equal(byId(results, "TENABLE-13").status, "fail");
});

test("control 1 reads GET /policies/{policy_id} for every policy referenced by a scan and judges safe checks, port range, and plugin families", async () => {
  const log = [];
  const healthy = await runAll(clientsFor(healthyRoutes(), { log }));
  const passing = byId(healthy, "TENABLE-01");
  assert.equal(passing.status, "pass");
  assert.ok(passing.summary.includes("safe_checks=yes"), passing.summary);
  assert.deepEqual(log.filter((entry) => /^GET \/policies\/\d+$/.test(entry.key)).map((entry) => entry.key).sort(), ["GET /policies/1", "GET /policies/2"]);
  assert.equal(passing.evidence.policies_evaluated.length, 2);
  assert.equal(passing.evidence.policies_evaluated[0].safe_checks, "yes");
  assert.equal(passing.evidence.policies_evaluated[0].plugin_families.enabled, 2);

  const unsafe = healthyRoutes();
  unsafe["GET /policies/2"] = healthyPolicyDetails({ settings: { safe_checks: "no" } });
  const unsafeFinding = byId(await runAll(clientsFor(unsafe)), "TENABLE-01");
  assert.equal(unsafeFinding.status, "fail");
  assert.ok(unsafeFinding.summary.includes("PCI policy [safe_checks is no"), unsafeFinding.summary);

  const disabledFamilies = healthyRoutes();
  disabledFamilies["GET /policies/1"] = healthyPolicyDetails({ plugins: { Windows: { status: "disabled" }, "Web Servers": { status: "disabled" } } });
  const disabledFinding = byId(await runAll(clientsFor(disabledFamilies)), "TENABLE-01");
  assert.equal(disabledFinding.status, "fail");
  assert.ok(disabledFinding.summary.includes("all 2 plugin families are disabled"), disabledFinding.summary);

  const customPorts = healthyRoutes();
  customPorts["GET /policies/1"] = healthyPolicyDetails({ settings: { portscan_range: "22,80,443" } });
  const customFinding = byId(await runAll(clientsFor(customPorts)), "TENABLE-01");
  assert.equal(customFinding.status, "warn");
  assert.ok(customFinding.summary.includes("custom range (22,80,443)"), customFinding.summary);

  const mostlyDisabled = healthyRoutes();
  mostlyDisabled["GET /policies/1"] = healthyPolicyDetails({ plugins: { Windows: { status: "enabled" }, "Web Servers": { status: "disabled" }, DNS: { status: "disabled" } } });
  assert.equal(byId(await runAll(clientsFor(mostlyDisabled)), "TENABLE-01").status, "warn");
});

test("control 1 is manual only when the policy details read is refused or the policy exposes no settings", async () => {
  const forbidden = healthyRoutes();
  forbidden["GET /policies/1"] = { __status: 403 };
  forbidden["GET /policies/2"] = { __status: 403 };
  const refused = byId(await runAll(clientsFor(forbidden)), "TENABLE-01");
  assert.equal(refused.status, "manual");
  assert.ok(refused.summary.includes("Standard [32]"), refused.summary);
  assert.equal(refused.evidence.policy_details_status, "forbidden");

  const partiallyForbidden = healthyRoutes();
  partiallyForbidden["GET /policies/2"] = { __status: 403 };
  const partial = byId(await runAll(clientsFor(partiallyForbidden)), "TENABLE-01");
  assert.equal(partial.status, "manual");
  assert.ok(partial.summary.includes("1 of 2 referenced scan policies were verified"), partial.summary);

  const noSettings = healthyRoutes();
  noSettings["GET /policies/1"] = { uuid: "tmpl-basic" };
  const unverified = byId(await runAll(clientsFor(noSettings)), "TENABLE-01");
  assert.equal(unverified.status, "manual");
  assert.ok(unverified.summary.includes("do not expose safe_checks"), unverified.summary);

  const noPolicyIds = healthyRoutes();
  noPolicyIds["GET /scans"] = { scans: healthyRoutes()["GET /scans"].scans.map(({ policy_id, ...scan }) => scan) };
  const unlinked = byId(await runAll(clientsFor(noPolicyIds)), "TENABLE-01");
  assert.equal(unlinked.status, "manual");
  assert.ok(unlinked.summary.includes("exposes a policy_id"), unlinked.summary);
});

test("control 11 treats the tenant-wide All Users group as broad, alongside AllUsers and AllTags", async () => {
  const allUsersGroup = healthyRoutes();
  allUsersGroup["GET /api/v3/access-control/permissions"] = {
    permissions: [
      { permission_uuid: "p-default", name: "All Assets [CanScan, CanView]", actions: ["CanView", "CanScan"], objects: [{ type: "AllAssets" }], subjects: [{ type: "UserGroup", uuid: "00000000-0000-0000-0000-000000000000", name: "All Users" }], created_by: "System" },
    ],
  };
  const groupFinding = byId(await runAll(clientsFor(allUsersGroup)), "TENABLE-11");
  assert.equal(groupFinding.status, "fail");
  assert.ok(groupFinding.summary.includes("00000000-0000-0000-0000-000000000000"), groupFinding.summary);
  assert.deepEqual(groupFinding.evidence.broad_permissions, ["All Assets [CanScan, CanView]"]);

  const allTags = healthyRoutes();
  allTags["GET /api/v3/access-control/permissions"] = {
    permissions: [{ permission_uuid: "p-tags", name: "Everyone edits tags", actions: ["CanEdit"], objects: [{ type: "AllTags" }], subjects: [{ type: "AllUsers" }] }],
  };
  assert.equal(byId(await runAll(clientsFor(allTags)), "TENABLE-11").status, "fail");

  const readOnly = healthyRoutes();
  readOnly["GET /api/v3/access-control/permissions"] = {
    permissions: [{ permission_uuid: "p-view", name: "Everyone views", actions: ["CanView"], objects: [{ type: "AllAssets" }], subjects: [{ type: "UserGroup", uuid: "00000000-0000-0000-0000-000000000000", name: "All Users" }] }],
  };
  assert.equal(byId(await runAll(clientsFor(readOnly)), "TENABLE-11").status, "pass");
});

test("control 19 ignores this tool's own export shape and only counts jobs within the documented three-day window", async () => {
  const ownRuns = healthyRoutes();
  ownRuns["GET /vulns/export/status"] = {
    exports: [
      { uuid: "prior-run-1", status: "FINISHED", created: NOW - 86_400_000, num_assets_per_chunk: 5000, filters: { state: ["OPEN", "REOPENED", "FIXED"], since: 1 } },
      { uuid: "prior-run-2", status: "FINISHED", created: NOW - 2 * 86_400_000, num_assets_per_chunk: 5000, filters: { state: ["open", "reopened", "fixed"], since: 1 } },
    ],
  };
  ownRuns["GET /assets/export/status"] = {
    exports: [
      { uuid: "prior-asset-1", status: "FINISHED", created: NOW - 86_400_000, num_assets_per_chunk: 10000, filters: {} },
      { uuid: "prior-asset-2", status: "FINISHED", created: NOW - 2 * 86_400_000, num_assets_per_chunk: 10000 },
    ],
  };
  const selfOnly = byId(await runAll(clientsFor(ownRuns)), "TENABLE-19");
  assert.equal(selfOnly.status, "manual");
  assert.equal(selfOnly.evidence.external_export_jobs_in_window, 0);
  assert.equal(selfOnly.evidence.excluded_own_shaped_jobs.length, 4);
  assert.ok(selfOnly.summary.includes("previous 3 days"), selfOnly.summary);

  const stale = healthyRoutes();
  stale["GET /vulns/export/status"] = { exports: [externalExportJob("old-1", NOW - 10 * 86_400_000), externalExportJob("old-2", NOW - 12 * 86_400_000)] };
  stale["GET /assets/export/status"] = { exports: [] };
  const staleFinding = byId(await runAll(clientsFor(stale)), "TENABLE-19");
  assert.equal(staleFinding.status, "manual");
  assert.equal(staleFinding.evidence.external_export_jobs_in_window, 0);

  const singleDay = healthyRoutes();
  singleDay["GET /vulns/export/status"] = { exports: [externalExportJob("one-1", NOW - 3_600_000), externalExportJob("one-2", NOW - 7_200_000)] };
  singleDay["GET /assets/export/status"] = { exports: [] };
  const singleDayFinding = byId(await runAll(clientsFor(singleDay)), "TENABLE-19");
  assert.equal(singleDayFinding.status, "warn");
  assert.equal(singleDayFinding.evidence.external_export_days.length, 1);

  const healthy = byId(await runAll(clientsFor(healthyRoutes())), "TENABLE-19");
  assert.equal(healthy.status, "pass");
  assert.equal(healthy.evidence.external_export_days.length, 2);
  assert.ok(healthy.summary.includes("report schedules are not exposed"), healthy.summary);
});

test("control 8 evaluates every scanner entry exposing loaded_plugin_set and never passes on zero evaluated scanners", async () => {
  const cloudStale = healthyRoutes();
  cloudStale["GET /scanners"] = { scanners: [{ id: 1, name: "US Cloud Scanner", status: "on", linked: 1, type: "local", pool: true, group: true, loaded_plugin_set: "202601010000" }] };
  const staleFinding = byId(await runAll(clientsFor(cloudStale)), "TENABLE-08");
  assert.equal(staleFinding.status, "fail");
  assert.deepEqual(staleFinding.evidence.stale_scanners, ["US Cloud Scanner (202601010000)"]);

  const cloudUndated = healthyRoutes();
  cloudUndated["GET /scanners"] = { scanners: [{ id: 1, name: "US Cloud Scanner", status: "on", linked: 1, type: "local", pool: true, group: true }] };
  const undatedFinding = byId(await runAll(clientsFor(cloudUndated)), "TENABLE-08");
  assert.equal(undatedFinding.status, "manual");
  assert.ok(undatedFinding.summary.includes("cannot pass"), undatedFinding.summary);

  const noScanners = healthyRoutes();
  noScanners["GET /scanners"] = { scanners: [] };
  const noneFinding = byId(await runAll(clientsFor(noScanners)), "TENABLE-08");
  assert.equal(noneFinding.status, "manual");
  assert.ok(noneFinding.summary.includes("returned zero scanners"), noneFinding.summary);

  const undatedInstance = healthyRoutes();
  undatedInstance["GET /scanners"] = { scanners: [...healthyRoutes()["GET /scanners"].scanners, { id: 2, name: "Appliance without plugin set", status: "on", linked: 1, type: "managed", pool: false, group: false }] };
  const mixed = byId(await runAll(clientsFor(undatedInstance)), "TENABLE-08");
  assert.equal(mixed.status, "warn");
  assert.deepEqual(mixed.evidence.undated_scanners, ["Appliance without plugin set"]);
});

test("control 10 requires at least one enabled user before it can pass", async () => {
  const noEnabledFlag = healthyRoutes();
  noEnabledFlag["GET /users"] = { users: healthyUsers().map(({ enabled, ...user }) => user) };
  const missing = byId(await runAll(clientsFor(noEnabledFlag)), "TENABLE-10");
  assert.equal(missing.status, "manual");
  assert.equal(missing.evidence.enabled_users, 0);
  assert.equal(missing.evidence.users_without_enabled_flag, 2);
  assert.ok(missing.summary.includes("none has enabled=true"), missing.summary);

  const allDisabled = healthyRoutes();
  allDisabled["GET /users"] = { users: healthyUsers().map((user) => ({ ...user, enabled: false })) };
  assert.equal(byId(await runAll(clientsFor(allDisabled)), "TENABLE-10").status, "manual");

  const someMissing = healthyRoutes();
  someMissing["GET /users"] = { users: [healthyUsers()[0], (({ enabled, ...user }) => user)(healthyUsers()[1])] };
  const partial = byId(await runAll(clientsFor(someMissing)), "TENABLE-10");
  assert.equal(partial.status, "warn");
  assert.equal(partial.evidence.users_without_enabled_flag, 1);
});

test("integration guide cites the v1 asset export that the code calls", () => {
  const guide = readFileSync(join(import.meta.dirname, "..", "..", "src", "content", "docs", "docs", "integrations", "tenable.md"), "utf8");
  assert.ok(guide.includes("https://developer.tenable.com/reference/export-assets-v1"), "guide must cite export-assets-v1");
  assert.ok(!guide.includes("export-assets-v2"), "guide must not cite the v2 asset export the code does not call");
  assert.ok(guide.includes("https://developer.tenable.com/reference/policies-details"), "guide must cite policies-details");
  assert.ok(!/[\u2014]/.test(guide), "guide must not contain em dashes");
});

test("Security Center controls become manual naming the missing URL when not configured, and read x-apikey when configured", async () => {
  const withoutSc = await runAll(clientsFor(healthyRoutes()));
  const scFindings = allFindings(withoutSc).filter((item) => item.id.endsWith("-SC"));
  assert.ok(scFindings.length >= 3);
  for (const item of scFindings) {
    assert.equal(item.status, "manual");
    assert.ok(item.summary.includes("TENABLE_SC_URL"), item.summary);
  }

  const log = [];
  const config = resolveTenableConfiguration({ url: "https://sc.example.internal", access_key: "sc-access-key", secret_key: "sc-secret-key", config_file: EMPTY_CONFIG_FILE }, EMPTY_ENV);
  const clients = createTenableClients(config, {
    fetchImpl: async (url, init) => {
      log.push({ url: String(url), headers: init.headers });
      return jsonResponse({ error_code: 0, response: { usable: [], manageable: [] } });
    },
    sleepImpl: async () => {},
  });
  const results = await runAll(clients);
  assert.equal(log[0].headers["x-apikey"], "accesskey=sc-access-key; secretkey=sc-secret-key;");
  assert.ok(log.every((entry) => entry.url.includes("/rest/")));
  const vmOnly = allFindings(results).filter((item) => !item.id.endsWith("-SC"));
  for (const item of vmOnly) {
    assert.notEqual(item.status, "pass", `${item.id} passed without a VM tenant`);
  }
  for (const item of allFindings(results).filter((entry) => entry.id.endsWith("-SC"))) {
    assert.notEqual(item.status, "pass", `${item.id} passed on an empty Security Center inventory`);
  }
});

test("exportTenableAuditBundle writes the documented layout, a paired zip, and never overwrites a prior bundle", async () => {
  const root = mkdtempSync(join(tmpdir(), "tenable-bundle-"));
  const clients = clientsFor(healthyRoutes());
  const first = await exportTenableAuditBundle(clients, root, { now: NOW });
  assert.ok(existsSync(first.outputDir));
  assert.ok(existsSync(first.zipPath));
  assert.equal(first.zipPath, `${first.outputDir}.zip`);
  for (const file of [
    "core_data/scans.json",
    "core_data/assets_export.json",
    "core_data/vulns_export.json",
    "core_data/users.json",
    "analysis/findings.json",
    "analysis/scan_program.json",
    "analysis/sensor_coverage.json",
    "analysis/access_control.json",
    "analysis/vulnerability_management.json",
    "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md",
    "compliance/fedramp/fedramp_compliance_report.md",
    "compliance/cmmc/cmmc_compliance_report.md",
    "compliance/soc2/soc2_compliance_report.md",
    "compliance/cis/cis_compliance_report.md",
    "compliance/pci_dss/pci_dss_compliance_report.md",
    "compliance/disa_stig/disa_stig_compliance_report.md",
    "compliance/irap/irap_compliance_report.md",
    "compliance/ismap/ismap_compliance_report.md",
    "QUICK_REFERENCE.md",
  ]) {
    assert.ok(existsSync(join(first.outputDir, file)), `${file} missing`);
  }
  assert.equal(existsSync(join(first.outputDir, "_errors.log")), false);
  const rawUsers = readFileSync(join(first.outputDir, "core_data/users.json"), "utf8");
  assert.ok(!rawUsers.includes("secret-key-654321"));
  assert.ok(first.findingCount >= 20);

  const second = await exportTenableAuditBundle(clients, root, { now: NOW });
  assert.notEqual(second.outputDir, first.outputDir);
  assert.equal(second.zipPath, `${second.outputDir}.zip`);
  assert.ok(existsSync(first.zipPath));
  assert.equal(readdirSync(root).filter((name) => name.endsWith(".zip")).length, 2);
});

test("exportTenableAuditBundle records _errors.log when collection partially fails", async () => {
  const root = mkdtempSync(join(tmpdir(), "tenable-bundle-errors-"));
  const routes = healthyRoutes();
  const clients = createTenableClients(vmConfig(), {
    fetchImpl: async (url, init) => {
      if (new URL(url).pathname === "/exclusions") return jsonResponse({ error: "forbidden" }, 403);
      return routerFetch(routes)(url, init);
    },
    sleepImpl: async () => {},
    exportPollMs: 0,
  });
  const result = await exportTenableAuditBundle(clients, root, { now: NOW });
  assert.ok(result.errorCount > 0);
  const errors = readFileSync(join(result.outputDir, "_errors.log"), "utf8");
  assert.ok(errors.includes("exclusions"), errors);
  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis/findings.json"), "utf8"));
  assert.equal(findings.find((item) => item.id === "TENABLE-13").status, "manual");
});

const CANARY_BEARER = "CANARY-BEARER-9f8e7d6c5b4a3210";
const CANARY_SESSION = "CANARY-SESSION-0a1b2c3d4e5f6789";
const CANARY_API_KEY = "CANARY-APIKEY-1122334455667788";
const CANARY_URL_TOKEN = "CANARY-URLTOKEN-99aa88bb77cc66dd";
const CANARIES = [CANARY_BEARER, CANARY_SESSION, CANARY_API_KEY, CANARY_URL_TOKEN];
const CANARY_URL = `https://api.example.com/v1/x?token=${CANARY_URL_TOKEN}`;

function htmlCanaryResponse() {
  const body = `<html><head><title>502 Bad Gateway</title></head><body><p>Authorization: Bearer ${CANARY_BEARER}</p>`
    + `<p>Set-Cookie: TNS_SESSIONID=${CANARY_SESSION}; Path=/</p><p>X-ApiKeys: accessKey=${CANARY_API_KEY};secretKey=${CANARY_API_KEY}</p>`
    + `<p>The upstream at ${CANARY_URL} did not answer in time, retry later.</p></body></html>`;
  return new Response(body, { status: 502, headers: { "content-type": "text/html; charset=utf-8" } });
}

function jsonCanaryResponse() {
  return jsonResponse({
    error: `Upstream refused Bearer ${CANARY_BEARER} when calling ${CANARY_URL} mid-sentence; session=${CANARY_SESSION} and api_key=${CANARY_API_KEY} were rejected`,
  }, 400);
}

function assertNoCanary(text, label) {
  for (const canary of CANARIES) assert.ok(!text.includes(canary), `${label}: ${canary} leaked`);
}

function canaryClients(routes, surfaceKey, makeResponse) {
  const fallback = routerFetch(routes);
  return createTenableClients(vmConfig(), {
    fetchImpl: async (url, init) => {
      const parsed = new URL(url);
      const key = `${(init?.method ?? "GET").toUpperCase()} ${parsed.pathname}`;
      if (key === surfaceKey) return makeResponse();
      return fallback(url, init);
    },
    sleepImpl: async () => {},
    exportPollMs: 0,
    exportTimeoutMs: 5_000,
    retryLimit: 1,
  });
}

test("error-body canary sweep: every Tenable surface failing with an HTML 502 or a JSON error body leaks no credential into any tool result, finding, or bundle file", async () => {
  const surfaces = Object.keys(healthyRoutes());
  assert.ok(surfaces.length >= 25, `expected every collector surface to be enumerated, found ${surfaces.length}`);
  const shapes = [
    { name: "html-502", make: htmlCanaryResponse, marker: /non-JSON text\/html response body \(\d+ bytes, not echoed\)/ },
    { name: "json-400", make: jsonCanaryResponse, marker: /\[REDACTED\]/ },
  ];
  for (const shape of shapes) {
    for (const surface of surfaces) {
      const label = `${shape.name} on ${surface}`;
      const clients = canaryClients(healthyRoutes(), surface, shape.make);

      const access = await checkTenableAccess(clients);
      assertNoCanary(JSON.stringify(access), `${label} access check`);
      const probed = access.surfaces.find((entry) => entry.endpoint === surface);
      if (probed) {
        assert.notEqual(probed.status, "readable", `${label}: surface should not be readable`);
        assert.match(probed.error ?? "", shape.marker, `${label}: access error must carry the note`);
      }

      const results = await runAll(clients, { expectedAssetCount: 2 });
      const serialized = JSON.stringify(results);
      assertNoCanary(serialized, `${label} assessments`);
      const errors = results.flatMap((result) => result.errors);
      assert.ok(errors.length > 0, `${label}: the failing surface must be recorded as an error`);
      assert.ok(errors.some((error) => shape.marker.test(error)), `${label}: errors must carry the note: ${JSON.stringify(errors)}`);
      for (const error of errors) assert.ok(!/<html|Bad Gateway|Set-Cookie|TNS_SESSIONID/i.test(error), `${label}: body text echoed: ${error}`);

      const bundle = await exportTenableAuditBundle(clients, mkdtempSync(join(tmpdir(), "tenable-canary-")), { now: NOW });
      const files = readBundleFiles(bundle.outputDir);
      const zipEntries = readZipEntries(bundle.zipPath);
      assert.ok(files.size >= 20 && zipEntries.size >= 20, `${label}: bundle and zip were written`);
      assertSecretsAbsent(assert, files, CANARIES, `${label} bundle`);
      assertSecretsAbsent(assert, zipEntries, CANARIES, `${label} zip`);
      const errorLog = files.get("_errors.log");
      assert.ok(errorLog !== undefined, `${label}: _errors.log must exist`);
      assert.match(errorLog, shape.marker, `${label}: _errors.log must carry the note`);
    }
  }
});

test("export polling, vendor reason strings, Security Center error_msg, and timeouts pass through the redacting sink", async () => {
  const routes = healthyRoutes();
  routes["GET /assets/export/asset-export-1/status"] = { status: "ERROR", chunks_available: [], chunks_failed: [], total_chunks: 0, reason: `worker rejected Bearer ${CANARY_BEARER} for ${CANARY_URL}` };
  const errored = await collectTenableVulnerabilityData(clientsFor(routes), { now: NOW });
  assert.equal(errored.assetExport.status, "error");
  assertNoCanary(errored.assetExport.error, "export reason");
  assert.match(errored.assetExport.error, /ended with status ERROR: worker rejected Bearer \[REDACTED\] for https:\/\/api\.example\.com\/v1\/x\?token=\[REDACTED\]/);
  const vuln = assessTenableVulnerabilityManagement(errored, { now: NOW });
  assertNoCanary(JSON.stringify(vuln), "vulnerability assessment with an errored export");
  assert.equal(vuln.summary.exported_assets, null);

  const stuck = healthyRoutes();
  stuck["GET /assets/export/asset-export-1/status"] = { status: "PROCESSING", chunks_available: [] };
  const slow = createTenableClients(vmConfig(), { fetchImpl: routerFetch(stuck), sleepImpl: async () => {}, exportPollMs: 0, exportTimeoutMs: 0 });
  const timedOut = await slow.vm.exportAssets();
  assert.equal(timedOut.truncated, null, "a walk that never observed a chunk list has no truncation flag to report");
  assert.equal(timedOut.fetchedChunks, null);
  assert.equal(timedOut.totalChunks, null);
  assert.equal(timedOut.exportUuid, "asset-export-1", "the export id stays with the result");
  assert.equal(timedOut.endpoint, "GET /assets/export/asset-export-1/status", "the last poll is the request that reported the state");
  assert.match(timedOut.status, /^TIMEOUT\(PROCESSING\)$/);
  const sensorData = await collectTenableSensorCoverageData(slow, { now: NOW });
  assert.equal(sensorData.assetExport.status, "error");
  assert.match(sensorData.assetExport.error, /did not finish within 0s/);
  const sensor = assessTenableSensorCoverage(sensorData, { now: NOW, expectedAssetCount: 2 });
  assert.equal(sensor.findings.find((item) => item.id === "TENABLE-03").status, "manual");
  assert.equal(sensor.summary.exported_assets, null);

  const scConfig = resolveTenableConfiguration({ url: "https://sc.example.internal", access_key: "sc-access-key", secret_key: "sc-secret-key", config_file: EMPTY_CONFIG_FILE }, EMPTY_ENV);
  const sc = createTenableClients(scConfig, {
    fetchImpl: async () => jsonResponse({ error_code: 143, error_msg: `Cookie TNS_SESSIONID=${CANARY_SESSION} is not authorized for ${CANARY_URL}; Authorization: Bearer ${CANARY_BEARER}` }),
    sleepImpl: async () => {},
  });
  const scResults = await runAll(sc);
  assertNoCanary(JSON.stringify(scResults), "Security Center error_msg");
  const scErrors = scResults.flatMap((result) => result.errors);
  assert.ok(scErrors.some((error) => error.includes("error_code 143") && error.includes("[REDACTED]")), JSON.stringify(scErrors));

  const transport = createTenableClients(vmConfig(), {
    fetchImpl: async () => { throw new Error(`connect ECONNREFUSED via proxy https://svc:${CANARY_SESSION}@proxy.example.com with Authorization: Bearer ${CANARY_BEARER}`); },
    sleepImpl: async () => {},
    retryLimit: 0,
  });
  await assert.rejects(() => transport.vm.listScans(), (error) => {
    assertNoCanary(error.message, "transport error");
    assert.match(error.message, /https:\/\/\[REDACTED\]@proxy\.example\.com/);
    return true;
  });

  const aborted = createTenableClients(vmConfig(), {
    fetchImpl: async () => { const abort = new Error(`aborted while sending Bearer ${CANARY_BEARER}`); abort.name = "AbortError"; throw abort; },
    sleepImpl: async () => {},
  });
  await assert.rejects(() => aborted.vm.listScans(), (error) => {
    assertNoCanary(error.message, "abort error");
    assert.match(error.message, /timed out after \d+ms/);
    return true;
  });
});

const FAKE_TENABLE_SECRETS = {
  sshPassword: "FAKE-SSH-PASSWORD-a1b2c3d4e5f6",
  sshPrivateKey: "FAKE-SSH-PRIVATE-KEY-001122334455",
  windowsPassword: "FAKE-WINDOWS-PASSWORD-99887766",
  smtpPassword: "FAKE-SMTP-PASSWORD-13579-24680",
  scannerKey: "FAKE-SCANNER-LINKING-KEY-5566778899",
  registrationCode: "FAKE-REGISTRATION-CODE-1122334455",
  licenseKey: "FAKE-LICENSE-KEY-aabbccddeeff0011",
  auditFieldToken: "FAKE-AUDIT-API-TOKEN-fedcba987654",
  webhookQueryToken: "FAKE-WEBHOOK-QUERY-TOKEN-0f1e2d3c",
  credentialSecret: "FAKE-CREDENTIAL-SETTINGS-SECRET-4242",
  camelCaseSecret: "FAKE-CAMEL-CLIENT-SECRET-777888999",
};

function secretBearingRoutes() {
  const routes = healthyRoutes();
  const secrets = FAKE_TENABLE_SECRETS;
  routes["GET /policies/1"] = {
    ...healthyPolicyDetails({ settings: { smtp_password: secrets.smtpPassword } }),
    credentials: {
      current: {
        Host: {
          SSH: [{ auth_method: "password", username: "svc-scan", password: secrets.sshPassword, private_key: secrets.sshPrivateKey, elevate_privileges_with: "sudo" }],
          Windows: [{ auth_method: "Password", username: "svc-win", password: secrets.windowsPassword, domain: "CORP" }],
        },
      },
    },
    audits: { current: { Unix: [{ file: "cis_ubuntu.audit" }] } },
  };
  routes["GET /scanners"] = {
    scanners: [{ ...healthyRoutes()["GET /scanners"].scanners[0], key: secrets.scannerKey, registration_code: secrets.registrationCode, license: { type: "commercial", key: secrets.licenseKey, agents: 100 } }],
  };
  routes["GET /audit-log/v1/events"] = {
    events: [{
      ...healthyRoutes()["GET /audit-log/v1/events"].events[0],
      fields: [
        { name: "api_token", value: secrets.auditFieldToken },
        { name: "target_url", value: `https://hooks.example.com/services/T000/B000?token=${secrets.webhookQueryToken}` },
        { name: "X-Client-Id", value: "client-1" },
      ],
    }],
    pagination: { total: 1 },
  };
  routes["GET /credentials"] = {
    credentials: [{ ...healthyRoutes()["GET /credentials"].credentials[0], settings: { auth_method: "password", username: "svc", password: secrets.credentialSecret, clientSecret: secrets.camelCaseSecret } }],
    pagination: { total: 1 },
  };
  return routes;
}

test("exportTenableAuditBundle never writes policy credentials, scanner linking keys, or credential-named properties into the bundle or the zip", async () => {
  const root = mkdtempSync(join(tmpdir(), "tenable-bundle-secrets-"));
  const secrets = Object.values(FAKE_TENABLE_SECRETS);
  const clients = clientsFor(secretBearingRoutes());
  const result = await exportTenableAuditBundle(clients, root, { now: NOW });
  const files = readBundleFiles(result.outputDir);
  const zipEntries = readZipEntries(result.zipPath);
  assert.ok(files.has("core_data/policy_details.json") && files.has("core_data/scanners.json") && files.has("core_data/audit_log_events.json") && files.has("core_data/credentials.json"));
  assertSecretsAbsent(assert, files, secrets, "bundle");
  assertSecretsAbsent(assert, zipEntries, secrets, "zip");
  assert.deepEqual([...files.keys()].sort(), [...zipEntries.keys()].sort(), "the zip mirrors the bundle directory");

  const policyDetails = JSON.parse(files.get("core_data/policy_details.json"));
  const projected = policyDetails.find((entry) => String(entry.policyId) === "1");
  assert.deepEqual(Object.keys(projected.details).sort(), ["plugins", "settings", "uuid"], "policy details are projected to the verdict inputs only");
  assert.equal(projected.details.settings.safe_checks, "yes");
  assert.equal(projected.details.settings.smtp_password, "[REDACTED]");
  assert.ok(!files.get("core_data/policy_details.json").includes("\"credentials\""));

  const scanners = JSON.parse(files.get("core_data/scanners.json"));
  assert.equal(scanners[0].key, "[REDACTED]");
  assert.equal(scanners[0].registration_code, "[REDACTED]");
  assert.equal(scanners[0].license, "[REDACTED]");
  assert.equal(scanners[0].loaded_plugin_set, RECENT_PLUGIN_SET, "verdict inputs survive the scrub");

  const events = JSON.parse(files.get("core_data/audit_log_events.json"));
  const fields = events[0].fields;
  assert.deepEqual(fields.find((field) => field.name === "api_token").value, "[REDACTED]");
  assert.equal(fields.find((field) => field.name === "target_url").value, "https://hooks.example.com/services/T000/B000?token=[REDACTED]");
  assert.equal(fields.find((field) => field.name === "X-Client-Id").value, "client-1");

  const credentials = JSON.parse(files.get("core_data/credentials.json"));
  assert.equal(credentials[0].settings.password, "[REDACTED]");
  assert.equal(credentials[0].settings.clientSecret, "[REDACTED]");
  assert.equal(credentials[0].settings.username, "svc");
  assert.equal(credentials[0].name, "Linux SSH");

  const findings = JSON.parse(files.get("analysis/findings.json"));
  assert.equal(findings.find((item) => item.id === "TENABLE-01").status, "pass", "projection keeps the settings the verdict reads");
  assert.equal(findings.find((item) => item.id === "TENABLE-08").status, "pass", "scanner plugin currency survives the credential scrub");
  const healthyCredentials = byId(await runAll(clientsFor(healthyRoutes())), "TENABLE-12");
  const scrubbedCredentials = findings.find((item) => item.id === "TENABLE-12");
  assert.equal(scrubbedCredentials.status, healthyCredentials.status, "the credential inventory verdict is unaffected by the scrub");
  assert.deepEqual(scrubbedCredentials.evidence.types, healthyCredentials.evidence.types);
  assert.equal(result.errorCount, 0);
  assert.ok(files.get("QUICK_REFERENCE.md").includes("redacted"), "the quick reference describes the redaction");

  const results = await runAll(clients);
  for (const secret of secrets) assert.ok(!JSON.stringify(results).includes(secret), `${secret} reached an assessment result`);
});

test("listPaginated stops as truncated when the endpoint ignores offset and replays the same page", async () => {
  let calls = 0;
  const stuck = createTenableClients(vmConfig(), {
    fetchImpl: async () => {
      calls += 1;
      return jsonResponse({ networks: [{ uuid: "net-1", name: "Default", scanner_count: 1 }, { uuid: "net-2", name: "DMZ", scanner_count: 1 }], pagination: { total: 10 } });
    },
    sleepImpl: async () => {},
  });
  const page = await stuck.vm.listPaginated("/networks", "networks", {}, { pageLimit: 2, maxPages: 50 });
  assert.equal(calls, 2, "the repeated page is detected on the second request");
  assert.equal(page.items.length, 2, "duplicate records are not counted twice");
  assert.equal(page.total, 10);
  assert.equal(page.truncated, true, "a stuck offset is a partial inventory");

  const routes = healthyRoutes();
  const fallback = routerFetch(routes);
  const clients = createTenableClients(vmConfig(), {
    fetchImpl: async (url, init) => (new URL(url).pathname === "/networks"
      ? jsonResponse({ networks: Array.from({ length: 50 }, (_, index) => ({ uuid: `net-${index}`, name: `Network ${index}`, scanner_count: 1 })) })
      : fallback(url, init)),
    sleepImpl: async () => {},
    exportPollMs: 0,
  });
  const data = await collectTenableSensorCoverageData(clients, { now: NOW });
  assert.equal(data.networks.status, "ok");
  assert.equal(data.networks.truncated, true);
  assert.equal(data.networks.seen, 50, "the walk stopped at the first repeated page");
  const finding = assessTenableSensorCoverage(data, { now: NOW }).findings.find((item) => item.id === "TENABLE-09");
  assert.equal(finding.status, "warn", finding.summary);
  assert.match(finding.summary, /capped at warn/);
});

function forbidding(key) {
  const routes = healthyRoutes();
  // The healthy scanner last connected two days ago (TENABLE-07 fails on that); a recent
  // connect makes scanner health depend only on the scanner list and the caller role.
  routes["GET /scanners"] = { scanners: [{ ...routes["GET /scanners"].scanners[0], last_connect: Math.floor((NOW - 3_600_000) / 1000) }] };
  routes[key] = { __status: 403 };
  return routes;
}

test("rule 1 corollary: a pass never survives an unreadable secondary inventory and unread evidence renders null", async () => {
  const templates = await runAll(clientsFor(forbidding("GET /editor/scan/templates")), { expectedAssetCount: 2 });
  const scanPolicy = byId(templates, "TENABLE-01");
  assert.equal(scanPolicy.status, "warn", scanPolicy.summary);
  assert.match(scanPolicy.summary, /GET \/editor\/scan\/templates refused the API key with HTTP 403 .*discovery-only scan detection was not possible/);
  assert.equal(scanPolicy.evidence.scan_templates_in_use, null);
  assert.equal(scanPolicy.evidence.policy_templates, null);
  assert.equal(scanPolicy.evidence.discovery_only_scans, null);
  assert.equal(scanPolicy.evidence.scan_templates_status, "forbidden");
  assert.equal(byId(templates, "TENABLE-17").status, "manual");

  const agents = await runAll(clientsFor(forbidding("GET /scanners/null/agents")), { expectedAssetCount: 2 });
  const pluginCurrency = byId(agents, "TENABLE-08");
  assert.equal(pluginCurrency.status, "warn", pluginCurrency.summary);
  assert.match(pluginCurrency.summary, /GET \/scanners\/null\/agents refused the API key with HTTP 403 .*agent plugin currency is unknown/);
  assert.equal(pluginCurrency.evidence.stale_online_agents, null);
  assert.equal(pluginCurrency.evidence.agents_status, "forbidden");
  assert.equal(byId(agents, "TENABLE-07").status, "pass", "scanner health does not read the agent list");
  assert.equal(byId(agents, "TENABLE-05").status, "manual");
  assert.equal(byId(agents, "TENABLE-06").status, "manual");
  assert.equal(agents[1].summary.agent_count, null);

  const networks = await runAll(clientsFor(forbidding("GET /networks")), { expectedAssetCount: 2 });
  const coverage = byId(networks, "TENABLE-03");
  assert.equal(coverage.status, "warn", coverage.summary);
  assert.match(coverage.summary, /GET \/networks refused the API key with HTTP 403/);
  assert.equal(coverage.evidence.networks_without_assets, null);
  assert.equal(coverage.evidence.networks_status, "forbidden");
  assert.equal(byId(networks, "TENABLE-09").status, "manual");
  assert.equal(networks[1].summary.network_count, null);

  const tagValues = await runAll(clientsFor(forbidding("GET /tags/values")), { expectedAssetCount: 2 });
  const tagging = byId(tagValues, "TENABLE-16");
  assert.equal(tagging.status, "warn", tagging.summary);
  assert.match(tagging.summary, /GET \/tags\/values refused the API key with HTTP 403/);
  assert.equal(tagging.evidence.tag_value_count, null);

  const serverProperties = await runAll(clientsFor(forbidding("GET /server/properties")));
  const agentHealth = byId(serverProperties, "TENABLE-05");
  assert.equal(agentHealth.status, "warn", agentHealth.summary);
  assert.match(agentHealth.summary, /GET \/server\/properties refused the API key with HTTP 403 .*licensed agent count \(license\.agents\) is unknown/);
  assert.equal(agentHealth.evidence.licensed_agents, null);
  assert.equal(byId(serverProperties, "TENABLE-08").status, "manual");

  const agentGroups = await runAll(clientsFor(forbidding("GET /scanners/null/agent-groups")));
  const grouping = byId(agentGroups, "TENABLE-06");
  assert.equal(grouping.status, "manual");
  assert.equal(grouping.evidence.groups, null);
  assert.equal(grouping.evidence.agent_group_count, null);

  const roles = await runAll(clientsFor(forbidding("GET /access-control/v1/roles")));
  const userAccess = byId(roles, "TENABLE-10");
  assert.equal(userAccess.status, "warn", userAccess.summary);
  assert.match(userAccess.summary, /GET \/access-control\/v1\/roles refused the API key with HTTP 403/);
  assert.equal(userAccess.evidence.custom_roles, null);

  const groups = await runAll(clientsFor(forbidding("GET /groups")));
  const permissions = byId(groups, "TENABLE-11");
  assert.equal(permissions.status, "warn", permissions.summary);
  assert.match(permissions.summary, /GET \/groups refused the API key with HTTP 403/);
  assert.equal(permissions.evidence.user_groups, null);

  const accessGroups = await runAll(clientsFor(forbidding("GET /v2/access-groups")));
  const legacy = byId(accessGroups, "TENABLE-11");
  assert.equal(legacy.status, "warn");
  assert.equal(legacy.evidence.legacy_access_groups, null);
  assert.equal(legacy.evidence.access_groups_status, "forbidden");

  const jobs = await runAll(clientsFor(forbidding("GET /assets/export/status")));
  const automation = byId(jobs, "TENABLE-19");
  assert.equal(automation.status, "warn", automation.summary);
  assert.match(automation.summary, /GET \/assets\/export\/status refused the API key with HTTP 403/);
  assert.equal(automation.evidence.asset_export_jobs_listed, null);
  assert.equal(automation.evidence.vuln_export_jobs_listed, 2);

  const users = await runAll(clientsFor(forbidding("GET /users")), { expectedAssetCount: 2 });
  assert.equal(byId(users, "TENABLE-07").status, "warn", "scanner health is capped when the caller role is unknown");
  assert.equal(users[1].summary.caller_is_administrator, null);
  assert.equal(users[2].summary.user_count, null);
});

test("assessment summaries render null, not zero, for every unreadable dataset", async () => {
  const [scan, sensor, access, vuln] = await runAll(clientsFor(healthyRoutes(), { status: 403 }));
  for (const [key, value] of Object.entries(scan.summary)) {
    if (["scan_count", "policy_count", "exclusion_count", "target_group_count", "exported_assets", "caller_is_administrator"].includes(key)) assert.equal(value, null, `scan_program.summary.${key}`);
  }
  for (const key of ["exported_assets", "agent_count", "scanner_entries", "linked_scanners", "network_count", "tag_categories", "caller_is_administrator"]) assert.equal(sensor.summary[key], null, `sensor_coverage.summary.${key}`);
  for (const key of ["user_count", "permission_count", "credential_count", "audit_events", "caller_is_administrator"]) assert.equal(access.summary[key], null, `access_control.summary.${key}`);
  for (const key of ["exported_findings", "exported_assets"]) assert.equal(vuln.summary[key], null, `vulnerability_management.summary.${key}`);
  for (const result of [scan, sensor, access, vuln]) {
    assert.equal(result.summary.pass, 0, `${result.category}: nothing passes on forbidden data`);
    assert.ok(result.summary.manual >= 1, `${result.category}: unreadable inventories are manual`);
  }
});

test("resolveSecureOutputPath rejects traversal and symlinked parents", () => {
  const base = mkdtempSync(join(tmpdir(), "tenable-secure-"));
  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /outside/);
  assert.throws(() => resolveSecureOutputPath(base, "../../etc/passwd"), /outside/);
  const target = mkdtempSync(join(tmpdir(), "tenable-symlink-target-"));
  symlinkSync(target, join(base, "linked"));
  assert.throws(() => resolveSecureOutputPath(base, "linked/child"), /symlink/i);
  const safe = resolveSecureOutputPath(base, "nested/report.json");
  assert.ok(safe.startsWith(base));
});

test("registerTenableTools registers the read-only tool set with TypeBox schemas", async () => {
  const registered = [];
  registerTenableTools({ registerTool: (tool) => registered.push(tool) });
  assert.deepEqual(registered.map((tool) => tool.name), [
    "tenable_check_access",
    "tenable_assess_scan_program",
    "tenable_assess_sensor_coverage",
    "tenable_assess_access_control",
    "tenable_assess_vulnerability_management",
    "tenable_export_audit_bundle",
  ]);
  for (const tool of registered) {
    assert.equal(tool.parameters.type, "object");
    assert.ok(tool.parameters.properties.access_key);
    assert.ok(tool.description.length > 40);
  }

  const originalFetch = globalThis.fetch;
  globalThis.fetch = routerFetch(healthyRoutes());
  try {
    const check = registered.find((tool) => tool.name === "tenable_check_access");
    const result = await check.execute("call-1", check.prepareArguments({ access_key: "access-key-123456", secret_key: "secret-key-654321", config_file: EMPTY_CONFIG_FILE }));
    assert.ok(result.content[0].text.includes("healthy"), result.content[0].text);
    const failure = await check.execute("call-2", check.prepareArguments({ config_file: EMPTY_CONFIG_FILE, url: "https://cloud.tenable.com" }));
    assert.ok(JSON.stringify(failure).includes("TENABLE_ACCESS_KEY"));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Tenable tools appear in the registered tool catalog under the Tenable group", () => {
  const tools = getRegisteredToolSummaries().filter((tool) => tool.name.startsWith("tenable_"));
  assert.equal(tools.length, 6);
  for (const tool of tools) assert.equal(tool.group, "Tenable");
});
