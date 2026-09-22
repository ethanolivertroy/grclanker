import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";

import {
  TenableApiError,
  assessTenableAccessControl,
  assessTenableScanProgram,
  assessTenableSensorCoverage,
  assessTenableVulnerabilityManagement,
  checkTenableAccess,
  collectTenableAccessControlData,
  collectTenableScanProgramData,
  collectTenableSensorCoverageData,
  collectTenableVulnerabilityData,
  configuredTenableSecrets,
  createTenableClients,
  describeErrorBody,
  exportTenableAuditBundle,
  isCredentialKey,
  propertyNameIsCredential,
  redactConfiguredSecrets,
  redactCredentialProperties,
  redactCredentialValueText,
  redactErrorText,
  redactSecrets,
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

// The configured API keys of the fixtures, which only the configured-secret pass (guard 2)
// removes: they are deliberately name-shaped, so bare in prose no carrier or token-shape
// rule touches them and their absence proves that pass ran. Their words appear nowhere in
// the module's own vocabulary, no 6-character window of them does either, and the two
// share no 6-character window with each other, so a leaked window names its key.
const FIXTURE_ACCESS_KEY = "amber-quarry-summit-2026";
const FIXTURE_SECRET_KEY = "cobalt-meadow-ridge-2026";

// The forms a configured secret can be echoed in: as is, JSON-escaped, URL-encoded, base64, base64url.
function secretForms(value) {
  return [...new Set([value, JSON.stringify(value).slice(1, -1), encodeURIComponent(value), Buffer.from(value).toString("base64"), Buffer.from(value).toString("base64url")])];
}

// The window rule (addendum 8): every leak assertion against a planted credential checks
// the whole value and every window of it from LEAK_WINDOW_MIN to LEAK_WINDOW_MAX characters,
// so a partial echo (the 10-character window JSON.parse quotes, a token cut by a length cap,
// the head of a base64 form split by a marker) cannot pass. The planted values are alphanumeric
// and random-looking, and the fixture self-check below proves that no 6-character window of
// any of them occurs in the fixtures' legitimate text, so every failure is a real leak.
const LEAK_WINDOW_MIN = 6;
const LEAK_WINDOW_MAX = 24;
const leakWindowCache = new Map();

// The whole value plus every window of LEAK_WINDOW_MIN to LEAK_WINDOW_MAX characters, longest
// first so a failure names the largest fragment that survived, and the shortest windows on
// their own: a longer window contains its own first LEAK_WINDOW_MIN characters, so every
// window is absent exactly when the whole value and every shortest window are.
function leakWindows(canary) {
  let entry = leakWindowCache.get(canary);
  if (entry === undefined) {
    const all = [canary];
    for (let size = Math.min(LEAK_WINDOW_MAX, canary.length - 1); size >= LEAK_WINDOW_MIN; size -= 1) {
      for (let index = 0; index + size <= canary.length; index += 1) all.push(canary.slice(index, index + size));
    }
    const shortest = Math.min(LEAK_WINDOW_MIN, canary.length);
    entry = { all: [...new Set(all)], probes: [...new Set(all.filter((window) => window.length === shortest))] };
    leakWindowCache.set(canary, entry);
  }
  return entry;
}

// Neither the canary nor any window of it from 6 to 24 characters may survive in the text.
function assertNoWindow(text, canary, label) {
  const { all, probes } = leakWindows(canary);
  if (!probes.some((probe) => text.includes(probe))) return;
  const leaked = all.find((window) => text.includes(window));
  assert.fail(leaked === canary ? `${label}: ${canary} leaked` : `${label}: window ${leaked} of ${canary} leaked`);
}

// Every bundle file or zip entry against every planted secret: the shared whole-value scan, then every window.
function assertNoSecretWindows(contents, secrets, label) {
  assertSecretsAbsent(assert, contents, secrets, label);
  for (const [name, text] of contents) {
    for (const secret of secrets) assertNoWindow(text, secret, `${label} ${name}`);
  }
}

// The 6-character windows of a planted value (the value itself when shorter), for the fixture self-check.
function sixWindows(value) {
  return leakWindows(value).probes;
}

function jsonResponse(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}

function vmConfig(extra = {}) {
  return resolveTenableConfiguration({ access_key: FIXTURE_ACCESS_KEY, secret_key: FIXTURE_SECRET_KEY, config_file: EMPTY_CONFIG_FILE, ...extra }, EMPTY_ENV);
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

test("round 7(b): environment credentials survive an argument overlay that carries unrelated or undefined keys, and the source chain names the environment", () => {
  const configPath = join(mkdtempSync(join(tmpdir(), "tenable-env-overlay-")), "config.yaml");
  writeFileSync(configPath, "access_key: fileA7sD2fG9hJ4kL1zX\nsecret_key: fileM3nB8vC5xZ2qW6eR\nurl: https://fedcloud.tenable.com\n");
  const env = { ...EMPTY_ENV, TENABLE_CONFIG_FILE: configPath, TENABLE_ACCESS_KEY: "envH5jK8lZ3xC6vB2nM9", TENABLE_SECRET_KEY: "envR4tY7uI1oP8aS3dF6" };
  // The overlay a tool builds from optional arguments: one unrelated argument plus the
  // credential keys present but undefined, as a spread of an unfilled schema produces.
  const overlay = { timeout_seconds: 33, access_key: undefined, secret_key: undefined, url: undefined, sc_url: undefined, config_file: undefined };
  const config = resolveTenableConfiguration(overlay, env);
  assert.equal(config.vm.accessKey, env.TENABLE_ACCESS_KEY);
  assert.equal(config.vm.secretKey, env.TENABLE_SECRET_KEY, "the environment value beats the config file and is not erased by the undefined argument");
  assert.equal(config.vm.baseUrl, "https://fedcloud.tenable.com", "the file's URL still applies where the environment is silent");
  assert.equal(config.timeoutMs, 33_000, "the unrelated argument still applies");
  for (const source of ["environment-TENABLE_ACCESS_KEY", "environment-TENABLE_SECRET_KEY"]) {
    assert.ok(config.sourceChain.includes(source), `${source} in ${config.sourceChain.join(", ")}`);
  }
  assert.ok(!config.sourceChain.some((source) => source.startsWith("arguments-")), config.sourceChain.join(", "));
  assert.ok(!config.sourceChain.some((source) => /^config-file-(access_key|secret_key)$/.test(source)), config.sourceChain.join(", "));
});

// Config loader canaries: no two share a 6-character window, so any fragment a parser
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
  for (const canary of canaries) assertNoWindow(text, canary, `${label} (${text})`);
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
      assert.equal(redactErrorText(error.message), error.message, `${entry.label}: the loader text survives the scrub`);
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
  assert.equal(log[0].headers["X-ApiKeys"], `accessKey=${FIXTURE_ACCESS_KEY};secretKey=${FIXTURE_SECRET_KEY}`);
  assert.ok(log[0].url.includes("limit=200"), log[0].url);
  assert.ok(log.some((entry) => entry.url.includes("offset=2")), "second page requested");

  const deniedBody = `denied for accessKey=${FIXTURE_ACCESS_KEY};secretKey=${FIXTURE_SECRET_KEY}`;
  const failing = createTenableClients(vmConfig(), {
    fetchImpl: async () => new Response(deniedBody, { status: 403 }),
    sleepImpl: async () => {},
  });
  await assert.rejects(() => failing.vm.listScans(), (error) => {
    assert.equal(error.status, 403);
    for (const secret of [FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY]) assertNoWindow(error.message, secret, "non-JSON denial");
    assert.ok(!error.message.includes("denied for"), `non-JSON bodies are never echoed: ${error.message}`);
    assert.match(error.message, new RegExp(`403[^;]*; non-JSON text/plain response body \\(${deniedBody.length} bytes, not echoed\\)`));
    return true;
  });

  const jsonFailure = createTenableClients(vmConfig(), {
    fetchImpl: async () => jsonResponse({ error: `invalid credentials accessKey=${FIXTURE_ACCESS_KEY};secretKey=${FIXTURE_SECRET_KEY}` }, 401),
    sleepImpl: async () => {},
  });
  await assert.rejects(() => jsonFailure.vm.listScans(), (error) => {
    assert.equal(error.status, 401);
    assert.ok(error.message.includes("invalid credentials"), "documented JSON error fields are kept");
    for (const secret of [FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY]) assertNoWindow(error.message, secret, "JSON denial");
    assert.equal(error.message, "Tenable request GET /scans failed (HTTP 401; invalid credentials accessKey=[REDACTED];secretKey=[REDACTED])", "both halves of the echoed header go, the key names stay");
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
  assert.ok(result.notes.some((note) => note.includes("audit_log requires role Administrator;")));
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
  assertNoWindow(rawUsers, FIXTURE_SECRET_KEY, "core_data/users.json");
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

// ---------------------------------------------------------------------------
// Scrub boundary ruling: a name-shaped value bare in prose stays, a carrier loses its value
// whatever its shape, a configured secret is removed in every form whatever its shape, and
// real token shapes are removed bare.
// ---------------------------------------------------------------------------
const NAME_SHAPED_VALUES = ["prod-us-east-2026", "fw-dc1-01", "sess-canary-COOKIE-31415926535897", "my-bucket-prod-2026-logs", "3f2b1c9e-8a7d-4e6f-9b0a-1c2d3e4f5a6b"];

// Every carrier of the ruling with the value in it, and the exact rendering after the scrub.
function carriersOf(value) {
  return [
    [`Authorization: Bearer ${value}`, /^Authorization: (?:Bearer )?\[REDACTED\]$/],
    [`Proxy-Authorization: Basic ${value}`, /^Proxy-Authorization: (?:Basic )?\[REDACTED\]$/],
    [`Cookie: TNS_SESSIONID=${value}; theme=dark`, /^Cookie: \[REDACTED\]$/],
    [`Set-Cookie: TNS_SESSIONID=${value}; Path=/; HttpOnly`, /^Set-Cookie: \[REDACTED\]$/],
    [`X-ApiKeys: accessKey=${value};secretKey=${value}`, /^X-ApiKeys: \[REDACTED\]$/],
    [`x-apikey: accesskey=${value}; secretkey=${value};`, /^x-apikey: \[REDACTED\]$/],
    [`X-SecurityCenter: ${value}`, /^X-SecurityCenter: \[REDACTED\]$/],
    [`X-Cookie: token=${value}`, /^X-Cookie: \[REDACTED\]$/],
    [`X-Api-Key: ${value}`, /^X-Api-Key: \[REDACTED\]$/],
    [`<p>X-ApiKeys: accessKey=${value};secretKey=${value}</p><p>next</p>`, /^<p>X-ApiKeys: \[REDACTED\]<\/p><p>next<\/p>$/],
    [`accessKey=${value};secretKey=${value}`, /^accessKey=\[REDACTED\];secretKey=\[REDACTED\]$/],
    [`TNS_SESSIONID=${value}; Path=/`, /^TNS_SESSIONID=\[REDACTED\]; Path=\/$/],
    [`session=${value} expired`, /^session=\[REDACTED\] expired$/],
    [`https://svc:${value}@proxy.example.com/x`, /^https:\/\/\[REDACTED\]@proxy\.example\.com\/x$/],
    [`https://hooks.example.com/tenable?token=${value}&channel=ops`, /^https:\/\/hooks\.example\.com\/tenable\?token=\[REDACTED\]&channel=ops$/],
    [`https://x.example.com/cb?state=1&api_key=${value}`, /^https:\/\/x\.example\.com\/cb\?state=1&api_key=\[REDACTED\]$/],
    [`GET /login?user=a&pass=${value}`, /^GET \/login\?user=a&pass=\[REDACTED\]$/],
    [`https://x.example.com/cb#access_token=${value}&state=1`, /^https:\/\/x\.example\.com\/cb#access_token=\[REDACTED\]&state=1$/],
    [`https://hooks.slack.com/services/${value}`, /^https:\/\/hooks\.slack\.com\/services\/\[REDACTED\]$/],
    [`Bearer ${value}`, /^Bearer \[REDACTED\]$/],
    [`Basic ${value}`, /^Basic \[REDACTED\]$/],
    [`Token ${value}`, /^Token \[REDACTED\]$/],
    [`ApiKey ${value}`, /^ApiKey \[REDACTED\]$/],
    [`password=${value}`, /^password=\[REDACTED\]$/],
    [`password: ${value}`, /^password: \[REDACTED\]$/],
    [`registration_code: ${value} and more words`, /^registration_code: \[REDACTED\]$/],
    [`linking_key=${value}&name=x`, /^linking_key=\[REDACTED\]&name=x$/],
    [`{"secretKey":"${value}","name":"svc"}`, /^\{"secretKey":"\[REDACTED\]","name":"svc"\}$/],
    [`{"private_key": "${value}", "id": 7}`, /^\{"private_key": "\[REDACTED\]", "id": 7\}$/],
    [`<scanner name="s1" key="${value}"/>`, /^<scanner name="s1" key="\[REDACTED\]"\/>$/],
    [`<field name='pw' password='${value}'/>`, /^<field name='pw' password='\[REDACTED\]'\/>$/],
  ];
}

test("scrub boundary: name-shaped values stay bare in prose, leave every carrier whatever their shape, and go as configured secrets in every form", () => {
  for (const value of NAME_SHAPED_VALUES) {
    for (const prose of [`inventory ${value} was not read`, `${value}`, `scanner ${value} reported 12 of 40 agents`, `path /var/lib/${value}/state`]) {
      assert.equal(redactErrorText(prose), prose, `${value} stays bare in error text`);
      assert.equal(redactCredentialValueText(prose), prose, `${value} stays bare in a data value`);
    }
    for (const [text, expected] of carriersOf(value)) {
      for (const scrub of [redactErrorText, redactCredentialValueText]) {
        const out = scrub(text);
        assert.match(out, expected, `${scrub.name}(${JSON.stringify(text)}) -> ${JSON.stringify(out)}`);
        assertNoWindow(out, value, `${scrub.name} ${text}`);
        assert.equal(scrub(out), out, `${scrub.name} is idempotent on ${out}`);
      }
    }
    // A configured secret goes bare and in every encoded form, however name-shaped it is.
    for (const form of secretForms(value)) {
      assert.equal(redactSecrets(`login rejected for ${form} by upstream`, [value]), "login rejected for [REDACTED] by upstream", `configured ${value} as ${form}`);
      assert.equal(redactConfiguredSecrets(`login rejected for ${form} by upstream`, [value]), "login rejected for [REDACTED] by upstream", `guard 2 alone on ${form}`);
    }
  }
  // Both halves of each configured key pair are secrets; the Security Center pair joins when configured.
  assert.deepEqual(configuredTenableSecrets(vmConfig()), [FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY]);
  assert.deepEqual(
    configuredTenableSecrets(vmConfig({ sc_url: "https://sc.example.internal", sc_access_key: "sc-fixture-access-2026", sc_secret_key: "sc-fixture-secret-2026" })),
    [FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY, "sc-fixture-access-2026", "sc-fixture-secret-2026"],
  );
  assert.deepEqual(configuredTenableSecrets(resolveTenableConfiguration({ url: "https://sc.example.internal", access_key: "sc-access-key", secret_key: "sc-secret-key", config_file: EMPTY_CONFIG_FILE }, EMPTY_ENV)), ["sc-access-key", "sc-secret-key"]);
  const header = `X-ApiKeys: accessKey=${FIXTURE_ACCESS_KEY};secretKey=${FIXTURE_SECRET_KEY}`;
  assert.equal(redactConfiguredSecrets(header, configuredTenableSecrets(vmConfig())), "X-ApiKeys: accessKey=[REDACTED];secretKey=[REDACTED]", "the composed header value is covered by its halves");
  assert.equal(redactConfiguredSecrets("a pin 4711 and pin 47110", ["4711"]), "a pin [REDACTED] and pin 47110", "a short secret is removed as a whole token only");
  assert.equal(redactConfiguredSecrets("too short abc", ["abc"]), "too short abc", "below the minimum length nothing is scrubbed");

  // Real token shapes go bare from error text, and stay in data values where they are identifiers.
  for (const [text, expected] of [
    ["bare Kq7Zx2Vw9Lm4Tp8R token", "bare [REDACTED] token"],
    ["digest 0f9e8d7c6b5a4938 shown", "digest [REDACTED] shown"],
    ["hash 3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b shown", "hash [REDACTED] shown"],
    ["jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcdefghijk expired", "jwt [REDACTED] expired"],
    ["bare dXNlcjpwYXNzd29yZA== padded", "bare [REDACTED] padded"],
    ["akid AKIAIOSFODNN7EXAMPLE shown", "akid [REDACTED] shown"],
    ["panos LUFRPT1234567890abcdefghijklmnop shown", "panos [REDACTED] shown"],
    ["-----BEGIN RSA PRIVATE KEY-----\nMIIEfake\n-----END RSA PRIVATE KEY-----", "[REDACTED]"],
    ["-----BEGIN CERTIFICATE-----\nMIIEfake\n-----END CERTIFICATE-----", "[REDACTED]"],
    ["truncated -----BEGIN PRIVATE KEY-----\nMIIEfake", "truncated [REDACTED]"],
  ]) {
    assert.equal(redactErrorText(text), expected);
    assert.equal(redactErrorText(expected), expected, "idempotent");
  }
  // After a scheme the value goes whatever its shape, a plain lowercase word included,
  // unless it is one of the listed prose words; after the noun "Token" any short plain
  // lowercase word is prose.
  for (const [text, expected] of [
    ["Bearer abcdefghijklmnop rejected", "Bearer [REDACTED] rejected"],
    ["Basic canarybasic rejected", "Basic [REDACTED] rejected"],
    ["ApiKey canaryapikey rejected", "ApiKey [REDACTED] rejected"],
    ["Token abcdefghijklmnopq expired", "Token [REDACTED] expired"],
    ["Token hygiene could not be judged; token inventory read; Token count 3", "Token hygiene could not be judged; token inventory read; Token count 3"],
    ["API key basic auth; Bearer tokens expire; Basic credential; Basic authentication is required", "API key basic auth; Bearer tokens expire; Basic credential; Basic authentication is required"],
    // A Titlecase word makes the scheme name an adjective in a title; a digit, a symbol,
    // token casing, or a run longer than a word still marks a credential.
    ["templates: Basic Network Scan, Basic Agent Scan, Advanced Scan; Bearer Token rotation; Token Hygiene; ApiKey Rotation", "templates: Basic Network Scan, Basic Agent Scan, Advanced Scan; Bearer Token rotation; Token Hygiene; ApiKey Rotation"],
    ["Basic Canary2026 rejected; Basic dXNlcjpwYXNz rejected; Bearer Abcdefghijklmnopqrstu rejected; Basic Canary-Basic rejected", "Basic [REDACTED] rejected; Basic [REDACTED] rejected; Bearer [REDACTED] rejected; Basic [REDACTED] rejected"],
  ]) {
    assert.equal(redactErrorText(text), expected);
    assert.equal(redactCredentialValueText(text), expected);
  }
  // A digit string under a singular credential word is still a credential (a PIN, a numeric token).
  assert.equal(redactErrorText('"pin": 4711, "token": 12345678, otp=123456, "api_keys": 2'), '"pin": [REDACTED], "token": [REDACTED], otp=[REDACTED], "api_keys": 2');
  assert.equal(redactCredentialValueText("bare Kq7Zx2Vw9Lm4Tp8R id"), "bare Kq7Zx2Vw9Lm4Tp8R id", "an opaque identifier in evidence is not a secret");
  assert.equal(redactCredentialValueText("plugin set 202609211000 loaded"), "plugin set 202609211000 loaded", "a plugin set is a digit string, a name");
  const certificate = "-----BEGIN CERTIFICATE-----\nMIIEfake\n-----END CERTIFICATE-----";
  assert.equal(redactCredentialValueText(certificate), certificate, "a public certificate is evidence");
  assert.equal(redactCredentialValueText("-----BEGIN PRIVATE KEY-----\nMIIEfake\n-----END PRIVATE KEY-----"), "[REDACTED]");
  assert.equal(redactCredentialValueText(`${certificate}\n-----BEGIN EC PRIVATE KEY-----\nMHcC`), `${certificate}\n[REDACTED]`, "a truncated private block after a kept certificate");

  // Names, prose, and this module's own vocabulary survive.
  for (const text of [
    "Tenable request GET /scans failed (HTTP 403 Forbidden)",
    "Tenable request GET /scanners/null/agents failed (HTTP 502 Bad Gateway; non-JSON text/html response body (1234 bytes, not echoed))",
    "GET /assets/export/asset-export-1/chunks/1 replayed the same page at offset 200, so the walk could not advance",
    "Export 550e8400-e29b-41d4-a716-446655440000 ended with status TIMEOUT(PROCESSING): the last GET /vulns/export/550e8400-e29b-41d4-a716-446655440000/status poll reported PROCESSING.",
    "credentialed scan ratio 0.8; credential inventory read 12 of 40; managed credentials: 12; credential_threshold=0.8",
    "TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY (or access_key and secret_key arguments) are required for Tenable Vulnerability Management.",
    "Tenable Security Center GET /rest/scan returned error_code 143: not authorized",
    "Unable to read Tenable config file /etc/tenable.yaml (EACCES)",
    "Unable to parse Tenable config file: invalid YAML in /etc/tenable.yaml at line 3",
    "/tmp/tenable-loader-errors-Ab3xY9/nested.yaml",
    "policy 550e8400-e29b-41d4-a716-446655440000 unified_compliance_matrix ENOENT PCI-DSS-4 FREQ=WEEKLY;INTERVAL=1;BYDAY=MO",
    "Basic authentication is required; the Bearer token is missing; token expired, retry later",
    '"pass": 12, "pass_rate": 95, "two_factor": {"sms_enabled": 1}, "password": {"min_length": 12}, "last_apikey_access": 1726920000000',
    '"api_keys": 3, "secrets": 0, "credentials": 12; keys=3 tokens: 7 cookies: 0',
    "agent_offline_days=7 auth_type=saml credentials_file=/etc/x access_key_id=AKIA plugin_set=202609211000 loaded_plugin_set=202609211000",
    "arguments-access_key environment-TENABLE_SECRET_KEY config-file-sc_secret_key default-url",
  ]) {
    assert.equal(redactErrorText(text), text, text);
  }

  for (const [key, expected] of [
    ["key", true], ["token", true], ["accessKey", true], ["secretKey", true], ["api_key", true], ["X-ApiKeys", true], ["Set-Cookie", true],
    ["TNS_SESSIONID", true], ["session_id", true], ["JSESSIONID", true], ["password1", true], ["authtoken", true],
    ["sharedsecret", true], ["privatekey", true], ["password_hash", true], ["token_value", true], ["authorization_header", true],
    ["registration_code", true], ["linking_key", true], ["license_key", true], ["client_secret", true], ["sid", true], ["sig", true],
    ["last_apikey_access", false], ["public_key", false], ["tokenCount", false], ["scopes", false], ["client_id", false], ["user", false],
    ["login", false], ["max_keys", false], ["auth_type", false], ["password_policy", false], ["two_factor", false],
    ["pass_rate", false], ["pass", false], ["access_key_id", false], ["monkey", false], ["oauth", false], ["sessions", false],
    ["credential_threshold", false], ["credentials_file", false], ["credentialed_ratio", false], ["plugin_set", false], ["loaded_plugin_set", false],
    ["activation_code", true], ["authorization_code", true], ["recovery_codes", true], ["status_code", false], ["error_code", false], ["country_code", false], ["code", false],
  ]) {
    assert.equal(isCredentialKey(key), expected, key);
  }
  // Property names in payloads follow Tenable's data model: a bare key is a tag key, not a credential.
  for (const [name, expected] of [
    ["password", true], ["secretKey", true], ["accessKey", true], ["registration_code", true], ["linking_key", true], ["linkingkey", true],
    ["clientSecret", true], ["private_key", true], ["api_token", true], ["TNS_SESSIONID", true], ["key", false], ["value", false],
    ["last_apikey_access", false], ["credentials", false], ["two_factor", false], ["plugin_set", false],
  ]) {
    assert.equal(propertyNameIsCredential(name), expected, name);
  }
});

test("no window of a carried or configured canary survives, for every canary length from 6 to 24", () => {
  // A deterministic generator so a failure reproduces; one digit is forced so the value
  // never falls under a prose exception after a scheme.
  let seed = 0x2545f491;
  const next = () => {
    seed = (seed * 1103515245 + 12345) % 0x80000000;
    return seed;
  };
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const canary = (length) => {
    let value = "";
    for (let index = 0; index < length; index += 1) value += alphabet[next() % alphabet.length];
    return `${value.slice(0, -1)}${next() % 10}`;
  };
  for (let length = 6; length <= 24; length += 1) {
    for (let sample = 0; sample < 3; sample += 1) {
      const value = canary(length);
      for (const [text] of carriersOf(value)) {
        for (const scrub of [redactErrorText, redactCredentialValueText]) {
          assertNoWindow(scrub(text), value, `${scrub.name} ${text}`);
        }
      }
      for (const form of secretForms(value)) {
        assertNoWindow(redactSecrets(`upstream echoed ${form} in a ${length}-character reply`, [value]), value, `configured ${value} as ${form}`);
      }
    }
  }
});

test("the healthy bundle is fixed text the scrubs leave untouched, so every marker in a bundle is attributable to a credential or an echo", async () => {
  const clients = clientsFor(healthyRoutes());
  const bundle = await exportTenableAuditBundle(clients, mkdtempSync(join(tmpdir(), "tenable-fixed-text-")), { now: NOW });
  const files = readBundleFiles(bundle.outputDir);
  assert.ok(files.size >= 20);
  for (const [name, content] of files) {
    if (name.startsWith("core_data/") && name.endsWith(".json")) {
      // core_data/ is the vendor payload after the data scrub, where a {key, value} tag
      // pair is evidence: it is fixed under the data scrub it was written through, while
      // the whole-text scrubs, which no sink applies to a payload, would read the
      // serialized "key": pair as a carrier.
      const payload = JSON.parse(content);
      assert.deepEqual(redactCredentialProperties(payload), payload, `${name} is fixed under the data scrub`);
    } else {
      assert.equal(redactErrorText(content), content, `${name} is fixed text redactErrorText leaves alone`);
      assert.equal(redactCredentialValueText(content), content, `${name} is fixed text redactCredentialValueText leaves alone`);
    }
    assert.equal(redactConfiguredSecrets(content, configuredTenableSecrets(vmConfig())), content, `${name} carries no configured secret`);
    // QUICK_REFERENCE.md describes the marker; every other file is marker-free on a healthy tenant.
    if (name !== "QUICK_REFERENCE.md") assert.ok(!content.includes("[REDACTED]"), `${name} carries no marker on a healthy tenant`);
  }
  const access = await checkTenableAccess(clients);
  const results = await runAll(clients, { expectedAssetCount: 2 });
  for (const [label, text] of [["access check", JSON.stringify(access)], ["assessments", JSON.stringify(results)]]) {
    assert.equal(redactErrorText(text), text, `${label} is fixed text`);
    assert.ok(!text.includes("[REDACTED]"), `${label} carries no marker on a healthy tenant`);
  }
});

// Round 7(a): fixed message text can itself match a credential-pair scrub ("credentials: <path>"
// reads as a pair), so every fixed text this module emits on the unhealthy paths is driven out
// of the module over HTTP and run through the general scrub: the not-collected markers and
// their collection status, the could-not-be-read causes, the non-JSON and silent-success
// notes, the partial-view line, the Security Center not-configured texts, the manual and
// capped summaries, and _errors.log must all be the identity under redactErrorText. Because
// the writer scrubs before it writes, a fixed text mangled on the way in would surface as a
// marker, so with nothing planted no file or result may carry one (QUICK_REFERENCE.md
// describes the marker and is exempt).
test("round 7(a): every fixed text emitted on refused, unavailable, failed, capped, and silent-success paths survives the scrubs unchanged", async () => {
  const routes = healthyRoutes();
  const everyRoute = (makeResponse) => createTenableClients(vmConfig(), { fetchImpl: async () => makeResponse(), sleepImpl: async () => {}, exportPollMs: 0, exportTimeoutMs: 5_000 });
  const fallback = routerFetch(routes);
  const cappedNetworks = fullPageFetch("networks", 50);
  const fixtures = [
    ["every read refused", clientsFor(routes, { status: 403 })],
    ["every read unavailable", clientsFor(routes, { status: 404 })],
    ["every read behind a proxy page", everyRoute(() => new Response("<html><body>502 Bad Gateway</body></html>", { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html" } }))],
    ["every read an empty success", everyRoute(() => new Response("", { status: 200, statusText: "OK", headers: { "content-type": "application/json" } }))],
    ["a page-capped walk", createTenableClients(vmConfig(), {
      fetchImpl: async (url, init) => (new URL(url).pathname === "/networks" ? cappedNetworks(url) : fallback(url, init)),
      sleepImpl: async () => {},
      exportPollMs: 0,
      exportTimeoutMs: 5_000,
    })],
  ];
  const corpus = [];
  for (const [label, clients] of fixtures) {
    const access = await checkTenableAccess(clients);
    const bundle = await exportTenableAuditBundle(clients, mkdtempSync(join(tmpdir(), "tenable-fixed-text-unhealthy-")), { now: NOW });
    const rendered = [["check_access", JSON.stringify(access)], ["assessments", JSON.stringify(await runAll(clients, { expectedAssetCount: 2 }))], ...readBundleFiles(bundle.outputDir)];
    assert.ok(rendered.some(([name]) => name === "_errors.log"), `${label}: the failures are logged`);
    for (const [name, text] of rendered) {
      if (name.startsWith("core_data/") && name.endsWith(".json")) {
        const payload = JSON.parse(text);
        assert.deepEqual(redactCredentialProperties(payload), payload, `${label}: a fixed text in ${name} is changed by the data scrub`);
      } else {
        assert.equal(redactErrorText(text), text, `${label}: a fixed text in ${name} is changed by the general scrub`);
      }
      if (name !== "QUICK_REFERENCE.md") assert.ok(!text.includes("[REDACTED]"), `${label}: ${name} carries a marker with nothing planted`);
      corpus.push(text);
    }
  }

  // The loader texts, with the fs code and the structured line they carry, are fixed text too.
  const base = mkdtempSync(join(tmpdir(), "tenable-fixed-loader-"));
  mkdirSync(join(base, "dir.yaml"));
  writeFileSync(join(base, "broken.yaml"), "url: https://cloud.tenable.com\nkey: value: nested\n");
  for (const file of [join(base, "dir.yaml"), join(base, "missing.yaml"), join(base, "broken.yaml")]) {
    assert.throws(() => resolveTenableConfiguration({ config_file: file, url: "https://cloud.tenable.com" }, EMPTY_ENV), (error) => {
      assert.equal(redactErrorText(error.message), error.message, `${file}: the loader text survives the scrub`);
      assert.equal(redactCredentialValueText(error.message), error.message, `${file}: the loader text survives the data scrub`);
      corpus.push(error.message);
      return true;
    });
  }

  // Positive controls: the fixtures reach every family of fixed text the rule names.
  const emitted = corpus.join("\n");
  for (const family of [
    /"collected":\s*false/,
    /"dataset_status":\s*"forbidden"/,
    /"dataset_status":\s*"error"/,
    /"dataset_status":\s*"not_configured"/,
    /Tenable request GET \/users failed \(HTTP 404; forbidden\)/,
    // The error line of a dataset named for what it holds keeps its whole message.
    /"credentials dataset: Tenable request GET \/credentials failed \(HTTP 403; forbidden\)"/,
    /"credentials dataset: Tenable request GET \/credentials failed \(HTTP 502 Bad Gateway; non-JSON text\/html response body \(\d+ bytes, not echoed\)\)"/,
    /"networks dataset: partial view \(10000 of unknown records retrieved; the walk stopped at the 200-page cap\)\."/,
    // The role note names the Basic role, which is also a scheme word, and keeps its whole text.
    /"server_properties requires role Basic; GET \/server\/properties refused the API key with HTTP 403: Tenable request GET \/server\/properties failed \(HTTP 403; forbidden\)"/,
    /"roles requires role Administrator; GET \/access-control\/v1\/roles refused the API key with HTTP 403/,
    /"credentials requires role Basic with Can Use on credentials; GET \/credentials refused the API key with HTTP 403/,
    / could not be read because /,
    /A human must collect/,
    /TENABLE_SC_URL/,
    /so the verdict is capped at warn/,
    /200 OK with an empty response body where the documented JSON document was expected/,
    /Unable to read Tenable config file .* \((EISDIR|ENOENT)\)/,
    /Unable to parse Tenable config file: invalid YAML in .* at line \d+/,
  ]) {
    assert.match(emitted, family, `the fixtures emit the ${family} family`);
  }
});

test("a documented error field is scrubbed of the configured secrets before it is shortened, so the 200-character cut never leaves a fragment of a secret", async () => {
  const forms = [...secretForms(FIXTURE_ACCESS_KEY), ...secretForms(FIXTURE_SECRET_KEY)];
  for (const form of forms) {
    // The form straddles the 200-character boundary of the shortened field: scrubbing
    // after the cut would leave its head behind.
    const error = `${"x".repeat(200 - Math.floor(form.length / 2))} ${form} was rejected by the upstream identity provider`;
    const body = JSON.stringify({ error });
    const clients = createTenableClients(vmConfig(), {
      fetchImpl: async () => new Response(body, { status: 403, statusText: "Forbidden", headers: { "content-type": "application/json" } }),
      sleepImpl: async () => {},
    });
    await assert.rejects(clients.vm.listScans(), (thrown) => {
      assertNoWindow(thrown.message, form, `straddling ${form}`);
      assert.match(thrown.message, /HTTP 403 Forbidden; x{20,} \[REDACTED\]/, thrown.message);
      return true;
    });
    // The helper on its own, with the default scrub, keeps the same guarantee for the
    // shapes the general scrub knows (the form itself is name-shaped, so only the caller's
    // configured-secret scrub removes it).
    const response = new Response(body, { status: 403, statusText: "Forbidden", headers: { "content-type": "application/json" } });
    assertNoWindow(describeErrorBody(response, body, (text) => redactSecrets(text, [FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY])), form, `describeErrorBody ${form}`);
  }
});

// Canary values that must never survive into any tool result, finding, summary, or bundle
// file: random-looking alphanumerics, no two sharing a 6-character window, so a leaked
// window is attributable (see the window rule above).
const CANARY_BEARER = "rSdnWN7hjTh2aO3y1uHbpA";
const CANARY_SESSION = "Fo9NJvYaHnUppTgu60tP8C";
const CANARY_API_KEY = "l9zRN6mVdNtN6JZ7xz1MXL";
const CANARY_URL_TOKEN = "ho4A04gykhqEgcruJ1Hu65";
// A name-shaped value (the ruling's own example) that only its carrier, a cookie
// assignment, gives away, and a plain lowercase word that only the Bearer scheme does.
const CANARY_NAMED = "sess-canary-COOKIE-31415926535897";
const CANARY_PLAIN = "uhfsumxscmhlzj";
const CANARIES = [CANARY_BEARER, CANARY_SESSION, CANARY_API_KEY, CANARY_URL_TOKEN, CANARY_NAMED, CANARY_PLAIN];
const CANARY_URL = `https://api.example.com/v1/x?token=${CANARY_URL_TOKEN}`;

function htmlCanaryResponse() {
  const body = `<html><head><title>502 Bad Gateway</title></head><body><p>Authorization: Bearer ${CANARY_BEARER}</p>`
    + `<p>Set-Cookie: TNS_SESSIONID=${CANARY_SESSION}; Path=/</p><p>X-ApiKeys: accessKey=${CANARY_API_KEY};secretKey=${CANARY_API_KEY}</p>`
    + `<p>Proxy-Authorization: Bearer ${CANARY_PLAIN}</p><p>Cookie: sid=${CANARY_NAMED}</p>`
    + `<p>The upstream at ${CANARY_URL} did not answer in time, retry later.</p></body></html>`;
  // retry-after: 0 keeps the client's 5xx retries instant when the response reaches a real sleep.
  return new Response(body, { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html; charset=utf-8", "retry-after": "0" } });
}

function jsonCanaryResponse() {
  return new Response(JSON.stringify({
    error: `Upstream refused Bearer ${CANARY_BEARER} at ${CANARY_URL} mid-sentence; session=${CANARY_SESSION}, api_key=${CANARY_API_KEY}, Bearer ${CANARY_PLAIN}, sid=${CANARY_NAMED} rejected`,
  }), { status: 400, statusText: "Bad Request", headers: { "content-type": "application/json" } });
}

// The scrubbed rendering of the JSON canary sentence, as every error string must carry it.
const JSON_CANARY_MARKER = /HTTP 400 Bad Request; Upstream refused Bearer \[REDACTED\] at https:\/\/api\.example\.com\/v1\/x\?token=\[REDACTED\] mid-sentence; session=\[REDACTED\], api_key=\[REDACTED\], Bearer \[REDACTED\], sid=\[REDACTED\] rejected/;
const HTML_CANARY_MARKER = /HTTP 502 Bad Gateway; non-JSON text\/html response body \(\d+ bytes, not echoed\)/;

// The configured secrets of the sweep fixture, echoed bare in prose in every encoded form:
// nothing but the configured-secret pass (guard 2) removes a name-shaped key, so their
// absence proves that pass ran at every sink.
const ECHOED_FORMS = [...secretForms(FIXTURE_ACCESS_KEY), ...secretForms(FIXTURE_SECRET_KEY)];
const ECHOED_MARKER = /HTTP 400 Bad Request; credentials(?: \[REDACTED\])+ rejected/;

function echoedSecretsResponse() {
  return new Response(JSON.stringify({ error: `credentials ${ECHOED_FORMS.join(" ")} rejected` }), { status: 400, statusText: "Bad Request", headers: { "content-type": "application/json" } });
}

function assertNoCanary(text, label, canaries = CANARIES) {
  for (const canary of canaries) assertNoWindow(text, canary, label);
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

// Body text the notes must never echo, whatever the shape (the status text itself is part of the note).
const ECHOED_BODY_TEXT = /<html|Set-Cookie|X-ApiKeys:|TNS_SESSIONID|did not answer|Proxy-Authorization/i;

test("error-body canary sweep: every Tenable surface failing with an HTML 502 or a JSON error body leaks no credential into any tool result, finding, or bundle file", async () => {
  const surfaces = Object.keys(healthyRoutes());
  assert.ok(surfaces.length >= 25, `expected every collector surface to be enumerated, found ${surfaces.length}`);
  const shapes = [
    { name: "html-502", make: htmlCanaryResponse, marker: HTML_CANARY_MARKER, canaries: CANARIES },
    { name: "json-400", make: jsonCanaryResponse, marker: JSON_CANARY_MARKER, canaries: CANARIES },
    { name: "echoed-secrets", make: echoedSecretsResponse, marker: ECHOED_MARKER, canaries: ECHOED_FORMS },
  ];
  // Fixture self-check: each body carries every canary or form verbatim before the scrubs see it.
  for (const shape of shapes) {
    const body = await shape.make().text();
    for (const canary of shape.canaries) assert.ok(body.includes(canary), `fixture self-check: ${shape.name} carries ${canary}`);
  }
  for (const shape of shapes) {
    for (const surface of surfaces) {
      const label = `${shape.name} on ${surface}`;
      const clients = canaryClients(healthyRoutes(), surface, shape.make);
      const noCanary = (text, where) => assertNoCanary(text, where, shape.canaries);

      const access = await checkTenableAccess(clients);
      noCanary(JSON.stringify(access), `${label} access check`);
      const probed = access.surfaces.find((entry) => entry.endpoint === surface);
      if (probed) {
        assert.notEqual(probed.status, "readable", `${label}: surface should not be readable`);
        assert.match(probed.error ?? "", shape.marker, `${label}: access error must carry the note: ${probed.error}`);
      }

      const results = await runAll(clients, { expectedAssetCount: 2 });
      const serialized = JSON.stringify(results);
      noCanary(serialized, `${label} assessments`);
      const errors = results.flatMap((result) => result.errors);
      assert.ok(errors.length > 0, `${label}: the failing surface must be recorded as an error`);
      assert.ok(errors.some((error) => shape.marker.test(error)), `${label}: errors must carry the note: ${JSON.stringify(errors)}`);
      for (const error of errors) assert.doesNotMatch(error, ECHOED_BODY_TEXT, `${label}: body text echoed: ${error}`);

      const bundle = await exportTenableAuditBundle(clients, mkdtempSync(join(tmpdir(), "tenable-canary-")), { now: NOW });
      const files = readBundleFiles(bundle.outputDir);
      const zipEntries = readZipEntries(bundle.zipPath);
      assert.ok(files.size >= 20 && zipEntries.size >= 20, `${label}: bundle and zip were written`);
      assertNoSecretWindows(files, shape.canaries, `${label} bundle`);
      assertNoSecretWindows(zipEntries, shape.canaries, `${label} zip`);
      for (const [name, content] of files) noCanary(content, `${label} ${name}`);
      const errorLog = files.get("_errors.log");
      assert.ok(errorLog !== undefined, `${label}: _errors.log must exist`);
      assert.match(errorLog, shape.marker, `${label}: _errors.log must carry the note`);
    }
  }
});

test("the registered tools scrub error strings end to end over HTTP: access check, every assess tool, and the export", async () => {
  // A local server is not a Tenable cloud host, so the resolver treats it as Tenable
  // Security Center: the registered tools run the Security Center surfaces over the real
  // fetch, the real retry path, and the real config resolver, with the API keys supplied by
  // a YAML config file rather than arguments so the tool boundary must learn them from the
  // resolved configuration. The Vulnerability Management surfaces are covered by the
  // mocked sweep above through the same client and sink code.
  const scUser = { id: "1", username: "auditor", role: { id: "1", name: "Security Manager" }, lastLogin: String(Math.floor(NOW / 1000) - 3600) };
  const scRoutes = {
    "GET /rest/currentUser": { error_code: 0, response: scUser },
    "GET /rest/scan": { error_code: 0, response: { usable: [{ id: "1", name: "Weekly", status: "completed", schedule: { type: "ical", repeatRule: "FREQ=WEEKLY" }, policy: { id: "1" }, credentials: [{ id: "1" }], modifiedTime: String(Math.floor(NOW / 1000) - 3600) }], manageable: [] } },
    "GET /rest/scanResult": { error_code: 0, response: { usable: [{ id: "1", name: "Weekly", status: "Completed", startTime: String(Math.floor(NOW / 1000) - 7200), finishTime: String(Math.floor(NOW / 1000) - 3600), scannedIPs: "10", totalIPs: "10" }], manageable: [] } },
    "GET /rest/scanner": { error_code: 0, response: { usable: [{ id: "1", name: "sc-scanner", status: "1", enabled: "true", version: "10.8.0", pluginSet: RECENT_PLUGIN_SET, loadedPluginSet: RECENT_PLUGIN_SET, lastCheckinTime: String(Math.floor(NOW / 1000) - 600) }], manageable: [] } },
    "GET /rest/user": { error_code: 0, response: { usable: [{ ...scUser, status: "0", locked: "false", failedLogins: "0", authType: "tns" }], manageable: [] } },
    "GET /rest/feed": { error_code: 0, response: { active: { updateTime: String(Math.floor(NOW / 1000) - 3600), stale: "false" } } },
  };
  const failing = new Map();
  const server = createServer((request, response) => {
    const key = `${request.method} ${new URL(`http://127.0.0.1${request.url}`).pathname}`;
    const upstream = failing.has(key)
      ? failing.get(key)()
      : scRoutes[key] !== undefined
        ? jsonResponse(scRoutes[key])
        : jsonResponse({ error_code: 146, error_msg: `unrouted ${key}` }, 404);
    upstream.text().then((text) => {
      response.writeHead(upstream.status, Object.fromEntries(upstream.headers));
      response.end(text);
    });
  });
  await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  const { port } = server.address();
  const configFile = join(mkdtempSync(join(tmpdir(), "tenable-tool-config-")), "config.yaml");
  writeFileSync(configFile, `url: http://127.0.0.1:${port}\naccess_key: ${FIXTURE_ACCESS_KEY}\nsecret_key: ${FIXTURE_SECRET_KEY}\n`);

  const tools = new Map();
  registerTenableTools({ registerTool: (tool) => tools.set(tool.name, tool) });
  const run = async (name, extra = {}) => {
    const tool = tools.get(name);
    return tool.execute("call-tools", tool.prepareArguments({ config_file: configFile, ...extra }));
  };
  const assessTools = ["tenable_assess_scan_program", "tenable_assess_sensor_coverage", "tenable_assess_access_control", "tenable_assess_vulnerability_management"];
  const failingSurfaces = { "GET /rest/scan": "sc_scans", "GET /rest/user": "sc_users" };

  try {
    const healthy = await run("tenable_check_access");
    assert.notEqual(healthy.isError, true, healthy.content[0].text);
    assert.equal(healthy.details.platform, `Tenable Security Center http://127.0.0.1:${port}`, "the local server resolves as Security Center");
    // Security Center alone: its surfaces read, the Vulnerability Management ones are not configured.
    const scProbes = healthy.details.surfaces.filter((probe) => probe.name.startsWith("sc_"));
    assert.ok(scProbes.length >= 4 && scProbes.every((probe) => probe.status === "readable"), JSON.stringify(healthy.details.surfaces));
    assert.ok(healthy.details.surfaces.every((probe) => probe.name.startsWith("sc_") || probe.status === "not_configured"), JSON.stringify(healthy.details.surfaces));
    assert.deepEqual(Object.values(failingSurfaces).filter((name) => !scProbes.some((probe) => probe.name === name)), [], "the failing surfaces are probed by name");
    for (const secret of [FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY]) assertNoWindow(JSON.stringify(healthy), secret, "healthy access check");

    for (const shape of [
      { name: "html-502", make: htmlCanaryResponse, marker: HTML_CANARY_MARKER, canaries: [...CANARIES, ...ECHOED_FORMS] },
      { name: "json-400", make: jsonCanaryResponse, marker: JSON_CANARY_MARKER, canaries: [...CANARIES, ...ECHOED_FORMS] },
      { name: "echoed-secrets", make: echoedSecretsResponse, marker: ECHOED_MARKER, canaries: ECHOED_FORMS },
    ]) {
      failing.clear();
      for (const surface of Object.keys(failingSurfaces)) failing.set(surface, shape.make);
      const noCanary = (text, where) => { for (const canary of shape.canaries) assertNoWindow(text, canary, where); };

      const access = await run("tenable_check_access");
      noCanary(JSON.stringify(access), `${shape.name} tenable_check_access`);
      assert.notEqual(access.isError, true, access.content[0].text);
      const failedProbes = access.details.surfaces.filter((probe) => probe.status !== "readable" && probe.status !== "not_configured");
      assert.deepEqual(failedProbes.map((probe) => probe.name).sort(), Object.values(failingSurfaces).sort(), `${shape.name}: exactly the failing surfaces probe as unreadable`);
      for (const probe of failedProbes) {
        assert.equal(probe.status, "not_readable");
        assert.equal(probe.count, null);
        assert.match(probe.error, shape.marker, `${shape.name}: ${probe.name}: ${probe.error}`);
        assert.equal(probe.httpStatus, shape.name === "html-502" ? 502 : 400, `${shape.name}: the probe carries the observed status`);
      }
      assert.doesNotMatch(access.content[0].text, ECHOED_BODY_TEXT);

      const recorded = [];
      for (const name of assessTools) {
        const result = await run(name);
        noCanary(JSON.stringify(result), `${shape.name} ${name}`);
        assert.notEqual(result.isError, true, result.content[0].text);
        assert.equal(result.details.tool, name);
        for (const error of result.details.errors) {
          assert.doesNotMatch(error, ECHOED_BODY_TEXT, error);
          if (shape.marker.test(error)) recorded.push(error);
        }
        assert.doesNotMatch(result.content[0].text, ECHOED_BODY_TEXT);
      }
      assert.ok(recorded.length >= Object.keys(failingSurfaces).length, `${shape.name}: every failing surface is recorded with the note by the assessment that reads it: ${JSON.stringify(recorded)}`);

      const exported = await run("tenable_export_audit_bundle", { output_dir: mkdtempSync(join(tmpdir(), "tenable-tool-export-")) });
      noCanary(JSON.stringify(exported), `${shape.name} tenable_export_audit_bundle`);
      assert.notEqual(exported.isError, true, exported.content[0].text);
      assert.ok(exported.details.error_count >= Object.keys(failingSurfaces).length, `${shape.name}: the export counts the failed reads`);
      const files = readBundleFiles(exported.details.output_dir);
      const zipEntries = readZipEntries(exported.details.zip_path);
      assert.ok(files.size >= 20 && zipEntries.size === files.size, `${shape.name}: bundle and zip were written`);
      for (const [name, text] of files) noCanary(text, `${shape.name} tool bundle ${name}`);
      for (const [name, text] of zipEntries) noCanary(text, `${shape.name} tool zip ${name}`);
      assert.ok(files.get("_errors.log").split("\n").some((line) => shape.marker.test(line)), `${shape.name}: _errors.log carries the note`);
      // The keys came from the config file alone: metadata names the file, never the values.
      const metadata = JSON.parse(files.get("metadata.json"));
      assert.ok(metadata.source_chain.some((entry) => entry === `config:${configFile}`), JSON.stringify(metadata.source_chain));
    }
  } finally {
    server.close();
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

// Fake credential values the fixtures plant where a real tenant carries them; none may reach
// the bundle. Random-looking alphanumerics (see the window rule above).
const FAKE_TENABLE_SECRETS = {
  sshPassword: "9U1CEev6U71JmHG2ldC100",
  sshPrivateKey: "R1M0s5f4SrgBX0CgcNzyzJ",
  windowsPassword: "KoZR57LLWDrl7waJR0GOBv",
  smtpPassword: "hftgrr92BIbTnK98YFN4io",
  scannerKey: "9U4Je6VR8IKId3TLiyyNFq",
  registrationCode: "BnHNcwxb33SF3JaByM3XfK",
  licenseKey: "PKJwsecPe18jp19Xw6vO2r",
  auditFieldToken: "Yd7rmz2KDiBHYn4oc83WbN",
  webhookQueryToken: "5OvJOMuFTt9kEn8tS14NAW",
  credentialSecret: "0aLPuMBcC3LrhC03EFlIq8",
  camelCaseSecret: "2dzaTJuwLGmPzB5L9ZZEK4",
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
  assertNoSecretWindows(files, secrets, "bundle");
  assertNoSecretWindows(zipEntries, secrets, "zip");
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
  for (const secret of secrets) assertNoWindow(JSON.stringify(results), secret, "assessment result");
});
// Every planted credential of this fixture. The deliberate exceptions to the alphanumeric
// shape are the name-shaped values that prove the configured-secret pass and the carrier
// rules run on their own (hyphenated words with one digit group) and the plain lowercase
// word that only the Bearer scheme gives away.
const PLANTED_CREDENTIALS = [...Object.values(LOADER_CANARIES), ...CANARIES, ...Object.values(FAKE_TENABLE_SECRETS), FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY];
const SHAPED_CREDENTIALS = new Set([CANARY_NAMED, CANARY_PLAIN, FIXTURE_ACCESS_KEY, FIXTURE_SECRET_KEY]);

test("fixture self-check: planted credentials are alphanumeric and random-looking, share no 6-character window with each other, and no 6-character window of any occurs in the fixtures' legitimate text", async () => {
  const owners = new Map();
  for (const value of PLANTED_CREDENTIALS) {
    assert.ok(value.length >= LEAK_WINDOW_MIN, `${value} is too short to carry a window`);
    if (!SHAPED_CREDENTIALS.has(value)) {
      assert.match(value, /^[A-Za-z0-9]+$/, `${value} is not alphanumeric`);
      assert.ok((value.match(/\d/g) ?? []).length >= 2 && (value.match(/[A-Za-z]/g) ?? []).length >= 4, `${value} does not look random`);
    }
    assert.doesNotMatch(value, /(.)\1\1/, `${value} repeats a character three times`);
    for (const window of sixWindows(value)) {
      const owner = owners.get(window);
      assert.ok(owner === undefined || owner === value, `${value} shares the window ${window} with ${owner}`);
      owners.set(window, value);
    }
  }

  // Legitimate text: everything the healthy fixture renders (the access check, every
  // assessment, and every bundle file), plus everything the secret-bearing fixture renders
  // with the planted values themselves removed, so what remains is the fixture's ordinary
  // vocabulary: names, hosts, URLs, ids, dates, and this module's own wording.
  const corpus = [];
  for (const routes of [healthyRoutes(), secretBearingRoutes()]) {
    corpus.push(JSON.stringify(await checkTenableAccess(clientsFor(routes))), JSON.stringify(await runAll(clientsFor(routes))));
    const bundle = await exportTenableAuditBundle(clientsFor(routes), mkdtempSync(join(tmpdir(), "tenable-self-check-")), { now: NOW });
    for (const text of readBundleFiles(bundle.outputDir).values()) corpus.push(text);
  }
  const legitimate = PLANTED_CREDENTIALS.reduce((rest, value) => rest.split(value).join(""), corpus.join("\n"));
  assert.ok(legitimate.length > 10_000, "the legitimate corpus is not empty");
  for (const value of PLANTED_CREDENTIALS) {
    for (const window of sixWindows(value)) assert.ok(!legitimate.includes(window), `window ${window} of ${value} occurs in legitimate fixture text`);
  }
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

/** Wraps a fetch so every request and the status it received are on record for request matching. */
function recordingTenableFetch(inner) {
  const requests = [];
  const fetchImpl = async (url, init = {}) => {
    const parsed = new URL(url);
    const entry = { method: (init.method ?? "GET").toUpperCase(), path: parsed.pathname, status: null };
    requests.push(entry);
    const response = await inner(url, init);
    entry.status = response.status;
    return response;
  };
  return { fetchImpl, requests };
}

/** Whether a "METHOD /path" label (with {placeholder} segments) and status name a request the run made and the status it received. */
function tenableRequestObserved(requests, endpoint, status) {
  const [method, path] = endpoint.split(" ");
  const pattern = new RegExp(`^${path.split("/").map((segment) => (/^\{.+\}$/.test(segment) ? "[^/]+" : segment.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))).join("/")}$`);
  return requests.some((request) => request.method === method && pattern.test(request.path) && (status === null || request.status === status));
}

/** Every object carrying an endpoint, with the HTTP status it names (http_status on a status entry or evidence, status on a marker). */
function tenableEndpointMentions(value, path = []) {
  if (Array.isArray(value)) return value.flatMap((item, index) => tenableEndpointMentions(item, [...path, String(index)]));
  if (!value || typeof value !== "object") return [];
  const mentions = Object.entries(value).flatMap(([key, child]) => tenableEndpointMentions(child, [...path, key]));
  if (typeof value.endpoint === "string") {
    const status = typeof value.http_status === "number" ? value.http_status : typeof value.httpStatus === "number" ? value.httpStatus : typeof value.status === "number" ? value.status : null;
    mentions.push({ at: path.join("."), endpoint: value.endpoint, status });
  }
  return mentions;
}

test("addendum 5: refused or failed Tenable reads write not-collected markers naming the failed request and its status, and every endpoint or status named anywhere matches an observed request", async () => {
  const routes = healthyRoutes();
  routes["GET /users"] = { __status: 403 };
  routes["GET /scanners/null/agents"] = { __status: 403 };
  const { fetchImpl, requests } = recordingTenableFetch(async (url, init) => {
    if (new URL(url).pathname === "/server/properties") return new Response("<html><body>502 Bad Gateway</body></html>", { status: 502, headers: { "content-type": "text/html" } });
    return routerFetch(routes)(url, init);
  });
  const clients = createTenableClients(vmConfig(), { fetchImpl, sleepImpl: async () => {}, exportPollMs: 0, exportTimeoutMs: 5_000 });
  const root = mkdtempSync(join(tmpdir(), "tenable-markers-"));
  const result = await exportTenableAuditBundle(clients, root, { now: NOW });
  const files = readBundleFiles(result.outputDir);
  const read = (name) => JSON.parse(files.get(join("core_data", name)));

  const users = read("users.json");
  assert.deepEqual(users, { collected: false, status: 403, dataset_status: "forbidden", endpoint: "GET /users", error: users.error });
  assert.match(users.error, /403/);
  const agents = read("agents.json");
  assert.equal(agents.collected, false);
  assert.equal(agents.status, 403);
  assert.equal(agents.endpoint, "GET /scanners/null/agents");
  const serverProperties = read("server_properties.json");
  assert.deepEqual(serverProperties, { collected: false, status: 502, dataset_status: "error", endpoint: "GET /server/properties", error: serverProperties.error });
  assert.match(serverProperties.error, /502.*text\/html.*bytes, not echoed/);
  assert.ok(Array.isArray(read("scans.json")), "readable lists keep their content");
  assert.ok(Array.isArray(read("groups.json")));

  const findings = JSON.parse(files.get(join("analysis", "findings.json")));
  const analysis = files.get(join("analysis", "findings.json"));
  const mfa = findings.find((item) => item.id === "TENABLE-10");
  assert.equal(mfa.status, "manual");
  assert.deepEqual(mfa.evidence, { collected: false, endpoint: "GET /users", dataset_status: "forbidden", http_status: 403, error: mfa.evidence.error });
  assert.match(mfa.summary, /GET \/users could not be read because GET \/users refused the API key with HTTP 403/);

  const [scan, sensor, access, vuln] = await runAll(createTenableClients(vmConfig(), { fetchImpl, sleepImpl: async () => {}, exportPollMs: 0, exportTimeoutMs: 5_000 }));
  assert.deepEqual(access.summary.collection.users, { status: "forbidden", endpoint: "GET /users", http_status: 403, seen: null, total: null, truncated: null, error: access.summary.collection.users.error });
  assert.deepEqual(sensor.summary.collection.agents.truncated, null, "a refused walk is neither complete nor truncated");
  assert.equal(sensor.summary.collection.server_properties.http_status, 502);
  assert.equal(sensor.summary.collection.server_properties.status, "error");
  assert.equal(sensor.summary.collection.scanners.status, "ok");
  assert.equal(sensor.summary.collection.scanners.seen, 1);
  assert.equal(sensor.summary.collection.scanners.truncated, false);
  assert.equal(access.summary.user_count, null);
  assert.equal(sensor.summary.agent_count, null);

  const mentions = [
    ...Object.keys(Object.fromEntries(files)).filter((name) => name.startsWith("core_data/")).flatMap((name) => tenableEndpointMentions(JSON.parse(files.get(name)), [name])),
    ...tenableEndpointMentions(findings, ["findings"]),
    ...[scan, sensor, access, vuln].flatMap((assessment) => tenableEndpointMentions(assessment.summary, [assessment.category, "summary"])),
  ];
  assert.ok(mentions.length >= 40, `every dataset is mentioned with its request (${mentions.length})`);
  for (const mention of mentions) {
    assert.ok(tenableRequestObserved(requests, mention.endpoint, mention.status), `${mention.at} names ${mention.endpoint} (status ${mention.status}) but no such request was made`);
  }
  assert.deepEqual([...new Set(mentions.filter((mention) => mention.status === 403).map((mention) => mention.endpoint))].sort(), ["GET /scanners/null/agents", "GET /users"]);
  assert.deepEqual([...new Set(mentions.filter((mention) => mention.status === 502).map((mention) => mention.endpoint))], ["GET /server/properties"]);
  // Finding summaries name requests only in "METHOD /path" form, and only ones the run made.
  for (const match of analysis.matchAll(/\b(GET|POST) (\/[A-Za-z0-9_\-{}/]+(?:\.[A-Za-z0-9_\-{}/]+)*)/g)) {
    assert.ok(tenableRequestObserved(requests, `${match[1]} ${match[2]}`, null), `findings name ${match[0]} but no such request was made`);
  }
  for (const match of analysis.matchAll(/HTTP (\d{3})/g)) {
    assert.ok(requests.some((request) => request.status === Number(match[1])), `findings name HTTP ${match[1]} but no response carried it`);
  }
});

// The Security Center surfaces alongside the Vulnerability Management ones: both
// platforms configured at once, so one sweep covers every request the integration makes.
function healthyScRoutes() {
  const scUser = { id: "1", username: "auditor", role: { id: "1", name: "Security Manager" }, lastLogin: String(Math.floor(NOW / 1000) - 3600) };
  return {
    "GET /rest/currentUser": { error_code: 0, response: scUser },
    "GET /rest/scan": { error_code: 0, response: { usable: [{ id: "1", name: "Weekly", status: "completed", schedule: { type: "ical", repeatRule: "FREQ=WEEKLY" }, policy: { id: "1" }, credentials: [{ id: "1" }], modifiedTime: String(Math.floor(NOW / 1000) - 3600) }], manageable: [] } },
    "GET /rest/scanResult": { error_code: 0, response: { usable: [{ id: "1", name: "Weekly", status: "Completed", startTime: String(Math.floor(NOW / 1000) - 7200), finishTime: String(Math.floor(NOW / 1000) - 3600), scannedIPs: "10", totalIPs: "10" }], manageable: [] } },
    "GET /rest/scanner": { error_code: 0, response: { usable: [{ id: "1", name: "sc-scanner", status: "1", enabled: "true", version: "10.8.0", pluginSet: RECENT_PLUGIN_SET, loadedPluginSet: RECENT_PLUGIN_SET, lastCheckinTime: String(Math.floor(NOW / 1000) - 600) }], manageable: [] } },
    "GET /rest/user": { error_code: 0, response: { usable: [{ ...scUser, status: "0", locked: "false", failedLogins: "0", authType: "tns" }], manageable: [] } },
    "GET /rest/feed": { error_code: 0, response: { active: { updateTime: String(Math.floor(NOW / 1000) - 3600), stale: "false" } } },
  };
}

const SC_FIXTURE = { sc_url: "https://sc.example.internal", sc_access_key: "fixture-sc-access-key-2026", sc_secret_key: "fixture-sc-secret-key-2026" };

function bothPlatformClients(fetchImpl) {
  // A short export deadline: a poll that never reaches a terminal state must not spin for seconds.
  return createTenableClients(vmConfig(SC_FIXTURE), { fetchImpl, sleepImpl: async () => {}, exportPollMs: 0, exportTimeoutMs: 200, retryLimit: 1 });
}

function verdictMap(results) {
  return new Map(allFindings(results).map((finding) => [finding.id, finding.status]));
}

function namedTenableStatusCodes(text) {
  return [...text.matchAll(/HTTP (\d{3})\b/g)].map((match) => Number(match[1]));
}

// Where each surface lands in core_data, so the not-collected marker can be read back.
const SILENT_SUCCESS_MARKERS = {
  "GET /scans": ["scans.json"],
  "GET /policies": ["policies.json"],
  "GET /editor/scan/templates": ["scan_templates.json"],
  "GET /exclusions": ["exclusions.json"],
  "GET /target-groups": ["target_groups.json"],
  "GET /server/properties": ["server_properties.json"],
  "GET /scanners": ["scanners.json"],
  "GET /scanners/null/agents": ["agents.json"],
  "GET /scanners/null/agent-groups": ["agent_groups.json"],
  "GET /networks": ["networks.json"],
  "GET /tags/categories": ["tag_categories.json"],
  "GET /tags/values": ["tag_values.json"],
  "GET /users": ["users.json"],
  "GET /groups": ["groups.json"],
  "GET /access-control/v1/roles": ["roles.json"],
  "GET /api/v3/access-control/permissions": ["permissions.json"],
  "GET /v2/access-groups": ["access_groups.json"],
  "GET /credentials": ["credentials.json"],
  "GET /audit-log/v1/events": ["audit_log_events.json"],
  "GET /vulns/export/status": ["export_jobs.json", "vulns"],
  "GET /assets/export/status": ["export_jobs.json", "assets"],
  "POST /assets/export": ["assets_export.json"],
  "GET /assets/export/asset-export-1/status": ["assets_export.json"],
  "GET /assets/export/asset-export-1/chunks/1": ["assets_export.json"],
  "POST /vulns/export": ["vulns_export.json"],
  "GET /vulns/export/vuln-export-1/status": ["vulns_export.json"],
  "GET /vulns/export/vuln-export-1/chunks/1": ["vulns_export.json"],
  "GET /rest/scan": ["security_center.json", "scans"],
  "GET /rest/scanResult": ["security_center.json", "scan_results"],
  "GET /rest/scanner": ["security_center.json", "scanners"],
  "GET /rest/user": ["security_center.json", "users"],
  "GET /rest/feed": ["security_center.json", "feed"],
};

// Text of the page or of JSON.parse's own message (which quotes a window of the body)
// that must never reach any output.
const NON_DOCUMENT_ECHO = /Captive portal canary page|Unexpected token|is not valid JSON|Unexpected end of JSON|prod-us-east-2026/;

// Every body a proxy, captive portal, sign-in page, or misrouted request can serve with
// a 2xx status in place of the documented document, driven through the real client
// parser path. The page carries two carried canaries so an echo would show; the last
// shape carries a content type that is not shaped like a media type, which is never
// quoted. The foreign object carries no "status" member, so on an export status poll it
// is a foreign document rather than an unknown export state.
const SILENT_SUCCESS_SHAPES = [
  {
    name: "200-html",
    make: () => new Response(
      `<html><head><title>Captive portal canary page</title></head><body><p>Authorization: Bearer ${CANARY_BEARER}</p><p>Cookie: sid=${CANARY_NAMED}</p></body></html>`,
      { status: 200, statusText: "OK", headers: { "content-type": "text/html; charset=utf-8" } },
    ),
    note: /HTTP 200 OK with a non-JSON text\/html response body \(\d+ bytes, not echoed\) where the documented JSON document was expected/,
  },
  {
    name: "200-empty",
    make: () => new Response("", { status: 200, statusText: "OK", headers: { "content-type": "application/json" } }),
    note: /HTTP 200 OK with an empty response body where the documented JSON document was expected/,
  },
  {
    name: "200-json-array",
    make: () => new Response("[]", { status: 200, statusText: "OK", headers: { "content-type": "application/json" } }),
    note: /HTTP 200 OK with a JSON array response body \(2 bytes, not echoed\) where the documented JSON object was expected/,
    // The documented answer of a role list or an export chunk is an array, so [] is a complete empty answer there.
    documentedWhen: (healthy) => Array.isArray(healthy),
  },
  {
    name: "200-foreign-object",
    make: () => new Response(JSON.stringify({ ok: true, region: "prod-us-east-2026" }), { status: 200, statusText: "OK", headers: { "content-type": "application/json" } }),
    note: /HTTP 200 OK with (?:a JSON response body without (?:the documented "[a-z_]+" (?:array|object|list|member)|any of the documented members (?:"[a-z_]+"(?:, )?)+) \(\d+ bytes, not echoed\)|a JSON object response body \(\d+ bytes, not echoed\) where the documented JSON array was expected)/,
  },
  {
    name: "200-hostile-media-type",
    make: () => new Response("<html>Captive portal canary page</html>", { status: 200, statusText: "OK", headers: { "content-type": `Bearer ${CANARY_BEARER}` } }),
    note: /HTTP 200 OK with a non-JSON unknown response body \(\d+ bytes, not echoed\) where the documented JSON document was expected/,
  },
];

test("silent-success class: a 2xx answer without the documented JSON document on any Vulnerability Management or Security Center surface is an unreadable surface with the observed status, never an empty inventory, a readable probe, a healthy check, or a hard verdict", async () => {
  const routes = { ...healthyRoutes(), ...healthyScRoutes() };
  const surfaces = Object.keys(routes);
  assert.ok(surfaces.length >= 34, `every surface of both platforms is enumerated (${surfaces.length})`);
  const overriding = (surface, make) => {
    const fallback = routerFetch(routes);
    return async (url, init) => {
      const key = `${(init?.method ?? "GET").toUpperCase()} ${new URL(url).pathname}`;
      return key === surface ? make() : fallback(url, init);
    };
  };

  // Baseline: both platforms healthy, every request answered 200, and no error recorded.
  const baselineFetch = recordingTenableFetch(routerFetch(routes));
  const baselineClients = bothPlatformClients(baselineFetch.fetchImpl);
  const baselineAccess = await checkTenableAccess(baselineClients);
  assert.equal(baselineAccess.status, "healthy", JSON.stringify(baselineAccess.notes));
  const baselineResults = await runAll(baselineClients, { expectedAssetCount: 2 });
  assert.deepEqual(baselineResults.flatMap((result) => result.errors), []);
  assert.ok(baselineFetch.requests.every((request) => request.status === 200), `the healthy fixture answers every request: ${JSON.stringify(baselineFetch.requests.filter((request) => request.status !== 200))}`);
  const baseline = verdictMap(baselineResults);

  // Positive control: the parser's own message quotes the page, so only the fixed note keeps it out.
  const htmlBody = await SILENT_SUCCESS_SHAPES[0].make().text();
  assert.throws(() => JSON.parse(htmlBody), (error) => /Unexpected token|is not valid JSON/.test(error.message));
  for (const shape of SILENT_SUCCESS_SHAPES) assert.equal(shape.make().status, 200, `${shape.name} is served as a success`);

  for (const surface of surfaces) {
    // A 2xx without the document demotes exactly the verdicts a refusal of the same surface demotes.
    const refusedResults = await runAll(bothPlatformClients(overriding(surface, () => jsonResponse({ error: "forbidden" }, 403))), { expectedAssetCount: 2 });
    const refused = verdictMap(refusedResults);
    const dependents = [...baseline.keys()].filter((id) => refused.get(id) !== baseline.get(id));
    // A surface only the access check reads (the Security Center caller) records no collection error.
    const probeOnly = refusedResults.every((result) => result.errors.length === 0);
    assert.equal(probeOnly, surface === "GET /rest/currentUser", `${surface}: ${probeOnly ? "no collector reads it" : "a collector reads it"}`);
    const [markerFile, markerKey] = SILENT_SUCCESS_MARKERS[surface] ?? [];
    assert.equal(markerFile !== undefined, !probeOnly && !surface.startsWith("GET /policies/"), `${surface}: a collected surface lands in core_data`);

    for (const shape of SILENT_SUCCESS_SHAPES) {
      const label = `${shape.name} on ${surface}`;
      const { fetchImpl, requests } = recordingTenableFetch(overriding(surface, shape.make));
      const clients = bothPlatformClients(fetchImpl);

      if (shape.documentedWhen?.(routes[surface])) {
        // The documented empty answer: a complete, empty inventory, never an error.
        const results = await runAll(clients, { expectedAssetCount: 2 });
        assert.deepEqual(results.flatMap((result) => result.errors), [], `${label}: the documented empty array is not an error`);
        const probe = (await checkTenableAccess(clients)).surfaces.find((entry) => entry.endpoint === surface);
        if (probe) assert.deepEqual({ status: probe.status, count: probe.count }, { status: "readable", count: 0 }, label);
        continue;
      }

      const access = await checkTenableAccess(clients);
      const accessText = JSON.stringify(access);
      assertNoCanary(accessText, `${label} access check`);
      assert.doesNotMatch(accessText, NON_DOCUMENT_ECHO, `${label}: the page or the parser message reached the access check`);
      const probe = access.surfaces.find((entry) => entry.endpoint === surface);
      if (probe) {
        assert.equal(probe.status, "not_readable", `${label}: the probe does not count the surface as readable`);
        assert.equal(probe.httpStatus, 200, `${label}: the probe carries the status the request observed`);
        assert.equal(probe.count, null, `${label}: nothing was read, so nothing is counted`);
        assert.match(probe.error, shape.note, `${label}: ${probe.error}`);
        assert.equal(access.status, "limited", `${label}: a surface that produced no data is not a healthy check`);
        assert.ok(access.notes.some((note) => note.startsWith(`${probe.name} could not be read: `)), `${label}: the notes name the surface: ${access.notes.join(" | ")}`);
        assert.match(access.recommendedNextStep, /Investigate the failed surfaces/, `${label}: the next step names the surface, not the credential`);
        assert.equal(access.surfaces.filter((entry) => entry.status !== "readable").length, 1, `${label}: only the failing surface is unreadable`);
      } else {
        assert.equal(access.status, "healthy", `${label}: the access check does not read this surface`);
      }

      const results = await runAll(clients, { expectedAssetCount: 2 });
      const resultsText = JSON.stringify(results);
      assertNoCanary(resultsText, `${label} assessments`);
      assert.doesNotMatch(resultsText, NON_DOCUMENT_ECHO, `${label}: the page or the parser message reached an assessment`);
      const errors = results.flatMap((result) => result.errors);
      assert.equal(errors.length > 0, !probeOnly, `${label}: the surface is recorded as a collection error exactly when a collector reads it: ${JSON.stringify(errors)}`);
      for (const error of errors) assert.match(error, shape.note, `${label}: ${error}`);
      for (const [id, status] of verdictMap(results)) {
        assert.equal(status, refused.get(id), `${label}: ${id} renders ${status} where a refused read of the same surface renders ${refused.get(id)}`);
        if (dependents.includes(id)) assert.ok(["warn", "manual"].includes(status), `${label}: dependent ${id} rendered the hard verdict ${status}`);
      }
      for (const code of namedTenableStatusCodes(`${accessText}\n${resultsText}`)) {
        assert.equal(code, 200, `${label}: status ${code} is named in output but the fixture served only 200`);
      }

      const exported = await exportTenableAuditBundle(clients, mkdtempSync(join(tmpdir(), "tenable-silent-success-")), { now: NOW });
      const files = readBundleFiles(exported.outputDir);
      for (const [name, content] of files) {
        assertNoCanary(content, `${label} ${name}`);
        assert.doesNotMatch(content, NON_DOCUMENT_ECHO, `${label}: the page or the parser message reached ${name}`);
      }
      if (probeOnly) {
        assert.equal(files.has("_errors.log"), false, `${label}: no collector failed, so there is no _errors.log`);
        const bundledProbe = JSON.parse(files.get(join("core_data", "access_check.json"))).surfaces.find((entry) => entry.endpoint === surface);
        assert.match(bundledProbe.error, shape.note, `${label}: the bundled access check carries the note`);
      } else {
        assert.match(files.get("_errors.log"), shape.note, `${label}: _errors.log carries the note`);
      }
      if (markerFile) {
        const document = JSON.parse(files.get(join("core_data", markerFile)));
        const marker = markerKey ? document[markerKey] : document;
        assert.deepEqual(
          { collected: marker.collected, status: marker.status, dataset_status: marker.dataset_status },
          { collected: false, status: 200, dataset_status: "error" },
          `${label}: the dataset is a marker carrying the observed status, not an empty list: ${JSON.stringify(marker)}`,
        );
        assert.match(marker.error, shape.note, `${label}: the marker carries the note`);
        assert.ok(tenableRequestObserved(requests, marker.endpoint, 200), `${label}: the marker names a request the run made: ${marker.endpoint}`);
      }
      assert.ok(requests.every((request) => request.status === 200), `${label}: every request in the run observed a 2xx`);
    }
  }
});

test("TenableApiClient fails a later page, a status poll, a chunk, or a Security Center envelope that lacks the documented member instead of returning a shorter complete inventory", async () => {
  const scripted = (responses, config = vmConfig()) => {
    let index = 0;
    return createTenableClients(config, { fetchImpl: async () => responses[Math.min(index++, responses.length - 1)](), sleepImpl: async () => {}, exportPollMs: 0, exportTimeoutMs: 200 });
  };
  const ok = (body) => new Response(JSON.stringify(body), { status: 200, statusText: "OK", headers: { "content-type": "application/json" } });

  await assert.rejects(
    scripted([() => ok({ agents: [{ id: 1 }], pagination: { total: 3 } }), () => ok({ pagination: { total: 3 } })]).vm.listAgents(),
    (error) => {
      assert.ok(error instanceof TenableApiError);
      assert.equal(error.status, 200);
      assert.equal(error.endpoint, "GET /scanners/null/agents");
      assert.match(error.message, /^Tenable request GET \/scanners\/null\/agents returned HTTP 200 OK with a JSON response body without the documented "agents" array \(\d+ bytes, not echoed\)$/);
      return true;
    },
  );
  // The documented empty collection (null or []) is still an empty, complete inventory.
  assert.deepEqual(await scripted([() => ok({ scans: null })]).vm.listScans(), []);
  assert.deepEqual(await scripted([() => ok({ users: [] })]).vm.listUsers(), []);
  await assert.rejects(scripted([() => ok({ users: { id: 1 } })]).vm.listUsers(), /without the documented "users" array/);
  await assert.rejects(scripted([() => ok({ ok: true })]).vm.getServerProperties(), /without any of the documented members "plugin_set", "loaded_plugin_set", "server_version", "nessus_type", "nessus_ui_version", "license" \(\d+ bytes, not echoed\)$/);
  await assert.rejects(scripted([() => ok({ ok: true })]).vm.getPolicyDetails(7), /GET \/policies\/7 returned HTTP 200 OK with a JSON response body without any of the documented members "uuid", "settings", "plugins", "credentials"/);
  await assert.rejects(scripted([() => ok({ roles: [] })]).vm.listRoles(), /returned HTTP 200 OK with a JSON object response body \(\d+ bytes, not echoed\) where the documented JSON array was expected$/);
  // A 204 is not a documented answer to any read here and carries no document.
  await assert.rejects(scripted([() => new Response(null, { status: 204, statusText: "No Content" })]).vm.listGroups(), /returned HTTP 204 No Content with an empty response body where the documented JSON document was expected$/);

  // Export: a start without export_uuid, a poll without status, and a chunk that is not an array.
  await assert.rejects(scripted([() => ok({ ok: true })]).vm.exportAssets(), /POST \/assets\/export returned HTTP 200 OK with a JSON response body without the documented "export_uuid" member/);
  const pollFailed = await scripted([() => ok({ export_uuid: "x-1" }), () => ok({ ok: true })]).vm.exportAssets();
  assert.equal(pollFailed.status, "STATUS_UNREADABLE");
  assert.equal(pollFailed.httpStatus, 200);
  assert.equal(pollFailed.endpoint, "GET /assets/export/x-1/status");
  assert.match(pollFailed.reason, /GET \/assets\/export\/x-1\/status returned HTTP 200 OK with a JSON response body without the documented "status" member/);
  const chunkFailed = await scripted([() => ok({ export_uuid: "x-2" }), () => ok({ status: "FINISHED", chunks_available: [1], chunks_failed: [], total_chunks: 1 }), () => ok({ assets: [] })]).vm.exportAssets();
  assert.deepEqual({ status: chunkFailed.status, fetchedChunks: chunkFailed.fetchedChunks, downloadFailures: chunkFailed.downloadFailures, truncated: chunkFailed.truncated, httpStatus: chunkFailed.httpStatus, endpoint: chunkFailed.endpoint }, { status: "FINISHED", fetchedChunks: 0, downloadFailures: 1, truncated: true, httpStatus: 200, endpoint: "GET /assets/export/x-2/chunks/1" });
  assert.match(chunkFailed.reason, /1 chunk downloads failed: Tenable request GET \/assets\/export\/x-2\/chunks\/1 returned HTTP 200 OK with a JSON object response body \(\d+ bytes, not echoed\) where the documented JSON array was expected/);

  // Security Center: the envelope must carry response, and response must have the documented shape.
  const sc = (responses) => scripted(responses, resolveTenableConfiguration({ url: "https://sc.example.internal", access_key: "sc-access-key", secret_key: "sc-secret-key", config_file: EMPTY_CONFIG_FILE }, EMPTY_ENV)).securityCenter;
  await assert.rejects(sc([() => ok({ error_code: 0 })]).getCurrentUser(), /GET \/rest\/currentUser returned HTTP 200 OK with a JSON response body without the documented "response" member/);
  await assert.rejects(sc([() => ok({ error_code: 0, response: [] })]).getCurrentUser(), /without the documented "response" object/);
  await assert.rejects(sc([() => ok({ error_code: 0, response: { id: "1" } })]).listScans(), /GET \/rest\/scan returned HTTP 200 OK with a JSON response body without the documented "response" list/);
  await assert.rejects(sc([() => ok({ error_code: 0, response: "ok" })]).listUsers(), /without the documented "response" list/);
  assert.deepEqual(await sc([() => ok({ error_code: 0, response: { usable: [], manageable: [] } })]).listScanners(), []);
  assert.deepEqual(await sc([() => ok({ error_code: 0, response: [{ id: "9" }] })]).listUsers(), [{ id: "9" }]);
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
    const result = await check.execute("call-1", check.prepareArguments({ access_key: FIXTURE_ACCESS_KEY, secret_key: FIXTURE_SECRET_KEY, config_file: EMPTY_CONFIG_FILE }));
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
