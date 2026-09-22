import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  ANSIBLE_CONTROLS,
  ANSIBLE_REDACTION_MARKER,
  AnsibleAapClient,
  ansibleFixedTexts,
  assessAnsibleHostCoverage,
  assessAnsibleJobHealth,
  assessAnsiblePlatformSecurity,
  checkAnsibleAccess,
  createTlsOptOutFetch,
  currentUserFromMe,
  exportAnsibleAuditBundle,
  findPlaintextSecrets,
  parseRruleInterval,
  projectPing,
  projectUser,
  redactCredentialTree,
  redactErrorText,
  redactVariables,
  resolveAnsibleConfiguration,
  resolveSecureOutputPath,
  sanitizeScmUrl,
} from "../dist/extensions/grc-tools/ansible.js";
import { readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";
import {
  CANARY_VALUES,
  ENCODED_FORM_SECRET,
  HTML_BODY_NOTE,
  PARSER_SNIPPET_CANARY,
  PARSER_WORDING,
  REDACTED_CANARY_URL,
  SHORT_BODY_CANARY,
  SHORT_BODY_CONTENT_TYPE,
  assertCanaryFixture,
  assertNoCanaries,
  assertNoCanaryWindows,
  assertNoCanaryWindowsInFiles,
  assertNoShortBodyFragments,
  assertRedactionCases,
  assertScrubBoundary,
  assertShortBodyRecordedAsNote,
  htmlCanaryBody,
  jsonCanaryMessage,
  parserMessageFor,
  parserSnippetBody,
} from "./helpers/error-canaries.mjs";
import {
  ESCAPED_HEADER_LINES,
  JSON_ESCAPES,
  QUOTED_NON_CREDENTIAL_GROUP,
  assertCredentialPairValuesRemoved,
  assertEscapedHeaderCarriers,
  assertFixedTextsSurvive,
  assertIdentifierKeyRows,
  assertMustKeepRows,
  assertMustRedactRowsBesideMustKeep,
} from "./helpers/redaction-table.mjs";

const NOW = new Date("2026-09-21T00:00:00.000Z");
const SUPERUSER = { id: 1, username: "auditor", is_superuser: true, is_system_auditor: false };
const LIMITED_USER = { id: 2, username: "ops", is_superuser: false, is_system_auditor: false };

const JOB_HEALTH_CONTROLS = [1, 2, 3, 4, 5, 28];
const HOST_COVERAGE_CONTROLS = [6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const PLATFORM_SECURITY_CONTROLS = [16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 29, 30];

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function jsonResponse(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function job(id, template, name, status, started, options = {}) {
  const startedAt = new Date(started);
  const elapsed = options.elapsed ?? 600;
  return {
    id,
    name,
    unified_job_template: template,
    status,
    launch_type: options.launch_type ?? "scheduled",
    started: startedAt.toISOString(),
    finished: status === "running" || status === "pending" ? null : new Date(startedAt.getTime() + elapsed * 1000).toISOString(),
    elapsed: status === "running" || status === "pending" ? 0 : elapsed,
  };
}

function host(id, name, finished, enabled = true) {
  return {
    id,
    name,
    enabled,
    last_job: finished ? 100 + id : null,
    summary_fields: finished ? { last_job: { id: 100 + id, status: "successful", finished } } : {},
  };
}

function jobTemplate(id, name, options = {}) {
  return {
    id,
    name,
    playbook: options.playbook ?? `${name.toLowerCase().replace(/\s+/g, "_")}.yml`,
    description: options.description ?? "",
    last_job_run: options.last_job_run === undefined ? "2026-09-20T00:00:00Z" : options.last_job_run,
    execution_environment: options.execution_environment === undefined ? 1 : options.execution_environment,
    extra_vars: options.extra_vars ?? "---\nregion: us-east-1",
    survey_enabled: options.survey_enabled ?? false,
    ask_variables_on_launch: options.ask_variables_on_launch ?? false,
    ask_credential_on_launch: options.ask_credential_on_launch ?? false,
    ask_execution_environment_on_launch: options.ask_execution_environment_on_launch ?? false,
    summary_fields: {
      credentials: options.credentials ?? [{ id: 1, name: "machine", kind: "ssh" }],
    },
  };
}

let roleSequence = 0;

function role(name, resourceType, resourceName) {
  roleSequence += 1;
  return { id: roleSequence, name, summary_fields: { resource_type: resourceType, resource_name: resourceName, resource_id: 1 } };
}

const HEALTHY_ROUTES = {
  "/api/v2/jobs/": [
    job(13, 12, "Deploy App", "running", "2026-09-20T23:50:00Z"),
    job(12, 10, "Patch Linux", "successful", "2026-09-20T00:00:00Z"),
    job(11, 11, "Harden Baseline", "successful", "2026-09-19T00:00:00Z"),
    job(10, 12, "Deploy App", "successful", "2026-09-18T00:00:00Z", { elapsed: 900 }),
    job(9, 12, "Deploy App", "successful", "2026-09-16T00:00:00Z", { elapsed: 900 }),
    job(8, 12, "Deploy App", "successful", "2026-09-15T00:00:00Z", { elapsed: 900, launch_type: "manual" }),
    job(7, 10, "Patch Linux", "successful", "2026-09-13T00:00:00Z"),
    job(6, 11, "Harden Baseline", "successful", "2026-09-12T00:00:00Z"),
    job(5, 10, "Patch Linux", "failed", "2026-09-10T00:00:00Z"),
    job(4, 10, "Patch Linux", "successful", "2026-09-06T00:00:00Z"),
    job(3, 11, "Harden Baseline", "successful", "2026-09-05T00:00:00Z"),
    job(2, 10, "Patch Linux", "successful", "2026-08-30T00:00:00Z"),
    job(1, 10, "Patch Linux", "successful", "2026-08-23T00:00:00Z"),
  ],
  "/api/v2/settings/jobs/": { SCHEDULE_MAX_JOBS: 10, MAX_FORKS: 200, AD_HOC_COMMANDS: [] },
  "/api/v2/instance_groups/": [{ id: 1, name: "default", max_concurrent_jobs: 0, max_forks: 100 }],
  "/api/v2/hosts/": [
    host(1, "web-1", "2026-09-20T00:10:00Z"),
    host(2, "web-2", "2026-09-19T00:10:00Z"),
    host(3, "db-1", "2026-09-18T00:10:00Z"),
  ],
  "/api/v2/inventory_sources/": [{ id: 1, name: "aws", status: "successful", last_update_failed: false, last_updated: "2026-09-20T00:00:00Z" }],
  "/api/v2/job_host_summaries/": [1, 2, 3].flatMap((hostId) =>
    [0, 1, 2].map((run) => ({ id: hostId * 10 + run, host: hostId, host_name: `host-${hostId}`, failed: false, created: `2026-09-1${run}T00:00:00Z` })),
  ),
  "/api/v2/job_templates/": [
    jobTemplate(10, "Patch Linux"),
    jobTemplate(11, "Harden Baseline", { last_job_run: "2026-09-19T00:00:00Z" }),
    jobTemplate(12, "Deploy App", { credentials: [{ id: 2, name: "deploy", kind: "ssh" }] }),
  ],
  "/api/v2/schedules/": [
    { id: 1, name: "weekly patch", unified_job_template: 10, enabled: true, next_run: "2026-09-27T00:00:00Z", rrule: "DTSTART:20260101T000000Z RRULE:FREQ=WEEKLY;INTERVAL=1" },
    { id: 2, name: "weekly harden", unified_job_template: 11, enabled: true, next_run: "2026-09-26T00:00:00Z", rrule: "DTSTART:20260101T000000Z RRULE:FREQ=WEEKLY;INTERVAL=1" },
  ],
  "/api/v2/workflow_job_templates/": [{ id: 1, name: "Patch and validate", description: "" }],
  "/api/v2/organizations/": [{ id: 1, name: "Default" }],
  "/api/v2/organizations/1/admins/": [{ id: 1, username: "auditor" }],
  "/api/v2/users/": [
    SUPERUSER,
    LIMITED_USER,
    { id: 3, username: "reviewer", is_superuser: false, is_system_auditor: true },
  ],
  "/api/v2/users/1/roles/": [role("System Administrator", "", "")],
  "/api/v2/users/2/roles/": [role("Execute", "job_template", "Patch Linux")],
  "/api/v2/users/3/roles/": [role("Auditor", "organization", "Default")],
  "/api/v2/teams/": [{ id: 1, name: "ops-team" }],
  "/api/v2/teams/1/roles/": [role("Execute", "job_template", "Patch Linux")],
  "/api/v2/credentials/": [
    { id: 1, name: "machine", kind: "ssh", managed: false, modified: "2026-09-01T00:00:00Z", inputs: { username: "ansible", ssh_key_data: "$encrypted$" }, summary_fields: { owners: [{ type: "user", name: "auditor" }] } },
    { id: 2, name: "deploy", kind: "ssh", managed: false, modified: "2026-08-15T00:00:00Z", inputs: { username: "deploy" }, summary_fields: { owners: [{ type: "team", name: "ops-team" }] } },
    { id: 3, name: "prod vault", kind: "vault", managed: false, modified: "2026-09-10T00:00:00Z", inputs: { vault_id: "prod", vault_password: "$encrypted$" }, summary_fields: { owners: [{ type: "user", name: "auditor" }] } },
  ],
  "/api/v2/tokens/": [{ id: 1, created: "2026-09-01T00:00:00Z", expires: "2026-12-01T00:00:00Z" }],
  "/api/v2/projects/": [{ id: 1, name: "playbooks", scm_type: "git", last_update_failed: false, last_updated: "2026-09-20T00:00:00Z" }],
  "/api/v2/inventories/": [{ id: 1, name: "prod", variables: "---\nenv: prod" }],
  "/api/v2/groups/": [{ id: 1, name: "web", variables: "{}" }],
  "/api/v2/execution_environments/": [{ id: 1, name: "default-ee", image: "quay.io/org/ee:2026.9", pull: "missing" }],
  "/api/v2/notification_templates/": [{ id: 1, name: "slack alerts" }],
  "/api/v2/job_templates/10/notification_templates_error/": [{ id: 1, name: "slack alerts" }],
  "/api/v2/job_templates/11/notification_templates_error/": [{ id: 1, name: "slack alerts" }],
  "/api/v2/notifications/": [{ id: 1, status: "successful" }],
  "/api/v2/activity_stream/": [{ id: 1, timestamp: "2026-09-20T22:00:00Z" }],
  "/api/v2/settings/authentication/": { AUTH_LDAP_SERVER_URI: "ldaps://ldap.example.com", SOCIAL_AUTH_SAML_ENABLED_IDPS: {} },
  "/api/v2/settings/system/": { ACTIVITY_STREAM_ENABLED: true },
  "/api/v2/settings/logging/": { LOG_AGGREGATOR_ENABLED: true, LOG_AGGREGATOR_TYPE: "splunk" },
};

function forbidden(path) {
  throw new Error(`AAP request failed: ${path} (403 Forbidden) {"detail":"You do not have permission to perform this action."}`);
}

/**
 * Builds an in-memory client surface. Modes:
 * - normal: serve HEALTHY_ROUTES merged with overrides
 * - forbidden: every endpoint except /api/v2/me/ returns 403
 * - empty: every list is empty and every settings object is {}
 */
function createMockClient({ now = NOW, routes = {}, me = SUPERUSER, mode = "normal", counts = {}, forbiddenPaths = [] } = {}) {
  const resolvedRoutes = { ...HEALTHY_ROUTES, ...routes };
  const requested = [];
  const client = {
    requested,
    getNow: () => now,
    async get(path) {
      requested.push(path);
      if (path === "/api/v2/me/") return { count: 1, results: [me] };
      if (mode === "forbidden" || forbiddenPaths.includes(path)) forbidden(path);
      if (path === "/api/v2/ping/") return { version: "4.6.0", active_node: "controller-1" };
      if (mode === "empty") return {};
      const value = resolvedRoutes[path];
      if (value === undefined) throw new Error(`AAP request failed: ${path} (404 Not Found)`);
      return value;
    },
    async listCollection(path, _query = {}, options = {}) {
      requested.push(path);
      if (mode === "forbidden" || forbiddenPaths.includes(path)) forbidden(path);
      if (mode === "empty") return { items: [], complete: true, total: 0 };
      const value = resolvedRoutes[path];
      if (value === undefined) throw new Error(`AAP request failed: ${path} (404 Not Found)`);
      const items = Array.isArray(value) ? value : value.results ?? [];
      const limit = options.limit ?? Number.POSITIVE_INFINITY;
      const sliced = items.slice(0, limit);
      const complete = sliced.length === items.length;
      return {
        items: sliced,
        complete,
        total: items.length,
        truncation: complete ? undefined : `stopped at the requested limit of ${limit} with a next page still available`,
      };
    },
    async list(path, query, options) {
      return (await client.listCollection(path, query, options)).items;
    },
    async count(path) {
      if (mode === "forbidden" || forbiddenPaths.includes(path)) forbidden(path);
      if (path in counts) return counts[path];
      const value = resolvedRoutes[path];
      if (Array.isArray(value)) return mode === "empty" ? 0 : value.length;
      if (value && typeof value === "object") return 1;
      throw new Error(`AAP request failed: ${path} (404 Not Found)`);
    },
  };
  return client;
}

function byId(result, id) {
  return result.findings.find((item) => item.id === id);
}

function byControl(result, controlNumber) {
  return result.findings.find((item) => item.control === controlNumber);
}

function controlsOf(result) {
  return result.findings.map((item) => item.control).sort((left, right) => left - right);
}

async function runAllAssessments(client) {
  return [
    await assessAnsibleJobHealth(client),
    await assessAnsibleHostCoverage(client),
    await assessAnsiblePlatformSecurity(client),
  ];
}

function assertControlSets(results) {
  assert.deepEqual(controlsOf(results[0]), JOB_HEALTH_CONTROLS);
  assert.deepEqual(controlsOf(results[1]), HOST_COVERAGE_CONTROLS);
  assert.deepEqual(controlsOf(results[2]), PLATFORM_SECURITY_CONTROLS);
}

test("ANSIBLE_CONTROLS maps every spec control 1 to 30 to a unique finding id with six framework mappings", () => {
  assert.equal(ANSIBLE_CONTROLS.length, 30);
  assert.deepEqual(ANSIBLE_CONTROLS.map((item) => item.control).sort((left, right) => left - right), Array.from({ length: 30 }, (_, index) => index + 1));
  assert.equal(new Set(ANSIBLE_CONTROLS.map((item) => item.id)).size, 30);
  for (const definition of ANSIBLE_CONTROLS) {
    assert.deepEqual(Object.keys(definition.mappings).sort(), ["cis", "cmmc", "disa_stig", "fedramp", "pci_dss", "soc2"]);
  }
});

test("resolveAnsibleConfiguration prefers explicit non-secret args and keeps passwords in env", () => {
  const resolved = resolveAnsibleConfiguration(
    {
      url: "https://aap.example.com/api/v2/",
      username: " arg-user ",
      timeout_seconds: "12",
    },
    {
      AAP_URL: "https://env-aap.example.com",
      AAP_USERNAME: "env-user",
      AAP_PASSWORD: "env-password",
    },
  );

  assert.equal(resolved.baseUrl, "https://aap.example.com");
  assert.equal(resolved.username, "arg-user");
  assert.equal(resolved.password, "env-password");
  assert.equal(resolved.timeoutMs, 12_000);
  assert.equal(resolved.verifySsl, true);
  assert.ok(resolved.sourceChain.includes("environment-password"));

  assert.throws(
    () => resolveAnsibleConfiguration({ url: "https://aap.example.com", password: "nope" }, {}),
    /AAP_PASSWORD must be provided via environment/,
  );
});

test("config resolution: credentials set through the environment survive an argument overlay that carries every credential key as undefined and names only an unrelated argument, and the source chain names the environment", () => {
  const env = { AAP_URL: "https://env-aap.example.com", AAP_TOKEN: "hQ2vT8mKp4Xw9ZrLc6Nd", AAP_USERNAME: "env-user", AAP_PASSWORD: "Wq7Lm3Zx8Rt2Vk5Pn9Yb" };
  // The shape createClient hands the resolver: every documented key present, only the unrelated one carrying a value.
  const overlay = { url: undefined, username: undefined, token: undefined, timeout_seconds: 12, verify_ssl: undefined };

  const token = resolveAnsibleConfiguration(overlay, { AAP_URL: env.AAP_URL, AAP_TOKEN: env.AAP_TOKEN });
  assert.equal(token.token, env.AAP_TOKEN, "the environment token resolves");
  assert.equal(token.baseUrl, env.AAP_URL, "the environment URL resolves");
  assert.equal(token.timeoutMs, 12_000, "the unrelated argument is applied");
  assert.deepEqual(token.sourceChain, ["environment"], "the source chain names the environment");

  const session = resolveAnsibleConfiguration(overlay, { AAP_URL: env.AAP_URL, AAP_USERNAME: env.AAP_USERNAME, AAP_PASSWORD: env.AAP_PASSWORD });
  assert.equal(session.username, env.AAP_USERNAME, "the environment username resolves");
  assert.equal(session.password, env.AAP_PASSWORD, "the environment password resolves");
  assert.deepEqual(session.sourceChain, ["environment", "environment-password"], "the source chain names the environment for both");

  // A blank string argument is "not provided" as well: it never shadows the environment value.
  const blank = resolveAnsibleConfiguration({ ...overlay, url: "", token: "  " }, { AAP_URL: env.AAP_URL, AAP_TOKEN: env.AAP_TOKEN });
  assert.equal(blank.token, env.AAP_TOKEN, "a blank token argument does not erase the environment token");
  assert.equal(blank.baseUrl, env.AAP_URL, "a blank url argument does not erase the environment URL");
  assert.deepEqual(blank.sourceChain, ["environment"]);
});

test("resolveAnsibleConfiguration reads AAP_VERIFY_SSL and lets verify_ssl override it", () => {
  const env = { AAP_URL: "https://aap.example.com", AAP_TOKEN: "t", AAP_VERIFY_SSL: "false" };
  assert.equal(resolveAnsibleConfiguration({}, env).verifySsl, false);
  assert.equal(resolveAnsibleConfiguration({ verify_ssl: true }, env).verifySsl, true);
  assert.equal(resolveAnsibleConfiguration({}, { ...env, AAP_VERIFY_SSL: "0" }).verifySsl, false);
  assert.equal(resolveAnsibleConfiguration({}, { ...env, AAP_VERIFY_SSL: "yes" }).verifySsl, true);
  assert.equal(resolveAnsibleConfiguration({}, { AAP_URL: env.AAP_URL, AAP_TOKEN: "t" }).verifySsl, true);
});

test("AAP_VERIFY_SSL=false is request scoped and never mutates NODE_TLS_REJECT_UNAUTHORIZED", async () => {
  const before = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  const server = createHttpServer((request, response) => {
    if (request.url === "/api/v2/me/") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ count: 1, results: [{ id: 7, username: "svc-audit", is_superuser: true, is_system_auditor: false }] }));
      return;
    }
    response.writeHead(403, { "content-type": "application/json" });
    response.end(JSON.stringify({ detail: "forbidden" }));
  });
  await new Promise((resolvePromise) => server.listen(0, "127.0.0.1", resolvePromise));
  try {
    const { port } = server.address();
    const config = resolveAnsibleConfiguration({ url: `http://127.0.0.1:${port}` }, { AAP_TOKEN: "abc", AAP_VERIFY_SSL: "false" });
    assert.equal(config.verifySsl, false);
    const client = new AnsibleAapClient(config);
    const me = await client.get("/api/v2/me/");
    assert.equal(me.results[0].username, "svc-audit");
    await assert.rejects(() => client.get("/api/v2/jobs/"), /403/);
    assert.equal(process.env.NODE_TLS_REJECT_UNAUTHORIZED, before);
  } finally {
    await new Promise((resolvePromise) => server.close(resolvePromise));
  }
  assert.equal(process.env.NODE_TLS_REJECT_UNAUTHORIZED, before);
});

test("createTlsOptOutFetch accepts a self-signed certificate that the default fetch rejects", async (t) => {
  const certDir = createTempBase("grclanker-ansible-tls-");
  try {
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
      "-subj", "/CN=127.0.0.1",
      "-addext", "subjectAltName=IP:127.0.0.1",
      "-keyout", join(certDir, "key.pem"), "-out", join(certDir, "cert.pem"),
    ], { stdio: "ignore" });
  } catch {
    t.skip("openssl is unavailable, so the self-signed TLS fixture cannot be generated");
    return;
  }
  const before = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  const server = createHttpsServer(
    { key: readFileSync(join(certDir, "key.pem")), cert: readFileSync(join(certDir, "cert.pem")) },
    (request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ count: 1, results: [{ id: 1, username: "auditor", is_superuser: true, is_system_auditor: false }], received: request.headers.authorization }));
    },
  );
  await new Promise((resolvePromise) => server.listen(0, "127.0.0.1", resolvePromise));
  try {
    const { port } = server.address();
    const url = `https://127.0.0.1:${port}/api/v2/me/`;
    await assert.rejects(() => fetch(url), (error) => /self.signed|certificate|CERT/i.test(String(error?.cause?.code ?? error?.cause?.message ?? error?.message)));

    const optOut = createTlsOptOutFetch();
    const response = await optOut(url, { method: "GET", headers: { authorization: "Bearer opt-out", accept: "application/json" } });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.received, "Bearer opt-out");

    const client = new AnsibleAapClient({ baseUrl: `https://127.0.0.1:${port}`, token: "scoped", timeoutMs: 5_000, verifySsl: false, sourceChain: ["tests"] });
    const me = await client.get("/api/v2/me/");
    assert.equal(me.results[0].username, "auditor");

    const verifying = new AnsibleAapClient({ baseUrl: `https://127.0.0.1:${port}`, token: "scoped", timeoutMs: 5_000, verifySsl: true, sourceChain: ["tests"] });
    await assert.rejects(() => verifying.get("/api/v2/me/"));
    assert.equal(process.env.NODE_TLS_REJECT_UNAUTHORIZED, before);
  } finally {
    await new Promise((resolvePromise) => server.close(resolvePromise));
  }
  assert.equal(process.env.NODE_TLS_REJECT_UNAUTHORIZED, before);
});

test("AnsibleAapClient sends bearer auth and follows AAP pagination to completion", async () => {
  const seenAuth = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seenAuth.push(init.headers?.authorization);

    if (url.pathname === "/api/v2/jobs/" && !url.searchParams.get("page")) {
      assert.equal(url.searchParams.get("page_size"), "100");
      return jsonResponse({
        count: 2,
        next: "/api/v2/jobs/?page=2&page_size=100",
        results: [{ id: 1, status: "failed" }],
      });
    }

    if (url.pathname === "/api/v2/jobs/" && url.searchParams.get("page") === "2") {
      return jsonResponse({
        count: 2,
        next: null,
        results: [{ id: 2, status: "successful" }],
      });
    }

    return jsonResponse({ detail: "not found" }, 404);
  };

  const client = new AnsibleAapClient(
    {
      baseUrl: "https://aap.example.com",
      token: "aap-token",
      timeoutMs: 30_000,
      verifySsl: true,
      sourceChain: ["tests"],
    },
    { fetchImpl },
  );

  const jobs = await client.list("/api/v2/jobs/");
  assert.equal(jobs.length, 2);
  assert.deepEqual(seenAuth, ["Bearer aap-token", "Bearer aap-token"]);
  const collection = await client.listCollection("/api/v2/jobs/");
  assert.equal(collection.complete, true);
  assert.equal(collection.total, 2);
});

test("verdict rule 7: AnsibleAapClient records truncation when a limit stops before the next page", async () => {
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const page = Number(url.searchParams.get("page") ?? "1");
    return jsonResponse({
      count: 300,
      next: page < 3 ? `/api/v2/hosts/?page=${page + 1}&page_size=100` : null,
      results: Array.from({ length: 100 }, (_, index) => ({ id: (page - 1) * 100 + index + 1 })),
    });
  };
  const client = new AnsibleAapClient(
    { baseUrl: "https://aap.example.com", token: "aap-token", timeoutMs: 30_000, verifySsl: true, sourceChain: ["tests"] },
    { fetchImpl },
  );
  const truncated = await client.listCollection("/api/v2/hosts/", {}, { limit: 150 });
  assert.equal(truncated.items.length, 150);
  assert.equal(truncated.complete, false);
  assert.equal(truncated.total, 300);
  assert.match(truncated.truncation, /next page still available/);

  const full = await client.listCollection("/api/v2/hosts/");
  assert.equal(full.items.length, 300);
  assert.equal(full.complete, true);
});

test("verdict rule 10: listCollection reports a trimmed last page, a repeated next link, an empty page with next, and a count mismatch as incomplete", async () => {
  const makeClient = (fetchImpl) => new AnsibleAapClient(
    { baseUrl: "https://aap.example.com", token: "aap-token", timeoutMs: 30_000, verifySsl: true, sourceChain: ["tests"] },
    { fetchImpl },
  );

  const trimmedLastPage = makeClient(async () => jsonResponse({
    count: 120,
    next: null,
    results: Array.from({ length: 120 }, (_, index) => ({ id: index + 1 })),
  }));
  const trimmed = await trimmedLastPage.listCollection("/api/v2/activity_stream/", {}, { limit: 10 });
  assert.equal(trimmed.items.length, 10);
  assert.equal(trimmed.complete, false, "a limit below the page size must not report the collection complete");
  assert.equal(trimmed.total, 120);
  assert.match(trimmed.truncation, /stopped at the requested limit of 10; 110 items on the last page were not collected/);

  let repeatedCalls = 0;
  const repeatedNext = makeClient(async () => {
    repeatedCalls += 1;
    return jsonResponse({ count: 500, next: "/api/v2/organizations/?page=2&page_size=100", results: Array.from({ length: 100 }, (_, index) => ({ id: index + 1 })) });
  });
  const repeated = await repeatedNext.listCollection("/api/v2/organizations/");
  assert.equal(repeated.complete, false);
  assert.equal(repeatedCalls, 2, "a repeated next link exits after the first repeat instead of looping");
  assert.match(repeated.truncation, /repeated the same next page link/);

  const emptyWithNext = makeClient(async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const page = Number(url.searchParams.get("page") ?? "1");
    return jsonResponse({ count: 200, next: `/api/v2/users/?page=${page + 1}&page_size=100`, results: page === 1 ? [{ id: 1 }] : [] });
  });
  const stalled = await emptyWithNext.listCollection("/api/v2/users/");
  assert.equal(stalled.items.length, 1);
  assert.equal(stalled.complete, false);
  assert.match(stalled.truncation, /empty page while advertising a next page/);

  const shortCount = makeClient(async () => jsonResponse({ count: 7, next: null, results: [{ id: 1 }, { id: 2 }] }));
  const mismatch = await shortCount.listCollection("/api/v2/teams/");
  assert.equal(mismatch.complete, false);
  assert.equal(mismatch.total, 7);
  assert.match(mismatch.truncation, /reported 7 items but only 2 were returned/);

  const noCount = makeClient(async () => jsonResponse({ results: [{ id: 1 }] }));
  assert.equal(await noCount.count("/api/v2/teams/"), undefined, "a missing count is reported as unknown, not as the probe page size");
});

// A `next` link the server controls: its path segment, its query token, a userinfo password, the username of the
// only user the foreign page would serve, and two name-shaped parts the token scrub would keep, so they vanish only
// when nothing echoes the link itself.
const NEXT_LINK_PATH_CANARY = "Hq7vTm3KpXw9ZbLn2Rf";
const NEXT_LINK_QUERY_CANARY = "Wn4kJd8VqRz2TxPy6Mc";
const NEXT_LINK_USERINFO_CANARY = "Fy9bNs2LtKp7WqXm4Vd";
const FOREIGN_PAGE_USER_CANARY = "Zc3tRv8HnQm5KwYp7Lb";
const NEXT_LINK_PATH_NAME = "offsite-hop-segment";
const NEXT_LINK_QUERY_NAME = "offsite-query-marker";
const NEXT_LINK_CANARIES = Object.freeze([NEXT_LINK_PATH_CANARY, NEXT_LINK_QUERY_CANARY, NEXT_LINK_USERINFO_CANARY, FOREIGN_PAGE_USER_CANARY, NEXT_LINK_PATH_NAME, NEXT_LINK_QUERY_NAME]);
const FOREIGN_NEXT_HOST = "offsite.example.net";
/** Origin of AAP_CLIENT_CONFIG.baseUrl, spelled out because that config is declared further down the file. */
const AAP_ORIGIN = "https://aap.example.com";

/**
 * Every shape a server-supplied `next` link can take off the configured base, each with the refusal class its
 * truncation reason must name, plus the same-origin controls (AAP's real root-relative form and the absolute form)
 * that must still be followed.
 */
function aapNextLinkVariants(listPath) {
  const path = `/${NEXT_LINK_PATH_CANARY}/${NEXT_LINK_PATH_NAME}/page2`;
  const query = `page=2&page_size=100&token=${NEXT_LINK_QUERY_CANARY}&hop=${NEXT_LINK_QUERY_NAME}`;
  return {
    refused: {
      host: [`https://${FOREIGN_NEXT_HOST}${path}?${query}`, /another origin \(scheme, host, or port\)/],
      port: [`${AAP_ORIGIN}:8443${path}?${query}`, /another origin \(scheme, host, or port\)/],
      scheme: [`${AAP_ORIGIN.replace("https://", "http://")}${path}?${query}`, /another origin \(scheme, host, or port\)/],
      userinfo: [`${AAP_ORIGIN.replace("https://", `https://intruder:${NEXT_LINK_USERINFO_CANARY}@`)}${path}?${query}`, /carrying userinfo/],
      protocol_relative: [`//${FOREIGN_NEXT_HOST}${path}?${query}`, /another origin \(scheme, host, or port\)/],
      unparseable: [`https://[${NEXT_LINK_PATH_CANARY}${path}?${query}`, /could not be parsed/],
    },
    followed: {
      relative_same_origin: `${listPath}?page=2&page_size=100&token=ctrl-page-2`,
      absolute_same_origin: `${AAP_ORIGIN}${listPath}?page=2&page_size=100&token=ctrl-page-2`,
    },
  };
}

function requestOrigin(url) {
  try {
    return new URL(url).origin;
  } catch {
    return "unparseable";
  }
}

/**
 * Transport for a planted `next` link on the users list: page one carries the link, the same-origin control page
 * serves one control user, and any request that leaves the configured base is answered with a page carrying the
 * foreign superuser so a followed link shows up as inventory poisoning as well as in the request log.
 */
function plantedNextLinkFetch(routes, listPath, link, calls) {
  const routed = aapRoutedFetch(routes);
  return async (url, init) => {
    calls.push({ url, credential: Boolean(init?.headers?.authorization || init?.headers?.cookie) });
    if (requestOrigin(url) !== AAP_ORIGIN) {
      return jsonResponse({ count: 1, next: null, previous: null, results: [{ id: 999, username: FOREIGN_PAGE_USER_CANARY, is_superuser: true, is_system_auditor: false }] });
    }
    const parsed = new URL(url);
    if (parsed.pathname === listPath && parsed.searchParams.get("token") === "ctrl-page-2") {
      return jsonResponse({ count: 4, next: null, previous: `${listPath}?page_size=100`, results: [{ id: 42, username: "ctrl-page-2-user", is_superuser: false, is_system_auditor: false }] });
    }
    if (parsed.pathname === listPath && !parsed.searchParams.get("page")) {
      const firstPage = await routes[listPath](parsed).json();
      return jsonResponse({ ...firstPage, count: firstPage.results.length + 1, next: link });
    }
    return routed(url, init);
  };
}

test("rule 9: a next link that leaves the configured base is refused before any request is made for it, recorded as the collection's truncation reason, and never echoed", async () => {
  const listPath = "/api/v2/users/";
  assert.equal(new URL(AAP_CLIENT_CONFIG.baseUrl).origin, AAP_ORIGIN, "the planted links are built against the configured base");
  const variants = aapNextLinkVariants(listPath);
  for (const [variant, [link, reason]] of Object.entries(variants.refused)) {
    const label = `next (${variant})`;
    const calls = [];
    const client = new AnsibleAapClient(AAP_CLIENT_CONFIG, { fetchImpl: plantedNextLinkFetch(healthyAapRoutes(), listPath, link, calls), now: () => NOW });
    const collection = await client.listCollection(listPath);
    assert.equal(calls.length, 1, `${label}: only page one is requested; the planted link never reaches the transport`);
    assert.equal(new URL(calls[0].url).pathname, listPath, `${label}: the one request is the list itself`);
    assert.deepEqual(collection.items.map((user) => user.username), ["auditor", "ops", "reviewer"], `${label}: the inventory is page one only, nothing merged from the link`);
    assert.equal(collection.complete, false, `${label}: the collection is reported incomplete`);
    assert.equal(collection.total, 4, `${label}: the API's count is kept as the total`);
    assert.match(collection.truncation ?? "", reason, `${label}: the truncation reason names the refusal class`);
    assert.match(collection.truncation, /so the walk was stopped; the link was not followed and no request was made for it/, `${label}: the reason states that no request left`);
    assertNoCanaryWindows(assert, collection, NEXT_LINK_CANARIES, `${label} collection`);
    assert.ok(!JSON.stringify(collection).includes(FOREIGN_NEXT_HOST), `${label}: the reason is fixed text without the link's host`);
  }
  for (const [variant, link] of Object.entries(variants.followed)) {
    const label = `next (${variant})`;
    const calls = [];
    const client = new AnsibleAapClient(AAP_CLIENT_CONFIG, { fetchImpl: plantedNextLinkFetch(healthyAapRoutes(), listPath, link, calls), now: () => NOW });
    const collection = await client.listCollection(listPath);
    assert.equal(calls.length, 2, `${label}: the same-origin control page is followed`);
    assert.equal(requestOrigin(calls[1].url), AAP_ORIGIN, `${label}: the control request stays on the configured base`);
    assert.equal(new URL(calls[1].url).searchParams.get("token"), "ctrl-page-2", `${label}: the control link is requested as served`);
    assert.deepEqual(collection.items.map((user) => user.username), ["auditor", "ops", "reviewer", "ctrl-page-2-user"], `${label}: both pages are merged`);
    assert.equal(collection.complete, true, `${label}: a complete same-origin walk is complete`);
    assert.equal(collection.truncation, undefined, `${label}: a complete walk carries no reason`);
  }

  // The rule also sits in front of the transport itself, ahead of the session login, so a target that reaches get()
  // from anywhere else is refused with fixed text and no request (login bootstrap included) is made for it.
  for (const config of [AAP_CLIENT_CONFIG, { ...AAP_CLIENT_CONFIG, token: undefined, username: "auditor", password: "session-password-for-tests-1" }]) {
    let transportCalls = 0;
    const guarded = new AnsibleAapClient(config, { fetchImpl: async () => { transportCalls += 1; return jsonResponse({}); }, now: () => NOW });
    for (const [variant, [link]] of Object.entries(variants.refused)) {
      const error = await guarded.get(link).then(() => undefined, (thrown) => thrown);
      assert.equal(error?.name, "AnsibleApiError", `${variant}: the refusal is an AnsibleApiError`);
      assert.equal(error.message, "AAP request refused: the target is not on the configured origin, so no request was made.");
      assert.equal(error.endpoint, "not requested", `${variant}: the endpoint field never carries the refused target's path`);
      assert.equal(error.status, undefined, `${variant}: no HTTP status, because no request was made`);
      assertNoCanaryWindows(assert, { message: error.message, endpoint: error.endpoint }, NEXT_LINK_CANARIES, `${variant} refusal`);
    }
    assert.equal(transportCalls, 0, `${config.token ? "token" : "session"} auth: a refused target never reaches the transport`);
  }
  for (const text of ["AAP request refused: the target is not on the configured origin, so no request was made.", "not requested"]) {
    assert.ok(ansibleFixedTexts().includes(text), `"${text}" is in the fixed-text list`);
  }
});

test("rule 9: a refused next link on the users list leaves the access check, the verdicts, and the bundle without any part of the link or the foreign principal, with the reason recorded", async () => {
  const listPath = "/api/v2/users/";
  const [link] = aapNextLinkVariants(listPath).refused.host;
  const calls = [];
  const client = new AnsibleAapClient(AAP_CLIENT_CONFIG, { fetchImpl: plantedNextLinkFetch(healthyAapRoutes(), listPath, link, calls), now: () => NOW });
  const run = await runEveryAnsibleTool(client, createTempBase("grclanker-ansible-next-link-"));

  assert.deepEqual(calls.filter((call) => requestOrigin(call.url) !== AAP_ORIGIN), [], "no request leaves the configured base, credentialed or not");
  assert.equal(run.accessError, undefined);
  assert.equal(run.access.surfaces.find((surface) => surface.name === "users").status, "readable");
  assertNoCanaryWindows(assert, run.access, NEXT_LINK_CANARIES, "check_access");

  const rbac = run.assessments.flatMap((assessment) => assessment.findings).find((item) => item.control === 23);
  assert.equal(rbac.status, "warn", "a verdict over the truncated users list is downgraded from pass");
  assert.equal(rbac.evidence.probed_users, 3, "only the users of page one were probed");
  assert.ok(rbac.evidence.partial_view.some((note) => /^users: 3 of 4 seen \(the API advertised a next page on another origin \(scheme, host, or port\), so the walk was stopped; the link was not followed and no request was made for it\)$/.test(note)), `the partial view carries the reason: ${JSON.stringify(rbac.evidence.partial_view)}`);
  for (const assessment of run.assessments) assertNoCanaryWindows(assert, assessment, NEXT_LINK_CANARIES, assessment.title);

  assert.equal(run.exportError, undefined);
  const files = readBundleFiles(run.exported.outputDir);
  assertNoCanaryWindowsInFiles(assert, files, NEXT_LINK_CANARIES, "bundle");
  assertNoCanaryWindowsInFiles(assert, readZipEntries(run.exported.zipPath), NEXT_LINK_CANARIES, "zip");
  const users = JSON.parse(files.get("core_data/users.json"));
  assert.equal(users.data.complete, false);
  assert.match(users.data.truncation, /another origin/);
  assert.deepEqual(users.data.items.map((user) => user.username), ["auditor", "ops", "reviewer"], "the dataset holds page one only");
  const allText = [...files.values()].join("\n");
  assert.ok(!allText.includes(FOREIGN_NEXT_HOST), "the bundle never names the link's host");
});

test("checkAnsibleAccess reports readable AAP audit surfaces and visibility", async () => {
  const counts = {
    "/api/v2/organizations/": 2,
    "/api/v2/users/": 10,
    "/api/v2/teams/": 3,
    "/api/v2/inventories/": 4,
    "/api/v2/hosts/": 20,
    "/api/v2/job_templates/": 8,
    "/api/v2/workflow_job_templates/": 1,
    "/api/v2/jobs/": 100,
    "/api/v2/job_host_summaries/": 400,
    "/api/v2/credentials/": 6,
    "/api/v2/schedules/": 5,
    "/api/v2/projects/": 4,
    "/api/v2/execution_environments/": 2,
    "/api/v2/instance_groups/": 1,
    "/api/v2/notification_templates/": 1,
    "/api/v2/activity_stream/": 12,
    "/api/v2/settings/authentication/": 1,
    "/api/v2/settings/jobs/": 1,
  };
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.pathname === "/api/v2/me/") {
      return jsonResponse({ count: 1, results: [{ id: 1, username: "auditor", is_superuser: false, is_system_auditor: true }] });
    }
    if (url.pathname === "/api/v2/ping/") {
      return jsonResponse({ version: "4.6.0" });
    }
    if (url.pathname in counts) {
      return jsonResponse({ count: counts[url.pathname], results: [] });
    }
    return jsonResponse({ detail: "not found" }, 404);
  };

  const client = new AnsibleAapClient(
    { baseUrl: "https://aap.example.com", token: "aap-token", timeoutMs: 30_000, verifySsl: true, sourceChain: ["tests"] },
    { fetchImpl },
  );

  const result = await checkAnsibleAccess(client);
  assert.equal(result.status, "healthy");
  assert.equal(result.surfaces.length, 18);
  assert.equal(result.surfaces.filter((surface) => surface.status === "readable").length, 18);
  assert.ok(result.notes.some((note) => /full visibility/.test(note)));
  assert.match(result.recommendedNextStep, /ansible_assess_job_health/);

  const limited = await checkAnsibleAccess(new AnsibleAapClient(
    { baseUrl: "https://aap.example.com", token: "aap-token", timeoutMs: 30_000, verifySsl: true, sourceChain: ["tests"] },
    {
      fetchImpl: async (input) => {
        const url = new URL(typeof input === "string" ? input : input.toString());
        if (url.pathname === "/api/v2/me/") return jsonResponse({ count: 1, results: [{ id: 2, username: "ops", is_superuser: false, is_system_auditor: false }] });
        return jsonResponse({ detail: "forbidden" }, 403);
      },
    },
  ));
  assert.equal(limited.status, "limited");
  assert.ok(limited.notes.some((note) => /not a superuser or system auditor/.test(note)));
  assert.match(limited.recommendedNextStep, /System Auditor/);
});

test("healthy superuser fixture passes all 30 controls with no duplicates", async () => {
  const results = await runAllAssessments(createMockClient());
  assertControlSets(results);
  const findings = results.flatMap((result) => result.findings);
  assert.equal(findings.length, 30);
  const notPassing = findings.filter((item) => item.status !== "pass").map((item) => `${item.id}: ${item.status} ${item.summary}`);
  assert.deepEqual(notPassing, []);
  assert.deepEqual(results.flatMap((result) => result.errors), []);
  for (const item of findings) {
    assert.ok(item.mappings.some((mapping) => mapping.startsWith("FedRAMP ")), `${item.id} lacks FedRAMP mapping`);
    assert.equal(item.mappings.length >= 6, true);
  }
});

test("assessAnsibleJobHealth flags low success, chronic failures, and manual launches", async () => {
  const client = createMockClient({
    routes: {
      "/api/v2/jobs/": [
        job(4, 10, "Patch Linux", "failed", "2026-09-20T00:00:00Z", { launch_type: "manual" }),
        job(3, 10, "Patch Linux", "failed", "2026-09-19T00:00:00Z", { launch_type: "manual" }),
        job(2, 10, "Patch Linux", "failed", "2026-09-18T00:00:00Z"),
        job(1, 11, "Baseline", "successful", "2026-09-17T00:00:00Z"),
      ],
    },
  });

  const result = await assessAnsibleJobHealth(client, { minSuccessRate: 90, maxManualRate: 25 });
  assert.equal(result.summary.total_jobs, 4);
  assert.equal(byId(result, "AAP-JOB-01")?.status, "fail");
  assert.equal(byId(result, "AAP-JOB-02")?.status, "fail");
  assert.equal(byId(result, "AAP-JOB-03")?.status, "warn");
});

test("control 3 flags running jobs beyond 2x the template's successful runtime and never clears undated ones", async () => {
  const stuck = await assessAnsibleJobHealth(createMockClient({
    routes: {
      "/api/v2/jobs/": [
        job(3, 12, "Deploy App", "running", "2026-09-20T21:00:00Z"),
        job(2, 12, "Deploy App", "successful", "2026-09-18T00:00:00Z", { elapsed: 900 }),
        job(1, 12, "Deploy App", "successful", "2026-09-16T00:00:00Z", { elapsed: 900 }),
      ],
    },
  }));
  const stuckFinding = byId(stuck, "AAP-JOB-04");
  assert.equal(stuckFinding.status, "warn");
  assert.equal(stuckFinding.evidence.stuck.length, 1);
  assert.equal(stuckFinding.evidence.stuck[0].baseline_seconds, 900);

  const undated = await assessAnsibleJobHealth(createMockClient({
    routes: {
      "/api/v2/jobs/": [
        { id: 3, name: "Deploy App", unified_job_template: 12, status: "pending", started: null, finished: null, launch_type: "scheduled" },
        job(2, 12, "Deploy App", "successful", "2026-09-18T00:00:00Z", { elapsed: 900 }),
      ],
    },
  }));
  assert.equal(byId(undated, "AAP-JOB-04").status, "warn");
  assert.equal(byId(undated, "AAP-JOB-04").evidence.undated_active, 1);
});

test("control 5 fails unremediated failures, passes remediated ones, and caps undated failures at warn", async () => {
  const unremediated = await assessAnsibleJobHealth(createMockClient({
    routes: {
      "/api/v2/jobs/": [
        job(3, 10, "Patch Linux", "successful", "2026-09-20T00:00:00Z"),
        job(2, 10, "Patch Linux", "failed", "2026-09-01T00:00:00Z"),
        job(1, 11, "Harden Baseline", "successful", "2026-08-25T00:00:00Z"),
      ],
    },
  }));
  const failing = byId(unremediated, "AAP-JOB-05");
  assert.equal(failing.status, "fail");
  assert.equal(failing.evidence.unremediated.length, 1);

  const healthy = await assessAnsibleJobHealth(createMockClient());
  assert.equal(byId(healthy, "AAP-JOB-05").status, "pass");
  assert.equal(byId(healthy, "AAP-JOB-05").evidence.remediated, 1);

  const undated = await assessAnsibleJobHealth(createMockClient({
    routes: {
      "/api/v2/jobs/": [
        job(3, 10, "Patch Linux", "successful", "2026-09-20T00:00:00Z"),
        { id: 2, name: "Patch Linux", unified_job_template: 10, status: "failed", started: null, finished: null, launch_type: "scheduled" },
        job(1, 10, "Patch Linux", "successful", "2026-09-06T00:00:00Z"),
      ],
    },
  }));
  assert.equal(byId(undated, "AAP-JOB-05").status, "warn");
  assert.equal(byId(undated, "AAP-JOB-05").evidence.undated.length, 1);
});

test("control 28 warns on unlimited instance groups and goes manual when limit fields are absent", async () => {
  const unlimited = await assessAnsibleJobHealth(createMockClient({
    routes: { "/api/v2/instance_groups/": [{ id: 1, name: "default", max_concurrent_jobs: 0, max_forks: 0 }] },
  }));
  assert.equal(byId(unlimited, "AAP-JOB-06").status, "warn");
  assert.deepEqual(byId(unlimited, "AAP-JOB-06").evidence.unlimited_groups, ["default"]);

  const legacy = await assessAnsibleJobHealth(createMockClient({
    routes: { "/api/v2/settings/jobs/": { AD_HOC_COMMANDS: [] } },
  }));
  assert.equal(byId(legacy, "AAP-JOB-06").status, "manual");
  assert.match(byId(legacy, "AAP-JOB-06").summary, /SCHEDULE_MAX_JOBS absent/);
});

test("assessAnsibleHostCoverage flags unmanaged, stale, disabled, and sync health gaps", async () => {
  const client = createMockClient({
    routes: {
      "/api/v2/hosts/": [
        host(1, "never-ran", undefined),
        host(2, "stale", "2026-06-01T00:00:00Z"),
        host(3, "disabled", "2026-09-20T00:00:00Z", false),
      ],
      "/api/v2/inventory_sources/": [{ id: 9, name: "aws", status: "failed", last_update_failed: true, last_updated: "2026-09-10T00:00:00Z" }],
    },
  });

  const result = await assessAnsibleHostCoverage(client, { staleHostDays: 30, criticalStaleHostDays: 60 });
  assert.equal(result.summary.total_hosts, 3);
  assert.equal(byId(result, "AAP-HOST-01")?.status, "fail");
  assert.equal(byId(result, "AAP-HOST-02")?.status, "fail");
  assert.equal(byId(result, "AAP-HOST-02")?.severity, "critical");
  assert.equal(byId(result, "AAP-HOST-03")?.status, "warn");
  assert.equal(byId(result, "AAP-HOST-04")?.status, "warn");
});

test("control 9 flags hosts failing more than 30 percent of runs and refuses to judge thin history", async () => {
  const flagged = await assessAnsibleHostCoverage(createMockClient({
    routes: {
      "/api/v2/job_host_summaries/": [
        ...[0, 1, 2, 3].map((run) => ({ id: run, host: 1, host_name: "web-1", failed: run < 3, created: "2026-09-10T00:00:00Z" })),
        ...[0, 1, 2].map((run) => ({ id: 10 + run, host: 2, host_name: "web-2", failed: false, created: "2026-09-10T00:00:00Z" })),
      ],
    },
  }));
  const finding = byId(flagged, "AAP-HOST-05");
  assert.equal(finding.status, "warn");
  assert.equal(finding.evidence.flagged.length, 1);
  assert.equal(finding.evidence.flagged[0].name, "web-1");

  const thin = await assessAnsibleHostCoverage(createMockClient({
    routes: { "/api/v2/job_host_summaries/": [{ id: 1, host: 1, host_name: "web-1", failed: false, created: "2026-09-10T00:00:00Z" }] },
  }));
  assert.equal(byId(thin, "AAP-HOST-05").status, "warn");
});

test("controls 11 to 15 cover stale, unscheduled, missed, disabled schedules and workflow coverage", async () => {
  const result = await assessAnsibleHostCoverage(createMockClient({
    routes: {
      "/api/v2/job_templates/": [
        jobTemplate(10, "Patch Linux", { last_job_run: "2026-01-01T00:00:00Z" }),
        jobTemplate(11, "Harden Baseline", { last_job_run: null }),
        jobTemplate(12, "Deploy App"),
      ],
      "/api/v2/schedules/": [
        { id: 1, name: "weekly patch", unified_job_template: 10, enabled: true, next_run: "2026-09-01T00:00:00Z", rrule: "DTSTART:20260101T000000Z RRULE:FREQ=WEEKLY;INTERVAL=1" },
        { id: 3, name: "nightly deploy", unified_job_template: 12, enabled: false, next_run: null, rrule: "DTSTART:20260101T000000Z RRULE:FREQ=DAILY;INTERVAL=1" },
      ],
      "/api/v2/workflow_job_templates/": [],
    },
  }));

  const stale = byId(result, "AAP-TMPL-01");
  assert.equal(stale.status, "warn");
  assert.deepEqual(stale.evidence.stale, ["Patch Linux"]);
  assert.deepEqual(stale.evidence.never_ran, ["Harden Baseline"]);

  const unscheduled = byId(result, "AAP-TMPL-02");
  assert.equal(unscheduled.status, "fail");
  assert.deepEqual(unscheduled.evidence.unscheduled, ["Harden Baseline"]);

  const missed = byId(result, "AAP-SCHED-01");
  assert.equal(missed.status, "fail");
  assert.match(missed.evidence.missed[0].reason, /next_run is in the past/);

  const disabled = byId(result, "AAP-SCHED-02");
  assert.equal(disabled.status, "warn");
  assert.deepEqual(disabled.evidence.disabled, ["nightly deploy"]);

  const workflows = byId(result, "AAP-TMPL-03");
  assert.equal(workflows.status, "fail");
  assert.match(workflows.summary, /treated as fail/);
});

test("control 13 uses the rrule interval against the template's last run", async () => {
  const result = await assessAnsibleHostCoverage(createMockClient({
    routes: {
      "/api/v2/job_templates/": [jobTemplate(10, "Patch Linux", { last_job_run: "2026-08-01T00:00:00Z" })],
      "/api/v2/schedules/": [
        { id: 1, name: "weekly patch", unified_job_template: 10, enabled: true, next_run: "2026-09-27T00:00:00Z", rrule: "DTSTART:20260101T000000Z RRULE:FREQ=WEEKLY;INTERVAL=1" },
      ],
    },
  }));
  const missed = byId(result, "AAP-SCHED-01");
  assert.equal(missed.status, "fail");
  assert.match(missed.evidence.missed[0].reason, /exceeds 1.5x the WEEKLY x1 interval/);
  const hourly = parseRruleInterval("DTSTART:20260101T000000Z RRULE:FREQ=HOURLY;INTERVAL=6");
  assert.equal(hourly.label, "HOURLY x6");
  assert.ok(Math.abs(hourly.days - 0.25) < 1e-9);
  assert.equal(parseRruleInterval("RRULE:FREQ=BOGUS"), undefined);
  assert.equal(parseRruleInterval(null), undefined);
});

test("assessAnsiblePlatformSecurity flags RBAC, auth, audit, credential, token, and project risks", async () => {
  const client = createMockClient({
    routes: {
      "/api/v2/settings/authentication/": { AUTH_LDAP_SERVER_URI: "" },
      "/api/v2/organizations/1/admins/": [{ id: 1 }, { id: 2 }, { id: 3 }, { id: 4 }],
      "/api/v2/credentials/": [{ id: 1, name: "machine", kind: "ssh", managed: false, modified: "2025-01-01T00:00:00Z", summary_fields: { owners: [{ type: "user", name: "auditor" }] } }],
      "/api/v2/tokens/": [{ id: 1, created: "2025-01-01T00:00:00Z", expires: null }],
      "/api/v2/projects/": [{ id: 1, name: "local playbooks", scm_type: "manual", last_update_failed: false }],
      "/api/v2/notification_templates/": [],
      "/api/v2/activity_stream/": [{ id: 1, timestamp: "2026-09-10T00:00:00Z" }],
    },
  });

  const result = await assessAnsiblePlatformSecurity(client, { maxOrgAdmins: 3, staleCredentialDays: 90, staleTokenDays: 90 });
  assert.equal(byId(result, "AAP-RBAC-01")?.status, "fail");
  assert.equal(byId(result, "AAP-RBAC-02")?.status, "fail");
  assert.equal(byId(result, "AAP-AUDIT-01")?.status, "fail");
  assert.equal(byId(result, "AAP-CRED-01")?.status, "fail");
  assert.deepEqual(byId(result, "AAP-CRED-01")?.evidence.stale_by_kind, { ssh: 1 });
  assert.equal(byId(result, "AAP-CRED-02")?.status, "warn");
  assert.equal(byId(result, "AAP-PROJ-01")?.status, "warn");
  assert.equal(byId(result, "AAP-AUDIT-02")?.status, "fail");
});

test("controls 17 to 19 flag shared credentials, plaintext secrets, and orphaned credentials", async () => {
  const sharedCredential = { id: 1, name: "machine", kind: "ssh" };
  const result = await assessAnsiblePlatformSecurity(createMockClient({
    routes: {
      "/api/v2/job_templates/": [
        ...Array.from({ length: 6 }, (_, index) => jobTemplate(20 + index, `Deploy ${index}`, { credentials: [sharedCredential] })),
        jobTemplate(10, "Patch Linux", { extra_vars: "---\ndb_password: hunter22\nregion: us-east-1", ask_variables_on_launch: true, credentials: [{ id: 3, name: "prod vault", kind: "vault" }] }),
        jobTemplate(11, "Survey Template", { survey_enabled: true, credentials: [] }),
      ],
      "/api/v2/job_templates/11/survey_spec/": {
        name: "",
        spec: [
          { variable: "api_token", type: "text", default: "abc123def456" },
          { variable: "vault_password", type: "password", default: "$encrypted$" },
        ],
      },
      "/api/v2/groups/": [{ id: 1, name: "web", variables: "---\nservice_token: tok_live_9988" }],
      "/api/v2/credentials/": [
        { id: 1, name: "machine", kind: "ssh", managed: false, modified: "2026-09-01T00:00:00Z", summary_fields: { owners: [] } },
        { id: 4, name: "legacy", kind: "ssh", managed: false, modified: "2026-09-01T00:00:00Z", summary_fields: {} },
      ],
      "/api/v2/credentials/4/owner_users/": [],
      "/api/v2/credentials/4/owner_teams/": [],
    },
  }), { maxSharedTemplates: 5 });

  const shared = byId(result, "AAP-CRED-03");
  assert.equal(shared.status, "fail");
  assert.equal(shared.evidence.shared[0].template_count, 6);
  assert.equal(shared.evidence.shared[0].kind, "ssh");

  const plaintext = byId(result, "AAP-CRED-04");
  assert.equal(plaintext.status, "fail");
  const hitTypes = plaintext.evidence.hits.map((hit) => hit.type).sort();
  assert.deepEqual(hitTypes, ["group", "job_template", "survey_spec"]);
  assert.equal(plaintext.evidence.ask_variables_on_launch_templates, 1);
  assert.match(plaintext.summary, /launch-time extra_vars are not scanned/);

  const ownership = byId(result, "AAP-CRED-05");
  assert.equal(ownership.status, "warn");
  assert.deepEqual(ownership.evidence.orphaned, ["machine", "legacy"]);
});

test("findPlaintextSecrets ignores templated, vaulted, and encrypted values", () => {
  assert.deepEqual(findPlaintextSecrets("db_password: hunter22\napi_key: '{{ lookup(\"env\", \"KEY\") }}'\nvault_token: !vault |\n  $ANSIBLE_VAULT;1.1\nssh_password: $encrypted$"), ["db_password"]);
  assert.deepEqual(findPlaintextSecrets('{"client_secret": "s3cr3tvalue", "region": "us-east-1"}'), ["client_secret"]);
  assert.deepEqual(findPlaintextSecrets(""), []);
  assert.deepEqual(findPlaintextSecrets(null), []);
});

test("controls 22 to 24 flag team admin roles, execute plus admin users, and missing auditors", async () => {
  const result = await assessAnsiblePlatformSecurity(createMockClient({
    routes: {
      "/api/v2/users/": [
        { id: 1, username: "root", is_superuser: true, is_system_auditor: false },
        { id: 2, username: "ops", is_superuser: false, is_system_auditor: false },
      ],
      "/api/v2/users/1/roles/": [role("Execute", "job_template", "Patch Linux"), role("System Administrator", "", "")],
      "/api/v2/users/2/roles/": [role("Execute", "job_template", "Patch Linux"), role("Admin", "credential", "machine")],
      "/api/v2/teams/": [{ id: 1, name: "platform-admins" }, { id: 2, name: "ops-team" }],
      "/api/v2/teams/1/roles/": [role("Admin", "organization", "Default")],
      "/api/v2/teams/2/roles/": [role("Execute", "job_template", "Patch Linux")],
    },
  }));

  const teamAudit = byId(result, "AAP-RBAC-03");
  assert.equal(teamAudit.status, "fail");
  assert.equal(teamAudit.evidence.org_admin_teams[0].team, "platform-admins");

  const separation = byId(result, "AAP-RBAC-04");
  assert.equal(separation.status, "fail");
  assert.equal(separation.evidence.violations.length, 2);
  assert.equal(separation.evidence.violations.find((item) => item.user === "root").is_superuser, true);

  const auditors = byId(result, "AAP-RBAC-05");
  assert.equal(auditors.status, "warn");
  assert.deepEqual(auditors.evidence.uncovered, ["Default"]);
});

test("control 30 warns on default or launch-time execution environments and reads the ask flag", async () => {
  const result = await assessAnsiblePlatformSecurity(createMockClient({
    routes: {
      "/api/v2/job_templates/": [
        jobTemplate(10, "Patch Linux", { execution_environment: null }),
        jobTemplate(11, "Harden Baseline", { execution_environment: null, ask_execution_environment_on_launch: true }),
        jobTemplate(12, "Deploy App"),
      ],
    },
  }));
  const finding = byId(result, "AAP-PLAT-01");
  assert.equal(finding.status, "warn");
  assert.deepEqual(finding.evidence.defaulted, ["Patch Linux"]);
  assert.deepEqual(finding.evidence.launch_time, ["Harden Baseline"]);
});

test("verdict rule 1: forbidden endpoints yield manual findings naming the cause and the evidence to collect", async () => {
  const jobHealth = await assessAnsibleJobHealth(createMockClient({ routes: { "/api/v2/jobs/": undefined } }));
  for (const controlNumber of [1, 2, 3, 4, 5]) {
    const finding = byControl(jobHealth, controlNumber);
    assert.equal(finding.status, "manual", `control ${controlNumber}`);
    assert.match(finding.summary, /404 Not Found/);
    assert.match(finding.summary, /Collect this evidence manually/);
  }
  assert.ok(jobHealth.errors.some((error) => error.includes("/api/v2/jobs/")));

  const platform = await assessAnsiblePlatformSecurity(createMockClient({
    routes: { "/api/v2/tokens/": undefined, "/api/v2/settings/authentication/": undefined },
  }));
  assert.equal(byId(platform, "AAP-CRED-02").status, "manual");
  assert.match(byId(platform, "AAP-CRED-02").summary, /Tokens tab/);
  assert.equal(byId(platform, "AAP-RBAC-02").status, "manual");
  assert.match(byId(platform, "AAP-RBAC-02").summary, /LDAP, SAML, or OIDC/);
});

test("verdict rule 2: empty inventories never pass by default and state their treatment", async () => {
  const jobHealth = await assessAnsibleJobHealth(createMockClient({ routes: { "/api/v2/jobs/": [] } }));
  assert.equal(byControl(jobHealth, 1).status, "fail");
  assert.match(byControl(jobHealth, 1).summary, /treated as fail/);
  for (const controlNumber of [2, 3, 4, 5]) {
    assert.equal(byControl(jobHealth, controlNumber).status, "manual");
    assert.match(byControl(jobHealth, controlNumber).summary, /treated as manual/);
  }

  const hosts = await assessAnsibleHostCoverage(createMockClient({ routes: { "/api/v2/hosts/": [], "/api/v2/schedules/": [] } }));
  for (const controlNumber of [6, 7, 10, 13, 14]) {
    assert.equal(byControl(hosts, controlNumber).status, "manual", `control ${controlNumber}`);
    assert.match(byControl(hosts, controlNumber).summary, /treated as manual/);
  }

  const platform = await assessAnsiblePlatformSecurity(createMockClient({
    routes: { "/api/v2/credentials/": [], "/api/v2/teams/": [], "/api/v2/notification_templates/": [], "/api/v2/activity_stream/": [] },
  }));
  assert.equal(byControl(platform, 16).status, "manual");
  assert.equal(byControl(platform, 19).status, "manual");
  assert.equal(byControl(platform, 22).status, "manual");
  assert.equal(byControl(platform, 27).status, "fail");
  assert.match(byControl(platform, 27).summary, /treated as fail/);
  assert.equal(byControl(platform, 26).status, "fail");
  assert.match(byControl(platform, 26).summary, /treated as fail/);
});

test("verdict rule 3: controls the deployment cannot expose render as manual, never pass", async () => {
  const platform = await assessAnsiblePlatformSecurity(createMockClient({
    routes: {
      "/api/v2/execution_environments/": undefined,
      "/api/v2/settings/authentication/": { SESSION_COOKIE_AGE: 1800 },
    },
  }));
  assert.equal(byId(platform, "AAP-PLAT-01").status, "manual");
  assert.match(byId(platform, "AAP-PLAT-01").summary, /predate execution environments/);
  assert.equal(byId(platform, "AAP-RBAC-02").status, "manual");
  assert.match(byId(platform, "AAP-RBAC-02").summary, /platform gateway/);

  const noField = await assessAnsiblePlatformSecurity(createMockClient({
    routes: { "/api/v2/job_templates/": [{ id: 10, name: "Patch Linux", last_job_run: "2026-09-20T00:00:00Z", summary_fields: { credentials: [] } }] },
  }));
  assert.equal(byId(noField, "AAP-PLAT-01").status, "manual");
  assert.match(byId(noField, "AAP-PLAT-01").summary, /do not expose an execution_environment field/);

  const legacyJobs = await assessAnsibleJobHealth(createMockClient({ routes: { "/api/v2/settings/jobs/": { AD_HOC_COMMANDS: [] } } }));
  assert.equal(byId(legacyJobs, "AAP-JOB-06").status, "manual");
});

test("verdict rule 4: items missing a date are never counted fresh and cap at warn", async () => {
  const hosts = await assessAnsibleHostCoverage(createMockClient({
    routes: {
      "/api/v2/hosts/": [{ id: 1, name: "web-1", enabled: true, last_job: 101, summary_fields: { last_job: { id: 101, status: "successful" } } }],
      "/api/v2/inventory_sources/": [{ id: 1, name: "aws", status: "never updated", last_update_failed: false, last_updated: null }],
      "/api/v2/job_templates/": [jobTemplate(10, "Patch Linux", { last_job_run: null })],
    },
  }));
  assert.equal(byId(hosts, "AAP-HOST-01").status, "pass");
  assert.equal(byId(hosts, "AAP-HOST-02").status, "warn");
  assert.match(byId(hosts, "AAP-HOST-02").summary, /cannot be counted as fresh/);
  assert.equal(byId(hosts, "AAP-HOST-03").status, "warn");
  assert.equal(byId(hosts, "AAP-TMPL-01").status, "warn");

  const platform = await assessAnsiblePlatformSecurity(createMockClient({
    routes: {
      "/api/v2/credentials/": [{ id: 1, name: "machine", kind: "ssh", managed: false, modified: null, summary_fields: { owners: [{ type: "user", name: "auditor" }] } }],
      "/api/v2/tokens/": [{ id: 1, created: null, expires: "2026-12-01T00:00:00Z" }],
      "/api/v2/projects/": [{ id: 1, name: "playbooks", scm_type: "git", last_update_failed: false, last_updated: null }],
      "/api/v2/activity_stream/": [{ id: 1, timestamp: null }],
    },
  }));
  assert.equal(byId(platform, "AAP-CRED-01").status, "warn");
  assert.equal(byId(platform, "AAP-CRED-02").status, "warn");
  assert.equal(byId(platform, "AAP-PROJ-01").status, "warn");
  assert.equal(byId(platform, "AAP-AUDIT-01").status, "warn");
});

test("verdict rule 5: a non-superuser audit account downgrades every would-be pass to warn", async () => {
  const results = await runAllAssessments(createMockClient({ me: LIMITED_USER }));
  assertControlSets(results);
  const findings = results.flatMap((result) => result.findings);
  assert.equal(findings.filter((item) => item.status === "pass").length, 0);
  const downgraded = findings.filter((item) => item.status === "warn" && /Downgraded from pass to warn/.test(item.summary));
  assert.ok(downgraded.length >= 25, `expected most controls downgraded, got ${downgraded.length}`);
  for (const item of downgraded) {
    assert.ok(item.evidence.partial_view.some((note) => /neither a superuser nor a system auditor/.test(note)));
  }
  assert.equal(results[0].summary.full_visibility, false);
});

test("verdict rule 5 and 7: a truncated list is flagged as partial and downgrades pass to warn", async () => {
  const client = createMockClient({
    routes: {
      "/api/v2/hosts/": Array.from({ length: 12 }, (_, index) => host(index + 1, `web-${index + 1}`, "2026-09-20T00:10:00Z")),
    },
  });
  const result = await assessAnsibleHostCoverage(client, { hostLimit: 5 });
  const unmanaged = byId(result, "AAP-HOST-01");
  assert.equal(unmanaged.status, "warn");
  assert.match(unmanaged.summary, /inventory is partial/);
  assert.ok(unmanaged.evidence.partial_view.some((note) => /hosts: 5 of 12 seen/.test(note)));
  assert.equal(result.summary.total_hosts, 5);
  assert.equal(result.summary.hosts_total_reported, 12);
});

test("verdict rule 6: documented flags drive verdicts", async () => {
  const hosts = await assessAnsibleHostCoverage(createMockClient({
    routes: {
      "/api/v2/schedules/": [
        { id: 1, name: "weekly patch", unified_job_template: 10, enabled: true, next_run: "2026-09-27T00:00:00Z", rrule: "DTSTART:20260101T000000Z RRULE:FREQ=WEEKLY;INTERVAL=1" },
        { id: 2, name: "weekly harden", unified_job_template: 11, next_run: "2026-09-26T00:00:00Z", rrule: "DTSTART:20260101T000000Z RRULE:FREQ=WEEKLY;INTERVAL=1" },
      ],
    },
  }));
  assert.equal(byId(hosts, "AAP-SCHED-02").status, "warn");
  assert.match(byId(hosts, "AAP-SCHED-02").summary, /have no enabled flag/);

  const platform = await assessAnsiblePlatformSecurity(createMockClient({
    routes: {
      "/api/v2/job_templates/": [
        jobTemplate(10, "Patch Linux", { ask_credential_on_launch: true }),
        jobTemplate(11, "Harden Baseline"),
        jobTemplate(12, "Deploy App", { credentials: [{ id: 2, name: "deploy", kind: "ssh" }] }),
      ],
      "/api/v2/users/": [
        { id: 1, username: "auditor", is_superuser: true, is_system_auditor: false },
        { id: 2, username: "ops", is_superuser: false, is_system_auditor: false },
        { id: 3, username: "reviewer", is_superuser: false, is_system_auditor: false },
      ],
    },
  }));
  const shared = byId(platform, "AAP-CRED-03");
  assert.deepEqual(shared.evidence.ask_credential_on_launch_templates, ["Patch Linux"]);
  assert.match(shared.summary, /ask_credential_on_launch/);
  const plaintext = byId(platform, "AAP-CRED-04");
  assert.deepEqual(plaintext.evidence.vault_credentials, [{ name: "prod vault", vault_id: "prod" }]);
  assert.match(plaintext.summary, /1 Vault credentials \(vault_id: prod\)/);
  const auditors = byId(platform, "AAP-RBAC-05");
  assert.equal(auditors.status, "pass");
  assert.deepEqual(auditors.evidence.system_auditors, []);
  assert.deepEqual(auditors.evidence.audited_organizations, ["Default"]);

  const noAuditor = await assessAnsiblePlatformSecurity(createMockClient({
    routes: {
      "/api/v2/users/": [{ id: 1, username: "auditor", is_superuser: true, is_system_auditor: false }],
      "/api/v2/teams/1/roles/": [role("Execute", "job_template", "Patch Linux")],
      "/api/v2/users/1/roles/": [role("System Administrator", "", "")],
    },
  }));
  assert.equal(byId(noAuditor, "AAP-RBAC-05").status, "warn");
});

test("false-pass self-check (a): all-403 fixture produces no pass in any assess tool", async () => {
  const results = await runAllAssessments(createMockClient({ mode: "forbidden" }));
  assertControlSets(results);
  const findings = results.flatMap((result) => result.findings);
  assert.equal(findings.length, 30);
  assert.equal(findings.filter((item) => item.status === "pass").length, 0);
  assert.equal(findings.filter((item) => item.status === "manual").length, 30);
  for (const item of findings) {
    assert.match(item.summary, /403 Forbidden|could not be read/);
  }
  assert.ok(results.every((result) => result.errors.length > 0));
});

test("false-pass self-check (b): all-empty fixture passes only where emptiness is compliant by intent", async () => {
  const results = await runAllAssessments(createMockClient({ mode: "empty" }));
  assertControlSets(results);
  const findings = results.flatMap((result) => result.findings);
  const passes = findings.filter((item) => item.status === "pass").map((item) => item.id);
  assert.deepEqual(passes, ["AAP-CRED-02"]);
  assert.match(byId(results[2], "AAP-CRED-02").summary, /compliant by intent/);
  assert.deepEqual(findings.filter((item) => item.status === "fail").map((item) => item.id).sort(), ["AAP-AUDIT-01", "AAP-AUDIT-02", "AAP-JOB-01"]);
  const manualOrWarn = findings.filter((item) => item.status === "manual" || item.status === "warn");
  assert.equal(manualOrWarn.length, 26);
});

test("false-pass self-check (c): partial-inventory fixture produces no pass in any assess tool", async () => {
  const limitedScope = await runAllAssessments(createMockClient({ me: LIMITED_USER }));
  assert.equal(limitedScope.flatMap((result) => result.findings).filter((item) => item.status === "pass").length, 0);

  const capped = createMockClient();
  const cappedResults = [
    await assessAnsibleJobHealth(capped, { jobLimit: 5 }),
    await assessAnsibleHostCoverage(capped, { hostLimit: 2, templateLimit: 2 }),
    await assessAnsiblePlatformSecurity(capped, { userLimit: 2, templateLimit: 2 }),
  ];
  assertControlSets(cappedResults);
  const expectations = [
    [cappedResults[0], [1, 2, 3, 4, 5], /jobs: 5 of 13 seen/],
    [cappedResults[1], [6, 7, 10], /hosts: 2 of 3 seen/],
    [cappedResults[1], [11, 12, 13, 15], /job templates: 2 of 3 seen/],
    [cappedResults[2], [17, 18, 30], /job templates: 2 of 3 seen/],
    [cappedResults[2], [22, 23, 24], /users: 2 of 3 seen/],
  ];
  for (const [result, controls, note] of expectations) {
    for (const controlNumber of controls) {
      const finding = byControl(result, controlNumber);
      assert.notEqual(finding.status, "pass", `control ${controlNumber} passed on a capped list`);
      assert.ok(finding.evidence.partial_view.some((entry) => note.test(entry)), `control ${controlNumber} lacks the truncation note`);
    }
  }
  assert.equal(cappedResults[0].summary.total_jobs, 5);
  assert.equal(cappedResults[0].summary.jobs_total_reported, 13);
});

test("exportAnsibleAuditBundle writes the shared layout with compliance reports and a matching zip", async () => {
  const base = createTempBase("grclanker-ansible-export-");
  const client = createMockClient();
  const config = {
    baseUrl: "https://aap.example.com",
    token: ANSIBLE_EXPORT_TOKEN_CANARY,
    timeoutMs: 30_000,
    verifySsl: true,
    sourceChain: ["tests"],
  };

  const result = await exportAnsibleAuditBundle(client, config, base, { days: 30, job_limit: 20, host_limit: 20 });

  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.equal(result.zipPath, `${result.outputDir}.zip`);
  assert.equal(result.findingCount, 30);
  assert.equal(result.errorCount, 0);
  assert.ok(!existsSync(join(result.outputDir, "_errors.log")));
  for (const relativePath of [
    "README.md",
    "QUICK_REFERENCE.md",
    "core_data/access.json",
    "core_data/jobs.json",
    "core_data/hosts.json",
    "core_data/schedules.json",
    "core_data/credentials.json",
    "core_data/settings_authentication.json",
    "analysis/findings.json",
    "analysis/metadata.json",
    "analysis/job-health.json",
    "analysis/host-coverage.md",
    "analysis/platform-security.json",
    "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md",
    "compliance/fedramp/fedramp_compliance_report.md",
    "compliance/cmmc/cmmc_compliance_report.md",
    "compliance/soc2/soc2_compliance_report.md",
    "compliance/cis/cis_compliance_report.md",
    "compliance/pci_dss/pci_dss_compliance_report.md",
    "compliance/disa_stig/stig_compliance_checklist.md",
  ]) {
    assert.ok(existsSync(join(result.outputDir, relativePath)), `${relativePath} missing`);
  }
  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  assert.equal(findings.length, 30);
  assert.match(readFileSync(join(result.outputDir, "compliance", "executive_summary.md"), "utf8"), /Controls assessed: 30 of 30/);
  assert.match(readFileSync(join(result.outputDir, "compliance", "unified_compliance_matrix.md"), "utf8"), /AAP-JOB-01/);
  assert.match(readFileSync(join(result.outputDir, "compliance", "fedramp", "fedramp_compliance_report.md"), "utf8"), /CA-7, SI-2/);
  assert.equal(readFileSync(result.zipPath).subarray(0, 2).toString("utf8"), "PK");
  const metadata = JSON.parse(readFileSync(join(result.outputDir, "analysis", "metadata.json"), "utf8"));
  assert.equal(metadata.controls_assessed, 30);
  assert.equal(metadata.verify_ssl, true);
  const rawBundle = readFileSync(join(result.outputDir, "core_data", "credentials.json"), "utf8");
  assertNoCanaryWindows(assert, rawBundle, [ANSIBLE_EXPORT_TOKEN_CANARY], "core_data/credentials.json");
});

test("exportAnsibleAuditBundle writes _errors.log when some reads fail but the bundle completes", async () => {
  const base = createTempBase("grclanker-ansible-export-errors-");
  const client = createMockClient({ routes: { "/api/v2/tokens/": undefined, "/api/v2/settings/logging/": undefined } });
  const config = { baseUrl: "https://aap.example.com", token: "aap-token", timeoutMs: 30_000, verifySsl: false, sourceChain: ["tests"] };

  const result = await exportAnsibleAuditBundle(client, config, base, {});
  assert.ok(result.errorCount >= 2);
  const errorLog = readFileSync(join(result.outputDir, "_errors.log"), "utf8");
  assert.match(errorLog, /\/api\/v2\/tokens\//);
  assert.match(errorLog, /\/api\/v2\/settings\/logging\//);
  assert.match(readFileSync(join(result.outputDir, "compliance", "executive_summary.md"), "utf8"), /Partial Collection Warnings/);
  assert.match(readFileSync(join(result.outputDir, "compliance", "executive_summary.md"), "utf8"), /disabled for this run/);
});

test("verdict rule 8: re-running the export allocates a new directory and never overwrites the prior bundle", async () => {
  const base = createTempBase("grclanker-ansible-export-rerun-");
  const config = { baseUrl: "https://aap.example.com", token: "aap-token", timeoutMs: 30_000, verifySsl: true, sourceChain: ["tests"] };

  const first = await exportAnsibleAuditBundle(createMockClient(), config, base, {});
  const marker = join(first.outputDir, "README.md");
  const firstReadme = readFileSync(marker, "utf8");
  const firstZipStat = statSync(first.zipPath);
  writeFileSync(marker, `${firstReadme}\nlocal note\n`);

  const second = await exportAnsibleAuditBundle(createMockClient({ routes: { "/api/v2/tokens/": [] } }), config, base, {});
  assert.notEqual(second.outputDir, first.outputDir);
  assert.notEqual(second.zipPath, first.zipPath);
  assert.equal(second.zipPath, `${second.outputDir}.zip`);
  assert.ok(second.outputDir.endsWith("-2"));
  assert.equal(readFileSync(marker, "utf8"), `${firstReadme}\nlocal note\n`);
  assert.equal(statSync(first.zipPath).size, firstZipStat.size);
  assert.deepEqual(
    readdirSync(base).filter((entry) => entry.endsWith(".zip")).sort(),
    [first.zipPath, second.zipPath].map((entry) => entry.slice(entry.lastIndexOf("/") + 1)).sort(),
  );
});

/**
 * Planted values that must never reach the bundle, alphanumeric and random-looking so no 6-character window of
 * them occurs in the fixture's legitimate values (see the fixture self-check).
 */
const FAKE_ANSIBLE_SECRETS = {
  jobVar: "VGXeGJApvMQs9N9Y",
  templateVar: "jBq3DGELKj3xDV8H",
  workflowVar: "CMdZGBb9hMDPcVpZ",
  scheduleVar: "Y8gNVnxh6p7QBk5U",
  hostVar: "bUwvuYPqv7yeHWfK",
  sourceVar: "vu2F9nhApyBVTj8X",
  inventoryVar: "k4wMSMDh5DKqUQRA",
  groupVar: "RQ2avbAVnVWzCv9W",
  proxyPassword: "xTMeP8Wvx92YAXw8",
  galaxyToken: "Rrv2Mnx7EX7KgtTz",
  webhookPath: "w5Mv8GTS59UdHUAR",
  errorWebhookPath: "aHBxdNsXyU59Ckeq",
  headerValue: "bSvyaK4E7sDNdZqy",
  pairHeaderValue: "pr5yrQe2qGeJBP3f",
  slackToken: "uUVRsNMEa9w6DN2K",
  scmToken: "X89StUkLvF4K83bS",
  activityChange: "QWK8kfEm8Gd6DXVn",
  surveyDefault: "qQp96Geme6eWUxjR",
  credentialInput: "Pj8nfpDspLwLrnSD",
  tokenValue: "JSPjcxzMspntP5VF",
  refreshToken: "hGcSb2PCzW26RTva",
  ldapBind: "KhwadpYp5MPJkFDF",
  samlKey: "Y5GNkYQtTmcrkMM4",
  oauthSecret: "wU4Gga3pBBcjBCtv",
  redhatPassword: "vLcMQ4fU9Ckw4k2y",
  licenseKey: "c9nD6HXEBzhV9Th5",
  loggingPassword: "cWqm4dQNJrBzMMJY",
  userHash: "jgN3H9xRJb3Dnatz",
  meHash: "aS3Hte3RFCkaP2es",
  podSpec: "ZWGCgMMzLwj5zm3p",
  notificationBody: "yzdzMCH3vcrj7LK6",
};

/** The export tests' configured token and the current user's email local part, both kept out of the bundle. */
const ANSIBLE_EXPORT_TOKEN_CANARY = "VqAngJDvPREAn5FP2K3M";
const ANSIBLE_AUDITOR_LOCAL_PART_CANARY = "KE9cNJeCaYuq";
const ANSIBLE_AUDITOR_EMAIL = `${ANSIBLE_AUDITOR_LOCAL_PART_CANARY}@example.com`;

function secretBearingRoutes() {
  const secrets = FAKE_ANSIBLE_SECRETS;
  const webhook = (path, headers) => ({
    id: 1,
    name: "slack alerts",
    notification_type: "webhook",
    organization: 1,
    notification_configuration: { url: `https://hooks.slack.com/services/${path}`, headers, token: secrets.slackToken, http_method: "POST" },
  });
  return {
    "/api/v2/jobs/": HEALTHY_ROUTES["/api/v2/jobs/"].map((entry, index) => (index === 0 ? { ...entry, extra_vars: `---\ndb_password: ${secrets.jobVar}\nregion: us-east-1` } : entry)),
    "/api/v2/settings/jobs/": {
      SCHEDULE_MAX_JOBS: 10,
      MAX_FORKS: 200,
      AWX_TASK_ENV: { HTTPS_PROXY: `http://svc:${secrets.proxyPassword}@proxy.example.com:3128` },
      GALAXY_TASK_ENV: { ANSIBLE_GALAXY_SERVER_TOKEN: secrets.galaxyToken },
    },
    "/api/v2/instance_groups/": [{ id: 1, name: "default", max_concurrent_jobs: 0, max_forks: 100, pod_spec_override: `env:\n  - name: API_TOKEN\n    value: ${secrets.podSpec}` }],
    "/api/v2/hosts/": [{ ...host(1, "web-1", "2026-09-20T00:10:00Z"), variables: `---\nansible_password: ${secrets.hostVar}` }],
    "/api/v2/inventory_sources/": [{ id: 1, name: "aws", status: "successful", last_update_failed: false, last_updated: "2026-09-20T00:00:00Z", source_vars: `---\naws_secret_key: ${secrets.sourceVar}` }],
    "/api/v2/job_templates/": [
      jobTemplate(10, "Patch Linux", { extra_vars: `---\napi_token: ${secrets.templateVar}\nregion: us-east-1` }),
      jobTemplate(11, "Survey Template", { survey_enabled: true }),
    ],
    "/api/v2/job_templates/11/survey_spec/": { name: "", spec: [{ variable: "api_token", type: "text", default: secrets.surveyDefault, required: true }] },
    "/api/v2/job_templates/10/notification_templates_error/": [webhook(secrets.errorWebhookPath, { "X-Api-Key": secrets.headerValue })],
    "/api/v2/schedules/": [
      { id: 1, name: "weekly patch", unified_job_template: 10, enabled: true, next_run: "2026-09-27T00:00:00Z", rrule: "DTSTART:20260101T000000Z RRULE:FREQ=WEEKLY;INTERVAL=1", extra_data: { api_token: secrets.scheduleVar } },
    ],
    "/api/v2/workflow_job_templates/": [{ id: 1, name: "Patch and validate", description: "", extra_vars: `{"client_secret": "${secrets.workflowVar}"}` }],
    "/api/v2/organizations/1/admins/": [{ id: 1, username: "auditor", password: secrets.userHash, email: ANSIBLE_AUDITOR_EMAIL }],
    "/api/v2/users/": [
      { ...SUPERUSER, password: secrets.userHash, email: ANSIBLE_AUDITOR_EMAIL, ldap_dn: "cn=auditor,dc=example" },
      { ...LIMITED_USER, password: secrets.userHash },
      { id: 3, username: "reviewer", is_superuser: false, is_system_auditor: true, password: secrets.userHash },
    ],
    "/api/v2/credentials/": [
      { id: 1, name: "machine", kind: "ssh", managed: false, modified: "2026-09-01T00:00:00Z", inputs: { username: "ansible", password: secrets.credentialInput }, summary_fields: { owners: [{ type: "user", name: "auditor" }] } },
    ],
    "/api/v2/tokens/": [{ id: 1, created: "2026-09-01T00:00:00Z", expires: "2026-12-01T00:00:00Z", token: secrets.tokenValue, refresh_token: secrets.refreshToken, scope: "read" }],
    "/api/v2/projects/": [{ id: 1, name: "playbooks", scm_type: "git", scm_url: `https://svc:${secrets.scmToken}@git.example.com/org/playbooks.git`, last_update_failed: false, last_updated: "2026-09-20T00:00:00Z" }],
    "/api/v2/inventories/": [{ id: 1, name: "prod", variables: `---\nvault_password: ${secrets.inventoryVar}` }],
    "/api/v2/groups/": [{ id: 1, name: "web", variables: `{"service_token": "${secrets.groupVar}"}` }],
    "/api/v2/notification_templates/": [webhook(secrets.webhookPath, [{ name: "Authorization", value: secrets.pairHeaderValue }])],
    "/api/v2/notifications/": [{ id: 1, status: "successful", body: `token=${secrets.notificationBody}` }],
    "/api/v2/activity_stream/": [{ id: 1, timestamp: "2026-09-20T22:00:00Z", operation: "update", object1: "job_template", changes: { extra_vars: ["---", `db_password: ${secrets.activityChange}`] }, summary_fields: { actor: { id: 1, username: "auditor", email: "auditor@example.com" } } }],
    "/api/v2/settings/authentication/": {
      AUTH_LDAP_SERVER_URI: "ldaps://ldap.example.com",
      AUTH_LDAP_BIND_DN: "cn=svc,dc=example",
      AUTH_LDAP_BIND_PASSWORD: secrets.ldapBind,
      SOCIAL_AUTH_SAML_SP_PRIVATE_KEY: secrets.samlKey,
      SOCIAL_AUTH_GITHUB_SECRET: secrets.oauthSecret,
      SOCIAL_AUTH_SAML_ENABLED_IDPS: { okta: { entity_id: "https://idp.example.com", url: `https://idp.example.com/sso?token=${secrets.oauthSecret}` } },
    },
    "/api/v2/settings/system/": { ACTIVITY_STREAM_ENABLED: true, REDHAT_PASSWORD: secrets.redhatPassword, LICENSE: { license_key: secrets.licenseKey, subscription_name: "AAP" } },
    "/api/v2/settings/logging/": { LOG_AGGREGATOR_ENABLED: true, LOG_AGGREGATOR_TYPE: "splunk", LOG_AGGREGATOR_PASSWORD: secrets.loggingPassword },
  };
}

test("verdict rule 9: exportAnsibleAuditBundle never writes variables bodies, credential inputs, tokens, webhook secrets, or settings secrets into the bundle or its zip", async () => {
  const base = createTempBase("grclanker-ansible-export-secrets-");
  const secrets = Object.values(FAKE_ANSIBLE_SECRETS);
  const client = createMockClient({ routes: secretBearingRoutes(), me: { ...SUPERUSER, password: FAKE_ANSIBLE_SECRETS.meHash, email: ANSIBLE_AUDITOR_EMAIL } });
  const config = { baseUrl: "https://aap.example.com", token: ANSIBLE_EXPORT_TOKEN_CANARY, timeoutMs: 30_000, verifySsl: true, sourceChain: ["tests"] };

  const result = await exportAnsibleAuditBundle(client, config, base, {});
  assert.equal(result.findingCount, 30);
  const files = readBundleFiles(result.outputDir);
  for (const relativePath of ["core_data/jobs.json", "core_data/job_settings.json", "core_data/credentials.json", "core_data/tokens.json", "core_data/projects.json", "core_data/notification_templates.json", "core_data/template_error_notifications.json", "core_data/survey_specs.json", "core_data/activity_stream.json", "core_data/settings_authentication.json", "analysis/platform-security.json"]) {
    assert.ok(files.has(join(...relativePath.split("/"))), `expected ${relativePath}`);
  }
  assertNoCanaryWindowsInFiles(assert, files, [...secrets, ANSIBLE_EXPORT_TOKEN_CANARY, ANSIBLE_AUDITOR_LOCAL_PART_CANARY], "bundle directory");
  const zipEntries = readZipEntries(result.zipPath);
  assert.equal(zipEntries.size, files.size, "the zip carries exactly the written files");
  assertNoCanaryWindowsInFiles(assert, zipEntries, [...secrets, ANSIBLE_EXPORT_TOKEN_CANARY, ANSIBLE_AUDITOR_LOCAL_PART_CANARY], "zip archive");

  const assessments = await runAllAssessments(client);
  const access = await checkAnsibleAccess(client);
  assertNoCanaryWindows(assert, assessments, [...secrets, ANSIBLE_AUDITOR_LOCAL_PART_CANARY], "assessment results");
  assertNoCanaryWindows(assert, access, [...secrets, ANSIBLE_AUDITOR_LOCAL_PART_CANARY], "access check result");
  const plaintext = byId(assessments[2], "AAP-CRED-04");
  assert.equal(plaintext.status, "fail", "the in-memory scanner still sees the raw variables");
  assert.deepEqual(plaintext.evidence.hits.map((hit) => hit.type).sort(), ["group", "inventory", "job_template", "survey_spec"]);

  const read = (name) => JSON.parse(files.get(join("core_data", name)));
  assert.equal(read("jobs.json").data.items[0].extra_vars, `${ANSIBLE_REDACTION_MARKER} (variable names: db_password, region)`);
  assert.equal(read("jobs.json").data.items[0].status, "running");
  assert.equal(read("job_templates.json").data.items[0].extra_vars, `${ANSIBLE_REDACTION_MARKER} (variable names: api_token, region)`);
  assert.deepEqual(read("job_templates.json").data.items[0].summary_fields.credentials, [{ id: 1, name: "machine", kind: "ssh" }]);
  assert.equal(read("workflow_job_templates.json").data.items[0].extra_vars, `${ANSIBLE_REDACTION_MARKER} (variable names: client_secret)`);
  assert.equal(read("schedules.json").data.items[0].extra_data, `${ANSIBLE_REDACTION_MARKER} (variable names: api_token)`);
  assert.equal(read("schedules.json").data.items[0].rrule, "DTSTART:20260101T000000Z RRULE:FREQ=WEEKLY;INTERVAL=1");
  assert.equal(read("hosts.json").data.items[0].variables, `${ANSIBLE_REDACTION_MARKER} (variable names: ansible_password)`);
  assert.equal(read("hosts.json").data.items[0].summary_fields.last_job.status, "successful");
  assert.equal(read("inventory_sources.json").data.items[0].source_vars, `${ANSIBLE_REDACTION_MARKER} (variable names: aws_secret_key)`);
  assert.equal(read("inventories.json").data.items[0].variables, `${ANSIBLE_REDACTION_MARKER} (variable names: vault_password)`);
  assert.equal(read("groups.json").data.items[0].variables, `${ANSIBLE_REDACTION_MARKER} (variable names: service_token)`);
  const jobSettings = read("job_settings.json").data;
  assert.deepEqual(jobSettings, {
    SCHEDULE_MAX_JOBS: 10,
    MAX_FORKS: 200,
    AWX_TASK_ENV: { HTTPS_PROXY: ANSIBLE_REDACTION_MARKER },
    GALAXY_TASK_ENV: { ANSIBLE_GALAXY_SERVER_TOKEN: ANSIBLE_REDACTION_MARKER },
  });
  assert.ok(!("pod_spec_override" in read("instance_groups.json").data.items[0]));
  assert.deepEqual(read("credentials.json").data.items[0].inputs, { username: ANSIBLE_REDACTION_MARKER, password: ANSIBLE_REDACTION_MARKER });
  assert.deepEqual(read("credentials.json").data.items[0].summary_fields.owners, [{ type: "user", name: "auditor" }]);
  assert.equal(read("tokens.json").data.items[0].token, ANSIBLE_REDACTION_MARKER);
  assert.equal(read("tokens.json").data.items[0].refresh_token, ANSIBLE_REDACTION_MARKER);
  assert.equal(read("tokens.json").data.items[0].scope, "read");
  assert.equal(read("projects.json").data.items[0].scm_url, "https://git.example.com/org/playbooks.git");
  const notification = read("notification_templates.json").data.items[0];
  assert.equal(notification.notification_configuration.url, "https://hooks.slack.com");
  assert.equal(notification.notification_configuration.token, ANSIBLE_REDACTION_MARKER);
  assert.deepEqual(notification.notification_configuration.headers, [{ name: "Authorization", value: ANSIBLE_REDACTION_MARKER }]);
  const errorNotification = read("template_error_notifications.json")["10"].data.items[0];
  assert.equal(errorNotification.notification_configuration.url, "https://hooks.slack.com");
  assert.deepEqual(errorNotification.notification_configuration.headers, { "X-Api-Key": ANSIBLE_REDACTION_MARKER });
  const survey = read("survey_specs.json")["11"].data.spec[0];
  assert.deepEqual(survey, { variable: "api_token", type: "text", required: true, default: ANSIBLE_REDACTION_MARKER });
  assert.equal(read("activity_stream.json").data.items[0].changes, `${ANSIBLE_REDACTION_MARKER} (variable names: extra_vars)`);
  assert.deepEqual(read("activity_stream.json").data.items[0].summary_fields.actor, { id: 1, username: "auditor" });
  const authSettings = read("settings_authentication.json").data;
  assert.equal(authSettings.AUTH_LDAP_SERVER_URI, "ldaps://ldap.example.com");
  assert.equal(authSettings.AUTH_LDAP_BIND_DN, "cn=svc,dc=example");
  assert.equal(authSettings.AUTH_LDAP_BIND_PASSWORD, ANSIBLE_REDACTION_MARKER);
  assert.equal(authSettings.SOCIAL_AUTH_SAML_SP_PRIVATE_KEY, ANSIBLE_REDACTION_MARKER);
  assert.equal(authSettings.SOCIAL_AUTH_SAML_ENABLED_IDPS.okta.url, "https://idp.example.com/sso", "URL query strings are dropped from settings values");
  assert.deepEqual(read("settings_system.json").data, { ACTIVITY_STREAM_ENABLED: true, REDHAT_PASSWORD: ANSIBLE_REDACTION_MARKER, LICENSE: { license_key: ANSIBLE_REDACTION_MARKER, subscription_name: "AAP" } });
  assert.equal(read("settings_logging.json").data.LOG_AGGREGATOR_PASSWORD, ANSIBLE_REDACTION_MARKER);
  assert.equal(read("settings_logging.json").data.LOG_AGGREGATOR_TYPE, "splunk");
  assert.deepEqual(Object.keys(read("users.json").data.items[0]).sort(), ["id", "is_superuser", "is_system_auditor", "username"]);
  assert.deepEqual(read("access.json").currentUser, { id: 1, username: "auditor", is_superuser: true, is_system_auditor: false });
  assert.deepEqual(Object.keys(read("notifications.json").data.items[0]).sort(), ["id", "status"]);
  assert.match(files.get("QUICK_REFERENCE.md"), /\[REDACTED\]/);
});

test("verdict rule 9: redaction helpers cover camelCase keys, pair shapes, environment dictionaries, and URL userinfo", () => {
  assert.deepEqual(redactCredentialTree({
    apiKey: "FAKE_SECRET_TOKEN_1",
    refreshToken: "FAKE_SECRET_TOKEN_2",
    "X-Auth-Token": "FAKE_SECRET_TOKEN_3",
    AUTH_LDAP_BIND_DN: "cn=svc",
    nested: { client_secret: "FAKE_SECRET_TOKEN_4", enabled: true, empty: "", missing: null },
    headers: [{ name: "Authorization", value: "FAKE_SECRET_TOKEN_5" }, { key: "X-Tenant", value: "acme" }],
    AWX_TASK_ENV: { HTTP_PROXY: "http://user:FAKE_SECRET_TOKEN_6@proxy:3128", NO_PROXY: "localhost" },
    endpoint: "https://user:FAKE_SECRET_TOKEN_7@api.example.com/v1?sig=FAKE_SECRET_TOKEN_8#frag",
    list: ["plain", { token: "FAKE_SECRET_TOKEN_9" }],
  }), {
    apiKey: "[REDACTED]",
    refreshToken: "[REDACTED]",
    "X-Auth-Token": "[REDACTED]",
    AUTH_LDAP_BIND_DN: "cn=svc",
    nested: { client_secret: "[REDACTED]", enabled: true, empty: "", missing: null },
    headers: [{ name: "Authorization", value: "[REDACTED]" }, { key: "X-Tenant", value: "[REDACTED]" }],
    AWX_TASK_ENV: { HTTP_PROXY: "[REDACTED]", NO_PROXY: "[REDACTED]" },
    endpoint: "https://api.example.com/v1",
    list: ["plain", { token: "[REDACTED]" }],
  });
  assert.equal(redactVariables(`---\ndb_password: x\nregion: us-east-1\n  nested: y`), "[REDACTED] (variable names: db_password, region)");
  assert.equal(redactVariables('{"api_token": "x", "count": 1}'), "[REDACTED] (variable names: api_token, count)");
  assert.equal(redactVariables({ vault_pass: "x" }), "[REDACTED] (variable names: vault_pass)");
  assert.equal(redactVariables("hunter22"), "[REDACTED]");
  assert.equal(redactVariables(""), "");
  assert.equal(redactVariables(null), null);
  assert.equal(sanitizeScmUrl("https://svc:FAKE_SECRET_TOKEN_1@git.example.com/org/repo.git?token=FAKE_SECRET_TOKEN_2"), "https://git.example.com/org/repo.git");
  assert.equal(sanitizeScmUrl("git@github.com:org/repo.git"), "git@github.com:org/repo.git");
  assert.equal(sanitizeScmUrl("svc:FAKE_SECRET_TOKEN_1@git.example.com:org/repo.git"), "[REDACTED]");
  assert.equal(sanitizeScmUrl(""), "");
});

test("verdict rule 9: AnsibleAapClient error messages keep the structured detail and never echo raw response bodies", async () => {
  const htmlBody = `<html>gateway error ${ANSIBLE_ERROR_BODY_CANARIES.html}</html>`;
  const client = new AnsibleAapClient(
    { baseUrl: "https://aap.example.com", token: "aap-token", timeoutMs: 30_000, verifySsl: true, sourceChain: ["tests"] },
    {
      fetchImpl: async (input) => {
        const url = new URL(typeof input === "string" ? input : input.toString());
        if (url.pathname === "/api/v2/jobs/") {
          return new Response(JSON.stringify({ detail: "You do not have permission to perform this action.", token: ANSIBLE_ERROR_BODY_CANARIES.json }), {
            status: 403,
            statusText: "Forbidden",
            headers: { "content-type": "application/json" },
          });
        }
        return new Response(htmlBody, { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html" } });
      },
    },
  );
  await assert.rejects(() => client.get("/api/v2/jobs/"), (error) => {
    assert.match(error.message, /\/api\/v2\/jobs\/ \(403 Forbidden\) You do not have permission/);
    assertNoCanaryWindows(assert, error.message, [ANSIBLE_ERROR_BODY_CANARIES.json], "JSON error body field");
    return true;
  });
  await assert.rejects(() => client.get("/api/v2/hosts/"), (error) => {
    assert.equal(error.message, `AAP request failed: /api/v2/hosts/ (502 Bad Gateway): non-JSON body (text/html, ${Buffer.byteLength(htmlBody, "utf8")} bytes)`);
    assertNoCanaryWindows(assert, error.message, [ANSIBLE_ERROR_BODY_CANARIES.html], "non-JSON body");
    assert.equal(error.status, 502);
    assert.equal(error.endpoint, "/api/v2/hosts/");
    return true;
  });
});

test("verdict rule 10: survey spec and error notification probes capped at 50 templates demote controls 18 and 27 with seen versus total", async () => {
  const templates = Array.from({ length: 60 }, (_, index) => jobTemplate(100 + index, `Patch Server ${index}`, { survey_enabled: true }));
  const routes = { "/api/v2/job_templates/": templates };
  for (const template of templates) {
    routes[`/api/v2/job_templates/${template.id}/survey_spec/`] = { name: "", spec: [{ variable: "target", type: "text", default: "web" }] };
    routes[`/api/v2/job_templates/${template.id}/notification_templates_error/`] = [{ id: 1, name: "slack alerts" }];
  }
  const result = await assessAnsiblePlatformSecurity(createMockClient({ routes }));

  const plaintext = byId(result, "AAP-CRED-04");
  assert.equal(plaintext.status, "warn");
  assert.equal(plaintext.evidence.surveys_scanned, 50);
  assert.equal(plaintext.evidence.survey_templates_eligible, 60);
  assert.ok(plaintext.evidence.partial_view.some((note) => /survey specs: 50 of 60 probed/.test(note)), plaintext.summary);
  assert.match(plaintext.summary, /survey specs: 50 of 60 probed/);

  const notifications = byId(result, "AAP-AUDIT-02");
  assert.equal(notifications.status, "warn");
  assert.equal(notifications.evidence.critical_templates, 50);
  assert.equal(notifications.evidence.critical_templates_eligible, 60);
  assert.match(notifications.summary, /critical templates: 50 of 60 probed/);

  const underCap = await assessAnsiblePlatformSecurity(createMockClient({ routes: {
    ...routes,
    "/api/v2/job_templates/": templates.slice(0, 50),
  } }));
  assert.equal(byId(underCap, "AAP-CRED-04").status, "pass");
  assert.equal(byId(underCap, "AAP-AUDIT-02").status, "pass");
});

test("rule 1 corollary: multi-inventory findings never pass when a secondary inventory returns 403 and name the unreadable inventory", async () => {
  const cases = [
    { control: 12, assess: assessAnsibleHostCoverage, forbidden: "/api/v2/schedules/", names: /schedules could not be read/ },
    { control: 13, assess: assessAnsibleHostCoverage, forbidden: "/api/v2/job_templates/", names: /job templates list could not be read/ },
    { control: 18, assess: assessAnsiblePlatformSecurity, forbidden: "/api/v2/credentials/", names: /Vault credential usage could not be read \(credential records \(\/api\/v2\/credentials\/\): /, expected: "warn" },
    { control: 18, assess: assessAnsiblePlatformSecurity, forbidden: "/api/v2/inventories/", names: /variable sources \(inventories\) could not be read/, expected: "manual" },
    { control: 21, assess: assessAnsiblePlatformSecurity, forbidden: "/api/v2/organizations/1/admins/", names: /admins list of 1 organizations \(Default\) could not be read/, expected: "manual" },
    { control: 22, assess: assessAnsiblePlatformSecurity, forbidden: "/api/v2/inventories/", names: /inventories list could not be read/, expected: "warn", partialView: /^inventories: unreadable \(inventories \(\/api\/v2\/inventories\/\): / },
    { control: 22, assess: assessAnsiblePlatformSecurity, forbidden: "/api/v2/teams/1/roles/", names: /roles of 1 teams could not be read/, expected: "manual" },
    { control: 23, assess: assessAnsiblePlatformSecurity, forbidden: "/api/v2/users/2/roles/", names: /roles of 1 users could not be read/, expected: "manual" },
    { control: 24, assess: assessAnsiblePlatformSecurity, forbidden: "/api/v2/teams/", names: /teams list could not be read/, expected: "warn" },
    { control: 24, assess: assessAnsiblePlatformSecurity, forbidden: "/api/v2/users/3/roles/", names: /1 user or team role lists could not be read/, expected: "warn" },
    { control: 26, assess: assessAnsiblePlatformSecurity, forbidden: "/api/v2/settings/system/", names: /system settings could not be read/, expected: "warn" },
    { control: 26, assess: assessAnsiblePlatformSecurity, forbidden: "/api/v2/settings/logging/", names: /logging settings could not be read/, expected: "warn" },
    { control: 27, assess: assessAnsiblePlatformSecurity, forbidden: "/api/v2/notifications/", names: /notification delivery history could not be read/, expected: "warn", partialView: /^notifications: unreadable \(notifications \(\/api\/v2\/notifications\/\): / },
    { control: 27, assess: assessAnsiblePlatformSecurity, forbidden: "/api/v2/job_templates/", names: /job templates list could not be read/, expected: "manual" },
    { control: 28, assess: assessAnsibleJobHealth, forbidden: "/api/v2/instance_groups/", names: /instance groups could not be read/, expected: "manual" },
    { control: 28, assess: assessAnsibleJobHealth, forbidden: "/api/v2/settings/jobs/", names: /job settings could not be read/, expected: "manual" },
    { control: 30, assess: assessAnsiblePlatformSecurity, forbidden: "/api/v2/execution_environments/", names: /Execution environments could not be read/, expected: "manual" },
  ];
  for (const testCase of cases) {
    const result = await testCase.assess(createMockClient({ forbiddenPaths: [testCase.forbidden] }));
    const finding = byControl(result, testCase.control);
    assert.notEqual(finding.status, "pass", `control ${testCase.control} passed with ${testCase.forbidden} forbidden: ${finding.summary}`);
    if (testCase.expected) assert.equal(finding.status, testCase.expected, `control ${testCase.control} with ${testCase.forbidden} forbidden: ${finding.summary}`);
    assert.match(finding.summary, testCase.names, `control ${testCase.control} with ${testCase.forbidden} forbidden`);
    if (testCase.partialView) {
      assert.ok(finding.evidence.partial_view.some((note) => testCase.partialView.test(note)), `control ${testCase.control}: partial_view names the unreadable inventory: ${JSON.stringify(finding.evidence.partial_view)}`);
    }
    assert.ok(result.errors.some((error) => error.includes(testCase.forbidden)), `control ${testCase.control}: errors array names ${testCase.forbidden}`);
  }
  const healthy = await runAllAssessments(createMockClient());
  assert.equal(healthy.flatMap((result) => result.findings).filter((item) => item.status !== "pass").length, 0, "the healthy fixture still passes every control");
});

test("rule 1 corollary: partialNotes caps any pass built on an unreadable view at warn without a per-control branch", async () => {
  const forbiddenNotifications = await assessAnsiblePlatformSecurity(createMockClient({ forbiddenPaths: ["/api/v2/notifications/"] }));
  const notifications = byControl(forbiddenNotifications, 27);
  assert.equal(notifications.status, "warn");
  assert.ok(notifications.evidence.partial_view.some((note) => /^notifications: unreadable \(/.test(note)), JSON.stringify(notifications.evidence.partial_view));
  assert.equal(notifications.evidence.notifications_readable, false);

  const forbiddenInventories = await assessAnsiblePlatformSecurity(createMockClient({ forbiddenPaths: ["/api/v2/inventories/"] }));
  const teams = byControl(forbiddenInventories, 22);
  assert.equal(teams.status, "warn");
  assert.equal(teams.evidence.inventories_readable, false);
  assert.equal(teams.evidence.total_inventories, null, "an unreadable inventory total renders null, never a count");
  assert.ok(teams.evidence.partial_view.some((note) => /^inventories: unreadable \(/.test(note)), JSON.stringify(teams.evidence.partial_view));
  assert.doesNotMatch(teams.summary, /on every inventory\./);
});

// Fixtures over the real AnsibleAapClient: the error constructor, the request wrapper, the login
// path, and every collector catch block are the code under test, not the mock client above.
/** Planted credentials for the client tests: the run token and the values an error body echoes. */
const ANSIBLE_RUN_TOKEN_CANARY = "VJQu6BSFDkFPS2g6GsLGSMsg";
const ANSIBLE_ERROR_BODY_CANARIES = Object.freeze({ json: "Uw34sFSRwES87v9q", html: "PYZakdJQxmAaNZv7" });

/**
 * A 2xx body that is valid JSON but not the documented object (a JSON string or array): 19 characters plus
 * the quotes make the 21-character body the reviewer measured leaking in full through a TypeError message.
 */
const ANSIBLE_PRIMITIVE_BODY_CANARY = "kR7dQx2mVt9HpZ4wLc3";

/** Every planted canary an Ansible output is swept for, window by window. */
const ANSIBLE_PLANTED_CANARIES = Object.freeze([
  ...CANARY_VALUES,
  SHORT_BODY_CANARY,
  PARSER_SNIPPET_CANARY,
  ...Object.values(FAKE_ANSIBLE_SECRETS),
  ANSIBLE_EXPORT_TOKEN_CANARY,
  ANSIBLE_AUDITOR_LOCAL_PART_CANARY,
  ANSIBLE_RUN_TOKEN_CANARY,
  ...Object.values(ANSIBLE_ERROR_BODY_CANARIES),
  ANSIBLE_PRIMITIVE_BODY_CANARY,
]);

const AAP_CLIENT_CONFIG = { baseUrl: "https://aap.example.com", token: ANSIBLE_RUN_TOKEN_CANARY, timeoutMs: 30_000, verifySsl: true, sourceChain: ["tests"] };

function aapResponse(body, status, statusText, contentType) {
  return new Response(body, { status, statusText, headers: { "content-type": contentType } });
}

function aapPage(items) {
  return { count: items.length, next: null, previous: null, results: items };
}

function aapForbidden() {
  return aapResponse(JSON.stringify({ detail: "You do not have permission to perform this action." }), 403, "Forbidden", "application/json");
}

function aapNotFound() {
  return aapResponse(JSON.stringify({ detail: "Not found." }), 404, "Not Found", "application/json");
}

function aapCanaryHtml() {
  return aapResponse(htmlCanaryBody(), 502, "Bad Gateway", "text/html");
}

function aapCanaryJson() {
  return aapResponse(JSON.stringify({ detail: jsonCanaryMessage() }), 403, "Forbidden", "application/json");
}

function healthyAapRoutes() {
  const routes = {
    "/api/v2/me/": () => jsonResponse({ count: 1, results: [SUPERUSER] }),
    "/api/v2/ping/": () => jsonResponse({ version: "4.6.0", active_node: "controller-1" }),
  };
  for (const [path, value] of Object.entries(HEALTHY_ROUTES)) {
    routes[path] = Array.isArray(value) ? () => jsonResponse(aapPage(value)) : () => jsonResponse(value);
  }
  return routes;
}

function aapRoutedFetch(routes, log) {
  return async (input, init) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const route = routes[url.pathname];
    if (!route) throw new Error(`Unexpected request: ${url.pathname}`);
    const response = await route(url);
    log?.push({ method: init?.method ?? "GET", path: url.pathname, status: response.status });
    return response;
  };
}

function aapClient(routes, log) {
  return new AnsibleAapClient(AAP_CLIENT_CONFIG, { fetchImpl: aapRoutedFetch(routes, log), now: () => NOW });
}

/** Runs the access check, the three assessments, and the export, keeping the thrown text when a step fails outright. */
async function runEveryAnsibleTool(client, outputRoot) {
  const run = { access: undefined, accessError: undefined, assessments: [], exported: undefined, exportError: undefined };
  try {
    run.access = await checkAnsibleAccess(client);
  } catch (error) {
    run.accessError = error.message;
  }
  run.assessments = await runAllAssessments(client);
  try {
    run.exported = await exportAnsibleAuditBundle(client, AAP_CLIENT_CONFIG, outputRoot);
  } catch (error) {
    run.exportError = error.message;
  }
  return run;
}

/** Every string an assessment records about a failed read: the errors array plus evidence error fields and partial-view notes. */
function recordedAnsibleErrors(assessments) {
  const recorded = [];
  for (const assessment of assessments) {
    recorded.push(...assessment.errors);
    for (const item of assessment.findings) {
      if (typeof item.evidence?.error === "string") recorded.push(item.evidence.error);
      for (const note of item.evidence?.partial_view ?? []) {
        if (/unreadable \(/.test(note)) recorded.push(note);
      }
    }
  }
  return recorded;
}

test("rule 9: redactErrorText scrubs every credential shape in the shared cases and leaves prose diagnosable", () => {
  assertRedactionCases(assert, redactErrorText);
  assert.equal(redactErrorText(`login failed with token ${AAP_CLIENT_CONFIG.token}`), "login failed with token [REDACTED]", "the configured token is a registered secret once a client exists");
});

test("rule 9 scrub boundary: name-shaped values stay bare, any value in a carrier is removed, token-shaped values are removed bare, the configured secret is removed in every encoded form, and the integration's fixed texts survive", () => {
  new AnsibleAapClient({ ...AAP_CLIENT_CONFIG, token: ENCODED_FORM_SECRET }, { fetchImpl: async () => new Response("{}"), now: () => NOW });
  assertScrubBoundary(assert, redactErrorText, {
    configuredSecret: ENCODED_FORM_SECRET,
    mustKeep: [
      "AAP request failed: /api/v2/settings/system/ (403 Forbidden): You do not have permission to perform this action.",
      "AAP request failed: /api/v2/hosts/ (502 Bad Gateway): non-JSON body (text/html, 46 bytes)",
      "SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body",
      "inventories: unreadable (AAP request failed: /api/v2/inventories/ (403 Forbidden))",
      "ACTIVITY_STREAM_ENABLED not readable; records under one day old cannot prove the stream is on",
      "organization Default-Org-2026 has 3 teams with Admin on every inventory",
      ...ansibleFixedTexts(),
    ],
  });
});

test("rule 9 fixed texts (GWS note 1): every fixed-text message the integration emits survives redactErrorText unchanged, from the SyntaxError and non-JSON notes through the not attempted marker and unreadable-view wordings to the session-login and manual-review prose", () => {
  const texts = ansibleFixedTexts();
  assertFixedTextsSurvive(assert, redactErrorText, texts, { minimum: 30 });
  const deniedDetail = "You do not have permission to perform this action.";
  for (const required of [
    "SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body",
    `not attempted: the parent list could not be read (AAP request failed: /api/v2/inventories/ (403 Forbidden) ${deniedDetail})`,
    "the read failed",
    "unknown",
    `inventories: unreadable (AAP request failed: /api/v2/inventories/ (403 Forbidden) ${deniedDetail})`,
    "hosts: 1 of 40 seen (page cap reached)",
    "current user could not be read, so the visibility of the audit account is unknown",
    "current user (/api/v2/me/): no user returned",
    "AAP request failed: /api/v2/ping/ (network error: fetch failed)",
    "AAP request failed: /api/v2/ping/ (network error: This operation was aborted)",
    "AAP session login failed (network error: fetch failed).",
    "AAP session login failed (401 Unauthorized).",
    "AAP session auth requires AAP_USERNAME and AAP_PASSWORD.",
    "ACTIVITY_STREAM_ENABLED is not exposed by the system settings, so it was not confirmed",
  ]) {
    assert.ok(texts.includes(required), `the fixed-text list carries: ${required}`);
  }
  assert.ok(texts.some((text) => HTML_BODY_NOTE.test(text)), "the fixed-text list carries the non-JSON body note");
  assert.ok(texts.some((text) => /^inventories could not be read \(AAP request failed: \/api\/v2\/inventories\/ \(403 Forbidden\) .*\), so this control cannot be verified from the API\. Collect this evidence manually: /.test(text)), "the manual-for-unreadable summary is in the list");
  assert.ok(texts.some((text) => /^No team holds the Admin role on every inventory\. Downgraded from pass to warn because the inventory is partial or unreadable: current user could not be read, so the visibility of the audit account is unknown; inventories: unreadable \(/.test(text)), "the warn-capped pass summary built on an unreadable view is in the list");

  // The renderings the client throws, built the way requestJson and responseDetail build them, survive too.
  const thrown = [
    `AAP request failed: /api/v2/settings/system/ (403 Forbidden) ${deniedDetail}`,
    "AAP request failed: /api/v2/hosts/ (502 Bad Gateway): non-JSON body (text/html, 46 bytes)",
    "AAP request failed: /api/v2/ping/ (200 OK): non-JSON body (text/plain, 21 bytes)",
    "AAP request failed: /api/v2/tokens/ (401 Unauthorized) Authentication credentials were not provided.",
  ];
  for (const message of thrown) {
    assert.equal(redactErrorText(message), message, `the thrown rendering survives the scrub: ${message}`);
  }
});

test("rule 9 must-keep and must-redact table (addendum 7): every endpoint path, name, principal, status text, control id, and fixed text the summaries, markers, probes, and evidence rely on survives redactErrorText alone and inside a realistic summary sentence, and every canary planted in every carrier beside one of them is removed while the row survives (extends the rule 9 scrub boundary fixed texts)", () => {
  const deniedDetail = "You do not have permission to perform this action.";
  const groups = [
    {
      label: "endpoint paths",
      values: [
        "/api/v2/ping/",
        "/api/v2/me/",
        "/api/v2/inventories/",
        "/api/v2/hosts/",
        "/api/v2/users/3/roles/",
        "/api/v2/teams/1/roles/",
        "/api/v2/organizations/1/admins/",
        "/api/v2/job_templates/10/notification_templates_error/",
        "/api/v2/settings/system/",
        "/api/v2/settings/logging/",
        "/api/v2/settings/authentication/",
        "/api/v2/notifications/",
        "/api/v2/notification_templates/",
        "/api/v2/credentials/",
        "/api/v2/activity_stream/",
        "/api/v2/execution_environments/",
        "/api/v2/tokens/",
        "https://aap.example.com/api/v2/ping/",
      ],
      sentence: (value) => `AAP request failed: ${value} (403 Forbidden) ${deniedDetail}`,
    },
    {
      label: "names",
      values: [
        "Default",
        "Default-Org-2026",
        "prod-us-east-2026",
        "ops-team",
        "prod vault",
        "default-ee",
        "controller-1",
        "aap.example.com",
        "Patch and validate",
        "weekly harden",
        "ACTIVITY_STREAM_ENABLED",
        "LOG_AGGREGATOR_ENABLED",
        "AAP_USERNAME and AAP_PASSWORD",
      ],
      sentence: (value) => `${value} could not be read (403 Forbidden), so this control cannot be verified from the API; its count is null and the verdict is manual.`,
    },
    {
      label: "principals",
      values: ["auditor", "deploy", "svc-deploy", "reviewer", "ansible", "System Auditor", "Admin"],
      sentence: (value) => `${value} could not be checked because /api/v2/users/3/roles/ returned 403 Forbidden; the role count is null.`,
    },
    {
      label: "status text",
      values: [
        "403 Forbidden",
        "401 Unauthorized",
        "502 Bad Gateway",
        "200 OK",
        "network error: fetch failed",
        "network error: This operation was aborted",
        deniedDetail,
        "non-JSON body (text/html, 46 bytes)",
        "no user returned",
        "page cap reached",
      ],
      sentence: (value) => `the inventories list could not be read (${value}), so inventory-wide Admin roles were not checked`,
    },
    {
      label: "control ids",
      values: ["AAP-AUDIT-01", "AAP-CRED-01", "AAP-HOST-01", "AAP-JOB-01", "AAP-PLAT-01", "AAP-RBAC-02", "AAP-SCHED-01", "AAP-TMPL-03"],
      sentence: (value) => `${value} is manual because /api/v2/inventories/ was not readable (403 Forbidden).`,
    },
    {
      label: "fixed texts",
      values: ansibleFixedTexts(),
      sentence: (value) => `AAP-RBAC-02: ${value}`,
    },
    QUOTED_NON_CREDENTIAL_GROUP,
  ];
  assertMustKeepRows(assert, redactErrorText, groups);
  assertMustRedactRowsBesideMustKeep(assert, redactErrorText, groups);
});

test("rule 9 escapes (reviewer D round 5 escapes): a header carrier after a two-character or six-character JSON escape is removed exactly as at a line start, for the nineteen header lines the integrations send, the six escapes, and five forms, at 6-to-24 windows, direct and through the client's JSON error path", async () => {
  const judged = assertEscapedHeaderCarriers(assert, redactErrorText);
  assert.equal(judged, ESCAPED_HEADER_LINES.length * JSON_ESCAPES.length * 5);
  assert.equal(ESCAPED_HEADER_LINES.length, 19);

  // The two classes reviewer D found leaking, carried by an error message on a probed surface: a later cookie
  // pair whose name has no credential word, and X-Auth-Key with an alphabetic value, each after a two-character
  // and a six-character escape.
  const tracker = "Rk7mVq2Zt9Xw4Ly6Pn8Hc3Jb";
  const globalKey = "prodkeyQz8Nv3Tm5Rk2Wy7";
  const message = `request failed\\nCookie: theme=dark; my.tracker=${tracker}\\u000aX-Auth-Key: ${globalKey}`;
  assert.ok(message.includes("\\n") && message.includes("\\u000a"), "the message carries the escapes as backslash text");
  const expectedTail = "\\nCookie: [REDACTED]\\u000aX-Auth-Key: [REDACTED]";
  const probeLog = [];
  await checkAnsibleAccess(aapClient(healthyAapRoutes(), probeLog));
  const surface = probeLog.map((entry) => entry.path).find((path) => path !== "/api/v2/me/" && path !== "/api/v2/ping/");
  assert.ok(surface, "the access check probes a surface beyond me and ping");
  const access = await checkAnsibleAccess(aapClient({ ...healthyAapRoutes(), [surface]: () => aapResponse(JSON.stringify({ detail: message }), 403, "Forbidden", "application/json") }));
  const failed = access.surfaces.find((entry) => entry.endpoint === surface);
  assert.equal(failed.status, "not_readable");
  assert.ok(failed.error.includes(expectedTail), `both carriers are removed whole after their escapes: ${failed.error}`);
  assertNoCanaryWindows(assert, access, [tracker, globalKey], "check_access after escaped headers");
});

test("rule 9 credential-named pairs (reviewer D round 5 baseline): a value under a credential-named key is removed whatever its shape and length, unquoted as well as quoted, in every form the pair takes, while identifier-named keys keep their values unless the value's own shape removes it", () => {
  assertCredentialPairValuesRemoved(assert, redactErrorText);
  assertIdentifierKeyRows(assert, redactErrorText);
  // The retired value-shape test would have kept every one of these; the pair rule no longer asks.
  for (const [text, expected] of [
    ["password=letmein", "password=[REDACTED]"],
    ["DB_PASSWORD=Sunshine", "DB_PASSWORD=[REDACTED]"],
    ["AZURE_CLIENT_SECRET: abc12", "AZURE_CLIENT_SECRET: [REDACTED]"],
    ["DUO_SKEY=p@ss", "DUO_SKEY=[REDACTED]"],
    ["DUO_IKEY=DIXXXXXXXXXXXXXXXXXX", "DUO_IKEY=[REDACTED]"],
    ["DUO_IKEY=letmein", "DUO_IKEY=[REDACTED]"],
    ["ikey: monkey", "ikey: [REDACTED]"],
    ['{"DUO_IKEY":"Sunshine"}', '{"DUO_IKEY":"[REDACTED]"}'],
    ['"ikey": "abc12"', '"ikey": "[REDACTED]"'],
    ["Authorization: Basic letmein", "Authorization: Basic [REDACTED]"],
    ["token: value shape", "token: [REDACTED] shape"],
  ]) {
    assert.equal(redactErrorText(text), expected, `credential-named pair: ${text}`);
  }
  // A PascalCase error code that ends in a credential word is prose, and a bare scheme word or a path segment is not a pair.
  for (const text of [
    "InvalidAuthenticationToken: Access token has expired. Basic authentication is disabled for this tenant.",
    "ExpiredToken: The security token included in the request is expired",
    "sent as Authorization: Bearer) or as X-Auth-Key",
    "GET /_security/api_key: 403 Forbidden",
    "POST /tenant/oauth2/v2.0/token: 401 Unauthorized",
    "oauth: invalid_grant was returned",
  ]) {
    assert.equal(redactErrorText(text), text, `prose beside a credential word survives: ${text}`);
  }
});

test("fixture self-check: every planted canary is alphanumeric and random-looking, and no 6-to-24-character window of any canary occurs in the healthy fixture's legitimate values, so a windowed leak assertion can fail only on a real echo", async () => {
  const legitimate = new Map();
  for (const [path, route] of Object.entries(healthyAapRoutes())) {
    legitimate.set(`route ${path}`, await route(new URL(`https://aap.example.com${path}`)).text());
  }
  const run = await runEveryAnsibleTool(aapClient(healthyAapRoutes()), createTempBase("grclanker-ansible-self-check-"));
  assert.equal(run.accessError, undefined);
  assert.equal(run.exportError, undefined);
  legitimate.set("check_access", run.access);
  for (const assessment of run.assessments) legitimate.set(assessment.title, assessment);
  for (const [name, text] of readBundleFiles(run.exported.outputDir)) legitimate.set(`bundle ${name}`, text);
  for (const [name, text] of readZipEntries(run.exported.zipPath)) legitimate.set(`zip ${name}`, text);
  legitimate.set("users", [SUPERUSER, LIMITED_USER]);
  assertCanaryFixture(assert, ANSIBLE_PLANTED_CANARIES, legitimate, "ansible fixture");
});

test("rule 9: a 502 HTML page or a JSON error message carrying credentials on any AAP surface never reaches a probe, finding, summary, or bundle file", async () => {
  const outputRoot = createTempBase("grclanker-ansible-canary-");

  // The healthy run proves the route table is the surface list: every route is requested and nothing else is.
  const healthyLog = [];
  const healthyRun = await runEveryAnsibleTool(aapClient(healthyAapRoutes(), healthyLog), outputRoot);
  assert.equal(healthyRun.accessError, undefined);
  assert.equal(healthyRun.exported.errorCount, 0, "the healthy fixture records no errors");
  for (const assessment of healthyRun.assessments) {
    for (const item of assessment.findings) assert.equal(item.status, "pass", `${item.id}: ${item.summary}`);
  }
  const surfaces = Object.keys(healthyAapRoutes());
  assert.deepEqual([...new Set(healthyLog.map((entry) => entry.path))].sort(), [...surfaces].sort(), "every documented surface is exercised by the access check, the assessments, or the export");
  const accessLog = [];
  await checkAnsibleAccess(aapClient(healthyAapRoutes(), accessLog));
  const probed = new Set(accessLog.map((entry) => entry.path));

  for (const surface of surfaces) {
    for (const [variant, response, expectedNote, expectedStatus] of [
      ["html", aapCanaryHtml, HTML_BODY_NOTE, 502],
      ["json", aapCanaryJson, REDACTED_CANARY_URL, 403],
    ]) {
      const label = `${surface} (${variant})`;
      const run = await runEveryAnsibleTool(aapClient({ ...healthyAapRoutes(), [surface]: response }), createTempBase("grclanker-ansible-canary-"));

      if (surface === "/api/v2/me/") {
        assert.ok(run.accessError, `${label}: the access check fails outright when the current user cannot be read`);
        assertNoCanaryWindows(assert, run.accessError, ANSIBLE_PLANTED_CANARIES, `${label} check_access error`);
        assert.match(run.accessError, expectedNote, `${label}: the thrown text carries the expected note`);
      } else {
        assertNoCanaryWindows(assert, run.access, ANSIBLE_PLANTED_CANARIES, `${label} check_access`);
        if (probed.has(surface) && surface !== "/api/v2/ping/") {
          const failed = run.access.surfaces.filter((entry) => entry.status === "not_readable");
          assert.deepEqual(failed.map((entry) => entry.endpoint), [surface], `${label}: the access check records exactly the failing surface`);
          for (const entry of failed) {
            assert.match(entry.error, expectedNote, `${label}: probe ${entry.name} carries the expected note`);
            assert.equal(entry.count, null, `${label}: probe ${entry.name} renders no count`);
            assert.equal(entry.http_status, expectedStatus, `${label}: probe ${entry.name} records the observed status`);
          }
        }
      }

      for (const assessment of run.assessments) assertNoCanaryWindows(assert, assessment, ANSIBLE_PLANTED_CANARIES, `${label} ${assessment.title}`);
      const recorded = recordedAnsibleErrors(run.assessments);
      if (surface !== "/api/v2/ping/") {
        assert.ok(recorded.length > 0, `${label}: the failing surface is recorded by an assessment`);
        for (const error of recorded) assert.match(error, expectedNote, `${label}: "${error}" carries the expected note`);
        if (variant === "html") {
          assert.ok(recorded.some((error) => /\(502 Bad Gateway\): non-JSON body \(text\/html, \d+ bytes\)/.test(error)), `${label}: the note names the observed status`);
        }
      }

      if (run.exportError !== undefined) {
        assert.equal(surface, "/api/v2/me/", `${label}: only an unreadable current user fails the export outright (${run.exportError})`);
        assertNoCanaryWindows(assert, run.exportError, ANSIBLE_PLANTED_CANARIES, `${label} export error`);
        continue;
      }
      const files = readBundleFiles(run.exported.outputDir);
      assertNoCanaryWindowsInFiles(assert, files, ANSIBLE_PLANTED_CANARIES, `${label} bundle`);
      assertNoCanaryWindowsInFiles(assert, readZipEntries(run.exported.zipPath), ANSIBLE_PLANTED_CANARIES, `${label} zip`);
      if (surface !== "/api/v2/ping/") {
        assert.ok(run.exported.errorCount > 0, `${label}: the export logs the failed read`);
        assert.match(files.get("_errors.log"), expectedNote, `${label}: _errors.log carries the expected note`);
      }
    }
  }
});

/**
 * Single-surface denials with the core_data file the denied list is written to and the summary or
 * evidence fields a consumer reads for that inventory. Every listed field must render null, never
 * the zero or empty list of an in-memory fallback.
 */
const ANSIBLE_DENIAL_TABLE = [
  { surface: "/api/v2/jobs/", file: "core_data/jobs.json", summary: [0, ["total_jobs", "jobs_total_reported", "successful", "failed"]] },
  { surface: "/api/v2/instance_groups/", file: "core_data/instance_groups.json", summary: [0, ["instance_groups"]] },
  { surface: "/api/v2/hosts/", file: "core_data/hosts.json", summary: [1, ["total_hosts", "hosts_total_reported"]] },
  { surface: "/api/v2/inventory_sources/", file: "core_data/inventory_sources.json", summary: [1, ["inventory_sources"]] },
  { surface: "/api/v2/job_host_summaries/", file: "core_data/job_host_summaries.json", summary: [1, ["job_host_summaries"]] },
  {
    surface: "/api/v2/job_templates/",
    file: "core_data/job_templates.json",
    summary: [1, ["job_templates"]],
    evidence: ["AAP-AUDIT-02", ["critical_templates", "critical_templates_eligible", "covered", "unreadable"]],
    alsoSummary: [2, ["job_templates"]],
  },
  { surface: "/api/v2/schedules/", file: "core_data/schedules.json", summary: [1, ["schedules"]] },
  { surface: "/api/v2/workflow_job_templates/", file: "core_data/workflow_job_templates.json", summary: [1, ["workflow_job_templates"]] },
  { surface: "/api/v2/organizations/", file: "core_data/organizations.json", summary: [2, ["organizations"]] },
  { surface: "/api/v2/users/", file: "core_data/users.json", summary: [2, ["users"]] },
  { surface: "/api/v2/teams/", file: "core_data/teams.json", summary: [2, ["teams"]] },
  { surface: "/api/v2/credentials/", file: "core_data/credentials.json", summary: [2, ["credentials"]], evidence: ["AAP-CRED-04", ["vault_credentials"]] },
  { surface: "/api/v2/tokens/", file: "core_data/tokens.json", summary: [2, ["tokens"]] },
  { surface: "/api/v2/projects/", file: "core_data/projects.json", summary: [2, ["projects"]] },
  { surface: "/api/v2/inventories/", file: "core_data/inventories.json", evidence: ["AAP-CRED-04", ["inventories"]] },
  { surface: "/api/v2/groups/", file: "core_data/groups.json", evidence: ["AAP-CRED-04", ["groups"]] },
  { surface: "/api/v2/execution_environments/", file: "core_data/execution_environments.json", summary: [2, ["execution_environments"]] },
  { surface: "/api/v2/notification_templates/", file: "core_data/notification_templates.json", summary: [2, ["notification_templates"]] },
  { surface: "/api/v2/notifications/", file: "core_data/notifications.json", evidence: ["AAP-AUDIT-02", ["failed_notifications"]] },
  { surface: "/api/v2/activity_stream/", file: "core_data/activity_stream.json", evidence: ["AAP-AUDIT-01", ["error"]], evidenceNotNull: true },
];

function assertNotCollectedMarker(marker, surface, label) {
  assert.deepEqual(Object.keys(marker).sort(), ["collected", "endpoint", "error", "status"], `${label}: the denied dataset is a marker object, not an empty collection`);
  assert.equal(marker.collected, false);
  assert.equal(marker.status, 403, `${label}: the marker carries the status the request observed`);
  assert.equal(marker.endpoint, surface, `${label}: the marker names the path the request actually used`);
  assert.match(marker.error, /\(403 Forbidden\) You do not have permission to perform this action\./);
}

test("denied-list markers: a denied list writes a not-collected marker in core_data with the observed status and path, every dependent summary field renders null, and a readable-but-empty list keeps its empty collection", async () => {
  // Each export gets its own base: the allocator caps re-runs of the same target name (rule 8).
  const outputRoot = () => createTempBase("grclanker-ansible-markers-");

  for (const testCase of ANSIBLE_DENIAL_TABLE) {
    const { surface, file } = testCase;
    // One other list is served readable-but-empty as the control: its file keeps the collection shape.
    const control = surface === "/api/v2/workflow_job_templates/" ? "/api/v2/tokens/" : "/api/v2/workflow_job_templates/";
    const controlFile = control === "/api/v2/tokens/" ? "core_data/tokens.json" : "core_data/workflow_job_templates.json";
    const client = aapClient({ ...healthyAapRoutes(), [surface]: aapForbidden, [control]: () => jsonResponse(aapPage([])) });
    const assessments = await runAllAssessments(client);
    const exported = await exportAnsibleAuditBundle(client, AAP_CLIENT_CONFIG, outputRoot());
    const files = readBundleFiles(exported.outputDir);

    assertNotCollectedMarker(JSON.parse(files.get(file)), surface, surface);
    assert.deepEqual(JSON.parse(files.get(controlFile)), { data: { items: [], complete: true, total: 0 } }, `${surface} denied: a readable-but-empty list is still an empty, complete collection`);

    for (const [index, keys] of [testCase.summary, testCase.alsoSummary].filter(Boolean)) {
      for (const key of keys) {
        assert.equal(assessments[index].summary[key], null, `${surface} denied: summary.${key} renders null, not ${JSON.stringify(assessments[index].summary[key])}`);
      }
    }
    if (testCase.evidence) {
      const [id, keys] = testCase.evidence;
      const item = assessments.flatMap((assessment) => assessment.findings).find((candidate) => candidate.id === id);
      assert.notEqual(item.status, "pass", `${surface} denied: ${id} never passes (${item.summary})`);
      for (const key of keys) {
        if (testCase.evidenceNotNull) {
          assert.match(String(item.evidence[key]), /403 Forbidden/, `${surface} denied: ${id} evidence.${key} names the denial`);
          assert.equal(item.evidence.http_status, 403, `${surface} denied: ${id} evidence carries the observed status`);
          assert.equal(item.evidence.endpoint, surface, `${surface} denied: ${id} evidence names the denied path`);
        } else {
          assert.equal(item.evidence[key], null, `${surface} denied: ${id} evidence.${key} renders null, not ${JSON.stringify(item.evidence[key])}`);
        }
      }
    }
    const denied = assessments.flatMap((assessment) => assessment.errors).filter((error) => error.includes(surface));
    assert.ok(denied.length > 0, `${surface} denied: the errors array names the denied endpoint`);
    assert.ok(files.get("_errors.log").includes(surface), `${surface} denied: _errors.log names the denied endpoint`);
  }

  // Per-item lists: the denied item is a marker beside its readable siblings, and the finding keeps the item with a null count.
  const perItem = aapClient({
    ...healthyAapRoutes(),
    "/api/v2/users/3/roles/": aapForbidden,
    "/api/v2/teams/1/roles/": aapForbidden,
    "/api/v2/organizations/1/admins/": aapForbidden,
    "/api/v2/job_templates/10/notification_templates_error/": aapForbidden,
  });
  const perItemAssessments = await runAllAssessments(perItem);
  const perItemFiles = readBundleFiles((await exportAnsibleAuditBundle(perItem, AAP_CLIENT_CONFIG, outputRoot())).outputDir);
  const userRoles = JSON.parse(perItemFiles.get("core_data/user_roles.json"));
  assertNotCollectedMarker(userRoles["3"], "/api/v2/users/3/roles/", "user_roles.json[3]");
  assert.equal(userRoles["1"].data.items.length, 1, "a readable sibling keeps its projected items");
  assert.equal(userRoles["1"].collected, undefined, "a readable sibling carries no marker keys");
  assertNotCollectedMarker(JSON.parse(perItemFiles.get("core_data/team_roles.json"))["1"], "/api/v2/teams/1/roles/", "team_roles.json[1]");
  assertNotCollectedMarker(JSON.parse(perItemFiles.get("core_data/organization_admins.json"))["1"], "/api/v2/organizations/1/admins/", "organization_admins.json[1]");
  const errorNotifications = JSON.parse(perItemFiles.get("core_data/template_error_notifications.json"));
  assertNotCollectedMarker(errorNotifications["10"], "/api/v2/job_templates/10/notification_templates_error/", "template_error_notifications.json[10]");
  assert.equal(errorNotifications["11"].data.items.length, 1);
  const orgAdmins = byId(perItemAssessments[2], "AAP-RBAC-01");
  assert.equal(orgAdmins.status, "manual");
  assert.deepEqual(orgAdmins.evidence.organizations.map((org) => [org.name, org.admin_count, org.complete, org.http_status, org.endpoint]), [["Default", null, null, 403, "/api/v2/organizations/1/admins/"]], "the organization stays listed with a null admin count and the denial beside it");
  const coverage = byId(perItemAssessments[2], "AAP-AUDIT-02");
  assert.equal(coverage.evidence.unreadable, 1);
  assert.equal(coverage.evidence.covered, 1);

  // Per-item files whose parent list was denied were never probed: one not-attempted marker names the parent read.
  const parentDenied = aapClient({ ...healthyAapRoutes(), "/api/v2/users/": aapForbidden, "/api/v2/job_templates/": aapForbidden });
  const parentFiles = readBundleFiles((await exportAnsibleAuditBundle(parentDenied, AAP_CLIENT_CONFIG, outputRoot())).outputDir);
  for (const [file, parent] of [
    ["core_data/user_roles.json", "/api/v2/users/"],
    ["core_data/template_error_notifications.json", "/api/v2/job_templates/"],
    ["core_data/survey_specs.json", "/api/v2/job_templates/"],
  ]) {
    const marker = JSON.parse(parentFiles.get(file));
    assert.deepEqual(Object.keys(marker).sort(), ["collected", "endpoint", "error", "status"], `${file}: a per-item file under a denied parent is a marker, not {}`);
    assert.equal(marker.collected, false);
    assert.equal(marker.status, 403);
    assert.equal(marker.endpoint, parent, `${file}: the marker names the parent list that was denied`);
    assert.match(marker.error, /^not attempted: the parent list could not be read \(/);
  }
  const teamRoles = JSON.parse(parentFiles.get("core_data/team_roles.json"));
  assert.equal(teamRoles["1"].data.items.length, 1, "a per-item file whose parent was readable keeps its record shape");

  // Object datasets: settings and job settings write the same marker, and the flags they feed stay null.
  const objectDenied = aapClient({
    ...healthyAapRoutes(),
    "/api/v2/settings/system/": aapForbidden,
    "/api/v2/settings/logging/": aapForbidden,
    "/api/v2/settings/authentication/": aapForbidden,
    "/api/v2/settings/jobs/": aapForbidden,
  });
  const objectAssessments = await runAllAssessments(objectDenied);
  const objectFiles = readBundleFiles((await exportAnsibleAuditBundle(objectDenied, AAP_CLIENT_CONFIG, outputRoot())).outputDir);
  for (const [file, surface] of [
    ["core_data/settings_system.json", "/api/v2/settings/system/"],
    ["core_data/settings_logging.json", "/api/v2/settings/logging/"],
    ["core_data/settings_authentication.json", "/api/v2/settings/authentication/"],
    ["core_data/job_settings.json", "/api/v2/settings/jobs/"],
  ]) {
    assertNotCollectedMarker(JSON.parse(objectFiles.get(file)), surface, file);
  }
  const audit = byId(objectAssessments[2], "AAP-AUDIT-01");
  assert.equal(audit.status, "warn");
  assert.deepEqual(
    { enabled: audit.evidence.activity_stream_enabled, system: audit.evidence.system_settings_readable, aggregator: audit.evidence.log_aggregator_enabled, type: audit.evidence.log_aggregator_type, logging: audit.evidence.logging_settings_readable },
    { enabled: null, system: false, aggregator: null, type: null, logging: false },
    "settings-derived flags render null with their readable flags false",
  );
  assert.equal(objectAssessments[2].summary.external_auth, null);
  assert.equal(objectAssessments[2].summary.auth_settings_readable, false);
  const concurrency = byControl(objectAssessments[0], 28);
  assert.equal(concurrency.status, "manual");
  assert.deepEqual(concurrency.evidence, { error: concurrency.evidence.error, http_status: 403, endpoint: "/api/v2/settings/jobs/" });

  // The scope probe renders visibility as unknown, never false, when the current user cannot be read.
  const meDenied = aapClient({ ...healthyAapRoutes(), "/api/v2/me/": aapForbidden });
  const meAssessments = await runAllAssessments(meDenied);
  for (const assessment of meAssessments) {
    assert.equal(assessment.summary.full_visibility, null, `${assessment.category}: full_visibility is null while the current user is unread`);
  }
});

test("AAP-RBAC-05 never names an organization as uncovered while any probed role list was denied", async () => {
  const noSystemAuditor = { "/api/v2/users/": [SUPERUSER, LIMITED_USER, { id: 3, username: "reviewer", is_superuser: false, is_system_auditor: false }] };

  const readable = byId(await assessAnsiblePlatformSecurity(createMockClient({ routes: noSystemAuditor })), "AAP-RBAC-05");
  assert.equal(readable.status, "pass");
  assert.deepEqual(readable.evidence.audited_organizations, ["Default"]);
  assert.deepEqual(readable.evidence.uncovered, []);
  assert.equal(readable.evidence.coverage_unknown_organizations, 0);

  const roleDenied = byId(await assessAnsiblePlatformSecurity(createMockClient({ routes: noSystemAuditor, forbiddenPaths: ["/api/v2/users/3/roles/"] })), "AAP-RBAC-05");
  assert.equal(roleDenied.status, "manual", roleDenied.summary);
  assert.deepEqual(roleDenied.evidence.audited_organizations, []);
  assert.equal(roleDenied.evidence.uncovered, null, "no organization is called uncovered when the list that would show its auditor was denied");
  assert.equal(roleDenied.evidence.coverage_unknown_organizations, 1);
  assert.equal(roleDenied.evidence.unreadable_role_lists, 1);
  assert.match(roleDenied.summary, /coverage is unknown for 1 organizations because 1 user or team role lists could not be read/);
  assert.doesNotMatch(roleDenied.summary, /Default/);

  const teamsDenied = byId(await assessAnsiblePlatformSecurity(createMockClient({ routes: noSystemAuditor, forbiddenPaths: ["/api/v2/teams/"] })), "AAP-RBAC-05");
  assert.equal(teamsDenied.status, "warn", teamsDenied.summary);
  assert.equal(teamsDenied.evidence.uncovered, null);
  assert.match(teamsDenied.summary, /the teams list could not be read/);

  const withSystemAuditor = byId(await assessAnsiblePlatformSecurity(createMockClient({ forbiddenPaths: ["/api/v2/users/3/roles/"] })), "AAP-RBAC-05");
  assert.equal(withSystemAuditor.status, "warn", "a system auditor keeps the control at warn while the role list gap is named");
  assert.equal(withSystemAuditor.evidence.uncovered, null);
  assert.match(withSystemAuditor.summary, /1 system auditors exist and an Auditor role holder was confirmed for 0 of 1 organizations and coverage is unknown for 1 organizations/);

  const trulyUncovered = byId(await assessAnsiblePlatformSecurity(createMockClient({ routes: { ...noSystemAuditor, "/api/v2/users/3/roles/": [] } })), "AAP-RBAC-05");
  assert.equal(trulyUncovered.status, "warn");
  assert.deepEqual(trulyUncovered.evidence.uncovered, ["Default"], "with every role list readable, an organization without an auditor is named");
  assert.match(trulyUncovered.summary, /1\/1 organizations have no Auditor role holder/);
});

function namedAapEndpoints(text) {
  return new Set(text.match(/\/api\/v2\/[A-Za-z0-9_/-]+/g) ?? []);
}

function namedAapStatusCodes(text) {
  const codes = new Set();
  for (const match of text.matchAll(/\((\d{3}) (?:[A-Z][A-Za-z]*(?: |\)))/g)) codes.add(Number(match[1]));
  for (const match of text.matchAll(/"(?:http_)?status": ?(\d{3})\b/g)) codes.add(Number(match[1]));
  return codes;
}

test("request matching: every endpoint path and HTTP status named in any output corresponds to a request the run made and observed", async () => {
  const outputRoot = createTempBase("grclanker-ansible-request-log-");
  const log = [];
  const client = aapClient({
    ...healthyAapRoutes(),
    "/api/v2/jobs/": aapForbidden,
    "/api/v2/credentials/": aapCanaryHtml,
    "/api/v2/settings/logging/": aapNotFound,
  }, log);

  const outputs = [JSON.stringify(await checkAnsibleAccess(client))];
  for (const assessment of await runAllAssessments(client)) outputs.push(JSON.stringify(assessment));
  const exported = await exportAnsibleAuditBundle(client, AAP_CLIENT_CONFIG, outputRoot);
  outputs.push(...readBundleFiles(exported.outputDir).values());

  const requestedPaths = new Set(log.map((entry) => entry.path));
  const observedStatuses = new Set(log.map((entry) => entry.status));
  assert.ok(observedStatuses.has(403) && observedStatuses.has(502) && observedStatuses.has(404), "the fixture served every failure status under test");

  const text = outputs.join("\n");
  const endpoints = namedAapEndpoints(text);
  const statuses = namedAapStatusCodes(text);
  assert.ok(endpoints.has("/api/v2/jobs/") && endpoints.has("/api/v2/credentials/") && endpoints.has("/api/v2/settings/logging/"), "the outputs name the failing endpoints");
  assert.ok(statuses.has(403) && statuses.has(502) && statuses.has(404), "the outputs name the observed failure statuses");
  for (const endpoint of endpoints) {
    assert.ok(requestedPaths.has(endpoint), `endpoint ${endpoint} is named in output but the run never requested it`);
  }
  for (const status of statuses) {
    assert.ok(observedStatuses.has(status), `status ${status} is named in output but no request observed it`);
  }
  assertNoCanaries(assert, text, "request matching run");
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-ansible-paths-");
  const outside = createTempBase("grclanker-ansible-outside-");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);

  const symlinkTarget = join(base, "symlink-target");
  const symlinkParent = join(base, "symlink-parent");
  writeFileSync(symlinkTarget, "x");
  symlinkSync(outside, symlinkParent);

  assert.throws(() => resolveSecureOutputPath(base, "symlink-parent/file.txt"), /symlinked parent directory/);
});

test("config loader errors: a SyntaxError raised by the transport is recorded by name only, never by the parser's message that quotes the body", async () => {
  const snippet = parserSnippetBody();
  const fetchImpl = async () => {
    throw new SyntaxError(`Unexpected token '<', "${snippet}"... is not valid JSON`);
  };
  const note = "SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body";
  const client = new AnsibleAapClient(AAP_CLIENT_CONFIG, { fetchImpl, now: () => NOW });

  await assert.rejects(() => client.get("/api/v2/me/"), (error) => {
    assert.equal(error.name, "AnsibleApiError");
    assertNoCanaryWindows(assert, error.message, [PARSER_SNIPPET_CANARY], "thrown client error");
    assert.doesNotMatch(error.message, PARSER_WORDING, `the parser's message was interpolated: ${error.message}`);
    assert.equal(error.message, `AAP request failed: /api/v2/me/ (network error: ${note})`);
    return true;
  });

  const outputs = [
    await checkAnsibleAccess(client).then((result) => JSON.stringify(result), (error) => error.message),
    JSON.stringify(await assessAnsibleJobHealth(client)),
  ];
  for (const text of outputs) {
    assertNoCanaryWindows(assert, text, [PARSER_SNIPPET_CANARY], "tool output");
    assert.doesNotMatch(text, PARSER_WORDING, `a slice of the parser's message reached an output: ${text.slice(0, 400)}`);
    assert.ok(text.includes(note), `the output records the parse failure by name: ${text.slice(0, 400)}`);
  }
});

test("config loader errors: a 200 answer whose body is short non-JSON text is recorded as the non-JSON note only; no 6-to-24-character window of the body and no parser wording reaches the thrown client error, the access check, an assessment, or the bundle", async () => {
  // Positive control for the class: V8 quotes the whole source when it is 21 characters or shorter.
  assert.ok(SHORT_BODY_CANARY.length <= 21 && parserMessageFor(SHORT_BODY_CANARY).includes(SHORT_BODY_CANARY), "the parser's message carries the whole short body");

  const surface = "/api/v2/jobs/";
  const log = [];
  const client = aapClient({ ...healthyAapRoutes(), [surface]: () => aapResponse(SHORT_BODY_CANARY, 200, "OK", SHORT_BODY_CONTENT_TYPE) }, log);

  // The thrown client error is fixed text: a scrub at the tool boundary would not protect a caller that logs it.
  await assert.rejects(() => client.get(surface), (error) => {
    assert.equal(error.name, "AnsibleApiError");
    assert.equal(error.status, 200);
    assert.equal(error.endpoint, surface);
    assertShortBodyRecordedAsNote(assert, error.message, "thrown client error");
    assert.equal(error.message, `AAP request failed: ${surface} (200 OK): non-JSON body (${SHORT_BODY_CONTENT_TYPE}, 18 bytes)`);
    return true;
  });

  const run = await runEveryAnsibleTool(client, createTempBase("grclanker-ansible-short-body-"));
  assert.equal(run.accessError, undefined, "the access check completes when a secondary surface fails");
  assertShortBodyRecordedAsNote(assert, run.access, "check_access");
  const probe = run.access.surfaces.find((entry) => entry.name === "jobs");
  assert.ok(probe && probe.status !== "readable", "the jobs probe is not readable");
  assert.equal(probe.http_status, 200, "the probe records the observed status");
  assertShortBodyRecordedAsNote(assert, run.assessments[0], `${run.assessments[0].title} assessment`);
  for (const assessment of run.assessments) assertNoShortBodyFragments(assert, assessment, `${assessment.title} assessment`);

  assert.equal(run.exportError, undefined, "the export completes when a secondary surface fails");
  const files = readBundleFiles(run.exported.outputDir);
  for (const [name, text] of files) assertNoShortBodyFragments(assert, text, `bundle ${name}`);
  for (const [name, text] of readZipEntries(run.exported.zipPath)) assertNoShortBodyFragments(assert, text, `zip ${name}`);
  assertShortBodyRecordedAsNote(assert, files.get("_errors.log"), "_errors.log");
  assert.ok(log.some((entry) => entry.path === surface && entry.status === 200), "the 200 answer named in the note was observed");
});

const PRIMITIVE_BODY_WORDING = /Cannot use 'in' operator|TypeError|is not an object/;

test("rule 9: a 200 answer whose body is a JSON string or array on /api/v2/ping/ or /api/v2/me/ is not the documented object and is dropped; no 6-to-24-character window of it and no TypeError wording reaches the access check, an assessment, or the bundle", async () => {
  // Positive control for the class: the `in` operator on a primitive quotes the whole value in its TypeError message.
  assert.throws(() => "version" in ANSIBLE_PRIMITIVE_BODY_CANARY, (error) => error instanceof TypeError && error.message.includes(ANSIBLE_PRIMITIVE_BODY_CANARY));
  const stringBody = JSON.stringify(ANSIBLE_PRIMITIVE_BODY_CANARY);
  assert.equal(stringBody.length, 21, "the string body is the 21-character shape the reviewer measured");

  for (const [surface, body] of [
    ["/api/v2/ping/", stringBody],
    ["/api/v2/ping/", JSON.stringify([ANSIBLE_PRIMITIVE_BODY_CANARY])],
    ["/api/v2/me/", stringBody],
  ]) {
    const label = `${surface} ${body[0] === "[" ? "array" : "string"} body`;
    const log = [];
    const client = aapClient({ ...healthyAapRoutes(), [surface]: () => aapResponse(body, 200, "OK", "application/json") }, log);
    const run = await runEveryAnsibleTool(client, createTempBase("grclanker-ansible-primitive-body-"));

    assert.equal(run.accessError, undefined, `${label}: the access check completes`);
    if (surface === "/api/v2/ping/") {
      assert.equal(run.access.ping, undefined, `${label}: a body that is not the ping object is dropped, not projected`);
      assert.equal(run.access.status, "healthy", `${label}: the ping body does not change the verdict of the readable surfaces`);
    } else {
      assert.equal(run.access.currentUser, undefined, `${label}: a body that is not the user object yields no current user`);
      assert.ok(run.access.notes.includes("Authentication succeeded but /api/v2/me/ did not return a recognizable user."), `${label}: the access check says the user was not recognizable`);
      assert.equal(run.access.status, "limited", `${label}: no current user caps the access verdict`);
    }
    assertNoCanaryWindows(assert, run.access, [ANSIBLE_PRIMITIVE_BODY_CANARY], `${label} check_access`);
    assert.doesNotMatch(JSON.stringify(run.access), PRIMITIVE_BODY_WORDING, `${label}: no TypeError wording reaches check_access`);
    for (const assessment of run.assessments) {
      assertNoCanaryWindows(assert, assessment, [ANSIBLE_PRIMITIVE_BODY_CANARY], `${label} ${assessment.title}`);
      assert.doesNotMatch(JSON.stringify(assessment), PRIMITIVE_BODY_WORDING, `${label}: no TypeError wording reaches ${assessment.title}`);
    }

    assert.equal(run.exportError, undefined, `${label}: the export completes`);
    const files = readBundleFiles(run.exported.outputDir);
    assertNoCanaryWindowsInFiles(assert, files, [ANSIBLE_PRIMITIVE_BODY_CANARY], `${label} bundle`);
    assertNoCanaryWindowsInFiles(assert, readZipEntries(run.exported.zipPath), [ANSIBLE_PRIMITIVE_BODY_CANARY], `${label} zip`);
    for (const [name, text] of files) assert.doesNotMatch(text, PRIMITIVE_BODY_WORDING, `${label}: no TypeError wording reaches bundle ${name}`);
    const accessFile = JSON.parse(files.get("core_data/access.json"));
    if (surface === "/api/v2/ping/") assert.equal(accessFile.ping, undefined, `${label}: access.json carries no ping`);
    assert.ok(log.some((entry) => entry.path === surface && entry.status === 200), `${label}: the 200 answer was observed`);
  }
});

const ANSIBLE_NESTED_SHORT_CANARY = "Wq4nTz8kBv2xRj6mPc7Ld";
const ANSIBLE_NESTED_LONG_CANARY = "Hx9pLm3vQt7wZk2nRb5cYd8fJg4sNa6uEe1rTi0oKy3qXz7wVb5nMc8dLp2gHf4jSk6tUa9yWo1zPl3eRv7iBn5xCm8oDq2uFa3tGw6yJb9k";

test("rule 9 (round 4 item E): a nested object or array under a documented ping or me key is not the documented value and is dropped, never copied verbatim; no 6-to-24-character window of it reaches the access check, an assessment, or the bundle, and a nested user is not a recognizable user", async () => {
  assert.equal(ANSIBLE_NESTED_SHORT_CANARY.length, 21);
  assert.ok(ANSIBLE_NESTED_LONG_CANARY.length > 100);
  const canaries = [ANSIBLE_NESTED_SHORT_CANARY, ANSIBLE_NESTED_LONG_CANARY];

  // The typed projections alone: documented keys keep only their documented types.
  assert.deepEqual(
    projectPing({ version: { nested: ANSIBLE_NESTED_SHORT_CANARY }, active_node: [ANSIBLE_NESTED_SHORT_CANARY], ha: { flag: ANSIBLE_NESTED_SHORT_CANARY }, instances: { count: ANSIBLE_NESTED_SHORT_CANARY }, results: { username: ANSIBLE_NESTED_SHORT_CANARY }, detail: { text: ANSIBLE_NESTED_SHORT_CANARY } }),
    {},
    "nested21: every documented key holds another shape and is dropped",
  );
  assert.deepEqual(
    projectPing({ version: "4.6.0", active_node: "controller-1", ha: false, instances: [{ node: "controller-1", node_type: "hybrid", capacity: 61, heartbeat: { nested: ANSIBLE_NESTED_LONG_CANARY }, extra: ANSIBLE_NESTED_LONG_CANARY }, ANSIBLE_NESTED_LONG_CANARY], instance_groups: [{ name: "default", capacity: 61, instances: ["controller-1", { node: ANSIBLE_NESTED_LONG_CANARY }] }] }),
    { version: "4.6.0", active_node: "controller-1", ha: false, instances: [{ node: "controller-1", node_type: "hybrid", capacity: 61 }], instance_groups: [{ name: "default", capacity: 61, instances: ["controller-1"] }] },
    "a documented ping keeps its documented fields, list entries included, and drops the nested values beside them",
  );
  assert.deepEqual(projectPing({ version: "4.6.0", active_node: null, ha: true }), { version: "4.6.0", active_node: null, ha: true }, "null is the API's unset and is kept");
  assert.deepEqual(projectUser({ id: "1", username: { nested: ANSIBLE_NESTED_LONG_CANARY }, is_superuser: "true", is_system_auditor: { flag: true }, email: { addr: ANSIBLE_NESTED_LONG_CANARY }, last_login: null }), { last_login: null }, "a user whose documented keys hold other types projects to nothing but its nulls");
  assert.deepEqual(projectUser(SUPERUSER), SUPERUSER, "a documented user is unchanged");
  assert.equal(currentUserFromMe({ count: 1, results: [{ username: { nested: ANSIBLE_NESTED_LONG_CANARY }, id: ANSIBLE_NESTED_LONG_CANARY, email: { addr: ANSIBLE_NESTED_LONG_CANARY } }] }), undefined, "nestedLong: no string username or numeric id, so no user");
  assert.equal(currentUserFromMe({ version: { nested: ANSIBLE_NESTED_SHORT_CANARY }, results: { username: ANSIBLE_NESTED_SHORT_CANARY } }), undefined, "nested21: results is not a list, so no user");
  assert.deepEqual(currentUserFromMe({ count: 1, results: [{ ...SUPERUSER, password: ANSIBLE_NESTED_LONG_CANARY, email: { addr: ANSIBLE_NESTED_LONG_CANARY } }] }), SUPERUSER, "a documented user projects to its documented fields");

  const nested21 = { version: { nested: ANSIBLE_NESTED_SHORT_CANARY }, active_node: [ANSIBLE_NESTED_SHORT_CANARY], ha: { flag: ANSIBLE_NESTED_SHORT_CANARY }, instances: { count: ANSIBLE_NESTED_SHORT_CANARY }, results: { username: ANSIBLE_NESTED_SHORT_CANARY }, detail: { text: ANSIBLE_NESTED_SHORT_CANARY } };
  const nestedLong = { version: { nested: ANSIBLE_NESTED_LONG_CANARY }, active_node: { node: ANSIBLE_NESTED_LONG_CANARY }, results: [{ username: { nested: ANSIBLE_NESTED_LONG_CANARY }, id: ANSIBLE_NESTED_LONG_CANARY, email: { addr: ANSIBLE_NESTED_LONG_CANARY } }], detail: [ANSIBLE_NESTED_LONG_CANARY] };
  for (const [surface, bodyName, body] of [
    ["/api/v2/ping/", "nested21", nested21],
    ["/api/v2/ping/", "nestedLong", nestedLong],
    ["/api/v2/me/", "nested21", nested21],
    ["/api/v2/me/", "nestedLong", nestedLong],
  ]) {
    const label = `${surface} ${bodyName}`;
    const log = [];
    const client = aapClient({ ...healthyAapRoutes(), [surface]: () => aapResponse(JSON.stringify(body), 200, "OK", "application/json") }, log);
    const run = await runEveryAnsibleTool(client, createTempBase("grclanker-ansible-nested-body-"));

    assert.equal(run.accessError, undefined, `${label}: the access check completes`);
    if (surface === "/api/v2/ping/") {
      assert.deepEqual(run.access.ping, {}, `${label}: the ping projects to no documented field`);
      assert.equal(run.access.status, "healthy", `${label}: the ping body does not change the verdict of the readable surfaces`);
    } else {
      assert.equal(run.access.currentUser, undefined, `${label}: a nested user is not a recognizable user`);
      assert.ok(run.access.notes.includes("Authentication succeeded but /api/v2/me/ did not return a recognizable user."), `${label}: the access check says the user was not recognizable`);
      assert.equal(run.access.status, "limited", `${label}: no current user caps the access verdict`);
    }
    assertNoCanaryWindows(assert, run.access, canaries, `${label} check_access`);
    assert.doesNotMatch(JSON.stringify(run.access), PRIMITIVE_BODY_WORDING, `${label}: no TypeError wording reaches check_access`);
    for (const assessment of run.assessments) {
      assertNoCanaryWindows(assert, assessment, canaries, `${label} ${assessment.title}`);
      assert.doesNotMatch(JSON.stringify(assessment), PRIMITIVE_BODY_WORDING, `${label}: no TypeError wording reaches ${assessment.title}`);
    }

    assert.equal(run.exportError, undefined, `${label}: the export completes`);
    const files = readBundleFiles(run.exported.outputDir);
    assertNoCanaryWindowsInFiles(assert, files, canaries, `${label} bundle`);
    assertNoCanaryWindowsInFiles(assert, readZipEntries(run.exported.zipPath), canaries, `${label} zip`);
    for (const [name, text] of files) assert.doesNotMatch(text, PRIMITIVE_BODY_WORDING, `${label}: no TypeError wording reaches bundle ${name}`);
    assert.ok(log.some((entry) => entry.path === surface && entry.status === 200), `${label}: the 200 answer was observed`);
  }
});
