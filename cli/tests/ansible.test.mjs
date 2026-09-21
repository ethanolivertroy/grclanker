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
  AnsibleAapClient,
  assessAnsibleHostCoverage,
  assessAnsibleJobHealth,
  assessAnsiblePlatformSecurity,
  checkAnsibleAccess,
  createTlsOptOutFetch,
  exportAnsibleAuditBundle,
  findPlaintextSecrets,
  parseRruleInterval,
  resolveAnsibleConfiguration,
  resolveSecureOutputPath,
} from "../dist/extensions/grc-tools/ansible.js";

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
function createMockClient({ now = NOW, routes = {}, me = SUPERUSER, mode = "normal", counts = {} } = {}) {
  const resolvedRoutes = { ...HEALTHY_ROUTES, ...routes };
  const requested = [];
  const client = {
    requested,
    getNow: () => now,
    async get(path) {
      requested.push(path);
      if (path === "/api/v2/me/") return { count: 1, results: [me] };
      if (mode === "forbidden") forbidden(path);
      if (path === "/api/v2/ping/") return { version: "4.6.0", active_node: "controller-1" };
      if (mode === "empty") return {};
      const value = resolvedRoutes[path];
      if (value === undefined) throw new Error(`AAP request failed: ${path} (404 Not Found)`);
      return value;
    },
    async listCollection(path, _query = {}, options = {}) {
      requested.push(path);
      if (mode === "forbidden") forbidden(path);
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
      if (mode === "forbidden") forbidden(path);
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
    token: "aap-token",
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
  assert.ok(!rawBundle.includes("aap-token"));
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
