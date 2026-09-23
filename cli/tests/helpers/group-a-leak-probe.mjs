/**
 * Group A adapters for the shared leak-probe harness (Box, LaunchDarkly, KnowBe4, Datadog, Elastic).
 *
 * Each adapter wires the integration's entry points into the harness: the error scrubber and the data
 * walker as text sinks, the walker itself for the depth and data-side classes, the configured secrets
 * the client registers, an export runner that runs the bundle export through the harness's fetch, and
 * for LaunchDarkly (the only group A client that follows a server-supplied link) a next-link runner.
 * Class 9 (truncated-page and denial flips) is not wired here: the rule 1 corollary leaf-diff tests
 * and the rule 10 sweeps in each integration's suite pin those flips per inventory.
 *
 * `runGroupALeakProbe(integration)` returns the harness result, the planted configured secrets, and
 * every bundle and zip text the export runner wrote, so the caller can scan the bundles for a
 * configured secret the harness did not plant itself.
 *
 * The suites call `runGroupALeakProbeInFreshProcess` instead: each integration module keeps every
 * configured secret ever registered with it for the life of the process (a secret once known is
 * scrubbed from then on), so a probe run inside a suite would also scrub the fixture values the
 * earlier tests registered, and a fixture value such as `client-secret` inside a probe row's key name
 * turns the key into the marker and leaves the value beside it. A fresh process reads only what the
 * probe itself configured, which is also what the reviewers' standalone runner reads. Running this
 * file directly (`node group-a-leak-probe.mjs <integration> <result.json>`) is that child.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { assertNoLeaks, leakedWindow, makeCanaries, runLeakProbe } from "./leak-probe-harness.mjs";
import { readBundleFiles, readZipEntries } from "./bundle-contents.mjs";
import * as box from "../../dist/extensions/grc-tools/box.js";
import * as launchdarkly from "../../dist/extensions/grc-tools/launchdarkly.js";
import * as knowbe4 from "../../dist/extensions/grc-tools/knowbe4.js";
import * as datadog from "../../dist/extensions/grc-tools/datadog.js";
import * as elastic from "../../dist/extensions/grc-tools/elastic.js";

export const GROUP_A_INTEGRATIONS = Object.freeze(["box", "launchdarkly", "knowbe4", "datadog", "elastic"]);

const THIS_FILE = fileURLToPath(import.meta.url);
// The Box probe runs about eighteen thousand class 1 cells through two sinks; a slow runner needs minutes, not seconds.
const FRESH_PROCESS_TIMEOUT_MS = 10 * 60 * 1000;
const NOW = new Date("2026-09-22T12:00:00Z");
const CANARY_COUNT = 14;
const noSleep = async () => {};

function tempBase(prefix) {
  return mkdtempSync(join(tmpdir(), `${prefix}-`));
}

function jsonResponse(body, status = 200) {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  return new Response(text, { status, headers: { "content-type": "application/json" } });
}

function urlOf(input) {
  return typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
}

function fixtureTextOf(options) {
  return [
    ...(options.headerNames ?? []),
    ...(options.schemeWords ?? []),
    ...(options.credentialKeys ?? []),
    ...(options.settingKeys ?? []),
    ...(options.identifierKeys ?? []),
    ...(options.mustKeep ?? []),
  ].join("\n");
}

async function exportOutcome(run, scrub, bundles) {
  try {
    const result = await run();
    bundles.push(result);
    return { outputDir: result.outputDir, zipPath: result.zipPath, toolPayloads: [result] };
  } catch (error) {
    if (error instanceof SyntaxError) return { toolPayloads: ["SyntaxError: response could not be parsed as JSON"] };
    return { toolPayloads: [scrub(error instanceof Error ? error.message : String(error))] };
  }
}

function sinks(scrubError, walkerName, redactValues) {
  return {
    error: [{ name: "scrubErrorText", fn: (text) => scrubError(text) }],
    data: [{ name: `${walkerName}(string)`, fn: (text) => String(redactValues(text)) }],
  };
}

// The harness nests `depth` containers under the root, alternating an array every third level.
function nestLikeHarness(depth, leaf) {
  let value = leaf;
  for (let level = depth; level >= 1; level -= 1) value = level % 3 === 0 ? [value] : { [`level_${level}`]: value };
  return value;
}

function leafOfNest(value, depth) {
  let current = value;
  for (let level = 1; level <= depth; level += 1) {
    if (current === null || typeof current !== "object") return current;
    current = Array.isArray(current) ? current[0] : current[`level_${level}`];
  }
  return current;
}

/**
 * The harness's own `detectCap` nests directly under the root; its class 7 cells nest under `settings` on a record, one
 * level deeper. The cap is stated in cell terms: the deepest nesting under `settings` whose leaf record survives.
 */
function detectCellCap(walker) {
  for (let depth = 1; depth <= 80; depth += 1) {
    const out = walker({ id: "rec-1", settings: nestLikeHarness(depth, { name: "leaf" }) });
    const leaf = leafOfNest(out.settings, depth);
    if (leaf === null || typeof leaf !== "object") return depth - 1;
  }
  return null;
}

function walkerOf(name, fn) {
  return { name, fn, cap: detectCellCap(fn) };
}

function recordRequests(requests, input, init) {
  requests.push({ url: urlOf(input), method: init?.method ?? "GET", headers: init?.headers ?? {} });
}

// ---------------------------------------------------------------- Box

function boxProbe(canaries) {
  const tokens = canaries.tokens;
  const options = {
    integration: "box",
    headerNames: ["Authorization", "Cookie", "Set-Cookie", "X-Api-Key"],
    schemeWords: ["Bearer", "Basic"],
    credentialKeys: ["BOX_CLIENT_SECRET", "BOX_JWT_PRIVATE_KEY", "BOX_JWT_PASSPHRASE", "BOX_ACCESS_TOKEN", "BOX_REFRESH_TOKEN", "refresh_token", "access_token", "developer_token"],
    settingKeys: ["BOX_AUTH_METHOD", "BOX_JWT_ALGORITHM", "BOX_TOKEN_URL", "auth_method", "subject_type"],
    identifierKeys: ["BOX_CLIENT_ID", "BOX_ENTERPRISE_ID", "BOX_SUBJECT_ID", "enterprise_id", "subject_id"],
    mustKeep: ["GET /users?fields=id,login&limit=1000", "enterprise 123456", "access_denied_insufficient_permissions", "svc-reporting-2026"],
  };
  const config = {
    authMode: "ccg",
    clientId: "client-id",
    clientSecret: tokens[10],
    enterpriseId: "123456",
    subjectType: "enterprise",
    subjectId: "123456",
    baseUrl: "https://api.box.com/2.0",
    tokenUrl: "https://api.box.com/oauth2/token",
    timeoutMs: 30000,
    maxRetries: 0,
    sourceChain: ["tests"],
  };
  // Constructing the client registers the configured secret with the shared scrubber.
  new box.BoxApiClient(config, { fetchImpl: async () => jsonResponse({}), sleep: noSleep });
  const bundles = [];
  const extraPlanted = [tokens[10], tokens[11]];
  const exportRunner = async ({ scenario, fetchImpl, requests }) => {
    const routed = async (input, init) => {
      const url = urlOf(input);
      if (url.startsWith(config.tokenUrl)) {
        recordRequests(requests, input, init);
        return jsonResponse({ access_token: tokens[11], expires_in: 3600, token_type: "bearer" });
      }
      return fetchImpl(input, init);
    };
    const client = new box.BoxApiClient(config, { fetchImpl: routed, sleep: noSleep, now: () => NOW });
    return exportOutcome(() => box.exportBoxAuditBundle(client, config, tempBase(`box-${scenario}`)), box.scrubErrorText, bundles);
  };
  return {
    canaries,
    extraPlanted,
    bundles,
    options: {
      ...options,
      canaries,
      textScrubbers: sinks(box.scrubErrorText, "redactCredentialValues", box.redactCredentialValues),
      configuredSecrets: [tokens[10], tokens[11]],
      dataWalker: walkerOf("redactCredentialValues", box.redactCredentialValues),
      exportRunner,
    },
  };
}

// ---------------------------------------------------------------- LaunchDarkly

function launchdarklyProbe(canaries) {
  const tokens = canaries.tokens;
  const origin = "https://app.launchdarkly.com";
  const options = {
    integration: "launchdarkly",
    origin,
    headerNames: ["Authorization", "Cookie", "Set-Cookie"],
    schemeWords: ["Bearer"],
    credentialKeys: ["LAUNCHDARKLY_ACCESS_TOKEN", "LD_API_KEY", "access_token", "api_key", "sdk_key", "mobile_key", "relay_key"],
    settingKeys: ["LAUNCHDARKLY_API_VERSION", "api_version", "LAUNCHDARKLY_BASE_URL"],
    identifierKeys: ["project_key", "environment_key", "flag_key", "LAUNCHDARKLY_PROJECT_KEYS"],
    mustKeep: ["GET /api/v2/members?limit=20&offset=0", "prod-us-east-2026", "svc-reporting-2026"],
  };
  const config = {
    token: tokens[10],
    baseUrl: origin,
    apiVersion: "20240415",
    timeoutMs: 30000,
    allowedDomains: ["example.com"],
    projectKeys: [],
    configPath: "/nonexistent/config.toml",
    sourceChain: ["tests"],
  };
  new launchdarkly.LaunchdarklyApiClient(config, { fetchImpl: async () => jsonResponse({}), sleep: noSleep, maxRetries: 0 });
  const bundles = [];
  const exportRunner = async ({ scenario, fetchImpl }) => {
    const client = new launchdarkly.LaunchdarklyApiClient(config, { fetchImpl, sleep: noSleep, maxRetries: 0 });
    return exportOutcome(() => launchdarkly.exportLaunchdarklyAuditBundle(client, config, tempBase(`launchdarkly-${scenario}`), { now: NOW.getTime() }), launchdarkly.scrubErrorText, bundles);
  };
  const nextLinkRunner = async ({ nextLink, fetchImpl }) => {
    const requests = [];
    let first = true;
    const routed = async (input, init) => {
      recordRequests(requests, input, init);
      if (first) {
        first = false;
        return jsonResponse({ items: [{ _id: "m1", email: "member-one@example.com" }], totalCount: 2, _links: { next: { href: nextLink } } });
      }
      return fetchImpl(input, init);
    };
    const client = new launchdarkly.LaunchdarklyApiClient(config, { fetchImpl: routed, sleep: noSleep, maxRetries: 0 });
    try {
      const members = await client.list("/api/v2/members", {}, { limit: 10, pageSize: 1 });
      return { requests, errorTexts: [], findings: [], truncated: members.truncated, note: members.truncationReason };
    } catch (error) {
      const text = launchdarkly.scrubErrorText(error instanceof Error ? error.message : String(error));
      return { requests, errorTexts: [text], findings: [], truncated: true, note: text };
    }
  };
  return {
    canaries,
    extraPlanted: [tokens[10]],
    bundles,
    options: {
      ...options,
      canaries,
      textScrubbers: sinks(launchdarkly.scrubErrorText, "redactCredentialValues", launchdarkly.redactCredentialValues),
      configuredSecrets: [tokens[10]],
      dataWalker: walkerOf("redactCredentialValues", launchdarkly.redactCredentialValues),
      exportRunner,
      nextLinkRunner,
    },
  };
}

// ---------------------------------------------------------------- KnowBe4

function knowbe4Probe(canaries) {
  const tokens = canaries.tokens;
  const options = {
    integration: "knowbe4",
    headerNames: ["Authorization", "X-Phisher-Token", "Cookie", "Set-Cookie"],
    schemeWords: ["Bearer"],
    credentialKeys: ["KNOWBE4_API_TOKEN", "KNOWBE4_PHISHER_API_TOKEN", "api_token", "phisher_api_token", "reporting_token"],
    settingKeys: ["KNOWBE4_REGION", "region", "KNOWBE4_REDACT_PII"],
    identifierKeys: ["account_id", "user_id", "campaign_id", "KNOWBE4_ACCOUNT_ID"],
    mustKeep: ["GET /v1/users?page=1&per_page=500", "us.api.knowbe4.com", "svc-reporting-2026"],
  };
  const config = {
    apiToken: tokens[10],
    region: "us",
    baseUrl: "https://us.api.knowbe4.com",
    phisherApiToken: tokens[11],
    phisherGraphqlUrl: "https://training.knowbe4.com/graphql",
    timeoutMs: 30000,
    redactPii: false,
    configFile: "/nonexistent/config.yaml",
    sourceChain: ["tests"],
  };
  new knowbe4.Knowbe4ApiClient(config, { fetchImpl: async () => jsonResponse({}), sleepImpl: noSleep, maxRetries: 0 });
  const bundles = [];
  const exportRunner = async ({ scenario, fetchImpl }) => {
    const client = new knowbe4.Knowbe4ApiClient(config, { fetchImpl, sleepImpl: noSleep, maxRetries: 0 });
    return exportOutcome(() => knowbe4.exportKnowbe4AuditBundle(client, config, tempBase(`knowbe4-${scenario}`), { now: NOW }), knowbe4.scrubErrorText, bundles);
  };
  return {
    canaries,
    extraPlanted: [tokens[10], tokens[11]],
    bundles,
    options: {
      ...options,
      canaries,
      textScrubbers: sinks(knowbe4.scrubErrorText, "redactCredentialValues", knowbe4.redactCredentialValues),
      configuredSecrets: [tokens[10], tokens[11]],
      dataWalker: walkerOf("redactCredentialValues", knowbe4.redactCredentialValues),
      exportRunner,
    },
  };
}

// ---------------------------------------------------------------- Datadog

function datadogProbe(canaries) {
  const tokens = canaries.tokens;
  const options = {
    integration: "datadog",
    headerNames: ["Authorization", "DD-API-KEY", "DD-APPLICATION-KEY", "Cookie", "Set-Cookie"],
    schemeWords: ["Bearer", "Basic"],
    credentialKeys: ["DD_API_KEY", "DD_APP_KEY", "DATADOG_API_KEY", "DATADOG_APP_KEY", "api_key", "application_key", "app_key"],
    settingKeys: ["DD_SITE", "site", "DD_MAX_RETRIES"],
    identifierKeys: ["org_id", "public_id", "key_id", "DD_ORG_ID"],
    mustKeep: ["GET /api/v2/users?page[size]=100", "datadoghq.com", "us-east-1", "svc-reporting-2026"],
  };
  const config = {
    apiKey: tokens[10],
    appKey: tokens[11],
    site: "datadoghq.com",
    baseUrl: "https://api.datadoghq.com",
    timeoutMs: 30000,
    maxRetries: 0,
    sourceChain: ["tests"],
  };
  new datadog.DatadogApiClient(config, { fetchImpl: async () => jsonResponse({}), sleepImpl: noSleep });
  const bundles = [];
  const exportRunner = async ({ scenario, fetchImpl }) => {
    const client = new datadog.DatadogApiClient(config, { fetchImpl, sleepImpl: noSleep });
    return exportOutcome(() => datadog.exportDatadogAuditBundle(client, config, tempBase(`datadog-${scenario}`), { now: NOW }), datadog.scrubErrorText, bundles);
  };
  return {
    canaries,
    extraPlanted: [tokens[10], tokens[11]],
    bundles,
    options: {
      ...options,
      canaries,
      textScrubbers: sinks(datadog.scrubErrorText, "redactCredentialValues", datadog.redactCredentialValues),
      configuredSecrets: [tokens[10], tokens[11]],
      dataWalker: walkerOf("redactCredentialValues", datadog.redactCredentialValues),
      exportRunner,
    },
  };
}

// ---------------------------------------------------------------- Elastic

function elasticProbe(canaries) {
  const tokens = canaries.tokens;
  const options = {
    integration: "elastic",
    headerNames: ["Authorization", "Cookie", "Set-Cookie", "X-Api-Key"],
    schemeWords: ["Bearer", "Basic", "ApiKey"],
    credentialKeys: ["ELASTIC_API_KEY", "ELASTIC_PASSWORD", "ELASTIC_BEARER_TOKEN", "ELASTIC_CLOUD_API_KEY", "bind_password", "secure_password", "keystore_password", "api_key", "password"],
    settingKeys: ["ELASTIC_AUTH_MODE", "auth_mode", "ELASTICSEARCH_URL", "KIBANA_URL"],
    identifierKeys: ["ELASTIC_USERNAME", "username", "api_key_id", "cluster_uuid"],
    mustKeep: ["GET /_security/user", "https://es.example.com:9200", "audit-key-id", "svc-reporting-2026"],
  };
  const apiKeySecret = tokens[10];
  const apiKey = Buffer.from(`audit-key-id:${apiKeySecret}`).toString("base64");
  const config = {
    elasticsearchUrl: "https://es.example.com:9200",
    kibanaUrl: "https://kibana.example.com:5601",
    kibanaSpaceId: undefined,
    authMode: "api_key",
    apiKey,
    cloudApiUrl: "https://api.elastic-cloud.com",
    timeoutMs: 5000,
    maxRetries: 0,
    sourceChain: ["tests"],
  };
  new elastic.ElasticApiClient(config, { fetchImpl: async () => jsonResponse({}), sleepImpl: noSleep });
  const bundles = [];
  const exportRunner = async ({ scenario, fetchImpl }) => {
    const client = new elastic.ElasticApiClient(config, { fetchImpl, sleepImpl: noSleep });
    return exportOutcome(() => elastic.exportElasticAuditBundle(client, config, tempBase(`elastic-${scenario}`), {}), elastic.scrubErrorText, bundles);
  };
  return {
    canaries,
    extraPlanted: [apiKey, apiKeySecret],
    bundles,
    options: {
      ...options,
      canaries,
      textScrubbers: sinks(elastic.scrubErrorText, "redactSensitiveValues", elastic.redactSensitiveValues),
      configuredSecrets: [apiKey, apiKeySecret],
      dataWalker: walkerOf("redactSensitiveValues", elastic.redactSensitiveValues),
      exportRunner,
    },
  };
}

const PROBES = { box: boxProbe, launchdarkly: launchdarklyProbe, knowbe4: knowbe4Probe, datadog: datadogProbe, elastic: elasticProbe };

/** Runs the harness for one integration; returns the harness result plus the planted extras and bundle texts. */
export async function runGroupALeakProbe(integration) {
  const probeFactory = PROBES[integration];
  if (!probeFactory) throw new Error(`unknown group A integration: ${integration}`);
  // Canaries are drawn against the integration's own vocabulary, so the fixture text must be known before the probe.
  const vocabularyProbe = probeFactory({ tokens: Array.from({ length: CANARY_COUNT }, (_, index) => `placeholder${index}`) });
  const canaries = makeCanaries(CANARY_COUNT, fixtureTextOf(vocabularyProbe.options));
  const probe = probeFactory(canaries);
  const result = await runLeakProbe(probe.options);
  const bundleTexts = [];
  for (const bundle of probe.bundles) {
    if (bundle?.outputDir) for (const [, text] of readBundleFiles(bundle.outputDir)) bundleTexts.push(text);
    if (bundle?.zipPath) for (const [, text] of readZipEntries(bundle.zipPath)) bundleTexts.push(text);
  }
  return { result, extraPlanted: probe.extraPlanted, bundleTexts, bundles: probe.bundles };
}

/**
 * Runs `runGroupALeakProbe` for one integration in a fresh Node process (see the file comment) and returns what it
 * returned, less the bundle records, which stay with the child. A child that fails to produce a result throws with
 * its stderr, so a crash inside the probe reads as that crash and not as a missing file.
 */
export function runGroupALeakProbeInFreshProcess(integration) {
  if (!GROUP_A_INTEGRATIONS.includes(integration)) throw new Error(`unknown group A integration: ${integration}`);
  const resultDir = tempBase(`group-a-leak-probe-${integration}`);
  const resultPath = join(resultDir, "result.json");
  try {
    const child = spawnSync(process.execPath, [THIS_FILE, integration, resultPath], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: FRESH_PROCESS_TIMEOUT_MS,
      maxBuffer: 64 * 1024 * 1024,
    });
    if (child.error) throw child.error;
    if (child.status !== 0) {
      throw new Error(`leak-probe child for ${integration} exited with ${child.status ?? `signal ${child.signal}`}:\n${child.stderr}${child.stdout}`);
    }
    return JSON.parse(readFileSync(resultPath, "utf8"));
  } finally {
    rmSync(resultDir, { recursive: true, force: true });
  }
}

/** The headline and the class table of a harness report, without the example cells. */
export function reportTable(result) {
  const lines = result.report.split("\n");
  const end = lines.findIndex((line, index) => index > 2 && line.trim() === "");
  return (end === -1 ? lines : lines.slice(0, end)).join("\n");
}

/**
 * The group A reading of a harness result: zero gating leaks, must-keep losses, and idempotence failures; every class
 * the integration wires ran cells (class 8 only where a next-link runner exists, class 9 never, see the file comment);
 * the depth cap was detected and the containers past it became the marker; and no window (6 through 24 characters) of
 * a configured secret the harness did not plant itself reached a bundle or zip text.
 */
export function assertGroupALeakProbe(assert, run, { integration, nextLinks = false }) {
  const { result, extraPlanted, bundleTexts } = run;
  assert.equal(result.integration, integration);
  assertNoLeaks(result);
  for (const cls of result.classes) {
    if (cls.id === 9) {
      assert.equal(cls.skipped, "no truncationRunner given", `${integration}: class 9 is not wired for group A`);
    } else if (cls.id === 8 && !nextLinks) {
      assert.equal(cls.skipped, "no nextLinkRunner given", `${integration}: only LaunchDarkly follows a server-supplied link`);
    } else {
      assert.equal(cls.skipped, null, `${integration}: class ${cls.id} ran`);
      assert.ok(cls.cells > 0, `${integration}: class ${cls.id} ran cells`);
    }
    if (cls.id === 7) {
      assert.ok(cls.notes.some((note) => /cap \d+ given/.test(note)), `${integration}: the walker's depth cap is stated in cell terms`);
      assert.ok(cls.notes.some((note) => /past the cap\): the container was replaced by a marker/.test(note)), `${integration}: a container past the cap becomes the marker`);
    }
  }
  assert.ok(bundleTexts.length > 0, `${integration}: the export runner wrote bundles the scan can read`);
  for (const text of bundleTexts) {
    for (const value of extraPlanted) {
      assert.equal(leakedWindow(text, value), undefined, `${integration}: a window of a configured secret reached a bundle text`);
    }
  }
}

// Direct execution is the child of `runGroupALeakProbeInFreshProcess`: the probe result goes to the given path.
if (process.argv[1] && resolve(process.argv[1]) === THIS_FILE) {
  const [integration, resultPath] = process.argv.slice(2);
  if (!resultPath) {
    process.stderr.write(`usage: node ${THIS_FILE} <${GROUP_A_INTEGRATIONS.join("|")}> <result.json>\n`);
    process.exit(2);
  }
  const { result, extraPlanted, bundleTexts } = await runGroupALeakProbe(integration);
  writeFileSync(resultPath, JSON.stringify({ result, extraPlanted, bundleTexts }));
}
