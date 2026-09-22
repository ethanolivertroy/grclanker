import test from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse as parseYaml } from "yaml";

import {
  ELASTIC_ALL_DATASETS,
  ELASTIC_CONTROLS,
  ELASTIC_FRAMEWORKS,
  ElasticApiClient,
  ElasticRequestError,
  assessElasticAccessControl,
  assessElasticClusterHardening,
  assessElasticIdentity,
  assessElasticKibana,
  assessElasticTransportSecurity,
  checkElasticAccess,
  collectElasticSnapshot,
  describeResponseShape,
  evaluateElasticArea,
  exportElasticAuditBundle,
  matchesResponseShape,
  normalizeElasticApiKey,
  projectDataset,
  redactSecrets,
  redactSensitiveValues,
  reduceUrlsToOrigin,
  registerElasticTools,
  resolveElasticConfiguration,
  resolveSecureOutputPath,
  scrubErrorText,
} from "../dist/extensions/grc-tools/elastic.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";
import { readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";
import { assertCanaryFixture, assertCanaryWindowsAbsent } from "./helpers/canary-windows.mjs";
import { scrubAlterations } from "./helpers/scrub-survival.mjs";

const DAY_MS = 86_400_000;
// The configured API key: its base64 form and the secret half of its decoded id:api_key form are both alphanumeric and
// random-looking so that every 6-to-24-character window of each can be asserted absent (helpers/canary-windows.mjs).
const API_KEY_SECRET = "pf4bJ2aaYRdRv9UBB5ZkrDKRUzxMhBa7";
const API_KEY = Buffer.from(`audit-key-id:${API_KEY_SECRET}`).toString("base64");

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function sampleConfig(overrides = {}) {
  return {
    elasticsearchUrl: "https://es.example.com:9200",
    kibanaUrl: "https://kibana.example.com:5601",
    kibanaSpaceId: undefined,
    authMode: "api_key",
    apiKey: API_KEY,
    cloudApiUrl: "https://api.elastic-cloud.com",
    timeoutMs: 5000,
    maxRetries: 3,
    sourceChain: ["tests"],
    ...overrides,
  };
}

function jsonResponse(value, options = {}) {
  return new Response(JSON.stringify(value), {
    status: options.status ?? 200,
    statusText: options.statusText ?? (options.status && options.status >= 400 ? "Error" : "OK"),
    headers: {
      "content-type": "application/json",
      ...(options.headers ?? {}),
    },
  });
}

function headerValue(headers, name) {
  if (!headers) return undefined;
  if (headers instanceof Headers) return headers.get(name) ?? undefined;
  if (typeof headers.get === "function") return headers.get(name) ?? undefined;
  return headers[name] ?? headers[name.toLowerCase()];
}

function healthyFixtures(now = Date.now()) {
  return {
    authenticate: {
      username: "grc-auditor",
      roles: ["grc_auditor"],
      enabled: true,
      authentication_realm: { name: "native1", type: "native" },
      lookup_realm: { name: "native1", type: "native" },
      authentication_type: "api_key",
    },
    hasPrivileges: {
      username: "grc-auditor",
      has_all_requested: false,
      cluster: {
        monitor: true,
        read_security: true,
        manage_security: false,
        manage_api_key: true,
        read_pipeline: true,
        manage_pipeline: false,
        monitor_snapshot: true,
        read_ilm: true,
        manage_ilm: false,
        read_slm: true,
        manage_slm: false,
        monitor_watcher: true,
      },
      index: { ".security*": { read: true } },
      application: {},
    },
    license: {
      license: {
        status: "active",
        uid: "lic-1",
        type: "platinum",
        issue_date_in_millis: now - 100 * DAY_MS,
        expiry_date_in_millis: now + 400 * DAY_MS,
        max_nodes: 100,
      },
    },
    xpackInfo: {
      build: { hash: "abc", date: "2026-01-01T00:00:00.000Z" },
      features: {
        security: { available: true, enabled: true },
        watcher: { available: true, enabled: true },
      },
    },
    xpackUsage: {
      security: {
        available: true,
        enabled: true,
        realms: {
          native: { enabled: true, available: true, size: 3 },
          file: { enabled: true, available: true, size: 0 },
          saml: { enabled: true, available: true, size: 1 },
        },
        roles: { native: { size: 4, fls: true, dls: true }, file: { size: 0, fls: false, dls: false } },
        ssl: { http: { enabled: true }, transport: { enabled: true } },
        audit: { enabled: true, outputs: ["logfile"] },
        ipfilter: { http: false, transport: false },
        anonymous: { enabled: false },
        token_service: { enabled: true },
        api_key_service: { enabled: true },
        fips_140: { enabled: false },
      },
    },
    clusterSettings: {
      persistent: {},
      transient: {},
      defaults: { "cluster.name": "audit-cluster", "xpack.security.enabled": "true" },
    },
    nodeSettings: {
      _nodes: { total: 1, successful: 1, failed: 0 },
      cluster_name: "audit-cluster",
      nodes: {
        "node-1": {
          name: "es-1",
          version: "8.15.0",
          settings: {
            "xpack.security.enabled": "true",
            "xpack.security.transport.ssl.enabled": "true",
            "xpack.security.transport.ssl.verification_mode": "certificate",
            "xpack.security.transport.ssl.supported_protocols": ["TLSv1.3", "TLSv1.2"],
            "xpack.security.http.ssl.enabled": "true",
            "xpack.security.http.ssl.supported_protocols": ["TLSv1.3", "TLSv1.2"],
            "xpack.security.audit.enabled": "true",
            "xpack.security.audit.logfile.events.include": [
              "access_denied",
              "authentication_failed",
              "security_config_change",
              "run_as_denied",
            ],
            "xpack.security.authc.realms.native.native1.order": "0",
            "xpack.security.authc.realms.saml.corp_sso.order": "2",
            "xpack.security.authc.realms.saml.corp_sso.attributes.principal": "nameid",
            "xpack.security.authc.realms.saml.corp_sso.attributes.groups": "groups",
            "xpack.security.authc.password_hashing.algorithm": "bcrypt",
            "xpack.security.authc.token.enabled": "true",
            "xpack.security.authc.api_key.enabled": "true",
          },
        },
      },
    },
    sslCertificates: [
      {
        path: "certs/http.p12",
        format: "PKCS12",
        alias: "http",
        subject_dn: "CN=es-1",
        serial_number: "01",
        has_private_key: true,
        expiry: new Date(now + 700 * DAY_MS).toISOString(),
      },
    ],
    users: {
      elastic: { username: "elastic", roles: ["superuser"], enabled: true, metadata: { _reserved: true } },
      auditor: { username: "auditor", roles: ["analyst_fls"], enabled: true, metadata: {} },
    },
    roles: {
      superuser: {
        cluster: ["all"],
        indices: [{ names: ["*"], privileges: ["all"], allow_restricted_indices: true }],
        metadata: { _reserved: true },
      },
      analyst_fls: {
        cluster: ["monitor"],
        indices: [{ names: ["customers-*"], privileges: ["read"], field_security: { grant: ["id", "region"] } }],
        metadata: {},
      },
      tenant_dls: {
        cluster: [],
        indices: [{ names: ["tenant-*"], privileges: ["read"], query: "{\"term\":{\"tenant_id\":\"{{_user.metadata.tenant}}\"}}" }],
        metadata: {},
      },
    },
    roleMappings: {
      saml_users: {
        enabled: true,
        roles: ["kibana_user"],
        rules: { field: { "realm.name": "corp_sso" } },
        metadata: {},
      },
    },
    apiKeys: [
      {
        id: "key-1",
        name: "ci-reader",
        type: "rest",
        creation: now - 10 * DAY_MS,
        expiration: now + 30 * DAY_MS,
        invalidated: false,
        username: "auditor",
        realm: "native1",
        metadata: {},
        role_descriptors: { reader: { cluster: ["monitor"], indices: [{ names: ["logs-*"], privileges: ["read"] }] } },
        limited_by: [{ analyst_fls: { cluster: ["monitor"], indices: [] } }],
        _sort: [now - 10 * DAY_MS, "ci-reader"],
      },
    ],
    ilmStatus: { operation_mode: "RUNNING" },
    ilmPolicies: {
      "logs-retention": {
        version: 1,
        modified_date: "2026-01-01T00:00:00.000Z",
        policy: {
          phases: {
            hot: { min_age: "0ms", actions: { rollover: { max_age: "7d" } } },
            delete: { min_age: "365d", actions: { delete: {} } },
          },
        },
        in_use_by: { indices: ["logs-000001"], data_streams: [], composable_templates: [] },
      },
    },
    slmStatus: { operation_mode: "RUNNING" },
    slmPolicies: {
      nightly: {
        version: 1,
        name: "<nightly-{now/d}>",
        schedule: "0 30 1 * * ?",
        repository: "backups",
        policy: { indices: ["*"] },
        last_success: { snapshot_name: "nightly-2026.09.20", time: now - DAY_MS },
        next_execution_millis: now + DAY_MS,
      },
    },
    snapshotRepositories: {
      backups: { type: "gcs", settings: { bucket: "es-backups" } },
    },
    watches: [
      {
        _id: "cpu-alert",
        watch: {
          trigger: { schedule: { interval: "5m" } },
          actions: {
            notify: { webhook: { scheme: "https", host: "hooks.example.com", port: 443, method: "post", path: "/alerts" } },
          },
        },
      },
    ],
    ingestPipelines: {
      "logs-enrich": { processors: [{ set: { field: "event.kind", value: "event" } }] },
      ".fleet_final_pipeline-1": { _meta: { managed: true }, processors: [{ script: { source: "ctx.x = 1" } }] },
    },
    kibanaStatus: {
      name: "kibana",
      uuid: "kb-1",
      version: { number: "8.15.0" },
      status: { overall: { level: "available" } },
    },
    spaces: [
      { id: "default", name: "Default", disabledFeatures: [], _reserved: true },
      { id: "security-team", name: "Security", disabledFeatures: ["ml"] },
    ],
    kibanaRoles: [
      {
        name: "superuser",
        metadata: { _reserved: true },
        elasticsearch: { cluster: ["all"], indices: [] },
        kibana: [{ base: ["all"], feature: {}, spaces: ["*"] }],
      },
      {
        name: "security_analyst",
        metadata: {},
        elasticsearch: { cluster: [], indices: [] },
        kibana: [{ base: [], feature: { siem: ["all"], discover: ["read"] }, spaces: ["security-team"] }],
      },
    ],
    agentPolicies: [{ id: "policy-1", name: "Linux servers", is_protected: true, namespace: "default" }],
    fleetOutputs: [
      { id: "default-output", name: "default", type: "elasticsearch", hosts: ["https://es.example.com:9200"], ca_trusted_fingerprint: "abc123", is_default: true },
    ],
    enrollmentKeys: [{ id: "enroll-1", active: true, policy_id: "policy-1", api_key_id: "ak-1", api_key: "enrollment-secret", name: "Default" }],
    fleetServerHosts: [{ id: "fleet-1", name: "Default", host_urls: ["https://fleet.example.com:8220"], is_default: true }],
    detectionRules: [{ id: "rule-1", name: "Suspicious login", enabled: true, actions: [] }],
    alertingRules: [{ id: "alert-1", name: "CPU high", enabled: true, actions: [{ id: "connector-1", group: "default" }] }],
    connectors: [
      { id: "connector-1", name: "slack-hook", connector_type_id: ".webhook", is_missing_secrets: false, config: { url: "https://hooks.slack.com/services/x" } },
    ],
    cloudDeployments: [{ id: "deployment-1", name: "prod" }],
  };
}

function stubClient(fixtures, overrides = {}, configOverrides = {}) {
  const base = {
    getResolvedConfig: () => sampleConfig(configOverrides),
    authenticate: async () => fixtures.authenticate,
    hasPrivileges: async () => fixtures.hasPrivileges,
    getLicense: async () => fixtures.license,
    getXpackInfo: async () => fixtures.xpackInfo,
    getXpackUsage: async () => fixtures.xpackUsage,
    getClusterSettings: async () => fixtures.clusterSettings,
    getNodeSettings: async () => fixtures.nodeSettings,
    listSslCertificates: async () => fixtures.sslCertificates,
    listUsers: async () => fixtures.users,
    listRoles: async () => fixtures.roles,
    listRoleMappings: async () => fixtures.roleMappings,
    listApiKeys: async () => fixtures.apiKeys,
    getIlmStatus: async () => fixtures.ilmStatus,
    listIlmPolicies: async () => fixtures.ilmPolicies,
    getSlmStatus: async () => fixtures.slmStatus,
    listSlmPolicies: async () => fixtures.slmPolicies,
    listSnapshotRepositories: async () => fixtures.snapshotRepositories,
    listWatches: async () => fixtures.watches,
    listIngestPipelines: async () => fixtures.ingestPipelines,
    getKibanaStatus: async () => fixtures.kibanaStatus,
    listSpaces: async () => fixtures.spaces,
    listKibanaRoles: async () => fixtures.kibanaRoles,
    listAgentPolicies: async () => fixtures.agentPolicies,
    listFleetOutputs: async () => fixtures.fleetOutputs,
    listEnrollmentApiKeys: async () => fixtures.enrollmentKeys,
    listFleetServerHosts: async () => fixtures.fleetServerHosts,
    listDetectionRules: async () => fixtures.detectionRules,
    listAlertingRules: async () => fixtures.alertingRules,
    listConnectors: async () => fixtures.connectors,
    listCloudDeployments: async () => fixtures.cloudDeployments,
  };
  return { ...base, ...overrides };
}

function forbidden(message) {
  return async () => {
    throw new ElasticRequestError(message, 403, "elasticsearch");
  };
}

function findingById(result, id) {
  const item = result.findings.find((entry) => entry.id === id);
  assert.ok(item, `expected finding ${id} in ${result.findings.map((entry) => entry.id).join(", ")}`);
  return item;
}

function healthyRoutes(fixtures) {
  return {
    "GET /_security/_authenticate": fixtures.authenticate,
    "POST /_security/user/_has_privileges": fixtures.hasPrivileges,
    "GET /_license": fixtures.license,
    "GET /_xpack": fixtures.xpackInfo,
    "GET /_xpack/usage": fixtures.xpackUsage,
    "GET /_cluster/settings": fixtures.clusterSettings,
    "GET /_nodes/settings": fixtures.nodeSettings,
    "GET /_ssl/certificates": fixtures.sslCertificates,
    "GET /_security/user": fixtures.users,
    "GET /_security/role": fixtures.roles,
    "GET /_security/role_mapping": fixtures.roleMappings,
    "POST /_security/_query/api_key": { total: fixtures.apiKeys.length, count: fixtures.apiKeys.length, api_keys: fixtures.apiKeys },
    "GET /_ilm/status": fixtures.ilmStatus,
    "GET /_ilm/policy": fixtures.ilmPolicies,
    "GET /_slm/status": fixtures.slmStatus,
    "GET /_slm/policy": fixtures.slmPolicies,
    "GET /_snapshot/_all": fixtures.snapshotRepositories,
    "POST /_watcher/_query/watches": { count: fixtures.watches.length, watches: fixtures.watches },
    "GET /_ingest/pipeline": fixtures.ingestPipelines,
    "GET /api/status": fixtures.kibanaStatus,
    "GET /api/spaces/space": fixtures.spaces,
    "GET /api/security/role": fixtures.kibanaRoles,
    "GET /api/fleet/agent_policies": { items: fixtures.agentPolicies, total: fixtures.agentPolicies.length, page: 1, perPage: 100 },
    "GET /api/fleet/outputs": { items: fixtures.fleetOutputs },
    "GET /api/fleet/enrollment_api_keys": { items: fixtures.enrollmentKeys, total: fixtures.enrollmentKeys.length, page: 1, perPage: 100 },
    "GET /api/fleet/fleet_server_hosts": { items: fixtures.fleetServerHosts, total: fixtures.fleetServerHosts.length, page: 1, perPage: 100 },
    "GET /api/detection_engine/rules/_find": { data: fixtures.detectionRules, total: fixtures.detectionRules.length, page: 1, perPage: 100 },
    "GET /api/alerting/rules/_find": { data: fixtures.alertingRules, total: fixtures.alertingRules.length, page: 1, per_page: 100 },
    "GET /api/actions/connectors": fixtures.connectors,
    "GET /api/v1/deployments": { deployments: fixtures.cloudDeployments },
  };
}

function createRouter(routes, seen = []) {
  return async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const method = init.method ?? "GET";
    seen.push({
      method,
      host: url.host,
      pathname: url.pathname,
      search: url.search,
      headers: init.headers,
      body: init.body ? JSON.parse(init.body) : undefined,
    });
    const handler = routes[`${method} ${url.pathname}`];
    if (handler === undefined) {
      return jsonResponse({ error: { type: "resource_not_found_exception", reason: `no route for ${method} ${url.pathname}` } }, { status: 404 });
    }
    const result = typeof handler === "function" ? await handler(url, init) : handler;
    return result instanceof Response ? result : jsonResponse(result);
  };
}

function writeConfigFile(dir, contents) {
  const location = join(dir, "config.yaml");
  writeFileSync(location, contents, "utf8");
  return location;
}

test("resolveElasticConfiguration applies config file, then environment, then explicit arguments", () => {
  const base = createTempBase("elastic-config-");
  const configPath = writeConfigFile(base, [
    "url: https://file.example.com:9200",
    "api_key: ZmlsZS1pZDpmaWxlLWtleQ==",
    "kibana:",
    "  url: https://kibana-file.example.com:5601/",
    "  space_id: file-space",
    "cloud:",
    "  api_key: file-cloud-key",
    "timeout: 45",
    "",
  ].join("\n"));

  const fromFile = resolveElasticConfiguration({ config_file: configPath }, {}, { homeDir: base });
  assert.equal(fromFile.elasticsearchUrl, "https://file.example.com:9200");
  assert.equal(fromFile.kibanaUrl, "https://kibana-file.example.com:5601");
  assert.equal(fromFile.kibanaSpaceId, "file-space");
  assert.equal(fromFile.authMode, "api_key");
  assert.equal(fromFile.apiKey, "ZmlsZS1pZDpmaWxlLWtleQ==");
  assert.equal(fromFile.cloudApiKey, "file-cloud-key");
  assert.equal(fromFile.timeoutMs, 45000);
  assert.deepEqual(fromFile.sourceChain, [`config:${configPath}`]);

  const withEnv = resolveElasticConfiguration(
    { config_file: configPath },
    { ELASTIC_URL: "https://env.example.com:9200", ELASTIC_USERNAME: "env-user", ELASTIC_PASSWORD: "env-pass" },
    { homeDir: base },
  );
  assert.equal(withEnv.elasticsearchUrl, "https://env.example.com:9200");
  assert.equal(withEnv.authMode, "basic", "environment credentials replace lower-precedence file credentials");
  assert.equal(withEnv.username, "env-user");
  assert.equal(withEnv.apiKey, undefined);
  assert.equal(withEnv.kibanaUrl, "https://kibana-file.example.com:5601");
  assert.deepEqual(withEnv.sourceChain, [`config:${configPath}`, "environment"]);

  const withArgs = resolveElasticConfiguration(
    { config_file: configPath, elasticsearch_url: "https://args.example.com:9200/", api_key: "arg-id:arg-secret", space_id: "default", timeout_seconds: 9 },
    { ELASTIC_URL: "https://env.example.com:9200", ELASTIC_USERNAME: "env-user", ELASTIC_PASSWORD: "env-pass", KIBANA_URL: "https://kibana-env.example.com" },
    { homeDir: base },
  );
  assert.equal(withArgs.elasticsearchUrl, "https://args.example.com:9200");
  assert.equal(withArgs.kibanaUrl, "https://kibana-env.example.com");
  assert.equal(withArgs.kibanaSpaceId, undefined, "the default space is represented as no space prefix");
  assert.equal(withArgs.authMode, "api_key");
  assert.equal(withArgs.apiKey, Buffer.from("arg-id:arg-secret").toString("base64"));
  assert.equal(withArgs.timeoutMs, 9000);
  assert.deepEqual(withArgs.sourceChain, [`config:${configPath}`, "environment", "arguments"]);
});

test("resolveElasticConfiguration reads the default config file, ELASTIC_SEC_INSPECTOR_CONFIG, and every auth mode", () => {
  const home = createTempBase("elastic-home-");
  mkdirSync(join(home, ".elastic-sec-inspector"), { recursive: true });
  writeFileSync(join(home, ".elastic-sec-inspector", "config.yaml"), [
    "elasticsearch:",
    "  url: https://home.example.com:9200",
    "  username: home-user",
    "  password: home-pass",
    "",
  ].join("\n"));
  const fromHome = resolveElasticConfiguration({}, {}, { homeDir: home });
  assert.equal(fromHome.elasticsearchUrl, "https://home.example.com:9200");
  assert.equal(fromHome.authMode, "basic");
  assert.deepEqual(fromHome.sourceChain, ["config:~/.elastic-sec-inspector/config.yaml"]);

  const alternate = createTempBase("elastic-alt-");
  const alternatePath = writeConfigFile(alternate, "url: https://alt.example.com:9200\nbearer_token: alt-bearer\n");
  const fromEnvPath = resolveElasticConfiguration({}, { ELASTIC_SEC_INSPECTOR_CONFIG: alternatePath }, { homeDir: home });
  assert.equal(fromEnvPath.elasticsearchUrl, "https://alt.example.com:9200");
  assert.equal(fromEnvPath.authMode, "bearer");
  assert.equal(fromEnvPath.bearerToken, "alt-bearer");

  const bearer = resolveElasticConfiguration({}, { ELASTICSEARCH_URL: "https://env.example.com:9200", ELASTIC_BEARER_TOKEN: "env-bearer" }, { homeDir: alternate });
  assert.equal(bearer.authMode, "bearer");
  assert.deepEqual(bearer.sourceChain, ["environment"]);

  const cloud = resolveElasticConfiguration(
    {},
    { ELASTIC_URL: "https://env.example.com:9200", ELASTIC_API_KEY: API_KEY, ELASTIC_CLOUD_API_KEY: "cloud-key", ELASTIC_CLOUD_API_URL: "https://cloud.example.com/", KIBANA_SPACE_ID: "audit" },
    { homeDir: alternate },
  );
  assert.equal(cloud.cloudApiKey, "cloud-key");
  assert.equal(cloud.cloudApiUrl, "https://cloud.example.com");
  assert.equal(cloud.kibanaSpaceId, "audit");
  assert.equal(cloud.maxRetries, 3);
});

test("resolveElasticConfiguration rejects missing URL or credentials", () => {
  const home = createTempBase("elastic-empty-home-");
  assert.throws(() => resolveElasticConfiguration({}, {}, { homeDir: home }), /Elasticsearch URL is required/);
  assert.throws(
    () => resolveElasticConfiguration({ elasticsearch_url: "https://es.example.com" }, {}, { homeDir: home }),
    /credentials are required/,
  );
  assert.throws(
    () => resolveElasticConfiguration({ elasticsearch_url: "https://es.example.com", username: "only-user" }, {}, { homeDir: home }),
    /credentials are required/,
  );
});

const CONFIG_FILE_CANARY = "RKnRPLu6AhK3iGHdJCCo4EAup4Gw9IDW";

/** Malformed YAML shapes; the yaml package quotes the offending source line in its own message for most of them. */
const MALFORMED_YAML_CONFIGS = [
  { name: "unterminated quote", line: 4, content: `url: https://es.example.com:9200\nkibana_url: https://kibana.example.com:5601\napi_key: "${CONFIG_FILE_CANARY}\n` },
  { name: "bad indent", line: 3, content: `elasticsearch:\n  url: https://es.example.com:9200\n api_key: ${CONFIG_FILE_CANARY}\n` },
  { name: "duplicate key", line: 3, content: `url: https://es.example.com:9200\napi_key: first-key\napi_key: ${CONFIG_FILE_CANARY}\n` },
  { name: "trailing comma", line: 1, content: `elasticsearch: { url: https://es.example.com:9200, api_key: ${CONFIG_FILE_CANARY},, }\n` },
  { name: "tab indentation", line: 2, content: `url: https://es.example.com:9200\n\tapi_key: ${CONFIG_FILE_CANARY}\n` },
];

test("rule 9 / addendum 6: a malformed config file whose bad line carries a credential yields fixed text naming only the path and the parser's line, from the resolver and from every tool", async () => {
  const registered = [];
  registerElasticTools({ registerTool: (tool) => registered.push(tool) });
  const checkTool = registered.find((tool) => tool.name === "elastic_check_access");
  const exportTool = registered.find((tool) => tool.name === "elastic_export_audit_bundle");
  const originalFetch = globalThis.fetch;
  globalThis.fetch = () => { throw new Error("no request may be made while the config file is unreadable"); };
  try {
    for (const shape of MALFORMED_YAML_CONFIGS) {
      const base = createTempBase("elastic-malformed-config-");
      const configPath = join(base, "config.yaml");
      writeFileSync(configPath, shape.content, "utf8");
      const outputDir = join(base, "export");
      const expected = `Unable to parse Elastic config file: invalid YAML in ${configPath} at line ${shape.line}`;

      let thrown;
      try {
        resolveElasticConfiguration({ config_file: configPath }, {}, { homeDir: base });
      } catch (error) {
        thrown = error;
      }
      assert.ok(thrown, `${shape.name}: the resolver must reject the file`);
      assert.equal(thrown.name, "ElasticConfigFileError", shape.name);
      assert.equal(thrown.code, "INVALID_YAML", shape.name);
      assert.equal(thrown.line, shape.line, `${shape.name}: the parser's structured line position is carried`);
      assert.equal(thrown.path, configPath, shape.name);
      assert.equal(thrown.message, expected, `${shape.name}: fixed text only`);
      assertCanaryWindowsAbsent(assert, thrown.message, [CONFIG_FILE_CANARY], `${shape.name} resolver message`);
      assert.ok(!thrown.message.includes("api_key") && !thrown.message.includes("first-key"), `${shape.name}: no key name or value from the file: ${thrown.message}`);

      const access = await checkTool.execute("call-config", checkTool.prepareArguments({ config_file: configPath }));
      assert.equal(access.isError, true, shape.name);
      assertCanaryWindowsAbsent(assert, JSON.stringify(access), [CONFIG_FILE_CANARY], `${shape.name} check_access payload`);
      assert.equal(access.content[0].text, `Elastic access check failed: ${expected}`, shape.name);

      const exported = await exportTool.execute("call-config-export", exportTool.prepareArguments({ config_file: configPath, output_dir: outputDir }));
      assert.equal(exported.isError, true, shape.name);
      assertCanaryWindowsAbsent(assert, JSON.stringify(exported), [CONFIG_FILE_CANARY], `${shape.name} export payload`);
      assert.equal(exported.content[0].text, `Elastic audit bundle export failed: ${expected}`, shape.name);
      assert.equal(existsSync(outputDir), false, `${shape.name}: nothing is written when the config file is unreadable`);
    }

    // A file that parses to a scalar carrying the credential is ignored, not echoed.
    const scalarBase = createTempBase("elastic-config-scalar-");
    writeFileSync(join(scalarBase, "config.yaml"), `${CONFIG_FILE_CANARY}\n`, "utf8");
    let scalarError;
    try {
      resolveElasticConfiguration({ config_file: join(scalarBase, "config.yaml") }, {}, { homeDir: scalarBase });
    } catch (error) {
      scalarError = error;
    }
    assert.match(scalarError.message, /Elasticsearch URL is required/);
    assertCanaryWindowsAbsent(assert, scalarError.message, [CONFIG_FILE_CANARY], "scalar-valued config file");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

// ---------------------------------------------------------------------------------------------------------------
// Addendum 6b: config loader errors are fixed text carrying only the path, a validated code, and a line.
// ---------------------------------------------------------------------------------------------------------------

// Alphanumeric and random-looking so that every 6-to-24-character window can be asserted absent (helpers/canary-windows.mjs).
const ELASTIC_CONFIG_CANARIES = {
  nestedKey: "h7nLwCmVUWbZdsum53HeFFT3vpneLNMZ",
  nestedValue: "aJJarKiYeinNFRWUyCByEx3DbWg8qCDw",
  alias: "BnfQbGSUVRi9bLDovUZBoStTChiFLaH5",
  unreadable: "dGsYY9jcfAHYM5mTc4LeUL3H4ycW5WRZ",
};
const ES_PARSER_SNIPPET_CANARY = "eJSJDuDHDVYbBbBu2pt8VPomHyvFAuTz";

const LIBRARY_WORDING = ["Nested mappings", "is not valid JSON", "Unresolved alias", "illegal operation", "permission denied", "no such file"];

/** Asserts a message carries neither any window of a canary nor the parser's or filesystem's own wording. */
function assertFixedTextOnly(message, canaries, label) {
  assertCanaryWindowsAbsent(assert, message, canaries, label);
  for (const wording of LIBRARY_WORDING) assert.ok(!message.includes(wording), `${label}: carries library wording "${wording}": ${message}`);
}

test("config loader errors: an Elastic config file that cannot be read or parsed yields fixed text with only the path, a validated code, and the parser's line, from the resolver and from check_access", async () => {
  const registered = [];
  registerElasticTools({ registerTool: (tool) => registered.push(tool) });
  const checkTool = registered.find((tool) => tool.name === "elastic_check_access");
  const exportTool = registered.find((tool) => tool.name === "elastic_export_audit_bundle");
  const canaries = Object.values(ELASTIC_CONFIG_CANARIES);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = () => { throw new Error("no request may be made while the config file is unreadable"); };
  try {
    const base = createTempBase("elastic-config-errors-");
    const cases = [];

    // YAML nested mapping: the parser quotes the whole source line, key, value, and bearer token included.
    const nested = join(base, "nested.yaml");
    writeFileSync(nested, `api_key: ${ELASTIC_CONFIG_CANARIES.nestedKey}: Bearer ${ELASTIC_CONFIG_CANARIES.nestedValue}\n`, "utf8");
    assert.throws(() => parseYaml(readFileSync(nested, "utf8")), (error) => error.message.includes(ELASTIC_CONFIG_CANARIES.nestedKey) && error.message.includes("Nested mappings"), "positive control: yaml.parse quotes the line");
    cases.push({ name: "yaml nested mapping", path: nested, code: "INVALID_YAML", line: 1, message: `Unable to parse Elastic config file: invalid YAML in ${nested} at line 1` });

    // YAML alias: a plain ReferenceError (no linePos) whose message leads with the value and no key name.
    const alias = join(base, "alias.yaml");
    writeFileSync(alias, `api_key: *${ELASTIC_CONFIG_CANARIES.alias}\n`, "utf8");
    assert.throws(() => parseYaml(readFileSync(alias, "utf8")), (error) => error instanceof ReferenceError && error.message.includes(ELASTIC_CONFIG_CANARIES.alias) && error.message.includes("Unresolved alias"), "positive control: yaml.parse throws a ReferenceError carrying the value");
    cases.push({ name: "yaml alias", path: alias, code: "INVALID_YAML", line: undefined, message: `Unable to parse Elastic config file: invalid YAML in ${alias}` });

    // EISDIR: a directory at the path is a read failure, not a parse failure.
    const directory = join(base, "config-dir");
    mkdirSync(directory);
    assert.throws(() => readFileSync(directory, "utf8"), (error) => error.code === "EISDIR" && /illegal operation/.test(error.message), "positive control: the filesystem message carries its own wording");
    cases.push({ name: "EISDIR", path: directory, code: "EISDIR", line: undefined, message: `Unable to read Elastic config file ${directory} (EISDIR)` });

    // EACCES: an unreadable file (root reads everything, so the case is skipped when running as root).
    if (typeof process.getuid === "function" && process.getuid() !== 0) {
      const unreadable = join(base, "unreadable.yaml");
      writeFileSync(unreadable, `api_key: ${ELASTIC_CONFIG_CANARIES.unreadable}\n`, "utf8");
      chmodSync(unreadable, 0o000);
      assert.throws(() => readFileSync(unreadable, "utf8"), (error) => error.code === "EACCES" && /permission denied/.test(error.message), "positive control");
      cases.push({ name: "EACCES", path: unreadable, code: "EACCES", line: undefined, message: `Unable to read Elastic config file ${unreadable} (EACCES)` });
    }

    // ENOENT on an explicit path: a missing file named by argument or environment is an error, not a silent default.
    const missing = join(base, "missing.yaml");
    cases.push({ name: "ENOENT", path: missing, code: "ENOENT", line: undefined, message: `Unable to read Elastic config file ${missing} (ENOENT)` });

    for (const item of cases) {
      let thrown;
      try {
        resolveElasticConfiguration({ config_file: item.path }, {}, { homeDir: base, cwd: base });
      } catch (error) {
        thrown = error;
      }
      assert.ok(thrown, `${item.name}: the resolver must reject the file`);
      assert.equal(thrown.name, "ElasticConfigFileError", item.name);
      assert.equal(thrown.message, item.message, `${item.name}: fixed text only`);
      assert.equal(thrown.code, item.code, item.name);
      assert.equal(thrown.line, item.line, item.name);
      assert.equal(thrown.path, item.path, item.name);
      assertFixedTextOnly(thrown.message, canaries, `${item.name} resolver`);

      const access = await checkTool.execute("call-config", checkTool.prepareArguments({ config_file: item.path }));
      assert.equal(access.isError, true, item.name);
      assert.equal(access.content[0].text, `Elastic access check failed: ${item.message}`, item.name);
      assertFixedTextOnly(JSON.stringify(access), canaries, `${item.name} check_access`);

      const outputDir = join(base, `export-${item.code}`);
      const exported = await exportTool.execute("call-config-export", exportTool.prepareArguments({ config_file: item.path, output_dir: outputDir }));
      assert.equal(exported.isError, true, item.name);
      assert.equal(exported.content[0].text, `Elastic audit bundle export failed: ${item.message}`, item.name);
      assert.equal(existsSync(outputDir), false, `${item.name}: nothing is written when the config file is unreadable`);
    }

    // The environment variable is an explicit path too, and a missing default file is still simply absent.
    assert.throws(
      () => resolveElasticConfiguration({ elasticsearch_url: "https://es.example.com:9200", api_key: API_KEY }, { ELASTIC_SEC_INSPECTOR_CONFIG: missing }, { homeDir: base, cwd: base }),
      { message: `Unable to read Elastic config file ${missing} (ENOENT)` },
    );
    assert.equal(resolveElasticConfiguration({ elasticsearch_url: "https://es.example.com:9200", api_key: API_KEY }, {}, { homeDir: base, cwd: base }).apiKey, API_KEY);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("config loader errors: a SyntaxError raised by the transport is recorded by name only, never by the parser's message that quotes the body", async () => {
  const snippet = `<html>${ES_PARSER_SNIPPET_CANARY}</html>`;
  const config = sampleConfig({ maxRetries: 0 });
  const client = new ElasticApiClient(config, {
    fetchImpl: async () => { throw new SyntaxError(`Unexpected token '<', "${snippet}"... is not valid JSON`); },
    sleepImpl: async () => {},
  });
  await assert.rejects(() => client.listUsers(), (error) => {
    assert.equal(error.message, "elasticsearch request GET /_security/user failed: SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body");
    return true;
  });
  const access = await checkElasticAccess(client);
  assertCanaryWindowsAbsent(assert, JSON.stringify(access), [ES_PARSER_SNIPPET_CANARY], "check_access");
  assert.ok(access.surfaces.every((surface) => surface.status !== "readable"), "no surface reads through a transport that cannot be parsed");
  const snapshot = await collectElasticSnapshot(client, ELASTIC_ALL_DATASETS, {});
  const assessments = ALL_AREAS.map((area) => evaluateElasticArea(area, snapshot, {}, { elasticsearchUrl: config.elasticsearchUrl }));
  const errors = assessments.flatMap((assessment) => assessment.errors ?? []);
  assert.ok(errors.length > 0 && errors.every((text) => text.includes("SyntaxError: response could not be parsed as JSON")), errors.join("\n"));
  assertCanaryWindowsAbsent(assert, JSON.stringify(assessments), [ES_PARSER_SNIPPET_CANARY], "assess payload");
});

test("normalizeElasticApiKey encodes id:key pairs and preserves base64 values", () => {
  assert.equal(normalizeElasticApiKey("abc:def"), Buffer.from("abc:def").toString("base64"));
  assert.equal(normalizeElasticApiKey(API_KEY), API_KEY);
  assert.equal(normalizeElasticApiKey("opaque-value"), "opaque-value");
});

test("redaction removes credentials from errors and secret values from snapshots", () => {
  const config = sampleConfig({ authMode: "basic", apiKey: undefined, username: "audit", password: "sup3r-secret" });
  const basic = Buffer.from("audit:sup3r-secret").toString("base64");
  const redacted = redactSecrets(`Authorization: Basic ${basic} failed with password=sup3r-secret and api_key: abc123`, config);
  assert.ok(!redacted.includes(basic));
  assert.ok(!redacted.includes("sup3r-secret"));
  assert.ok(!redacted.includes("abc123"));
  assert.match(redacted, /\[REDACTED\]/);

  const snapshot = redactSensitiveValues({
    "xpack.security.authc.token.enabled": "true",
    "xpack.security.authc.password_hashing.algorithm": "bcrypt",
    "xpack.security.authc.realms.ldap.ldap1.bind_password": "hunter2",
    "xpack.security.authc.realms.oidc.op.rp.client_secret": "oidc-secret",
    nested: { api_key: "k", password: 42, authorization: "Basic x", secure_key: "s", is_missing_secrets: "false", ssl: { key: "certs/node.key", enabled: true } },
    list: [{ token: "t", name: "keep" }],
  });
  assert.equal(snapshot["xpack.security.authc.token.enabled"], "true");
  assert.equal(snapshot["xpack.security.authc.password_hashing.algorithm"], "bcrypt");
  assert.equal(snapshot["xpack.security.authc.realms.ldap.ldap1.bind_password"], "[REDACTED]");
  assert.equal(snapshot["xpack.security.authc.realms.oidc.op.rp.client_secret"], "[REDACTED]");
  assert.equal(snapshot.nested.is_missing_secrets, "false");
  assert.equal(snapshot.nested.api_key, "[REDACTED]");
  assert.equal(snapshot.nested.password, "[REDACTED]");
  assert.equal(snapshot.nested.authorization, "[REDACTED]");
  assert.equal(snapshot.nested.secure_key, "[REDACTED]");
  assert.equal(snapshot.nested.ssl.key, "[REDACTED]");
  assert.equal(snapshot.nested.ssl.enabled, true);
  assert.equal(snapshot.list[0].token, "[REDACTED]");
  assert.equal(snapshot.list[0].name, "keep");
});

test("ElasticApiClient sends ApiKey, Basic, Bearer, and Elastic Cloud authorization headers", async () => {
  const seen = [];
  const fetchImpl = createRouter({
    "GET /_security/_authenticate": { username: "audit" },
    "GET /api/v1/deployments": { deployments: [] },
  }, seen);

  await new ElasticApiClient(sampleConfig(), { fetchImpl }).authenticate();
  await new ElasticApiClient(sampleConfig({ authMode: "basic", apiKey: undefined, username: "audit", password: "pw" }), { fetchImpl }).authenticate();
  await new ElasticApiClient(sampleConfig({ authMode: "bearer", apiKey: undefined, bearerToken: "bearer-token" }), { fetchImpl }).authenticate();
  await new ElasticApiClient(sampleConfig({ cloudApiKey: "cloud-key" }), { fetchImpl }).listCloudDeployments();

  assert.equal(seen[0].host, "es.example.com:9200");
  assert.equal(seen[0].pathname, "/_security/_authenticate");
  assert.equal(headerValue(seen[0].headers, "authorization"), `ApiKey ${API_KEY}`);
  assert.equal(headerValue(seen[0].headers, "kbn-xsrf"), undefined);
  assert.equal(headerValue(seen[0].headers, "accept"), "application/json");
  assert.equal(headerValue(seen[1].headers, "authorization"), `Basic ${Buffer.from("audit:pw").toString("base64")}`);
  assert.equal(headerValue(seen[2].headers, "authorization"), "Bearer bearer-token");
  assert.equal(seen[3].host, "api.elastic-cloud.com");
  assert.equal(headerValue(seen[3].headers, "authorization"), "ApiKey cloud-key");
});

test("ElasticApiClient adds kbn-xsrf and space-aware paths for Kibana requests", async () => {
  const seen = [];
  const fetchImpl = createRouter({
    "GET /s/audit-space/api/spaces/space": [{ id: "audit-space" }],
    "GET /api/spaces/space": [{ id: "default" }],
    "GET /api/status": { name: "kibana", uuid: "kb-1", version: { number: "8.15.0" }, status: { overall: { level: "available" } } },
  }, seen);

  const spaced = new ElasticApiClient(sampleConfig({ kibanaSpaceId: "audit-space" }), { fetchImpl });
  const spaces = await spaced.listSpaces();
  assert.deepEqual(spaces.map((space) => space.id), ["audit-space"]);
  assert.equal(seen[0].host, "kibana.example.com:5601");
  assert.equal(seen[0].pathname, "/s/audit-space/api/spaces/space");
  assert.equal(headerValue(seen[0].headers, "kbn-xsrf"), "true");
  assert.equal(headerValue(seen[0].headers, "authorization"), `ApiKey ${API_KEY}`);

  const plain = new ElasticApiClient(sampleConfig(), { fetchImpl });
  await plain.getKibanaStatus();
  assert.equal(seen[1].pathname, "/api/status");

  const withoutKibana = new ElasticApiClient(sampleConfig({ kibanaUrl: undefined }), { fetchImpl });
  await assert.rejects(() => withoutKibana.listSpaces(), /KIBANA_URL is not configured/);
  assert.equal(withoutKibana.hasKibana(), false);
});

test("foreign-origin next link: a URL-shaped Elastic search_after value travels only inside the request body to the configured origin, so no request leaves for the origin it names", async () => {
  const FOREIGN = "https://collector.attacker.example/_security/_query/api_key";
  const seen = [];
  const fetchImpl = createRouter({
    "POST /_security/_query/api_key": (_url, init) => {
      const body = JSON.parse(init.body);
      return body.search_after
        ? { total: 3, count: 1, api_keys: [{ id: "k3", _sort: [3, "k3"] }] }
        : { total: 3, count: 2, api_keys: [{ id: "k1", _sort: [1, "k1"] }, { id: "k2", _sort: [FOREIGN, "k2"] }] };
    },
  }, seen);
  const client = new ElasticApiClient(sampleConfig(), { fetchImpl });

  const keys = await client.listApiKeys(10, 2);

  assert.deepEqual(keys.items.map((key) => key.id), ["k1", "k2", "k3"], "paging continued through the planted cursor");
  assert.equal(seen.length, 2);
  assert.ok(seen.every((request) => request.host === "es.example.com:9200" && request.pathname === "/_security/_query/api_key"), "every request, including the one that carried the planted cursor, went to the configured Elasticsearch origin");
  assert.deepEqual(seen[1].body.search_after, [FOREIGN, "k2"], "the cursor travels only as a value inside the POST body");
});

test("ElasticApiClient paginates API keys with search_after, Watcher with from/size, and Kibana with page parameters", async () => {
  const apiKeys = Array.from({ length: 150 }, (_, index) => ({ id: `k${index + 1}`, _sort: [index + 1, `k${index + 1}`] }));
  const watches = Array.from({ length: 150 }, (_, index) => ({ _id: `w${index + 1}` }));
  const rules = Array.from({ length: 150 }, (_, index) => ({ id: `r${index + 1}` }));
  const pageOf = (items, page, perPage) => items.slice((page - 1) * perPage, page * perPage);
  const seen = [];
  const fetchImpl = createRouter({
    "POST /_security/_query/api_key": (_url, init) => {
      const body = JSON.parse(init.body);
      const start = body.search_after ? apiKeys.findIndex((key) => key._sort[0] === body.search_after[0]) + 1 : 0;
      const page = apiKeys.slice(start, start + body.size);
      return { total: apiKeys.length, count: page.length, api_keys: page };
    },
    "POST /_watcher/_query/watches": (_url, init) => {
      const body = JSON.parse(init.body);
      return { count: watches.length, watches: watches.slice(body.from, body.from + body.size) };
    },
    "GET /api/detection_engine/rules/_find": (url) => {
      const page = Number(url.searchParams.get("page"));
      const perPage = Number(url.searchParams.get("per_page"));
      return { page, perPage, total: rules.length, data: pageOf(rules, page, perPage) };
    },
    "GET /api/alerting/rules/_find": (url) => {
      const page = Number(url.searchParams.get("page"));
      const perPage = Number(url.searchParams.get("per_page"));
      return { page, per_page: perPage, total: rules.length, data: pageOf(rules, page, perPage) };
    },
    "GET /api/fleet/agent_policies": (url) => {
      const page = Number(url.searchParams.get("page"));
      const perPage = Number(url.searchParams.get("perPage"));
      return { items: pageOf(rules, page, perPage), total: rules.length, page, perPage };
    },
    "GET /api/fleet/enrollment_api_keys": { items: [{ id: "e1", api_key: "enrollment-secret", active: true }], total: 1, page: 1, perPage: 100 },
  }, seen);
  const client = new ElasticApiClient(sampleConfig(), { fetchImpl });

  const limitedKeys = await client.listApiKeys(2);
  assert.deepEqual(limitedKeys.items.map((key) => key.id), ["k1", "k2"], "limit caps the number of API keys returned");
  assert.deepEqual({ seen: limitedKeys.seen, total: limitedKeys.total, truncated: limitedKeys.truncated, pages: limitedKeys.pages }, { seen: 2, total: 150, truncated: true, pages: 1 });
  assert.equal(seen[0].search, "?with_limited_by=true");
  assert.equal(seen[0].body.size, 2);
  assert.deepEqual(seen[0].body.sort, [{ creation: { order: "asc" } }, { name: { order: "asc" } }]);
  assert.equal(seen.length, 1);

  const allKeys = await client.listApiKeys(200);
  assert.equal(allKeys.items.length, 150);
  assert.equal(allKeys.items[149].id, "k150");
  assert.deepEqual({ seen: allKeys.seen, total: allKeys.total, truncated: allKeys.truncated, pages: allKeys.pages }, { seen: 150, total: 150, truncated: false, pages: 2 });
  assert.equal(seen.length, 3);
  assert.equal(seen[1].body.search_after, undefined);
  assert.deepEqual(seen[2].body.search_after, [100, "k100"]);

  const allWatches = await client.listWatches(500);
  assert.equal(allWatches.items.length, 150);
  assert.equal(allWatches.truncated, false);
  assert.deepEqual(seen.slice(3).map((entry) => entry.body.from), [0, 100]);

  const limitedRules = await client.listDetectionRules(2);
  assert.deepEqual(limitedRules.items.map((rule) => rule.id), ["r1", "r2"]);
  assert.equal(limitedRules.truncated, true);
  assert.equal(seen[5].search, "?page=1&per_page=2");

  const allRules = await client.listDetectionRules(1000);
  assert.equal(allRules.items.length, 150);
  assert.equal(allRules.truncated, false);
  assert.deepEqual(seen.slice(6).map((entry) => entry.search), ["?page=1&per_page=100", "?page=2&per_page=100"]);

  const alertingRules = await client.listAlertingRules(120);
  assert.equal(alertingRules.items.length, 120);
  assert.deepEqual({ seen: alertingRules.seen, total: alertingRules.total, truncated: alertingRules.truncated }, { seen: 120, total: 150, truncated: true });
  assert.deepEqual(seen.slice(8).map((entry) => entry.search), ["?page=1&per_page=100", "?page=2&per_page=100"]);

  const policies = await client.listAgentPolicies(150);
  assert.equal(policies.items.length, 150);
  assert.equal(policies.truncated, false);
  assert.deepEqual(seen.slice(10).map((entry) => entry.search), ["?page=1&perPage=100", "?page=2&perPage=100"]);

  const enrollment = await client.listEnrollmentApiKeys(10);
  assert.equal(enrollment.items[0].api_key, "[REDACTED]");
  assert.equal(seen[12].search, "?page=1&perPage=10");
});

test("verdict rule 7: pagination runs to completion and a missing total still records truncation when the cap is hit", async () => {
  const watches = Array.from({ length: 230 }, (_, index) => ({ _id: `w${index + 1}` }));
  const fetchImpl = createRouter({
    "POST /_watcher/_query/watches": (_url, init) => {
      const body = JSON.parse(init.body);
      return { watches: watches.slice(body.from, body.from + body.size) };
    },
    "GET /api/fleet/agent_policies": (url) => {
      const page = Number(url.searchParams.get("page"));
      const perPage = Number(url.searchParams.get("perPage"));
      const items = Array.from({ length: 250 }, (_, index) => ({ id: `p${index + 1}` }));
      return { items: items.slice((page - 1) * perPage, page * perPage), page, perPage };
    },
  });
  const client = new ElasticApiClient(sampleConfig(), { fetchImpl });

  const complete = await client.listWatches(500);
  assert.deepEqual({ seen: complete.seen, pages: complete.pages, truncated: complete.truncated, total: complete.total }, { seen: 230, pages: 3, truncated: false, total: undefined });

  const capped = await client.listWatches(200);
  assert.deepEqual({ seen: capped.seen, pages: capped.pages, truncated: capped.truncated }, { seen: 200, pages: 2, truncated: true });

  const policies = await client.listAgentPolicies(100);
  assert.deepEqual({ seen: policies.seen, pages: policies.pages, truncated: policies.truncated }, { seen: 100, pages: 1, truncated: true });

  const snapshot = await collectElasticSnapshot(client, ["watches"], { watchLimit: 200 });
  assert.deepEqual(snapshot.watches.page, { seen: 200, total: undefined, truncated: true, pages: 2 });
  assert.equal(snapshot.watches.data.length, 200);
});

test("ElasticApiClient retries 429 and 5xx responses with backoff and honors Retry-After", async () => {
  let attempts = 0;
  const sleeps = [];
  const fetchImpl = async () => {
    attempts += 1;
    if (attempts === 1) return jsonResponse({ error: { type: "too_many_requests" } }, { status: 429, headers: { "retry-after": "2" } });
    if (attempts === 2) return jsonResponse({ error: { type: "unavailable" } }, { status: 503 });
    return jsonResponse({ license: { type: "basic" } });
  };
  const client = new ElasticApiClient(sampleConfig(), { fetchImpl, sleepImpl: async (ms) => { sleeps.push(ms); } });

  const license = await client.getLicense();
  assert.equal(license.license.type, "basic");
  assert.equal(attempts, 3);
  assert.deepEqual(sleeps, [2000, 500]);
});

test("ElasticApiClient stops retrying after maxRetries and surfaces the last status", async () => {
  let attempts = 0;
  const fetchImpl = async () => {
    attempts += 1;
    return jsonResponse({ error: { type: "unavailable", reason: "shard down" } }, { status: 503, statusText: "Service Unavailable" });
  };
  const client = new ElasticApiClient(sampleConfig({ maxRetries: 2 }), { fetchImpl, sleepImpl: async () => {} });

  await assert.rejects(() => client.getLicense(), (error) => {
    assert.ok(error instanceof ElasticRequestError);
    assert.equal(error.status, 503);
    assert.match(error.message, /GET \/_license failed \(503 Service Unavailable\): shard down: unavailable/);
    return true;
  });
  assert.equal(attempts, 3);
});

test("ElasticApiClient does not retry 4xx errors and redacts secrets in error messages", async () => {
  let attempts = 0;
  const fetchImpl = async () => {
    attempts += 1;
    return jsonResponse(
      { error: { type: "security_exception", reason: `unable to authenticate with ApiKey ${API_KEY}` } },
      { status: 401, statusText: "Unauthorized" },
    );
  };
  const client = new ElasticApiClient(sampleConfig(), { fetchImpl, sleepImpl: async () => {} });

  await assert.rejects(() => client.listRoles(), (error) => {
    assert.ok(error instanceof ElasticRequestError);
    assert.equal(error.status, 401);
    assert.equal(error.target, "elasticsearch");
    assert.ok(!error.message.includes(API_KEY), "API key must not leak into the error");
    assert.match(error.message, /\[REDACTED\]/);
    return true;
  });
  assert.equal(attempts, 1);
});

test("ElasticApiClient retries transient network failures and aborts on timeout", async () => {
  let attempts = 0;
  const fetchImpl = async () => {
    attempts += 1;
    if (attempts === 1) throw new TypeError("fetch failed");
    return jsonResponse({ username: "audit" });
  };
  const client = new ElasticApiClient(sampleConfig(), { fetchImpl, sleepImpl: async () => {} });
  assert.deepEqual(await client.authenticate(), { username: "audit" });
  assert.equal(attempts, 2);

  const hanging = (_input, init) => new Promise((_resolve, reject) => {
    init.signal.addEventListener("abort", () => {
      const error = new Error("This operation was aborted");
      error.name = "AbortError";
      reject(error);
    });
  });
  const slow = new ElasticApiClient(sampleConfig({ timeoutMs: 20 }), { fetchImpl: hanging, sleepImpl: async () => {} });
  await assert.rejects(() => slow.authenticate(), /timed out after 20ms/);
});

test("checkElasticAccess reports healthy when every surface is readable and privileges are granted", async () => {
  const fixtures = healthyFixtures();
  const seen = [];
  const client = new ElasticApiClient(sampleConfig({ cloudApiKey: "cloud-key" }), { fetchImpl: createRouter(healthyRoutes(fixtures), seen) });

  const result = await checkElasticAccess(client);

  assert.equal(result.status, "healthy");
  assert.equal(result.authenticatedAs, "grc-auditor");
  assert.equal(result.authenticationRealm, "native");
  assert.equal(result.cloudConfigured, true);
  assert.deepEqual(result.missingClusterPrivileges, []);
  assert.deepEqual(result.missingIndexPrivileges, []);
  assert.ok(result.surfaces.every((surface) => surface.status === "readable"), JSON.stringify(result.surfaces.filter((surface) => surface.status !== "readable")));
  assert.equal(result.surfaces.find((surface) => surface.name === "roles").count, 3);
  assert.equal(result.surfaces.find((surface) => surface.name === "node_settings").count, 1);
  assert.equal(result.surfaces.find((surface) => surface.name === "kibana_spaces").count, 2);
  assert.match(result.recommendedNextStep, /elastic_assess_identity/);
  const privilegeProbe = seen.find((entry) => entry.pathname === "/_security/user/_has_privileges");
  assert.ok(privilegeProbe);
  assert.ok(privilegeProbe.body.cluster.includes("read_security"));
  assert.ok(privilegeProbe.body.cluster.includes("monitor_watcher"));
});

test("checkElasticAccess reports limited access with missing privileges and unconfigured surfaces", async () => {
  const fixtures = healthyFixtures();
  fixtures.hasPrivileges = {
    ...fixtures.hasPrivileges,
    cluster: { ...fixtures.hasPrivileges.cluster, monitor_watcher: false, read_ilm: false, manage_ilm: false },
    index: { ".security*": { read: false } },
  };
  const client = stubClient(fixtures, {
    listSslCertificates: forbidden("elasticsearch request GET /_ssl/certificates failed (403 Forbidden): unauthorized for user [grc-auditor]"),
    listWatches: forbidden("elasticsearch request POST /_watcher/_query/watches failed (403 Forbidden)"),
  }, { kibanaUrl: undefined });

  const result = await checkElasticAccess(client);

  assert.equal(result.status, "limited");
  assert.deepEqual(result.missingClusterPrivileges, ["read_ilm (or manage_ilm)", "monitor_watcher"]);
  assert.deepEqual(result.missingIndexPrivileges, [".security*:read"]);
  assert.equal(result.surfaces.find((surface) => surface.name === "ssl_certificates").status, "not_readable");
  assert.match(result.surfaces.find((surface) => surface.name === "ssl_certificates").error, /403/);
  assert.equal(result.surfaces.find((surface) => surface.name === "kibana_spaces").status, "not_configured");
  assert.equal(result.surfaces.find((surface) => surface.name === "cloud_deployments").status, "not_configured");
  assert.ok(result.notes.some((note) => note.includes("Missing cluster privileges")));
  assert.ok(result.notes.some((note) => note.includes("Kibana is not configured")));
  assert.match(result.recommendedNextStep, /Grant the auditing principal/);
});

test("collectElasticSnapshot redacts secrets in payloads and records per-dataset errors", async () => {
  const fixtures = healthyFixtures();
  fixtures.nodeSettings.nodes["node-1"].settings["xpack.security.authc.realms.ldap.ldap1.bind_password"] = "ldap-secret";
  const client = stubClient(fixtures, { listRoles: forbidden("elasticsearch request GET /_security/role failed (403 Forbidden)") });

  const snapshot = await collectElasticSnapshot(client, ["node_settings", "roles", "kibana_spaces"], {});

  assert.equal(snapshot.node_settings.data.nodes["node-1"].settings["xpack.security.authc.realms.ldap.ldap1.bind_password"], "[REDACTED]");
  assert.equal(snapshot.node_settings.data.nodes["node-1"].settings["xpack.security.authc.token.enabled"], "true");
  assert.match(snapshot.roles.error, /403/);
  assert.equal(snapshot.roles.data, undefined);
  assert.equal(snapshot.kibana_spaces.error, undefined);
});

test("assessElasticIdentity passes with secure realms, SSO mappings, no anonymous access, and scoped API keys", async () => {
  const result = await assessElasticIdentity(stubClient(healthyFixtures()));

  assert.equal(result.area, "identity");
  assert.deepEqual(result.findings.map((item) => item.id), ["ELASTIC-01", "ELASTIC-09", "ELASTIC-10", "ELASTIC-13", "ELASTIC-14"]);
  assert.equal(findingById(result, "ELASTIC-01").status, "pass");
  assert.deepEqual(findingById(result, "ELASTIC-01").evidence.secure_realm_types, ["saml"]);
  assert.equal(findingById(result, "ELASTIC-09").status, "pass");
  assert.equal(findingById(result, "ELASTIC-10").status, "pass");
  assert.equal(findingById(result, "ELASTIC-13").status, "pass");
  assert.deepEqual(findingById(result, "ELASTIC-13").evidence.sso_realms[0].role_mappings, ["saml_users"]);
  assert.equal(findingById(result, "ELASTIC-14").status, "pass");
  assert.deepEqual(result.errors, []);
  assert.ok(findingById(result, "ELASTIC-01").mappings.includes("FedRAMP IA-2"));
  assert.ok(findingById(result, "ELASTIC-09").mappings.includes("PCI-DSS 8.6.1"));
});

test("assessElasticIdentity fails on native-only realms, anonymous superuser, and unscoped stale API keys", async () => {
  const now = Date.now();
  const fixtures = healthyFixtures(now);
  fixtures.nodeSettings.nodes["node-1"].settings = {
    "xpack.security.enabled": "true",
    "xpack.security.authc.realms.native.native1.order": "0",
    "xpack.security.authc.anonymous.username": "guest",
    "xpack.security.authc.anonymous.roles": ["superuser"],
  };
  delete fixtures.xpackUsage.security.realms.saml;
  fixtures.xpackUsage.security.anonymous.enabled = true;
  fixtures.apiKeys = [
    {
      id: "key-legacy",
      name: "legacy-admin",
      creation: now - 400 * DAY_MS,
      invalidated: false,
      username: "elastic",
      realm: "reserved",
      role_descriptors: { admin: { cluster: ["all"], indices: [{ names: ["*"], privileges: ["all"] }] } },
    },
    { id: "key-old", name: "revoked", creation: now - 500 * DAY_MS, invalidated: true, username: "elastic", realm: "reserved", role_descriptors: {} },
  ];

  const result = await assessElasticIdentity(stubClient(fixtures), { maxApiKeyAgeDays: 90 });

  assert.equal(findingById(result, "ELASTIC-01").status, "fail");
  assert.equal(findingById(result, "ELASTIC-13").status, "manual");
  assert.match(findingById(result, "ELASTIC-13").summary, /Not applicable/);
  assert.equal(findingById(result, "ELASTIC-14").status, "fail");
  assert.deepEqual(findingById(result, "ELASTIC-14").evidence.anonymous_roles, ["superuser"]);
  const keys = findingById(result, "ELASTIC-09");
  assert.equal(keys.status, "fail");
  assert.equal(keys.evidence.without_expiration, 1);
  assert.equal(keys.evidence.older_than_max_age, 1);
  assert.equal(keys.evidence.invalidated, 1);
  assert.equal(keys.evidence.flagged[0].name, "legacy-admin");
  const scope = findingById(result, "ELASTIC-10");
  assert.equal(scope.status, "fail");
  assert.equal(scope.evidence.privileged.length, 1);
});

test("assessElasticIdentity produces manual findings when settings and API keys are unreadable", async () => {
  const fixtures = healthyFixtures();
  const client = stubClient(fixtures, {
    getNodeSettings: forbidden("elasticsearch request GET /_nodes/settings failed (403 Forbidden)"),
    getClusterSettings: forbidden("elasticsearch request GET /_cluster/settings failed (403 Forbidden)"),
    getXpackUsage: forbidden("elasticsearch request GET /_xpack/usage failed (403 Forbidden)"),
    listApiKeys: forbidden("elasticsearch request POST /_security/_query/api_key failed (403 Forbidden)"),
  });

  const result = await assessElasticIdentity(client);

  for (const id of ["ELASTIC-01", "ELASTIC-09", "ELASTIC-10", "ELASTIC-13", "ELASTIC-14"]) {
    const item = findingById(result, id);
    assert.equal(item.status, "manual", `${id} should be manual`);
    assert.match(item.summary, /Collect manually:/);
    assert.ok(item.evidence.manual_evidence);
  }
  assert.equal(result.errors.length, 4);
});

test("assessElasticAccessControl passes when superusers stay within threshold and FLS/DLS cover supplied patterns", async () => {
  const result = await assessElasticAccessControl(stubClient(healthyFixtures()), {
    maxSuperusers: 1,
    sensitiveIndexPatterns: ["customers-2026"],
    tenantIndexPatterns: ["tenant-acme"],
  });

  assert.equal(result.area, "access_control");
  assert.deepEqual(result.findings.map((item) => item.id), ["ELASTIC-06", "ELASTIC-07", "ELASTIC-08"]);
  assert.equal(findingById(result, "ELASTIC-06").status, "pass");
  assert.deepEqual(findingById(result, "ELASTIC-06").evidence.superusers, ["elastic"]);
  assert.equal(findingById(result, "ELASTIC-07").status, "pass");
  assert.deepEqual(findingById(result, "ELASTIC-07").evidence.uncovered_patterns, []);
  assert.equal(findingById(result, "ELASTIC-08").status, "pass");
  assert.equal(result.summary.license_type, "platinum");
  assert.ok(findingById(result, "ELASTIC-06").mappings.includes("CIS 6.1"));
});

test("assessElasticAccessControl fails on excess superusers, broad custom roles, and missing FLS/DLS coverage", async () => {
  const fixtures = healthyFixtures();
  fixtures.roles = {
    superuser: fixtures.roles.superuser,
    power_user: { cluster: ["all"], indices: [{ names: ["*"], privileges: ["all"] }], metadata: {} },
    reader: { cluster: [], indices: [{ names: ["logs-*"], privileges: ["read"] }], metadata: {} },
  };
  fixtures.users = {
    elastic: { username: "elastic", roles: ["superuser"], enabled: true },
    ops: { username: "ops", roles: ["superuser"], enabled: true },
    dev: { username: "dev", roles: ["superuser"], enabled: true },
    intern: { username: "intern", roles: ["power_user"], enabled: true },
  };
  fixtures.license.license.type = "basic";

  const result = await assessElasticAccessControl(stubClient(fixtures), {
    maxSuperusers: 2,
    sensitiveIndexPatterns: ["customers-*"],
    tenantIndexPatterns: ["tenant-*"],
  });

  const rbac = findingById(result, "ELASTIC-06");
  assert.equal(rbac.status, "fail");
  assert.deepEqual(rbac.evidence.superusers, ["elastic", "ops", "dev"]);
  assert.deepEqual(rbac.evidence.cluster_all_roles, ["power_user"]);
  assert.deepEqual(rbac.evidence.users_with_broad_roles, ["intern"]);
  assert.equal(findingById(result, "ELASTIC-07").status, "fail");
  assert.equal(findingById(result, "ELASTIC-07").evidence.license_supports_feature, false);
  assert.equal(findingById(result, "ELASTIC-08").status, "fail");

  const unreadable = await assessElasticAccessControl(stubClient(fixtures, { listRoles: forbidden("roles forbidden") }));
  const rbacUnreadable = findingById(unreadable, "ELASTIC-06");
  assert.equal(rbacUnreadable.status, "fail", "observed superuser excess still fails when roles are unreadable");
  assert.match(rbacUnreadable.summary, /Additional sources were unreadable or partial: roles \(GET \/_security\/role\): roles forbidden/);
  assert.equal(findingById(unreadable, "ELASTIC-07").status, "manual");
  assert.equal(findingById(unreadable, "ELASTIC-08").status, "manual");

  const patternsUnreadable = await assessElasticAccessControl(
    stubClient(healthyFixtures(), { listRoles: forbidden("roles forbidden") }),
    { sensitiveIndexPatterns: ["customers-*"], tenantIndexPatterns: ["tenant-*"] },
  );
  for (const id of ["ELASTIC-06", "ELASTIC-07", "ELASTIC-08"]) {
    assert.equal(findingById(patternsUnreadable, id).status, "manual", `${id} must not fail or pass on absent role data`);
  }
  assert.match(findingById(patternsUnreadable, "ELASTIC-07").summary, /could not be evaluated/);
});

test("assessElasticTransportSecurity passes with TLS on both layers, modern protocols, and valid certificates", async () => {
  const result = await assessElasticTransportSecurity(stubClient(healthyFixtures()));

  assert.equal(result.area, "transport_security");
  assert.deepEqual(result.findings.map((item) => item.id), ["ELASTIC-02", "ELASTIC-03", "ELASTIC-04", "ELASTIC-05"]);
  assert.equal(findingById(result, "ELASTIC-02").status, "pass");
  assert.deepEqual(findingById(result, "ELASTIC-02").evidence.verification_mode_per_node, [{ node: "es-1", value: "certificate" }]);
  assert.equal(findingById(result, "ELASTIC-03").status, "pass");
  assert.equal(findingById(result, "ELASTIC-03").evidence.elasticsearch_url_scheme, "https");
  assert.equal(findingById(result, "ELASTIC-04").status, "pass");
  assert.equal(findingById(result, "ELASTIC-05").status, "pass");
  assert.match(findingById(result, "ELASTIC-05").summary, /single-node cluster, so the inventory is complete/);
  assert.equal(result.summary.transport_tls, true);
  assert.ok(findingById(result, "ELASTIC-04").mappings.includes("FedRAMP SC-8(1)"));
});

test("assessElasticTransportSecurity fails on disabled TLS, weak protocols, plain http, and expired certificates", async () => {
  const now = Date.now();
  const fixtures = healthyFixtures(now);
  const settings = fixtures.nodeSettings.nodes["node-1"].settings;
  settings["xpack.security.transport.ssl.enabled"] = "false";
  settings["xpack.security.http.ssl.enabled"] = "false";
  settings["xpack.security.transport.ssl.supported_protocols"] = ["TLSv1.2", "TLSv1"];
  fixtures.sslCertificates = [
    { path: "certs/old.p12", alias: "old", subject_dn: "CN=old", has_private_key: true, expiry: new Date(now - 5 * DAY_MS).toISOString() },
    { path: "certs/soon.p12", alias: "soon", subject_dn: "CN=soon", has_private_key: true, expiry: new Date(now + 10 * DAY_MS).toISOString() },
  ];

  const result = await assessElasticTransportSecurity(stubClient(fixtures, {}, { elasticsearchUrl: "http://es.example.com:9200" }), { certExpiryWarningDays: 30 });

  assert.equal(findingById(result, "ELASTIC-02").status, "fail");
  assert.deepEqual(findingById(result, "ELASTIC-02").evidence.disabled_nodes, ["es-1"]);
  assert.equal(findingById(result, "ELASTIC-03").status, "fail");
  assert.match(findingById(result, "ELASTIC-03").summary, /plain http/);
  assert.equal(findingById(result, "ELASTIC-04").status, "fail");
  assert.deepEqual(findingById(result, "ELASTIC-04").evidence.weak_protocols, ["TLSv1"]);
  const certs = findingById(result, "ELASTIC-05");
  assert.equal(certs.status, "fail");
  assert.equal(certs.evidence.expired, 1);
  assert.equal(certs.evidence.expiring_soon, 1);

  const unreadable = await assessElasticTransportSecurity(stubClient(fixtures, {
    getNodeSettings: forbidden("nodes forbidden"),
    getClusterSettings: forbidden("cluster forbidden"),
    getXpackUsage: forbidden("usage forbidden"),
    listSslCertificates: forbidden("certs forbidden"),
  }));
  assert.ok(unreadable.findings.every((item) => item.status === "manual"), unreadable.findings.map((item) => `${item.id}:${item.status}`).join(", "));
});

test("assessElasticClusterHardening passes on a hardened cluster and keeps audit forwarding manual", async () => {
  const fixtures = healthyFixtures();
  fixtures.spaces = [fixtures.spaces[0]];
  const result = await assessElasticClusterHardening(stubClient(fixtures));

  assert.equal(result.area, "cluster_hardening");
  assert.deepEqual(
    result.findings.map((item) => item.id),
    ["ELASTIC-11", "ELASTIC-12", "ELASTIC-17", "ELASTIC-18", "ELASTIC-19", "ELASTIC-20", "ELASTIC-22", "ELASTIC-23"],
  );
  assert.equal(findingById(result, "ELASTIC-11").status, "pass");
  assert.equal(findingById(result, "ELASTIC-12").status, "manual");
  assert.match(findingById(result, "ELASTIC-12").summary, /tamper-resistant destination/);
  assert.equal(findingById(result, "ELASTIC-17").status, "pass");
  assert.equal(findingById(result, "ELASTIC-18").status, "pass");
  assert.equal(findingById(result, "ELASTIC-19").status, "pass");
  assert.equal(findingById(result, "ELASTIC-20").status, "pass");
  assert.equal(findingById(result, "ELASTIC-22").status, "pass");
  assert.equal(findingById(result, "ELASTIC-23").status, "pass");
  assert.deepEqual(findingById(result, "ELASTIC-23").evidence.unsupported_features, []);
  assert.ok(findingById(result, "ELASTIC-11").mappings.includes("SOC 2 CC7.2"));
});

test("assessElasticClusterHardening fails on disabled audit, missing ILM and snapshots, weak settings, and license gaps", async () => {
  const fixtures = healthyFixtures();
  const settings = fixtures.nodeSettings.nodes["node-1"].settings;
  settings["xpack.security.audit.enabled"] = "false";
  settings["xpack.security.enabled"] = "false";
  fixtures.clusterSettings.defaults = {};
  fixtures.xpackUsage.security.audit = { enabled: false };
  fixtures.xpackUsage.security.enabled = false;
  fixtures.ilmPolicies = {};
  fixtures.snapshotRepositories = {};
  fixtures.watches = [
    { _id: "legacy", watch: { actions: { notify: { webhook: { scheme: "http", host: "internal", port: 80, auth: { basic: { username: "u", password: "p" } } } } } } },
  ];
  fixtures.connectors = [{ id: "c-http", name: "plain", connector_type_id: ".webhook", is_missing_secrets: true, config: { url: "http://hooks.internal/x" } }];
  fixtures.ingestPipelines = {
    "leaky": { processors: [{ set: { field: "api_password", value: "hunter2hunter2" } }, { script: { source: "ctx.a = 1" } }] },
  };
  fixtures.license.license.type = "basic";

  const result = await assessElasticClusterHardening(stubClient(fixtures));

  assert.equal(findingById(result, "ELASTIC-11").status, "fail");
  assert.equal(findingById(result, "ELASTIC-12").status, "fail");
  assert.equal(findingById(result, "ELASTIC-17").status, "fail");
  assert.equal(findingById(result, "ELASTIC-18").status, "fail");
  assert.equal(findingById(result, "ELASTIC-19").status, "fail");
  const alerting = findingById(result, "ELASTIC-20");
  assert.equal(alerting.status, "fail");
  assert.equal(alerting.evidence.insecure_watch_webhooks.length, 1);
  assert.equal(alerting.evidence.insecure_connectors.length, 1);
  const pipelines = findingById(result, "ELASTIC-22");
  assert.equal(pipelines.status, "fail");
  assert.deepEqual(pipelines.evidence.pipelines_with_sensitive_set[0].sensitive_set_processors, ["api_password"]);
  const license = findingById(result, "ELASTIC-23");
  assert.equal(license.status, "fail");
  assert.ok(license.evidence.unsupported_features.includes("saml realm"));
});

test("assessElasticClusterHardening warns on partial hardening and turns unreadable surfaces into manual findings", async () => {
  const fixtures = healthyFixtures();
  fixtures.ilmPolicies["no-delete"] = { policy: { phases: { hot: { actions: {} } } }, in_use_by: { indices: ["hot-000001"], data_streams: [], composable_templates: [] } };
  fixtures.snapshotRepositories = { local: { type: "fs", settings: { location: "/mnt/backups" } } };
  fixtures.nodeSettings.nodes["node-1"].settings["xpack.security.authc.password_hashing.algorithm"] = "ssha256";
  fixtures.ingestPipelines = { "custom-script": { processors: [{ script: { source: "ctx.a = 1" } }] } };
  fixtures.license.license.type = "trial";

  const result = await assessElasticClusterHardening(stubClient(fixtures, { listWatches: forbidden("watcher forbidden") }));

  assert.equal(findingById(result, "ELASTIC-17").status, "warn");
  assert.equal(findingById(result, "ELASTIC-18").status, "manual");
  assert.match(findingById(result, "ELASTIC-18").summary, /local:fs/);
  assert.equal(findingById(result, "ELASTIC-19").status, "warn");
  assert.equal(findingById(result, "ELASTIC-20").status, "manual", "a licensed but unreadable Watcher never yields pass");
  assert.equal(findingById(result, "ELASTIC-20").evidence.watcher_unreadable, "watcher forbidden");
  assert.match(findingById(result, "ELASTIC-20").summary, /watcher forbidden/);
  assert.equal(findingById(result, "ELASTIC-22").status, "warn");
  assert.equal(findingById(result, "ELASTIC-23").status, "warn");

  const dark = await assessElasticClusterHardening(stubClient(fixtures, {
    getNodeSettings: forbidden("nodes forbidden"),
    getClusterSettings: forbidden("cluster forbidden"),
    getXpackUsage: forbidden("usage forbidden"),
    listIlmPolicies: forbidden("ilm forbidden"),
    listSnapshotRepositories: forbidden("snapshot forbidden"),
    listWatches: forbidden("watcher forbidden"),
    listConnectors: forbidden("connectors forbidden"),
    listIngestPipelines: forbidden("pipelines forbidden"),
    getLicense: forbidden("license forbidden"),
  }));
  assert.ok(dark.findings.every((item) => item.status === "manual"), dark.findings.map((item) => `${item.id}:${item.status}`).join(", "));
  assert.equal(dark.errors.length, 9);
});

test("assessElasticKibana passes with isolated spaces, scoped roles, and hardened Fleet", async () => {
  const result = await assessElasticKibana(stubClient(healthyFixtures()));

  assert.equal(result.area, "kibana");
  assert.deepEqual(result.findings.map((item) => item.id), ["ELASTIC-15", "ELASTIC-16", "ELASTIC-21"]);
  assert.equal(findingById(result, "ELASTIC-15").status, "pass");
  assert.deepEqual(findingById(result, "ELASTIC-15").evidence.space_scoped_roles, ["security_analyst"]);
  assert.equal(findingById(result, "ELASTIC-16").status, "pass");
  assert.equal(findingById(result, "ELASTIC-21").status, "pass");
  assert.equal(result.summary.kibana_version, "8.15.0");
  assert.equal(result.summary.kibana_status, "available");
  assert.ok(findingById(result, "ELASTIC-15").mappings.includes("FedRAMP AC-4"));
});

test("assessElasticKibana fails on global-all roles and plain http Fleet outputs", async () => {
  const fixtures = healthyFixtures();
  fixtures.spaces = [fixtures.spaces[0]];
  fixtures.kibanaRoles = [
    ...fixtures.kibanaRoles,
    { name: "everything", metadata: {}, elasticsearch: { cluster: ["all"] }, kibana: [{ base: ["all"], feature: {}, spaces: ["*"] }] },
  ];
  fixtures.fleetOutputs = [{ id: "plain", name: "plain", type: "elasticsearch", hosts: ["http://es.internal:9200"] }];
  fixtures.agentPolicies = [{ id: "policy-1", name: "Unprotected", is_protected: false }];

  const result = await assessElasticKibana(stubClient(fixtures));

  assert.equal(findingById(result, "ELASTIC-15").status, "warn");
  assert.equal(findingById(result, "ELASTIC-16").status, "fail");
  assert.deepEqual(findingById(result, "ELASTIC-16").evidence.global_all_roles, ["everything"]);
  const fleet = findingById(result, "ELASTIC-21");
  assert.equal(fleet.status, "fail");
  assert.deepEqual(fleet.evidence.insecure_outputs, ["plain"]);
  assert.deepEqual(fleet.evidence.unprotected_policies, ["Unprotected"]);
});

test("assessElasticKibana emits manual findings when Kibana is not configured or unreadable", async () => {
  const fixtures = healthyFixtures();
  const unconfigured = await assessElasticKibana(stubClient(fixtures, {}, { kibanaUrl: undefined }));
  assert.deepEqual(unconfigured.findings.map((item) => `${item.id}:${item.status}`), ["ELASTIC-15:manual", "ELASTIC-16:manual", "ELASTIC-21:manual"]);
  assert.match(unconfigured.findings[0].summary, /KIBANA_URL/);
  assert.equal(unconfigured.summary.kibana_configured, false);

  const unreadable = await assessElasticKibana(stubClient(fixtures, {
    listSpaces: forbidden("spaces forbidden"),
    listKibanaRoles: forbidden("roles forbidden"),
    listAgentPolicies: forbidden("fleet forbidden"),
  }));
  assert.ok(unreadable.findings.every((item) => item.status === "manual"));
  assert.equal(unreadable.errors.length, 3);
});

test("the five assessment areas together cover all 23 spec controls with every framework mapping", async () => {
  const fixtures = healthyFixtures();
  assert.equal(ELASTIC_ALL_DATASETS.length, 30);
  const snapshot = await collectElasticSnapshot(stubClient(fixtures), ELASTIC_ALL_DATASETS);
  const areas = ["identity", "access_control", "transport_security", "cluster_hardening", "kibana"];
  const findings = areas.flatMap((area) => evaluateElasticArea(area, snapshot, {}, { elasticsearchUrl: "https://es.example.com:9200" }).findings);

  assert.equal(ELASTIC_CONTROLS.length, 23);
  assert.equal(findings.length, 23);
  assert.deepEqual(
    findings.map((item) => item.id).sort(),
    ELASTIC_CONTROLS.map((control) => control.id).sort(),
  );
  for (const item of findings) {
    assert.equal(item.mappings.length, ELASTIC_FRAMEWORKS.length, `${item.id} should map to every framework`);
    for (const framework of ELASTIC_FRAMEWORKS) {
      assert.ok(item.mappings.some((mapping) => mapping.startsWith(framework.prefix)), `${item.id} lacks ${framework.label}`);
    }
    assert.ok(["critical", "high", "medium", "low", "info"].includes(item.severity));
    assert.ok(["pass", "warn", "fail", "manual"].includes(item.status));
    assert.equal(typeof item.evidence.spec_control, "number");
  }
  assert.throws(() => evaluateElasticArea("unknown", snapshot), /Unsupported Elastic assessment area/);
});

test("exportElasticAuditBundle writes the full layout and zip without leaking credentials", async () => {
  const fixtures = healthyFixtures();
  const config = sampleConfig({ cloudApiKey: "cloud-secret-key" });
  const client = new ElasticApiClient(config, { fetchImpl: createRouter(healthyRoutes(fixtures)) });
  const base = createTempBase("elastic-bundle-");

  const result = await exportElasticAuditBundle(client, config, base);

  assert.equal(result.findingCount, 23);
  assert.equal(result.errorCount, 0);
  assert.ok(result.outputDir.startsWith(base));
  assert.ok(existsSync(result.zipPath));
  assert.ok(result.zipPath.endsWith("es.example.com-audit-bundle.zip"));
  const expectedFiles = [
    "QUICK_REFERENCE.md",
    "metadata.json",
    "core_data/authenticate.json",
    "core_data/node_settings.json",
    "core_data/api_keys.json",
    "core_data/kibana_spaces.json",
    "core_data/fleet_enrollment_api_keys.json",
    "core_data/cloud_deployments.json",
    "analysis/access.json",
    "analysis/findings.json",
    "analysis/identity.json",
    "analysis/access_control.json",
    "analysis/transport_security.json",
    "analysis/cluster_hardening.json",
    "analysis/kibana.json",
    "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md",
    ...ELASTIC_FRAMEWORKS.map((framework) => `compliance/frameworks/${framework.key}.md`),
  ];
  for (const relativePath of expectedFiles) {
    assert.ok(existsSync(join(result.outputDir, relativePath)), `missing ${relativePath}`);
  }
  assert.equal(readdirSync(join(result.outputDir, "core_data")).length, 30);
  assert.equal(existsSync(join(result.outputDir, "_errors.log")), false);
  assert.equal(result.zipPath, `${result.outputDir}.zip`, "the archive name is derived from the allocated directory");
  const apiKeysRaw = JSON.parse(readFileSync(join(result.outputDir, "core_data", "api_keys.json"), "utf8"));
  assert.deepEqual(apiKeysRaw.page, { seen: 1, total: 1, truncated: false, pages: 1 });
  assert.ok(result.fileCount >= expectedFiles.length);

  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  assert.equal(findings.length, 23);
  const matrix = readFileSync(join(result.outputDir, "compliance", "unified_compliance_matrix.md"), "utf8");
  assert.match(matrix, /ELASTIC-01/);
  assert.match(matrix, /IA-2/);
  const summary = readFileSync(join(result.outputDir, "compliance", "executive_summary.md"), "utf8");
  assert.match(summary, /Manual controls: 1/);
  assert.match(summary, /ELASTIC-12/);
  const metadata = JSON.parse(readFileSync(join(result.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.auth_mode, "api_key");
  assert.equal(metadata.controls_covered, 23);
  const enrollment = JSON.parse(readFileSync(join(result.outputDir, "core_data", "fleet_enrollment_api_keys.json"), "utf8"));
  assert.equal(enrollment.data[0].api_key, "[REDACTED]");

  const walk = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory() ? walk(join(dir, entry.name)) : [join(dir, entry.name)]);
  for (const file of walk(result.outputDir)) {
    const text = readFileSync(file, "utf8");
    assert.ok(!text.includes(API_KEY), `${file} leaks the API key`);
    assert.ok(!text.includes("cloud-secret-key"), `${file} leaks the cloud key`);
    assert.ok(!text.includes("enrollment-secret"), `${file} leaks the enrollment key`);
  }
});

test("exportElasticAuditBundle records partial failures in _errors.log and still produces a zip", async () => {
  const fixtures = healthyFixtures();
  const routes = healthyRoutes(fixtures);
  routes["GET /_ssl/certificates"] = () => jsonResponse(
    { error: { type: "security_exception", reason: "action [cluster:monitor/xpack/ssl/certificates/get] is unauthorized" } },
    { status: 403, statusText: "Forbidden" },
  );
  routes["POST /_watcher/_query/watches"] = () => jsonResponse({ error: { type: "security_exception", reason: "unauthorized" } }, { status: 403, statusText: "Forbidden" });
  const config = sampleConfig({ kibanaUrl: undefined });
  const client = new ElasticApiClient(config, { fetchImpl: createRouter(routes) });
  const base = createTempBase("elastic-bundle-partial-");

  const result = await exportElasticAuditBundle(client, config, base);

  assert.equal(result.errorCount, 2);
  assert.equal(result.findingCount, 23);
  assert.ok(existsSync(result.zipPath));
  const errors = readFileSync(join(result.outputDir, "_errors.log"), "utf8");
  assert.match(errors, /ssl_certificates \(GET \/_ssl\/certificates\): .*403/);
  assert.match(errors, /watches \(POST \/_watcher\/_query\/watches\)/);
  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  assert.equal(findings.find((item) => item.id === "ELASTIC-05").status, "manual");
  assert.equal(findings.find((item) => item.id === "ELASTIC-15").status, "manual");
  const certificates = JSON.parse(readFileSync(join(result.outputDir, "core_data", "ssl_certificates.json"), "utf8"));
  assert.match(certificates.error, /403/);
  assert.equal(certificates.collected, false);
  assert.equal(certificates.status, 403);
  const spaces = JSON.parse(readFileSync(join(result.outputDir, "core_data", "kibana_spaces.json"), "utf8"));
  assert.equal(spaces.collected, false);
  assert.equal(spaces.status, "not-collected");
  assert.equal(spaces.reason, "not_configured");
  assert.equal(spaces.error, "KIBANA_URL is not configured");
  const summary = readFileSync(join(result.outputDir, "compliance", "executive_summary.md"), "utf8");
  assert.match(summary, /Collection errors: 2 \(see _errors.log\)/);

  const firstZipBefore = readFileSync(result.zipPath);
  const second = await exportElasticAuditBundle(client, config, base);
  assert.notEqual(second.outputDir, result.outputDir, "repeat exports allocate a fresh directory");
  assert.notEqual(second.zipPath, result.zipPath, "verdict rule 8: repeat exports never reuse the archive name");
  assert.equal(second.zipPath, `${second.outputDir}.zip`, "directory and archive stay paired");
  assert.ok(second.outputDir.endsWith("es.example.com-audit-bundle-2"));
  assert.ok(existsSync(result.zipPath) && existsSync(second.zipPath));
  assert.ok(firstZipBefore.equals(readFileSync(result.zipPath)), "the prior archive is left untouched");
});

test("verdict rule 8: a stray archive blocks reuse of its paired directory name", async () => {
  const fixtures = healthyFixtures();
  const config = sampleConfig({ kibanaUrl: undefined });
  const client = new ElasticApiClient(config, { fetchImpl: createRouter(healthyRoutes(fixtures)) });
  const base = createTempBase("elastic-bundle-stray-");
  writeFileSync(join(base, "es.example.com-audit-bundle.zip"), "prior archive", "utf8");

  const result = await exportElasticAuditBundle(client, config, base);

  assert.ok(result.outputDir.endsWith("es.example.com-audit-bundle-2"), result.outputDir);
  assert.equal(result.zipPath, `${result.outputDir}.zip`);
  assert.equal(readFileSync(join(base, "es.example.com-audit-bundle.zip"), "utf8"), "prior archive");
});

function pagedList(items, total, truncated, pages = 1) {
  return { items, total, truncated, pages, seen: items.length };
}

function forbiddenEverywhere(fixtures, configOverrides = {}) {
  const client = stubClient(fixtures, {}, configOverrides);
  const overrides = {};
  for (const [name, value] of Object.entries(client)) {
    if (name !== "getResolvedConfig" && typeof value === "function") {
      overrides[name] = forbidden(`elasticsearch request ${name} failed (403 Forbidden): action is unauthorized for user [grc-auditor]`);
    }
  }
  return { ...client, ...overrides };
}

function emptyInventoryFixtures(now = Date.now()) {
  const fixtures = healthyFixtures(now);
  Object.assign(fixtures, {
    users: {},
    roles: {},
    roleMappings: {},
    apiKeys: [],
    sslCertificates: [],
    ilmPolicies: {},
    slmPolicies: {},
    snapshotRepositories: {},
    watches: [],
    ingestPipelines: {},
    spaces: [],
    kibanaRoles: [],
    agentPolicies: [],
    fleetOutputs: [],
    enrollmentKeys: [],
    fleetServerHosts: [],
    detectionRules: [],
    alertingRules: [],
    connectors: [],
    cloudDeployments: [],
  });
  return fixtures;
}

function withoutSecurityFlag(fixtures) {
  delete fixtures.nodeSettings.nodes["node-1"].settings["xpack.security.enabled"];
  fixtures.clusterSettings.defaults = {};
  delete fixtures.xpackUsage.security.enabled;
  delete fixtures.xpackInfo.features.security.enabled;
  return fixtures;
}

function statusMap(result) {
  return Object.fromEntries(result.findings.map((item) => [item.id, item.status]));
}

const ALL_AREAS = ["identity", "access_control", "transport_security", "cluster_hardening", "kibana"];

async function assessAll(client, options = {}) {
  const snapshot = await collectElasticSnapshot(client, ELASTIC_ALL_DATASETS, options);
  const config = client.getResolvedConfig();
  return ALL_AREAS.flatMap((area) => evaluateElasticArea(area, snapshot, options, { elasticsearchUrl: config.elasticsearchUrl, kibanaSpaceId: config.kibanaSpaceId }).findings);
}

test("verdict rule 1: forbidden or errored dependencies yield manual verdicts that name the cause, never pass", async () => {
  const fixtures = healthyFixtures();
  fixtures.spaces = [fixtures.spaces[0]];
  const options = { sensitiveIndexPatterns: ["customers-*"], tenantIndexPatterns: ["tenant-*"] };

  const fleet = await assessElasticKibana(stubClient(fixtures, { listFleetOutputs: forbidden("kibana request GET /api/fleet/outputs failed (403 Forbidden): missing fleet read") }));
  const fleetFinding = findingById(fleet, "ELASTIC-21");
  assert.equal(fleetFinding.status, "manual", "policies readable but outputs forbidden must not pass");
  assert.match(fleetFinding.summary, /required evidence could not be read: fleet_outputs \(GET \/api\/fleet\/outputs\): .*403 Forbidden.*missing fleet read/);
  assert.match(fleetFinding.summary, /Collect manually:/);
  assert.deepEqual(fleetFinding.evidence.unreadable_sources.length, 1);

  const connectors = await assessElasticClusterHardening(stubClient(fixtures, { listConnectors: forbidden("kibana request GET /api/actions/connectors failed (403 Forbidden)") }));
  assert.equal(findingById(connectors, "ELASTIC-20").status, "manual", "readable watches with forbidden connectors must not pass");
  assert.match(findingById(connectors, "ELASTIC-20").summary, /connectors \(GET \/api\/actions\/connectors\): .*403/);

  const statuses = await assessElasticClusterHardening(stubClient(fixtures, {
    getIlmStatus: forbidden("GET /_ilm/status failed (403 Forbidden)"),
    getSlmStatus: forbidden("GET /_slm/status failed (403 Forbidden)"),
  }));
  assert.equal(findingById(statuses, "ELASTIC-17").status, "manual");
  assert.match(findingById(statuses, "ELASTIC-17").summary, /ilm_status \(GET \/_ilm\/status\)/);
  assert.equal(findingById(statuses, "ELASTIC-18").status, "manual");
  assert.match(findingById(statuses, "ELASTIC-18").summary, /slm_status \(GET \/_slm\/status\)/);

  const privileges = await assessElasticIdentity(stubClient(fixtures, { hasPrivileges: forbidden("POST /_security/user/_has_privileges failed (403 Forbidden)") }));
  assert.equal(findingById(privileges, "ELASTIC-09").status, "manual", "API key visibility cannot be confirmed without the privilege probe");
  assert.equal(findingById(privileges, "ELASTIC-10").status, "manual");
  assert.match(findingById(privileges, "ELASTIC-09").summary, /privileges \(POST \/_security\/user\/_has_privileges\)/);

  const license = await assessElasticAccessControl(stubClient(fixtures, { getLicense: forbidden("GET /_license failed (401 Unauthorized)") }), options);
  assert.equal(findingById(license, "ELASTIC-07").status, "manual", "covered patterns cannot pass when the license tier is unreadable");
  assert.equal(findingById(license, "ELASTIC-08").status, "manual");
  const licenseIdentity = await assessElasticIdentity(stubClient(fixtures, { getLicense: forbidden("GET /_license failed (401 Unauthorized)") }));
  assert.equal(findingById(licenseIdentity, "ELASTIC-13").status, "manual");
  assert.match(findingById(licenseIdentity, "ELASTIC-13").summary, /license \(GET \/_license\): .*401/);

  const kibanaRoles = await assessElasticKibana(stubClient(fixtures, { listKibanaRoles: forbidden("GET /api/security/role failed (403 Forbidden)") }));
  assert.equal(findingById(kibanaRoles, "ELASTIC-15").status, "manual", "space isolation depends on readable roles");
  assert.equal(findingById(kibanaRoles, "ELASTIC-16").status, "manual");

  const timeout = await assessElasticTransportSecurity(stubClient(fixtures, {
    listSslCertificates: async () => { throw new Error("elasticsearch request GET /_ssl/certificates timed out after 5000ms"); },
  }));
  assert.equal(findingById(timeout, "ELASTIC-05").status, "manual");
  assert.match(findingById(timeout, "ELASTIC-05").summary, /timed out after 5000ms/);
});

test("verdict rule 2: empty inventories never pass by default and the summary states how emptiness is judged", async () => {
  const fixtures = healthyFixtures();
  fixtures.spaces = [fixtures.spaces[0]];

  const noUsers = await assessElasticAccessControl(stubClient({ ...fixtures, users: {} }));
  assert.equal(findingById(noUsers, "ELASTIC-06").status, "manual");
  assert.match(findingById(noUsers, "ELASTIC-06").summary, /users \(GET \/_security\/user\) returned zero entries although built-in users such as elastic are always returned/);

  const noRoles = await assessElasticAccessControl(stubClient({ ...fixtures, roles: {} }), { sensitiveIndexPatterns: ["customers-*"] });
  assert.deepEqual(statusMap(noRoles), { "ELASTIC-06": "manual", "ELASTIC-07": "manual", "ELASTIC-08": "manual" });

  const noMappings = await assessElasticIdentity(stubClient({ ...fixtures, roleMappings: {} }));
  assert.equal(findingById(noMappings, "ELASTIC-13").status, "fail", "an SSO realm with zero role mappings fails, never passes");
  assert.match(findingById(noMappings, "ELASTIC-13").summary, /zero enabled role mappings and no authorization_realms .* fails this control/);

  const noKeys = await assessElasticIdentity(stubClient({ ...fixtures, apiKeys: [] }));
  assert.equal(findingById(noKeys, "ELASTIC-09").status, "pass", "zero API keys passes only because the control is about existing keys");
  assert.match(findingById(noKeys, "ELASTIC-09").summary, /This control concerns existing keys, so an empty inventory is compliant/);
  assert.match(findingById(noKeys, "ELASTIC-09").summary, /with full inventory visibility/);
  assert.equal(findingById(noKeys, "ELASTIC-10").status, "pass");
  const noKeysNoVisibility = await assessElasticIdentity(stubClient({
    ...fixtures,
    apiKeys: [],
    hasPrivileges: { ...fixtures.hasPrivileges, cluster: { ...fixtures.hasPrivileges.cluster, read_security: false, manage_api_key: false, manage_security: false } },
  }));
  assert.equal(findingById(noKeysNoVisibility, "ELASTIC-09").status, "warn", "zero keys without full visibility is a partial view, not a pass");

  const noIlm = await assessElasticClusterHardening(stubClient({ ...fixtures, ilmPolicies: {} }));
  assert.equal(findingById(noIlm, "ELASTIC-17").status, "fail");
  assert.match(findingById(noIlm, "ELASTIC-17").summary, /zero policies is a failure for this control/);

  const noRepos = await assessElasticClusterHardening(stubClient({ ...fixtures, snapshotRepositories: {} }));
  assert.equal(findingById(noRepos, "ELASTIC-18").status, "fail");
  assert.match(findingById(noRepos, "ELASTIC-18").summary, /zero repositories is a failure/);
  const noSlm = await assessElasticClusterHardening(stubClient({ ...fixtures, slmPolicies: {} }));
  assert.equal(findingById(noSlm, "ELASTIC-18").status, "fail");
  assert.match(findingById(noSlm, "ELASTIC-18").summary, /zero snapshot lifecycle policies/);

  const noPipelines = await assessElasticClusterHardening(stubClient({ ...fixtures, ingestPipelines: {} }));
  assert.equal(findingById(noPipelines, "ELASTIC-22").status, "manual");
  assert.match(findingById(noPipelines, "ELASTIC-22").summary, /returned zero entries although Elasticsearch ships managed pipelines/);

  const noAlerting = await assessElasticClusterHardening(stubClient({ ...fixtures, watches: [], connectors: [] }));
  assert.equal(findingById(noAlerting, "ELASTIC-20").status, "pass", "zero destinations in a confirmed single space is compliant for a control about existing destinations");
  assert.match(findingById(noAlerting, "ELASTIC-20").summary, /Zero watches and zero connectors exist in the only Kibana space.*this passes because the control governs the security of existing alerting destinations/);
  const noAlertingMultiSpace = await assessElasticClusterHardening(stubClient({ ...healthyFixtures(), watches: [], connectors: [] }));
  assert.equal(findingById(noAlertingMultiSpace, "ELASTIC-20").status, "manual");
  assert.match(findingById(noAlertingMultiSpace, "ELASTIC-20").summary, /connector inventory is space-scoped/);

  const noCerts = await assessElasticTransportSecurity(stubClient({ ...fixtures, sslCertificates: [] }));
  assert.equal(findingById(noCerts, "ELASTIC-05").status, "manual");
  assert.match(findingById(noCerts, "ELASTIC-05").summary, /returned zero entries although a TLS-enabled node always reports/);

  const noFleet = await assessElasticKibana(stubClient({ ...fixtures, agentPolicies: [] }));
  assert.equal(findingById(noFleet, "ELASTIC-21").status, "manual", "zero Fleet policies is not applicable, never pass");
  assert.match(findingById(noFleet, "ELASTIC-21").summary, /Not applicable: zero Fleet agent policies .*\(emptiness is reported as manual, not pass\)/);

  const noKibanaInventory = await assessElasticKibana(stubClient({ ...fixtures, spaces: [], kibanaRoles: [] }));
  assert.deepEqual(statusMap(noKibanaInventory), { "ELASTIC-15": "manual", "ELASTIC-16": "manual", "ELASTIC-21": "pass" });
  assert.match(findingById(noKibanaInventory, "ELASTIC-15").summary, /kibana_spaces \(GET \/api\/spaces\/space\) returned zero entries although the default space always exists/);
  const reservedOnly = await assessElasticKibana(stubClient({ ...fixtures, kibanaRoles: [fixtures.kibanaRoles[0]] }));
  assert.equal(findingById(reservedOnly, "ELASTIC-16").status, "warn", "reserved-only roles mean no privilege separation was implemented");
});

test("verdict rule 3: scoped-out, disabled, or unlicensed controls render as manual with a not applicable summary", async () => {
  const fixtures = healthyFixtures();
  fixtures.spaces = [fixtures.spaces[0]];

  const noSso = healthyFixtures();
  for (const key of Object.keys(noSso.nodeSettings.nodes["node-1"].settings)) {
    if (key.includes("realms.saml")) delete noSso.nodeSettings.nodes["node-1"].settings[key];
  }
  const ssoResult = await assessElasticIdentity(stubClient(noSso));
  assert.equal(findingById(ssoResult, "ELASTIC-13").status, "manual");
  assert.match(findingById(ssoResult, "ELASTIC-13").summary, /Not applicable from settings: no enabled SAML or OIDC realm is configured/);

  const basic = healthyFixtures();
  basic.license.license.type = "basic";
  delete basic.license.license.expiry_date_in_millis;
  const flsResult = await assessElasticAccessControl(stubClient(basic));
  for (const id of ["ELASTIC-07", "ELASTIC-08"]) {
    assert.equal(findingById(flsResult, id).status, "manual");
    assert.match(findingById(flsResult, id).summary, /Not applicable on this license tier: the basic license \(status active\) does not include/);
  }

  const noKibana = await assessElasticKibana(stubClient(fixtures, {}, { kibanaUrl: undefined }));
  for (const item of noKibana.findings) {
    assert.equal(item.status, "manual");
    assert.match(item.summary, /Scoped out: Kibana is not configured \(KIBANA_URL is not configured\)/);
  }
  const noKibanaAlerting = await assessElasticClusterHardening(stubClient(fixtures, {}, { kibanaUrl: undefined }));
  assert.equal(findingById(noKibanaAlerting, "ELASTIC-20").status, "manual", "clean watches alone cannot pass when the Kibana half is scoped out");
  assert.match(findingById(noKibanaAlerting, "ELASTIC-20").summary, /Scoped out: Kibana is not configured .* 1 watch\(es\) were reviewed/);

  const unlicensedWatcher = { ...fixtures, license: { license: { ...fixtures.license.license, type: "basic" } } };
  const nothingApplies = await assessElasticClusterHardening(stubClient(unlicensedWatcher, {
    listWatches: forbidden("POST /_watcher/_query/watches failed (403 Forbidden): current license is non-compliant for [watcher]"),
  }, { kibanaUrl: undefined }));
  assert.equal(findingById(nothingApplies, "ELASTIC-20").status, "manual");
  assert.match(findingById(nothingApplies, "ELASTIC-20").summary, /Not applicable or scoped out: Watcher is not available on the basic license and Kibana is not configured/);
  const connectorsOnly = await assessElasticClusterHardening(stubClient(unlicensedWatcher, {
    listWatches: forbidden("POST /_watcher/_query/watches failed (403 Forbidden): current license is non-compliant for [watcher]"),
  }));
  assert.equal(findingById(connectorsOnly, "ELASTIC-20").status, "pass", "a confirmed unlicensed Watcher is an absence, not missing evidence");
  assert.match(findingById(connectorsOnly, "ELASTIC-20").summary, /Watcher is not available on the basic license, so only Kibana connectors were assessed/);
  assert.equal(findingById(connectorsOnly, "ELASTIC-20").evidence.watcher_not_applicable, true);

  const auditUnlicensed = await assessElasticClusterHardening(stubClient(unlicensedWatcher));
  assert.equal(findingById(auditUnlicensed, "ELASTIC-11").status, "fail");
  assert.match(findingById(auditUnlicensed, "ELASTIC-11").summary, /basic license \(status active\) does not include audit logging/);
});

test("verdict rule 4: items without dates are bucketed separately, reported, and cap the verdict at warn", async () => {
  const now = Date.now();
  const fixtures = healthyFixtures(now);
  fixtures.spaces = [fixtures.spaces[0]];

  const undatedKey = { ...fixtures.apiKeys[0], id: "key-undated", name: "undated", creation: undefined, expiration: now + 5 * DAY_MS };
  const keys = await assessElasticIdentity(stubClient({ ...fixtures, apiKeys: [fixtures.apiKeys[0], undatedKey] }), { maxApiKeyAgeDays: 90 });
  const hygiene = findingById(keys, "ELASTIC-09");
  assert.equal(hygiene.status, "warn");
  assert.match(hygiene.summary, /1 active key\(s\) report no creation date and are not counted as fresh/);
  assert.equal(hygiene.evidence.missing_creation_date.length, 1);
  assert.equal(hygiene.evidence.missing_creation_date[0].name, "undated");
  assert.equal(hygiene.evidence.older_than_max_age, 0, "an undated key is never counted as stale or fresh");

  const certs = await assessElasticTransportSecurity(stubClient({
    ...fixtures,
    sslCertificates: [fixtures.sslCertificates[0], { path: "certs/ca.pem", alias: null, subject_dn: "CN=ca", has_private_key: false }],
  }));
  const certFinding = findingById(certs, "ELASTIC-05");
  assert.equal(certFinding.status, "warn");
  assert.match(certFinding.summary, /1 report no expiry date \(not counted as valid\)/);
  assert.equal(certFinding.evidence.missing_expiry, 1);

  const slm = await assessElasticClusterHardening(stubClient({
    ...fixtures,
    slmPolicies: { nightly: { ...fixtures.slmPolicies.nightly, last_success: undefined } },
  }));
  assert.equal(findingById(slm, "ELASTIC-18").status, "warn");
  assert.match(findingById(slm, "ELASTIC-18").summary, /1\/1 SLM policies report no last_success time .* not counted as working backups/);

  const licenseNoExpiry = await assessElasticClusterHardening(stubClient({
    ...fixtures,
    license: { license: { status: "active", type: "platinum", uid: "lic-2" } },
  }));
  assert.equal(findingById(licenseNoExpiry, "ELASTIC-23").status, "warn", "an undated license is never counted as valid");
  assert.match(findingById(licenseNoExpiry, "ELASTIC-23").summary, /platinum license is active but reports no expiry date/);
  assert.equal(findingById(licenseNoExpiry, "ELASTIC-23").evidence.expiry_missing, true);
  const goldNoExpiry = await assessElasticClusterHardening(stubClient({
    ...fixtures,
    license: { license: { status: "active", type: "gold", uid: "lic-2b" } },
  }));
  assert.equal(findingById(goldNoExpiry, "ELASTIC-23").status, "fail", "a missing expiry never masks a coverage failure on a lower tier");
  assert.match(findingById(goldNoExpiry, "ELASTIC-23").summary, /gold license does not cover configured features/);
  assert.equal(findingById(goldNoExpiry, "ELASTIC-23").evidence.expiry_missing, true);
  const licenseNoStatus = await assessElasticClusterHardening(stubClient({
    ...fixtures,
    license: { license: { type: "platinum", uid: "lic-3", expiry_date_in_millis: now + 400 * DAY_MS } },
  }));
  assert.equal(findingById(licenseNoStatus, "ELASTIC-23").status, "warn");
  assert.match(findingById(licenseNoStatus, "ELASTIC-23").summary, /reports no status field/);
});

test("verdict rule 5: partial inventories are flagged with seen and total counts instead of passing", async () => {
  const now = Date.now();
  const fixtures = healthyFixtures(now);

  const ownKeysOnly = await assessElasticIdentity(stubClient({
    ...fixtures,
    hasPrivileges: { ...fixtures.hasPrivileges, cluster: { ...fixtures.hasPrivileges.cluster, read_security: false, manage_api_key: false, manage_security: false } },
  }));
  for (const id of ["ELASTIC-09", "ELASTIC-10"]) {
    const item = findingById(ownKeysOnly, id);
    assert.equal(item.status, "warn", `${id} must not pass on the caller's own keys`);
    assert.match(item.summary, /Verdict is capped at warn because the inventory is partial: the credential lacks read_security, manage_api_key, and manage_security, so POST \/_security\/_query\/api_key returns only its own keys \(1 seen of an unknown total\)/);
    assert.equal(item.evidence.full_visibility, false);
  }

  const truncatedKeys = await assessElasticIdentity(stubClient(fixtures, {
    listApiKeys: async () => pagedList(Array.from({ length: 100 }, (_, index) => ({ ...fixtures.apiKeys[0], id: `k${index}`, _sort: [index, `k${index}`] })), 250, true),
  }));
  const truncated = findingById(truncatedKeys, "ELASTIC-09");
  assert.equal(truncated.status, "warn");
  assert.match(truncated.summary, /100 key\(s\) seen of 250 total/);
  assert.match(truncated.summary, /api_keys is truncated \(100 of 250 seen across 1 page\(s\); raise the collection limit\)/);
  assert.equal(truncated.evidence.total_reported, 250);
  assert.equal(findingById(truncatedKeys, "ELASTIC-10").status, "warn");

  const partialNodes = healthyFixtures(now);
  partialNodes.nodeSettings._nodes = { total: 3, successful: 1, failed: 2 };
  const identity = await assessElasticIdentity(stubClient(partialNodes));
  assert.equal(findingById(identity, "ELASTIC-01").status, "warn");
  assert.match(findingById(identity, "ELASTIC-01").summary, /node_settings covers 1 of 3 nodes \(2 failed to respond\)/);
  assert.equal(findingById(identity, "ELASTIC-14").status, "warn");
  const transport = await assessElasticTransportSecurity(stubClient(partialNodes));
  assert.deepEqual(statusMap(transport), { "ELASTIC-02": "warn", "ELASTIC-03": "warn", "ELASTIC-04": "warn", "ELASTIC-05": "warn" });
  assert.match(findingById(transport, "ELASTIC-05").summary, /GET \/_ssl\/certificates reports only the node that handled the request, but the cluster has 3 nodes/);
  const hardening = await assessElasticClusterHardening(stubClient(partialNodes));
  assert.equal(findingById(hardening, "ELASTIC-11").status, "warn");
  assert.equal(findingById(hardening, "ELASTIC-19").status, "warn");
  assert.equal(findingById(hardening, "ELASTIC-23").status, "warn");

  const multiSpace = await assessElasticClusterHardening(stubClient(fixtures));
  assert.equal(findingById(multiSpace, "ELASTIC-20").status, "warn");
  assert.match(findingById(multiSpace, "ELASTIC-20").summary, /read from the default space only; 1 other space\(s\) exist \(security-team\), so set space_id to inspect each/);
  const spacesUnreadable = await assessElasticClusterHardening(stubClient({ ...fixtures, spaces: [fixtures.spaces[0]] }, { listSpaces: forbidden("GET /api/spaces/space failed (403 Forbidden)") }));
  assert.equal(findingById(spacesUnreadable, "ELASTIC-20").status, "warn");
  assert.match(findingById(spacesUnreadable, "ELASTIC-20").summary, /space list could not be read/);

  const truncatedFleet = await assessElasticKibana(stubClient(fixtures, {
    listAgentPolicies: async () => pagedList(Array.from({ length: 100 }, (_, index) => ({ id: `p${index}`, name: `Policy ${index}`, is_protected: true })), 340, true),
  }));
  assert.equal(findingById(truncatedFleet, "ELASTIC-21").status, "warn");
  assert.match(findingById(truncatedFleet, "ELASTIC-21").summary, /fleet_agent_policies is truncated \(100 of 340 seen/);

  const truncatedWatches = await assessElasticClusterHardening(stubClient({ ...fixtures, spaces: [fixtures.spaces[0]] }, {
    listWatches: async () => pagedList(Array.from({ length: 100 }, (_, index) => ({ ...fixtures.watches[0], _id: `w${index}` })), 500, true),
  }));
  assert.equal(findingById(truncatedWatches, "ELASTIC-20").status, "warn");
  assert.match(findingById(truncatedWatches, "ELASTIC-20").summary, /watches is truncated \(100 of 500 seen/);
});

test("verdict rule 6: every enabling flag is read, absent or false flags never support pass, and settings precedence is honored", async () => {
  const now = Date.now();

  const noFlag = withoutSecurityFlag(healthyFixtures(now));
  noFlag.spaces = [noFlag.spaces[0]];
  const identity = await assessElasticIdentity(stubClient(noFlag));
  assert.equal(findingById(identity, "ELASTIC-01").status, "warn");
  assert.match(findingById(identity, "ELASTIC-01").summary, /xpack.security.enabled was not visible/);
  assert.equal(findingById(identity, "ELASTIC-14").status, "warn");
  assert.match(findingById(identity, "ELASTIC-14").summary, /could not be confirmed disabled/);
  assert.equal(findingById(identity, "ELASTIC-13").status, "warn");
  const transport = await assessElasticTransportSecurity(stubClient(noFlag));
  assert.equal(findingById(transport, "ELASTIC-02").status, "warn");
  assert.match(findingById(transport, "ELASTIC-02").summary, /xpack.security.enabled was not visible/);
  assert.equal(findingById(transport, "ELASTIC-03").status, "warn");
  assert.equal(findingById(transport, "ELASTIC-04").status, "warn");
  const hardening = await assessElasticClusterHardening(stubClient(noFlag));
  assert.equal(findingById(hardening, "ELASTIC-19").status, "warn");
  assert.match(findingById(hardening, "ELASTIC-19").summary, /xpack.security.enabled was not visible in node settings, cluster settings, usage statistics, or xpack info/);
  assert.equal(findingById(hardening, "ELASTIC-11").status, "warn");

  const unsetTls = healthyFixtures(now);
  delete unsetTls.nodeSettings.nodes["node-1"].settings["xpack.security.transport.ssl.enabled"];
  const unsetTlsResult = await assessElasticTransportSecurity(stubClient(unsetTls));
  assert.equal(findingById(unsetTlsResult, "ELASTIC-02").status, "warn", "usage statistics alone cannot prove transport TLS when the setting is unset");
  assert.match(findingById(unsetTlsResult, "ELASTIC-02").summary, /not explicitly set on es-1 \(the documented default is false\) and usage statistics report it enabled/);

  const noVerification = healthyFixtures(now);
  noVerification.nodeSettings.nodes["node-1"].settings["xpack.security.transport.ssl.verification_mode"] = "none";
  const noVerificationResult = await assessElasticTransportSecurity(stubClient(noVerification));
  assert.equal(findingById(noVerificationResult, "ELASTIC-02").status, "warn");
  assert.match(findingById(noVerificationResult, "ELASTIC-02").summary, /verification_mode is none on es-1/);

  const noAudit = healthyFixtures(now);
  delete noAudit.nodeSettings.nodes["node-1"].settings["xpack.security.audit.enabled"];
  const noAuditResult = await assessElasticClusterHardening(stubClient(noAudit));
  assert.equal(findingById(noAuditResult, "ELASTIC-11").status, "fail");
  assert.match(findingById(noAuditResult, "ELASTIC-11").summary, /not true in transient or persistent cluster settings or on any inspected node \(the documented default is false\)/);
  assert.equal(findingById(noAuditResult, "ELASTIC-12").status, "fail");

  const disabledRealm = healthyFixtures(now);
  disabledRealm.nodeSettings.nodes["node-1"].settings["xpack.security.authc.realms.saml.corp_sso.enabled"] = "false";
  const disabledRealmResult = await assessElasticIdentity(stubClient(disabledRealm));
  assert.equal(findingById(disabledRealmResult, "ELASTIC-01").status, "fail", "a disabled realm does not count as enabled");
  assert.deepEqual(findingById(disabledRealmResult, "ELASTIC-01").evidence.realms.find((realm) => realm.name === "corp_sso").enabled, false);
  assert.equal(findingById(disabledRealmResult, "ELASTIC-13").status, "manual");

  const expiredLicense = healthyFixtures(now);
  expiredLicense.license.license.status = "expired";
  const expiredIdentity = await assessElasticIdentity(stubClient(expiredLicense));
  assert.equal(findingById(expiredIdentity, "ELASTIC-13").status, "fail");
  assert.match(findingById(expiredIdentity, "ELASTIC-13").summary, /platinum license \(status expired\) does not include SAML\/OIDC/);
  const expiredAccess = await assessElasticAccessControl(stubClient(expiredLicense), { sensitiveIndexPatterns: ["customers-*"] });
  assert.equal(findingById(expiredAccess, "ELASTIC-07").status, "fail");
  const expiredHardening = await assessElasticClusterHardening(stubClient(expiredLicense));
  assert.equal(findingById(expiredHardening, "ELASTIC-23").status, "fail");
  assert.match(findingById(expiredHardening, "ELASTIC-23").summary, /license status is expired/);
  assert.equal(findingById(expiredHardening, "ELASTIC-11").status, "fail", "audit logging on an inactive license produces no audit trail");

  const precedence = healthyFixtures(now);
  precedence.spaces = [precedence.spaces[0]];
  precedence.clusterSettings.defaults["xpack.security.enabled"] = "false";
  precedence.clusterSettings.persistent["xpack.security.authc.anonymous.roles"] = ["viewer"];
  precedence.clusterSettings.transient["xpack.security.authc.anonymous.roles"] = ["superuser"];
  const precedenceHardening = await assessElasticClusterHardening(stubClient(precedence));
  assert.equal(findingById(precedenceHardening, "ELASTIC-19").status, "pass", "node-level true overrides the defaults section");
  assert.equal(findingById(precedenceHardening, "ELASTIC-19").evidence.security_enabled_source, "cluster or node settings");
  const precedenceIdentity = await assessElasticIdentity(stubClient(precedence));
  assert.equal(findingById(precedenceIdentity, "ELASTIC-14").status, "fail", "transient settings override persistent settings");
  assert.deepEqual(findingById(precedenceIdentity, "ELASTIC-14").evidence.anonymous_roles, ["superuser"]);

  const unflaggedPolicy = healthyFixtures(now);
  unflaggedPolicy.agentPolicies = [{ id: "policy-1", name: "Legacy" }];
  const unflaggedResult = await assessElasticKibana(stubClient(unflaggedPolicy));
  assert.equal(findingById(unflaggedResult, "ELASTIC-21").status, "warn");
  assert.match(findingById(unflaggedResult, "ELASTIC-21").summary, /lack tamper protection \(is_protected is not true\)/);
});

test("false-pass self-check (a): every endpoint forbidden yields only manual verdicts across all five assess tools", async () => {
  const fixtures = healthyFixtures();
  const runs = [
    ["identity", assessElasticIdentity],
    ["access_control", assessElasticAccessControl],
    ["transport_security", assessElasticTransportSecurity],
    ["cluster_hardening", assessElasticClusterHardening],
    ["kibana", assessElasticKibana],
  ];
  const withKibana = forbiddenEverywhere(fixtures);
  const withoutKibana = forbiddenEverywhere(fixtures, { kibanaUrl: undefined });
  const seen = new Set();
  for (const [area, assess] of runs) {
    for (const client of [withKibana, withoutKibana]) {
      const result = await assess(client);
      assert.equal(result.area, area);
      if (client === withoutKibana && area === "kibana") {
        assert.equal(result.errors.length, 0, "an unconfigured Kibana is scoped out, not requested");
        assert.ok(result.findings.every((item) => /Scoped out: Kibana is not configured/.test(item.summary)), "kibana findings must say the area was scoped out");
      } else {
        assert.ok(result.errors.length > 0, `${area} should record collection errors`);
      }
      for (const item of result.findings) {
        seen.add(item.id);
        assert.equal(item.status, "manual", `${item.id} must be manual when every endpoint is forbidden, got ${item.status}: ${item.summary}`);
        assert.match(item.summary, /Collect manually:/, `${item.id} must tell the reviewer what to collect`);
        assert.match(item.summary, /403 Forbidden|Scoped out|Not applicable|could not be read|not configured/, `${item.id} must name the cause`);
        assert.ok(item.evidence.manual_evidence, `${item.id} must carry manual_evidence`);
      }
    }
  }
  assert.equal(seen.size, 23, "the self-check exercised every control");

  const bundleFindings = await assessAll(withKibana);
  assert.equal(bundleFindings.length, 23);
  assert.ok(bundleFindings.every((item) => item.status === "manual"));
});

test("false-pass self-check (b): empty inventories pass only where the control's intent makes emptiness compliant", async () => {
  const findings = await assessAll(stubClient(emptyInventoryFixtures()));
  assert.equal(findings.length, 23);
  const statuses = Object.fromEntries(findings.map((item) => [item.id, item.status]));

  const settingsOrLicenseBased = ["ELASTIC-01", "ELASTIC-02", "ELASTIC-03", "ELASTIC-04", "ELASTIC-11", "ELASTIC-19", "ELASTIC-23"];
  const compliantWhenEmpty = ["ELASTIC-09", "ELASTIC-10", "ELASTIC-14"];
  const passing = Object.entries(statuses).filter(([, status]) => status === "pass").map(([id]) => id).sort();
  assert.deepEqual(passing, [...settingsOrLicenseBased, ...compliantWhenEmpty].sort(), `unexpected pass set: ${JSON.stringify(statuses)}`);
  for (const id of compliantWhenEmpty) {
    const item = findings.find((entry) => entry.id === id);
    assert.match(item.summary, /empty inventory is compliant|absence of anonymous roles is the compliant state/, `${id} must state why emptiness passes`);
  }
  for (const id of settingsOrLicenseBased) {
    const item = findings.find((entry) => entry.id === id);
    assert.ok(!/inventory|zero|empty/i.test(item.summary) || /license/i.test(item.summary), `${id} pass must not rest on an empty inventory: ${item.summary}`);
  }

  assert.deepEqual(
    Object.fromEntries(Object.entries(statuses).filter(([id]) => ![...settingsOrLicenseBased, ...compliantWhenEmpty].includes(id))),
    {
      "ELASTIC-05": "manual",
      "ELASTIC-06": "manual",
      "ELASTIC-07": "manual",
      "ELASTIC-08": "manual",
      "ELASTIC-12": "manual",
      "ELASTIC-13": "fail",
      "ELASTIC-15": "manual",
      "ELASTIC-16": "manual",
      "ELASTIC-17": "fail",
      "ELASTIC-18": "fail",
      "ELASTIC-20": "manual",
      "ELASTIC-21": "manual",
      "ELASTIC-22": "manual",
    },
  );
});

test("false-pass self-check (c): capped, truncated, or privilege-limited inventories never pass in any assess tool", async () => {
  const now = Date.now();
  const partial = healthyFixtures(now);
  partial.nodeSettings._nodes = { total: 3, successful: 1, failed: 2 };
  partial.hasPrivileges = { ...partial.hasPrivileges, cluster: { ...partial.hasPrivileges.cluster, read_security: false, manage_api_key: false, manage_security: false } };
  const truncatedKeys = pagedList(Array.from({ length: 100 }, (_, index) => ({ ...partial.apiKeys[0], id: `k${index}`, _sort: [index, `k${index}`] })), 250, true);
  const truncatedWatches = pagedList(Array.from({ length: 100 }, (_, index) => ({ ...partial.watches[0], _id: `w${index}` })), 500, true);
  const truncatedPolicies = pagedList(Array.from({ length: 100 }, (_, index) => ({ id: `p${index}`, name: `Policy ${index}`, is_protected: true })), 340, true);
  const truncatedRules = pagedList(Array.from({ length: 100 }, (_, index) => ({ id: `r${index}`, actions: [] })), 1200, true);

  const identity = await assessElasticIdentity(stubClient(partial, { listApiKeys: async () => truncatedKeys }));
  const accessControl = await assessElasticAccessControl(stubClient(partial, {
    listRoleMappings: forbidden("GET /_security/role_mapping failed (403 Forbidden): read_security missing"),
    getLicense: forbidden("GET /_license failed (403 Forbidden): monitor missing"),
  }), { sensitiveIndexPatterns: ["customers-*"], tenantIndexPatterns: ["tenant-*"] });
  const transport = await assessElasticTransportSecurity(stubClient(partial));
  const hardening = await assessElasticClusterHardening(stubClient(partial, {
    listWatches: async () => truncatedWatches,
    listAlertingRules: async () => truncatedRules,
    getIlmStatus: forbidden("GET /_ilm/status failed (403 Forbidden): read_ilm missing"),
    getSlmStatus: forbidden("GET /_slm/status failed (403 Forbidden): read_slm missing"),
    listIngestPipelines: forbidden("GET /_ingest/pipeline failed (403 Forbidden): read_pipeline missing"),
  }));
  const kibana = await assessElasticKibana(stubClient(partial, {
    listAgentPolicies: async () => truncatedPolicies,
    listKibanaRoles: forbidden("GET /api/security/role failed (403 Forbidden): manage_security missing"),
  }));

  const all = [identity, accessControl, transport, hardening, kibana].flatMap((result) => result.findings);
  assert.equal(all.length, 23);
  for (const item of all) {
    assert.notEqual(item.status, "pass", `${item.id} passed on a partial inventory: ${item.summary}`);
  }
  assert.deepEqual(statusMap(identity), { "ELASTIC-01": "warn", "ELASTIC-09": "warn", "ELASTIC-10": "warn", "ELASTIC-13": "warn", "ELASTIC-14": "warn" });
  assert.deepEqual(statusMap(accessControl), { "ELASTIC-06": "manual", "ELASTIC-07": "manual", "ELASTIC-08": "manual" });
  assert.deepEqual(statusMap(transport), { "ELASTIC-02": "warn", "ELASTIC-03": "warn", "ELASTIC-04": "warn", "ELASTIC-05": "warn" });
  assert.deepEqual(statusMap(hardening), {
    "ELASTIC-11": "warn",
    "ELASTIC-12": "manual",
    "ELASTIC-17": "manual",
    "ELASTIC-18": "manual",
    "ELASTIC-19": "warn",
    "ELASTIC-20": "warn",
    "ELASTIC-22": "manual",
    "ELASTIC-23": "warn",
  });
  assert.deepEqual(statusMap(kibana), { "ELASTIC-15": "manual", "ELASTIC-16": "manual", "ELASTIC-21": "warn" });
  for (const item of all.filter((entry) => entry.status === "warn")) {
    assert.ok(
      (item.evidence.partial_sources ?? []).length > 0 || /seen|truncated|only|not visible|reports only/.test(item.summary),
      `${item.id} warn must explain the partial view: ${item.summary}`,
    );
  }
});

test("review fix 1: ELASTIC-04 warns when supported_protocols is unset on an 8.x node and names the documented default", async () => {
  const documentedDefault = "TLSv1.3,TLSv1.2,TLSv1.1 (TLSv1.2,TLSv1.1 when the JVM lacks TLSv1.3)";

  const httpUnset = healthyFixtures();
  delete httpUnset.nodeSettings.nodes["node-1"].settings["xpack.security.http.ssl.supported_protocols"];
  const httpResult = await assessElasticTransportSecurity(stubClient(httpUnset));
  const httpFinding = findingById(httpResult, "ELASTIC-04");
  assert.equal(httpFinding.status, "warn", "an unset supported_protocols on an 8.x node must not pass");
  assert.match(httpFinding.summary, /supported_protocols is not explicitly set on es-1 \(http layer\)/);
  assert.match(httpFinding.summary, /the documented default is TLSv1\.3,TLSv1\.2,TLSv1\.1 \(TLSv1\.2,TLSv1\.1 when the JVM lacks TLSv1\.3\), which permits TLSv1\.1/);
  assert.deepEqual(httpFinding.evidence.unset_supported_protocols, [{ node: "es-1", unset_keys: ["xpack.security.http.ssl.supported_protocols"] }]);
  assert.equal(httpFinding.evidence.documented_default, documentedDefault);
  assert.deepEqual(httpFinding.evidence.node_major_versions, [8]);
  assert.deepEqual(httpFinding.evidence.weak_protocols, []);

  const bothUnset = healthyFixtures();
  delete bothUnset.nodeSettings.nodes["node-1"].settings["xpack.security.http.ssl.supported_protocols"];
  delete bothUnset.nodeSettings.nodes["node-1"].settings["xpack.security.transport.ssl.supported_protocols"];
  const bothResult = await assessElasticTransportSecurity(stubClient(bothUnset));
  assert.equal(findingById(bothResult, "ELASTIC-04").status, "warn");
  assert.match(findingById(bothResult, "ELASTIC-04").summary, /es-1 \(transport and http layer\)/);
  assert.ok(!/8\.x/.test(findingById(bothResult, "ELASTIC-04").summary), "the verdict must not rest on the node major version");

  const legacy = healthyFixtures();
  legacy.nodeSettings.nodes["node-1"].version = "7.17.0";
  delete legacy.nodeSettings.nodes["node-1"].settings["xpack.security.http.ssl.supported_protocols"];
  const legacyResult = await assessElasticTransportSecurity(stubClient(legacy));
  assert.equal(findingById(legacyResult, "ELASTIC-04").status, "warn");
  assert.equal(findingById(legacyResult, "ELASTIC-04").summary, httpFinding.summary, "7.x and 8.x produce the same verdict and wording for an unset value");

  const explicit = await assessElasticTransportSecurity(stubClient(healthyFixtures()));
  assert.equal(findingById(explicit, "ELASTIC-04").status, "pass");
  assert.match(findingById(explicit, "ELASTIC-04").summary, /explicitly restricted to TLSv1\.3, TLSv1\.2 on both layers of all 1 node\(s\)/);
  assert.deepEqual(findingById(explicit, "ELASTIC-04").evidence.unset_supported_protocols, []);
});

test("review fix 2: a license reporting status valid is treated as active alongside active", async () => {
  const now = Date.now();
  const valid = healthyFixtures(now);
  valid.spaces = [valid.spaces[0]];
  valid.license.license.status = "valid";

  const hardening = await assessElasticClusterHardening(stubClient(valid));
  assert.equal(findingById(hardening, "ELASTIC-23").status, "pass", "a valid platinum license must not fail as inactive");
  assert.match(findingById(hardening, "ELASTIC-23").summary, /platinum license is active/);
  assert.equal(findingById(hardening, "ELASTIC-23").evidence.status, "valid");
  assert.equal(findingById(hardening, "ELASTIC-11").status, "pass");
  assert.equal(findingById(hardening, "ELASTIC-11").evidence.license_supports_audit, true);
  const identity = await assessElasticIdentity(stubClient(valid));
  assert.equal(findingById(identity, "ELASTIC-13").status, "pass");
  const access = await assessElasticAccessControl(stubClient(valid), { sensitiveIndexPatterns: ["customers-*"], tenantIndexPatterns: ["tenant-*"] });
  assert.equal(findingById(access, "ELASTIC-07").status, "pass");
  assert.equal(findingById(access, "ELASTIC-07").evidence.license_supports_feature, true);
  assert.equal(findingById(access, "ELASTIC-08").status, "pass");
  assert.equal(hardening.summary.license_status, "valid");

  for (const status of ["invalid", "expired"]) {
    const inactive = healthyFixtures(now);
    inactive.license.license.status = status;
    const inactiveHardening = await assessElasticClusterHardening(stubClient(inactive));
    assert.equal(findingById(inactiveHardening, "ELASTIC-23").status, "fail", `${status} is not an active status`);
    assert.match(findingById(inactiveHardening, "ELASTIC-23").summary, new RegExp(`license status is ${status}`));
    assert.equal(findingById(inactiveHardening, "ELASTIC-11").status, "fail");
  }

  const upper = healthyFixtures(now);
  upper.license.license.status = "VALID";
  assert.equal(findingById(await assessElasticClusterHardening(stubClient(upper)), "ELASTIC-23").status, "pass", "status comparison is case-insensitive");
});

test("review fix 3: xpack.security.audit.enabled honors transient and persistent cluster settings over node settings", async () => {
  const persistentOnly = healthyFixtures();
  delete persistentOnly.nodeSettings.nodes["node-1"].settings["xpack.security.audit.enabled"];
  persistentOnly.clusterSettings.persistent["xpack.security.audit.enabled"] = "true";
  const persistentResult = await assessElasticClusterHardening(stubClient(persistentOnly));
  const persistentFinding = findingById(persistentResult, "ELASTIC-11");
  assert.equal(persistentFinding.status, "pass", "a persistent-only enablement is a valid runtime enablement");
  assert.match(persistentFinding.summary, /enabled on all 1 node\(s\) via persistent cluster settings/);
  assert.equal(persistentFinding.evidence.setting, "xpack.security.audit.enabled");
  assert.equal(persistentFinding.evidence.cluster_level_value, true);
  assert.equal(persistentFinding.evidence.cluster_level_source, "persistent");
  assert.deepEqual(persistentFinding.evidence.per_node, [{ node: "es-1", node_value: null, effective: true, source: "persistent cluster settings" }]);
  assert.deepEqual(persistentFinding.evidence.enabled_nodes, ["es-1"]);
  assert.equal(findingById(persistentResult, "ELASTIC-12").status, "manual", "audit output stays a manual item, not a fail, when auditing is enabled at the cluster level");

  const transientOverride = healthyFixtures();
  transientOverride.clusterSettings.persistent["xpack.security.audit.enabled"] = "true";
  transientOverride.clusterSettings.transient["xpack.security.audit.enabled"] = "false";
  const transientResult = await assessElasticClusterHardening(stubClient(transientOverride));
  const transientFinding = findingById(transientResult, "ELASTIC-11");
  assert.equal(transientFinding.status, "fail", "a transient false overrides both persistent and elasticsearch.yml true");
  assert.match(transientFinding.summary, /is false in transient cluster settings, which overrides elasticsearch\.yml on every node/);
  assert.equal(transientFinding.evidence.cluster_level_source, "transient");
  assert.deepEqual(transientFinding.evidence.per_node, [{ node: "es-1", node_value: true, effective: false, source: "transient cluster settings" }]);
  assert.equal(findingById(transientResult, "ELASTIC-12").status, "fail");

  const mixed = healthyFixtures();
  mixed.nodeSettings._nodes = { total: 2, successful: 2, failed: 0 };
  mixed.nodeSettings.nodes["node-2"] = {
    name: "es-2",
    version: "8.15.0",
    settings: Object.fromEntries(Object.entries(mixed.nodeSettings.nodes["node-1"].settings).filter(([key]) => key !== "xpack.security.audit.enabled")),
  };
  const mixedResult = await assessElasticClusterHardening(stubClient(mixed));
  const mixedFinding = findingById(mixedResult, "ELASTIC-11");
  assert.equal(mixedFinding.status, "fail");
  assert.match(mixedFinding.summary, /enabled on es-1 but disabled or unset on es-2/);
  assert.deepEqual(mixedFinding.evidence.per_node, [
    { node: "es-1", node_value: true, effective: true, source: "node settings" },
    { node: "es-2", node_value: null, effective: null, source: "unset" },
  ]);

  const defaultsOnly = healthyFixtures();
  delete defaultsOnly.nodeSettings.nodes["node-1"].settings["xpack.security.audit.enabled"];
  defaultsOnly.clusterSettings.defaults["xpack.security.audit.enabled"] = "false";
  const defaultsFinding = findingById(await assessElasticClusterHardening(stubClient(defaultsOnly)), "ELASTIC-11");
  assert.equal(defaultsFinding.status, "fail");
  assert.deepEqual(defaultsFinding.evidence.per_node, [{ node: "es-1", node_value: null, effective: false, source: "cluster defaults" }]);
});

test("review fix 4: FLS and DLS usage flags are read as the documented booleans", async () => {
  const fixtures = healthyFixtures();
  fixtures.xpackUsage.security.roles = { native: { size: 4, fls: true, dls: false }, file: { size: 1, fls: false, dls: true } };
  const result = await assessElasticAccessControl(stubClient(fixtures), { sensitiveIndexPatterns: ["customers-*"], tenantIndexPatterns: ["tenant-*"] });
  const fls = findingById(result, "ELASTIC-07");
  const dls = findingById(result, "ELASTIC-08");
  assert.deepEqual(fls.evidence.usage_reports_in_use, { native_roles: true, file_roles: false });
  assert.deepEqual(dls.evidence.usage_reports_in_use, { native_roles: false, file_roles: true });
  assert.equal("usage_count" in fls.evidence, false, "the numeric usage_count field no longer exists");
  assert.equal("usage_count" in dls.evidence, false);

  const numericShape = healthyFixtures();
  numericShape.xpackUsage.security.roles = { native: { size: 4, fls: 1, dls: 1 } };
  const numericResult = await assessElasticAccessControl(stubClient(numericShape));
  assert.deepEqual(findingById(numericResult, "ELASTIC-07").evidence.usage_reports_in_use, { native_roles: null, file_roles: null }, "non-boolean values are not coerced into a verdict input");

  const missing = healthyFixtures();
  delete missing.xpackUsage.security.roles;
  assert.deepEqual(findingById(await assessElasticAccessControl(stubClient(missing)), "ELASTIC-08").evidence.usage_reports_in_use, { native_roles: null, file_roles: null });
});

test("review fix 5: the default audit include list contains access_granted and matches the documented nine events", async () => {
  const documentedDefault = [
    "access_denied",
    "access_granted",
    "anonymous_access_denied",
    "authentication_failed",
    "connection_denied",
    "tampered_request",
    "run_as_denied",
    "run_as_granted",
    "security_config_change",
  ];

  const defaults = healthyFixtures();
  delete defaults.nodeSettings.nodes["node-1"].settings["xpack.security.audit.logfile.events.include"];
  const defaultsFinding = findingById(await assessElasticClusterHardening(stubClient(defaults)), "ELASTIC-11");
  assert.equal(defaultsFinding.status, "pass");
  assert.deepEqual(defaultsFinding.evidence.events_include, []);
  assert.deepEqual(defaultsFinding.evidence.effective_include, documentedDefault);
  assert.deepEqual(defaultsFinding.evidence.missing_required_events, []);

  const excluded = healthyFixtures();
  delete excluded.nodeSettings.nodes["node-1"].settings["xpack.security.audit.logfile.events.include"];
  excluded.nodeSettings.nodes["node-1"].settings["xpack.security.audit.logfile.events.exclude"] = ["access_granted", "run_as_granted"];
  const excludedFinding = findingById(await assessElasticClusterHardening(stubClient(excluded)), "ELASTIC-11");
  assert.equal(excludedFinding.status, "pass", "excluding access_granted does not remove a required event");
  assert.deepEqual(excludedFinding.evidence.effective_include, documentedDefault.filter((event) => event !== "access_granted" && event !== "run_as_granted"));

  const explicit = findingById(await assessElasticClusterHardening(stubClient(healthyFixtures())), "ELASTIC-11");
  assert.deepEqual(explicit.evidence.effective_include, ["access_denied", "authentication_failed", "security_config_change", "run_as_denied"], "an explicit include list replaces the default rather than merging with it");
});

test("review fix 6: listFleetServerHosts sends no query parameters and reads items and total from the response", async () => {
  const seen = [];
  const hosts = Array.from({ length: 3 }, (_, index) => ({ id: `host-${index + 1}`, host_urls: [`https://fleet-${index + 1}.example.com:8220`] }));
  const client = new ElasticApiClient(sampleConfig(), {
    fetchImpl: createRouter({
      "GET /api/fleet/fleet_server_hosts": () => ({ items: hosts, total: hosts.length, page: 1, perPage: 20 }),
    }, seen),
  });

  const complete = await client.listFleetServerHosts();
  assert.equal(seen.length, 1);
  assert.equal(seen[0].pathname, "/api/fleet/fleet_server_hosts");
  assert.equal(seen[0].search, "", "GET /api/fleet/fleet_server_hosts documents no query parameters");
  assert.deepEqual({ seen: complete.seen, total: complete.total, pages: complete.pages, truncated: complete.truncated }, { seen: 3, total: 3, pages: 1, truncated: false });
  assert.deepEqual(complete.items.map((item) => item.id), ["host-1", "host-2", "host-3"]);

  const capped = await client.listFleetServerHosts(2);
  assert.equal(seen[1].search, "", "the collection cap is applied client-side, not sent as a parameter");
  assert.deepEqual({ seen: capped.seen, total: capped.total, truncated: capped.truncated }, { seen: 2, total: 3, truncated: true });

  const serverTotal = new ElasticApiClient(sampleConfig(), {
    fetchImpl: createRouter({ "GET /api/fleet/fleet_server_hosts": () => ({ items: hosts.slice(0, 2), total: 5, page: 1, perPage: 2 }) }),
  });
  const partial = await serverTotal.listFleetServerHosts();
  assert.deepEqual({ seen: partial.seen, total: partial.total, truncated: partial.truncated }, { seen: 2, total: 5, truncated: true }, "a server total above the returned items records truncation");

  const noTotal = new ElasticApiClient(sampleConfig(), {
    fetchImpl: createRouter({ "GET /api/fleet/fleet_server_hosts": () => ({ items: hosts }) }),
  });
  const inferred = await noTotal.listFleetServerHosts();
  assert.deepEqual({ seen: inferred.seen, total: inferred.total, truncated: inferred.truncated }, { seen: 3, total: 3, truncated: false });

  const snapshot = await collectElasticSnapshot(client, ["fleet_server_hosts"], { kibanaLimit: 2 });
  assert.deepEqual(snapshot.fleet_server_hosts.page, { seen: 2, total: 3, truncated: true, pages: 1 });
});

test("resolveSecureOutputPath rejects traversal and symlinked parents", () => {
  const base = createTempBase("elastic-secure-");
  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, join("..", "..", "etc", "passwd")), /Refusing to write outside/);

  const target = createTempBase("elastic-secure-target-");
  symlinkSync(target, join(base, "linked"));
  assert.throws(() => resolveSecureOutputPath(base, join("linked", "bundle")), /symlinked parent/);

  const safe = resolveSecureOutputPath(base, join("nested", "bundle"));
  assert.ok(safe.startsWith(base));
});

test("registerElasticTools exposes the check, assessment, and export tools with normalized arguments", async () => {
  const registered = [];
  registerElasticTools({ registerTool: (tool) => registered.push(tool) });

  assert.deepEqual(registered.map((tool) => tool.name), [
    "elastic_check_access",
    "elastic_assess_identity",
    "elastic_assess_access_control",
    "elastic_assess_transport_security",
    "elastic_assess_cluster_hardening",
    "elastic_assess_kibana",
    "elastic_export_audit_bundle",
  ]);
  for (const tool of registered) {
    assert.equal(typeof tool.description, "string");
    assert.ok(tool.description.length > 40);
    assert.equal(tool.parameters.type, "object");
    assert.ok(tool.parameters.properties.elasticsearch_url);
    assert.ok(tool.parameters.properties.kibana_url);
    assert.ok(tool.parameters.properties.api_key);
    assert.ok(tool.parameters.properties.username);
    assert.ok(tool.parameters.properties.cloud_api_key);
  }
  const exportTool = registered.find((tool) => tool.name === "elastic_export_audit_bundle");
  assert.ok(exportTool.parameters.properties.output_dir);
  assert.deepEqual(
    exportTool.prepareArguments({ url: "https://es.example.com", sensitive_index_patterns: "a-*, b-*", output: "./out", timeout_seconds: "5" }),
    {
      elasticsearch_url: "https://es.example.com",
      kibana_url: undefined,
      space_id: undefined,
      api_key: undefined,
      username: undefined,
      password: undefined,
      bearer_token: undefined,
      cloud_api_key: undefined,
      cloud_api_url: undefined,
      config_file: undefined,
      timeout_seconds: 5,
      api_key_limit: undefined,
      max_api_key_age_days: undefined,
      max_superusers: undefined,
      sensitive_index_patterns: ["a-*", "b-*"],
      tenant_index_patterns: [],
      cert_expiry_warning_days: undefined,
      watch_limit: undefined,
      kibana_limit: undefined,
      max_enrollment_keys_per_policy: undefined,
      output_dir: "./out",
    },
  );

  const fixtures = healthyFixtures();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = createRouter(healthyRoutes(fixtures));
  // An explicit but missing config path is an error since addendum 6b, so an empty file keeps the home config out of the way.
  const emptyConfig = join(createTempBase("elastic-no-config-"), "empty.yaml");
  writeFileSync(emptyConfig, "", "utf8");
  try {
    const kibanaTool = registered.find((tool) => tool.name === "elastic_assess_kibana");
    const result = await kibanaTool.execute("call-1", kibanaTool.prepareArguments({
      elasticsearch_url: "https://es.example.com:9200",
      kibana_url: "https://kibana.example.com:5601",
      api_key: API_KEY,
      config_file: emptyConfig,
    }));
    assert.equal(result.isError, undefined);
    assert.match(result.content[0].text, /Elastic Kibana governance and Fleet/);
    assert.match(result.content[0].text, /ELASTIC-16/);
    assert.equal(result.details.tool, "elastic_assess_kibana");
    assert.equal(result.details.findings.length, 3);

    const checkTool = registered.find((tool) => tool.name === "elastic_check_access");
    const failure = await checkTool.execute("call-2", checkTool.prepareArguments({
      elasticsearch_url: "https://es.example.com:9200",
      config_file: emptyConfig,
    }));
    assert.equal(failure.isError, true);
    assert.match(failure.content[0].text, /credentials are required/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Elastic tools appear in the tool catalog under the Elastic group", () => {
  const tools = getRegisteredToolSummaries();
  const elasticTools = tools.filter((tool) => tool.name.startsWith("elastic_"));

  assert.deepEqual(elasticTools.map((tool) => tool.name).sort(), [
    "elastic_assess_access_control",
    "elastic_assess_cluster_hardening",
    "elastic_assess_identity",
    "elastic_assess_kibana",
    "elastic_assess_transport_security",
    "elastic_check_access",
    "elastic_export_audit_bundle",
  ]);
  for (const tool of elasticTools) {
    assert.equal(tool.group, "Elastic");
    assert.equal(tool.kind, "domain");
    assert.ok(tool.parameterSummaries.some((parameter) => parameter.name === "elasticsearch_url"));
  }
});

// ---------------------------------------------------------------------------
// Rules 9 and 10, the rule 1 corollary, and the addenda on error strings,
// null rendering, principal gating, collection status, request matching, and
// denied-list markers.
// ---------------------------------------------------------------------------

// Every planted credential is alphanumeric and random-looking; helpers/canary-windows.mjs asserts every 6-to-24-character
// window of each one absent, and the fixture self-check below proves no window occurs in the fixture's own values.
const CANARIES = {
  bearer: "KV3PDsExQn2buYHteENDtKHoF75wU56R",
  cookie: "fc8LS4ZkLg8o2K2ESNUKtMgakj8WsGzL",
  apiKey: "AaB6wvMiGMD7ReAp6tKkmeQD9QWYFmuM",
  urlToken: "TrRpRjXEmKud7cZtPAgpAWkRGDofqgAU",
  jwtHeader: "GXUKHX6WPPhMwBy7ioU2NGJV5v7EzQA4",
  jwtPayload: "gUW9vPruHKyYYnVZMBZs8RJ5zhEKZCsu",
  jwtSignature: "jwsQai2T465DcCfuENuALQ5pL6UPcCxB",
  privateKey: "RH6KajwLmtW4pn5csRcoGWhqC5nM2GFw",
  bindPassword: "csbj7LDHYpDgAsPDECbjN4Gh6iykWaJj",
  connectorSecret: "4DwXTMoA5vB7sAEpZsJQyU7vVXvL5sbF",
  watchPassword: "m8zZdEUbAErhQC8WXbaTYdXutb7uG7zG",
  pipelineLiteral: "8acNmFonH3gV9L5WMe68ZvLDDJDLwQJx",
  enrollmentKey: "e3mNEELYbK9PcGrRFHn4KTRDadLwdn3a",
  outputKey: "2xp33ZaXQ83GeheL5KqCzkZdKRLubJQw",
  headerToken: "t8eA28gPGYmT7Y6c7fXedGwoMyHbavaB",
  urlPath: "4YcuDZFGa9BFBXKWJfQWCEag6MriQbKm",
};
const JWT_CANARY = `eyJ${CANARIES.jwtHeader}.${CANARIES.jwtPayload}.${CANARIES.jwtSignature}`;

function canaryValues() {
  return [...Object.values(CANARIES), JWT_CANARY];
}

function canaryFixtures(now = Date.now()) {
  const fixtures = healthyFixtures(now);
  fixtures.clusterSettings.persistent["xpack.security.authc.realms.ldap.ldap1.bind_password"] = CANARIES.bindPassword;
  fixtures.clusterSettings.persistent["xpack.security.http.ssl.key"] = CANARIES.privateKey;
  fixtures.nodeSettings.nodes["node-1"].settings["xpack.security.transport.ssl.keystore.secure_password"] = CANARIES.privateKey;
  fixtures.connectors = [
    {
      id: "connector-1",
      name: "slack-hook",
      connector_type_id: ".webhook",
      is_missing_secrets: false,
      config: {
        url: `https://hooks.example.com/services/${CANARIES.urlPath}?token=${CANARIES.urlToken}`,
        headers: { Authorization: `Bearer ${CANARIES.headerToken}`, "X-Api-Key": CANARIES.apiKey },
        hasAuth: true,
      },
      secrets: { user: "svc", password: CANARIES.connectorSecret },
    },
  ];
  fixtures.watches = [
    {
      _id: "cpu-alert",
      watch: {
        trigger: { schedule: { interval: "5m" } },
        actions: {
          notify: {
            webhook: {
              scheme: "https",
              host: "hooks.example.com",
              port: 443,
              method: "post",
              path: `/alerts/${CANARIES.urlPath}`,
              params: { token: CANARIES.urlToken },
              headers: { Authorization: `Basic ${CANARIES.headerToken}` },
              auth: { basic: { username: "svc", password: CANARIES.watchPassword } },
              body: `{"token":"${CANARIES.urlToken}"}`,
            },
          },
        },
      },
    },
  ];
  fixtures.ingestPipelines = {
    "logs-enrich": { processors: [{ set: { field: "event.kind", value: "event" } }, { set: { field: "http.request.headers.authorization", value: CANARIES.pipelineLiteral } }] },
    ".fleet_final_pipeline-1": { _meta: { managed: true }, processors: [{ script: { source: "ctx.x = 1" } }] },
  };
  fixtures.enrollmentKeys = [{ id: "enroll-1", active: true, policy_id: "policy-1", api_key_id: "ak-1", api_key: CANARIES.enrollmentKey, name: "Default" }];
  fixtures.fleetOutputs = [
    { id: "default-output", name: "default", type: "elasticsearch", hosts: ["https://es.example.com:9200"], ca_trusted_fingerprint: "abc123", is_default: true, ssl: { certificate: "cert", key: CANARIES.outputKey } },
  ];
  fixtures.apiKeys[0].metadata = { rotation_token: CANARIES.apiKey };
  return fixtures;
}

const HTML_ERROR_BODY = `<html><body><h1>502 Bad Gateway</h1><p>upstream sent Authorization: Bearer ${CANARIES.bearer}; Set-Cookie: session=${CANARIES.cookie}; api_key=${CANARIES.apiKey}; retry at https://api.example.com/v1/x?token=${CANARIES.urlToken} later; jwt ${JWT_CANARY}</p></body></html>`;

function htmlGateway() {
  return () => new Response(HTML_ERROR_BODY, { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html; charset=utf-8" } });
}

function jsonErrorWithUrl() {
  return () => jsonResponse(
    { error: { type: "security_exception", reason: `unauthorized; see https://api.example.com/v1/x?token=${CANARIES.urlToken} for details`, header: { "WWW-Authenticate": `Bearer ${CANARIES.bearer}` } }, status: 403 },
    { status: 403, statusText: "Forbidden" },
  );
}

/**
 * Router that also records the status of every response it served, for request-log assertions.
 * Kibana space prefixes (/s/<space>/api/...) are routed to the unprefixed fixture route while the
 * log keeps the path exactly as requested.
 */
function createLoggingRouter(routes, log) {
  const inner = createRouter(routes);
  return async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const routed = new URL(url.toString());
    routed.pathname = url.pathname.replace(/^\/s\/[^/]+(?=\/api\/)/, "");
    const response = await inner(routed.toString(), init);
    log.push({ method: init.method ?? "GET", url: url.toString(), path: url.pathname, status: response.status });
    return response;
  };
}

function allText(values) {
  return values.map((value) => (typeof value === "string" ? value : JSON.stringify(value))).join("\n");
}

test("verdict rule 9: redactSecrets scrubs configured secrets and every credential class anywhere in an error string", () => {
  const config = sampleConfig({ apiKey: API_KEY, password: undefined });
  const text = [
    `elasticsearch request GET /_security/user failed (502 Bad Gateway): proxy said Authorization: Bearer ${CANARIES.bearer}`,
    `and ApiKey ${API_KEY} and Basic dXNlcjpwYXNzd29yZA== then Set-Cookie: session=${CANARIES.cookie}; Path=/`,
    `api_key="${CANARIES.apiKey}" token=${CANARIES.urlToken} secret: ${CANARIES.connectorSecret}`,
    `retry at https://user:${CANARIES.bindPassword}@api.example.com/v1/x?token=${CANARIES.urlToken}#frag mid sentence and ${JWT_CANARY} as jwt`,
    `the raw secret ${API_KEY_SECRET} must go too`,
  ].join(" ");
  const scrubbed = redactSecrets(text, config);
  assertCanaryWindowsAbsent(assert, scrubbed, [CANARIES.bearer, CANARIES.cookie, CANARIES.apiKey, CANARIES.urlToken, CANARIES.connectorSecret, CANARIES.bindPassword, JWT_CANARY, API_KEY, API_KEY_SECRET], "redactSecrets output");
  assert.ok(!scrubbed.includes("dXNlcjpwYXNzd29yZA=="), `the Basic value survived redaction in: ${scrubbed}`);
  assert.match(scrubbed, /GET \/_security\/user failed \(502 Bad Gateway\)/, "the request line and status stay readable");
  assert.match(scrubbed, /https:\/\/api\.example\.com\/v1\/x\?\[REDACTED\]/, "URLs keep scheme, host, and path but lose userinfo, query, and fragment");
  assert.match(scrubbed, /Authorization: Bearer \[REDACTED\]/, "the header keeps its scheme so the message still says what was replayed");
  assert.match(scrubbed, /ApiKey \[REDACTED\] and Basic \[REDACTED\]/);
});

test("verdict rule 9: redactSensitiveValues masks whole subtrees, plural and camelCase keys, and deep nesting while keeping booleans", () => {
  const nested = { level: 0 };
  let cursor = nested;
  for (let depth = 1; depth <= 40; depth += 1) {
    cursor.child = { level: depth, password: `deep-${depth}` };
    cursor = cursor.child;
  }
  const redacted = redactSensitiveValues({
    secrets: { user: "svc", password: "p1", nested: { token: "t1" } },
    tokens: ["t2", "t3"],
    apiKey: "camel",
    api_keys: ["k1"],
    keystore: { key: "ks", path: "/etc/ks.p12" },
    ssl: { key: "pem", certificate: "cert" },
    tls: { key: "pem2" },
    bind_password: "bp",
    passphrase: "pp",
    truststore_password: "tp",
    sessionToken: "st",
    is_missing_secrets: false,
    has_private_key: true,
    "xpack.security.http.ssl.key": "flat-key",
    fine: { name: "ok", count: 2 },
    deep: nested,
  });
  assert.equal(redacted.secrets, "[REDACTED]", "an object under a secret-shaped key is replaced whole");
  assert.equal(redacted.tokens, "[REDACTED]", "an array under a plural secret key is replaced whole");
  assert.equal(redacted.apiKey, "[REDACTED]");
  assert.equal(redacted.api_keys, "[REDACTED]");
  assert.equal(redacted.keystore.key, "[REDACTED]");
  assert.equal(redacted.keystore.path, "/etc/ks.p12");
  assert.equal(redacted.ssl.key, "[REDACTED]");
  assert.equal(redacted.ssl.certificate, "cert");
  assert.equal(redacted.tls.key, "[REDACTED]");
  assert.equal(redacted.bind_password, "[REDACTED]");
  assert.equal(redacted.passphrase, "[REDACTED]");
  assert.equal(redacted.truststore_password, "[REDACTED]");
  assert.equal(redacted.sessionToken, "[REDACTED]");
  assert.equal(redacted["xpack.security.http.ssl.key"], "[REDACTED]");
  assert.equal(redacted.is_missing_secrets, false, "boolean flags whose names merely mention secrets are preserved");
  assert.equal(redacted.has_private_key, true);
  assert.deepEqual(redacted.fine, { name: "ok", count: 2 });
  assert.ok(!JSON.stringify(redacted).includes("deep-40"), "values past the depth cap are replaced, never copied through");
  let level = redacted.deep;
  for (let depth = 1; depth <= 31; depth += 1) level = level.child;
  assert.equal(level.level, 31);
  assert.equal(level.child, "[REDACTED]", "the container past the depth cap becomes the uniform marker, the same shape Box and LaunchDarkly render");
});

test("verdict rule 9: ElasticApiClient describes non-JSON bodies by status and length and echoes only documented JSON error fields", async () => {
  const routes = healthyRoutes(healthyFixtures());
  routes["GET /_security/user"] = htmlGateway();
  routes["GET /_security/role_mapping"] = jsonErrorWithUrl();
  routes["GET /_license"] = () => new Response("<html>login page</html>", { status: 200, statusText: "OK", headers: { "content-type": "text/html" } });
  routes["GET /_ilm/status"] = () => jsonResponse({ unexpected: `field carrying ${CANARIES.apiKey}` }, { status: 500, statusText: "Internal Server Error" });
  const client = new ElasticApiClient(sampleConfig({ maxRetries: 0 }), { fetchImpl: createRouter(routes) });

  await assert.rejects(client.listUsers(), (error) => {
    assert.ok(error instanceof ElasticRequestError);
    assert.equal(error.status, 502);
    assert.match(error.message, /GET \/_security\/user failed \(502 Bad Gateway\): 502 Bad Gateway: non-JSON body \(text\/html, \d+ bytes, not echoed\)/);
    assertCanaryWindowsAbsent(assert, error.message, canaryValues(), "502 error message");
    return true;
  });
  await assert.rejects(client.listRoleMappings(), (error) => {
    assert.equal(error.status, 403);
    assert.match(error.message, /security_exception/);
    assert.match(error.message, /https:\/\/api\.example\.com\/v1\/x\?\[REDACTED\]/, "a URL embedded mid-message loses its query string");
    assertCanaryWindowsAbsent(assert, error.message, [CANARIES.urlToken, CANARIES.bearer], "403 error message (undocumented header fields are never echoed)");
    return true;
  });
  await assert.rejects(client.getLicense(), (error) => {
    assert.equal(error.status, 200);
    assert.match(error.message, /returned a 200 OK: non-JSON body \(text\/html, \d+ bytes, not echoed\); the endpoint is not serving the JSON API/);
    assert.ok(!error.message.includes("login page"));
    return true;
  });
  await assert.rejects(client.getIlmStatus(), (error) => {
    assert.equal(error.status, 500);
    assert.match(error.message, /500 Internal Server Error: JSON body without a documented error field \(application\/json, \d+ bytes, not echoed\)/);
    assertCanaryWindowsAbsent(assert, error.message, [CANARIES.apiKey], "500 error message");
    return true;
  });
});

test("canary fixture self-check: every planted Elastic credential is alphanumeric, random-looking, and shares no 6-character window with the fixture's legitimate values", async () => {
  const config = sampleConfig({ maxRetries: 0 });
  const client = new ElasticApiClient(config, { fetchImpl: createRouter(healthyRoutes(healthyFixtures())) });
  const access = await checkElasticAccess(client);
  const result = await exportElasticAuditBundle(client, config, createTempBase("elastic-self-check-"), { sensitiveIndexPatterns: ["customers-*"] });
  const snapshot = await collectElasticSnapshot(client, ELASTIC_ALL_DATASETS, {});
  const assessments = ALL_AREAS.map((area) => evaluateElasticArea(area, snapshot, {}, { elasticsearchUrl: config.elasticsearchUrl }));
  const legitimate = new Map([
    ...readBundleFiles(result.outputDir),
    ["fixture", JSON.stringify(healthyFixtures())],
    ["principal fixture", JSON.stringify(principalFixtures())],
    ["access", JSON.stringify(access)],
    ["assessments", JSON.stringify(assessments)],
    ["config", JSON.stringify({ ...config, apiKey: null })],
  ]);
  const canaries = [...Object.values(CANARIES), API_KEY, API_KEY_SECRET, CONFIG_FILE_CANARY, ...Object.values(ELASTIC_CONFIG_CANARIES), ES_PARSER_SNIPPET_CANARY, ...Object.values(DATA_CARRIERS)];
  assertCanaryFixture(assert, canaries, legitimate, "Elastic canaries");
});

test("verdict rule 9: the Elastic bundle, its zip, every assess payload, and the access check never carry any window of a canary from bodies or collected objects", async () => {
  const fixtures = canaryFixtures();
  const routes = healthyRoutes(fixtures);
  routes["GET /_security/role_mapping"] = htmlGateway();
  routes["GET /_ssl/certificates"] = jsonErrorWithUrl();
  const config = sampleConfig({ maxRetries: 0 });
  const client = new ElasticApiClient(config, { fetchImpl: createRouter(routes) });
  const base = createTempBase("elastic-canary-");

  const access = await checkElasticAccess(client);
  const result = await exportElasticAuditBundle(client, config, base, { sensitiveIndexPatterns: ["customers-*"] });
  const snapshot = await collectElasticSnapshot(client, ELASTIC_ALL_DATASETS, {});
  const assessments = ALL_AREAS.map((area) => evaluateElasticArea(area, snapshot, {}, { elasticsearchUrl: config.elasticsearchUrl }));

  const files = readBundleFiles(result.outputDir);
  const entries = readZipEntries(result.zipPath);
  assert.ok(files.size > 20 && entries.size === files.size, `expected the zip to mirror ${files.size} files, got ${entries.size}`);
  const planted = [...canaryValues(), API_KEY, API_KEY_SECRET];
  assertCanaryWindowsAbsent(assert, files, planted, "bundle file");
  assertCanaryWindowsAbsent(assert, entries, planted, "zip entry");
  assertCanaryWindowsAbsent(assert, new Map([["access", JSON.stringify(access)], ["assessments", JSON.stringify(assessments)]]), planted, "tool payload");

  const errors = files.get("_errors.log");
  assert.match(errors, /role_mappings \(GET \/_security\/role_mapping\): elasticsearch request GET \/_security\/role_mapping failed \(502 Bad Gateway\): 502 Bad Gateway: non-JSON body \(text\/html, \d+ bytes, not echoed\)/);
  assert.match(errors, /ssl_certificates \(GET \/_ssl\/certificates\): .*403 Forbidden.*https:\/\/api\.example\.com\/v1\/x\?\[REDACTED\]/);
  const roleMappings = JSON.parse(files.get("core_data/role_mappings.json"));
  assert.equal(roleMappings.collected, false);
  assert.equal(roleMappings.status, 502);
  assert.match(roleMappings.error, /non-JSON body \(text\/html/);

  const connectors = JSON.parse(files.get("core_data/connectors.json")).data;
  assert.equal(connectors[0].config.url, "https://hooks.example.com", "connector URLs are reduced to origin");
  assert.deepEqual(connectors[0].config.headers, ["Authorization", "X-Api-Key"], "header names are kept, header values are not");
  assert.equal(connectors[0].secrets, undefined, "connector secrets are dropped by projection");
  const watches = JSON.parse(files.get("core_data/watches.json")).data;
  assert.equal(watches[0].actions.notify.webhook.scheme, "https");
  assert.equal(watches[0].actions.notify.webhook.path, "[REDACTED]");
  assert.deepEqual(watches[0].actions.notify.webhook.auth.types, ["basic"]);
  const pipelines = JSON.parse(files.get("core_data/ingest_pipelines.json")).data;
  assert.equal(pipelines["logs-enrich"].processors[1].set.sensitive_literal, true);
  assert.equal(pipelines["logs-enrich"].processors[1].set.value, undefined, "set literals are classified, never copied");
  const pipelineFinding = assessments[3].findings.find((item) => item.id === "ELASTIC-22");
  assert.equal(pipelineFinding.status, "fail", "the projected pipeline still drives the sensitive-literal verdict");
  assert.deepEqual(pipelineFinding.evidence.pipelines_with_sensitive_set[0].sensitive_set_processors, ["http.request.headers.authorization"]);
});

/** Every error string an Elastic run can record, gathered from the access check, the assess payloads, and the bundle. */
function recordedErrorStrings(access, assessments, files) {
  const strings = [];
  for (const surface of access.surfaces) if (typeof surface.error === "string") strings.push(surface.error);
  strings.push(...access.notes);
  for (const assessment of assessments) {
    strings.push(...(assessment.errors ?? []));
    for (const finding of assessment.findings) {
      strings.push(finding.summary);
      for (const [, value] of leaves(finding.evidence)) if (typeof value === "string") strings.push(value);
    }
  }
  const errorsLog = files.get("_errors.log");
  if (errorsLog) strings.push(...errorsLog.split("\n"));
  return strings;
}

/** A 403 body echoing weak human-chosen pairs (no digits, symbols, or length a shape gate would catch) under vendor env names and a config key. */
const WEAK_PAIR_BODY = "Access denied: LAUNCHDARKLY_API_TOKEN=monkey LD_ACCESS_TOKEN=Sunshine DB_PASSWORD=letmein DD_APP_KEY=p@ss BOX_CLIENT_SECRET=football KNOWBE4_API_TOKEN=qwerty ELASTIC_PASSWORD=iloveyou developer_token: letmein2024";
const WEAK_PAIR_VALUES = ["monkey", "Sunshine", "letmein", "p@ss", "football", "qwerty", "iloveyou", "letmein2024"];
const WEAK_PAIR_KEYS = ["LAUNCHDARKLY_API_TOKEN", "LD_ACCESS_TOKEN", "DB_PASSWORD", "DD_APP_KEY", "BOX_CLIENT_SECRET", "KNOWBE4_API_TOKEN", "ELASTIC_PASSWORD", "developer_token"];

test("row (a): an Elastic 403 body echoing weak values under credential-named keys reaches the access check with every value gone and every key kept", async () => {
  const routes = healthyRoutes(healthyFixtures());
  routes["GET /_ssl/certificates"] = () => jsonResponse({ error: { type: "security_exception", reason: WEAK_PAIR_BODY }, status: 403 }, { status: 403, statusText: "Forbidden" });
  const seen = [];
  const client = new ElasticApiClient(sampleConfig({ maxRetries: 0 }), { fetchImpl: createRouter(routes, seen) });
  const access = await checkElasticAccess(client);
  const certificates = access.surfaces.find((surface) => surface.name === "ssl_certificates");
  assert.equal(certificates.status, "not_readable");
  assert.match(certificates.error, /^elasticsearch request GET \/_ssl\/certificates failed \(403 Forbidden\): .*Access denied: /);
  for (const key of WEAK_PAIR_KEYS) assert.ok(certificates.error.includes(`${key}=[REDACTED]`) || certificates.error.includes(`${key}: [REDACTED]`), `${key} keeps its name and gets the marker: ${certificates.error}`);
  assertCanaryWindowsAbsent(assert, JSON.stringify(access), WEAK_PAIR_VALUES, "check_access payload");
});

test("addendum 4: a 502 HTML page or a JSON error message carrying credentials on any Elastic surface never reaches the access check, an assess payload, or the bundle, and every recorded error carries the status-and-length note", async () => {
  const fixtures = canaryFixtures();
  const surfaces = Object.keys(healthyRoutes(fixtures));
  assert.ok(surfaces.length >= 30, `expected every collector and access probe route, got ${surfaces.length}`);
  const config = sampleConfig({ maxRetries: 0 });
  const planted = [...canaryValues(), API_KEY, API_KEY_SECRET];
  const variants = [
    { name: "html502", handler: htmlGateway, note: /502 Bad Gateway: non-JSON body \(text\/html, \d+ bytes, not echoed\)/ },
    { name: "json403", handler: jsonErrorWithUrl, note: /403 Forbidden/ },
  ];
  let notedSurfaces = 0;
  for (const surface of surfaces) {
    for (const variant of variants) {
      const routes = healthyRoutes(fixtures);
      routes[surface] = variant.handler();
      const client = new ElasticApiClient(config, { fetchImpl: createRouter(routes) });
      const label = `${surface} ${variant.name}`;

      const access = await checkElasticAccess(client);
      const snapshot = await collectElasticSnapshot(client, ELASTIC_ALL_DATASETS, { sensitiveIndexPatterns: ["customers-*"] });
      const assessments = ALL_AREAS.map((area) => evaluateElasticArea(area, snapshot, { sensitiveIndexPatterns: ["customers-*"] }, { elasticsearchUrl: config.elasticsearchUrl }));
      const result = await exportElasticAuditBundle(client, config, createTempBase("elastic-surface-canary-"), { sensitiveIndexPatterns: ["customers-*"] });
      const files = readBundleFiles(result.outputDir);
      const entries = readZipEntries(result.zipPath);

      assertCanaryWindowsAbsent(assert, files, planted, `${label} bundle file`);
      assertCanaryWindowsAbsent(assert, entries, planted, `${label} zip entry`);
      assertCanaryWindowsAbsent(assert, new Map([["access", JSON.stringify(access)], ["assessments", JSON.stringify(assessments)]]), planted, `${label} tool payload`);

      const [method, path] = surface.split(" ");
      const aboutSurface = recordedErrorStrings(access, assessments, files).filter((text) => text.includes(`${method} ${path}`) && /failed|returned|timed out/.test(text));
      if (aboutSurface.length === 0) continue;
      notedSurfaces += 1;
      for (const text of aboutSurface) {
        assert.match(text, variant.note, `${label}: error string lacks the status note: ${text}`);
        assert.ok(!/<html|Bad Gateway<\/|upstream sent/.test(text), `${label}: error string echoes the body: ${text}`);
        if (variant.name === "json403") assertCanaryWindowsAbsent(assert, text, [CANARIES.urlToken], `${label} error string`);
      }
    }
  }
  assert.ok(notedSurfaces >= surfaces.length, `every surface should record its failure at least once across the variants, got ${notedSurfaces} of ${surfaces.length * variants.length}`);
});

test("verdict rule 10: listApiKeys reports truncation when a full page has no search_after cursor and listFleetOutputs reports the cap and total", async () => {
  const fixtures = healthyFixtures();
  const now = Date.now();
  const cursorlessKeys = Array.from({ length: 3 }, (_, index) => ({ id: `key-${index}`, name: `key-${index}`, creation: now - index * DAY_MS, invalidated: false }));
  const routes = healthyRoutes(fixtures);
  routes["POST /_security/_query/api_key"] = () => jsonResponse({ total: 500, count: 3, api_keys: cursorlessKeys });
  routes["GET /api/fleet/outputs"] = { items: fixtures.fleetOutputs.concat(fixtures.fleetOutputs, fixtures.fleetOutputs), total: 7 };
  const client = new ElasticApiClient(sampleConfig(), { fetchImpl: createRouter(routes) });

  const keys = await client.listApiKeys(3, 3);
  assert.equal(keys.seen, 3);
  assert.equal(keys.total, 500);
  assert.equal(keys.truncated, true, "a full page without _sort cannot be continued, so the remainder is unknown");

  const routesWithCursor = healthyRoutes(fixtures);
  let calls = 0;
  routesWithCursor["POST /_security/_query/api_key"] = () => {
    calls += 1;
    return jsonResponse(calls === 1
      ? { total: 4, count: 3, api_keys: cursorlessKeys.map((key) => ({ ...key, _sort: [key.creation, key.name] })) }
      : { total: 4, count: 1, api_keys: [{ id: "key-last", name: "key-last", creation: now, invalidated: false, _sort: [now, "key-last"] }] });
  };
  const complete = await (new ElasticApiClient(sampleConfig(), { fetchImpl: createRouter(routesWithCursor) })).listApiKeys(10, 3);
  assert.equal(complete.seen, 4);
  assert.equal(complete.truncated, false, "an exhausted cursor walk that reaches total is complete");

  const outputs = await client.listFleetOutputs(2);
  assert.equal(outputs.seen, 2);
  assert.equal(outputs.total, 7);
  assert.equal(outputs.truncated, true);
  const outputsUncapped = await client.listFleetOutputs(10);
  assert.equal(outputsUncapped.seen, 3);
  assert.equal(outputsUncapped.truncated, true, "fewer items than the advertised total is still truncated");
});

/**
 * The data-side carrier classes of the batch 1 review, one random canary each: userinfo in URL values, bearer tokens
 * and query-string tokens in free text, webhook-style paths, assignment pairs, name/value pairs, and bare tokens in
 * notes, spread over the 19 core_data files the review found them in. Each is planted in a field no verdict reads, so
 * the projection drops it, or in a field a verdict reads, so the scrub reduces it (URL origin, marker).
 */
const DATA_CARRIERS = {
  csUserinfo: "Rp3LnrUG21ICji5YWmflylRgTp9ap9DZ",
  csBareToken: "z4vwczZ3wciSgujZu5okOpC2GOSEUuse",
  csSettingBare: "AdwT3zlaOPYAi0yrQjj1IONiXyirPEGe",
  nsExporterUserinfo: "4EBlZ2FPRmPnySVsr9aI3zH8v4bxfoLK",
  nsIdpQuery: "ri5FXoBzHS5jVwzWfC0COiylvlDTLiou",
  authMetaPairValue: "qykqlQJBFt8Qlt48qnH43GKBnUsakj9Y",
  userMetaPasswordPair: "6WHC8a6NVk0LTUArutZ7wjhnNauZpeGY",
  userNameValuePair: "KNWNIhmQKQyTTAAYr1AM7XMUqyDfWJFY",
  roleMetaQuery: "mih3m7UmTYdLoJRiTeELoTju2XgOTGWQ",
  rmMetaBearer: "X9mgImalhvj3pbHpeVU2QDK9oS8Vuv1x",
  keyWebhookPath: "pAK0qHjsDBBWtEz4cMrnJV3AjvBcXOAH",
  keyKvPair: "OGYVOxq9KdXXf8ZYGZxfnFRw3TbLqyIE",
  keyMetaBare: "qcTKOOqVk8geD6X6NGQMozTRCHnNSf2A",
  ilmMetaPair: "4RvwTbXIjoxFqtYApreI4F22QqT24DW6",
  slmMetaPair: "3EQvuCdpDeV2SrI7fBTYxX1tOkyhnzm0",
  repoUrlUserinfo: "IiPGt54CgFZHFlohCAiD8xC6l3QKymeu",
  pipeDescBearer: "bYJO5Wq4hEluvgAV2Ynr7IkWDod23xt0",
  kroleMetaQuery: "qX7og8AH9m46LFVd5ubAB2diwbARVEdv",
  spaceDescBare: "vpF1PmhUr3SpBBpDyaC31nEFPj6cdqqW",
  policyDescQuery: "L1JSRmj5KRdCYW6DOkX3HjXm91HRmjwo",
  policyOverrideUserinfo: "CfhpPnzvqOU7TVH7PGPjC85OcWw1kuRa",
  outputHostUserinfo: "bBOot5m30grizlyJE8cpVlQFl9m8I1Ka",
  outputYamlPassphrase: "GkU7jb9kicZPJXiy1r9pqZ5LnQBYlES2",
  fshUserinfo: "2i4U8v0meo6Ixf6VsTOBLMZ5FdIfhvz6",
  ruleDescBearer: "kLfqQ3gD1RB3FDkbiUbp9GlBdQT6uKMq",
  ruleQueryBearer: "BOBA20w5EpfCLZM13iHBEYBHbzV5oe4q",
  ruleNoteQuery: "5Rl51PAsJk2xt68K4MTbCuQyX8x3j5Ha",
  ruleRefQuery: "0xDUAHLWpxtrnRfcnilsuH8A3GE6ndrx",
  alertParamUrl: "glLU0tXx0SuALE0U5HqjLoXa54dOeVsw",
  ruleActionPath: "JDhScRQydwDgA8MZxAR0CHJYXKorioMp",
  alertActionBodyPair: "mtyvwwtn6VwgP8p5MuNz9nDIODvSgSsB",
  cloudMetaBare: "9UqnjUhcKnCrs0XYA1bz5d4Gy2SV0iYJ",
};

/** The healthy fixture with every DATA_CARRIERS class planted; the verdicts must not move. */
function carrierFixtures(now = Date.now()) {
  const C = DATA_CARRIERS;
  const fixtures = healthyFixtures(now);
  const node = fixtures.nodeSettings.nodes["node-1"];
  fixtures.clusterSettings.persistent["xpack.security.authc.realms.ldap.ldap1.url"] = `ldaps://svc:${C.csUserinfo}@ldap.example.com:636`;
  fixtures.clusterSettings.persistent["xpack.security.authc.realms.saml.corp_sso.attributes.mail"] = C.csSettingBare;
  fixtures.clusterSettings.persistent["cluster.metadata.owner_note"] = `rotate with ${C.csBareToken} on request`;
  node.settings["xpack.monitoring.exporters.cloud.host"] = [`https://svc:${C.nsExporterUserinfo}@monitor.example.com:9243`];
  node.settings["xpack.security.authc.realms.saml.corp_sso.idp.metadata.path"] = `https://idp.example.com/metadata?token=${C.nsIdpQuery}`;
  fixtures.authenticate.metadata = { headers: [{ name: "X-Api-Key", value: C.authMetaPairValue }] };
  fixtures.users.auditor.metadata = { note: `password=${C.userMetaPasswordPair}`, attributes: [{ name: "api_token", value: C.userNameValuePair }] };
  fixtures.roles.analyst_fls.metadata = { docs: `https://wiki.example.com/roles?token=${C.roleMetaQuery}` };
  fixtures.roleMappings.saml_users.metadata = { note: `upstream sends Authorization: Bearer ${C.rmMetaBearer}` };
  fixtures.apiKeys[0].metadata = { webhook: `https://hooks.slack.com/services/T000/B000/${C.keyWebhookPath}`, pairs: [{ name: "secret", value: C.keyKvPair }], note: C.keyMetaBare };
  fixtures.ilmPolicies["logs-retention"].policy._meta = { managed: false, note: `token=${C.ilmMetaPair}` };
  fixtures.slmPolicies.nightly.policy = { indices: ["*"], config: { indices: ["*"], metadata: { note: `secret=${C.slmMetaPair}` } } };
  fixtures.snapshotRepositories.offsite = { type: "s3", settings: { bucket: "es-offsite", server_side_encryption: true, endpoint: `https://svc:${C.repoUrlUserinfo}@s3.example.com/snapshots` } };
  fixtures.ingestPipelines["logs-enrich"].description = `enrich; the upstream proxy sends Authorization: Bearer ${C.pipeDescBearer}`;
  fixtures.kibanaRoles[1].metadata = { docs: `https://wiki.example.com/kibana?token=${C.kroleMetaQuery}` };
  fixtures.spaces[1].description = C.spaceDescBare;
  fixtures.agentPolicies[0].description = `see https://wiki.example.com/fleet?token=${C.policyDescQuery}`;
  fixtures.agentPolicies[0].overrides = { outputs: { default: { hosts: [`https://svc:${C.policyOverrideUserinfo}@es.example.com:9200`] } } };
  fixtures.fleetOutputs[0].hosts = [`https://svc:${C.outputHostUserinfo}@es.example.com:9200`];
  fixtures.fleetOutputs[0].config_yaml = `ssl.key_passphrase: ${C.outputYamlPassphrase}\n`;
  fixtures.fleetServerHosts[0].host_urls = [`https://agent:${C.fshUserinfo}@fleet.example.com:8220`];
  fixtures.detectionRules[0].description = `Detects replay of Authorization: Bearer ${C.ruleDescBearer}`;
  fixtures.detectionRules[0].query = `http.request.headers.authorization:"Bearer ${C.ruleQueryBearer}"`;
  fixtures.detectionRules[0].note = `Runbook https://runbook.example.com/login?token=${C.ruleNoteQuery}`;
  fixtures.detectionRules[0].references = [`https://ref.example.com/x?token=${C.ruleRefQuery}`];
  fixtures.alertingRules[0].params = { url: `https://hook.example.com/notify?token=${C.alertParamUrl}` };
  fixtures.alertingRules[0].actions[0].params = { path: `/services/T000/B000/${C.ruleActionPath}`, body: `{"token":"${C.alertActionBodyPair}"}` };
  fixtures.cloudDeployments[0].metadata = { tags: [{ key: "note", value: C.cloudMetaBare }] };
  return fixtures;
}

test("verdict rule 9: every collected dataset is projected to the fields its verdicts read and scrubbed before it is assessed or written, so userinfo, free-text tokens, webhook paths, pairs, and bare tokens in 19 core_data files never reach the bundle, the zip, an assess payload, or the access check, and the verdicts do not move", async () => {
  const config = sampleConfig({ maxRetries: 0, cloudApiKey: "cloud-key" });
  const options = { sensitiveIndexPatterns: ["customers-*"] };
  const baseline = new ElasticApiClient(config, { fetchImpl: createRouter(healthyRoutes(healthyFixtures())) });
  const baselineStatuses = Object.fromEntries((await assessAll(baseline, options)).map((finding) => [finding.id, finding.status]));

  const client = new ElasticApiClient(config, { fetchImpl: createRouter(healthyRoutes(carrierFixtures())) });
  const access = await checkElasticAccess(client);
  const snapshot = await collectElasticSnapshot(client, ELASTIC_ALL_DATASETS, options);
  const assessments = ALL_AREAS.map((area) => evaluateElasticArea(area, snapshot, options, { elasticsearchUrl: config.elasticsearchUrl }));
  const result = await exportElasticAuditBundle(client, config, createTempBase("elastic-carriers-"), options);
  const files = readBundleFiles(result.outputDir);
  const entries = readZipEntries(result.zipPath);
  const planted = Object.values(DATA_CARRIERS);

  const coreFiles = [...files.keys()].filter((name) => name.startsWith("core_data/"));
  assert.ok(coreFiles.length >= 29, `expected every dataset in core_data, got ${coreFiles.length}`);
  assertCanaryWindowsAbsent(assert, files, planted, "bundle file");
  assertCanaryWindowsAbsent(assert, entries, planted, "zip entry");
  assertCanaryWindowsAbsent(assert, new Map([["access", JSON.stringify(access)], ["assessments", JSON.stringify(assessments)], ["snapshot", JSON.stringify(snapshot)]]), planted, "tool payload");

  const statuses = Object.fromEntries(assessments.flatMap((assessment) => assessment.findings).map((finding) => [finding.id, finding.status]));
  assert.deepEqual(statuses, baselineStatuses, "carriers in fields no verdict reads do not move a verdict, and the projection keeps every field the verdicts read");
  assert.equal(access.status, "healthy");

  const core = (name) => JSON.parse(files.get(`core_data/${name}.json`)).data;
  assert.equal(core("cluster_settings").persistent["xpack.security.authc.realms.ldap.ldap1.url"], "ldaps://ldap.example.com:636", "a URL setting keeps scheme and host only");
  assert.equal(core("cluster_settings").persistent["xpack.security.authc.realms.saml.corp_sso.attributes.mail"], "[REDACTED]", "a bare token in a kept setting is the marker");
  assert.equal(core("cluster_settings").persistent["cluster.metadata.owner_note"], undefined, "settings outside xpack.security are not written");
  assert.equal(core("node_settings").nodes["node-1"].settings["xpack.security.authc.realms.saml.corp_sso.idp.metadata.path"], "https://idp.example.com");
  assert.equal(core("node_settings").nodes["node-1"].settings["xpack.monitoring.exporters.cloud.host"], undefined);
  assert.deepEqual(core("authenticate"), { username: "grc-auditor", roles: ["grc_auditor"], enabled: true, authentication_type: "api_key", authentication_realm: { name: "native1", type: "native" }, lookup_realm: { name: "native1", type: "native" } });
  assert.deepEqual(core("users").auditor, { username: "auditor", roles: ["analyst_fls"], enabled: true, metadata: {} }, "user metadata keeps only its reserved flags");
  assert.deepEqual(core("roles").analyst_fls.metadata, {});
  assert.deepEqual(core("role_mappings").saml_users, { enabled: true, roles: ["kibana_user"], rules: { field: { "realm.name": "corp_sso" } }, metadata: {} });
  assert.deepEqual(core("api_keys")[0].metadata, {});
  assert.deepEqual(core("ilm_policies")["logs-retention"].policy._meta, { managed: false });
  assert.deepEqual(core("ilm_policies")["logs-retention"].policy.phases, { hot: { min_age: "0ms", actions: { rollover: { max_age: "7d" } } }, delete: { min_age: "365d", actions: { delete: {} } } });
  assert.deepEqual(core("slm_policies").nightly.policy, { config: { indices: ["*"] } });
  assert.deepEqual(core("snapshot_repositories").offsite, { type: "s3", settings: { bucket: "es-offsite", server_side_encryption: true, endpoint: "https://s3.example.com" } });
  assert.deepEqual(
    redactSensitiveValues(projectDataset("snapshot_repositories", { mirror: { type: "url", settings: { url: `https://svc:${DATA_CARRIERS.repoUrlUserinfo}@repo.example.com/snapshots?sig=${DATA_CARRIERS.repoUrlUserinfo}`, readonly: true } } })),
    { mirror: { type: "url", settings: { readonly: true, url: "https://repo.example.com" } } },
    "a read-only URL repository keeps scheme and host only",
  );
  assert.equal(core("ingest_pipelines")["logs-enrich"].has_description, true);
  assert.equal(core("ingest_pipelines")["logs-enrich"].description, undefined);
  assert.deepEqual(core("kibana_roles")[1].metadata, {});
  assert.deepEqual(core("kibana_spaces")[1], { id: "security-team", name: "Security", disabledFeatures: ["ml"] });
  assert.deepEqual(core("fleet_agent_policies")[0], { id: "policy-1", name: "Linux servers", namespace: "default", is_protected: true });
  assert.deepEqual(core("fleet_outputs")[0].hosts, ["https://es.example.com:9200"], "output hosts keep scheme and host only");
  assert.equal(core("fleet_outputs")[0].config_yaml, undefined);
  assert.deepEqual(core("fleet_server_hosts")[0].host_urls, ["https://fleet.example.com:8220"]);
  assert.deepEqual(core("detection_rules")[0], { id: "rule-1", name: "Suspicious login", enabled: true, actions: [] });
  assert.deepEqual(core("alerting_rules")[0], { id: "alert-1", name: "CPU high", enabled: true, actions: [{ id: "connector-1", group: "default" }] });
  assert.deepEqual(core("cloud_deployments")[0], { id: "deployment-1", name: "prod", metadata: {} });

  // The plain-http verdicts still read the reduced hosts.
  const plain = principalFixtures();
  plain.fleetOutputs[1].hosts = [`http://svc:${DATA_CARRIERS.outputHostUserinfo}@es-plain.example.com:9200`];
  const plainClient = new ElasticApiClient(config, { fetchImpl: createRouter(healthyRoutes(plain)) });
  const plainFindings = await assessAll(plainClient, options);
  const fleet = plainFindings.find((finding) => finding.id === "ELASTIC-21");
  assert.equal(fleet.status, "fail");
  assert.deepEqual(fleet.evidence.insecure_outputs, ["output-canary-plain"]);
  assertCanaryWindowsAbsent(assert, JSON.stringify(plainFindings), [DATA_CARRIERS.outputHostUserinfo], "plain-http verdict payload");
});

test("verdict rule 9: reduceUrlsToOrigin reduces a URL value and every URL embedded in free text to scheme and host, and redactSensitiveValues applies it to every collected string", () => {
  assert.equal(reduceUrlsToOrigin("https://user:pw@host.example.com:9243/path/x?token=abc#frag"), "https://host.example.com:9243");
  assert.equal(reduceUrlsToOrigin("  ldaps://svc:pw@ldap.example.com:636 "), "ldaps://ldap.example.com:636");
  assert.equal(reduceUrlsToOrigin("see https://a.example.com/x?token=abc, then http://b.example.com/y#f."), "see https://a.example.com, then http://b.example.com.");
  assert.equal(reduceUrlsToOrigin("no url here"), "no url here");
  assert.equal(reduceUrlsToOrigin("http://"), "[REDACTED]", "a URL that does not parse is the marker rather than copied");
  const scrubbed = redactSensitiveValues({
    hosts: ["https://svc:pw@es.example.com:9200"],
    note: "docs at https://wiki.example.com/x?token=abc",
    nested: { url: "https://u:p@h.example.com/a" },
    id: "https://id.example.com/x?token=abc",
  });
  assert.deepEqual(scrubbed, {
    hosts: ["https://es.example.com:9200"],
    note: "docs at https://wiki.example.com",
    nested: { url: "https://h.example.com" },
    id: "https://id.example.com",
  });
});

test("verdict rule 9: a configured secret straddling the 240-character error detail cut is scrubbed at full length before the cut in every encoding, so no fragment survives in the error, a tool payload, or the bundle", async () => {
  // Each encoding is the secret as the body carries it; the JSON-escaped fragment wraps the plain secret in an escaped
  // JSON pair, the way a proxy quotes the request body it rejected.
  const base64Secret = Buffer.from(API_KEY_SECRET, "utf8").toString("base64");
  const base64urlKey = Buffer.from(API_KEY, "utf8").toString("base64url");
  const encodings = {
    plain_secret: { text: API_KEY_SECRET, canary: API_KEY_SECRET },
    configured_key: { text: API_KEY, canary: API_KEY },
    base64_secret: { text: base64Secret, canary: base64Secret },
    base64url_key: { text: base64urlKey, canary: base64urlKey },
    url_encoded_key: { text: encodeURIComponent(`${API_KEY}=`), canary: API_KEY },
    json_escaped_fragment: { text: `{\\"api_key\\":\\"${API_KEY_SECRET}\\"}`, canary: API_KEY_SECRET },
  };
  const planted = [API_KEY_SECRET, API_KEY, base64Secret, base64urlKey];
  const config = sampleConfig({ maxRetries: 0 });
  for (const [encoding, { text, canary }] of Object.entries(encodings)) {
    for (const offset of [225, 235, 239, 240]) {
      const reason = `${"denied ".repeat(50).slice(0, offset)}${text} was rejected by the proxy`;
      const routes = healthyRoutes(healthyFixtures());
      routes["GET /_security/user"] = () => jsonResponse({ error: { type: "security_exception", reason }, status: 403 }, { status: 403, statusText: "Forbidden" });
      const client = new ElasticApiClient(config, { fetchImpl: createRouter(routes) });
      await assert.rejects(client.listUsers(), (error) => {
        const label = `${encoding} at offset ${offset}`;
        assertCanaryWindowsAbsent(assert, error.message, [...planted, canary], label);
        assert.match(error.message, /^elasticsearch request GET \/_security\/user failed \(403 Forbidden\): \(detail truncated to 240 characters\) denied /, `${label}: the documented message is still quoted up to the cut, behind the truncation note`);
        assert.ok(error.message.length <= 360, `${label}: the detail is still cut (${error.message.length} characters)`);
        return true;
      });
    }
  }

  const routes = healthyRoutes(healthyFixtures());
  const reason = `${"denied ".repeat(50).slice(0, 235)}${API_KEY_SECRET} was rejected by the proxy`;
  routes["GET /_security/user"] = () => jsonResponse({ error: { type: "security_exception", reason }, status: 403 }, { status: 403, statusText: "Forbidden" });
  const client = new ElasticApiClient(config, { fetchImpl: createRouter(routes) });
  const access = await checkElasticAccess(client);
  const snapshot = await collectElasticSnapshot(client, ELASTIC_ALL_DATASETS, {});
  const assessments = ALL_AREAS.map((area) => evaluateElasticArea(area, snapshot, {}, { elasticsearchUrl: config.elasticsearchUrl }));
  const result = await exportElasticAuditBundle(client, config, createTempBase("elastic-secret-cut-"), {});
  const files = readBundleFiles(result.outputDir);
  assertCanaryWindowsAbsent(assert, files, planted, "bundle file");
  assertCanaryWindowsAbsent(assert, readZipEntries(result.zipPath), planted, "zip entry");
  assertCanaryWindowsAbsent(assert, new Map([["access", JSON.stringify(access)], ["assessments", JSON.stringify(assessments)]]), planted, "tool payload");
  assert.match(files.get("_errors.log"), /users \(GET \/_security\/user\): elasticsearch request GET \/_security\/user failed \(403 Forbidden\): \(detail truncated to 240 characters\) denied /);
});

const ELASTIC_SILENT_BODIES = [
  ["empty", () => new Response("", { status: 200, statusText: "OK" }), /returned a 200 OK: empty body \(0 bytes\); the endpoint is not serving the JSON API$/],
  ["html", () => new Response("<html><body>Sign in to Kibana</body></html>", { status: 200, statusText: "OK", headers: { "content-type": "text/html" } }), /returned a 200 OK: non-JSON body \(text\/html, \d+ bytes, not echoed\); the endpoint is not serving the JSON API$/],
  ["foreign", () => jsonResponse({ status: "ok", service: "status-page" }), /returned a 200 OK: JSON body that is not the documented JSON (object|array)[^;]*\(application\/json, \d+ bytes, not echoed\); the endpoint is not serving the JSON API$/],
];

test("silent success: matchesResponseShape accepts only the documented container of each Elastic response", () => {
  assert.equal(matchesResponseShape({ username: "u", roles: [] }, { kind: "object", keys: ["username", "roles"] }), true);
  assert.equal(matchesResponseShape({ status: "ok" }, { kind: "object", keys: ["username", "roles"] }), false, "an object without a documented key is foreign");
  assert.equal(matchesResponseShape([], { kind: "object", keys: ["username"] }), false);
  assert.equal(matchesResponseShape({ name: "kibana", uuid: "kb-1", version: { number: "8.15.0" }, status: { overall: { level: "available" } } }, { kind: "object", keys: ["name", "uuid", "version", "status"], all: true }), true);
  assert.equal(matchesResponseShape({ status: "ok", service: "status-page" }, { kind: "object", keys: ["name", "uuid", "version", "status"], all: true }), false, "a status page sharing one common key with the Kibana status document is foreign");
  assert.equal(matchesResponseShape({ name: "kibana", uuid: "kb-1", version: { number: "8.15.0" } }, { kind: "object", keys: ["name", "uuid", "version", "status"], all: true }), false, "an all-keys shape needs every key");
  assert.equal(describeResponseShape({ kind: "object", keys: ["name", "uuid", "version", "status"], all: true }), "JSON object with all of name, uuid, version, status");
  assert.equal(matchesResponseShape({}, { kind: "map", entryKeys: ["username"] }), true, "an empty map is a documented answer (no mappings, no repositories)");
  assert.equal(matchesResponseShape({ elastic: { username: "elastic" } }, { kind: "map", entryKeys: ["username", "roles"] }), true);
  assert.equal(matchesResponseShape({ message: "ok" }, { kind: "map", entryKeys: ["username"] }), false, "a map whose entry is not an object is foreign");
  assert.equal(matchesResponseShape({ foo: { bar: 1 } }, { kind: "map", entryKeys: ["username"] }), false, "a map whose entry carries no documented key is foreign");
  assert.equal(matchesResponseShape([], { kind: "array" }), true);
  assert.equal(matchesResponseShape([{ id: "x" }], { kind: "array" }), true);
  assert.equal(matchesResponseShape([1, 2], { kind: "array" }), false);
  assert.equal(matchesResponseShape({ items: [] }, { kind: "array" }), false);
  assert.equal(matchesResponseShape({ items: [] }, { kind: "list", key: "items" }), true);
  assert.equal(matchesResponseShape({ items: {} }, { kind: "list", key: "items" }), false);
  assert.equal(matchesResponseShape({}, { kind: "list", key: "api_keys" }), false, "a bare object is not an empty listing");
  assert.equal(describeResponseShape({ kind: "list", key: "api_keys" }), "JSON object with an array under api_keys");
  assert.equal(describeResponseShape({ kind: "map", entryKeys: ["username", "roles"] }), "JSON object of named entries each carrying any of username, roles");
  for (const shape of [{ kind: "object", keys: ["license"] }, { kind: "map", entryKeys: ["policy", "version"] }, { kind: "array" }, { kind: "list", key: "items" }]) {
    const text = describeResponseShape(shape);
    assert.equal(scrubErrorText(text), text, `the shape description is fixed text the scrubber leaves alone: ${text}`);
  }
});

test("silent success: a 2xx whose body is empty, an HTML page, or JSON of another shape on any Elastic surface is a failed read with http_status 200, a marker in core_data, and only manual or warn movement in the findings, never an empty inventory", async () => {
  const config = sampleConfig({ maxRetries: 0, cloudApiKey: "cloud-key" });
  const options = { sensitiveIndexPatterns: ["customers-*"] };
  const surfaces = Object.keys(healthyRoutes(healthyFixtures()));
  assert.ok(surfaces.length >= 30, `expected every collector and access probe route, got ${surfaces.length}`);
  const baselineClient = new ElasticApiClient(config, { fetchImpl: createRouter(healthyRoutes(healthyFixtures())) });
  const baseline = Object.fromEntries((await assessAll(baselineClient, options)).map((finding) => [finding.id, finding.status]));

  // Every surface, every body: the surface is not readable with the 200 the server sent, the error is fixed text that
  // survives the scrubber, and no finding moves anywhere but manual or warn.
  for (const surface of surfaces) {
    for (const [kind, body, expected] of ELASTIC_SILENT_BODIES) {
      const label = `${surface} served a ${kind} 200`;
      const routes = healthyRoutes(healthyFixtures());
      routes[surface] = body;
      const client = new ElasticApiClient(config, { fetchImpl: createRouter(routes) });
      const access = await checkElasticAccess(client);
      const row = access.surfaces.find((entry) => entry.endpoint === surface || (entry.endpoint !== null && entry.endpoint.startsWith(`${surface}?`)));
      if (row) {
        assert.deepEqual({ status: row.status, collected: row.collected, http_status: row.http_status, count: row.count, truncated: row.truncated }, { status: "not_readable", collected: false, http_status: 200, count: null, truncated: null }, label);
        assert.match(row.error, expected, label);
        assert.equal(scrubErrorText(row.error), row.error, `${label}: the recorded error is fixed text`);
        assert.ok(!/status-page|Sign in/.test(row.error), `${label}: the body is not echoed`);
      } else {
        assert.equal(surface, "POST /_security/user/_has_privileges", `${label}: only the privilege probe has no surface row`);
        assert.equal(access.privilegeProbe, "not_readable", label);
        assert.match(access.notes.find((note) => note.startsWith("Privilege probe failed")), expected, label);
      }
      const findings = await assessAll(client, options);
      for (const finding of findings) {
        if (baseline[finding.id] === finding.status) continue;
        assert.ok(["manual", "warn"].includes(finding.status), `${label}: ${finding.id} moved ${baseline[finding.id]} -> ${finding.status}; only manual or warn may follow an unobserved read: ${finding.summary}`);
        assert.ok(!/full inventory visibility/.test(finding.summary), `${label}: ${finding.id} claims full visibility of an unobserved inventory: ${finding.summary}`);
      }
    }
  }

  // The reviewer's shapes, end to end: an empty API key listing rendered ELASTIC-09/10 pass on zero keys, and an empty
  // or foreign body rendered ELASTIC-17/18/23 fail and ELASTIC-06/22 pass on data that was never observed.
  for (const [kind, body, expected] of ELASTIC_SILENT_BODIES) {
    const routes = healthyRoutes(healthyFixtures());
    routes["POST /_security/_query/api_key"] = body;
    const client = new ElasticApiClient(config, { fetchImpl: createRouter(routes) });
    const exported = await exportElasticAuditBundle(client, config, createTempBase("elastic-silent-"), options);
    const files = readBundleFiles(exported.outputDir);
    const label = `api_keys served a ${kind} 200`;
    const row = JSON.parse(files.get("collection_status.json")).datasets.find((entry) => entry.name === "api_keys");
    assert.deepEqual({ status: row.status, collected: row.collected, http_status: row.http_status, count: row.count, paged: row.paged, truncated: row.truncated, seen: row.seen, total: row.total }, { status: "not_readable", collected: false, http_status: 200, count: null, paged: null, truncated: null, seen: null, total: null }, label);
    assert.match(row.error, expected, label);
    const written = JSON.parse(files.get("core_data/api_keys.json"));
    assert.deepEqual({ collected: written.collected, status: written.status, reason: written.reason, page: written.page }, { collected: false, status: 200, reason: "not_readable", page: null }, `${label}: core_data carries a marker, not []`);
    assert.deepEqual(written.data, { collected: false, status: 200, endpoint: "POST /_security/_query/api_key?with_limited_by=true", target: "elasticsearch", error: written.error, reason: "not_readable" }, label);
    const findings = JSON.parse(files.get("analysis/findings.json"));
    for (const id of ["ELASTIC-09", "ELASTIC-10"]) {
      const finding = findings.find((item) => item.id === id);
      assert.equal(finding.status, "manual", `${label}: ${id} is ${finding.status}: ${finding.summary}`);
      assert.match(finding.summary, /api_keys \(POST \/_security\/_query\/api_key\?with_limited_by=true\)/, `${label}: ${id} names the unread inventory`);
      assert.equal(finding.evidence.inventory.read, false, label);
      assert.equal(finding.evidence.inventory.status, "not_readable", label);
    }
    assert.match(files.get("_errors.log"), new RegExp(expected.source, "m"), label);

    // Every endpoint silent: nothing was observed, so no finding may pass or fail.
    const silentRoutes = Object.fromEntries(surfaces.map((route) => [route, body]));
    const silentClient = new ElasticApiClient(config, { fetchImpl: createRouter(silentRoutes) });
    const silentAccess = await checkElasticAccess(silentClient);
    assert.equal(silentAccess.status, "limited", `${kind} on every endpoint: the access check is limited`);
    assert.ok(silentAccess.surfaces.every((entry) => entry.status === "not_readable" && entry.http_status === 200), `${kind} on every endpoint: every surface is a failed read with the observed 200`);
    for (const finding of await assessAll(silentClient, options)) {
      assert.equal(finding.status, "manual", `${kind} on every endpoint: ${finding.id} is ${finding.status}: ${finding.summary}`);
    }
  }

  // Documented empty containers stay readable: an empty map is no role mappings or repositories, an empty array is no
  // connectors, and an empty listing is zero watches; the emptiness rules, not the shape guard, judge them.
  const emptyRoutes = healthyRoutes(healthyFixtures());
  emptyRoutes["GET /_security/role_mapping"] = {};
  emptyRoutes["GET /_snapshot/_all"] = {};
  emptyRoutes["GET /api/actions/connectors"] = [];
  emptyRoutes["POST /_watcher/_query/watches"] = { count: 0, watches: [] };
  const emptyClient = new ElasticApiClient(config, { fetchImpl: createRouter(emptyRoutes) });
  const emptyAccess = await checkElasticAccess(emptyClient);
  for (const name of ["role_mappings", "snapshot_repositories", "connectors", "watches"]) {
    const row = emptyAccess.surfaces.find((entry) => entry.name === name);
    assert.deepEqual({ status: row.status, collected: row.collected, http_status: row.http_status, count: row.count }, { status: "readable", collected: true, http_status: null, count: 0 }, `${name}: a documented empty container is a readable zero-entry inventory`);
  }
});

const ELASTIC_MULTI_INVENTORY = [
  { id: "ELASTIC-01", assess: assessElasticIdentity, secondaries: { getXpackUsage: "xpack_usage", getClusterSettings: "cluster_settings" }, nullEvidence: { xpack_usage: ["usage_realm_types"], cluster_settings: ["realms", "secure_realm_types"] }, nullSummary: { xpack_usage: [], cluster_settings: ["realm_types", "secure_realm_types", "anonymous_roles"] } },
  { id: "ELASTIC-13", assess: assessElasticIdentity, secondaries: { listRoleMappings: "role_mappings", getLicense: "license" }, nullEvidence: { role_mappings: ["role_mapping_count"], license: ["license_supports_sso"] }, nullSummary: { role_mappings: ["role_mappings"], license: ["license_type"] } },
  { id: "ELASTIC-14", assess: assessElasticIdentity, secondaries: { getXpackUsage: "xpack_usage", getClusterSettings: "cluster_settings" }, nullEvidence: { xpack_usage: ["usage_anonymous_enabled"], cluster_settings: ["anonymous_roles", "anonymous_roles_grant_broad_access"] }, nullSummary: { xpack_usage: [], cluster_settings: ["anonymous_roles"] } },
  { id: "ELASTIC-09", assess: assessElasticIdentity, secondaries: { hasPrivileges: "privileges" }, nullEvidence: { privileges: ["inspected", "active", "without_expiration", "flagged", "missing_creation_date"] }, nullSummary: { privileges: ["api_keys_complete"] } },
  { id: "ELASTIC-10", assess: assessElasticIdentity, secondaries: { hasPrivileges: "privileges" }, nullEvidence: { privileges: ["active", "privileged", "unverifiable"] }, nullSummary: { privileges: [] } },
  { id: "ELASTIC-06", assess: assessElasticAccessControl, secondaries: { listUsers: "users", listRoleMappings: "role_mappings" }, nullEvidence: { users: ["users_reviewed", "superusers", "superuser_count", "users_with_broad_roles"], role_mappings: ["role_mappings_reviewed", "superuser_role_mappings"] }, nullSummary: { users: ["users_reviewed", "superusers"], role_mappings: ["role_mappings_reviewed"] } },
  { id: "ELASTIC-07", assess: assessElasticAccessControl, secondaries: { getLicense: "license", getXpackUsage: "xpack_usage" }, nullEvidence: { license: ["license_type", "license_status"], xpack_usage: ["usage_reports_in_use"] }, nullSummary: { license: ["license_type", "license_status"], xpack_usage: [] } },
  { id: "ELASTIC-08", assess: assessElasticAccessControl, secondaries: { getLicense: "license", getXpackUsage: "xpack_usage" }, nullEvidence: { license: ["license_type"], xpack_usage: ["usage_reports_in_use"] }, nullSummary: { license: ["license_type"], xpack_usage: [] } },
  { id: "ELASTIC-02", assess: assessElasticTransportSecurity, secondaries: { getXpackUsage: "xpack_usage", getClusterSettings: "cluster_settings" }, nullEvidence: { xpack_usage: ["usage_reported_enabled"], cluster_settings: ["per_node", "enabled_nodes"] }, nullSummary: { xpack_usage: [], cluster_settings: ["weak_protocols"] } },
  { id: "ELASTIC-03", assess: assessElasticTransportSecurity, secondaries: { getXpackUsage: "xpack_usage", getClusterSettings: "cluster_settings" }, nullEvidence: { xpack_usage: ["usage_reported_enabled"], cluster_settings: ["per_node"] }, nullSummary: { xpack_usage: [], cluster_settings: [] } },
  { id: "ELASTIC-04", assess: assessElasticTransportSecurity, secondaries: { getClusterSettings: "cluster_settings" }, nullEvidence: { cluster_settings: ["protocols_per_node", "weak_protocols", "unset_supported_protocols", "node_major_versions"] }, nullSummary: { cluster_settings: ["weak_protocols"] } },
  { id: "ELASTIC-05", assess: assessElasticTransportSecurity, secondaries: { getNodeSettings: "node_settings" }, nullEvidence: { node_settings: ["nodes_in_cluster"] }, nullSummary: { node_settings: ["nodes_inspected"] } },
  { id: "ELASTIC-11", assess: assessElasticClusterHardening, secondaries: { getLicense: "license", getXpackUsage: "xpack_usage" }, nullEvidence: { license: ["license_type"], xpack_usage: ["outputs", "usage_reported_enabled"] }, nullSummary: { license: ["license_type"], xpack_usage: ["audit_outputs"] } },
  { id: "ELASTIC-17", assess: assessElasticClusterHardening, secondaries: { getIlmStatus: "ilm_status" }, nullEvidence: { ilm_status: ["operation_mode"] }, nullSummary: { ilm_status: ["ilm_operation_mode"] } },
  { id: "ELASTIC-18", assess: assessElasticClusterHardening, secondaries: { listSlmPolicies: "slm_policies", getSlmStatus: "slm_status" }, nullEvidence: { slm_policies: ["slm_policy_count", "slm_policies", "slm_policies_without_last_success"], slm_status: ["slm_operation_mode"] }, nullSummary: { slm_policies: ["slm_policies"], slm_status: ["slm_operation_mode"] } },
  { id: "ELASTIC-19", assess: assessElasticClusterHardening, secondaries: { getXpackUsage: "xpack_usage", getXpackInfo: "xpack_info" }, nullEvidence: { xpack_usage: [], xpack_info: [] }, nullSummary: { xpack_usage: ["audit_outputs"], xpack_info: [] } },
  { id: "ELASTIC-20", assess: assessElasticClusterHardening, secondaries: { listConnectors: "connectors", listAlertingRules: "alerting_rules", listDetectionRules: "detection_rules", getLicense: "license" }, nullEvidence: { connectors: ["connectors", "insecure_connectors", "connectors_missing_secrets"], alerting_rules: ["alerting_rules", "rules_with_actions"], detection_rules: ["detection_rules", "rules_with_actions"], license: ["watcher_not_applicable"] }, nullSummary: { connectors: ["connectors"], alerting_rules: ["alerting_rules"], detection_rules: ["detection_rules"], license: ["license_type"] } },
  { id: "ELASTIC-23", assess: assessElasticClusterHardening, secondaries: { getNodeSettings: "node_settings", listRoles: "roles", getXpackUsage: "xpack_usage", getXpackInfo: "xpack_info", listWatches: "watches" }, nullEvidence: { node_settings: ["unsupported_features"], roles: ["unsupported_features"], xpack_usage: ["unsupported_features"], xpack_info: [], watches: ["unsupported_features"] }, nullSummary: { node_settings: ["audit_enabled"], roles: [], xpack_usage: ["audit_outputs"], xpack_info: [], watches: ["watches"] } },
  { id: "ELASTIC-15", assess: assessElasticKibana, secondaries: { listKibanaRoles: "kibana_roles" }, nullEvidence: { kibana_roles: ["space_scoped_roles", "global_all_roles"] }, nullSummary: { kibana_roles: ["kibana_roles", "global_all_roles"] } },
  { id: "ELASTIC-21", assess: assessElasticKibana, secondaries: { listFleetOutputs: "fleet_outputs", listEnrollmentApiKeys: "fleet_enrollment_api_keys", listFleetServerHosts: "fleet_server_hosts" }, nullEvidence: { fleet_outputs: ["outputs", "insecure_outputs", "outputs_without_ca_trust"], fleet_enrollment_api_keys: ["enrollment_keys_active", "enrollment_keys_inactive", "policies_over_enrollment_key_threshold"], fleet_server_hosts: ["fleet_server_hosts", "insecure_fleet_server_hosts"] }, nullSummary: { fleet_outputs: ["fleet_outputs"], fleet_enrollment_api_keys: ["enrollment_keys"], fleet_server_hosts: ["fleet_server_hosts"] } },
];

/** Names that only ever appear in the fixture inventory they belong to, so their absence proves gating. */
const PRINCIPAL_CANARIES = {
  users: ["usr-canary-superadmin", "usr-canary-analyst"],
  role_mappings: ["mapping-canary-saml"],
  roles: ["role-canary-broad"],
  kibana_roles: ["kbrole-canary-global"],
  fleet_outputs: ["output-canary-plain"],
  fleet_server_hosts: ["fleet-canary-plain"],
  fleet_enrollment_api_keys: ["policy-canary-crowded"],
  connectors: ["connector-canary-http"],
  slm_policies: ["slm-canary-stale"],
  api_keys: ["apikey-canary-stale"],
  watches: ["watch-canary-http"],
};

function principalFixtures(now = Date.now()) {
  const fixtures = healthyFixtures(now);
  fixtures.users = {
    "usr-canary-superadmin": { username: "usr-canary-superadmin", roles: ["superuser"], enabled: true, metadata: {} },
    "usr-canary-analyst": { username: "usr-canary-analyst", roles: ["role-canary-broad"], enabled: true, metadata: {} },
  };
  fixtures.roles["role-canary-broad"] = { cluster: ["all"], indices: [{ names: ["*"], privileges: ["all"] }], metadata: {} };
  fixtures.roleMappings = { "mapping-canary-saml": { enabled: true, roles: ["superuser"], rules: { field: { "realm.name": "corp_sso" } }, metadata: {} } };
  fixtures.kibanaRoles.push({ name: "kbrole-canary-global", metadata: {}, elasticsearch: { cluster: [], indices: [] }, kibana: [{ base: ["all"], feature: {}, spaces: ["*"] }] });
  fixtures.fleetOutputs.push({ id: "out-2", name: "output-canary-plain", type: "elasticsearch", hosts: ["http://es-plain.example.com:9200"], is_default: false });
  fixtures.fleetServerHosts.push({ id: "fleet-2", name: "fleet-canary-plain", host_urls: ["http://fleet-plain.example.com:8220"], is_default: false });
  fixtures.enrollmentKeys = Array.from({ length: 6 }, (_, index) => ({ id: `enroll-${index}`, active: true, policy_id: "policy-canary-crowded", api_key_id: `ak-${index}`, name: `key ${index}` }));
  fixtures.connectors.push({ id: "connector-2", name: "connector-canary-http", connector_type_id: ".webhook", is_missing_secrets: true, config: { url: "http://hooks.example.com/plain" } });
  fixtures.slmPolicies["slm-canary-stale"] = { version: 1, repository: "backups", policy: { indices: ["*"] } };
  fixtures.apiKeys.push({ id: "key-2", name: "apikey-canary-stale", type: "rest", creation: now - 400 * DAY_MS, invalidated: false, username: "auditor", realm: "native1", metadata: {}, role_descriptors: { reader: { cluster: ["all"] } }, _sort: [now - 400 * DAY_MS, "apikey-canary-stale"] });
  fixtures.watches.push({ _id: "watch-canary-http", watch: { trigger: {}, actions: { hook: { webhook: { scheme: "http", host: "hooks.example.com", port: 80 } } } } });
  return fixtures;
}

function leaves(value, path = "", output = []) {
  if (value !== null && typeof value === "object") {
    for (const [key, entry] of Object.entries(value)) leaves(entry, path ? `${path}.${key}` : key, output);
  } else {
    output.push([path, value]);
  }
  return output;
}

function pluck(value, path) {
  return path.split(".").reduce((cursor, key) => (cursor === null || cursor === undefined ? undefined : cursor[key]), value);
}

test("verdict rule 1 corollary: Elastic findings that read several inventories never pass, name the unreadable inventory, render its counts null, and name no principal from it", async () => {
  const fixtures = principalFixtures();
  const options = { sensitiveIndexPatterns: ["customers-*"], tenantIndexPatterns: ["tenant-*"] };
  const checked = [];
  for (const entry of ELASTIC_MULTI_INVENTORY) {
    const baseline = await entry.assess(stubClient(fixtures), options);
    const baselineFinding = findingById(baseline, entry.id);
    for (const [method, dataset] of Object.entries(entry.secondaries)) {
      const result = await entry.assess(stubClient(fixtures, { [method]: forbidden(`request ${method} failed (403 Forbidden): action is unauthorized for user [grc-auditor]`) }), options);
      const finding = findingById(result, entry.id);
      const label = `${entry.id} with ${dataset} forbidden`;
      assert.notEqual(finding.status, "pass", `${label} must not pass (was ${finding.status}: ${finding.summary})`);
      assert.ok(finding.summary.includes(dataset), `${label}: summary must name the unreadable inventory, got: ${finding.summary}`);
      const sources = [...(finding.evidence.unreadable_sources ?? []), ...(finding.evidence.unchecked_sources ?? []), ...(finding.evidence.partial_sources ?? [])];
      assert.ok(sources.some((source) => source.startsWith(`${dataset} (`)), `${label}: evidence must list ${dataset} among unreadable/unchecked sources, got ${JSON.stringify(sources)}`);
      if (finding.status === "manual") assert.match(finding.summary, /Collect manually:/, `${label}: manual verdicts say what a human must collect`);
      for (const field of entry.nullEvidence[dataset] ?? []) {
        const value = pluck(finding.evidence, field);
        assert.equal(value, null, `${label}: evidence.${field} must render null, got ${JSON.stringify(value)} (baseline ${JSON.stringify(pluck(baselineFinding.evidence, field))})`);
      }
      for (const field of entry.nullSummary[dataset] ?? []) {
        assert.equal(result.summary[field], null, `${label}: summary.${field} must render null, got ${JSON.stringify(result.summary[field])}`);
      }
      for (const [path, value] of leaves(finding.evidence)) {
        if (path.startsWith("unreadable_sources") || path.startsWith("unchecked_sources") || path.startsWith("partial_sources") || path.startsWith("inventories") || path.startsWith("inventory")) continue;
        const baselineValue = pluck(baselineFinding.evidence, path);
        if ((value === 0 || value === "none") && baselineValue !== 0 && baselineValue !== "none" && baselineValue !== undefined) {
          assert.fail(`${label}: evidence.${path} fell back to ${JSON.stringify(value)} from baseline ${JSON.stringify(baselineValue)} instead of null`);
        }
      }
      const serialized = JSON.stringify(finding);
      for (const principal of PRINCIPAL_CANARIES[dataset] ?? []) {
        assert.ok(!serialized.includes(principal), `${label}: ${principal} is named from the denied ${dataset} inventory`);
      }
      const inventories = finding.evidence.inventories ?? (finding.evidence.inventory ? [finding.evidence.inventory] : []);
      for (const inventory of inventories) {
        if (inventory.dataset === dataset) {
          assert.equal(inventory.read, false, `${label}: inventory state for ${dataset} must say it was not read`);
          assert.equal(inventory.seen, null);
          assert.equal(inventory.complete, false);
        }
      }
      checked.push(label);
    }
  }
  assert.ok(checked.length >= 38, `expected every multi-inventory pairing to be exercised, got ${checked.length}`);
});

test("verdict rule 1 corollary: Elastic findings keep judging readable inventories and still fail on them while a secondary is unreadable", async () => {
  const fixtures = principalFixtures();
  const rbac = findingById(await assessElasticAccessControl(stubClient(fixtures, { listRoleMappings: forbidden("request listRoleMappings failed (403 Forbidden)") })), "ELASTIC-06");
  assert.equal(rbac.status, "fail", "a violation observed in the readable users inventory is a real finding and is not hidden behind manual");
  assert.equal(rbac.evidence.observed_status, "fail");
  assert.match(rbac.summary, /Additional sources were unreadable or partial: role_mappings \(GET \/_security\/role_mapping\): request listRoleMappings failed \(403 Forbidden\)/);
  assert.match(rbac.summary, /The picture is incomplete until a human collects: /, "an unreadable essential inventory still says what a human must collect");
  assert.equal(typeof rbac.evidence.manual_evidence, "string");
  assert.equal(rbac.evidence.superuser_role_mappings, null);
  assert.equal(rbac.evidence.role_mappings_reviewed, null);
  assert.deepEqual(rbac.evidence.superusers, ["usr-canary-superadmin"], "principals from the readable users inventory are still named");
  assert.ok(!JSON.stringify(rbac).includes("mapping-canary-saml"), "no principal is named from the denied role_mappings inventory");

  const rbacNoViolation = findingById(await assessElasticAccessControl(stubClient(healthyFixtures(), { listRoleMappings: forbidden("request listRoleMappings failed (403 Forbidden)") })), "ELASTIC-06");
  assert.equal(rbacNoViolation.status, "manual", "without an observed violation, an unreadable essential inventory leaves the verdict unknown");
  assert.equal(rbacNoViolation.evidence.observed_status, "pass");
  assert.match(rbacNoViolation.summary, /Verdict is unknown because required evidence could not be read: role_mappings \(GET \/_security\/role_mapping\)/);

  const realms = findingById(await assessElasticIdentity(stubClient(fixtures, { getXpackUsage: forbidden("request getXpackUsage failed (403 Forbidden)") })), "ELASTIC-01");
  assert.equal(realms.status, "warn");
  assert.match(realms.summary, /Secure authentication realms are enabled beyond native\/file: saml/);
  assert.match(realms.summary, /not checked because they could not be read: xpack_usage \(GET \/_xpack\/usage\)/);
  assert.equal(realms.evidence.usage_realm_types, null);

  fixtures.nodeSettings.nodes["node-1"].settings["xpack.security.transport.ssl.enabled"] = "false";
  const transport = findingById(await assessElasticTransportSecurity(stubClient(fixtures, { getXpackUsage: forbidden("request getXpackUsage failed (403 Forbidden)") })), "ELASTIC-02");
  assert.equal(transport.status, "fail", "a violation observed in readable settings still fails");
  assert.match(transport.summary, /Additional sources were unreadable or partial: xpack_usage/);
});

test("verdict rule 5 / addendum 3: a truncated API key inventory never names a key and renders every count null", async () => {
  const now = Date.now();
  const fixtures = principalFixtures(now);
  const truncatedKeys = pagedList(fixtures.apiKeys, 5000, true, 1);
  const result = await assessElasticIdentity(stubClient(fixtures, { listApiKeys: async () => truncatedKeys }));
  for (const id of ["ELASTIC-09", "ELASTIC-10"]) {
    const finding = findingById(result, id);
    assert.notEqual(finding.status, "pass");
    assert.match(finding.summary, /api_keys inventory was not fully read \(2 key\(s\) seen of 5000 total\), so violators are neither counted nor named/);
    assert.ok(!JSON.stringify(finding).includes("apikey-canary-stale"), `${id} names a key from the truncated inventory`);
    assert.equal(finding.evidence.inventory.complete, false);
    assert.equal(finding.evidence.inventory.seen, 2);
    assert.equal(finding.evidence.inventory.total, 5000);
    assert.equal(finding.evidence.active, null);
    assert.equal(finding.evidence.inspected, null);
    assert.equal(finding.evidence.violation_observed, true, "a violation seen among the read keys is still reported without naming it");
  }
  assert.equal(findingById(result, "ELASTIC-09").status, "fail");
  assert.equal(findingById(result, "ELASTIC-09").evidence.flagged, null);
  assert.equal(findingById(result, "ELASTIC-10").evidence.privileged, null);
  assert.equal(result.summary.api_keys_complete, false);
  assert.equal(result.summary.api_keys_total, 5000);
  assert.match(result.truncated[0], /api_keys \(POST \/_security\/_query\/api_key\?with_limited_by=true\): truncated after 2 of 5000/);
});

test("addendum 5: access check surfaces and collection_status render collected/count/truncated as null for reads that never completed", async () => {
  const fixtures = healthyFixtures();
  const routes = healthyRoutes(fixtures);
  routes["GET /_security/role_mapping"] = jsonErrorWithUrl();
  routes["POST /_security/user/_has_privileges"] = htmlGateway();
  const config = sampleConfig({ maxRetries: 0, kibanaUrl: undefined });
  const client = new ElasticApiClient(config, { fetchImpl: createRouter(routes) });

  const access = await checkElasticAccess(client);
  const denied = access.surfaces.find((surface) => surface.name === "role_mappings");
  assert.deepEqual({ status: denied.status, collected: denied.collected, http_status: denied.http_status, count: denied.count, truncated: denied.truncated }, { status: "not_readable", collected: false, http_status: 403, count: null, truncated: null });
  const readable = access.surfaces.find((surface) => surface.name === "api_keys");
  assert.deepEqual({ collected: readable.collected, http_status: readable.http_status, count: readable.count, truncated: readable.truncated }, { collected: true, http_status: null, count: 1, truncated: false });
  const skipped = access.surfaces.find((surface) => surface.name === "kibana_spaces");
  assert.deepEqual({ status: skipped.status, collected: skipped.collected, http_status: skipped.http_status, count: skipped.count, truncated: skipped.truncated }, { status: "not_configured", collected: false, http_status: null, count: null, truncated: null });
  assert.equal(access.privilegeProbe, "not_readable");
  assert.equal(access.missingClusterPrivileges, null, "a failed privilege probe leaves missing privileges unknown, not empty");
  assert.equal(access.missingIndexPrivileges, null);
  assert.equal(access.status, "limited");
  assert.ok(access.notes.some((note) => /Privilege probe failed, so missing privileges are unknown: .*502 Bad Gateway: non-JSON body \(text\/html, \d+ bytes, not echoed\)/.test(note)), access.notes.join("\n"));
  for (const canary of canaryValues()) assert.ok(!JSON.stringify(access).includes(canary));

  const result = await exportElasticAuditBundle(client, config, createTempBase("elastic-collection-status-"));
  const status = JSON.parse(readFileSync(join(result.outputDir, "collection_status.json"), "utf8"));
  const deniedStatus = status.datasets.find((dataset) => dataset.name === "role_mappings");
  assert.deepEqual(
    { collected: deniedStatus.collected, status: deniedStatus.status, http_status: deniedStatus.http_status, count: deniedStatus.count, truncated: deniedStatus.truncated, paged: deniedStatus.paged, seen: deniedStatus.seen },
    { collected: false, status: "not_readable", http_status: 403, count: null, truncated: null, paged: null, seen: null },
  );
  const keyStatus = status.datasets.find((dataset) => dataset.name === "api_keys");
  assert.deepEqual({ collected: keyStatus.collected, truncated: keyStatus.truncated, seen: keyStatus.seen, total: keyStatus.total }, { collected: true, truncated: false, seen: 1, total: 1 });
  const skippedStatus = status.datasets.find((dataset) => dataset.name === "connectors");
  assert.deepEqual({ collected: skippedStatus.collected, status: skippedStatus.status, truncated: skippedStatus.truncated, http_status: skippedStatus.http_status }, { collected: false, status: "not_configured", truncated: null, http_status: null });
  assert.equal(status.totals.not_readable, 2, "role_mappings and the privilege probe were denied");
  assert.equal(status.totals.truncation_unknown, status.totals.not_readable + status.totals.not_configured);
  assert.equal(result.notCollectedCount, status.totals.not_configured);
  assert.equal(result.truncatedCount, 0);
});

test("addendum 5: denied list datasets write a not-collected marker in core_data while readable-but-empty datasets stay []", async () => {
  // role_mappings is keyed by mapping name in the Elasticsearch API, so its readable-but-empty shape is {}.
  const denials = [
    ["role_mappings", "GET /_security/role_mapping", "object"],
    ["ssl_certificates", "GET /_ssl/certificates", "array"],
    ["api_keys", "POST /_security/_query/api_key", "array"],
    ["watches", "POST /_watcher/_query/watches", "array"],
    ["connectors", "GET /api/actions/connectors", "array"],
    ["fleet_outputs", "GET /api/fleet/outputs", "array"],
  ];
  const isEmptyNativeShape = (data, shape) => (shape === "array"
    ? Array.isArray(data) && data.length === 0
    : !Array.isArray(data) && data !== null && typeof data === "object" && Object.keys(data).length === 0);
  for (const [dataset, route] of denials) {
    const fixtures = emptyInventoryFixtures();
    const routes = healthyRoutes(fixtures);
    routes[route] = jsonErrorWithUrl();
    const config = sampleConfig({ maxRetries: 0 });
    const result = await exportElasticAuditBundle(new ElasticApiClient(config, { fetchImpl: createRouter(routes) }), config, createTempBase(`elastic-marker-${dataset}-`));
    const files = readBundleFiles(result.outputDir);
    const file = JSON.parse(files.get(`core_data/${dataset}.json`));
    assert.equal(file.collected, false, `${dataset}: denied dataset must carry collected: false`);
    assert.equal(file.status, 403, `${dataset}: the marker carries the observed HTTP status`);
    assert.equal(`${file.endpoint}`.split("?")[0], route, `${dataset}: the marker names the endpoint that was requested`);
    assert.match(file.error, /403 Forbidden/);
    assert.equal(file.reason, "not_readable");
    assert.ok(!Array.isArray(file.data), `${dataset}: data must be the marker object, never []`);
    assert.equal(file.data.collected, false);
    assert.equal(file.data.status, 403);
    for (const [other, otherRoute, shape] of denials) {
      if (other === dataset) continue;
      const readable = JSON.parse(files.get(`core_data/${other}.json`));
      assert.equal(readable.collected, true, `${other} is readable when only ${dataset} is denied`);
      assert.equal(readable.status, "readable");
      assert.ok(isEmptyNativeShape(readable.data, shape), `${other}: readable-but-empty stays ${shape === "array" ? "[]" : "{}"}, got ${JSON.stringify(readable.data)} (route ${otherRoute})`);
      assert.equal(readable.data.collected, undefined, `${other}: an empty inventory never carries a marker field`);
    }
    assertCanaryWindowsAbsent(assert, files, canaryValues(), `marker bundle for ${dataset}`);
  }
});

function mentionedEndpoints(text) {
  return [...text.matchAll(/\b(GET|POST|PUT|PATCH|DELETE)\s+(\/[A-Za-z0-9_./?=&*<>-]+)/g)].map((match) => ({ method: match[1], path: match[2].split("?")[0].replace(/[.,;:)]+$/, "") }));
}

function mentionedStatusCodes(text) {
  const codes = new Set();
  for (const match of text.matchAll(/\b([1-5]\d\d) (?:OK|Forbidden|Unauthorized|Bad Gateway|Not Found|Internal Server Error|Service Unavailable|Gateway Timeout|Error)\b/g)) codes.add(Number(match[1]));
  for (const match of text.matchAll(/"(?:http_)?status":\s*([1-5]\d\d)\b/g)) codes.add(Number(match[1]));
  for (const match of text.matchAll(/\bstatus(?:Code)? ([1-5]\d\d)\b/g)) codes.add(Number(match[1]));
  return [...codes];
}

test("addendum 5: every endpoint and status code named in Elastic output corresponds to a request the run made and observed", async () => {
  const fixtures = canaryFixtures();
  const routes = healthyRoutes(fixtures);
  routes["GET /_security/role_mapping"] = htmlGateway();
  routes["GET /_ssl/certificates"] = jsonErrorWithUrl();
  routes["GET /api/fleet/outputs"] = () => jsonResponse({ statusCode: 403, error: "Forbidden", message: "missing fleet read" }, { status: 403, statusText: "Forbidden" });
  const log = [];
  const config = sampleConfig({ maxRetries: 0, kibanaSpaceId: "audit" });
  const client = new ElasticApiClient(config, { fetchImpl: createLoggingRouter(routes, log) });

  const access = await checkElasticAccess(client);
  const result = await exportElasticAuditBundle(client, config, createTempBase("elastic-request-log-"), { sensitiveIndexPatterns: ["customers-*"] });
  const files = readBundleFiles(result.outputDir);
  const outputs = [...files.values(), JSON.stringify(access)];

  const requested = new Set(log.map((entry) => `${entry.method} ${entry.path.replace(/^\/s\/[^/]+/, "")}`));
  const statuses = new Set(log.map((entry) => entry.status));
  assert.ok(statuses.has(502) && statuses.has(403) && statuses.has(200), `fixture must have served 200, 403, and 502; got ${[...statuses]}`);
  let endpointMentions = 0;
  let statusMentions = 0;
  for (const text of outputs) {
    for (const { method, path } of mentionedEndpoints(text)) {
      endpointMentions += 1;
      assert.ok(requested.has(`${method} ${path}`), `output names ${method} ${path} but the run never requested it; requested: ${[...requested].sort().join(", ")}`);
    }
    for (const code of mentionedStatusCodes(text)) {
      statusMentions += 1;
      assert.ok(statuses.has(code), `output names HTTP ${code} but no request observed it; observed: ${[...statuses]}`);
    }
  }
  assert.ok(endpointMentions > 30, `expected endpoint mentions across the bundle, got ${endpointMentions}`);
  assert.ok(statusMentions > 3, `expected status mentions across the bundle, got ${statusMentions}`);
  assert.ok(log.some((entry) => entry.path.startsWith("/s/audit/api/")), "Kibana requests carry the configured space prefix");

  // Kibana not configured: no Kibana endpoint may be named because none was requested.
  const noKibanaLog = [];
  const noKibanaConfig = sampleConfig({ maxRetries: 0, kibanaUrl: undefined });
  const noKibana = await exportElasticAuditBundle(new ElasticApiClient(noKibanaConfig, { fetchImpl: createLoggingRouter(healthyRoutes(healthyFixtures()), noKibanaLog) }), noKibanaConfig, createTempBase("elastic-no-kibana-"));
  const noKibanaRequested = new Set(noKibanaLog.map((entry) => `${entry.method} ${entry.path}`));
  assert.ok(![...noKibanaRequested].some((entry) => entry.includes("/api/")), "no Kibana request is made without KIBANA_URL");
  for (const [name, text] of readBundleFiles(noKibana.outputDir)) {
    for (const { method, path } of mentionedEndpoints(text)) {
      assert.ok(noKibanaRequested.has(`${method} ${path}`), `${name} names ${method} ${path} although Kibana was never requested`);
    }
  }
});

// ---------------------------------------------------------------------------------------------------------------
// Scrub boundary: fixed message text and every string a run records about legitimate data survive the scrubber.
// ---------------------------------------------------------------------------------------------------------------

/** Every fixed-text message the Elastic integration emits that a fixture run does not already produce. */
const ELASTIC_FIXED_TEXT_MESSAGES = [
  "Unable to read Elastic config file /home/auditor/.elastic-sec-inspector/config.yaml (ENOENT)",
  "Unable to read Elastic config file /home/auditor/.elastic-sec-inspector/config.yaml (EACCES)",
  "Unable to parse Elastic config file: invalid YAML in /home/auditor/.elastic-sec-inspector/config.yaml at line 3",
  "Unable to parse Elastic config file: invalid YAML in /home/auditor/.elastic-sec-inspector/config.yaml",
  "Elasticsearch URL is required. Set ELASTIC_URL, configure url in ~/.elastic-sec-inspector/config.yaml, or pass elasticsearch_url explicitly.",
  "KIBANA_URL is not configured.",
  "502 Bad Gateway: non-JSON body (text/html, 5120 bytes, not echoed)",
  "403 Forbidden: JSON body without a documented error field (application/json, 64 bytes, not echoed)",
  "elasticsearch request GET /_security/role_mapping failed (502 Bad Gateway): 502 Bad Gateway: non-JSON body (text/html, 5120 bytes, not echoed)",
  "elasticsearch request GET /_ssl/certificates failed (403 Forbidden): security_exception: unauthorized; see https://api.example.com/v1/x?[REDACTED] for details",
  "kibana request GET /api/fleet/outputs failed (403 Forbidden): Forbidden: missing fleet read",
  "elasticsearch request GET /_security/user returned a 200 OK: non-JSON body (text/html, 1024 bytes, not echoed); the endpoint is not serving the JSON API",
  "elasticsearch request GET /_security/user returned a 200 OK: empty body (0 bytes); the endpoint is not serving the JSON API",
  "elasticsearch request GET /_security/user failed (403 Forbidden): (detail truncated to 240 characters) security_exception: action [cluster:admin/xpack/security/user/get] is unauthorized for user [grc-auditor]",
  "elasticsearch request POST /_security/_query/api_key returned a 200 OK: JSON body that is not the documented JSON object with an array under api_keys (application/json, 41 bytes, not echoed); the endpoint is not serving the JSON API",
  "elasticsearch request GET /_security/user returned a 200 OK: JSON body that is not the documented JSON object of named entries each carrying any of username, roles, enabled (application/json, 41 bytes, not echoed); the endpoint is not serving the JSON API",
  "elasticsearch request GET /_security/role_mapping returned a 200 OK: JSON body that is not the documented JSON object of named entries each carrying any of enabled, roles, role_templates, rules, metadata (application/json, 41 bytes, not echoed); the endpoint is not serving the JSON API",
  "kibana request GET /api/spaces/space returned a 200 OK: JSON body that is not the documented JSON array of objects (application/json, 41 bytes, not echoed); the endpoint is not serving the JSON API",
  "elasticsearch request GET /_license returned a 200 OK: JSON body that is not the documented JSON object with any of license (application/json, 41 bytes, not echoed); the endpoint is not serving the JSON API",
  "elasticsearch request POST /_security/_query/api_key timed out after 30000ms",
  "elasticsearch request GET /_cluster/settings failed: SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body",
  "Using Elasticsearch https://es.example.com:9200 with api_key authentication.",
  "Kibana https://kibana.example.com:5601 (space audit) is configured.",
  "Kibana is not configured (set KIBANA_URL to enable Kibana checks).",
  "Privilege probe failed, so missing privileges are unknown: elasticsearch request POST /_security/user/_has_privileges failed (502 Bad Gateway): 502 Bad Gateway: non-JSON body (text/html, 5120 bytes, not echoed)",
  "Grant the auditing principal the monitor, read_security (or manage_security), manage_api_key, read_pipeline, monitor_snapshot, read_ilm, read_slm, and monitor_watcher cluster privileges, and set KIBANA_URL for Kibana checks.",
  "Verdict is unknown because required evidence could not be read: role_mappings (GET /_security/role_mapping): elasticsearch request GET /_security/role_mapping failed (403 Forbidden): security_exception: action [cluster:admin/xpack/security/role_mapping/get] is unauthorized for user [grc-auditor]. Observed from readable sources: no superuser role mappings",
  "Additional sources were unreadable or partial: xpack_usage (GET /_xpack/usage): request getXpackUsage failed (403 Forbidden)",
  "the watch definitions (POST /_watcher/_query/watches) and the Kibana connector inventory from every space (configure KIBANA_URL so the connectors API can be queried, or export the connectors from each space), then confirm webhook destinations use https and credentials are stored as secrets.",
  "Kibana evidence manually or set KIBANA_URL so the Kibana API can be queried:",
  "Only the default space exists, so Kibana space isolation between teams is not in use; confirm whether multi-team separation is required.",
  "api_keys inventory was not fully read (2 key(s) seen of 5000 total), so violators are neither counted nor named",
  "api_keys (POST /_security/_query/api_key?with_limited_by=true): truncated after 2 of 5000",
  JSON.stringify({ collected: false, status: 403, endpoint: "GET /_security/role_mapping", error: "elasticsearch request GET /_security/role_mapping failed (403 Forbidden): security_exception: unauthorized", reason: "not_readable" }),
  JSON.stringify({ collected: false, status: "not-collected", endpoint: null, error: "KIBANA_URL is not configured", reason: "not_configured" }),
];

test("scrub boundary: every fixed-text message the Elastic integration emits survives its own scrubber unchanged, including every string a healthy or partially denied run records", async () => {
  for (const message of ELASTIC_FIXED_TEXT_MESSAGES) {
    assert.equal(scrubErrorText(message), message, `fixed text was altered by the scrubber: ${message}`);
  }

  // Every string a run writes about legitimate data is fixed text from the run's point of view: the scrubber must not
  // rewrite a finding summary, a manual-evidence instruction, an inventory gap, or a bundle document. The principal
  // fixture is served over HTTP and every surface is denied in turn, so every named user, role, mapping, key, output,
  // connector, policy, and watch the run can mention is swept, beside every denial message the run can record.
  const config = sampleConfig({ maxRetries: 0 });
  const options = { sensitiveIndexPatterns: ["customers-*"], tenantIndexPatterns: ["tenant-*"] };
  const surfaces = Object.keys(healthyRoutes(principalFixtures()));
  const runs = [healthyRoutes(principalFixtures())];
  for (const surface of surfaces) {
    const routes = healthyRoutes(principalFixtures());
    routes[surface] = jsonErrorWithUrl();
    runs.push(routes);
  }
  let checked = 0;
  const altered = new Set();
  for (const routes of runs) {
    const client = new ElasticApiClient(config, { fetchImpl: createRouter(routes) });
    const access = await checkElasticAccess(client);
    const snapshot = await collectElasticSnapshot(client, ELASTIC_ALL_DATASETS, options);
    const assessments = ALL_AREAS.map((area) => evaluateElasticArea(area, snapshot, options, { elasticsearchUrl: config.elasticsearchUrl }));
    const exported = await exportElasticAuditBundle(client, config, createTempBase("elastic-scrub-survival-"), options);
    const files = readBundleFiles(exported.outputDir);
    const texts = [
      ...recordedErrorStrings(access, assessments, files),
      ...[...files].filter(([name]) => !name.startsWith("core_data/")).map(([, text]) => text),
      ...leaves(assessments).map(([, value]) => value).filter((value) => typeof value === "string"),
    ];
    checked += texts.length;
    for (const alteration of scrubAlterations(texts, scrubErrorText)) altered.add(alteration);
  }
  assert.ok(surfaces.length >= 30, `expected every collector and access probe route, got ${surfaces.length}`);
  assert.ok(checked > 2000, `expected thousands of recorded strings, got ${checked}`);
  assert.deepEqual([...altered], [], `legitimate run text altered by the scrubber:\n${[...altered].join("\n")}`);
});
