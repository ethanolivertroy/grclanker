import test from "node:test";
import assert from "node:assert/strict";
import {
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
  evaluateElasticArea,
  exportElasticAuditBundle,
  normalizeElasticApiKey,
  redactSecrets,
  redactSensitiveValues,
  registerElasticTools,
  resolveElasticConfiguration,
  resolveSecureOutputPath,
} from "../dist/extensions/grc-tools/elastic.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";

const DAY_MS = 86_400_000;
const API_KEY = Buffer.from("audit-id:audit-secret-value").toString("base64");

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
        roles: { native: { size: 4, fls: 1, dls: 1 }, file: { size: 0, fls: 0, dls: 0 } },
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
    "GET /api/status": { status: { overall: { level: "available" } } },
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
    "GET /api/fleet/fleet_server_hosts": (url) => {
      const page = Number(url.searchParams.get("page"));
      const perPage = Number(url.searchParams.get("perPage"));
      const items = Array.from({ length: 250 }, (_, index) => ({ id: `h${index + 1}` }));
      return { items: items.slice((page - 1) * perPage, page * perPage), page, perPage };
    },
  });
  const client = new ElasticApiClient(sampleConfig(), { fetchImpl });

  const complete = await client.listWatches(500);
  assert.deepEqual({ seen: complete.seen, pages: complete.pages, truncated: complete.truncated, total: complete.total }, { seen: 230, pages: 3, truncated: false, total: undefined });

  const capped = await client.listWatches(200);
  assert.deepEqual({ seen: capped.seen, pages: capped.pages, truncated: capped.truncated }, { seen: 200, pages: 2, truncated: true });

  const hosts = await client.listFleetServerHosts(100);
  assert.deepEqual({ seen: hosts.seen, pages: hosts.pages, truncated: hosts.truncated }, { seen: 100, pages: 1, truncated: true });

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
  const spaces = JSON.parse(readFileSync(join(result.outputDir, "core_data", "kibana_spaces.json"), "utf8"));
  assert.equal(spaces.skipped, "KIBANA_URL is not configured");
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
  try {
    const kibanaTool = registered.find((tool) => tool.name === "elastic_assess_kibana");
    const result = await kibanaTool.execute("call-1", kibanaTool.prepareArguments({
      elasticsearch_url: "https://es.example.com:9200",
      kibana_url: "https://kibana.example.com:5601",
      api_key: API_KEY,
      config_file: join(createTempBase("elastic-no-config-"), "missing.yaml"),
    }));
    assert.equal(result.isError, undefined);
    assert.match(result.content[0].text, /Elastic Kibana governance and Fleet/);
    assert.match(result.content[0].text, /ELASTIC-16/);
    assert.equal(result.details.tool, "elastic_assess_kibana");
    assert.equal(result.details.findings.length, 3);

    const checkTool = registered.find((tool) => tool.name === "elastic_check_access");
    const failure = await checkTool.execute("call-2", checkTool.prepareArguments({
      elasticsearch_url: "https://es.example.com:9200",
      config_file: join(createTempBase("elastic-no-config-"), "missing.yaml"),
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
