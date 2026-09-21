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
  MulesoftApiClient,
  MulesoftApiError,
  assessMulesoftApiGateway,
  assessMulesoftAuditMonitoring,
  assessMulesoftIdentityAccess,
  assessMulesoftRuntimeInfrastructure,
  checkMulesoftAccess,
  exportMulesoftAuditBundle,
  getMulesoftControlCatalog,
  parseSimpleToml,
  redactSecretText,
  redactSnapshot,
  resolveMulesoftConfiguration,
  resolveSecureOutputPath,
} from "../dist/extensions/grc-tools/mulesoft.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";

const DAY_MS = 24 * 60 * 60 * 1000;
const ORG_ID = "org-1";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function isoDaysFromNow(days) {
  return new Date(Date.now() + days * DAY_MS).toISOString();
}

function sampleConfig(overrides = {}) {
  return {
    organizationId: ORG_ID,
    controlPlane: "us",
    baseUrl: "https://anypoint.mulesoft.com",
    authMode: "token",
    token: "anypoint-token",
    environmentFilter: [],
    timeoutMs: 30000,
    sourceChain: ["tests"],
    ...overrides,
  };
}

function jsonResponse(value, options = {}) {
  return new Response(JSON.stringify(value), {
    status: options.status ?? 200,
    statusText: options.statusText ?? "",
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

function findingById(result, id) {
  return result.findings.find((item) => item.id === id);
}

function statusOf(result, id) {
  return findingById(result, id)?.status;
}

// The NewDefault-v1 and OldDefault suites documented at docs.mulesoft.com/cloudhub/lb-cert-validation.
const STRONG_CIPHER_SUITE = "ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384";
const OLD_DEFAULT_CIPHER_SUITE = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4";

const ENVIRONMENTS = [
  { id: "env-prod", name: "Production", isProduction: true, type: "production" },
  { id: "env-sandbox", name: "Sandbox", isProduction: false, type: "sandbox" },
];

function healthyIdentityClient(overrides = {}) {
  return {
    getResolvedConfig: () => sampleConfig(),
    async getOrganization() {
      return { id: ORG_ID, name: "Acme", isFederated: true, entitlements: { createSubOrgs: true } };
    },
    async getOrganizationHierarchy() {
      return { id: ORG_ID, isRoot: true, subOrganizations: [{ id: "bg-1", name: "Payments" }] };
    },
    async listIdentityProviders() {
      return [{ provider_id: "idp-1", name: "Okta SAML", type: { name: "saml" } }];
    },
    async getIdentityProviderSettings() {
      return { allow_new_non_sso_users: false };
    },
    async listMembers() {
      return [{ id: "u1", username: "alice" }, { id: "u2", username: "bob" }];
    },
    async listMfaExemptUsers() {
      return [];
    },
    async listRoleGroups() {
      return [
        { role_group_id: "rg-admin", name: "Organization Administrators", editable: false },
        { role_group_id: "rg-dev", name: "Developers", editable: true },
      ];
    },
    async listRoleGroupRoles(roleGroupId) {
      if (roleGroupId === "rg-admin") return [{ role_id: "r1", name: "Organization Administrator" }];
      return [{ role_id: "r2", name: "CloudHub Developer", context_params: { envId: "env-prod" } }];
    },
    async listRoleGroupUsers() {
      return [{ id: "u1", username: "alice" }];
    },
    async listEnvironments() {
      return ENVIRONMENTS;
    },
    async listConnectedApplications() {
      return [{ client_id: "app-1", client_name: "Auditor", enabled: true, last_used: isoDaysFromNow(-3), client_secret: "hidden" }];
    },
    async listConnectedApplicationScopes() {
      return [{ scope: "read:audit_logs" }, { scope: "profile" }];
    },
    ...overrides,
  };
}

function healthyApiGatewayClient(overrides = {}) {
  return {
    getResolvedConfig: () => sampleConfig(),
    async getOrganizationHierarchy() {
      return { id: ORG_ID, isRoot: true, subOrganizations: [] };
    },
    async listEnvironments() {
      return ENVIRONMENTS;
    },
    async listManagedApis(environmentId) {
      if (environmentId === "env-prod") {
        return [{ id: 101, assetName: "orders-api", instanceLabel: "v1", environmentId, activeContractsCount: 3 }];
      }
      return [{ id: 201, assetName: "orders-api", environmentId, activeContractsCount: 0 }];
    },
    async listApiPolicies() {
      return [
        { policyId: 1, assetId: "client-id-enforcement", disabled: false },
        { policyId: 2, assetId: "rate-limiting", disabled: false },
      ];
    },
    async listExchangeAssets() {
      return [{ organizationId: ORG_ID, assetId: "orders-api", name: "Orders API", status: "published", isPublic: false, type: "rest-api" }];
    },
    ...overrides,
  };
}

function healthyRuntimeClient(overrides = {}) {
  return {
    getResolvedConfig: () => sampleConfig(),
    async getOrganizationHierarchy() {
      return { id: ORG_ID, isRoot: true, subOrganizations: [] };
    },
    async listEnvironments() {
      return ENVIRONMENTS;
    },
    async listCloudhubApplications(environmentId) {
      if (environmentId === "env-prod") {
        return [{
          domain: "orders-prod",
          muleVersion: { version: "4.6.0", endOfSupportDate: isoDaysFromNow(400) },
          workers: { amount: 2, type: { name: "Small", weight: 0.2 }, recentStatistics: { cpu: 45 } },
          persistentQueues: true,
          persistentQueuesEncrypted: true,
          properties: { "db.password": "****" },
          propertiesOptions: { "db.password": { secure: true } },
        }];
      }
      return [{
        domain: "orders-dev",
        muleVersion: { version: "4.6.0", endOfSupportDate: isoDaysFromNow(400) },
        workers: { amount: 1, type: { name: "Micro", weight: 0.1 } },
        persistentQueues: false,
        properties: {},
      }];
    },
    async listVpcs() {
      return [{ id: "vpc-1", name: "prod-vpc" }];
    },
    async getVpc() {
      return { id: "vpc-1", name: "prod-vpc", firewallRules: [{ cidrBlock: "10.0.0.0/16", protocol: "tcp", fromPort: 8091, toPort: 8092 }] };
    },
    async listLoadBalancers() {
      return [{
        id: "lb-1",
        name: "prod-dlb",
        domain: "prod-dlb.lb.anypointdns.net",
        httpMode: "redirect",
        tlsv1: false,
        tlsv13: true,
        state: "STARTED",
        defaultCipherSuite: STRONG_CIPHER_SUITE,
      }];
    },
    async probeCertificate(host) {
      return { host, subject: "*.example.com", issuer: "Example CA", validFrom: isoDaysFromNow(-100), validTo: isoDaysFromNow(200) };
    },
    async listHybridServers(environmentId) {
      return environmentId === "env-prod" ? [{ id: 1, name: "onprem-1", status: "RUNNING", muleVersion: "4.6.0" }] : [];
    },
    async listMqRegions(environmentId) {
      return environmentId === "env-prod" ? [{ regionId: "us-east-1" }] : [];
    },
    async listMqQueues() {
      return [{ queueId: "orders", encrypted: true }];
    },
    async listMqClients() {
      return [{ clientId: "mq-client-1", clientSecret: "hidden" }];
    },
    async listSecretGroups(environmentId) {
      return environmentId === "env-prod" ? [{ id: "sg-1", name: "prod-secrets" }] : [];
    },
    ...overrides,
  };
}

function healthyAuditClient(overrides = {}) {
  return {
    getResolvedConfig: () => sampleConfig(),
    async getOrganizationHierarchy() {
      return { id: ORG_ID, isRoot: true, subOrganizations: [] };
    },
    async listEnvironments() {
      return ENVIRONMENTS;
    },
    async listAuditPlatforms() {
      return [{ name: "Access Management" }, { name: "API Manager" }];
    },
    async queryAuditLogs() {
      return { data: [{ timestamp: new Date().toISOString(), platform: "Access Management", action: "LOGIN", objectType: "User" }], total: 42 };
    },
    async listCloudhubAlerts(environmentId) {
      return environmentId === "env-prod" ? [{ id: "alert-1", name: "CPU", enabled: true, condition: { resources: ["*"] } }] : [];
    },
    async listHybridAlerts() {
      return [];
    },
    async listCloudhubApplications(environmentId) {
      return environmentId === "env-prod" ? [{ domain: "orders-prod" }] : [];
    },
    ...overrides,
  };
}

function healthyBundleClient(overrides = {}) {
  return {
    ...healthyIdentityClient(),
    ...healthyApiGatewayClient(),
    ...healthyRuntimeClient(),
    ...healthyAuditClient(),
    async getCurrentUser() {
      return { user: { id: "u1", username: "alice" } };
    },
    async listCloudhubApplications(environmentId) {
      return healthyRuntimeClient().listCloudhubApplications(environmentId);
    },
    ...overrides,
  };
}

test("control catalog covers all 25 spec controls with eight framework mappings each", () => {
  const catalog = getMulesoftControlCatalog();
  assert.equal(catalog.length, 25);
  assert.deepEqual(catalog.map((item) => item.number), Array.from({ length: 25 }, (_, index) => index + 1));
  assert.equal(new Set(catalog.map((item) => item.id)).size, 25);
  for (const definition of catalog) {
    assert.deepEqual(
      Object.keys(definition.mappings).sort(),
      ["cis", "cmmc", "disa_stig", "fedramp", "irap", "ismap", "pci_dss", "soc2"],
    );
    assert.ok(Object.values(definition.mappings).every((value) => typeof value === "string" && value.length > 0));
  }
});

test("parseSimpleToml handles sections, comments, arrays, and quoted values", () => {
  const parsed = parseSimpleToml([
    "# comment",
    "org_id = \"org-file\" # trailing comment",
    "timeout = 45",
    "verbose = true",
    "",
    "[auth]",
    "client_id = 'file-client'",
    "environments = [\"Production\", \"Sandbox\"]",
  ].join("\n"));

  assert.equal(parsed.org_id, "org-file");
  assert.equal(parsed.timeout, 45);
  assert.equal(parsed.verbose, true);
  assert.equal(parsed["auth.client_id"], "file-client");
  assert.deepEqual(parsed["auth.environments"], ["Production", "Sandbox"]);
});

test("resolveMulesoftConfiguration prefers explicit args over environment and config file", () => {
  const home = createTempBase("grclanker-mulesoft-home-");
  const configPath = join(home, "config.toml");
  writeFileSync(configPath, [
    "org_id = \"org-file\"",
    "client_id = \"file-client\"",
    "client_secret = \"file-secret\"",
    "control_plane = \"eu\"",
    "environments = [\"FileEnv\"]",
    "timeout = 45",
  ].join("\n"));
  const env = {
    ANYPOINT_ORG_ID: "org-env",
    ANYPOINT_CLIENT_ID: "env-client",
    ANYPOINT_CLIENT_SECRET: "env-secret",
    ANYPOINT_CONTROL_PLANE: "gov",
    ANYPOINT_ENVIRONMENTS: "EnvA, EnvB",
    MULESOFT_SEC_INSPECTOR_CONFIG: configPath,
  };

  const fromArgs = resolveMulesoftConfiguration({
    organization_id: "org-arg",
    client_id: "arg-client",
    client_secret: "arg-secret",
    control_plane: "us",
    environments: "ArgEnv",
    timeout_seconds: 12,
  }, env, { homeDir: home });
  assert.equal(fromArgs.organizationId, "org-arg");
  assert.equal(fromArgs.clientId, "arg-client");
  assert.equal(fromArgs.clientSecret, "arg-secret");
  assert.equal(fromArgs.authMode, "connected_app");
  assert.equal(fromArgs.controlPlane, "us");
  assert.equal(fromArgs.baseUrl, "https://anypoint.mulesoft.com");
  assert.deepEqual(fromArgs.environmentFilter, ["ArgEnv"]);
  assert.equal(fromArgs.timeoutMs, 12000);
  assert.ok(fromArgs.sourceChain.includes("arguments-organization"));
  assert.ok(fromArgs.sourceChain.includes(`config:${configPath}`));

  const fromEnv = resolveMulesoftConfiguration({}, env, { homeDir: home });
  assert.equal(fromEnv.organizationId, "org-env");
  assert.equal(fromEnv.clientId, "env-client");
  assert.equal(fromEnv.controlPlane, "gov");
  assert.equal(fromEnv.baseUrl, "https://gov.anypoint.mulesoft.com");
  assert.deepEqual(fromEnv.environmentFilter, ["EnvA", "EnvB"]);
  assert.ok(fromEnv.sourceChain.includes("environment-organization"));

  const fromFile = resolveMulesoftConfiguration({}, { MULESOFT_SEC_INSPECTOR_CONFIG: configPath }, { homeDir: home });
  assert.equal(fromFile.organizationId, "org-file");
  assert.equal(fromFile.clientId, "file-client");
  assert.equal(fromFile.clientSecret, "file-secret");
  assert.equal(fromFile.controlPlane, "eu");
  assert.equal(fromFile.baseUrl, "https://eu1.anypoint.mulesoft.com");
  assert.deepEqual(fromFile.environmentFilter, ["FileEnv"]);
  assert.equal(fromFile.timeoutMs, 45000);
  assert.ok(fromFile.sourceChain.includes("config-organization"));
});

test("resolveMulesoftConfiguration reads the default config.toml location under the home directory", () => {
  const home = createTempBase("grclanker-mulesoft-defaulthome-");
  const configDir = join(home, ".config", "mulesoft-sec-inspector");
  mkdirSync(configDir, { recursive: true });
  writeFileSync(join(configDir, "config.toml"), "org_id = \"org-home\"\nusername = \"auditor\"\npassword = \"pw-home\"\n");

  const resolved = resolveMulesoftConfiguration({}, {}, { homeDir: home });
  assert.equal(resolved.organizationId, "org-home");
  assert.equal(resolved.authMode, "credentials");
  assert.equal(resolved.username, "auditor");
  assert.equal(resolved.password, "pw-home");
});

test("resolveMulesoftConfiguration selects auth mode, control planes, and custom base URLs", () => {
  const home = createTempBase("grclanker-mulesoft-empty-home-");

  const tokenMode = resolveMulesoftConfiguration({}, {
    ANYPOINT_ORG_ID: ORG_ID,
    ANYPOINT_TOKEN: "pre-issued",
    ANYPOINT_CLIENT_ID: "client",
    ANYPOINT_CLIENT_SECRET: "secret",
  }, { homeDir: home });
  assert.equal(tokenMode.authMode, "token");
  assert.equal(tokenMode.token, "pre-issued");

  const credentialsMode = resolveMulesoftConfiguration({}, {
    ANYPOINT_ORG_ID: ORG_ID,
    ANYPOINT_USERNAME: "auditor",
    ANYPOINT_PASSWORD: "pw",
  }, { homeDir: home });
  assert.equal(credentialsMode.authMode, "credentials");

  const euPlane = resolveMulesoftConfiguration({ control_plane: "EU" }, { ANYPOINT_ORG_ID: ORG_ID, ANYPOINT_TOKEN: "t" }, { homeDir: home });
  assert.equal(euPlane.controlPlane, "eu");
  assert.equal(euPlane.baseUrl, "https://eu1.anypoint.mulesoft.com");

  const govPlane = resolveMulesoftConfiguration({ control_plane: "gov" }, { ANYPOINT_ORG_ID: ORG_ID, ANYPOINT_TOKEN: "t" }, { homeDir: home });
  assert.equal(govPlane.baseUrl, "https://gov.anypoint.mulesoft.com");

  const baseUrlPlane = resolveMulesoftConfiguration({}, {
    ANYPOINT_ORG_ID: ORG_ID,
    ANYPOINT_TOKEN: "t",
    ANYPOINT_BASE_URL: "https://eu1.anypoint.mulesoft.com/",
  }, { homeDir: home });
  assert.equal(baseUrlPlane.controlPlane, "eu");
  assert.equal(baseUrlPlane.baseUrl, "https://eu1.anypoint.mulesoft.com");

  const customPlane = resolveMulesoftConfiguration({ base_url: "https://anypoint.example.internal/" }, { ANYPOINT_ORG_ID: ORG_ID, ANYPOINT_TOKEN: "t" }, { homeDir: home });
  assert.equal(customPlane.controlPlane, "custom");
  assert.equal(customPlane.baseUrl, "https://anypoint.example.internal");

  assert.throws(() => resolveMulesoftConfiguration({ control_plane: "apac" }, { ANYPOINT_ORG_ID: ORG_ID, ANYPOINT_TOKEN: "t" }, { homeDir: home }), /Unsupported MuleSoft control plane/);
  assert.throws(() => resolveMulesoftConfiguration({}, { ANYPOINT_TOKEN: "t" }, { homeDir: home }), /ANYPOINT_ORG_ID/);
  assert.throws(() => resolveMulesoftConfiguration({}, { ANYPOINT_ORG_ID: ORG_ID }, { homeDir: home }), /connected app credentials/);
  assert.throws(() => resolveMulesoftConfiguration({}, { ANYPOINT_ORG_ID: ORG_ID, ANYPOINT_CLIENT_ID: "only-id" }, { homeDir: home }), /connected app credentials/);
});

test("MulesoftApiClient exchanges connected app credentials and paginates with limit and offset", async () => {
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({
      pathname: url.pathname,
      search: url.search,
      method: init.method ?? "GET",
      auth: headerValue(init.headers, "authorization"),
      body: init.body ? JSON.parse(init.body) : undefined,
    });

    if (url.pathname === "/accounts/api/v2/oauth2/token") {
      return jsonResponse({ access_token: "oauth-token", expires_in: 3600, token_type: "bearer" });
    }

    const offset = Number(url.searchParams.get("offset"));
    if (offset === 0) return jsonResponse({ data: [{ id: "u1" }, { id: "u2" }], total: 3 });
    return jsonResponse({ data: [{ id: "u3" }], total: 3 });
  };

  const client = new MulesoftApiClient(resolveMulesoftConfiguration({
    organization_id: ORG_ID,
    client_id: "client-id",
    client_secret: "client-secret",
  }, {}, { homeDir: createTempBase("grclanker-mulesoft-client-home-") }), { fetchImpl });
  const members = await client.listOffset(`/accounts/api/organizations/${ORG_ID}/members`, { limit: 10, pageSize: 2 });

  assert.deepEqual(members.items.map((member) => member.id), ["u1", "u2", "u3"]);
  assert.equal(members.total, 3);
  assert.equal(members.truncated, false);
  assert.equal(seen[0].pathname, "/accounts/api/v2/oauth2/token");
  assert.equal(seen[0].method, "POST");
  assert.equal(seen[0].auth, undefined);
  assert.deepEqual(seen[0].body, { grant_type: "client_credentials", client_id: "client-id", client_secret: "client-secret" });
  assert.equal(seen[1].pathname, `/accounts/api/organizations/${ORG_ID}/members`);
  assert.equal(seen[1].auth, "Bearer oauth-token");
  assert.ok(seen[1].search.includes("limit=2"));
  assert.ok(seen[1].search.includes("offset=0"));
  assert.ok(seen[2].search.includes("offset=2"));
  assert.equal(seen.filter((item) => item.pathname === "/accounts/api/v2/oauth2/token").length, 1);
});

test("MulesoftApiClient logs in with username and password and sends environment headers", async () => {
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({
      pathname: url.pathname,
      method: init.method ?? "GET",
      body: init.body ? JSON.parse(init.body) : undefined,
      envHeader: headerValue(init.headers, "X-ANYPNT-ENV-ID"),
      orgHeader: headerValue(init.headers, "X-ANYPNT-ORG-ID"),
      auth: headerValue(init.headers, "authorization"),
    });
    if (url.pathname === "/accounts/login") {
      return jsonResponse({ access_token: "login-token", token_type: "bearer" });
    }
    return jsonResponse({ data: [{ domain: "orders-prod" }] });
  };

  const client = new MulesoftApiClient(sampleConfig({ authMode: "credentials", token: undefined, username: "auditor", password: "pw" }), { fetchImpl });
  const applications = await client.listCloudhubApplications("env-prod");

  assert.deepEqual(applications, [{ domain: "orders-prod" }]);
  assert.equal(seen[0].pathname, "/accounts/login");
  assert.deepEqual(seen[0].body, { username: "auditor", password: "pw" });
  assert.equal(seen[1].pathname, "/cloudhub/api/v2/applications");
  assert.equal(seen[1].envHeader, "env-prod");
  assert.equal(seen[1].orgHeader, ORG_ID);
  assert.equal(seen[1].auth, "Bearer login-token");
});

test("MulesoftApiClient uses a pre-issued token without exchanging credentials", async () => {
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({ pathname: url.pathname, auth: headerValue(init.headers, "authorization") });
    return jsonResponse({ id: ORG_ID, name: "Acme" });
  };

  const client = new MulesoftApiClient(sampleConfig(), { fetchImpl });
  const organization = await client.getOrganization();

  assert.equal(organization.name, "Acme");
  assert.equal(seen.length, 1);
  assert.equal(seen[0].pathname, `/accounts/api/organizations/${ORG_ID}`);
  assert.equal(seen[0].auth, "Bearer anypoint-token");
});

test("MulesoftApiClient retries 429 and 5xx responses with backoff", async () => {
  let attempts = 0;
  const sleeps = [];
  const fetchImpl = async () => {
    attempts += 1;
    if (attempts === 1) return jsonResponse({ message: "slow down" }, { status: 429, headers: { "retry-after": "2" } });
    if (attempts === 2) return jsonResponse({ message: "upstream" }, { status: 503 });
    return jsonResponse({ data: [{ role_group_id: "rg-1", name: "Developers" }], total: 1 });
  };

  const client = new MulesoftApiClient(sampleConfig(), {
    fetchImpl,
    sleepImpl: async (ms) => {
      sleeps.push(ms);
    },
    retryBaseDelayMs: 10,
  });
  const roleGroups = await client.listRoleGroups();

  assert.equal(roleGroups.items.length, 1);
  assert.equal(roleGroups.truncated, false);
  assert.equal(attempts, 3);
  assert.deepEqual(sleeps, [2000, 20]);
});

test("MulesoftApiClient surfaces non-retryable errors with status and redacted secrets", async () => {
  const sleeps = [];
  const fetchImpl = async () => jsonResponse(
    { error: "forbidden", message: "Not allowed for client_secret=top-secret-value with Bearer anypoint-token" },
    { status: 403, statusText: "Forbidden" },
  );
  const client = new MulesoftApiClient(sampleConfig(), {
    fetchImpl,
    sleepImpl: async (ms) => {
      sleeps.push(ms);
    },
  });

  await assert.rejects(
    () => client.listMembers(),
    (error) => {
      assert.ok(error instanceof MulesoftApiError);
      assert.equal(error.status, 403);
      assert.match(error.message, /403/);
      assert.match(error.message, /\/accounts\/api\/organizations\/org-1\/members/);
      assert.doesNotMatch(error.message, /top-secret-value/);
      assert.doesNotMatch(error.message, /anypoint-token/);
      return true;
    },
  );
  assert.deepEqual(sleeps, []);
});

test("redaction helpers mask secret-bearing keys and token text", () => {
  const redacted = redactSnapshot({
    client_id: "app-1",
    client_secret: "shh",
    nested: [{ password: "pw", name: "ok" }],
    authorization: "Bearer abc",
  });
  assert.equal(redacted.client_id, "app-1");
  assert.equal(redacted.client_secret, "[REDACTED]");
  assert.equal(redacted.nested[0].password, "[REDACTED]");
  assert.equal(redacted.nested[0].name, "ok");
  assert.equal(redacted.authorization, "[REDACTED]");

  const text = redactSecretText("Authorization: Bearer abc.def-ghi, client_secret=super-secret, \"password\": \"pw123\" body my-token-value", ["my-token-value"]);
  assert.doesNotMatch(text, /abc\.def-ghi/);
  assert.doesNotMatch(text, /super-secret/);
  assert.doesNotMatch(text, /pw123/);
  assert.doesNotMatch(text, /my-token-value/);
});

test("checkMulesoftAccess reports a healthy organization when every surface is readable", async () => {
  const result = await checkMulesoftAccess(healthyBundleClient());

  assert.equal(result.status, "healthy");
  assert.equal(result.organizationId, ORG_ID);
  assert.equal(result.controlPlane, "us");
  assert.equal(result.authMode, "token");
  assert.ok(result.surfaces.length >= 18);
  assert.ok(result.surfaces.every((surface) => surface.status === "readable"));
  assert.deepEqual(result.missingPermissions, []);
  assert.ok(result.notes.some((note) => note.includes("alice")));
  assert.ok(result.notes.some((note) => note.includes("Production")));
  assert.match(result.recommendedNextStep, /mulesoft_assess_identity_access/);
  for (const name of ["organization", "identity_providers", "members", "role_groups", "environments", "api_manager_apis", "exchange_assets", "cloudhub_applications", "vpcs", "load_balancers", "audit_query", "mq_regions", "secret_groups"]) {
    assert.ok(result.surfaces.some((surface) => surface.name === name), `expected surface ${name}`);
  }
});

test("checkMulesoftAccess reports limited access and missing permissions when surfaces are forbidden", async () => {
  const forbidden = (permissionLabel) => async () => {
    throw new MulesoftApiError(403, `Anypoint request failed (403 Forbidden) for ${permissionLabel}`);
  };
  const client = healthyBundleClient({
    listIdentityProviders: forbidden("identityProviders"),
    listConnectedApplications: forbidden("connectedApplications"),
    listManagedApis: forbidden("apis"),
    listVpcs: forbidden("vpcs"),
    listLoadBalancers: forbidden("loadbalancers"),
    listAuditPlatforms: forbidden("platforms"),
    queryAuditLogs: forbidden("query"),
    listMqRegions: forbidden("regions"),
    listSecretGroups: forbidden("secretGroups"),
    async listEnvironments() {
      throw new Error("network unreachable");
    },
  });

  const result = await checkMulesoftAccess(client);

  assert.equal(result.status, "limited");
  assert.ok(result.surfaces.some((surface) => surface.name === "identity_providers" && surface.status === "not_readable" && surface.httpStatus === 403));
  assert.ok(result.surfaces.some((surface) => surface.name === "environments" && surface.status === "not_readable" && surface.httpStatus === undefined));
  assert.ok(result.surfaces.some((surface) => surface.name === "cloudhub_applications" && surface.status === "skipped"));
  assert.ok(result.missingPermissions.some((permission) => /Audit Log Viewer/.test(permission)));
  assert.ok(result.missingPermissions.some((permission) => /CloudHub Network Viewer/.test(permission)));
  assert.ok(result.missingPermissions.some((permission) => /View Connected Applications/.test(permission)));
  assert.match(result.recommendedNextStep, /Grant the connected app or user these read permissions/);
  assert.ok(result.notes.some((note) => note.includes("No environment was readable")));
});

test("assessMulesoftIdentityAccess passes a federated, least-privilege organization", async () => {
  const result = await assessMulesoftIdentityAccess(healthyIdentityClient());

  assert.equal(result.category, "identity_access");
  assert.deepEqual(result.findings.map((item) => item.control), [1, 2, 3, 4, 5, 6, 18, 19, 25]);
  assert.equal(statusOf(result, "MULESOFT-IAM-01"), "pass");
  assert.equal(statusOf(result, "MULESOFT-IAM-02"), "manual");
  assert.match(findingById(result, "MULESOFT-IAM-02").summary, /multi-factor authentication setting/);
  assert.equal(statusOf(result, "MULESOFT-IAM-03"), "pass");
  assert.equal(statusOf(result, "MULESOFT-IAM-04"), "pass");
  assert.equal(statusOf(result, "MULESOFT-IAM-05"), "pass");
  assert.equal(statusOf(result, "MULESOFT-IAM-06"), "pass");
  assert.equal(statusOf(result, "MULESOFT-IAM-18"), "pass");
  assert.equal(statusOf(result, "MULESOFT-IAM-19"), "pass");
  assert.equal(statusOf(result, "MULESOFT-IAM-25"), "pass");
  assert.equal(result.summary.organization_admins, 1);
  assert.deepEqual(result.errors, []);
  assert.equal(result.snapshots.connected_applications[0].client_secret, "[REDACTED]");
  for (const item of result.findings) {
    assert.equal(item.mappings.length, 8);
    assert.ok(item.mappings.some((mapping) => mapping.startsWith("FedRAMP ")));
    assert.ok(item.mappings.some((mapping) => mapping.startsWith("ISMAP ")));
  }
  assert.ok(findingById(result, "MULESOFT-IAM-01").mappings.includes("FedRAMP IA-2(1)"));
  assert.ok(findingById(result, "MULESOFT-IAM-01").mappings.includes("PCI-DSS 8.4.1"));
});

test("assessMulesoftIdentityAccess fails weak identity and privilege posture", async () => {
  const orgWideRoles = ["CloudHub Admin", "Runtime Manager Admin", "API Manager Admin", "Application Deployer", "Anypoint MQ Admin", "Secrets Manager Admin"]
    .map((name, index) => ({ role_id: `role-${index}`, name }));
  const client = healthyIdentityClient({
    async listIdentityProviders() {
      return [];
    },
    async getIdentityProviderSettings() {
      return { allow_new_non_sso_users: true };
    },
    async listMfaExemptUsers() {
      return [{ id: "u3", username: "contractor", mfaVerificationExcluded: true }];
    },
    async listRoleGroups() {
      return [
        { role_group_id: "rg-admin", name: "Organization Administrators", editable: false },
        { role_group_id: "rg-power", name: "Power Users", editable: true },
        { role_group_id: "rg-ops", name: "Platform Ops", editable: true },
      ];
    },
    async listRoleGroupRoles(roleGroupId) {
      if (roleGroupId === "rg-admin") return [{ role_id: "r1", name: "Organization Administrator" }];
      if (roleGroupId === "rg-power") return [{ role_id: "r2", name: "Organization Administrator" }];
      return orgWideRoles;
    },
    async listRoleGroupUsers(roleGroupId) {
      if (roleGroupId === "rg-admin") return [{ id: "u1", username: "alice" }, { id: "u2", username: "bob" }];
      return [{ id: "u3", username: "contractor" }];
    },
    async listEnvironments() {
      return [{ id: "env-1", name: "prod-shared", isProduction: false, type: "sandbox" }];
    },
    async listConnectedApplications() {
      return [
        { client_id: "app-1", client_name: "Legacy Sync", grant_types: ["client_credentials"], enabled: true, last_used: isoDaysFromNow(-200) },
        { client_id: "app-2", client_name: "Disabled Tool", grant_types: ["authorization_code"], scopes: ["full", "profile"], enabled: false, last_used: isoDaysFromNow(-5) },
      ];
    },
    async listConnectedApplicationScopes(clientId) {
      return clientId === "app-1" ? [{ scope: "full" }] : [];
    },
    async getOrganizationHierarchy() {
      return { id: ORG_ID, isRoot: true, subOrganizations: [] };
    },
  });

  const result = await assessMulesoftIdentityAccess(client, { maxAdmins: 2 });

  assert.equal(statusOf(result, "MULESOFT-IAM-01"), "fail");
  assert.equal(statusOf(result, "MULESOFT-IAM-02"), "fail");
  assert.equal(statusOf(result, "MULESOFT-IAM-03"), "fail");
  assert.equal(findingById(result, "MULESOFT-IAM-03").evidence.admin_users.length, 3);
  assert.equal(statusOf(result, "MULESOFT-IAM-04"), "fail");
  assert.deepEqual(findingById(result, "MULESOFT-IAM-04").evidence.over_privileged_groups, ["Power Users"]);
  assert.equal(statusOf(result, "MULESOFT-IAM-05"), "fail");
  assert.equal(statusOf(result, "MULESOFT-IAM-06"), "fail");
  assert.equal(statusOf(result, "MULESOFT-IAM-18"), "fail");
  assert.deepEqual(findingById(result, "MULESOFT-IAM-18").evidence.admin_scoped_apps, ["Legacy Sync"]);
  assert.deepEqual(findingById(result, "MULESOFT-IAM-18").evidence.admin_scoped_delegated_apps, ["Disabled Tool"]);
  assert.equal(statusOf(result, "MULESOFT-IAM-19"), "warn");
  assert.deepEqual(findingById(result, "MULESOFT-IAM-19").evidence.stale_apps, ["Legacy Sync"]);
  assert.equal(statusOf(result, "MULESOFT-IAM-25"), "manual");
});

test("assessMulesoftIdentityAccess degrades to manual verdicts and records errors when reads fail", async () => {
  const client = healthyIdentityClient({
    async listRoleGroups() {
      throw new MulesoftApiError(403, "Anypoint request failed (403 Forbidden) for GET /rolegroups");
    },
    async listIdentityProviders() {
      throw new Error("timeout");
    },
    async listConnectedApplications() {
      return [{ client_id: "studio", client_name: "Anypoint Studio", grant_types: ["authorization_code"], scopes: ["full", "offline_access"], enabled: true, last_used: isoDaysFromNow(-1) }];
    },
    async listConnectedApplicationScopes() {
      return [];
    },
  });

  const result = await assessMulesoftIdentityAccess(client);

  assert.equal(statusOf(result, "MULESOFT-IAM-01"), "manual");
  assert.match(findingById(result, "MULESOFT-IAM-01").summary, /Could not evaluate: identity_providers could not be read, the read errored: timeout/);
  assert.match(findingById(result, "MULESOFT-IAM-01").summary, /Export Access Management > Identity Providers/);
  for (const id of ["MULESOFT-IAM-03", "MULESOFT-IAM-04", "MULESOFT-IAM-05"]) {
    assert.equal(statusOf(result, id), "manual", id);
    assert.match(findingById(result, id).summary, /role_groups could not be read, the credential lacks permission \(HTTP 403\)/);
  }
  assert.equal(statusOf(result, "MULESOFT-IAM-18"), "warn");
  assert.match(findingById(result, "MULESOFT-IAM-18").summary, /user-delegated/);
  assert.equal(statusOf(result, "MULESOFT-IAM-19"), "pass");
  assert.ok(result.errors.some((error) => error.startsWith("role_groups:")));
  assert.ok(result.errors.some((error) => error.startsWith("identity_providers:")));
  assert.equal(result.summary.unreadable_sources, 2);
});

test("assessMulesoftApiGateway passes when production APIs enforce authentication and rate limiting", async () => {
  const result = await assessMulesoftApiGateway(healthyApiGatewayClient());

  assert.equal(result.category, "api_gateway");
  assert.deepEqual(result.findings.map((item) => item.control), [7, 8, 9, 20]);
  assert.equal(statusOf(result, "MULESOFT-API-07"), "pass");
  assert.equal(statusOf(result, "MULESOFT-API-08"), "pass");
  assert.equal(statusOf(result, "MULESOFT-API-09"), "manual");
  assert.match(findingById(result, "MULESOFT-API-09").summary, /3 active contract/);
  assert.equal(statusOf(result, "MULESOFT-API-20"), "manual");
  assert.equal(result.summary.apis_sampled, 2);
  assert.equal(result.summary.production_apis, 1);
  assert.equal(result.snapshots.api_manager_apis[0].environment, "Production");
});

test("assessMulesoftApiGateway fails unprotected production APIs and flags public Exchange assets", async () => {
  const client = healthyApiGatewayClient({
    async listApiPolicies(environmentId) {
      if (environmentId === "env-prod") {
        return [
          { policyId: 1, assetId: "cors", disabled: false },
          { policyId: 2, assetId: "rate-limiting", disabled: true },
        ];
      }
      return [{ policyId: 3, template: { assetId: "jwt-validation" }, disabled: false }];
    },
    async listExchangeAssets() {
      return [
        { organizationId: ORG_ID, assetId: "orders-api", name: "Orders API", status: "published", isPublic: true, type: "rest-api" },
        { organizationId: "other-org", assetId: "shared", name: "Shared", status: "published", isPublic: true, type: "rest-api" },
      ];
    },
  });

  const result = await assessMulesoftApiGateway(client);

  assert.equal(statusOf(result, "MULESOFT-API-07"), "fail");
  assert.deepEqual(findingById(result, "MULESOFT-API-07").evidence.production_without_authentication, ["Production: orders-api (v1)"]);
  assert.equal(statusOf(result, "MULESOFT-API-08"), "fail");
  assert.equal(statusOf(result, "MULESOFT-API-20"), "warn");
  assert.deepEqual(findingById(result, "MULESOFT-API-20").evidence.public_assets, ["Orders API"]);
  assert.equal(result.summary.exchange_assets, 1);
});

test("assessMulesoftApiGateway warns when only non-production APIs lack policies and flags environment filters as a partial view", async () => {
  const client = healthyApiGatewayClient({
    getResolvedConfig: () => sampleConfig({ environmentFilter: ["Production"] }),
    async listApiPolicies(environmentId) {
      return environmentId === "env-prod"
        ? [{ assetId: "client-id-enforcement", disabled: false }, { assetId: "spike-control", disabled: false }]
        : [];
    },
  });

  const filtered = await assessMulesoftApiGateway(client);
  assert.equal(filtered.summary.environments_visible, 2);
  assert.equal(filtered.summary.environments_sampled, 1);
  assert.equal(statusOf(filtered, "MULESOFT-API-07"), "warn");
  assert.match(findingById(filtered, "MULESOFT-API-07").summary, /Partial view: the environment filter excluded 1 environment\(s\) \(0 production\): Sandbox/);
  assert.match(findingById(filtered, "MULESOFT-API-07").summary, /cannot pass on this sample/);
  assert.deepEqual(findingById(filtered, "MULESOFT-API-07").evidence.partial_view, ["the environment filter excluded 1 environment(s) (0 production): Sandbox"]);

  const unfiltered = await assessMulesoftApiGateway(healthyApiGatewayClient({ listApiPolicies: client.listApiPolicies }));
  assert.equal(statusOf(unfiltered, "MULESOFT-API-07"), "warn");
  assert.match(findingById(unfiltered, "MULESOFT-API-07").summary, /1 non-production instance\(s\) do not/);
  assert.equal(statusOf(unfiltered, "MULESOFT-API-08"), "warn");
  assert.equal(findingById(unfiltered, "MULESOFT-API-07").evidence.partial_view, undefined);
});

test("assessMulesoftRuntimeInfrastructure passes hardened CloudHub, VPC, DLB, MQ, and hybrid posture", async () => {
  const result = await assessMulesoftRuntimeInfrastructure(healthyRuntimeClient());

  assert.equal(result.category, "runtime_infrastructure");
  assert.deepEqual(result.findings.map((item) => item.control), [10, 11, 12, 13, 14, 15, 16, 21, 22, 23]);
  assert.equal(statusOf(result, "MULESOFT-RT-10"), "pass");
  assert.equal(statusOf(result, "MULESOFT-RT-11"), "pass");
  assert.equal(statusOf(result, "MULESOFT-RT-12"), "pass");
  assert.equal(statusOf(result, "MULESOFT-RT-13"), "pass");
  assert.equal(statusOf(result, "MULESOFT-RT-14"), "pass");
  assert.equal(statusOf(result, "MULESOFT-RT-15"), "pass");
  assert.equal(statusOf(result, "MULESOFT-RT-16"), "pass");
  assert.equal(statusOf(result, "MULESOFT-RT-21"), "manual");
  assert.equal(statusOf(result, "MULESOFT-RT-22"), "pass");
  assert.equal(statusOf(result, "MULESOFT-RT-23"), "pass");
  assert.equal(result.summary.cloudhub_applications, 2);
  assert.equal(result.summary.load_balancers, 1);
  assert.equal(findingById(result, "MULESOFT-RT-16").evidence.certificates[0].host, "prod-dlb.lb.anypointdns.net");
  assert.equal(result.snapshots.mq_clients[0].clients[0].clientSecret, "[REDACTED]");
  assert.deepEqual(result.errors, []);
});

test("assessMulesoftRuntimeInfrastructure fails unsupported runtimes, open firewalls, weak TLS, and plaintext secrets", async () => {
  const client = healthyRuntimeClient({
    async listCloudhubApplications(environmentId) {
      if (environmentId === "env-prod") {
        return [{
          domain: "legacy-prod",
          muleVersion: { version: "3.9.5", endOfSupportDate: isoDaysFromNow(-30) },
          workers: { amount: 4, type: { name: "Large", weight: 4 }, recentStatistics: { cpu: 3 } },
          persistentQueues: true,
          persistentQueuesEncrypted: false,
          properties: { "api.secret": "plaintext-value", "db.user": "svc" },
        }];
      }
      return [{
        domain: "big-dev",
        muleVersion: { version: "4.6.0", endOfSupportDate: isoDaysFromNow(400) },
        workers: { amount: 3, type: { name: "Large", weight: 4 } },
      }];
    },
    async getVpc() {
      return {
        id: "vpc-1",
        name: "prod-vpc",
        firewallRules: [
          { cidrBlock: "0.0.0.0/0", protocol: "tcp", fromPort: 22, toPort: 22 },
          { cidrBlock: "0.0.0.0/0", protocol: "all" },
          { cidrBlock: "10.0.0.0/8", protocol: "tcp", fromPort: 1000, toPort: 9000 },
        ],
      };
    },
    async listLoadBalancers() {
      return [{ id: "lb-1", name: "legacy-dlb", domain: "legacy-dlb.lb.anypointdns.net", httpMode: "on", tlsv1: true, tlsv13: false, state: "STARTED" }];
    },
    async probeCertificate(host) {
      return { host, subject: "legacy.example.com", issuer: "Example CA", validTo: isoDaysFromNow(10) };
    },
    async listMqQueues() {
      return [{ queueId: "orders", encrypted: false }];
    },
    async listSecretGroups() {
      return [];
    },
    async listHybridServers(environmentId) {
      return environmentId === "env-prod" ? [{ id: 1, name: "onprem-1", status: "DISCONNECTED", muleVersion: "4.4.0" }] : [];
    },
  });

  const result = await assessMulesoftRuntimeInfrastructure(client);

  assert.equal(statusOf(result, "MULESOFT-RT-10"), "fail");
  assert.deepEqual(findingById(result, "MULESOFT-RT-10").evidence.unsupported_runtime, ["Production: legacy-prod (3.9.5)"]);
  assert.equal(statusOf(result, "MULESOFT-RT-11"), "warn");
  assert.equal(findingById(result, "MULESOFT-RT-11").evidence.oversized_applications.length, 2);
  assert.equal(statusOf(result, "MULESOFT-RT-12"), "fail");
  assert.equal(statusOf(result, "MULESOFT-RT-13"), "fail");
  assert.equal(findingById(result, "MULESOFT-RT-13").evidence.all_protocol_rules.length, 1);
  assert.equal(statusOf(result, "MULESOFT-RT-14"), "fail");
  assert.equal(findingById(result, "MULESOFT-RT-14").evidence.open_non_standard_rules.length, 2);
  assert.equal(statusOf(result, "MULESOFT-RT-15"), "fail");
  assert.equal(statusOf(result, "MULESOFT-RT-16"), "fail");
  assert.equal(statusOf(result, "MULESOFT-RT-21"), "warn");
  assert.equal(statusOf(result, "MULESOFT-RT-22"), "fail");
  assert.deepEqual(findingById(result, "MULESOFT-RT-22").evidence.insecure_property_keys, ["Production: legacy-prod: api.secret"]);
  assert.equal(statusOf(result, "MULESOFT-RT-23"), "fail");
});

test("assessMulesoftRuntimeInfrastructure marks VPC controls manual and certificate probes manual when unavailable", async () => {
  const client = healthyRuntimeClient({
    async listVpcs() {
      return [];
    },
    async probeCertificate(host) {
      throw new Error(`TLS probe of ${host} timed out.`);
    },
    async listLoadBalancers() {
      return [{ id: "lb-1", name: "prod-dlb", domain: "prod-dlb.lb.anypointdns.net", httpMode: "redirect", tlsv1: false }];
    },
  });

  const result = await assessMulesoftRuntimeInfrastructure(client);

  assert.equal(statusOf(result, "MULESOFT-RT-13"), "manual");
  assert.match(findingById(result, "MULESOFT-RT-13").summary, /private space firewall rules/);
  assert.equal(statusOf(result, "MULESOFT-RT-14"), "manual");
  assert.equal(statusOf(result, "MULESOFT-RT-16"), "manual");
  assert.match(findingById(result, "MULESOFT-RT-16").summary, /Runtime Manager > Load Balancers/);
  assert.ok(result.errors.some((error) => error.startsWith("certificate_probe:prod-dlb.lb.anypointdns.net")));
});

test("assessMulesoftAuditMonitoring passes when audit logs flow and production alerts cover applications", async () => {
  const result = await assessMulesoftAuditMonitoring(healthyAuditClient(), { auditLookbackHours: 48 });

  assert.equal(result.category, "audit_monitoring");
  assert.deepEqual(result.findings.map((item) => item.control), [17, 24]);
  assert.equal(statusOf(result, "MULESOFT-AUD-17"), "pass");
  assert.match(findingById(result, "MULESOFT-AUD-17").summary, /42 audit log entries recorded within the last 48 hours/);
  assert.equal(statusOf(result, "MULESOFT-AUD-24"), "pass");
  assert.equal(result.summary.audit_platforms, 2);
  assert.equal(result.summary.enabled_alerts, 1);
  assert.deepEqual(result.errors, []);
});

test("assessMulesoftAuditMonitoring marks a forbidden audit query manual and fails production without alerts", async () => {
  const client = healthyAuditClient({
    async queryAuditLogs() {
      throw new MulesoftApiError(403, "Anypoint request failed (403 Forbidden) for POST /audit/v2/organizations/org-1/query");
    },
    async listCloudhubAlerts() {
      return [];
    },
  });

  const result = await assessMulesoftAuditMonitoring(client);

  assert.equal(statusOf(result, "MULESOFT-AUD-17"), "manual");
  assert.match(findingById(result, "MULESOFT-AUD-17").summary, /Could not evaluate: audit_query could not be read, the credential lacks permission \(HTTP 403\)/);
  assert.match(findingById(result, "MULESOFT-AUD-17").summary, /Audit Log Viewer/);
  assert.equal(statusOf(result, "MULESOFT-AUD-24"), "fail");
  assert.deepEqual(findingById(result, "MULESOFT-AUD-24").evidence.environments_without_alerts, ["Production"]);
  assert.ok(result.errors.some((error) => error.startsWith("audit_query:")));
});

test("assessMulesoftAuditMonitoring warns on stale audit activity and uncovered applications", async () => {
  let calls = 0;
  const client = healthyAuditClient({
    async queryAuditLogs() {
      calls += 1;
      return calls === 1 ? { data: [], total: 0 } : { data: [{ timestamp: isoDaysFromNow(-3) }], total: 1 };
    },
    async listCloudhubAlerts() {
      return [
        { id: "alert-1", name: "Orders CPU", enabled: true, condition: { resources: ["orders-prod"] } },
        { id: "alert-2", name: "Disabled", enabled: false, condition: { resources: ["*"] } },
      ];
    },
    async listCloudhubApplications(environmentId) {
      return environmentId === "env-prod" ? [{ domain: "orders-prod" }, { domain: "billing-prod" }] : [];
    },
  });

  const result = await assessMulesoftAuditMonitoring(client);

  assert.equal(calls, 2);
  assert.equal(statusOf(result, "MULESOFT-AUD-17"), "warn");
  assert.equal(statusOf(result, "MULESOFT-AUD-24"), "warn");
  assert.deepEqual(findingById(result, "MULESOFT-AUD-24").evidence.production_environments[0].uncovered_applications, ["billing-prod"]);
});

test("exportMulesoftAuditBundle writes core data, analysis, compliance reports, and a zip archive", async () => {
  const base = createTempBase("grclanker-mulesoft-export-");
  const result = await exportMulesoftAuditBundle(healthyBundleClient(), sampleConfig(), base);

  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.match(result.zipPath, /org-1-audit-bundle\.zip$/);
  assert.equal(result.findingCount, 25);
  assert.equal(result.errorCount, 0);
  assert.ok(result.fileCount >= 30);

  const metadata = JSON.parse(readFileSync(join(result.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.organization_id, ORG_ID);
  assert.equal(metadata.controls_assessed, 25);
  assert.equal(metadata.controls_in_catalog, 25);

  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  assert.equal(findings.length, 25);
  assert.deepEqual([...new Set(findings.map((item) => item.control))].sort((a, b) => a - b), Array.from({ length: 25 }, (_, index) => index + 1));
  assert.ok(findings.every((item) => item.mappings.length === 8));
  assert.ok(findings.every((item) => ["pass", "warn", "fail", "manual"].includes(item.status)));

  for (const file of [
    "QUICK_REFERENCE.md",
    join("core_data", "access_check.json"),
    join("core_data", "organization.json"),
    join("core_data", "identity_providers.json"),
    join("core_data", "role_groups.json"),
    join("core_data", "connected_applications.json"),
    join("core_data", "api_manager_apis.json"),
    join("core_data", "exchange_assets.json"),
    join("core_data", "cloudhub_applications.json"),
    join("core_data", "vpcs.json"),
    join("core_data", "load_balancers.json"),
    join("core_data", "audit_log_recent.json"),
    join("analysis", "identity_access.json"),
    join("analysis", "api_gateway.json"),
    join("analysis", "runtime_infrastructure.json"),
    join("analysis", "audit_monitoring.json"),
    join("analysis", "summary.json"),
    join("compliance", "executive_summary.md"),
    join("compliance", "unified_compliance_matrix.md"),
    join("compliance", "fedramp", "fedramp_compliance_report.md"),
    join("compliance", "cmmc", "cmmc_compliance_report.md"),
    join("compliance", "soc2", "soc2_compliance_report.md"),
    join("compliance", "cis", "cis_compliance_report.md"),
    join("compliance", "pci_dss", "pci_dss_compliance_report.md"),
    join("compliance", "disa_stig", "disa_stig_compliance_report.md"),
    join("compliance", "irap", "irap_compliance_report.md"),
    join("compliance", "ismap", "ismap_compliance_report.md"),
  ]) {
    assert.ok(existsSync(join(result.outputDir, file)), `expected ${file}`);
  }
  assert.ok(!existsSync(join(result.outputDir, "_errors.log")));

  const matrix = readFileSync(join(result.outputDir, "compliance", "unified_compliance_matrix.md"), "utf8");
  assert.match(matrix, /MULESOFT-IAM-01/);
  assert.match(matrix, /MULESOFT-AUD-24/);
  assert.match(matrix, /IA-2\(1\)/);
  const executive = readFileSync(join(result.outputDir, "compliance", "executive_summary.md"), "utf8");
  assert.match(executive, /Total controls assessed: 25 of 25/);
  assert.match(executive, /Manual Evidence Required/);
  const connectedApps = readFileSync(join(result.outputDir, "core_data", "connected_applications.json"), "utf8");
  assert.doesNotMatch(connectedApps, /hidden/);
  assert.match(connectedApps, /\[REDACTED\]/);
});

test("exportMulesoftAuditBundle records partial collection failures in _errors.log", async () => {
  const base = createTempBase("grclanker-mulesoft-export-errors-");
  const client = healthyBundleClient({
    async listVpcs() {
      throw new MulesoftApiError(403, "Anypoint request failed (403 Forbidden) for GET /cloudhub/api/organizations/org-1/vpcs");
    },
    async listExchangeAssets() {
      throw new Error("socket hang up");
    },
  });

  const result = await exportMulesoftAuditBundle(client, sampleConfig(), base);

  assert.equal(result.findingCount, 25);
  assert.equal(result.errorCount, 2);
  const errorLog = readFileSync(join(result.outputDir, "_errors.log"), "utf8");
  assert.match(errorLog, /\[runtime_infrastructure\] vpcs: /);
  assert.match(errorLog, /\[api_gateway\] exchange_assets: socket hang up/);
  assert.ok(existsSync(result.zipPath));

  const second = await exportMulesoftAuditBundle(client, sampleConfig(), base);
  assert.notEqual(second.outputDir, result.outputDir);
  assert.match(second.outputDir, /org-1-audit-bundle-2$/);
  assert.ok(readdirSync(base).includes("org-1-audit-bundle-2.zip"));
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-mulesoft-path-");
  const outside = createTempBase("grclanker-mulesoft-outside-");
  const linked = join(base, "linked");
  symlinkSync(outside, linked, "dir");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, join("..", "sibling", "file.txt")), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "linked/file.txt"), /symlinked parent directory/);

  const safe = resolveSecureOutputPath(base, join("compliance", "safe.txt"));
  assert.match(safe, /compliance\/safe\.txt$/);
});

test("MuleSoft tools are registered in the tool catalog under the MuleSoft group", () => {
  const tools = getRegisteredToolSummaries().filter((tool) => tool.name.startsWith("mulesoft_"));
  assert.deepEqual(
    tools.map((tool) => tool.name).sort(),
    [
      "mulesoft_assess_api_gateway",
      "mulesoft_assess_audit_monitoring",
      "mulesoft_assess_identity_access",
      "mulesoft_assess_runtime_infrastructure",
      "mulesoft_check_access",
      "mulesoft_export_audit_bundle",
    ],
  );
  assert.ok(tools.every((tool) => tool.group === "MuleSoft"));
  assert.ok(tools.every((tool) => tool.kind === "domain"));
  assert.ok(tools.every((tool) => tool.description.length > 40));
  const exportTool = tools.find((tool) => tool.name === "mulesoft_export_audit_bundle");
  assert.ok(exportTool.parameterSummaries.some((parameter) => parameter.name === "output_dir"));
  assert.ok(exportTool.parameterSummaries.some((parameter) => parameter.name === "control_plane"));
});


function forbidden(label) {
  return async () => {
    throw new MulesoftApiError(403, `Anypoint request failed (403 Forbidden) for GET ${label}`);
  };
}

function forbidAll(client) {
  const output = { getResolvedConfig: client.getResolvedConfig };
  for (const [name, value] of Object.entries(client)) {
    if (name !== "getResolvedConfig" && typeof value === "function") output[name] = forbidden(name);
  }
  return output;
}

function truncatedPage(items, total) {
  return { items, total, truncated: true, limit: items.length };
}

function assertNoPass(result, label) {
  for (const item of result.findings) {
    assert.notEqual(item.status, "pass", `${label}: ${item.id} must not pass but reported "${item.summary}"`);
  }
}

function assertAllManualNamingCause(result, label) {
  for (const item of result.findings) {
    assert.equal(item.status, "manual", `${label}: ${item.id} should be manual, got ${item.status}: ${item.summary}`);
    assert.match(item.summary, /could not be read/, `${label}: ${item.id} must name the unreadable source`);
    assert.match(item.summary, /HTTP 403/, `${label}: ${item.id} must name the HTTP cause`);
  }
}

function emptyIdentityClient() {
  return healthyIdentityClient({
    async getOrganization() {
      return {};
    },
    async getOrganizationHierarchy() {
      return { subOrganizations: [] };
    },
    async listIdentityProviders() {
      return [];
    },
    async getIdentityProviderSettings() {
      return {};
    },
    async listMembers() {
      return [];
    },
    async listRoleGroups() {
      return [];
    },
    async listRoleGroupRoles() {
      return [];
    },
    async listRoleGroupUsers() {
      return [];
    },
    async listEnvironments() {
      return [];
    },
    async listConnectedApplications() {
      return [];
    },
    async listConnectedApplicationScopes() {
      return [];
    },
  });
}

function emptyApiGatewayClient() {
  return healthyApiGatewayClient({
    async listManagedApis() {
      return [];
    },
    async listApiPolicies() {
      return [];
    },
    async listExchangeAssets() {
      return [];
    },
  });
}

function emptyRuntimeClient() {
  return healthyRuntimeClient({
    async listCloudhubApplications() {
      return [];
    },
    async listVpcs() {
      return [];
    },
    async getVpc() {
      return {};
    },
    async listLoadBalancers() {
      return [];
    },
    async listHybridServers() {
      return [];
    },
    async listMqRegions() {
      return [];
    },
    async listMqQueues() {
      return [];
    },
    async listMqClients() {
      return [];
    },
    async listSecretGroups() {
      return [];
    },
  });
}

function emptyAuditClient() {
  return healthyAuditClient({
    async listAuditPlatforms() {
      return [];
    },
    async queryAuditLogs() {
      return { data: [], total: 0 };
    },
    async listCloudhubAlerts() {
      return [];
    },
    async listHybridAlerts() {
      return [];
    },
    async listCloudhubApplications() {
      return [];
    },
  });
}

function partialIdentityClient() {
  return healthyIdentityClient({
    async getOrganizationHierarchy() {
      return { id: ORG_ID, isRoot: false, subOrganizations: [] };
    },
    async listMembers() {
      return truncatedPage([{ id: "u1", username: "alice" }], 1500);
    },
    async listRoleGroups() {
      return truncatedPage([{ role_group_id: "rg-admin", name: "Organization Administrators", editable: false }], 40);
    },
    async listConnectedApplications() {
      return truncatedPage([{ client_id: "app-1", client_name: "Auditor", enabled: true, last_used: isoDaysFromNow(-3) }], 12);
    },
  });
}

function partialApiGatewayClient() {
  return healthyApiGatewayClient({
    getResolvedConfig: () => sampleConfig({ environmentFilter: ["Sandbox"] }),
    async listExchangeAssets() {
      return truncatedPage([{ organizationId: ORG_ID, assetId: "orders-api", name: "Orders API", status: "published", isPublic: false, type: "rest-api" }], 900);
    },
  });
}

function partialRuntimeClient() {
  return healthyRuntimeClient({
    async listVpcs() {
      return Array.from({ length: 21 }, (_, index) => ({ id: `vpc-${index + 1}`, name: `vpc-${index + 1}` }));
    },
    async listLoadBalancers() {
      return Array.from({ length: 11 }, (_, index) => ({
        id: `lb-${index + 1}`,
        name: `dlb-${index + 1}`,
        domain: `dlb-${index + 1}.lb.anypointdns.net`,
        httpMode: "redirect",
        tlsv1: false,
        tlsv13: true,
        state: "STARTED",
      }));
    },
  });
}

function partialAuditClient() {
  return healthyAuditClient({
    async listEnvironments() {
      return [
        ...ENVIRONMENTS,
        { id: "env-prod-eu", name: "Production EU", isProduction: true, type: "production" },
      ];
    },
    async queryAuditLogs() {
      return { data: [{ timestamp: new Date().toISOString(), platform: "Access Management", action: "LOGIN", objectType: "User" }], total: 5000 };
    },
  });
}

test("verdict safety rule 1: unreadable, forbidden, or errored endpoints yield manual verdicts that name the cause, never pass", async () => {
  const identity = await assessMulesoftIdentityAccess(healthyIdentityClient({
    listConnectedApplications: forbidden("/connectedApplications"),
    async listIdentityProviders() {
      throw new Error("socket hang up");
    },
  }));
  for (const id of ["MULESOFT-IAM-18", "MULESOFT-IAM-19"]) {
    assert.equal(statusOf(identity, id), "manual", id);
    assert.match(findingById(identity, id).summary, /Could not evaluate: connected_applications could not be read, the credential lacks permission \(HTTP 403\)/);
    assert.match(findingById(identity, id).summary, /Access Management > Connected Apps/);
    assert.equal(findingById(identity, id).evidence.unreadable_sources.length, 1);
  }
  assert.equal(statusOf(identity, "MULESOFT-IAM-01"), "manual");
  assert.match(findingById(identity, "MULESOFT-IAM-01").summary, /the read errored: socket hang up/);

  const secondary = await assessMulesoftIdentityAccess(healthyIdentityClient({
    getIdentityProviderSettings: forbidden("/identityProviderSettings"),
  }));
  assert.equal(statusOf(secondary, "MULESOFT-IAM-01"), "manual");
  assert.match(findingById(secondary, "MULESOFT-IAM-01").summary, /^Could not confirm: identity_provider_settings could not be read/);
  assert.match(findingById(secondary, "MULESOFT-IAM-01").summary, /Partial evidence: 1 active identity provider/);

  const runtime = await assessMulesoftRuntimeInfrastructure(healthyRuntimeClient({
    listLoadBalancers: forbidden("/loadbalancers"),
    listHybridServers: forbidden("/hybrid/api/v1/servers"),
    async listMqRegions() {
      throw new MulesoftApiError(404, "Anypoint request failed (404 Not Found) for GET /mq/admin/api/v1/regions");
    },
  }));
  for (const id of ["MULESOFT-RT-15", "MULESOFT-RT-16", "MULESOFT-RT-23"]) {
    assert.equal(statusOf(runtime, id), "manual", id);
    assert.match(findingById(runtime, id).summary, /HTTP 403/);
  }
  assert.equal(statusOf(runtime, "MULESOFT-RT-21"), "manual");
  assert.match(findingById(runtime, "MULESOFT-RT-21").summary, /unavailable on this control plane or plan \(HTTP 404\)/);

  const gateway = await assessMulesoftApiGateway(healthyApiGatewayClient({
    async listApiPolicies(environmentId, apiId) {
      if (String(apiId) === "101") throw new MulesoftApiError(403, "Anypoint request failed (403 Forbidden) for GET /policies");
      return [{ assetId: "client-id-enforcement", disabled: false }, { assetId: "rate-limiting", disabled: false }];
    },
  }));
  for (const id of ["MULESOFT-API-07", "MULESOFT-API-08"]) {
    assert.equal(statusOf(gateway, id), "manual", id);
    assert.match(findingById(gateway, id).summary, /api_policies could not be read, the credential lacks permission \(HTTP 403\)/, id);
    assert.match(findingById(gateway, id).summary, /1 of 2 reads failed/, id);
  }
  assert.equal(statusOf(gateway, "MULESOFT-API-09"), "manual");
  assert.match(findingById(gateway, "MULESOFT-API-09").summary, /^Anypoint Platform does not expose client secret rotation timestamps\. Export the 3 active contract\(s\)/);

  const audit = await assessMulesoftAuditMonitoring(healthyAuditClient({
    listCloudhubApplications: forbidden("/cloudhub/api/v2/applications"),
  }));
  assert.equal(statusOf(audit, "MULESOFT-AUD-24"), "manual");
  assert.match(findingById(audit, "MULESOFT-AUD-24").summary, /cloudhub_applications could not be read/);
  assert.equal(statusOf(audit, "MULESOFT-AUD-17"), "pass");
});

test("verdict safety rule 2: empty inventories never pass and each summary states whether emptiness is fail or manual", async () => {
  const identity = await assessMulesoftIdentityAccess(emptyIdentityClient());
  assertNoPass(identity, "identity/empty");
  assert.equal(statusOf(identity, "MULESOFT-IAM-01"), "fail");
  assert.match(findingById(identity, "MULESOFT-IAM-01").summary, /Zero providers is treated as fail/);
  for (const id of ["MULESOFT-IAM-03", "MULESOFT-IAM-04", "MULESOFT-IAM-05"]) {
    assert.equal(statusOf(identity, id), "manual", id);
    assert.match(findingById(identity, id).summary, /Zero role groups is treated as manual/);
  }
  assert.equal(statusOf(identity, "MULESOFT-IAM-06"), "manual");
  assert.match(findingById(identity, "MULESOFT-IAM-06").summary, /Zero environments is treated as manual/);
  for (const id of ["MULESOFT-IAM-18", "MULESOFT-IAM-19"]) {
    assert.equal(statusOf(identity, id), "manual", id);
    assert.match(findingById(identity, id).summary, /Zero apps is treated as manual rather than pass/);
  }

  const gateway = await assessMulesoftApiGateway(emptyApiGatewayClient());
  assertNoPass(gateway, "gateway/empty");
  for (const id of ["MULESOFT-API-07", "MULESOFT-API-08"]) {
    assert.equal(statusOf(gateway, id), "manual", id);
    assert.match(findingById(gateway, id).summary, /Zero instances cannot pass a policy-coverage control and is treated as manual/);
  }
  assert.equal(statusOf(gateway, "MULESOFT-API-20"), "manual");
  assert.match(findingById(gateway, "MULESOFT-API-20").summary, /Zero assets is treated as manual/);

  const runtime = await assessMulesoftRuntimeInfrastructure(emptyRuntimeClient());
  assertNoPass(runtime, "runtime/empty");
  for (const id of ["MULESOFT-RT-10", "MULESOFT-RT-11", "MULESOFT-RT-12", "MULESOFT-RT-22"]) {
    assert.match(findingById(runtime, id).summary, /Zero applications is treated as manual/, id);
  }
  assert.match(findingById(runtime, "MULESOFT-RT-13").summary, /Zero CloudHub VPCs are visible, which is treated as manual/);
  assert.match(findingById(runtime, "MULESOFT-RT-23").summary, /Zero hybrid runtime servers/);

  const audit = await assessMulesoftAuditMonitoring(emptyAuditClient());
  assertNoPass(audit, "audit/empty");
  assert.equal(statusOf(audit, "MULESOFT-AUD-17"), "fail");
  assert.match(findingById(audit, "MULESOFT-AUD-17").summary, /Zero events is treated as fail/);
  assert.equal(statusOf(audit, "MULESOFT-AUD-24"), "fail");
  assert.match(findingById(audit, "MULESOFT-AUD-24").summary, /no enabled CloudHub or Runtime Manager alerts/);

  const alertsWithoutApplications = await assessMulesoftAuditMonitoring(healthyAuditClient({
    async listCloudhubApplications() {
      return [];
    },
  }));
  assert.equal(statusOf(alertsWithoutApplications, "MULESOFT-AUD-24"), "manual");
  assert.match(findingById(alertsWithoutApplications, "MULESOFT-AUD-24").summary, /zero CloudHub applications are deployed/);
});

test("verdict safety rule 3: scoped-out, not applicable, or unavailable controls render as manual, never pass", async () => {
  const runtime = await assessMulesoftRuntimeInfrastructure(healthyRuntimeClient({
    async listLoadBalancers() {
      return [];
    },
    async listMqRegions() {
      return [];
    },
    async listHybridServers() {
      return [];
    },
    async listCloudhubApplications(environmentId) {
      const applications = await healthyRuntimeClient().listCloudhubApplications(environmentId);
      return applications.map((application) => ({ ...application, persistentQueues: false }));
    },
  }));
  for (const id of ["MULESOFT-RT-15", "MULESOFT-RT-16", "MULESOFT-RT-21", "MULESOFT-RT-23"]) {
    assert.equal(statusOf(runtime, id), "manual", id);
    assert.match(findingById(runtime, id).summary, /not applicable/, id);
  }
  assert.equal(statusOf(runtime, "MULESOFT-RT-12"), "manual");
  assert.match(findingById(runtime, "MULESOFT-RT-12").summary, /not applicable and is recorded as manual rather than pass/);

  const govCloud = await assessMulesoftRuntimeInfrastructure(healthyRuntimeClient({
    getResolvedConfig: () => sampleConfig({ controlPlane: "gov", baseUrl: "https://gov.anypoint.mulesoft.com" }),
    async listMqRegions() {
      throw new MulesoftApiError(404, "Anypoint request failed (404 Not Found) for GET /mq/admin/api/v1/organizations/org-1/environments/env-prod/regions");
    },
  }));
  assert.equal(statusOf(govCloud, "MULESOFT-RT-21"), "manual");
  assert.match(findingById(govCloud, "MULESOFT-RT-21").summary, /unavailable on this control plane or plan/);

  const scopedOut = await assessMulesoftApiGateway(healthyApiGatewayClient({
    getResolvedConfig: () => sampleConfig({ environmentFilter: ["Sandbox"] }),
  }));
  assert.equal(statusOf(scopedOut, "MULESOFT-API-07"), "manual");
  assert.match(findingById(scopedOut, "MULESOFT-API-07").summary, /none belong to a production environment \(0 of 1 production environment\(s\) sampled\)/);
  assert.match(findingById(scopedOut, "MULESOFT-API-07").summary, /Partial view: the environment filter excluded 1 environment\(s\) \(1 production\): Production/);

  const notEntitled = await assessMulesoftIdentityAccess(healthyIdentityClient({
    async getOrganization() {
      return { id: ORG_ID, name: "Acme", isFederated: true, entitlements: { createSubOrgs: false } };
    },
    async getOrganizationHierarchy() {
      return { id: ORG_ID, isRoot: true, subOrganizations: [] };
    },
  }));
  assert.equal(statusOf(notEntitled, "MULESOFT-IAM-25"), "manual");
  assert.match(findingById(notEntitled, "MULESOFT-IAM-25").summary, /createSubOrgs entitlement is false, so business groups are not available on this plan \(not applicable\)/);
});

test("verdict safety rule 4: items missing dates are bucketed separately and never counted as fresh or valid", async () => {
  const identity = await assessMulesoftIdentityAccess(healthyIdentityClient({
    async listConnectedApplications() {
      return [
        { client_id: "app-1", client_name: "Auditor", enabled: true, last_used: isoDaysFromNow(-3) },
        { client_id: "app-2", client_name: "No Usage", enabled: true, last_used: null, created_at: isoDaysFromNow(-400) },
      ];
    },
  }));
  assert.equal(statusOf(identity, "MULESOFT-IAM-19"), "warn");
  assert.match(findingById(identity, "MULESOFT-IAM-19").summary, /1 of 2 connected app\(s\) have no last-used timestamp and are not counted as active/);
  assert.deepEqual(findingById(identity, "MULESOFT-IAM-19").evidence.apps_without_usage_date, ["No Usage"]);
  assert.deepEqual(findingById(identity, "MULESOFT-IAM-19").evidence.stale_apps, []);
  assert.equal(findingById(identity, "MULESOFT-IAM-19").evidence.apps_with_usage_data, 1);

  const runtime = await assessMulesoftRuntimeInfrastructure(healthyRuntimeClient({
    async listLoadBalancers() {
      return [
        { id: "lb-1", name: "dated", domain: "dated.lb.anypointdns.net", httpMode: "redirect", tlsv1: false, tlsv13: true },
        { id: "lb-2", name: "undated", domain: "undated.lb.anypointdns.net", httpMode: "redirect", tlsv1: false, tlsv13: true },
      ];
    },
    async probeCertificate(host) {
      if (host.startsWith("dated")) return { host, subject: "dated", issuer: "CA", validTo: isoDaysFromNow(300) };
      return { host, subject: "undated", issuer: "CA" };
    },
    async listCloudhubApplications(environmentId) {
      const applications = await healthyRuntimeClient().listCloudhubApplications(environmentId);
      return applications.map((application) => ({ ...application, muleVersion: { version: application.muleVersion.version } }));
    },
  }));
  assert.equal(statusOf(runtime, "MULESOFT-RT-16"), "warn");
  assert.match(findingById(runtime, "MULESOFT-RT-16").summary, /1\/2 dedicated load balancer certificate\(s\) could not be dated/);
  const undated = findingById(runtime, "MULESOFT-RT-16").evidence.certificates.find((item) => item.load_balancer === "undated");
  assert.equal(undated.days_remaining, null);
  assert.match(undated.error, /did not expose a validTo date/);
  assert.equal(statusOf(runtime, "MULESOFT-RT-10"), "warn");
  assert.match(findingById(runtime, "MULESOFT-RT-10").summary, /did not expose an end of support date, so they are not counted as supported/);
  assert.equal(findingById(runtime, "MULESOFT-RT-10").evidence.unknown_support_dates, 2);

  const versionless = await assessMulesoftRuntimeInfrastructure(healthyRuntimeClient({
    async listCloudhubApplications(environmentId) {
      const applications = await healthyRuntimeClient().listCloudhubApplications(environmentId);
      return applications.map(({ muleVersion: _muleVersion, ...application }) => application);
    },
  }));
  assert.equal(statusOf(versionless, "MULESOFT-RT-10"), "warn");
  assert.match(findingById(versionless, "MULESOFT-RT-10").summary, /did not expose a Mule runtime version/);
});

test("verdict safety rule 5: partial inventories are flagged with seen and total counts instead of passing", async () => {
  const identity = await assessMulesoftIdentityAccess(healthyIdentityClient({
    async listConnectedApplications() {
      return truncatedPage([{ client_id: "app-1", client_name: "Auditor", enabled: true, last_used: isoDaysFromNow(-3) }], 40);
    },
    async listRoleGroups() {
      return truncatedPage([
        { role_group_id: "rg-admin", name: "Organization Administrators", editable: false },
        { role_group_id: "rg-dev", name: "Developers", editable: true },
      ], 25);
    },
  }));
  for (const id of ["MULESOFT-IAM-18", "MULESOFT-IAM-19"]) {
    assert.equal(statusOf(identity, id), "warn", id);
    assert.match(findingById(identity, id).summary, /^Partial view: connected apps list truncated at 1 of 40 total\./);
    assert.match(findingById(identity, id).summary, /cannot pass on this sample/);
  }
  for (const id of ["MULESOFT-IAM-03", "MULESOFT-IAM-04", "MULESOFT-IAM-05"]) {
    assert.equal(statusOf(identity, id), "warn", id);
    assert.match(findingById(identity, id).summary, /role groups list truncated at 2 of 25 total/);
  }

  const businessGroup = await assessMulesoftIdentityAccess(healthyIdentityClient({
    async getOrganizationHierarchy() {
      return { id: "bg-1", isRoot: false, subOrganizations: [] };
    },
  }));
  assert.equal(statusOf(businessGroup, "MULESOFT-IAM-25"), "manual");
  assert.match(findingById(businessGroup, "MULESOFT-IAM-25").summary, /business group \(isRoot=false\)/);
  for (const id of ["MULESOFT-IAM-01", "MULESOFT-IAM-03", "MULESOFT-IAM-04", "MULESOFT-IAM-05", "MULESOFT-IAM-06", "MULESOFT-IAM-18", "MULESOFT-IAM-19"]) {
    assert.equal(statusOf(businessGroup, id), "warn", id);
    assert.match(findingById(businessGroup, id).summary, /Partial view: this organization is a business group \(isRoot=false\)/, id);
  }
  assert.equal(statusOf(businessGroup, "MULESOFT-IAM-02"), "manual");
  assert.match(findingById(businessGroup, "MULESOFT-IAM-02").summary, /Partial view: this organization is a business group/);

  const runtime = await assessMulesoftRuntimeInfrastructure(healthyRuntimeClient(), { environmentLimit: 1, applicationLimit: 1 });
  for (const id of ["MULESOFT-RT-10", "MULESOFT-RT-11", "MULESOFT-RT-12", "MULESOFT-RT-21", "MULESOFT-RT-22", "MULESOFT-RT-23"]) {
    assert.notEqual(statusOf(runtime, id), "pass", `${id} is environment-scoped and must not pass on a sampled subset of environments`);
    assert.match(findingById(runtime, id).summary, /environment limit of 1|application limit of 1/, id);
  }
  for (const id of ["MULESOFT-RT-13", "MULESOFT-RT-14", "MULESOFT-RT-15", "MULESOFT-RT-16"]) {
    assert.equal(statusOf(runtime, id), "pass", `${id} reads organization-level VPC and load balancer inventories that an environment limit does not narrow`);
    assert.equal(findingById(runtime, id).evidence.partial_view, undefined, id);
  }
  assert.equal(statusOf(runtime, "MULESOFT-RT-10"), "warn");
  assert.match(findingById(runtime, "MULESOFT-RT-10").summary, /the environment limit of 1 excluded 1 environment\(s\) \(0 production\): Sandbox/);
  assert.equal(statusOf(runtime, "MULESOFT-RT-23"), "warn");
  assert.equal(runtime.summary.environments_visible, 2);
  assert.equal(runtime.summary.environments_sampled, 1);

  const capped = await assessMulesoftRuntimeInfrastructure(healthyRuntimeClient(), { applicationLimit: 1 });
  assert.equal(statusOf(capped, "MULESOFT-RT-10"), "warn");
  assert.match(findingById(capped, "MULESOFT-RT-10").summary, /the application limit of 1 left 1 application\(s\) uninspected/);
  assert.equal(capped.summary.applications_not_inspected, 1);

  const gateway = await assessMulesoftApiGateway(healthyApiGatewayClient({
    async listManagedApis(environmentId) {
      const apis = await healthyApiGatewayClient().listManagedApis(environmentId);
      return truncatedPage(apis, 300);
    },
  }));
  assert.equal(statusOf(gateway, "MULESOFT-API-07"), "warn");
  assert.match(findingById(gateway, "MULESOFT-API-07").summary, /Production API instance list truncated at 1 of 300 total/);
  assert.equal(statusOf(gateway, "MULESOFT-API-08"), "warn");

  const audit = await assessMulesoftAuditMonitoring(healthyAuditClient({
    async listEnvironments() {
      return [...ENVIRONMENTS, { id: "env-prod-eu", name: "Production EU", isProduction: true, type: "production" }];
    },
  }), { environmentLimit: 1 });
  assert.equal(statusOf(audit, "MULESOFT-AUD-24"), "warn");
  assert.match(findingById(audit, "MULESOFT-AUD-24").summary, /the environment limit of 1 excluded 2 environment\(s\) \(1 production\)/);
});

test("verdict safety rule 6: verdicts require the enabling flags to be read and present", async () => {
  const notFederated = await assessMulesoftIdentityAccess(healthyIdentityClient({
    async getOrganization() {
      return { id: ORG_ID, name: "Acme", entitlements: { createSubOrgs: true } };
    },
  }));
  assert.equal(statusOf(notFederated, "MULESOFT-IAM-01"), "warn");
  assert.match(findingById(notFederated, "MULESOFT-IAM-01").summary, /isFederated flag is absent/);

  const disabledProvider = await assessMulesoftIdentityAccess(healthyIdentityClient({
    async listIdentityProviders() {
      return [{ provider_id: "idp-1", name: "Okta SAML", type: { name: "saml" }, enabled: false }];
    },
  }));
  assert.equal(statusOf(disabledProvider, "MULESOFT-IAM-01"), "fail");
  assert.match(findingById(disabledProvider, "MULESOFT-IAM-01").summary, /every one is disabled/);

  const settingsWithoutFlag = await assessMulesoftIdentityAccess(healthyIdentityClient({
    async getIdentityProviderSettings() {
      return {};
    },
  }));
  assert.equal(statusOf(settingsWithoutFlag, "MULESOFT-IAM-01"), "warn");
  assert.match(findingById(settingsWithoutFlag, "MULESOFT-IAM-01").summary, /did not expose allow_new_non_sso_users/);

  const exemptWithoutFlag = await assessMulesoftIdentityAccess(healthyIdentityClient({
    async listMfaExemptUsers() {
      return [{ id: "u9", username: "contractor" }];
    },
  }));
  assert.equal(statusOf(exemptWithoutFlag, "MULESOFT-IAM-02"), "warn");
  assert.match(findingById(exemptWithoutFlag, "MULESOFT-IAM-02").summary, /did not include the mfaVerificationExcluded flag/);

  const noEntitlement = await assessMulesoftIdentityAccess(healthyIdentityClient({
    async getOrganization() {
      return { id: ORG_ID, name: "Acme", isFederated: true };
    },
  }));
  assert.equal(statusOf(noEntitlement, "MULESOFT-IAM-25"), "warn");
  assert.match(findingById(noEntitlement, "MULESOFT-IAM-25").summary, /did not expose the entitlements.createSubOrgs flag/);

  const untypedEnvironment = await assessMulesoftIdentityAccess(healthyIdentityClient({
    async listEnvironments() {
      return [...ENVIRONMENTS, { id: "env-x", name: "Integration" }];
    },
  }));
  assert.equal(statusOf(untypedEnvironment, "MULESOFT-IAM-06"), "warn");
  assert.match(findingById(untypedEnvironment, "MULESOFT-IAM-06").summary, /did not expose an isProduction or type flag/);

  const policyWithoutState = await assessMulesoftApiGateway(healthyApiGatewayClient({
    async listApiPolicies() {
      return [{ assetId: "client-id-enforcement" }, { assetId: "rate-limiting" }];
    },
  }));
  for (const id of ["MULESOFT-API-07", "MULESOFT-API-08"]) {
    assert.equal(statusOf(policyWithoutState, id), "warn", id);
    assert.match(findingById(policyWithoutState, id).summary, /whose disabled flag was not returned, so its enabled state is unknown/);
  }
  const disabledPolicy = await assessMulesoftApiGateway(healthyApiGatewayClient({
    async listApiPolicies() {
      return [{ assetId: "client-id-enforcement", disabled: true }, { assetId: "rate-limiting", disabled: false }];
    },
  }));
  assert.equal(statusOf(disabledPolicy, "MULESOFT-API-07"), "fail");
  assert.equal(statusOf(disabledPolicy, "MULESOFT-API-08"), "pass");

  const runtime = await assessMulesoftRuntimeInfrastructure(healthyRuntimeClient({
    async listLoadBalancers() {
      return [{ id: "lb-1", name: "flagless", domain: "flagless.lb.anypointdns.net", state: "STARTED" }];
    },
    async getVpc() {
      return { id: "vpc-1", name: "prod-vpc" };
    },
    async listCloudhubApplications(environmentId) {
      const applications = await healthyRuntimeClient().listCloudhubApplications(environmentId);
      return applications.map(({ persistentQueuesEncrypted: _flag, properties: _properties, ...application }) => application);
    },
  }));
  assert.equal(statusOf(runtime, "MULESOFT-RT-15"), "warn");
  assert.match(findingById(runtime, "MULESOFT-RT-15").summary, /did not return the tlsv1 or httpMode flags/);
  assert.equal(statusOf(runtime, "MULESOFT-RT-13"), "manual");
  assert.match(findingById(runtime, "MULESOFT-RT-13").summary, /did not return a firewallRules list/);
  assert.equal(statusOf(runtime, "MULESOFT-RT-14"), "manual");
  assert.equal(statusOf(runtime, "MULESOFT-RT-12"), "fail");
  assert.equal(statusOf(runtime, "MULESOFT-RT-22"), "warn");
  assert.match(findingById(runtime, "MULESOFT-RT-22").summary, /did not return a properties object/);

  const audit = await assessMulesoftAuditMonitoring(healthyAuditClient({
    async listCloudhubAlerts() {
      return [{ id: "alert-1", name: "CPU", condition: { resources: ["*"] } }];
    },
  }));
  assert.equal(statusOf(audit, "MULESOFT-AUD-24"), "warn");
  assert.match(findingById(audit, "MULESOFT-AUD-24").summary, /alerts whose enabled flag was not returned/);
  const unscopedAlert = await assessMulesoftAuditMonitoring(healthyAuditClient({
    async listCloudhubAlerts() {
      return [{ id: "alert-1", name: "CPU", enabled: true }];
    },
  }));
  assert.equal(statusOf(unscopedAlert, "MULESOFT-AUD-24"), "warn");
  assert.deepEqual(findingById(unscopedAlert, "MULESOFT-AUD-24").evidence.production_environments[0].uncovered_applications, ["orders-prod"]);
});

test("verdict safety rule 7: pagination runs to completion or records truncation", async () => {
  const population = Array.from({ length: 5 }, (_, index) => ({ id: `u${index + 1}` }));
  const requests = [];
  const pagedFetch = (options = {}) => async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const limit = Number(url.searchParams.get("limit"));
    const offset = Number(url.searchParams.get("offset"));
    requests.push({ limit, offset });
    const serverLimit = options.serverPageCap ? Math.min(limit, options.serverPageCap) : limit;
    const data = population.slice(offset, offset + serverLimit);
    return jsonResponse(options.withTotal ? { data, total: population.length } : { data });
  };

  requests.length = 0;
  const withTotal = await new MulesoftApiClient(sampleConfig(), { fetchImpl: pagedFetch({ withTotal: true }) })
    .listOffset("/accounts/api/organizations/org-1/members", { limit: 3, pageSize: 2 });
  assert.deepEqual(withTotal.items.map((item) => item.id), ["u1", "u2", "u3"]);
  assert.equal(withTotal.total, 5);
  assert.equal(withTotal.truncated, true);
  assert.deepEqual(requests, [{ limit: 2, offset: 0 }, { limit: 1, offset: 2 }]);

  requests.length = 0;
  const probed = await new MulesoftApiClient(sampleConfig(), { fetchImpl: pagedFetch() })
    .listOffset("/accounts/api/organizations/org-1/members", { limit: 4, pageSize: 2 });
  assert.equal(probed.items.length, 4);
  assert.equal(probed.total, undefined);
  assert.equal(probed.truncated, true);
  assert.deepEqual(requests.at(-1), { limit: 1, offset: 4 });

  requests.length = 0;
  const complete = await new MulesoftApiClient(sampleConfig(), { fetchImpl: pagedFetch() })
    .listOffset("/accounts/api/organizations/org-1/members", { limit: 100, pageSize: 100 });
  assert.equal(complete.items.length, 5);
  assert.equal(complete.truncated, false);
  assert.deepEqual(requests, [{ limit: 100, offset: 0 }, { limit: 95, offset: 5 }]);

  requests.length = 0;
  const shortPages = await new MulesoftApiClient(sampleConfig(), { fetchImpl: pagedFetch({ serverPageCap: 2 }) })
    .listOffset("/accounts/api/organizations/org-1/members", { limit: 100, pageSize: 100 });
  assert.deepEqual(shortPages.items.map((item) => item.id), ["u1", "u2", "u3", "u4", "u5"]);
  assert.equal(shortPages.truncated, false);
  assert.equal(requests.length, 4);

  requests.length = 0;
  const exactFit = await new MulesoftApiClient(sampleConfig(), { fetchImpl: pagedFetch() })
    .listOffset("/accounts/api/organizations/org-1/members", { limit: 5, pageSize: 5 });
  assert.equal(exactFit.items.length, 5);
  assert.equal(exactFit.truncated, false);
  assert.deepEqual(requests, [{ limit: 5, offset: 0 }, { limit: 1, offset: 5 }]);

  const apiManagerFetch = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const offset = Number(url.searchParams.get("offset"));
    const assets = [
      { assetId: "orders", name: "Orders", apis: [{ id: 1 }, { id: 2 }] },
      { assetId: "billing", name: "Billing", apis: [{ id: 3 }] },
      { assetId: "shipping", name: "Shipping", apis: [{ id: 4 }] },
    ];
    return jsonResponse({ total: assets.length, assets: assets.slice(offset, offset + Number(url.searchParams.get("limit"))) });
  };
  const apis = await new MulesoftApiClient(sampleConfig(), { fetchImpl: apiManagerFetch }).listManagedApis("env-prod", 2);
  assert.deepEqual(apis.items.map((api) => api.id), [1, 2]);
  assert.equal(apis.truncated, true);
  const allApis = await new MulesoftApiClient(sampleConfig(), { fetchImpl: apiManagerFetch }).listManagedApis("env-prod", 10);
  assert.equal(allApis.items.length, 4);
  assert.equal(allApis.truncated, false);
  assert.equal(allApis.total, 4);

  const result = await assessMulesoftIdentityAccess(healthyIdentityClient({
    async listRoleGroupRoles(roleGroupId) {
      const roles = await healthyIdentityClient().listRoleGroupRoles(roleGroupId);
      return roleGroupId === "rg-dev" ? truncatedPage(roles, 80) : roles;
    },
  }));
  assert.equal(statusOf(result, "MULESOFT-IAM-04"), "warn");
  assert.match(findingById(result, "MULESOFT-IAM-04").summary, /role assignments truncated for Developers/);
  assert.equal(statusOf(result, "MULESOFT-IAM-05"), "warn");
  assert.equal(result.snapshots.role_groups.find((item) => item.role_group.role_group_id === "rg-dev").roles_truncated, true);
});

test("verdict safety rule 8: re-running an export never overwrites a prior bundle and keeps directory and archive paired", async () => {
  const base = createTempBase("grclanker-mulesoft-rerun-");
  const first = await exportMulesoftAuditBundle(healthyBundleClient(), sampleConfig(), base);
  const firstZip = readFileSync(first.zipPath);
  assert.equal(first.zipPath, `${first.outputDir}.zip`);

  const second = await exportMulesoftAuditBundle(healthyBundleClient(), sampleConfig(), base);
  assert.notEqual(second.outputDir, first.outputDir);
  assert.equal(second.zipPath, `${second.outputDir}.zip`);
  assert.match(second.outputDir, /org-1-audit-bundle-2$/);
  assert.ok(existsSync(first.zipPath));
  assert.ok(existsSync(second.zipPath));
  assert.ok(readFileSync(first.zipPath).equals(firstZip), "the first archive must be byte-for-byte unchanged");

  writeFileSync(join(base, "org-1-audit-bundle-3.zip"), "orphan archive from an earlier run");
  const third = await exportMulesoftAuditBundle(healthyBundleClient(), sampleConfig(), base);
  assert.match(third.outputDir, /org-1-audit-bundle-4$/);
  assert.equal(third.zipPath, `${third.outputDir}.zip`);
  assert.equal(readFileSync(join(base, "org-1-audit-bundle-3.zip"), "utf8"), "orphan archive from an earlier run");
  assert.deepEqual(
    readdirSync(base).filter((name) => name.endsWith(".zip")).sort(),
    ["org-1-audit-bundle-2.zip", "org-1-audit-bundle-3.zip", "org-1-audit-bundle-4.zip", "org-1-audit-bundle.zip"],
  );
});

test("false-pass self-check (a): every endpoint forbidden yields no pass for any assess tool", async () => {
  const identity = await assessMulesoftIdentityAccess(forbidAll(healthyIdentityClient()));
  assert.equal(identity.findings.length, 9);
  assertNoPass(identity, "identity/403");
  assertAllManualNamingCause(identity, "identity/403");

  const gateway = await assessMulesoftApiGateway(forbidAll(healthyApiGatewayClient()));
  assert.equal(gateway.findings.length, 4);
  assertNoPass(gateway, "gateway/403");
  assertAllManualNamingCause(gateway, "gateway/403");

  const runtime = await assessMulesoftRuntimeInfrastructure(forbidAll(healthyRuntimeClient()));
  assert.equal(runtime.findings.length, 10);
  assertNoPass(runtime, "runtime/403");
  assertAllManualNamingCause(runtime, "runtime/403");

  const audit = await assessMulesoftAuditMonitoring(forbidAll(healthyAuditClient()));
  assert.equal(audit.findings.length, 2);
  assertNoPass(audit, "audit/403");
  assertAllManualNamingCause(audit, "audit/403");
});

test("false-pass self-check (b): every list empty yields no pass, and only IAM-01, AUD-17, and AUD-24 fail on emptiness", async () => {
  const results = [
    await assessMulesoftIdentityAccess(emptyIdentityClient()),
    await assessMulesoftApiGateway(emptyApiGatewayClient()),
    await assessMulesoftRuntimeInfrastructure(emptyRuntimeClient()),
    await assessMulesoftAuditMonitoring(emptyAuditClient()),
  ];
  const findings = results.flatMap((result) => result.findings);
  assert.equal(findings.length, 25);
  for (const result of results) assertNoPass(result, `${result.category}/empty`);
  assert.deepEqual(
    findings.filter((item) => item.status === "fail").map((item) => item.id).sort(),
    ["MULESOFT-AUD-17", "MULESOFT-AUD-24", "MULESOFT-IAM-01"],
  );
  assert.ok(findings.filter((item) => item.status === "manual").length === 22);
  for (const item of findings.filter((item) => item.status === "manual")) {
    assert.match(item.summary, /manual|not applicable|Confirm|Export|export/, `${item.id} must tell the reader what to collect`);
  }
});

test("false-pass self-check (c): partial inventories yield no pass in any assess tool, except AUD-17 whose organization-wide audit count is not narrowed by the fixture", async () => {
  const identity = await assessMulesoftIdentityAccess(partialIdentityClient());
  assertNoPass(identity, "identity/partial");
  for (const item of identity.findings) {
    assert.ok(
      /Partial view|business group|Could not|treated as manual/.test(item.summary),
      `${item.id} must explain the partial view: ${item.summary}`,
    );
  }

  const gateway = await assessMulesoftApiGateway(partialApiGatewayClient());
  assertNoPass(gateway, "gateway/partial");
  assert.equal(statusOf(gateway, "MULESOFT-API-20"), "manual");
  assert.match(findingById(gateway, "MULESOFT-API-20").summary, /Partial view: Exchange asset list truncated at 1 of 900 total/);
  assert.deepEqual(findingById(gateway, "MULESOFT-API-20").evidence.partial_view, ["Exchange asset list truncated at 1 of 900 total"]);
  for (const id of ["MULESOFT-API-07", "MULESOFT-API-08"]) {
    assert.equal(statusOf(gateway, id), "manual", id);
    assert.match(findingById(gateway, id).summary, /Partial view: the environment filter excluded 1 environment\(s\) \(1 production\): Production/, id);
  }

  const runtime = await assessMulesoftRuntimeInfrastructure(partialRuntimeClient(), { environmentLimit: 1, applicationLimit: 1 });
  assertNoPass(runtime, "runtime/partial");
  assert.match(findingById(runtime, "MULESOFT-RT-13").summary, /VPC list truncated at 20 of 21/);
  assert.match(findingById(runtime, "MULESOFT-RT-15").summary, /load balancer list truncated at 10 of 11/);
  assert.deepEqual(runtime.summary.partial_view, [
    "the environment limit of 1 excluded 1 environment(s) (0 production): Sandbox",
    "VPC list truncated at 20 of 21 total",
    "load balancer list truncated at 10 of 11 total",
  ]);
  assert.equal(runtime.summary.applications_not_inspected, 0);

  const audit = await assessMulesoftAuditMonitoring(partialAuditClient(), { environmentLimit: 1 });
  assert.equal(statusOf(audit, "MULESOFT-AUD-24"), "warn");
  assert.match(findingById(audit, "MULESOFT-AUD-24").summary, /Partial view: the environment limit of 1 excluded 2 environment\(s\) \(1 production\)/);
  assert.equal(
    statusOf(audit, "MULESOFT-AUD-17"),
    "pass",
    "AUD-17 decides on the organization-wide, server-reported count of entries in the lookback window; the environment limit does not scope the audit query and the capped sample is reported, not relied on",
  );
  assert.equal(findingById(audit, "MULESOFT-AUD-17").evidence.entries_in_window, 5000);
  assert.equal(findingById(audit, "MULESOFT-AUD-17").evidence.entries_fetched, 1);
  assert.match(findingById(audit, "MULESOFT-AUD-17").summary, /5000 audit log entries recorded within the last 24 hours \(1 fetched\)/);
  assert.equal(findingById(audit, "MULESOFT-AUD-17").evidence.partial_view, undefined);

  const allFindings = [identity, gateway, runtime, audit].flatMap((result) => result.findings);
  assert.equal(allFindings.length, 25);
  assert.deepEqual(allFindings.filter((item) => item.status === "pass").map((item) => item.id), ["MULESOFT-AUD-17"]);
});

// Review fixes for PR #27 (compliance review of the MuleSoft inspector)

function pagedServer(pathname, items, serverPageCap) {
  return (url) => {
    if (url.pathname !== pathname) return undefined;
    const offset = Number(url.searchParams.get("offset") ?? 0);
    const requested = url.searchParams.has("limit") ? Number(url.searchParams.get("limit")) : serverPageCap;
    const limit = Math.min(requested, serverPageCap);
    return jsonResponse({ data: items.slice(offset, offset + limit), total: items.length });
  };
}

function routedFetch(routes, seen = []) {
  return async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({ pathname: url.pathname, search: url.search, method: init.method ?? "GET" });
    for (const route of routes) {
      const response = route(url, init);
      if (response) return response;
    }
    return jsonResponse({ data: [], total: 0 });
  };
}

function rootHierarchyRoute() {
  return (url) => (url.pathname === `/accounts/api/organizations/${ORG_ID}/hierarchy` ? jsonResponse({ id: ORG_ID, isRoot: true, subOrganizations: [] }) : undefined);
}

function manyEnvironments(count, productionIndex) {
  return Array.from({ length: count }, (_, index) => ({
    id: `env-${index}`,
    name: index === productionIndex ? "Production" : `Sandbox ${index}`,
    isProduction: index === productionIndex,
    type: index === productionIndex ? "production" : "sandbox",
  }));
}

test("review fix 1: listEnvironments pages past the Access Management default of 25 and records truncation", async () => {
  const environments = manyEnvironments(30, 29);
  const seen = [];
  const client = new MulesoftApiClient(sampleConfig(), {
    fetchImpl: routedFetch([pagedServer(`/accounts/api/organizations/${ORG_ID}/environments`, environments, 25)], seen),
  });

  const complete = await client.listEnvironments();
  assert.equal(complete.items.length, 30);
  assert.equal(complete.items.at(-1).id, "env-29");
  assert.equal(complete.total, 30);
  assert.equal(complete.truncated, false);
  assert.ok(seen.every((request) => /limit=\d+/.test(request.search) && /offset=\d+/.test(request.search)), "every environments request carries limit and offset");
  assert.ok(seen.some((request) => request.search.includes("offset=25")), "the second page starts at offset 25");

  const capped = await client.listEnvironments(25);
  assert.equal(capped.items.length, 25);
  assert.equal(capped.total, 30);
  assert.equal(capped.truncated, true);
});

test("review fix 1: a production environment beyond the 25th is sampled through the real client so API-07 and API-08 fail instead of passing", async () => {
  const environments = manyEnvironments(30, 29);
  const client = new MulesoftApiClient(sampleConfig(), {
    fetchImpl: routedFetch([
      rootHierarchyRoute(),
      pagedServer(`/accounts/api/organizations/${ORG_ID}/environments`, environments, 25),
      (url) => (url.pathname.endsWith("/environments/env-29/apis")
        ? jsonResponse({
          assets: [{ name: "orders-api", groupId: ORG_ID, assetId: "orders-api", apis: [{ id: 901, instanceLabel: "v1", environmentId: "env-29", activeContractsCount: 2 }] }],
          total: 1,
        })
        : undefined),
      (url) => (/\/environments\/env-\d+\/apis$/.test(url.pathname) ? jsonResponse({ assets: [], total: 0 }) : undefined),
      (url) => (url.pathname.endsWith("/apis/901/policies") ? jsonResponse({ policies: [] }) : undefined),
      (url) => (url.pathname === "/exchange/api/v2/assets/search" ? jsonResponse([]) : undefined),
    ]),
  });

  const result = await assessMulesoftApiGateway(client, { environmentLimit: 30 });

  assert.equal(result.summary.environments_visible, 30);
  assert.deepEqual(result.summary.partial_view, []);
  assert.equal(statusOf(result, "MULESOFT-API-07"), "fail");
  assert.equal(findingById(result, "MULESOFT-API-07").evidence.production_without_authentication.length, 1);
  assert.match(findingById(result, "MULESOFT-API-07").evidence.production_without_authentication[0], /^Production: /);
  assert.equal(statusOf(result, "MULESOFT-API-08"), "fail");
});

test("review fix 1: a truncated environment inventory downgrades every environment-scoped control instead of passing", async () => {
  const truncated = async () => truncatedPage(ENVIRONMENTS, 30);
  const note = /Partial view: the environment list truncated at 2 of 30 total, so unseen environments \(which may include production\) were not sampled/;

  const identity = await assessMulesoftIdentityAccess(healthyIdentityClient({ listEnvironments: truncated }));
  assert.equal(statusOf(identity, "MULESOFT-IAM-06"), "warn");
  assert.match(findingById(identity, "MULESOFT-IAM-06").summary, /Partial view: environment list truncated at 2 of 30 total/);

  const gateway = await assessMulesoftApiGateway(healthyApiGatewayClient({ listEnvironments: truncated }));
  for (const id of ["MULESOFT-API-07", "MULESOFT-API-08"]) {
    assert.equal(statusOf(gateway, id), "warn", id);
    assert.match(findingById(gateway, id).summary, note, id);
  }
  assert.deepEqual(gateway.summary.partial_view, [
    "the environment list truncated at 2 of 30 total, so unseen environments (which may include production) were not sampled",
  ]);

  const runtime = await assessMulesoftRuntimeInfrastructure(healthyRuntimeClient({ listEnvironments: truncated }));
  for (const id of ["MULESOFT-RT-10", "MULESOFT-RT-11", "MULESOFT-RT-12", "MULESOFT-RT-22", "MULESOFT-RT-23"]) {
    assert.equal(statusOf(runtime, id), "warn", id);
    assert.match(findingById(runtime, id).summary, note, id);
  }
  assert.equal(statusOf(runtime, "MULESOFT-RT-21"), "manual");
  assert.match(findingById(runtime, "MULESOFT-RT-21").summary, note);

  const audit = await assessMulesoftAuditMonitoring(healthyAuditClient({ listEnvironments: truncated }));
  assert.equal(statusOf(audit, "MULESOFT-AUD-24"), "warn");
  assert.match(findingById(audit, "MULESOFT-AUD-24").summary, note);
});

test("review fix 2: the ARM server envelope is unwrapped so a RUNNING hybrid server passes RT-23 through the real client", async () => {
  const armServers = {
    data: [{
      data: {
        id: 1,
        timeCreated: 1700000000000,
        timeUpdated: 1700000600000,
        name: "onprem-1",
        type: "SERVER",
        muleVersion: "4.6.0",
        agentVersion: "2.7.0",
        status: "RUNNING",
        addresses: [{ ip: "10.0.0.5", networkInterface: "eth0" }],
      },
    }],
  };
  const client = new MulesoftApiClient(sampleConfig(), {
    fetchImpl: routedFetch([
      rootHierarchyRoute(),
      pagedServer(`/accounts/api/organizations/${ORG_ID}/environments`, ENVIRONMENTS, 25),
      (url, init) => (url.pathname === "/hybrid/api/v1/servers" && headerValue(init.headers, "X-ANYPNT-ENV-ID") === "env-prod" ? jsonResponse(armServers) : undefined),
      (url) => (url.pathname === "/hybrid/api/v1/alerts" ? jsonResponse({ data: [{ data: { id: "alert-1", name: "Server down", enabled: true } }] }) : undefined),
    ]),
  });

  const servers = await client.listHybridServers("env-prod");
  assert.equal(servers.length, 1);
  assert.equal(servers[0].status, "RUNNING");
  assert.equal(servers[0].muleVersion, "4.6.0");
  assert.equal(servers[0].name, "onprem-1");
  assert.equal(servers[0].data, undefined);

  const alerts = await client.listHybridAlerts("env-prod");
  assert.deepEqual(alerts, [{ id: "alert-1", name: "Server down", enabled: true }]);

  const result = await assessMulesoftRuntimeInfrastructure(client);
  assert.equal(statusOf(result, "MULESOFT-RT-23"), "pass", findingById(result, "MULESOFT-RT-23").summary);
  assert.deepEqual(findingById(result, "MULESOFT-RT-23").evidence.mule_versions, ["4.6.0"]);
  assert.deepEqual(findingById(result, "MULESOFT-RT-23").evidence.disconnected_servers, []);
});

test("review fix 3: listVpcs and listLoadBalancers page with limit and offset, request the long DLB format, and record truncation", async () => {
  const vpcs = Array.from({ length: 25 }, (_, index) => ({ id: `vpc-${index}`, name: `vpc-${index}` }));
  const loadBalancers = Array.from({ length: 12 }, (_, index) => ({ id: `lb-${index}`, name: `dlb-${index}`, domain: `dlb-${index}.lb.anypointdns.net`, tlsv1: false, httpMode: "redirect" }));
  const seen = [];
  const client = new MulesoftApiClient(sampleConfig(), {
    fetchImpl: routedFetch([
      pagedServer(`/cloudhub/api/organizations/${ORG_ID}/vpcs`, vpcs, 100),
      pagedServer(`/cloudhub/api/organizations/${ORG_ID}/loadbalancers`, loadBalancers, 100),
    ], seen),
  });

  const cappedVpcs = await client.listVpcs();
  assert.equal(cappedVpcs.items.length, 20);
  assert.equal(cappedVpcs.total, 25);
  assert.equal(cappedVpcs.truncated, true);
  const allVpcs = await client.listVpcs(25);
  assert.equal(allVpcs.items.length, 25);
  assert.equal(allVpcs.truncated, false);

  const cappedLoadBalancers = await client.listLoadBalancers();
  assert.equal(cappedLoadBalancers.items.length, 10);
  assert.equal(cappedLoadBalancers.total, 12);
  assert.equal(cappedLoadBalancers.truncated, true);
  const loadBalancerRequests = seen.filter((request) => request.pathname.endsWith("/loadbalancers"));
  assert.ok(loadBalancerRequests.length > 0);
  assert.ok(loadBalancerRequests.every((request) => request.search.includes("shortFormat=false") && /limit=\d+/.test(request.search) && /offset=\d+/.test(request.search)));
  assert.ok(seen.filter((request) => request.pathname.endsWith("/vpcs")).every((request) => /limit=\d+/.test(request.search) && /offset=\d+/.test(request.search)));
});

test("review fix 3: truncated VPC and load balancer pages downgrade RT-13 through RT-16 instead of passing", async () => {
  const healthy = healthyRuntimeClient();
  const client = healthyRuntimeClient({
    async listVpcs() {
      return truncatedPage(await healthy.listVpcs(), 30);
    },
    async listLoadBalancers() {
      return truncatedPage(await healthy.listLoadBalancers(), 15);
    },
  });

  const result = await assessMulesoftRuntimeInfrastructure(client);

  for (const id of ["MULESOFT-RT-13", "MULESOFT-RT-14"]) {
    assert.equal(statusOf(result, id), "warn", id);
    assert.match(findingById(result, id).summary, /Partial view: VPC list truncated at 1 of 30 total/, id);
  }
  for (const id of ["MULESOFT-RT-15", "MULESOFT-RT-16"]) {
    assert.equal(statusOf(result, id), "warn", id);
    assert.match(findingById(result, id).summary, /Partial view: load balancer list truncated at 1 of 15 total/, id);
  }
  assert.deepEqual(result.summary.partial_view, ["VPC list truncated at 1 of 30 total", "load balancer list truncated at 1 of 15 total"]);
});

test("review fix 6: 0.0.0.0/0 ingress on the DLB back-end ports 8091 and 8092 fails RT-14 while 8081 and 8082 only warn", async () => {
  const withRules = (firewallRules) => healthyRuntimeClient({
    async getVpc() {
      return { id: "vpc-1", name: "prod-vpc", firewallRules };
    },
  });

  const backEndOpen = await assessMulesoftRuntimeInfrastructure(withRules([
    { cidrBlock: "0.0.0.0/0", protocol: "tcp", fromPort: 8091, toPort: 8091 },
    { cidrBlock: "0.0.0.0/0", protocol: "tcp", fromPort: 8092, toPort: 8092 },
  ]));
  assert.equal(statusOf(backEndOpen, "MULESOFT-RT-14"), "fail");
  assert.match(findingById(backEndOpen, "MULESOFT-RT-14").summary, /8091 and 8092 are DLB back-end ports/);
  assert.deepEqual(findingById(backEndOpen, "MULESOFT-RT-14").evidence.open_non_standard_rules, [
    "prod-vpc: tcp 8091 from 0.0.0.0/0",
    "prod-vpc: tcp 8092 from 0.0.0.0/0",
  ]);

  const listenerOpen = await assessMulesoftRuntimeInfrastructure(withRules([
    { cidrBlock: "0.0.0.0/0", protocol: "tcp", fromPort: 8081, toPort: 8082 },
    { cidrBlock: "10.0.0.0/16", protocol: "tcp", fromPort: 8091, toPort: 8092 },
  ]));
  assert.equal(statusOf(listenerOpen, "MULESOFT-RT-14"), "warn");
  assert.deepEqual(findingById(listenerOpen, "MULESOFT-RT-14").evidence.open_non_standard_rules, []);
  assert.deepEqual(findingById(listenerOpen, "MULESOFT-RT-14").evidence.open_standard_port_rules, ["prod-vpc: tcp 8081-8082 from 0.0.0.0/0"]);
});

test("review fix 7: listConnectedApplications sends hide_managed=false so managed apps are inventoried and counted in the total", async () => {
  const connectedApps = [
    { client_id: "app-1", client_name: "Auditor", grant_types: ["client_credentials"], enabled: true },
    { client_id: "app-managed", client_name: "Managed integration", grant_types: ["client_credentials"], enabled: true, managed: true },
  ];
  const seen = [];
  const client = new MulesoftApiClient(sampleConfig(), {
    fetchImpl: routedFetch([
      (url) => {
        if (url.pathname !== `/accounts/api/organizations/${ORG_ID}/connectedApplications`) return undefined;
        const visible = url.searchParams.get("hide_managed") === "false" ? connectedApps : connectedApps.filter((app) => !app.managed);
        return jsonResponse({ data: visible, total: visible.length });
      },
      (url) => (url.pathname.endsWith("/connectedApplications/app-managed/scopes") ? jsonResponse({ data: [{ scope: "full" }], total: 1 }) : undefined),
      (url) => (url.pathname.endsWith("/scopes") ? jsonResponse({ data: [{ scope: "profile" }], total: 1 }) : undefined),
      (url) => (url.pathname === `/accounts/api/organizations/${ORG_ID}/hierarchy` ? jsonResponse({ id: ORG_ID, isRoot: true, subOrganizations: [] }) : undefined),
      pagedServer(`/accounts/api/organizations/${ORG_ID}/environments`, ENVIRONMENTS, 25),
    ], seen),
  });

  const page = await client.listConnectedApplications();
  assert.deepEqual(page.items.map((app) => app.client_id), ["app-1", "app-managed"]);
  assert.equal(page.total, 2);
  const request = seen.find((item) => item.pathname.endsWith("/connectedApplications"));
  assert.ok(request.search.includes("hide_managed=false"), request.search);
  assert.ok(request.search.includes("includeUsage=true"), request.search);

  const result = await assessMulesoftIdentityAccess(client);
  assert.equal(statusOf(result, "MULESOFT-IAM-18"), "fail");
  assert.deepEqual(findingById(result, "MULESOFT-IAM-18").evidence.admin_scoped_apps, ["Managed integration"]);
  assert.equal(findingById(result, "MULESOFT-IAM-18").evidence.connected_apps, 2);
  assert.equal(findingById(result, "MULESOFT-IAM-18").evidence.connected_apps_total, 2);
  assert.equal(findingById(result, "MULESOFT-IAM-18").evidence.managed_apps_included, true);
  assert.equal(findingById(result, "MULESOFT-IAM-19").evidence.connected_apps_total, 2);
});

test("review fix 8: CloudHub applications are listed with retrieveStatistics=true and RT-11 uses the returned CPU figures", async () => {
  const seen = [];
  const client = new MulesoftApiClient(sampleConfig(), {
    fetchImpl: routedFetch([
      (url) => (url.pathname === "/cloudhub/api/v2/applications"
        ? jsonResponse({ data: [{ domain: "orders-prod", workers: { amount: 4, type: { name: "Medium", weight: 1 }, recentStatistics: { cpu: 3.5 } } }] })
        : undefined),
    ], seen),
  });

  const applications = await client.listCloudhubApplications("env-prod");
  assert.equal(applications[0].workers.recentStatistics.cpu, 3.5);
  assert.ok(seen[0].search.includes("retrieveStatistics=true"), seen[0].search);

  const lowCpu = await assessMulesoftRuntimeInfrastructure(healthyRuntimeClient({
    async listCloudhubApplications(environmentId) {
      if (environmentId !== "env-prod") return [];
      return [{
        domain: "orders-prod",
        muleVersion: { version: "4.6.0", endOfSupportDate: isoDaysFromNow(400) },
        workers: { amount: 4, type: { name: "Medium", weight: 1 }, recentStatistics: { cpu: 3.5 } },
        properties: {},
      }];
    },
  }));
  assert.equal(statusOf(lowCpu, "MULESOFT-RT-11"), "warn");
  assert.deepEqual(findingById(lowCpu, "MULESOFT-RT-11").evidence.oversized_applications, ["Production: orders-prod: 4 x Medium"]);
  assert.equal(findingById(lowCpu, "MULESOFT-RT-11").evidence.applications_with_cpu_statistics, 1);

  const noStatistics = await assessMulesoftRuntimeInfrastructure(healthyRuntimeClient({
    async listCloudhubApplications(environmentId) {
      if (environmentId !== "env-prod") return [];
      return [{
        domain: "orders-prod",
        muleVersion: { version: "4.6.0", endOfSupportDate: isoDaysFromNow(400) },
        workers: { amount: 4, type: { name: "Medium", weight: 1 } },
        properties: {},
      }];
    },
  }));
  assert.equal(statusOf(noStatistics, "MULESOFT-RT-11"), "warn");
  assert.match(findingById(noStatistics, "MULESOFT-RT-11").summary, /returned no recentStatistics\.cpu even with retrieveStatistics=true/);
  assert.deepEqual(findingById(noStatistics, "MULESOFT-RT-11").evidence.large_applications_without_cpu_statistics, ["Production: orders-prod"]);
});

test("review fix 10: a business-group-scoped credential flags the partial view on runtime, gateway, and audit findings too", async () => {
  const businessGroup = async () => ({ id: ORG_ID, isRoot: false, parentId: "root-org", subOrganizations: [] });
  const note = /Partial view: this organization is a business group \(isRoot=false\), so root-level settings and sibling business groups are outside the view/;

  const runtime = await assessMulesoftRuntimeInfrastructure(healthyRuntimeClient({ getOrganizationHierarchy: businessGroup }));
  for (const id of ["MULESOFT-RT-13", "MULESOFT-RT-14", "MULESOFT-RT-15", "MULESOFT-RT-16", "MULESOFT-RT-10", "MULESOFT-RT-23"]) {
    assert.equal(statusOf(runtime, id), "warn", `${id}: ${findingById(runtime, id).summary}`);
    assert.match(findingById(runtime, id).summary, note, id);
  }
  assert.deepEqual(runtime.summary.partial_view, [
    "this organization is a business group (isRoot=false), so root-level settings and sibling business groups are outside the view",
  ]);

  const gateway = await assessMulesoftApiGateway(healthyApiGatewayClient({ getOrganizationHierarchy: businessGroup }));
  for (const id of ["MULESOFT-API-07", "MULESOFT-API-08"]) {
    assert.equal(statusOf(gateway, id), "warn", id);
    assert.match(findingById(gateway, id).summary, note, id);
  }
  assert.match(findingById(gateway, "MULESOFT-API-20").summary, note);

  const audit = await assessMulesoftAuditMonitoring(healthyAuditClient({ getOrganizationHierarchy: businessGroup }));
  for (const id of ["MULESOFT-AUD-17", "MULESOFT-AUD-24"]) {
    assert.equal(statusOf(audit, id), "warn", id);
    assert.match(findingById(audit, id).summary, note, id);
  }

  const unreadable = await assessMulesoftRuntimeInfrastructure(healthyRuntimeClient({ getOrganizationHierarchy: forbidden("/hierarchy") }));
  assert.equal(statusOf(unreadable, "MULESOFT-RT-13"), "warn");
  assert.match(findingById(unreadable, "MULESOFT-RT-13").summary, /Partial view: organization_hierarchy could not be read, the credential lacks permission \(HTTP 403\)/);

  const untyped = await assessMulesoftRuntimeInfrastructure(healthyRuntimeClient({ async getOrganizationHierarchy() { return { id: ORG_ID }; } }));
  assert.equal(statusOf(untyped, "MULESOFT-RT-15"), "warn");
  assert.match(findingById(untyped, "MULESOFT-RT-15").summary, /did not expose isRoot/);

  const root = await assessMulesoftRuntimeInfrastructure(healthyRuntimeClient());
  assert.equal(statusOf(root, "MULESOFT-RT-13"), "pass");
  assert.deepEqual(root.summary.partial_view, []);
});

test("review fix 4: RT-15 evaluates defaultCipherSuite, failing weak ciphers and warning on legacy or missing suites", async () => {
  const dlb = (overrides) => ({
    id: "lb-1",
    name: "prod-dlb",
    domain: "prod-dlb.lb.anypointdns.net",
    httpMode: "redirect",
    tlsv1: false,
    tlsv13: true,
    state: "STARTED",
    ...overrides,
  });
  const withLoadBalancers = (loadBalancers, extra = {}) => healthyRuntimeClient({
    async listLoadBalancers() {
      return loadBalancers;
    },
    ...extra,
  });

  const rc4 = await assessMulesoftRuntimeInfrastructure(withLoadBalancers([dlb({ defaultCipherSuite: `${STRONG_CIPHER_SUITE}:RC4-SHA:DES-CBC3-SHA` })]));
  assert.equal(statusOf(rc4, "MULESOFT-RT-15"), "fail");
  assert.match(findingById(rc4, "MULESOFT-RT-15").summary, /weak ciphers \(prod-dlb: RC4-SHA, DES-CBC3-SHA\)/);
  assert.deepEqual(findingById(rc4, "MULESOFT-RT-15").evidence.load_balancers[0].weak_ciphers, ["RC4-SHA", "DES-CBC3-SHA"]);

  const legacy = await assessMulesoftRuntimeInfrastructure(withLoadBalancers([dlb({ defaultCipherSuite: OLD_DEFAULT_CIPHER_SUITE })]));
  assert.equal(statusOf(legacy, "MULESOFT-RT-15"), "warn");
  assert.match(findingById(legacy, "MULESOFT-RT-15").summary, /non-forward-secret or broad OpenSSL groups/);
  const legacyEvidence = findingById(legacy, "MULESOFT-RT-15").evidence.load_balancers[0];
  assert.deepEqual(legacyEvidence.weak_ciphers, [], "exclusions such as !RC4 and !MD5 are not counted as offered ciphers");
  assert.ok(legacyEvidence.non_forward_secrecy_ciphers.includes("AES128-SHA"));
  assert.deepEqual(legacyEvidence.broad_cipher_keywords, ["HIGH"]);

  const strong = await assessMulesoftRuntimeInfrastructure(healthyRuntimeClient());
  assert.equal(statusOf(strong, "MULESOFT-RT-15"), "pass");
  assert.match(findingById(strong, "MULESOFT-RT-15").summary, /defaultCipherSuite limited to forward-secret suites/);
  assert.doesNotMatch(findingById(strong, "MULESOFT-RT-15").summary, /managed by Anypoint/);

  const missing = await assessMulesoftRuntimeInfrastructure(withLoadBalancers([dlb({})]));
  assert.equal(statusOf(missing, "MULESOFT-RT-15"), "warn");
  assert.match(findingById(missing, "MULESOFT-RT-15").summary, /did not return defaultCipherSuite \(prod-dlb\)/);

  const detailReads = [];
  const fromDetail = await assessMulesoftRuntimeInfrastructure(withLoadBalancers([dlb({ vpcId: "vpc-1" })], {
    async getLoadBalancer(vpcId, loadBalancerId) {
      detailReads.push([vpcId, loadBalancerId]);
      return { id: loadBalancerId, defaultCipherSuite: STRONG_CIPHER_SUITE, sslEndpoints: [] };
    },
  }));
  assert.deepEqual(detailReads, [["vpc-1", "lb-1"]]);
  assert.equal(statusOf(fromDetail, "MULESOFT-RT-15"), "pass");
  assert.equal(findingById(fromDetail, "MULESOFT-RT-15").evidence.load_balancers[0].default_cipher_suite, STRONG_CIPHER_SUITE);

  const detailForbidden = await assessMulesoftRuntimeInfrastructure(withLoadBalancers([dlb({ vpcId: "vpc-1" })], {
    getLoadBalancer: forbidden("/vpcs/vpc-1/loadbalancers/lb-1"),
  }));
  assert.equal(statusOf(detailForbidden, "MULESOFT-RT-15"), "manual");
  assert.match(findingById(detailForbidden, "MULESOFT-RT-15").summary, /Could not evaluate: load_balancer_details could not be read, the credential lacks permission \(HTTP 403\)/);
  assert.equal(statusOf(detailForbidden, "MULESOFT-RT-16"), "pass", "the certificate control does not depend on the DLB detail read");
});
