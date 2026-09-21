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
      }];
    },
    async listVpcs() {
      return [{ id: "vpc-1", name: "prod-vpc" }];
    },
    async getVpc() {
      return { id: "vpc-1", name: "prod-vpc", firewallRules: [{ cidrBlock: "10.0.0.0/16", protocol: "tcp", fromPort: 8091, toPort: 8092 }] };
    },
    async listLoadBalancers() {
      return [{ id: "lb-1", name: "prod-dlb", domain: "prod-dlb.lb.anypointdns.net", httpMode: "redirect", tlsv1: false, tlsv13: true, state: "STARTED" }];
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

  assert.deepEqual(members.map((member) => member.id), ["u1", "u2", "u3"]);
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
    return jsonResponse({ data: [{ role_group_id: "rg-1", name: "Developers" }] });
  };

  const client = new MulesoftApiClient(sampleConfig(), {
    fetchImpl,
    sleepImpl: async (ms) => {
      sleeps.push(ms);
    },
    retryBaseDelayMs: 10,
  });
  const roleGroups = await client.listRoleGroups();

  assert.equal(roleGroups.length, 1);
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
      return [{ id: "u3", username: "contractor" }];
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

test("assessMulesoftIdentityAccess degrades to warnings and errors when reads fail", async () => {
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

  assert.equal(statusOf(result, "MULESOFT-IAM-01"), "fail");
  assert.equal(statusOf(result, "MULESOFT-IAM-03"), "warn");
  assert.equal(statusOf(result, "MULESOFT-IAM-04"), "warn");
  assert.equal(statusOf(result, "MULESOFT-IAM-18"), "warn");
  assert.match(findingById(result, "MULESOFT-IAM-18").summary, /user-delegated/);
  assert.ok(result.errors.some((error) => error.startsWith("role_groups:")));
  assert.ok(result.errors.some((error) => error.startsWith("identity_providers:")));
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

test("assessMulesoftApiGateway warns when only non-production APIs lack policies and honors environment filters", async () => {
  const client = healthyApiGatewayClient({
    getResolvedConfig: () => sampleConfig({ environmentFilter: ["Production"] }),
    async listApiPolicies(environmentId) {
      return environmentId === "env-prod" ? [{ assetId: "client-id-enforcement" }, { assetId: "spike-control" }] : [];
    },
  });

  const filtered = await assessMulesoftApiGateway(client);
  assert.equal(filtered.summary.environments_sampled, 1);
  assert.equal(statusOf(filtered, "MULESOFT-API-07"), "pass");

  const unfiltered = await assessMulesoftApiGateway(healthyApiGatewayClient({ listApiPolicies: client.listApiPolicies }));
  assert.equal(statusOf(unfiltered, "MULESOFT-API-07"), "warn");
  assert.equal(statusOf(unfiltered, "MULESOFT-API-08"), "warn");
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

test("assessMulesoftAuditMonitoring fails when the audit query is forbidden and production has no alerts", async () => {
  const client = healthyAuditClient({
    async queryAuditLogs() {
      throw new MulesoftApiError(403, "Anypoint request failed (403 Forbidden) for POST /audit/v2/organizations/org-1/query");
    },
    async listCloudhubAlerts() {
      return [];
    },
  });

  const result = await assessMulesoftAuditMonitoring(client);

  assert.equal(statusOf(result, "MULESOFT-AUD-17"), "fail");
  assert.match(findingById(result, "MULESOFT-AUD-17").summary, /audit log query failed/);
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
