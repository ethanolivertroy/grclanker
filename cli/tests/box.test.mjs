import test from "node:test";
import assert from "node:assert/strict";
import { createVerify, generateKeyPairSync } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse as parseYaml, YAMLError } from "yaml";

import {
  BoxApiClient,
  BoxApiError,
  BoxConfigFileError,
  BoxTransportError,
  assessBoxDataGovernance,
  assessBoxIdentityAccess,
  assessBoxSharingCollaboration,
  assessBoxShieldMonitoring,
  buildBoxJwtAssertion,
  checkBoxAccess,
  exportBoxAuditBundle,
  isUnitlessDuration,
  listBoxControls,
  mappingsForControl,
  parseDurationHours,
  projectEnterpriseEvent,
  redactCredentialValues,
  redactSecrets,
  registerBoxTools,
  resolveBoxConfiguration,
  resolveSecureOutputPath,
  scrubErrorText,
} from "../dist/extensions/grc-tools/box.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";
import { assertSecretsAbsent, readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";
import { assertCanaryFixture, assertCanaryWindowsAbsent, assertDepthCapPins } from "./helpers/canary-windows.mjs";
import { assertCookieAttributeCarriersScrubbed } from "./helpers/cookie-attribute-carriers.mjs";
import { scrubAlterations } from "./helpers/scrub-survival.mjs";

const NOW = new Date("2026-09-21T00:00:00Z");
const FRAMEWORKS = ["FedRAMP", "CMMC", "SOC 2", "CIS", "PCI-DSS", "STIG", "IRAP", "ISMAP"];

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
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

function headerValue(headers, name) {
  if (!headers) return undefined;
  if (headers instanceof Headers) return headers.get(name) ?? undefined;
  if (typeof headers.get === "function") return headers.get(name) ?? undefined;
  return headers[name] ?? headers[name.toLowerCase()];
}

function decodeSegment(segment) {
  const padded = segment.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(segment.length / 4) * 4, "=");
  return JSON.parse(Buffer.from(padded, "base64").toString("utf8"));
}

function generateJwtConfig(directory, overrides = {}) {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pathname = join(directory, "box-jwt-config.json");
  writeFileSync(pathname, JSON.stringify({
    boxAppSettings: {
      clientID: "jwt-client-id",
      clientSecret: "jwt-client-secret",
      appAuth: {
        publicKeyID: "kid-1234",
        privateKey: privateKey.export({ type: "pkcs8", format: "pem" }),
        passphrase: "",
      },
    },
    enterpriseID: "987654",
    ...overrides,
  }));
  return { pathname, publicKey };
}

function sampleConfig(overrides = {}) {
  return {
    authMode: "ccg",
    clientId: "client-id",
    clientSecret: "client-secret",
    enterpriseId: "123456",
    subjectType: "enterprise",
    subjectId: "123456",
    baseUrl: "https://api.box.com/2.0",
    tokenUrl: "https://api.box.com/oauth2/token",
    timeoutMs: 30000,
    maxRetries: 3,
    sourceChain: ["tests"],
    ...overrides,
  };
}

function item(value) {
  return { is_used: true, value };
}

function hardenedConfiguration() {
  return {
    id: "123456",
    type: "enterprise_configuration",
    security: {
      is_multi_factor_auth_required: item(true),
      multi_factor_auth_type: item("totp"),
      is_weak_password_prevention_enabled: item(true),
      is_password_leak_detection_enabled: item(true),
      is_strong_password_for_ext_collab_enabled: item(true),
      password_min_length: item(14),
      password_min_uppercase_characters: item(1),
      password_min_numeric_characters: item(1),
      password_min_special_characters: item(1),
      password_reset_frequency: item("90 days"),
      previous_password_reuse_limit: item("5"),
      session_duration: item("12 hours"),
      is_custom_session_duration_enabled: item(false),
    },
    user_settings: {
      is_enterprise_sso_required: item(true),
      is_enterprise_sso_in_testing: item(false),
      is_device_limit_exemption_enabled_for_new_users: item(false),
      is_box_sync_restricted_for_new_users: item(true),
    },
    content_and_sharing: {
      external_collaboration_status: item("limit_collaboration_to_allowlisted_domains"),
      collaboration_restrictions: item(["external"]),
      external_collaboration_allowlist_users: item([]),
      shared_link_default_access: item("collaborators"),
      shared_link_access: item("company"),
      shared_link_company_definition: item("company"),
      is_shared_links_expiration_enabled: item(true),
      shared_links_expiration_days: item(30),
      is_public_shared_links_expiration_enabled: item(true),
      public_shared_links_expiration_days: item(7),
      shared_expiration_target: item("all"),
      is_watermarking_enterprise_feature_enabled: item(true),
    },
    shield: {
      shield_rules: [
        { id: "rule-1", type: "shield_rule", rule_category: "anomalous_download", name: "Anomalous download detection", priority: "high" },
        { id: "rule-2", type: "shield_rule", rule_category: "access_policy", name: "Block external sharing of confidential content", priority: "critical" },
      ],
    },
  };
}

function weakConfiguration() {
  return {
    id: "123456",
    type: "enterprise_configuration",
    security: {
      is_multi_factor_auth_required: item(false),
      is_weak_password_prevention_enabled: item(false),
      password_min_length: item(6),
      password_min_uppercase_characters: item(0),
      password_min_numeric_characters: item(0),
      password_min_special_characters: item(0),
      session_duration: item("never"),
    },
    user_settings: {
      is_enterprise_sso_required: item(false),
      is_enterprise_sso_in_testing: item(false),
    },
    content_and_sharing: {
      external_collaboration_status: item("enable_external_collaboration"),
      shared_link_default_access: item("open"),
      shared_link_access: item("open"),
      is_shared_links_expiration_enabled: item(false),
      is_public_shared_links_expiration_enabled: item(false),
      is_watermarking_enterprise_feature_enabled: item(false),
    },
    shield: {
      shield_rules: [],
    },
  };
}

function user(id, overrides = {}) {
  return {
    id,
    type: "user",
    name: `User ${id}`,
    login: `${id}@example.com`,
    role: "user",
    status: "active",
    created_at: "2024-01-01T00:00:00Z",
    is_platform_access_only: false,
    is_exempt_from_login_verification: false,
    ...overrides,
  };
}

function loginEvent(userId, type = "LOGIN") {
  return { event_id: `${type}-${userId}`, event_type: type, created_at: "2026-09-10T00:00:00Z", created_by: { id: userId, type: "user" } };
}

function hardenedFixture() {
  const users = [
    user("admin-1", { role: "admin" }),
    user("member-1"),
    user("member-2"),
    user("app-user", { is_platform_access_only: true }),
  ];
  return {
    configuration: hardenedConfiguration(),
    users,
    events: [
      loginEvent("admin-1", "ADMIN_LOGIN"),
      loginEvent("member-1"),
      loginEvent("member-2", "DOWNLOAD"),
      { event_id: "shield-1", event_type: "SHIELD_ALERT", created_at: "2026-09-11T00:00:00Z", created_by: { id: "member-1", type: "user" } },
      { event_id: "share-1", event_type: "TERMS_OF_SERVICE_ACCEPT", created_at: "2026-09-11T00:00:00Z", created_by: { id: "member-2", type: "user" } },
    ],
    devicePinners: [{ id: "pin-1", type: "device_pinner", product_name: "iPhone" }],
    classificationTemplate: {
      id: "template-1",
      type: "metadata_template",
      templateKey: "securityClassification-6VMVochwUWo",
      fields: [{ key: "Box__Security__Classification__Key", options: [{ key: "Public" }, { key: "Internal" }, { key: "Confidential" }] }],
    },
    metadataTemplates: [{ id: "template-2", type: "metadata_template", templateKey: "contractMetadata" }],
    retentionPolicies: [{
      id: "retention-1",
      type: "retention_policy",
      policy_name: "Seven year records",
      policy_type: "finite",
      retention_length: "2555",
      disposition_action: "remove_retention",
      status: "active",
      assignment_counts: { enterprise: 0, folder: 2, metadata_template: 0 },
    }],
    retentionAssignments: [{ id: "assignment-1", type: "retention_policy_assignment" }],
    legalHoldPolicies: [{ id: "hold-1", type: "legal_hold_policy", policy_name: "Litigation 2026", status: "active", assignment_counts: { user: 2, folder: 0, file: 0, file_version: 0 } }],
    legalHoldAssignments: [{ id: "hold-assignment-1", type: "legal_hold_policy_assignment" }],
    barriers: [{ id: "barrier-1", type: "shield_information_barrier", status: "enabled" }],
    barrierSegments: [{ id: "segment-1", type: "shield_information_barrier_segment", name: "Research" }],
    shieldLists: [
      { id: "list-1", type: "shield_list", name: "Corporate egress", content: { type: "ip", ip_addresses: ["10.0.0.0/8"] } },
      { id: "list-2", type: "shield_list", name: "Approved integrations", content: { type: "integration", integrations: [{ id: "app-1" }] } },
    ],
    allowlistEntries: [{ id: "entry-1", type: "collaboration_whitelist_entry", domain: "partner.example", direction: "both", created_at: "2026-06-01T00:00:00Z" }],
    exemptTargets: [],
    termsOfServices: [{ id: "tos-1", type: "terms_of_service", status: "enabled", tos_type: "managed", modified_at: "2026-01-01T00:00:00Z" }],
    groups: [{ id: "group-1", type: "group", name: "Finance" }],
  };
}

function weakFixture() {
  const privileged = Array.from({ length: 11 }, (_, index) => user(`admin-${index}`, { role: "admin", is_exempt_from_login_verification: index === 0 }));
  return {
    ...hardenedFixture(),
    configuration: weakConfiguration(),
    users: [
      ...privileged,
      user("coadmin-1", { role: "coadmin" }),
      user("member-1"),
      user("member-2"),
      user("member-3"),
      user("member-4", { is_exempt_from_login_verification: true }),
    ],
    events: [],
    devicePinners: [],
    classificationTemplate: {},
    retentionPolicies: [],
    legalHoldPolicies: [],
    barriers: [],
    shieldLists: [],
    allowlistEntries: [
      { id: "entry-1", type: "collaboration_whitelist_entry", domain: "gmail.com", direction: "both", created_at: "2020-01-01T00:00:00Z" },
      { id: "entry-2", type: "collaboration_whitelist_entry", domain: "partner.example", direction: "inbound", created_at: "2020-01-01T00:00:00Z" },
    ],
    exemptTargets: [{ id: "exempt-1", type: "collaboration_whitelist_exempt_target", user: { id: "member-1", type: "user" } }],
    termsOfServices: [],
  };
}

function page(items, truncated = false) {
  return { items, truncated };
}

function truncatedList(items) {
  return async () => page(items, true);
}

function createStubClient(fixture, overrides = {}) {
  const filterEvents = (options = {}) => {
    const eventTypes = options.eventTypes;
    const filtered = eventTypes && eventTypes.length > 0
      ? fixture.events.filter((event) => eventTypes.includes(event.event_type))
      : fixture.events;
    return page(filtered.slice(0, options.limit ?? filtered.length));
  };
  return {
    getResolvedConfig: () => sampleConfig(),
    getNow: () => NOW,
    async getCurrentUser() {
      return { id: "service-1", type: "user", name: "Audit Service", login: "AutomationUser_123@boxdevedition.com", role: "admin", enterprise: { id: "123456", type: "enterprise" } };
    },
    async resolveEnterpriseId() {
      return "123456";
    },
    async getEnterpriseConfiguration() {
      return fixture.configuration;
    },
    async listUsers() {
      return page(fixture.users);
    },
    async listGroups() {
      return page(fixture.groups);
    },
    async listEnterpriseEvents(options) {
      return filterEvents(options);
    },
    async listDevicePinners() {
      return page(fixture.devicePinners);
    },
    async listRetentionPolicies() {
      return page(fixture.retentionPolicies);
    },
    async listRetentionPolicyAssignments() {
      return page(fixture.retentionAssignments);
    },
    async listLegalHoldPolicies() {
      return page(fixture.legalHoldPolicies);
    },
    async listLegalHoldPolicyAssignments() {
      return page(fixture.legalHoldAssignments);
    },
    async listShieldInformationBarriers() {
      return page(fixture.barriers);
    },
    async listShieldInformationBarrierSegments() {
      return page(fixture.barrierSegments);
    },
    async listShieldLists() {
      return page(fixture.shieldLists);
    },
    async listCollaborationAllowlistEntries() {
      return page(fixture.allowlistEntries);
    },
    async listCollaborationAllowlistExemptTargets() {
      return page(fixture.exemptTargets);
    },
    async listEnterpriseMetadataTemplates() {
      return page(fixture.metadataTemplates);
    },
    async getClassificationTemplate() {
      return fixture.classificationTemplate;
    },
    async listTermsOfServices() {
      return page(fixture.termsOfServices);
    },
    ...overrides,
  };
}

function forbidden(message = "Access denied") {
  return async () => {
    throw new BoxApiError(`Box request failed (403 Forbidden): ${message}`, 403, "access_denied_insufficient_permissions");
  };
}

function findingById(result, id) {
  const found = result.findings.find((entry) => entry.id === id);
  assert.ok(found, `expected finding ${id} in ${result.findings.map((entry) => entry.id).join(", ")}`);
  return found;
}

function assertStatuses(result, expected) {
  for (const [id, status] of Object.entries(expected)) {
    const found = findingById(result, id);
    assert.equal(found.status, status, `${id} should be ${status} but was ${found.status}: ${found.summary}`);
    if (status === "manual") {
      assert.ok(found.manualEvidence, `${id} manual finding must describe the evidence to collect`);
    }
  }
}

function assertMappings(result) {
  for (const entry of result.findings) {
    assert.equal(entry.mappings.length, FRAMEWORKS.length, `${entry.id} needs one mapping per framework`);
    FRAMEWORKS.forEach((framework, index) => {
      assert.ok(entry.mappings[index].startsWith(`${framework} `), `${entry.id} mapping ${index} should start with ${framework}`);
    });
    assert.ok(["critical", "high", "medium", "low", "info"].includes(entry.severity));
    assert.ok(["pass", "warn", "fail", "manual"].includes(entry.status));
    assert.equal(typeof entry.summary, "string");
  }
}

test("resolveBoxConfiguration prefers explicit args over environment and config file values", () => {
  const home = createTempBase("grclanker-box-home-");
  const configDir = join(home, ".box-sec-inspector");
  mkdirSync(configDir, { recursive: true });
  writeFileSync(join(configDir, "config.yaml"), [
    "box:",
    "  auth_method: ccg",
    "  client_id: file-client",
    "  client_secret: file-secret",
    "  enterprise_id: file-enterprise",
    "  timeout_seconds: 5",
    "",
  ].join("\n"));

  const fromFile = resolveBoxConfiguration({}, {}, { homeDir: home });
  assert.equal(fromFile.authMode, "ccg");
  assert.equal(fromFile.clientId, "file-client");
  assert.equal(fromFile.enterpriseId, "file-enterprise");
  assert.equal(fromFile.subjectId, "file-enterprise");
  assert.equal(fromFile.timeoutMs, 5000);
  assert.deepEqual(fromFile.sourceChain, ["home:.box-sec-inspector/config.yaml"]);

  const fromEnv = resolveBoxConfiguration({}, {
    BOX_CLIENT_ID: "env-client",
    BOX_CLIENT_SECRET: "env-secret",
    BOX_ENTERPRISE_ID: "env-enterprise",
  }, { homeDir: home });
  assert.equal(fromEnv.clientId, "env-client");
  assert.equal(fromEnv.clientSecret, "env-secret");
  assert.equal(fromEnv.enterpriseId, "env-enterprise");
  assert.equal(fromEnv.timeoutMs, 5000);
  assert.deepEqual(fromEnv.sourceChain, ["home:.box-sec-inspector/config.yaml", "environment"]);

  const fromArgs = resolveBoxConfiguration({
    client_id: "arg-client",
    client_secret: "arg-secret",
    enterprise_id: "arg-enterprise",
    base_url: "https://api.box.example/2.0/",
    timeout_seconds: 9,
    max_retries: 1,
  }, {
    BOX_CLIENT_ID: "env-client",
    BOX_CLIENT_SECRET: "env-secret",
    BOX_ENTERPRISE_ID: "env-enterprise",
  }, { homeDir: home });
  assert.equal(fromArgs.clientId, "arg-client");
  assert.equal(fromArgs.clientSecret, "arg-secret");
  assert.equal(fromArgs.enterpriseId, "arg-enterprise");
  assert.equal(fromArgs.baseUrl, "https://api.box.example/2.0");
  assert.equal(fromArgs.tokenUrl, "https://api.box.com/oauth2/token");
  assert.equal(fromArgs.timeoutMs, 9000);
  assert.equal(fromArgs.maxRetries, 1);
  assert.deepEqual(fromArgs.sourceChain, ["home:.box-sec-inspector/config.yaml", "environment", "arguments"]);
});

test("resolveBoxConfiguration supports JWT config files, CCG env vars, OAuth tokens, and explicit config paths", () => {
  const base = createTempBase("grclanker-box-config-");
  const { pathname } = generateJwtConfig(base);

  const jwt = resolveBoxConfiguration({}, { BOX_JWT_CONFIG_PATH: pathname }, { homeDir: base });
  assert.equal(jwt.authMode, "jwt");
  assert.equal(jwt.clientId, "jwt-client-id");
  assert.equal(jwt.clientSecret, "jwt-client-secret");
  assert.equal(jwt.enterpriseId, "987654");
  assert.equal(jwt.subjectType, "enterprise");
  assert.equal(jwt.subjectId, "987654");
  assert.equal(jwt.jwt.publicKeyId, "kid-1234");
  assert.equal(jwt.jwt.algorithm, "RS512");
  assert.match(jwt.jwt.privateKey, /BEGIN PRIVATE KEY/);
  assert.ok(jwt.sourceChain.includes("jwt-config-file"));

  const jwtUser = resolveBoxConfiguration({ subject_type: "user", subject_id: "11111" }, { BOX_JWT_CONFIG_PATH: pathname, BOX_JWT_ALGORITHM: "RS256" }, { homeDir: base });
  assert.equal(jwtUser.subjectType, "user");
  assert.equal(jwtUser.subjectId, "11111");
  assert.equal(jwtUser.jwt.algorithm, "RS256");

  const ccg = resolveBoxConfiguration({}, {
    BOX_CLIENT_ID: "ccg-client",
    BOX_CLIENT_SECRET: "ccg-secret",
    BOX_ENTERPRISE_ID: "555",
  }, { homeDir: base });
  assert.equal(ccg.authMode, "ccg");
  assert.equal(ccg.subjectId, "555");
  assert.deepEqual(ccg.sourceChain, ["environment"]);

  const oauth = resolveBoxConfiguration({}, { BOX_ACCESS_TOKEN: "developer-token-value" }, { homeDir: base });
  assert.equal(oauth.authMode, "oauth");
  assert.equal(oauth.accessToken, "developer-token-value");
  assert.equal(oauth.enterpriseId, undefined);

  const explicitConfig = join(base, "custom.yaml");
  writeFileSync(explicitConfig, "auth_method: oauth\naccess_token: file-token\nbase_url: https://api.box.example/2.0\n");
  const explicit = resolveBoxConfiguration({ config_path: explicitConfig }, {}, { homeDir: base, cwd: base });
  assert.equal(explicit.authMode, "oauth");
  assert.equal(explicit.accessToken, "file-token");
  assert.equal(explicit.baseUrl, "https://api.box.example/2.0");
  assert.deepEqual(explicit.sourceChain, ["config:custom.yaml"]);

  assert.throws(() => resolveBoxConfiguration({}, {}, { homeDir: base }), /Box credentials are required/);
  assert.throws(() => resolveBoxConfiguration({}, { BOX_CLIENT_ID: "only-client", BOX_CLIENT_SECRET: "only-secret", BOX_AUTH_METHOD: "ccg" }, { homeDir: base }), /BOX_ENTERPRISE_ID/);
  assert.throws(() => resolveBoxConfiguration({ auth_method: "saml" }, {}, { homeDir: base }), /Unsupported Box auth method/);
  assert.throws(
    () => resolveBoxConfiguration({ config_path: join(base, "missing.yaml") }, {}, { homeDir: base, cwd: base }),
    (error) => error.name === "BoxConfigFileError" && error.code === "ENOENT" && /^Unable to read Box config file .*missing\.yaml \(ENOENT\)$/.test(error.message),
  );
});

test("BoxApiClient signs a JWT assertion, exchanges it for a token, and calls the API", async () => {
  const base = createTempBase("grclanker-box-jwt-");
  const { pathname, publicKey } = generateJwtConfig(base);
  const config = resolveBoxConfiguration({}, { BOX_JWT_CONFIG_PATH: pathname }, { homeDir: base });
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({ url, method: init.method ?? "GET", body: init.body, auth: headerValue(init.headers, "authorization") });
    if (url.pathname === "/oauth2/token") {
      return jsonResponse({ access_token: "jwt-access-token", expires_in: 3600, token_type: "bearer" });
    }
    return jsonResponse({ id: "service-1", type: "user", login: "AutomationUser@boxdevedition.com", enterprise: { id: "987654", type: "enterprise" } });
  };

  const client = new BoxApiClient(config, { fetchImpl, now: () => NOW });
  const me = await client.getCurrentUser();
  assert.equal(me.id, "service-1");
  assert.equal(await client.resolveEnterpriseId(), "987654");

  const tokenCall = seen[0];
  assert.equal(tokenCall.url.toString(), "https://api.box.com/oauth2/token");
  assert.equal(tokenCall.method, "POST");
  const body = new URLSearchParams(tokenCall.body);
  assert.equal(body.get("grant_type"), "urn:ietf:params:oauth:grant-type:jwt-bearer");
  assert.equal(body.get("client_id"), "jwt-client-id");
  assert.equal(body.get("client_secret"), "jwt-client-secret");

  const [headerSegment, claimsSegment, signatureSegment] = body.get("assertion").split(".");
  const header = decodeSegment(headerSegment);
  const claims = decodeSegment(claimsSegment);
  assert.equal(header.alg, "RS512");
  assert.equal(header.typ, "JWT");
  assert.equal(header.kid, "kid-1234");
  assert.equal(claims.iss, "jwt-client-id");
  assert.equal(claims.sub, "987654");
  assert.equal(claims.box_sub_type, "enterprise");
  assert.equal(claims.aud, "https://api.box.com/oauth2/token");
  assert.equal(claims.exp - claims.iat, 45);
  assert.equal(claims.iat, Math.floor(NOW.getTime() / 1000));
  assert.match(claims.jti, /^[a-f0-9]{64}$/);
  const verifier = createVerify("RSA-SHA512");
  verifier.update(`${headerSegment}.${claimsSegment}`);
  const signature = Buffer.from(signatureSegment.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  assert.equal(verifier.verify(publicKey, signature), true);

  const apiCall = seen[1];
  assert.equal(apiCall.url.pathname, "/2.0/users/me");
  assert.equal(apiCall.auth, "Bearer jwt-access-token");
  assert.equal(seen.length, 2, "current user lookups should be memoized");

  const direct = buildBoxJwtAssertion({
    clientId: "jwt-client-id",
    subjectId: "42",
    subjectType: "user",
    credentials: { ...config.jwt, algorithm: "RS256" },
    now: NOW,
  });
  assert.equal(decodeSegment(direct.split(".")[0]).alg, "RS256");
  assert.equal(decodeSegment(direct.split(".")[1]).box_sub_type, "user");
  assert.equal(decodeSegment(direct.split(".")[1]).aud, "https://api.box.com/oauth2/token");
});

test("BoxApiClient uses the configured token URL as the JWT audience", async () => {
  const base = createTempBase("grclanker-box-jwt-aud-");
  const { pathname } = generateJwtConfig(base);
  const tokenUrl = "https://api.box.example/oauth2/token";
  const config = resolveBoxConfiguration({}, { BOX_JWT_CONFIG_PATH: pathname, BOX_TOKEN_URL: tokenUrl }, { homeDir: base });
  assert.equal(config.tokenUrl, tokenUrl);
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({ url, body: init.body });
    if (url.pathname === "/oauth2/token") {
      return jsonResponse({ access_token: "jwt-access-token", expires_in: 3600, token_type: "bearer" });
    }
    return jsonResponse({ id: "service-1", type: "user" });
  };

  const client = new BoxApiClient(config, { fetchImpl, now: () => NOW });
  await client.getCurrentUser();

  assert.equal(seen[0].url.toString(), tokenUrl);
  const claims = decodeSegment(new URLSearchParams(seen[0].body).get("assertion").split(".")[1]);
  assert.equal(claims.aud, tokenUrl);
  assert.equal(claims.iss, "jwt-client-id");
});

test("BoxApiClient exchanges Client Credentials Grant and paginates users with markers", async () => {
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({ pathname: url.pathname, params: url.searchParams, method: init.method ?? "GET", body: init.body, auth: headerValue(init.headers, "authorization") });
    if (url.pathname === "/oauth2/token") {
      return jsonResponse({ access_token: "ccg-access-token", expires_in: 4103 });
    }
    if (url.pathname === "/2.0/users") {
      const marker = url.searchParams.get("marker");
      if (!marker) return jsonResponse({ entries: [{ id: "user-1", type: "user" }, { id: "user-2", type: "user" }], next_marker: "marker-2", limit: 2 });
      if (marker === "marker-2") return jsonResponse({ entries: [{ id: "user-3", type: "user" }], next_marker: "marker-3", limit: 2 });
      return jsonResponse({ entries: [{ id: "user-4", type: "user" }], next_marker: null });
    }
    if (url.pathname === "/2.0/groups") {
      const offset = Number(url.searchParams.get("offset") ?? "0");
      return offset === 0
        ? jsonResponse({ entries: [{ id: "group-1", type: "group" }], total_count: 2, offset: 0, limit: 1 })
        : jsonResponse({ entries: [{ id: "group-2", type: "group" }], total_count: 2, offset: 1, limit: 1 });
    }
    if (url.pathname === "/2.0/events") {
      const position = url.searchParams.get("stream_position");
      return position
        ? jsonResponse({ entries: [{ event_id: "e-2", event_type: "LOGIN" }], next_stream_position: position, chunk_size: 1 })
        : jsonResponse({ entries: [{ event_id: "e-1", event_type: "LOGIN" }], next_stream_position: "1152922976252290800", chunk_size: 1 });
    }
    return jsonResponse({}, { status: 404 });
  };

  const client = new BoxApiClient(resolveBoxConfiguration({
    client_id: "ccg-client",
    client_secret: "ccg-secret",
    enterprise_id: "123456",
  }, {}, { homeDir: createTempBase("grclanker-box-ccg-") }), { fetchImpl, now: () => NOW });

  const users = await client.listUsers(3);
  assert.deepEqual(users.items.map((entry) => entry.id), ["user-1", "user-2", "user-3"]);
  assert.equal(users.truncated, true, "a next_marker remained after the cap, so the list is partial");

  const tokenBody = new URLSearchParams(seen[0].body);
  assert.equal(seen[0].pathname, "/oauth2/token");
  assert.equal(tokenBody.get("grant_type"), "client_credentials");
  assert.equal(tokenBody.get("client_id"), "ccg-client");
  assert.equal(tokenBody.get("client_secret"), "ccg-secret");
  assert.equal(tokenBody.get("box_subject_type"), "enterprise");
  assert.equal(tokenBody.get("box_subject_id"), "123456");

  const userCalls = seen.filter((call) => call.pathname === "/2.0/users");
  assert.equal(userCalls.length, 2);
  assert.equal(userCalls[0].auth, "Bearer ccg-access-token");
  assert.equal(userCalls[0].params.get("usemarker"), "true");
  assert.equal(userCalls[0].params.get("limit"), "3");
  assert.equal(userCalls[0].params.get("marker"), null);
  assert.match(userCalls[0].params.get("fields"), /is_exempt_from_login_verification/);
  assert.equal(userCalls[1].params.get("marker"), "marker-2");
  assert.equal(userCalls[1].params.get("limit"), "1");

  const groups = await client.listGroups(5);
  assert.deepEqual(groups.items.map((entry) => entry.id), ["group-1", "group-2"]);
  assert.equal(groups.truncated, false, "offset paging reached total_count");

  const events = await client.listEnterpriseEvents({ eventTypes: ["LOGIN"], createdAfter: NOW, limit: 5 });
  assert.deepEqual(events.items.map((entry) => entry.event_id), ["e-1", "e-2"]);
  assert.equal(events.truncated, true, "a stream position that stops advancing while entries keep arriving cannot be drained, so the sample is partial");
  const eventCalls = seen.filter((call) => call.pathname === "/2.0/events");
  assert.equal(eventCalls[0].params.get("stream_type"), "admin_logs");
  assert.equal(eventCalls[0].params.get("event_type"), "LOGIN");
  assert.equal(eventCalls[0].params.get("created_after"), NOW.toISOString());
  assert.equal(eventCalls[1].params.get("stream_position"), "1152922976252290800");
  assert.equal(seen.filter((call) => call.pathname === "/oauth2/token").length, 1, "token should be cached across calls");
});

test("foreign-origin next link: a URL-shaped Box next_marker or next_stream_position is an opaque value appended to the configured base, so no request leaves for the origin it names", async () => {
  const FOREIGN = "https://collector.attacker.example/2.0/users?marker=stolen";
  const requests = [];
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    requests.push({ origin: url.origin, pathname: url.pathname, params: url.searchParams });
    if (url.pathname === "/oauth2/token") return jsonResponse({ access_token: "ccg-access-token", expires_in: 4103 });
    if (url.pathname === "/2.0/users") {
      return url.searchParams.get("marker")
        ? jsonResponse({ entries: [{ id: "user-2", type: "user" }], next_marker: null })
        : jsonResponse({ entries: [{ id: "user-1", type: "user" }], next_marker: FOREIGN, limit: 1 });
    }
    if (url.pathname === "/2.0/events") {
      return url.searchParams.get("stream_position")
        ? jsonResponse({ entries: [], next_stream_position: url.searchParams.get("stream_position"), chunk_size: 0 })
        : jsonResponse({ entries: [{ event_id: "e-1", event_type: "LOGIN" }], next_stream_position: FOREIGN, chunk_size: 1 });
    }
    return jsonResponse({}, { status: 404 });
  };
  const client = new BoxApiClient(resolveBoxConfiguration({
    client_id: "ccg-client",
    client_secret: "ccg-secret",
    enterprise_id: "123456",
  }, {}, { homeDir: createTempBase("grclanker-box-next-link-") }), { fetchImpl, now: () => NOW });

  const users = await client.listUsers(10);
  assert.deepEqual(users.items.map((entry) => entry.id), ["user-1", "user-2"], "paging continued through the planted marker");
  const events = await client.listEnterpriseEvents({ eventTypes: ["LOGIN"], createdAfter: NOW, limit: 5 });
  assert.deepEqual(events.items.map((entry) => entry.event_id), ["e-1"]);

  assert.ok(requests.length >= 5, "token, two user pages, and two event pages were requested");
  assert.ok(requests.every((request) => request.origin === "https://api.box.com"), "every request, including the ones that carried the planted values, went to the configured origin");
  const userCalls = requests.filter((request) => request.pathname === "/2.0/users");
  assert.equal(userCalls.length, 2);
  assert.equal(userCalls[1].params.get("marker"), FOREIGN, "the marker travels only as a query parameter value on the configured base");
  const eventCalls = requests.filter((request) => request.pathname === "/2.0/events");
  assert.equal(eventCalls.length, 2);
  assert.equal(eventCalls[1].params.get("stream_position"), FOREIGN, "the stream position travels only as a query parameter value on the configured base");
});

test("BoxApiClient reports list truncation only when a marker, offset, or stream position remains past the cap", async () => {
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.pathname === "/2.0/users") {
      const marker = url.searchParams.get("marker");
      if (!marker) return jsonResponse({ entries: [{ id: "user-1", type: "user" }, { id: "user-2", type: "user" }], next_marker: "marker-2" });
      return jsonResponse({ entries: [{ id: "user-3", type: "user" }], next_marker: null });
    }
    if (url.pathname === "/2.0/collaboration_whitelist_entries") {
      return jsonResponse({ entries: [{ id: "entry-1", type: "collaboration_whitelist_entry" }], next_marker: "" });
    }
    if (url.pathname === "/2.0/groups") {
      const offset = Number(url.searchParams.get("offset") ?? "0");
      return jsonResponse({ entries: [{ id: `group-${offset + 1}`, type: "group" }], total_count: 3, offset, limit: 1 });
    }
    if (url.pathname === "/2.0/events") {
      const position = url.searchParams.get("stream_position");
      const limit = Number(url.searchParams.get("limit"));
      const start = position ? Number(position) : 0;
      const entries = Array.from({ length: limit }, (_, index) => ({ event_id: `e-${start + index + 1}`, event_type: "LOGIN" }));
      return jsonResponse({ entries, next_stream_position: String(start + limit), chunk_size: entries.length });
    }
    return jsonResponse({}, { status: 404 });
  };
  const client = new BoxApiClient(sampleConfig({ authMode: "oauth", accessToken: "oauth-fixture-access-2026", clientId: undefined, clientSecret: undefined }), { fetchImpl, now: () => NOW });

  const complete = await client.listUsers(10);
  assert.deepEqual(complete.items.map((entry) => entry.id), ["user-1", "user-2", "user-3"]);
  assert.equal(complete.truncated, false, "the final page carried no next_marker");
  assert.equal(complete.truncation, undefined);

  const partial = await client.listUsers(2);
  assert.deepEqual(partial.items.map((entry) => entry.id), ["user-1", "user-2"]);
  assert.equal(partial.truncated, true, "exactly the cap was returned and a next_marker remained");
  assert.deepEqual(partial.truncation, { reason: "the 2-record cap was reached while the server offered a next marker", capReached: true });

  const fullPageWithoutMarker = await client.listCollaborationAllowlistEntries(1);
  assert.equal(fullPageWithoutMarker.items.length, 1);
  assert.equal(fullPageWithoutMarker.truncated, true, "a full last page at the cap with no next_marker cannot prove the remainder empty");
  assert.deepEqual(fullPageWithoutMarker.truncation, { reason: "the last page was full at the 1-record cap and the server gave no next marker, so the remainder is unknown", capReached: true });

  const emptyMarker = await client.listCollaborationAllowlistEntries(2);
  assert.equal(emptyMarker.items.length, 1);
  assert.equal(emptyMarker.truncated, false, "an empty next_marker on a page below the cap means the list is complete");
  assert.equal(emptyMarker.truncation, undefined);

  const groups = await client.listGroups(2);
  assert.deepEqual(groups.items.map((entry) => entry.id), ["group-1", "group-2"]);
  assert.equal(groups.truncated, true, "offset paging stopped before total_count");
  assert.deepEqual(groups.truncation, { reason: "the 2-record cap was reached while the server reported 3 records in total", capReached: true });

  const events = await client.listEnterpriseEvents({ limit: 3 });
  assert.equal(events.items.length, 3);
  assert.equal(events.truncated, true, "the cap filled while a fresh next_stream_position remained");
  assert.deepEqual(events.truncation, { reason: "the 3-event cap was reached while the server offered a next stream position", capReached: true });
});

test("verdict rule 10: every Box pagination exit that leaves records behind reports truncated", async () => {
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.pathname === "/2.0/users") {
      const marker = url.searchParams.get("marker");
      if (!marker) return jsonResponse({ entries: [{ id: "user-1", type: "user" }], next_marker: "marker-2" });
      return jsonResponse({ entries: [], next_marker: "marker-3" });
    }
    if (url.pathname === "/2.0/groups") {
      const offset = Number(url.searchParams.get("offset") ?? "0");
      if (offset === 0) return jsonResponse({ entries: [{ id: "group-1", type: "group" }], total_count: 5, offset, limit: 1 });
      return jsonResponse({ entries: [], total_count: 5, offset, limit: 1 });
    }
    if (url.pathname === "/2.0/events") {
      const kind = url.searchParams.get("event_type");
      const position = url.searchParams.get("stream_position");
      if (kind === "LOGIN") {
        return jsonResponse({ entries: [{ event_id: `e-${position ?? "0"}`, event_type: "LOGIN" }], next_stream_position: "stuck" });
      }
      if (kind === "SHIELD_ALERT") {
        return jsonResponse({ entries: [{ event_id: "alert-1", event_type: "SHIELD_ALERT" }, { event_id: "alert-2", event_type: "SHIELD_ALERT" }], next_stream_position: "same" });
      }
      return jsonResponse({ entries: [{ event_id: "e-1", event_type: "DOWNLOAD" }] });
    }
    if (url.pathname === "/2.0/retention_policies") {
      return jsonResponse({ entries: Array.from({ length: 60 }, (_, index) => ({ id: `policy-${index}`, type: "retention_policy", status: "active", assignment_counts: { folder: 1 } })), next_marker: null });
    }
    if (/^\/2\.0\/retention_policies\/[^/]+\/assignments$/.test(url.pathname)) {
      return jsonResponse({ entries: [{ id: `assignment-${url.pathname.split("/")[3]}`, type: "retention_policy_assignment" }], next_marker: null });
    }
    if (url.pathname === "/2.0/legal_hold_policies") return jsonResponse({ entries: [], next_marker: null });
    if (url.pathname === "/2.0/metadata_templates/enterprise") return jsonResponse({ entries: [], next_marker: null });
    if (url.pathname.startsWith("/2.0/enterprises/")) return jsonResponse({ entries: [], next_marker: null });
    if (url.pathname.startsWith("/2.0/metadata_templates/enterprise/")) return jsonResponse({ fields: [] });
    if (url.pathname.startsWith("/2.0/enterprise_configurations/")) return jsonResponse(hardenedConfiguration());
    return jsonResponse({}, { status: 404 });
  };
  const client = new BoxApiClient(sampleConfig({ authMode: "oauth", accessToken: "oauth-fixture-access-2026", clientId: undefined, clientSecret: undefined }), { fetchImpl, now: () => NOW });

  const emptyPageWithMarker = await client.listUsers(10);
  assert.deepEqual(emptyPageWithMarker.items.map((entry) => entry.id), ["user-1"]);
  assert.equal(emptyPageWithMarker.truncated, true, "an empty marker page that still carries next_marker is a partial inventory");
  assert.deepEqual(emptyPageWithMarker.truncation, { reason: "the server returned an empty page while still offering a next marker", capReached: false });

  const emptyPageBelowTotal = await client.listGroups(10);
  assert.deepEqual(emptyPageBelowTotal.items.map((entry) => entry.id), ["group-1"]);
  assert.equal(emptyPageBelowTotal.truncated, true, "an empty offset page while offset < total_count is a partial inventory");
  assert.deepEqual(emptyPageBelowTotal.truncation, { reason: "the server returned an empty page while the server reported 5 records in total", capReached: false });

  const stuckPosition = await client.listEnterpriseEvents({ eventTypes: ["LOGIN"], limit: 10 });
  assert.equal(stuckPosition.items.length, 2);
  assert.equal(stuckPosition.truncated, true, "a next_stream_position that stops advancing while entries keep arriving is a partial inventory");
  assert.deepEqual(stuckPosition.truncation, { reason: "the server repeated its stream position, so the remaining events could not be paged", capReached: false });

  const repeatedPage = await client.listEnterpriseEvents({ eventTypes: ["SHIELD_ALERT"], limit: 10 });
  assert.deepEqual(repeatedPage.items.map((event) => event.event_id), ["alert-1", "alert-2"], "a page re-served under a repeated stream position is counted once");
  assert.equal(repeatedPage.truncated, true);
  assert.deepEqual(repeatedPage.truncation, { reason: "the server repeated its stream position, so the remaining events could not be paged", capReached: false });

  const missingPosition = await client.listEnterpriseEvents({ eventTypes: ["DOWNLOAD"], limit: 10 });
  assert.equal(missingPosition.items.length, 1);
  assert.equal(missingPosition.truncated, true, "a non-empty page without next_stream_position cannot be continued");
  assert.deepEqual(missingPosition.truncation, { reason: "the server returned a page without a next stream position, so the remainder is unknown", capReached: false });

  const governance = await assessBoxDataGovernance(client, { listLimit: 100 });
  const cap = governance.truncated.find((note) => note.startsWith("retention_policy_assignments:"));
  assert.ok(cap, `the 50-policy assignment cap must be recorded, got ${JSON.stringify(governance.truncated)}`);
  assert.equal(cap, "retention_policy_assignments: collection stopped after 50 records because only the first 50 of 60 policies had their assignments read, a fixed cap; review the remainder in the Admin Console before treating absence as compliance");
  assert.doesNotMatch(cap, /raise list_limit/, "list_limit does not raise the fixed policy cap, so the note must not advise it");
  assert.equal(findingById(governance, "BOX-12").status, "pass", "assignment presence is still proven for the 50 policies that were read");

  const usersCaveat = await assessBoxIdentityAccess(client, { userLimit: 10 });
  assert.match(findingById(usersCaveat, "BOX-02").summary, /the user list stopped after 1 records because the server returned an empty page while still offering a next marker, so the inventory is partial/);
  assert.match(findingById(usersCaveat, "BOX-02").summary, /review the remainder in the Admin Console/);
  assert.doesNotMatch(findingById(usersCaveat, "BOX-02").summary, /raise user_limit/, "a higher user_limit does not read past a server that serves empty pages");
  assert.equal(usersCaveat.truncated.find((note) => note.startsWith("users:")), "users: collection stopped after 1 records because the server returned an empty page while still offering a next marker; review the remainder in the Admin Console before treating absence as compliance");
});

const RESERVED_EVENTS_REASON = "the server re-served already-collected events under a new stream position, so the remaining events could not be paged";

/** Every page answers with the same event under a fresh stream position (pos-1, pos-2, ...). */
function reservedEventsRoute(url) {
  const position = url.searchParams.get("stream_position");
  const next = position === null ? "pos-1" : `pos-${Number(position.slice(4)) + 1}`;
  return jsonResponse({ entries: [{ event_id: "e-1", event_type: "LOGIN", created_at: "2026-09-11T00:00:00Z", created_by: { id: "member-1", type: "user" } }], next_stream_position: next, chunk_size: 1 });
}

test("verdict rule 10 (gap 37): the events walk ends after the first page that adds no unseen event under a fresh stream position, a trickle of one new event per page ends at the page cap, and the bundle rows carry the reason", async () => {
  const positions = [];
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.url);
    if (url.pathname !== "/2.0/events") return jsonResponse({}, { status: 404 });
    positions.push(url.searchParams.get("stream_position"));
    if (url.searchParams.get("event_type") === "LOGIN") return reservedEventsRoute(url);
    // One never-seen event per page with a fresh position every time: the event cap is never reached from a trickle.
    const index = Number(url.searchParams.get("stream_position") ?? "0");
    return jsonResponse({ entries: [{ event_id: `fresh-${index}`, event_type: "DOWNLOAD" }], next_stream_position: String(index + 1), chunk_size: 1 });
  };
  const client = new BoxApiClient(sampleConfig({ authMode: "oauth", accessToken: "oauth-fixture-access-2026", clientId: undefined, clientSecret: undefined }), { fetchImpl, now: () => NOW });

  const reserved = await client.listEnterpriseEvents({ eventTypes: ["LOGIN"], limit: 10 });
  assert.deepEqual(positions, [null, "pos-1"], "the second page re-serves the collected event, so no third request is made");
  assert.deepEqual(reserved.items.map((event) => event.event_id), ["e-1"]);
  assert.equal(reserved.truncated, true);
  assert.deepEqual(reserved.truncation, { reason: RESERVED_EVENTS_REASON, capReached: false });

  positions.length = 0;
  const trickle = await client.listEnterpriseEvents({ eventTypes: ["DOWNLOAD"], limit: 100 });
  assert.equal(positions.length, 8, "a 100-event limit needs one 500-event page, so the walk is bounded at 4 pages per page needed plus 4");
  assert.deepEqual(trickle.items.map((event) => event.event_id), Array.from({ length: 8 }, (_, index) => `fresh-${index}`));
  assert.equal(trickle.truncated, true);
  assert.deepEqual(trickle.truncation, { reason: "the 8-page cap was reached with 8 of 100 events collected, so the remaining events could not be paged", capReached: true });

  // End to end over the routed client: each of the three event walks stops after two requests and every events row
  // in collection_status carries the reason, so the export completes against a server that never stops paging.
  const routed = httpBox(hardenedFixture(), { routes: { "GET /2.0/events": reservedEventsRoute } });
  const exported = await exportBoxAuditBundle(routed.client, routed.config, createTempBase("grclanker-box-reserved-events-"));
  const eventRequests = routed.log.filter((entry) => entry.path === "/2.0/events");
  // A walk is one event-type filter and lookback; its page size shrinks with the remainder, so it is not part of the key.
  const walks = new Set(eventRequests.map((entry) => {
    const url = new URL(entry.url);
    return `${url.searchParams.get("event_type")} ${url.searchParams.get("created_after")}`;
  }));
  assert.ok(walks.size >= 1, "the export walks the events stream at least once");
  assert.equal(eventRequests.length, walks.size * 2, `every events walk made exactly two requests: ${eventRequests.map((entry) => entry.url).join(" ")}`);
  const status = JSON.parse(readFileSync(join(exported.outputDir, "core_data/collection_status.json"), "utf8"));
  for (const file of ["core_data/enterprise_events_activity.json", "core_data/enterprise_events_sharing.json", "core_data/enterprise_events_shield.json"]) {
    const row = status.datasets.find((entry) => entry.file === file);
    assert.equal(row.truncated, true, `${file} is recorded truncated`);
    assert.equal(row.truncation_reason, RESERVED_EVENTS_REASON, `${file} carries the reason`);
  }
  assert.ok(status.truncated_datasets.some((note) => note.includes(RESERVED_EVENTS_REASON) && note.includes("review the remainder in the Admin Console")), `the truncation notes name the exit and do not advise raising event_limit: ${JSON.stringify(status.truncated_datasets)}`);
  assert.ok(!status.truncated_datasets.some((note) => note.includes(RESERVED_EVENTS_REASON) && note.includes("raise event_limit")));
});

const RESERVED_RECORDS_REASON = "the server re-served already-collected records under a new marker, so the remaining records could not be paged";
const EMPTY_MARKER_PAGE_REASON = "the server returned an empty page while still offering a next marker";

/** Every page answers with the same records under a fresh marker (m-1, m-2, ...): a marker list that never ends. */
function fullForeverRoute(entries) {
  return (url) => {
    const marker = url.searchParams.get("marker");
    const next = marker === null ? "m-1" : `m-${Number(marker.slice(2)) + 1}`;
    return jsonResponse({ entries, limit: entries.length, next_marker: next });
  };
}

const ASSIGNED_RETENTION_POLICY = { id: "retention-1", type: "retention_policy", policy_name: "Seven year records", policy_type: "finite", retention_length: "2555", disposition_action: "remove_retention", status: "active", assignment_counts: { enterprise: 0, folder: 2, metadata_template: 0 } };
const ASSIGNED_LEGAL_HOLD = { id: "hold-1", type: "legal_hold_policy", policy_name: "Litigation 2026", status: "active", assignment_counts: { user: 2, folder: 0, file: 0, file_version: 0 } };

test("gap 41: a marker list counts a record once by id, ends after a page that adds no unseen record or repeats its marker, and still completes over overlapping pages", async () => {
  const markers = [];
  const routed = httpBox(hardenedFixture(), {
    routes: {
      "GET /2.0/retention_policies": (url) => {
        markers.push(url.searchParams.get("marker"));
        return fullForeverRoute([ASSIGNED_RETENTION_POLICY])(url);
      },
      // New records on every page, but the same marker every time.
      "GET /2.0/legal_hold_policies": (url) => {
        const marker = url.searchParams.get("marker");
        const index = marker === null ? 0 : 1;
        return jsonResponse({ entries: [{ ...ASSIGNED_LEGAL_HOLD, id: `hold-${index + 1}` }], limit: 1, next_marker: "same" });
      },
      // Overlapping pages: the last record of one page opens the next; the server ends the list itself.
      "GET /2.0/enterprises/{enterprise}/device_pinners": (url) => {
        const marker = url.searchParams.get("marker");
        if (marker === null) return jsonResponse({ entries: [{ id: "pin-1", type: "device_pinner" }, { id: "pin-2", type: "device_pinner" }], limit: 2, next_marker: "p-2" });
        return jsonResponse({ entries: [{ id: "pin-2", type: "device_pinner" }, { id: "pin-3", type: "device_pinner" }], limit: 2 });
      },
    },
  });

  const reserved = await routed.client.listRetentionPolicies(100);
  assert.deepEqual(markers, [null, "m-1"], "the second page re-serves the collected policy, so no third request is made");
  assert.deepEqual(reserved.items.map((policy) => policy.id), ["retention-1"], "a re-served record is counted once");
  assert.equal(reserved.truncated, true);
  assert.deepEqual(reserved.truncation, { reason: RESERVED_RECORDS_REASON, capReached: false });

  const repeatedMarker = await routed.client.listLegalHoldPolicies(100);
  assert.deepEqual(repeatedMarker.items.map((policy) => policy.id), ["hold-1", "hold-2"], "the page served under the repeated marker is kept, then the walk ends");
  assert.equal(repeatedMarker.truncated, true);
  assert.deepEqual(repeatedMarker.truncation, { reason: "the server repeated its marker, so the remaining records could not be paged", capReached: false });

  const overlapping = await routed.client.listDevicePinners(100);
  assert.deepEqual(overlapping.items.map((pin) => pin.id), ["pin-1", "pin-2", "pin-3"], "a record served on two pages is counted once and the walk continues");
  assert.equal(overlapping.truncated, false, "the server ended the list itself, so an overlap is not a truncation");
  assert.equal(overlapping.truncation, undefined);

  // The governance findings over the same server: a re-served policy list is a truncated read, so the universal claim
  // over the policies read is a warn that carries the listing's own exit, the counts do not exceed the distinct ids and
  // are lower bounds, and the policy records are withheld until the listing is read to completion.
  const governance = await assessBoxDataGovernance(routed.client, { listLimit: 100 });
  const retention = findingById(governance, "BOX-12");
  assert.equal(retention.status, "warn", "every policy read has assignments, but the total behind the stop is unknown");
  assert.equal(retention.summary, `1/1 active retention policies have assignments among the 1 policies read, but the retention policy listing stopped after 1 records because ${RESERVED_RECORDS_REASON}; the total number of policies is unknown and the policies beyond the stop were not assessed, so the assignment coverage holds only for the policies read and both counts are lower bounds; review the remainder in the Admin Console.`);
  assert.doesNotMatch(retention.summary, /raise list_limit/, "a higher list_limit does not read past a server that re-serves records");
  assert.equal(retention.evidence.retention_policies_truncated, true);
  assert.equal(retention.evidence.policies_read, 1, "the read's own size counts the distinct policy once");
  assert.equal(retention.evidence.active_policies, 1);
  assert.equal(retention.evidence.assigned_policies, 1);
  assert.equal(retention.evidence.retention_policies, null, "policy records are withheld while the listing is truncated");
  assert.equal(governance.summary.retention_policies, 1, "the summary count does not exceed the distinct ids");
  assert.equal(governance.summary.retention_policies_truncated, true);
  const hold = findingById(governance, "BOX-13");
  assert.equal(hold.status, "warn");
  assert.equal(hold.summary, "2/2 active legal hold policies have custodian or content assignments among the 2 policies read, but the legal hold policy listing stopped after 2 records because the server repeated its marker, so the remaining records could not be paged; the total number of policies is unknown and the policies beyond the stop were not assessed, so the assignment coverage holds only for the policies read and both counts are lower bounds; review the remainder in the Admin Console.");
  assert.equal(hold.evidence.legal_hold_policies_truncated, true);
  assert.equal(hold.evidence.legal_hold_policies, null);
  assert.equal(hold.evidence.policies_read, 2);
  assert.equal(governance.summary.legal_hold_policies, 2);
  assert.ok(governance.truncated.some((note) => note.startsWith("retention_policies: ") && note.includes(RESERVED_RECORDS_REASON)), JSON.stringify(governance.truncated));
  assert.ok(governance.truncated.some((note) => note.startsWith("legal_hold_policies: ") && note.includes("repeated its marker")), JSON.stringify(governance.truncated));
});

test("gap 41: BOX-12 and BOX-13 test the listing's truncation before the empty branch, so an empty or inactive page under a next_marker never reads as absence", async () => {
  // Empty first pages that still offer a next marker: nothing was read, and nothing is asserted absent.
  const emptyPages = httpBox(hardenedFixture(), {
    routes: {
      "GET /2.0/retention_policies": () => jsonResponse({ entries: [], limit: 100, next_marker: "later" }),
      "GET /2.0/legal_hold_policies": () => jsonResponse({ entries: [], limit: 100, next_marker: "later" }),
    },
  });
  const empty = await assessBoxDataGovernance(emptyPages.client, { listLimit: 100 });
  const emptyRetention = findingById(empty, "BOX-12");
  assert.notEqual(emptyRetention.status, "fail", "an empty page under a next_marker is not evidence that no policy exists");
  assert.equal(emptyRetention.status, "warn");
  assert.equal(emptyRetention.summary, `The retention policy listing returned no policies before it stopped (${EMPTY_MARKER_PAGE_REASON}), so whether active retention policies exist is unknown; review the remainder in the Admin Console.`);
  assert.equal(emptyRetention.evidence.retention_policies_truncated, true);
  assert.equal(emptyRetention.evidence.retention_policies, null, "an empty page under a next_marker names no policy and asserts no absence");
  assert.equal(emptyRetention.evidence.policies_read, 0, "the read's own size is the one zero that renders");
  assert.equal(emptyRetention.evidence.active_policies, null, "zero active policies is not asserted from a truncated read");
  assert.equal(emptyRetention.evidence.assigned_policies, null, "zero assigned policies is not asserted from a truncated read");
  assert.equal(empty.summary.retention_policies, null);
  assert.equal(empty.summary.legal_hold_policies, null);
  assert.match(emptyRetention.manualEvidence, /Admin Console > Governance > Retention/);
  const emptyHold = findingById(empty, "BOX-13");
  assert.equal(emptyHold.status, "warn");
  assert.equal(emptyHold.summary, `The legal hold policy listing returned no policies before it stopped (${EMPTY_MARKER_PAGE_REASON}), so whether legal hold policies exist is unknown; review the remainder in the Admin Console.`);
  assert.doesNotMatch(emptyHold.summary, /No legal hold policies exist/);
  assert.equal(emptyHold.evidence.legal_hold_policies_truncated, true);
  assert.equal(empty.summary.assigned_retention_policies, null);
  assert.equal(empty.summary.assigned_legal_hold_policies, null);
  assert.equal(empty.truncated.filter((note) => note.startsWith("retention_policies: ") || note.startsWith("legal_hold_policies: ")).length, 2, JSON.stringify(empty.truncated));

  // A capped read whose collected policies are all retired: the fail branch is not reached, and the remedy names the cap option.
  const retired = { ...ASSIGNED_RETENTION_POLICY, status: "retired" };
  const cappedInactive = httpBox(hardenedFixture(), {
    routes: {
      "GET /2.0/retention_policies": (url) => boxMarkerPage([{ ...retired, id: "retention-1" }, { ...retired, id: "retention-2" }, ASSIGNED_RETENTION_POLICY], url),
      "GET /2.0/legal_hold_policies": (url) => boxMarkerPage([{ ...ASSIGNED_LEGAL_HOLD, id: "hold-1", status: "released" }, { ...ASSIGNED_LEGAL_HOLD, id: "hold-2", status: "released" }, ASSIGNED_LEGAL_HOLD], url),
    },
  });
  const capped = await assessBoxDataGovernance(cappedInactive.client, { listLimit: 2 });
  const cappedRetention = findingById(capped, "BOX-12");
  assert.equal(cappedRetention.status, "warn", "an inactive sample from a capped read does not prove that no active policy exists");
  assert.equal(cappedRetention.summary, "None of the 2 retention policies read is active, but the retention policy listing stopped after 2 records because the 2-record cap was reached while the server offered a next marker, so active policies may remain unread; raise list_limit and rerun.");
  assert.equal(cappedRetention.evidence.retention_policies_truncated, true);
  assert.equal(cappedRetention.evidence.active_policies, null, "no active policy among a capped sample is not a zero");
  assert.equal(cappedRetention.evidence.policies_read, 2);
  const cappedHold = findingById(capped, "BOX-13");
  assert.equal(cappedHold.status, "warn");
  assert.equal(cappedHold.summary, "None of the 2 legal hold policies read is active, but the legal hold policy listing stopped after 2 records because the 2-record cap was reached while the server offered a next marker, so active holds may remain unread; raise list_limit and rerun.");

  // A capped read that did observe assigned active policies: a universal claim over the policies read is a warn that
  // states the seen count against the unknown total, carries the cap option and the flag, and withholds the records
  // while the counts stand as lower bounds.
  const cappedAssigned = httpBox(hardenedFixture(), {
    routes: {
      "GET /2.0/retention_policies": (url) => boxMarkerPage([ASSIGNED_RETENTION_POLICY, { ...ASSIGNED_RETENTION_POLICY, id: "retention-2" }, { ...ASSIGNED_RETENTION_POLICY, id: "retention-3" }], url),
    },
  });
  const cappedPass = findingById(await assessBoxDataGovernance(cappedAssigned.client, { listLimit: 2 }), "BOX-12");
  assert.equal(cappedPass.status, "warn", "a pass over the seen part of a truncated listing is not a pass over the inventory");
  assert.equal(cappedPass.summary, "2/2 active retention policies have assignments among the 2 policies read, but the retention policy listing stopped after 2 records because the 2-record cap was reached while the server offered a next marker; the total number of policies is unknown and the policies beyond the stop were not assessed, so the assignment coverage holds only for the policies read and both counts are lower bounds; raise list_limit and rerun.");
  assert.equal(cappedPass.evidence.retention_policies_truncated, true);
  assert.equal(cappedPass.evidence.retention_policies, null);
  assert.equal(cappedPass.evidence.policies_read, 2);
  assert.equal(cappedPass.evidence.active_policies, 2, "a positive count from a truncated read renders as a lower bound");
  assert.equal(cappedPass.evidence.assigned_policies, 2);
  assert.match(cappedPass.manualEvidence, /Admin Console > Governance > Retention/);

  // Complete reads keep their wording, carry the flag as false, and render the records and every count, zero included.
  const complete = await assessBoxDataGovernance(httpBox(hardenedFixture()).client, { listLimit: 100 });
  assert.equal(findingById(complete, "BOX-12").status, "pass");
  assert.equal(findingById(complete, "BOX-12").summary, "1/1 active retention policies have assignments.");
  assert.equal(findingById(complete, "BOX-12").evidence.retention_policies_truncated, false);
  assert.equal(findingById(complete, "BOX-12").evidence.retention_policies.length, 1);
  assert.equal(findingById(complete, "BOX-13").status, "pass");
  assert.equal(findingById(complete, "BOX-13").summary, "1/1 active legal hold policies have custodian or content assignments.");
  assert.equal(findingById(complete, "BOX-13").evidence.legal_hold_policies_truncated, false);
  const completeEmpty = await assessBoxDataGovernance(httpBox(hardenedFixture(), {
    routes: { "GET /2.0/retention_policies": () => jsonResponse({ entries: [], limit: 100 }) },
  }).client, { listLimit: 100 });
  assert.equal(findingById(completeEmpty, "BOX-12").status, "fail");
  assert.deepEqual(findingById(completeEmpty, "BOX-12").evidence.retention_policies, [], "a complete empty read renders the empty list");
  assert.equal(findingById(completeEmpty, "BOX-12").evidence.active_policies, 0, "and asserts the zero");
  assert.equal(completeEmpty.summary.retention_policies, 0);
  const denied = await assessBoxDataGovernance(httpBox(hardenedFixture(), {
    routes: { "GET /2.0/retention_policies": () => jsonResponse({ type: "error", status: 403, code: "access_denied_insufficient_permissions", message: "Access denied" }, { status: 403 }) },
  }).client, { listLimit: 100 });
  assert.equal(findingById(denied, "BOX-12").status, "manual");
  assert.equal(findingById(denied, "BOX-12").evidence.retention_policies_truncated, null, "a denied read carries no truncation flag");
});

test("class 9: a zero from a user listing that stopped short renders null, user labels are withheld with a lower bound beside them, and a complete read renders every zero and name", async () => {
  // Truncated-empty: an empty first page under a next_marker read nothing, so nothing is asserted absent.
  const zeroRows = await assessBoxIdentityAccess(httpBox(hardenedFixture(), {
    routes: { "GET /2.0/users": () => jsonResponse({ entries: [], limit: 100, next_marker: "later" }) },
  }).client);
  for (const id of ["BOX-02", "BOX-03", "BOX-17", "BOX-18", "BOX-24"]) {
    const entry = findingById(zeroRows, id);
    assert.notEqual(entry.status, "pass", id);
    assert.match(entry.summary, /the user list stopped after 0 records because the server returned an empty page while still offering a next marker/, id);
    assert.equal(entry.evidence.sampled_users, 0, `${id}: the read's own size is the one zero that renders`);
    assert.equal(entry.evidence.users_truncated, true, id);
    assert.equal(entry.evidence.admin_users, null, `${id}: zero admins is not asserted from a truncated read`);
  }
  assert.equal(findingById(zeroRows, "BOX-02").evidence.privileged_users, null);
  assert.equal(findingById(zeroRows, "BOX-02").evidence.exempt_privileged_users, null);
  assert.equal(findingById(zeroRows, "BOX-02").evidence.exempt_privileged_users_count, null);
  assert.equal(findingById(zeroRows, "BOX-03").evidence.exempt_users, null);
  assert.equal(findingById(zeroRows, "BOX-17").evidence.admins, null);
  assert.equal(findingById(zeroRows, "BOX-17").evidence.coadmins, null);
  assert.equal(findingById(zeroRows, "BOX-17").evidence.coadmin_users, null);
  assert.equal(findingById(zeroRows, "BOX-18").evidence.coadmins, null);
  assert.equal(findingById(zeroRows, "BOX-24").evidence.active_users, null);
  assert.equal(findingById(zeroRows, "BOX-24").evidence.inactive_candidates, null);
  assert.equal(findingById(zeroRows, "BOX-24").evidence.inactive_candidates_count, null);
  assert.deepEqual(
    [zeroRows.summary.sampled_users, zeroRows.summary.users_truncated, zeroRows.summary.admins, zeroRows.summary.coadmins, zeroRows.summary.exempt_privileged_users, zeroRows.summary.inactive_candidates],
    [0, true, null, null, null, null],
    "the summary carries the read's size and its flag, and no zero derived from the truncated listing",
  );

  // Truncated-partial: the users read are real, so the counts render as lower bounds while the labels are withheld.
  const users = [
    user("admin-1", { role: "admin" }),
    user("coadmin-1", { role: "coadmin", is_exempt_from_login_verification: true }),
    user("member-1"),
    user("member-2"),
  ];
  const events = [loginEvent("admin-1", "ADMIN_LOGIN")];
  const capped = await assessBoxIdentityAccess(httpBox({ ...hardenedFixture(), users, events }).client, { userLimit: 2 });
  assertStatuses(capped, { "BOX-02": "fail", "BOX-17": "warn", "BOX-18": "manual", "BOX-24": "warn" });
  const cappedAdminMfa = findingById(capped, "BOX-02");
  assert.match(cappedAdminMfa.summary, /^1\/2 admin or co-admin accounts are exempt from login verification/);
  assert.equal(cappedAdminMfa.evidence.users_truncated, true);
  assert.equal(cappedAdminMfa.evidence.sampled_users, 2);
  assert.equal(cappedAdminMfa.evidence.privileged_users, 2, "a positive count from a truncated read is a lower bound");
  assert.equal(cappedAdminMfa.evidence.exempt_privileged_users, null, "the exempt admin is not named while the listing is truncated");
  assert.equal(cappedAdminMfa.evidence.exempt_privileged_users_count, 1, "but is counted");
  assert.match(cappedAdminMfa.evidence.inventory_gap, /the user list stopped after 2 records because the 2-record cap was reached/);
  const cappedAdmins = findingById(capped, "BOX-17");
  assert.equal(cappedAdmins.evidence.admins, null);
  assert.equal(cappedAdmins.evidence.admin_users, 1);
  assert.equal(cappedAdmins.evidence.coadmins, null);
  assert.equal(cappedAdmins.evidence.coadmin_users, 1);
  const cappedCoAdmins = findingById(capped, "BOX-18");
  assert.equal(cappedCoAdmins.summary, "1 co-admin accounts exist among the users read; the Box API does not expose individual co-admin permission sets, so scoping must be confirmed in the Admin Console.");
  assert.equal(cappedCoAdmins.evidence.coadmins, null);
  assert.equal(cappedCoAdmins.evidence.coadmin_users, 1);
  const cappedInactive = findingById(capped, "BOX-24");
  assert.equal(cappedInactive.evidence.active_users, 2);
  assert.equal(cappedInactive.evidence.inactive_candidates, null, "the inactive co-admin is not named while the user listing is truncated");
  assert.equal(cappedInactive.evidence.inactive_candidates_count, 1, "the count over the users read is a lower bound");
  assert.equal(cappedInactive.evidence.inactive_candidates_with_failed_logins, null);
  assert.equal(cappedInactive.evidence.inactive_candidates_with_failed_logins_count, null, "zero among a truncated read is not asserted");
  assert.deepEqual([capped.summary.admins, capped.summary.coadmins, capped.summary.exempt_privileged_users, capped.summary.inactive_candidates, capped.summary.users_truncated], [1, 1, 1, 1, true]);
  for (const text of JSON.stringify(capped).matchAll(/coadmin-1|member-1|member-2/g)) {
    assert.fail(`a user label from the truncated listing reached the output: ${text[0]}`);
  }

  // Complete: the same enterprise read whole names the exempt co-admin and the inactive users and asserts every zero.
  const complete = await assessBoxIdentityAccess(httpBox({ ...hardenedFixture(), users, events }).client, { userLimit: 100 });
  const completeAdminMfa = findingById(complete, "BOX-02");
  assert.equal(completeAdminMfa.evidence.users_truncated, false);
  assert.deepEqual(completeAdminMfa.evidence.exempt_privileged_users, ["coadmin-1@example.com"]);
  assert.equal(completeAdminMfa.evidence.exempt_privileged_users_count, 1);
  assert.deepEqual(findingById(complete, "BOX-03").evidence.exempt_users, []);
  assert.equal(findingById(complete, "BOX-03").evidence.exempt_users_count, 0);
  assert.deepEqual(findingById(complete, "BOX-17").evidence.admins, ["admin-1@example.com"]);
  assert.deepEqual(findingById(complete, "BOX-18").evidence.coadmins, ["coadmin-1@example.com"]);
  const completeInactive = findingById(complete, "BOX-24");
  assert.deepEqual(completeInactive.evidence.inactive_candidates, ["coadmin-1@example.com", "member-1@example.com", "member-2@example.com"]);
  assert.equal(completeInactive.evidence.inactive_candidates_count, 3);
  assert.deepEqual(completeInactive.evidence.inactive_candidates_with_failed_logins, []);
  assert.equal(completeInactive.evidence.inactive_candidates_with_failed_logins_count, 0);
  assert.equal(completeInactive.evidence.activity_events, 1);
  assert.equal(completeInactive.evidence.failed_login_events, 0, "a zero from a complete event read is asserted");
});

test("class 9: the allowlist and information barrier findings keep a presence-based pass under a truncated listing but state the stop, and never assert an empty allowlist or an unsegmented barrier from a page that stopped short", async () => {
  const entries = [
    { id: "entry-1", type: "collaboration_whitelist_entry", domain: "partner.example", direction: "both", created_at: "2026-06-01T00:00:00Z" },
    { id: "entry-2", type: "collaboration_whitelist_entry", domain: "vendor.example", direction: "inbound", created_at: "2026-06-01T00:00:00Z" },
    { id: "entry-3", type: "collaboration_whitelist_entry", domain: "supplier.example", direction: "outbound", created_at: "2026-06-01T00:00:00Z" },
  ];

  // Truncated-empty allowlist: the mode is read, the listing read nothing, so the allowlist is not called empty.
  const zeroRows = await assessBoxSharingCollaboration(httpBox(hardenedFixture(), {
    routes: { "GET /2.0/collaboration_whitelist_entries": () => jsonResponse({ entries: [], limit: 100, next_marker: "later" }) },
  }).client, { listLimit: 100 });
  const zeroMode = findingById(zeroRows, "BOX-04");
  assert.equal(zeroMode.status, "warn");
  assert.equal(zeroMode.summary, `External collaboration is limited to allowlisted domains, but the collaboration allowlist listing returned no entries before it stopped (${EMPTY_MARKER_PAGE_REASON}), so whether the allowlist is populated is unknown; review the remainder in the Admin Console.`);
  assert.doesNotMatch(zeroMode.summary, /allowlist is empty/);
  assert.equal(zeroMode.evidence.allowlist_entries, null, "zero entries is not asserted from a truncated read");
  assert.equal(zeroMode.evidence.allowlist_entries_truncated, true);
  const zeroAllowlist = findingById(zeroRows, "BOX-05");
  assert.equal(zeroAllowlist.status, "warn");
  assert.match(zeroAllowlist.summary, /^The collaboration allowlist collection stopped at the cap \(0 entries and 0 exempt users retrieved\)/);
  assert.equal(zeroAllowlist.evidence.allowlist_entries, null);
  assert.equal(zeroAllowlist.evidence.allowlist_entries_count, null);
  assert.equal(zeroAllowlist.evidence.public_email_domains, null);
  assert.equal(zeroAllowlist.evidence.public_email_domain_count, null);
  assert.equal(zeroRows.summary.allowlist_entries, null);
  assert.equal(zeroRows.summary.allowlist_entries_truncated, true);
  assert.equal(zeroRows.summary.public_email_domains, null);

  // Truncated-partial allowlist: the mode pass rests on the setting and stands with the stop stated; the domains read
  // are withheld from the evidence while the counts beside them stand as lower bounds.
  const capped = await assessBoxSharingCollaboration(httpBox({ ...hardenedFixture(), allowlistEntries: entries }).client, { listLimit: 2 });
  const cappedMode = findingById(capped, "BOX-04");
  assert.equal(cappedMode.status, "pass", "the pass rests on the enterprise setting, not on the listing");
  assert.equal(cappedMode.summary, "External collaboration is limited to allowlisted domains (2 domain entries visible; the collaboration allowlist listing stopped after 2 records because the 2-record cap was reached while the server offered a next marker, so the entry count is a lower bound; raise list_limit and rerun).");
  assert.equal(cappedMode.evidence.allowlist_entries, 2);
  assert.equal(cappedMode.evidence.allowlist_entries_truncated, true);
  const cappedAllowlist = findingById(capped, "BOX-05");
  assert.equal(cappedAllowlist.status, "warn");
  assert.equal(cappedAllowlist.evidence.allowlist_entries, null, "domain names are withheld while the listing is truncated");
  assert.equal(cappedAllowlist.evidence.allowlist_entries_count, 2);
  assert.equal(cappedAllowlist.evidence.both_direction_entries, 1);
  assert.equal(cappedAllowlist.evidence.stale_entries, null);
  assert.equal(cappedAllowlist.evidence.stale_entry_count, null, "zero stale entries among a truncated read is not asserted");
  assert.equal(cappedAllowlist.evidence.allowlist_truncated, true);
  assert.doesNotMatch(JSON.stringify(capped), /partner\.example|vendor\.example/, "no domain from the truncated listing reaches the output");
  assert.equal(capped.summary.allowlist_entries, 2);

  // Complete allowlist: the domains are named and every zero is asserted.
  const complete = await assessBoxSharingCollaboration(httpBox({ ...hardenedFixture(), allowlistEntries: entries }).client, { listLimit: 100 });
  assert.equal(findingById(complete, "BOX-04").summary, "External collaboration is limited to allowlisted domains (3 domain entries visible).");
  assert.equal(findingById(complete, "BOX-04").evidence.allowlist_entries_truncated, false);
  assert.deepEqual(findingById(complete, "BOX-05").evidence.allowlist_entries, ["partner.example (both)", "vendor.example (inbound)", "supplier.example (outbound)"]);
  assert.equal(findingById(complete, "BOX-05").evidence.allowlist_entries_count, 3);
  assert.deepEqual(findingById(complete, "BOX-05").evidence.public_email_domains, []);
  assert.equal(findingById(complete, "BOX-05").evidence.public_email_domain_count, 0);
  assert.equal(findingById(complete, "BOX-05").evidence.stale_entry_count, 0);
  const completeEmpty = await assessBoxSharingCollaboration(httpBox({ ...hardenedFixture(), allowlistEntries: [] }).client, { listLimit: 100 });
  assert.match(findingById(completeEmpty, "BOX-04").summary, /but the allowlist is empty/, "a complete empty read is the one that calls the allowlist empty");
  assert.equal(findingById(completeEmpty, "BOX-04").evidence.allowlist_entries, 0);
  assert.deepEqual(findingById(completeEmpty, "BOX-05").evidence.allowlist_entries, []);
  assert.equal(findingById(completeEmpty, "BOX-05").evidence.allowlist_entries_count, 0);

  // Barrier segments: an empty segment page under a next_marker leaves whether the barrier has segments unknown.
  const zeroSegments = await assessBoxShieldMonitoring(httpBox(hardenedFixture(), {
    routes: { "GET /2.0/shield_information_barrier_segments": () => jsonResponse({ entries: [], limit: 100, next_marker: "later" }) },
  }).client);
  const zeroBarrier = findingById(zeroSegments, "BOX-15");
  assert.equal(zeroBarrier.status, "warn");
  assert.equal(zeroBarrier.summary, `1 information barriers are enabled but their segment listing returned no segments before it stopped (for policy barrier-1, ${EMPTY_MARKER_PAGE_REASON}), so whether they have segments is unknown.`);
  assert.doesNotMatch(zeroBarrier.summary, /no visible segments/);
  assert.equal(zeroBarrier.evidence.barriers[0].segments, null, "zero segments is not asserted from a truncated segment listing");
  assert.equal(zeroBarrier.evidence.segments_truncated, true);
  assert.equal(zeroBarrier.evidence.enabled_barriers, 1);
  assert.match(zeroBarrier.manualEvidence, /Information Barriers/);

  // A capped segment listing: the pass rests on a segment existing and stands with the stop stated; the count is a lower bound.
  const segments = [
    { id: "segment-1", type: "shield_information_barrier_segment", name: "Research" },
    { id: "segment-2", type: "shield_information_barrier_segment", name: "Trading" },
  ];
  const cappedSegments = await assessBoxShieldMonitoring(httpBox({ ...hardenedFixture(), barrierSegments: segments }, {
    routes: { "GET /2.0/shield_information_barrier_segments": (url) => jsonResponse({ entries: segments.slice(0, 1), limit: 1, next_marker: "1" }) },
  }).client);
  const cappedBarrier = findingById(cappedSegments, "BOX-15");
  assert.equal(cappedBarrier.status, "pass", "a segment was read, so the presence-based pass stands");
  assert.match(cappedBarrier.summary, /^1 enabled information barriers have segments defined; the segment listing stopped after 1 segments because for policy barrier-1, the server re-served already-collected records under a new marker, so the remaining records could not be paged, so the segment counts are lower bounds; review the remainder in the Admin Console\.$/);
  assert.equal(cappedBarrier.evidence.barriers[0].segments, 1);
  assert.equal(cappedBarrier.evidence.segments_truncated, true);

  // Complete: the segment count and the flag as false.
  const completeBarrier = findingById(await assessBoxShieldMonitoring(httpBox(hardenedFixture()).client), "BOX-15");
  assert.equal(completeBarrier.summary, "1 enabled information barriers have segments defined.");
  assert.equal(completeBarrier.evidence.barriers[0].segments, 1);
  assert.equal(completeBarrier.evidence.segments_truncated, false);
  assert.equal(completeBarrier.evidence.barriers_truncated, false);

  // Device pins: an empty page under a next_marker is not "no device pins", and a capped read names no product.
  const zeroPins = findingById(await assessBoxDataGovernance(httpBox(hardenedFixture(), {
    routes: { "GET /2.0/enterprises/{enterprise}/device_pinners": () => jsonResponse({ entries: [], limit: 100, next_marker: "later" }) },
  }).client), "BOX-10");
  assert.equal(zeroPins.status, "manual");
  assert.equal(zeroPins.summary, `The device pin listing returned no pins before it stopped (${EMPTY_MARKER_PAGE_REASON}), so whether device pinning is in use is unknown; review the remainder in the Admin Console.`);
  assert.equal(zeroPins.evidence.device_pins, null);
  assert.equal(zeroPins.evidence.device_pin_products, null);
  assert.equal(zeroPins.evidence.device_pins_truncated, true);
  const pins = [{ id: "pin-1", type: "device_pinner", product_name: "iPhone" }, { id: "pin-2", type: "device_pinner", product_name: "Box Drive" }];
  const cappedPins = findingById(await assessBoxDataGovernance(httpBox({ ...hardenedFixture(), devicePinners: pins }).client, { listLimit: 1 }), "BOX-10");
  assert.equal(cappedPins.status, "manual");
  assert.match(cappedPins.summary, /^1 device pins are registered \(a lower bound: the device pin listing stopped after 1 records because the 1-record cap was reached while the server offered a next marker; raise list_limit and rerun\); the Box API/);
  assert.equal(cappedPins.evidence.device_pins, 1);
  assert.equal(cappedPins.evidence.device_pin_products, null, "the product breakdown is withheld while the listing is truncated");
  const completePins = findingById(await assessBoxDataGovernance(httpBox({ ...hardenedFixture(), devicePinners: pins }).client, { listLimit: 100 }), "BOX-10");
  assert.deepEqual(completePins.evidence.device_pin_products, { iPhone: 1, "Box Drive": 1 });
  assert.equal(completePins.evidence.device_pins_truncated, false);
});

test("verdict rule 9: non-JSON error bodies are described, never echoed, into Box error text", async () => {
  const fetchImpl = async () => new Response(`<html><body>gateway error; upstream header Authorization: Bearer FAKE_SECRET_TOKEN_8</body></html>`, {
    status: 502,
    statusText: "Bad Gateway",
    headers: { "content-type": "text/html" },
  });
  const client = new BoxApiClient(sampleConfig({ authMode: "oauth", accessToken: "oauth-fixture-access-2026", clientId: undefined, clientSecret: undefined, maxRetries: 0 }), { fetchImpl, now: () => NOW });
  await assert.rejects(client.listUsers(5), (error) => {
    assert.ok(error instanceof BoxApiError);
    assert.equal(error.status, 502);
    assert.match(error.message, /non-JSON text\/html response body \(\d+ bytes, not echoed\)/);
    assert.doesNotMatch(error.message, /FAKE_SECRET_TOKEN_8|gateway error/);
    return true;
  });
});

test("BoxApiClient retries 429 and 5xx responses with backoff and redacts secrets from errors", async () => {
  const delays = [];
  let attempts = 0;
  const fetchImpl = async (input) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    if (url.pathname === "/2.0/users/me") {
      attempts += 1;
      if (attempts === 1) return jsonResponse({ code: "rate_limit_exceeded" }, { status: 429, headers: { "retry-after": "2" } });
      if (attempts === 2) return jsonResponse({ message: "upstream unavailable" }, { status: 503 });
      return jsonResponse({ id: "service-1", type: "user" });
    }
    if (url.pathname === "/2.0/retention_policies") {
      return jsonResponse({
        type: "error",
        status: 403,
        code: "access_denied_insufficient_permissions",
        message: "Access denied - insufficient permission for token super-secret-token-value",
        request_id: "req-123",
      }, { status: 403 });
    }
    return jsonResponse({ message: "boom" }, { status: 500 });
  };

  const client = new BoxApiClient(sampleConfig({ authMode: "oauth", accessToken: "super-secret-token-value", clientId: undefined, clientSecret: undefined, maxRetries: 2 }), {
    fetchImpl,
    now: () => NOW,
    sleep: async (ms) => {
      delays.push(ms);
    },
  });

  const me = await client.getCurrentUser();
  assert.equal(me.id, "service-1");
  assert.deepEqual(delays, [2000, 1000]);

  await assert.rejects(
    () => client.listRetentionPolicies(10),
    (error) => {
      assert.ok(error instanceof BoxApiError);
      assert.equal(error.status, 403);
      assert.equal(error.code, "access_denied_insufficient_permissions");
      assert.equal(error.requestId, "req-123");
      assert.match(error.message, /403/);
      assert.doesNotMatch(error.message, /super-secret-token-value/);
      assert.match(error.message, /\[REDACTED\]/);
      return true;
    },
  );

  delays.length = 0;
  await assert.rejects(() => client.listGroups(5), (error) => {
    assert.ok(error instanceof BoxApiError);
    assert.equal(error.status, 500);
    return true;
  });
  assert.deepEqual(delays, [500, 1000], "5xx retries use exponential backoff until maxRetries is exhausted");

  assert.equal(redactSecrets("Authorization: Bearer abc.def-ghi and secret shh-secret-value", ["shh-secret-value", "tiny"]), "Authorization: Bearer [REDACTED] and secret [REDACTED]");
});

test("Box scrubber: a quoted header value in a recorded error is removed whole, in double or single quotes, with or without spaces, and JSON-escaped", () => {
  const canary = "RulingNameShapedProbeZq";
  assert.equal(scrubErrorText(`the resource ${canary} was not readable`), `the resource ${canary} was not readable`, "the name-shaped canary stays bare, so only the carrier removes it");
  const carriers = [
    [`Cookie: sid="${canary}"`, "Cookie: [REDACTED]"],
    [`Cookie: sid='${canary}'; Path=/; HttpOnly`, "Cookie: [REDACTED]"],
    [`X-Api-Key: "${canary}"`, 'X-Api-Key: "[REDACTED]"'],
    [`X-Api-Key:'${canary}'`, "X-Api-Key:'[REDACTED]'"],
    [`Authorization: Bearer "${canary}"`, 'Authorization: Bearer "[REDACTED]"'],
    [`Authorization: "Bearer ${canary}"`, 'Authorization: "Bearer [REDACTED]"'],
    [`"Authorization": "Bearer ${canary}"`, '"Authorization": "Bearer [REDACTED]"'],
    [`\\"Authorization\\":\\"Bearer ${canary}\\"`, '\\"Authorization\\":\\"Bearer [REDACTED]\\"'],
    [`\\"X-Api-Key\\": \\"${canary}\\"`, '\\"X-Api-Key\\": \\"[REDACTED]\\"'],
    [`Box request failed (502 Bad Gateway) for GET /2.0/users: upstream echoed {"headers":{"Authorization":"Bearer ${canary}","Cookie":"sid=${canary}","Content-Type":"application/json"}}`, 'Box request failed (502 Bad Gateway) for GET /2.0/users: upstream echoed {"headers":{"Authorization":"Bearer [REDACTED]","Cookie":"[REDACTED]","Content-Type":"application/json"}}'],
    // Compound lines: the header after a cookie or header value keeps its name and gets its own carrier treatment.
    [`Cookie: sid="${canary}"; X-Api-Key: "${canary}"; Content-Type: "application/json"`, 'Cookie: [REDACTED]; X-Api-Key: "[REDACTED]"; Content-Type: "application/json"'],
    [`Cookie: sid=${canary}; X-Api-Key: "${canary}"; Content-Type: "application/json"`, 'Cookie: [REDACTED]; X-Api-Key: "[REDACTED]"; Content-Type: "application/json"'],
    [`Cookie: sid=${canary}, X-Api-Key: ${canary}, Content-Type: application/json`, "Cookie: [REDACTED], X-Api-Key: [REDACTED], Content-Type: application/json"],
    [`X-Api-Key: "${canary}"; Authorization: Bearer "${canary}"`, 'X-Api-Key: "[REDACTED]"; Authorization: Bearer "[REDACTED]"'],
    [`X-Api-Key: "${canary}" {"token": "${canary}", "env": "production"}`, 'X-Api-Key: "[REDACTED]" {"token": "[REDACTED]", "env": "production"}'],
    [`\\"Cookie\\": \\"sid=${canary}\\", \\"X-Api-Key\\": \\"${canary}\\", \\"Content-Type\\": \\"application/json\\"`, '\\"Cookie\\": \\"[REDACTED]\\", \\"X-Api-Key\\": \\"[REDACTED]\\", \\"Content-Type\\": \\"application/json\\"'],
    [`Box request failed (502 Bad Gateway) for GET /2.0/users: upstream echoed Cookie: sid=${canary}; X-Api-Key: "${canary}"; Content-Type: "application/json"`, 'Box request failed (502 Bad Gateway) for GET /2.0/users: upstream echoed Cookie: [REDACTED]; X-Api-Key: "[REDACTED]"; Content-Type: "application/json"'],
  ];
  for (const [text, expected] of carriers) {
    const scrubbed = scrubErrorText(text);
    assert.equal(scrubbed, expected, text);
    assertCanaryWindowsAbsent(assert, scrubbed, [canary], text);
    assert.equal(scrubErrorText(scrubbed), scrubbed, `${text}: a second pass changed the text`);
    if (text.includes("Content-Type")) assert.ok(/Content-Type\\?"?: ?\\?"?(application\/json|text\/html)/.test(scrubbed), `${text}: Content-Type lost its name or value`);
  }
  assert.equal(scrubErrorText('Authorization: Bearer "token"'), 'Authorization: Bearer "[REDACTED]"', "a plain word in quotes is the value and goes");
  assert.equal(scrubErrorText('Content-Type: "application/json"; Accept: "application/json"'), 'Content-Type: "application/json"; Accept: "application/json"', "quoted non-credential headers stay");
  assert.equal(redactSecrets(`Cookie: sid="${canary}"`, [canary]), "Cookie: [REDACTED]", "registering the value as a secret changes nothing about the carrier result");
});

test("BoxApiClient refreshes an expired OAuth token after a 401", async () => {
  const seen = [];
  let refreshed = false;
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    seen.push({ pathname: url.pathname, body: init.body, auth: headerValue(init.headers, "authorization") });
    if (url.pathname === "/oauth2/token") {
      refreshed = true;
      return jsonResponse({ access_token: "fresh-token", refresh_token: "next-refresh", expires_in: 3600 });
    }
    if (!refreshed) return jsonResponse({ code: "unauthorized", message: "expired" }, { status: 401 });
    return jsonResponse({ entries: [{ id: "tos-1", type: "terms_of_service", status: "enabled", tos_type: "managed" }] });
  };

  const client = new BoxApiClient(sampleConfig({ authMode: "oauth", accessToken: "stale-token", refreshToken: "refresh-1" }), { fetchImpl, now: () => NOW });
  const terms = await client.listTermsOfServices();
  assert.equal(terms.items[0].id, "tos-1");
  assert.equal(terms.truncated, false);
  assert.equal(seen[0].auth, "Bearer stale-token");
  const refreshBody = new URLSearchParams(seen[1].body);
  assert.equal(seen[1].pathname, "/oauth2/token");
  assert.equal(refreshBody.get("grant_type"), "refresh_token");
  assert.equal(refreshBody.get("refresh_token"), "refresh-1");
  assert.equal(refreshBody.get("client_id"), "client-id");
  assert.equal(seen[2].auth, "Bearer fresh-token");
});

test("checkBoxAccess reports healthy when every audit surface is readable", async () => {
  const result = await checkBoxAccess(createStubClient(hardenedFixture()));
  assert.equal(result.status, "healthy");
  assert.equal(result.enterpriseId, "123456");
  assert.equal(result.authMode, "ccg");
  assert.equal(result.surfaces.length, 15);
  assert.ok(result.surfaces.every((surface) => surface.status === "readable"));
  const users = result.surfaces.find((surface) => surface.name === "users");
  assert.equal(users.count, 4);
  assert.equal(users.endpoint, "/users");
  assert.ok(result.notes.some((note) => note.includes("CCG")));
  assert.match(result.recommendedNextStep, /box_assess_identity_access/);
});

test("checkBoxAccess reports limited access when core surfaces fail", async () => {
  const result = await checkBoxAccess(createStubClient(hardenedFixture(), {
    getEnterpriseConfiguration: forbidden("manage_enterprise_properties scope missing"),
    listRetentionPolicies: forbidden(),
    listLegalHoldPolicies: forbidden(),
    listShieldInformationBarriers: forbidden(),
    async listEnterpriseEvents() {
      throw new Error("Box request timed out after 30000ms: https://api.box.com/2.0/events");
    },
  }));
  assert.equal(result.status, "limited");
  const configuration = result.surfaces.find((surface) => surface.name === "enterprise_configuration");
  assert.equal(configuration.status, "not_readable");
  assert.match(configuration.error, /manage_enterprise_properties/);
  const events = result.surfaces.find((surface) => surface.name === "enterprise_events");
  assert.equal(events.status, "not_readable");
  assert.match(events.error, /timed out/);
  assert.equal(result.surfaces.filter((surface) => surface.status === "readable").length, 10);
  assert.match(result.recommendedNextStep, /Manage enterprise properties/);

  const noEnterprise = await checkBoxAccess(createStubClient(hardenedFixture(), {
    async resolveEnterpriseId() {
      throw new Error("Unable to determine the Box enterprise ID; set BOX_ENTERPRISE_ID explicitly.");
    },
  }));
  assert.equal(noEnterprise.status, "limited");
  assert.equal(noEnterprise.enterpriseId, undefined);
  assert.equal(noEnterprise.surfaces.find((surface) => surface.name === "enterprise_configuration").status, "not_configured");
});

test("assessBoxIdentityAccess passes with hardened SSO, MFA, password, session, and admin posture", async () => {
  const result = await assessBoxIdentityAccess(createStubClient(hardenedFixture()), { lookbackDays: 30 });
  assert.equal(result.area, "identity_access");
  assert.deepEqual(result.findings.map((entry) => entry.id), ["BOX-01", "BOX-02", "BOX-03", "BOX-17", "BOX-18", "BOX-21", "BOX-22", "BOX-23", "BOX-24"]);
  assertStatuses(result, {
    "BOX-01": "pass",
    "BOX-02": "pass",
    "BOX-03": "pass",
    "BOX-17": "pass",
    "BOX-18": "pass",
    "BOX-21": "pass",
    "BOX-22": "pass",
    "BOX-23": "manual",
    "BOX-24": "pass",
  });
  assertMappings(result);
  assert.deepEqual(findingById(result, "BOX-01").mappings, mappingsForControl(1));
  assert.equal(findingById(result, "BOX-01").mappings[0], "FedRAMP IA-2");
  assert.equal(findingById(result, "BOX-02").mappings[1], "CMMC IA.L2-3.5.3");
  assert.match(findingById(result, "BOX-23").manualEvidence, /Admin Console/);
  assert.equal(result.summary.admins, 1);
  assert.equal(result.summary.coadmins, 0);
  assert.equal(result.summary.sso_required, true);
  assert.equal(result.summary.inactive_candidates, 0);
  assert.deepEqual(result.errors, []);
});

test("assessBoxIdentityAccess fails weak identity posture and flags admin sprawl and inactive users", async () => {
  const result = await assessBoxIdentityAccess(createStubClient(weakFixture()), { maxAdmins: 10, lookbackDays: 90 });
  assertStatuses(result, {
    "BOX-01": "fail",
    "BOX-02": "fail",
    "BOX-03": "fail",
    "BOX-17": "warn",
    "BOX-18": "manual",
    "BOX-21": "fail",
    "BOX-22": "fail",
    "BOX-23": "manual",
    "BOX-24": "fail",
  });
  assertMappings(result);
  assert.match(findingById(result, "BOX-01").summary, /SSO/);
  assert.match(findingById(result, "BOX-17").summary, /12 admin or co-admin accounts exceed/);
  assert.match(findingById(result, "BOX-18").manualEvidence, /Edit User Access Permissions/);
  assert.equal(findingById(result, "BOX-21").evidence.password_min_length, 6);
  assert.equal(findingById(result, "BOX-22").evidence.session_duration, "never");
  assert.equal(findingById(result, "BOX-24").evidence.inactive_candidates.length, 16);
  assert.equal(result.summary.exempt_privileged_users, 1);

  const exemptAdmins = await assessBoxIdentityAccess(createStubClient({
    ...hardenedFixture(),
    users: [user("admin-1", { role: "admin", is_exempt_from_login_verification: true }), user("member-1")],
  }));
  assertStatuses(exemptAdmins, { "BOX-02": "fail", "BOX-03": "pass" });
  assert.deepEqual(findingById(exemptAdmins, "BOX-02").evidence.exempt_privileged_users, ["admin-1@example.com"]);
});

test("assessBoxIdentityAccess falls back to manual findings when the API refuses configuration or users", async () => {
  const result = await assessBoxIdentityAccess(createStubClient(hardenedFixture(), {
    getEnterpriseConfiguration: forbidden("manage_enterprise_properties scope missing"),
  }));
  assertStatuses(result, {
    "BOX-01": "manual",
    "BOX-02": "manual",
    "BOX-03": "manual",
    "BOX-17": "pass",
    "BOX-21": "manual",
    "BOX-22": "manual",
  });
  assert.match(findingById(result, "BOX-01").summary, /lacks the scope or admin role/);
  assert.match(findingById(result, "BOX-01").manualEvidence, /Configure Single Sign On/);
  assert.equal(result.errors.length, 1);
  assert.match(result.errors[0], /^enterprise_configuration: /);

  const noUsers = await assessBoxIdentityAccess(createStubClient(hardenedFixture(), {
    listUsers: forbidden("manage_managed_users scope missing"),
    listEnterpriseEvents: forbidden(),
  }));
  assertStatuses(noUsers, {
    "BOX-01": "pass",
    "BOX-02": "manual",
    "BOX-03": "manual",
    "BOX-17": "manual",
    "BOX-18": "manual",
    "BOX-21": "pass",
    "BOX-24": "manual",
  });
  assert.match(findingById(noUsers, "BOX-02").summary, /Enterprise users could not be listed because the audit principal lacks the scope or admin role/);
  assert.match(findingById(noUsers, "BOX-02").summary, /enterprise MFA is required \(totp\)/);
  assert.match(findingById(noUsers, "BOX-02").manualEvidence, /Exempt from 2-step verification/);
  assert.equal(findingById(noUsers, "BOX-02").evidence.is_multi_factor_auth_required, true);
  assert.match(findingById(noUsers, "BOX-02").evidence.users_error, /403 Forbidden/);
  assert.match(findingById(noUsers, "BOX-03").summary, /per-user exemptions from login verification cannot be verified/);
  assert.match(findingById(noUsers, "BOX-03").manualEvidence, /2-Step Verification/);
  assert.ok(noUsers.errors.some((entry) => entry.startsWith("users: ")));
  assert.ok(noUsers.errors.some((entry) => entry.startsWith("enterprise_events: ")));

  const nothingReadable = await assessBoxIdentityAccess(createStubClient(hardenedFixture(), {
    getEnterpriseConfiguration: forbidden(),
    listUsers: forbidden(),
  }));
  assertStatuses(nothingReadable, { "BOX-02": "manual", "BOX-03": "manual" });
  assert.match(findingById(nothingReadable, "BOX-02").summary, /^Neither enterprise MFA settings/);
  assert.match(findingById(nothingReadable, "BOX-03").summary, /^Neither enterprise MFA settings/);
});

test("assessBoxIdentityAccess does not count failed logins as user activity", async () => {
  const fixture = {
    ...hardenedFixture(),
    users: [user("admin-1", { role: "admin" }), user("member-1"), user("member-2"), user("member-3")],
    events: [
      loginEvent("admin-1", "ADMIN_LOGIN"),
      loginEvent("member-1"),
      loginEvent("member-2", "FAILED_LOGIN"),
      { ...loginEvent("member-2", "FAILED_LOGIN"), event_id: "FAILED_LOGIN-member-2-retry" },
      loginEvent("member-3", "FAILED_LOGIN"),
    ],
  };
  const base = createStubClient(fixture);
  let requestedTypes;
  const client = {
    ...base,
    async listEnterpriseEvents(options) {
      requestedTypes = options.eventTypes;
      return base.listEnterpriseEvents(options);
    },
  };

  const result = await assessBoxIdentityAccess(client, { lookbackDays: 30 });
  assert.ok(requestedTypes.includes("FAILED_LOGIN"), "failed logins stay in the evidence query");
  assert.ok(requestedTypes.includes("LOGIN"));
  assertStatuses(result, { "BOX-24": "fail" });
  const inactive = findingById(result, "BOX-24");
  assert.deepEqual(inactive.evidence.inactive_candidates, ["member-2@example.com", "member-3@example.com"]);
  assert.deepEqual(inactive.evidence.inactive_candidates_with_failed_logins, ["member-2@example.com", "member-3@example.com"]);
  assert.equal(inactive.evidence.failed_login_events, 3);
  assert.equal(inactive.evidence.activity_events, 2);
  assert.equal(inactive.evidence.sampled_events, 5);
  assert.match(inactive.summary, /2\/4 active users had no successful login or content activity/);
  assert.match(inactive.summary, /2 of them only recorded failed logins/);
  assert.equal(result.summary.inactive_candidates, 2);

  const recovered = await assessBoxIdentityAccess(createStubClient({
    ...fixture,
    events: [...fixture.events, loginEvent("member-2"), loginEvent("member-3", "UPLOAD")],
  }), { lookbackDays: 30 });
  assertStatuses(recovered, { "BOX-24": "pass" });
  assert.deepEqual(findingById(recovered, "BOX-24").evidence.inactive_candidates, []);
  assert.equal(findingById(recovered, "BOX-24").evidence.failed_login_events, 3);
});

test("assessBoxIdentityAccess warns instead of passing on an empty user inventory", async () => {
  const empty = await assessBoxIdentityAccess(createStubClient({ ...hardenedFixture(), users: [], events: [] }));
  assertStatuses(empty, {
    "BOX-01": "pass",
    "BOX-02": "warn",
    "BOX-03": "warn",
    "BOX-17": "warn",
    "BOX-18": "warn",
    "BOX-21": "pass",
    "BOX-24": "warn",
  });
  assert.deepEqual(empty.errors, []);
  for (const id of ["BOX-02", "BOX-03", "BOX-17", "BOX-18", "BOX-24"]) {
    const entry = findingById(empty, id);
    assert.match(entry.summary, /returned zero managed users/, id);
    assert.match(entry.summary, /at least the primary admin/, id);
    assert.match(entry.evidence.inventory_gap, /inventory is empty/, id);
    assert.match(entry.manualEvidence, /Users & Groups/, id);
  }
  assert.match(findingById(empty, "BOX-02").summary, /^Multi-factor authentication is required for managed users \(totp\), but admin exemptions could not be assessed/);
  assert.match(findingById(empty, "BOX-03").summary, /per-user exemptions could not be assessed/);
  assert.equal(findingById(empty, "BOX-17").evidence.sampled_users, 0);
  assert.deepEqual(findingById(empty, "BOX-18").evidence.coadmins, [], "a complete empty read names no co-admin");
  assert.equal(findingById(empty, "BOX-18").evidence.coadmin_users, 0);
  assert.equal(findingById(empty, "BOX-24").evidence.active_users, 0, "zero active users is asserted from a complete read");
  assert.equal(empty.summary.admins, 0);
  assert.equal(empty.summary.users_truncated, false);

  const noAdmin = await assessBoxIdentityAccess(createStubClient({
    ...hardenedFixture(),
    users: [user("member-1"), user("member-2")],
    events: [loginEvent("member-1"), loginEvent("member-2", "DOWNLOAD")],
  }));
  assertStatuses(noAdmin, { "BOX-02": "warn", "BOX-03": "warn", "BOX-17": "warn", "BOX-18": "warn", "BOX-24": "warn" });
  assert.match(findingById(noAdmin, "BOX-17").summary, /2-user inventory contains no admin account/);
  assert.equal(findingById(noAdmin, "BOX-17").evidence.admin_users, 0);

  const exemptStillFails = await assessBoxIdentityAccess(createStubClient({
    ...hardenedFixture(),
    users: [user("coadmin-1", { role: "coadmin", is_exempt_from_login_verification: true })],
  }));
  assertStatuses(exemptStillFails, { "BOX-02": "fail", "BOX-18": "manual" });

  const onlyAppUsers = await assessBoxIdentityAccess(createStubClient({
    ...hardenedFixture(),
    users: [user("admin-1", { role: "admin", status: "inactive" }), user("app-user", { is_platform_access_only: true })],
    events: [],
  }));
  assertStatuses(onlyAppUsers, { "BOX-02": "pass", "BOX-17": "pass", "BOX-18": "pass", "BOX-24": "warn" });
  assert.match(findingById(onlyAppUsers, "BOX-24").summary, /None of the 2 sampled users are active managed users/);
});

test("truncated user and event lists downgrade absence-based identity verdicts to warn", async () => {
  const fixture = hardenedFixture();
  const truncatedUsers = await assessBoxIdentityAccess(createStubClient(fixture, { listUsers: truncatedList(fixture.users) }));
  assertStatuses(truncatedUsers, {
    "BOX-01": "pass",
    "BOX-02": "warn",
    "BOX-03": "warn",
    "BOX-17": "warn",
    "BOX-18": "warn",
    "BOX-21": "pass",
    "BOX-24": "warn",
  });
  for (const id of ["BOX-02", "BOX-03", "BOX-17", "BOX-18", "BOX-24"]) {
    const entry = findingById(truncatedUsers, id);
    assert.match(entry.summary, /stopped at the 4-record cap while Box reported more users/, id);
    assert.match(entry.summary, /raise user_limit/, id);
    assert.equal(entry.evidence.users_truncated, true, id);
    assert.match(entry.evidence.inventory_gap, /inventory is partial/, id);
  }
  assert.deepEqual(truncatedUsers.errors, []);
  assert.equal(truncatedUsers.truncated.length, 1);
  assert.match(truncatedUsers.truncated[0], /^users: collection stopped at the 4-record cap .*raise user_limit/);

  const weak = weakFixture();
  const truncatedWeak = await assessBoxIdentityAccess(createStubClient(weak, { listUsers: truncatedList(weak.users) }), { maxAdmins: 10 });
  assertStatuses(truncatedWeak, { "BOX-02": "fail", "BOX-03": "fail", "BOX-17": "warn", "BOX-18": "manual" });
  assert.match(findingById(truncatedWeak, "BOX-02").summary, /leaving 12 admin or co-admin accounts without an enforced second factor/);
  assert.match(findingById(truncatedWeak, "BOX-17").summary, /12 admin or co-admin accounts exceed/);
  assert.equal(findingById(truncatedWeak, "BOX-17").evidence.users_truncated, true);

  const base = createStubClient(fixture);
  const truncatedEvents = await assessBoxIdentityAccess({
    ...base,
    async listEnterpriseEvents(options) {
      const result = await base.listEnterpriseEvents(options);
      return page(result.items, true);
    },
  });
  assertStatuses(truncatedEvents, { "BOX-02": "pass", "BOX-17": "pass", "BOX-24": "warn" });
  const inactive = findingById(truncatedEvents, "BOX-24");
  assert.match(inactive.summary, /stopped at the 3-event cap while Box reported more events/);
  assert.match(inactive.summary, /raise event_limit/);
  assert.equal(inactive.evidence.events_truncated, true);
  assert.equal(inactive.evidence.users_truncated, false);
  assert.equal(truncatedEvents.truncated.length, 1);
  assert.match(truncatedEvents.truncated[0], /^enterprise_events: .*raise event_limit/);

  const exactCap = await assessBoxIdentityAccess(createStubClient(fixture), { eventLimit: 3 });
  assertStatuses(exactCap, { "BOX-24": "pass" });
  assert.equal(findingById(exactCap, "BOX-24").evidence.sampled_events, 3);
  assert.equal(findingById(exactCap, "BOX-24").evidence.events_truncated, false);
  assert.deepEqual(exactCap.truncated, []);
});

test("truncated allowlist and Shield event lists downgrade absence-based verdicts to warn", async () => {
  const fixture = hardenedFixture();
  const truncatedEntries = await assessBoxSharingCollaboration(createStubClient(fixture, {
    listCollaborationAllowlistEntries: truncatedList(fixture.allowlistEntries),
  }));
  assertStatuses(truncatedEntries, { "BOX-04": "pass", "BOX-05": "warn" });
  assert.match(findingById(truncatedEntries, "BOX-05").summary, /stopped at the cap \(1 entries and 0 exempt users retrieved\)/);
  assert.match(findingById(truncatedEntries, "BOX-05").summary, /raise list_limit/);
  assert.equal(findingById(truncatedEntries, "BOX-05").evidence.allowlist_truncated, true);
  assert.equal(truncatedEntries.truncated.length, 1);
  assert.match(truncatedEntries.truncated[0], /^collaboration_allowlist_entries: /);

  const truncatedExempt = await assessBoxSharingCollaboration(createStubClient(fixture, {
    listCollaborationAllowlistExemptTargets: truncatedList(fixture.exemptTargets),
  }));
  assertStatuses(truncatedExempt, { "BOX-05": "warn" });
  assert.match(truncatedExempt.truncated[0], /^collaboration_allowlist_exempt_targets: /);

  const weak = weakFixture();
  const publicStillFails = await assessBoxSharingCollaboration(createStubClient(weak, {
    listCollaborationAllowlistEntries: truncatedList(weak.allowlistEntries),
  }));
  assertStatuses(publicStillFails, { "BOX-05": "fail" });

  const deviceTrustEvent = { event_id: "device-1", event_type: "DEVICE_TRUST_CHECK_FAILED", created_at: "2026-09-11T00:00:00Z", created_by: { id: "member-1", type: "user" } };
  const shieldBase = createStubClient({ ...weak, events: [deviceTrustEvent] });
  const noRulesTruncated = await assessBoxShieldMonitoring({
    ...shieldBase,
    async listEnterpriseEvents(options) {
      const result = await shieldBase.listEnterpriseEvents(options);
      return page(result.items, true);
    },
  });
  assertStatuses(noRulesTruncated, { "BOX-16": "pass", "BOX-25": "warn" });
  assert.match(findingById(noRulesTruncated, "BOX-25").summary, /no Shield alerts appeared in the 1 sampled events, but the event collection stopped at the 1-event cap while Box reported more events/);
  assert.match(findingById(noRulesTruncated, "BOX-25").summary, /raise event_limit and rerun/);
  assert.match(noRulesTruncated.truncated[0], /^enterprise_events: collection stopped at the 1-record cap .*raise event_limit/);

  const noRulesComplete = await assessBoxShieldMonitoring(shieldBase);
  assertStatuses(noRulesComplete, { "BOX-25": "fail" });
  assert.deepEqual(noRulesComplete.truncated, []);

  const sampled = { sampled_events: 1, events_truncated: true };
  const truncatedMonitoring = findingById(noRulesTruncated, "BOX-25").evidence;
  assert.deepEqual(truncatedMonitoring.anomaly_events, { observed: 0, ...sampled }, "a zero counted in a truncated sample is labelled as observed");
  assert.deepEqual(truncatedMonitoring.content_access_events, { observed: 0, ...sampled });
  assert.equal(truncatedMonitoring.sampled_events, 1);
  assert.equal(truncatedMonitoring.events_truncated, true);
  assert.deepEqual(findingById(noRulesTruncated, "BOX-14").evidence.shield_events, { observed: {}, ...sampled }, "an empty Shield breakdown from a truncated sample is never a bare {}");
  assert.deepEqual(noRulesTruncated.summary.anomaly_events, { observed: 0, ...sampled });
  assert.equal(noRulesTruncated.summary.events_truncated, true);
  const completeMonitoring = findingById(noRulesComplete, "BOX-25").evidence;
  assert.equal(completeMonitoring.anomaly_events, 0, "a complete read keeps the plain count");
  assert.equal(completeMonitoring.events_truncated, false);
  assert.deepEqual(findingById(noRulesComplete, "BOX-14").evidence.shield_events, {});
  assert.equal(noRulesComplete.summary.anomaly_events, 0);
  for (const [leaf, value] of [
    ["BOX-25.evidence.anomaly_events", truncatedMonitoring.anomaly_events],
    ["BOX-25.evidence.content_access_events", truncatedMonitoring.content_access_events],
    ["BOX-14.evidence.shield_events", findingById(noRulesTruncated, "BOX-14").evidence.shield_events],
    ["summary.anomaly_events", noRulesTruncated.summary.anomaly_events],
  ]) {
    assert.notEqual(typeof value, "number", `${leaf} must not be a bare count under the cap`);
    assert.ok(value !== null && typeof value === "object" && Object.keys(value).length > 0, `${leaf} must not be a bare {} under the cap`);
    assert.equal(value.events_truncated, true, `${leaf} carries the truncation flag`);
  }

  const hardened = hardenedFixture();
  const alertsBase = createStubClient(hardened);
  const alertsTruncated = await assessBoxShieldMonitoring({
    ...alertsBase,
    async listEnterpriseEvents(options) {
      const result = await alertsBase.listEnterpriseEvents(options);
      return page(result.items, true);
    },
  });
  assertStatuses(alertsTruncated, { "BOX-25": "pass" });
  assert.match(findingById(alertsTruncated, "BOX-25").summary, /and 1 among 2 sampled events \(collection truncated\) Shield alert or block events show content access monitoring is active/);
  assert.deepEqual(findingById(alertsTruncated, "BOX-25").evidence.anomaly_events, { observed: 1, sampled_events: 2, events_truncated: true });
  assert.deepEqual(findingById(alertsTruncated, "BOX-14").evidence.shield_events, { observed: { SHIELD_ALERT: 1 }, sampled_events: 2, events_truncated: true });
});

test("assessBoxIdentityAccess treats null configuration categories as absent data instead of failing", async () => {
  const result = await assessBoxIdentityAccess(createStubClient({
    ...hardenedFixture(),
    configuration: { id: "123456", type: "enterprise_configuration", security: null, user_settings: null },
  }));
  assertStatuses(result, {
    "BOX-01": "manual",
    "BOX-02": "manual",
    "BOX-03": "manual",
    "BOX-17": "pass",
    "BOX-21": "manual",
    "BOX-22": "manual",
    "BOX-24": "pass",
  });
  for (const id of ["BOX-01", "BOX-02", "BOX-03", "BOX-21", "BOX-22"]) {
    const found = findingById(result, id);
    assert.notEqual(found.status, "fail", `${id} must not fail on a null category`);
    assert.match(found.summary, /category was returned as null/, `${id} should explain the null category`);
    assert.doesNotMatch(found.summary, /not required|do not expose/i, `${id} must not assert a negative posture from absent data`);
  }
  assert.match(findingById(result, "BOX-01").summary, /user_settings category/);
  assert.match(findingById(result, "BOX-02").summary, /security category/);
  assert.equal(findingById(result, "BOX-01").evidence.is_enterprise_sso_required, null);
  assert.equal(result.summary.sso_required, null);
  assert.equal(result.summary.mfa_required, null);
  assert.deepEqual(result.errors, []);

  const missingKeys = await assessBoxIdentityAccess(createStubClient({
    ...hardenedFixture(),
    configuration: { id: "123456", type: "enterprise_configuration", security: {}, user_settings: {} },
  }));
  assertStatuses(missingKeys, { "BOX-01": "warn", "BOX-02": "warn", "BOX-03": "warn", "BOX-21": "warn", "BOX-22": "warn" });
  assert.match(findingById(missingKeys, "BOX-01").summary, /did not expose is_enterprise_sso_required/);
  assert.match(findingById(missingKeys, "BOX-02").summary, /did not expose is_multi_factor_auth_required/);
  assert.match(findingById(missingKeys, "BOX-01").manualEvidence, /Configure Single Sign On/);
});

test("configuration items marked is_used false never support a pass verdict", async () => {
  const configuration = hardenedConfiguration();
  configuration.user_settings.is_enterprise_sso_required = { is_used: false, value: true };
  configuration.security.is_multi_factor_auth_required = { is_used: false, value: true };
  configuration.security.password_min_length = { is_used: false, value: 14 };
  configuration.security.session_duration = { is_used: false, value: "12 hours" };
  configuration.content_and_sharing.external_collaboration_status = { is_used: false, value: "limit_collaboration_to_users_within_enterprise" };
  configuration.content_and_sharing.shared_link_access = { is_used: false, value: "company" };
  configuration.content_and_sharing.is_shared_links_expiration_enabled = { is_used: false, value: true };
  configuration.content_and_sharing.is_watermarking_enterprise_feature_enabled = { is_used: false, value: true };

  const identity = await assessBoxIdentityAccess(createStubClient({ ...hardenedFixture(), configuration }));
  assertStatuses(identity, { "BOX-01": "warn", "BOX-02": "warn", "BOX-03": "warn", "BOX-21": "warn", "BOX-22": "warn" });
  for (const id of ["BOX-01", "BOX-02", "BOX-03", "BOX-21", "BOX-22"]) {
    const found = findingById(identity, id);
    assert.match(found.summary, /not in use for this enterprise \(is_used false\)/, `${id} should explain the is_used state`);
    assert.ok(found.manualEvidence, `${id} should point at the Admin Console evidence`);
  }
  const sso = findingById(identity, "BOX-01");
  assert.match(sso.summary, /is_enterprise_sso_required \(reported value true\)/);
  assert.equal(sso.evidence.is_enterprise_sso_required, null);
  assert.deepEqual(sso.evidence.is_used, { is_enterprise_sso_required: false, is_enterprise_sso_in_testing: true });
  assert.deepEqual(sso.evidence.unused_settings, { is_enterprise_sso_required: true });
  const adminMfa = findingById(identity, "BOX-02");
  assert.equal(adminMfa.evidence.is_used.is_multi_factor_auth_required, false);
  assert.deepEqual(adminMfa.evidence.unused_settings, { is_multi_factor_auth_required: true });
  assert.equal(findingById(identity, "BOX-21").evidence.password_min_length, null);
  assert.deepEqual(findingById(identity, "BOX-22").evidence.unused_settings, { session_duration: "12 hours" });
  assert.equal(identity.summary.sso_required, null);
  assert.equal(identity.summary.mfa_required, null);

  const sharing = await assessBoxSharingCollaboration(createStubClient({ ...hardenedFixture(), configuration }));
  assertStatuses(sharing, { "BOX-04": "warn", "BOX-05": "pass", "BOX-06": "warn", "BOX-07": "warn", "BOX-09": "warn" });
  for (const id of ["BOX-04", "BOX-06", "BOX-07", "BOX-09"]) {
    assert.match(findingById(sharing, id).summary, /is_used false/, `${id} should explain the is_used state`);
  }
  assert.deepEqual(findingById(sharing, "BOX-06").evidence.unused_settings, { shared_link_access: "company" });
  assert.equal(findingById(sharing, "BOX-06").evidence.is_used.shared_link_default_access, true);
  assert.equal(sharing.summary.external_collaboration_status, null);

  const noUsers = await assessBoxIdentityAccess(createStubClient({ ...hardenedFixture(), configuration }, { listUsers: forbidden() }));
  assertStatuses(noUsers, { "BOX-02": "manual", "BOX-03": "manual" });
  assert.match(findingById(noUsers, "BOX-02").summary, /enterprise MFA is reported but not in use \(is_used false\)/);

  const hardened = await assessBoxIdentityAccess(createStubClient(hardenedFixture()));
  assert.deepEqual(findingById(hardened, "BOX-01").evidence.is_used, { is_enterprise_sso_required: true, is_enterprise_sso_in_testing: true });
  assert.deepEqual(findingById(hardened, "BOX-01").evidence.unused_settings, {});

  const unusedSecondary = hardenedConfiguration();
  unusedSecondary.user_settings.is_enterprise_sso_in_testing = { is_used: false, value: true };
  unusedSecondary.security.is_custom_session_duration_enabled = { is_used: false, value: true };
  unusedSecondary.security.custom_session_duration_value = { is_used: false, value: "30 days" };
  const secondary = await assessBoxIdentityAccess(createStubClient({ ...hardenedFixture(), configuration: unusedSecondary }));
  assertStatuses(secondary, { "BOX-01": "pass", "BOX-22": "pass" });
  assert.equal(findingById(secondary, "BOX-01").evidence.is_enterprise_sso_in_testing, null);
  assert.deepEqual(findingById(secondary, "BOX-22").evidence.unused_settings, { is_custom_session_duration_enabled: true, custom_session_duration_value: "30 days" });
});

test("assessBoxSharingCollaboration and assessBoxShieldMonitoring treat null categories as absent data", async () => {
  const sharing = await assessBoxSharingCollaboration(createStubClient({
    ...hardenedFixture(),
    configuration: { id: "123456", type: "enterprise_configuration", security: null, content_and_sharing: null, user_settings: null },
  }));
  assertStatuses(sharing, { "BOX-04": "warn", "BOX-05": "pass", "BOX-06": "manual", "BOX-07": "manual", "BOX-08": "manual", "BOX-09": "manual", "BOX-20": "pass" });
  assert.match(findingById(sharing, "BOX-04").summary, /content_and_sharing category was returned as null/);
  assert.match(findingById(sharing, "BOX-06").summary, /content_and_sharing category was returned as null/);
  assert.deepEqual(sharing.errors, []);

  const noAllowlist = await assessBoxSharingCollaboration(createStubClient({
    ...hardenedFixture(),
    configuration: { id: "123456", type: "enterprise_configuration", content_and_sharing: null },
    allowlistEntries: [],
  }));
  assertStatuses(noAllowlist, { "BOX-04": "manual" });

  const missingExpiration = await assessBoxSharingCollaboration(createStubClient({
    ...hardenedFixture(),
    configuration: { id: "123456", type: "enterprise_configuration", content_and_sharing: { shared_link_default_access: item("collaborators") } },
  }));
  assertStatuses(missingExpiration, { "BOX-07": "warn" });
  assert.match(findingById(missingExpiration, "BOX-07").summary, /did not expose is_shared_links_expiration_enabled/);

  const shield = await assessBoxShieldMonitoring(createStubClient({
    ...hardenedFixture(),
    configuration: { id: "123456", type: "enterprise_configuration", shield: null },
  }));
  assertStatuses(shield, { "BOX-14": "manual", "BOX-15": "pass", "BOX-16": "pass", "BOX-25": "pass" });
  assert.match(findingById(shield, "BOX-14").summary, /shield category was returned as null/);
  assert.equal(findingById(shield, "BOX-25").evidence.anomaly_detection_rules, null);

  const quietShield = await assessBoxShieldMonitoring(createStubClient({
    ...weakFixture(),
    configuration: { id: "123456", type: "enterprise_configuration", shield: null },
  }));
  assertStatuses(quietShield, { "BOX-14": "manual", "BOX-25": "warn" });
  assert.match(findingById(quietShield, "BOX-25").summary, /Shield rule configuration could not be read/);

  const noEvents = await assessBoxShieldMonitoring(createStubClient(weakFixture(), {
    listEnterpriseEvents: forbidden("admin_logs requires report permissions"),
  }));
  assertStatuses(noEvents, { "BOX-14": "fail", "BOX-16": "manual", "BOX-25": "warn" });
  assert.match(findingById(noEvents, "BOX-25").summary, /event stream could not be read/);
});

test("assessBoxSharingCollaboration passes with restricted collaboration, links, watermarking, and terms", async () => {
  const result = await assessBoxSharingCollaboration(createStubClient(hardenedFixture()));
  assert.equal(result.area, "sharing_collaboration");
  assert.deepEqual(result.findings.map((entry) => entry.id), ["BOX-04", "BOX-05", "BOX-06", "BOX-07", "BOX-08", "BOX-09", "BOX-19", "BOX-20"]);
  assertStatuses(result, {
    "BOX-04": "pass",
    "BOX-05": "pass",
    "BOX-06": "pass",
    "BOX-07": "pass",
    "BOX-08": "manual",
    "BOX-09": "pass",
    "BOX-19": "manual",
    "BOX-20": "pass",
  });
  assertMappings(result);
  assert.match(findingById(result, "BOX-08").manualEvidence, /Shared Links/);
  assert.match(findingById(result, "BOX-19").manualEvidence, /Custom Apps Manager/);
  assert.equal(findingById(result, "BOX-19").evidence.integration_shield_lists[0], "Approved integrations");
  assert.equal(result.summary.external_collaboration_status, "limit_collaboration_to_allowlisted_domains");
  assert.equal(result.summary.allowlist_entries, 1);
  assert.equal(result.summary.managed_terms_enabled, 1);
  assert.deepEqual(result.errors, []);
});

test("assessBoxSharingCollaboration fails open collaboration, public allowlist domains, open links, and missing terms", async () => {
  const result = await assessBoxSharingCollaboration(createStubClient(weakFixture()), { staleAllowlistDays: 365 });
  assertStatuses(result, {
    "BOX-04": "fail",
    "BOX-05": "fail",
    "BOX-06": "fail",
    "BOX-07": "fail",
    "BOX-08": "manual",
    "BOX-09": "fail",
    "BOX-19": "manual",
    "BOX-20": "fail",
  });
  assertMappings(result);
  assert.deepEqual(findingById(result, "BOX-05").evidence.public_email_domains, ["gmail.com"]);
  assert.equal(findingById(result, "BOX-05").evidence.stale_entries.length, 2);
  assert.match(findingById(result, "BOX-06").summary, /public links/);
  assert.match(findingById(result, "BOX-20").summary, /No custom terms of service/);

  const staleOnly = await assessBoxSharingCollaboration(createStubClient({
    ...hardenedFixture(),
    allowlistEntries: [{ id: "entry-1", type: "collaboration_whitelist_entry", domain: "old-partner.example", direction: "both", created_at: "2019-01-01T00:00:00Z" }],
  }));
  assertStatuses(staleOnly, { "BOX-04": "pass", "BOX-05": "warn" });

  const unreadable = await assessBoxSharingCollaboration(createStubClient(hardenedFixture(), {
    getEnterpriseConfiguration: forbidden(),
    listCollaborationAllowlistEntries: forbidden(),
    listTermsOfServices: forbidden(),
  }));
  assertStatuses(unreadable, { "BOX-04": "manual", "BOX-05": "manual", "BOX-06": "manual", "BOX-07": "manual", "BOX-09": "manual", "BOX-20": "manual" });
  assert.equal(unreadable.errors.length, 3);
});

test("assessBoxSharingCollaboration warns on allowlist entries without a usable created_at instead of treating them as fresh", async () => {
  const entry = (id, domain, overrides = {}) => ({ id, type: "collaboration_whitelist_entry", domain, direction: "both", created_at: "2026-06-01T00:00:00Z", ...overrides });
  const undated = await assessBoxSharingCollaboration(createStubClient({
    ...hardenedFixture(),
    allowlistEntries: [
      entry("entry-1", "partner.example"),
      { id: "entry-2", type: "collaboration_whitelist_entry", domain: "missing-date.example", direction: "inbound" },
      entry("entry-3", "garbage-date.example", { created_at: "not-a-date" }),
      entry("entry-4", "null-date.example", { created_at: null }),
    ],
  }));
  assertStatuses(undated, { "BOX-04": "pass", "BOX-05": "warn" });
  const allowlist = findingById(undated, "BOX-05");
  assert.match(allowlist.summary, /^3 allowlist entries have a missing or unparseable created_at/);
  assert.match(allowlist.summary, /age cannot be assessed/);
  assert.doesNotMatch(allowlist.summary, /older than/);
  assert.deepEqual(allowlist.evidence.undated_entries, [
    "missing-date.example (created_at: missing)",
    'garbage-date.example (created_at: "not-a-date")',
    "null-date.example (created_at: null)",
  ]);
  assert.deepEqual(allowlist.evidence.stale_entries, []);
  assert.match(allowlist.manualEvidence, /record the creation date of any undated entry/);
  assert.equal(undated.summary.undated_allowlist_entries, 3);
  assert.equal(undated.summary.stale_allowlist_entries, 0);

  const mixed = await assessBoxSharingCollaboration(createStubClient({
    ...hardenedFixture(),
    allowlistEntries: [
      entry("entry-1", "old-partner.example", { created_at: "2019-01-01T00:00:00Z" }),
      entry("entry-2", "undated.example", { created_at: "" }),
    ],
    exemptTargets: [{ id: "exempt-1", type: "collaboration_whitelist_exempt_target", user: { id: "member-1", type: "user" } }],
  }));
  assertStatuses(mixed, { "BOX-05": "warn" });
  assert.match(findingById(mixed, "BOX-05").summary, /^1 allowlist entries are older than 365 days; 1 allowlist entries have a missing or unparseable created_at .*; 1 users are exempt from domain restrictions; review them/);

  const dated = await assessBoxSharingCollaboration(createStubClient(hardenedFixture()));
  assertStatuses(dated, { "BOX-05": "pass" });
  assert.deepEqual(findingById(dated, "BOX-05").evidence.undated_entries, []);
  assert.match(findingById(dated, "BOX-05").summary, /1 allowlist entries are dated, recent, non-public domains/);

  const publicWins = await assessBoxSharingCollaboration(createStubClient({
    ...hardenedFixture(),
    allowlistEntries: [{ id: "entry-1", type: "collaboration_whitelist_entry", domain: "gmail.com", direction: "both" }],
  }));
  assertStatuses(publicWins, { "BOX-05": "fail" });
  assert.equal(findingById(publicWins, "BOX-05").evidence.undated_entries.length, 1);
});

test("assessBoxDataGovernance passes with classification, retention, and legal hold coverage", async () => {
  const result = await assessBoxDataGovernance(createStubClient(hardenedFixture()));
  assert.equal(result.area, "data_governance");
  assert.deepEqual(result.findings.map((entry) => entry.id), ["BOX-10", "BOX-11", "BOX-12", "BOX-13"]);
  assertStatuses(result, {
    "BOX-10": "manual",
    "BOX-11": "pass",
    "BOX-12": "pass",
    "BOX-13": "pass",
  });
  assertMappings(result);
  assert.equal(findingById(result, "BOX-10").evidence.device_pins, 1);
  assert.match(findingById(result, "BOX-10").manualEvidence, /Device Trust/);
  assert.deepEqual(findingById(result, "BOX-11").evidence.classifications, ["Public", "Internal", "Confidential"]);
  assert.equal(findingById(result, "BOX-12").evidence.retention_policies[0].assignments, 1);
  assert.equal(result.summary.assigned_legal_hold_policies, 1);
  assert.deepEqual(result.errors, []);
});

test("assessBoxDataGovernance flags missing pins, classifications, retention, and unreadable legal holds", async () => {
  const notFound = async () => {
    throw new BoxApiError("Box request failed (404 Not Found): Not Found", 404, "not_found");
  };
  const result = await assessBoxDataGovernance(createStubClient(weakFixture(), {
    getClassificationTemplate: notFound,
    listLegalHoldPolicies: forbidden("manage_legal_holds scope missing"),
  }));
  assertStatuses(result, {
    "BOX-10": "warn",
    "BOX-11": "fail",
    "BOX-12": "fail",
    "BOX-13": "manual",
  });
  assertMappings(result);
  assert.match(findingById(result, "BOX-11").summary, /No classification labels/);
  assert.match(findingById(result, "BOX-13").summary, /manage_legal_holds/);
  assert.ok(result.errors.some((entry) => entry.startsWith("classification_template: ")));
  assert.ok(result.errors.some((entry) => entry.startsWith("legal_hold_policies: ")));

  const unassigned = await assessBoxDataGovernance(createStubClient({
    ...hardenedFixture(),
    retentionPolicies: [{ id: "retention-1", type: "retention_policy", policy_name: "Unassigned", status: "active", assignment_counts: { enterprise: 0, folder: 0, metadata_template: 0 } }],
    retentionAssignments: [],
    legalHoldPolicies: [],
  }));
  assertStatuses(unassigned, { "BOX-12": "warn", "BOX-13": "warn" });
});

test("assessBoxShieldMonitoring passes with Shield rules, barriers, streamed events, and anomaly detection", async () => {
  const result = await assessBoxShieldMonitoring(createStubClient(hardenedFixture()), { lookbackDays: 30 });
  assert.equal(result.area, "shield_monitoring");
  assert.deepEqual(result.findings.map((entry) => entry.id), ["BOX-14", "BOX-15", "BOX-16", "BOX-25"]);
  assertStatuses(result, {
    "BOX-14": "pass",
    "BOX-15": "pass",
    "BOX-16": "pass",
    "BOX-25": "pass",
  });
  assertMappings(result);
  assert.equal(findingById(result, "BOX-14").evidence.shield_rules.length, 2);
  assert.equal(findingById(result, "BOX-15").evidence.barriers[0].segments, 1);
  assert.equal(findingById(result, "BOX-25").evidence.anomaly_events, 1);
  assert.equal(result.summary.sampled_events, 2);
  assert.deepEqual(result.errors, []);

  const streaming = findingById(result, "BOX-16");
  assert.match(streaming.summary, /^Verified only that the enterprise admin_logs event stream is active and readable/);
  assert.match(streaming.summary, /SIEM consumption still requires the manual evidence/);
  assert.match(streaming.manualEvidence, /SIEM/);
  assert.match(streaming.manualEvidence, /stream_position/);
  assert.equal(streaming.evidence.siem_consumption_verified, false);
  assert.equal(streaming.evidence.verified_scope, "admin_logs stream readability only");
});

test("assessBoxShieldMonitoring fails when Shield rules and monitoring signals are absent", async () => {
  const result = await assessBoxShieldMonitoring(createStubClient(weakFixture()));
  assertStatuses(result, {
    "BOX-14": "fail",
    "BOX-15": "warn",
    "BOX-16": "warn",
    "BOX-25": "fail",
  });
  assertMappings(result);
  assert.match(findingById(result, "BOX-16").summary, /returned no monitoring events/);
  assert.match(findingById(result, "BOX-16").manualEvidence, /SIEM/);

  const unreadable = await assessBoxShieldMonitoring(createStubClient(weakFixture(), {
    getEnterpriseConfiguration: forbidden("Shield not licensed"),
    listShieldInformationBarriers: forbidden(),
    listEnterpriseEvents: forbidden("admin_logs requires report permissions"),
  }));
  assertStatuses(unreadable, {
    "BOX-14": "manual",
    "BOX-15": "manual",
    "BOX-16": "manual",
    "BOX-25": "manual",
  });
  assert.match(findingById(unreadable, "BOX-16").manualEvidence, /SIEM/);
  // Three denied reads plus the segment reads that were never requested because the barrier listing was denied.
  assert.equal(unreadable.errors.length, 4);
  assert.ok(unreadable.errors.some((entry) => /^shield_information_barrier_segments: not requested because the parent listing could not be read$/.test(entry)));
});

test("exportBoxAuditBundle writes core data, analysis, compliance reports, and a zip archive", async () => {
  const base = createTempBase("grclanker-box-export-");
  const result = await exportBoxAuditBundle(createStubClient(hardenedFixture()), sampleConfig(), base);

  assert.ok(existsSync(result.outputDir));
  assert.ok(result.outputDir.startsWith(base));
  assert.match(result.outputDir, /123456-audit-bundle$/);
  assert.ok(existsSync(result.zipPath));
  assert.match(result.zipPath, /123456-audit-bundle\.zip$/);
  assert.equal(result.findingCount, 25);
  assert.equal(result.errorCount, 0);
  assert.equal(result.fileCount, 40);
  assert.equal(existsSync(join(result.outputDir, "_errors.log")), false);

  const expectedFiles = [
    "QUICK_REFERENCE.md",
    "metadata.json",
    "core_data/access_check.json",
    "core_data/collection_status.json",
    "core_data/current_user.json",
    "core_data/enterprise_configuration.json",
    "core_data/users.json",
    "core_data/groups.json",
    "core_data/enterprise_events_activity.json",
    "core_data/enterprise_events_sharing.json",
    "core_data/enterprise_events_shield.json",
    "core_data/device_pinners.json",
    "core_data/classification_template.json",
    "core_data/metadata_templates.json",
    "core_data/retention_policies.json",
    "core_data/retention_policy_assignments.json",
    "core_data/legal_hold_policies.json",
    "core_data/legal_hold_policy_assignments.json",
    "core_data/shield_information_barriers.json",
    "core_data/shield_information_barrier_segments.json",
    "core_data/shield_lists.json",
    "core_data/collaboration_allowlist_entries.json",
    "core_data/collaboration_allowlist_exempt_targets.json",
    "core_data/terms_of_services.json",
    "analysis/findings.json",
    "analysis/summary.json",
    "analysis/identity_access.json",
    "analysis/sharing_collaboration.json",
    "analysis/data_governance.json",
    "analysis/shield_monitoring.json",
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
  ];
  for (const relativePath of expectedFiles) {
    assert.ok(existsSync(join(result.outputDir, relativePath)), `missing ${relativePath}`);
  }

  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis/findings.json"), "utf8"));
  assert.equal(findings.length, 25);
  const ids = findings.map((entry) => entry.id).sort();
  assert.deepEqual(ids, Array.from({ length: 25 }, (_, index) => `BOX-${String(index + 1).padStart(2, "0")}`));
  assert.ok(findings.every((entry) => entry.mappings.length === 8));

  const summary = JSON.parse(readFileSync(join(result.outputDir, "analysis/summary.json"), "utf8"));
  assert.equal(summary.controls_assessed, 25);
  assert.equal(summary.enterprise_id, "123456");
  assert.equal(summary.auth_mode, "ccg");
  assert.deepEqual(summary.truncated_datasets, []);

  const collectionStatus = JSON.parse(readFileSync(join(result.outputDir, "core_data/collection_status.json"), "utf8"));
  assert.equal(collectionStatus.datasets.length, 20);
  assert.ok(collectionStatus.datasets.every((entry) => entry.complete === true && entry.truncated === false && entry.error === null));
  const usersStatus = collectionStatus.datasets.find((entry) => entry.file === "core_data/users.json");
  assert.equal(usersStatus.count, 4);
  assert.equal(collectionStatus.datasets.find((entry) => entry.file === "core_data/retention_policy_assignments.json").count, 1);
  assert.deepEqual(collectionStatus.truncated_datasets, []);

  const executive = readFileSync(join(result.outputDir, "compliance/executive_summary.md"), "utf8");
  assert.match(executive, /Controls assessed: 25 of 25/);
  assert.match(executive, /Manual Evidence Required/);
  assert.doesNotMatch(executive, /client-secret/);

  const matrix = readFileSync(join(result.outputDir, "compliance/unified_compliance_matrix.md"), "utf8");
  assert.match(matrix, /\| Control \| Title \| FedRAMP \| CMMC \| SOC 2 \| CIS \| PCI-DSS \| STIG \| IRAP \| ISMAP \| Status \|/);
  assert.match(matrix, /\| BOX-01 \| SSO enforcement \| IA-2 \| AC\.L2-3\.1\.1 \| CC6\.1 \| 1\.1 \| 8\.3\.1 \| SRG-APP-000148 \| ISM-1557 \| CPS-04 \| PASS \|/);

  const fedramp = readFileSync(join(result.outputDir, "compliance/fedramp/fedramp_compliance_report.md"), "utf8");
  assert.match(fedramp, /^# FedRAMP \/ NIST 800-53 Compliance Report/);
  assert.match(fedramp, /\| BOX-25 \| Content access monitoring \| AU-6 \|/);

  const configuration = JSON.parse(readFileSync(join(result.outputDir, "core_data/enterprise_configuration.json"), "utf8"));
  assert.equal(configuration.security.is_multi_factor_auth_required.value, true);
  assert.equal(configuration.shield.shield_rules.length, 2);

  const firstZipSize = statSync(result.zipPath).size;
  const second = await exportBoxAuditBundle(createStubClient(hardenedFixture()), sampleConfig(), base);
  assert.match(second.outputDir, /123456-audit-bundle-2$/);
  assert.match(second.zipPath, /123456-audit-bundle-2\.zip$/);
  assert.notEqual(second.zipPath, result.zipPath, "a rerun must not overwrite the previous archive");
  assert.ok(existsSync(result.zipPath));
  assert.ok(existsSync(second.zipPath));
  assert.equal(statSync(result.zipPath).size, firstZipSize, "the first archive is untouched by the rerun");

  rmSync(result.outputDir, { recursive: true, force: true });
  const third = await exportBoxAuditBundle(createStubClient(hardenedFixture()), sampleConfig(), base);
  assert.match(third.outputDir, /123456-audit-bundle-3$/, "a kept archive reserves its suffix even after its directory is removed");
  assert.match(third.zipPath, /123456-audit-bundle-3\.zip$/);
  assert.ok(existsSync(result.zipPath));
});

test("exportBoxAuditBundle records partial collection failures in _errors.log", async () => {
  const base = createTempBase("grclanker-box-export-errors-");
  const result = await exportBoxAuditBundle(createStubClient(hardenedFixture(), {
    listRetentionPolicies: forbidden("manage_data_retention scope missing"),
    listShieldInformationBarriers: forbidden(),
  }), sampleConfig(), base);

  assert.ok(existsSync(result.zipPath));
  assert.equal(result.findingCount, 25);
  // Two denied reads plus the two child reads that were never requested because their parent listing was denied.
  assert.equal(result.errorCount, 4);
  const errorLog = readFileSync(join(result.outputDir, "_errors.log"), "utf8");
  assert.match(errorLog, /retention_policies: .*manage_data_retention/);
  assert.match(errorLog, /retention_policy_assignments: not requested because the parent listing could not be read/);
  assert.match(errorLog, /shield_information_barriers: /);
  assert.match(errorLog, /shield_information_barrier_segments: not requested because the parent listing could not be read/);

  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis/findings.json"), "utf8"));
  assert.equal(findings.find((entry) => entry.id === "BOX-12").status, "manual");
  assert.equal(findings.find((entry) => entry.id === "BOX-15").status, "manual");
  const executive = readFileSync(join(result.outputDir, "compliance/executive_summary.md"), "utf8");
  assert.match(executive, /Partial Collection Warnings/);
  assert.doesNotMatch(executive, /Truncated Datasets/);

  const collectionStatus = JSON.parse(readFileSync(join(result.outputDir, "core_data/collection_status.json"), "utf8"));
  const retentionStatus = collectionStatus.datasets.find((entry) => entry.file === "core_data/retention_policies.json");
  assert.equal(retentionStatus.collected, false);
  assert.equal(retentionStatus.status, "denied");
  assert.equal(retentionStatus.complete, null);
  assert.equal(retentionStatus.truncated, null);
  assert.equal(retentionStatus.count, null);
  assert.equal(retentionStatus.status_code, 403);
  assert.match(retentionStatus.error, /manage_data_retention/);
  const assignmentStatus = collectionStatus.datasets.find((entry) => entry.file === "core_data/retention_policy_assignments.json");
  assert.equal(assignmentStatus.collected, false);
  assert.equal(assignmentStatus.status, "not-requested");
  assert.equal(assignmentStatus.count, null);

  const deniedSnapshot = JSON.parse(readFileSync(join(result.outputDir, "core_data/retention_policies.json"), "utf8"));
  assert.equal(deniedSnapshot.collected, false);
  assert.equal(deniedSnapshot.status, 403);
  assert.equal(deniedSnapshot.reason, "not_readable");
  const notRequestedSnapshot = JSON.parse(readFileSync(join(result.outputDir, "core_data/retention_policy_assignments.json"), "utf8"));
  assert.deepEqual(notRequestedSnapshot, { collected: false, status: "not-collected", endpoint: null, error: null, reason: "not_requested" });
});

test("exportBoxAuditBundle records truncated snapshots without counting them as errors", async () => {
  const base = createTempBase("grclanker-box-export-truncated-");
  const fixture = hardenedFixture();
  const usersTruncation = { reason: "the 4-record cap was reached while the server offered a next marker", capReached: true };
  const result = await exportBoxAuditBundle(createStubClient(fixture, {
    listUsers: async () => ({ items: fixture.users, truncated: true, truncation: usersTruncation }),
    listGroups: truncatedList(fixture.groups),
  }), sampleConfig(), base);

  assert.equal(result.errorCount, 0);
  assert.equal(existsSync(join(result.outputDir, "_errors.log")), false);

  const collectionStatus = JSON.parse(readFileSync(join(result.outputDir, "core_data/collection_status.json"), "utf8"));
  const usersStatus = collectionStatus.datasets.find((entry) => entry.file === "core_data/users.json");
  assert.equal(usersStatus.truncated, true);
  assert.equal(usersStatus.complete, false);
  assert.equal(usersStatus.error, null);
  assert.equal(usersStatus.truncation_reason, usersTruncation.reason, "the status row carries the loader's reason beside the flag");
  const groupsStatus = collectionStatus.datasets.find((entry) => entry.file === "core_data/groups.json");
  assert.equal(groupsStatus.truncated, true);
  assert.equal(groupsStatus.truncation_reason, null, "a page that carried the flag alone has no reason to report");
  const activityStatus = collectionStatus.datasets.find((entry) => entry.file === "core_data/enterprise_events_activity.json");
  assert.equal(activityStatus.truncated, false);
  assert.equal(activityStatus.truncation_reason, null);
  assert.equal(collectionStatus.truncated_datasets.length, 2);
  assert.equal(collectionStatus.truncated_datasets[0], "users: collection stopped after 4 records because the 4-record cap was reached while the server offered a next marker; raise user_limit and rerun before treating absence as compliance");
  assert.match(collectionStatus.truncated_datasets[1], /^groups: collection stopped at the 1-record cap while the server reported more records; review the remainder in the Admin Console/);

  const summary = JSON.parse(readFileSync(join(result.outputDir, "analysis/summary.json"), "utf8"));
  assert.deepEqual(summary.truncated_datasets, collectionStatus.truncated_datasets);
  const identity = JSON.parse(readFileSync(join(result.outputDir, "analysis/identity_access.json"), "utf8"));
  assert.equal(identity.truncated.length, 1);
  assert.equal(identity.findings.find((entry) => entry.id === "BOX-17").status, "warn");
  const executive = readFileSync(join(result.outputDir, "compliance/executive_summary.md"), "utf8");
  assert.match(executive, /## Truncated Datasets/);
  assert.match(executive, /raise user_limit/);
  assert.doesNotMatch(executive, /Partial Collection Warnings/);
});

test("gap 36: Box redactCredentialValues keeps and scrubs every string down to depth 25 (inside the deepest kept container), masks the container at depth 25, and copies nothing from depth 26", () => {
  assertDepthCapPins(assert, redactCredentialValues, 24, "Box walker");
});

const MULTI_INVENTORY_CASES = [
  { id: "BOX-02", assess: assessBoxIdentityAccess, secondary: "listUsers", names: /users/ },
  { id: "BOX-02", assess: assessBoxIdentityAccess, secondary: "getEnterpriseConfiguration", names: /MFA settings/ },
  { id: "BOX-03", assess: assessBoxIdentityAccess, secondary: "listUsers", names: /users/ },
  { id: "BOX-03", assess: assessBoxIdentityAccess, secondary: "getEnterpriseConfiguration", names: /MFA settings/ },
  { id: "BOX-24", assess: assessBoxIdentityAccess, secondary: "listEnterpriseEvents", names: /events were unreadable/ },
  { id: "BOX-24", assess: assessBoxIdentityAccess, secondary: "listUsers", names: /users were unreadable/ },
  // The stub client's errors carry no request label, so the summaries name the inventory alone; the endpoint text
  // appears only when a real request failed (covered by the HTTP fixture tests below).
  { id: "BOX-04", assess: assessBoxSharingCollaboration, secondary: "listCollaborationAllowlistEntries", names: /collaboration_allowlist_entries could not be read/ },
  { id: "BOX-05", assess: assessBoxSharingCollaboration, secondary: "listCollaborationAllowlistExemptTargets", names: /collaboration_allowlist_exempt_targets could not be read/ },
  { id: "BOX-05", assess: assessBoxSharingCollaboration, secondary: "getEnterpriseConfiguration", names: /enterprise_configuration \(content_and_sharing\) could not be read/ },
  { id: "BOX-12", assess: assessBoxDataGovernance, secondary: "listRetentionPolicyAssignments", names: /retention_policy_assignments could not be read/ },
  { id: "BOX-13", assess: assessBoxDataGovernance, secondary: "listLegalHoldPolicyAssignments", names: /legal_hold_policy_assignments could not be read/ },
  { id: "BOX-15", assess: assessBoxShieldMonitoring, secondary: "listShieldInformationBarrierSegments", names: /shield_information_barrier_segments could not be read/ },
  { id: "BOX-25", assess: assessBoxShieldMonitoring, secondary: "getEnterpriseConfiguration", names: /enterprise_configuration \(shield\) could not be read/ },
  { id: "BOX-25", assess: assessBoxShieldMonitoring, secondary: "listEnterpriseEvents", names: /enterprise_events could not be read/ },
];

test("verdict rule 1 corollary: Box findings that read several inventories never pass while a secondary inventory is forbidden", async () => {
  for (const testCase of MULTI_INVENTORY_CASES) {
    const baseline = findingById(await testCase.assess(createStubClient(hardenedFixture())), testCase.id);
    assert.equal(baseline.status, "pass", `${testCase.id} must pass on the hardened fixture so the demotion below is meaningful`);

    const degraded = await testCase.assess(createStubClient(hardenedFixture(), { [testCase.secondary]: forbidden("scope missing") }));
    const found = findingById(degraded, testCase.id);
    assert.notEqual(found.status, "pass", `${testCase.id} passed while ${testCase.secondary} returned 403: ${found.summary}`);
    assert.ok(["warn", "manual"].includes(found.status), `${testCase.id} should be warn or manual, got ${found.status}`);
    assert.match(found.summary, testCase.names, `${testCase.id} summary must name the unreadable inventory when ${testCase.secondary} is forbidden`);
    assert.ok(found.manualEvidence, `${testCase.id} must tell a human what evidence to collect`);
    assert.ok(degraded.errors.some((entry) => /scope missing/.test(entry)), "the 403 is also disclosed in the errors array");
  }
});

const BOX_FAKE_SECRETS = [
  "FAKE_SECRET_TOKEN_1",
  "FAKE_SECRET_TOKEN_2",
  "FAKE_SECRET_TOKEN_3",
  "FAKE_SECRET_TOKEN_4",
  "FAKE_SECRET_TOKEN_5",
  "FAKE_SECRET_TOKEN_6",
  "FAKE_SECRET_TOKEN_7",
];

function secretBearingFixture() {
  const fixture = hardenedFixture();
  fixture.events[0].additional_details = { shared_link: "https://app.box.com/s/FAKE_SECRET_TOKEN_1", access_token: "FAKE_SECRET_TOKEN_2" };
  fixture.users[1].tracking_codes = [{ type: "tracking_code", name: "api_token", value: "FAKE_SECRET_TOKEN_3" }];
  fixture.configuration.security.sso_shared_secret = item("FAKE_SECRET_TOKEN_4");
  fixture.shieldLists[1].content.integrations[0].client_secret = "FAKE_SECRET_TOKEN_5";
  fixture.retentionPolicies[0].notification_webhook = "https://hooks.example.com/notify?token=FAKE_SECRET_TOKEN_6&policy=retention-1";
  fixture.groups[0].provisioning_password = "FAKE_SECRET_TOKEN_7";
  return fixture;
}

test("verdict rule 9: the Box bundle and its zip never carry credential-shaped values from any collected object", async () => {
  const base = createTempBase("grclanker-box-export-secrets-");
  const result = await exportBoxAuditBundle(createStubClient(secretBearingFixture()), sampleConfig(), base);

  const files = readBundleFiles(result.outputDir);
  assert.ok(files.size >= 40, `expected the full bundle layout, got ${files.size} files`);
  assertSecretsAbsent(assert, files, BOX_FAKE_SECRETS, "bundle directory");
  const zipEntries = readZipEntries(result.zipPath);
  assert.equal(zipEntries.size, files.size, "every written file is archived");
  assertSecretsAbsent(assert, zipEntries, BOX_FAKE_SECRETS, "zip archive");

  const events = JSON.parse(files.get("core_data/enterprise_events_activity.json"));
  assert.ok(events.length > 0);
  assert.ok(events.every((event) => event.additional_details === undefined), "events are projected to the fields the verdicts read");
  assert.equal(events[0].event_type, "ADMIN_LOGIN");
  assert.equal(events[0].created_by.id, "admin-1");

  const users = JSON.parse(files.get("core_data/users.json"));
  assert.deepEqual(users[1].tracking_codes, [{ type: "tracking_code", name: "api_token", value: "[REDACTED]" }], "pair-shaped credentials keep their name and lose their value");
  const configuration = JSON.parse(files.get("core_data/enterprise_configuration.json"));
  assert.equal(configuration.security.sso_shared_secret, "[REDACTED]");
  assert.equal(configuration.security.is_multi_factor_auth_required.value, true, "non-credential settings are untouched");
  const shieldLists = JSON.parse(files.get("core_data/shield_lists.json"));
  assert.equal(shieldLists[1].content.integrations[0].client_secret, "[REDACTED]");
  assert.equal(shieldLists[1].content.integrations[0].id, "app-1");
  const retention = JSON.parse(files.get("core_data/retention_policies.json"));
  assert.equal(retention[0].notification_webhook, "https://hooks.example.com/notify?[REDACTED]", "a URL keeps scheme, host, and path; its whole query is replaced by one marker");
  const groups = JSON.parse(files.get("core_data/groups.json"));
  assert.equal(groups[0].provisioning_password, "[REDACTED]");

  const findings = JSON.parse(files.get("analysis/findings.json"));
  assert.equal(findings.filter((entry) => entry.status === "pass").length, JSON.parse(readFileSync(join(result.outputDir, "analysis/summary.json"), "utf8")).status_counts.pass);
  assert.equal(result.errorCount, 0, "redaction never counts as a collection error");
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-box-path-");
  const outside = createTempBase("grclanker-box-outside-");
  const linked = join(base, "linked");
  symlinkSync(outside, linked, "dir");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, join("..", "sibling", "bundle")), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "linked/file.txt"), /symlinked parent directory/);

  const safe = resolveSecureOutputPath(base, join("reports", "safe.txt"));
  assert.match(safe, /reports\/safe\.txt$/);
});

test("exportBoxAuditBundle refuses to write through a planted symlink in the output root", async () => {
  const base = createTempBase("grclanker-box-export-symlink-");
  const outside = createTempBase("grclanker-box-export-outside-");
  symlinkSync(outside, join(base, "123456-audit-bundle"), "dir");

  await assert.rejects(
    () => exportBoxAuditBundle(createStubClient(hardenedFixture()), sampleConfig(), base),
    /symlinked parent directory/,
  );
  assert.equal(existsSync(join(outside, "QUICK_REFERENCE.md")), false);
});

test("Box control catalog covers all 25 spec controls with eight framework mappings each", () => {
  const controls = listBoxControls();
  assert.equal(controls.length, 25);
  assert.deepEqual(controls.map((entry) => entry.control), Array.from({ length: 25 }, (_, index) => index + 1));
  for (const entry of controls) {
    const mappings = mappingsForControl(entry.control);
    assert.equal(mappings.length, 8, `${entry.id} needs eight mappings`);
    FRAMEWORKS.forEach((framework, index) => assert.ok(mappings[index].startsWith(`${framework} `)));
  }
  const byArea = controls.reduce((counts, entry) => ({ ...counts, [entry.area]: (counts[entry.area] ?? 0) + 1 }), {});
  assert.deepEqual(byArea, { identity_access: 9, sharing_collaboration: 8, data_governance: 4, shield_monitoring: 4 });
  assert.deepEqual(mappingsForControl(99), []);

  assert.equal(parseDurationHours("12 hours"), 12);
  assert.equal(parseDurationHours("30 minutes"), 0.5);
  assert.equal(parseDurationHours("7 days"), 168);
  assert.equal(parseDurationHours("never"), Number.POSITIVE_INFINITY);
  assert.equal(parseDurationHours("24"), undefined, "a bare number has no documented unit");
  assert.equal(parseDurationHours("24h"), 24);
  assert.equal(parseDurationHours("1440 min"), 24);
  assert.equal(parseDurationHours(undefined), undefined);
  assert.equal(isUnitlessDuration("24"), true);
  assert.equal(isUnitlessDuration(" 1.5 "), true);
  assert.equal(isUnitlessDuration("24 hours"), false);
  assert.equal(isUnitlessDuration(undefined), false);
});

test("assessBoxIdentityAccess does not fail BOX-22 on a session duration without an explicit unit", async () => {
  const withDuration = (sessionDuration, extra = {}) => {
    const configuration = hardenedConfiguration();
    configuration.security.session_duration = item(sessionDuration);
    Object.assign(configuration.security, extra);
    return createStubClient({ ...hardenedFixture(), configuration });
  };

  const bare = await assessBoxIdentityAccess(withDuration("24"), { maxSessionHours: 12 });
  assertStatuses(bare, { "BOX-22": "warn" });
  assert.match(findingById(bare, "BOX-22").summary, /"24" has no explicit unit and Box does not document one/);
  assert.match(findingById(bare, "BOX-22").manualEvidence, /raw value "24"/);
  assert.equal(findingById(bare, "BOX-22").evidence.session_duration, "24");
  assert.equal(findingById(bare, "BOX-22").evidence.session_hours, null);

  const bareSmall = await assessBoxIdentityAccess(withDuration("1"), { maxSessionHours: 12 });
  assertStatuses(bareSmall, { "BOX-22": "warn" });

  const explicitPass = await assessBoxIdentityAccess(withDuration("24 hours"), { maxSessionHours: 24 });
  assertStatuses(explicitPass, { "BOX-22": "pass" });
  assert.equal(findingById(explicitPass, "BOX-22").evidence.session_hours, 24);

  const explicitFail = await assessBoxIdentityAccess(withDuration("2 days"), { maxSessionHours: 24 });
  assertStatuses(explicitFail, { "BOX-22": "fail" });
  assert.match(findingById(explicitFail, "BOX-22").summary, /2 days exceeds the 24-hour threshold/);

  const garbage = await assessBoxIdentityAccess(withDuration("until logout"));
  assertStatuses(garbage, { "BOX-22": "warn" });
  assert.match(findingById(garbage, "BOX-22").summary, /could not be interpreted as a duration/);

  const customBare = await assessBoxIdentityAccess(withDuration("8 hours", {
    is_custom_session_duration_enabled: item(true),
    custom_session_duration_value: item("48"),
  }), { maxSessionHours: 24 });
  assertStatuses(customBare, { "BOX-22": "warn" });
  assert.match(findingById(customBare, "BOX-22").summary, /custom group duration "48" has no explicit unit/);

  const customFail = await assessBoxIdentityAccess(withDuration("8 hours", {
    is_custom_session_duration_enabled: item(true),
    custom_session_duration_value: item("48 hours"),
  }), { maxSessionHours: 24 });
  assertStatuses(customFail, { "BOX-22": "fail" });
  assert.match(findingById(customFail, "BOX-22").summary, /custom group duration 48 hours exceeds 24 hours/);

  const customPass = await assessBoxIdentityAccess(withDuration("8 hours", {
    is_custom_session_duration_enabled: item(true),
    custom_session_duration_value: item("12 hours"),
  }), { maxSessionHours: 24 });
  assertStatuses(customPass, { "BOX-22": "pass" });
});

test("Box tools are registered in the tool catalog under the Box group", () => {
  const tools = getRegisteredToolSummaries().filter((tool) => tool.name.startsWith("box_"));
  assert.deepEqual(tools.map((tool) => tool.name).sort(), [
    "box_assess_data_governance",
    "box_assess_identity_access",
    "box_assess_sharing_collaboration",
    "box_assess_shield_monitoring",
    "box_check_access",
    "box_export_audit_bundle",
  ]);
  assert.ok(tools.every((tool) => tool.group === "Box"), tools.map((tool) => `${tool.name}=${tool.group}`).join(", "));
  assert.ok(tools.every((tool) => tool.kind === "domain"));
  const exportTool = tools.find((tool) => tool.name === "box_export_audit_bundle");
  assert.ok(exportTool.parameterSummaries.some((parameter) => parameter.name === "output_dir"));
  assert.ok(exportTool.parameterSummaries.some((parameter) => parameter.name === "jwt_config_path"));
  assert.match(exportTool.description, /FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, and ISMAP/);
});

// ---------------------------------------------------------------------------------------------------------------
// The real BoxApiClient over a fetch router, so the client's own read rules (shape guard, boundary scrub, paging)
// are what the assessments and the bundle see.
// ---------------------------------------------------------------------------------------------------------------

/** One marker-paged Box list response: entries from the numeric marker, and a next_marker while more remain. */
function boxMarkerPage(items, url) {
  const limit = Number(url.searchParams.get("limit") ?? "1000");
  const start = Number(url.searchParams.get("marker") ?? "0");
  const entries = items.slice(start, start + limit);
  const next = start + limit < items.length ? String(start + limit) : undefined;
  return jsonResponse({ entries, limit, ...(next === undefined ? {} : { next_marker: next }) });
}

/** One offset-paged Box list response. */
function boxOffsetPage(items, url) {
  const limit = Number(url.searchParams.get("limit") ?? "1000");
  const offset = Number(url.searchParams.get("offset") ?? "0");
  return jsonResponse({ entries: items.slice(offset, offset + limit), total_count: items.length, offset, limit });
}

const BOX_ROUTE_TEMPLATES = [
  ["POST /oauth2/token", /^\/oauth2\/token$/],
  ["GET /2.0/users/me", /^\/2\.0\/users\/me$/],
  ["GET /2.0/users", /^\/2\.0\/users$/],
  ["GET /2.0/groups", /^\/2\.0\/groups$/],
  ["GET /2.0/events", /^\/2\.0\/events$/],
  ["GET /2.0/enterprise_configurations/{enterprise}", /^\/2\.0\/enterprise_configurations\/([^/]+)$/],
  ["GET /2.0/enterprises/{enterprise}/device_pinners", /^\/2\.0\/enterprises\/([^/]+)\/device_pinners$/],
  ["GET /2.0/retention_policies", /^\/2\.0\/retention_policies$/],
  ["GET /2.0/retention_policies/{policy}/assignments", /^\/2\.0\/retention_policies\/([^/]+)\/assignments$/],
  ["GET /2.0/legal_hold_policies", /^\/2\.0\/legal_hold_policies$/],
  ["GET /2.0/legal_hold_policy_assignments", /^\/2\.0\/legal_hold_policy_assignments$/],
  ["GET /2.0/shield_information_barriers", /^\/2\.0\/shield_information_barriers$/],
  ["GET /2.0/shield_information_barrier_segments", /^\/2\.0\/shield_information_barrier_segments$/],
  ["GET /2.0/shield_lists", /^\/2\.0\/shield_lists$/],
  ["GET /2.0/collaboration_whitelist_entries", /^\/2\.0\/collaboration_whitelist_entries$/],
  ["GET /2.0/collaboration_whitelist_exempt_targets", /^\/2\.0\/collaboration_whitelist_exempt_targets$/],
  ["GET /2.0/metadata_templates/enterprise", /^\/2\.0\/metadata_templates\/enterprise$/],
  ["GET /2.0/metadata_templates/enterprise/{template}/schema", /^\/2\.0\/metadata_templates\/enterprise\/([^/]+)\/schema$/],
  ["GET /2.0/terms_of_services", /^\/2\.0\/terms_of_services$/],
];

/** One handler per Box surface; handlers receive the URL and the decoded path parameters. */
function boxRoutes(fixture) {
  return {
    "POST /oauth2/token": () => jsonResponse({ access_token: "router-issued-access-token-2026", expires_in: 3600, token_type: "bearer" }),
    "GET /2.0/users/me": () => jsonResponse({ id: "service-1", type: "user", name: "Audit Service", login: "AutomationUser_123@boxdevedition.com", role: "admin", enterprise: { id: "123456", type: "enterprise" } }),
    "GET /2.0/users": (url) => boxMarkerPage(fixture.users, url),
    "GET /2.0/groups": (url) => boxOffsetPage(fixture.groups, url),
    "GET /2.0/events": (url) => {
      const types = url.searchParams.get("event_type")?.split(",").filter(Boolean);
      const filtered = types && types.length > 0 ? fixture.events.filter((event) => types.includes(event.event_type)) : fixture.events;
      const limit = Number(url.searchParams.get("limit") ?? "500");
      const start = Number(url.searchParams.get("stream_position") ?? "0");
      const entries = filtered.slice(start, start + limit);
      return jsonResponse({ entries, chunk_size: entries.length, next_stream_position: String(start + entries.length) });
    },
    "GET /2.0/enterprise_configurations/{enterprise}": () => jsonResponse(fixture.configuration),
    "GET /2.0/enterprises/{enterprise}/device_pinners": (url) => boxMarkerPage(fixture.devicePinners, url),
    "GET /2.0/retention_policies": (url) => boxMarkerPage(fixture.retentionPolicies, url),
    "GET /2.0/retention_policies/{policy}/assignments": (url) => boxMarkerPage(fixture.retentionAssignments, url),
    "GET /2.0/legal_hold_policies": (url) => boxMarkerPage(fixture.legalHoldPolicies, url),
    "GET /2.0/legal_hold_policy_assignments": (url) => boxMarkerPage(fixture.legalHoldAssignments, url),
    "GET /2.0/shield_information_barriers": (url) => boxMarkerPage(fixture.barriers, url),
    "GET /2.0/shield_information_barrier_segments": (url) => boxMarkerPage(fixture.barrierSegments, url),
    "GET /2.0/shield_lists": () => jsonResponse({ entries: fixture.shieldLists }),
    "GET /2.0/collaboration_whitelist_entries": (url) => boxMarkerPage(fixture.allowlistEntries, url),
    "GET /2.0/collaboration_whitelist_exempt_targets": (url) => boxMarkerPage(fixture.exemptTargets, url),
    "GET /2.0/metadata_templates/enterprise": (url) => boxMarkerPage(fixture.metadataTemplates, url),
    "GET /2.0/metadata_templates/enterprise/{template}/schema": () => jsonResponse(fixture.classificationTemplate),
    "GET /2.0/terms_of_services": () => jsonResponse({ entries: fixture.termsOfServices }),
  };
}

/** The real BoxApiClient over a fetch router that records the method, path, URL, and status of every request served. */
function httpBox(fixture, options = {}) {
  const routes = { ...boxRoutes(fixture), ...(options.routes ?? {}) };
  const log = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(typeof input === "string" ? input : input.url);
    const method = (init.method ?? "GET").toUpperCase();
    const template = BOX_ROUTE_TEMPLATES.find(([name, pattern]) => name.startsWith(`${method} `) && pattern.test(url.pathname));
    let response;
    if (template) {
      const params = [...url.pathname.match(template[1])].slice(1).map(decodeURIComponent);
      response = await routes[template[0]](url, params, init);
    } else {
      response = jsonResponse({ type: "error", status: 404, code: "not_found", message: "Not Found" }, { status: 404, statusText: "Not Found" });
    }
    log.push({ method, path: url.pathname, url: url.toString(), host: url.host, status: response.status, authorization: headerValue(init.headers, "authorization") });
    return response;
  };
  const config = sampleConfig(options.config ?? {});
  const client = new BoxApiClient(config, { fetchImpl, now: () => NOW, sleep: async () => {} });
  return { client, config, log, routes, fetchImpl };
}

async function runAllBoxAssessments(client) {
  return [
    await assessBoxIdentityAccess(client),
    await assessBoxSharingCollaboration(client),
    await assessBoxDataGovernance(client),
    await assessBoxShieldMonitoring(client),
  ];
}

// ---------------------------------------------------------------------------------------------------------------
// Silent success: a 200 whose body is not the documented shape is a failed read, never an empty inventory.
// ---------------------------------------------------------------------------------------------------------------

/** Flattens a value into [dotted.path, leaf] pairs; arrays index as .0, .1, ... and empty containers are leaves. */
function boxLeafEntries(value, path = "", output = []) {
  if (Array.isArray(value)) {
    if (value.length === 0) output.push([path, "[]"]);
    value.forEach((entry, index) => boxLeafEntries(entry, path ? `${path}.${index}` : String(index), output));
  } else if (value !== null && typeof value === "object") {
    const keys = Object.keys(value);
    if (keys.length === 0) output.push([path, "{}"]);
    for (const key of keys) boxLeafEntries(value[key], path ? `${path}.${key}` : key, output);
  } else {
    output.push([path, value]);
  }
  return output;
}

function boxPluck(value, path) {
  return path.split(".").reduce((current, key) => (current === null || current === undefined ? undefined : current[key]), value);
}

const BOX_FALLBACK_VALUES = new Set([0, false, "none", "[]", "{}"]);

/** Fields that describe the read itself (read-state flags, unreadable inventories, caveats) and legitimately flip under a failed read. */
const BOX_READ_STATE_PATHS = [
  /(^|\.)[a-z_]*(complete|readable|observed|loaded|read|sampled|available|requested|collected|checked|truncated)$/,
  /^unreadable_inventories(\.|$)/,
  /^(pass|warn|fail|manual)$/,
  /(^|\.)(status_counts|counts)\.(pass|fail)$/,
];

/** True when a degraded-run value is a zero, false, or empty fallback where the all-readable baseline held real data. */
function isBoxFallback(path, value, baselineValue) {
  if (!BOX_FALLBACK_VALUES.has(value)) return false;
  if (baselineValue === undefined || baselineValue === null || BOX_FALLBACK_VALUES.has(baselineValue)) return false;
  if (Array.isArray(baselineValue) && baselineValue.length === 0) return false;
  if (typeof baselineValue === "object" && !Array.isArray(baselineValue) && Object.keys(baselineValue).length === 0) return false;
  return !BOX_READ_STATE_PATHS.some((pattern) => pattern.test(path));
}

/** A word planted in every silent body; any echo of the body into an output is caught by looking for it. */
const BOX_SILENT_MARKER = "SilentPortalMarkerZq";

/** The bodies a 200 can carry without being a Box answer, with the fixed note each must produce. */
const BOX_SILENT_BODIES = [
  { name: "empty body", response: () => new Response("", { status: 200, statusText: "OK" }), note: /returned 200( OK)? with an empty body \(0 bytes\); the endpoint is not serving the JSON API/ },
  { name: "HTML page", response: () => new Response(`<html><body><h1>Sign in</h1><p>${BOX_SILENT_MARKER}</p></body></html>`, { status: 200, statusText: "OK", headers: { "content-type": "text/html; charset=utf-8" } }), note: /returned 200( OK)? with a non-JSON text\/html; charset=utf-8 response body \(\d+ bytes, not echoed\); the endpoint is not serving the JSON API/ },
  { name: "foreign JSON object", response: () => jsonResponse({ status: "ok", service: BOX_SILENT_MARKER, version: "3.2.1" }), note: /returned 200( OK)? with a JSON body that is not the documented (list object with an entries array|resource object with any of [A-Za-z_, ]+) \(\d+ bytes, not echoed\); the endpoint is not serving the JSON API/ },
  { name: "JSON array", response: () => jsonResponse([{ id: BOX_SILENT_MARKER, type: "user" }]), note: /returned 200( OK)? with a JSON body that is not the documented (list object with an entries array|resource object with any of [A-Za-z_, ]+) \(\d+ bytes, not echoed\)/ },
];

/** Every dataset the bundle writes, with the route that serves it; `verdicts` marks the datasets at least one finding reads. */
const BOX_SILENT_DATASETS = [
  { file: "core_data/users.json", route: "GET /2.0/users", inventory: "users", surface: "users", verdicts: true },
  { file: "core_data/groups.json", route: "GET /2.0/groups", inventory: "groups", surface: "groups" },
  { file: "core_data/enterprise_events_activity.json", route: "GET /2.0/events", inventory: "enterprise_events", surface: "enterprise_events", verdicts: true },
  { file: "core_data/device_pinners.json", route: "GET /2.0/enterprises/{enterprise}/device_pinners", inventory: "device_pinners", surface: "device_pinners" },
  { file: "core_data/classification_template.json", route: "GET /2.0/metadata_templates/enterprise/{template}/schema", inventory: "classification_template", surface: "classification_template", verdicts: true },
  { file: "core_data/metadata_templates.json", route: "GET /2.0/metadata_templates/enterprise", inventory: "metadata_templates", surface: "metadata_templates" },
  { file: "core_data/retention_policies.json", route: "GET /2.0/retention_policies", inventory: "retention_policies", surface: "retention_policies", verdicts: true },
  { file: "core_data/legal_hold_policies.json", route: "GET /2.0/legal_hold_policies", inventory: "legal_hold_policies", surface: "legal_hold_policies", verdicts: true },
  { file: "core_data/shield_information_barriers.json", route: "GET /2.0/shield_information_barriers", inventory: "shield_information_barriers", surface: "shield_information_barriers", verdicts: true },
  { file: "core_data/shield_lists.json", route: "GET /2.0/shield_lists", inventory: "shield_lists", surface: "shield_lists" },
  { file: "core_data/collaboration_allowlist_entries.json", route: "GET /2.0/collaboration_whitelist_entries", inventory: "collaboration_allowlist_entries", surface: "collaboration_allowlist_entries", verdicts: true },
  { file: "core_data/collaboration_allowlist_exempt_targets.json", route: "GET /2.0/collaboration_whitelist_exempt_targets", inventory: "collaboration_allowlist_exempt_targets", surface: "collaboration_allowlist_exempt_targets", verdicts: true },
  { file: "core_data/terms_of_services.json", route: "GET /2.0/terms_of_services", inventory: "terms_of_services", surface: "terms_of_services", verdicts: true },
  { file: "core_data/enterprise_configuration.json", route: "GET /2.0/enterprise_configurations/{enterprise}", inventory: "enterprise_configuration", surface: "enterprise_configuration", verdicts: true },
];

test("verdict rule 1 (silent success): BoxApiClient treats a 200 with an empty, HTML, foreign-JSON, or array body as a failed read with http_status 200 and a fixed note, never as an empty inventory", async () => {
  for (const variant of BOX_SILENT_BODIES) {
    const { client } = httpBox(hardenedFixture(), { routes: { "GET /2.0/users": () => variant.response(), "GET /2.0/users/me": () => variant.response() } });
    await assert.rejects(client.listUsers(10), (error) => {
      assert.ok(error instanceof BoxApiError, `${variant.name}: the read fails as an API error`);
      assert.equal(error.status, 200, `${variant.name}: the observed 200 travels with the error`);
      assert.match(error.request, /^GET \/2\.0\/users\?/, `${variant.name}: the error names the request that was made`);
      assert.match(error.message, variant.note, `${variant.name}: the message is the fixed note`);
      assert.ok(!error.message.includes(BOX_SILENT_MARKER) && !error.message.includes("3.2.1") && !error.message.includes("Sign in"), `${variant.name}: nothing from the body is echoed`);
      return true;
    });
    await assert.rejects(client.getCurrentUser(), (error) => {
      assert.ok(error instanceof BoxApiError);
      assert.equal(error.status, 200, `${variant.name}: a single-resource read is guarded the same way`);
      assert.ok(!error.message.includes(BOX_SILENT_MARKER));
      return true;
    });
  }

  // A silent token endpoint is a failed authentication, not an access token of undefined.
  const { client: noToken } = httpBox(hardenedFixture(), { routes: { "POST /oauth2/token": () => jsonResponse({ status: "ok", service: BOX_SILENT_MARKER }) } });
  await assert.rejects(noToken.listUsers(10), (error) => {
    assert.ok(error instanceof BoxApiError);
    assert.equal(error.status, 200);
    assert.match(error.message, /POST \/oauth2\/token returned 200( OK)? with a JSON body that is not the documented resource object with any of access_token/);
    assert.ok(!error.message.includes(BOX_SILENT_MARKER));
    return true;
  });

  // The documented shapes still read: an empty inventory is `entries: []`, and a resource carries its documented keys.
  const { client: documented, log } = httpBox({ ...hardenedFixture(), users: [], allowlistEntries: [] });
  const none = await documented.listUsers(10);
  assert.deepEqual(none, { items: [], truncated: false }, "a documented empty listing stays a readable empty inventory");
  assert.equal((await documented.getCurrentUser()).id, "service-1");
  assert.ok(log.every((entry) => entry.status === 200));
});

test("verdict rule 1 (silent success): a silent 200 on any Box dataset is recorded not_readable with the observed 200 in core_data, collection_status, and the access check, no finding passes or fails on it, and nothing from the body is echoed", async () => {
  const baseline = await runAllBoxAssessments(httpBox(hardenedFixture()).client);
  const baselineStatuses = new Map(baseline.flatMap((result) => result.findings.map((item) => [item.id, item.status])));

  for (const [index, dataset] of BOX_SILENT_DATASETS.entries()) {
    const variant = BOX_SILENT_BODIES[index % BOX_SILENT_BODIES.length];
    const { client, config, log } = httpBox(hardenedFixture(), { routes: { [dataset.route]: () => variant.response() } });
    const label = `${dataset.inventory} answered with a silent 200 (${variant.name})`;
    const access = await checkBoxAccess(client);
    const results = await runAllBoxAssessments(client);
    const exported = await exportBoxAuditBundle(client, config, createTempBase("grclanker-box-silent-"));
    const files = readBundleFiles(exported.outputDir);

    const outputs = new Map([...files, ["access check", JSON.stringify(access)], ["assess payloads", JSON.stringify(results)]]);
    for (const [name, text] of outputs) {
      assert.ok(!text.includes(BOX_SILENT_MARKER), `${label}: the body text was echoed into ${name}`);
    }
    assert.ok(log.some((entry) => entry.status === 200), `${label}: the 200 the outputs cite was observed on the wire`);

    // The dataset's file is a marker object carrying the observed 200 and the fixed note, not an empty array or {}.
    const record = JSON.parse(files.get(dataset.file));
    assert.equal(record.collected, false, `${label}: ${dataset.file} is a not-collected marker`);
    assert.equal(record.status, 200, `${label}: the marker carries the observed status`);
    assert.match(record.error, variant.note, `${label}: the marker carries the fixed note`);
    const status = JSON.parse(files.get("core_data/collection_status.json"));
    const row = status.datasets.find((entry) => entry.file === dataset.file);
    assert.deepEqual(
      { collected: row.collected, status_code: row.status_code, count: row.count, complete: row.complete, truncated: row.truncated },
      { collected: false, status_code: 200, count: null, complete: null, truncated: null },
      `${label}: the collection_status row records a failed read with the observed 200 and null counts`,
    );
    assert.match(row.error, variant.note);
    assert.match(row.endpoint, /^GET \/2\.0\//, `${label}: the row names the request that was made`);

    // The access probe for the surface says not readable with the observed 200.
    const probe = access.surfaces.find((surface) => surface.name === dataset.surface);
    assert.ok(probe, `${label}: the access check probes this surface`);
    assert.deepEqual({ status: probe.status, httpStatus: probe.httpStatus, count: probe.count }, { status: "not_readable", httpStatus: 200, count: null }, `${label}: the access probe records the failed read`);
    assert.match(probe.error, variant.note);

    const changed = results.flatMap((result) => result.findings).filter((item) => item.status !== baselineStatuses.get(item.id));
    if (dataset.verdicts) assert.ok(changed.length > 0, `${label}: at least one verdict that reads this dataset leaves its baseline status`);
    assert.ok(changed.every((item) => item.status === "manual" || item.status === "warn"), `${label}: a finding left pass or fail for something other than manual or warn: ${changed.map((item) => `${item.id}:${item.status}`).join(" ")}`);
    // No verdict is reached on data that was never observed: every pass or fail in the degraded run was the same pass
    // or fail on the all-readable baseline (a finding that read the silent dataset goes manual or warn), and no
    // evidence or summary leaf falls back to zero, false, or empty where the baseline held data.
    for (const [areaIndex, result] of results.entries()) {
      for (const item of result.findings) {
        if (item.status === "pass" || item.status === "fail") {
          assert.equal(item.status, baselineStatuses.get(item.id), `${label}: ${item.id} reached ${item.status} while the baseline had ${baselineStatuses.get(item.id)}: ${item.summary}`);
          assert.doesNotMatch(item.summary, variant.note, `${label}: ${item.id} ${item.status} cites the silent read`);
        }
        const baselineFinding = findingById(baseline[areaIndex], item.id);
        for (const [path, value] of boxLeafEntries(item.evidence ?? {})) {
          const baselineValue = boxPluck(baselineFinding.evidence ?? {}, path);
          assert.ok(!isBoxFallback(path, value, baselineValue), `${label}: ${item.id} evidence.${path} = ${JSON.stringify(value)} fell back from ${JSON.stringify(baselineValue)}`);
        }
      }
      for (const [path, value] of boxLeafEntries(result.summary ?? {})) {
        const baselineValue = boxPluck(baseline[areaIndex].summary ?? {}, path);
        assert.ok(!isBoxFallback(path, value, baselineValue), `${label}: ${result.area} summary.${path} = ${JSON.stringify(value)} fell back from ${JSON.stringify(baselineValue)}`);
      }
    }
  }
});

// ---------------------------------------------------------------------------------------------------------------
// Data-side carriers: credential subtrees and free text in collected records.
// ---------------------------------------------------------------------------------------------------------------

// Random alphanumeric values with no 6-character window in common with each other or the fixture (self-checked below).
const BOX_DATA_CANARIES = {
  tosSessionToken: "5oBc7cx5Ap5GyoRLYF2spiykxV2neZ4K",
  tosHexSecret: "3f9a1c4e7b2d8f60a5c3e1b9d7f24a6c8e0b1d3f",
  tokensEntry: "vpzNAAhcRicNV6dbDCxX6GZDZQSByBMN",
  urlPathToken: "YuCrx3AeiPGNJUXAUKXsJecXdAKMuXxe",
  urlQueryToken: "PHusoCSroBiMZPU6N9wJwMMNtgN5KrpB",
  credentialsValue: "dYNfZ83NyGPawpD36FisN4mi7knLccqW",
  keysEntry: "LwpKhwybpxvF598hRekWfQ4RvQHhs4jN",
  bioBearer: "rzzeFBvjaahfmRUPxGGsEEbvHRPmKXN3",
};

/** A 403 body echoing weak human-chosen pairs (no digits, symbols, or length a shape gate would catch) under vendor env names, a config key, a webhook-prefixed credential key (gap 39), and a header-named key whose value opens with a scheme word. */
const WEAK_PAIR_BODY = "Access denied: LAUNCHDARKLY_API_TOKEN=monkey LD_ACCESS_TOKEN=Sunshine webhook_secret=hunter2 DD_APP_KEY=p@ss BOX_CLIENT_SECRET=football KNOWBE4_API_TOKEN=qwerty ELASTIC_PASSWORD=iloveyou x-api-key: splunk correcthorse";
const WEAK_PAIR_VALUES = ["monkey", "Sunshine", "hunter2", "p@ss", "football", "qwerty", "iloveyou", "splunk correcthorse"];
const WEAK_PAIR_KEYS = ["LAUNCHDARKLY_API_TOKEN", "LD_ACCESS_TOKEN", "webhook_secret", "DD_APP_KEY", "BOX_CLIENT_SECRET", "KNOWBE4_API_TOKEN", "ELASTIC_PASSWORD", "x-api-key"];

test("row (a): a Box 403 body echoing weak values under credential-named keys reaches the access check with every value gone and every key kept", async () => {
  const { client, log } = httpBox(hardenedFixture(), {
    routes: {
      "GET /2.0/retention_policies": () => jsonResponse(
        { type: "error", status: 403, code: "access_denied_insufficient_permissions", message: WEAK_PAIR_BODY, request_id: "req-weak" },
        { status: 403, statusText: "Forbidden" },
      ),
    },
  });
  const access = await checkBoxAccess(client);
  const retention = access.surfaces.find((surface) => surface.name === "retention_policies");
  assert.deepEqual({ status: retention.status, httpStatus: retention.httpStatus }, { status: "not_readable", httpStatus: 403 });
  assert.ok(log.some((entry) => entry.status === 403), "the 403 was observed on the wire");
  assert.match(retention.error, /^Box request failed \(403\) for GET \/2\.0\/retention_policies\?[^:]*: Access denied: /);
  for (const key of WEAK_PAIR_KEYS) assert.ok(retention.error.includes(`${key}=[REDACTED]`) || retention.error.includes(`${key}: [REDACTED]`), `${key} keeps its name and gets the marker: ${retention.error}`);
  assertCanaryWindowsAbsent(assert, JSON.stringify(access), WEAK_PAIR_VALUES, "check_access payload");
});

test("verdict rule 9 (data-side carriers): Box blanks the whole subtree under tokens, keys, and credentials keys, scrubs mid-string URL queries, webhook-style paths, bearer carriers, and bare or hex tokens out of free text, and projects terms of service to the fields the verdicts read", async () => {
  const canaries = Object.values(BOX_DATA_CANARIES);
  const baselineExport = await exportBoxAuditBundle(httpBox(hardenedFixture()).client, sampleConfig(), createTempBase("grclanker-box-data-baseline-"));
  assertCanaryFixture(assert, canaries.filter((canary) => canary !== BOX_DATA_CANARIES.tosHexSecret), readBundleFiles(baselineExport.outputDir), "data-side canaries");

  const fixture = hardenedFixture();
  fixture.termsOfServices[0] = {
    ...fixture.termsOfServices[0],
    text: `By continuing you accept the terms at https://terms.example.com/v3?session_token=${BOX_DATA_CANARIES.tosSessionToken} and the signing key ${BOX_DATA_CANARIES.tosHexSecret} applies.`,
  };
  fixture.users[1] = {
    ...fixture.users[1],
    tokens: [BOX_DATA_CANARIES.tokensEntry],
    api_keys: [{ id: "k1", value: BOX_DATA_CANARIES.keysEntry }],
    credentials: { value: BOX_DATA_CANARIES.credentialsValue, kind: "api" },
    notification_url: `https://hooks.slack.com/services/T0000000/B0000000/${BOX_DATA_CANARIES.urlPathToken}`,
    job_title: `Ops lead; profile at https://intranet.example.com/people/42?access_token=${BOX_DATA_CANARIES.urlQueryToken} mid sentence`,
    address: `Bearer ${BOX_DATA_CANARIES.bioBearer} was pasted here`,
  };

  const { client, config } = httpBox(fixture);
  const access = await checkBoxAccess(client);
  const results = await runAllBoxAssessments(client);
  const exported = await exportBoxAuditBundle(client, config, createTempBase("grclanker-box-data-"));
  const files = readBundleFiles(exported.outputDir);
  const entries = readZipEntries(exported.zipPath);

  assertCanaryWindowsAbsent(assert, files, canaries, "bundle file");
  assertCanaryWindowsAbsent(assert, entries, canaries, "zip entry");
  assertCanaryWindowsAbsent(assert, new Map([["access check", JSON.stringify(access)], ["assess payloads", JSON.stringify(results)]]), canaries, "tool payload");

  const terms = JSON.parse(files.get("core_data/terms_of_services.json"));
  assert.ok(!("text" in terms[0]), "the agreement text is not written");
  assert.deepEqual(
    { id: terms[0].id, tos_type: terms[0].tos_type, status: terms[0].status, text_length: typeof terms[0].text_length, modified_at: terms[0].modified_at },
    { id: "tos-1", tos_type: "managed", status: "enabled", text_length: "number", modified_at: "2026-01-01T00:00:00Z" },
  );
  const users = JSON.parse(files.get("core_data/users.json"));
  const written = users.find((entry) => entry.id === fixture.users[1].id);
  assert.equal(written.tokens, "[REDACTED]", "a credential-shaped list is blanked whole, not walked");
  assert.equal(written.api_keys, "[REDACTED]", "a qualified plural key blanks its subtree");
  assert.equal(written.credentials, "[REDACTED]", "a credential-shaped object is blanked whole");
  assert.match(written.notification_url, /^https:\/\/hooks\.slack\.com\/services\/\[REDACTED\]$|^https:\/\/hooks\.slack\.com$|^https:\/\/hooks\.slack\.com\/services\/T0000000\/B0000000\/\[REDACTED\]$/, `a webhook-style path loses its token: ${written.notification_url}`);
  assert.match(written.job_title, /^Ops lead; profile at https:\/\/intranet\.example\.com\/people\/42\?\[REDACTED\] mid sentence$/, `a URL query mid string is replaced: ${written.job_title}`);
  assert.match(written.address, /^(Bearer )?\[REDACTED\] was pasted here$/, `a bearer carrier in free text loses its value: ${written.address}`);
  assert.equal(written.login, fixture.users[1].login, "identifiers and logins are untouched");
});

test("bearer ids: an enterprise event's session_id survives the projection and the record walker writes the marker in its place before the file is written, while event_id, the actor id, and the address stay", () => {
  const sessionId = "Hq4vT9mXcR2pLw8ZbN6kJd3sVf7yGa5e";
  const event = {
    event_id: "e-1",
    event_type: "LOGIN",
    created_at: "2026-09-10T00:00:00Z",
    created_by: { id: "member-1", type: "user", name: "Ada", login: "ada@example.com" },
    source: { id: "file-1", type: "file" },
    session_id: sessionId,
    ip_address: "203.0.113.7",
    additional_details: { note: `Cookie: sid=${sessionId}` },
  };
  const projected = projectEnterpriseEvent(event);
  assert.equal(projected.session_id, sessionId, "the projection keeps the field; the walker decides its value");
  assert.equal(projected.additional_details, undefined, "the free-form bucket is dropped");
  const written = redactCredentialValues([projected])[0];
  assert.equal(written.session_id, "[REDACTED]", "a session id is a bearer id whatever its shape");
  assert.equal(written.event_id, "e-1");
  assert.equal(written.created_by.id, "member-1");
  assert.equal(written.created_by.login, "ada@example.com");
  assert.equal(written.ip_address, "203.0.113.7");
  assertCanaryWindowsAbsent(assert, JSON.stringify(written), [sessionId], "projected and redacted event");
  const uuid = "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b";
  const config = redactCredentialValues({ client_id: uuid, enterprise_id: "123456", subject_id: uuid, public_key_id: "kid-2026", secret_id: uuid, VAULT_SECRET_ID: uuid });
  assert.deepEqual(config, { client_id: uuid, enterprise_id: "123456", subject_id: uuid, public_key_id: "kid-2026", secret_id: "[REDACTED]", VAULT_SECRET_ID: "[REDACTED]" }, "client_id, enterprise_id, subject_id, and public_key_id are identifiers; secret_id is a credential");
});

test("cookie attribute class: a later cookie whose name holds a dot or another token character goes with the header value through the Box error text, secret, and record scrubbers", () => {
  assertCookieAttributeCarriersScrubbed(assert, scrubErrorText, "box scrubErrorText");
  assertCookieAttributeCarriersScrubbed(assert, (text) => redactSecrets(text, []), "box redactSecrets");
  assertCookieAttributeCarriersScrubbed(assert, (text) => redactCredentialValues({ note: text }).note, "box redactCredentialValues");
  assertCookieAttributeCarriersScrubbed(assert, (text) => redactCredentialValues([{ message: text }])[0].message, "box redactCredentialValues, error list");
});

// ---------------------------------------------------------------------------------------------------------------
// Config loader errors, transport parse errors, fixed-text survival, and the environment overlay.
// ---------------------------------------------------------------------------------------------------------------

// Random alphanumeric values planted in config files, a parser message, and the environment (self-checked below).
const BOX_CONFIG_CANARIES = {
  yamlQuote: "MwNL3pcZ20zfWntbHACd3RCUiGoP3097",
  yamlAlias: "M5nXQjEH99RdKXEp8TyaftpsJ4i7Leo0",
  yamlDuplicate: "rwvxKwmv56hUDT6efg8OZg2tT1bf9tzA",
  yamlTab: "XfrIGSM9qI0R5rJsZnB6bvNwFP6zhXBt",
  tomlLine: "xzFv33EsoDnyEGF18MRUW7DPJuKW4cy1",
  unrelatedKey: "f5GCpCy4b88x1VLSGueF6ZHW3KGLeN1z",
  unreadable: "pnkP3OcfUYN8t9fJmlxRyV7kwBVeLTIw",
  jwtValue: "RwFxfvM31YZUZFHodnrJUmuXqTYFXWQA",
};
const BOX_PARSER_SNIPPET_CANARY = "B2825Qtqrpi2IkJdb04OfHvJrZPzaRLf";
const BOX_ENV_TOKEN_CANARY = "AV0dmemkRXsetix24wXkRWifYWmR9WuJ";

/** Wording the yaml library, JSON.parse, and the filesystem put in their own messages; none of it may reach a recorded message. */
const BOX_LIBRARY_WORDING = [
  "Missing closing",
  "Unresolved alias",
  "Map keys must be unique",
  "Tabs are not allowed",
  ", column ",
  "is not valid JSON",
  "Unexpected token",
  "Expected ',' or '}'",
  "illegal operation",
  "permission denied",
  "no such file",
];

/** Asserts a message carries neither any window of a canary nor the parser's or filesystem's own wording. */
function assertBoxFixedTextOnly(message, canaries, label) {
  assertCanaryWindowsAbsent(assert, message, canaries, label);
  for (const wording of BOX_LIBRARY_WORDING) assert.ok(!message.includes(wording), `${label}: carries library wording "${wording}": ${message}`);
}

/** The Box tools as the runtime registers them, by name. */
function registeredBoxTools() {
  const registered = [];
  registerBoxTools({ registerTool: (tool) => registered.push(tool) });
  return new Map(registered.map((tool) => [tool.name, tool]));
}

/** Runs `fn` with every BOX_* variable removed from process.env (plus `overrides` set), restoring the environment afterwards. */
async function withBoxEnvironment(overrides, fn) {
  const saved = Object.fromEntries(Object.entries(process.env).filter(([key]) => key.startsWith("BOX_")));
  for (const key of Object.keys(saved)) delete process.env[key];
  for (const [key, value] of Object.entries(overrides)) process.env[key] = value;
  try {
    return await fn();
  } finally {
    for (const key of Object.keys(process.env)) if (key.startsWith("BOX_")) delete process.env[key];
    for (const [key, value] of Object.entries(saved)) process.env[key] = value;
  }
}

/**
 * Positive control for a YAML case: the yaml library rejects `text` with a message that quotes the planted value, and
 * the line it reports (undefined when the thrown value is not a YAMLError) is the only position the fixed text may carry.
 */
function yamlLibraryLine(text, canary, label) {
  let thrown;
  try {
    parseYaml(text);
  } catch (error) {
    thrown = error;
  }
  assert.ok(thrown, `${label}: positive control, the yaml library rejects the text`);
  assert.ok(thrown.message.includes(canary), `${label}: positive control, the library's own message quotes the source`);
  return thrown instanceof YAMLError ? thrown.linePos?.[0]?.line : undefined;
}

/**
 * Positive control for a JSON case: JSON.parse rejects `text`; its message and the position it reports (if any) come
 * back so the case can assert what the library exposes, the position being the only detail the fixed text may carry.
 */
function jsonLibraryError(text, label) {
  let thrown;
  try {
    JSON.parse(text);
  } catch (error) {
    thrown = error;
  }
  assert.ok(thrown instanceof SyntaxError, `${label}: positive control, JSON.parse rejects the text`);
  return { message: thrown.message, position: /at position (\d+)/.exec(thrown.message)?.[1] };
}

test("canary fixture self-check: every planted Box config, parser, and environment canary is alphanumeric, random-looking, and shares no 6-character window with the fixture's legitimate values", async () => {
  const { client, config } = httpBox(hardenedFixture());
  const access = await checkBoxAccess(client);
  const assessments = await runAllBoxAssessments(client);
  const exported = await exportBoxAuditBundle(client, config, createTempBase("grclanker-box-config-self-check-"));
  const legitimate = new Map([
    ...readBundleFiles(exported.outputDir),
    ["hardened fixture", JSON.stringify(hardenedFixture())],
    ["weak fixture", JSON.stringify(weakFixture())],
    ["check_access", JSON.stringify(access)],
    ["assessments", JSON.stringify(assessments)],
    ["config", JSON.stringify({ ...config, clientSecret: null })],
  ]);
  assertCanaryFixture(assert, [...Object.values(BOX_CONFIG_CANARIES), BOX_PARSER_SNIPPET_CANARY, BOX_ENV_TOKEN_CANARY], legitimate, "Box config canaries");
});

test("config loader errors: a Box config or JWT file that cannot be read or parsed yields fixed text with only the path, a validated code, and the parser's own line or position, from the resolver, from check_access, and from the export tool, which writes nothing", async () => {
  const tools = registeredBoxTools();
  const checkTool = tools.get("box_check_access");
  const exportTool = tools.get("box_export_audit_bundle");
  const canaries = Object.values(BOX_CONFIG_CANARIES);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = () => { throw new Error("no request may be made while a config file is unreadable"); };
  try {
    await withBoxEnvironment({}, async () => {
      const base = createTempBase("grclanker-box-config-errors-");
      const cases = [];

      // An unterminated quote: the library's message quotes the offending source line; the fixed text carries the line alone.
      const quote = join(base, "unterminated-quote.yaml");
      const quoteText = `# Box\nclient_id: abc\nclient_secret: "${BOX_CONFIG_CANARIES.yamlQuote}\n`;
      writeFileSync(quote, quoteText, "utf8");
      const quoteLine = yamlLibraryLine(quoteText, BOX_CONFIG_CANARIES.yamlQuote, "unterminated quote");
      assert.equal(typeof quoteLine, "number", "positive control: the library reports a line for an unterminated quote");
      cases.push({ name: "yaml unterminated quote", args: { config_path: quote }, path: quote, code: "INVALID_YAML", message: `Unable to parse Box config file: invalid YAML in ${quote} at line ${quoteLine}` });

      // An unresolved alias: the library throws a plain ReferenceError whose message ends with the alias, so no line is known.
      const alias = join(base, "alias.yaml");
      const aliasText = `client_id: abc\nclient_secret: *${BOX_CONFIG_CANARIES.yamlAlias}\n`;
      writeFileSync(alias, aliasText, "utf8");
      assert.equal(yamlLibraryLine(aliasText, BOX_CONFIG_CANARIES.yamlAlias, "unresolved alias"), undefined, "positive control: an unresolved alias is not a YAMLError and carries no line");
      cases.push({ name: "yaml unresolved alias", args: { config_path: alias }, path: alias, code: "INVALID_YAML", message: `Unable to parse Box config file: invalid YAML in ${alias}` });

      // A duplicate key: the library quotes both lines; the fixed text names the second.
      const duplicate = join(base, "duplicate-key.yaml");
      const duplicateText = `client_secret: ${BOX_CONFIG_CANARIES.yamlDuplicate}\nclient_secret: other\n`;
      writeFileSync(duplicate, duplicateText, "utf8");
      assert.equal(yamlLibraryLine(duplicateText, BOX_CONFIG_CANARIES.yamlDuplicate, "duplicate key"), 2);
      cases.push({ name: "yaml duplicate key", args: { config_path: duplicate }, path: duplicate, code: "INVALID_YAML", message: `Unable to parse Box config file: invalid YAML in ${duplicate} at line 2` });

      // Tab indentation: rejected by line, the line itself (which holds the secret) is not copied.
      const tab = join(base, "tab-indent.yaml");
      const tabText = `box:\n\tclient_secret: ${BOX_CONFIG_CANARIES.yamlTab}\n`;
      writeFileSync(tab, tabText, "utf8");
      assert.equal(yamlLibraryLine(tabText, BOX_CONFIG_CANARIES.yamlTab, "tab indentation"), 2);
      cases.push({ name: "yaml tab indentation", args: { config_path: tab }, path: tab, code: "INVALID_YAML", message: `Unable to parse Box config file: invalid YAML in ${tab} at line 2` });

      // A TOML-style line is valid YAML: one plain scalar, which is not a mapping, so the file holds no Box settings.
      const tomlStyle = join(base, "toml-style.yaml");
      const tomlText = `client_secret = "${BOX_CONFIG_CANARIES.tomlLine}"\n`;
      writeFileSync(tomlStyle, tomlText, "utf8");
      assert.equal(typeof parseYaml(tomlText), "string", "positive control: the line parses as one scalar that holds the value");
      cases.push({ name: "toml-style line", args: { config_path: tomlStyle }, path: tomlStyle, code: "EMPTY_CONFIG", message: `Box config file did not contain any Box settings: ${tomlStyle}` });

      // A mapping without any Box key: an explicitly named file that configures nothing is an error, and its values are not quoted.
      const unrelated = join(base, "unrelated.yaml");
      writeFileSync(unrelated, `service_note: ${BOX_CONFIG_CANARIES.unrelatedKey}\nregion: eu\n`, "utf8");
      cases.push({ name: "no Box settings", args: { config_path: unrelated }, path: unrelated, code: "EMPTY_CONFIG", message: `Box config file did not contain any Box settings: ${unrelated}` });

      // EISDIR: a directory at the path is a read failure, not a parse failure.
      const directory = join(base, "config-dir");
      mkdirSync(directory);
      assert.throws(() => readFileSync(directory, "utf8"), (error) => error.code === "EISDIR" && /illegal operation/.test(error.message), "positive control: the filesystem message carries its own wording");
      cases.push({ name: "EISDIR", args: { config_path: directory }, path: directory, code: "EISDIR", message: `Unable to read Box config file ${directory} (EISDIR)` });

      // EACCES: an unreadable file (root reads everything, so the case is skipped when running as root).
      if (typeof process.getuid === "function" && process.getuid() !== 0) {
        const unreadable = join(base, "unreadable.yaml");
        writeFileSync(unreadable, `client_secret: ${BOX_CONFIG_CANARIES.unreadable}\n`, "utf8");
        chmodSync(unreadable, 0o000);
        assert.throws(() => readFileSync(unreadable, "utf8"), (error) => error.code === "EACCES" && /permission denied/.test(error.message), "positive control");
        cases.push({ name: "EACCES", args: { config_path: unreadable }, path: unreadable, code: "EACCES", message: `Unable to read Box config file ${unreadable} (EACCES)` });
      }

      // ENOENT on an explicit path: a missing file named by argument or environment is an error, not a silent default.
      const missing = join(base, "missing.yaml");
      cases.push({ name: "ENOENT", args: { config_path: missing }, path: missing, code: "ENOENT", message: `Unable to read Box config file ${missing} (ENOENT)` });

      // The JWT app config, cut off after the secret: JSON.parse reports a position (and no source window), and the
      // fixed text carries that position alone.
      const jwtUnterminated = join(base, "jwt-unterminated.json");
      const jwtUnterminatedText = `{"boxAppSettings": {"clientID": "abc", "clientSecret": "${BOX_CONFIG_CANARIES.jwtValue}"`;
      writeFileSync(jwtUnterminated, jwtUnterminatedText, "utf8");
      const unterminated = jsonLibraryError(jwtUnterminatedText, "JWT unterminated object");
      assert.match(unterminated.position ?? "", /^\d+$/, `positive control: JSON.parse reports a position for an unterminated object: ${unterminated.message}`);
      cases.push({ name: "JWT JSON unterminated", args: { jwt_config_path: jwtUnterminated }, path: jwtUnterminated, code: "INVALID_JSON", message: `Unable to parse Box JWT config file: invalid JSON in ${jwtUnterminated} at position ${unterminated.position}` });

      // A bare secret where a JSON string was expected: JSON.parse quotes a window of the source around it and reports
      // no position, so the fixed text carries the path alone.
      const jwtBare = join(base, "jwt-bare-value.json");
      const jwtBareText = `{"boxAppSettings": {"clientID": "abc", "clientSecret": ${BOX_CONFIG_CANARIES.jwtValue}}}`;
      writeFileSync(jwtBare, jwtBareText, "utf8");
      const bare = jsonLibraryError(jwtBareText, "JWT bare value");
      assert.ok(bare.message.includes(BOX_CONFIG_CANARIES.jwtValue.slice(0, 6)), `positive control: JSON.parse quotes a window of the source: ${bare.message}`);
      assert.equal(bare.position, undefined, "positive control: an unexpected token carries no position, only the quoted window");
      cases.push({ name: "JWT JSON bare value", args: { jwt_config_path: jwtBare }, path: jwtBare, code: "INVALID_JSON", message: `Unable to parse Box JWT config file: invalid JSON in ${jwtBare}` });

      const jwtMissing = join(base, "jwt-missing.json");
      cases.push({ name: "JWT ENOENT", args: { jwt_config_path: jwtMissing }, path: jwtMissing, code: "ENOENT", message: `Unable to read Box JWT config file ${jwtMissing} (ENOENT)` });

      assert.ok(cases.length >= 12, `expected the full matrix, got ${cases.length} cases`);
      for (const [index, item] of cases.entries()) {
        let thrown;
        try {
          resolveBoxConfiguration(item.args, {}, { homeDir: base, cwd: base });
        } catch (error) {
          thrown = error;
        }
        assert.ok(thrown, `${item.name}: the resolver must reject the file`);
        assert.equal(thrown.name, "BoxConfigFileError", item.name);
        assert.ok(thrown instanceof BoxConfigFileError, item.name);
        assert.equal(thrown.message, item.message, `${item.name}: fixed text only`);
        assert.equal(thrown.code, item.code, item.name);
        assert.equal(thrown.path, item.path, item.name);
        assertBoxFixedTextOnly(thrown.message, canaries, `${item.name} resolver`);

        const access = await checkTool.execute("call-config", checkTool.prepareArguments(item.args));
        assert.equal(access.isError, true, item.name);
        assert.equal(access.content[0].text, `Box access check failed: ${item.message}`, item.name);
        assertBoxFixedTextOnly(JSON.stringify(access), canaries, `${item.name} check_access`);

        const outputDir = join(base, `export-${index}-${item.code.toLowerCase()}`);
        const exported = await exportTool.execute("call-config-export", exportTool.prepareArguments({ ...item.args, output_dir: outputDir }));
        assert.equal(exported.isError, true, item.name);
        assert.equal(exported.content[0].text, `Box audit bundle export failed: ${item.message}`, item.name);
        assertBoxFixedTextOnly(JSON.stringify(exported), canaries, `${item.name} export`);
        assert.equal(existsSync(outputDir), false, `${item.name}: nothing is written when a config file is unreadable`);
      }

      // The environment variable is an explicit path too, and a missing default file is still simply absent.
      assert.throws(() => resolveBoxConfiguration({ access_token: BOX_ENV_TOKEN_CANARY }, { BOX_CONFIG_PATH: missing }, { homeDir: base, cwd: base }), { message: `Unable to read Box config file ${missing} (ENOENT)` });
      assert.equal(resolveBoxConfiguration({ access_token: BOX_ENV_TOKEN_CANARY }, {}, { homeDir: base, cwd: base }).accessToken, BOX_ENV_TOKEN_CANARY);
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("config loader errors: a SyntaxError raised by the Box transport is recorded by name only, never by the parser's message that quotes the body", async () => {
  const snippet = `<html>${BOX_PARSER_SNIPPET_CANARY}</html>`;
  const client = new BoxApiClient(sampleConfig({ authMode: "oauth", accessToken: "oauth-fixture-access-2026", clientId: undefined, clientSecret: undefined, maxRetries: 0 }), {
    fetchImpl: async () => { throw new SyntaxError(`Unexpected token '<', "${snippet}"... is not valid JSON`); },
    now: () => NOW,
    sleep: async () => {},
  });
  await assert.rejects(() => client.getCurrentUser(), (error) => {
    assert.ok(error instanceof BoxTransportError);
    assert.match(error.message, /^Box request failed: GET \/2\.0\/users\/me\?fields=[A-Za-z0-9_%]+: SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body$/);
    assert.match(error.request, /^GET \/2\.0\/users\/me\?fields=/);
    assertCanaryWindowsAbsent(assert, error.message, [BOX_PARSER_SNIPPET_CANARY], "transport error");
    return true;
  });
  const access = await checkBoxAccess(client);
  assertCanaryWindowsAbsent(assert, JSON.stringify(access), [BOX_PARSER_SNIPPET_CANARY], "check_access");
  assert.ok(access.surfaces.length > 0 && access.surfaces.every((surface) => surface.status !== "readable"), "no surface reads through a transport that only throws");
  assert.ok(access.surfaces.every((surface) => typeof surface.error === "string" && surface.error.includes("SyntaxError: response could not be parsed as JSON")), access.surfaces.map((surface) => surface.error).join("\n"));
  const identity = await assessBoxIdentityAccess(client);
  assert.ok(identity.errors.length > 0 && identity.errors.every((text) => text.includes("SyntaxError: response could not be parsed as JSON")), identity.errors.join("\n"));
  assertCanaryWindowsAbsent(assert, JSON.stringify(identity), [BOX_PARSER_SNIPPET_CANARY], "assess payload");
});

/** Every fixed-text message the Box integration emits that a fixture run does not already produce. */
const BOX_FIXED_TEXT_MESSAGES = [
  "Unable to read Box config file /home/auditor/.box-sec-inspector/config.yaml (ENOENT)",
  "Unable to read Box config file /home/auditor/.box-sec-inspector/config.yaml (EACCES)",
  "Unable to parse Box config file: invalid YAML in /home/auditor/.box-sec-inspector/config.yaml at line 3",
  "Unable to parse Box config file: invalid YAML in /home/auditor/.box-sec-inspector/config.yaml",
  "Box config file did not contain any Box settings: /home/auditor/.box-sec-inspector/config.yaml",
  "Unable to read Box JWT config file /home/auditor/box-jwt-config.json (ENOENT)",
  "Unable to parse Box JWT config file: invalid JSON in /home/auditor/box-jwt-config.json at position 70",
  "Unable to parse Box JWT config file: invalid JSON in /home/auditor/box-jwt-config.json",
  "Box credentials are required. Set BOX_JWT_CONFIG_PATH for JWT, BOX_CLIENT_ID plus BOX_CLIENT_SECRET plus BOX_ENTERPRISE_ID for Client Credentials Grant, or BOX_ACCESS_TOKEN for OAuth 2.0.",
  "Box JWT auth requires BOX_JWT_CONFIG_PATH or a jwt_config_path argument.",
  "Box JWT config file did not include boxAppSettings.appAuth.privateKey.",
  "Box CCG auth requires a client ID and client secret (BOX_CLIENT_ID and BOX_CLIENT_SECRET).",
  "Box JWT auth requires BOX_ENTERPRISE_ID (or enterpriseID in the JWT config file).",
  "Box user-subject auth requires BOX_SUBJECT_ID.",
  "Box OAuth 2.0 auth requires BOX_ACCESS_TOKEN, or BOX_REFRESH_TOKEN with BOX_CLIENT_ID and BOX_CLIENT_SECRET.",
  'Unsupported Box JWT algorithm "RS1024". Use RS256, RS384, or RS512.',
  "Box Client Credentials Grant credentials are incomplete.",
  "Box OAuth 2.0 access token expired and no refresh token with client credentials is available.",
  "Box token response did not include access_token.",
  "Unable to determine the Box enterprise ID; set BOX_ENTERPRISE_ID explicitly.",
  "Box request timed out after 30000ms: GET /2.0/users/me?fields=id%2Ctype%2Cname%2Clogin%2Crole%2Cstatus%2Centerprise%2Cis_platform_access_only",
  "Box request failed: GET /2.0/users/me?fields=id%2Ctype%2Cname%2Clogin%2Crole%2Cstatus%2Centerprise%2Cis_platform_access_only: SyntaxError: response could not be parsed as JSON; the parser's message is not recorded because it quotes the body",
  "Box request GET /2.0/users?fields=id%2Clogin&limit=1000 returned 200 OK with an empty body (0 bytes); the endpoint is not serving the JSON API",
  "Box request GET /2.0/users?limit=1000 returned 200 OK with a non-JSON text/html; charset=utf-8 response body (128 bytes, not echoed); the endpoint is not serving the JSON API",
  "Box request GET /2.0/users?limit=1000 returned 200 OK with a JSON body that is not the documented list object with an entries array (64 bytes, not echoed); the endpoint is not serving the JSON API",
  "Box request POST /oauth2/token returned 200 OK with a JSON body that is not the documented resource object with any of access_token (32 bytes, not echoed); the endpoint is not serving the JSON API",
  "Box request failed (502 Bad Gateway) for GET /2.0/retention_policies?limit=100: non-JSON text/html response body (5120 bytes, not echoed)",
  "Box request failed (403 Forbidden) for GET /2.0/retention_policies?limit=100: JSON body without a documented error field (42 bytes, not echoed)",
  "Box request failed (403 Forbidden) for GET /2.0/shield_information_barriers?limit=100: Access denied - insufficient permission",
  "Box request failed (404 Not Found) for GET /2.0/metadata_templates/enterprise/securityClassification-6VMVochwUWo/schema: Not Found",
  "Box reported more users (a next_marker remained)",
  "Box reported more events (a next_stream_position remained)",
  "Box access check: healthy",
  "Box access check: limited",
  "Box audit bundle exported.",
];

/** A Box 403 for one route: the documented error object with a fixed message. */
function boxDenyRoute() {
  return () => jsonResponse(
    { type: "error", status: 403, code: "access_denied_insufficient_permissions", message: "Access denied - insufficient permission", request_id: "req-denied" },
    { status: 403, statusText: "Forbidden" },
  );
}

/** Every string a run records: surface errors and notes, assessment errors and truncation notes, finding text, evidence leaves, and the error log. */
function boxRecordedStrings(access, assessments, files) {
  const strings = [];
  for (const surface of access.surfaces) if (typeof surface.error === "string") strings.push(surface.error);
  strings.push(...access.notes, access.recommendedNextStep);
  for (const assessment of assessments) {
    strings.push(...(assessment.errors ?? []), ...(assessment.truncated ?? []));
    for (const finding of assessment.findings) {
      strings.push(finding.title, finding.summary);
      if (typeof finding.manualEvidence === "string") strings.push(finding.manualEvidence);
      for (const [, value] of boxLeafEntries(finding.evidence ?? {})) if (typeof value === "string") strings.push(value);
    }
    for (const [, value] of boxLeafEntries(assessment.summary ?? {})) if (typeof value === "string") strings.push(value);
  }
  const errorsLog = files.get("_errors.log");
  if (errorsLog) strings.push(...errorsLog.split("\n"));
  return strings;
}

test("round 7a: every fixed-text message the Box integration emits survives its own scrubber unchanged, including every string a healthy, weak, or partially denied run records", async () => {
  for (const message of BOX_FIXED_TEXT_MESSAGES) {
    assert.equal(scrubErrorText(message), message, `fixed text was altered by the scrubber: ${message}`);
  }

  // Every string a run writes about legitimate data is fixed text from the run's point of view: the scrubber must not
  // rewrite a finding summary, a manual-evidence instruction, an inventory gap, or a bundle document.
  const runs = [httpBox(hardenedFixture()), httpBox(weakFixture())];
  for (const dataset of BOX_SILENT_DATASETS) {
    runs.push(httpBox(hardenedFixture(), { routes: { [dataset.route]: boxDenyRoute() } }));
  }
  let checked = 0;
  const altered = new Set();
  for (const { client, config, log } of runs) {
    const access = await checkBoxAccess(client);
    const assessments = await runAllBoxAssessments(client);
    const exported = await exportBoxAuditBundle(client, config, createTempBase("grclanker-box-fixed-text-"));
    const files = readBundleFiles(exported.outputDir);
    const texts = [
      ...boxRecordedStrings(access, assessments, files),
      ...[...files].filter(([name]) => !name.startsWith("core_data/")).map(([, text]) => text),
      ...log.map((entry) => `${entry.method} ${entry.path}`),
    ];
    checked += texts.length;
    for (const alteration of scrubAlterations(texts, scrubErrorText)) altered.add(alteration);
  }
  assert.ok(checked > 2000, `expected thousands of recorded strings, got ${checked}`);
  assert.deepEqual([...altered], [], `legitimate run text altered by the scrubber:\n${[...altered].join("\n")}`);
});

test("round 7b: resolveBoxConfiguration keeps env-provided credentials and config path when an unrelated argument is passed, and the tool sends the env token to the instance the env-named file configures", async () => {
  const checkTool = registeredBoxTools().get("box_check_access");
  const home = createTempBase("grclanker-box-env-overlay-");
  const configPath = join(home, "canary.yaml");
  writeFileSync(configPath, "box:\n  base_url: https://api.box.eu/2.0\n  max_retries: 1\n", "utf8");
  const env = { BOX_ACCESS_TOKEN: BOX_ENV_TOKEN_CANARY, BOX_CONFIG_PATH: configPath };

  // The tool's prepareArguments emits every auth key (undefined when not passed); that shape must not erase env values.
  const prepared = checkTool.prepareArguments({ timeout_seconds: 45 });
  assert.ok(Object.prototype.hasOwnProperty.call(prepared, "access_token") && prepared.access_token === undefined, "the overlay carries an undefined access_token key");
  assert.ok(Object.prototype.hasOwnProperty.call(prepared, "config_path") && prepared.config_path === undefined, "the overlay carries an undefined config_path key");
  const resolved = resolveBoxConfiguration(prepared, env, { homeDir: home, cwd: home });
  assert.equal(resolved.accessToken, BOX_ENV_TOKEN_CANARY, "the env token survives an unrelated argument");
  assert.equal(resolved.authMode, "oauth", "the auth mode is inferred from the env token");
  assert.equal(resolved.baseUrl, "https://api.box.eu/2.0", "the file the env path names is still read");
  assert.equal(resolved.maxRetries, 1, "a file setting survives too");
  assert.equal(resolved.timeoutMs, 45000, "the unrelated argument still applies");
  assert.deepEqual(resolved.sourceChain, ["config:canary.yaml", "environment", "arguments"], `the source chain names the file, the environment, and the argument: ${resolved.sourceChain.join(" -> ")}`);

  // Through the registered tool with the environment set: every request carries the env token to the env-named instance.
  const { log, fetchImpl } = httpBox(hardenedFixture());
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = fetchImpl;
    const result = await withBoxEnvironment(env, () => checkTool.execute("call-env", checkTool.prepareArguments({ timeout_seconds: 45 })));
    assert.notEqual(result.isError, true, result.content[0].text);
    assert.ok(log.length > 0, "requests were made");
    assert.ok(log.every((entry) => entry.authorization === `Bearer ${BOX_ENV_TOKEN_CANARY}`), "every request carries the env token");
    assert.ok(log.every((entry) => entry.host === "api.box.eu"), `the base URL from the env-named config file is used: ${[...new Set(log.map((entry) => entry.host))].join(", ")}`);
    assert.ok(log.every((entry) => entry.path !== "/oauth2/token"), "a pre-issued token is used as it is; no token is requested");
    assert.match(result.content[0].text, /^Box access check: healthy/);
    assertCanaryWindowsAbsent(assert, JSON.stringify(result), [BOX_ENV_TOKEN_CANARY], "check_access result");
  } finally {
    globalThis.fetch = originalFetch;
  }
});
