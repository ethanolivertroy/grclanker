import test from "node:test";
import assert from "node:assert/strict";
import { createVerify, generateKeyPairSync } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  BoxApiClient,
  BoxApiError,
  assessBoxDataGovernance,
  assessBoxIdentityAccess,
  assessBoxSharingCollaboration,
  assessBoxShieldMonitoring,
  buildBoxJwtAssertion,
  checkBoxAccess,
  exportBoxAuditBundle,
  listBoxControls,
  mappingsForControl,
  parseDurationHours,
  redactSecrets,
  resolveBoxConfiguration,
  resolveSecureOutputPath,
} from "../dist/extensions/grc-tools/box.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";

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

function createStubClient(fixture, overrides = {}) {
  const filterEvents = (options = {}) => {
    const eventTypes = options.eventTypes;
    const filtered = eventTypes && eventTypes.length > 0
      ? fixture.events.filter((event) => eventTypes.includes(event.event_type))
      : fixture.events;
    return filtered.slice(0, options.limit ?? filtered.length);
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
      return fixture.users;
    },
    async listGroups() {
      return fixture.groups;
    },
    async listEnterpriseEvents(options) {
      return filterEvents(options);
    },
    async listDevicePinners() {
      return fixture.devicePinners;
    },
    async listRetentionPolicies() {
      return fixture.retentionPolicies;
    },
    async listRetentionPolicyAssignments() {
      return fixture.retentionAssignments;
    },
    async listLegalHoldPolicies() {
      return fixture.legalHoldPolicies;
    },
    async listLegalHoldPolicyAssignments() {
      return fixture.legalHoldAssignments;
    },
    async listShieldInformationBarriers() {
      return fixture.barriers;
    },
    async listShieldInformationBarrierSegments() {
      return fixture.barrierSegments;
    },
    async listShieldLists() {
      return fixture.shieldLists;
    },
    async listCollaborationAllowlistEntries() {
      return fixture.allowlistEntries;
    },
    async listCollaborationAllowlistExemptTargets() {
      return fixture.exemptTargets;
    },
    async listEnterpriseMetadataTemplates() {
      return fixture.metadataTemplates;
    },
    async getClassificationTemplate() {
      return fixture.classificationTemplate;
    },
    async listTermsOfServices() {
      return fixture.termsOfServices;
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
  assert.throws(() => resolveBoxConfiguration({ config_path: join(base, "missing.yaml") }, {}, { homeDir: base, cwd: base }), /not found or was empty/);
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
  assert.deepEqual(users.map((entry) => entry.id), ["user-1", "user-2", "user-3"]);

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
  assert.deepEqual(groups.map((entry) => entry.id), ["group-1", "group-2"]);

  const events = await client.listEnterpriseEvents({ eventTypes: ["LOGIN"], createdAfter: NOW, limit: 5 });
  assert.deepEqual(events.map((entry) => entry.event_id), ["e-1", "e-2"]);
  const eventCalls = seen.filter((call) => call.pathname === "/2.0/events");
  assert.equal(eventCalls[0].params.get("stream_type"), "admin_logs");
  assert.equal(eventCalls[0].params.get("event_type"), "LOGIN");
  assert.equal(eventCalls[0].params.get("created_after"), NOW.toISOString());
  assert.equal(eventCalls[1].params.get("stream_position"), "1152922976252290800");
  assert.equal(seen.filter((call) => call.pathname === "/oauth2/token").length, 1, "token should be cached across calls");
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
  assert.equal(terms[0].id, "tos-1");
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
  assert.equal(unreadable.errors.length, 3);
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
  assert.equal(result.fileCount, 39);
  assert.equal(existsSync(join(result.outputDir, "_errors.log")), false);

  const expectedFiles = [
    "QUICK_REFERENCE.md",
    "metadata.json",
    "core_data/access_check.json",
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

  const second = await exportBoxAuditBundle(createStubClient(hardenedFixture()), sampleConfig(), base);
  assert.match(second.outputDir, /123456-audit-bundle-2$/);
});

test("exportBoxAuditBundle records partial collection failures in _errors.log", async () => {
  const base = createTempBase("grclanker-box-export-errors-");
  const result = await exportBoxAuditBundle(createStubClient(hardenedFixture(), {
    listRetentionPolicies: forbidden("manage_data_retention scope missing"),
    listShieldInformationBarriers: forbidden(),
  }), sampleConfig(), base);

  assert.ok(existsSync(result.zipPath));
  assert.equal(result.findingCount, 25);
  assert.equal(result.errorCount, 2);
  const errorLog = readFileSync(join(result.outputDir, "_errors.log"), "utf8");
  assert.match(errorLog, /retention_policies: .*manage_data_retention/);
  assert.match(errorLog, /shield_information_barriers: /);

  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis/findings.json"), "utf8"));
  assert.equal(findings.find((entry) => entry.id === "BOX-12").status, "manual");
  assert.equal(findings.find((entry) => entry.id === "BOX-15").status, "manual");
  const executive = readFileSync(join(result.outputDir, "compliance/executive_summary.md"), "utf8");
  assert.match(executive, /Partial Collection Warnings/);
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
  assert.equal(parseDurationHours("24"), 24);
  assert.equal(parseDurationHours(undefined), undefined);
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
