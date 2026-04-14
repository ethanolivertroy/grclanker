import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  DuoAuditorClient,
  assessDuoAdminAccess,
  assessDuoAuthentication,
  assessDuoIntegrations,
  assessDuoMonitoring,
  exportDuoAuditBundle,
  resolveDuoConfiguration,
  resolveSecureOutputPath,
  runDuoAccessCheck,
} from "../dist/extensions/grc-tools/duo.js";

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function dataset(data, error) {
  return error ? { data, error } : { data };
}

function createSampleConfig() {
  return {
    apiHost: "api-example.duosecurity.com",
    ikey: "DIXXXXXXXXXXXXXXXXXX",
    skey: "super-secret-key",
    lookbackDays: 30,
    sourceChain: ["tests"],
  };
}

function createSampleAuthenticationData() {
  return {
    settings: dataset({
      helpdesk_bypass: "limit",
      helpdesk_bypass_expiration: 60,
    }),
    policies: dataset([
      {
        policy_key: "global",
        policy_name: "Global Policy",
        is_global_policy: true,
        sections: {
          authentication_methods: {
            allowed_auth_list: ["webauthn", "duo-push"],
            require_verified_push: true,
            verified_push_digits: 6,
          },
          new_user: {
            new_user_behavior: "enroll",
          },
          remembered_devices: {
            browser_apps: {
              enabled: true,
              user_based: {
                max_time_value: 7,
                max_time_units: "days",
              },
            },
          },
          trusted_endpoints: {
            trusted_endpoint_checking: "require-trusted",
            trusted_endpoint_checking_mobile: "require-trusted",
          },
          duo_desktop: {
            requires_duo_desktop: true,
          },
          screen_lock: {
            require_screen_lock: true,
          },
        },
      },
    ]),
    globalPolicy: dataset({
      policy_key: "global",
      policy_name: "Global Policy",
      is_global_policy: true,
      sections: {
        authentication_methods: {
          allowed_auth_list: ["webauthn", "duo-push"],
          require_verified_push: true,
          verified_push_digits: 6,
        },
        new_user: {
          new_user_behavior: "enroll",
        },
        remembered_devices: {
          browser_apps: {
            enabled: true,
            user_based: {
              max_time_value: 7,
              max_time_units: "days",
            },
          },
        },
        trusted_endpoints: {
          trusted_endpoint_checking: "require-trusted",
          trusted_endpoint_checking_mobile: "require-trusted",
        },
        duo_desktop: {
          requires_duo_desktop: true,
        },
      },
    }),
    users: dataset([{ user_id: "DU123", username: "person@example.gov" }]),
    bypassCodes: dataset([]),
    webauthnCredentials: dataset([{ webauthnkey: "WK123" }]),
    allowedAdminAuthMethods: dataset({
      verified_push_enabled: true,
      verified_push_length: 6,
      webauthn_enabled: true,
      sms_enabled: false,
      voice_enabled: false,
    }),
    authenticationLogs: dataset([
      { txid: "tx-1", factor: "verified_duo_push", result: "success" },
      { txid: "tx-2", factor: "webauthn", result: "success" },
    ]),
  };
}

function createSampleAdminData() {
  return {
    settings: dataset({
      helpdesk_bypass: "limit",
      helpdesk_bypass_expiration: 60,
    }),
    admins: dataset([
      {
        admin_id: "A1",
        email: "owner@example.gov",
        role: "Owner",
        last_login: new Date().toISOString(),
      },
      {
        admin_id: "A2",
        email: "security@example.gov",
        role: "Help Desk",
        last_login: new Date().toISOString(),
      },
    ]),
    allowedAdminAuthMethods: dataset({
      verified_push_enabled: true,
      verified_push_length: 6,
      webauthn_enabled: true,
      sms_enabled: false,
      voice_enabled: false,
    }),
    activityLogs: dataset([{ eventtype: "admin.login", username: "owner@example.gov" }]),
  };
}

function createSampleIntegrationData() {
  return {
    settings: dataset({
      global_ssp_policy_enforced: true,
    }),
    policies: dataset([{ policy_key: "PO1", policy_name: "Global Policy", is_global_policy: true }]),
    globalPolicy: dataset({ policy_key: "global", is_global_policy: true, sections: {} }),
    integrations: dataset([
      {
        integration_key: "DIWEB1",
        name: "VPN",
        type: "websdk",
        user_access: "ALL_USERS",
        policy_key: "PO-VPN",
        prompt_v4_enabled: 1,
        frameless_auth_prompt_enabled: 1,
      },
      {
        integration_key: "DIADMIN1",
        name: "Read-only Admin API",
        type: "adminapi",
        user_access: "NO_USERS",
        adminapi_read_log: 1,
        adminapi_read_resource: 1,
        adminapi_admins_read: 1,
      },
    ]),
  };
}

function createSampleMonitoringData() {
  return {
    settings: dataset({
      fraud_email_enabled: true,
      push_activity_notification_enabled: true,
      email_activity_notification_enabled: false,
    }),
    infoSummary: dataset({
      telephony_credits_remaining: 400,
    }),
    authenticationLogs: dataset([
      { txid: "tx-1", factor: "verified_duo_push", result: "success" },
      { txid: "tx-2", factor: "webauthn", result: "success" },
    ]),
    activityLogs: dataset([{ eventtype: "admin.login" }]),
    telephonyLogs: dataset([]),
    trustMonitorEvents: dataset([{ sekey: "SE1", priority_event: true, state: "new" }]),
  };
}

test("resolveDuoConfiguration prefers explicit args over environment values", () => {
  const base = resolveDuoConfiguration(
    {},
    {
      DUO_API_HOST: "api-home.duosecurity.com",
      DUO_IKEY: "home-ikey",
      DUO_SKEY: "home-skey",
      DUO_LOOKBACK_DAYS: "14",
    },
  );
  assert.equal(base.apiHost, "api-home.duosecurity.com");
  assert.equal(base.ikey, "home-ikey");
  assert.equal(base.lookbackDays, 14);
  assert.deepEqual(base.sourceChain, ["environment"]);

  const overridden = resolveDuoConfiguration(
    {
      api_host: "https://api-override.duosecurity.com",
      ikey: "arg-ikey",
      skey: "arg-skey",
      lookback_days: 45,
    },
    {
      DUO_API_HOST: "api-home.duosecurity.com",
      DUO_IKEY: "home-ikey",
      DUO_SKEY: "home-skey",
      DUO_LOOKBACK_DAYS: "14",
    },
  );
  assert.equal(overridden.apiHost, "api-override.duosecurity.com");
  assert.equal(overridden.ikey, "arg-ikey");
  assert.equal(overridden.skey, "arg-skey");
  assert.equal(overridden.lookbackDays, 45);
  assert.deepEqual(overridden.sourceChain, ["environment", "arguments"]);
});

test("DuoAuditorClient handles v2/v5 signing, retries, and pagination", async () => {
  const state = {
    userRetries: 0,
    capturedAuthHeaders: [],
  };

  const fetchImpl = async (input, init = {}) => {
    const requestUrl = new URL(typeof input === "string" ? input : input.toString());
    const authHeader = init.headers?.Authorization ?? init.headers?.authorization;
    if (authHeader) {
      state.capturedAuthHeaders.push(String(authHeader));
    }

    if (requestUrl.pathname === "/admin/v1/users") {
      const offset = requestUrl.searchParams.get("offset") ?? "0";
      if (offset === "0" && state.userRetries === 0) {
        state.userRetries += 1;
        return new Response(JSON.stringify({ stat: "FAIL", code: 42901, message: "Rate limited" }), {
          status: 429,
          statusText: "Too Many Requests",
        });
      }
      if (offset === "0") {
        return new Response(
          JSON.stringify({
            stat: "OK",
            response: [{ user_id: "DU-1" }],
            metadata: { next_offset: 1, total_objects: 2 },
          }),
          { status: 200 },
        );
      }
      return new Response(
        JSON.stringify({
          stat: "OK",
          response: [{ user_id: "DU-2" }],
          metadata: { total_objects: 2 },
        }),
        { status: 200 },
      );
    }

    if (requestUrl.pathname === "/admin/v3/integrations") {
      return new Response(
        JSON.stringify({
          stat: "OK",
          response: [{ integration_key: "DI-1", name: "VPN", type: "websdk" }],
          metadata: { total_objects: 1 },
        }),
        { status: 200 },
      );
    }

    if (requestUrl.pathname === "/admin/v2/logs/authentication") {
      const nextOffset = requestUrl.searchParams.get("next_offset");
      if (!nextOffset) {
        return new Response(
          JSON.stringify({
            stat: "OK",
            response: {
              items: [{ txid: "tx-1", factor: "verified_duo_push" }],
              metadata: { next_offset: ["1234567890000", "tx-1"], total_objects: 2 },
            },
          }),
          { status: 200 },
        );
      }
      return new Response(
        JSON.stringify({
          stat: "OK",
          response: {
            items: [{ txid: "tx-2", factor: "webauthn" }],
            metadata: { total_objects: 2 },
          },
        }),
        { status: 200 },
      );
    }

    throw new Error(`Unexpected request: ${requestUrl.pathname}`);
  };

  const client = new DuoAuditorClient(createSampleConfig(), { fetchImpl });
  const users = await client.listUsers();
  const integrations = await client.listIntegrations();
  const logs = await client.listAuthenticationLogs(2, 10);

  assert.equal(users.length, 2);
  assert.equal(integrations.length, 1);
  assert.equal(logs.length, 2);
  assert.equal(state.userRetries, 1);
  assert.equal(state.capturedAuthHeaders.length >= 4, true);
  assert.match(state.capturedAuthHeaders[0], /^Basic /);
  assert.notEqual(state.capturedAuthHeaders[0], state.capturedAuthHeaders[state.capturedAuthHeaders.length - 1]);
});

test("Duo assessments generate mapped findings across all focus areas", async () => {
  const config = createSampleConfig();
  const access = await runDuoAccessCheck(
    {
      getSettings: async () => ({ key: "value" }),
      listUsers: async () => [{ user_id: "DU-1" }],
      listPolicies: async () => [{ policy_key: "global" }],
      listAdmins: async () => [{ admin_id: "A1" }],
      listAuthenticationLogs: async () => [{ txid: "tx-1" }],
      listIntegrations: async () => {
        throw new Error("Duo API request failed for /admin/v3/integrations (403 Forbidden)");
      },
    },
    config,
  );
  assert.equal(access.status, "limited");
  assert.equal(access.probes.some((probe) => probe.key === "integrations" && probe.status === "forbidden"), true);

  const authentication = assessDuoAuthentication(createSampleAuthenticationData(), config);
  const admin = assessDuoAdminAccess(createSampleAdminData(), config);
  const integrations = assessDuoIntegrations(createSampleIntegrationData(), config);
  const monitoring = assessDuoMonitoring(createSampleMonitoringData(), config);

  assert.equal(authentication.findings.length >= 6, true);
  assert.equal(admin.findings.length >= 4, true);
  assert.equal(integrations.findings.length >= 4, true);
  assert.equal(monitoring.findings.length >= 4, true);
  assert.equal(authentication.findings.some((finding) => finding.frameworks.fedramp.length > 0), true);
  assert.equal(integrations.summary.Pass >= 1, true);
});

test("exportDuoAuditBundle writes the expected package and secure paths stay rooted", async () => {
  const outputRoot = createTempBase("grclanker-duo-export-");
  const config = createSampleConfig();

  const client = {
    getSettings: async () => ({
      helpdesk_bypass: "limit",
      helpdesk_bypass_expiration: 60,
      global_ssp_policy_enforced: true,
      fraud_email_enabled: true,
      push_activity_notification_enabled: true,
      email_activity_notification_enabled: false,
    }),
    listPolicies: async () => createSampleAuthenticationData().policies.data,
    getGlobalPolicy: async () => createSampleAuthenticationData().globalPolicy.data,
    listUsers: async () => createSampleAuthenticationData().users.data,
    listBypassCodes: async () => [],
    listWebauthnCredentials: async () => createSampleAuthenticationData().webauthnCredentials.data,
    getAdminAllowedAuthMethods: async () => createSampleAuthenticationData().allowedAdminAuthMethods.data,
    listAuthenticationLogs: async () => createSampleMonitoringData().authenticationLogs.data,
    listAdmins: async () => createSampleAdminData().admins.data,
    listActivityLogs: async () => createSampleAdminData().activityLogs.data,
    listIntegrations: async () => createSampleIntegrationData().integrations.data,
    getInfoSummary: async () => createSampleMonitoringData().infoSummary.data,
    listTelephonyLogs: async () => [],
    listTrustMonitorEvents: async () => createSampleMonitoringData().trustMonitorEvents.data,
  };

  const result = await exportDuoAuditBundle(client, config, outputRoot);

  assert.equal(existsSync(result.outputDir), true);
  assert.equal(existsSync(result.zipPath), true);
  assert.equal(existsSync(join(result.outputDir, "README.md")), true);
  assert.equal(existsSync(join(result.outputDir, "summary.md")), true);
  assert.equal(existsSync(join(result.outputDir, "frameworks", "fedramp.md")), true);
  assert.match(readFileSync(join(result.outputDir, "summary.md"), "utf8"), /Duo authentication assessment/);
  assert.equal(result.findingCount > 0, true);
  assert.equal(result.fileCount > 5, true);

  assert.throws(
    () => resolveSecureOutputPath(outputRoot, "../escape"),
    /outside output root|symlinked output path/,
  );
});
