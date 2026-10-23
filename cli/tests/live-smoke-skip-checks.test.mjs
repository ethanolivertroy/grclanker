import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  BOX_AUTH_RESOLVER,
  GCP_AUTH_RESOLVER,
  SERVICENOW_AUTH_RESOLVER,
  SLACK_AUTH_RESOLVER,
} from "../dist/extensions/grc-tools/auth-resolver-contracts.js";

const SCRIPTS_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "scripts");
const REQUEST_MARKER = "live-smoke-skip-check-test: request to";

// Preloaded into every smoke run. A run that gets past its skip check reaches its first request here, prints the
// marker, and stops on the 401 instead of reaching a real tenant.
const FETCH_STUB = `globalThis.fetch = async (input) => {
  process.stderr.write(${JSON.stringify(REQUEST_MARKER)} + " " + new URL(String(input?.url ?? input)).origin + "\\n");
  return new Response(JSON.stringify({ error: "stubbed by live-smoke-skip-checks.test.mjs" }), {
    status: 401,
    headers: { "content-type": "application/json" },
  });
};
`;

const PRIVATE_KEY_PEM = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ type: "pkcs8", format: "pem" });

const BOX_JWT_CONFIG = JSON.stringify({
  boxAppSettings: {
    clientID: "jwt-client-id",
    clientSecret: "jwt-client-secret",
    appAuth: { publicKeyID: "kid-1234", privateKey: PRIVATE_KEY_PEM, passphrase: "" },
  },
  enterpriseID: "987654",
});
const BOX_TOKEN_CONFIG = "access_token: box-config-token\n";

const GCP_SERVICE_ACCOUNT = JSON.stringify({
  type: "service_account",
  project_id: "smoke-project",
  private_key_id: "key-1",
  private_key: PRIVATE_KEY_PEM,
  client_email: "auditor@smoke-project.iam.gserviceaccount.com",
  client_id: "1234567890",
  token_uri: "https://oauth2.googleapis.com/token",
});

const SERVICENOW_TOKEN_CONFIG = "instance: smoke\naccess_token: servicenow-config-token\n";
const SLACK_TOKEN_CONFIG = JSON.stringify({ user_token: "xoxp-smoke-config" });

// Each credential case is a set the tool's resolver accepts on its own. `files` are written under a temporary root
// whose `home/` is HOME and whose `work/` is the working directory; `{root}` in an env value names that root.
const SMOKE_SCRIPTS = {
  box: {
    script: "box-live-smoke.mjs",
    contract: BOX_AUTH_RESOLVER,
    credentials: [
      { name: "BOX_ACCESS_TOKEN", env: { BOX_ACCESS_TOKEN: "box-access-token" } },
      { name: "BOX_TOKEN", env: { BOX_TOKEN: "box-access-token" } },
      { name: "BOX_DEVELOPER_TOKEN", env: { BOX_DEVELOPER_TOKEN: "box-developer-token" } },
      {
        name: "BOX_REFRESH_TOKEN with BOX_CLIENT_ID and BOX_CLIENT_SECRET",
        env: { BOX_REFRESH_TOKEN: "box-refresh-token", BOX_CLIENT_ID: "box-client", BOX_CLIENT_SECRET: "box-secret" },
      },
      {
        name: "BOX_CLIENT_ID, BOX_CLIENT_SECRET, and BOX_ENTERPRISE_ID",
        env: { BOX_CLIENT_ID: "box-client", BOX_CLIENT_SECRET: "box-secret", BOX_ENTERPRISE_ID: "987654" },
      },
      {
        name: "BOX_CLIENT_ID, BOX_CLIENT_SECRET, and a user BOX_SUBJECT_ID",
        env: { BOX_CLIENT_ID: "box-client", BOX_CLIENT_SECRET: "box-secret", BOX_SUBJECT_TYPE: "user", BOX_SUBJECT_ID: "12345" },
      },
      {
        name: "BOX_JWT_CONFIG_PATH",
        files: { "box-jwt-config.json": BOX_JWT_CONFIG },
        env: { BOX_JWT_CONFIG_PATH: "{root}/box-jwt-config.json" },
      },
      { name: "BOX_CONFIG_PATH", files: { "box.yaml": BOX_TOKEN_CONFIG }, env: { BOX_CONFIG_PATH: "{root}/box.yaml" } },
      { name: "~/.box-sec-inspector/config.yaml", files: { "home/.box-sec-inspector/config.yaml": BOX_TOKEN_CONFIG } },
    ],
    settings: {
      BOX_AUTH_METHOD: "picks an auth mode, which still needs the credentials above",
      BOX_JWT_PASSPHRASE: "decrypts the private key in the BOX_JWT_CONFIG_PATH file",
      BOX_JWT_ALGORITHM: "picks the JWT signing algorithm",
      BOX_API_BASE_URL: "an endpoint override",
      BOX_BASE_URL: "an endpoint override",
      BOX_TOKEN_URL: "an endpoint override",
      BOX_TIMEOUT: "a request setting",
      BOX_MAX_RETRIES: "a request setting",
    },
  },
  gcp: {
    script: "gcp-live-smoke.mjs",
    contract: GCP_AUTH_RESOLVER,
    credentials: [
      { name: "GCP_ACCESS_TOKEN with GCP_PROJECT_ID", env: { GCP_ACCESS_TOKEN: "ya29.gcp", GCP_PROJECT_ID: "smoke-project" } },
      { name: "GCP_ACCESS_TOKEN with GCP_ORG_ID", env: { GCP_ACCESS_TOKEN: "ya29.gcp", GCP_ORG_ID: "123456789" } },
      {
        name: "GOOGLE_OAUTH_ACCESS_TOKEN with GCP_ORGANIZATION_ID",
        env: { GOOGLE_OAUTH_ACCESS_TOKEN: "ya29.oauth", GCP_ORGANIZATION_ID: "123456789" },
      },
      { name: "GOOGLE_ACCESS_TOKEN with GCLOUD_PROJECT", env: { GOOGLE_ACCESS_TOKEN: "ya29.google", GCLOUD_PROJECT: "smoke-project" } },
      {
        name: "GOOGLE_ACCESS_TOKEN with GOOGLE_CLOUD_PROJECT",
        env: { GOOGLE_ACCESS_TOKEN: "ya29.google", GOOGLE_CLOUD_PROJECT: "smoke-project" },
      },
      {
        name: "a service account in GCP_CREDENTIALS_FILE",
        files: { "service-account.json": GCP_SERVICE_ACCOUNT },
        env: { GCP_CREDENTIALS_FILE: "{root}/service-account.json" },
      },
      {
        name: "a service account in GOOGLE_APPLICATION_CREDENTIALS",
        files: { "service-account.json": GCP_SERVICE_ACCOUNT },
        env: { GOOGLE_APPLICATION_CREDENTIALS: "{root}/service-account.json" },
      },
      {
        name: "an ADC file under CLOUDSDK_CONFIG",
        files: { "gcloud-config/application_default_credentials.json": GCP_SERVICE_ACCOUNT },
        env: { CLOUDSDK_CONFIG: "{root}/gcloud-config" },
      },
      {
        name: "the ADC file at ~/.config/gcloud",
        files: { "home/.config/gcloud/application_default_credentials.json": GCP_SERVICE_ACCOUNT },
      },
    ],
    settings: {
      APPDATA: "locates the ADC file on Windows, which the script finds through defaultAdcPath()",
    },
  },
  servicenow: {
    script: "servicenow-live-smoke.mjs",
    contract: SERVICENOW_AUTH_RESOLVER,
    credentials: [
      {
        name: "SERVICENOW_INSTANCE_URL with SERVICENOW_TOKEN",
        env: { SERVICENOW_INSTANCE_URL: "https://smoke.service-now.com", SERVICENOW_TOKEN: "servicenow-token" },
      },
      {
        name: "SERVICENOW_URL with SERVICENOW_USERNAME and SERVICENOW_PASSWORD",
        env: { SERVICENOW_URL: "https://smoke.service-now.com", SERVICENOW_USERNAME: "auditor", SERVICENOW_PASSWORD: "servicenow-password" },
      },
      {
        name: "SERVICENOW_INSTANCE with SERVICENOW_CLIENT_ID and SERVICENOW_CLIENT_SECRET",
        env: { SERVICENOW_INSTANCE: "smoke", SERVICENOW_CLIENT_ID: "servicenow-client", SERVICENOW_CLIENT_SECRET: "servicenow-secret" },
      },
      {
        name: "SERVICENOW_INSTANCE with SERVICENOW_REFRESH_TOKEN and client credentials",
        env: {
          SERVICENOW_INSTANCE: "smoke",
          SERVICENOW_CLIENT_ID: "servicenow-client",
          SERVICENOW_CLIENT_SECRET: "servicenow-secret",
          SERVICENOW_REFRESH_TOKEN: "servicenow-refresh-token",
        },
      },
      { name: "SERVICENOW_INSTANCE with SERVICENOW_ACCESS_TOKEN", env: { SERVICENOW_INSTANCE: "smoke", SERVICENOW_ACCESS_TOKEN: "servicenow-token" } },
      {
        name: "SERVICENOW_CONFIG_FILE",
        files: { "servicenow.yaml": SERVICENOW_TOKEN_CONFIG },
        env: { SERVICENOW_CONFIG_FILE: "{root}/servicenow.yaml" },
      },
      { name: "./.servicenow.yaml", files: { "work/.servicenow.yaml": SERVICENOW_TOKEN_CONFIG } },
      { name: "~/.servicenow-sec-inspector/config.yaml", files: { "home/.servicenow-sec-inspector/config.yaml": SERVICENOW_TOKEN_CONFIG } },
    ],
    settings: {
      SERVICENOW_AUTH_METHOD: "picks an auth mode, which still needs the credentials above",
      SERVICENOW_TIMEOUT: "a request setting",
      SERVICENOW_MAX_RETRIES: "a request setting",
      SERVICENOW_PAGE_SIZE: "a request setting",
    },
  },
  slack: {
    script: "slack-live-smoke.mjs",
    contract: SLACK_AUTH_RESOLVER,
    credentials: [
      { name: "SLACK_USER_TOKEN", env: { SLACK_USER_TOKEN: "xoxp-smoke" } },
      { name: "SLACK_TOKEN", env: { SLACK_TOKEN: "xoxp-smoke" } },
      { name: "SLACK_BOT_TOKEN", env: { SLACK_BOT_TOKEN: "xoxb-smoke" } },
      { name: "SLACK_CONFIG_FILE", files: { "slack.json": SLACK_TOKEN_CONFIG }, env: { SLACK_CONFIG_FILE: "{root}/slack.json" } },
      { name: "~/.config/grclanker/slack.json", files: { "home/.config/grclanker/slack.json": SLACK_TOKEN_CONFIG } },
    ],
    settings: {
      SLACK_SCIM_TOKEN: "used beside a user or bot token; the tool refuses to run on a SCIM token alone",
      SLACK_ORG_ID: "scopes an Enterprise Grid org",
      SLACK_ENTERPRISE_ID: "scopes an Enterprise Grid org",
      SLACK_WEB_API_BASE_URL: "an endpoint override",
      SLACK_SCIM_BASE_URL: "an endpoint override",
      SLACK_AUDIT_BASE_URL: "an endpoint override",
      SLACK_TIMEOUT: "a request setting",
    },
  },
};

function runSmoke(script, { files = {}, env = {} } = {}) {
  const root = mkdtempSync(join(tmpdir(), "grclanker-live-smoke-skip-"));
  try {
    const home = join(root, "home");
    const work = join(root, "work");
    mkdirSync(home);
    mkdirSync(work);
    for (const [relativePath, contents] of Object.entries(files)) {
      const pathname = join(root, relativePath);
      mkdirSync(dirname(pathname), { recursive: true });
      writeFileSync(pathname, contents);
    }
    const stub = join(root, "fetch-stub.mjs");
    writeFileSync(stub, FETCH_STUB);
    const caseEnv = Object.fromEntries(Object.entries(env).map(([name, value]) => [name, value.replaceAll("{root}", root)]));
    const run = spawnSync(process.execPath, ["--import", pathToFileURL(stub).href, join(SCRIPTS_DIR, script)], {
      cwd: work,
      encoding: "utf8",
      timeout: 60_000,
      env: { PATH: process.env.PATH, HOME: home, USERPROFILE: home, ...caseEnv },
    });
    return { status: run.status, stdout: run.stdout ?? "", stderr: run.stderr ?? "", error: run.error };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function transcript(run) {
  return `exit ${run.status}${run.error ? ` (${run.error.message})` : ""}\n--- stdout\n${run.stdout}--- stderr\n${run.stderr}`;
}

for (const [tool, smoke] of Object.entries(SMOKE_SCRIPTS)) {
  test(`${smoke.script} skips, without a request, when no ${tool} credentials are configured`, () => {
    const run = runSmoke(smoke.script);
    assert.equal(run.status, 0, transcript(run));
    assert.match(run.stdout, /^Skipping /, transcript(run));
    assert.ok(!run.stderr.includes(REQUEST_MARKER), `a skipped run sends no request\n${transcript(run)}`);
  });

  for (const credential of smoke.credentials) {
    test(`${smoke.script} runs, rather than skips, with ${credential.name}`, () => {
      const run = runSmoke(smoke.script, credential);
      assert.doesNotMatch(run.stdout, /Skipping/, `the tool accepts ${credential.name}, so its live smoke must not skip\n${transcript(run)}`);
      assert.ok(run.stderr.includes(REQUEST_MARKER), `the run never reached a request with ${credential.name}\n${transcript(run)}`);
    });
  }

  test(`every variable in the ${tool} auth contract has a ${smoke.script} credential case or is listed as a setting`, () => {
    const exercised = new Set(smoke.credentials.flatMap((credential) => Object.keys(credential.env ?? {})));
    const unclassified = smoke.contract.environment.filter((name) => !exercised.has(name) && !Object.hasOwn(smoke.settings, name));
    assert.deepEqual(
      unclassified,
      [],
      `give each credential variable a case above, so ${smoke.script}'s skip check is tested against it, or list it under settings with the reason it is not a credential`,
    );
    const stale = Object.keys(smoke.settings).filter((name) => !smoke.contract.environment.includes(name));
    assert.deepEqual(stale, [], "a listed setting is no longer in the auth contract");
  });
}
