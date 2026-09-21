import test from "node:test";
import assert from "node:assert/strict";
import { createVerify, generateKeyPairSync } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  realpathSync,
  readFileSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";

import {
  GCP_FRAMEWORKS,
  GcpAuditorClient,
  PUBLIC_MEMBER_IAM_QUERY,
  assessGcpDataProtection,
  assessGcpIdentity,
  assessGcpLoggingDetection,
  assessGcpNetworkSecurity,
  assessGcpOrgGuardrails,
  checkGcpAccess,
  createGcpServiceAccountAssertion,
  exchangeGcpCredentials,
  exportGcpAuditBundle,
  parseGcpCredentialsJson,
  resolveGcpConfiguration,
  resolveSecureOutputPath,
} from "../dist/extensions/grc-tools/gcp.js";

const NOW = new Date("2026-09-21T00:00:00.000Z");

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function sampleConfig(overrides = {}) {
  return {
    organizationId: "123456789012",
    projectId: "prod-audit",
    accessToken: "token",
    sourceChain: ["tests"],
    ...overrides,
  };
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    statusText: status === 200 ? "OK" : status === 403 ? "Forbidden" : "Error",
    headers: { "Content-Type": "application/json" },
  });
}

function forbidden() {
  return jsonResponse({ error: { code: 403, message: "Permission denied", status: "PERMISSION_DENIED" } }, 403);
}

const COMPLIANT = {
  organization: { name: "organizations/123456789012", displayName: "Example Org" },
  projects: {
    results: [
      { name: "//cloudresourcemanager.googleapis.com/projects/prod-audit", assetType: "cloudresourcemanager.googleapis.com/Project", project: "projects/111", displayName: "Prod Audit", state: "ACTIVE" },
    ],
  },
  iamPolicies: {
    results: [
      {
        resource: "//cloudresourcemanager.googleapis.com/projects/prod-audit",
        assetType: "cloudresourcemanager.googleapis.com/Project",
        project: "projects/111",
        policy: { bindings: [{ role: "roles/viewer", members: ["user:auditor@example.com", "serviceAccount:svc@prod-audit.iam.gserviceaccount.com"] }] },
      },
    ],
  },
  publicPolicies: { results: [] },
  serviceAccounts: { accounts: [{ name: "projects/prod-audit/serviceAccounts/svc@prod-audit.iam.gserviceaccount.com", email: "svc@prod-audit.iam.gserviceaccount.com" }] },
  keys: { keys: [] },
  entries: { entries: [{ insertId: "1", timestamp: "2026-09-20T00:00:00Z" }] },
  sinks: { sinks: [{ name: "audit-sink" }] },
  logBuckets: {
    buckets: [
      { name: "projects/prod-audit/locations/global/buckets/_Default", retentionDays: 90 },
      { name: "projects/prod-audit/locations/global/buckets/_Required", retentionDays: 400 },
    ],
  },
  settings: { name: "projects/prod-audit/settings" },
  sccSources: { sources: [{ name: "organizations/123456789012/sources/1" }] },
  sccFindings: { listFindingsResults: [] },
  booleanPolicy: { constraint: "constraints/x", booleanPolicy: { enforced: true } },
  listPolicy: { constraint: "constraints/iam.allowedPolicyMemberDomains", listPolicy: { allowedValues: ["C0abc123"] } },
  computeProject: { name: "prod-audit", commonInstanceMetadata: { items: [{ key: "enable-oslogin", value: "TRUE" }] } },
  instances: {
    items: {
      "zones/us-central1-a": {
        instances: [
          {
            name: "vm-1",
            status: "RUNNING",
            shieldedInstanceConfig: { enableSecureBoot: true, enableVtpm: true, enableIntegrityMonitoring: true },
            metadata: { items: [] },
            networkInterfaces: [{ network: "https://www.googleapis.com/compute/v1/projects/prod-audit/global/networks/default", subnetwork: "https://www.googleapis.com/compute/v1/projects/prod-audit/regions/us-central1/subnetworks/default" }],
          },
        ],
      },
    },
  },
  binaryAuthorization: { name: "projects/prod-audit/policy", defaultAdmissionRule: { evaluationMode: "REQUIRE_ATTESTATION", enforcementMode: "ENFORCED_BLOCK_AND_AUDIT_LOG" } },
  buckets: {
    items: [
      { name: "prod-bucket", iamConfiguration: { uniformBucketLevelAccess: { enabled: true }, publicAccessPrevention: "enforced" }, encryption: { defaultKmsKeyName: "projects/prod-audit/locations/us/keyRings/ring/cryptoKeys/key" } },
    ],
  },
  cryptoKeys: {
    assets: [
      {
        name: "//cloudkms.googleapis.com/projects/prod-audit/locations/us/keyRings/ring/cryptoKeys/key",
        assetType: "cloudkms.googleapis.com/CryptoKey",
        resource: { data: { name: "projects/prod-audit/locations/us/keyRings/ring/cryptoKeys/key", purpose: "ENCRYPT_DECRYPT", rotationPeriod: "7776000s", nextRotationTime: "2026-12-01T00:00:00Z", primary: { state: "ENABLED" } } },
      },
    ],
  },
  disks: { items: { "zones/us-central1-a": { disks: [{ name: "disk-1", diskEncryptionKey: { kmsKeyName: "projects/prod-audit/locations/us/keyRings/ring/cryptoKeys/key" } }] } } },
  managedZones: { managedZones: [{ name: "public-zone", dnsName: "example.com.", visibility: "public", dnssecConfig: { state: "on", defaultKeySpecs: [{ keyType: "keySigning", algorithm: "rsasha256" }] } }] },
  apiKeys: { keys: [{ name: "projects/111/locations/global/keys/abc", displayName: "maps", restrictions: { apiTargets: [{ service: "maps.googleapis.com" }], serverKeyRestrictions: { allowedIps: ["10.0.0.1"] } } }] },
  accessPolicies: { accessPolicies: [{ name: "accessPolicies/1", title: "default" }] },
  servicePerimeters: { servicePerimeters: [{ name: "accessPolicies/1/servicePerimeters/prod", perimeterType: "PERIMETER_TYPE_REGULAR", status: { resources: ["projects/111"], restrictedServices: ["storage.googleapis.com"] } }] },
  firewalls: { items: [{ name: "allow-internal-ssh", direction: "INGRESS", sourceRanges: ["10.0.0.0/8"], allowed: [{ IPProtocol: "tcp", ports: ["22"] }], network: "global/networks/default" }] },
  subnetworks: {
    items: {
      "regions/us-central1": {
        subnetworks: [{ name: "default", purpose: "PRIVATE", region: "https://www.googleapis.com/compute/v1/projects/prod-audit/regions/us-central1", network: "https://www.googleapis.com/compute/v1/projects/prod-audit/global/networks/default", logConfig: { enable: true, flowSampling: 0.5 }, privateIpGoogleAccess: true }],
      },
    },
  },
  routers: { items: { "regions/us-central1": { routers: [{ name: "nat-router", region: "https://www.googleapis.com/compute/v1/projects/prod-audit/regions/us-central1", network: "https://www.googleapis.com/compute/v1/projects/prod-audit/global/networks/default", nats: [{ name: "nat", natIpAllocateOption: "AUTO_ONLY", sourceSubnetworkIpRangesToNat: "ALL_SUBNETWORKS_ALL_IP_RANGES" }] }] } } },
  sslPolicies: { items: { global: { sslPolicies: [{ name: "strict", minTlsVersion: "TLS_1_2", profile: "RESTRICTED" }] } } },
  targetHttpsProxies: { items: { global: { targetHttpsProxies: [{ name: "web-proxy", sslPolicy: "https://www.googleapis.com/compute/v1/projects/prod-audit/global/sslPolicies/strict" }] } } },
  backendServices: { items: { global: { backendServices: [{ name: "web-backend", loadBalancingScheme: "EXTERNAL_MANAGED", protocol: "HTTPS", securityPolicy: "https://www.googleapis.com/compute/v1/projects/prod-audit/global/securityPolicies/armor" }] } } },
};

function routeCompliant(url, init, data = COMPLIANT) {
  const method = init?.method ?? "GET";
  const parsed = new URL(url);
  const path = parsed.pathname;
  if (parsed.hostname === "cloudresourcemanager.googleapis.com" && path.startsWith("/v1/organizations/")) return data.organization;
  if (path.endsWith(":searchAllResources")) {
    assert.equal(method, "GET");
    assert.equal(parsed.searchParams.get("assetTypes"), "cloudresourcemanager.googleapis.com/Project");
    return data.projects;
  }
  if (path.endsWith(":searchAllIamPolicies")) {
    assert.equal(method, "GET");
    return parsed.searchParams.get("query") === PUBLIC_MEMBER_IAM_QUERY ? data.publicPolicies : data.iamPolicies;
  }
  if (path.endsWith("/assets")) {
    assert.equal(parsed.searchParams.get("contentType"), "RESOURCE");
    return data.cryptoKeys;
  }
  if (path.endsWith("/keys") && parsed.hostname === "iam.googleapis.com") return data.keys;
  if (path.endsWith("/serviceAccounts")) return data.serviceAccounts;
  if (path.endsWith("/entries:list")) {
    assert.equal(method, "POST");
    return data.entries;
  }
  if (path.endsWith("/sinks")) return data.sinks;
  if (path.endsWith("/buckets") && parsed.hostname === "logging.googleapis.com") return data.logBuckets;
  if (path.endsWith("/settings")) return data.settings;
  if (path.endsWith("/sources")) return data.sccSources;
  if (path.endsWith("/findings")) return data.sccFindings;
  if (path.endsWith(":getEffectiveOrgPolicy")) {
    const body = JSON.parse(init.body);
    return body.constraint === "constraints/iam.allowedPolicyMemberDomains" ? data.listPolicy : data.booleanPolicy;
  }
  if (parsed.hostname === "compute.googleapis.com") {
    if (path.endsWith("/global/firewalls")) return data.firewalls;
    if (path.endsWith("/aggregated/subnetworks")) return data.subnetworks;
    if (path.endsWith("/aggregated/routers")) return data.routers;
    if (path.endsWith("/aggregated/instances")) return data.instances;
    if (path.endsWith("/aggregated/sslPolicies")) return data.sslPolicies;
    if (path.endsWith("/aggregated/targetHttpsProxies")) return data.targetHttpsProxies;
    if (path.endsWith("/aggregated/backendServices")) return data.backendServices;
    if (path.endsWith("/aggregated/disks")) return data.disks;
    if (/^\/compute\/v1\/projects\/[^/]+$/.test(path)) return data.computeProject;
  }
  if (parsed.hostname === "storage.googleapis.com" && path === "/storage/v1/b") return data.buckets;
  if (parsed.hostname === "dns.googleapis.com") return data.managedZones;
  if (parsed.hostname === "apikeys.googleapis.com") return data.apiKeys;
  if (path === "/v1/accessPolicies") return data.accessPolicies;
  if (path.endsWith("/servicePerimeters")) return data.servicePerimeters;
  if (parsed.hostname === "binaryauthorization.googleapis.com") return data.binaryAuthorization;
  throw new Error(`Unrouted URL in fixture: ${method} ${url}`);
}

function createClient(fetchImpl, config = sampleConfig()) {
  return new GcpAuditorClient(config, { fetchImpl, now: () => NOW });
}

async function runAllAssessments(client, options = {}) {
  return [
    await assessGcpIdentity(client, options),
    await assessGcpLoggingDetection(client, options),
    await assessGcpOrgGuardrails(client, options),
    await assessGcpDataProtection(client, options),
    await assessGcpNetworkSecurity(client, options),
  ];
}

function statuses(assessments) {
  return Object.fromEntries(assessments.flatMap((assessment) => assessment.findings.map((item) => [item.id, item.status])));
}

test("resolveGcpConfiguration prefers explicit args and accepts the GCP_ORG_ID alias", () => {
  const resolved = resolveGcpConfiguration(
    { organization_id: "123456789012", project_id: "project-a", access_token: "arg-token" },
    { GCP_ORGANIZATION_ID: "999999999999", GCP_PROJECT_ID: "env-project", GCP_ACCESS_TOKEN: "env-token" },
    () => undefined,
    () => undefined,
  );
  assert.equal(resolved.organizationId, "123456789012");
  assert.equal(resolved.projectId, "project-a");
  assert.equal(resolved.accessToken, "arg-token");
  assert.ok(resolved.sourceChain.includes("arguments-access-token"));

  const aliased = resolveGcpConfiguration({}, { GCP_ORG_ID: "555555555555", GCP_ACCESS_TOKEN: "env-token" }, () => undefined, () => undefined);
  assert.equal(aliased.organizationId, "555555555555");
  assert.ok(aliased.sourceChain.includes("environment-organization"));
});

test("resolveGcpConfiguration discovers service account and ADC credential files before gcloud", () => {
  const serviceAccount = JSON.stringify({ type: "service_account", client_email: "svc@p.iam.gserviceaccount.com", private_key: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n", token_uri: "https://oauth2.googleapis.com/token", project_id: "file-project" });
  const resolved = resolveGcpConfiguration(
    {},
    { GCP_CREDENTIALS_FILE: "/secure/sa.json", GCP_ORG_ID: "123456789012" },
    () => { throw new Error("gcloud must not run when a credentials file resolves"); },
    (pathname) => (pathname === "/secure/sa.json" ? serviceAccount : undefined),
  );
  assert.equal(resolved.accessToken, undefined);
  assert.equal(resolved.credentials.type, "service_account");
  assert.equal(resolved.projectId, "file-project");
  assert.ok(resolved.sourceChain.includes("environment-credentials-file"));

  const adc = JSON.stringify({ type: "authorized_user", client_id: "id", client_secret: "secret", refresh_token: "refresh" });
  const viaAdc = resolveGcpConfiguration({}, { GOOGLE_APPLICATION_CREDENTIALS: "/secure/adc.json", GCP_PROJECT_ID: "p" }, () => undefined, (pathname) => (pathname === "/secure/adc.json" ? adc : undefined));
  assert.equal(viaAdc.credentials.type, "authorized_user");
  assert.ok(viaAdc.sourceChain.includes("google-application-credentials"));

  assert.throws(() => resolveGcpConfiguration({}, { GCP_CREDENTIALS_FILE: "/missing.json", GCP_PROJECT_ID: "p" }, () => undefined, () => undefined), /not readable/);
  assert.throws(() => parseGcpCredentialsJson(JSON.stringify({ type: "external_account" })), /Unsupported credentials type/);
});

test("service account JWT flow signs RS256 assertions with documented claims and grant type", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const credentials = parseGcpCredentialsJson(JSON.stringify({
    type: "service_account",
    client_email: "svc@prod-audit.iam.gserviceaccount.com",
    private_key: privateKey.export({ type: "pkcs8", format: "pem" }),
    token_uri: "https://oauth2.googleapis.com/token",
  }));
  const assertion = createGcpServiceAccountAssertion(credentials, NOW);
  const [header, claims, signature] = assertion.split(".");
  assert.deepEqual(JSON.parse(Buffer.from(header, "base64url").toString()), { alg: "RS256", typ: "JWT" });
  const decodedClaims = JSON.parse(Buffer.from(claims, "base64url").toString());
  assert.equal(decodedClaims.iss, "svc@prod-audit.iam.gserviceaccount.com");
  assert.equal(decodedClaims.aud, "https://oauth2.googleapis.com/token");
  assert.equal(decodedClaims.scope, "https://www.googleapis.com/auth/cloud-platform");
  assert.equal(decodedClaims.exp - decodedClaims.iat, 3600);
  const verifier = createVerify("RSA-SHA256");
  verifier.update(`${header}.${claims}`);
  assert.ok(verifier.verify(publicKey, Buffer.from(signature, "base64url")));

  let tokenRequest;
  const token = await exchangeGcpCredentials(credentials, async (url, init) => {
    tokenRequest = { url, init, form: new URLSearchParams(init.body) };
    return jsonResponse({ access_token: "ya29.test", expires_in: 3599, token_type: "Bearer" });
  }, NOW);
  assert.equal(token, "ya29.test");
  assert.equal(tokenRequest.url, "https://oauth2.googleapis.com/token");
  assert.equal(tokenRequest.init.headers["Content-Type"], "application/x-www-form-urlencoded");
  assert.equal(tokenRequest.form.get("grant_type"), "urn:ietf:params:oauth:grant-type:jwt-bearer");
  assert.equal(tokenRequest.form.get("assertion"), assertion);

  const client = createClient(async (url, init) => {
    if (url === "https://oauth2.googleapis.com/token") return jsonResponse({ access_token: "ya29.client" });
    assert.equal(init.headers.Authorization, "Bearer ya29.client");
    return jsonResponse({ name: "organizations/123456789012" });
  }, sampleConfig({ accessToken: undefined, credentials }));
  assert.equal((await client.getOrganization()).name, "organizations/123456789012");
});

test("client encodes documented query parameters and paginates to completion with truncation flags", async () => {
  const seen = [];
  const client = createClient(async (url) => {
    seen.push(url);
    const parsed = new URL(url);
    if (parsed.pathname.endsWith(":searchAllIamPolicies")) {
      return jsonResponse(parsed.searchParams.get("pageToken") ? { results: [{ resource: "b" }] } : { results: [{ resource: "a" }], nextPageToken: "p2" });
    }
    if (parsed.pathname.endsWith("/global/firewalls")) {
      return jsonResponse({ items: [{ name: "fw-1" }], nextPageToken: "more" });
    }
    return jsonResponse({});
  });

  const publicBindings = await client.searchPublicIamBindings(500);
  assert.equal(publicBindings.items.length, 2);
  assert.equal(publicBindings.truncated, false);
  assert.ok(seen[0].endsWith("/v1/organizations/123456789012:searchAllIamPolicies?query=policy%3A%28allUsers+OR+allAuthenticatedUsers%29&pageSize=500"));
  assert.ok(seen[1].includes("pageToken=p2"));

  const firewalls = await client.listFirewalls("prod-audit", 1);
  assert.equal(firewalls.truncated, true);
  assert.ok(seen.at(-1).endsWith("/compute/v1/projects/prod-audit/global/firewalls?maxResults=500"));

  const assets = await client.listCryptoKeys(10);
  assert.ok(seen.at(-1).endsWith("/v1/organizations/123456789012/assets?contentType=RESOURCE&assetTypes=cloudkms.googleapis.com%2FCryptoKey&pageSize=10"));
  assert.deepEqual(assets.items, []);
});

test("self-check (a): every endpoint forbidden yields only manual verdicts", async () => {
  const client = createClient(async () => forbidden());
  const assessments = await runAllAssessments(client);
  const all = statuses(assessments);
  assert.equal(Object.keys(all).length, 31);
  for (const [id, status] of Object.entries(all)) {
    assert.equal(status, "manual", `${id} must be manual when every endpoint is forbidden`);
  }
  const identity = assessments[0];
  assert.match(identity.findings[0].summary, /403 Forbidden/);
  assert.match(identity.findings[0].summary, /Collect manually/);
  assert.ok(identity.errors.length > 0);

  const access = await checkGcpAccess(client);
  assert.equal(access.status, "limited");
  assert.ok(access.surfaces.every((surface) => surface.status === "not_readable"));
});

test("self-check (b): empty inventories never pass except where emptiness is compliant by intent", async () => {
  const client = createClient(async (url) => {
    const parsed = new URL(url);
    if (parsed.pathname.endsWith(":searchAllResources")) return jsonResponse(COMPLIANT.projects);
    if (parsed.hostname === "cloudresourcemanager.googleapis.com" && parsed.pathname.startsWith("/v1/organizations/")) return jsonResponse({});
    return jsonResponse({});
  });
  const all = statuses(await runAllAssessments(client));
  const passing = Object.entries(all).filter(([, status]) => status === "pass").map(([id]) => id);
  assert.deepEqual(passing, ["GCP-DATA-06"], "only API key restrictions may pass on an empty inventory (no keys exist)");
  assert.equal(all["GCP-IAM-01"], "manual");
  assert.equal(all["GCP-IAM-02"], "manual");
  assert.equal(all["GCP-LOG-04"], "manual");
  assert.equal(all["GCP-ORG-01"], "warn");
  assert.equal(all["GCP-DATA-01"], "manual");
  assert.equal(all["GCP-DATA-07"], "fail");
  assert.equal(all["GCP-NET-01"], "manual");
});

test("self-check (b2): an empty project inventory renders every per-project control manual", async () => {
  const client = createClient(async () => jsonResponse({}));
  const all = statuses(await runAllAssessments(client));
  assert.equal(Object.values(all).filter((status) => status === "pass").length, 0);
  assert.equal(all["GCP-IAM-02"], "manual");
  assert.equal(all["GCP-DATA-06"], "manual");
});

test("self-check (c): partial inventories (project cap, denied project) never pass", async () => {
  const client = createClient(async (url, init) => {
    const parsed = new URL(url);
    if (parsed.pathname.endsWith(":searchAllResources")) {
      return jsonResponse({
        results: [
          ...COMPLIANT.projects.results,
          { name: "//cloudresourcemanager.googleapis.com/projects/denied-project", assetType: "cloudresourcemanager.googleapis.com/Project", project: "projects/222" },
        ],
        nextPageToken: "more-projects",
      });
    }
    if (url.includes("denied-project")) return forbidden();
    return jsonResponse(routeCompliant(url, init));
  });
  const assessments = await runAllAssessments(client, { maxProjects: 2 });
  const all = statuses(assessments);
  for (const [id, status] of Object.entries(all)) {
    assert.notEqual(status, "pass", `${id} must not pass on a partial inventory`);
  }
  const uniform = assessments[3].findings.find((item) => item.id === "GCP-DATA-01");
  assert.equal(uniform.status, "warn");
  assert.match(uniform.summary, /Partial view: 1 of 2 projects denied/);
  assert.equal(uniform.evidence.seen, 1);
  assert.equal(assessments[0].summary.projects_truncated, true);
});

test("self-check (d): a fully compliant organization passes every automatable control", async () => {
  const client = createClient(async (url, init) => jsonResponse(routeCompliant(url, init)));
  const assessments = await runAllAssessments(client);
  const all = statuses(assessments);
  const notPassing = Object.entries(all).filter(([, status]) => status !== "pass");
  assert.deepEqual(notPassing, [], "every control must pass on the documented compliant fixture");
  assert.equal(Object.keys(all).length, 31);
  for (const assessment of assessments) {
    assert.deepEqual(assessment.errors, []);
    for (const item of assessment.findings) {
      assert.ok(item.controls.length > 0 && item.mappings.length > 0, `${item.id} needs spec controls and mappings`);
    }
  }
  const access = await checkGcpAccess(client);
  assert.equal(access.status, "healthy");
  assert.equal(access.surfaces.length, 10);
});

test("findings fail on documented violations (firewall, KMS, SSL, DNSSEC, OS Login, buckets)", async () => {
  const violating = {
    ...COMPLIANT,
    firewalls: { items: [{ name: "open-rdp", direction: "INGRESS", sourceRanges: ["0.0.0.0/0"], allowed: [{ IPProtocol: "tcp", ports: ["3380-3390"] }] }, { name: "disabled", disabled: true, sourceRanges: ["0.0.0.0/0"], allowed: [{ IPProtocol: "all" }] }] },
    cryptoKeys: { assets: [{ name: "k", assetType: "cloudkms.googleapis.com/CryptoKey", resource: { data: { name: "k", purpose: "ENCRYPT_DECRYPT", primary: { state: "ENABLED" } } } }] },
    targetHttpsProxies: { items: { global: { targetHttpsProxies: [{ name: "legacy", sslPolicy: undefined }] } } },
    managedZones: { managedZones: [{ name: "zone", visibility: "public", dnssecConfig: { state: "off" } }] },
    computeProject: { name: "prod-audit", commonInstanceMetadata: { items: [] } },
    booleanPolicy: { constraint: "constraints/x", booleanPolicy: {} },
    buckets: { items: [{ name: "legacy-bucket", iamConfiguration: { uniformBucketLevelAccess: { enabled: false } } }] },
    publicPolicies: { results: [{ resource: "//storage.googleapis.com/legacy-bucket", assetType: "storage.googleapis.com/Bucket", policy: { bindings: [{ role: "roles/storage.objectViewer", members: ["allUsers"] }] } }] },
    apiKeys: { keys: [{ name: "projects/111/locations/global/keys/open", restrictions: {} }] },
    binaryAuthorization: { defaultAdmissionRule: { evaluationMode: "ALWAYS_ALLOW", enforcementMode: "ENFORCED_BLOCK_AND_AUDIT_LOG" } },
    logBuckets: { buckets: [{ name: "projects/prod-audit/locations/global/buckets/_Default", retentionDays: 30 }, { name: "projects/prod-audit/locations/global/buckets/_Required", retentionDays: 400 }] },
  };
  const client = createClient(async (url, init) => jsonResponse(routeCompliant(url, init, violating)));
  const all = statuses(await runAllAssessments(client));
  assert.equal(all["GCP-NET-01"], "fail");
  assert.equal(all["GCP-DATA-03"], "fail");
  assert.equal(all["GCP-NET-05"], "fail");
  assert.equal(all["GCP-DATA-05"], "fail");
  assert.equal(all["GCP-ORG-06"], "fail");
  assert.equal(all["GCP-ORG-07"], "fail");
  assert.equal(all["GCP-DATA-01"], "fail");
  assert.equal(all["GCP-DATA-02"], "fail");
  assert.equal(all["GCP-DATA-06"], "fail");
  assert.equal(all["GCP-LOG-04"], "fail", "the fixed 400-day _Required bucket must not mask a 30-day _Default bucket");
  assert.equal(all["GCP-ORG-03"], "fail");
});

const COMPUTE_BACKED_FINDINGS = ["GCP-ORG-06", "GCP-ORG-08", "GCP-DATA-04", "GCP-NET-02", "GCP-NET-03", "GCP-NET-04", "GCP-NET-05", "GCP-NET-06"];

function withUnreachableScopes(data, decorate) {
  const copy = { ...data };
  for (const key of ["instances", "disks", "subnetworks", "routers", "sslPolicies", "targetHttpsProxies", "backendServices"]) {
    copy[key] = decorate(structuredClone(data[key]));
  }
  return copy;
}

test("self-check (c2): aggregatedList unreachables[] downgrade every compute-backed finding and name the scope", async () => {
  const partial = withUnreachableScopes(COMPLIANT, (list) => ({ ...list, unreachables: ["regions/europe-west1"] }));
  const client = createClient(async (url, init) => jsonResponse(routeCompliant(url, init, partial)));
  const assessments = await runAllAssessments(client);
  const all = statuses(assessments);
  for (const id of COMPUTE_BACKED_FINDINGS) {
    assert.equal(all[id], "warn", `${id} must not pass when a scope was unreachable`);
  }
  const flowLogs = assessments[4].findings.find((item) => item.id === "GCP-NET-02");
  assert.match(flowLogs.summary, /Partial view: 1 unreachable scopes not enumerated \(prod-audit: regions\/europe-west1\)/);
  assert.deepEqual(flowLogs.evidence.unreachable_scopes, ["prod-audit: regions/europe-west1"]);
  assert.equal(flowLogs.evidence.truncated, true);
  const osLogin = assessments[2].findings.find((item) => item.id === "GCP-ORG-06");
  assert.match(osLogin.summary, /unreachable scopes not enumerated/);
  assert.equal(Object.values(all).filter((status) => status === "pass").length, 31 - COMPUTE_BACKED_FINDINGS.length);
});

test("self-check (c3): a scope answering with warning.code UNREACHABLE is treated as not enumerated", async () => {
  const partial = withUnreachableScopes(COMPLIANT, (list) => ({
    ...list,
    items: { ...list.items, "zones/europe-west1-b": { warning: { code: "UNREACHABLE", message: "Scope unreachable", data: [{ key: "scope", value: "zones/europe-west1-b" }] } } },
  }));
  const client = createClient(async (url, init) => jsonResponse(routeCompliant(url, init, partial)));
  const assessments = await runAllAssessments(client);
  const all = statuses(assessments);
  for (const id of COMPUTE_BACKED_FINDINGS) {
    assert.equal(all[id], "warn", `${id} must not pass when a scope warns UNREACHABLE`);
  }
  const shielded = assessments[2].findings.find((item) => item.id === "GCP-ORG-08");
  assert.deepEqual(shielded.evidence.unreachable_scopes, ["prod-audit: zones/europe-west1-b"]);

  const client2 = createClient(async (url, init) => jsonResponse(routeCompliant(url, init, withUnreachableScopes(COMPLIANT, (list) => ({
    ...list,
    items: { ...list.items, "zones/europe-west1-c": { warning: { code: "NO_RESULTS_ON_PAGE", message: "No results" } } },
  })))));
  const emptyScope = await client2.listInstances("prod-audit");
  assert.equal(emptyScope.truncated, false, "an empty scope with NO_RESULTS_ON_PAGE is complete, not unreachable");
  assert.equal(emptyScope.unreachable, undefined);
});

test("GCP-NET-05 keys SSL policies by scope so a weak regional policy sharing a global name fails", async () => {
  const regionalPolicy = {
    name: "strict",
    minTlsVersion: "TLS_1_0",
    profile: "COMPATIBLE",
    region: "https://www.googleapis.com/compute/v1/projects/prod-audit/regions/europe-west1",
    selfLink: "https://www.googleapis.com/compute/v1/projects/prod-audit/regions/europe-west1/sslPolicies/strict",
  };
  const regionalProxy = {
    name: "eu-proxy",
    region: "https://www.googleapis.com/compute/v1/projects/prod-audit/regions/europe-west1",
    sslPolicy: "https://www.googleapis.com/compute/v1/projects/prod-audit/regions/europe-west1/sslPolicies/strict",
  };
  for (const globalFirst of [true, false]) {
    const globalScope = COMPLIANT.sslPolicies.items.global;
    const regionalScope = { sslPolicies: [regionalPolicy] };
    const colliding = {
      ...COMPLIANT,
      sslPolicies: { items: globalFirst ? { global: globalScope, "regions/europe-west1": regionalScope } : { "regions/europe-west1": regionalScope, global: globalScope } },
      targetHttpsProxies: { items: { ...COMPLIANT.targetHttpsProxies.items, "regions/europe-west1": { targetHttpsProxies: [regionalProxy] } } },
    };
    const client = createClient(async (url, init) => jsonResponse(routeCompliant(url, init, colliding)));
    const result = await assessGcpNetworkSecurity(client);
    const finding = result.findings.find((item) => item.id === "GCP-NET-05");
    assert.equal(finding.status, "fail", `regional TLS_1_0 policy must fail regardless of scope order (globalFirst=${globalFirst})`);
    assert.deepEqual(finding.evidence.weak_proxies.map((proxy) => proxy.proxy), ["eu-proxy"]);
    assert.equal(finding.evidence.weak_proxies[0].sslPolicy, "projects/prod-audit/regions/europe-west1/sslPolicies/strict");
    assert.deepEqual(finding.evidence.unresolved_proxies, []);
  }
});

test("GCP-NET-04 counts DIRECT_IPV6 access configs as external addresses", async () => {
  const ipv6Only = {
    ...COMPLIANT,
    instances: structuredClone(COMPLIANT.instances),
  };
  ipv6Only.instances.items["zones/us-central1-a"].instances[0].networkInterfaces[0].ipv6AccessConfigs = [
    { type: "DIRECT_IPV6", name: "external-ipv6", externalIpv6: "2600:1900:4000::", externalIpv6PrefixLength: 96, networkTier: "PREMIUM" },
  ];
  const client = createClient(async (url, init) => jsonResponse(routeCompliant(url, init, ipv6Only)));
  const result = await assessGcpNetworkSecurity(client);
  const finding = result.findings.find((item) => item.id === "GCP-NET-04");
  assert.equal(finding.status, "warn");
  assert.deepEqual(finding.evidence.instances_with_external_ip, [{ projectId: "prod-audit", instance: "vm-1" }]);
  assert.equal(result.summary.instances_with_external_ip, 1);
});

test("GCP-NET-02 reads enableFlowLogs as well as logConfig.enable", async () => {
  const legacyField = {
    ...COMPLIANT,
    subnetworks: { items: { "regions/us-central1": { subnetworks: [{ ...COMPLIANT.subnetworks.items["regions/us-central1"].subnetworks[0], logConfig: undefined, enableFlowLogs: true }] } } },
  };
  const client = createClient(async (url, init) => jsonResponse(routeCompliant(url, init, legacyField)));
  const result = await assessGcpNetworkSecurity(client);
  assert.equal(result.findings.find((item) => item.id === "GCP-NET-02").status, "pass");

  const neither = {
    ...COMPLIANT,
    subnetworks: { items: { "regions/us-central1": { subnetworks: [{ ...COMPLIANT.subnetworks.items["regions/us-central1"].subnetworks[0], logConfig: { enable: false }, enableFlowLogs: false }] } } },
  };
  const client2 = createClient(async (url, init) => jsonResponse(routeCompliant(url, init, neither)));
  const result2 = await assessGcpNetworkSecurity(client2);
  assert.equal(result2.findings.find((item) => item.id === "GCP-NET-02").status, "fail");
});

test("GCP-NET-04 judges NAT coverage per subnetwork from sourceSubnetworkIpRangesToNat", async () => {
  const base = COMPLIANT.subnetworks.items["regions/us-central1"].subnetworks[0];
  const sibling = { ...base, name: "backend", selfLink: "https://www.googleapis.com/compute/v1/projects/prod-audit/regions/us-central1/subnetworks/backend" };
  const listOfSubnetworks = {
    ...COMPLIANT,
    subnetworks: { items: { "regions/us-central1": { subnetworks: [{ ...base, selfLink: "https://www.googleapis.com/compute/v1/projects/prod-audit/regions/us-central1/subnetworks/default" }, sibling] } } },
    routers: {
      items: {
        "regions/us-central1": {
          routers: [{
            ...COMPLIANT.routers.items["regions/us-central1"].routers[0],
            nats: [{
              name: "nat",
              sourceSubnetworkIpRangesToNat: "LIST_OF_SUBNETWORKS",
              subnetworks: [{ name: "https://www.googleapis.com/compute/v1/projects/prod-audit/regions/us-central1/subnetworks/default", sourceIpRangesToNat: ["ALL_IP_RANGES"] }],
            }],
          }],
        },
      },
    },
  };
  const client = createClient(async (url, init) => jsonResponse(routeCompliant(url, init, listOfSubnetworks)));
  const result = await assessGcpNetworkSecurity(client);
  const finding = result.findings.find((item) => item.id === "GCP-NET-04");
  assert.equal(finding.status, "warn");
  assert.deepEqual(finding.evidence.subnets_without_nat.map((subnet) => subnet.subnetwork), ["backend"]);

  const noOption = structuredClone(listOfSubnetworks);
  delete noOption.routers.items["regions/us-central1"].routers[0].nats[0].sourceSubnetworkIpRangesToNat;
  const client2 = createClient(async (url, init) => jsonResponse(routeCompliant(url, init, noOption)));
  const result2 = await assessGcpNetworkSecurity(client2);
  assert.deepEqual(
    result2.findings.find((item) => item.id === "GCP-NET-04").evidence.subnets_without_nat.map((subnet) => subnet.subnetwork),
    ["default", "backend"],
    "a NAT without the documented option cannot support coverage (rule 6)",
  );
});

test("GCP-ORG-07 evaluates cluster, namespace, service account, and Istio admission rules", async () => {
  const strictDefault = COMPLIANT.binaryAuthorization.defaultAdmissionRule;
  const cases = [
    ["clusterAdmissionRules", "us-central1-a.prod-cluster"],
    ["kubernetesNamespaceAdmissionRules", "payments"],
    ["kubernetesServiceAccountAdmissionRules", "payments:deployer"],
    ["istioServiceIdentityAdmissionRules", "spiffe://example.com/ns/payments/sa/default"],
  ];
  for (const [mapName, key] of cases) {
    const permissive = {
      ...COMPLIANT,
      binaryAuthorization: { name: "projects/prod-audit/policy", defaultAdmissionRule: strictDefault, [mapName]: { [key]: { evaluationMode: "ALWAYS_ALLOW", enforcementMode: "ENFORCED_BLOCK_AND_AUDIT_LOG" } } },
    };
    const client = createClient(async (url, init) => jsonResponse(routeCompliant(url, init, permissive)));
    const result = await assessGcpOrgGuardrails(client);
    const finding = result.findings.find((item) => item.id === "GCP-ORG-07");
    assert.equal(finding.status, "fail", `${mapName} ALWAYS_ALLOW must fail under a strict default rule`);
    assert.deepEqual(finding.evidence.permissive_rules, [{ projectId: "prod-audit", rule: `${mapName}[${key}]`, evaluationMode: "ALWAYS_ALLOW" }]);
  }

  const dryRunCluster = {
    ...COMPLIANT,
    binaryAuthorization: { name: "projects/prod-audit/policy", defaultAdmissionRule: strictDefault, clusterAdmissionRules: { "us-central1-a.prod-cluster": { evaluationMode: "REQUIRE_ATTESTATION", enforcementMode: "DRYRUN_AUDIT_LOG_ONLY" } } },
  };
  const client = createClient(async (url, init) => jsonResponse(routeCompliant(url, init, dryRunCluster)));
  const finding = (await assessGcpOrgGuardrails(client)).findings.find((item) => item.id === "GCP-ORG-07");
  assert.equal(finding.status, "warn");
  assert.equal(finding.evidence.dry_run_rules[0].rule, "clusterAdmissionRules[us-central1-a.prod-cluster]");
});

test("project identifiers come only from the documented full resource name", async () => {
  const numbered = {
    ...COMPLIANT,
    projects: { results: [{ name: "//cloudresourcemanager.googleapis.com/projects/111", assetType: "cloudresourcemanager.googleapis.com/Project", project: "projects/111", displayName: "Prod Audit", state: "ACTIVE", additionalAttributes: { projectId: "ignored-attribute" } }] },
  };
  const seen = [];
  const client = createClient(async (url, init) => {
    seen.push(url);
    return jsonResponse(routeCompliant(url, init, numbered));
  });
  const result = await assessGcpNetworkSecurity(client);
  assert.deepEqual(result.snapshot.projects, ["111"]);
  assert.ok(seen.some((url) => url.includes("/compute/v1/projects/111/")));
  assert.ok(!seen.some((url) => url.includes("ignored-attribute")));

  const singleProject = new GcpAuditorClient(sampleConfig({ organizationId: undefined }), { fetchImpl: async () => jsonResponse({}), now: () => NOW });
  const inventory = await singleProject.listProjectInventory();
  assert.deepEqual(inventory.projects, [{ name: "//cloudresourcemanager.googleapis.com/projects/prod-audit", displayName: "prod-audit" }]);
});

test("GCP-NET-06 treats H2C backend services as HTTP(S) backends", async () => {
  const h2c = {
    ...COMPLIANT,
    backendServices: { items: { global: { backendServices: [{ name: "grpc-web", loadBalancingScheme: "EXTERNAL_MANAGED", protocol: "H2C" }] } } },
  };
  const client = createClient(async (url, init) => jsonResponse(routeCompliant(url, init, h2c)));
  const finding = (await assessGcpNetworkSecurity(client)).findings.find((item) => item.id === "GCP-NET-06");
  assert.equal(finding.status, "warn");
  assert.deepEqual(finding.evidence.backends_without_security_policy.map((backend) => backend.backendService), ["grpc-web"]);
});

test("assessGcpIdentity flags stale keys, undated keys, and privileged default service accounts", async () => {
  const client = {
    getNow: () => NOW,
    async listProjectInventory() {
      return { projects: [{ name: "//cloudresourcemanager.googleapis.com/projects/prod-audit" }], truncated: false };
    },
    async listServiceAccounts() {
      return [{ email: "svc@prod-audit.iam.gserviceaccount.com" }, { email: "other@prod-audit.iam.gserviceaccount.com" }];
    },
    async listServiceAccountKeys(_projectId, email) {
      return email.startsWith("svc") ? [{ name: "keys/1", validAfterTime: "2025-01-01T00:00:00Z" }] : [{ name: "keys/2" }];
    },
    async searchAllIamPolicies() {
      return {
        items: [{
          resource: "//cloudresourcemanager.googleapis.com/projects/prod-audit",
          policy: { bindings: [
            { role: "roles/owner", members: ["serviceAccount:123-compute@developer.gserviceaccount.com"] },
            { role: "roles/viewer", members: ["serviceAccount:svc@shared-services.iam.gserviceaccount.com"] },
          ] },
        }],
        truncated: false,
      };
    },
  };
  const result = await assessGcpIdentity(client, { staleDays: 90, maxKeys: 50 });
  const all = statuses([result]);
  assert.equal(all["GCP-IAM-01"], "fail");
  assert.equal(all["GCP-IAM-02"], "fail");
  assert.equal(all["GCP-IAM-03"], "warn");
  assert.equal(all["GCP-IAM-04"], "warn");
  assert.equal(all["GCP-IAM-05"], "fail");
  assert.equal(result.summary.undated_service_account_keys, 1);
});

test("exportGcpAuditBundle writes the shared layout, allocates -2 on rerun, and logs errors only when reads fail", async () => {
  const base = createTempBase("grclanker-gcp-export-");
  const client = createClient(async (url, init) => jsonResponse(routeCompliant(url, init)));
  const result = await exportGcpAuditBundle(client, sampleConfig(), base, { max_projects: 5 });
  assert.ok(result.outputDir.startsWith(realpathSync(base)));
  assert.equal(result.zipPath, `${result.outputDir}.zip`);
  assert.ok(existsSync(result.zipPath));
  assert.equal(result.errorCount, 0);
  assert.equal(result.findingCount, 31);
  for (const file of [
    "QUICK_REFERENCE.md",
    "metadata.json",
    "core_data/access.json",
    "core_data/identity.json",
    "core_data/network-security.json",
    "analysis/findings.json",
    "analysis/category_summaries.json",
    "analysis/data-protection.json",
    "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md",
    ...GCP_FRAMEWORKS.map((framework) => `compliance/frameworks/${framework.slug}.md`),
  ]) {
    assert.ok(existsSync(join(result.outputDir, file)), `${file} missing from bundle`);
  }
  assert.equal(GCP_FRAMEWORKS.length, 8);
  assert.ok(!existsSync(join(result.outputDir, "_errors.log")));
  const metadata = readFileSync(join(result.outputDir, "metadata.json"), "utf8");
  assert.ok(!metadata.includes("token"), "metadata must not include the access token value");
  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  assert.equal(findings.length, 31);

  const rerun = await exportGcpAuditBundle(client, sampleConfig(), base, { max_projects: 5 });
  assert.equal(basename(rerun.outputDir), `${basename(result.outputDir)}-2`);
  assert.equal(rerun.zipPath, `${rerun.outputDir}.zip`);

  const failingClient = createClient(async (url, init) => (new URL(url).hostname === "dns.googleapis.com" ? forbidden() : jsonResponse(routeCompliant(url, init))));
  const partial = await exportGcpAuditBundle(failingClient, sampleConfig(), base, { max_projects: 5 });
  assert.ok(partial.errorCount > 0);
  const errorLog = readFileSync(join(partial.outputDir, "_errors.log"), "utf8");
  assert.match(errorLog, /\[data-protection\] prod-audit: 403 Forbidden/);
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-gcp-output-");
  const nested = resolveSecureOutputPath(base, "bundle");
  assert.ok(nested.startsWith(realpathSync(base)));

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);

  const target = createTempBase("grclanker-gcp-symlink-target-");
  const linked = join(base, "linked");
  symlinkSync(target, linked);
  assert.throws(() => resolveSecureOutputPath(base, "linked/out"), /Refusing to use symlinked parent directory/);
});
