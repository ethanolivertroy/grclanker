import test from "node:test";
import assert from "node:assert/strict";
import { createVerify, generateKeyPairSync } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  realpathSync,
  readFileSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, relative } from "node:path";
import { inflateRawSync } from "node:zlib";

import {
  GCP_FRAMEWORKS,
  GCP_INVENTORIES,
  GCP_MAX_LIST_PAGES,
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
  for (const finding of assessments.flatMap((assessment) => assessment.findings)) {
    if ("seen" in finding.evidence) assert.equal(finding.evidence.seen, null, `${finding.id} must not render a count from an unreadable inventory`);
    assert.ok(finding.evidence.unreadable_inventories.length > 0, `${finding.id} must list the unreadable inventories`);
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
    return jsonResponse(routeCompliant(url, init, withUnreachableScopes(COMPLIANT, (list) => ({ ...list, unreachables: ["zones/europe-west1-b"] }))));
  });
  const assessments = await runAllAssessments(client, { maxProjects: 2 });
  const all = statuses(assessments);
  for (const [id, status] of Object.entries(all)) {
    assert.notEqual(status, "pass", `${id} must not pass on a partial inventory`);
  }
  const uniform = assessments[3].findings.find((item) => item.id === "GCP-DATA-01");
  assert.equal(uniform.status, "warn");
  // Round 4: a denied project is reported with the dataset and endpoint, not as a bare count.
  assert.match(uniform.summary, /Partial view: Cloud Storage buckets unreadable for 1 of 2 projects \(denied-project\) via storage\.googleapis\.com\/storage\/v1\/b\?project=\{project\} \(403 Forbidden\)/);
  assert.equal(uniform.evidence.seen, 1);
  assert.equal(uniform.evidence.denied_projects, 1);
  assert.deepEqual(uniform.evidence.unreadable_inventories.map((entry) => [entry.dataset, entry.scope]), [["Cloud Storage buckets", "1 of 2 projects (denied-project)"]]);
  assert.equal(assessments[0].summary.projects_truncated, true);
  const flowLogs = assessments[4].findings.find((item) => item.id === "GCP-NET-02");
  assert.match(flowLogs.summary, /VPC subnetworks unreadable for 1 of 2 projects \(denied-project\) via compute\.googleapis\.com\/compute\/v1\/projects\/\{project\}\/aggregated\/subnetworks \(403 Forbidden\); 1 unreachable scopes not enumerated \(prod-audit: zones\/europe-west1-b\); 1 seen, total unknown \(inventory incomplete\)/);
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

test("paginate records truncation when the cursor repeats or the page budget is reached", async () => {
  const fixedTokenUrls = [];
  const fixedToken = createClient(async (url) => {
    fixedTokenUrls.push(url);
    return jsonResponse({ items: [], nextPageToken: "stuck" });
  });
  const stuck = await fixedToken.listFirewalls("prod-audit");
  assert.deepEqual(stuck.items, []);
  assert.equal(stuck.truncated, true, "a cursor that stops advancing must be reported as truncation");
  assert.equal(fixedTokenUrls.length, 2, "the repeated token is fetched once and then abandoned");

  let advancing = 0;
  const advancingToken = createClient(async () => {
    advancing += 1;
    return jsonResponse({ items: [], nextPageToken: `page-${advancing}` });
  });
  const budgeted = await advancingToken.listFirewalls("prod-audit");
  assert.equal(budgeted.truncated, true, "an endless advancing cursor with empty pages must stop at the page budget");
  assert.equal(advancing, GCP_MAX_LIST_PAGES);

  let capped = 0;
  const cappedClient = createClient(async () => {
    capped += 1;
    return jsonResponse({ accounts: Array.from({ length: 100 }, (_, index) => ({ email: `sa-${capped}-${index}@prod-audit.iam.gserviceaccount.com` })), nextPageToken: `page-${capped}` });
  });
  const accounts = await cappedClient.listServiceAccounts("prod-audit", 250);
  assert.equal(accounts.items.length, 300);
  assert.equal(accounts.truncated, true, "a cap exit must report truncated");
  assert.equal(capped, 3);
});

test("every capped list threads truncation into the verdicts (never-ending sink, bucket, account, source, and perimeter pages)", async () => {
  let bucketPage = 0;
  const client = createClient(async (url, init) => {
    const parsed = new URL(url);
    const path = parsed.pathname;
    if (path.endsWith("/sinks")) return jsonResponse({ sinks: [{ name: "audit-sink" }], nextPageToken: "stuck" });
    if (path.endsWith("/buckets") && parsed.hostname === "logging.googleapis.com") {
      bucketPage += 1;
      return jsonResponse({
        buckets: Array.from({ length: 100 }, (_, index) => ({ name: `projects/prod-audit/locations/global/buckets/custom-${bucketPage}-${index}`, retentionDays: 400 })),
        nextPageToken: `page-${bucketPage}`,
      });
    }
    if (path.endsWith("/serviceAccounts")) return jsonResponse({ ...COMPLIANT.serviceAccounts, nextPageToken: "stuck" });
    if (path.endsWith("/sources")) return jsonResponse({ ...COMPLIANT.sccSources, nextPageToken: "stuck" });
    if (path === "/v1/accessPolicies") return jsonResponse({ ...COMPLIANT.accessPolicies, nextPageToken: "stuck" });
    if (path.endsWith("/servicePerimeters")) return jsonResponse({ ...COMPLIANT.servicePerimeters, nextPageToken: "stuck" });
    return jsonResponse(routeCompliant(url, init));
  });
  const assessments = await runAllAssessments(client);
  const all = statuses(assessments);
  for (const id of ["GCP-LOG-03", "GCP-LOG-04", "GCP-LOG-05", "GCP-IAM-02", "GCP-IAM-03", "GCP-DATA-07"]) {
    assert.equal(all[id], "warn", `${id} must not pass when its list was cut off by the cap or a stuck cursor`);
  }
  const retention = assessments[1].findings.find((item) => item.id === "GCP-LOG-04");
  assert.equal(retention.evidence.truncated, true);
  assert.equal(retention.evidence.seen, 5000);
  assert.match(retention.summary, /Partial view: 5000 seen, total unknown \(inventory incomplete\)/);
  const sinks = assessments[1].findings.find((item) => item.id === "GCP-LOG-03");
  assert.match(sinks.summary, /1 seen, total unknown/);
  assert.equal(assessments[1].snapshot.sinks[0].truncated, true);
  assert.equal(assessments[1].snapshot.log_buckets[0].buckets.length, 5000);
  assert.equal(bucketPage, 50, "the bucket cap of 5000 stops after 50 pages of 100");
});

test("GCP-LOG-03 counts only enabled sinks toward coverage and names disabled sinks", async () => {
  const enabledClient = createClient(async (url, init) => jsonResponse(routeCompliant(url, init)));
  const enabled = (await assessGcpLoggingDetection(enabledClient)).findings.find((item) => item.id === "GCP-LOG-03");
  assert.equal(enabled.status, "pass");
  assert.deepEqual(enabled.evidence.projects_without_sinks, []);
  assert.deepEqual(enabled.evidence.disabled_sinks, []);
  assert.match(enabled.summary, /at least one enabled log sink\./);

  const disabledSink = { name: "audit-sink", destination: "storage.googleapis.com/audit-archive", disabled: true };
  const disabledClient = createClient(async (url, init) => jsonResponse(routeCompliant(url, init, { ...COMPLIANT, sinks: { sinks: [disabledSink] } })));
  const result = await assessGcpLoggingDetection(disabledClient);
  const disabled = result.findings.find((item) => item.id === "GCP-LOG-03");
  assert.equal(disabled.status, "fail", "a project whose only sink is disabled exports nothing and must not pass");
  assert.deepEqual(disabled.evidence.projects_without_sinks, ["prod-audit"]);
  assert.deepEqual(disabled.evidence.disabled_sinks, [{ projectId: "prod-audit", sink: "audit-sink", destination: "storage.googleapis.com/audit-archive" }]);
  assert.match(disabled.summary, /1 of 1 sampled projects have no enabled log sink \(1 sinks are disabled and export nothing\)/);
  assert.equal(result.summary.projects_with_log_sinks, 0);
  assert.equal(result.summary.disabled_log_sinks, 1);
  assert.deepEqual(result.snapshot.sinks[0].sinks, [{ name: "audit-sink", destination: "storage.googleapis.com/audit-archive", disabled: true }]);

  const mixedClient = createClient(async (url, init) => jsonResponse(routeCompliant(url, init, { ...COMPLIANT, sinks: { sinks: [disabledSink, { name: "org-sink", disabled: false }] } })));
  const mixed = (await assessGcpLoggingDetection(mixedClient)).findings.find((item) => item.id === "GCP-LOG-03");
  assert.equal(mixed.status, "pass");
  assert.match(mixed.summary, /\(1 disabled sinks were not counted\)/);
  assert.equal(mixed.evidence.disabled_sinks.length, 1);
});

test("GCP-NET-05 CUSTOM profiles carry the documented customFeatures cipher list for manual review", async () => {
  const seeded = {
    ...COMPLIANT,
    sslPolicies: { items: { global: { sslPolicies: [{ name: "strict", minTlsVersion: "TLS_1_2", profile: "CUSTOM", customFeatures: ["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"] }] } } },
  };
  const client = createClient(async (url, init) => jsonResponse(routeCompliant(url, init, seeded)));
  const result = await assessGcpNetworkSecurity(client);
  const finding = result.findings.find((item) => item.id === "GCP-NET-05");
  assert.equal(finding.status, "warn");
  assert.deepEqual(finding.evidence.unresolved_proxies[0].customFeatures, ["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"]);
  assert.deepEqual(result.snapshot.ssl_policies[0].customFeatures, ["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"]);
});

test("org guardrail snapshots and evidence never pass metadata values through", async () => {
  const secret = "SEEDED-STARTUP-SCRIPT-4c1d2e";
  const seeded = {
    ...COMPLIANT,
    computeProject: {
      name: "prod-audit",
      commonInstanceMetadata: { items: [{ key: "enable-oslogin", value: "TRUE" }, { key: "ssh-keys", value: `admin:ssh-rsa ${secret}` }, { key: "db-password", value: secret }] },
    },
    instances: structuredClone(COMPLIANT.instances),
  };
  seeded.instances.items["zones/us-central1-a"].instances[0].metadata = { items: [{ key: "startup-script", value: secret }, { key: "serial-port-enable", value: "0" }] };
  seeded.instances.items["zones/us-central1-a"].instances[0].labels = { owner: secret };
  const client = createClient(async (url, init) => jsonResponse(routeCompliant(url, init, seeded)));
  const result = await assessGcpOrgGuardrails(client);
  assert.ok(!JSON.stringify(result).includes(secret), "no metadata value may reach the assessment result");
  assert.deepEqual(result.snapshot.compute_projects, [{ projectId: "prod-audit", name: "prod-audit", enable_oslogin: true }]);
  assert.deepEqual(result.snapshot.instances, [{
    projectId: "prod-audit",
    name: "vm-1",
    enable_oslogin: null,
    serial_port_enable: false,
    shieldedInstanceConfig: { enableSecureBoot: true, enableVtpm: true, enableIntegrityMonitoring: true },
  }]);
  assert.deepEqual(Object.keys(result.snapshot.effective_policies.requireOsLogin), ["constraint", "enforced", "booleanPolicy", "listPolicy", "restoreDefault"]);
  assert.deepEqual(result.snapshot.effective_policies.allowedPolicyMemberDomains.listPolicy, { allValues: null, allowedValues: ["C0abc123"], deniedValues: [] });
  assert.deepEqual(result.findings.find((item) => item.id === "GCP-ORG-02").evidence.policy.listPolicy.allowedValues, ["C0abc123"]);
  assert.equal(statuses([result])["GCP-ORG-08"], "pass");
});

test("API key snapshots keep name, displayName, and restrictions but never keyString", async () => {
  const keyString = "AIzaSEEDED-KEYSTRING-7b2c9d";
  const seeded = {
    ...COMPLIANT,
    apiKeys: { keys: [{ ...COMPLIANT.apiKeys.keys[0], keyString, uid: "uid-1", etag: "etag-1", annotations: { note: keyString } }] },
  };
  const client = createClient(async (url, init) => jsonResponse(routeCompliant(url, init, seeded)));
  const result = await assessGcpDataProtection(client);
  assert.ok(!JSON.stringify(result).includes(keyString));
  assert.deepEqual(result.snapshot.api_keys, [{
    projectId: "prod-audit",
    name: "projects/111/locations/global/keys/abc",
    displayName: "maps",
    restrictions: {
      apiTargets: [{ service: "maps.googleapis.com", methods: [] }],
      browserKeyRestrictions: null,
      serverKeyRestrictions: { allowedIps: 1 },
      androidKeyRestrictions: null,
      iosKeyRestrictions: null,
    },
  }]);
  assert.equal(statuses([result])["GCP-DATA-06"], "pass");
});

function seededSecret(label) {
  return `SEEDED-${label}-a9f3e1c7`;
}

function seededFixture() {
  const secrets = {};
  const seed = (label) => {
    secrets[label] = seededSecret(label);
    return secrets[label];
  };
  const data = structuredClone(COMPLIANT);
  data.organization.description = seed("organization");
  data.projects.results[0].labels = { owner: seed("project-label") };
  data.projects.results[0].additionalAttributes = { projectId: seed("project-attribute") };
  data.iamPolicies.results[0].policy.bindings[0].condition = { expression: seed("iam-condition"), title: "cond" };
  data.publicPolicies = {
    results: [{
      resource: "//storage.googleapis.com/shared-bucket",
      assetType: "storage.googleapis.com/Bucket",
      policy: { bindings: [{ role: "roles/storage.objectViewer", members: ["allUsers"], condition: { description: seed("public-condition") } }] },
    }],
  };
  data.serviceAccounts.accounts[0].description = seed("service-account");
  data.keys = { keys: [{ name: "projects/prod-audit/serviceAccounts/svc/keys/1", validAfterTime: "2026-09-01T00:00:00Z", privateKeyData: seed("service-account-key") }] };
  data.entries.entries[0].textPayload = seed("log-entry");
  data.sinks.sinks[0].filter = seed("sink-filter");
  data.sinks.sinks[0].writerIdentity = seed("sink-writer");
  data.logBuckets.buckets[0].description = seed("log-bucket");
  data.settings.kmsServiceAccountId = seed("logging-settings");
  data.sccSources.sources[0].description = seed("scc-source");
  data.sccFindings = { listFindingsResults: [{ finding: { name: "organizations/123456789012/sources/1/findings/f1", sourceProperties: { detail: seed("scc-finding") } } }] };
  data.booleanPolicy.etag = seed("boolean-policy");
  data.listPolicy.etag = seed("list-policy");
  data.computeProject.commonInstanceMetadata.items.push({ key: "ssh-keys", value: seed("project-ssh-keys") }, { key: "db-password", value: seed("project-metadata") });
  const instance = data.instances.items["zones/us-central1-a"].instances[0];
  instance.metadata = { items: [{ key: "startup-script", value: seed("instance-startup-script") }] };
  instance.labels = { env: seed("instance-label") };
  instance.description = seed("instance-description");
  data.binaryAuthorization.description = seed("binary-authorization");
  data.buckets.items[0].labels = { team: seed("bucket-label") };
  data.buckets.items[0].website = { mainPageSuffix: seed("bucket-website") };
  data.cryptoKeys.assets[0].resource.data.labels = { purpose: seed("crypto-key-label") };
  data.disks.items["zones/us-central1-a"].disks[0].diskEncryptionKey.rawKey = seed("disk-raw-key");
  data.disks.items["zones/us-central1-a"].disks[0].description = seed("disk-description");
  data.managedZones.managedZones[0].description = seed("managed-zone");
  data.apiKeys.keys[0].keyString = seed("api-key-string");
  data.accessPolicies.accessPolicies[0].title = seed("access-policy");
  data.servicePerimeters.servicePerimeters[0].title = seed("perimeter-title");
  data.servicePerimeters.servicePerimeters[0].description = seed("perimeter-description");
  data.firewalls.items[0].description = seed("firewall");
  const subnet = data.subnetworks.items["regions/us-central1"].subnetworks[0];
  subnet.description = seed("subnetwork");
  subnet.logConfig.filterExpr = seed("subnetwork-filter");
  data.routers.items["regions/us-central1"].routers[0].description = seed("router");
  data.sslPolicies.items.global.sslPolicies[0].description = seed("ssl-policy");
  data.sslPolicies.items.global.sslPolicies[0].fingerprint = seed("ssl-policy-fingerprint");
  data.targetHttpsProxies.items.global.targetHttpsProxies[0].description = seed("https-proxy");
  const backend = data.backendServices.items.global.backendServices[0];
  backend.description = seed("backend-service");
  backend.iap = { enabled: true, oauth2ClientId: "client-id", oauth2ClientSecret: seed("backend-iap-secret"), oauth2ClientSecretSha256: seed("backend-iap-sha") };
  return { data, secrets };
}

function walkFiles(root) {
  const files = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const pathname = join(root, entry.name);
    if (entry.isDirectory()) files.push(...walkFiles(pathname));
    else files.push(pathname);
  }
  return files;
}

function readZipEntries(zipPath) {
  const buffer = readFileSync(zipPath);
  const endOfCentralDirectory = buffer.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  assert.ok(endOfCentralDirectory >= 0, "zip end of central directory record missing");
  const entryCount = buffer.readUInt16LE(endOfCentralDirectory + 10);
  let offset = buffer.readUInt32LE(endOfCentralDirectory + 16);
  const entries = [];
  for (let index = 0; index < entryCount; index += 1) {
    assert.equal(buffer.readUInt32LE(offset), 0x02014b50, "central directory header signature");
    const method = buffer.readUInt16LE(offset + 10);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const localOffset = buffer.readUInt32LE(offset + 42);
    const name = buffer.toString("utf8", offset + 46, offset + 46 + nameLength);
    assert.equal(buffer.readUInt32LE(localOffset), 0x04034b50, "local file header signature");
    const dataStart = localOffset + 30 + buffer.readUInt16LE(localOffset + 26) + buffer.readUInt16LE(localOffset + 28);
    const data = buffer.subarray(dataStart, dataStart + compressedSize);
    entries.push({ name, content: method === 8 ? inflateRawSync(data).toString("utf8") : data.toString("utf8") });
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

test("exportGcpAuditBundle never writes a seeded secret to any bundle file or zip entry", async () => {
  const { data, secrets } = seededFixture();
  const seededValues = Object.values(secrets);
  assert.ok(seededValues.length >= 40);
  const base = createTempBase("grclanker-gcp-hygiene-");
  const client = createClient(async (url, init) => jsonResponse(routeCompliant(url, init, data)));
  const result = await exportGcpAuditBundle(client, sampleConfig({ accessToken: seededSecret("access-token") }), base, { max_projects: 5 });
  assert.equal(result.errorCount, 0);

  const files = walkFiles(result.outputDir).map((pathname) => ({ name: relative(result.outputDir, pathname), content: readFileSync(pathname, "utf8") }));
  assert.ok(files.some((file) => file.name === "core_data/org-guardrails.json"));
  assert.ok(files.some((file) => file.name === "analysis/findings.json"));
  const zipEntries = readZipEntries(result.zipPath).filter((entry) => !entry.name.endsWith("/"));
  assert.equal(zipEntries.length, files.length, "every bundle file must be present in the zip");
  for (const file of files) {
    const entry = zipEntries.find((candidate) => candidate.name === file.name);
    assert.ok(entry, `${file.name} missing from zip`);
    assert.equal(entry.content, file.content, `${file.name} differs between directory and zip`);
  }

  const leaks = [];
  for (const { name, content } of [...files, ...zipEntries]) {
    for (const [label, value] of Object.entries(secrets)) {
      if (content.includes(value)) leaks.push(`${label} -> ${name}`);
    }
    if (content.includes(seededSecret("access-token"))) leaks.push(`access-token -> ${name}`);
  }
  assert.deepEqual(leaks, [], "seeded secrets reached the bundle");

  const everything = files.map((file) => file.content).join("\n");
  assert.ok(everything.includes("prod-bucket"), "bundle content must still carry resource identifiers");
  assert.ok(everything.includes("public-zone"));
  const quickReference = files.find((file) => file.name === "QUICK_REFERENCE.md").content;
  assert.match(quickReference, /projected API snapshots/);
  assert.ok(!quickReference.includes("raw API snapshots"));
});

test("assessGcpIdentity flags stale keys, undated keys, and privileged default service accounts", async () => {
  const client = {
    getNow: () => NOW,
    async listProjectInventory() {
      return { projects: [{ name: "//cloudresourcemanager.googleapis.com/projects/prod-audit" }], truncated: false };
    },
    async listServiceAccounts() {
      return { items: [{ email: "svc@prod-audit.iam.gserviceaccount.com" }, { email: "other@prod-audit.iam.gserviceaccount.com" }], truncated: false };
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

const ALL_FINDING_IDS = [
  "GCP-IAM-01", "GCP-IAM-02", "GCP-IAM-03", "GCP-IAM-04", "GCP-IAM-05",
  "GCP-LOG-01", "GCP-LOG-02", "GCP-LOG-03", "GCP-LOG-04", "GCP-LOG-05",
  "GCP-ORG-01", "GCP-ORG-02", "GCP-ORG-03", "GCP-ORG-04", "GCP-ORG-05", "GCP-ORG-06", "GCP-ORG-07", "GCP-ORG-08",
  "GCP-DATA-01", "GCP-DATA-02", "GCP-DATA-03", "GCP-DATA-04", "GCP-DATA-05", "GCP-DATA-06", "GCP-DATA-07",
  "GCP-NET-01", "GCP-NET-02", "GCP-NET-03", "GCP-NET-04", "GCP-NET-05", "GCP-NET-06",
];

const SECOND_PROJECT = "second-project";
const TWO_PROJECTS = {
  ...COMPLIANT,
  projects: {
    results: [
      ...COMPLIANT.projects.results,
      { name: `//cloudresourcemanager.googleapis.com/projects/${SECOND_PROJECT}`, assetType: "cloudresourcemanager.googleapis.com/Project", project: "projects/222", displayName: "Second", state: "ACTIVE" },
    ],
  },
};

function requestProject(url, init) {
  const parsed = new URL(url);
  const fromPath = parsed.pathname.match(/\/projects\/([^/:]+)/)?.[1];
  const fromQuery = parsed.searchParams.get("project");
  const body = init?.body ? JSON.parse(init.body) : {};
  const fromBody = body.resourceNames?.[0]?.replace(/^projects\//, "");
  return fromPath ?? fromQuery ?? fromBody ?? undefined;
}

/** Serves the compliant fixture for any project by rewriting the prod-audit references to the requested project. */
function routeForProject(url, init, data = TWO_PROJECTS) {
  const projectId = requestProject(url, init);
  const scoped = projectId && projectId !== "prod-audit" ? JSON.parse(JSON.stringify(data).replaceAll("prod-audit", projectId)) : data;
  return routeCompliant(url, init, scoped);
}

function requestFacts(url, init) {
  const parsed = new URL(url);
  return { host: parsed.hostname, path: parsed.pathname, query: parsed.searchParams, body: init?.body ? JSON.parse(init.body) : {} };
}

function denied(status) {
  return jsonResponse({ error: { code: status, message: "denied", status: status === 500 ? "INTERNAL" : "PERMISSION_DENIED" } }, status);
}

/** A client that serves two compliant projects except for one inventory, made unreadable fully or for the second project only. */
function clientWithUnreadable(match, status = 403, mode = "full", data = TWO_PROJECTS) {
  return createClient(async (url, init) => {
    if (match(requestFacts(url, init)) && (mode === "full" || requestProject(url, init) === SECOND_PROJECT)) return denied(status);
    return jsonResponse(routeForProject(url, init, data));
  });
}

function findingsById(assessments) {
  return Object.fromEntries(assessments.flatMap((assessment) => assessment.findings.map((item) => [item.id, item])));
}

const ORG_POLICY_DEPENDENTS = {
  "constraints/iam.allowedPolicyMemberDomains": ["GCP-ORG-02"],
  "constraints/iam.disableServiceAccountKeyCreation": ["GCP-ORG-03"],
  "constraints/iam.disableServiceAccountKeyUpload": ["GCP-ORG-04"],
  "constraints/compute.disableSerialPortAccess": ["GCP-ORG-05"],
  "constraints/compute.requireShieldedVm": ["GCP-ORG-05"],
  "constraints/compute.requireOsLogin": ["GCP-ORG-06"],
};

/** The effective org policy is one GCP_INVENTORIES surface read once per constraint; each read gets its own sweep row. */
function policySurfaceId(constraint) {
  return `effectiveOrgPolicy:${constraint}`;
}

/** One sweep row: the GCP_INVENTORIES key it covers, the URL shape that identifies its requests, and its dependents. */
function surface(key, endpoint, perProject, match, dependents, id = key) {
  return { key, id, name: GCP_INVENTORIES[key].dataset, endpoint, perProject, match, dependents };
}

/**
 * Every inventory the five assessments read, the URL shape that identifies it,
 * whether it is read per project, and exactly which findings depend on it.
 * Mirrors the reviewer's corollary harness so the dependency map stays true.
 */
const INVENTORY_SURFACES = [
  surface("organization", "/v1/organizations/{organization}", false, (r) => r.host === "cloudresourcemanager.googleapis.com" && r.path.startsWith("/v1/organizations/"), ["GCP-ORG-01"]),
  surface("projects", ":searchAllResources", false, (r) => r.path.endsWith(":searchAllResources"), ALL_FINDING_IDS),
  surface("iamPolicies", ":searchAllIamPolicies", false, (r) => r.path.endsWith(":searchAllIamPolicies") && r.query.get("query") !== PUBLIC_MEMBER_IAM_QUERY, ["GCP-IAM-01", "GCP-IAM-04", "GCP-IAM-05"]),
  surface("publicBindings", ":searchAllIamPolicies", false, (r) => r.path.endsWith(":searchAllIamPolicies") && r.query.get("query") === PUBLIC_MEMBER_IAM_QUERY, ["GCP-DATA-02"]),
  surface("cryptoKeys", "/assets", false, (r) => r.path.endsWith("/assets"), ["GCP-DATA-03"]),
  surface("serviceAccounts", "/serviceAccounts", true, (r) => r.path.endsWith("/serviceAccounts"), ["GCP-IAM-02", "GCP-IAM-03"]),
  surface("serviceAccountKeys", "/keys", true, (r) => r.host === "iam.googleapis.com" && r.path.endsWith("/keys"), ["GCP-IAM-02", "GCP-IAM-03"]),
  surface("adminActivity", "entries:list", true, (r) => r.path.endsWith("/entries:list") && /activity/.test(r.body.filter ?? ""), ["GCP-LOG-01"]),
  surface("dataAccess", "entries:list", true, (r) => r.path.endsWith("/entries:list") && /data_access/.test(r.body.filter ?? ""), ["GCP-LOG-02"]),
  surface("sinks", "/sinks", true, (r) => r.path.endsWith("/sinks"), ["GCP-LOG-03"]),
  surface("logBuckets", "/locations/-/buckets", true, (r) => r.host === "logging.googleapis.com" && r.path.endsWith("/buckets"), ["GCP-LOG-04"]),
  surface("loggingSettings", "/settings", true, (r) => r.path.endsWith("/settings"), []),
  surface("sccSources", "/sources", false, (r) => r.path.endsWith("/sources"), ["GCP-LOG-05"]),
  surface("sccFindings", "/sources/-/findings", false, (r) => r.path.endsWith("/findings"), ["GCP-LOG-05"]),
  ...Object.entries(ORG_POLICY_DEPENDENTS).map(([constraint, dependents]) => ({
    ...surface("effectiveOrgPolicy", ":getEffectiveOrgPolicy", false, (r) => r.path.endsWith(":getEffectiveOrgPolicy") && r.body.constraint === constraint, dependents, policySurfaceId(constraint)),
    name: `${GCP_INVENTORIES.effectiveOrgPolicy.dataset} ${constraint}`,
  })),
  surface("computeProject", "compute/v1/projects/{project}", true, (r) => r.host === "compute.googleapis.com" && /^\/compute\/v1\/projects\/[^/]+$/.test(r.path), ["GCP-ORG-06"]),
  surface("instances", "aggregated/instances", true, (r) => r.path.endsWith("/aggregated/instances"), ["GCP-ORG-06", "GCP-ORG-08", "GCP-NET-04"]),
  surface("binaryAuthorization", "binaryauthorization.googleapis.com/v1/projects/{project}/policy", true, (r) => r.host === "binaryauthorization.googleapis.com", ["GCP-ORG-07"]),
  surface("buckets", "storage/v1/b", true, (r) => r.host === "storage.googleapis.com", ["GCP-DATA-01", "GCP-DATA-02", "GCP-DATA-04"]),
  surface("disks", "aggregated/disks", true, (r) => r.path.endsWith("/aggregated/disks"), ["GCP-DATA-04"]),
  surface("managedZones", "/managedZones", true, (r) => r.host === "dns.googleapis.com", ["GCP-DATA-05"]),
  surface("apiKeys", "/locations/global/keys", true, (r) => r.host === "apikeys.googleapis.com", ["GCP-DATA-06"]),
  surface("accessPolicies", "/v1/accessPolicies", false, (r) => r.path === "/v1/accessPolicies", ["GCP-DATA-07"]),
  surface("servicePerimeters", "/servicePerimeters", false, (r) => r.path.endsWith("/servicePerimeters"), ["GCP-DATA-07"]),
  surface("firewalls", "global/firewalls", true, (r) => r.path.endsWith("/global/firewalls"), ["GCP-NET-01"]),
  surface("subnetworks", "aggregated/subnetworks", true, (r) => r.path.endsWith("/aggregated/subnetworks"), ["GCP-NET-02", "GCP-NET-03", "GCP-NET-04"]),
  surface("routers", "aggregated/routers", true, (r) => r.path.endsWith("/aggregated/routers"), ["GCP-NET-04"]),
  surface("sslPolicies", "aggregated/sslPolicies", true, (r) => r.path.endsWith("/aggregated/sslPolicies"), ["GCP-NET-05"]),
  surface("targetHttpsProxies", "aggregated/targetHttpsProxies", true, (r) => r.path.endsWith("/aggregated/targetHttpsProxies"), ["GCP-NET-05"]),
  surface("backendServices", "aggregated/backendServices", true, (r) => r.path.endsWith("/aggregated/backendServices"), ["GCP-NET-06"]),
];
const PER_PROJECT_SURFACE_IDS = new Set(INVENTORY_SURFACES.filter((row) => row.perProject).map((row) => row.id));

/** Fields the verdict engine adds to every finding; they describe the read itself rather than data derived from it. */
const ENGINE_EVIDENCE = new Set(["seen", "truncated", "denied_projects", "unreachable_scopes", "unreadable_inventories"]);

/**
 * Which sweep surfaces each evidence field is derived from. A field derived from a surface
 * that is unreadable must render null; a field listed with no source is a constant or a flag.
 * An evidence field missing from this map fails the sweep until it is classified.
 */
const KEY_SOURCES = ["serviceAccounts", "serviceAccountKeys"];
const PERIMETER_SOURCES = ["accessPolicies", "servicePerimeters"];
const EVIDENCE_SOURCES = {
  "GCP-IAM-01": { bindings: ["iamPolicies"], policies_scanned: ["iamPolicies"] },
  "GCP-IAM-02": { stale_keys: KEY_SOURCES, undated_keys: KEY_SOURCES, service_accounts: ["serviceAccounts"] },
  "GCP-IAM-03": { user_managed_keys: KEY_SOURCES, service_accounts: ["serviceAccounts"] },
  "GCP-IAM-04": { cross_project_bindings: ["iamPolicies"] },
  "GCP-IAM-05": { privileged_default_service_accounts: ["iamPolicies"] },
  "GCP-LOG-01": { projects_without_admin_activity: ["adminActivity"], projects_read: ["adminActivity"] },
  "GCP-LOG-02": { projects_without_data_access: ["dataAccess"], projects_read: ["dataAccess"] },
  "GCP-LOG-03": { projects_without_sinks: ["sinks"], disabled_sinks: ["sinks"], projects_read: ["sinks"] },
  "GCP-LOG-04": { short_retention_buckets: ["logBuckets"], unknown_retention_buckets: ["logBuckets"], buckets_read: ["logBuckets"] },
  "GCP-LOG-05": { scc_sources: ["sccSources"], sources_truncated: [], scc_findings: ["sccFindings"], findings_truncated: [] },
  "GCP-ORG-01": { sampled_projects: ["projects"], projects_truncated: [], target_project: [] },
  "GCP-ORG-02": { policy: [policySurfaceId("constraints/iam.allowedPolicyMemberDomains")], partial: [] },
  "GCP-ORG-03": { policy: [policySurfaceId("constraints/iam.disableServiceAccountKeyCreation")], partial: [] },
  "GCP-ORG-04": { policy: [policySurfaceId("constraints/iam.disableServiceAccountKeyUpload")], partial: [] },
  "GCP-ORG-05": { serial_port_policy: [policySurfaceId("constraints/compute.disableSerialPortAccess")], shielded_vm_policy: [policySurfaceId("constraints/compute.requireShieldedVm")], partial: [] },
  "GCP-ORG-06": {
    policy: [policySurfaceId("constraints/compute.requireOsLogin")],
    policy_enforced: [policySurfaceId("constraints/compute.requireOsLogin")],
    projects_without_os_login: ["computeProject"],
    instance_overrides: ["instances"],
    projects_read: ["computeProject"],
    instances_read: ["instances"],
  },
  "GCP-ORG-07": { permissive_rules: ["binaryAuthorization"], dry_run_rules: ["binaryAuthorization"], projects_read: ["binaryAuthorization"] },
  "GCP-ORG-08": { shielded_violations: ["instances"], shielded_unknown: ["instances"], serial_port_enabled: ["instances"], instances_read: ["instances"] },
  "GCP-DATA-01": { non_uniform_buckets: ["buckets"], buckets_read: ["buckets"] },
  "GCP-DATA-02": { public_bindings: ["publicBindings"], query: [], policies_matched: ["publicBindings"], buckets_read: ["buckets"] },
  "GCP-DATA-03": { keys_without_rotation: ["cryptoKeys"], overdue_rotation: ["cryptoKeys"], keys_read: ["cryptoKeys"] },
  "GCP-DATA-04": { buckets_without_cmek: ["buckets"], disks_without_cmek: ["disks"], buckets_read: ["buckets"], disks_read: ["disks"] },
  "GCP-DATA-05": { zones_without_dnssec: ["managedZones"], public_zones: ["managedZones"], private_zones: ["managedZones"] },
  "GCP-DATA-06": { unrestricted_keys: ["apiKeys"], keys_read: ["apiKeys"] },
  "GCP-DATA-07": { enforced_perimeters: PERIMETER_SOURCES, dry_run_only_perimeters: PERIMETER_SOURCES, access_policies: ["accessPolicies"] },
  "GCP-NET-01": { open_admin_rules: ["firewalls"], firewalls_read: ["firewalls"], admin_ports: [] },
  "GCP-NET-02": { subnets_without_flow_logs: ["subnetworks"], subnets_read: ["subnetworks"] },
  "GCP-NET-03": { subnets_without_private_google_access: ["subnetworks"], subnets_read: ["subnetworks"] },
  "GCP-NET-04": {
    subnets_without_nat: ["subnetworks", "routers"],
    subnets_with_unknown_nat: ["subnetworks"],
    instances_with_external_ip: ["instances"],
    subnets_read: ["subnetworks"],
    routers_read: ["routers"],
    instances_read: ["instances"],
  },
  "GCP-NET-05": { weak_proxies: ["targetHttpsProxies"], unresolved_proxies: ["targetHttpsProxies"], proxies_read: ["targetHttpsProxies"], ssl_policies_read: ["sslPolicies"] },
  "GCP-NET-06": { backends_without_security_policy: ["backendServices"], external_backends_read: ["backendServices"] },
};

/** The same classification for every assessment-level summary counter. */
const SUMMARY_SOURCES = {
  identity: {
    sampled_projects: ["projects"],
    projects_truncated: [],
    iam_policies: ["iamPolicies"],
    service_accounts: ["serviceAccounts"],
    privileged_bindings: ["iamPolicies"],
    stale_service_account_keys: KEY_SOURCES,
    undated_service_account_keys: KEY_SOURCES,
    user_managed_service_account_keys: KEY_SOURCES,
    cross_project_service_accounts: ["iamPolicies"],
    privileged_default_service_accounts: ["iamPolicies"],
    collection_errors: [],
  },
  "logging-detection": {
    sampled_projects: ["projects"],
    projects_truncated: [],
    projects_with_admin_activity: ["adminActivity"],
    projects_with_data_access: ["dataAccess"],
    projects_with_log_sinks: ["sinks"],
    disabled_log_sinks: ["sinks"],
    configurable_log_buckets: ["logBuckets"],
    short_retention_buckets: ["logBuckets"],
    scc_sources: ["sccSources"],
    scc_findings: ["sccFindings"],
    collection_errors: [],
  },
  "org-guardrails": {
    sampled_projects: ["projects"],
    projects_truncated: [],
    organization_visible: ["organization"],
    target_project: [],
    domain_restricted_sharing: [policySurfaceId("constraints/iam.allowedPolicyMemberDomains")],
    service_account_key_creation_disabled: [policySurfaceId("constraints/iam.disableServiceAccountKeyCreation")],
    service_account_key_upload_disabled: [policySurfaceId("constraints/iam.disableServiceAccountKeyUpload")],
    serial_port_disabled: [policySurfaceId("constraints/compute.disableSerialPortAccess")],
    shielded_vm_required: [policySurfaceId("constraints/compute.requireShieldedVm")],
    os_login_required_by_policy: [policySurfaceId("constraints/compute.requireOsLogin")],
    instances: ["instances"],
    binary_authorization_projects: ["binaryAuthorization"],
    binary_authorization_api_disabled: ["binaryAuthorization"],
    collection_errors: [],
  },
  "data-protection": {
    sampled_projects: ["projects"],
    projects_truncated: [],
    buckets: ["buckets"],
    non_uniform_buckets: ["buckets"],
    public_bindings: ["publicBindings"],
    crypto_keys: ["cryptoKeys"],
    keys_without_rotation: ["cryptoKeys"],
    disks: ["disks"],
    resources_without_cmek: ["buckets", "disks"],
    public_dns_zones: ["managedZones"],
    zones_without_dnssec: ["managedZones"],
    api_keys: ["apiKeys"],
    unrestricted_api_keys: ["apiKeys"],
    enforced_perimeters: PERIMETER_SOURCES,
    collection_errors: [],
  },
  "network-security": {
    sampled_projects: ["projects"],
    projects_truncated: [],
    firewalls: ["firewalls"],
    open_admin_rules: ["firewalls"],
    subnetworks: ["subnetworks"],
    subnets_without_flow_logs: ["subnetworks"],
    subnets_without_private_google_access: ["subnetworks"],
    subnets_without_nat: ["subnetworks", "routers"],
    subnets_with_unknown_nat: ["subnetworks"],
    instances_with_external_ip: ["instances"],
    https_proxies: ["targetHttpsProxies"],
    weak_ssl_proxies: ["targetHttpsProxies"],
    external_backends: ["backendServices"],
    backends_without_cloud_armor: ["backendServices"],
    collection_errors: [],
  },
};

/** A denied project inventory blocks every per-project read, so their derived fields are nulled with it. */
function derivedFromUnreadable(sources, row) {
  return sources.includes(row.id) || (row.key === "projects" && sources.some((id) => PER_PROJECT_SURFACE_IDS.has(id)));
}

function isStandInShape(value) {
  return value === 0 || (Array.isArray(value) && value.length === 0);
}

/** Zero-count clauses such as "none of 0 instances" or "All 0 buckets"; HTTP codes such as 403 do not match. */
function zeroCountPhrases(summary) {
  return summary.match(/(?<![\w.])0 [A-Za-z][\w-]*/g) ?? [];
}

/**
 * Asserts the null-rendering contract for one object (finding evidence or assessment summary) against its baseline:
 * every field is classified, fields derived from the unreadable surface are null, and no other field flips from a
 * non-zero baseline to 0 or [] (a numeric stand-in for data that was not read).
 */
function assertNullRendering(label, sources, actual, baseline, row, skip = new Set()) {
  for (const [field, value] of Object.entries(actual)) {
    if (skip.has(field)) continue;
    const fieldSources = sources[field];
    assert.ok(fieldSources, `${label}: field "${field}" is not classified in the source map; add it with the surfaces it derives from`);
    if (derivedFromUnreadable(fieldSources, row)) {
      assert.equal(value, null, `${label}: "${field}" derives from ${row.name}, which is unreadable, so it must render null (got ${JSON.stringify(value)})`);
    } else {
      assert.ok(!(isStandInShape(value) && !isStandInShape(baseline[field])), `${label}: "${field}" flipped from ${JSON.stringify(baseline[field])} to ${JSON.stringify(value)} while ${row.name} was unreadable; that is a stand-in for unread data`);
    }
  }
}

/** A partial view (one of two projects denied) must render partial values, never null and never a zero stand-in. */
function assertPartialRendering(label, actual, baseline, skip = new Set()) {
  for (const [field, value] of Object.entries(actual)) {
    if (skip.has(field)) continue;
    const baselineValue = baseline[field];
    if (typeof baselineValue === "number" || Array.isArray(baselineValue)) {
      assert.ok(value !== null, `${label}: "${field}" is null although one project still answered; a partial view renders the partial value`);
    }
    assert.ok(!(isStandInShape(value) && !isStandInShape(baselineValue)), `${label}: "${field}" flipped from ${JSON.stringify(baselineValue)} to ${JSON.stringify(value)} on a partial view`);
  }
}

function assertNoNewZeroPhrases(label, summary, baselineSummary) {
  const known = new Set(zeroCountPhrases(baselineSummary));
  for (const phrase of zeroCountPhrases(summary)) {
    assert.ok(known.has(phrase), `${label}: summary counts "${phrase}" for data that was not read: ${summary}`);
  }
}

/** Like clientWithUnreadable, but records which sweep predicates each served request matched. */
function sweepClient(requests, match, status = 403, mode = "full") {
  return createClient(async (url, init) => {
    const facts = requestFacts(url, init);
    requests.push({ request: `${facts.host}${facts.path}`, surfaces: INVENTORY_SURFACES.filter((row) => row.match(facts)).map((row) => row.id) });
    if (match && match(facts) && (mode === "full" || requestProject(url, init) === SECOND_PROJECT)) return denied(status);
    return jsonResponse(routeForProject(url, init));
  });
}

function assertEveryRequestClassified(requests, label) {
  const unclassified = requests.filter((entry) => entry.surfaces.length !== 1).map((entry) => `${entry.request} -> [${entry.surfaces.join(", ")}]`);
  assert.deepEqual(unclassified, [], `${label}: every request the client issues must match exactly one sweep predicate`);
}

test("per-inventory sweep covers every GCP_INVENTORIES surface and every request the collectors issue", async () => {
  assert.deepEqual([...new Set(INVENTORY_SURFACES.map((row) => row.key))].sort(), Object.keys(GCP_INVENTORIES).sort(), "every GCP_INVENTORIES key needs a sweep row and every row a key");
  const policyRows = INVENTORY_SURFACES.filter((row) => row.key === "effectiveOrgPolicy");
  assert.equal(policyRows.length, Object.keys(ORG_POLICY_DEPENDENTS).length, "one row per effective org policy constraint the tool reads");
  assert.equal(INVENTORY_SURFACES.length, Object.keys(GCP_INVENTORIES).length + policyRows.length - 1);
  assert.equal(new Set(INVENTORY_SURFACES.map((row) => row.id)).size, INVENTORY_SURFACES.length, "row ids are unique");
  for (const row of INVENTORY_SURFACES) {
    assert.ok(row.name.startsWith(GCP_INVENTORIES[row.key].dataset), `${row.id} names its dataset`);
    assert.ok(GCP_INVENTORIES[row.key].endpoint.includes(row.endpoint), `${row.id} endpoint fragment "${row.endpoint}" must be part of ${GCP_INVENTORIES[row.key].endpoint}`);
  }
  for (const [id, fields] of Object.entries(EVIDENCE_SOURCES)) {
    assert.ok(ALL_FINDING_IDS.includes(id), `${id} in EVIDENCE_SOURCES is not a finding`);
    for (const [field, sources] of Object.entries(fields)) {
      for (const source of sources) assert.ok(INVENTORY_SURFACES.some((row) => row.id === source), `${id}.${field} names unknown surface ${source}`);
    }
  }
  assert.deepEqual(Object.keys(EVIDENCE_SOURCES).sort(), [...ALL_FINDING_IDS].sort(), "every finding classifies its evidence");
  for (const fields of Object.values(SUMMARY_SOURCES)) {
    for (const sources of Object.values(fields)) {
      for (const source of sources) assert.ok(INVENTORY_SURFACES.some((row) => row.id === source), `summary source ${source} is not a sweep surface`);
    }
  }

  const requests = [];
  const assessments = await runAllAssessments(sweepClient(requests));
  assertEveryRequestClassified(requests, "compliant baseline");
  const requested = new Set(requests.flatMap((entry) => entry.surfaces));
  assert.deepEqual(INVENTORY_SURFACES.filter((row) => !requested.has(row.id)).map((row) => row.id), [], "every sweep surface must be requested by a compliant two-project run");
  assert.deepEqual(assessments.map((assessment) => assessment.category).sort(), Object.keys(SUMMARY_SOURCES).sort(), "every assessment summary is classified");
  for (const assessment of assessments) {
    assert.deepEqual(Object.keys(assessment.summary).sort(), Object.keys(SUMMARY_SOURCES[assessment.category]).sort(), `${assessment.category} summary fields must all be classified`);
  }
});

test("per-inventory sweep: exactly the dependent findings drop below pass when any inventory is unreadable, fully or for one project, and nothing derived from it renders as 0 or []", async () => {
  const baselineRun = await runAllAssessments(createClient(async (url, init) => jsonResponse(routeForProject(url, init))));
  const baseline = statuses(baselineRun);
  const baselineFindings = findingsById(baselineRun);
  const baselineSummaries = Object.fromEntries(baselineRun.map((assessment) => [assessment.category, assessment.summary]));
  assert.equal(Object.keys(baseline).length, 31);
  assert.deepEqual(Object.entries(baseline).filter(([, status]) => status !== "pass"), [], "two compliant projects must pass every control before the sweep");

  const table = [];
  for (const row of INVENTORY_SURFACES) {
    const expected = [...row.dependents].sort();
    for (const status of [403, 401, 500]) {
      const requests = [];
      const full = await runAllAssessments(sweepClient(requests, row.match, status, "full"));
      assertEveryRequestClassified(requests, `${row.name} unreadable (${status}, fully)`);
      const fullStatuses = statuses(full);
      const demoted = Object.entries(fullStatuses).filter(([, value]) => value !== "pass").map(([id]) => id).sort();
      assert.deepEqual(demoted, expected, `${row.name} unreadable (${status}, fully) must demote exactly ${expected.join(", ") || "nothing"}`);
      const fullFindings = findingsById(full);
      for (const id of ALL_FINDING_IDS) {
        const finding = fullFindings[id];
        const label = `${id} with ${row.name} unreadable (${status}, fully)`;
        if (!row.dependents.includes(id)) {
          assert.deepEqual(finding.evidence, baselineFindings[id].evidence, `${label}: a finding that does not read the surface must be unchanged`);
          assert.equal(finding.summary, baselineFindings[id].summary, `${label}: summary must be unchanged`);
          continue;
        }
        assert.ok(finding.summary.includes(row.name), `${id} must name "${row.name}" when it is unreadable (${status}); got: ${finding.summary}`);
        assert.ok(finding.summary.includes(row.endpoint), `${id} must name the endpoint "${row.endpoint}" (${status}); got: ${finding.summary}`);
        assert.ok(
          finding.evidence.unreadable_inventories.some((entry) => entry.dataset === row.name && entry.endpoint.includes(row.endpoint)),
          `${id} evidence.unreadable_inventories must carry ${row.name}`,
        );
        assertNullRendering(label, EVIDENCE_SOURCES[id], finding.evidence, baselineFindings[id].evidence, row, ENGINE_EVIDENCE);
        assertNoNewZeroPhrases(label, finding.summary, baselineFindings[id].summary);
      }
      for (const assessment of full) {
        assertNullRendering(`${assessment.category} summary with ${row.name} unreadable (${status}, fully)`, SUMMARY_SOURCES[assessment.category], assessment.summary, baselineSummaries[assessment.category], row);
      }
      if (status === 403) table.push({ surface: row.name, mode: "fully", demoted: demoted.map((id) => `${id}=${fullStatuses[id]}`) });

      if (!row.perProject) continue;
      const partialRequests = [];
      const partial = await runAllAssessments(sweepClient(partialRequests, row.match, status, "project"));
      assertEveryRequestClassified(partialRequests, `${row.name} unreadable (${status}, ${SECOND_PROJECT} only)`);
      const partialStatuses = statuses(partial);
      const demotedPartial = Object.entries(partialStatuses).filter(([, value]) => value !== "pass").map(([id]) => id).sort();
      assert.deepEqual(demotedPartial, expected, `${row.name} unreadable (${status}, ${SECOND_PROJECT} only) must demote exactly ${expected.join(", ") || "nothing"}`);
      const partialFindings = findingsById(partial);
      for (const id of ALL_FINDING_IDS) {
        const finding = partialFindings[id];
        const label = `${id} with ${row.name} unreadable (${status}, ${SECOND_PROJECT} only)`;
        if (!row.dependents.includes(id)) {
          assert.deepEqual(finding.evidence, baselineFindings[id].evidence, `${label}: a finding that does not read the surface must be unchanged`);
          continue;
        }
        assert.equal(finding.status, "warn", `${id} must warn, not pass or go manual, when one of two projects denies ${row.name}`);
        assert.ok(finding.summary.includes(row.name) && finding.summary.includes(row.endpoint), `${id} must name dataset and endpoint; got: ${finding.summary}`);
        assert.ok(finding.summary.includes(SECOND_PROJECT), `${id} must name the denied project; got: ${finding.summary}`);
        assertPartialRendering(label, finding.evidence, baselineFindings[id].evidence, ENGINE_EVIDENCE);
        assertNoNewZeroPhrases(label, finding.summary, baselineFindings[id].summary);
      }
      for (const assessment of partial) {
        assertPartialRendering(`${assessment.category} summary with ${row.name} unreadable (${status}, ${SECOND_PROJECT} only)`, assessment.summary, baselineSummaries[assessment.category]);
      }
      if (status === 403) table.push({ surface: row.name, mode: `${SECOND_PROJECT} only`, demoted: demotedPartial.map((id) => `${id}=${partialStatuses[id]}`) });
    }
  }
  assert.equal(table.length, INVENTORY_SURFACES.length + INVENTORY_SURFACES.filter((row) => row.perProject).length);
});

test("GCP-ORG-06 demotes and names constraints/compute.requireOsLogin when the effective policy is unreadable (rule 1 corollary)", async () => {
  const client = clientWithUnreadable((r) => r.path.endsWith(":getEffectiveOrgPolicy") && r.body.constraint === "constraints/compute.requireOsLogin", 403, "full", COMPLIANT);
  const result = await assessGcpOrgGuardrails(client);
  const finding = result.findings.find((item) => item.id === "GCP-ORG-06");
  assert.equal(finding.status, "warn");
  assert.match(finding.summary, /enable-oslogin=TRUE is set in commonInstanceMetadata for all 1 sampled projects/);
  assert.match(finding.summary, /Partial view: effective org policy constraints\/compute\.requireOsLogin unreadable for the sampled project prod-audit via cloudresourcemanager\.googleapis\.com\/v1\/projects\/\{project\}:getEffectiveOrgPolicy \(403 Forbidden\)/);
  assert.equal(finding.evidence.policy, null);
  assert.equal(finding.evidence.policy_enforced, null);
  assert.deepEqual(finding.evidence.projects_without_os_login, []);
  assert.equal(finding.evidence.unreadable_inventories.length, 1);
  assert.equal(finding.evidence.unreadable_inventories[0].dataset, "effective org policy constraints/compute.requireOsLogin");
  assert.match(finding.evidence.unreadable_inventories[0].error, /403 Forbidden/);
  assert.equal(result.summary.os_login_required_by_policy, null);
  assert.equal(statuses([result])["GCP-ORG-05"], "pass", "other constraints stay readable and pass");
});

test("GCP-ORG-06 demotes when the instance inventory is unreadable and renders instance overrides as null", async () => {
  for (const enforced of [true, false]) {
    const data = { ...COMPLIANT, booleanPolicy: { constraint: "constraints/x", booleanPolicy: { enforced } } };
    const client = clientWithUnreadable((r) => r.path.endsWith("/aggregated/instances"), 403, "full", data);
    const result = await assessGcpOrgGuardrails(client);
    const finding = result.findings.find((item) => item.id === "GCP-ORG-06");
    assert.equal(finding.status, "warn", `policy enforced=${enforced}`);
    assert.match(finding.summary, /Partial view: Compute Engine instances unreadable for 1 of 1 projects \(prod-audit\) via compute\.googleapis\.com\/compute\/v1\/projects\/\{project\}\/aggregated\/instances \(403 Forbidden\)/);
    assert.equal(finding.evidence.instance_overrides, null);
    assert.equal(finding.evidence.instances_read, null);
    assert.equal(finding.evidence.policy_enforced, enforced);
    assert.equal(result.summary.instances, null);
    const shielded = result.findings.find((item) => item.id === "GCP-ORG-08");
    assert.equal(shielded.status, "manual");
    assert.match(shielded.summary, /every sampled project denied the read of Compute Engine instances \(compute\.googleapis\.com\/compute\/v1\/projects\/\{project\}\/aggregated\/instances\)/);
    assert.equal(shielded.evidence.seen, null);
  }
});

test("GCP-ORG-02 through ORG-06 demote and name the project inventory when it is unreadable while a project ID is configured", async () => {
  const client = clientWithUnreadable((r) => r.path.endsWith(":searchAllResources"), 403, "full", COMPLIANT);
  const result = await assessGcpOrgGuardrails(client);
  const byId = findingsById([result]);
  for (const id of ["GCP-ORG-02", "GCP-ORG-03", "GCP-ORG-04", "GCP-ORG-05"]) {
    assert.equal(byId[id].status, "warn", `${id} must not pass when the project list could not be read`);
    assert.match(byId[id].summary, /Partial view: project inventory unreadable for the configured scope via cloudasset\.googleapis\.com\/v1\/\{scope\}:searchAllResources \(403 Forbidden\), so the effective policy was resolved only for the configured project prod-audit/);
    assert.equal(byId[id].evidence.partial, true);
    assert.equal(byId[id].evidence.unreadable_inventories[0].dataset, "project inventory");
  }
  assert.equal(byId["GCP-ORG-06"].status, "manual");
  assert.match(byId["GCP-ORG-06"].summary, /Manual: project inventory unreadable for the configured scope via cloudasset\.googleapis\.com\/v1\/\{scope\}:searchAllResources \(403 Forbidden/);
  assert.equal(byId["GCP-ORG-06"].evidence.seen, null);
  assert.equal(byId["GCP-ORG-06"].evidence.instance_overrides, null);
  assert.equal(byId["GCP-ORG-06"].evidence.projects_without_os_login, null);
  assert.equal(byId["GCP-ORG-01"].status, "manual");
  assert.match(byId["GCP-ORG-01"].summary, /project inventory unreadable for the configured scope via cloudasset\.googleapis\.com\/v1\/\{scope\}:searchAllResources/);
  assert.equal(byId["GCP-ORG-01"].evidence.sampled_projects, null);

  assert.equal(Object.values(statuses([result])).filter((status) => status === "pass").length, 0);

  const orgOnlyClient = createClient(async (url, init) => (requestFacts(url, init).path.endsWith(":searchAllResources") ? denied(403) : jsonResponse(routeCompliant(url, init))), sampleConfig({ projectId: undefined }));
  const withoutProject = findingsById([await assessGcpOrgGuardrails(orgOnlyClient)]);
  for (const id of ["GCP-ORG-02", "GCP-ORG-03", "GCP-ORG-04", "GCP-ORG-05", "GCP-ORG-06"]) {
    assert.equal(withoutProject[id].status, "manual", `${id} has no project to resolve the effective policy against`);
    assert.match(withoutProject[id].summary, /:searchAllResources/, `${id} must name the failed project inventory`);
  }
});

test("GCP-LOG-05 demotes when the findings list is unreadable or truncated and never fabricates a zero", async () => {
  const unreadable = await assessGcpLoggingDetection(clientWithUnreadable((r) => r.path.endsWith("/findings"), 403, "full", COMPLIANT));
  const finding = unreadable.findings.find((item) => item.id === "GCP-LOG-05");
  assert.equal(finding.status, "warn");
  assert.match(finding.summary, /returned 1 sources and an unreadable findings list/);
  assert.match(finding.summary, /Partial view: Security Command Center findings unreadable for the organization scope via securitycenter\.googleapis\.com\/v1\/organizations\/\{organization\}\/sources\/-\/findings \(403 Forbidden\)\. A partial view cannot pass\./);
  assert.equal(finding.evidence.scc_findings, null);
  assert.equal(finding.evidence.unreadable_inventories[0].dataset, "Security Command Center findings");
  assert.match(finding.evidence.unreadable_inventories[0].error, /403 Forbidden/);
  assert.equal(unreadable.summary.scc_findings, null);
  assert.equal(unreadable.summary.scc_sources, 1);

  const truncated = await assessGcpLoggingDetection(createClient(async (url, init) => {
    const facts = requestFacts(url, init);
    if (facts.path.endsWith("/findings")) return jsonResponse({ listFindingsResults: [{ finding: { name: "f" } }], nextPageToken: "stuck" });
    return jsonResponse(routeCompliant(url, init));
  }));
  const truncatedFinding = truncated.findings.find((item) => item.id === "GCP-LOG-05");
  assert.equal(truncatedFinding.status, "warn");
  assert.match(truncatedFinding.summary, /returned 1 sources and 2\+ findings/, "a stuck cursor exits after two pages and reports the count as a floor");
  assert.match(truncatedFinding.summary, /Partial view: the findings list was truncated/);
  assert.equal(truncatedFinding.evidence.findings_truncated, true);

  const sourcesUnreadable = await assessGcpLoggingDetection(clientWithUnreadable((r) => r.path.endsWith("/sources"), 403, "full", COMPLIANT));
  const manual = sourcesUnreadable.findings.find((item) => item.id === "GCP-LOG-05");
  assert.equal(manual.status, "manual");
  assert.match(manual.summary, /Security Command Center sources were not readable via securitycenter\.googleapis\.com\/v1\/organizations\/\{organization\}\/sources \(403 Forbidden/);
  assert.equal(manual.evidence.scc_sources, null);
  assert.equal(sourcesUnreadable.summary.scc_sources, null);
});

test("GCP-ORG-06 fails on existing projects and instances without OS Login even when constraints/compute.requireOsLogin is enforced (rule 6)", async () => {
  const run = async (computeProject, instances = COMPLIANT.instances) => {
    const data = { ...COMPLIANT, computeProject, instances };
    const result = await assessGcpOrgGuardrails(createClient(async (url, init) => jsonResponse(routeCompliant(url, init, data))));
    return result.findings.find((item) => item.id === "GCP-ORG-06");
  };

  const disabled = await run({ name: "prod-audit", commonInstanceMetadata: { items: [{ key: "enable-oslogin", value: "FALSE" }] } });
  assert.equal(disabled.status, "fail", "an enforced constraint never enables OS Login on an existing project with enable-oslogin=FALSE");
  assert.match(disabled.summary, /1 of 1 sampled projects lack enable-oslogin=TRUE in commonInstanceMetadata \(prod-audit\) and 0 instances override it/);
  assert.match(disabled.summary, /constraints\/compute\.requireOsLogin is enforced in the effective policy, which protects newly created projects and blocks future disabling but does not enable OS Login on existing resources/);
  assert.equal(disabled.evidence.policy_enforced, true);
  assert.deepEqual(disabled.evidence.projects_without_os_login, ["prod-audit"]);

  const absent = await run({ name: "prod-audit", commonInstanceMetadata: { items: [] } });
  assert.equal(absent.status, "fail", "an absent enable-oslogin key means OS Login is off on an existing project");
  assert.deepEqual(absent.evidence.projects_without_os_login, ["prod-audit"]);

  const override = await run(COMPLIANT.computeProject, {
    items: { "zones/us-central1-a": { instances: [{ ...COMPLIANT.instances.items["zones/us-central1-a"].instances[0], metadata: { items: [{ key: "enable-oslogin", value: "false" }] } }] } },
  });
  assert.equal(override.status, "fail");
  assert.match(override.summary, /0 of 1 sampled projects lack enable-oslogin=TRUE in commonInstanceMetadata and 1 instances override it \(prod-audit\/vm-1\)/);
  assert.deepEqual(override.evidence.instance_overrides, [{ projectId: "prod-audit", instance: "vm-1" }]);

  const compliant = await run(COMPLIANT.computeProject);
  assert.equal(compliant.status, "pass");
  assert.match(compliant.summary, /enable-oslogin=TRUE is set in commonInstanceMetadata for all 1 sampled projects with Compute Engine and none of 1 instances overrides it\. constraints\/compute\.requireOsLogin is enforced/);
  assert.equal(compliant.evidence.policy_enforced, true);
});

test("multi-inventory findings name the unreadable dataset and endpoint instead of a bare denied count", async () => {
  const routers = await assessGcpNetworkSecurity(clientWithUnreadable((r) => r.path.endsWith("/aggregated/routers"), 403, "full", COMPLIANT));
  const nat = routers.findings.find((item) => item.id === "GCP-NET-04");
  assert.equal(nat.status, "warn");
  assert.match(nat.summary, /^1 of 1 eligible subnetworks could not be evaluated for Cloud NAT coverage because Cloud Routers were unreadable in their project \(compute\.googleapis\.com\/compute\/v1\/projects\/\{project\}\/aggregated\/routers\)\./);
  assert.match(nat.summary, /Partial view: Cloud Routers unreadable for 1 of 1 projects \(prod-audit\) via compute\.googleapis\.com\/compute\/v1\/projects\/\{project\}\/aggregated\/routers \(403 Forbidden\)/);
  assert.doesNotMatch(nat.summary, /not covered by a Cloud NAT/, "a denied router list is not a coverage violation");
  assert.equal(nat.evidence.subnets_without_nat, null, "coverage cannot be judged without any router list, so the violation list is null rather than an empty list");
  assert.equal(nat.evidence.subnets_with_unknown_nat.length, 1);
  assert.match(nat.evidence.subnets_with_unknown_nat[0].reason, /Cloud Routers unreadable in this project/);
  assert.equal(nat.evidence.routers_read, null);
  assert.equal(routers.summary.subnets_without_nat, null);
  assert.equal(routers.summary.subnets_with_unknown_nat, 1);

  const sslPolicies = await assessGcpNetworkSecurity(clientWithUnreadable((r) => r.path.endsWith("/aggregated/sslPolicies"), 403, "full", COMPLIANT));
  const ssl = sslPolicies.findings.find((item) => item.id === "GCP-NET-05");
  assert.equal(ssl.status, "warn");
  assert.match(ssl.summary, /^1 of 1 HTTPS target proxies could not be evaluated: SSL policies unreadable in this project via compute\.googleapis\.com\/compute\/v1\/projects\/\{project\}\/aggregated\/sslPolicies\./);
  assert.doesNotMatch(ssl.summary, /lacked the documented flag/);
  assert.match(ssl.evidence.unresolved_proxies[0].reason, /SSL policies unreadable in this project/);
  assert.equal(ssl.evidence.ssl_policies_read, null);

  const disks = await assessGcpDataProtection(clientWithUnreadable((r) => r.path.endsWith("/aggregated/disks"), 403, "full", COMPLIANT));
  const cmek = disks.findings.find((item) => item.id === "GCP-DATA-04");
  assert.equal(cmek.status, "warn");
  assert.match(cmek.summary, /Partial view: Compute Engine disks unreadable for 1 of 1 projects \(prod-audit\) via compute\.googleapis\.com\/compute\/v1\/projects\/\{project\}\/aggregated\/disks \(403 Forbidden\)/);
  assert.equal(cmek.evidence.disks_read, null);
  assert.equal(cmek.evidence.disks_without_cmek, null);
  assert.equal(cmek.evidence.buckets_read, 1);
  assert.deepEqual(cmek.evidence.buckets_without_cmek, []);
  assert.equal(disks.summary.disks, null);

  const keyMatch = (r) => r.host === "iam.googleapis.com" && r.path.endsWith("/keys");
  const keys = await assessGcpIdentity(clientWithUnreadable(keyMatch, 403, "full", COMPLIANT));
  for (const id of ["GCP-IAM-02", "GCP-IAM-03"]) {
    const finding = keys.findings.find((item) => item.id === id);
    assert.equal(finding.status, "manual", `${id}: keys are the dataset both findings score, so denying every key list leaves nothing to evaluate`);
    assert.match(finding.summary, /^Manual: service account keys unreadable for 1 of 1 service accounts \(prod-audit\) via iam\.googleapis\.com\/v1\/projects\/\{project\}\/serviceAccounts\/\{account\}\/keys \(svc@prod-audit\.iam\.gserviceaccount\.com: 403 Forbidden/);
    assert.equal(finding.evidence.seen, null);
    assert.equal(finding.evidence.unreadable_inventories.length, 1);
    assert.equal(finding.evidence.unreadable_inventories[0].dataset, "service account keys");
  }
  assert.equal(keys.findings.find((item) => item.id === "GCP-IAM-02").evidence.stale_keys, null);
  assert.equal(keys.findings.find((item) => item.id === "GCP-IAM-03").evidence.user_managed_keys, null);

  const someKeys = await assessGcpIdentity(clientWithUnreadable(keyMatch, 403, "project"));
  for (const id of ["GCP-IAM-02", "GCP-IAM-03"]) {
    const finding = someKeys.findings.find((item) => item.id === id);
    assert.equal(finding.status, "warn", `${id}: one of two service accounts denied its key list is a partial view, not a missing dataset`);
    assert.match(finding.summary, /Partial view: service account keys unreadable for 1 of 2 service accounts \(second-project\) via iam\.googleapis\.com\/v1\/projects\/\{project\}\/serviceAccounts\/\{account\}\/keys \(403 Forbidden\)/);
    assert.equal(finding.evidence.unreadable_inventories.length, 1);
  }
  assert.deepEqual(someKeys.findings.find((item) => item.id === "GCP-IAM-03").evidence.user_managed_keys, []);
});

test("GCP-DATA-02 folds bucket list truncation into its partial view", async () => {
  const client = createClient(async (url, init) => {
    const facts = requestFacts(url, init);
    if (facts.host === "storage.googleapis.com") return jsonResponse({ ...COMPLIANT.buckets, nextPageToken: "stuck" });
    return jsonResponse(routeCompliant(url, init));
  });
  const result = await assessGcpDataProtection(client);
  const exposure = result.findings.find((item) => item.id === "GCP-DATA-02");
  assert.equal(exposure.status, "warn");
  assert.equal(exposure.evidence.truncated, true);
  assert.match(exposure.summary, /seen, total unknown \(inventory incomplete\)/);
  assert.equal(result.findings.find((item) => item.id === "GCP-DATA-01").status, "warn");
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
