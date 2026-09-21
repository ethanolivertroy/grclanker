import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { inflateRawSync } from "node:zlib";

import {
  OCI_COMMAND_RUNNER_OPTIONS,
  OCI_SURFACE_DOCS,
  OciAuditorClient,
  OciCommandError,
  REDACTED_MARKER,
  assessOciComputeAndStorage,
  assessOciIdentity,
  assessOciLoggingDetection,
  assessOciTenancyGuardrails,
  checkOciAccess,
  collectAcrossCompartments,
  createOciCommandRunner,
  exportOciAuditBundle,
  isSensitiveFieldName,
  judgeKeyShape,
  ociCommandWords,
  parseServiceError,
  projectCompartmentSnapshot,
  redactSensitiveText,
  redactSensitiveValues,
  resolveOciConfiguration,
  resolveSecureOutputPath,
  ruleReachesSensitivePort,
  scopedStatus,
  scrubErrorText,
} from "../dist/extensions/grc-tools/oci.js";

const NOW = new Date("2026-09-21T00:00:00.000Z");
const TENANCY = "ocid1.tenancy.oc1..aaaaexample";
const ROOT = { id: TENANCY, compartmentId: TENANCY, name: "root", lifecycleState: "ACTIVE" };
const PROD = { id: "ocid1.compartment.oc1..prod", compartmentId: TENANCY, name: "prod", lifecycleState: "ACTIVE" };
const APPS = { id: "ocid1.compartment.oc1..apps", compartmentId: PROD.id, name: "apps", lifecycleState: "ACTIVE" };
const DENIED_ERROR = new Error("ServiceError: 404 NotAuthorizedOrNotFound: Authorization failed or requested resource not found.");
const FORBIDDEN_ERROR = new Error("ServiceError: 403 NotAllowed: Please go to http://docs.oracle.com/iaas/Content/Identity/Concepts/policies.htm for possible reasons.");

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function sampleConfig(overrides = {}) {
  return {
    configFile: "/tmp/oci/config",
    profile: "prod-audit",
    region: "us-ashburn-1",
    tenancyOcid: TENANCY,
    compartmentOcid: TENANCY,
    sourceChain: ["tests"],
    ...overrides,
  };
}

/**
 * Fixture (d): a fully compliant tenancy built strictly from documented
 * field names and shapes (REST datatypes cited in OCI_SURFACE_DOCS).
 */
function compliantClient() {
  return {
    getResolvedConfig: () => sampleConfig(),
    getNow: () => NOW,
    async listCompartments() {
      return [ROOT, PROD, APPS];
    },
    async listUsers() {
      return [
        { id: "ocid1.user.oc1..alice", name: "alice", lifecycleState: "ACTIVE", isMfaActivated: true, capabilities: { canUseConsolePassword: true, canUseApiKeys: true } },
        { id: "ocid1.user.oc1..svc", name: "svc", lifecycleState: "ACTIVE", isMfaActivated: false, capabilities: { canUseConsolePassword: false, canUseApiKeys: true } },
      ];
    },
    async getAuthenticationPolicy() {
      return {
        compartmentId: TENANCY,
        passwordPolicy: {
          minimumPasswordLength: 16,
          isLowercaseCharactersRequired: true,
          isUppercaseCharactersRequired: true,
          isNumericCharactersRequired: true,
          isSpecialCharactersRequired: true,
          isUsernameContainmentAllowed: false,
        },
      };
    },
    async listApiKeys() {
      return [{ fingerprint: "aa:bb", lifecycleState: "ACTIVE", timeCreated: "2026-08-01T00:00:00.000Z" }];
    },
    async listCustomerSecretKeys() {
      return [{ id: "csk-1", lifecycleState: "ACTIVE", timeCreated: "2026-08-15T00:00:00.000Z" }];
    },
    async listAuthTokens() {
      return [{ id: "tok-1", lifecycleState: "ACTIVE", timeCreated: "2026-09-01T00:00:00.000Z" }];
    },
    async listPolicies(compartmentId) {
      return compartmentId === TENANCY
        ? [{ id: "pol-1", name: "Auditors", lifecycleState: "ACTIVE", statements: ["Allow group Auditors to inspect all-resources in tenancy"] }]
        : [{ id: `pol-${compartmentId}`, name: "AppAdmins", lifecycleState: "ACTIVE", statements: ["Allow group AppAdmins to manage instance-family in compartment apps"] }];
    },
    async listAvailabilityDomains() {
      return [{ name: "Uocm:US-ASHBURN-AD-1", compartmentId: TENANCY, id: "ad-1" }];
    },
    async getAuditConfiguration() {
      return { retentionPeriodDays: 365 };
    },
    async listAuditEvents() {
      return [{ eventId: "evt-1", eventTime: "2026-09-20T12:00:00.000Z", eventType: "com.oraclecloud.identitycontrolplane.createuser" }];
    },
    async getCloudGuardConfiguration() {
      return { status: "ENABLED", reportingRegion: "us-ashburn-1", selfManageResources: false };
    },
    async listCloudGuardTargets() {
      return [{ id: "target-1", lifecycleState: "ACTIVE", recipeCount: 2, targetResourceType: "COMPARTMENT" }];
    },
    async listCloudGuardProblems() {
      return [];
    },
    async listResponderRecipes() {
      return [{ id: "recipe-1", lifecycleState: "ACTIVE", responderRules: [{ id: "rule-1", details: { isEnabled: true, mode: "USERACTION" } }] }];
    },
    async listEventRules(compartmentId) {
      return compartmentId === TENANCY
        ? [{ id: "rule-1", displayName: "iam-changes", isEnabled: true, lifecycleState: "ACTIVE", condition: JSON.stringify({ eventType: ["com.oraclecloud.identitycontrolplane.createpolicy"] }) }]
        : [];
    },
    async listSecurityLists(compartmentId) {
      return compartmentId === APPS.id
        ? [{ id: "sl-1", displayName: "app-sl", lifecycleState: "AVAILABLE", ingressSecurityRules: [{ protocol: "6", source: "10.0.0.0/8", sourceType: "CIDR_BLOCK", tcpOptions: { destinationPortRange: { min: 22, max: 22 } } }] }]
        : [];
    },
    async listNetworkSecurityGroups(compartmentId) {
      return compartmentId === APPS.id ? [{ id: "nsg-1", displayName: "app-nsg", lifecycleState: "AVAILABLE" }] : [];
    },
    async listNetworkSecurityGroupRules() {
      return [{ id: "sr-1", direction: "INGRESS", protocol: "6", source: "10.0.0.0/8", sourceType: "CIDR_BLOCK", tcpOptions: { destinationPortRange: { min: 443, max: 443 } } }];
    },
    async listInternetGateways() {
      return [];
    },
    async listBastions(compartmentId) {
      return compartmentId === PROD.id ? [{ id: "bastion-1", name: "ops", lifecycleState: "ACTIVE" }] : [];
    },
    async getBastion() {
      return { id: "bastion-1", name: "ops", lifecycleState: "ACTIVE", maxSessionTtlInSeconds: 3600, clientCidrBlockAllowList: ["203.0.113.0/24"] };
    },
    async listBastionSessions() {
      return [{ id: "session-1", lifecycleState: "ACTIVE", timeCreated: "2026-09-20T22:00:00.000Z", sessionTtlInSeconds: 1800 }];
    },
    async listVaults(compartmentId) {
      return compartmentId === PROD.id ? [{ id: "vault-1", displayName: "core", compartmentId: PROD.id, lifecycleState: "ACTIVE", managementEndpoint: "https://vault-management.example" }] : [];
    },
    async listKeys() {
      return [{ id: "key-1", displayName: "data", algorithm: "AES", lifecycleState: "ENABLED", protectionMode: "HSM", timeCreated: "2024-01-01T00:00:00.000Z" }];
    },
    async getKey(_vault, keyId) {
      return { id: keyId, displayName: "data", lifecycleState: "ENABLED", vaultId: "vault-1", compartmentId: PROD.id, currentKeyVersion: "kv-2", timeCreated: "2024-01-01T00:00:00.000Z", keyShape: { algorithm: "AES", length: 32 } };
    },
    async listKeyVersions() {
      return [
        { id: "kv-1", lifecycleState: "ENABLED", timeCreated: "2024-01-01T00:00:00.000Z" },
        { id: "kv-2", lifecycleState: "ENABLED", timeCreated: "2026-06-01T00:00:00.000Z" },
      ];
    },
    async getObjectStorageNamespace() {
      return "tenantns";
    },
    async listBuckets(_namespace, compartmentId) {
      return compartmentId === APPS.id ? [{ name: "logs", namespace: "tenantns", compartmentId: APPS.id }] : [];
    },
    async getBucket() {
      return { name: "logs", namespace: "tenantns", publicAccessType: "NoPublicAccess" };
    },
    async listPreauthenticatedRequests() {
      return [{ id: "par-1", name: "export", accessType: "ObjectRead", timeExpires: "2026-09-25T00:00:00.000Z" }];
    },
    async listInstances(compartmentId) {
      return compartmentId === APPS.id ? [{ id: "inst-1", displayName: "web", lifecycleState: "RUNNING", instanceOptions: { areLegacyImdsEndpointsDisabled: true } }] : [];
    },
    async listVolumes(compartmentId) {
      return compartmentId === APPS.id ? [{ id: "vol-1", displayName: "data", lifecycleState: "AVAILABLE", kmsKeyId: "ocid1.key.oc1..cmk" }] : [];
    },
    async listBootVolumes(compartmentId) {
      return compartmentId === APPS.id ? [{ id: "bv-1", displayName: "web-boot", lifecycleState: "AVAILABLE", kmsKeyId: "ocid1.key.oc1..cmk" }] : [];
    },
  };
}

/** Fixture (a): every surface fails with the documented NotAuthorizedOrNotFound response. */
function deniedClient() {
  const client = compliantClient();
  for (const key of Object.keys(client)) {
    if (key === "getResolvedConfig" || key === "getNow") continue;
    client[key] = async () => {
      throw DENIED_ERROR;
    };
  }
  return client;
}

/** Fixture (b): every list is empty and every single-object read returns null. */
function emptyClient() {
  const client = compliantClient();
  const singles = new Set(["getAuthenticationPolicy", "getAuditConfiguration", "getCloudGuardConfiguration", "getBastion", "getBucket", "getKey"]);
  for (const key of Object.keys(client)) {
    if (key === "getResolvedConfig" || key === "getNow") continue;
    if (key === "getObjectStorageNamespace") {
      client[key] = async () => "tenantns";
    } else if (singles.has(key)) {
      client[key] = async () => null;
    } else {
      client[key] = async () => [];
    }
  }
  return client;
}

/** Fixture (c): one compartment denied for every compartment-scoped list. */
function partialClient() {
  const client = compliantClient();
  const scopedLists = ["listPolicies", "listEventRules", "listSecurityLists", "listNetworkSecurityGroups", "listInternetGateways", "listBastions", "listVaults", "listInstances", "listVolumes", "listBootVolumes"];
  for (const key of scopedLists) {
    const original = client[key];
    client[key] = async (...args) => {
      if (args[0] === PROD.id) throw DENIED_ERROR;
      return original(...args);
    };
  }
  const originalBuckets = client.listBuckets;
  client.listBuckets = async (namespace, compartmentId) => {
    if (compartmentId === PROD.id) throw DENIED_ERROR;
    return originalBuckets(namespace, compartmentId);
  };
  return client;
}

const SECRET_PEM = "-----BEGIN RSA PRIVATE KEY-----\nFAKE_PEM_BODY_1\n-----END RSA PRIVATE KEY-----";
/** The documented OCI request-signing Authorization header form (signingrequests.htm), with fake identifiers. */
const SIGNING_HEADER = 'Signature version="1",keyId="ocid1.tenancy.oc1..FAKE_TENANCY_1/ocid1.user.oc1..FAKE_USER_1/FAKE_FINGERPRINT_1",algorithm="rsa-sha256",headers="(request-target) date host",signature="FAKE_SIGNATURE_BASE64_1=="';
const SECRET_ERROR = new Error(
  `Command failed: oci cloud-guard problem list --config-file /tmp/oci/config\nServiceError: 401 NotAuthenticated: Authorization: ${SIGNING_HEADER}\nDebug: keyId="ocid1.tenancy.oc1..FAKE_TENANCY_2/ocid1.user.oc1..FAKE_USER_2/FAKE_FINGERPRINT_2" signature="FAKE_SIGNATURE_BASE64_2==" Bearer FAKE_BEARER_1abcdefgh Signature FAKE_SIGNATURE_BARE_1abcdef key_file=/tmp/oci/FAKE_KEY_PATH_1.pem token=FAKE_ERROR_TOKEN_1 ${SECRET_PEM}`,
);

/**
 * Rule 9 fixture: the compliant tenancy with a distinctive FAKE_ marker in
 * every collected object that can carry credential material (documented
 * secret-bearing fields plus tags, descriptions, and metadata that must not be
 * dumped verbatim). Public key material uses the ALLOWED_ prefix because it
 * may legitimately appear.
 */
function secretLadenClient() {
  const client = compliantClient();
  const tags = (marker) => ({ freeformTags: { password: `FAKE_TAG_${marker}` }, definedTags: { audit: { token: `FAKE_DEFINED_TAG_${marker}` } } });
  const withSecrets = (items, marker, extra = {}) => items.map((item, index) => ({ ...item, ...tags(`${marker}_${index}`), description: `FAKE_DESCRIPTION_${marker}_${index}`, ...extra }));
  const wrapList = (method, marker, extra) => {
    const original = client[method];
    client[method] = async (...args) => withSecrets(await original(...args), marker, extra);
  };
  wrapList("listCompartments", "COMPARTMENT");
  wrapList("listUsers", "USER");
  wrapList("listApiKeys", "API_KEY", { keyValue: "-----BEGIN PUBLIC KEY-----\nFAKE_API_KEY_VALUE_1\n-----END PUBLIC KEY-----" });
  wrapList("listCustomerSecretKeys", "CSK", { key: "FAKE_CUSTOMER_SECRET_1" });
  wrapList("listAuthTokens", "AUTH_TOKEN", { token: "FAKE_SECRET_TOKEN_1" });
  wrapList("listPolicies", "POLICY");
  wrapList("listAuditEvents", "AUDIT", { data: { request: { headers: { authorization: ["FAKE_AUTH_HEADER_1"] } } } });
  wrapList("listCloudGuardTargets", "TARGET");
  wrapList("listResponderRecipes", "RECIPE");
  wrapList("listEventRules", "RULE", { actions: { actions: [{ actionType: "ONS", topicId: "ocid1.onstopic.oc1..topic", description: "FAKE_ACTION_DESCRIPTION_1" }] } });
  wrapList("listSecurityLists", "SL");
  wrapList("listNetworkSecurityGroups", "NSG");
  wrapList("listBastions", "BASTION");
  wrapList("listBastionSessions", "SESSION", { keyDetails: { publicKeyContent: "ssh-rsa ALLOWED_PUBLIC_KEY_1" }, sshPrivateKey: "FAKE_PRIVATE_KEY_1" });
  wrapList("listVaults", "VAULT", { secret: "FAKE_VAULT_SECRET_1" });
  wrapList("listKeys", "KEY", { keyMaterial: "FAKE_KEY_MATERIAL_1", wrappedImportKey: { wrappedKey: "FAKE_WRAPPED_KEY_1" } });
  wrapList("listKeyVersions", "KEY_VERSION", { publicKey: "ALLOWED_PUBLIC_KEY_2" });
  wrapList("listBuckets", "BUCKET", { metadata: { password: "FAKE_BUCKET_METADATA_SECRET_1" } });
  wrapList("listPreauthenticatedRequests", "PAR", { accessUri: "/p/FAKE_ACCESS_URI_1/n/tenantns/b/logs/o/", fullPath: "https://objectstorage.us-ashburn-1.oraclecloud.com/p/FAKE_ACCESS_URI_1/n/tenantns/b/logs/o/" });
  wrapList("listInstances", "INSTANCE", { metadata: { user_data: "FAKE_USER_DATA_SECRET_1", ssh_authorized_keys: "ssh-rsa ALLOWED_PUBLIC_KEY_3" }, extendedMetadata: { db_password: "FAKE_EXTENDED_METADATA_SECRET_1" } });
  wrapList("listVolumes", "VOLUME");
  wrapList("listBootVolumes", "BOOT_VOLUME");
  const originalBastion = client.getBastion;
  client.getBastion = async (...args) => ({ ...(await originalBastion(...args)), ...tags("BASTION_DETAIL"), phoneBookEntry: "FAKE_PHONE_BOOK_1" });
  const originalKey = client.getKey;
  client.getKey = async (...args) => ({ ...(await originalKey(...args)), ...tags("KEY_DETAIL"), keyMaterial: "FAKE_KEY_MATERIAL_2", wrappedImportKey: { wrappedKey: "FAKE_WRAPPED_KEY_2" } });
  const originalBucket = client.getBucket;
  client.getBucket = async (...args) => ({ ...(await originalBucket(...args)), ...tags("BUCKET_DETAIL"), metadata: { password: "FAKE_BUCKET_DETAIL_SECRET_1" } });
  const originalAuthPolicy = client.getAuthenticationPolicy;
  client.getAuthenticationPolicy = async () => ({ ...(await originalAuthPolicy()), networkPolicy: { networkSourceIds: ["FAKE_NETWORK_SOURCE_1"] } });
  client.listCloudGuardProblems = async () => {
    throw SECRET_ERROR;
  };
  client.getResolvedConfig = () => sampleConfig({ configFile: "/home/FAKE_HOME_1/.oci/config" });
  return client;
}

function listFilesRecursively(root) {
  const files = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const pathname = join(root, entry.name);
    if (entry.isDirectory()) files.push(...listFilesRecursively(pathname));
    else files.push(pathname);
  }
  return files;
}

/** Minimal zip reader (central directory plus raw deflate) so the archive content can be asserted without external tools. */
function readZipEntries(zipPath) {
  const buffer = readFileSync(zipPath);
  let eocdOffset = -1;
  for (let offset = buffer.length - 22; offset >= 0; offset -= 1) {
    if (buffer.readUInt32LE(offset) === 0x06054b50) {
      eocdOffset = offset;
      break;
    }
  }
  assert.ok(eocdOffset >= 0, "zip end of central directory record not found");
  const entryCount = buffer.readUInt16LE(eocdOffset + 10);
  let cursor = buffer.readUInt32LE(eocdOffset + 16);
  const entries = [];
  for (let index = 0; index < entryCount; index += 1) {
    assert.equal(buffer.readUInt32LE(cursor), 0x02014b50, "central directory signature");
    const method = buffer.readUInt16LE(cursor + 10);
    const compressedSize = buffer.readUInt32LE(cursor + 20);
    const nameLength = buffer.readUInt16LE(cursor + 28);
    const extraLength = buffer.readUInt16LE(cursor + 30);
    const commentLength = buffer.readUInt16LE(cursor + 32);
    const localHeaderOffset = buffer.readUInt32LE(cursor + 42);
    const name = buffer.subarray(cursor + 46, cursor + 46 + nameLength).toString("utf8");
    assert.equal(buffer.readUInt32LE(localHeaderOffset), 0x04034b50, "local header signature");
    const dataStart = localHeaderOffset + 30 + buffer.readUInt16LE(localHeaderOffset + 26) + buffer.readUInt16LE(localHeaderOffset + 28);
    const data = buffer.subarray(dataStart, dataStart + compressedSize);
    entries.push({ name, content: (method === 8 ? inflateRawSync(data) : data).toString("utf8") });
    cursor += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

function byId(result, id) {
  const item = result.findings.find((entry) => entry.id === id);
  assert.ok(item, `missing finding ${id}`);
  return item;
}

async function runAllAssessments(client, options = {}) {
  return [
    await assessOciIdentity(client, options),
    await assessOciLoggingDetection(client, options),
    await assessOciTenancyGuardrails(client, options),
    await assessOciComputeAndStorage(client, options),
  ];
}

test("resolveOciConfiguration prefers explicit arguments over environment and config", () => {
  const resolved = resolveOciConfiguration(
    {
      config_file: "/tmp/custom-oci-config",
      profile: "audit",
      region: "eu-frankfurt-1",
      tenancy_ocid: "ocid1.tenancy.oc1..explicit",
      compartment_ocid: "ocid1.compartment.oc1..explicit",
    },
    {
      OCI_CONFIG_FILE: "/tmp/env-oci-config",
      OCI_CLI_PROFILE: "env-profile",
      OCI_REGION: "us-phoenix-1",
      OCI_TENANCY_OCID: "ocid1.tenancy.oc1..env",
      OCI_COMPARTMENT_OCID: "ocid1.compartment.oc1..env",
    },
    () => `
[audit]
region=uk-london-1
tenancy=ocid1.tenancy.oc1..config
`,
  );

  assert.equal(resolved.configFile, "/tmp/custom-oci-config");
  assert.equal(resolved.profile, "audit");
  assert.equal(resolved.region, "eu-frankfurt-1");
  assert.equal(resolved.tenancyOcid, "ocid1.tenancy.oc1..explicit");
  assert.equal(resolved.compartmentOcid, "ocid1.compartment.oc1..explicit");
  assert.ok(resolved.sourceChain.includes("arguments-config-file"));
});

test("OciAuditorClient sends documented CLI commands and flags", async () => {
  const calls = [];
  const runner = (args) => {
    calls.push(args.slice(8));
    return JSON.stringify({ data: [] });
  };
  const client = new OciAuditorClient(sampleConfig(), runner, { now: () => NOW });
  await client.listCompartments();
  await client.listPolicies("ocid1.compartment.oc1..x");
  await client.listNetworkSecurityGroupRules("nsg-1");
  await client.listKeys({ id: "vault-1", compartmentId: "c1", managementEndpoint: "https://kms.example" });
  await client.listKeyVersions({ id: "vault-1", managementEndpoint: "https://kms.example" }, "key-1");
  await client.getKey({ id: "vault-1", managementEndpoint: "https://kms.example" }, "key-1");
  await client.listBootVolumes("c1", "AD-1");
  await client.listInstances("c1");
  await client.listVolumes("c1");
  await client.getBucket("ns", "bucket");
  await client.getBastion("bastion-1");
  await client.listCloudGuardProblems();

  assert.deepEqual(calls[0], ["iam", "compartment", "list", "--compartment-id", TENANCY, "--all", "--compartment-id-in-subtree", "true", "--access-level", "ACCESSIBLE", "--include-root", "true"]);
  assert.deepEqual(calls[1], ["iam", "policy", "list", "--compartment-id", "ocid1.compartment.oc1..x", "--all"]);
  assert.deepEqual(calls[2], ["network", "nsg", "rules", "list", "--nsg-id", "nsg-1", "--direction", "INGRESS", "--all"]);
  assert.deepEqual(calls[3], ["kms", "management", "key", "list", "--endpoint", "https://kms.example", "--compartment-id", "c1", "--all"]);
  assert.deepEqual(calls[4], ["kms", "management", "key-version", "list", "--endpoint", "https://kms.example", "--key-id", "key-1", "--all"]);
  assert.deepEqual(calls[5], ["kms", "management", "key", "get", "--endpoint", "https://kms.example", "--key-id", "key-1"]);
  assert.deepEqual(calls[6], ["bv", "boot-volume", "list", "--compartment-id", "c1", "--availability-domain", "AD-1", "--all"]);
  assert.deepEqual(calls[7], ["compute", "instance", "list", "--compartment-id", "c1", "--all"]);
  assert.deepEqual(calls[8], ["bv", "volume", "list", "--compartment-id", "c1", "--all"]);
  assert.deepEqual(calls[9], ["os", "bucket", "get", "--namespace-name", "ns", "--bucket-name", "bucket"]);
  assert.deepEqual(calls[10], ["bastion", "bastion", "get", "--bastion-id", "bastion-1"]);
  assert.deepEqual(calls[11], ["cloud-guard", "problem", "list", "--compartment-id", TENANCY, "--compartment-id-in-subtree", "true", "--access-level", "ACCESSIBLE", "--lifecycle-detail", "OPEN", "--all"]);
  for (const args of calls) {
    assert.ok(!args.includes("--query"), "no --query projection is used");
  }
  assert.equal(OCI_COMMAND_RUNNER_OPTIONS.timeout, 15_000);
  assert.ok(OCI_COMMAND_RUNNER_OPTIONS.maxBuffer >= 64 * 1024 * 1024, "maxBuffer is raised next to the timeout");
  assert.equal(OCI_COMMAND_RUNNER_OPTIONS.encoding, "utf8");
  for (const [name, doc] of Object.entries(OCI_SURFACE_DOCS)) {
    assert.match(doc.cli, /^https:\/\/docs\.oracle\.com\/en-us\/iaas\/tools\/oci-cli\//, `${name} cites the CLI reference`);
    assert.match(doc.rest, /^https:\/\/docs\.oracle\.com\/en-us\/iaas\/api\//, `${name} cites the REST reference`);
    assert.ok(doc.fields.length > 0);
  }
});

test("checkOciAccess reports readable OCI surfaces", async () => {
  const result = await checkOciAccess(compliantClient());
  assert.equal(result.status, "healthy");
  assert.equal(result.surfaces.filter((surface) => surface.status === "readable").length, 10);
  assert.match(result.recommendedNextStep, /oci_assess_compute_and_storage/);

  const denied = await checkOciAccess(deniedClient());
  assert.equal(denied.status, "limited");
  assert.equal(denied.surfaces.filter((surface) => surface.status === "not_readable").length, 10);
});

test("self-check fixture (d): fully compliant tenancy passes every automatable control", async () => {
  const results = await runAllAssessments(compliantClient());
  const findings = results.flatMap((result) => result.findings);
  const manual = findings.filter((item) => item.status === "manual").map((item) => item.id);
  assert.deepEqual(manual, ["OCI-IAM-06"], "only the undocumented password expiration stays manual");
  const nonPass = findings.filter((item) => item.status !== "pass" && item.id !== "OCI-IAM-06");
  assert.deepEqual(nonPass.map((item) => `${item.id}:${item.status}:${item.summary}`), []);
  assert.equal(findings.length, 21);
  assert.equal(results.flatMap((result) => result.errors).length, 0);
});

test("self-check fixture (a): denied surfaces never pass and name the cause", async () => {
  const results = await runAllAssessments(deniedClient());
  const findings = results.flatMap((result) => result.findings);
  assert.equal(findings.filter((item) => item.status === "pass").length, 0);
  for (const item of findings) {
    assert.equal(item.status, "manual", `${item.id} should be manual, got ${item.status}: ${item.summary}`);
    assert.match(item.summary, /Manual/);
  }
  assert.ok(findings.some((item) => /NotAuthorizedOrNotFound/.test(item.summary)));
  assert.ok(results.every((result) => result.errors.length > 0));
});

test("self-check fixture (b): empty inventories pass only where emptiness is compliant by intent", async () => {
  const results = await runAllAssessments(emptyClient());
  const findings = results.flatMap((result) => result.findings);
  const statuses = Object.fromEntries(findings.map((item) => [item.id, item.status]));
  assert.equal(statuses["OCI-IAM-01"], "manual");
  assert.equal(statuses["OCI-IAM-02"], "manual");
  assert.equal(statuses["OCI-IAM-03"], "manual");
  assert.equal(statuses["OCI-IAM-04"], "manual");
  assert.equal(statuses["OCI-IAM-05"], "fail");
  assert.equal(statuses["OCI-LOG-01"], "manual");
  assert.equal(statuses["OCI-LOG-02"], "manual");
  assert.equal(statuses["OCI-LOG-03"], "manual");
  assert.equal(statuses["OCI-LOG-06"], "manual");
  assert.equal(statuses["OCI-LOG-04"], "warn");
  assert.equal(statuses["OCI-LOG-05"], "manual");
  for (const id of ["OCI-GRD-01", "OCI-GRD-02", "OCI-GRD-03", "OCI-GRD-04", "OCI-GRD-05", "OCI-GRD-06", "OCI-CMP-01", "OCI-CMP-02", "OCI-CMP-03"]) {
    assert.equal(statuses[id], "manual", `${id} with no compartments must be manual`);
  }
  assert.equal(findings.filter((item) => item.status === "pass").length, 0);
});

test("self-check fixture (b) with compartments: vacuous NSG and gateway emptiness passes only beside readable security lists", async () => {
  const client = emptyClient();
  client.listCompartments = async () => [ROOT, PROD];
  client.listSecurityLists = async () => [{ id: "sl-1", lifecycleState: "AVAILABLE", ingressSecurityRules: [] }];
  const result = await assessOciTenancyGuardrails(client);
  assert.equal(byId(result, "OCI-GRD-01").status, "pass");
  assert.equal(byId(result, "OCI-GRD-02").status, "pass");
  assert.match(byId(result, "OCI-GRD-02").summary, /emptiness is compliant/);
  assert.equal(byId(result, "OCI-GRD-03").status, "pass");
  assert.equal(byId(result, "OCI-GRD-04").status, "manual");
  assert.equal(byId(result, "OCI-GRD-05").status, "manual");
  assert.equal(byId(result, "OCI-GRD-06").status, "manual");
  const compute = await assessOciComputeAndStorage(client);
  for (const item of compute.findings) {
    assert.equal(item.status, "manual", `${item.id} should be manual on empty inventory`);
  }
  const logging = await assessOciLoggingDetection(client);
  assert.equal(byId(logging, "OCI-LOG-05").status, "fail");
});

test("self-check fixture (c): partial inventories never pass and report seen versus total", async () => {
  const results = await runAllAssessments(partialClient());
  const findings = results.flatMap((result) => result.findings);
  const scoped = ["OCI-IAM-04", "OCI-LOG-05", "OCI-GRD-01", "OCI-GRD-02", "OCI-GRD-03", "OCI-GRD-04", "OCI-GRD-05", "OCI-GRD-06", "OCI-CMP-01", "OCI-CMP-02", "OCI-CMP-03"];
  for (const id of scoped) {
    const item = findings.find((entry) => entry.id === id);
    assert.notEqual(item.status, "pass", `${id} must not pass on a partial view: ${item.summary}`);
    assert.match(item.summary, /Partial view|Manual/, `${id} must flag the partial view`);
    assert.equal(item.evidence.compartments_total, 3);
    assert.ok(item.evidence.compartments_seen < 3);
  }
});

test("compartment cap withholds pass and records truncation", async () => {
  const client = compliantClient();
  const compute = await assessOciComputeAndStorage(client, { maxCompartments: 1 });
  for (const item of compute.findings) {
    assert.notEqual(item.status, "pass");
    assert.equal(item.evidence.compartments_truncated, true);
    assert.equal(item.evidence.compartments_seen, 1);
    assert.equal(item.evidence.compartments_total, 3);
  }
  const collection = await collectAcrossCompartments("x", [ROOT, PROD, APPS], 2, async () => [{ ok: true }]);
  assert.equal(collection.truncated, true);
  assert.equal(scopedStatus(collection, "pass", "manual"), "warn");
  assert.equal(scopedStatus({ ...collection, readable: false }, "pass", "manual"), "manual");
  assert.equal(scopedStatus({ ...collection, items: [] }, "pass", "fail"), "fail");
});

test("assessOciIdentity flags weak password policy, missing MFA, stale credentials, and broad policies", async () => {
  const client = compliantClient();
  client.getAuthenticationPolicy = async () => ({
    passwordPolicy: {
      minimumPasswordLength: 12,
      isLowercaseCharactersRequired: true,
      isUppercaseCharactersRequired: true,
      isNumericCharactersRequired: false,
      isSpecialCharactersRequired: true,
    },
  });
  client.listUsers = async () => [
    { id: "u1", name: "alice", lifecycleState: "ACTIVE", isMfaActivated: false, capabilities: { canUseConsolePassword: true } },
    { id: "u2", name: "bob", lifecycleState: "ACTIVE", isMfaActivated: true, capabilities: { canUseConsolePassword: true } },
    { id: "u3", name: "gone", lifecycleState: "DELETED", isMfaActivated: false, capabilities: { canUseConsolePassword: true } },
  ];
  client.listApiKeys = async (userId) => (userId === "u1" ? [{ fingerprint: "fp-1", lifecycleState: "ACTIVE", timeCreated: "2025-01-01T00:00:00Z" }] : []);
  client.listPolicies = async () => [{ id: "p", name: "AdminAll", lifecycleState: "ACTIVE", statements: ["Allow group Admins to manage all-resources in tenancy"] }];
  client.listCompartments = async () => [ROOT];

  const result = await assessOciIdentity(client, { staleDays: 90 });
  assert.equal(byId(result, "OCI-IAM-01").status, "fail");
  assert.equal(byId(result, "OCI-IAM-02").status, "fail");
  assert.match(byId(result, "OCI-IAM-02").summary, /1\/2 console-capable users/);
  assert.equal(byId(result, "OCI-IAM-03").status, "fail");
  assert.equal(byId(result, "OCI-IAM-04").status, "warn");
  assert.equal(byId(result, "OCI-IAM-05").status, "fail");
  assert.equal(byId(result, "OCI-IAM-06").status, "manual");
});

test("undated credentials and unknown MFA flags never count as compliant", async () => {
  const client = compliantClient();
  client.listApiKeys = async () => [{ fingerprint: "fp-undated", lifecycleState: "ACTIVE" }];
  client.listUsers = async () => [
    { id: "u1", name: "alice", lifecycleState: "ACTIVE", capabilities: { canUseConsolePassword: true } },
  ];
  const result = await assessOciIdentity(client);
  assert.equal(byId(result, "OCI-IAM-02").status, "warn");
  assert.match(byId(result, "OCI-IAM-02").summary, /did not report isMfaActivated/);
  assert.equal(byId(result, "OCI-IAM-03").status, "warn");
  assert.equal(byId(result, "OCI-IAM-03").evidence.undated_credentials.length, 1);
});

test("credential cap and per-user listing errors downgrade the rotation verdict", async () => {
  const client = compliantClient();
  const capped = await assessOciIdentity(client, { maxKeys: 1 });
  assert.equal(byId(capped, "OCI-IAM-03").status, "warn");
  assert.equal(byId(capped, "OCI-IAM-03").evidence.credential_cap_hit, true);

  client.listAuthTokens = async () => {
    throw DENIED_ERROR;
  };
  const errored = await assessOciIdentity(client);
  assert.equal(byId(errored, "OCI-IAM-03").status, "warn");
  assert.ok(errored.errors.some((error) => /auth_token/.test(error)));
});

test("assessOciLoggingDetection judges Cloud Guard, retention, and event rules from documented fields", async () => {
  const client = compliantClient();
  client.listCloudGuardProblems = async () => [{ id: "prob-1", lifecycleDetail: "OPEN", lifecycleState: "ACTIVE", riskLevel: "HIGH" }];
  client.getAuditConfiguration = async () => ({ retentionPeriodDays: 90 });
  client.listResponderRecipes = async () => [{ id: "recipe-1", lifecycleState: "ACTIVE", responderRules: [{ details: { isEnabled: false } }] }];
  client.listEventRules = async () => [{ id: "rule-1", isEnabled: false, lifecycleState: "ACTIVE", condition: "{\"eventType\":[\"com.oraclecloud.identitycontrolplane.createpolicy\"]}" }];

  const result = await assessOciLoggingDetection(client, { lookbackDays: 7 });
  assert.equal(byId(result, "OCI-LOG-01").status, "pass");
  assert.equal(byId(result, "OCI-LOG-02").status, "fail");
  assert.equal(byId(result, "OCI-LOG-03").status, "fail");
  assert.equal(byId(result, "OCI-LOG-06").status, "fail");
  assert.match(byId(result, "OCI-LOG-06").summary, /retentionPeriodDays is 90/);
  assert.equal(byId(result, "OCI-LOG-04").status, "pass");
  assert.equal(byId(result, "OCI-LOG-05").status, "fail");
  assert.match(byId(result, "OCI-LOG-05").summary, /none with a condition/);
});

test("Cloud Guard disabled turns empty problems and responders into manual, never pass", async () => {
  const client = compliantClient();
  client.getCloudGuardConfiguration = async () => ({ status: "DISABLED" });
  const result = await assessOciLoggingDetection(client);
  assert.equal(byId(result, "OCI-LOG-01").status, "fail");
  assert.equal(byId(result, "OCI-LOG-02").status, "manual");
  assert.equal(byId(result, "OCI-LOG-03").status, "manual");

  client.getCloudGuardConfiguration = async () => ({ reportingRegion: "us-ashburn-1" });
  const missingFlag = await assessOciLoggingDetection(client);
  assert.equal(byId(missingFlag, "OCI-LOG-01").status, "manual");
});

test("audit retention needs the documented field and the 365-day threshold", async () => {
  const client = compliantClient();
  client.getAuditConfiguration = async () => ({});
  assert.equal(byId(await assessOciLoggingDetection(client), "OCI-LOG-06").status, "manual");
  client.getAuditConfiguration = async () => ({ retentionPeriodDays: 365 });
  assert.equal(byId(await assessOciLoggingDetection(client), "OCI-LOG-06").status, "pass");
  client.getAuditConfiguration = async () => {
    throw new Error("oci: command not found");
  };
  const failed = byId(await assessOciLoggingDetection(client), "OCI-LOG-06");
  assert.equal(failed.status, "manual");
  assert.match(failed.summary, /oci audit config get failed/);
});

test("assessOciTenancyGuardrails flags exposed network paths, bastions, keys, and public buckets", async () => {
  const client = compliantClient();
  client.listSecurityLists = async (compartmentId) => (compartmentId === APPS.id
    ? [{ id: "sl-1", lifecycleState: "AVAILABLE", ingressSecurityRules: [{ protocol: "6", source: "0.0.0.0/0", tcpOptions: { destinationPortRange: { min: 20, max: 25 } } }] }]
    : []);
  client.listNetworkSecurityGroupRules = async () => [{ id: "sr-1", direction: "INGRESS", protocol: "all", source: "::/0" }];
  client.listInternetGateways = async (compartmentId) => (compartmentId === APPS.id ? [{ id: "igw-1", isEnabled: true, lifecycleState: "AVAILABLE" }] : []);
  client.getBastion = async () => ({ id: "bastion-1", maxSessionTtlInSeconds: 14400, clientCidrBlockAllowList: [] });
  client.listBastionSessions = async () => [{ id: "session-1", lifecycleState: "ACTIVE", timeCreated: "2026-09-20T00:00:00Z" }];
  client.listKeyVersions = async () => [{ id: "kv-1", lifecycleState: "ENABLED", timeCreated: "2024-01-01T00:00:00Z" }];
  client.getBucket = async () => ({ name: "logs", publicAccessType: "ObjectRead" });
  client.listPreauthenticatedRequests = async () => [{ id: "par-1", accessType: "ObjectRead", timeExpires: "2027-06-30T00:00:00Z" }];

  const result = await assessOciTenancyGuardrails(client);
  assert.equal(byId(result, "OCI-GRD-01").status, "fail");
  assert.equal(byId(result, "OCI-GRD-02").status, "fail");
  assert.equal(byId(result, "OCI-GRD-03").status, "warn");
  assert.equal(byId(result, "OCI-GRD-04").status, "fail");
  assert.equal(byId(result, "OCI-GRD-05").status, "fail");
  assert.match(byId(result, "OCI-GRD-05").summary, /1\/1 ENABLED keys judged from Key.keyShape: 1 weak/);
  assert.equal(byId(result, "OCI-GRD-05").evidence.weak_keys[0].reason, "newest enabled key version older than 365 days");
  assert.equal(byId(result, "OCI-GRD-06").status, "fail");
  assert.equal(byId(result, "OCI-GRD-06").evidence.long_lived_pars.length, 1);
});

test("guardrail sub-reads that fail or lack dates downgrade to warn instead of pass", async () => {
  const client = compliantClient();
  client.getBastion = async () => {
    throw DENIED_ERROR;
  };
  client.listKeyVersions = async () => [{ id: "kv-1", lifecycleState: "ENABLED" }];
  client.listPreauthenticatedRequests = async () => [{ id: "par-1", accessType: "ObjectRead" }];
  const result = await assessOciTenancyGuardrails(client);
  assert.equal(byId(result, "OCI-GRD-04").status, "warn");
  assert.equal(byId(result, "OCI-GRD-05").status, "warn");
  assert.equal(byId(result, "OCI-GRD-05").evidence.undated_keys.length, 1);
  assert.equal(byId(result, "OCI-GRD-06").status, "warn");
  assert.equal(byId(result, "OCI-GRD-06").evidence.undated_pars.length, 1);
  const twoBuckets = compliantClient();
  twoBuckets.listBuckets = async (_namespace, compartmentId) => (compartmentId === APPS.id
    ? [{ name: "logs", namespace: "tenantns", compartmentId: APPS.id }, { name: "backups", namespace: "tenantns", compartmentId: APPS.id }]
    : []);
  const capped = await assessOciTenancyGuardrails(twoBuckets, { maxBuckets: 1 });
  assert.equal(byId(capped, "OCI-GRD-06").status, "warn");
  assert.equal(byId(capped, "OCI-GRD-06").evidence.bucket_cap_hit, true);
});

test("judgeKeyShape applies the AES-256 and RSA-4096 byte floors and the documented ECDSA curves", () => {
  assert.equal(judgeKeyShape({ algorithm: "AES", length: 32 }), undefined);
  assert.equal(judgeKeyShape({ algorithm: "RSA", length: 512 }), undefined);
  assert.equal(judgeKeyShape({ algorithm: "ECDSA", length: 32, curveId: "NIST_P256" }), undefined);
  assert.equal(judgeKeyShape({ algorithm: "ECDSA", length: 66, curveId: "NIST_P521" }), undefined);
  assert.match(judgeKeyShape({ algorithm: "AES", length: 16 }).reason, /AES-128 is below the AES-256 floor/);
  assert.match(judgeKeyShape({ algorithm: "AES", length: 24 }).reason, /AES-192 is below the AES-256 floor/);
  assert.match(judgeKeyShape({ algorithm: "RSA", length: 256 }).reason, /RSA-2048 is below the RSA-4096 floor/);
  assert.match(judgeKeyShape({ algorithm: "RSA", length: 384 }).reason, /RSA-3072 is below the RSA-4096 floor/);
  assert.match(judgeKeyShape({ algorithm: "RSA" }).reason, /keyShape.length missing/);
  assert.match(judgeKeyShape({ algorithm: "ECDSA", length: 32 }).reason, /curveId missing or outside/);
  assert.match(judgeKeyShape({ algorithm: "ECDSA", length: 32, curveId: "SECP256K1" }).reason, /curveId missing or outside/);
  assert.match(judgeKeyShape({ algorithm: "DES", length: 8 }).reason, /outside the documented AES\/RSA\/ECDSA enum/);
  assert.match(judgeKeyShape({}).reason, /outside the documented AES\/RSA\/ECDSA enum/);
});

test("control 19: an RSA-2048 key fails OCI-GRD-05 while documented strong shapes pass", async () => {
  const rsa2048 = compliantClient();
  rsa2048.listKeys = async () => [{ id: "key-rsa", displayName: "signing", algorithm: "RSA", lifecycleState: "ENABLED" }];
  rsa2048.getKey = async (_vault, keyId) => ({ id: keyId, lifecycleState: "ENABLED", keyShape: { algorithm: "RSA", length: 256 } });
  const weak = await assessOciTenancyGuardrails(rsa2048);
  const finding = byId(weak, "OCI-GRD-05");
  assert.equal(finding.status, "fail");
  assert.equal(finding.evidence.keys_judged, 1);
  assert.equal(finding.evidence.weak_keys[0].lengthBytes, 256);
  assert.match(finding.evidence.weak_keys[0].reason, /RSA-2048 is below the RSA-4096 floor/);
  assert.match(finding.summary, /1\/1 ENABLED keys judged from Key.keyShape: 1 weak/);
  assert.match(finding.summary, /ECDSA keys pass on any documented KeyShape.curveId/);
  assert.equal(finding.evidence.source, OCI_SURFACE_DOCS.keyDetail.rest);
  assert.deepEqual(finding.evidence.length_floor_bytes, { AES: 32, RSA: 512 });

  const aes128 = compliantClient();
  aes128.getKey = async (_vault, keyId) => ({ id: keyId, lifecycleState: "ENABLED", keyShape: { algorithm: "AES", length: 16 } });
  assert.equal(byId(await assessOciTenancyGuardrails(aes128), "OCI-GRD-05").status, "fail");

  const missingLength = compliantClient();
  missingLength.getKey = async (_vault, keyId) => ({ id: keyId, lifecycleState: "ENABLED", keyShape: { algorithm: "AES" } });
  assert.equal(byId(await assessOciTenancyGuardrails(missingLength), "OCI-GRD-05").status, "fail");

  for (const shape of [{ algorithm: "RSA", length: 512 }, { algorithm: "ECDSA", length: 48, curveId: "NIST_P384" }, { algorithm: "ECDSA", length: 32, curveId: "NIST_P256" }]) {
    const strong = compliantClient();
    strong.getKey = async (_vault, keyId) => ({ id: keyId, lifecycleState: "ENABLED", keyShape: shape });
    const passing = byId(await assessOciTenancyGuardrails(strong), "OCI-GRD-05");
    assert.equal(passing.status, "pass", JSON.stringify(shape));
    assert.equal(passing.evidence.weak_keys.length, 0);
  }

  const noCurve = compliantClient();
  noCurve.getKey = async (_vault, keyId) => ({ id: keyId, lifecycleState: "ENABLED", keyShape: { algorithm: "ECDSA", length: 32 } });
  assert.equal(byId(await assessOciTenancyGuardrails(noCurve), "OCI-GRD-05").status, "fail");
});

test("control 19: a denied or shapeless key get never passes and names the cause", async () => {
  const denied = compliantClient();
  denied.getKey = async () => {
    throw DENIED_ERROR;
  };
  const single = byId(await assessOciTenancyGuardrails(denied), "OCI-GRD-05");
  assert.equal(single.status, "manual");
  assert.match(single.summary, /none of the 1 ENABLED keys could be read with kms management key get/);
  assert.match(single.summary, /NotAuthorizedOrNotFound/);
  assert.equal(single.evidence.key_detail_errors, 1);
  assert.equal(single.evidence.keys_judged, 0);

  const partial = compliantClient();
  partial.listKeys = async () => [
    { id: "key-1", displayName: "data", algorithm: "AES", lifecycleState: "ENABLED" },
    { id: "key-2", displayName: "backup", algorithm: "AES", lifecycleState: "ENABLED" },
  ];
  partial.getKey = async (_vault, keyId) => {
    if (keyId === "key-2") throw DENIED_ERROR;
    return { id: keyId, lifecycleState: "ENABLED", keyShape: { algorithm: "AES", length: 32 } };
  };
  const mixed = byId(await assessOciTenancyGuardrails(partial), "OCI-GRD-05");
  assert.equal(mixed.status, "warn");
  assert.equal(mixed.evidence.keys_total, 2);
  assert.equal(mixed.evidence.keys_judged, 1);
  assert.equal(mixed.evidence.key_detail_errors, 1);
  assert.match(mixed.summary, /1\/2 ENABLED keys judged from Key.keyShape/);
  assert.match(mixed.summary, /1 kms management key get reads failed/);

  const shapeless = compliantClient();
  shapeless.getKey = async (_vault, keyId) => ({ id: keyId, lifecycleState: "ENABLED" });
  const noShape = byId(await assessOciTenancyGuardrails(shapeless), "OCI-GRD-05");
  assert.equal(noShape.status, "manual");
  assert.match(noShape.summary, /response did not include keyShape/);
});

test("rule 10: the vault key cap reports seen versus total and withholds pass", async () => {
  const client = compliantClient();
  client.listKeys = async () => [
    { id: "key-1", displayName: "data", algorithm: "AES", lifecycleState: "ENABLED" },
    { id: "key-2", displayName: "backup", algorithm: "AES", lifecycleState: "ENABLED" },
    { id: "key-3", displayName: "retired", algorithm: "AES", lifecycleState: "DISABLED" },
  ];
  const capped = byId(await assessOciTenancyGuardrails(client, { maxKeys: 1 }), "OCI-GRD-05");
  assert.equal(capped.status, "warn");
  assert.equal(capped.evidence.key_cap_hit, true);
  assert.equal(capped.evidence.key_cap, 1);
  assert.equal(capped.evidence.keys_seen, 1);
  assert.equal(capped.evidence.keys_total, 2);
  assert.match(capped.summary, /Key cap 1 hit: 1\/2 ENABLED keys inspected; a pass verdict is withheld/);

  const exact = byId(await assessOciTenancyGuardrails(client, { maxKeys: 2 }), "OCI-GRD-05");
  assert.equal(exact.status, "pass");
  assert.equal(exact.evidence.key_cap_hit, false);
  assert.equal(exact.evidence.keys_judged, 2);
});

test("bastions that combine a world allow list with a long TTL fail instead of warn", async () => {
  const exposed = compliantClient();
  exposed.getBastion = async () => ({ id: "bastion-1", name: "ops", lifecycleState: "ACTIVE", maxSessionTtlInSeconds: 86400, clientCidrBlockAllowList: ["0.0.0.0/0"] });
  const failing = byId(await assessOciTenancyGuardrails(exposed), "OCI-GRD-04");
  assert.equal(failing.status, "fail");
  assert.equal(failing.evidence.exposed_bastions.length, 1);
  assert.equal(failing.evidence.weak_bastions.length, 0);
  assert.match(failing.summary, /1 bastions combine a world CIDR allow list/);

  const worldOnly = compliantClient();
  worldOnly.getBastion = async () => ({ id: "bastion-1", name: "ops", lifecycleState: "ACTIVE", maxSessionTtlInSeconds: 3600, clientCidrBlockAllowList: ["::/0"] });
  const warning = byId(await assessOciTenancyGuardrails(worldOnly), "OCI-GRD-04");
  assert.equal(warning.status, "warn");
  assert.equal(warning.evidence.exposed_bastions.length, 0);
  assert.equal(warning.evidence.weak_bastions.length, 1);

  const longTtlOnly = compliantClient();
  longTtlOnly.getBastion = async () => ({ id: "bastion-1", name: "ops", lifecycleState: "ACTIVE", maxSessionTtlInSeconds: 86400, clientCidrBlockAllowList: ["203.0.113.0/24"] });
  assert.equal(byId(await assessOciTenancyGuardrails(longTtlOnly), "OCI-GRD-04").status, "warn");
});

test("NSG rule evidence carries the documented SecurityRule.isValid flag", async () => {
  const client = compliantClient();
  client.listNetworkSecurityGroupRules = async () => [
    { id: "sr-1", direction: "INGRESS", protocol: "6", source: "0.0.0.0/0", sourceType: "CIDR_BLOCK", isValid: false, tcpOptions: { destinationPortRange: { min: 22, max: 22 } } },
    { id: "sr-2", direction: "INGRESS", protocol: "6", source: "10.0.0.0/8", sourceType: "CIDR_BLOCK", isValid: true, tcpOptions: { destinationPortRange: { min: 443, max: 443 } } },
  ];
  const finding = byId(await assessOciTenancyGuardrails(client), "OCI-GRD-02");
  assert.equal(finding.status, "fail");
  assert.equal(finding.evidence.nsg_rules_seen, 2);
  assert.equal(finding.evidence.nsg_rules_is_valid_false, 1);
  assert.equal(finding.evidence.permissive_nsg_rules[0].isValid, false);
  assert.ok(OCI_SURFACE_DOCS.networkSecurityGroupRules.fields.includes("isValid"));
});

test("rule 1 corollary: vacuous NSG and gateway emptiness never passes beside a partially unreadable security list inventory", async () => {
  const oneCompartmentForbidden = compliantClient();
  oneCompartmentForbidden.listNetworkSecurityGroups = async () => [];
  oneCompartmentForbidden.listSecurityLists = async (compartmentId) => {
    if (compartmentId === PROD.id) throw FORBIDDEN_ERROR;
    return compartmentId === APPS.id ? [{ id: "sl-1", lifecycleState: "AVAILABLE", ingressSecurityRules: [] }] : [];
  };
  const denied = await assessOciTenancyGuardrails(oneCompartmentForbidden);
  assert.equal(byId(denied, "OCI-GRD-01").status, "warn");
  for (const id of ["OCI-GRD-02", "OCI-GRD-03"]) {
    const item = byId(denied, id);
    assert.equal(item.status, "warn", `${id} must not pass beside a partial security list inventory: ${item.summary}`);
    assert.match(item.summary, /1 security lists were readable across 2\/3 compartments/);
    assert.match(item.summary, /The security list inventory is incomplete \(network security-list list denied or unreadable in 1 compartment\(s\): prod\), so a pass verdict is withheld/);
    assert.equal(item.evidence.security_lists_readable, true);
    assert.equal(item.evidence.security_lists_partial, true);
    assert.deepEqual(item.evidence.security_lists_denied_compartments, ["prod"]);
    assert.equal(item.evidence.security_lists_compartments_truncated, false);
  }
  assert.ok(denied.errors.some((error) => /network security-list list in compartment prod: ServiceError: 403 NotAllowed/.test(error)));

  const capped = compliantClient();
  capped.listNetworkSecurityGroups = async () => [];
  capped.listSecurityLists = async (compartmentId) => (compartmentId === TENANCY ? [{ id: "sl-root", lifecycleState: "AVAILABLE", ingressSecurityRules: [] }] : []);
  const truncated = await assessOciTenancyGuardrails(capped, { maxCompartments: 1 });
  for (const id of ["OCI-GRD-02", "OCI-GRD-03"]) {
    const item = byId(truncated, id);
    assert.equal(item.status, "warn", `${id}: ${item.summary}`);
    assert.match(item.summary, /compartment cap hit \(1\/3 compartments inspected by network security-list list\)/);
    assert.equal(item.evidence.security_lists_compartments_truncated, true);
  }

  const unreadable = compliantClient();
  unreadable.listNetworkSecurityGroups = async () => [];
  unreadable.listSecurityLists = async () => {
    throw DENIED_ERROR;
  };
  const manual = await assessOciTenancyGuardrails(unreadable);
  for (const id of ["OCI-GRD-02", "OCI-GRD-03"]) {
    const item = byId(manual, id);
    assert.equal(item.status, "manual", `${id}: ${item.summary}`);
    assert.match(item.summary, /no readable security lists were found \(network security-list list in compartment root: ServiceError: 404 NotAuthorizedOrNotFound/);
    assert.equal(item.evidence.security_lists_readable, false);
  }

  const complete = compliantClient();
  complete.listNetworkSecurityGroups = async () => [];
  const passing = await assessOciTenancyGuardrails(complete);
  for (const id of ["OCI-GRD-02", "OCI-GRD-03"]) {
    const item = byId(passing, id);
    assert.equal(item.status, "pass", `${id}: ${item.summary}`);
    assert.match(item.summary, /1 security lists were readable across 3\/3 compartments/);
    assert.equal(item.evidence.security_lists_partial, false);
  }
});

/**
 * Every client surface, the OCI CLI command it wraps, the findings whose
 * verdict or evidence reads it under fixture (d), and (for compartment-scoped
 * lists) the argument position of the compartment OCID. Findings not listed
 * for a surface must keep passing when only that surface fails, so the table
 * also guards against over-demotion.
 */
const INVENTORY_SWEEP = [
  { method: "listCompartments", command: "iam compartment list", dependents: ["OCI-IAM-04", "OCI-IAM-05", "OCI-LOG-05", "OCI-GRD-01", "OCI-GRD-02", "OCI-GRD-03", "OCI-GRD-04", "OCI-GRD-05", "OCI-GRD-06", "OCI-CMP-01", "OCI-CMP-02", "OCI-CMP-03"] },
  { method: "listUsers", command: "iam user list", dependents: ["OCI-IAM-02", "OCI-IAM-03"] },
  { method: "getAuthenticationPolicy", command: "iam authentication-policy get", dependents: ["OCI-IAM-01"] },
  { method: "listApiKeys", command: "iam user api-key list", dependents: ["OCI-IAM-03"] },
  { method: "listCustomerSecretKeys", command: "iam customer-secret-key list", dependents: ["OCI-IAM-03"] },
  { method: "listAuthTokens", command: "iam auth-token list", dependents: ["OCI-IAM-03"] },
  { method: "listPolicies", command: "iam policy list", dependents: ["OCI-IAM-04"], compartmentArg: 0 },
  { method: "listAvailabilityDomains", command: "iam availability-domain list", dependents: ["OCI-CMP-03"] },
  { method: "getAuditConfiguration", command: "audit config get", dependents: ["OCI-LOG-06"] },
  { method: "listAuditEvents", command: "audit event list", dependents: ["OCI-LOG-04"] },
  { method: "getCloudGuardConfiguration", command: "cloud-guard configuration get", dependents: ["OCI-LOG-01", "OCI-LOG-02", "OCI-LOG-03"] },
  { method: "listCloudGuardTargets", command: "cloud-guard target list", dependents: ["OCI-LOG-01"] },
  { method: "listCloudGuardProblems", command: "cloud-guard problem list", dependents: ["OCI-LOG-02"] },
  { method: "listResponderRecipes", command: "cloud-guard responder-recipe list", dependents: ["OCI-LOG-03"] },
  { method: "listEventRules", command: "events rule list", dependents: ["OCI-LOG-05"], compartmentArg: 0 },
  { method: "listSecurityLists", command: "network security-list list", dependents: ["OCI-GRD-01", "OCI-GRD-03"], compartmentArg: 0 },
  { method: "listNetworkSecurityGroups", command: "network nsg list", dependents: ["OCI-GRD-02"], compartmentArg: 0 },
  { method: "listNetworkSecurityGroupRules", command: "network nsg rules list", dependents: ["OCI-GRD-02"] },
  { method: "listInternetGateways", command: "network internet-gateway list", dependents: ["OCI-GRD-03"], compartmentArg: 0 },
  { method: "listBastions", command: "bastion bastion list", dependents: ["OCI-GRD-04"], compartmentArg: 0 },
  { method: "getBastion", command: "bastion bastion get", dependents: ["OCI-GRD-04"] },
  { method: "listBastionSessions", command: "bastion session list", dependents: ["OCI-GRD-04"] },
  { method: "listVaults", command: "kms management vault list", dependents: ["OCI-GRD-05"], compartmentArg: 0 },
  { method: "listKeys", command: "kms management key list", dependents: ["OCI-GRD-05"] },
  { method: "getKey", command: "kms management key get", dependents: ["OCI-GRD-05"] },
  { method: "listKeyVersions", command: "kms management key-version list", dependents: ["OCI-GRD-05"] },
  { method: "getObjectStorageNamespace", command: "os ns get", dependents: ["OCI-GRD-06"] },
  { method: "listBuckets", command: "os bucket list", dependents: ["OCI-GRD-06"], compartmentArg: 1 },
  { method: "getBucket", command: "os bucket get", dependents: ["OCI-GRD-06"] },
  { method: "listPreauthenticatedRequests", command: "os preauth-request list", dependents: ["OCI-GRD-06"] },
  { method: "listInstances", command: "compute instance list", dependents: ["OCI-CMP-01"], compartmentArg: 0 },
  { method: "listVolumes", command: "bv volume list", dependents: ["OCI-CMP-02"], compartmentArg: 0 },
  { method: "listBootVolumes", command: "bv boot-volume list", dependents: ["OCI-CMP-03"], compartmentArg: 0 },
];

function sweepClient(entry, mode, error) {
  const client = compliantClient();
  const original = client[entry.method];
  client[entry.method] = async (...args) => {
    if (mode === "full" || args[entry.compartmentArg] === PROD.id) throw error;
    return original(...args);
  };
  return client;
}

function hasNullEvidence(value) {
  if (value === null) return true;
  if (Array.isArray(value)) return value.some(hasNullEvidence);
  if (value && typeof value === "object") return Object.values(value).some(hasNullEvidence);
  return false;
}

test("per-inventory sweep: every finding that reads an unreadable surface drops below pass and names the command and compartment", async () => {
  assert.equal(INVENTORY_SWEEP.length, Object.keys(compliantClient()).filter((key) => key !== "getResolvedConfig" && key !== "getNow").length, "every client surface is in the sweep table");
  for (const entry of INVENTORY_SWEEP) {
    const modes = entry.compartmentArg === undefined ? ["full"] : ["full", "compartment"];
    for (const mode of modes) {
      for (const error of [DENIED_ERROR, FORBIDDEN_ERROR]) {
        const results = await runAllAssessments(sweepClient(entry, mode, error));
        const findings = results.flatMap((result) => result.findings);
        const label = `${entry.method} (${mode}, ${error.message.slice(14, 17)})`;
        for (const item of findings) {
          if (entry.dependents.includes(item.id)) {
            assert.notEqual(item.status, "pass", `${label}: ${item.id} must not pass: ${item.summary}`);
            assert.match(item.summary, new RegExp(entry.command), `${label}: ${item.id} must name the command: ${item.summary}`);
            if (mode === "compartment") {
              assert.match(item.summary, /\bprod\b/, `${label}: ${item.id} must name the denied compartment: ${item.summary}`);
            }
          } else if (item.id !== "OCI-IAM-06") {
            assert.equal(item.status, "pass", `${label}: ${item.id} does not read this surface and must keep passing: ${item.summary}`);
            assert.equal(hasNullEvidence(item.evidence), false, `${label}: ${item.id} passes with null evidence`);
          }
        }
        assert.ok(results.some((result) => result.errors.some((line) => line.includes(error.message))), `${label}: the collection error is recorded`);
      }
    }
  }
});

const CANARIES = {
  bearer: "CANARY-BEARER-oci-7f3a9c1d",
  session: "CANARY-SESSION-oci-7f3a9c1d",
  apiKey: "CANARY-APIKEY-oci-7f3a9c1d",
  urlToken: "CANARY-URLTOKEN-oci-7f3a9c1d",
  freeText: "CANARY-FREETEXT-oci-7f3a9c1d",
};
const CANARY_PATTERN = /CANARY-/;
const GATEWAY_PAGE = `<html><body><h1>502 Bad Gateway</h1><p>Authorization: Bearer ${CANARIES.bearer}</p><p>Set-Cookie: session_id=${CANARIES.session}; Path=/; HttpOnly</p><p>X-Api-Key: ${CANARIES.apiKey}</p></body></html>`;
const OPC_REQUEST_ID = "6B5074A48E0B435699E3CF5EC923D475/9C18FC7943F75E13A905193FD7FEC0A3/6C148159E67E634C115C8B7FFE780D0E";

/**
 * The `ServiceError:` block exactly as the CLI prints it (field set from the
 * docs.oracle.com known-issues example the runner cites), with a 403 so the
 * documented status, code, and opc-request-id can be asserted in the output.
 */
function serviceErrorBlock(message) {
  return `ServiceError:\n${JSON.stringify({
    client_version: "Oracle-PythonSDK/2.124.1, Oracle-PythonCLI/3.37.13",
    code: "NotAllowed",
    logging_tips: "Please run the OCI CLI command using --debug flag to find more debug information.",
    message,
    "opc-request-id": OPC_REQUEST_ID,
    operation_name: "list_users",
    request_endpoint: `GET https://identity.us-ashburn-1.oraclecloud.com/20160918/users?compartmentId=${TENANCY}`,
    status: 403,
    target_service: "identity",
    timestamp: "2026-09-21T22:47:00.000000+00:00",
    troubleshooting_tips: "See [https://docs.oracle.com/iaas/Content/API/References/apierrors.htm] for more information about resolving this error.",
  }, null, 4)}\n`;
}

const SERVICE_ERROR_DISCLOSURE = `exited 1 with ServiceError status=403 code=NotAllowed opc-request-id=${OPC_REQUEST_ID} message=`;

/** Three stderr shapes a failing `oci` process can produce; `disclosure` is the exact error string the runner must emit for a command. */
const ERROR_BODY_SHAPES = [
  {
    name: "A: exit 1 with a non-JSON gateway page on stderr",
    stderr: GATEWAY_PAGE,
    disclosure: (command) => `${command} exited 1; ${Buffer.byteLength(GATEWAY_PAGE, "utf8")} bytes of stderr and 0 bytes of stdout withheld (no documented ServiceError block)`,
  },
  {
    name: "B: exit 1 with a ServiceError block whose message embeds a tokenised URL",
    stderr: serviceErrorBlock(`Access denied; retry at https://example.invalid/callback?access_token=${CANARIES.urlToken}&state=x`),
    disclosure: (command) => `${command} ${SERVICE_ERROR_DISCLOSURE}Access denied; retry at https://example.invalid/callback?[redacted]`,
  },
  {
    name: "C: exit 1 with a ServiceError block whose free-text message carries a long token",
    stderr: serviceErrorBlock(`Upstream rejected the request; debug token ${CANARIES.freeText} then retry`),
    disclosure: (command) => `${command} ${SERVICE_ERROR_DISCLOSURE}Upstream rejected the request; debug token [redacted] then retry`,
  },
];

/** An error shaped exactly like Node's execFileSync failure, whose message echoes argv and stderr verbatim. */
function execFileSyncFailure(args, stderr, stdout = "") {
  return Object.assign(new Error(`Command failed: oci ${args.join(" ")}\n${stderr}`), {
    status: 1,
    signal: null,
    stdout,
    stderr,
    output: [null, stdout, stderr],
    pid: 4242,
  });
}

/** Every CLI surface the collectors call, derived from the client prototype so the walk cannot drift from the code. */
const CLI_SURFACES = Object.getOwnPropertyNames(OciAuditorClient.prototype)
  .filter((name) => /^(list|get)[A-Z]/.test(name) && name !== "getResolvedConfig" && name !== "getNow");

test("scrubErrorText is the one scrub for error strings: credential shapes go, operational text stays, and it is idempotent", () => {
  const cases = [
    [`Authorization: Bearer ${CANARIES.bearer}`, "Authorization: Bearer [redacted]"],
    ["Authorization: Basic dXNlcjpwYXNz", "Authorization: Basic [redacted]"],
    [`Set-Cookie: session_id=${CANARIES.session}; Path=/; HttpOnly`, "Set-Cookie=[redacted]; Path=/; HttpOnly"],
    [`Cookie: JSESSIONID=${CANARIES.session}; other=1`, "Cookie=[redacted]; other=1"],
    [`session_id=${CANARIES.session} sessionId: "${CANARIES.session}" session=${CANARIES.session}`, "session_id=[redacted] sessionId=[redacted] session=[redacted]"],
    [`X-Api-Key: ${CANARIES.apiKey} api_key="${CANARIES.apiKey}" apikey=${CANARIES.apiKey}`, "X-Api-Key=[redacted] api_key=[redacted] apikey=[redacted]"],
    [`access_token=${CANARIES.urlToken} "refresh_token": "${CANARIES.urlToken}" id_token: ${CANARIES.urlToken}`, 'access_token=[redacted] "refresh_token=[redacted] id_token=[redacted]'],
    ["client_secret=hunter2 password=letmein passwd: 'p@ss' pass_phrase=x", "client_secret=[redacted] password=[redacted] passwd=[redacted] pass_phrase=[redacted]"],
    [`retry at https://example.invalid/callback?access_token=${CANARIES.urlToken}&state=x.`, "retry at https://example.invalid/callback?[redacted]."],
    [`see https://x.example/cb#access_token=${CANARIES.urlToken}&x=y`, "see https://x.example/cb#[redacted]"],
    [`Authorization: ${SIGNING_HEADER}`, "Authorization: Signature [redacted]"],
    ['keyId="ocid1.tenancy.oc1..t/ocid1.user.oc1..u/aa:bb" signature="Zm9v=="', "keyId=[redacted] signature=[redacted]"],
    [`Upstream rejected the request; debug token ${CANARIES.freeText} then retry`, "Upstream rejected the request; debug token [redacted] then retry"],
    ["JWT eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "JWT [redacted].[redacted].[redacted]"],
  ];
  for (const [input, expected] of cases) {
    assert.equal(scrubErrorText(input), expected, input);
    assert.doesNotMatch(scrubErrorText(input), CANARY_PATTERN, input);
  }

  const benign = [
    `oci iam compartment list --compartment-id ${TENANCY} --all --compartment-id-in-subtree true --access-level ACCESSIBLE --include-root true`,
    "oci network security-list list in compartment prod: oci network security-list list exited 1; 236 bytes of stderr and 0 bytes of stdout withheld (no documented ServiceError block)",
    "ocid1.compartment.oc1..aaaaaaaabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123",
    "ServiceError: 404 NotAuthorizedOrNotFound: Authorization failed or requested resource not found.",
    "ServiceError: 403 NotAllowed: Please go to http://docs.oracle.com/iaas/Content/Identity/Concepts/policies.htm for possible reasons.",
    `status=403 code=NotAllowed opc-request-id=${OPC_REQUEST_ID} message=Authorization failed`,
    "token: user",
    "long_running_sessions: 3 credentials_seen: 12 Session idle timeout: 30 minutes",
    "kmsKeyId=ocid1.key.oc1..cmk masterKeyId: ocid1.key.oc1..cmk --key-id ocid1.key.oc1..cmk",
    "see https://docs.oracle.com/en-us/iaas/api/#/en/identity/20160918/User/ListUsers",
    "oci kms management key get exited 0 but printed 236 bytes of non-JSON stdout (withheld)",
  ];
  for (const text of benign) {
    assert.equal(scrubErrorText(text), text, `benign text must survive: ${text}`);
  }
  for (const [input] of cases) {
    assert.equal(scrubErrorText(scrubErrorText(input)), scrubErrorText(input), `idempotent: ${input}`);
  }
});

test("OciCommandError never echoes stderr or stdout and parseServiceError keeps only the documented fields", () => {
  const args = ["--config-file", "/tmp/oci/config", "--profile", "prod-audit", "--region", "us-ashburn-1", "--output", "json", "iam", "user", "list", "--compartment-id", TENANCY, "--all"];
  assert.deepEqual(ociCommandWords(args), ["iam", "user", "list"]);

  const runner = createOciCommandRunner((file, execArgs, options) => {
    assert.equal(file, "oci");
    assert.equal(options, OCI_COMMAND_RUNNER_OPTIONS);
    throw execFileSyncFailure(execArgs, GATEWAY_PAGE);
  });
  assert.throws(() => runner(args), (error) => {
    assert.ok(error instanceof OciCommandError);
    assert.equal(error.message, `oci iam user list exited 1; ${Buffer.byteLength(GATEWAY_PAGE, "utf8")} bytes of stderr and 0 bytes of stdout withheld (no documented ServiceError block)`);
    assert.equal(error.command, "oci iam user list");
    assert.equal(error.exitCode, 1);
    assert.equal(error.serviceError, undefined);
    assert.doesNotMatch(error.message, /Command failed|--config-file|<html>|CANARY-/);
    return true;
  });

  const parsed = parseServiceError(serviceErrorBlock(`Access denied; retry at https://example.invalid/callback?access_token=${CANARIES.urlToken}`));
  assert.deepEqual(Object.keys(parsed).sort(), ["code", "message", "opcRequestId", "status"]);
  assert.equal(parsed.status, 403);
  assert.equal(parsed.code, "NotAllowed");
  assert.equal(parsed.opcRequestId, OPC_REQUEST_ID);
  assert.equal(parseServiceError(GATEWAY_PAGE), undefined, "an HTML page is not a ServiceError block");
  assert.equal(parseServiceError("ServiceError:\n{ not json"), undefined, "a malformed block is described, not echoed");
  assert.equal(parseServiceError('ServiceError:\n{"code": "bad code <script>", "opc-request-id": "x y", "status": 500}').code, undefined, "an undocumented code shape is dropped");
  assert.equal(parseServiceError('ServiceError:\n{"code": "InternalServerError", "opc-request-id": "x y", "status": 500}').opcRequestId, undefined, "an undocumented request id shape is dropped");

  const serviceRunner = createOciCommandRunner((_file, execArgs) => {
    throw execFileSyncFailure(execArgs, serviceErrorBlock(`Access denied; retry at https://example.invalid/callback?access_token=${CANARIES.urlToken}&state=x`));
  });
  assert.throws(() => serviceRunner(args), (error) => {
    assert.equal(error.message, `oci iam user list ${SERVICE_ERROR_DISCLOSURE}Access denied; retry at https://example.invalid/callback?[redacted]`);
    assert.equal(error.serviceError.message, "Access denied; retry at https://example.invalid/callback?[redacted]");
    assert.doesNotMatch(error.message, /CANARY-|Oracle-Python|request_endpoint|compartmentId=/);
    return true;
  });

  const timedOut = OciCommandError.fromExecFailure(args, Object.assign(new Error("spawnSync oci ETIMEDOUT"), { status: null, signal: "SIGTERM", code: "ETIMEDOUT", stdout: "", stderr: "" }));
  assert.equal(timedOut.message, "oci iam user list did not exit normally (SIGTERM) (ETIMEDOUT); 0 bytes of stderr and 0 bytes of stdout withheld (no documented ServiceError block)");
  assert.equal(timedOut.exitCode, null);

  const client = new OciAuditorClient(sampleConfig(), () => GATEWAY_PAGE, { now: () => NOW });
  return assert.rejects(client.listUsers(), (error) => {
    assert.ok(error instanceof OciCommandError);
    assert.equal(error.message, `oci iam user list exited 0 but printed ${Buffer.byteLength(GATEWAY_PAGE, "utf8")} bytes of non-JSON stdout (withheld)`);
    return true;
  });
});

test("error-body walk: no CLI surface echoes a stderr or stdout canary into findings, summaries, errors, bundle files, the zip, or thrown errors", async () => {
  assert.deepEqual([...CLI_SURFACES].sort(), INVENTORY_SWEEP.map((entry) => entry.method).sort(), "the walk covers every prototype surface and the sweep table has not drifted");
  const base = createTempBase("grclanker-oci-error-body-");
  const walked = [];
  for (const entry of INVENTORY_SWEEP) {
    for (const shape of ERROR_BODY_SHAPES) {
      const label = `${entry.method} / ${shape.name}`;
      const command = `oci ${entry.command}`;
      const disclosure = shape.disclosure(command);
      const thrown = [];
      const real = new OciAuditorClient(
        sampleConfig(),
        createOciCommandRunner((_file, args) => {
          throw execFileSyncFailure(args, shape.stderr);
        }),
        { now: () => NOW },
      );
      const client = compliantClient();
      client[entry.method] = async (...args) => {
        try {
          return await real[entry.method](...args);
        } catch (error) {
          thrown.push(error);
          throw error;
        }
      };

      const access = await checkOciAccess(client);
      const results = await runAllAssessments(client);
      const bundle = await exportOciAuditBundle(client, sampleConfig(), base);

      assert.ok(thrown.length > 0, `${label}: the real client surface ran`);
      for (const error of thrown) {
        assert.ok(error instanceof OciCommandError, `${label}: CLI failures surface as OciCommandError`);
        assert.equal(error.message, disclosure, `${label}: the thrown error discloses the failure without echoing the body`);
        assert.equal(error.exitCode, 1, label);
        assert.equal(error.stderrBytes, Buffer.byteLength(shape.stderr, "utf8"), label);
      }
      const inMemory = JSON.stringify({ access, results });
      assert.doesNotMatch(inMemory, CANARY_PATTERN, `${label}: an in-memory finding, summary, or errors array leaked a canary`);
      assert.doesNotMatch(inMemory, /Command failed|<html>|Oracle-Python|request_endpoint/, `${label}: an in-memory output echoed the CLI body`);
      const allErrors = results.flatMap((result) => result.errors);
      assert.ok(allErrors.some((line) => line.includes(disclosure)), `${label}: an errors array discloses the failure: ${allErrors.join(" | ")}`);
      const dependents = results.flatMap((result) => result.findings).filter((item) => entry.dependents.includes(item.id));
      for (const item of dependents) {
        assert.notEqual(item.status, "pass", `${label}: ${item.id} must not pass`);
        assert.match(item.summary, new RegExp(entry.command), `${label}: ${item.id} names the command`);
      }

      const files = listFilesRecursively(bundle.outputDir);
      for (const file of files) {
        assert.doesNotMatch(readFileSync(file, "utf8"), CANARY_PATTERN, `${label}: ${relative(bundle.outputDir, file)} leaked a canary`);
      }
      const entries = readZipEntries(bundle.zipPath);
      assert.equal(entries.filter((zipEntry) => !zipEntry.name.endsWith("/")).length, files.length, label);
      for (const zipEntry of entries) {
        assert.doesNotMatch(zipEntry.content, CANARY_PATTERN, `${label}: zip entry ${zipEntry.name} leaked a canary`);
      }
      const errorsLog = readFileSync(join(bundle.outputDir, "_errors.log"), "utf8");
      assert.ok(errorsLog.includes(disclosure), `${label}: _errors.log discloses the failure`);
      walked.push(label);
    }
  }
  assert.equal(walked.length, INVENTORY_SWEEP.length * ERROR_BODY_SHAPES.length);
});

test("scrub covers the JSON-colon keyId form, signingKeyId, pass_phrase, and pass_word assignments", () => {
  const json = redactSensitiveText('{"keyId": "ocid1.tenancy.oc1..FAKE_T/ocid1.user.oc1..FAKE_U/FAKE_FP", "signature": "FAKE_SIG==", "kmsKeyId": "ocid1.key.oc1..cmk"}');
  assert.doesNotMatch(json, /FAKE_/);
  assert.match(json, /keyId=\[redacted\]/);
  assert.match(json, /signature=\[redacted\]/);
  assert.match(json, /"kmsKeyId": "ocid1\.key\.oc1\.\.cmk"/, "KMS key OCIDs stay readable");
  assert.equal(redactSensitiveText("signingKeyId=ocid1.tenancy.oc1..FAKE_T/ocid1.user.oc1..FAKE_U/FAKE_FP"), "signingKeyId=[redacted]");
  assert.equal(redactSensitiveText('SigningKeyId="ocid1.tenancy.oc1..FAKE_T/ocid1.user.oc1..FAKE_U/FAKE_FP"'), "SigningKeyId=[redacted]");
  assert.equal(redactSensitiveText("pass_phrase=FAKE_PASSPHRASE_1 passphrase=FAKE_PASSPHRASE_2 pass_word=FAKE_PASSWORD_1"), "pass_phrase=[redacted] passphrase=[redacted] pass_word=[redacted]");
  assert.equal(redactSensitiveText("masterKeyId=ocid1.key.oc1..cmk kmsKeyId=ocid1.key.oc1..cmk --key-id ocid1.key.oc1..cmk"), "masterKeyId=ocid1.key.oc1..cmk kmsKeyId=ocid1.key.oc1..cmk --key-id ocid1.key.oc1..cmk");
  assert.equal(isSensitiveFieldName("pass_phrase"), true);
});

test("OCI-LOG-04 reads as supporting evidence without framework mappings", async () => {
  const result = await assessOciLoggingDetection(compliantClient());
  const finding = byId(result, "OCI-LOG-04");
  assert.deepEqual(finding.mappings, []);
  assert.match(finding.evidence.role, /supporting evidence for control 11/);
  for (const item of result.findings.filter((entry) => entry.id !== "OCI-LOG-04")) {
    assert.ok(item.mappings.length >= 8, `${item.id} carries the full framework mapping row`);
  }
});

test("ruleReachesSensitivePort follows protocol and destination port range semantics", () => {
  assert.equal(ruleReachesSensitivePort({ protocol: "6", tcpOptions: { destinationPortRange: { min: 22, max: 22 } } }), true);
  assert.equal(ruleReachesSensitivePort({ protocol: "6", tcpOptions: { destinationPortRange: { min: 1, max: 65535 } } }), true);
  assert.equal(ruleReachesSensitivePort({ protocol: "6", tcpOptions: { destinationPortRange: { min: 443, max: 443 } } }), false);
  assert.equal(ruleReachesSensitivePort({ protocol: "17", udpOptions: { destinationPortRange: { min: 22, max: 22 } } }), false);
  assert.equal(ruleReachesSensitivePort({ protocol: "all" }), true);
  assert.equal(ruleReachesSensitivePort({ protocol: "6" }), true);
});

test("assessOciComputeAndStorage requires the documented IMDS and kmsKeyId flags", async () => {
  const client = compliantClient();
  client.listInstances = async (compartmentId) => (compartmentId === APPS.id
    ? [
      { id: "inst-1", lifecycleState: "RUNNING", instanceOptions: { areLegacyImdsEndpointsDisabled: true } },
      { id: "inst-2", lifecycleState: "RUNNING", instanceOptions: { areLegacyImdsEndpointsDisabled: false } },
      { id: "inst-3", lifecycleState: "RUNNING" },
      { id: "inst-4", lifecycleState: "TERMINATED" },
    ]
    : []);
  client.listVolumes = async (compartmentId) => (compartmentId === APPS.id ? [{ id: "vol-1", lifecycleState: "AVAILABLE" }] : []);
  client.listBootVolumes = async (compartmentId, availabilityDomain) => {
    assert.equal(availabilityDomain, "Uocm:US-ASHBURN-AD-1");
    return compartmentId === APPS.id ? [{ id: "bv-1", lifecycleState: "AVAILABLE", kmsKeyId: "ocid1.key.oc1..cmk" }] : [];
  };
  const result = await assessOciComputeAndStorage(client);
  assert.equal(byId(result, "OCI-CMP-01").status, "fail");
  assert.deepEqual(byId(result, "OCI-CMP-01").evidence.legacy_imds_instances, ["inst-2", "inst-3"]);
  assert.equal(byId(result, "OCI-CMP-02").status, "fail");
  assert.equal(byId(result, "OCI-CMP-03").status, "pass");

  client.listAvailabilityDomains = async () => [];
  const noAds = await assessOciComputeAndStorage(client);
  assert.equal(byId(noAds, "OCI-CMP-03").status, "manual");
  assert.match(byId(noAds, "OCI-CMP-03").summary, /availability domains/);
});

test("exportOciAuditBundle writes the shared layout and never overwrites a prior bundle", async () => {
  const base = createTempBase("grclanker-oci-export-");
  const result = await exportOciAuditBundle(compliantClient(), sampleConfig(), base);
  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.equal(result.zipPath, `${result.outputDir}.zip`);
  assert.equal(result.findingCount, 21);
  assert.equal(result.errorCount, 0);
  assert.ok(existsSync(join(result.outputDir, "QUICK_REFERENCE.md")));
  assert.ok(existsSync(join(result.outputDir, "analysis", "findings.json")));
  assert.ok(existsSync(join(result.outputDir, "analysis", "compute-storage.json")));
  assert.ok(existsSync(join(result.outputDir, "core_data", "access.json")));
  assert.ok(existsSync(join(result.outputDir, "core_data", "compartments.json")));
  assert.ok(existsSync(join(result.outputDir, "compliance", "executive_summary.md")));
  assert.ok(existsSync(join(result.outputDir, "compliance", "unified_compliance_matrix.md")));
  for (const framework of ["fedramp/fedramp_compliance_report.md", "cmmc/cmmc_compliance_report.md", "soc2/soc2_compliance_report.md", "cis_oci/cis_oci_benchmark_report.md", "pci_dss/pci_dss_compliance_report.md", "disa_stig/stig_compliance_checklist.md", "irap/irap_compliance_report.md", "ismap/ismap_compliance_report.md"]) {
    assert.ok(existsSync(join(result.outputDir, "compliance", framework)), framework);
  }
  assert.equal(existsSync(join(result.outputDir, "_errors.log")), false);
  const metadata = JSON.parse(readFileSync(join(result.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.region, "us-ashburn-1");
  assert.equal(metadata.profile, "prod-audit");
  const accessRaw = readFileSync(join(result.outputDir, "core_data", "access.json"), "utf8");
  assert.ok(!accessRaw.includes("key_file"));

  const rerun = await exportOciAuditBundle(compliantClient(), sampleConfig(), base);
  assert.notEqual(rerun.outputDir, result.outputDir);
  assert.match(rerun.outputDir, /-2$/);
  assert.equal(rerun.zipPath, `${rerun.outputDir}.zip`);
  assert.ok(existsSync(result.zipPath));
});

test("exportOciAuditBundle records partial collection in _errors.log", async () => {
  const base = createTempBase("grclanker-oci-export-errors-");
  const result = await exportOciAuditBundle(partialClient(), sampleConfig(), base);
  assert.ok(result.errorCount > 0);
  const errorsLog = readFileSync(join(result.outputDir, "_errors.log"), "utf8");
  assert.match(errorsLog, /NotAuthorizedOrNotFound/);
  const summary = readFileSync(join(result.outputDir, "compliance", "executive_summary.md"), "utf8");
  assert.match(summary, /Partial Collection Warnings/);
});

test("redaction keeps field names, drops credential-bearing values, and scrubs key material from text", () => {
  for (const name of ["accessUri", "keyValue", "token", "authToken", "key", "secret", "clientSecret", "customerSecretKey", "password", "db_password", "passphrase", "privateKey", "key_file", "keyMaterial", "wrappedKey", "plaintext", "plaintextChecksum", "ciphertext", "authorization", "userData", "security_token_file", "requestSignature"]) {
    assert.equal(isSensitiveFieldName(name), true, name);
  }
  for (const name of ["passwordPolicy", "password_policy", "kmsKeyId", "keys_seen", "weak_keys", "credentials_seen", "credential_cap_hit", "stale_credentials", "isMfaActivated", "tokens_seen"]) {
    assert.equal(isSensitiveFieldName(name), false, name);
  }
  const redacted = redactSensitiveValues({
    accessUri: "/p/abc/n/ns/b/bucket/o/",
    password_policy: { minimumPasswordLength: 14 },
    nested: { token: "FAKE_SECRET_TOKEN_1", count: 3, enabled: true, items: [{ key: "FAKE_CUSTOMER_SECRET_1", id: "csk-1" }] },
    note: `see ${SECRET_PEM}`,
  });
  assert.deepEqual(redacted, {
    accessUri: REDACTED_MARKER,
    password_policy: { minimumPasswordLength: 14 },
    nested: { token: REDACTED_MARKER, count: 3, enabled: true, items: [{ key: REDACTED_MARKER, id: "csk-1" }] },
    note: "see [redacted key material]",
  });
  const text = redactSensitiveText(SECRET_ERROR.message);
  assert.doesNotMatch(text, /FAKE_/);
  assert.match(text, /\[redacted key material\]/);
  assert.match(text, /token=\[redacted\]/);
  assert.match(text, /Signature \[redacted\]/);
  assert.equal(redactSensitiveText("https://objectstorage.example/p/FAKE_ACCESS_URI_1/n/ns/b/logs/o/"), "https://objectstorage.example/p/[redacted]/n/ns/b/logs/o/");
  assert.deepEqual(projectCompartmentSnapshot({ ...PROD, description: "secret", freeformTags: { password: "x" } }), {
    id: PROD.id,
    compartmentId: TENANCY,
    name: "prod",
    lifecycleState: "ACTIVE",
  });
});

test("OCI request-signing header values never survive text redaction", () => {
  const headerOnly = redactSensitiveText(`Authorization: ${SIGNING_HEADER}`);
  assert.equal(headerOnly, "Authorization: Signature [redacted]");
  const spaced = redactSensitiveText('Signature version = "1", keyId = "ocid1.tenancy.oc1..FAKE_T/ocid1.user.oc1..FAKE_U/FAKE_FP", signature = "FAKE_SIG=="');
  assert.equal(spaced, "Signature [redacted]");
  const standalone = redactSensitiveText('keyId="ocid1.tenancy.oc1..FAKE_T/ocid1.user.oc1..FAKE_U/FAKE_FP" signature="FAKE_SIG==" request_signature=FAKE_SIG_2');
  assert.equal(standalone, "keyId=[redacted] signature=[redacted] request_signature=[redacted]");
  const bare = redactSensitiveText("Signature FAKE_SIGNATURE_BARE_1abcdef Bearer FAKE_BEARER_1abcdefgh");
  assert.equal(bare, "Signature [redacted] Bearer [redacted]");
  const text = redactSensitiveText(SECRET_ERROR.message);
  assert.doesNotMatch(text, /FAKE_|rsa-sha256|version="1"/, "the parameter list is redacted as a whole");
  assert.match(text, /Authorization: Signature \[redacted\]/);
  assert.match(text, /Debug: keyId=\[redacted\] signature=\[redacted\] Bearer \[redacted\] Signature \[redacted\]/);
  assert.equal(redactSensitiveText("kmsKeyId=ocid1.key.oc1..cmk --key-id ocid1.key.oc1..cmk"), "kmsKeyId=ocid1.key.oc1..cmk --key-id ocid1.key.oc1..cmk", "KMS key OCIDs are not signing keyIds");
});

test("rule 9: bundle files, the zip, and tool outputs never carry credential-bearing values", async () => {
  const outputs = await runAllAssessments(secretLadenClient());
  const serialized = JSON.stringify(outputs);
  assert.doesNotMatch(serialized, /FAKE_/, "assessment outputs leaked a fake secret");
  assert.match(serialized, /\[redacted key material\]/, "collection errors keep a redaction marker");

  const base = createTempBase("grclanker-oci-secrets-");
  const result = await exportOciAuditBundle(secretLadenClient(), sampleConfig({ configFile: "/tmp/oci/FAKE_CONFIG_DIR/config" }), base);
  const files = listFilesRecursively(result.outputDir);
  assert.ok(files.length >= 20);
  for (const file of files) {
    const content = readFileSync(file, "utf8");
    assert.doesNotMatch(content, /FAKE_/, `${relative(result.outputDir, file)} leaked a fake secret`);
  }
  const compartments = JSON.parse(readFileSync(join(result.outputDir, "core_data", "compartments.json"), "utf8"));
  assert.equal(compartments.length, 3);
  for (const compartment of compartments) {
    assert.deepEqual(Object.keys(compartment).sort(), ["compartmentId", "id", "lifecycleState", "name"]);
  }
  const errorsLog = readFileSync(join(result.outputDir, "_errors.log"), "utf8");
  assert.match(errorsLog, /\[redacted key material\]/);
  assert.match(errorsLog, /token=\[redacted\]/);
  assert.match(errorsLog, /key_file=\[redacted\]/);
  assert.match(errorsLog, /--config-file \[redacted\]/);
  assert.match(errorsLog, /Authorization: Signature \[redacted\]/);
  assert.match(errorsLog, /keyId=\[redacted\] signature=\[redacted\]/);
  for (const file of files) {
    const content = readFileSync(file, "utf8");
    assert.doesNotMatch(content, /FAKE_SIGNATURE_BASE64|FAKE_TENANCY_|FAKE_FINGERPRINT_|rsa-sha256/, `${relative(result.outputDir, file)} leaked the signing header`);
  }
  const metadata = JSON.parse(readFileSync(join(result.outputDir, "metadata.json"), "utf8"));
  assert.equal(metadata.config_file, REDACTED_MARKER);
  const access = JSON.parse(readFileSync(join(result.outputDir, "core_data", "access.json"), "utf8"));
  assert.ok(access.notes.includes(`Using OCI config ${REDACTED_MARKER} profile prod-audit.`), access.notes.join("|"));

  const entries = readZipEntries(result.zipPath);
  const entryNames = entries.map((entry) => entry.name);
  assert.ok(entryNames.some((name) => name.endsWith("analysis/findings.json")), entryNames.join(","));
  assert.ok(entryNames.some((name) => name.endsWith("core_data/compartments.json")));
  assert.ok(entryNames.some((name) => name.endsWith("_errors.log")));
  assert.equal(entries.filter((entry) => !entry.name.endsWith("/")).length, files.length);
  for (const entry of entries) {
    assert.doesNotMatch(entry.content, /FAKE_/, `zip entry ${entry.name} leaked a fake secret`);
    assert.doesNotMatch(entry.content, /FAKE_SIGNATURE_BASE64|FAKE_TENANCY_|rsa-sha256/, `zip entry ${entry.name} leaked the signing header`);
  }
});

test("rule 10: the policy cap reports seen versus total and withholds pass", async () => {
  const client = compliantClient();
  const capped = await assessOciIdentity(client, { maxPolicies: 2 });
  const policies = byId(capped, "OCI-IAM-04");
  assert.equal(policies.status, "warn");
  assert.equal(policies.evidence.policy_cap_hit, true);
  assert.equal(policies.evidence.policies_seen, 2);
  assert.equal(policies.evidence.policies_total, 3);
  assert.match(policies.summary, /Policy cap 2 hit: 2\/3 active policies inspected/);

  const uncapped = await assessOciIdentity(client, { maxPolicies: 3 });
  assert.equal(byId(uncapped, "OCI-IAM-04").status, "pass");
  assert.equal(byId(uncapped, "OCI-IAM-04").evidence.policy_cap_hit, false);
});

test("rule 10: the credential cap stops enumeration and reports users and credentials seen versus total", async () => {
  const capped = await assessOciIdentity(compliantClient(), { maxKeys: 1 });
  const rotation = byId(capped, "OCI-IAM-03");
  assert.equal(rotation.status, "warn");
  assert.equal(rotation.evidence.credential_cap_hit, true);
  assert.equal(rotation.evidence.credentials_seen, 1);
  assert.equal(rotation.evidence.credentials_total, null);
  assert.equal(rotation.evidence.users_inspected, 1);
  assert.equal(rotation.evidence.users_total, 2);
  assert.match(rotation.summary, /Credential cap 1 hit: 1 credentials seen across 1\/2 active users; the total is unknown/);

  const exact = await assessOciIdentity(compliantClient(), { maxKeys: 6 });
  assert.equal(byId(exact, "OCI-IAM-03").status, "pass");
  assert.equal(byId(exact, "OCI-IAM-03").evidence.credentials_total, 6);
});

test("rule 10: the bucket cap reports seen versus total and withholds pass", async () => {
  const client = compliantClient();
  client.listBuckets = async (_namespace, compartmentId) => (compartmentId === APPS.id
    ? [{ name: "logs", namespace: "tenantns", compartmentId: APPS.id }, { name: "backups", namespace: "tenantns", compartmentId: APPS.id }, { name: "media", namespace: "tenantns", compartmentId: APPS.id }]
    : []);
  const capped = await assessOciTenancyGuardrails(client, { maxBuckets: 2 });
  const buckets = byId(capped, "OCI-GRD-06");
  assert.equal(buckets.status, "warn");
  assert.equal(buckets.evidence.bucket_cap_hit, true);
  assert.equal(buckets.evidence.buckets_seen, 2);
  assert.equal(buckets.evidence.buckets_total, 3);
  assert.match(buckets.summary, /Bucket cap 2 hit: 2\/3 buckets inspected/);

  const uncapped = await assessOciTenancyGuardrails(client, { maxBuckets: 3 });
  assert.equal(byId(uncapped, "OCI-GRD-06").status, "pass");
  assert.equal(byId(uncapped, "OCI-GRD-06").evidence.bucket_cap_hit, false);
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-oci-path-");
  const outside = createTempBase("grclanker-oci-outside-");
  const linked = join(base, "linked");
  symlinkSync(outside, linked, "dir");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "linked/file.txt"), /symlinked parent directory/);

  const safe = resolveSecureOutputPath(base, join("reports", "safe.txt"));
  assert.match(safe, /reports\/safe\.txt$/);
});
