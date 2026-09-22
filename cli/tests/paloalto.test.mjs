import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { createServer } from "node:http";

import {
  PanosApiClient,
  PrismaCloudClient,
  assessAdminAccess,
  assessDataLossPrevention,
  assessLogging,
  assessPaloaltoCloudPosture,
  assessPaloaltoDeviceHardening,
  assessPaloaltoFirewallPolicy,
  assessPaloaltoThreatPrevention,
  assessPanosDeviceHardening,
  assessPanosFirewallPolicy,
  assessPanosThreatPrevention,
  assessPrismaCloudPosture,
  assessPrismaCompute,
  buildComplianceMatrix,
  collectPrismaSnapshot,
  createInsecureFetch,
  PrismaComputeClient,
  REDACTION_MARKER,
  checkPaloaltoAccess,
  collectComputeSnapshot,
  collectPanosSnapshot,
  createPaloaltoClients,
  describePrismaErrorBody,
  exportPaloaltoAuditBundle,
  isCredentialPropertyName,
  isCredentialXmlName,
  isPrimaryFinding,
  parseXml,
  redactCredentialProperties,
  redactCredentialValueText,
  redactErrorText,
  redactSecrets,
  redactXmlCredentials,
  registerPaloaltoTools,
  resolvePaloaltoConfiguration,
  resolveSecureOutputPath,
  xmlFindAll,
  xmlPath,
  xmlText,
  xmlToJson,
} from "../dist/extensions/grc-tools/paloalto.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";
import { assertSecretsAbsent, readBundleFiles, readZipEntries } from "./helpers/bundle-contents.mjs";

const noSleep = async () => {};

function createTempBase(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function jsonResponse(value, options = {}) {
  return new Response(JSON.stringify(value), {
    status: options.status ?? 200,
    headers: { "content-type": "application/json", ...(options.headers ?? {}) },
  });
}

function xmlResponse(body, status = 200) {
  return new Response(body, { status, headers: { "content-type": "application/xml" } });
}

function panosSuccess(inner) {
  return `<response status="success"><result>${inner}</result></response>`;
}

function members(values) {
  return values.map((value) => `<member>${value}</member>`).join("");
}

function securityRule(name, options = {}) {
  const profiles = options.group
    ? `<profile-setting><group>${members([options.group])}</group></profile-setting>`
    : "";
  return `<entry name="${name}">
    <from>${members(options.from ?? ["trust"])}</from><to>${members(options.to ?? ["untrust"])}</to>
    <source>${members(options.source ?? ["10.0.0.0/8"])}</source><destination>${members(options.destination ?? ["any"])}</destination>
    <application>${members(options.application ?? ["web-browsing"])}</application><service>${members(options.service ?? ["application-default"])}</service>
    <action>${options.action ?? "allow"}</action>
    ${options.logEnd === false ? "<log-end>no</log-end>" : "<log-end>yes</log-end>"}
    ${options.logSetting ? `<log-setting>${options.logSetting}</log-setting>` : ""}
    ${options.disabled ? "<disabled>yes</disabled>" : ""}
    ${profiles}
  </entry>`;
}

function goodVsysXml() {
  return `<vsys><entry name="vsys1">
    <zone><entry name="trust"><network><zone-protection-profile>zp-default</zone-protection-profile></network></entry><entry name="untrust"><network><zone-protection-profile>zp-default</zone-protection-profile></network></entry></zone>
    <rulebase>
      <security><rules>
        ${securityRule("allow-web", { group: "strict", logSetting: "forward-siem" })}
        ${securityRule("deny-all", { action: "deny", from: ["any"], to: ["any"], source: ["any"], application: ["any"], service: ["any"], logSetting: "forward-siem" })}
      </rules></security>
      <default-security-rules><rules>
        <entry name="intrazone-default"><action>deny</action><log-end>yes</log-end></entry>
        <entry name="interzone-default"><action>deny</action><log-end>yes</log-end></entry>
      </rules></default-security-rules>
      <decryption><rules><entry name="decrypt-outbound"><action>decrypt</action></entry></rules></decryption>
    </rulebase>
    <profiles>
      <virus><entry name="av-strict"/></virus>
      <spyware><entry name="as-strict"/></spyware>
      <vulnerability><entry name="vp-strict"><rules><entry name="block-critical"><severity>${members(["critical", "high"])}</severity><action><reset-both/></action></entry></rules></entry></vulnerability>
      <url-filtering><entry name="url-strict"><block>${members(["malware", "phishing", "command-and-control", "grayware"])}</block><credential-enforcement><mode><ip-user/></mode></credential-enforcement></entry></url-filtering>
      <file-blocking><entry name="fb-strict"><rules><entry name="block-pe"><file-type>${members(["pe", "elf"])}</file-type><action>block</action></entry></rules></entry></file-blocking>
      <wildfire-analysis><entry name="wf-all"><rules><entry name="all"><application>${members(["any"])}</application><file-type>${members(["any"])}</file-type><analysis>public-cloud</analysis></entry></rules></entry></wildfire-analysis>
      <data-filtering><entry name="dlp-pii"/></data-filtering>
    </profiles>
    <profile-group><entry name="strict">
      <virus>${members(["av-strict"])}</virus><spyware>${members(["as-strict"])}</spyware><vulnerability>${members(["vp-strict"])}</vulnerability>
      <url-filtering>${members(["url-strict"])}</url-filtering><file-blocking>${members(["fb-strict"])}</file-blocking>
      <wildfire-analysis>${members(["wf-all"])}</wildfire-analysis><data-filtering>${members(["dlp-pii"])}</data-filtering>
    </entry></profile-group>
    <global-protect>
      <global-protect-portal><entry name="portal"><portal-config><client-auth><entry name="auth"><authentication-profile>mfa-radius</authentication-profile></entry></client-auth></portal-config></entry></global-protect-portal>
      <global-protect-gateway><entry name="gateway"><remote-user-tunnel-configs><entry name="cfg"><authentication-override/></entry></remote-user-tunnel-configs><client-auth><entry name="auth"><authentication-profile>mfa-radius</authentication-profile></entry></client-auth></entry></global-protect-gateway>
    </global-protect>
  </entry></vsys>`;
}

function badVsysXml() {
  return `<vsys><entry name="vsys1">
    <zone><entry name="trust"/><entry name="untrust"/></zone>
    <rulebase>
      <security><rules>
        ${securityRule("allow-everything", { from: ["any"], to: ["any"], source: ["any"], destination: ["any"], application: ["any"], service: ["any"], logEnd: false })}
        ${securityRule("shadowed-web", { logEnd: false })}
      </rules></security>
      <default-security-rules><rules><entry name="intrazone-default"><action>allow</action></entry><entry name="interzone-default"><action>deny</action></entry></rules></default-security-rules>
    </rulebase>
    <profiles>
      <url-filtering><entry name="url-weak"><block>${members(["adult"])}</block><credential-enforcement><mode><disabled/></mode></credential-enforcement></entry></url-filtering>
      <file-blocking><entry name="fb-weak"><rules><entry name="alert-only"><file-type>${members(["pe"])}</file-type><action>alert</action></entry></rules></entry></file-blocking>
    </profiles>
  </entry></vsys>`;
}

function goodSharedXml() {
  return `<shared>
    <log-settings><syslog><entry name="siem"><server><entry name="s1"><server>10.1.1.1</server></entry></server></entry></syslog><profiles><entry name="forward-siem"><match-list><entry name="traffic"><send-syslog>${members(["siem"])}</send-syslog><send-to-panorama>yes</send-to-panorama></entry></match-list></entry></profiles></log-settings>
    <ssl-tls-service-profile><entry name="tls-strict"><protocol-settings><min-version>tls1-2</min-version></protocol-settings></entry></ssl-tls-service-profile>
    <authentication-profile><entry name="mfa-radius"><multi-factor-auth><mfa-enable>yes</mfa-enable></multi-factor-auth></entry></authentication-profile>
  </shared>`;
}

function goodDeviceconfigXml() {
  return `<deviceconfig>
    <system><hostname>fw1</hostname><ntp-servers><primary-ntp-server><ntp-server-address>time.example.com</ntp-server-address></primary-ntp-server></ntp-servers>
      <dns-setting><servers><primary>10.0.0.53</primary></servers></dns-setting><login-banner>Authorized use only</login-banner>
      <permitted-ip><entry name="10.0.0.0/24"/></permitted-ip><service><disable-telnet>yes</disable-telnet><disable-http>yes</disable-http></service>
      <snmp-setting><access-setting><version><v3/></version></access-setting></snmp-setting></system>
    <setting><management><idle-timeout>10</idle-timeout></management></setting>
  </deviceconfig>`;
}

function badDeviceconfigXml() {
  return `<deviceconfig>
    <system><hostname>fw2</hostname><service><disable-telnet>no</disable-telnet><disable-http>no</disable-http></service>
      <snmp-setting><access-setting><version><v2c><snmp-community-string>public</snmp-community-string></v2c></version></access-setting></snmp-setting></system>
    <setting><management><idle-timeout>0</idle-timeout></management></setting>
  </deviceconfig>`;
}

function goodMgtConfigXml() {
  return `<mgt-config><users><entry name="admin"><permissions><role-based><superuser>yes</superuser></role-based></permissions><authentication-profile>mfa-radius</authentication-profile></entry><entry name="auditor"><permissions><role-based><superreader>yes</superreader></role-based></permissions><public-key>abc</public-key></entry></users><password-complexity><enabled>yes</enabled></password-complexity></mgt-config>`;
}

function badMgtConfigXml() {
  return `<mgt-config><users>${["a", "b", "c", "d"].map((name) => `<entry name="${name}"><permissions><role-based><superuser>yes</superuser></role-based></permissions><phash>x</phash></entry>`).join("")}</users><password-complexity><enabled>no</enabled></password-complexity></mgt-config>`;
}

// Fake credential values a real PAN-OS config carries verbatim; none may reach the bundle.
const FAKE_PANOS_SECRETS = {
  phash: "$1$fakesalt$fakehashvalue0123456789",
  radiusSecret: "radius-shared-secret-fake",
  ldapBindPassword: "ldap-bind-password-fake",
  presharedKey: "ike-psk-fake-0123456789abcdef",
  communityString: "snmp-c0mmun1ty-fake",
  authpwd: "snmpv3-auth-password-fake",
  privpwd: "snmpv3-priv-password-fake",
  privateKey: "-----BEGIN PRIVATE KEY-----fakekeymaterial-----END PRIVATE KEY-----",
  apiKey: "integration-api-key-fake",
};

function secretsMgtConfigXml() {
  return `<mgt-config><users><entry name="admin"><phash>${FAKE_PANOS_SECRETS.phash}</phash><permissions><role-based><superuser>yes</superuser></role-based></permissions><authentication-profile>mfa-radius</authentication-profile></entry><entry name="auditor"><permissions><role-based><superreader>yes</superreader></role-based></permissions><public-key>c3NoLXJzYSBBQUFBQjNOemFDMXlj</public-key></entry></users><password-complexity><enabled>yes</enabled></password-complexity></mgt-config>`;
}

function secretsSharedXml() {
  return goodSharedXml().replace("</shared>", `<server-profile>
      <radius><entry name="corp-radius"><server><entry name="r1"><ip-address>10.9.9.9</ip-address><secret>${FAKE_PANOS_SECRETS.radiusSecret}</secret><port>1812</port></entry></server></entry></radius>
      <ldap><entry name="corp-ad"><bind-dn>cn=svc-panos,dc=example,dc=com</bind-dn><bind-password>${FAKE_PANOS_SECRETS.ldapBindPassword}</bind-password></entry></ldap>
    </server-profile>
    <certificate><entry name="gp-portal"><private-key>${FAKE_PANOS_SECRETS.privateKey}</private-key><public-key>-----BEGIN CERTIFICATE-----fakecert-----END CERTIFICATE-----</public-key></entry></certificate>
    <integration api-key="${FAKE_PANOS_SECRETS.apiKey}" name="siem-connector"><url>https://siem.example.com</url></integration>
  </shared>`);
}

function secretsNetworkXml() {
  return `<network><ike><gateway><entry name="site-b"><authentication><pre-shared-key><key>${FAKE_PANOS_SECRETS.presharedKey}</key></pre-shared-key></authentication><peer-address><ip>203.0.113.10</ip></peer-address></entry></gateway></ike></network>`;
}

function secretsDeviceconfigXml() {
  return goodDeviceconfigXml().replace(
    "<snmp-setting><access-setting><version><v3/></version></access-setting></snmp-setting>",
    `<snmp-setting><access-setting><version><v2c><snmp-community-string>${FAKE_PANOS_SECRETS.communityString}</snmp-community-string></v2c><v3><users><entry name="monitor"><authpwd>${FAKE_PANOS_SECRETS.authpwd}</authpwd><privpwd>${FAKE_PANOS_SECRETS.privpwd}</privpwd></entry></users></v3></version></access-setting></snmp-setting>`,
  );
}

function systemInfoXml(version = "11.1.2") {
  return panosSuccess(`<system><hostname>fw1</hostname><model>PA-440</model><sw-version>${version}</sw-version><app-version>8800-8600</app-version><av-version>4900-5400</av-version><threat-version>8800-8600</threat-version><wildfire-version>900000-900000</wildfire-version><url-filtering-version>20240101.20000</url-filtering-version></system>`);
}

function haXml(enabled = "yes") {
  return panosSuccess(`<enabled>${enabled}</enabled><group><local-info><state>active</state></local-info></group>`);
}

function panosSnapshot(overrides = {}) {
  const good = overrides.good !== false;
  return {
    host: overrides.host ?? "fw1.example.com",
    platform: "firewall",
    reachable: overrides.reachable ?? true,
    haStateFailed: overrides.haStateFailed ?? false,
    failedXpaths: overrides.failedXpaths ?? [],
    systemInfo: overrides.systemInfo ?? { model: "PA-440", "sw-version": good ? "11.1.2" : "9.1.0", "av-version": good ? "4900-5400" : "0", "threat-version": "8800-8600" },
    haState: parseXml(haXml(good ? "yes" : "no")).children[0].children[0],
    config: [
      parseXml(good ? goodVsysXml() : badVsysXml()),
      parseXml(good ? goodSharedXml() : "<shared/>"),
      parseXml(good ? goodDeviceconfigXml() : badDeviceconfigXml()),
      parseXml(good ? goodMgtConfigXml() : badMgtConfigXml()),
    ],
    errors: overrides.errors ?? [],
  };
}

function computeSnapshot(overrides = {}) {
  const good = overrides.good !== false;
  return {
    consoleUrl: "https://compute.example.com",
    defenders: good ? [{ hostname: "node-1", connected: true, version: "34.00.100", lastModified: "2026-09-01T00:00:00Z" }] : [{ hostname: "node-2", connected: false, version: "30.00.100" }],
    runtimeContainerPolicy: good ? { rules: [{ name: "default", disabled: false, processes: { effect: "prevent" }, network: { effect: "alert" }, filesystem: { effect: "alert" } }] } : { rules: [{ name: "alert-only", processes: { effect: "alert" } }] },
    complianceContainerPolicy: { rules: good ? [{ name: "cis-containers", disabled: false }] : [] },
    complianceHostPolicy: { rules: good ? [{ name: "cis-hosts", disabled: false }] : [] },
    vulnerabilityImagePolicy: { rules: good ? [{ name: "block-critical", disabled: false, effect: "block" }] : [{ name: "alert", effect: "alert" }] },
    registrySettings: { specifications: good ? [{ registry: "registry.example.com", repository: "*", cap: 5, scanners: 2 }] : [] },
    registryScans: good ? [{ id: "sha256:1", scanTime: "2026-09-01T00:00:00Z" }] : [],
    images: good
      ? [{ id: "sha256:2", scanTime: "2026-09-01T00:00:00Z", repoTag: { repo: "app" }, vulnerabilityDistribution: { critical: 0, high: 2, medium: 4, low: 1, total: 7 } }]
      : [],
    vulnerabilityStats: good ? documentedVulnerabilityStats({ critical: 0, high: 3 }) : documentedVulnerabilityStats({ critical: 12, high: 30 }),
    complianceStats: good ? documentedComplianceStats({ failed: 3, total: 100 }) : documentedComplianceStats({ failed: 0, total: 0 }),
    cloudDiscovery: good ? [{ provider: "aws", serviceType: "eks", total: 3, defended: 3 }] : [],
    ciScans: good ? [{ time: "2026-09-01T00:00:00Z", pass: true }] : [],
    failed: overrides.failed ?? [],
    truncated: overrides.truncated ?? [],
    errors: overrides.errors ?? [],
  };
}

function documentedVulnerabilityStats({ critical, high }) {
  const resource = (count, criticalShare, highShare) => ({
    count,
    cves: { critical: criticalShare, high: highShare, medium: 5, low: 2, total: criticalShare + highShare + 7 },
    impacted: { critical: criticalShare, high: highShare, medium: 3, low: 1, total: criticalShare + highShare + 4 },
    vulnerabilities: [],
  });
  return [{
    _id: "stats",
    modified: "2026-09-01T00:00:00Z",
    images: resource(40, critical, high),
    registryImages: resource(10, 0, 0),
    containers: resource(12, 0, 0),
    hosts: resource(3, 0, 0),
    functions: resource(0, 0, 0),
  }];
}

function documentedComplianceStats({ failed, total }) {
  return {
    categories: [{ name: "CIS", failed, total }],
    daily: [{ _id: "2026-09-01", distribution: { critical: 0, high: failed, medium: 0, low: 0, total: failed }, modified: "2026-09-01T00:00:00Z" }],
    ids: [{ id: 41, benchmarkID: "CIS_Docker_v1.6.0", failed, total, severity: "high", type: "container" }],
    rules: [{ name: "cis-hosts", policyType: "hostCompliance", failed, total }],
    templates: [{ name: "CIS", failed, total }],
  };
}

function prismaSnapshot(overrides = {}) {
  const good = overrides.good !== false;
  return {
    failed: overrides.failed ?? [],
    alertsTruncated: overrides.alertsTruncated ?? false,
    alertsTotal: overrides.alertsTotal,
    compute: "compute" in overrides ? overrides.compute : computeSnapshot({ good }),
    computeUnavailableReason: overrides.computeUnavailableReason,
    posture: good
      ? { summary: { passedResources: 95, failedResources: 5, totalResources: 100 }, complianceDetails: [{ name: "CIS v1.4", passedResources: 95, failedResources: 5 }] }
      : { summary: { passedResources: 40, failedResources: 60, totalResources: 100 }, complianceDetails: [] },
    alertRules: good ? [{ name: "all-critical", enabled: true, alertRuleNotificationConfig: [{ type: "email" }] }] : [{ name: "old", enabled: false }],
    alerts: good ? [] : [
      { policy: { name: "AWS Security Group allows all traffic from internet", policyType: "network", severity: "critical" } },
      { policy: { name: "AWS IAM policy overly permissive", policyType: "iam", severity: "high" } },
      { policy: { name: "AWS EBS volume not encrypted", policyType: "config", severity: "medium" } },
    ],
    policies: [
      { name: "AWS EBS volume not encrypted with CMK", policyType: "config", enabled: good },
      { name: "IAM user with excessive permissions", policyType: "iam", enabled: true },
      { name: "AWS Security Group allows all traffic on SSH port (22)", policyType: "network", enabled: true },
      { name: "Sensitive data exposed in S3 (DLP)", policyType: "data", enabled: good },
    ],
    cloudAccounts: good ? [{ name: "prod", enabled: true, groups: [{ name: "Default" }], status: "ok" }] : [{ name: "legacy", enabled: false, groups: [] }],
    accountGroups: [{ name: "Default" }],
    userRoles: good ? [{ name: "Auditors", roleType: "Account Group Read Only" }] : [{ name: "r1", roleType: "System Admin" }, { name: "r2", roleType: "System Admin" }, { name: "r3", roleType: "System Admin" }, { name: "r4", roleType: "System Admin" }],
    integrations: good ? [{ name: "splunk", integrationType: "splunk" }] : [],
    errors: overrides.errors ?? [],
  };
}

function byId(findings, id) {
  return findings.find((item) => item.id === id);
}

test("resolvePaloaltoConfiguration prefers args over env over config file and supports both products", () => {
  const base = createTempBase("grclanker-paloalto-config-");
  const configFile = join(base, "paloalto.json");
  writeFileSync(configFile, JSON.stringify({
    PRISMA_API_URL: "https://api.file.prismacloud.io",
    PRISMA_ACCESS_KEY_ID: "file-key",
    PRISMA_SECRET_KEY: "file-secret",
    PANOS_HOST: "file-fw.example.com",
    PANOS_API_KEY: "file-panos-key",
  }));

  const fromFile = resolvePaloaltoConfiguration({ config_file: configFile }, {});
  assert.equal(fromFile.prisma.apiUrl, "https://api.file.prismacloud.io");
  assert.equal(fromFile.prisma.accessKeyId, "file-key");
  assert.equal(fromFile.panos[0].host, "file-fw.example.com");
  assert.ok(fromFile.sourceChain.includes("config-file-prisma-access-key"));

  const fromEnv = resolvePaloaltoConfiguration({ config_file: configFile }, {
    PRISMA_API_URL: "https://api2.prismacloud.io",
    PRISMA_ACCESS_KEY_ID: "env-key",
    PRISMA_SECRET_KEY: "env-secret",
    PANOS_HOST: "fw-a.example.com, fw-b.example.com",
    PANOS_USERNAME: "auditor",
    PANOS_PASSWORD: "env-pass",
    PANOS_VERIFY_TLS: "false",
  });
  assert.equal(fromEnv.prisma.apiUrl, "https://api2.prismacloud.io");
  assert.equal(fromEnv.prisma.accessKeyId, "env-key");
  assert.deepEqual(fromEnv.panos.map((item) => item.host), ["fw-a.example.com", "fw-b.example.com"]);
  assert.equal(fromEnv.panos[0].username, "auditor");
  assert.equal(fromEnv.panos[0].apiKey, undefined);
  assert.equal(fromEnv.verifyTls, false);

  const fromArgs = resolvePaloaltoConfiguration({
    prisma_api_url: "https://api.eu.prismacloud.io",
    prisma_access_key_id: "arg-key",
    prisma_secret_key: "arg-secret",
    panos_hosts: "192.0.2.10",
    panos_api_key: "arg-panos-key",
    timeout_seconds: 5,
  }, { PRISMA_ACCESS_KEY_ID: "env-key", PRISMA_SECRET_KEY: "env-secret" });
  assert.equal(fromArgs.prisma.apiUrl, "https://api.eu.prismacloud.io");
  assert.equal(fromArgs.prisma.accessKeyId, "arg-key");
  assert.equal(fromArgs.panos[0].baseUrl, "https://192.0.2.10");
  assert.equal(fromArgs.panos[0].apiKey, "arg-panos-key");
  assert.equal(fromArgs.timeoutMs, 5000);
  assert.equal(fromArgs.verifyTls, true);
  assert.ok(fromArgs.sourceChain.includes("arguments-prisma-access-key"));
});

test("resolvePaloaltoConfiguration allows a single product and rejects incomplete credentials", () => {
  const prismaOnly = resolvePaloaltoConfiguration({}, { PRISMA_ACCESS_KEY_ID: "k", PRISMA_SECRET_KEY: "s" });
  assert.equal(prismaOnly.prisma.apiUrl, "https://api.prismacloud.io");
  assert.equal(prismaOnly.panos.length, 0);

  const panosOnly = resolvePaloaltoConfiguration({}, { PANOS_HOST: "fw.example.com", PANOS_API_KEY: "key" });
  assert.equal(panosOnly.prisma, undefined);
  assert.equal(panosOnly.panos.length, 1);

  assert.throws(() => resolvePaloaltoConfiguration({}, {}), /Configure Prisma Cloud/);
  assert.throws(() => resolvePaloaltoConfiguration({}, { PRISMA_ACCESS_KEY_ID: "k" }), /both PRISMA_ACCESS_KEY_ID and PRISMA_SECRET_KEY/);
  assert.throws(() => resolvePaloaltoConfiguration({}, { PANOS_HOST: "fw.example.com" }), /PANOS_API_KEY or both/);
  assert.throws(() => resolvePaloaltoConfiguration({ config_file: "/nonexistent/paloalto.json" }, {}), /Unable to read Palo Alto config file \/nonexistent\/paloalto\.json \(ENOENT\)/);
});

// Config loader canaries: no two share an 8-character window, so any fragment a parser
// quotes from the file is attributable to one fixture. The short canary keeps the JSON
// short file at 20 characters, within the size at which JSON.parse quotes the whole source.
const LOADER_CANARIES = {
  yamlNestedKey: "cnrA1qz8Xw4LpT9vK2mD",
  yamlNestedBearer: "cnrB5hj3Yn7GsW2rQ8kF",
  yamlAlias: "cnrC9tb6Um1JdX3eN7wP",
  jsonUnquoted: "cnrD2vf7Zk5HcR8sL4yG",
  jsonShort: "cnrE6pm4Qa",
  jsonMultiline: "cnrF3gk8Wd2ZnT6iM9oJ",
};
const LIBRARY_ERROR_WORDING = ["Nested mappings", "is not valid JSON", "Unresolved alias", "illegal operation", "permission denied", "Unexpected token", "Expected ',' or '}'"];

function assertNoLoaderLeak(text, canaries, label) {
  for (const canary of canaries) {
    assert.ok(!text.includes(canary), `${label}: canary ${canary} leaked into: ${text}`);
    for (let index = 0; index + 8 <= canary.length; index += 1) {
      const fragment = canary.slice(index, index + 8);
      assert.ok(!text.includes(fragment), `${label}: canary fragment ${fragment} leaked into: ${text}`);
    }
  }
  for (const wording of LIBRARY_ERROR_WORDING) {
    assert.ok(!text.includes(wording), `${label}: library wording "${wording}" leaked into: ${text}`);
  }
}

test("config loader errors carry fixed text, the path, a validated code, and a structured line, never the file contents or library wording", async () => {
  const base = createTempBase("grclanker-paloalto-loader-errors-");
  const write = (name, text) => {
    const pathname = join(base, name);
    writeFileSync(pathname, text);
    return pathname;
  };
  const tools = new Map();
  registerPaloaltoTools({ registerTool: (tool) => tools.set(tool.name, tool) });
  const check = tools.get("paloalto_check_access");
  const checkAccessText = async (configFile) => JSON.stringify(await check.execute("call-loader", check.prepareArguments({ config_file: configFile })));

  const cases = [
    {
      // Not JSON at all: the parser quotes the first characters of the file.
      label: "YAML nested mapping",
      file: write("nested.yaml", `key: ${LOADER_CANARIES.yamlNestedKey}: Bearer ${LOADER_CANARIES.yamlNestedBearer}\n`),
      canaries: [LOADER_CANARIES.yamlNestedKey, LOADER_CANARIES.yamlNestedBearer],
      libraryThrows: true,
      expected: (pathname) => `Unable to parse Palo Alto config file: invalid JSON in ${pathname} (INVALID_JSON)`,
    },
    {
      label: "YAML alias",
      file: write("alias.yaml", `key: *${LOADER_CANARIES.yamlAlias}\n`),
      canaries: [LOADER_CANARIES.yamlAlias],
      libraryThrows: true,
      expected: (pathname) => `Unable to parse Palo Alto config file: invalid JSON in ${pathname} (INVALID_JSON)`,
    },
    {
      // The "Unexpected token" family quotes a 10-character window around the failure.
      label: "JSON unquoted value",
      file: write("unquoted.json", `{"PRISMA_SECRET_KEY": ${LOADER_CANARIES.jsonUnquoted}}\n`),
      canaries: [LOADER_CANARIES.jsonUnquoted],
      libraryThrows: true,
      libraryCarriesFragment: true,
      expected: (pathname) => `Unable to parse Palo Alto config file: invalid JSON in ${pathname} (INVALID_JSON)`,
    },
    {
      // At 20 characters or fewer the whole source is quoted, key on a scrub list or not.
      label: "JSON short file",
      file: write("short.json", `{"token":${LOADER_CANARIES.jsonShort}}`),
      canaries: [LOADER_CANARIES.jsonShort],
      libraryThrows: true,
      libraryCarriesCanary: true,
      expected: (pathname) => `Unable to parse Palo Alto config file: invalid JSON in ${pathname} (INVALID_JSON)`,
    },
    {
      // The structural family reports a position; only that position becomes a line.
      label: "JSON missing comma",
      file: write("multiline.json", `{\n  "PANOS_HOST": "fw1.example.com",\n  "PANOS_API_KEY": "${LOADER_CANARIES.jsonMultiline}"\n  "PANOS_VERIFY_TLS": "true"\n}\n`),
      canaries: [LOADER_CANARIES.jsonMultiline],
      libraryThrows: true,
      expected: (pathname) => `Unable to parse Palo Alto config file: invalid JSON in ${pathname} at line 4 (INVALID_JSON)`,
    },
    {
      label: "EISDIR",
      file: (() => {
        const pathname = join(base, "config-dir.json");
        mkdirSync(pathname);
        return pathname;
      })(),
      canaries: [],
      libraryThrows: false,
      expected: (pathname) => `Unable to read Palo Alto config file ${pathname} (EISDIR)`,
    },
    {
      label: "ENOENT",
      file: join(base, "missing.json"),
      canaries: [],
      libraryThrows: false,
      expected: (pathname) => `Unable to read Palo Alto config file ${pathname} (ENOENT)`,
    },
    ...(process.getuid?.() === 0 ? [] : [{
      label: "EACCES",
      file: (() => {
        const pathname = write("unreadable.json", JSON.stringify({ PANOS_HOST: "fw1.example.com", PANOS_API_KEY: LOADER_CANARIES.jsonMultiline }));
        chmodSync(pathname, 0o000);
        return pathname;
      })(),
      canaries: [LOADER_CANARIES.jsonMultiline],
      libraryThrows: false,
      expected: (pathname) => `Unable to read Palo Alto config file ${pathname} (EACCES)`,
    }]),
  ];
  assert.ok(readFileSync(cases[3].file, "utf8").length <= 20, "the short JSON fixture stays within the size JSON.parse quotes whole");

  for (const entry of cases) {
    if (entry.libraryThrows) {
      // Positive control: JSON.parse's own message quotes the file contents.
      assert.throws(() => JSON.parse(readFileSync(entry.file, "utf8")), (error) => {
        if (entry.libraryCarriesCanary) assert.ok(error.message.includes(entry.canaries[0]), `${entry.label}: positive control expected the whole canary: ${error.message}`);
        if (entry.libraryCarriesFragment) assert.ok(error.message.includes(entry.canaries[0].slice(0, 8)), `${entry.label}: positive control expected a canary fragment: ${error.message}`);
        return true;
      });
    }
    assert.throws(() => resolvePaloaltoConfiguration({ config_file: entry.file }, {}), (error) => {
      assert.equal(error.message, entry.expected(entry.file), `${entry.label}: resolver message`);
      assertNoLoaderLeak(error.message, entry.canaries, `${entry.label} resolver`);
      return true;
    });
    assert.throws(() => resolvePaloaltoConfiguration({}, { PALOALTO_CONFIG_FILE: entry.file }), (error) => {
      assert.equal(error.message, entry.expected(entry.file), `${entry.label}: PALOALTO_CONFIG_FILE is an explicit path too`);
      return true;
    });
    const toolText = await checkAccessText(entry.file);
    assertNoLoaderLeak(toolText, entry.canaries, `${entry.label} check_access`);
    assert.ok(toolText.includes(entry.expected(entry.file)), `${entry.label}: check_access carries the fixed loader text: ${toolText}`);
  }

  const shape = write("list.json", "[1, 2]");
  assert.throws(() => resolvePaloaltoConfiguration({ config_file: shape }, {}), new RegExp(`Unable to parse Palo Alto config file: .* must contain a JSON object \\(INVALID_CONFIG_SHAPE\\)`));
});

test("PrismaCloudClient logs in with the access key, paginates alerts, retries 429, and re-authenticates on 401", async () => {
  const seen = [];
  let logins = 0;
  let alertCalls = 0;
  let policyCalls = 0;
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(input);
    seen.push({ pathname: url.pathname, method: init.method ?? "GET", auth: new Headers(init.headers).get("x-redlock-auth"), body: init.body });
    if (url.pathname === "/login") {
      logins += 1;
      assert.deepEqual(JSON.parse(init.body), { username: "key-id", password: "secret-value" });
      return jsonResponse({ token: `jwt-${logins}` });
    }
    if (url.pathname === "/v2/alert") {
      alertCalls += 1;
      if (alertCalls === 1) return new Response("", { status: 429, headers: { "retry-after": "0" } });
      if (!url.searchParams.get("pageToken")) return jsonResponse({ items: [{ id: "a1" }], nextPageToken: "next" });
      return jsonResponse({ items: [{ id: "a2" }] });
    }
    if (url.pathname === "/v2/policy") {
      policyCalls += 1;
      if (policyCalls === 1) return jsonResponse([{ message: "token expired" }], { status: 401 });
      return jsonResponse([{ name: "policy" }]);
    }
    if (url.pathname === "/cloud") {
      return jsonResponse([{ message: "forbidden secret-value" }], { status: 403, headers: { "x-redlock-status": "[{\"i18nKey\":\"forbidden\"}]" } });
    }
    return jsonResponse({});
  };

  const client = new PrismaCloudClient({ apiUrl: "https://api2.prismacloud.io", accessKeyId: "key-id", secretKey: "secret-value" }, { fetchImpl, sleepImpl: noSleep });
  const alerts = await client.listOpenAlerts(10);
  assert.deepEqual(alerts.map((item) => item.id), ["a1", "a2"]);
  assert.equal(seen[0].pathname, "/login");
  assert.equal(seen[1].auth, "jwt-1");
  assert.ok(seen.some((item) => item.pathname === "/v2/alert" && item.auth === "jwt-1"));

  const policies = await client.listPolicies();
  assert.deepEqual(policies, [{ name: "policy" }]);
  assert.equal(logins, 2);

  await assert.rejects(() => client.listCloudAccounts(), (error) => {
    assert.match(error.message, /403/);
    assert.ok(!error.message.includes("secret-value"));
    return true;
  });
});

test("PanosApiClient generates an API key with keygen, sends X-PAN-KEY, parses XML, and surfaces API errors", async () => {
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(input);
    seen.push({ type: url.searchParams.get("type"), key: new Headers(init.headers).get("x-pan-key"), body: init.body, search: url.search });
    if (init.method === "POST") {
      const params = new URLSearchParams(init.body);
      assert.equal(params.get("type"), "keygen");
      assert.equal(params.get("user"), "auditor");
      assert.equal(params.get("password"), "hunter2");
      return xmlResponse(panosSuccess("<key>LUFRPT-generated</key>"));
    }
    if (url.searchParams.get("type") === "op") return xmlResponse(systemInfoXml());
    if (url.searchParams.get("xpath") === "/config/shared") return xmlResponse(panosSuccess(goodSharedXml()));
    if (url.searchParams.get("xpath") === "/config/mgt-config") {
      return xmlResponse('<response status="error" code="403"><result><msg>Insufficient privileges LUFRPT-generated</msg></result></response>', 403);
    }
    return xmlResponse(panosSuccess("<vsys/>"));
  };

  const client = new PanosApiClient({ host: "fw.example.com", baseUrl: "https://fw.example.com", username: "auditor", password: "hunter2" }, { fetchImpl, sleepImpl: noSleep });
  const info = await client.showSystemInfo();
  assert.equal(info.model, "PA-440");
  assert.equal(info["sw-version"], "11.1.2");
  assert.equal(seen[0].type, null);
  assert.equal(seen[1].key, "LUFRPT-generated");
  assert.ok(!seen[1].search.includes("key="));

  const shared = await client.showConfig("/config/shared");
  assert.equal(xmlText(xmlPath(shared, ["shared", "ssl-tls-service-profile", "entry", "protocol-settings", "min-version"])), "tls1-2");

  await assert.rejects(() => client.showConfig("/config/mgt-config"), (error) => {
    assert.match(error.message, /code 403/);
    assert.match(error.message, /Insufficient privileges/);
    assert.ok(!error.message.includes("LUFRPT-generated"));
    return true;
  });
});

test("parseXml handles attributes, nesting, CDATA, entities, and self-closing tags", () => {
  const doc = parseXml('<?xml version="1.0"?><!-- c --><response status="success"><result total-count="2"><entry name="a &amp; b"><v/><t><![CDATA[<raw>]]></t></entry><entry name="c">text&#65;</entry></result></response>');
  const response = doc.children[0];
  assert.equal(response.attributes.status, "success");
  const entries = xmlFindAll(response, "entry");
  assert.equal(entries.length, 2);
  assert.equal(entries[0].attributes.name, "a & b");
  assert.equal(xmlText(xmlPath(entries[0], ["t"])), "<raw>");
  assert.equal(xmlText(entries[1]), "textA");
  assert.equal(redactSecrets("https://fw/api/?type=op&key=LUFRPT123&cmd=x secret-value", ["secret-value"]), "https://fw/api/?type=op&key=[REDACTED]&cmd=x [REDACTED]");
  assert.equal(REDACTION_MARKER, "[REDACTED]");
});

test("collectPanosSnapshot detects Panorama and records per-xpath collection errors", async () => {
  const client = {
    host: "panorama.example.com",
    async showSystemInfo() {
      return { model: "Panorama", "sw-version": "11.1.0" };
    },
    async showHighAvailabilityState() {
      throw new Error("HA not licensed");
    },
    async showConfig(xpath) {
      if (xpath === "/config/panorama") throw new Error("denied");
      return parseXml(`<result><placeholder xpath="${xpath}"/></result>`);
    },
  };
  const snapshot = await collectPanosSnapshot(client);
  assert.equal(snapshot.platform, "panorama");
  assert.equal(snapshot.config.length, 6);
  assert.equal(snapshot.errors.length, 2);
  assert.match(snapshot.errors[0], /high-availability/);
  assert.match(snapshot.errors[1], /\/config\/panorama/);
});

const PANOS_FORBIDDEN = '<response status="error" code="403"><result><msg>Insufficient privileges</msg></result></response>';

function mockedFetch(options = {}) {
  const { denyAll = false, emptyAll = false, partial = false } = options;
  const compute = computeSnapshot();
  return async (input, init = {}) => {
    const url = new URL(input);
    if (url.hostname.endsWith("prismacloud.io")) {
      if (url.pathname === "/login") return jsonResponse({ token: "jwt" });
      if (denyAll) return jsonResponse({ message: "forbidden" }, { status: 403 });
      if (url.pathname === "/meta_info") return options.noCompute ? jsonResponse({}, { status: 404 }) : jsonResponse({ twistlockUrl: "https://compute.example.com" });
      if (emptyAll) {
        if (url.pathname === "/v2/compliance/posture") return jsonResponse({ summary: { passedResources: 0, failedResources: 0, totalResources: 0 }, complianceDetails: [] });
        if (url.pathname === "/v2/alert") return jsonResponse({ items: [] });
        return jsonResponse([]);
      }
      if (url.pathname === "/v2/compliance/posture") return partial ? jsonResponse({}, { status: 403 }) : jsonResponse(prismaSnapshot().posture);
      if (url.pathname === "/v2/alert/rule") return jsonResponse(prismaSnapshot().alertRules);
      if (url.pathname === "/v2/alert") {
        if (partial) return jsonResponse({ items: [{ policy: { name: "AWS S3 bucket public", policyType: "network", severity: "low" } }], nextPageToken: `next-${url.searchParams.get("pageToken") ?? "0"}`, totalRows: 5000 });
        return jsonResponse({ items: [] });
      }
      if (url.pathname === "/v2/policy") return jsonResponse(prismaSnapshot().policies);
      if (url.pathname === "/cloud") return partial ? jsonResponse({ message: "role cannot read accounts" }, { status: 403 }) : jsonResponse(prismaSnapshot().cloudAccounts);
      if (url.pathname === "/cloud/group") return jsonResponse(prismaSnapshot().accountGroups);
      if (url.pathname === "/user/role") return jsonResponse(prismaSnapshot().userRoles);
      if (url.pathname === "/integration" || url.pathname === "/api/v1/tenant/tenant-1/integration") {
        return options.integrationsDenied ? jsonResponse([], { status: 403 }) : jsonResponse(prismaSnapshot().integrations);
      }
      return jsonResponse({}, { status: 404 });
    }
    if (url.hostname === "compute.example.com") {
      if (url.pathname === "/api/v1/authenticate") return jsonResponse({ token: "compute-token" });
      if (denyAll || partial || options.computeDenied) return jsonResponse({ err: "forbidden" }, { status: 403 });
      const path = url.pathname.replace("/api/v1", "");
      if (emptyAll) return jsonResponse(path.startsWith("/policies") || path.startsWith("/settings") || path.startsWith("/stats") ? {} : []);
      if (path === "/defenders") return jsonResponse(compute.defenders);
      if (path === "/policies/runtime/container") return jsonResponse(compute.runtimeContainerPolicy);
      if (path === "/policies/compliance/container") return jsonResponse(compute.complianceContainerPolicy);
      if (path === "/policies/compliance/host") return jsonResponse(compute.complianceHostPolicy);
      if (path === "/policies/vulnerability/images") return jsonResponse(compute.vulnerabilityImagePolicy);
      if (path === "/settings/registry") return jsonResponse(compute.registrySettings);
      if (path === "/registry") return jsonResponse(compute.registryScans);
      if (path === "/images") return jsonResponse(compute.images);
      if (path === "/stats/vulnerabilities") return jsonResponse(compute.vulnerabilityStats);
      if (path === "/stats/compliance") return jsonResponse(compute.complianceStats);
      if (path === "/cloud/discovery") return jsonResponse(compute.cloudDiscovery);
      if (path === "/scans") return jsonResponse(compute.ciScans);
      return jsonResponse({}, { status: 404 });
    }
    if (partial && url.hostname === "fw2.example.com") throw new Error("connect ECONNREFUSED");
    const type = url.searchParams.get("type");
    if (denyAll) return xmlResponse(PANOS_FORBIDDEN, 403);
    if (type === "op") {
      if (url.searchParams.get("cmd").includes("high-availability")) return xmlResponse(emptyAll ? panosSuccess("") : haXml());
      return xmlResponse(emptyAll ? panosSuccess("<system><hostname>fw-empty</hostname></system>") : systemInfoXml());
    }
    const xpath = url.searchParams.get("xpath");
    if (emptyAll) return xmlResponse(panosSuccess(`<${xpath.split("/").at(-1)}/>`));
    if (xpath.endsWith("/vsys")) return xmlResponse(panosSuccess(goodVsysXml()));
    if (xpath.endsWith("/network")) return xmlResponse(panosSuccess(options.withSecrets ? secretsNetworkXml() : "<network/>"));
    if (xpath.endsWith("/deviceconfig")) return xmlResponse(panosSuccess(options.withSecrets ? secretsDeviceconfigXml() : goodDeviceconfigXml()));
    if (xpath.endsWith("/shared")) return xmlResponse(panosSuccess(options.withSecrets ? secretsSharedXml() : goodSharedXml()));
    if (xpath.endsWith("/mgt-config")) {
      if (options.mgtDenied) return xmlResponse(PANOS_FORBIDDEN, 403);
      return xmlResponse(panosSuccess(options.withSecrets ? secretsMgtConfigXml() : goodMgtConfigXml()));
    }
    return xmlResponse(panosSuccess("<empty/>"));
  };
}

function bothProductsConfig() {
  return resolvePaloaltoConfiguration({}, {
    PRISMA_API_URL: "https://api2.prismacloud.io",
    PRISMA_ACCESS_KEY_ID: "key",
    PRISMA_SECRET_KEY: "secret",
    PANOS_HOST: "fw1.example.com",
    PANOS_API_KEY: "LUFRPT-key",
  });
}

test("checkPaloaltoAccess reports healthy access across both products", async () => {
  const clients = createPaloaltoClients(bothProductsConfig(), mockedFetch());
  const result = await checkPaloaltoAccess(clients);
  assert.equal(result.status, "healthy");
  assert.deepEqual(result.products, ["prisma-cloud", "prisma-compute", "pan-os"]);
  assert.equal(result.surfaces.length, 8 + 8 + 2 + 5);
  assert.ok(result.notes.some((note) => note.includes("Compute console: https://compute.example.com")));
  assert.ok(result.surfaces.every((surface) => surface.status === "readable"));
  assert.match(result.recommendedNextStep, /paloalto_assess_cloud_posture/);
  assert.ok(result.notes.some((note) => /PA-440/.test(note)));
});

test("checkPaloaltoAccess reports degraded access and single-product configuration", async () => {
  const clients = createPaloaltoClients(bothProductsConfig(), mockedFetch({ integrationsDenied: true, mgtDenied: true }));
  const result = await checkPaloaltoAccess(clients);
  assert.equal(result.status, "degraded");
  const failed = result.surfaces.filter((surface) => surface.status === "not_readable");
  assert.deepEqual(failed.map((surface) => surface.name).sort(), ["integrations", "mgt-config"]);
  assert.match(failed.find((surface) => surface.name === "mgt-config").error, /Insufficient privileges/);

  const panosOnly = createPaloaltoClients(resolvePaloaltoConfiguration({}, { PANOS_HOST: "fw1.example.com", PANOS_API_KEY: "k" }), mockedFetch());
  const single = await checkPaloaltoAccess(panosOnly);
  assert.equal(single.status, "healthy");
  assert.deepEqual(single.products, ["pan-os"]);
  assert.ok(single.notes.some((note) => /Prisma Cloud not configured/.test(note)));
});

test("assessPrismaCloudPosture passes on a healthy tenant and fails on a weak one", () => {
  const good = assessPrismaCloudPosture(prismaSnapshot());
  assert.equal(good.length, 6);
  for (const item of good) assert.equal(item.status, "pass", `${item.id}: ${item.summary}`);
  assert.ok(byId(good, "PA-01").mappings.includes("FedRAMP CA-7"));
  assert.ok(byId(good, "PA-03").mappings.includes("ISMAP 6.1.1"));

  const bad = assessPrismaCloudPosture(prismaSnapshot({ good: false }));
  assert.equal(byId(bad, "PA-01").status, "fail");
  assert.equal(byId(bad, "PA-02").status, "fail");
  assert.equal(byId(bad, "PA-03").status, "fail");
  assert.equal(byId(bad, "PA-04").status, "fail");
  assert.equal(byId(bad, "PA-05").status, "fail");
  assert.equal(byId(bad, "PA-06").status, "fail");

  const missing = assessPrismaCloudPosture({ ...prismaSnapshot(), posture: undefined });
  assert.equal(byId(missing, "PA-01").status, "manual");
});

test("assessPrismaCompute evaluates controls 7-11, 24, and 25 from the Compute API and falls back to manual", () => {
  const good = assessPrismaCompute(prismaSnapshot());
  assert.deepEqual(good.map((item) => [item.control, item.status]), [[7, "pass"], [8, "pass"], [9, "pass"], [10, "pass"], [11, "pass"], [24, "pass"], [25, "warn"]]);
  assert.match(byId(good, "PA-25").summary, /Admission control policy has no verified public read endpoint/);

  const bad = assessPrismaCompute(prismaSnapshot({ good: false }));
  assert.deepEqual(bad.map((item) => [item.control, item.status]), [[7, "fail"], [8, "fail"], [9, "warn"], [10, "fail"], [11, "manual"], [24, "manual"], [25, "fail"]]);

  const unreachable = assessPrismaCompute(prismaSnapshot({ compute: undefined, computeUnavailableReason: "set PRISMA_COMPUTE_URL to the Compute console path." }));
  assert.ok(unreachable.every((item) => item.status === "manual"));
  assert.match(unreachable[0].summary, /PRISMA_COMPUTE_URL/);
  assert.ok(assessPrismaCompute(undefined).every((item) => item.status === "manual"));
});

test("assessPaloaltoCloudPosture automates Compute controls when the console is reachable and stays manual otherwise", async () => {
  const configured = await assessPaloaltoCloudPosture(createPaloaltoClients(bothProductsConfig(), mockedFetch()));
  assert.equal(configured.findings.length, 13);
  assert.equal(configured.summary.compute_configured, true);
  assert.deepEqual(configured.findings.filter((item) => item.status === "manual"), []);
  assert.equal(byId(configured.findings, "PA-10").status, "pass");

  const noCompute = await assessPaloaltoCloudPosture(createPaloaltoClients(bothProductsConfig(), mockedFetch({ noCompute: true })));
  assert.deepEqual(noCompute.findings.filter((item) => item.status === "manual").map((item) => item.control), [7, 8, 9, 10, 11, 24, 25]);
  assert.match(byId(noCompute.findings, "PA-10").summary, /PRISMA_COMPUTE_URL/);

  const override = createPaloaltoClients(resolvePaloaltoConfiguration({}, { PRISMA_ACCESS_KEY_ID: "k", PRISMA_SECRET_KEY: "s", PRISMA_COMPUTE_URL: "https://compute.example.com/" }), mockedFetch({ noCompute: true }));
  assert.equal(override.compute.baseUrl, "https://compute.example.com");
  const overridden = await assessPaloaltoCloudPosture(override);
  assert.equal(byId(overridden.findings, "PA-10").status, "pass");

  const panosOnly = createPaloaltoClients(resolvePaloaltoConfiguration({}, { PANOS_HOST: "fw1.example.com", PANOS_API_KEY: "k" }), mockedFetch());
  const unconfigured = await assessPaloaltoCloudPosture(panosOnly);
  assert.equal(unconfigured.findings.length, 13);
  assert.ok(unconfigured.findings.every((item) => item.status === "manual"));
  assert.match(byId(unconfigured.findings, "PA-01").summary, /Prisma Cloud credentials were not configured/);
});

test("assessPanosFirewallPolicy passes hardened rulebases and fails permissive ones", () => {
  const good = assessPanosFirewallPolicy([panosSnapshot()]);
  assert.deepEqual(good.map((item) => item.id), ["PA-12", "PA-13", "PA-14"]);
  for (const item of good) assert.equal(item.status, "pass", `${item.id}: ${item.summary}`);
  assert.ok(byId(good, "PA-12").mappings.includes("DISA STIG V-207184"));

  const bad = assessPanosFirewallPolicy([panosSnapshot({ good: false })]);
  assert.equal(byId(bad, "PA-12").status, "fail");
  assert.deepEqual(byId(bad, "PA-12").evidence.permissive_rules, ["fw1.example.com:security/allow-everything"]);
  assert.deepEqual(byId(bad, "PA-12").evidence.shadowed_rules, ["fw1.example.com:security/shadowed-web"]);
  assert.equal(byId(bad, "PA-13").status, "fail");
  assert.equal(byId(bad, "PA-14").status, "fail");

  const manual = assessPanosFirewallPolicy([]);
  assert.equal(byId(manual, "PA-12").status, "manual");
});

test("assessPanosThreatPrevention and DLP evaluate profiles and attachment", () => {
  const good = assessPanosThreatPrevention([panosSnapshot()]);
  assert.deepEqual(good.map((item) => item.id), ["PA-16", "PA-17", "PA-18", "PA-22"]);
  for (const item of good) assert.equal(item.status, "pass", `${item.id}: ${item.summary}`);

  const bad = assessPanosThreatPrevention([panosSnapshot({ good: false })]);
  assert.equal(byId(bad, "PA-16").status, "fail");
  assert.equal(byId(bad, "PA-17").status, "fail");
  assert.equal(byId(bad, "PA-18").status, "fail");
  assert.equal(byId(bad, "PA-22").status, "fail");

  assert.equal(assessDataLossPrevention(prismaSnapshot(), [panosSnapshot()]).status, "pass");
  assert.equal(assessDataLossPrevention(prismaSnapshot({ good: false }), [panosSnapshot({ good: false })]).status, "fail");
  assert.equal(assessDataLossPrevention(undefined, [panosSnapshot()]).status, "warn");
  assert.equal(assessDataLossPrevention(undefined, []).status, "manual");
});

test("assessPaloaltoThreatPrevention returns manual findings when PAN-OS is not configured", async () => {
  const prismaOnly = createPaloaltoClients(resolvePaloaltoConfiguration({}, { PRISMA_ACCESS_KEY_ID: "k", PRISMA_SECRET_KEY: "s", PRISMA_API_URL: "https://api2.prismacloud.io" }), mockedFetch());
  const result = await assessPaloaltoThreatPrevention(prismaOnly);
  assert.deepEqual(result.findings.map((item) => item.id), ["PA-16", "PA-17", "PA-18", "PA-21", "PA-22"]);
  assert.equal(byId(result.findings, "PA-16").status, "manual");
  assert.match(byId(result.findings, "PA-16").summary, /No PAN-OS firewall or Panorama host was configured/);
  assert.equal(byId(result.findings, "PA-21").status, "warn");
});

test("admin access, logging, and device hardening findings pass and fail on fixtures", () => {
  assert.equal(assessAdminAccess(prismaSnapshot(), [panosSnapshot()]).status, "pass");
  const badAdmins = assessAdminAccess(prismaSnapshot({ good: false }), [panosSnapshot({ good: false })], { maxSuperusers: 3 });
  assert.equal(badAdmins.status, "fail");
  assert.equal(badAdmins.evidence.panos_local_password_only.length, 4);
  assert.equal(assessAdminAccess(undefined, []).status, "manual");

  assert.equal(assessLogging(prismaSnapshot(), [panosSnapshot()]).status, "pass");
  assert.equal(assessLogging(prismaSnapshot({ good: false }), [panosSnapshot({ good: false })]).status, "fail");
  assert.equal(assessLogging(prismaSnapshot({ good: false }), []).status, "warn");

  const good = assessPanosDeviceHardening([panosSnapshot()]);
  assert.deepEqual(good.map((item) => item.id), ["PA-15", "PA-23", "PA-HA-01", "PA-SW-01"]);
  for (const item of good) assert.equal(item.status, "pass", `${item.id}: ${item.summary}`);

  const bad = assessPanosDeviceHardening([panosSnapshot({ good: false })]);
  assert.equal(byId(bad, "PA-15").status, "manual");
  assert.match(byId(bad, "PA-15").summary, /scoped out/);
  assert.equal(byId(bad, "PA-23").status, "fail");
  assert.equal(byId(bad, "PA-23").evidence.devices[0].default_snmp_community, true);
  assert.equal(byId(bad, "PA-HA-01").status, "warn");
  assert.equal(byId(bad, "PA-SW-01").status, "fail");
});

test("assessPaloaltoDeviceHardening covers controls 15, 19, 20, and 23 with live mocks and manual fallbacks", async () => {
  const both = await assessPaloaltoDeviceHardening(createPaloaltoClients(bothProductsConfig(), mockedFetch()));
  assert.deepEqual(both.findings.map((item) => item.id), ["PA-15", "PA-19", "PA-20", "PA-23", "PA-HA-01", "PA-SW-01"]);
  for (const item of both.findings) assert.equal(item.status, "pass", `${item.id}: ${item.summary}`);

  const prismaOnly = createPaloaltoClients(resolvePaloaltoConfiguration({}, { PRISMA_ACCESS_KEY_ID: "k", PRISMA_SECRET_KEY: "s" }), mockedFetch());
  const partial = await assessPaloaltoDeviceHardening(prismaOnly);
  assert.deepEqual(partial.findings.map((item) => [item.id, item.status]), [["PA-15", "manual"], ["PA-19", "warn"], ["PA-20", "warn"], ["PA-23", "manual"]]);
  assert.match(byId(partial.findings, "PA-19").summary, /PAN-OS not configured, so only the Prisma Cloud half/);
});

test("exportPaloaltoAuditBundle writes core_data, analysis, compliance reports, zip, and error log", async () => {
  const base = createTempBase("grclanker-paloalto-export-");
  const clients = createPaloaltoClients(bothProductsConfig(), mockedFetch({ mgtDenied: true }));
  const result = await exportPaloaltoAuditBundle(clients, base);

  assert.ok(existsSync(result.outputDir));
  assert.ok(existsSync(result.zipPath));
  assert.equal(result.findingCount, 13 + 3 + 5 + 6);
  assert.equal(result.errorCount, 1);
  for (const relativePath of [
    "QUICK_REFERENCE.md",
    "metadata.json",
    "_errors.log",
    "core_data/access.json",
    "core_data/prisma_cloud.json",
    "core_data/panos_fw1.example.com.json",
    "analysis/findings.json",
    "analysis/cloud_posture.json",
    "analysis/firewall_policy.json",
    "analysis/threat_prevention.json",
    "analysis/device_hardening.json",
    "compliance/executive_summary.md",
    "compliance/unified_compliance_matrix.md",
    "compliance/fedramp.md",
    "compliance/cmmc.md",
    "compliance/soc2.md",
    "compliance/cis.md",
    "compliance/pci-dss.md",
    "compliance/disa-stig.md",
    "compliance/irap.md",
    "compliance/ismap.md",
  ]) {
    assert.ok(existsSync(join(result.outputDir, relativePath)), `missing ${relativePath}`);
  }
  assert.match(readFileSync(join(result.outputDir, "_errors.log"), "utf8"), /mgt-config/);
  const findings = JSON.parse(readFileSync(join(result.outputDir, "analysis", "findings.json"), "utf8"));
  assert.equal(new Set(findings.map((item) => item.control)).size, 25);
  const bundleText = readFileSync(join(result.outputDir, "core_data", "prisma_cloud.json"), "utf8") + readFileSync(join(result.outputDir, "metadata.json"), "utf8");
  assert.ok(!bundleText.includes("LUFRPT-key"));
  assert.ok(!bundleText.includes("\"secret\""));
  assert.ok(result.fileCount >= 21);

  const clean = await exportPaloaltoAuditBundle(createPaloaltoClients(bothProductsConfig(), mockedFetch()), base);
  assert.equal(clean.errorCount, 0);
  assert.ok(!existsSync(join(clean.outputDir, "_errors.log")));
  assert.equal(basename(clean.zipPath), `${basename(clean.outputDir)}.zip`);
  assert.notEqual(clean.zipPath, result.zipPath);
  assert.ok(existsSync(result.zipPath) && existsSync(clean.zipPath));
});

test("redactXmlCredentials collapses credential-bearing PAN-OS nodes and leaves settings and the source tree intact", () => {
  const tree = parseXml(`<config>${secretsMgtConfigXml()}${secretsSharedXml()}${secretsNetworkXml()}${secretsDeviceconfigXml()}<placeholder><secret/></placeholder></config>`);
  const redacted = xmlToJson(redactXmlCredentials(tree));
  const text = JSON.stringify(redacted);
  for (const secret of Object.values(FAKE_PANOS_SECRETS)) {
    assert.ok(!text.includes(secret), `${secret} leaked into the redacted tree`);
  }

  const config = redacted.config;
  assert.equal(config["mgt-config"].users.entry[0].phash, "[REDACTED]");
  assert.equal(config["mgt-config"].users.entry[0]["@name"], "admin");
  assert.equal(config["mgt-config"].users.entry[0]["authentication-profile"], "mfa-radius");
  assert.equal(config["mgt-config"].users.entry[1]["public-key"], "c3NoLXJzYSBBQUFBQjNOemFDMXlj");
  assert.equal(config["mgt-config"]["password-complexity"].enabled, "yes");
  assert.equal(config.shared["server-profile"].radius.entry.server.entry.secret, "[REDACTED]");
  assert.equal(config.shared["server-profile"].radius.entry.server.entry.port, "1812");
  assert.equal(config.shared["server-profile"].ldap.entry["bind-password"], "[REDACTED]");
  assert.equal(config.shared["server-profile"].ldap.entry["bind-dn"], "cn=svc-panos,dc=example,dc=com");
  assert.equal(config.shared.certificate.entry["private-key"], "[REDACTED]");
  assert.match(config.shared.certificate.entry["public-key"], /BEGIN CERTIFICATE/);
  assert.equal(config.shared.integration["@api-key"], "[REDACTED]");
  assert.equal(config.shared.integration["@name"], "siem-connector");
  assert.equal(config.network.ike.gateway.entry.authentication["pre-shared-key"], "[REDACTED]", "the whole pre-shared-key subtree collapses");
  assert.equal(config.network.ike.gateway.entry["peer-address"].ip, "203.0.113.10");
  const snmpVersion = config.deviceconfig.system["snmp-setting"]["access-setting"].version;
  assert.equal(snmpVersion.v2c["snmp-community-string"], "[REDACTED]");
  assert.equal(snmpVersion.v3.users.entry.authpwd, "[REDACTED]");
  assert.equal(snmpVersion.v3.users.entry.privpwd, "[REDACTED]");
  assert.equal(config.placeholder.secret, "", "an empty credential node stays empty rather than claiming a redacted value");

  assert.equal(xmlText(xmlFindAll(tree, "snmp-community-string")[0]), FAKE_PANOS_SECRETS.communityString, "the source tree is not mutated");
  assert.equal(xmlText(xmlFindAll(tree, "phash")[0]), FAKE_PANOS_SECRETS.phash);
  assert.equal(xmlFindAll(tree, "pre-shared-key")[0].children.length, 1);

  for (const name of ["phash", "password", "bind-password", "secret", "shared-secret", "client-secret", "key", "pre-shared-key", "private-key", "master-key", "api-key", "passphrase", "private-key-passphrase", "authpwd", "privpwd", "snmp-community-string", "community", "token", "access-token", "hash", "Password", "api_key"]) {
    assert.equal(isCredentialXmlName(name), true, `${name} should be redacted`);
  }
  for (const name of ["public-key", "password-complexity", "password-profile", "password-change", "key-usage", "credential-enforcement", "api-key-lifetime", "hostname", "entry", "permissions", "enabled", "secret-key-length", "hashing"]) {
    assert.equal(isCredentialXmlName(name), false, `${name} should be kept`);
  }
});

test("exportPaloaltoAuditBundle never writes PAN-OS credentials into the bundle directory or its zip", async () => {
  const base = createTempBase("grclanker-paloalto-export-secrets-");
  const secrets = Object.values(FAKE_PANOS_SECRETS);
  const result = await exportPaloaltoAuditBundle(createPaloaltoClients(bothProductsConfig(), mockedFetch({ withSecrets: true })), base);
  assert.equal(result.errorCount, 0);

  const files = readBundleFiles(result.outputDir);
  assert.ok(files.has(join("core_data", "panos_fw1.example.com.json")));
  assertSecretsAbsent(assert, files, secrets, "bundle directory");
  const zipEntries = readZipEntries(result.zipPath);
  assert.equal(zipEntries.size, files.size, "the zip carries exactly the written files");
  assert.ok(zipEntries.has("core_data/panos_fw1.example.com.json"));
  assertSecretsAbsent(assert, zipEntries, secrets, "zip archive");

  const device = JSON.parse(files.get(join("core_data", "panos_fw1.example.com.json")));
  const mgtConfig = device.config.find((tree) => tree["mgt-config"])["mgt-config"];
  assert.equal(mgtConfig.users.entry[0].phash, "[REDACTED]");
  assert.equal(mgtConfig.users.entry[1]["public-key"], "c3NoLXJzYSBBQUFBQjNOemFDMXlj");
  assert.equal(mgtConfig["password-complexity"].enabled, "yes");
  const shared = device.config.find((tree) => tree.shared).shared;
  assert.equal(shared["server-profile"].radius.entry.server.entry.secret, "[REDACTED]");
  assert.equal(shared["server-profile"].ldap.entry["bind-password"], "[REDACTED]");
  assert.equal(shared.certificate.entry["private-key"], "[REDACTED]");
  assert.equal(shared.integration["@api-key"], "[REDACTED]");
  const network = device.config.find((tree) => tree.network).network;
  assert.equal(network.ike.gateway.entry.authentication["pre-shared-key"], "[REDACTED]");
  const deviceconfig = device.config.find((tree) => tree.deviceconfig).deviceconfig;
  assert.equal(deviceconfig.system["snmp-setting"]["access-setting"].version.v2c["snmp-community-string"], "[REDACTED]");
  assert.equal(JSON.stringify(device).split("[REDACTED]").length - 1, 9, "every fixture secret is replaced by one marker");

  const findings = JSON.parse(files.get(join("analysis", "findings.json")));
  const hardening = findings.find((item) => item.id === "PA-23");
  assert.equal(hardening.status, "pass", hardening.summary);
  assert.equal(hardening.evidence.devices[0].default_snmp_community, false, "the assessment still evaluated the raw community string in memory");
  assert.equal(findings.find((item) => item.id === "PA-19").status, "pass");
  assert.match(files.get("QUICK_REFERENCE.md"), /replaced with \[REDACTED\] before core_data\/ is written/);
});

test("resolveSecureOutputPath rejects traversal and symlink parents", () => {
  const base = createTempBase("grclanker-paloalto-path-");
  const outside = createTempBase("grclanker-paloalto-outside-");
  symlinkSync(outside, join(base, "linked"), "dir");

  assert.throws(() => resolveSecureOutputPath(base, "../escape"), /Refusing to write outside/);
  assert.throws(() => resolveSecureOutputPath(base, "linked/file.txt"), /symlinked parent directory/);
  assert.match(resolveSecureOutputPath(base, join("compliance", "safe.md")), /compliance\/safe\.md$/);
});

test("Palo Alto tools are registered in the catalog under the Palo Alto Networks group", () => {
  const tools = getRegisteredToolSummaries().filter((tool) => tool.name.startsWith("paloalto_"));
  assert.deepEqual(tools.map((tool) => tool.name).sort(), [
    "paloalto_assess_cloud_posture",
    "paloalto_assess_device_hardening",
    "paloalto_assess_firewall_policy",
    "paloalto_assess_threat_prevention",
    "paloalto_check_access",
    "paloalto_export_audit_bundle",
  ]);
  assert.ok(tools.every((tool) => tool.group === "Palo Alto Networks" && tool.kind === "domain"));
  assert.ok(tools.every((tool) => tool.parameterSummaries.some((parameter) => parameter.name === "panos_hosts")));
});

test("TLS opt-out is scoped to PAN-OS clients and never mutates NODE_TLS_REJECT_UNAUTHORIZED", async () => {
  const before = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  const clients = createPaloaltoClients(resolvePaloaltoConfiguration({}, {
    PRISMA_ACCESS_KEY_ID: "k",
    PRISMA_SECRET_KEY: "s",
    PANOS_HOST: "fw1.example.com",
    PANOS_API_KEY: "k",
    PANOS_VERIFY_TLS: "false",
  }));
  assert.equal(process.env.NODE_TLS_REJECT_UNAUTHORIZED, before);
  assert.equal(clients.config.verifyTls, false);
  assert.equal(clients.panos[0].tlsVerification, false);
  const strict = createPaloaltoClients(resolvePaloaltoConfiguration({}, { PANOS_HOST: "fw1.example.com", PANOS_API_KEY: "k" }));
  assert.equal(strict.panos[0].tlsVerification, true);
  assert.equal(process.env.NODE_TLS_REJECT_UNAUTHORIZED, before);

  const server = createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      response.writeHead(201, { "content-type": "application/json", "x-echo-method": request.method, "x-echo-auth": request.headers["x-pan-key"] ?? "" });
      response.end(JSON.stringify({ path: request.url, body }));
    });
  });
  await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  try {
    const insecureFetch = createInsecureFetch();
    const response = await insecureFetch(`http://127.0.0.1:${server.address().port}/api/?type=op`, { method: "POST", headers: { "X-PAN-KEY": "key" }, body: "cmd=1" });
    assert.equal(response.status, 201);
    assert.equal(response.headers.get("x-echo-method"), "POST");
    assert.equal(response.headers.get("x-echo-auth"), "key");
    assert.deepEqual(await response.json(), { path: "/api/?type=op", body: "cmd=1" });
  } finally {
    server.close();
  }
  assert.equal(process.env.NODE_TLS_REJECT_UNAUTHORIZED, before);
});

test("PrismaComputeClient authenticates with a Compute token, falls back to the CSPM JWT, and pages with offset", async () => {
  const seen = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(input);
    seen.push({ path: url.pathname, query: Object.fromEntries(url.searchParams), headers: Object.fromEntries(new Headers(init.headers ?? {})) });
    if (url.pathname === "/login") return jsonResponse({ token: "jwt" });
    if (url.pathname === "/api/v1/authenticate") return seen.filter((item) => item.path === "/api/v1/authenticate").length === 1 ? jsonResponse({ token: "compute-token" }) : jsonResponse({}, { status: 401 });
    if (url.pathname === "/api/v1/defenders") {
      const offset = Number(url.searchParams.get("offset"));
      return jsonResponse(offset === 0 ? Array.from({ length: 50 }, (_, index) => ({ hostname: `n${index}` })) : [{ hostname: "last" }]);
    }
    return jsonResponse({});
  };
  const cspm = new PrismaCloudClient({ apiUrl: "https://api2.prismacloud.io", accessKeyId: "key", secretKey: "secret" }, { fetchImpl });
  const compute = new PrismaComputeClient("https://compute.example.com/", cspm);
  const defenders = await compute.listDefenders();
  assert.equal(defenders.items.length, 51);
  assert.equal(defenders.truncated, false);
  const authenticate = seen.find((item) => item.path === "/api/v1/authenticate");
  assert.equal(authenticate.headers["content-type"], "application/json");
  assert.equal(seen.find((item) => item.path === "/api/v1/defenders").headers.authorization, "Bearer compute-token");
  assert.deepEqual(seen.filter((item) => item.path === "/api/v1/defenders").map((item) => item.query.offset), ["0", "50"]);

  const fallback = new PrismaComputeClient("https://compute.example.com", cspm);
  seen.length = 0;
  seen.push({ path: "/api/v1/authenticate" });
  await fallback.getRuntimeContainerPolicy();
  assert.equal(seen.at(-1).headers["x-redlock-auth"], "jwt");
});

test("rule 1: unreadable, forbidden, or errored evidence yields manual, never pass", async () => {
  const prisma = prismaSnapshot({ failed: ["alert rules"] });
  const cspm = assessPrismaCloudPosture(prisma);
  assert.equal(byId(cspm, "PA-02").status, "manual");
  assert.match(byId(cspm, "PA-02").summary, /Evidence unavailable/);
  assert.equal(byId(cspm, "PA-01").status, "pass");

  const compute = assessPrismaCompute(prismaSnapshot({ compute: computeSnapshot({ failed: ["defenders"] }) }));
  assert.equal(byId(compute, "PA-10").status, "manual");
  assert.equal(byId(compute, "PA-09").status, "manual");
  assert.equal(byId(compute, "PA-08").status, "manual");
  assert.equal(byId(compute, "PA-11").status, "pass");

  const failedVsys = assessPanosFirewallPolicy([panosSnapshot({ failedXpaths: ["/config/devices/entry/vsys"] })]);
  assert.ok(failedVsys.every((item) => item.status === "manual"), failedVsys.map((item) => `${item.id}:${item.status}`).join(","));
  const unreachable = assessPanosDeviceHardening([panosSnapshot({ reachable: false })]);
  assert.ok(unreachable.every((item) => item.status === "manual"));

  const snapshot = await collectPanosSnapshot({
    host: "fw1",
    showSystemInfo: async () => { throw new Error("PAN-OS API error 403: Insufficient privileges"); },
    showHighAvailabilityState: async () => { throw new Error("denied"); },
    showConfig: async () => { throw new Error("denied"); },
  });
  assert.equal(snapshot.reachable, false);
  assert.equal(snapshot.haStateFailed, true);
  assert.equal(snapshot.failedXpaths.length, 5);
});

test("rule 2: empty inventories are fail or manual per control intent and say which", () => {
  const emptyPrisma = assessPrismaCloudPosture({ ...prismaSnapshot(), posture: { summary: { totalResources: 0 } }, alertRules: [], alerts: [], policies: [], cloudAccounts: [] });
  assert.equal(byId(emptyPrisma, "PA-01").status, "manual");
  assert.match(byId(emptyPrisma, "PA-01").summary, /treated as manual/);
  assert.equal(byId(emptyPrisma, "PA-02").status, "fail");
  assert.match(byId(emptyPrisma, "PA-02").summary, /treated as fail/);
  assert.equal(byId(emptyPrisma, "PA-03").status, "manual");
  assert.equal(byId(emptyPrisma, "PA-04").status, "fail");
  assert.equal(byId(emptyPrisma, "PA-05").status, "manual");
  assert.equal(byId(emptyPrisma, "PA-06").status, "fail");

  const emptyCompute = assessPrismaCompute(prismaSnapshot({ compute: { ...computeSnapshot({ good: false }), defenders: [] } }));
  assert.equal(byId(emptyCompute, "PA-10").status, "fail");
  assert.match(byId(emptyCompute, "PA-10").summary, /Zero Defenders/);
  assert.equal(byId(emptyCompute, "PA-11").status, "manual");
  assert.equal(byId(emptyCompute, "PA-24").status, "manual");
  assert.equal(byId(emptyCompute, "PA-25").status, "fail");

  const emptyDevice = panosSnapshot({ good: false });
  emptyDevice.config = [parseXml("<vsys/>"), parseXml("<shared/>"), parseXml("<deviceconfig/>"), parseXml("<mgt-config/>")];
  const firewall = assessPanosFirewallPolicy([emptyDevice]);
  assert.equal(byId(firewall, "PA-12").status, "manual");
  assert.equal(byId(firewall, "PA-13").status, "manual");
  assert.equal(byId(firewall, "PA-14").status, "fail");
  const threat = assessPanosThreatPrevention([emptyDevice]);
  assert.ok(threat.every((item) => item.status === "fail"));
  assert.equal(assessAdminAccess(undefined, [emptyDevice]).status, "manual");
  assert.match(assessAdminAccess(undefined, [emptyDevice]).summary, /zero administrator accounts/);
  assert.equal(assessLogging(undefined, [emptyDevice]).status, "fail");
  assert.equal(byId(assessPanosDeviceHardening([emptyDevice]), "PA-23").status, "manual");
});

test("rule 3: scoped-out, disabled, or unlicensed controls are manual, never pass", () => {
  const noGp = panosSnapshot();
  noGp.config[0] = parseXml(goodVsysXml().replace(/<global-protect>[\s\S]*<\/global-protect>/, ""));
  const hardening = assessPanosDeviceHardening([noGp]);
  assert.equal(byId(hardening, "PA-15").status, "manual");
  assert.match(byId(hardening, "PA-15").summary, /scoped out/);

  const noIam = assessPrismaCloudPosture({ ...prismaSnapshot(), policies: prismaSnapshot().policies.filter((policy) => policy.policyType !== "iam") });
  assert.equal(byId(noIam, "PA-03").status, "manual");
  assert.match(byId(noIam, "PA-03").summary, /unlicensed/);

  const noCompute = assessPrismaCompute(prismaSnapshot({ compute: undefined, computeUnavailableReason: "Compute console discovery via CSPM /meta_info failed (404)" }));
  assert.ok(noCompute.every((item) => item.status === "manual"));
});

test("rule 4: items without dates are never counted fresh and cap the verdict at warn", () => {
  const compute = computeSnapshot();
  compute.defenders = [{ hostname: "node-1", connected: true, version: "34.00.100" }];
  compute.images = [{ id: "sha256:9", repoTag: { repo: "app" } }];
  compute.registryScans = [{ id: "sha256:8" }];
  const findings = assessPrismaCompute(prismaSnapshot({ compute }));
  assert.equal(byId(findings, "PA-10").status, "warn");
  assert.match(byId(findings, "PA-10").summary, /no lastModified timestamp/);
  assert.equal(byId(findings, "PA-07").status, "warn");
  assert.deepEqual(byId(findings, "PA-07").evidence.images_without_scan_time, ["sha256:9"]);
  assert.equal(byId(findings, "PA-11").status, "warn");

  const noVersion = panosSnapshot({ systemInfo: { model: "PA-440", "av-version": "4900-5400", "threat-version": "8800-8600" } });
  assert.equal(byId(assessPanosDeviceHardening([noVersion]), "PA-SW-01").status, "warn");
});

test("rule 5: partial inventories flag seen and total counts instead of passing", () => {
  const truncated = assessPrismaCloudPosture(prismaSnapshot({ alertsTruncated: true, alertsTotal: 5000 }));
  assert.equal(byId(truncated, "PA-02").status, "warn");
  assert.match(byId(truncated, "PA-02").summary, /truncated at 0 of 5000/);
  assert.equal(byId(truncated, "PA-05").status, "warn");
  assert.equal(byId(truncated, "PA-01").status, "pass");

  const twoDevices = assessPanosFirewallPolicy([panosSnapshot(), panosSnapshot({ host: "fw2.example.com", reachable: false })]);
  assert.ok(twoDevices.every((item) => item.status === "manual"));
  assert.match(byId(twoDevices, "PA-12").summary, /fw2.example.com unreachable/);

  const computeTruncated = assessPrismaCompute(prismaSnapshot({ compute: computeSnapshot({ truncated: ["defenders"] }) }));
  assert.equal(byId(computeTruncated, "PA-10").status, "warn");
  assert.match(byId(computeTruncated, "PA-10").summary, /truncated at 500 records/);
});

test("rule 6: absent or false enabling flags never support pass", () => {
  const implicit = prismaSnapshot();
  implicit.alertRules = [{ name: "no-flag", alertRuleNotificationConfig: [] }];
  implicit.cloudAccounts = [{ name: "prod", groups: [{ name: "Default" }], status: "ok" }];
  implicit.policies = implicit.policies.map((policy) => ({ ...policy, enabled: undefined }));
  const findings = assessPrismaCloudPosture(implicit);
  assert.equal(byId(findings, "PA-02").status, "fail");
  assert.equal(byId(findings, "PA-04").status, "fail");
  assert.equal(byId(findings, "PA-05").status, "manual");
  assert.equal(byId(findings, "PA-06").status, "fail");

  const implicitLog = panosSnapshot();
  implicitLog.config[0] = parseXml(goodVsysXml().replace(/<log-end>yes<\/log-end>/g, ""));
  const firewall = assessPanosFirewallPolicy([implicitLog]);
  assert.equal(byId(firewall, "PA-12").status, "warn");
  assert.match(byId(firewall, "PA-12").summary, /without an explicit log-end flag/);
  assert.equal(assessLogging(undefined, [implicitLog]).status, "warn");

  const haUnknown = panosSnapshot();
  haUnknown.haState = parseXml(panosSuccess("<group><local-info><state>active</state></local-info></group>")).children[0].children[0];
  assert.equal(byId(assessPanosDeviceHardening([haUnknown]), "PA-HA-01").status, "warn");

  const runtimeAlertOnly = computeSnapshot();
  runtimeAlertOnly.runtimeContainerPolicy = { rules: [{ name: "disabled-prevent", disabled: true, processes: { effect: "prevent" } }, { name: "alert", processes: { effect: "alert" } }] };
  assert.equal(byId(assessPrismaCompute(prismaSnapshot({ compute: runtimeAlertOnly })), "PA-09").status, "warn");
});

test("rule 7: alert pagination runs to completion or records truncation", async () => {
  const pages = [];
  const client = {
    getCompliancePosture: async () => prismaSnapshot().posture,
    listAlertRules: async () => prismaSnapshot().alertRules,
    collectOpenAlerts: async (limit) => {
      pages.push(limit);
      return { items: Array.from({ length: limit }, () => ({ policy: { name: "x", policyType: "config", severity: "low" } })), truncated: true, totalRows: 900 };
    },
    listPolicies: async () => prismaSnapshot().policies,
    listCloudAccounts: async () => prismaSnapshot().cloudAccounts,
    listAccountGroups: async () => prismaSnapshot().accountGroups,
    listUserRoles: async () => prismaSnapshot().userRoles,
    listIntegrations: async () => prismaSnapshot().integrations,
  };
  const snapshot = await collectPrismaSnapshot(client, 300);
  assert.equal(snapshot.alertsTruncated, true);
  assert.equal(snapshot.alertsTotal, 900);
  assert.deepEqual(pages, [300]);
  const findings = assessPrismaCloudPosture(snapshot);
  assert.equal(byId(findings, "PA-02").status, "warn");
  assert.match(byId(findings, "PA-02").summary, /truncated at 300 of 900/);

  const seen = [];
  const fetchImpl = async (input) => {
    const url = new URL(input);
    if (url.pathname === "/login") return jsonResponse({ token: "jwt" });
    seen.push(url.searchParams.get("pageToken"));
    return jsonResponse({ items: [{ id: seen.length }], nextPageToken: seen.length < 3 ? `t${seen.length}` : undefined, totalRows: 3 });
  };
  const complete = await new PrismaCloudClient({ apiUrl: "https://api2.prismacloud.io", accessKeyId: "k", secretKey: "s" }, { fetchImpl }).collectOpenAlerts(50);
  assert.equal(complete.truncated, false);
  assert.equal(complete.items.length, 3);
  assert.deepEqual(seen, [null, "t1", "t2"]);
});

test("rule 8: export reruns allocate a new directory and zip without overwriting", async () => {
  const base = createTempBase("grclanker-paloalto-rerun-");
  const first = await exportPaloaltoAuditBundle(createPaloaltoClients(bothProductsConfig(), mockedFetch()), base);
  const second = await exportPaloaltoAuditBundle(createPaloaltoClients(bothProductsConfig(), mockedFetch()), base);
  assert.notEqual(first.outputDir, second.outputDir);
  assert.notEqual(first.zipPath, second.zipPath);
  assert.equal(basename(first.zipPath), `${basename(first.outputDir)}.zip`);
  assert.equal(basename(second.zipPath), `${basename(second.outputDir)}.zip`);
  assert.ok(existsSync(first.zipPath) && existsSync(second.zipPath));
});

async function runAllAssessments(clients) {
  const results = [
    await assessPaloaltoCloudPosture(clients, { alertLimit: 2 }),
    await assessPaloaltoFirewallPolicy(clients),
    await assessPaloaltoThreatPrevention(clients),
    await assessPaloaltoDeviceHardening(clients),
  ];
  return results.flatMap((result) => result.findings);
}

function twoDeviceConfig(extra = {}) {
  return resolvePaloaltoConfiguration({}, {
    PRISMA_API_URL: "https://api2.prismacloud.io",
    PRISMA_ACCESS_KEY_ID: "key",
    PRISMA_SECRET_KEY: "secret",
    PANOS_HOST: "fw1.example.com,fw2.example.com",
    PANOS_API_KEY: "LUFRPT-key",
    ...extra,
  });
}

test("false-pass self-check (a): every endpoint forbidden or erroring yields no pass", async () => {
  const findings = await runAllAssessments(createPaloaltoClients(bothProductsConfig(), mockedFetch({ denyAll: true })));
  assert.equal(new Set(findings.map((item) => item.control)).size, 25);
  assert.deepEqual(findings.filter((item) => item.status === "pass"), []);
  assert.ok(findings.filter((item) => /^PA-\d\d$/.test(item.id)).every((item) => item.status === "manual"), findings.map((item) => `${item.id}:${item.status}`).join(","));
  assert.ok(findings.every((item) => item.status !== "manual" || /Manual evidence required/.test(item.summary)));
});

test("false-pass self-check (b): empty inventories only pass where emptiness is compliant", async () => {
  const findings = await runAllAssessments(createPaloaltoClients(bothProductsConfig(), mockedFetch({ emptyAll: true })));
  assert.equal(new Set(findings.map((item) => item.control)).size, 25);
  const passes = findings.filter((item) => item.status === "pass").map((item) => item.id);
  assert.deepEqual(passes, [], `unexpected passes: ${passes.join(",")}`);
  const expected = {
    "PA-01": "manual", "PA-02": "fail", "PA-03": "manual", "PA-04": "fail", "PA-05": "manual", "PA-06": "fail",
    "PA-07": "fail", "PA-08": "fail", "PA-09": "fail", "PA-10": "fail", "PA-11": "manual", "PA-24": "manual", "PA-25": "fail",
    "PA-12": "manual", "PA-13": "manual", "PA-14": "fail", "PA-15": "manual", "PA-16": "fail", "PA-17": "fail", "PA-18": "fail",
    "PA-19": "manual", "PA-20": "fail", "PA-21": "fail", "PA-22": "fail", "PA-23": "manual",
  };
  for (const [id, status] of Object.entries(expected)) assert.equal(byId(findings, id).status, status, `${id}: ${byId(findings, id).summary}`);
  for (const item of findings.filter((entry) => ["fail", "manual"].includes(entry.status) && /^PA-\d\d$/.test(entry.id) && !["PA-14", "PA-16", "PA-17", "PA-18", "PA-20", "PA-21", "PA-22", "PA-08", "PA-09", "PA-15", "PA-19", "PA-23"].includes(entry.id))) {
    assert.match(item.summary, /treated as (fail|manual)|Zero|zero/i, `${item.id}: ${item.summary}`);
  }
});

test("false-pass self-check (c): partial inventories never pass", async () => {
  const findings = await runAllAssessments(createPaloaltoClients(twoDeviceConfig(), mockedFetch({ partial: true })));
  assert.equal(new Set(findings.map((item) => item.control)).size, 25);
  assert.deepEqual(findings.filter((item) => item.status === "pass").map((item) => item.id), []);
  assert.equal(byId(findings, "PA-02").status, "warn");
  assert.match(byId(findings, "PA-02").summary, /truncated at 2 of 5000/);
  assert.equal(byId(findings, "PA-04").status, "manual");
  assert.equal(byId(findings, "PA-10").status, "manual");
  assert.equal(byId(findings, "PA-12").status, "manual");
  assert.match(byId(findings, "PA-12").summary, /fw2.example.com unreachable/);
});

test("review fix 1: PA-07 parses the documented /stats/vulnerabilities array and fails above the CVE threshold", () => {
  const above = assessPrismaCompute(prismaSnapshot({ compute: computeSnapshot({}) }));
  assert.equal(byId(above, "PA-07").status, "pass");
  assert.equal(byId(above, "PA-07").evidence.critical_cves, 0);
  assert.equal(byId(above, "PA-07").evidence.high_cves, 3);
  assert.equal(byId(above, "PA-07").evidence.cve_stats_by_resource.images.count, 40);
  assert.match(byId(above, "PA-07").summary, /0 critical and 3 high CVEs/);

  const hot = computeSnapshot({});
  hot.vulnerabilityStats = documentedVulnerabilityStats({ critical: 4, high: 9 });
  const failing = byId(assessPrismaCompute(prismaSnapshot({ compute: hot })), "PA-07");
  assert.equal(failing.status, "fail");
  assert.equal(failing.evidence.critical_cves, 4);
  assert.match(failing.summary, /4 critical CVEs remain/);

  const imageOnly = computeSnapshot({});
  imageOnly.vulnerabilityStats = [];
  imageOnly.images = [{ id: "sha256:9", scanTime: "2026-09-01T00:00:00Z", vulnerabilityDistribution: { critical: 2, high: 1, medium: 0, low: 0, total: 3 } }];
  const fromImages = byId(assessPrismaCompute(prismaSnapshot({ compute: imageOnly })), "PA-07");
  assert.equal(fromImages.status, "fail");
  assert.equal(fromImages.evidence.cve_stats_source, "image vulnerabilityDistribution");

  const stricter = computeSnapshot({});
  stricter.images = [{ id: "sha256:9", scanTime: "2026-09-01T00:00:00Z", vulnerabilityDistribution: { critical: 1, high: 0, medium: 0, low: 0, total: 1 } }];
  assert.equal(byId(assessPrismaCompute(prismaSnapshot({ compute: stricter })), "PA-07").status, "fail");

  const legacyObject = computeSnapshot({});
  legacyObject.vulnerabilityStats = [];
  legacyObject.images = [{ id: "sha256:9", scanTime: "2026-09-01T00:00:00Z" }];
  const unknown = byId(assessPrismaCompute(prismaSnapshot({ compute: legacyObject })), "PA-07");
  assert.equal(unknown.status, "warn");
  assert.equal(unknown.evidence.critical_cves, null);
});

test("review fix 2: PA-08 derives the compliance rate from documented rules[] or categories[] failed versus total", () => {
  const healthy = byId(assessPrismaCompute(prismaSnapshot()), "PA-08");
  assert.equal(healthy.status, "pass");
  assert.equal(healthy.evidence.compliance_rate, 97);
  assert.equal(healthy.evidence.compliance_source, "rules[] failed versus total");
  assert.match(healthy.summary, /3 failed of 100 compliance evaluations/);

  const below = computeSnapshot({});
  below.complianceStats = documentedComplianceStats({ failed: 15, total: 100 });
  const failing = byId(assessPrismaCompute(prismaSnapshot({ compute: below })), "PA-08");
  assert.equal(failing.status, "fail");
  assert.equal(failing.evidence.compliance_rate, 85);

  const categoriesOnly = computeSnapshot({});
  categoriesOnly.complianceStats = { categories: [{ name: "CIS", failed: 2, total: 50 }, { name: "PCI", failed: 0, total: 50 }], rules: [], daily: [], ids: [], templates: [] };
  const fromCategories = byId(assessPrismaCompute(prismaSnapshot({ compute: categoriesOnly })), "PA-08");
  assert.equal(fromCategories.status, "pass");
  assert.equal(fromCategories.evidence.compliance_rate, 98);
  assert.equal(fromCategories.evidence.compliance_source, "categories[] failed versus total");

  const legacy = computeSnapshot({});
  legacy.complianceStats = { complianceRate: 99 };
  const noEvaluations = byId(assessPrismaCompute(prismaSnapshot({ compute: legacy })), "PA-08");
  assert.equal(noEvaluations.status, "warn");
  assert.equal(noEvaluations.evidence.compliance_rate, null);
  assert.match(noEvaluations.summary, /zero evaluations/);
});

test("review fix 3: PA-08 and PA-09 gate on the Defender population and never pass when defenders are unreadable or absent", () => {
  const defendersForbidden = assessPrismaCompute(prismaSnapshot({ compute: computeSnapshot({ failed: ["defenders"], errors: ["GET /api/v1/defenders returned 403"] }) }));
  assert.equal(byId(defendersForbidden, "PA-09").status, "manual");
  assert.match(byId(defendersForbidden, "PA-09").summary, /defenders/);
  assert.equal(byId(defendersForbidden, "PA-08").status, "manual");
  assert.equal(byId(defendersForbidden, "PA-10").status, "manual");

  const noDefenders = computeSnapshot({});
  noDefenders.defenders = [];
  const none = assessPrismaCompute(prismaSnapshot({ compute: noDefenders }));
  assert.equal(byId(none, "PA-09").status, "fail");
  assert.match(byId(none, "PA-09").summary, /no Defender reports connected=true/);
  assert.equal(byId(none, "PA-08").status, "fail");
  assert.match(byId(none, "PA-08").summary, /no Defender reports connected=true/);

  const disconnected = computeSnapshot({});
  disconnected.defenders = [{ hostname: "node-3", connected: false, version: "34.00.100" }];
  const offline = assessPrismaCompute(prismaSnapshot({ compute: disconnected }));
  assert.equal(byId(offline, "PA-09").status, "fail");
  assert.equal(byId(offline, "PA-09").evidence.connected_defenders, 0);
});

test("review fix 4: integrations are read from the tenant-scoped microservice path when login returns a prismaId", async () => {
  const calls = [];
  const client = new PrismaCloudClient(
    { apiUrl: "https://api2.prismacloud.io", accessKeyId: "key", secretKey: "secret" },
    {
      fetchImpl: async (input) => {
        const url = new URL(input);
        calls.push(url.pathname);
        if (url.pathname === "/login") return jsonResponse({ token: "jwt", customerNames: [{ customerName: "acme", prismaId: "tenant-1", tosAccepted: true }] });
        if (url.pathname === "/api/v1/tenant/tenant-1/integration") return jsonResponse([{ name: "siem", integrationType: "splunk", enabled: true }]);
        return jsonResponse({ message: "unexpected path" }, { status: 404 });
      },
      sleep: noSleep,
    },
  );
  const integrations = await client.listIntegrations();
  assert.equal(client.tenantPrismaId, "tenant-1");
  assert.deepEqual(integrations.map((item) => item.integrationType), ["splunk"]);
  assert.ok(calls.includes("/api/v1/tenant/tenant-1/integration"));
  assert.ok(!calls.includes("/integration"));

  const fallback = new PrismaCloudClient(
    { apiUrl: "https://api2.prismacloud.io", accessKeyId: "key", secretKey: "secret" },
    {
      fetchImpl: async (input) => {
        const url = new URL(input);
        if (url.pathname === "/login") return jsonResponse({ token: "jwt" });
        if (url.pathname === "/integration") return jsonResponse([{ name: "okta", integrationType: "okta" }]);
        return jsonResponse({}, { status: 404 });
      },
      sleep: noSleep,
    },
  );
  assert.deepEqual((await fallback.listIntegrations()).map((item) => item.name), ["okta"]);
  assert.equal(fallback.tenantPrismaId, undefined);
});

test("review fix 5: PA-SW-01 maps to control 23 and the unified matrix has exactly one row per numbered control", async () => {
  const hardening = assessPanosDeviceHardening([panosSnapshot()]);
  const software = byId(hardening, "PA-SW-01");
  assert.equal(software.control, 23);
  assert.ok(software.mappings.some((mapping) => mapping.startsWith("FedRAMP ") && /CM-6/.test(mapping)));
  assert.ok(!software.mappings.some((mapping) => /RA-5|SI-2/.test(mapping)));
  assert.equal(byId(hardening, "PA-HA-01").control, 23);

  const all = [
    ...(await assessPaloaltoCloudPosture(createPaloaltoClients(bothProductsConfig(), mockedFetch()))).findings,
    ...(await assessPaloaltoFirewallPolicy(createPaloaltoClients(bothProductsConfig(), mockedFetch()))).findings,
    ...(await assessPaloaltoThreatPrevention(createPaloaltoClients(bothProductsConfig(), mockedFetch()))).findings,
    ...(await assessPaloaltoDeviceHardening(createPaloaltoClients(bothProductsConfig(), mockedFetch()))).findings,
  ];
  const primary = all.filter(isPrimaryFinding);
  assert.equal(primary.length, 25);
  assert.deepEqual([...new Set(primary.map((item) => item.control))].sort((a, b) => a - b), Array.from({ length: 25 }, (_, index) => index + 1));

  const matrix = buildComplianceMatrix(all);
  const [primarySection, supplementarySection] = matrix.split("## Supplementary findings");
  const controlColumn = (section) => section
    .split("\n")
    .filter((line) => /^\| PA-/.test(line))
    .map((line) => line.split("|").map((cell) => cell.trim()));
  const primaryRows = controlColumn(primarySection);
  assert.equal(primaryRows.length, 25);
  const controls = primaryRows.map((cells) => Number(cells[2]));
  assert.deepEqual(controls, Array.from({ length: 25 }, (_, index) => index + 1));
  assert.equal(new Set(controls).size, 25);
  assert.equal(controls.filter((control) => control === 7).length, 1);
  const supplementaryRows = controlColumn(supplementarySection);
  assert.deepEqual(supplementaryRows.map((cells) => cells[1]).sort(), ["PA-HA-01", "PA-SW-01"]);
  assert.ok(supplementaryRows.every((cells) => cells[2] === "23"));
});
