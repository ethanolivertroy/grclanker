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
  isCredentialKey,
  isCredentialPropertyName,
  isCredentialXmlName,
  isPrimaryFinding,
  parseXml,
  redactConfiguredSecrets,
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

// The configured Prisma Cloud secret key of every fixture. It is a configured secret, so
// the throw sites, the tool boundary, and the bundle writer remove it wherever it appears
// (guard 2). It is deliberately name-shaped: bare in prose nothing but guard 2 removes it,
// so its absence proves the configured-secret pass ran. Its words appear nowhere in the
// module's own vocabulary (source_chain renders "environment-prisma-secret-key", so
// "secret" and "key" are out), and it must not collide with a JSON property name such as
// "secret", which a whole-token match on a short word would erase from the written files.
const FIXTURE_SECRET_KEY = "fixture-ochre-lantern-2026";
// The PAN-OS keygen password of the sweep fixtures: every character class an encoding
// changes, so its JSON-escaped, URL-encoded, base64, and base64url forms all differ.
const FIXTURE_PANOS_PASSWORD = 'p@ss"w/rd+2026';

// The forms a configured secret can be echoed in: as is, JSON-escaped, URL-encoded, base64, base64url.
function secretForms(value) {
  return [...new Set([value, JSON.stringify(value).slice(1, -1), encodeURIComponent(value), Buffer.from(value).toString("base64"), Buffer.from(value).toString("base64url")])];
}

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

test("round 7(b): environment credentials survive an argument overlay that carries unrelated or undefined keys, and the source chain names the environment", () => {
  const configFile = join(createTempBase("grclanker-paloalto-env-overlay-"), "paloalto.json");
  writeFileSync(configFile, JSON.stringify({ PRISMA_SECRET_KEY: "fileQ7wR2tY8uI3oP5aS", PANOS_API_KEY: "fileL4kJ9hG2fD6sA8zX" }));
  const env = {
    PALOALTO_CONFIG_FILE: configFile,
    PRISMA_ACCESS_KEY_ID: "envK3mN8bV5cX2zL7qW4",
    PRISMA_SECRET_KEY: "envS9dF2gH6jK4lZ8xC1",
    PANOS_HOST: "fw1.example.com",
    PANOS_API_KEY: "envP5rT8yU2iO7pA3sD6",
  };
  // The overlay a tool builds from optional arguments: one unrelated argument plus the
  // credential keys present but undefined, as a spread of an unfilled schema produces.
  const overlay = { timeout_seconds: 45, prisma_access_key_id: undefined, prisma_secret_key: undefined, panos_api_key: undefined, panos_hosts: undefined, config_file: undefined };
  const config = resolvePaloaltoConfiguration(overlay, env);
  assert.equal(config.prisma.accessKeyId, env.PRISMA_ACCESS_KEY_ID);
  assert.equal(config.prisma.secretKey, env.PRISMA_SECRET_KEY, "the environment value beats the config file and is not erased by the undefined argument");
  assert.equal(config.panos[0].apiKey, env.PANOS_API_KEY);
  assert.equal(config.timeoutMs, 45_000, "the unrelated argument still applies");
  for (const source of ["environment-prisma-access-key", "environment-prisma-secret-key", "environment-panos-host", "environment-panos-api-key"]) {
    assert.ok(config.sourceChain.includes(source), `${source} in ${config.sourceChain.join(", ")}`);
  }
  assert.ok(!config.sourceChain.some((source) => source.startsWith("arguments-")), config.sourceChain.join(", "));
  assert.ok(!config.sourceChain.some((source) => source.startsWith("config-file-")), config.sourceChain.join(", "));
  // With nothing in the environment the same overlay falls through to the file.
  const fromFile = resolvePaloaltoConfiguration(overlay, { PALOALTO_CONFIG_FILE: configFile, PRISMA_ACCESS_KEY_ID: env.PRISMA_ACCESS_KEY_ID, PANOS_HOST: "fw1.example.com" });
  assert.equal(fromFile.prisma.secretKey, "fileQ7wR2tY8uI3oP5aS");
  assert.ok(fromFile.sourceChain.includes("config-file-prisma-secret-key"));
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

// Fake credential values Prisma Cloud CSPM and Compute payloads carry verbatim in real
// tenants (integrationConfig, registry credentials, image secrets, Defender proxies);
// none may reach an assessment payload, the bundle, or the zip.
const FAKE_PRISMA_SECRETS = {
  splunkAuthToken: "splunk-hec-auth-token-fake-0123",
  webhookQueryToken: "webhook-query-token-fake-4567",
  webhookHeaderBearer: "webhook-header-bearer-fake-89ab",
  slackWebhookPath: "T0FAKE/B0FAKE/slackwebhooksecretfake",
  serviceNowPassword: "servicenow-password-fake-cdef",
  tenableSecretKey: "tenable-secret-key-fake-0246",
  registryPlainSecret: "registry-pull-secret-plain-fake",
  registryBasicPassword: "registry-basic-password-fake",
  imageSecret: "AKIAFAKEIMAGESECRET0123456789",
  discoveryCredential: "cloud-discovery-credential-fake",
  defenderProxyPassword: "defender-proxy-password-fake",
};

function secretsIntegrations() {
  return [
    { name: "splunk", integrationType: "splunk", enabled: true, integrationConfig: { url: "https://splunk.example.com:8088/services/collector", authToken: FAKE_PRISMA_SECRETS.splunkAuthToken, sourceType: "prisma" } },
    {
      name: "soar-webhook",
      integrationType: "webhook",
      enabled: true,
      integrationConfig: {
        url: `https://soar.example.com/prisma?token=${FAKE_PRISMA_SECRETS.webhookQueryToken}&env=prod`,
        headers: [
          { key: "Authorization", value: `Bearer ${FAKE_PRISMA_SECRETS.webhookHeaderBearer}`, secure: true },
          { key: "Content-Type", value: "application/json", secure: false },
        ],
      },
    },
    { name: "slack", integrationType: "slack", enabled: true, integrationConfig: { webhookUrl: `https://hooks.slack.com/services/${FAKE_PRISMA_SECRETS.slackWebhookPath}` } },
    { name: "servicenow", integrationType: "service_now", enabled: true, integrationConfig: { hostUrl: "acme.service-now.com", login: "prisma-svc", password: FAKE_PRISMA_SECRETS.serviceNowPassword, tables: { incident: true } } },
    { name: "tenable", integrationType: "tenable", enabled: true, integrationConfig: { accessKey: "tenable-access-key-id", secretKey: FAKE_PRISMA_SECRETS.tenableSecretKey } },
  ];
}

function secretsRegistrySettings() {
  return {
    specifications: [
      { registry: "registry.example.com", repository: "*", cap: 5, scanners: 2, credentialID: "reg-cred-1", credential: { _id: "reg-cred-1", type: "basic", secret: { encrypted: "", plain: FAKE_PRISMA_SECRETS.registryPlainSecret } } },
      { registry: "ghcr.io", repository: "acme/*", cap: 5, scanners: 1, credentialID: "reg-cred-2", credential: { _id: "reg-cred-2", type: "basic", accountID: "acme-bot", secret: { plain: FAKE_PRISMA_SECRETS.registryBasicPassword } } },
    ],
  };
}

function secretsComputeSnapshot() {
  const snapshot = computeSnapshot();
  snapshot.defenders = [{ ...snapshot.defenders[0], proxy: { httpProxy: "http://proxy.example.com:3128", user: "defender", password: { encrypted: "", plain: FAKE_PRISMA_SECRETS.defenderProxyPassword } } }];
  snapshot.registrySettings = secretsRegistrySettings();
  snapshot.images = [{ ...snapshot.images[0], secrets: [FAKE_PRISMA_SECRETS.imageSecret], labels: { maintainer: "platform" } }];
  snapshot.cloudDiscovery = [{ ...snapshot.cloudDiscovery[0], credentialID: "aws-cred-1", credential: { _id: "aws-cred-1", type: "aws", secret: { plain: FAKE_PRISMA_SECRETS.discoveryCredential } } }];
  return snapshot;
}

function mockedFetch(options = {}) {
  const { denyAll = false, emptyAll = false, partial = false } = options;
  const compute = options.withSecrets ? secretsComputeSnapshot() : computeSnapshot();
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
        if (options.alertsDenied) return new Response("<html><body>502 Bad Gateway</body></html>", { status: 502, headers: { "content-type": "text/html" } });
        if (partial) return jsonResponse({ items: [{ policy: { name: "AWS S3 bucket public", policyType: "network", severity: "low" } }], nextPageToken: `next-${url.searchParams.get("pageToken") ?? "0"}`, totalRows: 5000 });
        return jsonResponse({ items: [] });
      }
      if (url.pathname === "/v2/policy") return jsonResponse(prismaSnapshot().policies);
      if (url.pathname === "/cloud") return partial ? jsonResponse({ message: "role cannot read accounts" }, { status: 403 }) : jsonResponse(prismaSnapshot().cloudAccounts);
      if (url.pathname === "/cloud/group") return jsonResponse(prismaSnapshot().accountGroups);
      if (url.pathname === "/user/role") return jsonResponse(prismaSnapshot().userRoles);
      if (url.pathname === "/integration" || url.pathname === "/api/v1/tenant/tenant-1/integration") {
        if (options.integrationsDenied) return jsonResponse([], { status: 403 });
        return jsonResponse(options.withSecrets ? secretsIntegrations() : prismaSnapshot().integrations);
      }
      return jsonResponse({}, { status: 404 });
    }
    if (url.hostname === "compute.example.com") {
      if (url.pathname === "/api/v1/authenticate") return jsonResponse({ token: "compute-token" });
      if (denyAll || partial || options.computeDenied) return jsonResponse({ err: "forbidden" }, { status: 403 });
      const path = url.pathname.replace("/api/v1", "");
      // The documented empty answers: a policy with no rules, no registry specifications,
      // no compliance evaluations, and null for an empty collection (Compute serves null).
      if (emptyAll) {
        if (path.startsWith("/policies")) return jsonResponse({ rules: [] });
        if (path === "/settings/registry") return jsonResponse({ specifications: [] });
        if (path === "/stats/compliance") return jsonResponse({ rules: [], categories: [] });
        return jsonResponse(path === "/stats/vulnerabilities" ? [] : null);
      }
      if (path === "/defenders") return jsonResponse(compute.defenders);
      if (path === "/policies/runtime/container") return jsonResponse(compute.runtimeContainerPolicy);
      if (path === "/policies/compliance/container") return jsonResponse(compute.complianceContainerPolicy);
      if (path === "/policies/compliance/host") return jsonResponse(compute.complianceHostPolicy);
      if (path === "/policies/vulnerability/images") return jsonResponse(compute.vulnerabilityImagePolicy);
      if (path === "/settings/registry") return options.registryDenied ? jsonResponse({ err: "registry settings require the Administrator role" }, { status: 403 }) : jsonResponse(compute.registrySettings);
      if (path === "/registry") return jsonResponse(compute.registryScans);
      if (path === "/images") return jsonResponse(compute.images);
      if (path === "/stats/vulnerabilities") return jsonResponse(compute.vulnerabilityStats);
      if (path === "/stats/compliance") return jsonResponse(compute.complianceStats);
      if (path === "/cloud/discovery") return jsonResponse(compute.cloudDiscovery);
      if (path === "/scans") return jsonResponse(compute.ciScans);
      return jsonResponse({}, { status: 404 });
    }
    if (partial && url.hostname === "fw2.example.com") throw new Error("connect ECONNREFUSED");
    if (init.method === "POST") return xmlResponse(panosSuccess("<key>LUFRPT-generated-fake</key>"));
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
    PRISMA_SECRET_KEY: FIXTURE_SECRET_KEY,
    PANOS_HOST: "fw1.example.com",
    PANOS_API_KEY: "LUFRPT-key",
  });
}

test("checkPaloaltoAccess reports healthy access across both products", async () => {
  const clients = createPaloaltoClients(bothProductsConfig(), mockedFetch());
  const result = await checkPaloaltoAccess(clients);
  assert.equal(result.status, "healthy");
  assert.deepEqual(result.products, ["prisma-cloud", "prisma-compute", "pan-os"]);
  assert.equal(result.surfaces.length, 8 + 9 + 2 + 5);
  assert.ok(result.notes.some((note) => note.includes("Compute console: https://compute.example.com")));
  assert.ok(result.surfaces.every((surface) => surface.status === "readable"));
  // A readable probe reports what it read and no HTTP failure status; every probe names one documented request.
  assert.ok(result.surfaces.every((surface) => typeof surface.count === "number" && surface.httpStatus === null && surface.partial === undefined), JSON.stringify(result.surfaces));
  assert.ok(result.surfaces.every((surface) => /^(GET|POST) \//.test(surface.endpoint)), result.surfaces.map((surface) => surface.endpoint).join("\n"));
  assert.equal(result.surfaces.find((surface) => surface.name === "system_info").endpoint, "GET /api/?type=op&cmd=<show><system><info></info></system></show>");
  assert.equal(result.surfaces.find((surface) => surface.name === "mgt-config").endpoint, "GET /api/?type=config&action=show&xpath=/config/mgt-config");
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
  // A failed probe read nothing (null, never 0 or false) and carries the status it observed.
  for (const surface of failed) {
    assert.equal(surface.count, null, surface.name);
    assert.equal(surface.partial, null, surface.name);
    assert.equal(surface.httpStatus, 403, surface.name);
  }
  assert.equal(failed.find((surface) => surface.name === "mgt-config").endpoint, "GET /api/?type=config&action=show&xpath=/config/mgt-config");

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
  // config is keyed by the xpath each subtree was read from.
  assert.deepEqual(Object.keys(device.config), ["/config/devices/entry/vsys", "/config/devices/entry/network", "/config/devices/entry/deviceconfig", "/config/shared", "/config/mgt-config"]);
  const mgtConfig = device.config["/config/mgt-config"]["mgt-config"];
  assert.equal(mgtConfig.users.entry[0].phash, "[REDACTED]");
  assert.equal(mgtConfig.users.entry[1]["public-key"], "c3NoLXJzYSBBQUFBQjNOemFDMXlj");
  assert.equal(mgtConfig["password-complexity"].enabled, "yes");
  const shared = device.config["/config/shared"].shared;
  assert.equal(shared["server-profile"].radius.entry.server.entry.secret, "[REDACTED]");
  assert.equal(shared["server-profile"].ldap.entry["bind-password"], "[REDACTED]");
  assert.equal(shared.certificate.entry["private-key"], "[REDACTED]");
  assert.equal(shared.integration["@api-key"], "[REDACTED]");
  const network = device.config["/config/devices/entry/network"].network;
  assert.equal(network.ike.gateway.entry.authentication["pre-shared-key"], "[REDACTED]");
  const deviceconfig = device.config["/config/devices/entry/deviceconfig"].deviceconfig;
  assert.equal(deviceconfig.system["snmp-setting"]["access-setting"].version.v2c["snmp-community-string"], "[REDACTED]");
  assert.equal(JSON.stringify(device).split("[REDACTED]").length - 1, 9, "every fixture secret is replaced by one marker");

  const findings = JSON.parse(files.get(join("analysis", "findings.json")));
  const hardening = findings.find((item) => item.id === "PA-23");
  assert.equal(hardening.status, "pass", hardening.summary);
  assert.equal(hardening.evidence.devices[0].default_snmp_community, false, "the assessment still evaluated the raw community string in memory");
  assert.equal(findings.find((item) => item.id === "PA-19").status, "pass");
  assert.match(files.get("QUICK_REFERENCE.md"), /replaced with \[REDACTED\] before core_data\/ is written/);
});

// ---------------------------------------------------------------------------
// Rule 9: redaction helpers, error-body descriptions, and Prisma Cloud secrets
// ---------------------------------------------------------------------------

// Canary values that must never survive into any probe, finding, summary, tool result, or
// bundle file. No two share an 8-character window, so a leaked fragment is attributable.
const CANARY_BEARER = "CANARY-BEARER-9f8e7d6c5b4a3210";
const CANARY_SESSION = "CANARY-SESSION-0a1b2c3d4e5f6789";
const CANARY_API_KEY = "CANARY-APIKEY-1122334455667788";
const CANARY_URL_TOKEN = "CANARY-URLTOKEN-99aa88bb77cc66dd";
// Name-shaped (one digit group per segment), so bare in prose it would stay: only the
// carrier it travels in (a session assignment) removes it.
const CANARY_NAMED = "sess-canary-COOKIE-31415926535897";
const CANARIES = [CANARY_BEARER, CANARY_SESSION, CANARY_API_KEY, CANARY_URL_TOKEN, CANARY_NAMED];
const CANARY_URL = `https://api.example.com/v1/x?token=${CANARY_URL_TOKEN}`;
const CANARY_SENTENCE = `Upstream refused Bearer ${CANARY_BEARER} when calling ${CANARY_URL} mid-sentence; _upstream_session=${CANARY_SESSION}, api_key=${CANARY_API_KEY}, and session=${CANARY_NAMED} were rejected`;
const SCRUBBED_SENTENCE = "Upstream refused Bearer [REDACTED] when calling https://api.example.com/v1/x?token=[REDACTED] mid-sentence; _upstream_session=[REDACTED], api_key=[REDACTED], and session=[REDACTED] were rejected";

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Neither the canary nor any window of `windowSize` characters of it may survive, so a
// partial echo (a slice, a split token) is attributable to the canary it came from.
function assertNoWindow(text, canary, windowSize, label) {
  assert.ok(!text.includes(canary), `${label}: ${canary} leaked`);
  for (let index = 0; index + windowSize <= canary.length; index += 1) {
    const fragment = canary.slice(index, index + windowSize);
    assert.ok(!text.includes(fragment), `${label}: fragment ${fragment} of ${canary} leaked`);
  }
}

function assertNoCanary(text, label, canaries = CANARIES) {
  for (const canary of canaries) assertNoWindow(text, canary, 8, label);
}

// A proxy or load balancer error page: HTML with header lines and a URL carrying a token.
// Retry-After is tiny so clients that do retry 5xx responses do so without waiting.
function htmlCanaryResponse() {
  const body = `<!DOCTYPE html><html><head><title>502 Bad Gateway</title></head><body><p>Authorization: Bearer ${CANARY_BEARER}</p>`
    + `<p>Set-Cookie: _upstream_session=${CANARY_SESSION}; Path=/</p><p>X-Api-Key: ${CANARY_API_KEY}</p>`
    + `<p>The upstream at ${CANARY_URL} did not answer in time, retry later.</p></body></html>`;
  return new Response(body, { status: 502, statusText: "Bad Gateway", headers: { "content-type": "text/html; charset=utf-8", "retry-after": "0.001" } });
}

function jsonCanaryResponse() {
  return jsonResponse({ message: CANARY_SENTENCE }, { status: 400, statusText: "Bad Request" });
}

function xmlCanaryResponse() {
  return xmlResponse(`<response status="error" code="403"><result><msg>${CANARY_SENTENCE}</msg></result></response>`, 403);
}

test("redaction helpers scrub credential-shaped text, JSON pairs, URL credentials, and credential-named properties", () => {
  assert.equal(redactErrorText(`upstream sent Bearer ${CANARY_BEARER} then stopped`), "upstream sent Bearer [REDACTED] then stopped");
  assert.equal(redactErrorText("Basic dXNlcjpwYXNzd29yZA== was refused"), "Basic [REDACTED] was refused");
  assert.equal(redactErrorText(`X-Api-Key: ${CANARY_API_KEY} rejected`), "X-Api-Key: [REDACTED]", "header lines are withheld to the end of the line");
  assert.equal(redactErrorText("Set-Cookie: PHPSESSID=abc123def; Path=/"), "Set-Cookie: [REDACTED]");
  assert.equal(redactErrorText("GET /api/?type=op&key=LUFRPT0123456789abcdefghij&cmd=x"), "GET /api/?type=op&key=[REDACTED]&cmd=x");
  assert.equal(redactErrorText("key LUFRPT0123456789abcdefghijklmnop expired"), "key [REDACTED] expired", "PAN-OS API keys are recognized by shape");
  assert.equal(redactErrorText("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcdefghijk expired"), "jwt [REDACTED] expired");
  assert.equal(redactErrorText(`connect via https://svc:${CANARY_SESSION}@proxy.example.com failed`), "connect via https://[REDACTED]@proxy.example.com failed");
  assert.equal(redactErrorText(`body {"password":"${CANARY_SESSION}","name":"svc"} rejected`), 'body {"password":"[REDACTED]","name":"svc"} rejected', "JSON pairs quoted inside a message are scrubbed");
  assert.equal(redactErrorText(CANARY_SENTENCE), SCRUBBED_SENTENCE);
  assert.equal(redactErrorText("PAN-OS keygen failed (code 403, status 403): Invalid credentials"), "PAN-OS keygen failed (code 403, status 403): Invalid credentials", "plain text without credential values is untouched");
  assert.equal(redactErrorText(SCRUBBED_SENTENCE), SCRUBBED_SENTENCE, "idempotent");
  assertNoCanary(redactErrorText(CANARY_SENTENCE), "redactErrorText");

  assert.equal(redactCredentialValueText(`https://soar.example.com/prisma?token=${CANARY_URL_TOKEN}&env=prod`), "https://soar.example.com/prisma?token=[REDACTED]&env=prod");
  assert.equal(redactCredentialValueText("https://svc:hunter2@registry.example.com/v2/"), "https://[REDACTED]@registry.example.com/v2/");
  assert.equal(redactCredentialValueText("https://hooks.slack.com/services/T0FAKE/B0FAKE/secretpart"), "https://hooks.slack.com/services/[REDACTED]");
  assert.equal(redactCredentialValueText('{"authToken":"abc123","url":"https://x.example.com"}'), '{"authToken":"[REDACTED]","url":"https://x.example.com"}');
  assert.equal(redactCredentialValueText("registry.example.com"), "registry.example.com");

  for (const name of ["authToken", "api_key", "apiKey", "APIKey", "X-Api-Key", "password", "clientSecret", "client_secret", "secretKey", "secret_key", "privateKey", "secrets", "credential", "credentials", "phash", "passphrase", "tokens", "authorization", "integrationKey", "sharedKey", "accessKey", "webhook_password"]) {
    assert.equal(isCredentialPropertyName(name), true, `${name} should be redacted`);
  }
  for (const name of ["credentialID", "credentialId", "hostUrl", "login", "key", "publicKey", "public_key", "url", "name", "type", "enabled", "secure", "keyId", "tokenCount", "passwordPolicy", "secretsManager", "webhookUrl", "sourceType", "registry", "repository"]) {
    assert.equal(isCredentialPropertyName(name), false, `${name} should be kept`);
  }

  const integrations = secretsIntegrations();
  const redacted = redactCredentialProperties(integrations);
  assert.equal(integrations[0].integrationConfig.authToken, FAKE_PRISMA_SECRETS.splunkAuthToken, "the source object is not mutated");
  assert.equal(redacted[0].integrationConfig.authToken, "[REDACTED]");
  assert.equal(redacted[0].integrationConfig.url, "https://splunk.example.com:8088/services/collector");
  assert.equal(redacted[1].integrationConfig.url, "https://soar.example.com/prisma?token=[REDACTED]&env=prod", "URL query credentials are scrubbed inside kept strings");
  assert.deepEqual(redacted[1].integrationConfig.headers, [
    { key: "Authorization", value: "[REDACTED]", secure: true },
    { key: "Content-Type", value: "application/json", secure: false },
  ], "only the value of a secure or credential-labelled header pair is replaced");
  assert.equal(redacted[2].integrationConfig.webhookUrl, "https://hooks.slack.com/services/[REDACTED]");
  assert.equal(redacted[3].integrationConfig.password, "[REDACTED]");
  assert.equal(redacted[3].integrationConfig.login, "prisma-svc");
  assert.equal(redacted[3].integrationConfig.hostUrl, "acme.service-now.com");
  assert.deepEqual(redacted[3].integrationConfig.tables, { incident: true });
  assert.equal(redacted[4].integrationConfig.secretKey, "[REDACTED]");

  const compute = redactCredentialProperties(secretsComputeSnapshot());
  assert.equal(compute.registrySettings.specifications[0].credential, "[REDACTED]", "a credential container collapses whole");
  assert.equal(compute.registrySettings.specifications[0].credentialID, "reg-cred-1");
  assert.equal(compute.registrySettings.specifications[0].registry, "registry.example.com");
  assert.equal(compute.images[0].secrets, "[REDACTED]");
  assert.deepEqual(compute.images[0].labels, { maintainer: "platform" });
  assert.equal(compute.defenders[0].proxy.password, "[REDACTED]");
  assert.equal(compute.defenders[0].proxy.user, "defender");
  assert.equal(compute.defenders[0].proxy.httpProxy, "http://proxy.example.com:3128");
  assert.equal(compute.cloudDiscovery[0].credential, "[REDACTED]");
  assert.deepEqual(redactCredentialProperties(compute), compute, "idempotent");
  assert.deepEqual(
    redactCredentialProperties({ password: "", token: null, secrets: [], credential: {} }),
    { password: "", token: null, secrets: [], credential: {} },
    "empty credential values stay empty rather than claiming a redacted value",
  );
  for (const secret of Object.values(FAKE_PRISMA_SECRETS)) {
    assert.ok(!JSON.stringify(redacted).includes(secret), `${secret} leaked from integrations`);
    assert.ok(!JSON.stringify(compute).includes(secret), `${secret} leaked from the Compute snapshot`);
  }
});

// The scrub boundary ruling: name-shaped values (words joined by hyphens or underscores
// with at most one digit group per segment) stay bare in prose because they are
// indistinguishable from resource names; the same values are removed from every carrier
// whatever their shape, a configured secret is removed in every form whatever its shape,
// and real token shapes are removed bare.
const NAME_SHAPED_VALUES = ["prod-us-east-2026", "fw-dc1-01", "sess-canary-COOKIE-31415926535897", "my-bucket-prod-2026-logs", "3f2b1c9e-8a7d-4e6f-9b0a-1c2d3e4f5a6b"];

// Every carrier of the ruling with the value in it, and the exact rendering after the scrub.
function carriersOf(value) {
  return [
    [`Authorization: Bearer ${value}`, /^Authorization: (?:Bearer )?\[REDACTED\]$/],
    [`Proxy-Authorization: Basic ${value}`, /^Proxy-Authorization: (?:Basic )?\[REDACTED\]$/],
    [`Cookie: sid=${value}; theme=dark`, /^Cookie: \[REDACTED\]$/],
    [`Set-Cookie: sid=${value}; Path=/; HttpOnly`, /^Set-Cookie: \[REDACTED\]$/],
    [`X-Api-Key: ${value}`, /^X-Api-Key: \[REDACTED\]$/],
    [`X-PAN-KEY: ${value}`, /^X-PAN-KEY: \[REDACTED\]$/],
    [`x-redlock-auth: ${value}`, /^x-redlock-auth: \[REDACTED\]$/],
    [`<p>X-Api-Key: ${value}</p><p>next</p>`, /^<p>X-Api-Key: \[REDACTED\]<\/p><p>next<\/p>$/],
    [`session=${value}; Path=/`, /^session=\[REDACTED\]; Path=\/$/],
    [`_upstream_session=${value} expired`, /^_upstream_session=\[REDACTED\] expired$/],
    [`PHPSESSID=${value}; Path=/`, /^PHPSESSID=\[REDACTED\]; Path=\/$/],
    [`https://svc:${value}@proxy.example.com/x`, /^https:\/\/\[REDACTED\]@proxy\.example\.com\/x$/],
    [`https://fw/api/?type=op&key=${value}&cmd=x`, /^https:\/\/fw\/api\/\?type=op&key=\[REDACTED\]&cmd=x$/],
    [`GET /api/?type=keygen&user=a&password=${value}`, /^GET \/api\/\?type=keygen&user=a&password=\[REDACTED\]$/],
    [`/login?user=a&pass=${value}`, /^\/login\?user=a&pass=\[REDACTED\]$/],
    [`https://x.example.com/cb#access_token=${value}&state=1`, /^https:\/\/x\.example\.com\/cb#access_token=\[REDACTED\]&state=1$/],
    [`Bearer ${value}`, /^Bearer \[REDACTED\]$/],
    [`Basic ${value}`, /^Basic \[REDACTED\]$/],
    [`Token ${value}`, /^Token \[REDACTED\]$/],
    [`ApiKey ${value}`, /^ApiKey \[REDACTED\]$/],
    [`SSWS ${value}`, /^SSWS \[REDACTED\]$/],
    [`password=${value}`, /^password=\[REDACTED\]$/],
    [`password: ${value}`, /^password: \[REDACTED\]$/],
    [`passphrase: ${value} and more words`, /^passphrase: \[REDACTED\]$/],
    [`client_secret=${value}&grant_type=x`, /^client_secret=\[REDACTED\]&grant_type=x$/],
    [`{"client_secret":"${value}","name":"svc"}`, /^\{"client_secret":"\[REDACTED\]","name":"svc"\}$/],
    [`{"authToken": "${value}", "url": "https://x"}`, /^\{"authToken": "\[REDACTED\]", "url": "https:\/\/x"\}$/],
    [`<entry name="fw1" key="${value}"/>`, /^<entry name="fw1" key="\[REDACTED\]"\/>$/],
    [`<entry name='r1' secret='${value}'/>`, /^<entry name='r1' secret='\[REDACTED\]'\/>$/],
    [`<server name="r1" community-string="${value}"/>`, /^<server name="r1" community-string="\[REDACTED\]"\/>$/],
  ];
}

test("scrub boundary: name-shaped values stay bare in prose, leave every carrier whatever their shape, and go as configured secrets in every form", () => {
  for (const value of NAME_SHAPED_VALUES) {
    for (const prose of [`device ${value} was not read`, `${value}`, `inventory ${value} read 12 of 40 resources`, `path /var/lib/${value}/state`]) {
      assert.equal(redactErrorText(prose), prose, `${value} stays bare in error text`);
      assert.equal(redactCredentialValueText(prose), prose, `${value} stays bare in a data value`);
    }
    for (const [text, expected] of carriersOf(value)) {
      for (const scrub of [redactErrorText, redactCredentialValueText]) {
        const out = scrub(text);
        assert.match(out, expected, `${scrub.name}(${JSON.stringify(text)}) -> ${JSON.stringify(out)}`);
        assertNoWindow(out, value, 6, `${scrub.name} ${text}`);
        assert.equal(scrub(out), out, `${scrub.name} is idempotent on ${out}`);
      }
    }
    // A configured secret goes bare and in every encoded form, however name-shaped it is.
    for (const form of secretForms(value)) {
      assert.equal(redactSecrets(`login rejected for ${form} by upstream`, [value]), "login rejected for [REDACTED] by upstream", `configured ${value} as ${form}`);
      assert.equal(redactConfiguredSecrets(`login rejected for ${form} by upstream`, [value]), "login rejected for [REDACTED] by upstream", `guard 2 alone on ${form}`);
    }
  }
  // Every encoding of a secret with characters each encoding changes.
  for (const form of secretForms(FIXTURE_PANOS_PASSWORD)) {
    assert.ok(form.length >= 8, form);
    assert.equal(redactConfiguredSecrets(`echo ${form} end`, [FIXTURE_PANOS_PASSWORD]), "echo [REDACTED] end", form);
  }
  assert.equal(secretForms(FIXTURE_PANOS_PASSWORD).length, 5, "the fixture password has five distinct forms");
  assert.equal(redactConfiguredSecrets("a pin 4711 and pin 47110", ["4711"]), "a pin [REDACTED] and pin 47110", "a short secret is removed as a whole token only");
  assert.equal(redactConfiguredSecrets("too short abc", ["abc"]), "too short abc", "below the minimum length nothing is scrubbed");

  // Real token shapes go bare from error text, and stay in data values where they are identifiers.
  for (const [text, expected] of [
    ["bare Kq7Zx2Vw9Lm4Tp8R token", "bare [REDACTED] token"],
    ["digest 0f9e8d7c6b5a4938 shown", "digest [REDACTED] shown"],
    ["hash 3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b shown", "hash [REDACTED] shown"],
    ["key LUFRPT0123456789abcdefghijklmnop expired", "key [REDACTED] expired"],
    ["jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcdefghijk expired", "jwt [REDACTED] expired"],
    ["bare dXNlcjpwYXNzd29yZA== padded", "bare [REDACTED] padded"],
    ["akid AKIAIOSFODNN7EXAMPLE shown", "akid [REDACTED] shown"],
    ["-----BEGIN RSA PRIVATE KEY-----\nMIIEfake\n-----END RSA PRIVATE KEY-----", "[REDACTED]"],
    ["-----BEGIN CERTIFICATE-----\nMIIEfake\n-----END CERTIFICATE-----", "[REDACTED]"],
    ["truncated -----BEGIN PRIVATE KEY-----\nMIIEfake", "truncated [REDACTED]"],
  ]) {
    assert.equal(redactErrorText(text), expected);
    assert.equal(redactErrorText(expected), expected, "idempotent");
  }
  // After a scheme the value goes whatever its shape, a plain lowercase word included,
  // unless it is one of the listed prose words; after the noun "Token" any short plain
  // lowercase word is prose.
  for (const [text, expected] of [
    ["Bearer abcdefghijklmnop rejected", "Bearer [REDACTED] rejected"],
    ["Basic canarybasic rejected", "Basic [REDACTED] rejected"],
    ["ApiKey canaryapikey rejected", "ApiKey [REDACTED] rejected"],
    ["SSWS canarysswsvalue rejected", "SSWS [REDACTED] rejected"],
    ["Token abcdefghijklmnopq expired", "Token [REDACTED] expired"],
    ["Token hygiene could not be judged; token inventory read; Token count 3", "Token hygiene could not be judged; token inventory read; Token count 3"],
    ["OAuth clients all declare scopes; an OAuth bearer token; OAuth abcdefghijklmnop", "OAuth clients all declare scopes; an OAuth bearer token; OAuth abcdefghijklmnop"],
    ["Basic with Can View on scans; Bearer tokens expire; Basic credential; Basic authentication is required", "Basic with Can View on scans; Bearer tokens expire; Basic credential; Basic authentication is required"],
    // A Titlecase word makes the scheme name an adjective in a title; a digit, a symbol,
    // token casing, or a run longer than a word still marks a credential.
    ["profiles: Basic Network Scan, Bearer Token rotation, Token Hygiene, ApiKey Rotation", "profiles: Basic Network Scan, Bearer Token rotation, Token Hygiene, ApiKey Rotation"],
    ["Basic Canary2026 rejected; Basic dXNlcjpwYXNz rejected; Bearer Abcdefghijklmnopqrstu rejected; Basic Canary-Basic rejected", "Basic [REDACTED] rejected; Basic [REDACTED] rejected; Bearer [REDACTED] rejected; Basic [REDACTED] rejected"],
  ]) {
    assert.equal(redactErrorText(text), expected);
    assert.equal(redactCredentialValueText(text), expected);
  }
  // A digit string under a singular credential word is still a credential (a PIN, a numeric token).
  assert.equal(redactErrorText('"pin": 4711, "token": 12345678, otp=123456, "tokens": 2'), '"pin": [REDACTED], "token": [REDACTED], otp=[REDACTED], "tokens": 2');
  assert.equal(redactCredentialValueText("bare Kq7Zx2Vw9Lm4Tp8R id"), "bare Kq7Zx2Vw9Lm4Tp8R id", "an opaque identifier in evidence is not a secret");
  const certificate = "-----BEGIN CERTIFICATE-----\nMIIEfake\n-----END CERTIFICATE-----";
  assert.equal(redactCredentialValueText(certificate), certificate, "a public certificate is evidence");
  assert.equal(redactCredentialValueText("-----BEGIN PRIVATE KEY-----\nMIIEfake\n-----END PRIVATE KEY-----"), "[REDACTED]");
  assert.equal(redactCredentialValueText("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA\n-----END OPENSSH PRIVATE KEY-----"), "[REDACTED]");
  assert.equal(redactCredentialValueText(`${certificate}\n-----BEGIN EC PRIVATE KEY-----\nMHcC`), `${certificate}\n[REDACTED]`, "a truncated private block after a kept certificate");

  // Names, prose, and this module's own vocabulary survive.
  for (const text of [
    "PAN-OS keygen failed (code 403, status 403): Invalid credentials",
    "Prisma Cloud GET /v2/policy failed (400): non-JSON text/html response body (1234 bytes, not echoed)",
    "GET /api/?type=config&action=show&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']",
    "arn:aws:iam::123456789012:role/AWSLambdaBasicExecutionRole",
    "/tmp/grclanker-paloalto-loader-errors-Ab3xY9/nested.yaml",
    "policy 550e8400-e29b-41d4-a716-446655440000 unified_compliance_matrix ENOENT PCI-DSS-4",
    "Basic authentication is required; the Bearer token is missing; token expired, retry later",
    "Unable to read Palo Alto config file /etc/paloalto.json (EACCES)",
    '"pass": 12, "pass_rate": 95, "default_snmp_community": false, "credential_enforcement_disabled": [], "password_complexity_by_device": [',
    '"api_keys": 3, "secrets": 0, "oauth_tokens": 1, "credentials": 12; keys=3 tokens: 7 cookies: 0',
    '"credential-enforcement": {\n "client-auth": {\n "multi-factor-auth": {\n "password-complexity": {',
    "session_timeout_minutes=30 auth_mode=saml credentials_file=/etc/x credentialID=reg-cred-1 access_key_id=AKIA client_id=abc",
    "misconfiguration of the Authorization Code flow on misconfigured-firewall-cluster",
  ]) {
    assert.equal(redactErrorText(text), text, text);
  }

  for (const [key, expected] of [
    ["key", true], ["token", true], ["pageToken", true], ["api_key", true], ["X-Api-Key", true], ["X-PAN-KEY", true], ["Set-Cookie", true],
    ["_upstream_session", true], ["session_id", true], ["PHPSESSID", true], ["JSESSIONID", true], ["password1", true], ["authtoken", true],
    ["sharedsecret", true], ["privatekey", true], ["password_hash", true], ["token_value", true], ["authorization_header", true],
    ["default_snmp_community", true], ["X-Amz-Signature", true], ["oauth_verifier", true], ["sid", true], ["sig", true], ["phash", true],
    ["credentialID", false], ["public_key", false], ["tokenCount", false], ["xpath", false], ["cmd", false], ["type", false], ["user", false],
    ["login", false], ["max_keys", false], ["auth_mode", false], ["password_complexity_by_device", false], ["credential_enforcement_disabled", false],
    ["pass_rate", false], ["pass", false], ["access_key_id", false], ["client_id", false], ["monkey", false], ["oauth", false], ["sessions", false],
    ["session_timeout_minutes", false], ["credentials_file", false], ["passwordPolicy", false], ["webhookUrl", false],
    ["registration_code", true], ["activation_code", true], ["authorization_code", true], ["recovery_codes", true],
    ["status_code", false], ["error_code", false], ["country_code", false], ["code", false],
  ]) {
    assert.equal(isCredentialKey(key), expected, key);
  }
});

test("no window of a carried or configured canary survives, for every canary length from 6 to 24", () => {
  // A deterministic generator so a failure reproduces; one digit is forced so the value
  // never falls under the one-plain-word prose exception after a scheme.
  let seed = 0x2545f491;
  const next = () => {
    seed = (seed * 1103515245 + 12345) % 0x80000000;
    return seed;
  };
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  for (let length = 6; length <= 24; length += 1) {
    const characters = Array.from({ length }, () => alphabet[next() % alphabet.length]);
    characters[Math.floor(length / 2)] = String(next() % 10);
    const canary = characters.join("");
    const window = Math.min(6, length);
    for (const input of [
      `Authorization: Bearer ${canary}`, `Cookie: sid=${canary}`, `X-Api-Key: ${canary}`, `?token=${canary}`, `&key=${canary}&cmd=x`,
      `password=${canary}`, `"api_key":"${canary}"`, `key="${canary}"`, `Basic ${canary}`, `https://u:${canary}@h.example.com/`,
    ]) {
      assert.ok(input.includes(canary), "fixture self-check");
      for (const scrub of [redactErrorText, redactCredentialValueText]) {
        assertNoWindow(scrub(input), canary, window, `${scrub.name} length ${length}: ${input}`);
      }
    }
    const configured = `value ${canary} shown`;
    assert.ok(configured.includes(canary), "fixture self-check");
    assert.equal(redactSecrets(configured, [canary]), "value [REDACTED] shown", `configured length ${length}`);
    for (const form of secretForms(canary)) assertNoWindow(redactConfiguredSecrets(`v ${form} w`, [canary]), form, window, `form ${form}`);
  }
});

test("describePrismaErrorBody and PanosApiClient.parseResponse describe non-JSON or non-XML bodies by status and length and redact before the length cap", async () => {
  const html = htmlCanaryResponse();
  const htmlText = await html.text();
  assert.equal(describePrismaErrorBody(html, htmlText), `non-JSON text/html response body (${htmlText.length} bytes, not echoed)`);

  const json = jsonCanaryResponse();
  assert.equal(describePrismaErrorBody(json, await json.text()), SCRUBBED_SENTENCE);

  const undocumented = jsonResponse({ foo: "bar", token: CANARY_SESSION }, { status: 500 });
  const undocumentedText = await undocumented.text();
  assert.equal(describePrismaErrorBody(undocumented, undocumentedText), `JSON response body without documented error fields (${undocumentedText.length} bytes, not echoed)`);
  assert.equal(describePrismaErrorBody(new Response("", { status: 503 }), ""), "empty response body");

  const header = new Response("", { status: 403, headers: { "x-redlock-status": JSON.stringify([{ i18nKey: "forbidden", severity: "error", subject: `Bearer ${CANARY_BEARER}` }]) } });
  assert.equal(describePrismaErrorBody(header, ""), "x-redlock-status forbidden, Bearer [REDACTED]; empty response body");
  const opaqueHeader = new Response("", { status: 403, headers: { "x-redlock-status": `Bearer ${CANARY_BEARER}` } });
  assert.equal(describePrismaErrorBody(opaqueHeader, ""), "x-redlock-status header present (not echoed); empty response body");

  // A userinfo password whose "@" falls past the 200-character cap would survive if the
  // cap were applied before redaction; redaction runs first, so the cap only shortens text.
  const longMessage = `${"x".repeat(155)} via https://svc:${CANARY_SESSION}@proxy.example.com refused`;
  const long = jsonResponse({ message: longMessage }, { status: 400 });
  const described = describePrismaErrorBody(long, await long.text());
  assertNoCanary(described, "capped Prisma message");
  assert.ok(described.includes("https://[REDACTED]@proxy.example.com"), described);
  assert.ok(described.length <= 200);

  const panos = new PanosApiClient(
    { host: "fw.example.com", baseUrl: "https://fw.example.com", apiKey: "LUFRPT-key" },
    { fetchImpl: async () => xmlResponse(`<response status="error" code="403"><result><msg>${"x".repeat(255)} via https://svc:${CANARY_SESSION}@proxy.example.com refused</msg></result></response>`, 403), retryAttempts: 0 },
  );
  await assert.rejects(panos.showSystemInfo(), (error) => {
    assertNoCanary(error.message, "capped PAN-OS message");
    assert.match(error.message, /failed \(code 403, status 403\): x+ via https:\/\/\[REDACTED\]@proxy\.example\.com/);
    return true;
  });
  const nonXml = new PanosApiClient({ host: "fw.example.com", baseUrl: "https://fw.example.com", apiKey: "LUFRPT-key" }, { fetchImpl: async () => htmlCanaryResponse(), retryAttempts: 0 });
  await assert.rejects(nonXml.showConfig("/config/shared"), (error) => {
    assertNoCanary(error.message, "PAN-OS HTML body");
    assert.equal(error.message, `PAN-OS config show /config/shared on fw.example.com returned a non-XML text/html response (status 502, ${htmlText.length} bytes, not echoed).`);
    return true;
  });
  const nonJson = new PrismaCloudClient({ apiUrl: "https://api2.prismacloud.io", accessKeyId: "k", secretKey: "s" }, {
    fetchImpl: async (input) => (new URL(input).pathname === "/login" ? jsonResponse({ token: "jwt" }) : new Response(`<html>Bearer ${CANARY_BEARER}</html>`, { status: 200, headers: { "content-type": "text/html" } })),
    retryAttempts: 0,
  });
  await assert.rejects(nonJson.listPolicies(), (error) => {
    assertNoCanary(error.message, "Prisma 200 HTML body");
    assert.match(error.message, /^Prisma Cloud GET \/v2\/policy returned status 200 with a non-JSON text\/html response body \(\d+ bytes, not echoed\) where the documented JSON document was expected\.$/);
    return true;
  });
});

test("the session tokens the clients obtain join the configured secrets, so a name-shaped token echoed bare in an error body still goes", async () => {
  // Both tokens are name-shaped on purpose: no carrier or token-shape rule would touch
  // them bare in prose, so their absence proves guard 2 learned them at login.
  const sessionToken = "session-fixture-lantern-2026";
  const computeToken = "compute-fixture-harbor-2026";
  const client = new PrismaCloudClient({ apiUrl: "https://api2.prismacloud.io", accessKeyId: "k", secretKey: "s" }, {
    fetchImpl: async (input) => {
      const { pathname } = new URL(input);
      if (pathname === "/login") return jsonResponse({ token: sessionToken });
      if (pathname === "/api/v1/authenticate") return jsonResponse({ token: computeToken });
      const echoed = pathname.startsWith("/api/v1") ? computeToken : sessionToken;
      return jsonResponse({ message: `upstream rejected ${echoed} for this tenant` }, { status: 403 });
    },
    retryAttempts: 0,
  });
  assert.ok(!client.knownSecrets.includes(sessionToken), "the token is not known before login");
  await assert.rejects(client.listPolicies(), (error) => {
    assert.equal(error.message, "Prisma Cloud GET /v2/policy failed (403): upstream rejected [REDACTED] for this tenant");
    return true;
  });
  assert.ok(client.knownSecrets.includes(sessionToken), "the session token is a known secret after login");
  const compute = new PrismaComputeClient("https://console.example.com", client);
  await assert.rejects(compute.get("/defenders"), (error) => {
    assert.equal(error.message, "Prisma Cloud Compute GET /defenders failed (403): upstream rejected [REDACTED] for this tenant");
    return true;
  });
  assert.ok(client.knownSecrets.includes(computeToken), "the Compute token is a known secret after authenticate");
  assert.equal(new Set(client.knownSecrets).size, client.knownSecrets.length, "a refreshed token is registered once");
});

test("exportPaloaltoAuditBundle and the assessment results never carry Prisma Cloud or Compute credentials while verdicts still read the same evidence", async () => {
  const base = createTempBase("grclanker-paloalto-prisma-secrets-");
  const secrets = Object.values(FAKE_PRISMA_SECRETS);
  const clients = createPaloaltoClients(bothProductsConfig(), mockedFetch({ withSecrets: true }));
  const result = await exportPaloaltoAuditBundle(clients, base);
  assert.equal(result.errorCount, 0);

  const files = readBundleFiles(result.outputDir);
  assertSecretsAbsent(assert, files, secrets, "bundle directory");
  const zipEntries = readZipEntries(result.zipPath);
  assert.equal(zipEntries.size, files.size);
  assertSecretsAbsent(assert, zipEntries, secrets, "zip archive");

  const prisma = JSON.parse(files.get(join("core_data", "prisma_cloud.json")));
  const integration = (name) => prisma.integrations.find((item) => item.name === name).integrationConfig;
  assert.equal(integration("splunk").authToken, "[REDACTED]");
  assert.equal(integration("splunk").url, "https://splunk.example.com:8088/services/collector");
  assert.equal(integration("soar-webhook").url, "https://soar.example.com/prisma?token=[REDACTED]&env=prod");
  assert.deepEqual(integration("soar-webhook").headers, [{ key: "Authorization", value: "[REDACTED]", secure: true }, { key: "Content-Type", value: "application/json", secure: false }]);
  assert.equal(integration("slack").webhookUrl, "https://hooks.slack.com/services/[REDACTED]");
  assert.equal(integration("servicenow").password, "[REDACTED]");
  assert.equal(integration("servicenow").login, "prisma-svc");
  assert.equal(integration("tenable").secretKey, "[REDACTED]");
  const registry = prisma.compute.registry_settings.specifications[0];
  assert.equal(registry.credential, "[REDACTED]");
  assert.equal(registry.credentialID, "reg-cred-1");
  assert.equal(prisma.compute.images[0].secrets, "[REDACTED]");
  assert.equal(prisma.compute.defenders[0].proxy.password, "[REDACTED]");
  assert.equal(prisma.compute.defenders[0].proxy.user, "defender");
  assert.equal(prisma.compute.cloud_discovery[0].credential, "[REDACTED]");
  // The healthy bundle reports every CSPM and Compute surface as read, with a documented request and no failure status.
  for (const [group, block] of [["prisma_cloud", prisma.collection], ["prisma_compute", prisma.compute.collection]]) {
    assert.ok(Object.keys(block).length >= 8, `${group} lists every surface`);
    for (const [surface, entry] of Object.entries(block)) {
      assert.equal(entry.status, "ok", `${group} ${surface}`);
      assert.equal(entry.http_status, null, `${group} ${surface}`);
      assert.match(entry.endpoint, /^GET \//, `${group} ${surface}`);
      assert.equal(typeof entry.seen, "number", `${group} ${surface}`);
    }
  }
  assert.equal(prisma.open_alerts_truncated, false);

  const findings = JSON.parse(files.get(join("analysis", "findings.json")));
  for (const id of ["PA-10", "PA-11", "PA-20", "PA-24"]) assert.equal(byId(findings, id).status, "pass", `${id}: ${byId(findings, id).summary}`);
  assert.deepEqual(byId(findings, "PA-20").evidence.prisma_integrations, ["splunk (splunk)", "soar-webhook (webhook)", "slack (slack)", "servicenow (service_now)", "tenable (tenable)"]);
  assert.match(files.get("QUICK_REFERENCE.md"), /credential-named properties replaced by \[REDACTED\]/);

  // The same redacted snapshot feeds every assessment result the tools spread into their payloads.
  const access = await checkPaloaltoAccess(clients);
  const payloads = [access, await assessPaloaltoCloudPosture(clients), await assessPaloaltoThreatPrevention(clients), await assessPaloaltoDeviceHardening(clients)];
  for (const payload of payloads) assertSecretsAbsent(assert, new Map([["payload", JSON.stringify(payload)]]), secrets, payload.title ?? "access check");
});

// ---------------------------------------------------------------------------
// Error-string canary sweep: every surface, every device, two body shapes
// ---------------------------------------------------------------------------

const PANOS_SWEEP_HOSTS = ["fw1.example.com", "fw2.example.com"];
const FIREWALL_XPATHS = ["/config/devices/entry/vsys", "/config/devices/entry/network", "/config/devices/entry/deviceconfig", "/config/shared", "/config/mgt-config"];
const PRISMA_CLOUD_PATHS = ["/login", "/meta_info", "/v2/compliance/posture", "/v2/alert/rule", "/v2/alert", "/v2/policy", "/cloud", "/cloud/group", "/user/role", "/integration"];
const PRISMA_COMPUTE_PATHS = ["/authenticate", "/defenders", "/policies/runtime/container", "/policies/compliance/container", "/policies/compliance/host", "/policies/vulnerability/images", "/settings/registry", "/registry", "/images", "/stats/vulnerabilities", "/stats/compliance", "/cloud/discovery", "/scans"];

// Every HTTP surface the three clients read, keyed by product (or PAN-OS host) and path.
function paloaltoRouteKey(input, init = {}) {
  const url = new URL(input);
  if (url.hostname.endsWith("prismacloud.io")) return `prisma-cloud ${url.pathname}`;
  if (url.hostname === "compute.example.com") return `prisma-compute ${url.pathname.replace(/^\/api\/v1/, "")}`;
  if ((init.method ?? "GET") === "POST") return `${url.hostname} keygen`;
  if (url.searchParams.get("type") === "op") return `${url.hostname} ${url.searchParams.get("cmd").includes("high-availability") ? "ha_state" : "system_info"}`;
  return `${url.hostname} ${url.searchParams.get("xpath")}`;
}

const PALOALTO_SURFACES = [
  ...PRISMA_CLOUD_PATHS.map((path) => `prisma-cloud ${path}`),
  ...PRISMA_COMPUTE_PATHS.map((path) => `prisma-compute ${path}`),
  ...PANOS_SWEEP_HOSTS.flatMap((host) => ["keygen", "system_info", "ha_state", ...FIREWALL_XPATHS].map((surface) => `${host} ${surface}`)),
];

function sweepFetch(failingSurface, makeResponse) {
  const healthy = mockedFetch();
  return async (input, init = {}) => (paloaltoRouteKey(input, init) === failingSurface ? makeResponse() : healthy(input, init));
}

// Both products and two devices reached through keygen, so key generation is a surface
// too; retries are off so a 502 fails immediately instead of sleeping through backoff.
function sweepConfig() {
  return {
    ...resolvePaloaltoConfiguration({}, {
      PRISMA_API_URL: "https://api2.prismacloud.io",
      PRISMA_ACCESS_KEY_ID: "key",
      PRISMA_SECRET_KEY: FIXTURE_SECRET_KEY,
      PANOS_HOST: PANOS_SWEEP_HOSTS.join(","),
      PANOS_USERNAME: "auditor",
      PANOS_PASSWORD: FIXTURE_PANOS_PASSWORD,
    }),
    retryAttempts: 0,
  };
}

const HTML_MARKERS = {
  "prisma-cloud": /\(502\): non-JSON text\/html response body \(\d+ bytes, not echoed\)/,
  "prisma-compute": /\(502\): non-JSON text\/html response body \(\d+ bytes, not echoed\)/,
  "pan-os": /returned a non-XML text\/html response \(status 502, \d+ bytes, not echoed\)/,
};
const STRUCTURED_MARKERS = {
  "prisma-cloud": new RegExp(`\\(400\\): ${escapeRegExp(SCRUBBED_SENTENCE)}`),
  "prisma-compute": new RegExp(`\\(400\\): ${escapeRegExp(SCRUBBED_SENTENCE)}`),
  "pan-os": new RegExp(`failed \\(code 403, status 403\\): ${escapeRegExp(SCRUBBED_SENTENCE)}`),
};
const ECHOED_BODY_TEXT = /<html|<!DOCTYPE|Set-Cookie|X-Api-Key:|did not answer/i;

test("the two-device keygen sweep fixture is healthy before the canary sweep relies on it, and every fixed text survives the scrubs", async () => {
  const clients = createPaloaltoClients(sweepConfig(), sweepFetch("none", () => htmlCanaryResponse()));
  const access = await checkPaloaltoAccess(clients);
  assert.equal(access.status, "healthy");
  assert.equal(access.surfaces.length, 8 + 9 + 2 * 7);
  const result = await exportPaloaltoAuditBundle(clients, createTempBase("grclanker-paloalto-sweep-healthy-"));
  assert.equal(result.errorCount, 0);
  const files = readBundleFiles(result.outputDir);
  const findings = JSON.parse(files.get(join("analysis", "findings.json")));
  assert.deepEqual(findings.filter((item) => item.status !== "pass").map((item) => item.id), ["PA-25"]);

  // Fixed-text survival: with nothing to redact, the configured-secret pass leaves every
  // written file alone (the only markers are the three lines of QUICK_REFERENCE.md that
  // describe the redaction), the access check carries none, and the general scrub is the
  // identity on every file and on every rendered string, so no fixed text this module
  // renders is ever mistaken for a credential.
  assert.equal(JSON.stringify(access).includes(REDACTION_MARKER), false);
  for (const [name, text] of files) {
    const markers = (text.match(/\[REDACTED\]/g) ?? []).length;
    assert.equal(markers, name === "QUICK_REFERENCE.md" ? 4 : 0, `${name} carries ${markers} markers`);
    assert.equal(redactErrorText(text), text, `${name} is changed by the general scrub`);
  }
  assert.equal(redactErrorText(JSON.stringify(access)), JSON.stringify(access));
  for (const item of findings) {
    for (const field of ["summary", "detail", "remediation", "note", "title"]) {
      if (typeof item[field] === "string") assert.equal(redactErrorText(item[field]), item[field], `${item.id} ${field}`);
    }
  }
});

// The failing surface echoes the configured secrets of its own product in every form a
// server might reflect them: as is, JSON-escaped, URL-encoded, base64, and base64url. The
// Prisma Cloud secret key is name-shaped, so nothing but the configured-secret pass can
// remove its plain form; every form must be absent from every probe, finding, analysis
// error, bundle file, and zip entry.
const ECHOED_MARKER = /credentials(?: \[REDACTED\])+ rejected/;

function echoedSecretsMessage(forms) {
  return `credentials ${forms.join(" ")} rejected`;
}

test("a documented error field is scrubbed of the configured secrets before it is shortened, so the 200-character cut never leaves a fragment of a secret", async () => {
  const forms = [...secretForms(FIXTURE_SECRET_KEY), ...secretForms("k")].filter((form) => form.length >= 8);
  for (const form of forms) {
    // The form straddles the 200-character boundary of the shortened field: scrubbing
    // after the cut would leave its head behind.
    const message = `${"x".repeat(200 - Math.floor(form.length / 2))} ${form} was rejected by the upstream identity provider`;
    const fetchImpl = async () => jsonResponse({ message }, { status: 400, statusText: "Bad Request" });
    const client = new PrismaCloudClient({ apiUrl: "https://api2.prismacloud.io", accessKeyId: "k", secretKey: FIXTURE_SECRET_KEY }, { fetchImpl, sleepImpl: noSleep });
    await assert.rejects(client.get("/v2/policy"), (error) => {
      assertNoWindow(error.message, form, 8, `straddling ${form}`);
      assert.match(error.message, /x{20,} \[REDACTED\]/, error.message);
      return true;
    });
  }
});

test("configured secrets echoed by an error body in every encoded form never reach a probe, finding, analysis error, bundle file, or zip entry", async () => {
  const prismaForms = secretForms(FIXTURE_SECRET_KEY);
  const panosForms = secretForms(FIXTURE_PANOS_PASSWORD);
  assert.equal(prismaForms.length, 3, "a name-shaped secret has three distinct forms (plain, base64, base64url)");
  assert.equal(panosForms.length, 5);
  const cases = [
    ["prisma-cloud /login", prismaForms, () => jsonResponse({ message: echoedSecretsMessage(prismaForms) }, { status: 400 })],
    ["prisma-cloud /v2/policy", prismaForms, () => jsonResponse({ message: echoedSecretsMessage(prismaForms) }, { status: 400 })],
    ["prisma-compute /defenders", prismaForms, () => jsonResponse({ err: echoedSecretsMessage(prismaForms) }, { status: 400 })],
    ["fw1.example.com keygen", panosForms, () => xmlResponse(`<response status="error" code="403"><result><msg>${echoedSecretsMessage(panosForms)}</msg></result></response>`, 403)],
    ["fw2.example.com /config/shared", panosForms, () => xmlResponse(`<response status="error" code="403"><result><msg>${echoedSecretsMessage(panosForms)}</msg></result></response>`, 403)],
  ];
  for (const [surface, forms, make] of cases) {
    const body = await make().text();
    // Fixture self-check: the message the server sends carries every form verbatim.
    const message = body.startsWith("{") ? Object.values(JSON.parse(body))[0] : body;
    for (const form of forms) assert.ok(message.includes(form), `fixture self-check: ${surface} echoes ${form}`);
    const clients = createPaloaltoClients(sweepConfig(), sweepFetch(surface, make));
    const access = await checkPaloaltoAccess(clients);
    const failed = access.surfaces.filter((probe) => probe.status !== "readable");
    assert.ok(failed.length >= 1, surface);
    for (const probe of failed) assert.match(probe.error, ECHOED_MARKER, `${surface}: ${probe.name}: ${probe.error}`);
    assertNoCanary(JSON.stringify(access), `${surface} access`, forms);

    const bundle = await exportPaloaltoAuditBundle(clients, createTempBase("grclanker-paloalto-echoed-secrets-"));
    const files = readBundleFiles(bundle.outputDir);
    for (const [name, text] of files) assertNoCanary(text, `${surface} bundle ${name}`, forms);
    for (const [name, text] of readZipEntries(bundle.zipPath)) assertNoCanary(text, `${surface} zip ${name}`, forms);
    for (const line of files.get("_errors.log").trim().split("\n")) assert.match(line, ECHOED_MARKER, `${surface}: ${line}`);
  }
});

test("error-body canary sweep: every Palo Alto surface on every device failing with an HTML 502 or a JSON/XML error body leaks no credential into any probe, finding, summary, or bundle file", async () => {
  assert.equal(PALOALTO_SURFACES.length, 10 + 13 + 16, "every endpoint the clients read is enumerated, per device");
  const shapes = [
    { name: "html-502", make: () => htmlCanaryResponse(), markers: HTML_MARKERS },
    { name: "structured-error", make: (product) => (product === "pan-os" ? xmlCanaryResponse() : jsonCanaryResponse()), markers: STRUCTURED_MARKERS },
  ];
  const productOf = (surface) => (surface.startsWith("prisma-cloud ") ? "prisma-cloud" : surface.startsWith("prisma-compute ") ? "prisma-compute" : "pan-os");
  // Surfaces the access check does not probe directly (Compute registry scans, images, and
  // compliance stats are collector-only) still flow through the collectors and _errors.log.
  const unprobed = new Set(["prisma-cloud /meta_info", "prisma-compute /registry", "prisma-compute /images", "prisma-compute /stats/compliance"]);
  for (const shape of shapes) {
    for (const surface of PALOALTO_SURFACES) {
      const product = productOf(surface);
      const label = `${shape.name} on ${surface}`;
      const marker = shape.markers[product];
      const clients = createPaloaltoClients(sweepConfig(), sweepFetch(surface, () => shape.make(product)));
      const bundle = await exportPaloaltoAuditBundle(clients, createTempBase("grclanker-paloalto-canary-"));
      const files = readBundleFiles(bundle.outputDir);
      const zipEntries = readZipEntries(bundle.zipPath);
      assert.equal(zipEntries.size, files.size, `${label}: the zip carries exactly the written files`);
      for (const [name, text] of files) assertNoCanary(text, `${label} bundle ${name}`);
      for (const [name, text] of zipEntries) assertNoCanary(text, `${label} zip ${name}`);

      const access = JSON.parse(files.get(join("core_data", "access.json")));
      const failedProbes = access.surfaces.filter((entry) => entry.status !== "readable");
      if (surface === "prisma-compute /authenticate") {
        // The Compute token exchange falls back to the CSPM JWT, so nothing fails and nothing is recorded.
        assert.equal(failedProbes.length, 0, label);
        assert.equal(bundle.errorCount, 0, label);
        assert.equal(access.status, "healthy", label);
        continue;
      }
      if (!unprobed.has(surface)) assert.ok(failedProbes.length >= 1, `${label}: the failing surface must probe as not readable`);
      for (const probe of failedProbes) {
        assert.equal(probe.status, "not_readable", `${label}: ${probe.name} status`);
        assert.match(probe.error, marker, `${label}: probe ${probe.name} must carry the note: ${probe.error}`);
        assert.doesNotMatch(probe.error, ECHOED_BODY_TEXT, `${label}: body text echoed into probe ${probe.name}: ${probe.error}`);
      }
      for (const note of access.notes) assert.doesNotMatch(note, ECHOED_BODY_TEXT, `${label}: body text echoed into a note: ${note}`);

      assert.ok(bundle.errorCount >= 1, `${label}: the failing surface must be recorded as a collection error`);
      const errorLog = files.get("_errors.log");
      assert.ok(errorLog !== undefined, `${label}: _errors.log must exist`);
      for (const line of errorLog.trim().split("\n")) {
        assert.match(line, marker, `${label}: every error must carry the note: ${line}`);
        assert.doesNotMatch(line, ECHOED_BODY_TEXT, `${label}: body text echoed: ${line}`);
      }
      const findings = JSON.parse(files.get(join("analysis", "findings.json")));
      for (const item of findings) {
        if (marker.test(item.summary) || marker.test(JSON.stringify(item.evidence ?? {}))) {
          assert.notEqual(item.status, "pass", `${label}: ${item.id} passed while naming the failed read`);
        }
      }
      assert.ok(findings.some((item) => item.status === "manual"), `${label}: the failed read must leave at least one finding manual`);
      for (const analysis of ["cloud_posture", "firewall_policy", "threat_prevention", "device_hardening"]) {
        const result = JSON.parse(files.get(join("analysis", `${analysis}.json`)));
        for (const error of result.errors) assert.match(error, marker, `${label}: ${analysis} error must carry the note: ${error}`);
      }
    }
  }
});

test("the registered tools scrub error strings end to end over HTTP: access check, every assess tool, and the export", async () => {
  const failing = new Map();
  const upstream = mockedFetch();
  let port = 0;
  // Bridges real HTTP requests from the tools onto the mocked fixtures: /prisma, /compute,
  // and /panos prefixes stand in for the three hosts, and /meta_info points Compute
  // discovery back at this server.
  const server = createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", async () => {
      const match = /^\/(prisma|compute|panos)(\/.*)$/.exec(request.url);
      const origin = match[1] === "prisma" ? "https://api2.prismacloud.io" : match[1] === "compute" ? "https://compute.example.com" : "https://fw1.example.com";
      const target = `${origin}${match[2]}`;
      const init = { method: request.method, body: request.method === "POST" ? body : undefined };
      const key = paloaltoRouteKey(target, init);
      const upstreamResponse = failing.has(key)
        ? failing.get(key)()
        : key === "prisma-cloud /meta_info"
          ? jsonResponse({ twistlockUrl: `http://127.0.0.1:${port}/compute` })
          : await upstream(target, init);
      const text = await upstreamResponse.text();
      response.writeHead(upstreamResponse.status, Object.fromEntries(upstreamResponse.headers));
      response.end(text);
    });
  });
  await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  port = server.address().port;

  const tools = new Map();
  registerPaloaltoTools({ registerTool: (tool) => tools.set(tool.name, tool) });
  const baseArgs = {
    prisma_api_url: `http://127.0.0.1:${port}/prisma`,
    prisma_access_key_id: "key",
    prisma_secret_key: FIXTURE_SECRET_KEY,
    panos_hosts: `http://127.0.0.1:${port}/panos`,
    panos_api_key: "LUFRPT-key",
  };
  const run = async (name, extra = {}) => {
    const tool = tools.get(name);
    return tool.execute("call-sweep", tool.prepareArguments({ ...baseArgs, ...extra }));
  };
  const anyMarker = (markers) => new RegExp([markers["prisma-cloud"], markers["pan-os"]].map((pattern) => pattern.source).join("|"));
  // Every form of both products' configured secrets, echoed by every failing surface: a
  // Prisma Cloud error carrying the PAN-OS key (or the reverse) is scrubbed by nothing but
  // the tool boundary, which knows every configured secret.
  const crossProductForms = [...secretForms(FIXTURE_SECRET_KEY), ...secretForms(baseArgs.panos_api_key)];
  const echoedSecretsJson = () => jsonResponse({ message: echoedSecretsMessage(crossProductForms) }, { status: 400 });
  const echoedSecretsXml = () => xmlResponse(`<response status="error" code="403"><result><msg>${echoedSecretsMessage(crossProductForms)}</msg></result></response>`, 403);
  const echoedMarkers = { "prisma-cloud": ECHOED_MARKER, "prisma-compute": ECHOED_MARKER, "pan-os": ECHOED_MARKER };

  try {
    for (const shape of [
      { name: "structured-error", prisma: jsonCanaryResponse, panos: xmlCanaryResponse, markers: STRUCTURED_MARKERS, canaries: CANARIES },
      { name: "html-502", prisma: htmlCanaryResponse, panos: htmlCanaryResponse, markers: HTML_MARKERS, canaries: CANARIES },
      { name: "echoed-secrets", prisma: echoedSecretsJson, panos: echoedSecretsXml, markers: echoedMarkers, canaries: [...CANARIES, ...crossProductForms] },
    ]) {
      failing.clear();
      failing.set("prisma-cloud /v2/policy", shape.prisma);
      failing.set("prisma-compute /defenders", shape.prisma);
      failing.set("fw1.example.com /config/mgt-config", shape.panos);
      const marker = anyMarker(shape.markers);

      const access = await run("paloalto_check_access");
      assertNoCanary(JSON.stringify(access), `${shape.name} paloalto_check_access`, shape.canaries);
      assert.notEqual(access.isError, true, access.content[0].text);
      assert.equal(access.details.status, "degraded");
      const failedProbes = access.details.surfaces.filter((probe) => probe.status !== "readable");
      assert.deepEqual(failedProbes.map((probe) => probe.name).sort(), ["defenders", "mgt-config", "policies"]);
      for (const probe of failedProbes) assert.match(probe.error, shape.markers[probe.product], `${shape.name}: ${probe.name}: ${probe.error}`);
      assert.doesNotMatch(access.content[0].text, ECHOED_BODY_TEXT);
      // The Note column is capped at 80 characters, so only the head of the note is guaranteed to render.
      assert.match(access.content[0].text, /non-JSON text\/html response body|non-XML text\/html response|\[REDACTED\]/, "the rendered table carries the note or the marker");

      for (const name of ["paloalto_assess_cloud_posture", "paloalto_assess_firewall_policy", "paloalto_assess_threat_prevention", "paloalto_assess_device_hardening"]) {
        const result = await run(name);
        assertNoCanary(JSON.stringify(result), `${shape.name} ${name}`, shape.canaries);
        assert.notEqual(result.isError, true, result.content[0].text);
        assert.ok(result.details.errors.length >= 1, `${name}: the failing surfaces must be recorded`);
        for (const error of result.details.errors) {
          assert.match(error, marker, `${shape.name} ${name}: ${error}`);
          assert.doesNotMatch(error, ECHOED_BODY_TEXT, error);
        }
        assert.doesNotMatch(result.content[0].text, ECHOED_BODY_TEXT);
      }

      const exported = await run("paloalto_export_audit_bundle", { output_dir: createTempBase("grclanker-paloalto-tool-export-") });
      assertNoCanary(JSON.stringify(exported), `${shape.name} paloalto_export_audit_bundle`, shape.canaries);
      assert.notEqual(exported.isError, true, exported.content[0].text);
      const files = readBundleFiles(exported.details.output_dir);
      for (const [name, text] of files) assertNoCanary(text, `${shape.name} tool bundle ${name}`, shape.canaries);
      for (const [name, text] of readZipEntries(exported.details.zip_path)) assertNoCanary(text, `${shape.name} tool zip ${name}`, shape.canaries);
      for (const line of files.get("_errors.log").trim().split("\n")) assert.match(line, marker, line);
    }
  } finally {
    server.close();
  }
});

// ---------------------------------------------------------------------------
// Rule 10: pagination exits that must report truncation, with the reason
// ---------------------------------------------------------------------------

test("collectOpenAlerts reports every exit other than the cursor ending as truncated with the reason, and the dependent findings demote", async () => {
  const alert = (id) => ({ id, policy: { name: `policy-${id}`, policyType: "config", severity: "low" } });
  const scripted = (pages) => {
    let index = 0;
    return new PrismaCloudClient({ apiUrl: "https://api2.prismacloud.io", accessKeyId: "k", secretKey: "s" }, {
      fetchImpl: async (input) => {
        if (new URL(input).pathname === "/login") return jsonResponse({ token: "jwt" });
        const page = pages[Math.min(index, pages.length - 1)];
        index += 1;
        return jsonResponse(page);
      },
      sleepImpl: noSleep,
    });
  };

  const emptyPage = await scripted([{ items: [alert(1)], nextPageToken: "t1" }, { items: [], nextPageToken: "t2" }]).collectOpenAlerts(50);
  assert.equal(emptyPage.truncated, true);
  assert.equal(emptyPage.items.length, 1);
  assert.match(emptyPage.truncationReason, /empty page while still returning a nextPageToken/);

  const stuck = await scripted([{ items: [alert(1)], nextPageToken: "t1" }, { items: [alert(2)], nextPageToken: "t1" }]).collectOpenAlerts(50);
  assert.equal(stuck.truncated, true);
  assert.equal(stuck.items.length, 2);
  assert.match(stuck.truncationReason, /repeated a nextPageToken \(stuck cursor\)/);

  const capped = await scripted([{ items: [alert(1), alert(2)], nextPageToken: "t1" }, { items: [alert(3), alert(4)], nextPageToken: "t2" }]).collectOpenAlerts(3);
  assert.equal(capped.truncated, true);
  assert.equal(capped.items.length, 3, "the cap is never exceeded");
  assert.match(capped.truncationReason, /alert_limit 3 reached/);

  const surplus = await scripted([{ items: [alert(1), alert(2), alert(3)] }]).collectOpenAlerts(2);
  assert.equal(surplus.truncated, true, "a server that ignores the limit parameter still reports truncation");
  assert.equal(surplus.items.length, 2);

  const undercount = await scripted([{ items: [alert(1)], totalRows: 7 }]).collectOpenAlerts(50);
  assert.equal(undercount.truncated, true);
  assert.match(undercount.truncationReason, /totalRows 7 but the cursor ended after 1 alerts/);

  const complete = await scripted([{ items: [alert(1)], nextPageToken: "t1", totalRows: 2 }, { items: [alert(2)], totalRows: 2 }]).collectOpenAlerts(50);
  assert.equal(complete.truncated, false);
  assert.equal(complete.truncationReason, undefined);
  assert.equal(complete.items.length, 2);

  const source = {
    getCompliancePosture: async () => prismaSnapshot().posture,
    listAlertRules: async () => prismaSnapshot().alertRules,
    collectOpenAlerts: async () => stuck,
    listPolicies: async () => prismaSnapshot().policies,
    listCloudAccounts: async () => prismaSnapshot().cloudAccounts,
    listAccountGroups: async () => prismaSnapshot().accountGroups,
    listUserRoles: async () => prismaSnapshot().userRoles,
    listIntegrations: async () => prismaSnapshot().integrations,
  };
  const snapshot = await collectPrismaSnapshot(source, 50);
  assert.equal(snapshot.alertsTruncated, true);
  assert.match(snapshot.alertsTruncationReason, /stuck cursor/);
  const findings = assessPrismaCloudPosture(snapshot);
  for (const id of ["PA-02", "PA-03", "PA-05", "PA-06"]) {
    assert.equal(byId(findings, id).status, "warn", `${id}: ${byId(findings, id).summary}`);
    assert.match(byId(findings, id).summary, /Partial inventory: open alerts truncated at 2 \(GET \/v2\/alert repeated a nextPageToken \(stuck cursor\)/);
    assert.deepEqual(byId(findings, id).evidence.partial_inventory.length, 1);
  }
  assert.equal(byId(findings, "PA-01").status, "pass", "a finding that does not read alerts is not demoted");
  const result = await assessPaloaltoCloudPosture(createPaloaltoClients(bothProductsConfig(), mockedFetch()), {}, snapshot);
  assert.equal(result.summary.open_alerts_truncated, true);
  assert.match(result.summary.open_alerts_truncation_reason, /stuck cursor/);
  assert.equal(result.summary.open_alerts_sampled, 2);
});

test("Compute listPaged reports a stuck offset and the record cap as truncated with the reason, and PA-10 demotes", async () => {
  const fullPage = (offset, distinct) => Array.from({ length: 50 }, (_, index) => ({ hostname: distinct ? `node-${offset + index}` : `node-${index}`, connected: true, version: "34.00.100", lastModified: "2026-09-01T00:00:00Z" }));
  const client = (distinct) => {
    const fetchImpl = async (input) => {
      const url = new URL(input);
      if (url.pathname === "/login") return jsonResponse({ token: "jwt" });
      if (url.pathname === "/api/v1/authenticate") return jsonResponse({ token: "compute-token" });
      if (url.pathname.startsWith("/api/v1/policies")) return jsonResponse({ rules: [] });
      if (url.pathname === "/api/v1/settings/registry") return jsonResponse({ specifications: [] });
      if (url.pathname === "/api/v1/stats/compliance") return jsonResponse({ rules: [], categories: [] });
      if (url.pathname === "/api/v1/stats/vulnerabilities") return jsonResponse([]);
      return jsonResponse(fullPage(Number(url.searchParams.get("offset")), distinct));
    };
    return new PrismaComputeClient("https://compute.example.com", new PrismaCloudClient({ apiUrl: "https://api2.prismacloud.io", accessKeyId: "k", secretKey: "s" }, { fetchImpl, sleepImpl: noSleep }));
  };

  const stuck = await client(false).listDefenders(1000);
  assert.equal(stuck.truncated, true);
  assert.equal(stuck.items.length, 50, "the repeated page is not appended twice");
  assert.match(stuck.truncationReason, /returned the same page for offset 50 as for the previous offset \(stuck offset\)/);

  const capped = await client(true).listDefenders(120);
  assert.equal(capped.truncated, true);
  assert.equal(capped.items.length, 150);
  assert.match(capped.truncationReason, /capped at 120 records while full pages were still being returned/);

  const compute = await collectComputeSnapshot(client(false));
  assert.deepEqual(compute.failed, []);
  assert.deepEqual(compute.truncated, ["defenders", "registry scans", "images", "cloud discovery", "ci scans"]);
  assert.match(compute.truncationReasons.defenders, /stuck offset/);
  const findings = assessPrismaCompute(prismaSnapshot({ compute }));
  assert.equal(byId(findings, "PA-10").status, "warn");
  assert.match(byId(findings, "PA-10").summary, /Partial inventory: prisma-compute defenders truncated \(GET \/api\/v1\/defenders returned the same page for offset 50/);
  assert.equal(byId(findings, "PA-10").evidence.defenders, 50);
});

test("checkPaloaltoAccess marks probes that stopped at the page cap as partial with lower-bound counts", async () => {
  const healthy = mockedFetch();
  const fetchImpl = async (input, init) => {
    const url = new URL(input);
    if (url.hostname.endsWith("prismacloud.io") && url.pathname === "/v2/alert") {
      return jsonResponse({ items: Array.from({ length: 100 }, (_, index) => ({ id: index })), nextPageToken: "more", totalRows: 5000 });
    }
    if (url.hostname === "compute.example.com" && url.pathname === "/api/v1/defenders") {
      return jsonResponse(Array.from({ length: 50 }, (_, index) => ({ hostname: `node-${index}` })));
    }
    return healthy(input, init);
  };
  const result = await checkPaloaltoAccess(createPaloaltoClients(bothProductsConfig(), fetchImpl));
  assert.equal(result.status, "healthy", "a capped probe is readable, just not an inventory total");
  const alerts = result.surfaces.find((surface) => surface.name === "open_alerts");
  assert.equal(alerts.partial, true);
  assert.equal(alerts.count, 100);
  const defenders = result.surfaces.find((surface) => surface.name === "defenders");
  assert.equal(defenders.partial, true);
  assert.equal(defenders.count, 50);
  assert.ok(result.surfaces.filter((surface) => surface.partial).length === 2);
  assert.ok(result.notes.some((note) => /2 probes stopped at the page cap, so counts marked \+ are lower bounds, not inventory totals/.test(note)), result.notes.join("\n"));
  const plain = await checkPaloaltoAccess(createPaloaltoClients(bothProductsConfig(), healthy));
  assert.ok(plain.surfaces.every((surface) => surface.partial === undefined));
  assert.ok(!plain.notes.some((note) => /page cap/.test(note)));
});

// ---------------------------------------------------------------------------
// Rule 1 corollary and uniform null rendering
// ---------------------------------------------------------------------------

test("PA-15 gates on /config/shared and renders mfa_authentication_profiles null when the shared tree was not read", () => {
  const sharedFailed = panosSnapshot({ failedXpaths: ["/config/shared"] });
  sharedFailed.config = sharedFailed.config.filter((tree) => !tree.children.some((child) => child.name === "shared"));
  const finding = byId(assessPanosDeviceHardening([sharedFailed]), "PA-15");
  assert.equal(finding.status, "manual", finding.summary);
  assert.match(finding.summary, /Evidence unavailable \(fw1\.example\.com config show failed for \/config\/shared\)/);
  assert.equal(finding.evidence.mfa_authentication_profiles, null, "the MFA list comes from the shared tree, so it is unknown rather than empty");
  assert.deepEqual(finding.evidence.portals, ["fw1.example.com/portal"], "GlobalProtect objects from the readable vsys tree are still reported");
  assert.deepEqual(finding.evidence.unreadable_sources, ["fw1.example.com config show failed for /config/shared"]);

  const networkFailed = panosSnapshot({ failedXpaths: ["/config/devices/entry/network"] });
  const gp = byId(assessPanosDeviceHardening([networkFailed]), "PA-15");
  assert.equal(gp.status, "manual");
  assert.equal(gp.evidence.portals, null);
  assert.equal(gp.evidence.gateways, null);

  const readable = byId(assessPanosDeviceHardening([panosSnapshot()]), "PA-15");
  assert.equal(readable.status, "pass");
  assert.deepEqual(readable.evidence.mfa_authentication_profiles, ["fw1.example.com/mfa-radius"]);
});

test("evidence and summaries derived from unreadable surfaces render null, never 0 or an empty list", async () => {
  const cspm = assessPrismaCloudPosture(prismaSnapshot({ failed: ["cloud accounts", "open alerts", "policies"] }));
  const accounts = byId(cspm, "PA-04");
  assert.equal(accounts.status, "manual");
  assert.equal(accounts.evidence.accounts, null);
  assert.equal(accounts.evidence.disabled_accounts, null);
  assert.equal(accounts.evidence.ungrouped_accounts, null);
  assert.equal(accounts.evidence.account_groups, 1, "the readable half keeps its value");
  const rules = byId(cspm, "PA-02");
  assert.equal(rules.status, "manual");
  assert.deepEqual(rules.evidence.open_alerts, { count: null, critical: null, high: null, top_policies: null });
  assert.deepEqual(rules.evidence.enabled_rules, ["all-critical"]);
  const iam = byId(cspm, "PA-03");
  assert.equal(iam.evidence.iam_policies, null);
  assert.equal(iam.evidence.iam_policies_enabled, null);
  assert.equal(iam.evidence.iam_alerts.count, null);
  const network = byId(cspm, "PA-05");
  assert.equal(network.evidence.network_policies_enabled, null);
  assert.equal(network.evidence.count, null);
  assert.equal(network.evidence.top_policies, null);
  const encryption = byId(cspm, "PA-06");
  assert.equal(encryption.evidence.encryption_policies, null);
  assert.equal(encryption.evidence.encryption_alerts.critical, null);
  const posture = byId(assessPrismaCloudPosture(prismaSnapshot({ failed: ["compliance posture"] })), "PA-01");
  assert.equal(posture.status, "manual");
  assert.equal(posture.evidence.passed_resources, null);
  assert.equal(posture.evidence.failed_resources, null);
  assert.equal(posture.evidence.standards, null);

  const compute = assessPrismaCompute(prismaSnapshot({ compute: computeSnapshot({ failed: ["defenders", "images", "registry scans", "cloud discovery", "ci scans", "compliance stats"] }) }));
  assert.equal(byId(compute, "PA-07").evidence.images_scanned, null);
  assert.equal(byId(compute, "PA-07").evidence.critical_cves, null);
  assert.equal(byId(compute, "PA-07").evidence.vulnerability_rules_enabled, 1, "the readable policy keeps its count");
  assert.equal(byId(compute, "PA-08").evidence.connected_defenders, null);
  assert.equal(byId(compute, "PA-08").evidence.compliance_rate, null);
  assert.equal(byId(compute, "PA-08").evidence.compliance_total, null);
  assert.equal(byId(compute, "PA-08").evidence.host_rules_enabled, 1);
  assert.equal(byId(compute, "PA-09").evidence.connected_defenders, null);
  assert.deepEqual(byId(compute, "PA-09").evidence.protective_rules, ["default"]);
  assert.equal(byId(compute, "PA-10").evidence.defenders, null);
  assert.equal(byId(compute, "PA-10").evidence.disconnected, null);
  assert.equal(byId(compute, "PA-10").evidence.versions, null);
  assert.equal(byId(compute, "PA-11").evidence.registry_scans, null);
  assert.deepEqual(byId(compute, "PA-11").evidence.registries, ["registry.example.com/*"]);
  assert.equal(byId(compute, "PA-24").evidence.discovery_entries, null);
  assert.equal(byId(compute, "PA-24").evidence.unprotected, null);
  assert.equal(byId(compute, "PA-25").evidence.ci_scans, null);
  assert.equal(byId(compute, "PA-25").evidence.failed_scans, null);
  for (const id of ["PA-07", "PA-08", "PA-09", "PA-10", "PA-11", "PA-24", "PA-25"]) assert.equal(byId(compute, id).status, "manual", id);

  const admin = assessAdminAccess(prismaSnapshot({ failed: ["user roles"] }), [panosSnapshot({ failedXpaths: ["/config/mgt-config"] })]);
  assert.equal(admin.status, "manual");
  assert.equal(admin.evidence.panos_admins, null);
  assert.equal(admin.evidence.panos_local_password_only, null);
  assert.equal(admin.evidence.password_complexity_by_device, null);
  assert.equal(admin.evidence.prisma_roles, null);
  const adminRolesOnly = assessAdminAccess(prismaSnapshot({ failed: ["user roles"] }), [panosSnapshot()]);
  assert.equal(adminRolesOnly.evidence.prisma_roles, null);
  assert.deepEqual(adminRolesOnly.evidence.panos_admins, ["fw1.example.com/admin (superuser)", "fw1.example.com/auditor"]);

  const logging = assessLogging(prismaSnapshot({ failed: ["integrations"] }), [panosSnapshot({ failedXpaths: ["/config/devices/entry/deviceconfig"] })]);
  assert.equal(logging.status, "manual");
  assert.equal(logging.evidence.prisma_integrations, null);
  assert.equal(logging.evidence.syslog_server_profiles, null);
  assert.equal(logging.evidence.log_forwarding_profiles, null);
  assert.equal(logging.evidence.panorama_forwarding, null);
  assert.deepEqual(logging.evidence.unlogged_rules, [], "rule logging came from the readable vsys tree, so its empty list is real");

  const clients = createPaloaltoClients(bothProductsConfig(), mockedFetch());
  const cloud = await assessPaloaltoCloudPosture(clients, {}, prismaSnapshot({ failed: ["cloud accounts", "open alerts"], compute: computeSnapshot({ failed: ["defenders"], truncated: ["images"] }) }));
  assert.equal(cloud.summary.cloud_accounts, null);
  assert.equal(cloud.summary.open_alerts_sampled, null);
  assert.equal(cloud.summary.open_alerts_truncated, null);
  assert.equal(cloud.summary.open_alerts_truncation_reason, null);
  assert.deepEqual(cloud.summary.unreadable_surfaces, ["prisma-cloud cloud accounts", "prisma-cloud open alerts", "prisma-compute defenders"]);
  assert.deepEqual(cloud.summary.truncated_surfaces, ["prisma-compute images"]);
  const healthySummary = (await assessPaloaltoCloudPosture(clients)).summary;
  assert.equal(healthySummary.cloud_accounts, 1);
  assert.equal(healthySummary.open_alerts_sampled, 0);
  assert.equal(healthySummary.open_alerts_truncated, false);
  assert.deepEqual(healthySummary.unreadable_surfaces, []);

  const devices = [panosSnapshot(), panosSnapshot({ host: "fw2.example.com", reachable: false, haStateFailed: true, failedXpaths: ["/config/shared"] })];
  const threat = await assessPaloaltoThreatPrevention(clients, devices, prismaSnapshot({ failed: ["policies"] }));
  assert.equal(threat.summary.devices, 2);
  assert.deepEqual(threat.summary.unreachable_hosts, ["fw2.example.com"]);
  assert.deepEqual(threat.summary.failed_xpaths, ["fw2.example.com: /config/shared"]);
  assert.deepEqual(threat.summary.ha_state_unreadable, ["fw2.example.com"]);
  assert.deepEqual(threat.summary.prisma_unreadable_surfaces, ["prisma-cloud policies"]);
  const hardening = await assessPaloaltoDeviceHardening(clients, {}, devices, prismaSnapshot());
  assert.deepEqual(hardening.summary.unreachable_hosts, ["fw2.example.com"]);
  assert.deepEqual(hardening.summary.prisma_unreadable_surfaces, []);
  const firewall = await assessPaloaltoFirewallPolicy(clients, devices);
  assert.deepEqual(firewall.summary.platforms, ["fw1.example.com: firewall", "fw2.example.com: firewall"]);
  assert.ok(firewall.findings.every((item) => item.status === "manual"), "an unreachable device leaves every multi-device finding manual");
});

/** Wraps a fetch so every request and the status it received are on record for request matching. */
function recordingPaloaltoFetch(inner) {
  const requests = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(input);
    const entry = { method: init.method ?? "GET", host: url.hostname, path: url.pathname, query: Object.fromEntries(url.searchParams), status: null };
    requests.push(entry);
    const response = await inner(input, init);
    entry.status = response.status;
    return response;
  };
  return { fetchImpl, requests };
}

/** Whether a "METHOD /path[?a=b&c=d]" label with the given status names a request the run actually made and the status it received. */
function paloaltoRequestObserved(requests, endpoint, status) {
  const [method, rest] = endpoint.split(" ");
  const [path, query = ""] = rest.split("?");
  const pairs = query ? query.split("&").map((pair) => pair.split(/=(.*)/s).slice(0, 2)) : [];
  return requests.some((request) =>
    request.method === method
    && request.path === path
    && pairs.every(([name, value]) => request.query[name] === value)
    && (status === null || request.status === status),
  );
}

/** Every object carrying an endpoint, with the HTTP status it names (http_status on a status entry, status on a marker). */
function endpointMentions(value, path = []) {
  if (Array.isArray(value)) return value.flatMap((item, index) => endpointMentions(item, [...path, String(index)]));
  if (!value || typeof value !== "object") return [];
  const mentions = Object.entries(value).flatMap(([key, child]) => endpointMentions(child, [...path, key]));
  if (typeof value.endpoint === "string") {
    const status = typeof value.http_status === "number" ? value.http_status : typeof value.httpStatus === "number" ? value.httpStatus : typeof value.status === "number" ? value.status : null;
    mentions.push({ at: path.join("."), endpoint: value.endpoint, status });
  }
  return mentions;
}

test("addendum 5: denied CSPM, Compute, and PAN-OS reads write not-collected markers naming the failed request and its status, never an empty value", async () => {
  const { fetchImpl, requests } = recordingPaloaltoFetch(mockedFetch({ integrationsDenied: true, mgtDenied: true, registryDenied: true, alertsDenied: true }));
  const clients = createPaloaltoClients({ ...bothProductsConfig(), retryAttempts: 0 }, fetchImpl);
  const access = await checkPaloaltoAccess(clients);
  const result = await exportPaloaltoAuditBundle(clients, createTempBase("grclanker-paloalto-markers-"));
  const files = readBundleFiles(result.outputDir);

  const prisma = JSON.parse(files.get(join("core_data", "prisma_cloud.json")));
  assert.deepEqual(prisma.integrations, { collected: false, status: 403, dataset_status: "forbidden", endpoint: "GET /integration", error: prisma.integrations.error });
  assert.match(prisma.integrations.error, /403/);
  assert.equal(prisma.collection.integrations.status, "forbidden");
  assert.equal(prisma.collection.integrations.http_status, 403);
  assert.equal(prisma.collection.integrations.seen, null, "a refused read never counts 0");
  assert.equal(prisma.collection.integrations.truncated, null);
  assert.equal(prisma.open_alerts.collected, false);
  assert.equal(prisma.open_alerts.status, 502);
  assert.equal(prisma.open_alerts.dataset_status, "error");
  assert.equal(prisma.open_alerts.endpoint, "GET /v2/alert");
  assert.match(prisma.open_alerts.error, /502.*text\/html.*bytes, not echoed/);
  assert.equal(prisma.open_alerts_truncated, null, "no alert walk happened, so it was neither complete nor truncated");
  assert.equal(prisma.open_alerts_total, null);
  assert.equal(prisma.collection.open_alerts.truncated, null);
  assert.equal(prisma.collection.policies.status, "ok");
  assert.equal(prisma.collection.policies.seen, prisma.policies.length);
  assert.deepEqual(prisma.compute.registry_settings, { collected: false, status: 403, dataset_status: "forbidden", endpoint: "GET /api/v1/settings/registry", error: prisma.compute.registry_settings.error });
  assert.equal(prisma.compute.collection.registry_settings.http_status, 403);
  assert.equal(prisma.compute.collection.registry_settings.seen, null);
  assert.equal(prisma.compute.collection.defenders.status, "ok");

  const device = JSON.parse(files.get(join("core_data", "panos_fw1.example.com.json")));
  assert.deepEqual(device.config["/config/mgt-config"], { collected: false, status: 403, dataset_status: "forbidden", endpoint: "GET /api/?type=config&action=show&xpath=/config/mgt-config", error: device.config["/config/mgt-config"].error });
  assert.match(device.config["/config/mgt-config"].error, /Insufficient privileges/);
  assert.ok(device.config["/config/shared"].shared, "the readable subtrees keep their content");
  assert.equal(device.collection["/config/mgt-config"].status, "forbidden");
  assert.equal(device.collection["/config/mgt-config"].http_status, 403);
  assert.equal(device.collection["/config/mgt-config"].seen, null);
  assert.equal(device.collection.system_info.status, "ok");
  assert.equal(device.collection.system_info.endpoint, "GET /api/?type=op&cmd=<show><system><info></info></system></show>");
  assert.equal(device.collection.ha_state.status, "ok");

  const mentions = [
    ...endpointMentions(prisma, ["prisma_cloud.json"]),
    ...endpointMentions(device, ["panos_fw1.example.com.json"]),
    ...endpointMentions(JSON.parse(files.get(join("core_data", "access.json"))), ["access.json"]),
    ...endpointMentions(access, ["check_access"]),
  ];
  assert.ok(mentions.length >= 8 + 12 + 7 + 24, `every surface is mentioned with its request (${mentions.length})`);
  for (const mention of mentions) {
    assert.ok(paloaltoRequestObserved(requests, mention.endpoint, mention.status), `${mention.at} names ${mention.endpoint} (status ${mention.status}) but no such request was made`);
  }
  const forbiddenMentions = mentions.filter((mention) => mention.status === 403);
  assert.deepEqual([...new Set(forbiddenMentions.map((mention) => mention.endpoint))].sort(), ["GET /api/?type=config&action=show&xpath=/config/mgt-config", "GET /api/v1/settings/registry", "GET /integration"]);
  assert.deepEqual([...new Set(mentions.filter((mention) => mention.status === 502).map((mention) => mention.endpoint))], ["GET /v2/alert"]);

  const assessment = await assessPaloaltoCloudPosture(clients);
  assert.equal(assessment.summary.collection.prisma_cloud.integrations.http_status, 403);
  assert.equal(assessment.summary.collection.prisma_cloud.open_alerts.seen, null);
  assert.equal(assessment.summary.collection.prisma_compute.registry_settings.status, "forbidden");
  for (const mention of endpointMentions(assessment.summary, ["summary"])) {
    assert.ok(paloaltoRequestObserved(requests, mention.endpoint, mention.status), `${mention.at} names ${mention.endpoint}`);
  }
});

test("addendum 5: an unreachable Compute console writes an unavailable marker naming the /meta_info request, and a transport failure records a null status", async () => {
  const { fetchImpl, requests } = recordingPaloaltoFetch(async (input, init) => {
    const url = new URL(input);
    if (url.pathname === "/meta_info") return jsonResponse({ message: "meta_info is disabled for this role" }, { status: 403 });
    return mockedFetch()(input, init);
  });
  const clients = createPaloaltoClients({ ...bothProductsConfig(), retryAttempts: 0 }, fetchImpl);
  const result = await exportPaloaltoAuditBundle(clients, createTempBase("grclanker-paloalto-compute-marker-"));
  const prisma = JSON.parse(readBundleFiles(result.outputDir).get(join("core_data", "prisma_cloud.json")));
  assert.equal(prisma.compute.collected, false);
  assert.equal(prisma.compute.dataset_status, "unavailable");
  assert.equal(prisma.compute.status, 403);
  assert.equal(prisma.compute.endpoint, "GET /meta_info");
  assert.match(prisma.compute.error, /Compute console discovery via CSPM \/meta_info failed/);
  assert.ok(paloaltoRequestObserved(requests, "GET /meta_info", 403));

  const offline = createPaloaltoClients(twoDeviceConfig(), async (input, init) => {
    const url = new URL(input);
    if (url.hostname === "fw2.example.com") throw new Error("connect ECONNREFUSED 10.0.0.2:443");
    return mockedFetch()(input, init);
  });
  const access = await checkPaloaltoAccess(offline);
  const fw2 = access.surfaces.filter((surface) => surface.target === "fw2.example.com");
  assert.ok(fw2.length >= 2);
  for (const surface of fw2) {
    assert.equal(surface.status, "not_readable");
    assert.equal(surface.httpStatus, null, "no response arrived, so no status is claimed");
    assert.equal(surface.count, null);
    assert.match(surface.error, /ECONNREFUSED/);
  }
  const systemInfoRead = "GET /api/?type=op&cmd=<show><system><info></info></system></show>";
  assert.equal(fw2.find((surface) => surface.name === "system_info").endpoint, systemInfoRead, "with an API key configured the read itself is the request that failed");
  const bundle = await exportPaloaltoAuditBundle(offline, createTempBase("grclanker-paloalto-offline-"));
  const device = JSON.parse(readBundleFiles(bundle.outputDir).get(join("core_data", "panos_fw2.example.com.json")));
  assert.equal(device.system_info.collected, false);
  assert.equal(device.system_info.status, null);
  assert.equal(device.system_info.dataset_status, "error");
  assert.equal(device.system_info.endpoint, systemInfoRead);
  assert.equal(device.collection.system_info.http_status, null);
  assert.equal(device.collection.system_info.seen, null);
  for (const xpath of FIREWALL_XPATHS) {
    assert.equal(device.config[xpath].collected, false, xpath);
    assert.equal(device.config[xpath].endpoint, `GET /api/?type=config&action=show&xpath=${xpath}`, xpath);
  }

  // A device that must generate its key names the keygen request when that is what failed.
  const keygenConfig = { ...resolvePaloaltoConfiguration({}, { PANOS_HOST: "fw3.example.com", PANOS_USERNAME: "auditor", PANOS_PASSWORD: "pw" }), retryAttempts: 0 };
  const keygenClients = createPaloaltoClients(keygenConfig, async () => { throw new Error("connect ETIMEDOUT 10.0.0.3:443"); });
  const keygenAccess = await checkPaloaltoAccess(keygenClients);
  assert.ok(keygenAccess.surfaces.length >= 2);
  for (const surface of keygenAccess.surfaces) {
    assert.equal(surface.endpoint, "POST /api/?type=keygen", surface.name);
    assert.equal(surface.httpStatus, null);
  }
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
    return jsonResponse({ rules: [] });
  };
  const cspm = new PrismaCloudClient({ apiUrl: "https://api2.prismacloud.io", accessKeyId: "key", secretKey: FIXTURE_SECRET_KEY }, { fetchImpl });
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

// Retries are disabled so the unreachable device fails immediately instead of sleeping
// through the exponential backoff; retry behavior has its own coverage above.
function twoDeviceConfig(extra = {}) {
  return {
    ...resolvePaloaltoConfiguration({}, {
      PRISMA_API_URL: "https://api2.prismacloud.io",
      PRISMA_ACCESS_KEY_ID: "key",
      PRISMA_SECRET_KEY: FIXTURE_SECRET_KEY,
      PANOS_HOST: "fw1.example.com,fw2.example.com",
      PANOS_API_KEY: "LUFRPT-key",
      ...extra,
    }),
    retryAttempts: 0,
  };
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
    { apiUrl: "https://api2.prismacloud.io", accessKeyId: "key", secretKey: FIXTURE_SECRET_KEY },
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
    { apiUrl: "https://api2.prismacloud.io", accessKeyId: "key", secretKey: FIXTURE_SECRET_KEY },
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
