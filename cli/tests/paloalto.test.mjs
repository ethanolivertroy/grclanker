import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

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
  checkPaloaltoAccess,
  collectPanosSnapshot,
  createPaloaltoClients,
  exportPaloaltoAuditBundle,
  parseXml,
  redactSecrets,
  resolvePaloaltoConfiguration,
  resolveSecureOutputPath,
  xmlFindAll,
  xmlPath,
  xmlText,
} from "../dist/extensions/grc-tools/paloalto.js";
import { getRegisteredToolSummaries } from "../dist/pi/tool-catalog.js";

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

function prismaSnapshot(overrides = {}) {
  const good = overrides.good !== false;
  return {
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
  assert.throws(() => resolvePaloaltoConfiguration({ config_file: "/nonexistent/paloalto.json" }, {}), /config file not found/);
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
  assert.equal(redactSecrets("https://fw/api/?type=op&key=LUFRPT123&cmd=x secret-value", ["secret-value"]), "https://fw/api/?type=op&key=[redacted]&cmd=x [redacted]");
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

function mockedFetch(options = {}) {
  return async (input, init = {}) => {
    const url = new URL(input);
    if (url.hostname.endsWith("prismacloud.io")) {
      if (url.pathname === "/login") return jsonResponse({ token: "jwt" });
      if (url.pathname === "/v2/compliance/posture") return jsonResponse(prismaSnapshot().posture);
      if (url.pathname === "/v2/alert/rule") return jsonResponse(prismaSnapshot().alertRules);
      if (url.pathname === "/v2/alert") return jsonResponse({ items: [] });
      if (url.pathname === "/v2/policy") return jsonResponse(prismaSnapshot().policies);
      if (url.pathname === "/cloud") return jsonResponse(prismaSnapshot().cloudAccounts);
      if (url.pathname === "/cloud/group") return jsonResponse(prismaSnapshot().accountGroups);
      if (url.pathname === "/user/role") return jsonResponse(prismaSnapshot().userRoles);
      if (url.pathname === "/integration") {
        return options.integrationsDenied ? jsonResponse([], { status: 403 }) : jsonResponse(prismaSnapshot().integrations);
      }
      return jsonResponse({}, { status: 404 });
    }
    const type = url.searchParams.get("type");
    if (type === "op") {
      return url.searchParams.get("cmd").includes("high-availability") ? xmlResponse(haXml()) : xmlResponse(systemInfoXml());
    }
    const xpath = url.searchParams.get("xpath");
    if (xpath.endsWith("/vsys")) return xmlResponse(panosSuccess(goodVsysXml()));
    if (xpath.endsWith("/network")) return xmlResponse(panosSuccess("<network/>"));
    if (xpath.endsWith("/deviceconfig")) return xmlResponse(panosSuccess(goodDeviceconfigXml()));
    if (xpath.endsWith("/shared")) return xmlResponse(panosSuccess(goodSharedXml()));
    if (xpath.endsWith("/mgt-config")) {
      return options.mgtDenied
        ? xmlResponse('<response status="error" code="403"><result><msg>Insufficient privileges</msg></result></response>', 403)
        : xmlResponse(panosSuccess(goodMgtConfigXml()));
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
  assert.deepEqual(result.products, ["prisma-cloud", "pan-os"]);
  assert.equal(result.surfaces.length, 8 + 2 + 5);
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
  assert.equal(byId(missing, "PA-01").status, "warn");
});

test("assessPaloaltoCloudPosture emits manual findings for Compute controls and for unconfigured Prisma Cloud", async () => {
  const configured = await assessPaloaltoCloudPosture(createPaloaltoClients(bothProductsConfig(), mockedFetch()));
  assert.equal(configured.findings.length, 13);
  assert.deepEqual(configured.findings.filter((item) => item.status === "manual").map((item) => item.control), [7, 8, 9, 10, 11, 24, 25]);
  assert.match(byId(configured.findings, "PA-10").summary, /Manual evidence required/);

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
  assert.equal(byId(manual, "PA-12").status, "warn");
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
  assert.equal(byId(bad, "PA-15").status, "pass");
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
  assert.deepEqual(partial.findings.map((item) => [item.id, item.status]), [["PA-15", "manual"], ["PA-19", "pass"], ["PA-20", "pass"], ["PA-23", "manual"]]);
  assert.match(byId(partial.findings, "PA-19").summary, /PAN-OS not configured/);
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
