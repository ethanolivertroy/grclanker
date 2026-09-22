import test from "node:test";
import assert from "node:assert/strict";

import {
  IntegrationError,
  LONG_TOKEN_MIN_LENGTH,
  REDACTED,
  errorMessage,
  redactSecretValues,
  scrubDataText,
  scrubError,
  scrubErrorText,
} from "../dist/extensions/grc-tools/hardening/error-text.js";
import { CANARY, assertRedactionCases } from "./helpers/error-canaries.mjs";
import { ENCODED_FORM_SECRET, ERROR_CANARY, assertNoCanaryWindowIn, assertNoFragment } from "./helpers/hardening-canaries.mjs";

/**
 * Coordinator addendum 7: a scrub in front of every error string can redact the identifying text a
 * corollary summary must keep, so a module-wide scrub ships with a must-keep and a must-redact table
 * as a test. Every must-keep value is asserted unchanged in isolation and inside realistic summary
 * sentences through each scrub the library exposes; every must-redact value is asserted absent down
 * to its 6-character windows. The rows are grouped by the addendum's categories, and the path-safety
 * rows name the shapes the long-token rule must leave alone: URL path segments, hyphenated lowercase
 * names, dotted hostnames, colon-separated ARNs, commands, and statements.
 */
const MUST_KEEP = Object.freeze([
  // requested endpoint paths (relative paths keep a benign query; an absolute URL keeps scheme, host, and path, see below)
  ["endpoint path", "/urlFilteringRules"],
  ["endpoint path", "/api/v1/adminUsers?page=1&pageSize=100"],
  ["endpoint path", "/v1/users?max_results=1000&per_page_limit_max=100&page=2"],
  ["endpoint path", "/api/v2/tenants/acme-corp-2026/users"],
  ["endpoint path", "/services/data/v60.0/sobjects/User/describe"],
  ["endpoint path", "/api/now/table/sys_user_has_role?sysparm_limit=10000&sysparm_fields=user_name,role"],
  ["endpoint path", "/admin/directory/v1/customer/my_customer/roleassignments"],
  ["endpoint path", "/2013-04-01/hostedzone/Z0123456789ABCDEFGHIJ/rrset"],
  ["endpoint URL", "https://zsapi.zscalerthree.net/api/v1/urlFilteringRules"],
  ["endpoint URL", "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token"],
  ["endpoint URL", "https://ec2-54-123-45-67.compute-1.amazonaws.com/latest/meta-data/iam/info"],
  // tenant, region, account, and org names with digits and hyphens
  ["tenant name", "prod-us-east-2026"],
  ["tenant name", "acme-corp-2026"],
  ["tenant name", "contoso.onmicrosoft.com"],
  ["tenant name", "tenant_prod_2026"],
  ["tenant name", "zscalerthree"],
  ["region name", "us-east-1"],
  ["region name", "europe-west2"],
  ["region name", "us-central1-a"],
  ["region name", "northamerica-northeast1"],
  ["account name", "123456789012"],
  ["account name", "my-project-123456"],
  ["account name", "xy12345.us-east-2.aws"],
  ["org name", "org-2026-security-audit"],
  ["org name", "snapshot-1718033988749"],
  ["org name", "my-bucket-prod-2026-logs"],
  // principal identifiers in vendor shapes
  ["principal", "alice.admin@example.com"],
  ["principal", "alice.admin_example.com#EXT#@contoso.onmicrosoft.com"],
  ["principal", "user:alice@example.com"],
  ["principal", "serviceAccount:deploy-bot-2026@my-project-123456.iam.gserviceaccount.com"],
  ["principal", "arn:aws:iam::123456789012:user/alice.admin"],
  ["principal", "arn:aws:iam::123456789012:role/OrganizationAccountAccessRole"],
  ["principal", "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_AdministratorAccess_0123456789abcdef/alice"],
  ["principal", "2f3c1a9e-7b6d-4c5e-8f9a-0b1c2d3e4f5a"],
  ["principal", "U01ABCDEFGH"],
  ["principal", "svc_backup_2026"],
  ["principal", "CN=Backup Operators,OU=Groups,DC=corp,DC=example,DC=com"],
  ["principal", "DOMAIN\\svc-backup-2026"],
  // resource names in vendor shapes
  ["resource", "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"],
  ["resource", "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
  ["resource", "arn:aws:s3:::my-bucket-prod-2026-logs"],
  ["resource", "arn:aws:lambda:us-east-1:123456789012:function:rotate-keys-nightly-2026"],
  ["resource", "IAMReadOnlyAccess"],
  ["resource", "AmazonEC2FullAccess"],
  ["resource", "AWSCloudTrail2024Policy"],
  ["resource", "projects/my-project-123456/serviceAccounts/deploy-bot-2026@my-project-123456.iam.gserviceaccount.com"],
  ["resource", "/subscriptions/2f3c1a9e-7b6d-4c5e-8f9a-0b1c2d3e4f5a/resourceGroups/rg-prod-2026/providers/Microsoft.KeyVault/vaults/kv-prod-2026"],
  // status text
  ["status text", "Too Many Requests"],
  ["status text", "Service Unavailable"],
  ["status text", "Bad Gateway"],
  ["status text", "Unauthorized"],
  ["status text", "Forbidden"],
  ["status text", "Internal Server Error"],
  // finding ids
  ["finding id", "ZIA-URL-FILTER-12"],
  ["finding id", "AWS-IAM-04"],
  ["finding id", "CF-IAM-04"],
  ["finding id", "AAP-RBAC-05"],
  ["finding id", "GWS-2SV-01"],
  ["finding id", "OKTA-MFA-03"],
  ["finding id", "SNOW-ACL-11"],
  ["finding id", "M365-CA-07"],
  ["finding id", "CIS-1.22"],
  ["finding id", "AC-2(3)"],
  // commands and statements
  ["command", "gcloud compute instances list --project my-project-123456 --format json"],
  ["command", "kubectl get pods -n kube-system --context prod-us-east-2026"],
  ["command", 'az ad user list --filter "accountEnabled eq true" --query "[].userPrincipalName"'],
  ["command", "aws iam list-users --max-items 1000 --region us-east-1"],
  ["command", "oci iam user list --compartment-id ocid1.tenancy.oc1 --all"],
  ["command", "gws users list --customer my_customer --max-results 500 --impersonate-service-account"],
  ["command", "vault list auth/approle/role"],
  ["statement", "SELECT user_name, sys_id FROM sys_user_has_role WHERE role = 'admin' LIMIT 10000"],
  ["statement", "SHOW GRANTS ON ACCOUNT"],
  ["statement", "SELECT name FROM snowflake.account_usage.users WHERE disabled = false"],
  ["statement", "| tstats count where index=_audit by user"],
  ["statement", "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'"],
  // standing fixed texts
  ["fixed text", "Unable to read config file /home/user/.config/tool/credentials.json (EACCES)"],
  ["fixed text", "Unable to parse config file: invalid YAML in /home/user/.config/tool/config.yaml at line 2, column 6 (BLOCK_AS_IMPLICIT_KEY)"],
  ["fixed text", "GET /v1/users failed with 502 Bad Gateway: non-JSON body (text/html, 1234 bytes)"],
  ["fixed text", "POST /oauth2/v1/token failed with 400 Bad Request: JSON body without a documented message field (2 bytes)"],
  ["fixed text", "stopped after 500 of 1200 items with more pages available (500 item limit)"],
  ["fixed text", "seen 40 of 120"],
  ["fixed text", "40 seen, total unknown"],
  ["fixed text", "not collected"],
  ["fixed text", REDACTED],
  // path-safety shapes the long-token rule must leave alone
  ["path segment", "urlFilteringRules"],
  ["path segment", "roleassignments"],
  ["path segment", "application_default_credentials.json"],
  ["hyphenated name", "prod-us-east-2026"],
  ["hyphenated name", "ec2-54-123-45-67"],
  ["hyphenated name", "eBay-enterprise-account-2026"],
  ["hyphenated name", "x86_64-unknown-linux-gnu"],
  ["hyphenated name", "--impersonate-service-account"],
  ["dotted hostname", "ec2-54-123-45-67.compute-1.amazonaws.com"],
  ["dotted hostname", "graph.microsoft.com"],
  ["dotted hostname", "myverylongtenantname2026.zscalerbeta.net"],
  ["colon-separated ARN", "arn:aws:iam::123456789012:role/OrganizationAccountAccessRole"],
  ["camel and acronym word", "XMLHttpRequest"],
  ["camel and acronym word", "getHTTPSUrl"],
  ["camel and acronym word", "oauth2Client"],
  ["camel and acronym word", "InvalidAuthenticationTokenProvided"],
  ["timestamp", "2026-09-22T05:36:00.123Z"],
  ["media type", "application/x-www-form-urlencoded"],
  // key=value pairs whose value is a name (the AWS secret shape is matched after "=" too; a name is not that shape)
  ["assignment", "AWS_PROFILE=prod-us-east-2026"],
  ["assignment", "AWS_REGION=us-east-1"],
  ["assignment", "GOOGLE_CLOUD_PROJECT=my-project-123456"],
  ["assignment", "ROLE=OrganizationAccountAccessRole"],
  ["assignment", "BUCKET=my-bucket-prod-2026-logs"],
  ["assignment", "x=AWSLambdaBasicExecutionRole"],
  ["assignment", "policy=AmazonElasticContainerRegistryPublicRead"],
  ["assignment", "resource=arn:aws:iam::123456789012:role/OrganizationAccountAccessRole"],
  ["assignment", "max_results_per_page=1000"],
]);

/** The AWS secret access key canaries: the random-looking one, its slash and plus variants, and the group D value. */
const AWS_SECRETS = Object.freeze([
  ERROR_CANARY.awsSecret,
  `${ERROR_CANARY.awsSecret.slice(0, 13)}/${ERROR_CANARY.awsSecret.slice(14, 21)}/${ERROR_CANARY.awsSecret.slice(22)}`,
  `${ERROR_CANARY.awsSecret.slice(0, 20)}+${ERROR_CANARY.awsSecret.slice(21)}`,
  CANARY.awsSecret,
]);

/** Assignment carriers under a key that does not name a credential, where only the secret's own shape can catch it. */
const ASSIGNMENT_CARRIERS = Object.freeze([
  (value) => `x=${value}`,
  (value) => `ENV_VALUE=${value}`,
  (value) => `description=${value} rejected`,
  (value) => `GET /v1/users?x=${value}&page=2 failed with 403 Forbidden: non-JSON body (text/html, 512 bytes)`,
]);

/** Realistic summary sentences that place a value where a corollary summary or an error line would. */
const SENTENCES = Object.freeze([
  (value) => `Inventory ${value} was not readable, so the finding is manual and names it.`,
  (value) => `GET ${value} failed with 403 Forbidden: non-JSON body (text/html, 512 bytes)`,
  (value) => `Unread inventory: ${value} (429 Too Many Requests, seen 40 of 120).`,
  (value) => `Finding withheld for ${value} because the read of ${value} stopped after 500 of 1200 items with more pages available.`,
]);

/** Every scrub the library exposes for error text and data text, each returning the text it produces. */
const SCRUBS = Object.freeze([
  ["scrubErrorText", (text) => scrubErrorText(text)],
  ["scrubDataText", (text) => scrubDataText(text)],
  ["scrubError", (text) => scrubError(new Error(text)).message],
  ["errorMessage", (text) => errorMessage(new Error(text))],
  ["IntegrationError", (text) => new IntegrationError(text).message],
  ["redactSecretValues", (text) => redactSecretValues(text)],
]);

/**
 * Values that are removed from error text by design because their shape is a token's: opaque
 * identifiers travel in a validated structured field, not in the message. `scrubDataText` keeps them
 * because in a data value they are evidence.
 */
const OPAQUE_IDENTIFIERS = Object.freeze([
  ["Okta record id", "00u1abcd2EFGHijkl3m4"],
  ["ServiceNow sys_id", "4f3a9c1b7e2d8f6a0b5c4d3e2f1a0b9c"],
  ["EC2 instance id", "i-0abc123def456789a"],
  ["OCID unique part", "aaaaaaaaz3k7q2m9x1c4v8b6n5p0t7r2w9y4u1i3o6"],
  ["New Relic entity guid", "MzgwNjUyNnxBUE18QVBQTElDQVRJT058MTIzNDU2Nzg"],
]);

/**
 * Canaries shaped like names: words joined by separators with one numeric segment. Bare, they are
 * indistinguishable from `my-bucket-prod-2026-logs`, so the path-safe long-token rule keeps them and
 * they are caught only where a carrier names them, which is where the shared cases plant them.
 */
const NAME_SHAPED_CANARIES = Object.freeze([
  [CANARY.sessionCookie, `Set-Cookie: session=${CANARY.sessionCookie}; Path=/`],
  [CANARY.apiKey, `x-api-key: ${CANARY.apiKey} for the caller`],
  [CANARY.urlToken, `retry at https://api.example.com/v1/x?token=${CANARY.urlToken} later`],
]);

const TOKEN_SHAPED_CANARIES = Object.freeze([
  ...Object.values(ERROR_CANARY),
  CANARY.bearer,
  CANARY.basic,
  CANARY.jwt,
  CANARY.awsAccessKeyId,
  CANARY.awsSecret,
]);

function keepValues() {
  return MUST_KEEP.map(([, value]) => value);
}

test("must-keep fixture: no 6-character window of a planted value occurs in a kept value or a sentence template", () => {
  assertNoCanaryWindowIn(
    [...keepValues(), ...SENTENCES.map((sentence) => sentence("VALUE")), ...ASSIGNMENT_CARRIERS.map((carrier) => carrier("VALUE"))],
    [...TOKEN_SHAPED_CANARIES, ...AWS_SECRETS, ENCODED_FORM_SECRET],
  );
  assert.ok(MUST_KEEP.some(([, value]) => value.length >= LONG_TOKEN_MIN_LENGTH), "the table must exercise runs the long-token rule judges");
});

test("must-keep: every value comes back unchanged from every scrub, in isolation", () => {
  for (const [category, value] of MUST_KEEP) {
    for (const [scrubName, scrub] of SCRUBS) {
      assert.equal(scrub(value), value, `${category} ${JSON.stringify(value)} was changed by ${scrubName}`);
    }
  }
});

test("must-keep: every value survives inside realistic summary sentences through every scrub", () => {
  for (const [category, value] of MUST_KEEP) {
    for (const sentence of SENTENCES) {
      const text = sentence(value);
      for (const [scrubName, scrub] of SCRUBS) {
        assert.equal(scrub(text), text, `${category} ${JSON.stringify(value)} was changed by ${scrubName} inside ${JSON.stringify(text)}`);
      }
    }
  }
});

test("must-keep: an absolute URL keeps scheme, host, and path and loses its query as one marker (the shared URL rule)", () => {
  const url = "https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName&$top=999";
  assert.equal(scrubErrorText(url), `https://graph.microsoft.com/v1.0/users?${REDACTED}`);
  assert.equal(scrubErrorText("https://graph.microsoft.com/v1.0/users"), "https://graph.microsoft.com/v1.0/users");
});

test("must-redact: token-shaped canaries leave no 6- to 24-character fragment, bare or inside the sentences, through every error-text scrub", () => {
  const errorTextScrubs = SCRUBS.filter(([name]) => name !== "scrubDataText" && name !== "redactSecretValues");
  for (const canary of TOKEN_SHAPED_CANARIES) {
    for (const [scrubName, scrub] of errorTextScrubs) {
      const bare = scrub(canary);
      assertNoFragment(bare, canary, { label: `${scrubName} bare` });
      assert.ok(bare.includes(REDACTED), `${scrubName}: the marker must stand where ${canary} was: ${bare}`);
      for (const sentence of SENTENCES) {
        const text = sentence(canary);
        const scrubbed = scrub(text);
        assertNoFragment(scrubbed, canary, { label: `${scrubName} sentence` });
        assert.ok(scrubbed.includes(REDACTED), `${scrubName}: the marker must stand in ${scrubbed}`);
        assert.ok(scrubbed.includes("seen 40 of 120") || scrubbed.includes("failed with 403 Forbidden") || scrubbed.includes("not readable") || scrubbed.includes("more pages available"), `${scrubName}: the fixed words around the token must survive: ${scrubbed}`);
      }
    }
  }
});

test("must-redact: a 40-character AWS secret after any assignment operator is removed by its shape through every scrub, including the data scrubs", () => {
  for (const secret of AWS_SECRETS) {
    assert.equal(secret.length, 40);
    for (const carrier of ASSIGNMENT_CARRIERS) {
      const text = carrier(secret);
      const expected = carrier(REDACTED);
      for (const [scrubName, scrub] of SCRUBS) {
        const scrubbed = scrub(text);
        assertNoFragment(scrubbed, secret, { label: `${scrubName} of ${text}` });
        assert.equal(scrubbed, expected, `${scrubName}: the key and the fixed words around the marker stay`);
      }
      for (const sentence of SENTENCES) {
        const scrubbed = scrubErrorText(sentence(text));
        assertNoFragment(scrubbed, secret, { label: `sentence ${text}` });
        assert.equal(scrubbed, sentence(expected));
        assertNoFragment(scrubDataText(sentence(text)), secret, { label: `data sentence ${text}` });
      }
    }
    const record = redactSecretValues({ description: `ENV_VALUE=${secret}`, notes: [`x=${secret}`] });
    assertNoFragment(record, secret, { label: "record values" });
    assert.deepEqual(record, { description: `ENV_VALUE=${REDACTED}`, notes: [`x=${REDACTED}`] });
  }
  for (const scrub of [scrubErrorText, scrubDataText]) {
    assert.equal(scrub(`secret_access_key=${ERROR_CANARY.awsSecret}`), `secret_access_key=${REDACTED}`, "a credential key of 16 or more characters keeps its name in front of one marker");
    assert.equal(scrub(`aws_secret_access_key=${CANARY.awsSecret} and more`), `aws_secret_access_key=${REDACTED} and more`);
  }
});

test("must-redact: a configured secret leaves no fragment in any encoded form through the secrets option", () => {
  const forms = [ENCODED_FORM_SECRET, encodeURIComponent(ENCODED_FORM_SECRET), Buffer.from(ENCODED_FORM_SECRET, "utf8").toString("base64"), JSON.stringify(ENCODED_FORM_SECRET).slice(1, -1)];
  for (const form of forms) {
    for (const sentence of SENTENCES) {
      const text = sentence(form);
      const scrubbed = scrubErrorText(text, { secrets: [ENCODED_FORM_SECRET] });
      assertNoFragment(scrubbed, form, { label: `configured secret form ${form}` });
      assert.equal(scrubDataText(text, { secrets: [ENCODED_FORM_SECRET] }), scrubbed, "data text applies the configured-secret rule the same way");
      assert.equal(errorMessage(new Error(text), { secrets: [ENCODED_FORM_SECRET] }), scrubbed);
    }
  }
});

test("must-redact: the shared carrier cases hold for every scrub that accepts text", () => {
  assertRedactionCases(assert, scrubErrorText);
  assertRedactionCases(assert, scrubDataText);
  assertRedactionCases(assert, (text) => errorMessage(new Error(text)));
  assertRedactionCases(assert, (text) => new IntegrationError(text).message);
  assertRedactionCases(assert, (text) => redactSecretValues(text));
});

test("boundary: name-shaped canaries are kept bare and redacted in their carriers", () => {
  for (const [canary, carrier] of NAME_SHAPED_CANARIES) {
    assert.equal(scrubErrorText(canary), canary, `a bare value shaped like a name is a name: ${canary}`);
    const scrubbed = scrubErrorText(carrier);
    assertNoFragment(scrubbed, canary, { label: `carrier ${carrier}` });
    assert.ok(scrubbed.includes(REDACTED), scrubbed);
  }
});

test("boundary: opaque identifiers are removed from error text and kept in data text", () => {
  for (const [label, identifier] of OPAQUE_IDENTIFIERS) {
    assert.ok(identifier.length >= LONG_TOKEN_MIN_LENGTH, `${label} must be long enough for the rule to judge`);
    assert.equal(scrubErrorText(`record ${identifier} not found`), `record ${REDACTED} not found`, `${label} in error text`);
    assert.equal(scrubDataText(`record ${identifier} not found`), `record ${identifier} not found`, `${label} in data text`);
    assert.equal(redactSecretValues({ id: identifier }).id, identifier, `${label} as a data value`);
  }
});
