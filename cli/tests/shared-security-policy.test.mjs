import test from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createSnapshotCredentialScrubber } from "../dist/extensions/grc-tools/security/snapshot-scrubber.js";
import { createPairCredentialScrubber } from "../dist/extensions/grc-tools/security/pair-scrubber.js";
import { createPemCredentialScrubber } from "../dist/extensions/grc-tools/security/pem-scrubber.js";
import { writeBundleAtomically } from "../dist/extensions/grc-tools/atomic-output.js";
import { resolveSecureOutputPath, writeSecureTextFile } from "../dist/extensions/grc-tools/secure-output.js";

test("shared credential policies isolate configured-secret state between integrations", () => {
  const first = createSnapshotCredentialScrubber();
  const second = createSnapshotCredentialScrubber();
  first.registerConfiguredSecrets("orchard");
  assert.match(first.redactCarrierText("request orchard rejected"), /\[REDACTED\]/);
  assert.equal(second.redactCarrierText("request orchard rejected"), "request orchard rejected");

  const identity = createPairCredentialScrubber();
  const sql = createPairCredentialScrubber();
  identity.registerConfiguredSecrets(["orchard"]);
  assert.match(identity.scrubDataText("request orchard rejected"), /\[REDACTED\]/);
  assert.equal(sql.scrubDataText("request orchard rejected"), "request orchard rejected");
});

test("shared policies keep public certificates in evidence and redact vendor HMAC proofs", () => {
  const pem = createPemCredentialScrubber();
  const certificate = "-----BEGIN CERTIFICATE-----\npublic-certificate-evidence\n-----END CERTIFICATE-----";
  assert.equal(pem.scrubCarriers(certificate, "private"), certificate);
  assert.equal(pem.redactErrorText(certificate), "[REDACTED]");
  const veracode = createPairCredentialScrubber(["VERACODE-HMAC-SHA-256"]);
  const output = veracode.scrubErrorText("VERACODE-HMAC-SHA-256 id=sample-id,ts=1234,nonce=opaque-proof,sig=opaque-signature");
  assert.match(output, /VERACODE-HMAC-SHA-256/);
  assert.doesNotMatch(output, /sample-id|opaque-proof|opaque-signature/);
});

test("atomic publication refuses symlink roots even when no caller supplies safety hooks", async () => {
  const base = mkdtempSync(join(tmpdir(), "grclanker-publish-policy-"));
  try {
    const actual = join(base, "actual");
    const alias = join(base, "alias");
    mkdirSync(actual);
    symlinkSync(actual, alias, "dir");
    let writes = 0;
    await assert.rejects(writeBundleAtomically({ root: alias, names: ["evidence"] }, async () => {
      writes += 1;
    }), /symlink/);
    assert.equal(writes, 0);
    assert.deepEqual(readdirSync(actual), []);
    await assert.rejects(writeBundleAtomically({ root: join(base, "prepared"), createRoot: () => alias, names: ["evidence"] }, async () => {
      writes += 1;
    }), /symlink/);
    assert.equal(writes, 0);
    assert.deepEqual(readdirSync(actual), []);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("vendor output entrypoints enforce the shared root, containment, and symlink policy", async () => {
  const base = mkdtempSync(join(tmpdir(), "grclanker-vendor-output-policy-"));
  try {
    const outside = join(base, "outside");
    const root = join(base, "root");
    const alias = join(base, "alias");
    mkdirSync(outside);
    mkdirSync(root);
    symlinkSync(outside, alias, "dir");
    symlinkSync(outside, join(root, "linked"), "dir");
    for (const family of ["aws", "box", "gcp", "okta", "mulesoft", "paloalto", "tenable", "zendesk"]) {
      const vendor = await import(`../dist/extensions/grc-tools/${family}.js`);
      assert.throws(() => vendor.resolveSecureOutputPath(alias, "evidence.json"), /symlink/, family);
      assert.throws(() => vendor.resolveSecureOutputPath(root, "../outside/evidence.json"), /outside/, family);
      assert.throws(() => vendor.resolveSecureOutputPath(root, "..\\outside\\evidence.json"), /outside/, family);
      assert.throws(() => vendor.resolveSecureOutputPath(root, "linked/evidence.json"), /symlink/, family);
    }
    assert.deepEqual(readdirSync(outside), []);
    await writeSecureTextFile(root, "nested/evidence.txt", "reviewed evidence");
    const target = join(realpathSync(root), "nested", "evidence.txt");
    assert.equal(readFileSync(target, "utf8"), "reviewed evidence");
    if (process.platform !== "win32") assert.equal(statSync(target).mode & 0o777, 0o600);
    assert.throws(() => resolveSecureOutputPath(root, "linked/other.txt"), /symlink/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});
