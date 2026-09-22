import test from "node:test";
import assert from "node:assert/strict";

import * as index from "../dist/extensions/grc-tools/hardening/index.js";
import * as collectionStatus from "../dist/extensions/grc-tools/hardening/collection-status.js";
import * as configFile from "../dist/extensions/grc-tools/hardening/config-file.js";
import * as errorText from "../dist/extensions/grc-tools/hardening/error-text.js";
import * as nextLink from "../dist/extensions/grc-tools/hardening/next-link.js";
import * as pagination from "../dist/extensions/grc-tools/hardening/pagination.js";

const MODULES = { "collection-status": collectionStatus, "config-file": configFile, "error-text": errorText, "next-link": nextLink, pagination };

test("the hardening index re-exports every runtime export of every module, each exactly once", () => {
  const seen = new Map();
  for (const [name, module] of Object.entries(MODULES)) {
    for (const key of Object.keys(module)) {
      assert.equal(index[key], module[key], `${name}.${key} is not re-exported by the index`);
      assert.ok(!seen.has(key), `${key} is exported by both ${seen.get(key)} and ${name}`);
      seen.set(key, name);
    }
  }
  const total = Object.values(MODULES).reduce((count, module) => count + Object.keys(module).length, 0);
  assert.equal(Object.keys(index).length, total, "the index exports nothing of its own");
});

test("the four constructor points the audit named are present under one import", () => {
  assert.equal(typeof index.scrubErrorText, "function");
  assert.equal(typeof index.describeErrorBody, "function");
  assert.equal(typeof index.scrubError, "function");
  assert.equal(typeof index.errorMessage, "function");
  assert.ok(new index.IntegrationError("x") instanceof Error);
  assert.equal(typeof index.readYamlConfig, "function");
  assert.equal(typeof index.readJsonConfig, "function");
  assert.equal(typeof index.readConfigText, "function");
  assert.ok(new index.ConfigFileError({ kind: "read", path: "/p" }) instanceof Error);
  assert.equal(typeof index.coreDataValue, "function");
  assert.equal(typeof index.derived, "function");
  assert.equal(typeof index.countIfReadable, "function");
  assert.equal(typeof index.gatedPrincipals, "function");
  assert.equal(typeof index.describePagination, "function");
  assert.equal(typeof index.resolveSameOriginUrl, "function");
});
