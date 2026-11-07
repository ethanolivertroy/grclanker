import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, readdir, writeFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildToolManifest, serializeToolManifest } from "../dist/core/tool-manifest.js";
import { collectEnvironmentVariables, environmentReferences, synchronizeToolManifest } from "../scripts/generate-tool-manifest.mjs";

const summary = (name, kind = "domain") => ({
  name,
  label: name,
  description: `Description of ${name}`,
  group: kind === "domain" ? "Demo" : "Compute Backend",
  kind,
  parameters: { type: "object", properties: { limit: { type: "number", default: 5 } } },
  parameterSummaries: [{ name: "limit", type: "number", required: false, defaultValue: 5 }],
});

test("the neutral manifest retains parameter metadata and uses the actual conservative effect policy", () => {
  const tools = [summary("demo_assess_users"), summary("demo_generate_report"), summary("demo_get_export"), summary("demo_unknown"), ...["bash", "read", "write", "edit", "ls", "find", "grep"].map((name) => summary(name, "compute"))];
  const manifest = buildToolManifest({ tools, toolPrefixes: ["demo_", "demo_"], environmentVariables: ["Z_TOKEN", "A_TOKEN", "Z_TOKEN"] });
  assert.equal(manifest.schemaVersion, 1);
  assert.deepEqual(manifest.toolPrefixes, ["demo_"]);
  assert.deepEqual(manifest.environmentVariables, ["A_TOKEN", "Z_TOKEN"]);
  const byName = new Map(manifest.tools.map((tool) => [tool.name, tool]));
  for (const name of ["demo_assess_users", "read", "ls", "find", "grep"]) assert.equal(byName.get(name).effect, "read", name);
  for (const name of ["demo_generate_report", "demo_get_export", "demo_unknown", "bash", "write", "edit"]) assert.equal(byName.get(name).effect, "write", name);
  assert.deepEqual(byName.get("demo_assess_users").parameterSummaries, tools[0].parameterSummaries);
  assert.equal(serializeToolManifest(manifest), serializeToolManifest(buildToolManifest({ tools: [...tools].reverse(), toolPrefixes: ["demo_"], environmentVariables: ["Z_TOKEN", "A_TOKEN"] })));
  assert.throws(() => buildToolManifest({ tools: [tools[0], tools[0]], toolPrefixes: [], environmentVariables: [] }), /Duplicate tool manifest name/);
});

test("environment identifier discovery handles computed resolver declarations without harvesting API enum strings", () => {
  const source = [
    "process.env.DEMO_API_KEY; env['DEMO_REGION'];",
    "const DEMO_MODEL_ENV = 'DEMO_MODEL'; process.env[DEMO_MODEL_ENV];",
    "const VENDOR_ENV = { token: 'DEMO_CONTRACT_TOKEN' }; env[VENDOR_ENV.token];",
    "const contract = { environment: ['DEMO_TIMEOUT'] };",
    "const STATUS = 'NOT_AN_ENVIRONMENT';",
    "pick('account', input.account, ['COMPUTED_ACCOUNT'], ['account']);",
    '${GRCLANKER_INSTALL_DIR:-default}',
    '$env:GRCLANKER_VERSION',
  ].join("\n");
  assert.deepEqual(environmentReferences(source, { shell: true }), ["COMPUTED_ACCOUNT", "DEMO_API_KEY", "DEMO_CONTRACT_TOKEN", "DEMO_MODEL", "DEMO_REGION", "DEMO_TIMEOUT", "GRCLANKER_INSTALL_DIR", "GRCLANKER_VERSION"]);
  assert.deepEqual(environmentReferences('const text = `${TEMPLATE_EXPRESSION}`;'), [], "JavaScript interpolation is not a shell environment read");
});

async function fixtureRepository() {
  const repoRoot = await mkdtemp(join(tmpdir(), "grclanker-tool-manifest-"));
  const files = {
    "cli/extensions/demo.ts": "process.env.DEMO_API_KEY;\n",
    "cli/scripts/demo-live-smoke.mjs": "process.env.DEMO_SMOKE_REGIONS;\n",
    "public/install": '${GRCLANKER_INSTALL_DIR:-default}\n',
    "public/install.ps1": '$env:GRCLANKER_VERSION\n',
    "cli/tests/hidden.test.mjs": "process.env.TEST_ONLY;\n",
    "cli/dist/hidden.js": "process.env.DIST_ONLY;\n",
    "cli/node_modules/hidden.js": "process.env.DEPENDENCY_ONLY;\n",
    "cli/.git/hidden.js": "process.env.GIT_ONLY;\n",
    "cli/.cache/hidden.js": "process.env.CACHE_ONLY;\n",
    "cli/.dist.stage-example/hidden.js": "process.env.STAGING_ONLY;\n",
    "cli/release/hidden.js": "process.env.RELEASE_ONLY;\n",
    "cli/coverage/hidden.js": "process.env.COVERAGE_ONLY;\n",
  };
  await Promise.all(Object.entries(files).map(async ([path, content]) => {
    const destination = join(repoRoot, path);
    await mkdir(join(destination, ".."), { recursive: true });
    await writeFile(destination, content);
  }));
  return repoRoot;
}

test("manifest generation excludes tests, dependencies, generated output, and environment values; check mode never writes", async () => {
  const repoRoot = await fixtureRepository();
  assert.deepEqual(await collectEnvironmentVariables(repoRoot), ["DEMO_API_KEY", "DEMO_SMOKE_REGIONS", "GRCLANKER_INSTALL_DIR", "GRCLANKER_VERSION"]);
  const options = { repoRoot, tools: [summary("demo_assess_users")], toolPrefixes: ["demo_"] };
  const destination = join(repoRoot, "cli/tool-manifest.json");
  await assert.rejects(synchronizeToolManifest({ ...options, check: true }), /is stale/);
  await assert.rejects(readFile(destination), { code: "ENOENT" });
  const manifest = await synchronizeToolManifest(options);
  assert.equal(await readFile(destination, "utf8"), serializeToolManifest(manifest));
  const before = await stat(destination);
  await synchronizeToolManifest({ ...options, check: true });
  assert.equal((await stat(destination)).mtimeMs, before.mtimeMs);
  await writeFile(destination, '{"old":true}\n');
  await assert.rejects(synchronizeToolManifest({ ...options, check: true }), /is stale/);
  assert.equal(await readFile(destination, "utf8"), '{"old":true}\n');
  assert.ok((await readdir(join(repoRoot, "cli"))).every((name) => !name.endsWith(".tmp")));
});
