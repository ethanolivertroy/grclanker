import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  assembleOscalSsp,
  checkOscalTrestle,
  createOscalModel,
  generateOscalSspMarkdown,
  importOscalModel,
  initOscalWorkspace,
  inspectTrestleWorkspace,
  resolveOscalModelType,
  resolveTrestleExecutable,
  validateOscalModel,
} from "../dist/extensions/grc-tools/oscal.js";

function createTempDir(prefix) {
  return mkdtempSync(join(tmpdir(), prefix));
}

function createWorkspace(root, { dist = false } = {}) {
  mkdirSync(join(root, ".trestle"), { recursive: true });
  for (const dirName of [
    "catalogs",
    "profiles",
    "component-definitions",
    "system-security-plans",
    "assessment-plans",
    "assessment-results",
    "plan-of-action-and-milestones",
  ]) {
    mkdirSync(join(root, dirName), { recursive: true });
    if (dist) {
      mkdirSync(join(root, "dist", dirName), { recursive: true });
    }
  }
}

function successResult(overrides = {}) {
  return {
    executable: "/mock/trestle",
    displayExecutable: "/mock/trestle",
    exitCode: 0,
    stdout: "",
    stderr: "",
    ...overrides,
  };
}

test("resolveOscalModelType supports friendly aliases", () => {
  assert.equal(resolveOscalModelType("ssp"), "system-security-plan");
  assert.equal(resolveOscalModelType("component"), "component-definition");
  assert.equal(resolveOscalModelType("sar"), "assessment-results");
  assert.equal(resolveOscalModelType("poam"), "plan-of-action-and-milestones");
  assert.throws(() => resolveOscalModelType("banana"), /Unsupported OSCAL model type/i);
});

test("resolveTrestleExecutable prefers explicit environment overrides", () => {
  const result = resolveTrestleExecutable({
    GRCLANKER_TRESTLE_BIN: "/custom/trestle",
  });
  assert.equal(result.executable, "/custom/trestle");
  assert.equal(result.displayExecutable, "/custom/trestle");
});

test("inspectTrestleWorkspace reports initialization and model counts", () => {
  const root = createTempDir("grclanker-oscal-inspect-");
  createWorkspace(root, { dist: true });
  mkdirSync(join(root, "profiles", "fedramp-moderate"), { recursive: true });
  mkdirSync(join(root, "system-security-plans", "acme-ssp"), { recursive: true });

  const inspection = inspectTrestleWorkspace(root);
  assert.equal(inspection.isWorkspace, true);
  assert.equal(inspection.hasDist, true);
  assert.equal(inspection.modelCounts.profile, 1);
  assert.equal(inspection.modelCounts["system-security-plan"], 1);
});

test("checkOscalTrestle reports missing trestle gracefully", async () => {
  const root = createTempDir("grclanker-oscal-check-");
  const result = await checkOscalTrestle(
    { workspace_dir: root },
    async () => {
      throw new Error("Trestle is not installed or not on PATH.");
    },
  );

  assert.equal(result.installed, false);
  assert.match(result.notes[0] ?? "", /not installed/i);
});

test("initOscalWorkspace initializes the requested workspace mode", async () => {
  const root = createTempDir("grclanker-oscal-init-");
  const calls = [];

  const result = await initOscalWorkspace(
    { workspace_dir: root, mode: "full" },
    async (args, options) => {
      calls.push({ args, options });
      createWorkspace(options.cwd, { dist: true });
      return successResult();
    },
  );

  assert.deepEqual(calls[0]?.args, ["init", "--full"]);
  assert.equal(result.alreadyInitialized, false);
  assert.equal(result.workspace.isWorkspace, true);
  assert.equal(result.workspace.hasDist, true);
});

test("importOscalModel detects the imported model path", async () => {
  const root = createTempDir("grclanker-oscal-import-");
  createWorkspace(root);

  const result = await importOscalModel(
    {
      workspace_dir: root,
      file: "https://example.com/profile.json",
      output: "fedramp-moderate",
    },
    async (args) => {
      assert.deepEqual(args, [
        "import",
        "-f",
        "https://example.com/profile.json",
        "-o",
        "fedramp-moderate",
      ]);
      const filePath = join(root, "profiles", "fedramp-moderate", "profile.json");
      mkdirSync(join(root, "profiles", "fedramp-moderate"), { recursive: true });
      writeFileSync(filePath, "{\"profile\":{}}");
      return successResult();
    },
  );

  assert.equal(result.modelType, "profile");
  assert.ok(result.importedPath?.endsWith("/profiles/fedramp-moderate/profile.json"));
});

test("createOscalModel creates the expected file path", async () => {
  const root = createTempDir("grclanker-oscal-create-");
  createWorkspace(root);

  const result = await createOscalModel(
    {
      workspace_dir: root,
      model_type: "ssp",
      name: "acme-ssp",
      format: "json",
      include_optional_fields: true,
    },
    async (args) => {
      assert.deepEqual(args, [
        "create",
        "-t",
        "system-security-plan",
        "-o",
        "acme-ssp",
        "-x",
        "json",
        "--include-optional-fields",
      ]);
      const filePath = join(
        root,
        "system-security-plans",
        "acme-ssp",
        "system-security-plan.json",
      );
      mkdirSync(join(root, "system-security-plans", "acme-ssp"), { recursive: true });
      writeFileSync(filePath, "{\"system-security-plan\":{}}");
      return successResult();
    },
  );

  assert.ok(result.filePath.endsWith("/system-security-plans/acme-ssp/system-security-plan.json"));
  assert.equal(existsSync(result.filePath), true);
});

test("OSCAL output names stay inside the trestle workspace", async () => {
  const root = createTempDir("grclanker-oscal-escape-");
  createWorkspace(root);
  const runner = async () => {
    throw new Error("runner should not be called");
  };

  await assert.rejects(
    () => createOscalModel({ workspace_dir: root, model_type: "catalog", name: "../escape" }, runner),
    /model name must be a single name inside the workspace/,
  );
  await assert.rejects(
    () => importOscalModel({ workspace_dir: root, file: "profile.json", output: "/tmp/escape" }, runner),
    /output name must be a single name inside the workspace/,
  );
  await assert.rejects(
    () => generateOscalSspMarkdown(
      { workspace_dir: root, profile: "fedramp-moderate", output: "..\\escape" },
      runner,
    ),
    /output directory name must be a single name inside the workspace/,
  );
});

test("validateOscalModel builds workspace validation selectors", async () => {
  const root = createTempDir("grclanker-oscal-validate-");
  createWorkspace(root);
  const calls = [];

  const byName = await validateOscalModel(
    {
      workspace_dir: root,
      model_type: "sar",
      name: "q1-assessment",
    },
    async (args) => {
      calls.push(args);
      return successResult();
    },
  );

  const all = await validateOscalModel(
    {
      workspace_dir: root,
      all: true,
      quiet: false,
    },
    async (args) => {
      calls.push(args);
      return successResult();
    },
  );

  assert.deepEqual(calls[0], ["validate", "-t", "assessment-results", "-n", "q1-assessment", "-q"]);
  assert.deepEqual(calls[1], ["validate", "-a"]);
  assert.equal(byName.selector, "assessment-results:q1-assessment");
  assert.equal(all.selector, "all workspace models");
});

test("generateOscalSspMarkdown reports markdown count and inheritance view", async () => {
  const root = createTempDir("grclanker-oscal-ssp-generate-");
  createWorkspace(root);

  const result = await generateOscalSspMarkdown(
    {
      workspace_dir: root,
      profile: "fedramp-moderate",
      output: "ssp-md",
      component_definitions: ["app-stack", "shared-services"],
      leveraged_ssp: "provider-ssp",
      include_all_parts: true,
    },
    async (args) => {
      assert.deepEqual(args, [
        "author",
        "ssp-generate",
        "-p",
        "fedramp-moderate",
        "-o",
        "ssp-md",
        "-cd",
        "app-stack,shared-services",
        "-ls",
        "provider-ssp",
        "-iap",
      ]);
      mkdirSync(join(root, "ssp-md", "ac"), { recursive: true });
      mkdirSync(join(root, "ssp-md", "inheritance"), { recursive: true });
      writeFileSync(join(root, "ssp-md", "ac", "ac-1.md"), "# AC-1");
      writeFileSync(join(root, "ssp-md", "inheritance", "readme.md"), "# inheritance");
      return successResult();
    },
  );

  assert.equal(result.controlMarkdownCount, 1);
  assert.equal(result.hasInheritanceView, true);
});

test("assembleOscalSsp finds the assembled SSP output path", async () => {
  const root = createTempDir("grclanker-oscal-ssp-assemble-");
  createWorkspace(root);

  const result = await assembleOscalSsp(
    {
      workspace_dir: root,
      markdown: "ssp-md",
      output: "assembled-ssp",
      component_definitions: ["app-stack"],
      source_ssp_name: "baseline-ssp",
      version: "1.2.3",
    },
    async (args) => {
      assert.deepEqual(args, [
        "author",
        "ssp-assemble",
        "-m",
        "ssp-md",
        "-o",
        "assembled-ssp",
        "-cd",
        "app-stack",
        "-n",
        "baseline-ssp",
        "-vn",
        "1.2.3",
      ]);
      mkdirSync(join(root, "system-security-plans", "assembled-ssp"), { recursive: true });
      writeFileSync(
        join(root, "system-security-plans", "assembled-ssp", "system-security-plan.json"),
        "{\"system-security-plan\":{}}",
      );
      return successResult();
    },
  );

  assert.ok(
    result.filePath?.endsWith(
      "/system-security-plans/assembled-ssp/system-security-plan.json",
    ),
  );
});
