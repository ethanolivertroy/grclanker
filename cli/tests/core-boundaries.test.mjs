import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { collectDomainToolDefinitions } from "../dist/core/domain-tools.js";
import { collectRegisteredToolDefinitions } from "../dist/pi/tool-catalog.js";

const cliRoot = fileURLToPath(new URL("..", import.meta.url));
const computeNames = new Set(["bash", "read", "write", "edit", "ls", "find", "grep"]);

test("shared core discovers and executes GRC tools with all agent hosts blocked", () => {
  const workspace = mkdtempSync(resolve(tmpdir(), "grclanker-core-boundary-"));
  try {
    const probe = spawnSync(process.execPath, ["--input-type=module", "-e", `
      import assert from "node:assert/strict";
      import { readdirSync } from "node:fs";
      import { registerHooks } from "node:module";
      import { pathToFileURL } from "node:url";
      registerHooks({
        resolve(specifier, context, nextResolve) {
          if (/^@earendil-works\\/(?:pi-coding-agent|pi-tui|pi-durable|pi-ai)(?:$|\\/)/.test(specifier)
            || /^@(?:grok\\/agent-sdk|cursor\\/(?:bdk|sdk)|openai\\/(?:agents|codex-sdk)|anthropic-ai\\/(?:claude-agent-sdk|sdk)|flue\\/runtime)(?:$|\\/)/.test(specifier)) {
            throw new Error("Agent host must not load: " + specifier);
          }
          const resolved = nextResolve(specifier, context);
          if (/\\/dist\\/(?:pi|adapters|flue|durable)\\//.test(resolved.url)
            || /\\/dist\\/extensions\\/grc-tools\\.js$/.test(resolved.url)) {
            throw new Error("Agent adapter must not load: " + resolved.url);
          }
          return resolved;
        },
      });
      await assert.rejects(import("@earendil-works/pi-coding-agent"), /Agent host must not load/);
      const core = pathToFileURL(process.cwd() + "/dist/core/");
      for (const file of readdirSync(core).filter((name) => name.endsWith(".js"))) {
        await import(new URL(file, core));
      }
      const { collectRegisteredGrcTools } = await import(new URL("registry.js", core));
      const { executeRegisteredGrcTool } = await import(new URL("tools.js", core));
      const { workflowSkillConfig } = await import(new URL("skills.js", core));
      const tools = collectRegisteredGrcTools();
      assert.ok(tools.length > 0);
      assert.ok(tools.every((tool) => !new Set(["bash", "read", "write", "edit", "ls", "find", "grep"]).has(tool.name)));
      assert.match(workflowSkillConfig("audit").markdown, /audit/i);
      const result = await executeRegisteredGrcTool("oscal_check_trestle", { workspace_dir: process.env.CORE_TEST_WORKSPACE });
      assert.equal(result.isError, undefined);
      assert.match(result.content[0].text, /Trestle is not available yet/);
      process.stdout.write("core executed without agent hosts");
    `], {
      cwd: cliRoot,
      env: {
        ...process.env,
        CORE_TEST_WORKSPACE: workspace,
        GRCLANKER_TRESTLE_BIN: resolve(workspace, "trestle-deliberately-absent"),
      },
      encoding: "utf8",
    });
    assert.equal(probe.status, 0, probe.stderr);
    assert.equal(probe.stdout, "core executed without agent hosts");
    assert.deepEqual(readdirSync(workspace), []);
  } finally {
    rmSync(workspace, { recursive: true, force: true });
  }
});

test("Pi adds only its compute tools to the same domain definitions exposed by core", () => {
  const core = collectDomainToolDefinitions();
  const pi = collectRegisteredToolDefinitions();
  assert.deepEqual(pi.filter((tool) => computeNames.has(tool.name)).map((tool) => tool.name).sort(), [...computeNames].sort());
  assert.equal(pi.length, core.length + computeNames.size);
  assert.deepEqual(
    pi.filter((tool) => !computeNames.has(tool.name)).map((tool) => ({ name: tool.name, parameters: JSON.parse(JSON.stringify(tool.parameters)) })),
    core.map((tool) => ({ name: tool.name, parameters: JSON.parse(JSON.stringify(tool.parameters)) })),
  );
});
