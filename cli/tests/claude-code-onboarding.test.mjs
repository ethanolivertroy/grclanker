import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const cliRoot = fileURLToPath(new URL("../", import.meta.url));
const repoRoot = dirname(cliRoot.slice(0, -1));
const required = process.env.GRCLANKER_REQUIRE_CLAUDE_CODE_ONBOARDING === "1";

// This regression uses the pinned SDK's real CLI only in the dedicated checks job.
// Installing or checking the Claude Code MCP adapter itself never requires that SDK.
function claudeExecutable() {
  if (process.env.GRCLANKER_CLAUDE_CODE_BIN) return resolve(process.env.GRCLANKER_CLAUDE_CODE_BIN);
  const musl = process.platform === "linux" && !process.report.getReport().header.glibcVersionRuntime;
  const packageName = `claude-agent-sdk-${process.platform}-${process.arch}${musl ? "-musl" : ""}`;
  const packageRoot = join(cliRoot, "adapters", "claude-agent-sdk", "node_modules", "@anthropic-ai", packageName);
  const executable = join(packageRoot, process.platform === "win32" ? "claude.exe" : "claude");
  if (!existsSync(executable)) return undefined;
  const adapter = JSON.parse(readFileSync(join(cliRoot, "adapters", "claude-agent-sdk", "package.json"), "utf8"));
  const installed = JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8"));
  assert.equal(installed.version, adapter.dependencies["@anthropic-ai/claude-agent-sdk"], "exercise the pinned CLI");
  return executable;
}

function registrationCommands(markdown) {
  return [...markdown.matchAll(/^```bash[ \t]*\n([\s\S]*?)^```[ \t]*$/gm)].flatMap(([, block]) =>
    block.replace(/\\\r?\n[ \t]*/g, " ").split("\n")
      .filter((line) => /^claude mcp (?:add|remove|list)\b/.test(line))
      .map((command) => ({ command, block, operation: command.match(/^claude mcp (\w+)/)[1] })),
  );
}

const documents = [
  {
    path: "src/content/docs/docs/getting-started/claude-code.md",
    selections: [
      [],
      ["kevs_search", "kevs_get_epss"],
      ["github_check_access", "github_assess_org_access", "github_assess_repo_protection"],
      ["--allow-writes", "github_check_access", "github_export_audit_bundle"],
    ],
  },
  {
    path: "cli/adapters/claude-code/README.md",
    selections: [
      [],
      ["kevs_search,kevs_get_epss", "github_*"],
      ["--allow-writes", "github_check_access", "github_export_audit_bundle"],
    ],
  },
];

for (const document of documents) {
  test(`Claude Code registration examples run sequentially: ${document.path}`, { timeout: 120_000 }, (t) => {
    const binary = claudeExecutable();
    if (!binary || process.platform === "win32") {
      assert.ok(!required, "install the pinned Claude Agent SDK platform package for the required onboarding check");
      t.skip("real Claude CLI unavailable; the dedicated checks job requires it");
      return;
    }
    assert.ok(existsSync(binary), "GRCLANKER_CLAUDE_CODE_BIN must name an existing executable");

    const fixture = mkdtempSync(join(tmpdir(), "grclanker-claude-code-onboarding-"));
    t.after(() => rmSync(fixture, { recursive: true, force: true }));
    const checkout = join(fixture, "checkout");
    const config = join(fixture, "config");
    const bin = join(fixture, "bin");
    const homeDirectory = join(fixture, "home");
    for (const directory of [checkout, config, bin, homeDirectory]) mkdirSync(directory);
    symlinkSync(cliRoot, join(checkout, "cli"), "dir");
    symlinkSync(binary, join(bin, "claude"));
    // No developer credentials or Claude settings enter these child processes.
    const env = {
      PATH: `${bin}${delimiter}${process.env.PATH ?? ""}`,
      HOME: homeDirectory,
      CLAUDE_CONFIG_DIR: config,
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
      DISABLE_TELEMETRY: "1",
    };
    // The documented commands run inside a Git checkout. Without its own Git
    // boundary, Claude Code can scope "local" to an ancestor repository (for
    // example /tmp/.git on a managed VM) instead of this isolated fixture.
    const initialized = spawnSync("git", ["init", "--quiet"], { cwd: checkout, env, encoding: "utf8", timeout: 30_000 });
    assert.ifError(initialized.error);
    assert.equal(initialized.status, 0, `initialize fixture checkout\n${initialized.stdout}\n${initialized.stderr}`);
    const markdown = readFileSync(join(repoRoot, document.path), "utf8");
    const commands = registrationCommands(markdown);
    assert.equal(commands.filter((entry) => entry.operation === "add").length, document.selections.length);
    assert.equal(commands.filter((entry) => entry.operation === "remove").length, document.selections.length - 1);
    assert.equal(commands.filter((entry) => entry.operation === "list").length, document.selections.length);

    let selection = 0;
    for (const { command, block, operation } of commands) {
      if (operation !== "list") assert.match(command, /--scope local\b/, "remove and add must target the same explicit scope");
      if (operation === "add" && /github_/.test(command)) {
        assert.match(block, /^export GITHUB_ORG=/m, "the tenant example supplies its organization");
        assert.match(block, /^export GITHUB_TOKEN=/m, "the tenant example supplies credentials before starting Claude Code");
        assert.match(block, /^claude$/m, "restart Claude Code after replacing its server");
      }
      const result = spawnSync("bash", ["-c", command], { cwd: checkout, env, encoding: "utf8", timeout: 30_000 });
      assert.ifError(result.error);
      assert.equal(result.status, 0, `${command}\n${result.stdout}\n${result.stderr}`);
      const configuration = JSON.parse(readFileSync(join(config, ".claude.json"), "utf8"));
      assert.ok(configuration.projects?.[checkout], `local registration belongs to the checkout; configured projects: ${Object.keys(configuration.projects ?? {}).join(", ")}`);
      const registration = configuration.projects[checkout].mcpServers.grclanker;
      assert.equal(configuration.mcpServers?.grclanker, undefined, "local examples must not create a user-wide registration");
      assert.equal(existsSync(join(checkout, ".mcp.json")), false, "local examples must not create shared project configuration");
      if (operation === "remove") assert.equal(registration, undefined);
      else if (operation === "add") {
        assert.equal(registration.command, "node");
        assert.deepEqual(registration.args, [join(checkout, "cli", "adapters", "claude-code", "mcp-server.mjs"), ...document.selections[selection++]]);
        assert.deepEqual(registration.env ?? {}, {}, "vendor secrets are inherited at launch, not saved in the registration");
      } else assert.match(result.stdout, /grclanker:.*Connected/, "the documented selection must start the real MCP server");
    }
    assert.equal(selection, document.selections.length);
  });
}
