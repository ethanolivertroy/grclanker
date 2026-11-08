import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js";
import { createGrclankerClaudeOptions, mcpToolName } from "./agent.mjs";
import { approvalKey, createGrclankerMcpServer, WriteApprovals } from "./server.mjs";
import { DEFAULT_CLAUDE_GRC_TOOLS, selectTools } from "./tools.mjs";
import { runOfflineScenario, resultText } from "./check-helpers.mjs";
import { checkReliability } from "./check-reliability.mjs";

// Tool selection and approval bookkeeping.
assert.deepEqual(selectTools().map((tool) => tool.name), DEFAULT_CLAUDE_GRC_TOOLS);
assert.deepEqual(selectTools(["oscal_check_trestle", "oscal_check_trestle"]).map((tool) => tool.name), ["oscal_check_trestle"]);
assert.throws(() => selectTools([]), /at least one/);
assert.throws(() => selectTools([""]), /at least one/);
assert.throws(() => selectTools(["missing_tool"]), /Unknown grclanker tool/);
assert.equal(approvalKey("t", { b: 1, a: [{ d: 2, c: 3 }] }), approvalKey("t", { a: [{ c: 3, d: 2 }], b: 1 }));
const ledger = new WriteApprovals();
ledger.grant("t", { a: 1 });
assert.equal(ledger.consume("t", { a: 2 }), false);
assert.equal(ledger.consume("t", { a: 1 }), true);
assert.equal(ledger.consume("t", { a: 1 }), false);

const built = createGrclankerClaudeOptions({ toolNames: ["oscal_check_trestle", "oscal_init_workspace"] });
const isolation = built.options;
const signal = new AbortController().signal;
assert.deepEqual(isolation.tools, ["Agent"]);
assert.deepEqual(isolation.settingSources, []);
assert.equal(isolation.strictMcpConfig, true);
assert.equal(isolation.persistSession, false);
assert.equal(isolation.allowedTools, undefined);
assert.ok(built.readTools.includes(mcpToolName("oscal_check_trestle")));
assert.deepEqual(built.approvalTools, [mcpToolName("oscal_init_workspace")]);
const sdkServerInfo = { name: "grclanker", source: "sdk" };
assert.equal((await isolation.canUseTool(mcpToolName("oscal_check_trestle"), {}, { signal, toolUseID: "r", mcpServer: sdkServerInfo })).behavior, "allow");
assert.equal((await isolation.canUseTool("Agent", {}, { signal, toolUseID: "a" })).behavior, "allow");
// A configured server reusing the name is not the host's in-process server.
assert.equal((await isolation.canUseTool(mcpToolName("oscal_check_trestle"), {}, { signal, toolUseID: "p", mcpServer: { name: "grclanker", source: "project" } })).behavior, "deny");
for (const name of ["auditor", "verifier"]) assert.deepEqual(isolation.agents[name].tools, []);
const denied = await isolation.canUseTool(mcpToolName("oscal_init_workspace"), {}, { signal, toolUseID: "x", mcpServer: sdkServerInfo });
assert.equal(denied.behavior, "deny");
const foreign = await isolation.canUseTool("Bash", { command: "id" }, { signal, toolUseID: "y" });
assert.equal(foreign.behavior, "deny");

function textResult(result) {
  const parsed = CallToolResultSchema.parse(result);
  return { ...parsed, text: parsed.content.filter((item) => item.type === "text").map((item) => item.text).join("\n") };
}

const fixture = await mkdtemp(join(tmpdir(), "grclanker-claude-check-"));
const savedTrestle = process.env.GRCLANKER_TRESTLE_BIN;
process.env.GRCLANKER_TRESTLE_BIN = join(fixture, "unavailable-trestle");
try {
  const workspace = join(fixture, "workspace");
  await mkdir(join(workspace, ".trestle"), { recursive: true });
  await mkdir(join(workspace, "catalogs", "sample-catalog"), { recursive: true });
  const forbidden = join(fixture, "forbidden");

  // The in-process MCP server: discovery, validation, allowlist, and write gate.
  const approvals = new WriteApprovals();
  const sdkServer = createGrclankerMcpServer(selectTools(["oscal_check_trestle", "oscal_init_workspace", "kevs_get_epss"]), approvals);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await sdkServer.instance.connect(serverTransport);
  const client = new Client({ name: "grclanker-claude-check", version: "0.1.0" });
  await client.connect(clientTransport);
  try {
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((tool) => tool.name), ["oscal_check_trestle", "oscal_init_workspace", "kevs_get_epss", "grclanker_load_workflow", "grclanker_load_skill"]);
    assert.equal(tools[0].inputSchema.type, "object");
    assert.equal(tools[0].annotations?.readOnlyHint, true);
    assert.equal(tools[1].annotations?.readOnlyHint, false);
    const invalid = textResult(await client.callTool({ name: "kevs_get_epss", arguments: { cve_ids: [] } }));
    assert.equal(invalid.isError, true);
    assert.match(invalid.text, /requires at least one CVE ID/);
    const unselected = textResult(await client.callTool({ name: "github_export_audit_bundle", arguments: {} }));
    assert.equal(unselected.isError, true);
    assert.match(unselected.text, /not enabled/);
    const unapproved = textResult(await client.callTool({ name: "oscal_init_workspace", arguments: { workspace_dir: forbidden } }));
    assert.equal(unapproved.isError, true);
    assert.match(unapproved.text, /requires operator approval/);
    await assert.rejects(stat(forbidden), { code: "ENOENT" });
    const workflow = textResult(await client.callTool({ name: "grclanker_load_workflow", arguments: { name: "audit" } }));
    assert.notEqual(workflow.isError, true);
    assert.match(workflow.text, /audit/i);
    const badWorkflow = textResult(await client.callTool({ name: "grclanker_load_workflow", arguments: { name: "nope" } }));
    assert.equal(badWorkflow.isError, true);
  } finally {
    await client.close();
  }

  // Run the real SDK and its bundled Claude Code executable against a local
  // fake Messages API. The script calls a read tool, then a writer the
  // operator denies, then answers.
  const approvalsAsked = [];
  const { requests, result } = await runOfflineScenario({
    fixture,
    toolNames: ["oscal_check_trestle", "oscal_init_workspace"],
    mainScript: [
      { type: "tool_use", id: "toolu_read", name: mcpToolName("oscal_check_trestle"), input: { workspace_dir: workspace } },
      { type: "tool_use", id: "toolu_write", name: mcpToolName("oscal_init_workspace"), input: { workspace_dir: forbidden } },
      { type: "text", text: "offline SDK result" },
    ],
    async approveWrite(request) { approvalsAsked.push(request); return false; },
  });
  assert.equal(result.result, "offline SDK result");
  assert.ok(requests.length >= 3, `expected three main-loop model requests, saw ${requests.length}`);

  const first = requests[0];
  const system = Array.isArray(first.system) ? first.system.map((part) => part.text).join("\n") : String(first.system);
  assert.match(system, /Claude Agent SDK runtime/);
  const offered = first.tools.map((tool) => tool.name);
  assert.ok(offered.includes(mcpToolName("oscal_check_trestle")));
  assert.ok(offered.includes(mcpToolName("oscal_init_workspace")));
  for (const builtin of ["Bash", "Read", "Write", "Edit", "WebFetch", "WebSearch"]) assert.ok(!offered.includes(builtin), `${builtin} must not be offered`);

  const finalRequest = requests.at(-1);
  assert.ok(resultText(finalRequest, "toolu_read").includes(`Workspace dir: ${workspace}`));
  assert.match(resultText(finalRequest, "toolu_read"), /Trestle is not available yet/);
  assert.match(resultText(finalRequest, "toolu_write"), /did not approve/);
  assert.equal(approvalsAsked.length, 1);
  assert.equal(approvalsAsked[0].toolName, "oscal_init_workspace");
  await assert.rejects(stat(forbidden), { code: "ENOENT" });
  await checkReliability(fixture);
  console.log("Claude Agent SDK isolation options, in-process MCP discovery, input validation, tool allowlist, and write approval passed; the real SDK ran a read tool and a denied writer against a local fake Messages API. No real API credentials or network calls used.");
} finally {
  if (savedTrestle === undefined) delete process.env.GRCLANKER_TRESTLE_BIN;
  else process.env.GRCLANKER_TRESTLE_BIN = savedTrestle;
  await rm(fixture, { recursive: true, force: true });
}
