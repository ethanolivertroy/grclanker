import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js";
import { Codex } from "@openai/codex-sdk";
import { defaultTools, selectTools } from "./tools.mjs";
import { buildCodexOptions, threadOptions } from "./config.mjs";

assert.deepEqual(selectTools().map((tool) => tool.name), defaultTools);
assert.deepEqual(selectTools(["oscal_check_trestle", "oscal_check_trestle"]).map((tool) => tool.name), ["oscal_check_trestle"]);
assert.throws(() => selectTools([]), /at least one/);
assert.throws(() => selectTools([""]), /at least one/);
assert.throws(() => selectTools(["github_export_audit_bundle"]), /read tools only/);
assert.throws(() => selectTools(["missing_tool"]), /Unknown grclanker tool/);

/** @param {string[] | undefined} names @param {Record<string, string>} [env] */
async function connect(names, env) {
  const client = new Client({ name: "grclanker-codex-check", version: "0.1.0" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [fileURLToPath(new URL("./mcp-server.mjs", import.meta.url)), ...(names ?? [])],
    ...(env ? { env } : {}),
  });
  await client.connect(transport);
  return client;
}

/** @param {unknown} result */
function textResult(result) {
  const parsed = CallToolResultSchema.parse(result);
  const content = parsed.content.filter((item) => item.type === "text").map((item) => item.text).join("\n");
  return { ...parsed, text: content };
}

const client = await connect(undefined);
try {
  const { tools } = await client.listTools();
  assert.deepEqual(tools.map((tool) => tool.name), ["kevs_search", "kevs_get_epss"]);
  assert.ok(tools[0]);
  assert.equal(tools[0].inputSchema.type, "object");
  assert.equal(tools[0].annotations?.readOnlyHint, true);
  const invalid = textResult(await client.callTool({ name: "kevs_get_epss", arguments: { cve_ids: [] } }));
  assert.equal(invalid.isError, true);
  assert.match(invalid.text, /requires at least one CVE ID/);
  // These two denials distinguish the server's allowlist from the write gate.
  for (const name of ["github_export_audit_bundle", "oscal_check_trestle", "missing_tool"]) {
    const denied = textResult(await client.callTool({ name, arguments: {} }));
    assert.equal(denied.isError, true);
    assert.match(denied.text, /not enabled/);
  }
} finally {
  await client.close();
}

const fixture = await mkdtemp(join(tmpdir(), "grclanker-codex-check-"));
try {
  const workspace = join(fixture, "workspace");
  await mkdir(join(workspace, ".trestle"), { recursive: true });
  await mkdir(join(workspace, "catalogs", "sample-catalog"), { recursive: true });
  const inspector = await connect(["oscal_check_trestle"], {
    GRCLANKER_TRESTLE_BIN: join(fixture, "unavailable-trestle"),
  });
  try {
    const { tools } = await inspector.listTools();
    assert.deepEqual(tools.map((tool) => tool.name), ["oscal_check_trestle"]);
    const result = textResult(await inspector.callTool({ name: "oscal_check_trestle", arguments: { workspace_dir: workspace } }));
    assert.notEqual(result.isError, true);
    assert.ok(result.text.includes(`Workspace dir: ${workspace}`));
    assert.match(result.text, /Workspace:\s+initialized/);
    assert.match(result.text, /Trestle is not available yet/);
    assert.match(result.text, /catalog\s+[│|]\s+1/);
    // Reject the unselected writer before it can create a workspace directory.
    const denied = textResult(await inspector.callTool({ name: "oscal_init_workspace", arguments: { workspace_dir: join(fixture, "forbidden") } }));
    assert.equal(denied.isError, true);
    await assert.rejects(stat(join(fixture, "forbidden")), { code: "ENOENT" });
  } finally {
    await inspector.close();
  }

  // Use the real SDK with a local fake executable to check its subprocess
  // boundary: configuration, credentials, input, and JSONL result handling.
  const executable = join(fixture, "fake-codex.mjs");
  const capture = join(fixture, "capture.json");
  await writeFile(executable, `#!${process.execPath}
import { writeFile } from "node:fs/promises";
let input = "";
for await (const chunk of process.stdin) input += chunk;
await writeFile(process.env.CODEX_CHECK_CAPTURE, JSON.stringify({ args: process.argv.slice(2), apiKey: process.env.CODEX_API_KEY, input }));
console.log(JSON.stringify({ type: "thread.started", thread_id: "offline-check-thread" }));
console.log(JSON.stringify({ type: "item.completed", item: { id: "answer", type: "agent_message", text: "offline SDK result" } }));
console.log(JSON.stringify({ type: "turn.completed", usage: { input_tokens: 1, cached_input_tokens: 0, output_tokens: 1 } }));
`, { mode: 0o700 });
  const codex = new Codex({
    ...buildCodexOptions(["oscal_check_trestle"], "offline-placeholder-key"),
    codexPathOverride: executable,
    env: { CODEX_CHECK_CAPTURE: capture },
  });
  const thread = codex.startThread(threadOptions);
  const result = await thread.run("Inspect the temporary OSCAL workspace.");
  assert.equal(result.finalResponse, "offline SDK result");
  assert.equal(thread.id, "offline-check-thread");
  const invocation = JSON.parse(await readFile(capture, "utf8"));
  assert.equal(invocation.apiKey, "offline-placeholder-key");
  assert.equal(invocation.input, "Inspect the temporary OSCAL workspace.");
  const args = invocation.args;
  assert.ok(args.includes('mcp_servers.grclanker.env_vars=["GITHUB_ORG", "GITHUB_TOKEN", "GH_TOKEN"]'));
  assert.ok(args.includes(`mcp_servers.grclanker.command=${JSON.stringify(process.execPath)}`));
  assert.ok(args.includes(`mcp_servers.grclanker.args=[${JSON.stringify(fileURLToPath(new URL("./mcp-server.mjs", import.meta.url)))}, "oscal_check_trestle"]`));
  assert.ok(args.includes("mcp_servers.grclanker.required=true"));
  assert.equal(args[args.indexOf("--sandbox") + 1], "read-only");
  assert.ok(args.includes('approval_policy="never"'));
  assert.equal(args[args.indexOf("--cd") + 1], threadOptions.workingDirectory);
  console.log("Codex SDK subprocess configuration and result transport; MCP discovery, successful OSCAL inspection, input validation, and tool restrictions passed. No real API credentials or network calls used.");
} finally {
  await rm(fixture, { recursive: true, force: true });
}
