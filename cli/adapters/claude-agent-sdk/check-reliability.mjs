/** Authorization/cancellation regressions through MCP and the real SDK executable. */
import assert from "node:assert/strict";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { getRegisteredGrcTool } from "../../dist/core/registry.js";
import { createGrclankerClaudeOptions, mcpToolName, restrictReviewerAgents } from "./agent.mjs";
import { createGrclankerMcpServer, WriteApprovals } from "./server.mjs";
import { selectTools } from "./tools.mjs";
import { runOfflineScenario, resultText, toolResults } from "./check-helpers.mjs";

const writerName = "oscal_init_workspace";
const sdkServerInfo = { name: "grclanker", source: "sdk" };
const toolCall = (id, name, input) => ({ type: "tool_use", id, name, input });
const responseText = (result) => result.content.map((block) => block.text ?? "").join("\n");

async function connect(server) {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.instance.connect(serverTransport);
  const client = new Client({ name: "grclanker-reliability-check", version: "0.1.0" });
  await client.connect(clientTransport);
  return client;
}

async function createWriterFixture(fixture, name) {
  const workspace = join(fixture, name);
  const executionLog = join(workspace, "executions.log");
  await mkdir(workspace);
  // Node runs "init" as a script when the native OSCAL tool invokes ["init", "--full"].
  await writeFile(join(workspace, "init"), `
    const fs = require("node:fs");
    fs.appendFileSync(${JSON.stringify(executionLog)}, "initialized\\n");
    fs.mkdirSync(".trestle");
  `);
  return { workspace, executionLog };
}

async function checkReviewerScope(fixture) {
  const native = getRegisteredGrcTool("oscal_check_trestle");
  const original = native.execute;
  let nativeCalls = 0;
  native.execute = (...args) => { nativeCalls += 1; return original(...args); };
  try {
    const { requests, childRequests, subagentStarts, hookInputs } = await runOfflineScenario({
      fixture,
      toolNames: [native.name],
      mainScript: [
        toolCall("forbidden_explore", "Agent", { subagent_type: "Explore", description: "Search new evidence", prompt: "Collect fresh evidence.", run_in_background: false }),
        toolCall("allowed_auditor", "Agent", { subagent_type: "auditor", description: "Audit supplied evidence", prompt: "Review only this supplied evidence: a test.", run_in_background: false }),
        toolCall("allowed_verifier", "Agent", { subagent_type: "verifier", description: "Verify supplied evidence", prompt: "Review only this supplied evidence: a test.", run_in_background: false }),
        { type: "text", text: "reviewer scenario complete" },
      ],
      // Deliberately request an unavailable tenant tool from both reviewers.
      childScript: [
        toolCall("child_native_attempt", mcpToolName(native.name), { workspace_dir: fixture }),
        { type: "text", text: "review complete without new evidence" },
      ],
    });
    const final = requests.at(-1);
    assert.match(resultText(final, "forbidden_explore"), /Only the auditor and verifier/);
    assert.equal(toolResults(final).find((result) => result.tool_use_id === "forbidden_explore").is_error, true);
    assert.deepEqual(subagentStarts.map((start) => start.agent_type).sort(), ["auditor", "verifier"]);
    assert.ok(hookInputs.some((input) => input.tool_input?.subagent_type === "Explore"), "the real PreToolUse hook must inspect Explore");
    assert.match(resultText(final, "allowed_auditor"), /review complete without new evidence/);
    assert.match(resultText(final, "allowed_verifier"), /review complete without new evidence/);
    assert.ok(childRequests.length >= 4, "both permitted reviewers must actually run and receive tool errors");
    for (const request of childRequests) assert.deepEqual(request.tools ?? [], [], "reviewers must have no tools");
    const childFailures = childRequests.flatMap(toolResults).filter((result) => result.tool_use_id === "child_native_attempt");
    assert.equal(childFailures.length, 2, "each reviewer must receive its attempted native call's rejection");
    for (const failure of childFailures) assert.equal(failure.is_error, true);
    assert.equal(nativeCalls, 0, "neither blocked Explore nor reviewer tool attempts may reach native execution");
  } finally {
    native.execute = original;
  }
  for (const input of [{}, { subagent_type: "general-purpose" }, { subagent_type: "fork" }, { subagent_type: "auditor", isolation: "worktree" }]) {
    assert.equal((await restrictReviewerAgents({ tool_name: "Agent", tool_input: input })).hookSpecificOutput.permissionDecision, "deny");
  }
}

async function checkApprovedWrites(fixture) {
  const native = getRegisteredGrcTool(writerName);
  const original = native.execute;
  const previousExecutable = process.env.GRCLANKER_TRESTLE_BIN;
  process.env.GRCLANKER_TRESTLE_BIN = process.execPath;
  let nativeCalls = 0;
  native.execute = (...args) => { nativeCalls += 1; return original(...args); };
  try {
    const { workspace, executionLog } = await createWriterFixture(fixture, "approved-sdk-write");
    const changed = join(fixture, "unapproved-changed-sdk-write");
    const approvalsAsked = [];
    const { requests } = await runOfflineScenario({
      fixture, toolNames: [writerName],
      mainScript: [
        toolCall("approved_write", mcpToolName(writerName), { workspace_dir: workspace }),
        toolCall("replayed_write", mcpToolName(writerName), { workspace_dir: workspace }),
        toolCall("changed_write", mcpToolName(writerName), { workspace_dir: changed }),
        { type: "text", text: "write scenario complete" },
      ],
      async approveWrite(request) { approvalsAsked.push(request.input.workspace_dir); return approvalsAsked.length === 1; },
    });
    assert.deepEqual(approvalsAsked, [workspace, workspace, changed], "approval must be requested independently for every SDK write");
    const final = requests.at(-1);
    assert.match(resultText(final, "approved_write"), /Trestle workspace initialized/);
    assert.match(resultText(final, "replayed_write"), /did not approve/);
    assert.match(resultText(final, "changed_write"), /did not approve/);
    assert.equal(nativeCalls, 1);
    assert.equal(await readFile(executionLog, "utf8"), "initialized\n");
    await stat(join(workspace, ".trestle"));
    await assert.rejects(stat(changed), { code: "ENOENT" });

    // Exercise the MCP gate itself: a changed request cannot spend an approval,
    // and a successful exact-input handoff consumes it before native execution.
    const direct = await createWriterFixture(fixture, "approved-mcp-write");
    const approvals = new WriteApprovals();
    const client = await connect(createGrclankerMcpServer(selectTools([writerName]), approvals));
    try {
      approvals.grant(writerName, { workspace_dir: direct.workspace });
      const altered = await client.callTool({ name: writerName, arguments: { workspace_dir: changed } });
      assert.equal(altered.isError, true);
      assert.match(responseText(altered), /requires operator approval/);
      const approved = await client.callTool({ name: writerName, arguments: { workspace_dir: direct.workspace } });
      assert.notEqual(approved.isError, true);
      assert.match(responseText(approved), /Trestle workspace initialized/);
      const replayed = await client.callTool({ name: writerName, arguments: { workspace_dir: direct.workspace } });
      assert.equal(replayed.isError, true);
      assert.match(responseText(replayed), /requires operator approval/);
      assert.equal(nativeCalls, 2);
      assert.equal(await readFile(direct.executionLog, "utf8"), "initialized\n");
    } finally { await client.close(); }
  } finally {
    native.execute = original;
    if (previousExecutable === undefined) delete process.env.GRCLANKER_TRESTLE_BIN;
    else process.env.GRCLANKER_TRESTLE_BIN = previousExecutable;
  }
}

async function checkCancelledApprovals(fixture) {
  const secret = "synthetic-secret-approval-error";
  for (const mode of ["before", "pending", "rejected", "granted"]) {
    const controller = new AbortController();
    let approve;
    let asked = 0;
    const { options } = createGrclankerClaudeOptions({
      toolNames: [writerName],
      approveWrite: async () => {
        asked += 1;
        if (mode === "rejected") throw new Error(secret);
        if (mode === "granted") return true;
        return new Promise((resolve) => { approve = resolve; });
      },
    });
    const input = { workspace_dir: join(fixture, `cancelled-${mode}`) };
    if (mode === "before") controller.abort(new Error(secret));
    const pending = options.canUseTool(mcpToolName(writerName), input, { signal: controller.signal, mcpServer: sdkServerInfo });
    if (mode === "pending") {
      await Promise.resolve();
      assert.equal(asked, 1, "cancellation must interrupt a UI that actually started");
      controller.abort(new Error(secret));
    }
    const result = await pending;
    if (mode === "granted") { assert.equal(result.behavior, "allow"); controller.abort(new Error(secret)); }
    else { assert.equal(result.behavior, "deny"); assert.ok(!JSON.stringify(result).includes(secret)); }
    if (mode === "before") assert.equal(asked, 0);
    approve?.(true); // A UI completing after cancellation must not resurrect its grant.
    await Promise.resolve();
    const client = await connect(options.mcpServers.grclanker);
    try {
      const denied = await client.callTool({ name: writerName, arguments: input });
      assert.equal(denied.isError, true);
      assert.match(responseText(denied), /requires operator approval/);
      await assert.rejects(stat(input.workspace_dir), { code: "ENOENT" });
    } finally { await client.close(); }
  }
  const approvals = new WriteApprovals();
  const cancelled = new AbortController();
  approvals.grant(writerName, {}, cancelled.signal);
  approvals.grant(writerName, {});
  cancelled.abort();
  assert.equal(approvals.consume(writerName, {}), true, "cancelling one grant must preserve a separate identical approval");
  assert.equal(approvals.consume(writerName, {}), false);
}

export async function checkReliability(fixture) {
  await checkReviewerScope(fixture);
  await checkApprovedWrites(fixture);
  await checkCancelledApprovals(fixture);
  console.log("Claude SDK reliability: only auditor/verifier started; reviewer tool attempts denied; approved native writer ran exactly once; altered/replayed calls denied; cancelled, failed, and late approvals could not execute.");
}
