import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { parseArgs } from "@earendil-works/pi-coding-agent";
import { runPrintMode } from "../node_modules/@earendil-works/pi-coding-agent/dist/modes/print-mode.js";
import { CLI_HELP } from "../dist/pi/cli-help.js";
import grcTools from "../dist/extensions/grc-tools.js";
import { routeCliInvocation } from "../dist/pi/cli-routing.js";
import { buildCliLaunchArgs } from "../dist/pi/launch.js";
import {
  extractInitialPrompt,
  materializeInitialPrompt,
  serializeInitialPrompt,
} from "../dist/pi/prompt-envelope.js";
import { renderWorkflowPrompt } from "../dist/pi/workflow-prompt.js";

const cliRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const workflows = ["assess", "audit", "investigate", "validate"];

function renderWorkflow(workflow, subject) {
  return renderWorkflowPrompt(
    readFileSync(resolve(cliRoot, "prompts", `${workflow}.md`), "utf8"),
    subject,
  );
}

function registeredInitialPromptHandler() {
  let handler;
  grcTools({
    on(event, candidate) {
      if (event === "input") handler = candidate;
      return () => {};
    },
    registerTool() {},
  });
  assert.equal(typeof handler, "function");
  return handler;
}

async function runRecordingPrintMode(initialMessage, inputHandler) {
  const promptCalls = [];
  const lifecycle = [];
  const session = {
    sessionManager: { getHeader: () => undefined },
    state: { messages: [] },
    async bindExtensions() {},
    subscribe() {
      return () => {};
    },
    async prompt(text) {
      lifecycle.push("prompt");
      const result = await inputHandler({ type: "input", text, source: "interactive" });
      assert.equal(result.action, "transform");
      promptCalls.push(result.text);
      await Promise.resolve();
      session.state.messages.push({ role: "assistant", content: [] });
      lifecycle.push("turn-complete");
    },
  };
  const runtime = {
    session,
    async dispose() {
      lifecycle.push("disposed");
    },
    setRebindSession() {},
  };

  await runPrintMode(runtime, { mode: "text", initialMessage });
  return { lifecycle, promptCalls };
}

test("non-option invocations route as one free-form Pi prompt", () => {
  const invocation = routeCliInvocation(
    ["Investigate", "CVE-2024-3094", "--compute", "modal"],
    workflows,
  );

  assert.deepEqual(invocation, {
    kind: "prompt",
    compute: "modal",
    prompt: "Investigate CVE-2024-3094",
  });

  const args = buildCliLaunchArgs(cliRoot, "/tmp/grclanker-home/agent", {}, {
    kind: "prompt",
    content: invocation.prompt,
  });
  const parsed = parseArgs(args);
  assert.equal(parsed.fileArgs.length, 0);
  assert.deepEqual(parsed.messages, [args.at(-1)]);
  assert.equal(args.at(-1).startsWith("-"), false);
  assert.equal(args.includes("--no-prompt-templates"), false);
});

test("workflow subjects survive both --compute forms and positions", () => {
  const cases = [
    [["investigate", "CVE-2024-3094", "--compute", "modal"], "modal", "CVE-2024-3094"],
    [["audit", "--compute=docker", "production", "AWS"], "docker", "production AWS"],
    [["assess", "Acme", "--compute", "host", "production"], "host", "Acme production"],
    [["validate", "OpenSSL", "--compute=host"], "host", "OpenSSL"],
  ];

  for (const [args, compute, subject] of cases) {
    const invocation = routeCliInvocation(args, workflows);
    assert.equal(invocation.kind, "command");
    assert.equal(invocation.compute, compute);
    assert.equal(invocation.prompt, subject);
  }
});

test("all workflow templates render their subject through $ARGUMENTS", () => {
  for (const workflow of workflows) {
    const prompt = renderWorkflow(workflow, "CVE-2024-3094 OpenSSL");
    assert.match(prompt, /Subject: CVE-2024-3094 OpenSSL/);
    assert.equal(prompt.includes("$ARGUMENTS"), false);
  }
});

test("workflow invocation preserves delimiter-protected --compute text", () => {
  const invocation = routeCliInvocation(
    ["investigate", "--", "--compute", "not-a-backend"],
    workflows,
  );

  assert.deepEqual(invocation, {
    kind: "command",
    command: "investigate",
    prompt: "--compute not-a-backend",
  });
  assert.match(renderWorkflow(invocation.command, invocation.prompt), /Subject: --compute not-a-backend/);
});

test("reserved roots, option-like commands, and workflow typos retain the Unknown command route", () => {
  assert.deepEqual(
    routeCliInvocation(["--not-a-command", "subject"], workflows),
    { kind: "unknown-option", command: "--not-a-command" },
  );
  assert.deepEqual(
    routeCliInvocation(["env", "exe", "--", "hostname"], workflows),
    { kind: "unknown-command", command: "env" },
  );
  assert.deepEqual(
    routeCliInvocation(["setup", "typo"], ["setup", ...workflows]),
    { kind: "unknown-command", command: "setup" },
  );
  assert.deepEqual(
    routeCliInvocation(["invesigate", "OpenSSL"], workflows),
    { kind: "unknown-command", command: "invesigate" },
  );
  assert.deepEqual(
    routeCliInvocation(["auidt", "AWS"], workflows),
    { kind: "unknown-command", command: "auidt" },
  );
});

test("workflow commands without a subject remain valid", () => {
  const invocation = routeCliInvocation(["investigate"], workflows);
  assert.deepEqual(invocation, { kind: "command", command: "investigate" });
  assert.match(renderWorkflow(invocation.command), /# Vulnerability Investigation/);
  assert.match(renderWorkflow(invocation.command), /Subject:\s*\n/);
});

test("initial prompt envelopes preserve literal user text and workflow precedence over piped input", () => {
  const literal = `@evidence "quoted" O'Reilly /audit --compute=modal`;
  const serialized = serializeInitialPrompt({ kind: "prompt", content: literal });
  const parsed = parseArgs([serialized]);
  assert.deepEqual(parsed.messages, [serialized]);
  assert.deepEqual(parsed.fileArgs, []);

  const freeForm = extractInitialPrompt(serialized);
  assert.deepEqual(freeForm, { pipedInput: "", payload: { kind: "prompt", content: literal } });
  assert.equal(materializeInitialPrompt(freeForm.payload, freeForm.pipedInput), literal);

  const workflow = renderWorkflow("audit", literal);
  const piped = extractInitialPrompt(`tenant evidence${serializeInitialPrompt({ kind: "workflow", content: workflow })}`);
  assert.ok(piped);
  const materialized = materializeInitialPrompt(piped.payload, piped.pipedInput);
  assert.ok(materialized.startsWith(workflow));
  assert.match(materialized, /## Piped input\n\ntenant evidence$/);
  assert.equal(materialized.includes("$ARGUMENTS"), false);
});

test("slash-leading free-form prompts stay literal without disabling later templates", async () => {
  const literal = "/audit x";
  const handler = registeredInitialPromptHandler();
  const result = await handler({
    type: "input",
    text: serializeInitialPrompt({ kind: "prompt", content: literal }),
    source: "interactive",
  });
  assert.deepEqual(result, { action: "transform", text: `## CLI prompt\n\n${literal}` });

  assert.deepEqual(
    await handler({
      type: "input",
      text: serializeInitialPrompt({ kind: "prompt", content: literal }),
      source: "rpc",
    }),
    { action: "continue" },
  );
  assert.deepEqual(
    await handler({
      type: "input",
      text: serializeInitialPrompt({ kind: "prompt", content: literal }),
      source: "extension",
    }),
    { action: "continue" },
  );
});

test("serialized prompts complete in print mode before runtime disposal", async () => {
  const content = renderWorkflow("investigate", `@evidence "quoted" O'Reilly`);
  const initialMessage = serializeInitialPrompt({ kind: "workflow", content });
  const result = await runRecordingPrintMode(initialMessage, registeredInitialPromptHandler());

  assert.deepEqual(result.promptCalls, [content]);
  assert.deepEqual(result.lifecycle, ["prompt", "turn-complete", "disposed"]);
});

test("help documents prompt, workflow, compute, and delimiter invocation forms", () => {
  assert.match(CLI_HELP, /grclanker "<prompt>"/);
  for (const workflow of workflows) {
    assert.match(CLI_HELP, new RegExp(`${workflow} <subject> \\[--compute <kind>\\]`));
  }
  assert.match(CLI_HELP, /Treat all following text literally/);
});
