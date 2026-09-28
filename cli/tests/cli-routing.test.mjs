import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { expandPromptTemplate } from "../node_modules/@earendil-works/pi-coding-agent/dist/core/prompt-templates.js";
import { routeCliInvocation } from "../dist/pi/cli-routing.js";
import { buildCliLaunchArgs, buildWorkflowPrompt } from "../dist/pi/launch.js";

const cliRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const workflows = ["assess", "audit", "investigate", "validate"];

function expandWorkflow(workflow, subject) {
  return expandPromptTemplate(
    buildWorkflowPrompt(workflow, subject),
    [{
      name: workflow,
      content: readFileSync(resolve(cliRoot, "prompts", `${workflow}.md`), "utf8"),
    }],
  );
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

  const args = buildCliLaunchArgs(cliRoot, "/tmp/grclanker-home/agent", {}, invocation.prompt);
  assert.deepEqual(args.slice(-2), ["--", "Investigate CVE-2024-3094"]);
  assert.equal(args.includes("--compute"), false);
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

test("all workflow templates expand their subject through $ARGUMENTS", () => {
  for (const workflow of workflows) {
    const prompt = expandWorkflow(workflow, "CVE-2024-3094 OpenSSL");
    assert.match(prompt, /Subject: CVE-2024-3094 OpenSSL/);
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
  assert.match(
    expandWorkflow(invocation.command, invocation.prompt),
    /Subject: --compute not-a-backend/,
  );
});

test("option-like unknown commands retain the Unknown command route", () => {
  assert.deepEqual(
    routeCliInvocation(["--not-a-command", "subject"], workflows),
    { kind: "unknown-option", command: "--not-a-command" },
  );
});

test("workflow commands without a subject remain valid", () => {
  const invocation = routeCliInvocation(["investigate"], workflows);
  assert.deepEqual(invocation, { kind: "command", command: "investigate" });
  assert.match(expandWorkflow(invocation.command), /# Vulnerability Investigation/);
  assert.match(expandWorkflow(invocation.command), /Subject:\s*\n/);
});
