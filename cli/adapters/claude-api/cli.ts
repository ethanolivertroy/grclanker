import { createInterface } from "node:readline/promises";
import { stdin, stdout, stderr } from "node:process";
import Anthropic from "@anthropic-ai/sdk";
import { classifyGrcToolEffect } from "../../core/effects.js";
import { getRegisteredGrcTool, listRegisteredGrcToolNames } from "../../core/registry.js";
import { redactSensitiveArguments } from "../../core/redact.js";
import { CLAUDE_API_MODEL_ENV_VAR, createGrclankerClaudeApiAgent, type WriteApprovalRequest } from "./agent.js";
import { claudeApiFailureMessage, claudeCompletionFailure } from "./runtime.js";

const HELP = `Usage: npm --prefix cli run claude-api:run -- [options] "message"

  --check             Build the agent and print its exposed tools, without a model request
  --list-tools        List every available native domain tool, without a model request
  --tools a,b,c       Select a deployment's domain tools (default: four public-data lookups)
  --model id          Override ${CLAUDE_API_MODEL_ENV_VAR}
  --no-fallback       Do not re-run declined turns on Anthropic's fallback model
  --help              Show this help

Model runs require ANTHROPIC_API_KEY (or an \`ant auth login\` profile). Write calls require
approval at an interactive terminal.
`;

/** Diagnostics constructed from local, controlled strings rather than provider responses. */
class ClaudeApiCliError extends Error {}

function describeArguments(toolName: string, input: unknown): string {
  try {
    return JSON.stringify(redactSensitiveArguments(input, getRegisteredGrcTool(toolName).parameters));
  } catch {
    // Unknown calls must not echo untrusted raw arguments.
    return "(arguments unavailable)";
  }
}

async function main() {
  const args = process.argv.slice(2);
  const messages: string[] = [];
  let toolNames: string[] | undefined;
  let model: string | undefined;
  let check = false;
  let list = false;
  let serverSideFallback = true;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--help") {
      stdout.write(HELP);
      return;
    }
    if (arg === "--check") check = true;
    else if (arg === "--list-tools") list = true;
    else if (arg === "--no-fallback") serverSideFallback = false;
    else if (arg === "--tools" || arg === "--model") {
      const value = args[++index];
      if (!value || value.startsWith("--")) throw new ClaudeApiCliError(`${arg} needs a value.`);
      if (arg === "--tools") toolNames = value.split(",").map((name) => name.trim()).filter(Boolean);
      else model = value;
    } else if (arg.startsWith("--")) throw new ClaudeApiCliError("Unknown option; use --help for supported arguments.");
    else messages.push(arg);
  }
  if (list) {
    stdout.write(`${JSON.stringify(listRegisteredGrcToolNames().map((name) => ({ name, effect: classifyGrcToolEffect(name) ?? "write" })), null, 2)}\n`);
    return;
  }
  if (toolNames?.length === 0) throw new ClaudeApiCliError("Select at least one GRC tool with --tools.");
  if (toolNames) {
    const registered = new Set(listRegisteredGrcToolNames());
    if (toolNames.some((name) => !registered.has(name))) {
      throw new ClaudeApiCliError("Unknown GRC tool; use --list-tools to choose registered tool names.");
    }
  }

  const controller = new AbortController();
  const terminal = stdin.isTTY && stderr.isTTY ? createInterface({ input: stdin, output: stderr }) : undefined;
  const cancel = (exitCode: number) => {
    process.exitCode = exitCode;
    controller.abort();
    terminal?.close();
  };
  const interrupt = () => cancel(130);
  const terminate = () => cancel(143);
  const inputClosed = () => {
    if (!controller.signal.aborted) cancel(1);
  };
  process.once("SIGINT", interrupt);
  process.once("SIGTERM", terminate);
  terminal?.on("SIGINT", interrupt);
  terminal?.on("close", inputClosed);
  // Parallel tool calls can ask at once; ask one question at a time.
  let queue: Promise<unknown> = Promise.resolve();
  const approveWrite = ({ toolName, input, signal = controller.signal }: WriteApprovalRequest) => {
    const answer = queue.then(async () => {
      signal.throwIfAborted();
      stderr.write(`Approval required: ${toolName} ${describeArguments(toolName, input)}\n`);
      if (!terminal) {
        stderr.write("No interactive terminal; write denied.\n");
        return false;
      }
      return (await terminal.question("Approve this call? [y/N] ", { signal })).trim().toLowerCase() === "y";
    });
    queue = answer.catch(() => undefined);
    return answer;
  };

  try {
    // The client reads ANTHROPIC_API_KEY or another configured credential at request time.
    const client = new Anthropic();
    const agent = createGrclankerClaudeApiAgent(client, { toolNames, model, approveWrite, serverSideFallback });
    if (check) {
      stdout.write(`${JSON.stringify({ name: "grclanker", model: agent.model, tools: agent.tools.map((entry) => entry.name) }, null, 2)}\n`);
      return;
    }
    const message = messages.join(" ").trim();
    if (!message) throw new ClaudeApiCliError(HELP);

    const runner = client.beta.messages.toolRunner({ ...agent.params, stream: false, messages: [{ role: "user", content: message }] }, { signal: controller.signal });
    for await (const turn of runner) {
      for (const block of turn.content) {
        if (block.type === "tool_use") stderr.write(`Tool: ${block.name}\n`);
      }
    }
    const final = await runner.done();
    if (controller.signal.aborted) throw new ClaudeApiCliError(claudeApiFailureMessage(undefined, controller.signal));
    const text = final.content.flatMap((block) => block.type === "text" ? [block.text] : []).join("\n");
    const failure = claudeCompletionFailure(final.stop_reason, text, "run");
    if (failure) throw new ClaudeApiCliError(failure);
    stdout.write(`${text}\n`);
  } finally {
    process.removeListener("SIGINT", interrupt);
    process.removeListener("SIGTERM", terminate);
    terminal?.removeListener("SIGINT", interrupt);
    terminal?.removeListener("close", inputClosed);
    terminal?.close();
  }
}

main().catch((error: unknown) => {
  stderr.write(`${error instanceof ClaudeApiCliError ? error.message : claudeApiFailureMessage(error)}\n`);
  if (process.exitCode !== 130 && process.exitCode !== 143) process.exitCode = 1;
});
