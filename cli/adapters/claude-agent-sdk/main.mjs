import { createInterface } from "node:readline/promises";
import { stdin, stdout, stderr } from "node:process";
import { query } from "@anthropic-ai/claude-agent-sdk";
import { classifyGrcToolEffect } from "../../dist/core/effects.js";
import { redactSensitiveArguments } from "../../dist/core/redact.js";
import { getRegisteredGrcTool, listRegisteredGrcToolNames } from "../../dist/core/registry.js";
import { CLAUDE_MODEL_ENV_VAR, createGrclankerClaudeOptions } from "./agent.mjs";
import { parseToolList } from "./tools.mjs";

const HELP = `Usage: npm --prefix cli run claude:run -- [options] "message"

  --check             Build the agent options and print the exposed tools, without a model request
  --list-tools        List every available native domain tool, without a model request
  --tools a,b,c       Select a deployment's domain tools (default: GRCLANKER_TOOLS, else four public-data lookups)
  --model id          Override ${CLAUDE_MODEL_ENV_VAR}
  --persist-session   Save the transcript under ~/.claude/projects and print its session ID
  --resume id         Continue a saved session (implies --persist-session)
  --help              Show this help

Model runs require ANTHROPIC_API_KEY (or Claude Code's Bedrock, Vertex AI, or Foundry
settings). Write calls require approval at an interactive terminal.
`;

function parseArgs(args) {
  const parsed = { messages: [], check: false, list: false, persistSession: false };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--help") parsed.help = true;
    else if (arg === "--check") parsed.check = true;
    else if (arg === "--list-tools") parsed.list = true;
    else if (arg === "--persist-session") parsed.persistSession = true;
    else if (arg === "--tools" || arg === "--model" || arg === "--resume") {
      const value = args[++index];
      if (!value || value.startsWith("--")) throw new Error(`${arg} needs a value.`);
      if (arg === "--tools") parsed.toolNames = parseToolList(value);
      else if (arg === "--model") parsed.model = value;
      else {
        parsed.resume = value;
        parsed.persistSession = true;
      }
    } else if (arg.startsWith("--")) throw new Error(`Unknown option: ${arg}`);
    else parsed.messages.push(arg);
  }
  return parsed;
}

function describeArguments(toolName, input) {
  try {
    return JSON.stringify(redactSensitiveArguments(input, getRegisteredGrcTool(toolName).parameters));
  } catch {
    // Unknown calls must not echo untrusted raw arguments.
    return "(arguments unavailable)";
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    stdout.write(HELP);
    return;
  }
  if (args.list) {
    stdout.write(`${JSON.stringify(listRegisteredGrcToolNames().map((name) => ({ name, effect: classifyGrcToolEffect(name) ?? "write" })), null, 2)}\n`);
    return;
  }
  const toolNames = args.toolNames
    ?? (process.env.GRCLANKER_TOOLS === undefined ? undefined : parseToolList(process.env.GRCLANKER_TOOLS));
  const terminal = stdin.isTTY && stderr.isTTY ? createInterface({ input: stdin, output: stderr }) : undefined;
  // Concurrent write calls can ask at once, and readline does not queue
  // questions; ask one at a time so each answer binds to the call shown.
  let queue = Promise.resolve();
  const approveWrite = ({ toolName, input, signal }) => {
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
    const { options, model, readTools, approvalTools } = createGrclankerClaudeOptions({
      toolNames,
      model: args.model,
      persistSession: args.persistSession,
      approveWrite,
    });
    if (args.check) {
      stdout.write(`${JSON.stringify({
        name: "grclanker",
        model,
        tools: readTools,
        approvalRequired: approvalTools,
        subagents: Object.keys(options.agents),
        settingSources: options.settingSources,
      }, null, 2)}\n`);
      return;
    }
    const message = args.messages.join(" ").trim();
    if (!message) throw new Error(HELP);

    let failed = false;
    for await (const event of query({ prompt: message, options: { ...options, ...(args.resume ? { resume: args.resume } : {}) } })) {
      if (event.type === "assistant") {
        for (const block of event.message.content) {
          if (block.type === "tool_use") stderr.write(`Tool: ${block.name}\n`);
        }
      } else if (event.type === "result") {
        if (event.subtype === "success") stdout.write(`${event.result}\n`);
        else {
          failed = true;
          stderr.write(`Claude Agent SDK run ended: ${event.subtype}${event.errors?.length ? ` (${event.errors.join("; ")})` : ""}\n`);
        }
        if (args.persistSession) stderr.write(`Claude session: ${event.session_id}\n`);
      }
    }
    if (failed) process.exitCode = 1;
  } finally {
    terminal?.close();
  }
}

main().catch((error) => {
  stderr.write(`${error instanceof Error ? error.message : "Claude Agent SDK run failed."}\n`);
  process.exitCode = 1;
});
