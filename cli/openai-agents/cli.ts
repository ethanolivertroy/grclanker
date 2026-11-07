import { createInterface } from "node:readline/promises";
import { stdin, stdout, stderr } from "node:process";
import { Runner } from "@openai/agents";
import { classifyGrcToolEffect } from "../runtime/effects.js";
import { getRegisteredGrcTool, listRegisteredGrcToolNames } from "../runtime/registry.js";
import { redactSensitiveArguments } from "../runtime/redact.js";
import { createGrclankerOpenAIAgent, OPENAI_MODEL_ENV_VAR } from "./agent.js";

const HELP = `Usage: npm --prefix cli run openai-agents:run -- [options] "message"

  --check             Build the agent and print its exposed tools, without a model request
  --list-tools        List every available native domain tool, without a model request
  --tools a,b,c       Select a deployment's domain tools (default: four public-data lookups)
  --model id          Override ${OPENAI_MODEL_ENV_VAR}
  --help              Show this help

Model runs require OPENAI_API_KEY. Write calls require approval at an interactive terminal.
`;

async function main() {
  const args = process.argv.slice(2);
  const messages: string[] = [];
  let toolNames: string[] | undefined;
  let model: string | undefined;
  let check = false;
  let list = false;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--help") {
      stdout.write(HELP);
      return;
    }
    if (arg === "--check") check = true;
    else if (arg === "--list-tools") list = true;
    else if (arg === "--tools" || arg === "--model") {
      const value = args[++index];
      if (!value || value.startsWith("--")) throw new Error(`${arg} needs a value.`);
      if (arg === "--tools") toolNames = value.split(",").map((name) => name.trim()).filter(Boolean);
      else model = value;
    } else if (arg.startsWith("--")) throw new Error(`Unknown option: ${arg}`);
    else messages.push(arg);
  }
  if (list) {
    stdout.write(`${JSON.stringify(listRegisteredGrcToolNames().map((name) => ({ name, effect: classifyGrcToolEffect(name) ?? "write" })), null, 2)}\n`);
    return;
  }
  const agent = createGrclankerOpenAIAgent({ toolNames, model });
  if (check) {
    stdout.write(`${JSON.stringify({ name: agent.name, model: agent.model, tools: agent.tools.map((entry) => entry.type === "function" ? { name: entry.name } : { type: entry.type }) }, null, 2)}\n`);
    return;
  }
  const message = messages.join(" ").trim();
  if (!message) throw new Error(HELP);
  if (!process.env.OPENAI_API_KEY?.trim()) throw new Error("Set OPENAI_API_KEY before running a model turn.");

  // This CLI keeps evidence out of the SDK's separate tracing exporter. Model
  // requests still contain the selected tools' inputs, results, and prompts.
  const runner = new Runner({ tracingDisabled: true });
  let result = await runner.run(agent, message, { maxTurns: 20 });
  const terminal = stdin.isTTY && stderr.isTTY
    ? createInterface({ input: stdin, output: stderr })
    : undefined;
  try {
    while (result.interruptions.length > 0) {
      for (const interruption of result.interruptions) {
        const name = interruption.name ?? "unknown";
        let displayArguments = "(arguments unavailable)";
        try {
          displayArguments = JSON.stringify(redactSensitiveArguments(
            JSON.parse(interruption.arguments ?? "{}"),
            getRegisteredGrcTool(name).parameters,
          ));
        } catch {
          // Malformed or unknown calls must not echo untrusted raw arguments.
        }
        stderr.write(`Approval required: ${name} ${displayArguments}\n`);
        const answer = terminal ? await terminal.question("Approve this call? [y/N] ") : "n";
        if (answer.trim().toLowerCase() === "y") result.state.approve(interruption);
        else result.state.reject(interruption);
      }
      result = await runner.run(agent, result.state, { maxTurns: 20 });
    }
    stdout.write(`${result.finalOutput ?? ""}\n`);
  } finally {
    terminal?.close();
  }
}

main().catch((error: unknown) => {
  stderr.write(`${error instanceof Error ? error.message : "OpenAI Agents SDK run failed."}\n`);
  process.exitCode = 1;
});
