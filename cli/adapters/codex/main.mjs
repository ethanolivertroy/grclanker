import { Codex } from "@openai/codex-sdk";
import { buildGrclankerInstructions } from "../../dist/core/instructions.js";
import { defaultTools } from "./tools.mjs";
import { buildCodexOptions, threadOptions } from "./config.mjs";

const toolNames = process.env.GRCLANKER_TOOLS === undefined
  ? defaultTools
  : process.env.GRCLANKER_TOOLS.split(",").map((name) => name.trim());

if (!process.env.OPENAI_API_KEY) {
  throw new Error("Set OPENAI_API_KEY for this Codex SDK example.");
}

const codex = new Codex(buildCodexOptions(toolNames, process.env.OPENAI_API_KEY));
const thread = codex.startThread(threadOptions);

const instructions = buildGrclankerInstructions(`
You are running in the Codex SDK. The enabled GRC tools are available through
the grclanker MCP server: ${toolNames.join(", ")}.
Use those tools for evidence. This example permits read operations only and has
no configured auditor or verifier subagents. Do not write files or run shell
commands to gather evidence. Explain unavailable evidence and tool failures.
Help the organization assess governance, risk, and compliance; separate observed
configuration from policy judgments and decisions that need an accountable owner.
`);
const prompt = process.argv.slice(2).join(" ") ||
  "Check CVE-2024-3400 in the CISA KEV catalog and get its EPSS score. Explain the evidence and its limits.";

const turn = await thread.run(`${instructions}\n\nUser request:\n${prompt}`);
console.log(turn.finalResponse);
console.error(`Codex thread: ${thread.id}`);
