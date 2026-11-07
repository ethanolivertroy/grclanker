/** JSON interface for hosts that run GRC tools as local subprocesses. */
import { pathToFileURL } from "node:url";
import { isGrcWriteTool, classifyGrcToolEffect } from "./effects.js";
import { buildGrclankerInstructions } from "./instructions.js";
import { collectRegisteredGrcTools, getRegisteredGrcTool } from "./registry.js";
import { errorEnvelope } from "./results.js";
import { toJsonSchema } from "./schema.js";
import { executeRegisteredGrcTool } from "./tools.js";

const MAX_INPUT_BYTES = 1024 * 1024;

function printJson(value: unknown): void {
  process.stdout.write(`${JSON.stringify(value)}\n`);
}

async function readInput(): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += bytes.length;
    if (size > MAX_INPUT_BYTES) throw new Error("Tool input exceeds the 1 MiB limit.");
    chunks.push(bytes);
  }
  let input: unknown;
  try {
    input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new Error("Pass one JSON object on stdin. Invalid JSON is not echoed.");
  }
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("Tool input must be a JSON object.");
  }
  return input as Record<string, unknown>;
}

export async function runRuntimeCli(args: string[] = process.argv.slice(2)): Promise<void> {
  try {
    const [command, ...rest] = args;
    if (command === "list") {
      const tools = rest.length ? rest.map(getRegisteredGrcTool) : collectRegisteredGrcTools();
      printJson(tools.map((tool) => ({
        name: tool.name,
        description: tool.description,
        inputSchema: toJsonSchema(tool.parameters),
        effect: classifyGrcToolEffect(tool.name),
        needsApproval: isGrcWriteTool(tool.name),
      })));
      return;
    }
    if (command === "instructions" && rest.length === 0) {
      process.stdout.write(buildGrclankerInstructions());
      return;
    }
    if (command === "call" && rest[0] && (rest.length === 1 || (rest.length === 2 && rest[1] === "--allow-write"))) {
      const result = await executeRegisteredGrcTool(rest[0], await readInput(), {
        allowWrites: rest[1] === "--allow-write",
      });
      printJson(result);
      if (result.isError) process.exitCode = 1;
      return;
    }
    throw new Error("Usage: runtime/cli.js list [TOOL ...] | instructions | call TOOL [--allow-write] (JSON object on stdin)");
  } catch (error) {
    printJson(errorEnvelope(error instanceof Error ? error.message : "GRC tool runner failed."));
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await runRuntimeCli();
}
