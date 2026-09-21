/**
 * `grclanker flue ...` command surface.
 *
 * Also runnable directly as `node dist/flue/cli.js run --message "..."`.
 */
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { GrclankerFlueConfigError } from "./render.js";
import {
  createDefaultFlueRunDeps,
  exitCodeForOutcome,
  runGrclankerFlueAgent,
  type FlueRunDeps,
  type FlueRunOutcome,
  type FlueRunRequest,
} from "./run.js";

export interface FlueCommandIo {
  writeOut: (line: string) => void;
  writeErr: (line: string) => void;
}

export interface ParsedFlueRunArgs {
  request: FlueRunRequest;
  json: boolean;
}

export class FlueUsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FlueUsageError";
  }
}

export function formatFlueHelp(): string {
  return `
grclanker flue

Run grclanker as a Flue Framework agent (https://flueframework.com/).

Usage:
  grclanker flue run --message <text> [--id <conversation>] [--db <path|:memory:>] [--json]

Options:
  -m, --message <text>   The user message to deliver (required)
  --id <conversation>    Conversation id to create or continue (default: a fresh id)
  --db <path>            SQLite file for conversations (default: ~/.grclanker/flue/conversations.db)
  --json                 Print a JSON result envelope instead of the reply text
  --help, -h             Show this help

Environment:
  GRCLANKER_FLUE_MODEL     provider/model specifier (default: hosted setup, else anthropic/claude-sonnet-4-6)
  GRCLANKER_FLUE_SANDBOX   "local" (default) attaches a local sandbox for file and shell tools, "none" disables it
  Provider API keys        for example ANTHROPIC_API_KEY or OPENAI_API_KEY, read by the Flue runtime

Official CLI alternative (from the cli/ directory):
  npx flue run flue/agent.ts --message "<text>"
`.trim();
}

function readOptionValue(argv: string[], index: number, flag: string): string {
  const value = argv[index + 1];
  if (value === undefined || value.startsWith("-")) {
    throw new FlueUsageError(`${flag} requires a value.`);
  }
  return value;
}

export function parseFlueRunArgs(argv: string[]): ParsedFlueRunArgs {
  let message: string | undefined;
  let id: string | undefined;
  let db: string | undefined;
  let json = false;

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    switch (arg) {
      case "-m":
      case "--message":
        message = readOptionValue(argv, index, arg);
        index += 1;
        break;
      case "--id":
        id = readOptionValue(argv, index, arg);
        index += 1;
        break;
      case "--db":
        db = readOptionValue(argv, index, arg);
        index += 1;
        break;
      case "--json":
        json = true;
        break;
      default:
        throw new FlueUsageError(`Unknown option for 'grclanker flue run': ${arg}`);
    }
  }

  if (!message || message.trim().length === 0) {
    throw new FlueUsageError("'grclanker flue run' requires --message <text>.");
  }

  return { request: { message, id, db }, json };
}

export function formatFlueRunOutcome(outcome: FlueRunOutcome, json: boolean): { out?: string; err?: string } {
  if (json) return { out: JSON.stringify(outcome) };

  switch (outcome.outcome) {
    case "completed":
      return { out: outcome.message ?? "" };
    case "failed":
      return { err: `grclanker flue run failed: ${outcome.error ?? "unknown error"}` };
    case "aborted":
      return { err: `grclanker flue run was aborted: ${outcome.error ?? "no reason recorded"}` };
    default: {
      const exhaustive: never = outcome.outcome;
      throw new Error(`Unhandled outcome: ${String(exhaustive)}`);
    }
  }
}

function defaultIo(): FlueCommandIo {
  return {
    writeOut: (line) => process.stdout.write(`${line}\n`),
    writeErr: (line) => process.stderr.write(`${line}\n`),
  };
}

/** Dispatch `grclanker flue <subcommand>`; resolves with the process exit code. */
export async function runFlueCommand(
  argv: string[],
  io: FlueCommandIo = defaultIo(),
  deps?: Partial<FlueRunDeps>,
): Promise<number> {
  const [subcommand, ...rest] = argv;

  if (!subcommand || subcommand === "--help" || subcommand === "-h") {
    io.writeOut(formatFlueHelp());
    return 0;
  }

  if (subcommand !== "run") {
    io.writeErr(`Unknown flue subcommand: ${subcommand}`);
    io.writeErr("Run 'grclanker flue --help' for usage.");
    return 1;
  }

  try {
    const { request, json } = parseFlueRunArgs(rest);
    const outcome = await runGrclankerFlueAgent(request, {
      ...createDefaultFlueRunDeps(),
      writeErr: io.writeErr,
      ...deps,
    });
    const { out, err } = formatFlueRunOutcome(outcome, json);
    if (out !== undefined) io.writeOut(out);
    if (err !== undefined) io.writeErr(err);
    return exitCodeForOutcome(outcome.outcome);
  } catch (error) {
    if (error instanceof FlueUsageError || error instanceof GrclankerFlueConfigError) {
      io.writeErr(error.message);
      if (error instanceof FlueUsageError) io.writeErr("Run 'grclanker flue --help' for usage.");
      return 1;
    }
    throw error;
  }
}

const invokedDirectly =
  typeof process.argv[1] === "string" && resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (invokedDirectly) {
  runFlueCommand(process.argv.slice(2))
    .then((exitCode) => {
      process.exitCode = exitCode;
    })
    .catch((error) => {
      console.error(error);
      process.exitCode = 1;
    });
}
