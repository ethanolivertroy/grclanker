/**
 * `grclanker durable ...`: the experimental Pi Durable runtime.
 */
import { randomUUID } from "node:crypto";
import type { LiveState } from "@earendil-works/pi-durable";
import { resolveCliRoot } from "../agent-sdk/lib/paths.js";
import { syncBundledAssets } from "../bootstrap/sync.js";
import { getGrclankerAgentDir, getGrclankerSettingsPath } from "../config/paths.js";
import { ConfigFileError } from "../extensions/grc-tools/hardening/config-file.js";
import { readGrclankerSettings } from "../pi/settings.js";
import { DurableUsageError, DurableUserError } from "./errors.js";
import { DURABLE_MODEL_ENV, loadGrclankerModels, resolveDurableModelChoice } from "./models.js";
import { runDurable, type DurableOutcome, type DurableRunDeps, type DurableRunReport, type DurableRunRequest } from "./run.js";
import { durableSessionExists, durableSessionsDir, newDurableSessionId, resolveDurableSession } from "./session.js";
import { openDurableTui, type DurableTuiRequest, type DurableView } from "./tui/runtime.js";
import { runDurableTui } from "./tui/tui.js";

export interface DurableCommandIo {
  writeOut: (line: string) => void;
  writeErr: (line: string) => void;
}

/** `tui` opens the session in the terminal app instead of running one request. */
export type DurableCommandRequest = DurableRunRequest | (DurableTuiRequest & { command: "tui" });

export type DurableSubcommand = DurableCommandRequest["command"];

export interface ParsedDurableArgs {
  command: DurableSubcommand;
  message?: string;
  session?: string;
  requestId?: string;
  model?: string;
  json: boolean;
}

export const DURABLE_EXPERIMENTAL_BANNER = "grclanker durable (experimental)";

export function formatDurableHelp(): string {
  return `
${DURABLE_EXPERIMENTAL_BANNER}

Run the grclanker agent under the Pi Durable runtime. The session is stored on
disk, so a run that crashes or is stopped can be resumed. On resume, read-only
tools that were interrupted run again; tools that can write are never rerun and
are reported as interrupted instead.

Experimental: the commands, output, and session format may change between releases.

Usage:
  grclanker durable run --message <text> [--session <id>] [--request-id <id>] [--model <provider/model>] [--json]
  grclanker durable resume --session <id> [--model <provider/model>] [--json]
  grclanker durable tui [--session <id>] [--model <provider/model>]

Commands:
  run      Send a message: starts a new session, or continues the one named by --session
  resume   Finish the work an interrupted command left in a session
  tui      Chat in a terminal app: starts a new session, or opens the one named by --session
           and continues any work an interrupted command left in it

Options:
  -m, --message <text>      The message to send (run only, required)
  --session <id>            Session to create or continue (run, tui), or to resume (required for resume)
  --request-id <id>         Idempotency key for the message (default: a new UUID). Reusing the id of an
                            earlier request in the session reattaches to that request; the message is not compared
  --model <provider/model>  Model for this command (default: ${DURABLE_MODEL_ENV}, else the grclanker setup choice)
  --json                    Print a JSON report instead of the answer text
  --help, -h                Show this help

Sessions live in ~/.grclanker/durable/sessions/<id>/, and one process can use a session at a time.
Progress lines go to stderr. The answer, or the JSON report, goes to stdout.
Exit codes: 0 answered (or nothing to resume), 1 no answer or an error, 130 stopped by Ctrl-C.

In the terminal app, Enter sends a message (it steers the turn when one is running), Alt+Enter
(Ctrl+Q on Windows) queues a follow-up, Esc aborts the turn, and Ctrl+C, or Ctrl+D on an empty
editor, exits with code 0. Exiting keeps the session: work in flight continues when the session is
opened again.
/model picks a model, /compact summarizes older context, and /tasks hides or shows the task panel.
`.trim();
}

function readOptionValue(argv: string[], index: number, flag: string): string {
  const value = argv[index + 1];
  if (value === undefined || value.startsWith("-")) {
    throw new DurableUsageError(`${flag} requires a value.`);
  }
  return value;
}

export function parseDurableArgs(command: DurableSubcommand, argv: string[]): ParsedDurableArgs {
  const parsed: ParsedDurableArgs = { command, json: false };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    switch (arg) {
      case "-m":
      case "--message":
        parsed.message = readOptionValue(argv, index, arg);
        index += 1;
        break;
      case "--session":
        parsed.session = readOptionValue(argv, index, arg);
        index += 1;
        break;
      case "--request-id":
        parsed.requestId = readOptionValue(argv, index, arg);
        index += 1;
        break;
      case "--model":
        parsed.model = readOptionValue(argv, index, arg);
        index += 1;
        break;
      case "--json":
        parsed.json = true;
        break;
      default:
        throw new DurableUsageError(`Unknown option for 'grclanker durable ${command}': ${arg}`);
    }
  }

  switch (command) {
    case "run":
      if (!parsed.message || parsed.message.trim().length === 0) {
        throw new DurableUsageError("'grclanker durable run' requires --message <text>.");
      }
      if (parsed.requestId !== undefined && parsed.requestId.trim().length === 0) {
        throw new DurableUsageError("--request-id must not be empty.");
      }
      break;
    case "resume":
      if (!parsed.session) throw new DurableUsageError("'grclanker durable resume' requires --session <id>.");
      if (parsed.message !== undefined || parsed.requestId !== undefined) {
        throw new DurableUsageError(
          "'grclanker durable resume' takes no message. Use 'grclanker durable run --session <id> --message <text>' to continue a session.",
        );
      }
      break;
    case "tui":
      if (parsed.message !== undefined || parsed.requestId !== undefined || parsed.json) {
        throw new DurableUsageError(
          "'grclanker durable tui' takes only --session and --model. Type messages in the terminal app, or use 'grclanker durable run' to send one from the command line.",
        );
      }
      break;
    default: {
      const exhaustive: never = command;
      throw new Error(`Unhandled durable command: ${String(exhaustive)}`);
    }
  }

  return parsed;
}

export function buildDurableRequest(args: ParsedDurableArgs, env: NodeJS.ProcessEnv = process.env): DurableCommandRequest {
  const choice = resolveDurableModelChoice({
    flag: args.model,
    env,
    settings: readGrclankerSettings(getGrclankerSettingsPath()),
  });

  switch (args.command) {
    case "run":
      return {
        command: "run",
        session: resolveDurableSession(args.session ?? newDurableSessionId()),
        message: args.message ?? "",
        requestId: args.requestId?.trim() ?? randomUUID(),
        ...choice,
      };
    case "resume": {
      const session = resolveDurableSession(args.session ?? "");
      if (!durableSessionExists(session)) {
        throw new DurableUserError(`No durable session "${session.id}" in ${durableSessionsDir()}.`);
      }
      return { command: "resume", session, ...choice };
    }
    case "tui":
      return { command: "tui", session: resolveDurableSession(args.session ?? newDurableSessionId()), ...choice };
    default: {
      const exhaustive: never = args.command;
      throw new Error(`Unhandled durable command: ${String(exhaustive)}`);
    }
  }
}

export function exitCodeForDurableOutcome(outcome: DurableOutcome): number {
  switch (outcome) {
    case "completed":
    case "nothing_to_resume":
      return 0;
    case "unanswered":
      return 1;
    case "interrupted":
      return 130;
    default: {
      const exhaustive: never = outcome;
      throw new Error(`Unhandled outcome: ${String(exhaustive)}`);
    }
  }
}

export function formatDurableReport(report: DurableRunReport, json: boolean): { out: string[]; err: string[] } {
  if (json) return { out: [JSON.stringify(report)], err: [] };

  const out: string[] = [];
  const err: string[] = [];
  switch (report.outcome) {
    case "completed":
      out.push(report.answer ?? "");
      break;
    case "unanswered":
      err.push(`The request settled without an answer: ${report.reason ?? "no reason recorded"}`);
      break;
    case "interrupted":
      err.push(`Stopped. The session keeps its unfinished work: grclanker durable resume --session ${report.session}`);
      break;
    case "nothing_to_resume":
      err.push(`Nothing to resume: every request in session ${report.session} has settled.`);
      break;
    default: {
      const exhaustive: never = report.outcome;
      throw new Error(`Unhandled outcome: ${String(exhaustive)}`);
    }
  }

  const interrupted = report.tools.filter((tool) => tool.status === "interrupted").map((tool) => tool.tool);
  if (interrupted.length > 0) {
    err.push(
      `Interrupted and not rerun: ${interrupted.join(", ")}. Check what they wrote before running them again.`,
    );
  }
  return { out, err };
}

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** First Ctrl-C (or SIGTERM) stops the command and keeps the session resumable; a second exits at once. */
function handleInterrupts(controller: AbortController, io: DurableCommandIo): () => void {
  let interrupts = 0;
  const onSignal = () => {
    interrupts += 1;
    if (interrupts > 1) process.exit(130);
    io.writeErr("Stopping. Press Ctrl-C again to exit at once.");
    controller.abort();
  };
  process.on("SIGINT", onSignal);
  process.on("SIGTERM", onSignal);
  return () => {
    process.off("SIGINT", onSignal);
    process.off("SIGTERM", onSignal);
  };
}

function defaultIo(): DurableCommandIo {
  return {
    writeOut: (line) => process.stdout.write(`${line}\n`),
    writeErr: (line) => process.stderr.write(`${line}\n`),
  };
}

function isBusy(view: DurableView): boolean {
  return ((view.conversation.docs["pi.live"] ?? {}) as LiveState).run !== undefined;
}

/** Run the terminal app until the user exits. The session keeps work in flight for the next open. */
async function runDurableTuiCommand(
  request: DurableTuiRequest,
  io: DurableCommandIo,
  deps: Partial<DurableRunDeps>,
): Promise<number> {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new DurableUserError(
      "'grclanker durable tui' needs an interactive terminal. From a script or a pipe, use 'grclanker durable run --message <text>'.",
    );
  }
  const agentDir = getGrclankerAgentDir();
  // The grclanker theme, as the interactive CLI installs it, for a home that has never launched that CLI.
  syncBundledAssets(resolveCliRoot(), agentDir);
  const durable = await openDurableTui(request, {
    loadModels: deps.loadModels ?? (() => loadGrclankerModels()),
    ...(deps.tools ? { tools: deps.tools } : {}),
    ...(deps.settings ? { settings: deps.settings } : {}),
  });
  try {
    await runDurableTui(durable.view, durable.controller, { agentDir, banner: DURABLE_EXPERIMENTAL_BANNER });
  } finally {
    await durable.close();
  }
  const id = request.session.id;
  io.writeErr(
    isBusy(durable.view.current())
      ? `Closed with work in flight; it continues when session ${id} is opened again: grclanker durable tui --session ${id} (or grclanker durable resume --session ${id} to finish it without the terminal app).`
      : `Session ${id} is saved. Open it again with: grclanker durable tui --session ${id}`,
  );
  return 0;
}

/** Dispatch `grclanker durable <subcommand>`; resolves with the process exit code. */
export async function runDurableCommand(
  argv: string[],
  io: DurableCommandIo = defaultIo(),
  deps: Partial<DurableRunDeps> = {},
): Promise<number> {
  const [subcommand, ...rest] = argv;

  if (!subcommand || subcommand === "--help" || subcommand === "-h" || rest.includes("--help") || rest.includes("-h")) {
    io.writeOut(formatDurableHelp());
    return 0;
  }

  if (subcommand !== "run" && subcommand !== "resume" && subcommand !== "tui") {
    io.writeErr(`Unknown durable subcommand: ${subcommand}`);
    io.writeErr("Run 'grclanker durable --help' for usage.");
    return 1;
  }

  try {
    const args = parseDurableArgs(subcommand, rest);
    const request = buildDurableRequest(args);
    io.writeErr(DURABLE_EXPERIMENTAL_BANNER);
    if (request.command === "tui") return await runDurableTuiCommand(request, io, deps);

    const controller = new AbortController();
    const stopHandling = handleInterrupts(controller, io);
    try {
      const report = await runDurable(request, {
        loadModels: () => loadGrclankerModels(),
        onActivity: io.writeErr,
        onReport: (error) => io.writeErr(`durable runtime: ${describeError(error)}`),
        signal: controller.signal,
        ...deps,
      });
      const { out, err } = formatDurableReport(report, args.json);
      for (const line of out) io.writeOut(line);
      for (const line of err) io.writeErr(line);
      return exitCodeForDurableOutcome(report.outcome);
    } finally {
      stopHandling();
    }
  } catch (error) {
    if (error instanceof DurableUserError || error instanceof ConfigFileError) {
      io.writeErr(error.message);
      if (error instanceof DurableUsageError) io.writeErr("Run 'grclanker durable --help' for usage.");
      return 1;
    }
    throw error;
  }
}
