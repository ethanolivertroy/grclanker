/**
 * Preload for end-to-end `grclanker durable` runs: Pi's faux provider stands in
 * for the model, and fetch answers PagerDuty requests from a fixture. Nothing
 * leaves the machine and no credential is real.
 *
 *   node --import <file URL of this module> dist/index.js durable run --model faux/faux-1 ...
 *
 * The faux model answers a request with one parallel tool round (a fast and a
 * slow read-only assessment plus an audit bundle export), then with a summary
 * of the tool results once the transcript holds them.
 *
 * Environment:
 * - GRCLANKER_TEST_DURABLE_LOG: JSONL file that receives one line per model
 *   call, per API request, and per hanging request aborted, each with the
 *   process id.
 * - GRCLANKER_TEST_DURABLE_HANG: comma-separated API paths that never answer in
 *   this process. A request to one stays open until its signal aborts, so the
 *   tools that read them are still running when the process is killed or stopped.
 */
import { appendFileSync } from "node:fs";
import { createModels } from "@earendil-works/pi-ai/models";
import { fauxAssistantMessage, fauxProvider, fauxText, fauxToolCall } from "@earendil-works/pi-ai/providers/faux";
import { ModelRuntime } from "@earendil-works/pi-coding-agent";

export const FAST_READ_TOOL = "pagerduty_assess_access_control";
export const SLOW_READ_TOOL = "pagerduty_assess_oncall_coverage";
export const WRITE_TOOL = "pagerduty_export_audit_bundle";
export const DURABLE_E2E_MODEL = "faux/faux-1";

const logPath = process.env.GRCLANKER_TEST_DURABLE_LOG;
const hangingPaths = new Set((process.env.GRCLANKER_TEST_DURABLE_HANG ?? "").split(",").filter(Boolean));

function log(event) {
  if (logPath) appendFileSync(logPath, `${JSON.stringify({ pid: process.pid, ...event })}\n`);
}

/** The prompt sections in effect: system messages declare them, and later ones replace or remove them by name. */
function promptSections(messages) {
  const sections = new Map();
  for (const message of messages) {
    if (message.role !== "system" || !message.sections) continue;
    for (const [name, text] of Object.entries(message.sections)) {
      if (text === null) sections.delete(name);
      else sections.set(name, text);
    }
  }
  return sections;
}

function respond(context) {
  const messages = context.messages;
  const lastUser = messages.findLastIndex((message) => message.role === "user");
  const results = messages.slice(lastUser + 1).filter((message) => message.role === "toolResult");
  const sections = promptSections(messages);
  log({
    kind: "model",
    userMessages: messages.filter((message) => message.role === "user").length,
    toolResults: results.length,
    sections: [...sections.keys()],
    durableNote: [...sections.values()].some((text) => text.includes("## Durable Runtime (experimental)")),
    assessmentState: [...sections.values()].some((text) => text.includes("Recorded tool calls:")),
  });

  if (results.length === 0) {
    return fauxAssistantMessage(
      [
        fauxToolCall(FAST_READ_TOOL, {}, { id: "call-access" }),
        fauxToolCall(SLOW_READ_TOOL, {}, { id: "call-oncall" }),
        fauxToolCall(WRITE_TOOL, { output_dir: "bundles" }, { id: "call-export" }),
      ],
      { stopReason: "toolUse" },
    );
  }
  const lines = results.map((result) => `- ${result.toolName}: ${result.isError ? "error" : "ok"}`);
  return fauxAssistantMessage([fauxText(`Assessment summary:\n${lines.join("\n")}`)]);
}

// The 241 grclanker tool declarations alone fill most of a 128k window, which would start compaction at once.
const faux = fauxProvider({ models: [{ id: "faux-1", contextWindow: 1_000_000 }] });
faux.setResponses(Array.from({ length: 20 }, () => respond));
const models = createModels();
models.setProvider(faux.provider);
ModelRuntime.create = async () => models;

const USERS = [
  { id: "U1", name: "Alice", email: "alice@example.test", role: "owner", teams: [] },
  { id: "U2", name: "Bob", email: "bob@example.test", role: "admin", teams: [] },
  { id: "U3", name: "Carol", email: "carol@example.test", role: "user", teams: [{ id: "T1" }] },
];

// One payload answers every list endpoint the PagerDuty tools read.
const FIXTURE = {
  abilities: ["sso"],
  users: USERS,
  teams: [],
  schedules: [{ id: "S1", name: "Primary", users: [{ id: "U3" }], escalation_policies: [] }],
  oncalls: [],
  more: false,
};

globalThis.fetch = async (input, init = {}) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  if (url.hostname !== "api.pagerduty.com") throw new Error(`Unexpected request in a durable test: ${url.origin}`);
  log({ kind: "request", path: url.pathname });
  if (!hangingPaths.has(url.pathname)) return Response.json(FIXTURE);
  const signal = init.signal ?? (input instanceof Request ? input.signal : undefined);
  // The timer keeps the process alive the way a stalled socket would, until the request's signal aborts; a bare
  // pending promise would let the process exit.
  return new Promise((_, reject) => {
    const socket = setInterval(() => {}, 60_000);
    const abort = () => {
      clearInterval(socket);
      log({ kind: "request-aborted", path: url.pathname });
      reject(signal.reason);
    };
    if (signal?.aborted) abort();
    else signal?.addEventListener("abort", abort, { once: true });
  });
};
