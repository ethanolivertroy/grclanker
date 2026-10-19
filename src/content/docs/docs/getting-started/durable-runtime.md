---
title: Durable Runtime
description: "Experimental: run the grclanker agent under Pi Durable, from the command line or a terminal app, so a run that crashes or is stopped can be resumed."
---

**Experimental.** `grclanker durable` is new. Its commands, output, and session format may change between releases, and every run prints `grclanker durable (experimental)` to stderr.

`grclanker durable` runs the GRC agent under [Pi Durable](https://www.npmjs.com/package/@earendil-works/pi-durable), Pi's durable conversation runtime. Pi Durable writes the conversation and each tool round to a SQLite database as the run goes. If the process crashes, is killed, or is stopped with Ctrl-C, a later command picks the session up where it stopped instead of starting over.

The command is on `main` and is not in a release bundle yet. `v0.1.2` and older do not have it.

## What the runtime maps

The runtime lives in `cli/durable/` and is additive. The interactive CLI, the Cursor Agent SDK project, and the Flue runtime are unchanged.

| grclanker asset | Pi Durable surface |
| --- | --- |
| 241 native domain tools, from the registry in `cli/agent-sdk/lib/registry.ts` | Durable tools with the same names, descriptions, parameter schemas, and argument repair |
| Each tool's effect class in `cli/agent-sdk/lib/effects.ts` | Its replay policy: the 199 read-only tools are replay-safe, and the 42 tools that can write are not. A tool the classifier cannot place counts as a writer |
| `cli/.grclanker/SYSTEM.md` | A system prompt section, followed by a short note on this runtime |
| Tool details | Strict JSON: `NaN` and infinities become `null`, bigints become strings, cycles become `"[Circular]"`, and `undefined` values are dropped |
| Findings, call outcomes, and exports in tool details | An assessment document stored with the conversation and summarized into the system prompt |
| The `grclanker setup` model, `auth.json`, and `models.json` | The model and credentials for each command |
| Pi compute backends, workflow prompts, skills, and subagent personas | Not mapped. The domain tools are the only tools in this mode |

## Run it

From a [source checkout](/docs/getting-started/installation#install-from-source), with Node.js 22.19 or newer:

```bash
npm --prefix cli ci
npm --prefix cli run build
node cli/bin/grclanker.js durable run --message "Is BoringCrypto FIPS validated?"
```

With a source checkout linked through `npm link`, the same command is `grclanker durable run`. `grclanker durable --help` prints the options.

`run` without `--session` starts a new session with an id such as `20261019-143012-a1b2c3` and prints it to stderr. Name a session to continue its conversation, or ask for a JSON report:

```bash
grclanker durable run --session fips-review --message "Is BoringCrypto FIPS validated?"
grclanker durable run --session fips-review --message "Now check KEV exposure for it"
grclanker durable run --session fips-review --message "Summarize the findings" --json
```

A session id is up to 64 letters, digits, dots, dashes, or underscores, starting with a letter or digit.

## Terminal app

`grclanker durable tui` opens a session in a terminal app instead of sending one message from the command line:

```bash
grclanker durable tui
grclanker durable tui --session fips-review
grclanker durable tui --session fips-review --model ollama/gemma4
```

Without `--session`, it starts a new session. With `--session`, it shows the session's conversation and continues any work an interrupted command left in it, with the same replay policy as [`resume`](#crash-and-resume). A session can move between the terminal app, `run`, and `resume`, one process at a time: while the app is open, it holds the [session lock](#sessions-and-the-lock).

The app is adapted from the experimental durable coding agent in [Pi](https://github.com/earendil-works/pi) (MIT License, see `NOTICE`). It uses the theme set in `~/.grclanker/agent/settings.json`, the grclanker theme by default. Below the transcript, which shows each tool call and its result, the screen has:

- A task panel listing Pi Durable's live tasks
- Messages queued for the end of the turn
- The last four notices: a tool round resumed from an earlier process, an interrupted tool (and, for a tool that can write, that it was not rerun), a request that settled without an answer, a failed task, and compaction results
- The editor, with a status line while the model answers or a tool runs
- A footer with token use and cost, how full the model's context window is, the tool calls, findings, and exports in the [assessment document](#assessment-document), the session id, the model, and the thinking level

| Key or command | Action |
| --- | --- |
| Enter | Send the message. While a turn runs, the message steers it |
| Alt+Enter (Ctrl+Q on Windows and WSL) | Queue the message as a follow-up for when the turn ends |
| Esc | Abort the running turn |
| Ctrl+O | Expand or collapse tool output and compaction summaries |
| Shift+Tab | Cycle the thinking level, on a model that supports thinking |
| Ctrl+L or `/model` | Switch to another model whose provider has credentials. In the list, Esc or Ctrl+C closes it without switching |
| `/compact [instructions]` | Summarize older context now |
| `/tasks` | Hide or show the task panel |
| Ctrl+C, or Ctrl+D on an empty editor | Exit |

The keys are Pi's defaults. Override them in `~/.grclanker/agent/keybindings.json`, keyed by Pi's action names such as `app.model.select`.

Exiting closes the session, prints the command that opens it again, and exits `0`. A turn still running when you exit is not cancelled: it continues the next time the session is opened, in the terminal app or with `resume`. Tool calls that were running are cancelled as the session closes, so they stop calling APIs, and an unfinished export writes nothing. The next open handles them like those of a crashed process: read-only tools run again, and tools that can write are reported and not rerun.

The terminal app takes only `--session` and `--model`, and needs an interactive terminal. From a script or a pipe, it exits `1` and points to `grclanker durable run`. A usage, configuration, or lock error also exits `1` before the app opens.

## Crash and resume

A command that crashes, is killed, or is stopped leaves its request unsettled in the session. Finish it with `resume`:

```bash
grclanker durable resume --session fips-review
```

Or rerun the same `run` command with the same `--request-id`:

```bash
grclanker durable run --session fips-review --request-id fips-1 --message "Is BoringCrypto FIPS validated?"
```

A request id that the session already holds reattaches to that request. The message is not sent a second time, and it is not compared with the original. Once the request has settled, the same id prints the stored answer without calling the model or any tool. Without `--request-id`, every `run` sends a new request with a new id.

On resume, Pi Durable treats the tool round that was in flight as follows:

- **Finished tool calls** keep their stored results and do not run again.
- **Interrupted read-only tools** run again from the start. A tool reruns only when it was replay-safe both when the model called it and when the session resumes.
- **Interrupted tools that can write** are never rerun. These are the tools whose names carry `export`, `generate`, `collect`, `import`, `init`, `create`, or `assemble`, plus any tool the classifier cannot place. Each settles with an error result saying the tool was interrupted and may have partially run, which the model sees. The command lists them on stderr as `Interrupted and not rerun: <tools>. Check what they wrote before running them again.` With `--json`, they appear in the report's `tools` with the status `interrupted` instead.

The model then continues the same request with those results, so the request is not asked twice. `resume` finishes every request an earlier process left unsettled and reports the last one. When every request has settled, it prints `Nothing to resume` (with `--json`, the outcome `nothing_to_resume`) and exits `0`.

The first Ctrl-C (or `SIGTERM`) stops the command, closes the session with its work pending, prints the `resume` command to run (with `--json`, a report with the outcome `interrupted`), and exits `130`. Tool calls that were running are cancelled as the session closes, as in the terminal app. A second Ctrl-C exits at once.

## Sessions and the lock

Each session is a directory under `~/.grclanker/durable/sessions/<id>/`:

| File | Contents |
| --- | --- |
| `session.sqlite` | The Pi Durable database: the conversation, tool rounds, tool results, and the assessment document |
| `session.lock` | The single-process lock |

One process can use a session at a time. A second `grclanker durable` command on a busy session exits `1` with `Another grclanker durable process is using this session.` instead of waiting.

The lock is an exclusive SQLite lock that the operating system drops when the process exits for any reason, `SIGKILL` included, so a crash never leaves a stale lock behind.

Delete a session directory to discard the session.

## Output and exit codes

Progress goes to stderr: the experimental banner, the session and request ids, one `-> <tool>` line when a tool starts and one `<- <tool> ok|error|interrupted` line when it ends, model retries, failed tasks, compaction, and a line when a command resumes a tool round left by an earlier process. Progress lines name tools but never print their arguments or results.

The answer goes to stdout. With `--json`, stdout carries one JSON report instead:

| Field | Meaning |
| --- | --- |
| `experimental` | Always `true` |
| `command` | `run` or `resume` |
| `session`, `sessionDir` | The session id and its directory |
| `conversationId` | The session's conversation in Pi Durable |
| `model` | The `provider/model` this command used |
| `requestId`, `submissionId` | The request's idempotency key and Pi Durable's id for it, when there is a request |
| `outcome` | `completed`, `unanswered`, `interrupted`, or `nothing_to_resume` |
| `answer` | The final answer text, when `completed` |
| `reason` | Why the request settled without an answer, when `unanswered` |
| `tools` | The request's tool results in transcript order, each with `callId`, `tool`, `replay` (`safe` or `unsafe`), and `status` (`ok`, `error`, or `interrupted`). Empty when no request settled (`interrupted` or `nothing_to_resume`). Calls that finished before a stop are still recorded in `assessment` |
| `assessment` | The conversation's [assessment document](#assessment-document) |

| Exit code | Meaning |
| --- | --- |
| `0` | Answered, or nothing to resume |
| `1` | The request settled without an answer, or a usage, configuration, or lock error |
| `130` | Stopped by Ctrl-C or `SIGTERM`. The session can be resumed |

### Redaction

When a tool returns or throws an error, its message and details pass through the same redaction as the [Flue runtime](/docs/getting-started/flue-runtime/#output-and-redaction) before they are stored. Credential-shaped argument values are scrubbed from the message, and credential-shaped fields in the details are redacted.

Pi Durable validates arguments itself before a tool runs. Its validation errors are stored as Pi writes them, ending with the arguments the model sent. The session already holds those arguments in the model's tool call, and neither progress lines nor the JSON report print them.

Successful tool results are stored as the tool returned them.

## Assessment document

Each conversation keeps an assessment document next to its transcript. Each time a tool returns, the runtime records:

- The call: the tool, its replay policy, `completed` or `error`, how many findings it returned, and when.
- Each finding in the tool's details that has an `id` and a `status`, with its severity and title. Findings are keyed by integration and finding id, so the latest assessment of a control replaces an earlier one.
- Where an export went, from the tool's `zip_path` or `output_dir`.

Entries are keyed by the tool call, so a read-only tool that reruns after a crash replaces its own record instead of adding a second one.

A short summary of the document goes into the system prompt, so the model can use finished work instead of repeating it. The JSON report includes the whole document.

## Configuration

| Setting | Effect |
| --- | --- |
| `--model <provider/model>` | Model for one command, for example `anthropic/claude-sonnet-4-6` or `ollama/gemma4` |
| `GRCLANKER_DURABLE_MODEL` | Model for every durable command without `--model` |
| `grclanker setup` | Without either of the above, the provider and model saved in `~/.grclanker/agent/settings.json` are used, along with its `defaultThinkingLevel` when set. With no model configured at all, the command exits `1` and says so |
| Provider credentials | Read from `~/.grclanker/agent/auth.json`, as saved by `grclanker setup`, or from the provider's usual environment variable (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, and so on) |
| Local-first models | Custom providers in `~/.grclanker/agent/models.json`, such as the Ollama entry `grclanker setup` writes, work as in the interactive CLI |
| Integration credentials | The same environment variables and config files the interactive CLI uses, as listed in each integration guide |
| `GRCLANKER_HOME` | Honored as in the interactive CLI, for settings, credentials, and sessions |

An unknown model exits `1` before the session is touched. Each command uses the model chosen when it runs, so a continued or resumed session switches to it.

Tools that accept `output_dir`, `workspace_dir`, or `zip_path` resolve relative paths against the directory the command was started in.

## Limitations

- The runtime is experimental. Commands, output, and the session format may change, and a session written by one release may not open in a later one.
- Only the domain tools are available. There are no compute backends (no shell or file tools), workflow prompts, skills, or subagent personas.
- The terminal app has only the keys and commands listed under [Terminal app](#terminal-app). The interactive CLI's commands, such as `/login` and `/settings`, are not in it.
- An interrupted writer may have written part of its output before the process stopped. It is reported, not rerun. Check its output directory before you ask for the export again.
- The session database keeps the whole conversation: your messages, the tool arguments the model sent, and tool results. Tool error text is redacted before it is stored, but a credential you paste into a message, or that the model passes as a tool argument, is stored as is. Treat `~/.grclanker/durable/sessions/` like a credential store and keep it out of shared locations and CI caches.
- Every model request offers all 241 tool declarations, a large share of a 128k-token context window. Pi Durable compacts the conversation as it nears the model's window (the `compacting the conversation` progress line), so long sessions on small-window models compact often.
- One process per session. Run separate sessions to work in parallel.

## Validate the runtime

```bash
npm --prefix cli run test:cli
```

`cli/tests/durable-crash-resume.test.mjs` runs the real `grclanker durable` command with Pi's faux model provider and a mocked PagerDuty API. It kills the process with `SIGKILL` partway through a tool round, after one read-only assessment has finished while a second assessment and an audit bundle export are still running. It then checks that:

- A second process is turned away by the session lock while the first holds it.
- The resumed command keeps the finished assessment and reruns the interrupted one.
- The interrupted export is reported and not rerun, and no bundle is written.
- The model is not asked the request twice.
- A settled request id returns the stored answer without new model calls or API requests.
- Ctrl-C at the same point aborts every API request in flight and the process exits `130` on its own, with no bundle written. `resume` then finishes the round.

`cli/tests/durable-tui.test.mjs` drives the terminal app on an in-memory screen, and the real `grclanker durable tui` in a pseudo-terminal. It checks that:

- A turn shows the message, tool calls, results, answer, and footer counts, and reopening the session shows them again without new model calls or tool runs.
- An app closed partway through a tool round aborts the signal of each tool still running and leaves the round in the session. Reopened, it reruns the read-only tool, reports the writer without rerunning it, and shows both notices in full on a narrow screen.
- `/model`, Esc, and a thinking change on a model without thinking never reach the model.
- `grclanker durable tui`, killed with `SIGKILL` partway through the PagerDuty tool round above, holds the session lock while it runs. Opened again, it keeps the finished assessment, reruns the interrupted one, and does not rerun the export.
- `grclanker durable tui`, closed with Ctrl+C partway through that tool round, exits on its own at once: closing the session aborts the stalled API requests, and the export writes nothing, not even its output directory. `resume` then finishes the round without rerunning the export.

`cli/tests/durable.test.mjs` covers:

- The replay policy of every registry tool
- The session lock, including its release after `SIGKILL`
- Strict-JSON details
- The assessment document
- The tool adapter, including the abort signal it passes to each tool, and redaction
- Model selection
- The command surface
- In-process runs that continue, replay, stop, and resume a session

`cli/tests/abort-signals.test.mjs` checks that every registry tool honors its abort signal. A call whose signal has already aborted sends, runs, and writes nothing. Each tool that requests through fetch, aborted mid-request, rejects within a second and writes nothing, while a concurrent call with the same credentials keeps running.

No test makes a live model call or uses a real credential.
