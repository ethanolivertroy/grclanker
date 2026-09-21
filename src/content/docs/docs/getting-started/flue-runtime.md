---
title: Flue Runtime
description: Run the grclanker GRC agent, its 107 domain tools, workflow prompts, and personas under the Flue Framework with grclanker flue run or the official flue run CLI.
---

grclanker ships as a Pi-based CLI. The same GRC agent can also run as a [Flue Framework](https://flueframework.com/) agent. Flue is itself built on Pi, so the tools and prompts carry over without changing what they do.

## What the adapter maps

The adapter lives in `cli/flue/` and is additive. Nothing in the Pi CLI path changes.

| grclanker asset | Flue surface |
| --- | --- |
| 107 native domain tools from `cli/extensions/grc-tools/` | `useTool()` definitions built with `defineTool()` |
| `.grclanker/SYSTEM.md` | The agent function's returned instructions, plus a short Flue runtime note |
| `prompts/investigate.md`, `audit.md`, `assess.md`, `validate.md` | Skills named `investigate`, `audit`, `assess`, `validate` (activated through Flue's `activate_skill` tool) |
| `skills/crypto-validation/SKILL.md` | A skill named `crypto-validation` |
| `.grclanker/agents/auditor.md` and `verifier.md` | Subagents reachable through Flue's `task` tool, each mounting only the tools its persona allows |
| Pi compute backends (`bash`, `read`, `write`, `edit`, `ls`, `find`, `grep`) | Not mapped. Flue's own `local()` sandbox provides file and shell tools instead |

Tool parameters are declared with TypeBox JSON Schema in the Pi extension. Flue requires Valibot object schemas, so the adapter converts each schema at the boundary and Flue renders the model-facing JSON Schema from the Valibot version. Property names, required lists, types, descriptions, defaults, and literal unions round-trip. Inside the adapter, each tool's `prepareArguments` normalizer runs before validation and values are coerced with the same rules as TypeBox `Value.Convert`, so arguments reach a tool exactly as Pi's loop would hand them over (verified against every domain tool in `cli/tests/flue.test.mjs`).

Pi tool results map onto Flue's result envelope: text content becomes the tool output, `terminate` is forwarded, and a Pi `errorResult()` becomes a Flue tool error the model can react to.

## Run with the bundled runner

The runner uses Flue's documented `start()` and `init()` APIs from `@flue/runtime`, which is a dependency of `@grclanker/cli`. No additional install is needed.

```bash
export ANTHROPIC_API_KEY=...
grclanker flue run --message "Is BoringCrypto FIPS validated?"
```

Continue a conversation by reusing an id, or ask for a JSON envelope:

```bash
grclanker flue run --message "Now check KEV exposure for it" --id fips-review
grclanker flue run --message "Summarize the findings" --id fips-review --json
```

The reply prints to stdout. Tool activity and the conversation id print to stderr. Exit codes follow `flue run`: `0` completed, `1` failed, `130` aborted.

## Run with the official Flue CLI

The agent module is `cli/flue/agent.ts`, a `'use agent'` module that exports one agent named `grclanker`. `@flue/cli` is a devDependency of the CLI package, so from a repo checkout, in the `cli/` directory after `npm install`, with Node.js 22.19 or newer:

```bash
npx flue run flue/agent.ts --message "Is BoringCrypto FIPS validated?"
npx flue run flue/agent.ts --message "Any update?" --id fips-review
```

`flue run` loads the TypeScript module directly and stores conversations in `node_modules/.cache/flue/run.db` unless a `flue.config.*` database entry says otherwise. The same module can be mounted in a Flue application with `createAgentRouter()` if you want it behind HTTP.

The CLI has to be installed next to the runtime it drives. `@flue/runtime` publishes import-only package exports, which defeats the CLI's single-copy resolver, so a separately downloaded CLI (for example `npx @flue/cli run ...` in a checkout without the devDependency) loads its own runtime copy and the agent's hooks fail with `useModel() was called outside an agent function`. Keep the devDependency, or install `@flue/cli` into the same `node_modules` before running it.

## Configuration

| Setting | Effect |
| --- | --- |
| `GRCLANKER_FLUE_MODEL` | `provider/model` specifier, for example `anthropic/claude-sonnet-4-6` or `openai/gpt-5.5`. Without it, a hosted `grclanker setup` provider and model are reused; with no setup at all, `anthropic/claude-sonnet-4-6` is used. |
| Provider API keys | Read from the environment by the Flue runtime (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, and so on). `flue run` also loads a project `.env`. |
| `GRCLANKER_FLUE_SANDBOX` | `local` (default) attaches Flue's local sandbox for the current directory. `none` runs with domain tools only. |
| `--db <path>` | SQLite file for conversations. Defaults to `~/.grclanker/flue/conversations.db`; `:memory:` keeps nothing. |
| `GRCLANKER_HOME` | Honored as in the Pi CLI, both for reading settings and for the default database location. |

## Limitations

- Local-first models configured through `grclanker setup` (the Ollama path) are not available under Flue. The Flue runtime registers Pi's built-in providers only, and grclanker refuses to switch providers silently. Set `GRCLANKER_FLUE_MODEL` to a supported `provider/model` instead.
- The Pi compute backends (`host`, `sandbox-runtime`, Docker, Parallels) do not apply. Use `GRCLANKER_FLUE_SANDBOX` to attach or skip Flue's local sandbox, or swap in another Flue sandbox adapter in your own agent module.
- Flue's runtime validates the raw model arguments against the rendered JSON Schema before the adapter (and therefore any normalizer) sees them. Payloads that a Pi normalizer would have repaired instead return a validation error naming the field, and the model retries: alias keys standing in for a missing required argument, invalid enum values, wrong-typed or out-of-range values a normalizer would drop or clamp, scalars sent for array fields, non-integer numbers for integer fields, and bare non-object payloads. Numeric strings, `"true"` and `"false"`, and numbers for string fields pass that check. One coercion differs in effect: `null` for an optional scalar becomes `0`, `false`, or an empty string at that check instead of being dropped.
- Tool output reaches the model as a JSON string, because Flue JSON-serializes every tool `output`. Multi-line tables therefore arrive with escaped newlines and quotes rather than as raw text as under Pi.
- Node.js 22.19 or newer is required by `@flue/runtime` and `@flue/cli`. On Node 22, Flue's SQLite persistence prints an experimental-feature warning from Node itself.

## Validate the adapter

```bash
npm --prefix cli run test:cli
```

`cli/tests/flue.test.mjs` covers the schema conversion, tool bridging for all 107 tools, prompt loading, the hook-level render, the runner and command surface, and one end-to-end run on the real Flue runtime with a faux model provider. No test makes a live model call.
