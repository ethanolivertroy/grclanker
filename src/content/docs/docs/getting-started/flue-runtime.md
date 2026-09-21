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

Tool parameters are declared with TypeBox JSON Schema in the Pi extension. Flue requires Valibot object schemas, so the adapter converts each schema at the boundary and Flue renders the model-facing JSON Schema from the Valibot version. Property names, required lists, types, descriptions, defaults, and literal unions round-trip. Inside the adapter, each tool's `prepareArguments` normalizer runs before validation, and the validation itself is as strict as the Pi CLI's, so arguments reach a tool exactly as the Pi CLI's loop would hand them over (verified against every domain tool with pi-ai's own `validateToolArguments` in `cli/tests/flue.test.mjs`).

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

The reply prints to stdout. Tool activity and the conversation id print to stderr; tool arguments in those lines are redacted when their names look like credentials (`token`, `secret`, `password`, `private_key`, `api_key`, `credential`, `authorization`, `assertion`, Duo's `ikey` and `skey`) or when the tool schema marks them `writeOnly`, `format: "password"`, or `sensitive`, so API tokens and client secrets never reach terminal scrollback or CI logs. Exit codes follow `flue run`: `0` completed, `1` failed, `130` aborted.

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
| `GRCLANKER_FLUE_MODEL` | `provider/model` specifier, for example `anthropic/claude-sonnet-4-6`, `openai/gpt-5.5`, or `ollama/gemma4`. Without it, the `grclanker setup` provider and model are reused (hosted or local-first); with no setup at all, `anthropic/claude-sonnet-4-6` is used. |
| Provider API keys | Read from the environment by the Flue runtime for hosted providers (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, and so on). `flue run` also loads a project `.env`. |
| `GRCLANKER_FLUE_SANDBOX` | `local` (default) attaches Flue's local sandbox for the current directory. `none` runs with domain tools only. |
| `--db <path>` | SQLite file for conversations. Defaults to `~/.grclanker/flue/conversations.db`; `:memory:` keeps nothing. |
| `GRCLANKER_HOME` | Honored as in the Pi CLI, both for reading settings and for the default database location. |

## Local-first models

The Flue runtime registers Pi's built-in hosted providers on its own. To keep grclanker's local-first path working, the agent module reads the custom providers `grclanker setup` wrote to `~/.grclanker/agent/models.json` (the Ollama entry, or any other provider with its own `models` list), rebuilds each one with Pi's `createProvider()`, and registers it with Flue's `setProvider()` at module scope, as the Flue Models guide prescribes for custom endpoints. That happens whether the module is loaded by `grclanker flue run` or by `flue run`, so a local-first setup resolves to `ollama/gemma4` without any extra configuration.

Supported `models.json` entries use the `openai-completions`, `openai-responses`, or `anthropic-messages` API with a `baseUrl` on the provider or model; other APIs are skipped with a warning. The `apiKey` may be a literal or an environment variable template such as `$OLLAMA_API_KEY`. Entries whose `apiKey` runs a shell command (`!command`) are refused. Model metadata defaults match the Pi CLI (`contextWindow` 128000, `maxTokens` 16384, zero cost). If a local-first setup has no usable entry, the adapter reports that instead of switching to a hosted provider silently.

## Limitations

- The Pi compute backends (`host`, `sandbox-runtime`, Docker, Parallels) do not apply. Use `GRCLANKER_FLUE_SANDBOX` to attach or skip Flue's local sandbox, or swap in another Flue sandbox adapter in your own agent module.
- Flue's runtime validates the raw model arguments against the rendered JSON Schema before the adapter (and therefore any normalizer) sees them, and it coerces typed values on the way in, which the Pi CLI does not do. Payloads that a Pi normalizer would have repaired instead return a validation error naming the field, and the model retries: alias keys standing in for a missing required argument, invalid enum values, wrong-typed or out-of-range values a normalizer would drop or clamp, scalars sent for array fields, non-integer numbers for integer fields, and bare non-object payloads. In the other direction, that check admits typed values the Pi CLI rejects: numeric strings become numbers, `"true"` and `"false"` become booleans, numbers and booleans become strings for string fields (a boolean sent for a `string | integer` union arrives as `"true"`), non-string array items become strings (`[1]` arrives as `["1"]`), and `null` for an optional scalar arrives as `0`, `false`, or an empty string instead of being dropped. For typed values the Flue path is therefore at least as permissive as the Pi CLI and never stricter; it is stricter only where a normalizer would have repaired the payload.
- Tool output reaches the model as a JSON string, because Flue JSON-serializes every tool `output`. Multi-line tables therefore arrive with escaped newlines and quotes rather than as raw text as under Pi.
- Node.js 22.19 or newer is required by `@flue/runtime` and `@flue/cli`. On Node 22, Flue's SQLite persistence prints an experimental-feature warning from Node itself.

## Validate the adapter

```bash
npm --prefix cli run test:cli
```

`cli/tests/flue.test.mjs` covers the schema conversion, tool bridging for all 107 tools, a differential check of argument handling against the Pi CLI's own `validateToolArguments` for every tool, prompt loading, the hook-level render, the runner and command surface, custom provider registration, and two end-to-end runs on the real Flue runtime: one with a faux model provider and one with a local-first provider against a mock OpenAI-compatible server. No test makes a live model call.
