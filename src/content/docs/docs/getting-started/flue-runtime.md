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

Tool parameters are declared with TypeBox JSON Schema in the Pi extension. Flue requires Valibot object schemas, so the adapter converts each schema at the boundary and Flue renders the model-facing JSON Schema from the Valibot version. Property names, required lists, types, descriptions, defaults, `pattern` constraints, and literal unions round-trip. Validation happens in two stages. First, Flue's runtime validates the raw model arguments against that rendered schema before the adapter or any normalizer sees them, so a payload must satisfy the declared schema as sent, after Flue's own type coercions (this stage is also where `pattern` constraints are enforced); a Pi normalizer never gets the chance to repair alias keys, invalid enum values, or wrong-typed values (see [Limitations](#limitations)). Only then does the adapter run the tool's `prepareArguments` normalizer and check its result, which is the part that mirrors the Pi CLI (`cli/tests/flue.test.mjs` pins both stages against pi-ai's own `validateToolArguments` for every domain tool).

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

The reply prints to stdout. Tool activity and the conversation id print to stderr; tool arguments in those lines are redacted when their names look like credentials (`token`, `secret`, `password`, `private_key`, `api_key`, `credential`, `authorization`, `assertion`, Duo's `ikey` and `skey`) or when the tool schema marks them `writeOnly`, `format: "password"`, or `sensitive`. Tool error lines are treated the same way: the payload that Pi's validation error echoes (`Received arguments:`) is withheld, only the field-level reasons print, and any redacted value from the call is scrubbed if a tool's own message repeats it, whether as is, JSON-escaped, URL-encoded as a URI component (`%20` for a space) or as a form field (`+` for a space, `~ ! ' ( ) *` percent-encoded, as in an echoed `application/x-www-form-urlencoded` body), base64 or base64url encoded, case-changed, or as a PEM re-flowed onto one line or quoted line by line. Names shaped like thresholds, durations, counts, or file references (`max_keys`, `token_limit`, `stale_token_days`, `credentials_file`) stay visible. API tokens and client secrets therefore never reach terminal scrollback or CI logs through these lines. Exit codes follow `flue run`: `0` completed, `1` failed, `130` aborted.

The conversation database is different: Flue persists conversations verbatim, including raw tool arguments, tool results, and user messages, and offers no hook to redact before writing (see Limitations). Treat `~/.grclanker/flue/conversations.db` like a credential store, and use `--db :memory:` in CI.

## Run with the official Flue CLI

The agent module is `cli/flue/agent.ts`, a `'use agent'` module that exports one agent named `grclanker`. `@flue/cli` is a devDependency of the CLI package, so from a repo checkout, in the `cli/` directory after `npm install`, with Node.js 22.19 or newer:

```bash
npx flue run flue/agent.ts --message "Is BoringCrypto FIPS validated?"
npx flue run flue/agent.ts --message "Any update?" --id fips-review
```

`flue run` loads the TypeScript module directly and stores conversations in `node_modules/.cache/flue/run.db` unless a `flue.config.*` database entry says otherwise; it has no `--db` option. That file holds raw tool inputs and results, credentials included. It is covered by the repository's `node_modules/` ignore rule, but it travels with any CI cache of `node_modules`, so delete `node_modules/.cache/flue` after a CI run or exclude it from the cache, and never share it. The same module can be mounted in a Flue application with `createAgentRouter()` if you want it behind HTTP.

The CLI has to be installed next to the runtime it drives. `@flue/runtime` publishes import-only package exports, which defeats the CLI's single-copy resolver, so a separately downloaded CLI (for example `npx @flue/cli run ...` in a checkout without the devDependency) loads its own runtime copy and the agent's hooks fail with `useModel() was called outside an agent function`. Keep the devDependency, or install `@flue/cli` into the same `node_modules` before running it.

## Configuration

| Setting | Effect |
| --- | --- |
| `GRCLANKER_FLUE_MODEL` | `provider/model` specifier, for example `anthropic/claude-sonnet-4-6`, `openai/gpt-5.5`, or `ollama/gemma4`. Without it, the `grclanker setup` provider and model are reused (hosted or local-first); with no setup at all, `anthropic/claude-sonnet-4-6` is used. |
| Provider API keys | Read from the environment by the Flue runtime for hosted providers (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, and so on). `flue run` also loads a project `.env`. |
| `GRCLANKER_FLUE_SANDBOX` | `local` (default) attaches Flue's local sandbox for the current directory. `none` runs with domain tools only. |
| `--db <path>` | SQLite file for conversations, stored verbatim (raw tool arguments included). Defaults to `~/.grclanker/flue/conversations.db`; `:memory:` keeps nothing and is the right choice for CI. |
| `GRCLANKER_HOME` | Honored as in the Pi CLI, both for reading settings and for the default database location. |

## Local-first models

The Flue runtime registers Pi's built-in hosted providers on its own. To keep grclanker's local-first path working, the agent module reads the custom providers `grclanker setup` wrote to `~/.grclanker/agent/models.json` (the Ollama entry, or any other provider with its own `models` list), rebuilds each one with Pi's `createProvider()`, and registers it with Flue's `setProvider()` at module scope, as the Flue Models guide prescribes for custom endpoints. That happens whether the module is loaded by `grclanker flue run` or by `flue run`, so a local-first setup resolves to `ollama/gemma4` without any extra configuration.

Supported `models.json` entries use the `openai-completions`, `openai-responses`, or `anthropic-messages` API with a `baseUrl` on the provider or model; other APIs are skipped with a warning. The `apiKey` may be a literal or an environment variable template such as `$OLLAMA_API_KEY`. Entries whose `apiKey` runs a shell command (`!command`) are refused. Model metadata defaults match the Pi CLI (`contextWindow` 128000, `maxTokens` 16384, zero cost). If a local-first setup has no usable entry, the adapter reports that instead of switching to a hosted provider silently.

## Limitations

- The Pi compute backends (`host`, `sandbox-runtime`, Docker, Parallels) do not apply. Use `GRCLANKER_FLUE_SANDBOX` to attach or skip Flue's local sandbox, or swap in another Flue sandbox adapter in your own agent module.
- Flue's runtime validates the raw model arguments against the rendered JSON Schema before the adapter (and therefore any normalizer) sees them, and it coerces typed values on the way in, which the Pi CLI does not do. Payloads that a Pi normalizer would have repaired instead return a validation error naming the field, and the model retries: alias keys standing in for a missing required argument, invalid enum values, wrong-typed or out-of-range values a normalizer would drop or clamp, scalars sent for array fields, non-integer numbers for integer fields, and bare non-object payloads. In the other direction, that check admits typed values the Pi CLI rejects: numeric strings become numbers, `"true"` and `"false"` become booleans, numbers and booleans become strings for string fields (a boolean sent for a `string | integer` union arrives as `"true"`), non-string array items become strings (`[1]` arrives as `["1"]`), and `null` for an optional scalar arrives as `0`, `false`, or an empty string instead of being dropped. For typed values the Flue path is therefore at least as permissive as the Pi CLI and never stricter; it is stricter only where a normalizer would have repaired the payload.
- Tool output reaches the model as a JSON string, because Flue JSON-serializes every tool `output`. Multi-line tables therefore arrive with escaped newlines and quotes rather than as raw text as under Pi.
- Flue's conversation database stores tool arguments, tool results, and messages verbatim, credentials included, and `@flue/runtime@2.1.0` exposes no hook to redact before persistence: `start()` accepts only a persistence adapter for `db`, and its built-in handling covers reasoning blocks the provider marks encrypted or redacted and image bytes in events, not tool arguments. The adapter's redaction is limited to the stderr activity lines. Use `--db :memory:` where persistence is not wanted, and keep `~/.grclanker/flue/conversations.db` and `node_modules/.cache/flue` out of CI caches and shared locations.
- Value scrubbing in error lines has limits. It recognizes a secret in the forms listed above (both URL encodings, and base64 with or without padding or URL-encoded, included) and nothing else a tool might derive from it: a hash, a fingerprint, a truncated prefix, another encoding, or a combination of them (base64 of the URL-encoded value, MIME-wrapped base64 with line breaks inside it, a PEM re-wrapped at a different column width). Values of four to seven characters are scrubbed only where they stand as a whole token, so a four-digit passcode disappears from `passcode 4711 rejected` but not from `sub_4711abc`; values shorter than four characters are never scrubbed; numeric secrets are scrubbed in the decimal form `JSON.stringify` prints. Free text inside `task` messages or sandbox `command` strings is printed truncated and cannot be classified by key. Key-based redaction on the `->` line is unaffected by any of this.
- Node.js 22.19 or newer is required by `@flue/runtime` and `@flue/cli`. On Node 22, Flue's SQLite persistence prints an experimental-feature warning from Node itself.

## Validate the adapter

```bash
npm --prefix cli run test:cli
```

`cli/tests/flue.test.mjs` covers the schema conversion, tool bridging for all 107 tools, a differential check of argument handling against the Pi CLI's own `validateToolArguments` for every tool, prompt loading, the hook-level render, the runner and command surface, custom provider registration, and two end-to-end runs on the real Flue runtime: one with a faux model provider and one with a local-first provider against a mock OpenAI-compatible server. No test makes a live model call.
