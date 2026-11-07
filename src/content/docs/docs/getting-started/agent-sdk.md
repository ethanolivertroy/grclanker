---
title: Cursor Agent SDK
description: Run all 241 grclanker domain tools as a Cursor Agent SDK agent built on @grok/agent-sdk.
---

grclanker ships a [Cursor Agent SDK](https://cursor.com/docs/agent-sdk) project next to the Pi terminal CLI. The project lives in `cli/agent-sdk/` and adapts the bundled 241-tool domain registry instead of duplicating it.

The Agent SDK lets you define, test, and run agents as a folder of Markdown and TypeScript. grclanker's project is built on [`@grok/agent-sdk`](https://www.npmjs.com/package/@grok/agent-sdk) 0.6.0, the package behind the `agent-sdk` CLI. It was published as `@cursor/bdk` before the public release.

## Quick start

This path runs from a clone of the repo and uses the `cli/` package. Node.js 22.19 or newer, never Bun. `@grok/agent-sdk` itself accepts 22.13. The grclanker tools it loads use the CLI package's 22.19 floor. The site package at the repository root asks for 22.22, and that floor applies when you build the site.

```bash
git clone https://github.com/ethanolivertroy/grclanker.git
cd grclanker
npm --prefix cli install
npm --prefix cli run agent-sdk:validate
npm --prefix cli run agent-sdk:call -- kevs_search --input '{"query":"CVE-2021-44228"}'
```

`npm --prefix cli install` installs the `cli/` tree: `@grok/agent-sdk`, the tool implementations under `cli/extensions/grc-tools/`, and the prompts and personas the adapter reads. Install from `cli/`. `cli/agent-sdk/package.json` has no dependencies, so an install inside that directory does not provide the `agent-sdk` CLI or the tools. The install runs `cli/scripts/patch-embedded-pi.mjs`, which rebrands the embedded Pi package. The Agent SDK scripts do not launch `grclanker`. The install fails if that patch fails.

`validate` and `tool call` need no prior `npm --prefix cli run build`. The SDK loads the TypeScript sources. The last command runs one grclanker tool with no model turn and prints a JSON envelope with `"ok": true` and the matching Log4j entries from the CISA KEV feed. It needs network access. A Cursor credential is optional for that command.

### What this path leaves unused

- The repository-root site and its docs build (`npm install` and `npm run build` at the repo root)
- `npm --prefix cli run build`, `npm link`, and the `grclanker` binary
- `grclanker setup`, Ollama, and `~/.grclanker/agent/settings.json`

[Configuration](/docs/getting-started/configuration/) describes that settings file for the Pi terminal CLI. The Agent SDK project does not read it, and `grclanker setup` does not select this agent's model. Set `GRCLANKER_AGENT_SDK_MODEL` to a Cursor model id when you want one other than the default below.

A model turn needs a Cursor credential before it starts. Sign in once with `npx agent-sdk login` inside `cli/`, or set `CURSOR_API_KEY` on the `agent-sdk` process. `npx agent-sdk whoami` reports whether a credential is present. The SDK also accepts `CURSOR_API_KEY_FILE` and `CURSOR_SERVICE_ACCOUNT_KEY`.

## What the agent exposes

| grclanker asset | Agent SDK surface |
|---|---|
| 241 domain tools from `cli/extensions/grc-tools/` | Server tools under their native names (`cmvp_search_modules`, `fedramp_check_sources`, `aws_check_access`, ...) |
| `cli/.grclanker/SYSTEM.md` | Always-on instructions, followed by a short runtime note |
| `cli/prompts/{investigate,audit,assess,validate}.md` | On-demand skills named `investigate`, `audit`, `assess`, and `validate` |
| `cli/skills/crypto-validation/SKILL.md` | Skill named `crypto-validation` |
| `cli/.grclanker/agents/{auditor,verifier}.md` | Subagents named `auditor` and `verifier` |

Pi's compute-backend tools (`bash`, `read`, `write`, `edit`, `ls`, `find`, `grep`) are not exposed. The Cursor harness supplies `shell` plus the native file tools `Read`, `Write`, `StrReplace`, `Grep`, `Glob`, `LS`, and `Delete`, so the `docker`, `sandbox-runtime`, and `parallels-vm` compute backends do not apply to this run mode. A successful file read is `{ status: "success", value: { content } }`.

`bot/agent.ts` leaves the harness sandbox off and does not set a built-in tool allowlist. `shell` runs with the `agent-sdk` process environment, including any tenant credentials that process holds, and shell commands auto-approve. The approval gate on the 42 domain writers does not cover `shell`, `Write`, `StrReplace`, or `Delete`.

`auditor` and `verifier` inherit that same surface. The `Allowed:` lines in their persona files are instructions for the model. This runtime does not filter their tools. The Flue runtime mounts only the tools those lines name.

The four workflow skills are the Pi prompt files with an empty subject, so the conversation supplies the subject. Slash commands such as `/investigate` are not available here. Load the matching skill.

Each tool keeps the same behavior as in the CLI:

- TypeBox parameter schemas are converted to plain JSON Schema at the adapter boundary. Literal unions become `enum`, TypeBox metadata is stripped, and the schema is forwarded to the model unchanged otherwise.
- Arguments go through the tool's `prepareArguments` shim and Pi's own validator before `execute` runs, so loosely typed calls are normalized the same way the CLI normalizes them.
- Results keep the text and image content the CLI shows the model, and error results keep `isError`.
- Tools whose name carries a read-only verb and no write verb declare `effect: "read"`. There are 199 such tools.
  - Read-only verbs: `check`, `assess`, `search`, `get`, `list`, `plan`, `recent`, `review`, `investigate`, `trace`, `validate`.
  - Write verbs: `export`, `generate`, `collect`, `init`, `import`, `create`, `assemble`.
- An Agent SDK dry-run session executes those 199 tools and stubs the 42 writers (the exporters, generators, evidence collector, and OSCAL workspace commands).
  - The FedRAMP lookups mirror the official catalog to `~/.grclanker/.state/fedramp/`. When the SDK marks a session as a dry run (`ctx.session.dryRun`), the adapter runs them with on-disk caching disabled, so they still return live data while the session leaves `~/.grclanker` (`GRCLANKER_HOME`) untouched.
  - The SDK host still writes its own session state under `.agent-serve/`.
- The 42 writers set `needsApproval: true`.
  - A model-initiated call to one of them parks until a person approves or denies it from the playground Approve / Deny buttons or `POST /v1/session/:sessionId/approvals/:callId`. Use `agent-sdk:dev` and the playground for turns that export or generate files.
  - Deterministic `agent-sdk tool call` runs bypass the gate because the caller chose the tool and input.

## Run it

The Agent SDK project runs from a source checkout. `@grok/agent-sdk` is a devDependency of the CLI package, so `npm --prefix cli install` provides the `agent-sdk` CLI. The npm scripts wrap it:

| Script | Runs |
|---|---|
| `agent-sdk:validate` | `agent-sdk validate --dir agent-sdk` |
| `agent-sdk:info` | `agent-sdk info --dir agent-sdk` |
| `agent-sdk:call` | `agent-sdk tool call --dir agent-sdk` |
| `agent-sdk:dev` | `agent-sdk dev agent-sdk --mode single` |
| `agent-sdk:run` | `agent-sdk run --dir agent-sdk` |

`validate`, `info`, and `tool call` need no Cursor credential. `tool call` runs a server tool deterministically with no model turn, which is the fastest way to confirm a tool works before blaming a prompt.

Model turns need the Cursor credential from the quick start, then serve the agent with the playground:

```bash
npm --prefix cli run agent-sdk:dev
# playground at http://127.0.0.1:3000/playground
npm --prefix cli run agent-sdk:run -- --message "Is BoringCrypto FIPS validated?"
```

Turns that leave the model unset use the Agent SDK default, `grok-4.7` with `reasoning_effort=high` and `fast=true`. Set `GRCLANKER_AGENT_SDK_MODEL` to a Cursor model id, for example `GRCLANKER_AGENT_SDK_MODEL=composer-2.5`, to override it.

Tool credentials work the same way as in the CLI. The 29 reference tools (CMVP, KEV/EPSS, SCF, FedRAMP, and OSCAL) need no tenant. The 212 platform tools read the same environment variables, config files, and local CLIs as the terminal CLI, including `~/.aws`, `az`, `gcloud`, and an OCI config. Each integration page lists its own names. `gws_ops_*` needs the `gws` binary (`GRCLANKER_GWS_BIN`). OSCAL commands other than `oscal_check_trestle` need `compliance-trestle` (`GRCLANKER_TRESTLE_BIN` or `TRESTLE_BIN`). A missing credential or binary comes back as a tool result with `isError: true`, and `agent-sdk tool call` then exits 1. The JSON envelope still carries the message.

Commands that start a local host, and `agent-sdk tool call`, print a `[bdk] GitHub auth:` line on stderr. That line is about the Agent SDK's own GitHub integration, which this project does not use. The tools run whether or not it finds a credential. When the line tells you to run `gh auth login`, that login does not configure the `github_*` domain tools. Those tools read their own credentials, as listed on the [GitHub](/docs/integrations/github/) page.

Session state, traces, and eval batches land in `cli/agent-sdk/.agent-serve/`, which is gitignored.

## Where exported files land

Server tools run inside the `agent-sdk` process. A relative `output_dir`, `workspace_dir`, or `zip_path` therefore resolves against that process's working directory (`cli/` when you use the npm scripts), not against the model's session workspace, which the Agent SDK keeps in a per-project directory under `~/.cache`.

The defaults are the same as in the CLI: exporters write under `./export/<domain>/` and the OSCAL tools use `./oscal-workspace/`. Both directories are gitignored.

Every writer returns the absolute paths it created, and the runtime note tells the model to pass an absolute path when files must land in its workspace.

## Keep the tool entries in sync

After adding or renaming a tool in `cli/extensions/grc-tools/`, regenerate the tool entries:

```bash
npm --prefix cli run sync:agent-sdk-tools
```

The Agent SDK derives tool names from filenames, so `cli/agent-sdk/bot/tools/` holds one generated entry per domain tool, in the `bot/` layout described in [Project layout](https://cursor.com/docs/agent-sdk/reference/project-layout).

The sync compiles the registry without the generated entries (`cli/tsconfig.agent-sdk-sync.json`), rewrites every entry, and then runs the full build. That way, the sync still works when the existing entries no longer compile, for example right after a package rename.

`npm --prefix cli run test:cli` covers the adapter with a mocked SDK (registration, schema conversion, argument bridging, result mapping, and every entry file) and fails when the generated entries drift.

`npm --prefix cli run test:agent-sdk:validate` checks the pinned SDK with real `agent-sdk validate` and `agent-sdk info --json` discovery, including every tool's effect and approval gate. It also previews and executes a local-only OSCAL check and verifies input-schema rejection without a model or provider request. It skips when `@grok/agent-sdk` is not installed.

## Limitations

- Source checkout only: The release bundles do not include the Agent SDK project or `@grok/agent-sdk`, and `@grclanker/cli` is not published to npm.
- `@grok/agent-sdk` is pinned to an exact version (`0.6.0`) in `cli/package.json`, and Dependabot proposes bumps in their own group. When a newer release is published, the CLI prints an "outdated" warning. Skip the `agent-sdk update` it suggests and bump the pin deliberately instead. `@grok/agent-sdk` 0.6.0 requires `@cursor/sdk` 1.3.0, which the CLI install pulls in.
- `zod` is a peer dependency of `@grok/agent-sdk` and a CLI devDependency.
- The project runs locally and is not deployed to Cursor-managed hosting.
- Turns run on the local Cursor harness, the Agent SDK's default runtime, so `bot/agent.ts` does not set `runtime`. In-process server tools only run on local turns.
- Node 22.19 or newer, the CLI package's `engines` floor, and never Bun. `@grok/agent-sdk` itself accepts 22.13, but the grclanker tools it loads require 22.19.

## Learn more

- [Agent SDK docs](https://cursor.com/docs/agent-sdk), including the [CLI reference](https://cursor.com/docs/agent-sdk/reference/cli) and [tools reference](https://cursor.com/docs/agent-sdk/reference/tools)
- [`@grok/agent-sdk` on npm](https://www.npmjs.com/package/@grok/agent-sdk)
