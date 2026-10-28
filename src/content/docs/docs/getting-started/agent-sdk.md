---
title: Cursor Agent SDK
description: Run all 241 grclanker domain tools as a Cursor Agent SDK agent built on @grok/agent-sdk.
---

grclanker ships a [Cursor Agent SDK](https://cursor.com/docs/agent-sdk) project next to the Pi terminal CLI. The project lives in `cli/agent-sdk/` and adapts the bundled 241-tool domain registry instead of duplicating it.

The Agent SDK lets you define, test, and run agents as a folder of Markdown and TypeScript. grclanker's project is built on [`@grok/agent-sdk`](https://www.npmjs.com/package/@grok/agent-sdk) 0.4.0, the package behind the `agent-sdk` CLI. It was published as `@cursor/bdk` before the public release.

## Quick start

From a clone of the repo, on Node.js 22.19 or newer:

```bash
npm --prefix cli install
npm --prefix cli run agent-sdk:validate
npm --prefix cli run agent-sdk:call -- kevs_search --input '{"query":"CVE-2021-44228"}'
```

The last command runs one grclanker tool with no model turn and prints a JSON envelope with `"ok": true` and the matching Log4j entries from the CISA KEV feed. It needs network access but no Cursor credential.

## What the agent exposes

| grclanker asset | Agent SDK surface |
|---|---|
| 241 domain tools from `cli/extensions/grc-tools/` | Server tools under their native names (`cmvp_search_modules`, `fedramp_check_sources`, `aws_check_access`, ...) |
| `cli/.grclanker/SYSTEM.md` | Always-on instructions, followed by a short runtime note |
| `cli/prompts/{investigate,audit,assess,validate}.md` | On-demand skills named `investigate`, `audit`, `assess`, and `validate` |
| `cli/skills/crypto-validation/SKILL.md` | Skill named `crypto-validation` |
| `cli/.grclanker/agents/{auditor,verifier}.md` | Subagents named `auditor` and `verifier` |

Pi's compute-backend tools (`bash`, `read`, `write`, `edit`, `ls`, `find`, `grep`) are not exposed. The Cursor harness supplies its own shell and file tools, so the `docker`, `sandbox-runtime`, and `parallels-vm` compute backends do not apply to this run mode.

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

Model turns need a Cursor credential. Sign in once with `npx agent-sdk login` inside `cli/`, or export `CURSOR_API_KEY`, then serve the agent with the playground:

```bash
npm --prefix cli run agent-sdk:dev
# playground at http://127.0.0.1:3000/playground
npm --prefix cli run agent-sdk:run -- --message "Is BoringCrypto FIPS validated?"
```

The Agent SDK default model applies unless `GRCLANKER_AGENT_SDK_MODEL` names a Cursor model id, for example `GRCLANKER_AGENT_SDK_MODEL=composer-2.5`.

Tool credentials work the same way as in the CLI: the cloud and SaaS tools read their environment variables from the `agent-sdk` process.

Commands that start a local host print a `[bdk] GitHub auth:` line on stderr. That line is about the Agent SDK's own GitHub integration, which this project does not use, so the tools run whether or not it finds a credential. The `github_*` domain tools read their own credentials, as listed on the [GitHub](/docs/integrations/github/) page.

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
- `@grok/agent-sdk` is pinned to an exact version (`0.4.0`) in `cli/package.json`, and Dependabot proposes bumps in their own group. When a newer release is published, the CLI prints an "outdated" warning. Skip the `agent-sdk update` it suggests and bump the pin deliberately instead.
- `zod` is a peer dependency of `@grok/agent-sdk` and a CLI devDependency.
- The project runs locally and is not deployed to Cursor-managed hosting.
- Turns run on the local Cursor harness, the Agent SDK's default runtime, so `bot/agent.ts` does not set `runtime`. In-process server tools only run on local turns.
- Node 22.19 or newer, the CLI package's `engines` floor, and never Bun. `@grok/agent-sdk` itself accepts 22.13, but the grclanker tools it loads require 22.19.

## Learn more

- [Agent SDK docs](https://cursor.com/docs/agent-sdk), including the [CLI reference](https://cursor.com/docs/agent-sdk/reference/cli) and [tools reference](https://cursor.com/docs/agent-sdk/reference/tools)
- [`@grok/agent-sdk` on npm](https://www.npmjs.com/package/@grok/agent-sdk)
