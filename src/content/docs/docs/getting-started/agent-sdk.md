---
title: Cursor Agent SDK
description: Run the grclanker GRC tools, workflow prompts, and personas as a Cursor Agent SDK agent built on @cursor/july, and validate the agent surface without a Cursor credential.
---

grclanker ships a second run mode next to the Pi terminal CLI: a Cursor Agent SDK project built on [`@cursor/july`](https://www.npmjs.com/package/@cursor/july), the early-alpha package behind the `agent-sdk` CLI. It lives in `cli/agent-sdk/` and adapts the bundled extension instead of duplicating it.

## What the agent exposes

| grclanker asset | Agent SDK surface |
|---|---|
| 107 domain tools from `cli/extensions/grc-tools/` | Server tools under their native names (`cmvp_search_modules`, `fedramp_check_sources`, `aws_check_access`, ...) |
| `cli/.grclanker/SYSTEM.md` | Always-on instructions, followed by a short runtime note |
| `cli/prompts/{investigate,audit,assess,validate}.md` | On-demand skills named `investigate`, `audit`, `assess`, and `validate` |
| `cli/skills/crypto-validation/SKILL.md` | Skill named `crypto-validation` |
| `cli/.grclanker/agents/{auditor,verifier}.md` | Subagents named `auditor` and `verifier` |

Pi's compute-backend tools (`bash`, `read`, `write`, `edit`, `ls`, `find`, `grep`) are not exposed. The Cursor harness supplies its own shell and file tools, so the `docker`, `sandbox-runtime`, and `parallels-vm` compute backends do not apply to this run mode.

Each tool keeps the same behavior as in the CLI:

- TypeBox parameter schemas are converted to plain JSON Schema at the adapter boundary. Literal unions become `enum`, TypeBox metadata is stripped, and the schema is forwarded to the model unchanged otherwise.
- Arguments go through the tool's `prepareArguments` shim and Pi's own validator before `execute` runs, so loosely typed calls are normalized the same way the CLI normalizes them.
- Results keep the text and image content the CLI shows the model; error results keep `isError`.
- Tools whose name carries a read-only verb (`check`, `assess`, `search`, `get`, `list`, `plan`, `recent`, `review`, `investigate`, `trace`, `validate`) and no write verb (`export`, `generate`, `collect`, `init`, `import`, `create`, `assemble`) declare `effect: "read"`: 85 tools. An Agent SDK dry-run session executes them and stubs the 22 writers (the exporters, generators, evidence collector, and OSCAL workspace commands). The FedRAMP lookups mirror the official catalog to `~/.grclanker/.state/fedramp/`; when the SDK marks a session as a dry run (`ctx.session.dryRun`), the adapter runs them with on-disk caching disabled, so they still return live data while the session leaves `~/.grclanker` (`GRCLANKER_HOME`) untouched. The SDK host still writes its own session state under `.agent-serve/`.
- The 22 writers set `needsApproval: true`. A model-initiated call to one of them parks until a person approves or denies it from the playground Approve / Deny buttons or `POST /v1/session/:sessionId/approvals/:callId`; the terminal `agent-sdk chat` client shows the parked call but cannot resolve it, so use `agent-sdk:dev` and the playground for turns that export or generate files. Deterministic `agent-sdk call` runs bypass the gate because the caller chose the tool and input.

## Run it

The Agent SDK project runs from a source checkout. `@cursor/july` is a devDependency of the CLI package, so `npm --prefix cli install` provides `agent-sdk`:

```bash
npm --prefix cli install
npm --prefix cli run agent-sdk:validate
npm --prefix cli run agent-sdk:info
npm --prefix cli run agent-sdk:call -- kevs_search --input '{"query":"CVE-2024-3094"}'
```

`validate`, `info`, and `call` need no Cursor credential. `call` runs a server tool deterministically with no model turn, which is the fastest way to confirm a tool works before blaming a prompt.

Model turns need a Cursor credential. Sign in once with `npx agent-sdk login` inside `cli/`, or export `CURSOR_API_KEY`, then serve the agent with the playground:

```bash
npm --prefix cli run agent-sdk:dev
# playground at http://127.0.0.1:3000/playground
npm --prefix cli run agent-sdk:run -- --message "Is BoringCrypto FIPS validated?"
```

The Agent SDK default model applies unless `GRCLANKER_AGENT_SDK_MODEL` names a Cursor model id, for example `GRCLANKER_AGENT_SDK_MODEL=composer-2.5`. Tool credentials work the same way as in the CLI: the cloud and SaaS tools read their environment variables from the `agent-sdk` process.

Session state, traces, and eval batches land in `cli/agent-sdk/.agent-serve/`, which is gitignored.

## Where exported files land

Server tools run inside the `agent-sdk` process, so a relative `output_dir`, `workspace_dir`, or `zip_path` resolves against that process's working directory (`cli/` when you use the npm scripts), not against the model's session workspace under `~/.cache/agent-serve/agent-sdk/`. The defaults are the same as in the CLI: exporters write under `./export/<domain>/` and the OSCAL tools use `./oscal-workspace/`. Every writer returns the absolute paths it created, and the runtime note tells the model to pass an absolute path when files must land in its workspace. Both directories are gitignored.

`agent-sdk info --json` writes its 107-tool payload with an unawaited stdout write, so pipe it to a file rather than another process (`npm --prefix cli run -s agent-sdk:info -- --json > /tmp/info.json`); a pipe truncates the output at 64 KiB. The `test:agent-sdk:validate` script captures it through a file descriptor for this reason.

## Keep the tool entries in sync

The Agent SDK derives tool names from filenames, so `cli/agent-sdk/agent/tools/` holds one generated entry per domain tool. After adding or renaming a tool in `cli/extensions/grc-tools/`, regenerate them:

```bash
npm --prefix cli run sync:agent-sdk-tools
```

`npm --prefix cli run test:cli` covers the adapter with a mocked SDK (registration, schema conversion, argument bridging, result mapping, and every entry file) and fails when the generated entries drift. `npm --prefix cli run test:agent-sdk:validate` runs the real `agent-sdk validate` and `agent-sdk info --json` discovery and skips when `@cursor/july` is not installed.

## Limitations

- Source checkout only: the published `@grclanker/cli` package and the release bundles do not include the Agent SDK project or `@cursor/july`.
- `@cursor/july` is early alpha and pinned to an exact version in `cli/package.json`; expect to bump it deliberately.
- Turns run on the local Cursor harness (`runtime: "local"`). The cloud runtime is not configured because in-process server tools only run on local turns.
- Node 22.19 or newer, the CLI package's `engines` floor, and never Bun. `@cursor/july` itself accepts 22.13, but the grclanker tools it loads require 22.19.
