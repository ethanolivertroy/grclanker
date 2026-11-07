---
title: Cursor / Grok Agent SDK
description: Install, configure, and run grclanker as an independent Cursor / Grok Agent SDK GRC engineer agent.
---

Run a grclanker GRC engineer agent with the [Cursor Agent SDK](https://cursor.com/docs/agent-sdk). This guide contains the complete source-install, authentication, configuration, code, and local deployment steps for this path. You do not need to install or run the Pi terminal app, Codex, or another agent SDK.

**Cursor / Grok names:** Cursor's Agent SDK currently ships as [`@grok/agent-sdk`](https://www.npmjs.com/package/@grok/agent-sdk), formerly `@cursor/bdk`. These names refer to the same SDK path here. Choosing a Grok model in this harness uses this deployment; a separate xAI API integration is not included.

The project lives in `cli/agent-sdk/`. It loads grclanker's native GRC tools, system instructions, workflow skills, and auditor/verifier personas. Use it to gather security evidence, assess controls, investigate findings, and prepare reviewable compliance artifacts. Broader autonomous governance and risk management remain product goals; the installed tools and their evidence determine what the agent can substantiate today.

## Prerequisites

- Node.js **22.19 or newer**, npm, and Git. Use Node, not Bun.
- A source checkout of grclanker. Release binaries do not include this project, and `@grclanker/cli` is not published to npm.
- A Cursor credential for model turns. The installation and local tool check below need no model credential.
- Network access to Cursor for model turns and to each data source you use. Cloud and SaaS assessments also need that source's credentials.

Commands below use a POSIX shell and start at the repository root unless a step explicitly changes directory. The SDK is pinned to **`@grok/agent-sdk` 0.6.0** in `cli/package.json`; no global installation is needed.

## Install and verify

```bash
git clone https://github.com/ethanolivertroy/grclanker.git
cd grclanker
npm --prefix cli ci
npm --prefix cli run build
npm --prefix cli run agent-sdk:validate
npm --prefix cli run agent-sdk:info
```

Keep development dependencies installed: they contain the pinned SDK and its `zod` peer dependency. A successful validation prints `has no diagnostics`. Discovery lists the agent's tools, five skills, and two subagents.

Check one real tool without a model, credentials, or an external API:

```bash
npm --prefix cli run agent-sdk:call -- oscal_check_trestle \
  --input '{"workspace_dir":"."}' --json
```

Expect `"ok": true`, `"isError": false`, and a workspace/Trestle status report. A report that Trestle is unavailable is a successful check of the adapter; you only need to install Trestle when using OSCAL workspace operations. This read does not create an OSCAL workspace.

To check a public data source as well:

```bash
npm --prefix cli run agent-sdk:call -- kevs_search \
  --input '{"query":"CVE-2021-44228"}' --json
```

This second check requires access to the CISA KEV feed, but no Cursor credential. It should return the matching Log4j entries.

## Authenticate and run a model turn

Sign in with the locally installed SDK:

```bash
cd cli
npx --no-install agent-sdk login
cd ..
```

Complete the browser sign-in before continuing. For an unattended process, supply `CURSOR_API_KEY` through your environment or secret manager instead of browser login. This credential authenticates the agent harness; it does not grant access to your cloud or SaaS tenants.

Run a single read-only turn:

```bash
npm --prefix cli run agent-sdk:run -- \
  --message "Use kevs_search to check CVE-2021-44228. Cite the tool evidence and explain the remediation priority."
```

With no `--url`, `run` starts its own temporary local host. The model's answer and trajectory print in the terminal. The pinned SDK defaults to `grok-4.7` with `reasoning_effort=high` and `fast=true`. To select another Cursor model ID:

```bash
GRCLANKER_AGENT_SDK_MODEL=composer-2.5 \
  npm --prefix cli run agent-sdk:run -- \
  --message "Use kevs_search to check CVE-2021-44228 and summarize the evidence."
```

## Use the playground and approvals

Start a persistent local host in terminal 1:

```bash
npm --prefix cli run agent-sdk:dev
```

Open the playground URL printed by the SDK, normally `http://127.0.0.1:3000/playground`. In terminal 2, from the same repository root, send a turn to that host:

```bash
npm --prefix cli run agent-sdk:run -- \
  --url http://127.0.0.1:3000 \
  --message "Assess the available evidence, identify gaps, and propose the next GRC engineering actions."
```

Use the port printed by terminal 1 if port 3000 is occupied. You can also send the request directly in the playground. Stop the host with Ctrl-C.

Model-initiated exporters, generators, evidence collectors, and OSCAL workspace writers wait for the playground's **Approve / Deny** action before executing. Use this persistent-host flow for a request that creates artifacts so its approval stays reachable. A caller-selected `agent-sdk tool call` executes directly and bypasses this approval gate.

Read-only tools execute during a dry-run session; writers are stubbed. The adapter also disables persistent grclanker catalog caches during those read calls. The SDK still writes its own session state, so dry run is not a claim that the entire host is free of disk writes.

## Configure an organization integration

Data-source credentials belong to the host process that runs the tools. As one complete example, configure a GitHub organization with a PAT in the shell that will start the host:

```bash
export GITHUB_ORG="your-organization"
export GITHUB_TOKEN="<your-read-only-github-token>"

npm --prefix cli run agent-sdk:call -- github_check_access --input '{}' --json
npm --prefix cli run agent-sdk:dev
```

Replace both placeholders. For the full assessment, the principal needs organization-owner visibility with read access to organization administration, members, webhooks, Actions, repositories, and repository administration. Authorize the PAT for SSO if the organization requires it. Keep the token in your shell or secret manager; do not put it in a prompt or commit it.

In the playground, ask:

```text
Use the assess skill to review our GitHub organization. Begin with
 github_check_access, then assess identity, repository protection, Actions,
code security, and integrations. Report failed controls, evidence gaps,
framework references, and recommended next actions. Verify the findings
before giving the final report.
```

An access result of `limited` means some surfaces cannot be read. Preserve those gaps in the report; an unread control is not a passing control. The `[bdk] GitHub auth:` line on stderr describes the SDK's own GitHub integration. The grclanker `github_*` tools use the credentials above independently.

Other cloud and SaaS families use their own host environment credentials and `<provider>_check_access` tool. Their [integration pages](/docs/integrations/aws/) describe provider-specific permissions; they are reference material for those services, not setup dependencies on another runtime.

## The agent code

The source checkout already includes the complete agent. Its entry point, `cli/agent-sdk/bot/agent.ts`, is:

```ts
import { defineAgent } from "@grok/agent-sdk";
import { grclankerAgentConfig } from "../lib/agent.js";

export default defineAgent(grclankerAgentConfig());
```

The configuration names the GRC agent and reads `GRCLANKER_AGENT_SDK_MODEL`. Each domain tool has its own generated definition, for example `cli/agent-sdk/bot/tools/kevs_search.ts`:

```ts
import { defineTool } from "@grok/agent-sdk/tools";
import { grclankerToolConfig } from "../../lib/tools.js";

export default defineTool(grclankerToolConfig("kevs_search"));
```

These are the actual source files, not files you need to create after installing. The adapter registers the domain tools directly and does not start a Pi session. It validates and normalizes tool arguments, converts their parameter schemas, preserves text/image results and error status, and declares the approval policy for each tool.

| Included asset | Agent SDK surface |
|---|---|
| Native domain tools in `cli/extensions/grc-tools/` | Server tools under their native names |
| `cli/.grclanker/SYSTEM.md` and `cli/agent-sdk/prompts/runtime.md` | Always-on GRC instructions and runtime guidance |
| `cli/prompts/{investigate,audit,assess,validate}.md` | Skills named `investigate`, `audit`, `assess`, and `validate` |
| `cli/skills/crypto-validation/SKILL.md` | Skill named `crypto-validation` |
| `cli/.grclanker/agents/{auditor,verifier}.md` | Subagents named `auditor` and `verifier` |

Ask for the relevant workflow in ordinary language, such as “use the audit skill to map this evidence to SOC 2.” The auditor maps gathered evidence to controls; the verifier checks claims against sources. Terminal slash commands are not registered in this harness.

The Cursor harness supplies `shell`, `Read`, `Write`, `StrReplace`, `Grep`, `Glob`, `LS`, and `Delete`. The domain adapter's approval gates apply to its domain tools; configure and isolate the harness separately for its built-in shell and file access. The CLI's `docker`, `sandbox-runtime`, and `parallels-vm` compute-backend settings do not configure this harness.

## Files, state, and self-hosting

Server tools execute in the SDK host process. Relative `output_dir`, `workspace_dir`, and `zip_path` arguments resolve against its working directory: **`cli/` when using the npm scripts above**. They do not resolve against the model's separate session workspace. Pass an absolute path to place artifacts in a specific workspace, and use the absolute paths returned by the tool.

Default exports go under `cli/export/<domain>/` and OSCAL workspaces under `cli/oscal-workspace/`. The SDK's state, traces, and eval batches go under `cli/agent-sdk/.agent-serve/`. These local directories are gitignored. Treat reports and traces as organization evidence and control access to them.

For local development, `agent-sdk:dev` is sufficient. To run the existing source checkout as a persistent service on your own machine, install/build as above, provide the Cursor and integration credentials to the service, and run from `cli/`:

```bash
cd cli
npx --no-install agent-sdk serve --dir agent-sdk --mode single \
  --host 127.0.0.1 --port 3000 \
  --state-root /var/lib/grclanker-agent-sdk
```

Create that state directory with write access for the service account first. Keep loopback access or place an authenticated TLS proxy in front of the service. The SDK also supports a `--bearer-token` option; supply its value through your service's secret handling when exposing HTTP routes. Persist the state root and the artifact directories that your organization needs to retain.

**Cursor-managed hosting is not configured or validated for this grclanker project.** Its current adapter uses in-process server tools on the local harness and source/assets from the parent `cli/` package. Copying `cli/agent-sdk/` alone or running a generic managed-hosting deploy command is not a complete deployment of these tools.

## Validate changes and troubleshoot

After changing adapter code, run:

```bash
npm --prefix cli run build
npm --prefix cli run test:agent-sdk:validate
```

The smoke test checks the pinned SDK's real discovery, tool effects and approval flags, plus a local OSCAL tool call and invalid-input rejection without a model or provider request. After adding or renaming native tools, regenerate their SDK definitions with:

```bash
npm --prefix cli run sync:agent-sdk-tools
```

| Symptom | Action |
|---|---|
| `agent-sdk` not found | Run `npm --prefix cli ci` without omitting development dependencies, then use the npm scripts or `npx --no-install` from `cli/`. |
| Authentication error on a model turn | Complete `agent-sdk login` from `cli/` or supply a valid `CURSOR_API_KEY` to the host process. Tool-only validation needs neither. |
| A turn waits while exporting | Open the persistent host's playground and approve or deny the tool call. Ensure your run used that host's `--url`. |
| Provider access is missing or limited | Set that integration's credentials in the host environment, restart the host, and run its access-check tool directly. |
| An artifact is missing from the session workspace | Check the absolute path in the tool result; relative paths use the host working directory. |
| A new tool does not appear | Regenerate the tool entries, rebuild, and rerun discovery. |
| The SDK prints an outdated-version notice | Keep the tested pin; update `cli/package.json` and the lockfile deliberately, then rerun the adapter tests. |

See the official [Agent SDK overview](https://cursor.com/docs/agent-sdk), [CLI reference](https://cursor.com/docs/agent-sdk/reference/cli), [tools reference](https://cursor.com/docs/agent-sdk/reference/tools), and [project layout](https://cursor.com/docs/agent-sdk/reference/project-layout) for SDK API details.
