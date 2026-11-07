---
title: Codex SDK
description: Run a GRC engineering assistant with the OpenAI Codex SDK and a local grclanker tool server.
---

Use this path to embed a GRC engineering assistant in an application or a worker you operate. The adapter in `cli/adapters/codex/` uses `@openai/codex-sdk` for the agent loop and a local MCP server for selected native grclanker tools. This page contains its complete setup and operating instructions.

The Codex SDK wraps the Codex CLI and runs it as a subprocess. It is a separate package and harness from the OpenAI Agents SDK. See the official [Codex SDK reference](https://github.com/openai/codex/tree/main/sdk/typescript) for its thread, streaming, and configuration APIs.

## Prerequisites and installation

Use macOS or Linux with Git, npm, and Node.js 22.22 or newer. You need an OpenAI API key with access to a Codex-compatible model. Public vulnerability lookups also need outbound HTTPS access to CISA's catalog on `raw.githubusercontent.com` and FIRST's `api.first.org` API.

From a new checkout:

```bash
git clone https://github.com/ethanolivertroy/grclanker.git
cd grclanker
npm --prefix cli ci
npm --prefix cli run build
npm --prefix cli run codex:install
npm --prefix cli run codex:check
```

`npm --prefix cli ci` and the build prepare the shared GRC library and native tool dependencies. `codex:install` installs the adapter's additional pinned dependencies: `@openai/codex-sdk` and `@modelcontextprotocol/sdk`. Host configuration is separate from the other adapters, but dependency installation is not fully isolated: Codex still needs the shared CLI package and build. It runs without a grclanker terminal session or model setup wizard.

The offline check starts the MCP server and executes a real OSCAL workspace inspection against temporary local fixtures. It also checks tool discovery, invalid input, empty and unknown tool selections, and blocked unselected tools. A fake local Codex executable verifies the real SDK's configuration, credential forwarding, and prompt/result transport. No model or tenant API calls or real credentials are used, and compliance-trestle does not need to be installed.

## Authenticate and run

Set the API key in the shell that starts the worker:

```bash
export OPENAI_API_KEY='your-api-key'
npm --prefix cli run codex:run -- \
  "Check CVE-2024-3400 in the CISA KEV catalog and get its EPSS score. Cite the evidence and explain uncertainty."
```

This starts a fresh Codex thread with `kevs_search` and `kevs_get_epss`. The final answer prints to stdout and the thread ID prints to stderr. A successful response identifies the evidence source, the EPSS score date when available, and any failed or incomplete lookups. The result can change as upstream data changes.

This adapter passes `OPENAI_API_KEY` to the SDK explicitly. A model API key and a tenant integration credential serve different purposes; the former does not grant access to your organization's systems.

## How the code connects the agent and tools

The host-specific implementation is in [`cli/adapters/codex`](https://github.com/ethanolivertroy/grclanker/tree/main/cli/adapters/codex). It consumes shared code in `cli/core/`, native tools in `cli/extensions/grc-tools/`, and the GRC role in `cli/.grclanker/`. Its own files are:

| File | Purpose |
| --- | --- |
| `package.json` and `package-lock.json` | Pinned adapter dependencies and run commands. |
| `main.mjs` | Select tools, load GRC instructions, and run a request. |
| `config.mjs` | Define typed SDK options, tool server settings, and credential forwarding. |
| `mcp-server.mjs` | Expose the selected domain tools over local stdio MCP. |
| `tools.mjs` | Validate tool names and reject tools with write effects. |
| `check.mjs` | Execute a local GRC inspection and verify SDK transport, configuration, validation, and restrictions without a model call. |

The SDK connection uses settings from `config.mjs`, including absolute executable and server paths. The following standalone excerpt shows the same setup:

```javascript
import { fileURLToPath } from "node:url";
import { Codex } from "@openai/codex-sdk";

const toolNames = ["kevs_search", "kevs_get_epss"];
const codex = new Codex({
  apiKey: process.env.OPENAI_API_KEY,
  config: {
    mcp_servers: {
      grclanker: {
        command: process.execPath,
        args: [
          fileURLToPath(new URL("./mcp-server.mjs", import.meta.url)),
          ...toolNames,
        ],
        env_vars: ["GITHUB_ORG", "GITHUB_TOKEN", "GH_TOKEN"],
        required: true,
        startup_timeout_sec: 30,
        tool_timeout_sec: 300,
      },
    },
  },
});

const thread = codex.startThread({
  workingDirectory: fileURLToPath(new URL("./", import.meta.url)),
  sandboxMode: "read-only",
  approvalPolicy: "never",
});
const turn = await thread.run("Use the grclanker tools to investigate CVE-2024-3400.");
console.log(turn.finalResponse);
```

This excerpt belongs in the adapter directory after installation. The checked-in `main.mjs` also adds the shared GRC methodology, validates the tool selection, and accepts your request on the command line. `required: true` makes failure to start the tool server fail the run rather than leaving the agent without its evidence tools. OpenAI documents the server settings in its [MCP configuration reference](https://developers.openai.com/codex/mcp/).

The tool server reads the registry and schemas from `cli/dist/core`, then uses the shared argument validation, cancellation, error redaction, and result conversion. It exposes no shell or file tools. Each call must name an enabled tool, and the executor denies write tools by default.

Codex's filesystem sandbox applies to its built-in execution tools. The MCP server is a separate local process and makes its own API calls with the credentials forwarded to it. A read-only Codex thread does not impose a filesystem sandbox on that server. The supplied server accepts only read tools; public-data tools may maintain local caches.

## Connect a tenant: GitHub example

Run the following from the checkout root. Use a PAT permitted to read the organization and repositories in scope, and authorize it for SSO if required:

```bash
export GITHUB_ORG='your-organization'
export GITHUB_TOKEN='your-github-token'
export GRCLANKER_TOOLS='github_check_access,github_assess_org_access,github_assess_repo_protection'
npm --prefix cli run codex:run -- \
  "Run github_check_access first. Explain unreadable surfaces, then assess organization access and repository protection. Give evidence, unknowns, and remediation priorities."
```

`GRCLANKER_TOOLS` replaces the default tool selection. `config.mjs` already forwards the GitHub environment variable names to the server. An organization owner PAT or an appropriately permissioned GitHub App may be needed for complete coverage; a limited token produces incomplete evidence. The optional [GitHub integration reference](/docs/integrations/github/) describes App authentication and control coverage.

To select another integration, inspect its tools from the checkout root:

```bash
node cli/dist/core/cli.js list
node cli/dist/core/cli.js list github_check_access
```

Then set `GRCLANKER_TOOLS` to its exact read-tool names and add the integration's credential variable names to `env_vars` in `config.mjs`. Supply the values through the worker's environment or secret manager. Configure access to the vendor endpoint from the machine running the MCP process.

You can check credentials deterministically before paying for a model turn:

```bash
printf '%s' '{}' | node cli/dist/core/cli.js call github_check_access
```

An error result exits with status 1. Read the returned access report before treating subsequent findings as complete.

## Use it as a GRC engineer assistant

Provide the organization boundary, relevant systems, applicable framework, evidence period, owners, and output you need. For example:

```bash
npm --prefix cli run codex:run -- \
  "Assess the configured GitHub organization's access controls for our SOC 2 review. Separate observed settings, missing evidence, policy questions for the control owner, and remediation work."
```

The shipped methodology covers scope, evidence gathering, control alignment, risk prioritization, and recommendations. Extend the request to policy analysis, risk treatment planning, audit preparation, or control design when you supply the necessary organizational context. The platform integrations provide evidence for those tasks. Broader policy approval, risk acceptance, and organization-wide workflow automation remain responsibilities of your surrounding application and operating process.

This adapter returns a report in the conversation. It does not enable evidence exporters, OSCAL workspace writers, tenant changes, recurring jobs, or verifier subagents. Supporting a write workflow requires a host-controlled authorization step and an explicit change to the server's selection and execution policy; prompting the model to approve itself is insufficient.

## Deploy and maintain

Run `npm --prefix cli run codex:run -- "<request>"` from a worker, job runner, or service you operate. Deploy the checkout's `cli/dist`, `cli/.grclanker` assets, CLI dependencies, and the installed `cli/adapters/codex` directory at the same relative paths. Copying the adapter directory alone does not supply the core or native tools. The SDK needs its platform-compatible Codex executable; install dependencies on the target operating system and architecture.

Provision the model key and selected tenant credentials through your deployment's secret manager. Allow outbound access to OpenAI and the integration endpoints. Preserve a private home directory if you want Codex session history to survive restarts; Codex normally saves it under `~/.codex/sessions`. Public-data caches use the common grclanker state directory. No tenant credentials or generated reports belong in the source repository.

Each invocation starts a new thread. To build a conversation service, keep the returned `thread` and call `thread.run()` again, or persist its ID and use `codex.resumeThread(id, threadOptions)` with the same server configuration. Keep each organization's credentials and session history isolated. Add scheduling, retention, and application authentication in the host service when needed.

After pulling source updates, rerun `npm --prefix cli ci`, `npm --prefix cli run build`, `npm --prefix cli run codex:install`, and the offline check. A successful offline check validates the bridge; a credentialed live run is still required to verify model access and your tenant's permissions.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| Missing `dist/core` module | Run `npm --prefix cli run build` from the checkout root. |
| Missing SDK package or executable | Run `npm --prefix cli run codex:install` on the target platform; avoid copying dependencies from another architecture. |
| OpenAI authentication or model error | Set `OPENAI_API_KEY` for this process and verify that the key has model access and API credit. |
| Tool server startup fails | Run the offline check; inspect the tool names and retain the adapter's relative layout. |
| Tool is not enabled or is rejected as a writer | Select an exact read-tool name. This supplied server deliberately rejects write tools. |
| Tenant credentials missing in a tool | Set the variables in the launching process and include their names in the server's `env_vars`. |
| EPSS, KEV, or tenant request fails | Check network access from the MCP host and preserve the incomplete-evidence result. |
| Need files or recurring assessments | Add an explicit artifact or scheduling workflow in your host application. This adapter runs one read-only assessment turn. |
