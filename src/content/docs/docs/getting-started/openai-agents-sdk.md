---
title: OpenAI Agents SDK
description: Build and run a GRC engineer assistant with the OpenAI Agents SDK, grclanker's native tools, workflows, and evidence reviewers.
---

Run grclanker inside the **OpenAI Agents SDK for TypeScript** using the adapter in `cli/adapters/openai-agents/`. This page includes installation, credentials, runnable code, tool selection, approval behavior, and deployment instructions. It does not require another runtime's guide or configuration.

The adapter uses `@openai/agents` **0.21.0** and the provider-neutral GRC registry in `cli/core/`. Native tools live in `cli/extensions/grc-tools/`; shared instructions, workflow prompts, skills, and personas live in `cli/.grclanker/`, `cli/prompts/`, and `cli/skills/`. The [OpenAI Agents SDK](https://developers.openai.com/api/docs/guides/agents/sdk) runs the model and tool loop in your Node process.

This host has its own agent configuration, credentials, approvals, and runner. It does not import or require another adapter's setup. Source dependencies and the TypeScript build are shared in `cli/package.json`, so the adapter is not an independently packaged installation. Its `agent.ts` and `cli.ts` compile to `cli/dist/adapters/openai-agents/`.

## Prerequisites

- Node.js **22.19 or newer**, npm, and Git.
- An OpenAI API project with billing and access to your selected model. This adapter uses `OPENAI_API_KEY`.
- Outbound network access to OpenAI and the data sources or vendor APIs you select.
- For organization assessments, credentials with read access to the target tenant. Public CMVP and vulnerability lookups do not need tenant credentials.

This integration runs from a source checkout. The downloadable terminal bundle does not include it, and `@grclanker/cli` is not published to npm. Commands below start in the repository root and use a POSIX shell.

## Install and verify locally

```bash
git clone https://github.com/ethanolivertroy/grclanker.git
cd grclanker
npm --prefix cli ci
npm --prefix cli run build
npm --prefix cli run openai-agents:check
```

The check builds the agent configuration and prints its model and tools. It makes no model request and needs no provider or tenant credentials. The default model is `gpt-5.4`; `--model` or `GRCLANKER_OPENAI_MODEL` changes it.

List every available native GRC tool and its read/write classification:

```bash
npm --prefix cli run openai-agents:run -- --list-tools
```

## Authenticate and run your first task

Set the API key in the shell that starts the agent, or inject it through your deployment's secret manager:

```bash
export OPENAI_API_KEY="your-openai-api-key"
npm --prefix cli run openai-agents:run -- \
  "Investigate CVE-2021-44228. Use KEV and EPSS evidence, cite the sources, and explain what still needs organization-specific verification."
```

The default deployment exposes `cmvp_search_modules`, `cmvp_get_module`, `kevs_search`, and `kevs_get_epss`. It also exposes the workflow and cryptographic skill loaders and the two evidence reviewers. A successful run prints the agent's final answer. Provider or network errors end with a nonzero exit status; a tool-level failure is returned to the agent with `isError: true` and must be treated as unavailable evidence.

To select a different model:

```bash
npm --prefix cli run openai-agents:run -- --model gpt-5.4 \
  "Check BoringCrypto's validation status and identify the evidence needed for a deployment-specific conclusion."
```

Model requests incur OpenAI API usage. The CLI disables the SDK's separate tracing exporter. Prompts, tool arguments, evidence results, and evidence passed to reviewer agents still go to the selected model.

## Connect an organization tool

Choose the tool names for the deployment with `--tools`; this replaces the default four domain tools. All registered GRC domain tools are available for selection. Up to **124 domain tools** can be exposed in one agent, leaving four slots for methodology and evidence review. For larger deployments, create agents scoped to a tenant, system, or workflow.

Here is a complete GitHub read-only assessment setup:

```bash
export OPENAI_API_KEY="your-openai-api-key"
export GITHUB_ORG="your-organization"
export GITHUB_TOKEN="your-github-token"
npm --prefix cli run openai-agents:run -- \
  --tools github_check_access,github_assess_org_access,github_assess_repo_protection,github_assess_actions_security,github_assess_code_security,github_assess_integrations \
  "Assess our GitHub organization. Check access first, separate unread surfaces from failing controls, map evidence to SOC 2 controls, and propose prioritized remediation with owners and evidence needed to close each gap."
```

The token needs organization and repository read access for the requested surfaces. A complete assessment needs organization-owner visibility, including members without 2FA, audit logs, webhooks, and integration details. Authorize the PAT for SSO when the organization requires it. Partial or denied access is evidence of a coverage gap, not a passing control. Other credential families and control coverage are available in the optional [GitHub integration reference](/docs/integrations/github/).

Tools read their own credentials from the Node process's environment. The OpenAI key authorizes model calls; it does not grant access to GitHub, AWS, Okta, or another source. Select that source's access-check tool and confirm its result before interpreting assessment findings. Inject tenant credentials into the process rather than putting them in prompts.

## Embed the agent in your own application

After the installation above, save this complete example as `cli/openai-example.mjs`. Keeping it under `cli/` lets Node resolve the installed SDK and the built adapter:

```javascript
import { Runner } from "@openai/agents";
import { createGrclankerOpenAIAgent } from "./dist/adapters/openai-agents/agent.js";

const agent = createGrclankerOpenAIAgent({
  model: "gpt-5.4",
  toolNames: ["kevs_search", "kevs_get_epss"],
});
const runner = new Runner({ tracingDisabled: true });
const result = await runner.run(
  agent,
  "Investigate CVE-2021-44228, cite evidence, and prioritize verification steps.",
  { maxTurns: 20 },
);

// This example selects read-only tools. An unexpected approval must stop here.
if (result.interruptions.length > 0) {
  throw new Error("A tool is awaiting approval; resolve it before continuing.");
}
console.log(result.finalOutput);
```

Run it from the repository root:

```bash
export OPENAI_API_KEY="your-openai-api-key"
node cli/openai-example.mjs
```

`createGrclankerOpenAIAgent({ toolNames, model })` returns a normal SDK `Agent`. Omitting `toolNames` selects the four public-data tools. Omitting `model` reads `GRCLANKER_OPENAI_MODEL`, then falls back to `gpt-5.4`. You can create several agents with different tool selections using the same adapter.

The adapter uses non-strict model-facing JSON schemas so native optional arguments stay optional. Before execution, inputs still pass through each tool's normalization and TypeBox validation. Text/image content and `isError` are retained in the JSON result envelope; internal UI metadata is omitted. Cancellation from the SDK is forwarded to the native tool.

## Workflows and evidence review

The agent has four additional tools in every deployment:

| Tool | Purpose |
|---|---|
| `grclanker_load_workflow` | Load `investigate`, `audit`, `assess`, or `validate` instructions before a structured task |
| `grclanker_load_skill` | Load the cryptographic validation methodology |
| `auditor` | Ask the auditor agent to map supplied evidence to controls and identify gaps |
| `verifier` | Ask the verifier agent to check claims, sources, and evidence chains |

The reviewers receive evidence from the main agent and cannot query tenants themselves. These are actual SDK agents exposed as tools. Their calls use the selected model and consume additional model usage. Workflow names are tool inputs; terminal slash commands and the terminal setup wizard do not apply here.

Use the agent for evidence collection, risk prioritization, framework mapping, audit preparation, and remediation planning. It can help draft policies, control ownership, risk treatment plans, and governance decisions from supplied context. Tool coverage determines which claims it can verify. Organizational risk acceptance and official compliance decisions still belong to the responsible owners.

## Approve file-writing tools

Exports, generators, evidence collectors, and OSCAL workspace writers set SDK `needsApproval: true`. The SDK pauses before execution; the shipped CLI shows the selected tool and redacted arguments, then asks for approval for that call. A noninteractive run rejects pending writes. It never auto-approves them.

For example, add the GitHub exporter to an interactive deployment:

```bash
npm --prefix cli run openai-agents:run -- \
  --tools github_check_access,github_export_audit_bundle \
  "Check access, then export a GitHub audit bundle under /tmp/grclanker-github-evidence. Explain the output before requesting approval."
```

The GitHub environment variables from the earlier example must be set. Exporting writes evidence locally; it does not change the GitHub organization. Relative `output_dir`, `workspace_dir`, and `zip_path` arguments resolve against the Node process's working directory, which is `cli/` for these npm scripts. Use absolute paths for predictable output locations. Export tools return the paths they created.

In an embedded application, inspect `result.interruptions`, resolve each with `result.state.approve(item)` or `result.state.reject(item)`, then resume with `runner.run(agent, result.state)`. Bind those decisions to the authenticated operator and displayed call. See OpenAI's [approval lifecycle](https://openai.github.io/openai-agents-js/guides/human-in-the-loop/) for persistent application workflows. Calling a function tool's `invoke` directly bypasses the SDK runner's approval lifecycle; use `Runner` for agent-initiated calls.

## Deploy on your infrastructure

Build the checkout in CI with the install and build commands above. Run `node cli/dist/adapters/openai-agents/cli.js` from the repository root for a one-shot job, or call the exported factory from your Node service. Preserve the `cli/package.json`, installed production dependencies, built `cli/dist/`, and bundled assets under `cli/.grclanker/`, `cli/prompts/`, and `cli/skills/`; the adapter resolves its instructions from those assets.

Inject `OPENAI_API_KEY` and the selected tenant credentials at runtime. Provide network access to the model and the selected tools' APIs. Mount a persistent output directory if evidence must survive a job. Public lookups can cache reference data under `~/.grclanker/.state/`; set `GRCLANKER_HOME` when you need a dedicated state directory.

The shipped CLI is a local process and one-shot runner, not a hosted website, scheduler, or multiuser service. Its write approvals require an interactive terminal. For an unattended worker, use read-only tool selections; for a service that supports writes, implement authenticated approval and resume handling. The adapter does not register a generic shell or file editor and does not use the terminal runtime's compute-backend settings. Native GRC tools still run on the host and use any external utilities required by those tools.

## Troubleshooting and verification

| Symptom | Action |
|---|---|
| `Cannot find module` under `dist/adapters/openai-agents` | Run `npm --prefix cli ci` and `npm --prefix cli run build` from the checkout |
| Missing `OPENAI_API_KEY`, or provider 401 | Inject a valid OpenAI API key into the agent process; local agent construction does not test authentication |
| Model is unavailable | Choose a model your API project can access with `--model` |
| Agent cannot call an organization tool | Add its exact name to `--tools` and inject that vendor's credentials into the process |
| Tool reports missing access or partial evidence | Fix the tenant permissions and rerun its access check; do not interpret unread settings as passing |
| Export is rejected in CI | Noninteractive runs reject writes; use read-only jobs or an application with approval/resume support |
| Output appears in an unexpected directory | Supply an absolute output path; npm scripts execute inside `cli/` |
| Public feed lookup fails | Check outbound access and the data source response; `--check` tests configuration only |

Run the adapter's offline regression checks after building:

```bash
npm --prefix cli run build
cd cli
node --test tests/openai-agents.test.mjs
```

The tests exercise registration, native validation, credential redaction, workflow loading, tool selection limits, and the real SDK's pause/approve/reject lifecycle with a scripted model. They make no live provider requests. A successful authenticated task is the separate live check for your model, credentials, and network.

For SDK API details, see the official [function tools guide](https://openai.github.io/openai-agents-js/guides/tools/).
