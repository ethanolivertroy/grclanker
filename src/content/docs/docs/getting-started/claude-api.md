---
title: Claude API Tool Runner
description: Build and run a GRC engineering assistant with the tool runner in Anthropic's API SDK, grclanker's native tools, workflows, evidence reviewers, and write approvals.
---

This adapter runs grclanker with the tool runner in Anthropic's regular API SDK (`@anthropic-ai/sdk` 1.2.0, `client.beta.messages.toolRunner`). The SDK drives the request, tool call, and result loop over the tools grclanker defines. It is lighter than the [Claude Agent SDK](/docs/getting-started/claude-agent-sdk/) path: there is no Claude Code executable and no built-in shell, file, or web tool. The code lives in `cli/adapters/claude-api/` and imports the provider-neutral `cli/core/` bridge.

To use grclanker inside Claude Code with your own sign-in, including a Claude subscription, use the [Claude Code (MCP)](/docs/getting-started/claude-code/) path instead.

## Prerequisites

You need Git, npm, Node.js 22.19 or newer, and an Anthropic API key with access to your chosen model. The SDK reads `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, or an `ant auth login` profile. Vendor credentials separately authorize the GRC tools to read your organization.

## Install and verify locally

```bash
git clone https://github.com/ethanolivertroy/grclanker.git
cd grclanker
npm --prefix cli ci
npm --prefix cli run build
npm --prefix cli run claude-api:check
```

The check builds the agent and prints its tools without a model request. `node --test tests/claude-api*.test.mjs`, run from `cli/` after the build, checks tool adaptation, validation, provider-error redaction, incomplete responses, cancellation, and write approval using local fake Messages APIs.

## Authenticate and run your first task

```bash
export ANTHROPIC_API_KEY='your-anthropic-api-key'
npm --prefix cli run claude-api:run -- \
  "Investigate CVE-2024-3400 using KEV and EPSS evidence. Cite sources and explain what still needs organization-specific verification."
```

| Option | Effect |
| --- | --- |
| `--tools a,b,c` | Replace the domain tools; the default is `cmvp_search_modules`, `cmvp_get_module`, `kevs_search`, and `kevs_get_epss` |
| `--model id` | Change the model; `GRCLANKER_CLAUDE_API_MODEL` sets it, and the default is `claude-opus-5-5` |
| `--no-fallback` | Do not re-run declined turns on Anthropic's fallback model |
| `--check` | Print the exposed tools without a model request |
| `--list-tools` | List every registered domain tool and its effect |

The runner prints each tool call to stderr and the final answer to stdout.

## Connect an organization tool

```bash
export GITHUB_ORG='your-organization'
export GITHUB_TOKEN='your-github-token'
npm --prefix cli run claude-api:run -- \
  --tools github_check_access,github_assess_org_access,github_assess_repo_protection \
  "Check access first, assess GitHub access and repository protection, then report evidence gaps and remediation priorities."
```

The token needs read access to the organization and repositories, with SSO authorization when required. Tools run in the Node process and read credentials from its environment.

## Embed the agent in your own application

`createGrclankerClaudeApiAgent(client, options)` returns the tools and tool runner parameters without messages. After building, create `cli/claude-api-example.mjs`:

```javascript
import Anthropic from "@anthropic-ai/sdk";
import { createGrclankerClaudeApiAgent } from "./dist/adapters/claude-api/agent.js";

const client = new Anthropic();
const agent = createGrclankerClaudeApiAgent(client, {
  toolNames: ["kevs_search", "kevs_get_epss"],
  // Bind this to your authenticated operator; omit it to decline every write.
  approveWrite: async ({ toolName, input }) => false,
});
const final = await client.beta.messages.toolRunner({
  ...agent.params,
  stream: false,
  messages: [{ role: "user", content: "Investigate CVE-2024-3400 and cite evidence." }],
});
console.log(final.content.filter((block) => block.type === "text").map((block) => block.text).join("\n"));
```

Run `node cli/claude-api-example.mjs` from the repository root. Options also include `model` and `serverSideFallback`.

## Request settings

- **Model and thinking:** `claude-opus-5-5` with adaptive thinking at `high` effort, `max_tokens` 16000, and at most 30 loop iterations.
- **Prompt caching:** the system prompt carries a `cache_control` breakpoint, so the stable instructions and tool list are cached across turns of a run.
- **No server-side threads:** `thread: false` resends the history each turn instead of keeping evidence in a server-side message thread.
- **Refusal fallback:** requests send `fallbacks: "default"` with beta `server-side-fallback-2026-07-01`, so a turn Claude declines is re-run on Anthropic's fallback model in the same call. Use `--no-fallback` to turn it off.

## Workflows and evidence review

Before a structured investigation, audit, assessment, or validation, the agent loads the matching workflow with `grclanker_load_workflow`; `grclanker_load_skill` loads the crypto-validation methodology. The `auditor` and `verifier` tools each make one separate model call with the persona instructions and the evidence the agent passes in. They cannot gather evidence or run tenant tools.

## Approve file-writing tools

Exports and other writers call `approveWrite` with the exact tool name, arguments, and abort signal inside the tool's `run` function, before anything executes. A declined call returns an error result to the model and writes nothing. The shipped runner shows the call with credential-like values redacted, asks at an interactive terminal one call at a time, and denies writes when there is no terminal. Cancellation stops the approval wait and prevents a late answer from executing the call; an embedding service should use the signal to cancel its approval interface. Relative paths resolve against the Node process working directory; use absolute `output_dir`, `workspace_dir`, or `zip_path` values.

The CLI exits unsuccessfully when a response is refused, interrupted, truncated, or has no final text. Partial output is not a completed assessment. Incomplete auditor or verifier responses are reported as tool errors so the agent can identify missing review evidence. Provider failures report bounded error information without copying raw error bodies into model results or terminal output.

## Deploy on your infrastructure

Deploy the shared CLI build, its production dependencies, and the GRC assets in `cli/.grclanker/`, `cli/prompts/`, and `cli/skills/` with their relative paths intact. Supply the Anthropic and vendor credentials through your secret manager. Each run is a single conversation held in memory; store the messages yourself if you need to continue one later.

## Troubleshooting and verification

- **`Claude API authentication failed`:** set `ANTHROPIC_API_KEY`, or sign in with `ant auth login`.
- **A request rejected with HTTP 400:** check your model and request settings. If your account or platform does not accept server-side fallback, rerun with `--no-fallback`.
- **`Unknown grclanker tool`:** check the names with `--list-tools`.
- **`did not approve`:** a writer was declined. Run at an interactive terminal, or implement `approveWrite`.
- **Vendor tools report missing access:** an access failure is missing evidence, not a passing control.
