---
title: Claude Agent SDK
description: Run a GRC engineering assistant with the Claude Agent SDK, grclanker's native tools over in-process MCP, evidence reviewers, and per-call write approval.
---

The grclanker Claude Agent SDK adapter pairs Anthropic's agent loop with the GRC engineer instructions, workflow prompts, an explicitly chosen set of domain tools, and auditor and verifier subagents. It lives in `cli/adapters/claude-agent-sdk/` and imports the provider-neutral `cli/core/` bridge; it does not depend on another provider's adapter.

To use grclanker inside Claude Code with your own Claude Code sign-in, including a Claude subscription, use the [Claude Code (MCP)](/docs/getting-started/claude-code/) path instead; it needs no API key.

The [Claude Agent SDK](https://code.claude.com/docs/en/agent-sdk/overview) (`@anthropic-ai/claude-agent-sdk`, pinned to 0.3.305) runs its loop through a bundled Claude Code executable. grclanker removes Claude Code's built-in shell, file, web, and editing tools and serves the selected GRC tools from an MCP server inside your Node process.

## Prerequisites and installation

You need Git, npm, Node.js 22.19 or newer, and an Anthropic API key with access to your chosen model. From a fresh checkout:

```bash
git clone https://github.com/ethanolivertroy/grclanker.git
cd grclanker
npm --prefix cli ci
npm --prefix cli run build
npm --prefix cli run claude:install
npm --prefix cli run claude:check
```

`claude:install` installs the SDK, the MCP SDK, and Zod from the adapter's own lockfile. The SDK adds a platform-specific Claude Code executable of about 280 MB, which is why it is not part of the shared `cli/package.json` install.

`claude:check` needs no credentials and makes no network requests. It checks tool selection, the isolation options, and the permission callback, and drives the in-process MCP server for discovery, argument validation, the tool allowlist, and the write gate. It then runs the real SDK and Claude Code executable against a local fake Messages API that calls a read tool and a writer the operator denies, and confirms that no built-in tools were offered and that the denied writer created nothing.

## Authenticate and run

Claude authentication and vendor authentication are separate. `ANTHROPIC_API_KEY` authenticates the model; Claude Code's Amazon Bedrock, Google Vertex AI, and Microsoft Foundry settings also work when set in the environment. Vendor credentials only authorize the GRC tools to read your organization.

```bash
export ANTHROPIC_API_KEY='your-anthropic-api-key'
npm --prefix cli run claude:run -- \
  "Investigate CVE-2024-3400 using KEV and EPSS evidence. Cite sources and explain what still needs organization-specific verification."
```

The default tools are four public-data lookups: `cmvp_search_modules`, `cmvp_get_module`, `kevs_search`, and `kevs_get_epss`. Runner options:

| Option | Effect |
| --- | --- |
| `--tools a,b,c` | Replace the domain tool selection; `GRCLANKER_TOOLS` sets the same list |
| `--model id` | Change the model; `GRCLANKER_CLAUDE_MODEL` sets it, and the default is `claude-opus-5-5` |
| `--check` | Print the exposed tools, approval-gated writers, and subagents without a model request |
| `--list-tools` | List every registered domain tool and its effect |
| `--persist-session` | Save the transcript and print the session ID |
| `--resume id` | Continue a saved session |

The runner prints each tool call to stderr and the final answer to stdout.

## Connect a tenant: GitHub example

```bash
export GITHUB_ORG='your-organization'
export GITHUB_TOKEN='your-github-token'
npm --prefix cli run claude:run -- \
  --tools github_check_access,github_assess_org_access,github_assess_repo_protection \
  "Check access first, assess GitHub access and repository protection, then report evidence gaps and remediation priorities."
```

Use a token authorized to read the organization and repositories, including SSO authorization when required. Limited permissions produce incomplete assessments. The tools run inside the Node process and read their credentials from its environment. Run `node cli/dist/core/cli.js list` or `--list-tools` to find other tool names.

## How the code connects the agent and tools

| File | Role |
| --- | --- |
| `agent.mjs` | `createGrclankerClaudeOptions()` builds `query()` options: system prompt, MCP server, subagents, and the permission callback |
| `server.mjs` | In-process MCP server listing the selected tools with their shared JSON schemas, plus `grclanker_load_workflow` and `grclanker_load_skill` |
| `tools.mjs` | Default selection and validation of tool names |
| `main.mjs` | One-shot runner with terminal approval |
| `check.mjs` | Offline check |

The system prompt is the shared grclanker instructions plus a Claude runtime note; it replaces Claude Code's default coding prompt. Tools appear to the model as `mcp__grclanker__<tool>`. The common executor validates arguments strictly, honors cancellation, and scrubs credentials from error text. Results keep their `isError` flag.

To embed the adapter, create `cli/adapters/claude-agent-sdk/example.mjs`:

```javascript
import { query } from "@anthropic-ai/claude-agent-sdk";
import { createGrclankerClaudeOptions } from "./agent.mjs";

const { options } = createGrclankerClaudeOptions({
  toolNames: ["kevs_search", "kevs_get_epss"],
  // Bind this to your authenticated operator; omit it to deny every write.
  approveWrite: async ({ toolName, input }) => false,
});
for await (const message of query({ prompt: "Investigate CVE-2024-3400 and cite evidence.", options })) {
  if (message.type === "result") console.log(message.subtype === "success" ? message.result : message.subtype);
}
```

Run it with `node cli/adapters/claude-agent-sdk/example.mjs`. `createGrclankerClaudeOptions()` also accepts `model`, `persistSession`, `env` (the Claude Code process environment, default `process.env`), and `cwd`.

## Isolation, approvals, and human review

The options run the SDK in isolation mode:

- `settingSources: []` loads no user, project, or local Claude settings and no CLAUDE.md files, so a developer's own allow rules cannot pre-approve calls.
- `strictMcpConfig: true` ignores `.mcp.json`, plugins, and other MCP configuration. `skills: []` enables no skills.
- `tools: ["Agent"]` removes every built-in tool except the launcher for the auditor and verifier subagents. Those subagents have no tools and review only the evidence they are given.

Every permission decision goes through the adapter's `canUseTool` callback; there are no `allowedTools` rules. It allows the selected read tools, the loaders, and the subagent launcher, and denies everything else, including a same-named tool from any server other than the host's in-process server.

Exports and other file-writing tools need a human decision for each call. The callback passes the tool name and arguments to `approveWrite`; the shipped runner shows them with credential-like values redacted and asks at an interactive terminal, and denies writes when there is no terminal. An approval is recorded for the exact tool and arguments, and the MCP handler runs a writer only after consuming one, so a writer never runs without approval for those arguments. An embedding service must bind `approveWrite` to its authenticated operator.

Review the final report, control mappings, and any generated artifact before relying on them. Proposed policies and risk acceptance decisions are drafts for the organization's owners.

## Workflows and sessions

Before a structured investigation, audit, assessment, or validation, the agent loads the matching workflow with `grclanker_load_workflow`; `grclanker_load_skill` loads the crypto-validation methodology. Ask for an audit, for example, and the agent loads the audit workflow, gathers evidence with the selected tools, and can hand that evidence to the auditor and verifier subagents.

Sessions are not saved by default. With `--persist-session` (or `persistSession: true`), Claude Code saves the transcript under `~/.claude/projects/` and the runner prints the session ID for `--resume`. Transcripts contain tool inputs and results, so protect that directory as evidence storage.

## Deploy and maintain

Deploy the CLI build, its production dependencies, the GRC assets in `cli/.grclanker/`, `cli/prompts/`, and `cli/skills/`, and the installed adapter directory with their relative paths intact. Run `claude:install` on the target OS and architecture so the bundled executable matches. Supply `ANTHROPIC_API_KEY` and vendor credentials through your secret manager. Relative output paths resolve against the Node process working directory; use absolute `output_dir`, `workspace_dir`, or `zip_path` values. Rerun `claude:check` after upgrading the SDK.

## Troubleshooting

- **`Unknown grclanker tool`:** a name in `--tools` or `GRCLANKER_TOOLS` is not registered. Check `--list-tools`.
- **Authentication errors from the model:** set `ANTHROPIC_API_KEY`, or your Bedrock, Vertex AI, or Foundry settings, in the environment that runs the adapter.
- **`requires operator approval` or `did not approve`:** a writer was denied. Run at an interactive terminal, or implement `approveWrite` in your service.
- **Vendor tools report missing access:** the vendor credential is missing or lacks read scope. An access failure is missing evidence, not a passing control.
- **The Claude Code executable is missing:** rerun `claude:install` on the target platform; optional platform packages must not be omitted.
