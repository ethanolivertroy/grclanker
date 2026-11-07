# grclanker with the Claude Agent SDK

This adapter runs grclanker's GRC engineering role and selected native tools in the Claude Agent SDK (`@anthropic-ai/claude-agent-sdk`). The SDK drives Anthropic's agent loop through its bundled Claude Code executable; grclanker supplies the system prompt, an in-process MCP server for the selected tools, auditor and verifier subagents, and a permission callback. Shared domain tools and methodology come from `cli/dist/core/` and `cli/extensions/grc-tools/`.

Source installation and the core build are shared with the other hosts in `cli/package.json`. This adapter's SDK and MCP dependencies have a local manifest and lockfile, because the SDK installs a platform-specific Claude Code executable (about 280 MB) that the other hosts do not need. That does not make it a standalone installation; keep the shared build, dependencies, and GRC assets when deploying it.

Use Git, npm, Node.js 22.19 or newer, and an Anthropic API key. From the repository root:

```bash
npm --prefix cli ci
npm --prefix cli run build
npm --prefix cli run claude:install
npm --prefix cli run claude:check
export ANTHROPIC_API_KEY='your-anthropic-api-key'
npm --prefix cli run claude:run -- \
  "Investigate CVE-2024-3400 using KEV and EPSS evidence. Cite sources and explain what still needs organization-specific verification."
```

`claude:check` needs no credentials or network. It checks tool selection, the isolation options, and the permission callback; drives the in-process MCP server for discovery, argument validation, the tool allowlist, and the write gate; then runs the real SDK and Claude Code executable against a local fake Messages API that calls a read tool and a writer the operator denies. `node main.mjs --check` prints the tools a configuration exposes without a model request.

The default tools are four public-data lookups: `cmvp_search_modules`, `cmvp_get_module`, `kevs_search`, and `kevs_get_epss`. `--tools` or `GRCLANKER_TOOLS` replaces the selection; `--model` or `GRCLANKER_CLAUDE_MODEL` changes the model (default `claude-opus-5-5`). `--list-tools` lists every registered tool and its effect.

For an organization assessment:

```bash
export GITHUB_ORG='your-organization'
export GITHUB_TOKEN='your-github-token'
npm --prefix cli run claude:run -- \
  --tools github_check_access,github_assess_org_access,github_assess_repo_protection \
  "Check access first, assess GitHub access and repository protection, then report evidence gaps and remediation priorities."
```

The vendor token needs read access to the organization and repositories. Model credentials do not grant vendor access. The tools run inside this Node process and read credentials from its environment.

## Code

| File | Role |
| --- | --- |
| `agent.mjs` | `createGrclankerClaudeOptions()`: `query()` options, runtime note, subagents, and permission callback |
| `server.mjs` | In-process MCP server with the shared JSON schemas, workflow and skill loaders, and the write gate |
| `tools.mjs` | Default tool selection and validation |
| `main.mjs` | One-shot runner with terminal approval |
| `check.mjs` | Offline check |

To embed it, create `cli/adapters/claude-agent-sdk/example.mjs`:

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

## Isolation and approvals

The options run the SDK in isolation mode: `settingSources: []` loads no user, project, or local Claude settings or CLAUDE.md files, `strictMcpConfig` ignores other MCP configuration, and `skills: []` enables no skills. `tools: ["Agent"]` removes every built-in Claude Code tool (shell, files, web, editing) except the launcher for the auditor and verifier subagents, which themselves have no tools.

Every permission decision goes through the adapter's `canUseTool` callback; there are no `allowedTools` rules. It allows the selected read tools, the loaders, and the subagent launcher, and denies anything else, including a tool from a server that is not the host's in-process server. Exports and other writers call `approveWrite` for each call. An approval is recorded for the exact tool and arguments, and the MCP handler runs the writer only after consuming it, so a writer cannot run without an approval for those arguments. The shipped runner asks at an interactive terminal and denies writes otherwise. Relative output paths resolve against the Node process working directory; use absolute paths for deployment outputs.

Sessions are not saved by default. `--persist-session` saves the transcript under `~/.claude/projects/` and prints the session ID; `--resume id` continues it. Transcripts contain tool inputs and results, so treat that directory as evidence storage.

Deploy the CLI build, assets, and dependencies plus this installed directory with their relative paths intact. Install on the target OS and architecture so the SDK's executable matches. See the complete [Claude Agent SDK guide](https://grclanker.com/docs/getting-started/claude-agent-sdk/) and the [official SDK overview](https://code.claude.com/docs/en/agent-sdk/overview).
