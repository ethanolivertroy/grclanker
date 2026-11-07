# Claude API tool runner adapter

This adapter runs grclanker's GRC engineering role and selected native tools with the tool runner in Anthropic's regular API SDK (`@anthropic-ai/sdk`, `client.beta.messages.toolRunner`). The SDK drives the request, tool call, and result loop over tools this adapter defines; there is no Claude Code executable and no built-in shell, file, or web tool. `agent.ts` exports the tool adapters and the runner parameters; `cli.ts` provides the one-shot runner. Shared domain tools and methodology come from `cli/core/` and `cli/extensions/grc-tools/`.

Use Git, npm, Node.js 22.19 or newer, and an Anthropic API key. The SDK resolves `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, or an `ant auth login` profile. From the repository root:

```bash
npm --prefix cli ci
npm --prefix cli run build
npm --prefix cli run claude-api:check
export ANTHROPIC_API_KEY='your-anthropic-api-key'
npm --prefix cli run claude-api:run -- \
  "Investigate CVE-2024-3400 using KEV and EPSS evidence. Cite sources and explain what still needs organization-specific verification."
```

The check builds the agent without calling a provider or tenant. The default agent exposes four public-data tools, workflow and cryptographic skill loaders, and auditor and verifier review tools. `--model` or `GRCLANKER_CLAUDE_API_MODEL` changes the model (default `claude-opus-5-5`); `--tools` replaces the domain tool selection.

For an organization assessment:

```bash
export GITHUB_ORG='your-organization'
export GITHUB_TOKEN='your-github-token'
npm --prefix cli run claude-api:run -- \
  --tools github_check_access,github_assess_org_access,github_assess_repo_protection \
  "Check access first, assess GitHub access and repository protection, then report evidence gaps and remediation priorities."
```

## Request settings

Each request uses adaptive thinking at `high` effort, `max_tokens` 16000, and at most 30 loop iterations. The system prompt (the shared GRC instructions plus a runtime note) carries a `cache_control` breakpoint, so the stable instructions and tool list are cached across turns. `thread: false` sends the full history each turn instead of keeping it in a server-side message thread. Requests opt into server-side fallback (`fallbacks: "default"`, beta `server-side-fallback-2026-07-01`), so a turn Claude declines is re-run on Anthropic's fallback model; `--no-fallback` or `serverSideFallback: false` turns that off. The auditor and verifier tools each make one separate model call with the persona instructions and the evidence passed to them.

## Approvals

Exports and other file-writing tools call `approveWrite` inside the tool's `run` function before executing, with the exact arguments. A declined or unapproved call returns an error result to the model and writes nothing. The shipped runner shows the call with credential-like arguments redacted, asks at an interactive terminal one call at a time, and denies writes when there is no terminal. An embedding service must bind `approveWrite` to its authenticated operator.

To embed it after building, create `cli/claude-api-example.mjs`:

```javascript
import Anthropic from "@anthropic-ai/sdk";
import { createGrclankerClaudeApiAgent } from "./dist/adapters/claude-api/agent.js";

const client = new Anthropic();
const agent = createGrclankerClaudeApiAgent(client, {
  toolNames: ["kevs_search", "kevs_get_epss"],
  approveWrite: async ({ toolName, input }) => false,
});
const final = await client.beta.messages.toolRunner({
  ...agent.params,
  stream: false,
  messages: [{ role: "user", content: "Investigate CVE-2024-3400 and cite evidence." }],
});
console.log(final.content.filter((block) => block.type === "text").map((block) => block.text).join("\n"));
```

Run `node cli/claude-api-example.mjs` from the repository root. After building, `node --test tests/claude-api.test.mjs` from `cli/` runs offline regression coverage, including a real tool runner loop against a local fake Messages API. A live run separately verifies model and tenant access.

The adapter has its own configuration and runs without Pi terminal setup. Its dependency installation and TypeScript build are shared in `cli/package.json`. See the complete [Claude API tool runner guide](https://grclanker.com/docs/getting-started/claude-api/).
