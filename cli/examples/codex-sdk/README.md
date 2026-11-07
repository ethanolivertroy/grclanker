# grclanker with the Codex SDK

This is an independent Codex SDK worker with a local MCP server for selected GRC tools. It uses the common `cli/dist/runtime` library, and does not start another agent harness.

Use Git, npm, Node.js 22.22+, and an OpenAI API key. From the repository root:

```bash
npm --prefix cli ci
npm --prefix cli run build
npm --prefix cli/examples/codex-sdk ci
npm --prefix cli/examples/codex-sdk run check
export OPENAI_API_KEY='your-api-key'
npm --prefix cli/examples/codex-sdk start -- "Investigate CVE-2024-3400 using KEV and EPSS evidence."
```

The check executes a real GRC OSCAL workspace inspection through MCP using temporary local fixtures, without requiring compliance-trestle. It tests default/custom tool discovery, selection validation, argument errors, and denial of unselected read and write tools. It also runs the real Codex SDK against a fake executable to verify server configuration, credential forwarding, prompt delivery, and JSONL result handling. No network access or real credentials are used. A real run needs model and data-source network access.

The default tools are `kevs_search` and `kevs_get_epss`. To assess a GitHub organization:

```bash
export GITHUB_ORG='your-organization'
export GITHUB_TOKEN='your-github-token'
export GRCLANKER_TOOLS='github_check_access,github_assess_org_access,github_assess_repo_protection'
npm --prefix cli/examples/codex-sdk start -- "Check GitHub access, then assess access governance and repository protection. Report missing evidence and remediation priorities."
```

Use a token authorized to read the organization and repositories, including SSO authorization when required. Limited permissions produce incomplete assessments. Run `node cli/dist/runtime/cli.js list` to inspect other tool definitions. Set exact names in `GRCLANKER_TOOLS` and add the relevant credential variable names to `config.mjs`'s `env_vars` before using another integration.

The MCP server is a separate local process. It accepts selected read tools only; write tools are refused both at startup and by the common executor. Codex's read-only filesystem sandbox does not sandbox the MCP process. Public-data tools may maintain local caches. The example returns its report in the conversation and does not enable export tools, scheduling, or tenant changes.

Deploy the CLI build, assets and dependencies plus this installed directory with their relative paths intact. Install on the target OS and architecture so the SDK's Codex executable matches the worker. Supply keys through your secret manager and retain a private persistent home for Codex history under `~/.codex/sessions`. Each invocation creates a fresh thread; keep the `Thread` object or use `codex.resumeThread(id, options)` for ongoing conversations.

See the complete [Codex SDK guide](https://grclanker.com/docs/getting-started/codex-sdk/) for setup, code, deployment, and troubleshooting. SDK API reference: [OpenAI Codex SDK](https://github.com/openai/codex/tree/main/sdk/typescript).
