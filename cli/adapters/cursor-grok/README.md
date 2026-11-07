# Cursor / Grok Agent SDK adapter

This directory contains grclanker's project for Cursor's `@grok/agent-sdk`. Cursor and Grok refer to the same SDK path here; a separate xAI API integration is not included. `bot/agent.ts` is the project entry point, `bot/tools/` contains generated domain tool definitions, and `lib/` translates shared GRC code to SDK tools, skills, and subagents.

Use Git, npm, and Node.js 22.19 or newer. From the repository root:

```bash
npm --prefix cli ci
npm --prefix cli run build
npm --prefix cli run cursor:validate
npm --prefix cli run cursor:info
npm --prefix cli run cursor:call -- oscal_check_trestle --input '{"workspace_dir":"."}' --json
```

Keep development dependencies installed: the pinned SDK and its CLI resolve from the parent `cli/package.json`. The local tool check needs no model credential, tenant credential, network request, or installed compliance-trestle. A report that trestle is unavailable is a successful adapter check.

For model turns, sign in from `cli/`, or inject `CURSOR_API_KEY` into the host environment:

```bash
cd cli
npx --no-install agent-sdk login
cd ..
npm --prefix cli run cursor:run -- \
  --message "Use kevs_search to check CVE-2024-3400. Cite evidence and explain uncertainty."
```

Use `GRCLANKER_AGENT_SDK_MODEL` to override the Cursor model ID. This legacy environment variable belongs to this adapter. The `cursor:*` npm scripts explicitly select this project; older `agent-sdk:*` names remain compatibility aliases. The vendor's executable is still named `agent-sdk`.

For organization evidence, put that vendor's credentials in the tool-host environment. For example:

```bash
export GITHUB_ORG='your-organization'
export GITHUB_TOKEN='your-github-token'
npm --prefix cli run cursor:call -- github_check_access --input '{}' --json
npm --prefix cli run cursor:dev
```

Use a PAT with organization/repository read access and SSO authorization when required. Open the playground URL printed by `cursor:dev`. Model-initiated exports and other writers wait for an operator's approval there. Direct `cursor:call` commands are explicit tool execution and bypass the model approval gate.

Native tools come from `cli/extensions/grc-tools/` through `cli/core/`; this adapter adds SDK effect and approval declarations. Cursor supplies its own built-in shell and file capabilities. Pi compute settings do not configure those capabilities. Artifact paths resolve against the SDK host's working directory, `cli/` when using the npm scripts. Use explicit absolute output paths.

After a native tool is added, run `npm --prefix cli run sync:cursor-tools`. Validate adapter changes with `npm --prefix cli run test:cursor:validate`; that check exercises the pinned SDK's real discovery and local tool execution without a model request.

This project uses a local harness and shared source/assets from the parent CLI package. Copying this folder alone does not deploy its tools, and managed Cursor hosting is not configured or validated. SDK dependencies and the TypeScript build are shared with the other source hosts; no Pi terminal setup or another adapter's authentication is needed. See the complete [Cursor / Grok guide](https://grclanker.com/docs/getting-started/agent-sdk/) for self-hosting, approvals, and troubleshooting.
