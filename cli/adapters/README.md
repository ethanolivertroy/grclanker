# Agent SDK adapters

Choose the adapter for the agent host you want. Each directory documents its own setup, credentials, code, first run, and operating limits.

| Adapter | Model and tool loop | Entry point | Local check after the shared build |
| --- | --- | --- | --- |
| [OpenAI Agents SDK](openai-agents/README.md) | `@openai/agents` in your Node process | `openai-agents/cli.ts`, or exported factory in `agent.ts` | `npm --prefix cli run openai-agents:check` |
| [Codex SDK](codex/README.md) | `@openai/codex-sdk` subprocess, with GRC tools over local MCP | `codex/main.mjs` and `mcp-server.mjs` | `npm --prefix cli run codex:install`, then `npm --prefix cli run codex:check` |
| [Cursor / Grok Agent SDK](cursor-grok/README.md) | `@grok/agent-sdk` local harness | `cursor-grok/bot/agent.ts` | `npm --prefix cli run cursor:validate` |

Commands run from the repository root. First install and build the common source package:

```bash
npm --prefix cli ci
npm --prefix cli run build
```

The adapters use the native tool implementations in `cli/extensions/grc-tools/` through `cli/core/`. Shared code supplies domain registration, JSON schemas, argument preparation and validation, result envelopes, redaction, and GRC methodology assets. Each adapter supplies host-specific configuration, authentication, tool selection, sessions, and approval integration. No SDK adapter imports another SDK adapter.

Source dependency installation and the TypeScript build still belong to `cli/package.json`. These directories are code boundaries, not independently published packages. The Codex directory has an additional manifest for its own SDK and MCP dependencies; copying that directory alone does not include the GRC core or native tool dependencies.

The default Pi terminal host remains in [`cli/pi/`](../pi/README.md), with additional Flue and experimental Durable hosts in `cli/flue/` and `cli/durable/`. Pi model setup and compute-backend settings configure Pi, while each SDK adapter uses its own host settings. Claude Agent SDK support is planned; there is no runnable Claude adapter yet.

Cursor and Grok name one SDK path here: Cursor currently distributes the SDK as `@grok/agent-sdk`. This is separate from an xAI API SDK integration. The legacy `agent-sdk:*` npm scripts are compatibility aliases for `cursor:*`; they do not select among all SDKs.
