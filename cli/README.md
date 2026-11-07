# GRC engineering hosts and shared code

This package contains grclanker's shared GRC implementation and its agent hosts. Start with the host you want to run; the release installer starts the Pi terminal application.

| Host | Source | Setup and first check from the repository root |
| --- | --- | --- |
| Pi terminal | [`pi/`](pi/README.md), launched by `index.ts` | Build the shared package, then run `node cli/bin/grclanker.js tools` and `node cli/bin/grclanker.js setup`. |
| OpenAI Agents SDK | [`adapters/openai-agents/`](adapters/openai-agents/README.md) | Build the shared package, then run `npm --prefix cli run openai-agents:check`. |
| Codex SDK | [`adapters/codex/`](adapters/codex/README.md) | Build the shared package, then run `npm --prefix cli run codex:install` and `npm --prefix cli run codex:check`. |
| Cursor / Grok Agent SDK | [`adapters/cursor-grok/`](adapters/cursor-grok/README.md) | Build the shared package, then run `npm --prefix cli run cursor:validate`. |

Build the shared package with Git, npm, and Node.js 22.19 or newer. The Codex adapter requires Node.js 22.22 or newer.

```bash
git clone https://github.com/ethanolivertroy/grclanker.git
cd grclanker
npm --prefix cli ci
npm --prefix cli run build
```

Each host has its own model loop, credentials, configuration, session behavior, and approval policy. Running OpenAI or Codex does not require running the Pi setup wizard or configuring Cursor. Source dependencies and the TypeScript build are currently shared in `cli/package.json`; these folders are not separately published or independently installable SDK packages. Codex has an additional local manifest and lockfile for its SDK and MCP dependencies, and still requires the shared CLI build.

## Code map

```text
cli/
  core/                     Shared domain registry, schemas, validation, results,
                            effects, redaction, instructions, and asset loading
  extensions/grc-tools/     Native cloud, SaaS, framework, and public-data tools
  extensions/grc-tools.ts   Pi extension combining domain and compute tools
  pi/                       Pi terminal, setup, and compute backend implementation
  adapters/
    openai-agents/          OpenAI Agents SDK adapter and one-shot runner
    codex/                  Codex SDK worker and local MCP server
    cursor-grok/            Cursor/Grok project, generated tool definitions, skills
  flue/                     Additional Flue host
  durable/                  Experimental Pi Durable host
  .grclanker/               Shared GRC role and auditor/verifier persona assets
  prompts/                  Shared investigate/audit/assess/validate workflows
  skills/                   Bundled GRC skills
  tests/                    Native tool, shared code, and host regression tests
```

Compiled TypeScript mirrors those directories under `dist/`: shared code is in `dist/core/`, and the TypeScript SDK adapters are in `dist/adapters/`. The Codex `.mjs` worker runs directly from `adapters/codex/` and imports the built core. Tool implementations stay in one place; adapters translate their schemas, results, and host approval behavior rather than duplicating connectors.

To inspect or call shared tools without an agent loop:

```bash
node cli/dist/core/cli.js list
printf '%s' '{}' | node cli/dist/core/cli.js call oscal_check_trestle
```

Calls require a JSON object on stdin. File-writing tools are denied unless the calling host explicitly authorizes them. Vendor tools separately need their tenant credentials and network access; model credentials do not grant that access.

## Where to change behavior

- Add or repair a vendor tool in `extensions/grc-tools/` and its regression tests in `tests/`.
- Change common schemas, validation, redaction, result handling, or methodology loading in `core/`.
- Change a host's model, sessions, approvals, or SDK translation in its own adapter folder or `pi/`.
- Change shared GRC role, workflows, and personas in `.grclanker/`, `prompts/`, and `skills/`.

After adding a native tool, run `npm --prefix cli run sync:cursor-tools` to update the Cursor/Grok project's generated tool definitions. OpenAI and Codex select tools from the shared registry. The old `agent-sdk:*` and `sync:agent-sdk-tools` script names remain compatibility aliases for Cursor/Grok; new instructions use `cursor:*` and `sync:cursor-tools`.

Run `npm --prefix cli run test:cli` for the CLI regression suite, `npm --prefix cli run test:cursor:validate` for the pinned Cursor SDK's discovery/execution smoke test, and `npm --prefix cli run codex:check` for the Codex SDK/MCP offline check after installing its dependencies. These checks do not establish live model or tenant access.
