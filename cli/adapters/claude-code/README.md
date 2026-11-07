# grclanker in Claude Code (local MCP server)

This adapter adds grclanker's GRC tools, role, and workflows to [Claude Code](https://code.claude.com/docs/en/overview) as a local stdio MCP server. Claude Code is the agent and uses your own Claude Code sign-in, including a Claude subscription. The server runs on your machine, makes no Anthropic requests, and needs no API key. It imports the shared `cli/dist/core/` build and the native tools in `cli/extensions/grc-tools/`.

Source installation and the core build are shared with the other hosts in `cli/package.json`; this directory adds only the MCP SDK from its own manifest and lockfile. From the repository root:

```bash
npm --prefix cli ci
npm --prefix cli run build
npm --prefix cli run claude-code:install
npm --prefix cli run claude-code:check
claude mcp add grclanker -- node "$PWD/cli/adapters/claude-code/mcp-server.mjs"
```

`claude-code:check` needs no credentials or network. It starts the server over stdio and checks tool selection, the write opt-in, discovery, server instructions, the loaders and workflow prompts, argument validation, the tool allowlist, and a real OSCAL workspace inspection. Then `claude mcp list` should show `grclanker: ... Connected`.

## Choose tools

Arguments after the script select tools; with none, the server exposes four public-data lookups (`cmvp_search_modules`, `cmvp_get_module`, `kevs_search`, `kevs_get_epss`). Separate names with spaces or commas. `family_*` adds every read tool with that prefix. `GRCLANKER_TOOLS` is used when no names are given.

```bash
claude mcp add grclanker -- node "$PWD/cli/adapters/claude-code/mcp-server.mjs" kevs_search,kevs_get_epss github_*
```

The server inherits the environment Claude Code starts with, so export vendor credentials such as `GITHUB_ORG` and `GITHUB_TOKEN` before running `claude`. `claude mcp add --env` also works but stores the value in Claude Code's configuration file. Model credentials do not grant vendor access.

## Write tools

Exports and other file-writing tools are hidden unless you add `--allow-writes`. A writer named exactly without it stops the server at startup; a `family_*` pattern skips writers. With `--allow-writes`, writers are marked as not read-only and Claude Code asks before each call unless you have allowed the tool. Relative output paths resolve against the server's working directory; use absolute paths.

```bash
claude mcp add grclanker -- node "$PWD/cli/adapters/claude-code/mcp-server.mjs" --allow-writes github_*
```

## Role and workflows

Claude Code keeps its own system prompt. The server's MCP instructions tell Claude to call `grclanker_load_instructions` for the GRC role before GRC work. `grclanker_load_workflow`, `grclanker_load_skill`, and `grclanker_load_reviewer` load the investigate, audit, assess, and validate workflows, the crypto-validation methodology, and the auditor and verifier review instructions.

The four workflows are also MCP prompts, so Claude Code lists them as slash commands that include the GRC role:

```text
/mcp__grclanker__audit Example SaaS against SOC 2
```

Claude Code's own tools stay available in the session. Use `--scope project` or `--scope user` with `claude mcp add` to choose where it is registered, and `claude mcp remove grclanker` to remove it. See the complete [Claude Code guide](https://grclanker.com/docs/getting-started/claude-code/).
