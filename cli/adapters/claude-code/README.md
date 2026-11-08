# grclanker in Claude Code (local MCP server)

This adapter adds grclanker's GRC tools, role, and workflows to [Claude Code](https://code.claude.com/docs/en/overview) as a local stdio MCP server. Claude Code is the agent and uses your own Claude Code sign-in, including a Claude subscription. The server runs on your machine, makes no Anthropic requests, and needs no API key. It imports the shared `cli/dist/core/` build and the native tools in `cli/extensions/grc-tools/`.

You need Git, npm, Node.js 22.19 or newer, and Claude Code installed and signed in. Source installation and the core build are shared with the other hosts in `cli/package.json`; this directory adds only the MCP SDK from its own manifest and lockfile. In a POSIX shell, from the repository root:

```bash
npm --prefix cli ci
npm --prefix cli run build
npm --prefix cli run claude-code:install
npm --prefix cli run claude-code:check
claude mcp add --scope local grclanker -- node "$PWD/cli/adapters/claude-code/mcp-server.mjs"
claude mcp list
```

`claude-code:check` needs no credentials or network. It starts the server over stdio and checks tool selection, the write opt-in, discovery, server instructions, the loaders and workflow prompts, argument validation, the tool allowlist, and a real OSCAL workspace inspection. `claude mcp list` should show `grclanker: ... Connected`.

Register `grclanker` once: `mcp add` rejects a name that already exists. These examples use `--scope local`, private to this checkout, and must run from the same repository root. To share the registration in `.mcp.json`, use `--scope project`; for every project, use `--scope user`. Keep the same scope on remove and add. To move an existing registration, remove it from its old scope before adding it in the new scope.

## Choose tools

Arguments after the script select tools; with none, the server exposes four public-data lookups (`cmvp_search_modules`, `cmvp_get_module`, `kevs_search`, `kevs_get_epss`). Separate names with spaces or commas. `family_*` adds every read tool with that prefix. `GRCLANKER_TOOLS` is used when no names are given.

Exit any running Claude Code session, then replace the registration to select GitHub read tools alongside KEV and EPSS. Quote patterns so the shell passes them to the server:

```bash
export GITHUB_ORG='your-organization'
export GITHUB_TOKEN='your-github-token'
claude mcp remove --scope local grclanker
claude mcp add --scope local grclanker -- node "$PWD/cli/adapters/claude-code/mcp-server.mjs" kevs_search,kevs_get_epss 'github_*'
claude mcp list
claude
```

The server inherits the environment Claude Code starts with, so export vendor credentials such as `GITHUB_ORG` and `GITHUB_TOKEN` before running `claude`. `claude mcp add --env` also works but stores the value in Claude Code's configuration file. Model credentials do not grant vendor access.

Removing a registration removes any `--env` values stored in it. The examples export credentials in the launching shell, so replacing the registration does not require saving secrets in the configuration. Each replacement below also works directly after the initial registration.

## Write tools

Exports and other file-writing tools are hidden unless you add `--allow-writes`. A writer named exactly without it stops the server at startup; a `family_*` pattern skips writers. With `--allow-writes`, writers are marked as not read-only and Claude Code asks before each call unless you have allowed the tool. Relative output paths resolve against the server's working directory; use absolute paths.

Exit Claude Code, then replace the registration to enable the GitHub access check and exporter:

```bash
export GITHUB_ORG='your-organization'
export GITHUB_TOKEN='your-github-token'
claude mcp remove --scope local grclanker
claude mcp add --scope local grclanker -- node "$PWD/cli/adapters/claude-code/mcp-server.mjs" --allow-writes github_check_access github_export_audit_bundle
claude mcp list
claude
```

Ask Claude to check access, then export the audit bundle to an absolute output directory. Review the proposed call before approving it. To disable writes, remove the registration and re-add the read-tool selection without `--allow-writes`.

## Role and workflows

Claude Code keeps its own system prompt. The server's MCP instructions tell Claude to call `grclanker_load_instructions` for the GRC role before GRC work. `grclanker_load_workflow`, `grclanker_load_skill`, and `grclanker_load_reviewer` load the investigate, audit, assess, and validate workflows, the crypto-validation methodology, and the auditor and verifier review instructions.

The four workflows are also MCP prompts, so Claude Code lists them as slash commands that include the GRC role:

```text
/mcp__grclanker__audit Example SaaS against SOC 2
```

Claude Code's own tools stay available in the session. If `mcp add` reports that `grclanker` already exists, remove it in the scope where you registered it before adding the replacement. See the complete [Claude Code guide](https://grclanker.com/docs/getting-started/claude-code/).
