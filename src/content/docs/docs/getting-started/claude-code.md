---
title: Claude Code (MCP)
description: Add grclanker's GRC tools, role, and workflows to Claude Code as a local MCP server, using your own Claude Code sign-in.
---

This path adds grclanker to [Claude Code](https://code.claude.com/docs/en/overview) as a local MCP server. Claude Code is the agent and uses your own Claude Code sign-in, including a Claude subscription. grclanker only supplies tools, its GRC role, and workflow prompts. The server runs on your machine as a child process of Claude Code, makes no Anthropic requests, and needs no API key.

Use it when you already work in Claude Code. To embed grclanker in your own application with Anthropic's agent loop, use the [Claude Agent SDK](/docs/getting-started/claude-agent-sdk/) path instead, which authenticates with an API key.

## Prerequisites and installation

You need Git, npm, Node.js 22.19 or newer, and Claude Code installed and signed in. From a fresh checkout:

```bash
git clone https://github.com/ethanolivertroy/grclanker.git
cd grclanker
npm --prefix cli ci
npm --prefix cli run build
npm --prefix cli run claude-code:install
npm --prefix cli run claude-code:check
```

`claude-code:install` installs the MCP SDK from the adapter's own lockfile. `claude-code:check` needs no credentials or network. It starts the server over stdio and checks tool selection, the write opt-in, discovery, server instructions, the loaders and workflow prompts, argument validation, the tool allowlist, and a real OSCAL workspace inspection.

## Add it to Claude Code

From the checkout root:

```bash
claude mcp add grclanker -- node "$PWD/cli/adapters/claude-code/mcp-server.mjs"
claude mcp list
```

`claude mcp list` should show `grclanker: ... Connected`. Claude Code starts the server for each session. Add `--scope project` to share the registration in the project's `.mcp.json`, or `--scope user` for every project. `claude mcp remove grclanker` removes it.

Start `claude` and ask:

```text
Investigate CVE-2024-3400 using KEV and EPSS evidence. Cite sources and explain what still needs organization-specific verification.
```

## Choose tools

Arguments after the script select tools. With none, the server exposes four public-data lookups: `cmvp_search_modules`, `cmvp_get_module`, `kevs_search`, and `kevs_get_epss`.

| Argument | Effect |
| --- | --- |
| `kevs_search,kevs_get_epss` | Exact tool names, separated by commas or spaces |
| `github_*` | Every read tool whose name starts with `github_` |
| `--allow-writes` | Also expose named writers, and writers matched by a pattern |

`GRCLANKER_TOOLS` sets the list when no names are given. Run `node cli/dist/core/cli.js list` to see every tool.

## Connect a tenant: GitHub example

```bash
export GITHUB_ORG='your-organization'
export GITHUB_TOKEN='your-github-token'
claude mcp add grclanker -- node "$PWD/cli/adapters/claude-code/mcp-server.mjs" github_check_access github_assess_org_access github_assess_repo_protection
claude
```

The server inherits the environment Claude Code starts with, so export vendor credentials before starting `claude`. `claude mcp add --env NAME=value` also works but saves the value in Claude Code's configuration file. Use a token authorized to read the organization and repositories, including SSO authorization when required. Limited permissions produce incomplete assessments.

## Role, workflows, and reviewers

Claude Code keeps its own system prompt. The server's MCP instructions tell Claude to load the grclanker role with `grclanker_load_instructions` before GRC work and treat failed tool results as missing evidence. Three more loaders are always present:

- `grclanker_load_workflow` loads the investigate, audit, assess, or validate workflow.
- `grclanker_load_skill` loads the crypto-validation methodology.
- `grclanker_load_reviewer` loads the auditor or verifier review instructions, to apply directly or hand to a Claude Code subagent along with the collected evidence.

The workflows are also MCP prompts, which Claude Code lists as slash commands. Each one includes the GRC role:

```text
/mcp__grclanker__audit Example SaaS against SOC 2
```

## Write tools and human review

Exports and other file-writing tools are hidden unless the server is started with `--allow-writes`. A writer named without it stops the server at startup, and a `family_*` pattern skips writers. With `--allow-writes`, writers are marked as not read-only, and Claude Code asks before each call unless you have allowed the tool in your Claude Code permissions. Relative output paths resolve against the server's working directory; use absolute `output_dir`, `workspace_dir`, or `zip_path` values.

Claude Code's own tools, such as shell and file access, remain available in the session under your Claude Code permission settings. Review reports, control mappings, and generated artifacts before relying on them. Proposed policies and risk acceptance decisions are drafts for the organization's owners.

## Troubleshooting

- **`claude mcp list` shows the server as failed:** run the same `node .../mcp-server.mjs ...` command directly. Startup errors such as an unknown tool name or a writer without `--allow-writes` print to stderr.
- **`Cannot find module` errors:** run `npm --prefix cli run build` and `npm --prefix cli run claude-code:install`.
- **Vendor tools report missing access:** the credential was not in the environment Claude Code started with, or it lacks read scope. An access failure is missing evidence, not a passing control.
