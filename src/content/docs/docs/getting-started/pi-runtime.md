---
title: Pi Terminal Runtime
description: Install, configure, and run grclanker as a GRC engineering assistant in its Pi terminal runtime.
---

Use this path for an interactive GRC engineering assistant on your machine. grclanker embeds Pi and supplies its GRC tools, personas, and workflow prompts. You can use a local model or a hosted model. This guide includes the complete setup for this runtime.

In source, `cli/pi/` owns the terminal, setup, sessions, and compute backends; `cli/index.ts` launches it. The host embeds Pi 1.4. Native GRC implementations remain in `cli/extensions/grc-tools/`, with shared domain registration and tool handling in `cli/core/`. Source dependencies and the TypeScript build are shared with SDK adapters in `cli/package.json`. The Pi release bundle is the self-contained terminal installation described below.

## Install

On macOS or Linux, run:

```bash
curl -fsSL https://grclanker.com/install | bash
grclanker --version
grclanker tools
```

The release bundle includes its own Node.js runtime. If `grclanker` is not found, add the installer's launcher directory to your shell's `PATH`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Windows support is best-effort. In PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://grclanker.com/install.ps1 | iex"
grclanker --version
```

To run current source instead, install Git, npm, and Node.js 22.19 or newer, then:

```bash
git clone https://github.com/ethanolivertroy/grclanker.git
cd grclanker
npm --prefix cli ci
npm --prefix cli run build
cd cli
npm link
cd ..
grclanker tools
```

The CLI package is not published to npm. Use the bundle or source commands above. Source updates require `git pull`, `npm --prefix cli ci`, and `npm --prefix cli run build` from the checkout root.

## Configure a model

Choose one of the following model configurations. Integration credentials, such as a GitHub token, are configured separately after this step.

### Local model with Ollama

Install Ollama from [ollama.com/download](https://ollama.com/download). grclanker's installer does not install it.

If Ollama is not already serving, start it in a separate terminal and leave that terminal open:

```bash
OLLAMA_CONTEXT_LENGTH=128000 ollama serve
```

If the Ollama app or a service already runs the server, increase its context length setting instead of starting another server. The full GRC tool surface needs a large context window; Ollama's smaller defaults can fill before the conversation starts. A larger window also needs more memory.

In your working terminal:

```bash
ollama pull gemma4
grclanker setup
```

Choose `Local-first`, keep the endpoint `http://localhost:11434/v1`, and select `gemma4`. Keep the `host` compute backend and `Bundled grclanker skills only` for a first run. Setup checks the endpoint and model; an unavailable local model does not trigger a switch to a hosted provider.

### Hosted model

Run:

```bash
grclanker setup
```

Choose `Hosted`, select your provider and model, and keep the `host` compute backend for a first run. Supply the selected provider's credential to the shell that launches grclanker:

| Provider | Environment variable |
| --- | --- |
| OpenAI | `OPENAI_API_KEY` |
| Anthropic | `ANTHROPIC_API_KEY` |
| Google | `GEMINI_API_KEY` |

For example, for OpenAI:

```bash
export OPENAI_API_KEY='your-api-key'
grclanker
```

You can also use `/login` inside a session to store a provider credential locally. Hosted models receive the prompts and tool output used in the conversation.

## Verify the runtime and run a first task

From the directory where you want to work:

```bash
grclanker env doctor
grclanker env smoke-test
grclanker tools kevs_search
grclanker investigate "Is CVE-2024-3400 in the CISA KEV catalog?"
```

The first two commands check the compute backend. The third prints the tool's schema without a model call. The last opens an interactive session with the investigation workflow and your question loaded. It can use `kevs_search` to read CISA's public KEV catalog without tenant credentials. EPSS lookups use `kevs_get_epss` and FIRST's public API. These lookups still need outbound network access.

You can also start a general session with `grclanker` and ask:

```text
Use kevs_search to check CVE-2024-3400. Cite the catalog evidence and distinguish
confirmed exploitation from whether this organization is exposed.
```

## Connect a tenant: GitHub example

The model's API key does not authorize access to GitHub. Set a GitHub organization and a PAT before launching a new session:

```bash
export GITHUB_ORG='your-organization'
export GITHUB_TOKEN='your-github-token'
grclanker
```

Use a credential with permission to read the organization and repositories being assessed. Complete coverage includes owner-only organization reads; an organization owner PAT, or an appropriately permissioned GitHub App, may be required. Authorize a PAT for SSO when the organization requires it.

In the session, start with an access check:

```text
Run github_check_access for the configured organization. Report each unreadable
surface and the permission needed before assessing compliance.
```

Then ask:

```text
Run github_assess_org_access and github_assess_repo_protection. Give me the
evidence-backed findings, unknowns, and a prioritized remediation plan.
```

The inspector reads tenant configuration. Its assessments report missing or partial evidence instead of treating it as a pass. To create local evidence files, explicitly request `github_export_audit_bundle` and name an output directory. The default is `./export/github` relative to the process's working directory. Export does not modify the GitHub organization.

Other integrations follow their own credential and permission requirements. The optional [GitHub integration reference](/docs/integrations/github/) lists App authentication, enterprise endpoints, and individual control coverage.

## Use it for GRC engineering

Start a focused workflow from your shell, replacing the subject with your scope:

```bash
grclanker investigate "Prioritize the vulnerabilities affecting the payments service"
grclanker audit "Map our GitHub evidence to the requested SOC 2 controls"
grclanker assess "Review our GitHub organization and order the remediation work"
grclanker validate "Check the FIPS validation claim for a named cryptographic module"
```

These commands open interactive sessions. Inside a session, `/investigate`, `/audit`, `/assess`, and `/validate` accept the same kind of scope.

Use the assistant to collect evidence, inspect platform posture, research control language and framework crosswalks, explain risks, draft remediation plans, and prepare reviewable compliance artifacts. For organizational work, provide the system boundary, applicable frameworks, evidence period, owners, and desired output. Ask it to separate observed facts, assumptions, missing evidence, and proposed decisions.

The tools are the evidence foundation for a broader GRC engineering assistant. Current prompts and tools support assessments and artifact workflows; an organization-wide policy approval process, risk acceptance authority, and continuous operation require your own operating process and any additional integrations. A generated report does not itself establish compliance.

## State, outputs, and ongoing use

Settings, model definitions, provider credentials stored with `/login`, and session state live under `~/.grclanker/agent`. Use a persistent home directory on a workstation or a machine you operate. To relocate grclanker state, set `GRCLANKER_HOME` before setup and every subsequent run; grclanker uses `<base>/.grclanker/agent` unless the base already ends in `.grclanker`.

Exit with `/quit` or Ctrl+D. Use `/resume` in a new session to choose a previous conversation, or use the `grclanker --session <id>` command printed on exit. Keep the working directory and exported artifacts when continuing an assessment. Give export tools explicit output directories when the evidence must survive a machine or container restart.

The Pi path runs as an interactive terminal application. Running it on a remote machine requires a terminal, configured model access, tenant credentials, writable state, and network access to the selected providers and integrations. It does not install a background service or recurring assessment schedule.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| Command missing after installation | Add `~/.local/bin` to `PATH`, or rerun `npm link` inside `cli/` for a source checkout. |
| Source launcher rejects Node.js | Upgrade to Node.js 22.19 or newer, or use the release bundle. |
| Setup requires a terminal | Run `grclanker setup` in an interactive terminal before starting a session. |
| Ollama connection or context error | Start the server, pull the selected model, raise the server context window, and rerun setup. |
| Hosted provider rejects authentication | Set the selected provider's API key in the launching shell, or run `/login`. |
| GitHub access is limited | Check organization name, PAT permissions, and SSO authorization; review every probe in `github_check_access`. |
| Compute tools fail | Run `grclanker env doctor` and `grclanker env smoke-test`; the initial `host` backend requires local shell/file access. |
| `find` or `grep` binary unavailable offline | Install `fd` and `rg` on `PATH`; their normal first-run download requires network access. |
