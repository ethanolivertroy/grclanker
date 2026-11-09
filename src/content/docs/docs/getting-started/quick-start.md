---
title: Quick Start
description: Install grclanker, choose a hosted or local model, and verify your first Pi terminal response.
---

This guide runs the Pi terminal host. Use [Choose a Deployment](/docs/getting-started/deployment/) for Claude Code and the SDK hosts, or [Installation](/docs/getting-started/installation/) for source builds, pinned versions, and skills-only installs.

## 1. Install

On macOS or Linux:

```bash
curl -fsSL https://grclanker.com/install | bash
```

On Windows PowerShell (best effort):

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://grclanker.com/install.ps1 | iex"
```

The installer fetches `v0.1.5`, with 241 domain tools and its own Node.js runtime. Open a new terminal if the installer added `grclanker` to your `PATH`, then check:

```bash
grclanker --version
```

## 2. Choose a model

Choose either path below. Both use the same GRC tools and workflows.

### Hosted: Anthropic, OpenAI, or Google

Run the wizard:

```bash
grclanker setup
```

For the Anthropic path, choose **Hosted → Anthropic → claude-sonnet-4-6**. Keep the default host compute backend and bundled skills to start. OpenAI and Google are also available; [Setup](/docs/getting-started/setup/#hosted-path) lists their defaults.

Start a session:

```bash
grclanker
```

Run `/login` inside the session and enter your provider's API key. It is saved in your private runtime directory. If you already provide `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `GEMINI_API_KEY` in the environment, you can skip `/login`.

Hosted models send your prompts and tool results to the selected provider. Model access and API billing belong to that provider; integration credentials are separate.

Continue to [verify a response](#3-verify-a-model-response).

### Local: Ollama + Gemma 4

Install Ollama from [ollama.com/download](https://ollama.com/download). The grclanker installer does not install it. A local model with a large context window needs enough memory; the [Setup guide](/docs/getting-started/setup/#context-length) explains the requirements.

If Ollama is not already serving, start it in its own terminal and leave it running:

```bash
OLLAMA_CONTEXT_LENGTH=128000 ollama serve
```

If the app or background service is already running, raise its context length setting instead. grclanker's tool definitions use about 100k tokens, so a smaller window can prevent tool calls.

In a second terminal:

```bash
ollama pull gemma4
grclanker setup
```

Choose **Local-first**, confirm `http://localhost:11434/v1`, and select your installed model. Keep the default host compute backend and bundled skills to start. Then run:

```bash
grclanker
```

## 3. Verify a model response

Check the provider and model shown in the session footer. For the Anthropic path above, it should show `claude-sonnet-4-6`.

Send a small first request:

```text
Reply exactly READY and do not use tools.
```

A `READY` response verifies that the model can answer with your current credentials or local endpoint. An open terminal UI or a successful `grclanker tools` command alone does not verify model access. If the request fails, check your provider key and model access, or the local endpoint and context window.

## 4. Ask a useful first question

Try a public-data question that needs no vendor credentials:

```text
Is CVE-2024-3400 in the CISA KEV catalog, and what is its EPSS score? Report the source and retrieval date.
```

The agent can use `kevs_search` and `kevs_get_epss` to gather the evidence. `kevs_recent` lists recent catalog additions, and `kevs_check_ransomware` checks the catalog's ransomware flag. All four ship in the release bundle. See [KEV / EPSS](/docs/integrations/kevs/) for coverage and limitations.

For a structured investigation, start a new session with the subject included:

```bash
grclanker investigate "CVE-2024-3094"
```

The other workflows are `audit`, `assess`, and `validate`. Their guides explain the expected evidence and output. Use `grclanker tools` to inspect the full tool catalog before connecting a vendor integration.

Leave a session with `/quit` or Ctrl+D. Reopen it with the `grclanker --session <id>` command printed on exit, or use `/resume` inside a session.

Next, connect an [integration](/docs/integrations/aws/), choose a [compute backend](/docs/getting-started/compute-backends/), or use a repository [spec as a build input](/docs/specs/using-specs-as-inputs/).
