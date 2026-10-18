---
title: Quick Start
description: The shortest path from install to a useful local grclanker session.
---

If you want the fast path, do this in order. For Windows notes, pinned versions, the source install, or skills-only installs, use the [Installation](/docs/getting-started/installation) page.

## 1. Install

```bash
curl -fsSL https://grclanker.com/install | bash
```

This installs the newest release bundle, currently `v0.1.2`, with all 241 domain tools, `grclanker tools`, and `grclanker flue run`. To run unreleased changes from `main` instead, [install from source](/docs/getting-started/installation#install-from-source) and `npm link` it so the `grclanker` commands below run that build.

## 2. Set up a model

The recommended first backend is local: Ollama with Gemma 4 on your own machine. A higher-memory Apple Silicon Mac is a strong local target. A 64 GB MacBook is an especially comfortable fit for the experimental local-first path, but it is not a hard requirement.

To use a hosted model instead, skip Ollama: run `grclanker setup`, choose `Hosted`, and pick OpenAI, Anthropic, or Google. Your prompts and tool output then go to that provider. grclanker reads the provider's key from `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `GEMINI_API_KEY`, or from a key you store with `/login` inside a session. The [hosted path](/docs/getting-started/setup#hosted-path) on the Setup page lists each provider's default model. Then go to [step 3](#3-start-the-companion).

For the local path, install Ollama from [ollama.com/download](https://ollama.com/download). The grclanker installer does not install it.

If the Ollama app or background service is already running, skip this command. Otherwise start the server in its own terminal and leave it running:

```bash
ollama serve
```

Then, in a second terminal:

```bash
ollama pull gemma4
grclanker setup
```

Choose `Local-first` when prompted. Setup defaults to the Ollama endpoint at `http://localhost:11434/v1`.

## 3. Start the companion

```bash
grclanker
```

Or open a session with a workflow's instructions preloaded:

```bash
grclanker investigate
grclanker audit
grclanker assess
grclanker validate
```

A workflow command also takes its subject, and a quoted prompt goes straight to the agent:

```bash
grclanker investigate "CVE-2024-3094"
grclanker "Is CVE-2024-3400 in the CISA KEV catalog?"
```

The older `v0.0.1` bundle does not take either form. There, name the vendor, product, CVE, or framework in the session once it opens.

List the full tool surface first:

```bash
grclanker tools
```

## 4. Ask one useful first question

In the session, try:

```text
Is CVE-2024-3400 in the CISA KEV catalog, and what is its EPSS score?
```

```text
Which vulnerabilities were added to the CISA KEV catalog in the last 30 days?
```

Both are answered by the KEV and EPSS tools (`kevs_search`, `kevs_get_epss`, `kevs_recent`), which ship in every release bundle.

## 5. Review or extend a shipped integration

This step needs a source checkout, because the release bundle does not include the `specs/` directory. Start `grclanker` from the repository root and ask:

```text
Read specs/aws-sec-inspector.spec.md, inspect the shipped AWS tools, and propose an extension.
```

grclanker ships 35 integrations, and most have a spec under `specs/`. Use a spec to inspect coverage, plan a change, or seed an independent implementation.

The Pi terminal CLI is the default path. A source checkout can also run the same domain tools through the [Cursor Agent SDK](/docs/getting-started/agent-sdk/) or [Flue](/docs/getting-started/flue-runtime/).
