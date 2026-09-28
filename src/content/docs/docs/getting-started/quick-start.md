---
title: Quick Start
description: The shortest path from install to a useful local grclanker session.
---

If you want the fast path, do this in order. If you need Windows notes, pinned versions, a source-checkout fallback, or skills-only installs, use the [Installation](/docs/getting-started/installation) page.

## 1. Install the bundle

```bash
curl -fsSL https://grclanker.com/install | bash
```

## 2. Prepare the local-first path

grclanker now has an explicit setup flow for local-only use. The recommended first local backend is Ollama with Gemma 4.

```bash
ollama serve
ollama pull gemma4
grclanker setup
```

Choose the `local-first` option when prompted.

> A higher-memory Apple Silicon Mac is a strong local target. A 64 GB MacBook is an especially comfortable fit for the experimental local-first path, but it is not a hard requirement.

## 3. Start the companion

See the bundled tool surface first:

```bash
grclanker tools
```

```bash
grclanker
```

Or jump straight to a workflow:

```bash
grclanker investigate
grclanker audit
grclanker assess
grclanker validate
```

## 4. Ask one useful first question

```bash
grclanker "what is the CMVP certificate for BoringCrypto?"
grclanker investigate "CVE-2024-3094"
```

## 5. Review or extend a shipped integration

```bash
grclanker "read specs/aws-sec-inspector.spec.md, inspect the shipped AWS tools, and propose an extension"
```

grclanker ships 35 integrations, each with a repository spec. Use a spec to inspect coverage, plan a change, or seed an independent implementation.

The Pi terminal CLI is the default path. A source checkout can run the same domain tools through the [Cursor Agent SDK](/docs/getting-started/agent-sdk/) or [Flue](/docs/getting-started/flue-runtime/).
