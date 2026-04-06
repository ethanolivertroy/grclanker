---
title: Quick Start
description: The shortest path from install to a useful local grclanker session.
---

If you want the fast path, do this in order. If you need Windows notes, pinned versions, package-manager fallback, or skills-only installs, use the [Installation](/docs/getting-started/installation) page.

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

## 5. Use the repo’s own specs as inputs

```bash
grclanker "read specs/aws-sec-inspector.spec.md and build the tool"
```

That is the real shape of the project now: the companion is the front door, and the specs are one of the surfaces it can work on.
