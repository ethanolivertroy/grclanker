---
title: Configuration
description: Understand the grclanker runtime state, settings, and local model configuration files.
---

grclanker keeps its runtime state under:

```text
~/.grclanker/agent
```

That directory is where settings, local model definitions, themes, bundled agents, and session state live.

## settings.json

Main runtime settings live in:

```text
~/.grclanker/agent/settings.json
```

Local-first setup adds these important fields:

```json
{
  "theme": "grclanker",
  "quietStartup": true,
  "collapseChangelog": true,
  "agentScope": "both",
  "skillDiscoveryMode": "bundled-only",
  "modelMode": "local",
  "providerKind": "ollama",
  "providerBaseUrl": "http://localhost:11434/v1",
  "defaultProvider": "ollama",
  "defaultModel": "gemma4"
}
```

Hosted setup writes the same `defaultProvider` and `defaultModel` pair, but switches `modelMode` to `hosted`.

`skillDiscoveryMode` controls whether grclanker stays limited to its bundled GRC skills or also allows Pi-style project skill discovery from `.agents/skills` and related paths. The recommended default is `bundled-only`.

Backend-related fields may also appear here:

```json
{
  "computeBackend": "docker",
  "dockerImage": "ubuntu:24.04",
  "dockerWorkspacePath": "/workspace",
  "parallelsSourceKind": "template",
  "parallelsTemplateName": "grclanker-linux-template",
  "parallelsClonePrefix": "grclanker-sandbox",
  "parallelsWorkspacePath": "/media/psf/grclanker-workspace-repo",
  "parallelsAutoStart": true
}
```

Those fields are optional and only matter for the backend you actually choose. For Parallels, grclanker now prefers a dedicated template source and falls back to a stopped base VM source, then creates a disposable sandbox for the actual session so it does not touch your existing VM directly.

## models.json

Custom local providers live in:

```text
~/.grclanker/agent/models.json
```

grclanker uses that file for the local-first path instead of expecting you to hand-author Pi model config from scratch.

Example local configuration:

```json
{
  "providers": {
    "ollama": {
      "baseUrl": "http://localhost:11434/v1",
      "api": "openai-completions",
      "apiKey": "ollama",
      "compat": {
        "supportsDeveloperRole": false,
        "supportsReasoningEffort": false
      },
      "models": [
        {
          "id": "gemma4",
          "name": "Gemma 4 (Local)",
          "reasoning": false,
          "input": ["text"]
        }
      ]
    }
  }
}
```

## Bundled assets

grclanker syncs these bundled assets into the runtime namespace:

- themes
- agent personas
- skills

That sync is how the runtime keeps its branded deck, workflow rails, and bundled behavior without leaking back to generic Pi paths.

## Changing modes

Use the setup command instead of editing everything manually:

```bash
grclanker setup
```

That is the supported way to move between local-first and hosted mode in the current experimental release.

If you need details on backend-specific fields or validation, use [Compute Backends](/docs/getting-started/compute-backends/).
