---
title: Configuration
description: Understand the grclanker runtime state, settings, and local model configuration files.
---

grclanker keeps its runtime state under:

```text
~/.grclanker/agent
```

That directory is where settings, local model definitions, stored provider credentials (`auth.json`), themes, bundled agents, and session state live. Set `GRCLANKER_HOME` to move it (see [Environment variables](#environment-variables)).

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

Hosted setup writes the same `defaultProvider` and `defaultModel` pair, sets `providerKind` to the hosted provider, switches `modelMode` to `hosted`, and removes `providerBaseUrl`.

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
          "name": "gemma4 (Local)",
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

## Environment variables

These are the `GRCLANKER_*` variables grclanker reads:

| Variable | Effect |
| --- | --- |
| `GRCLANKER_HOME` | Base directory for runtime state instead of your home directory. grclanker uses `$GRCLANKER_HOME/.grclanker`, or the path itself when it already ends in `.grclanker`, and refuses any path inside a `.pi` directory. |
| `GRCLANKER_FLUE_MODEL` | `provider/model` for `grclanker flue run`. See [Flue Runtime](/docs/getting-started/flue-runtime/#configuration). |
| `GRCLANKER_FLUE_SANDBOX` | `local` (default) or `none` for `grclanker flue run`. |
| `GRCLANKER_AGENT_SDK_MODEL` | Cursor model id for the [Cursor Agent SDK](/docs/getting-started/agent-sdk/) project. |
| `GRCLANKER_TRESTLE_BIN` | Path to the `trestle` executable for the `oscal_*` tools (`TRESTLE_BIN` also works). |
| `GRCLANKER_GWS_BIN` | Path to the `gws` executable for the `gws_ops_*` tools. |
| `GRCLANKER_LIVE_BACKENDS` | Comma-separated backend kinds that `npm --prefix cli run test:compute-backends:live` should exercise. |
| `GRCLANKER_VERSION` | Build-only. Version stamped on release bundles built with `npm --prefix cli run build:bundle` (default: the `cli/package.json` version). |
| `GRCLANKER_NODE_VERSION` | Build-only. Node.js version that `npm --prefix cli run build:bundle` packages (default `22.20.0`). |

grclanker sets `GRCLANKER_CODING_AGENT_DIR` and `GRCLANKER_COMPUTE_BACKEND` itself when it launches the embedded Pi runtime, and `GRCLANKER_COMPUTE_BACKEND_OVERRIDE` when you pass `--compute <kind>`. Leave them unset; use `grclanker setup` or a per-run `--compute <kind>` instead.

Provider and integration credentials use each vendor's own variable names (for example `ANTHROPIC_API_KEY`, `RUNPOD_API_KEY`, `MODAL_TOKEN_ID`); the integration and compute backend guides list them.
