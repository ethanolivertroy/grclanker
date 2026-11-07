---
title: Configuration
description: Pi terminal CLI settings, and the variables the Cursor Agent SDK project reads.
---

This page is the Pi terminal CLI: `grclanker`, `~/.grclanker/agent/settings.json`, and `grclanker setup`.

The [Cursor Agent SDK](/docs/getting-started/agent-sdk/) project does not read `settings.json`, `models.json`, or the model `grclanker setup` saves. A fork that only runs that project skips `grclanker setup` and Ollama. Its model is `GRCLANKER_AGENT_SDK_MODEL`, or the Agent SDK default when that variable is unset, and a model turn needs a Cursor credential on the `agent-sdk` process. Of the variables below, that project reads `GRCLANKER_AGENT_SDK_MODEL`, `GRCLANKER_HOME`, `GRCLANKER_TRESTLE_BIN`, and `GRCLANKER_GWS_BIN`. The Flue, durable, and compute-backend rows belong to those other runtimes.

The Pi terminal CLI keeps its runtime state under:

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

Hosted setup:

- writes the same `defaultProvider` and `defaultModel` pair
- sets `providerKind` to the hosted provider
- switches `modelMode` to `hosted`
- removes `providerBaseUrl`

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

Those fields are optional and only matter for the backend you actually choose.

For Parallels, grclanker now prefers a dedicated template source and falls back to a stopped base VM source. It then creates a disposable sandbox for the actual session so it does not touch your existing VM directly.

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

`grclanker setup` moves the Pi terminal CLI between local-first and hosted mode. It does not configure the Cursor Agent SDK project. When you are running `grclanker`, use the setup command instead of editing `settings.json` by hand:

```bash
grclanker setup
```

That is the supported way to move the Pi terminal CLI between local-first and hosted mode in the current experimental release.

If you need details on backend-specific fields or validation, use [Compute Backends](/docs/getting-started/compute-backends/).

## Environment variables

These are the `GRCLANKER_*` variables grclanker reads:

| Variable | Effect |
| --- | --- |
| `GRCLANKER_HOME` | Base directory for runtime state instead of your home directory. grclanker uses `$GRCLANKER_HOME/.grclanker`, or the path itself when it already ends in `.grclanker`, and refuses any path inside a `.pi` directory. |
| `GRCLANKER_FLUE_MODEL` | `provider/model` for `grclanker flue run`. See [Flue Runtime](/docs/getting-started/flue-runtime/#configuration). |
| `GRCLANKER_FLUE_SANDBOX` | `local` (default) or `none` for `grclanker flue run`. |
| `GRCLANKER_DURABLE_MODEL` | `provider/model` for the experimental `grclanker durable` commands. See [Durable Runtime](/docs/getting-started/durable-runtime/#configuration). |
| `GRCLANKER_AGENT_SDK_MODEL` | Cursor model id for the [Cursor Agent SDK](/docs/getting-started/agent-sdk/) project. That project does not read `settings.json`. Unset, turns use `grok-4.7` with `reasoning_effort=high` and `fast=true`. A model turn also needs a Cursor credential on the `agent-sdk` process. |
| `GRCLANKER_TRESTLE_BIN` | Path to the `trestle` executable for the `oscal_*` tools (`TRESTLE_BIN` also works). |
| `GRCLANKER_GWS_BIN` | Path to the `gws` executable for the `gws_ops_*` tools. |
| `GRCLANKER_LIVE_BACKENDS` | Comma-separated backend kinds that `npm --prefix cli run test:compute-backends:live` should exercise. |
| `GRCLANKER_VERSION` | Build-only. Version stamped on release bundles built with `npm --prefix cli run build:bundle` (default: the `cli/package.json` version). |
| `GRCLANKER_NODE_VERSION` | Build-only. Node.js version that `npm --prefix cli run build:bundle` packages (default `24.22.0`). |

`GRCLANKER_CODING_AGENT_DIR`, `GRCLANKER_COMPUTE_BACKEND`, and `GRCLANKER_COMPUTE_BACKEND_OVERRIDE` belong to the Pi terminal CLI. grclanker sets the first two when it launches the embedded Pi runtime, and it sets the override when you pass `--compute <kind>`. Leave them unset. For that runtime, use `grclanker setup` or a per-run `--compute <kind>`.

Provider and integration credentials use each vendor's own variable names (for example `ANTHROPIC_API_KEY`, `RUNPOD_API_KEY`, `MODAL_TOKEN_ID`). The integration and compute backend guides list them.
