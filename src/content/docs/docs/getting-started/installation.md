---
title: Installation
description: Install grclanker with the bundled runtime, package-manager fallback, or skills-only path.
---

The recommended path is the one-line bundle installer. It downloads a prebuilt runtime bundle, unpacks it under `~/.local/share/grclanker`, and links the launcher into `~/.local/bin`.

If you just want the shortest install-to-first-run path, use the [Quick Start](/docs/getting-started/quick-start). This page is the full reference for installers, pinned versions, skills-only installs, and fallback paths.

> `0.0.1` is primarily tested on macOS and Linux. Windows support is best-effort right now and is not a priority for this first experimental release. If you want the least-friction path, use macOS or Linux.

## One-line installer (recommended)

On macOS or Linux:

```bash
curl -fsSL https://grclanker.com/install | bash
```

On Windows PowerShell (best effort):

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://grclanker.com/install.ps1 | iex"
```

After install, run:

```bash
grclanker setup
```

That setup step is where you choose the local-first or hosted path. grclanker no longer expects you to guess how model configuration is supposed to work.

## Configure grclanker for local-only use

The main thing people miss is that install and model setup are separate on purpose.

If you want grclanker to stay local-first instead of silently drifting to a hosted provider, do this immediately after install:

```bash
ollama serve
ollama pull gemma4
grclanker setup
```

Choose `local-first` when prompted.

The default documented local path in `0.0.1` is:

- endpoint: `http://localhost:11434/v1`
- provider kind: `ollama`
- model example: `gemma4`

If the endpoint is unreachable, setup stops and tells you exactly what to fix. It does not silently fall back to GPT or another hosted model.

## What the installer does

- Detects the matching OS and architecture.
- Downloads the matching release bundle.
- Installs the runtime under `~/.local/share/grclanker`.
- Links `grclanker` into `~/.local/bin`.
- Keeps runtime state under `~/.grclanker/agent`.

If you previously installed grclanker through `npm` or `bun`, your shell may still resolve the old global binary first. Run `which -a grclanker`, then `hash -r`, or launch the standalone shim directly from `~/.local/bin/grclanker`.

## Skills only

If you only want the Codex/CLAUDE-style skills and not the full terminal runtime:

User-scoped install:

```bash
curl -fsSL https://grclanker.com/install-skills | bash
```

Repo-local install:

```bash
curl -fsSL https://grclanker.com/install-skills | bash -s -- --repo
```

Windows PowerShell (best effort):

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://grclanker.com/install-skills.ps1 | iex"
```

These installers download only the `skills/` tree. They do not install the runtime bundle, the terminal UI, or the state under `~/.grclanker/agent`.

## Pinned versions

Pin the experimental release explicitly when you want a specific bundle:

```bash
curl -fsSL https://grclanker.com/install | bash -s -- 0.0.1
```

Windows PowerShell (best effort):

```powershell
powershell -ExecutionPolicy Bypass -c "& ([scriptblock]::Create((irm https://grclanker.com/install.ps1))) -Version 0.0.1"
```

## Package-manager fallback

Use this path only when you already manage your own Node runtime and do not need the bundled installer:

```bash
npm install -g @grclanker/cli
bun install -g @grclanker/cli
```

The package-manager installs do not solve runtime Node requirements for you. The bundle installer does.

## Verify the install

```bash
grclanker --help
grclanker setup
```

If the help output appears and setup starts, the install is healthy.

## Troubleshooting

- If `grclanker` resolves to an older global install, run `which -a grclanker` and `hash -r`.
- If local-first setup fails, check that Ollama is actually serving on `http://localhost:11434/v1`.
- If `gemma4` is missing, run `ollama pull gemma4` and rerun `grclanker setup`.
- If you do not want local-first, rerun `grclanker setup` and choose `hosted` explicitly.

If you are on Windows and something is weird, that is not surprising in `0.0.1`. The recommended path for now is macOS or Linux.
