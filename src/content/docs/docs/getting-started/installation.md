---
title: Installation
description: Install the grclanker release bundle, build the current main branch from source, or install only the skills.
---

There are two ways to install grclanker:

- **Release bundle.** The one-line installer fetches the newest GitHub release bundle, currently `v0.1.0`, with all 241 domain tools and its own Node.js runtime.
- **Source checkout.** Build `main` yourself to run unreleased changes or to work on grclanker.

If you just want the shortest install-to-first-run path, use the [Quick Start](/docs/getting-started/quick-start). This page is the full reference for both paths, pinned versions, skills-only installs, and troubleshooting.

> grclanker is primarily tested on macOS and Linux. Windows support is best-effort. If you want the least-friction path, use macOS or Linux.

## What the current release includes

The `v0.1.0` bundle gives you:

- 241 domain tools, including the 35 platform integrations (AWS, Okta, GitHub, and the rest of the [integrations](/docs/integrations/aws/) section) plus the CMVP, KEV/EPSS, FedRAMP, OSCAL, and SCF tools
- the interactive CLI, `grclanker setup`, and the `investigate`, `audit`, `assess`, and `validate` workflows
- `grclanker tools`, which lists every bundled tool
- `grclanker flue run`, which runs the same agent under the [Flue runtime](/docs/getting-started/flue-runtime/)
- `grclanker env list`, `env doctor`, `env smoke-test`, and `env exec`
- `grclanker "<prompt>"` for a free-form prompt, and a subject after `investigate`, `audit`, `assess`, or `validate`
- `--compute <kind>` to pick a compute backend: for one run of `investigate`, `audit`, `assess`, `validate`, or a `"<prompt>"`; with `grclanker setup --compute <kind>` to save it as the preferred backend; and as an alias for `--backend` on `env smoke-test` and `env exec`. A bare `grclanker --compute <kind>` is rejected as an unknown command.

[What's New](/docs/changelog/) lists everything that changed since `v0.0.1`.

## One-line installer

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

That setup step is where you choose the local-first or hosted model path.

## What the installer does

- Detects your OS and architecture. Bundles exist for `darwin-arm64`, `darwin-x64`, `linux-arm64`, `linux-x64` (glibc), `win32-arm64`, and `win32-x64`. Linux musl hosts (such as Alpine) are not supported; use a [source checkout](#install-from-source) there.
- Downloads the bundle for your platform from the newest full release, skipping prereleases such as `v0.2.0-rc.1`. If the GitHub API is unavailable or rate limited, it follows the `releases/latest` link on github.com instead.
- Checks the archive against the release's `SHA256SUMS.txt` when it can, and aborts on a mismatch. If the checksum file cannot be fetched, has no entry for the archive, or no SHA-256 tool is available, or if `GRCLANKER_ASSET_URL` points at a custom archive, it prints a warning and installs without verification.
- Replaces `~/.local/share/grclanker` with the unpacked bundle. The bundle includes its own Node.js runtime, so you do not need Node installed.
- Links `grclanker` into `~/.local/bin`. On Windows it writes a `grclanker.cmd` launcher there instead.
- Warns if `~/.local/bin` is not on your `PATH`. On macOS and Linux it prints the `export PATH=...` line to add to your shell profile.

grclanker keeps its settings and runtime state under `~/.grclanker/agent`, separate from the install directory, so reinstalling does not reset your setup.

## Pinned versions and install locations

Pin a release explicitly:

```bash
curl -fsSL https://grclanker.com/install | bash -s -- 0.1.0
```

Windows PowerShell (best effort):

```powershell
powershell -ExecutionPolicy Bypass -c "& ([scriptblock]::Create((irm https://grclanker.com/install.ps1))) -Version 0.1.0"
```

Both installers also read these environment variables:

| Variable | Default | Effect |
| --- | --- | --- |
| `GRCLANKER_VERSION` | `latest` | Release to install, with or without the leading `v`. A positional version or `-Version` wins over it. |
| `GRCLANKER_INSTALL_DIR` | `~/.local/share/grclanker` | Where the bundle is unpacked. The installer deletes and recreates this directory. |
| `GRCLANKER_BIN_DIR` | `~/.local/bin` | Where the `grclanker` launcher is linked. |

For example:

```bash
curl -fsSL https://grclanker.com/install | GRCLANKER_INSTALL_DIR="$HOME/opt/grclanker" GRCLANKER_BIN_DIR="$HOME/bin" bash
```

## Install from source

A source checkout gives you everything on `main`, including changes that have not been released yet. You need `git`, `npm`, and Node.js 22.19 or newer, the `engines` floor in `cli/package.json`. The Pi and Flue runtime packages the CLI depends on require it.

```bash
git clone https://github.com/ethanolivertroy/grclanker.git
cd grclanker
npm --prefix cli ci
npm --prefix cli run build
node cli/bin/grclanker.js --help
node cli/bin/grclanker.js tools
```

`grclanker tools` should report `241 domain tools + 7 compute backend tools`. Run `node cli/bin/grclanker.js setup` next.

To put `grclanker` on your `PATH`, link the package from inside `cli/`:

```bash
cd cli
npm link
```

Run `npm link` from the `cli/` directory. `npm --prefix cli link` does not work, because `--prefix` also redirects npm's global link directory into the checkout.

If you would rather have the same self-contained layout as the release installer, build a bundle for your platform and install it from the checkout root:

```bash
npm --prefix cli run build:bundle
bash public/install
```

When run from a checkout, the installer uses the newest matching bundle in `cli/release/` instead of downloading one, and checks it against the `SHA256SUMS.txt` that `build:bundle` writes next to it. The install banner shows the version in `cli/package.json`.

To update a source install, run `git pull`, then repeat `npm --prefix cli ci` and `npm --prefix cli run build` (and `build:bundle` plus `bash public/install` if you use the bundle layout).

## Configure grclanker for local-only use

Install and model setup are separate on purpose.

If you want grclanker to stay local-first instead of using a hosted provider, install Ollama first from [ollama.com/download](https://ollama.com/download). The grclanker installer does not install it.

Ollama must be serving before setup. If the Ollama app or background service is already running, skip this step. Otherwise start the server in its own terminal and leave it running:

```bash
ollama serve
```

Then, in a second terminal:

```bash
ollama pull gemma4
grclanker setup
```

Choose `Local-first` when prompted. The defaults are:

- endpoint: `http://localhost:11434/v1`
- provider kind: `ollama`
- model example: `gemma4`

If the endpoint is unreachable, setup stops and prints the commands to fix it. If the model you name is not installed, setup offers another installed local model or asks you to pull one. It does not fall back to a hosted model. See [Setup](/docs/getting-started/setup/) for the full wizard.

## Skills only

If you only want the grclanker agent skill for Codex or another skills-aware agent, and not the terminal runtime:

User-scoped install, into `~/.codex/skills/grclanker`:

```bash
curl -fsSL https://grclanker.com/install-skills | bash
```

Repo-local install, into `.agents/skills/grclanker` under the current directory:

```bash
curl -fsSL https://grclanker.com/install-skills | bash -s -- --repo
```

Windows PowerShell (best effort):

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://grclanker.com/install-skills.ps1 | iex"
```

These installers download only `skills/grclanker/SKILL.md` from the `main` branch. They do not install the runtime bundle, the terminal UI, or the state under `~/.grclanker/agent`.

## Package managers

`@grclanker/cli` is not published to npm, so `npm install -g @grclanker/cli` and `bun install -g @grclanker/cli` fail. If no release bundle fits your platform, use a [source checkout](#install-from-source) instead.

## Verify the install

```bash
grclanker --help
grclanker setup
```

If the help output appears and setup starts, the install is healthy. `grclanker tools` also lists every registered tool.

## Troubleshooting

- If `grclanker` resolves to a different install (for example an `npm link` from a source checkout), run `which -a grclanker` and `hash -r`, or launch `~/.local/bin/grclanker` directly. The installer warns when another `grclanker` is already on your `PATH`.
- If `grclanker tools` or `grclanker flue run` prints `Unknown command`, you are still running the `v0.0.1` bundle. Rerun the [one-line installer](#one-line-installer) to upgrade.
- If local-first setup fails, check that Ollama is serving on `http://localhost:11434/v1`.
- If `gemma4` is missing, run `ollama pull gemma4` and rerun `grclanker setup`.
- If you do not want local-first, rerun `grclanker setup` and choose `Hosted`.

On Windows, expect rough edges. The recommended path for now is macOS or Linux.
