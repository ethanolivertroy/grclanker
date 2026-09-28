---
title: Installation
description: Install the grclanker release bundle, build the current main branch from source, or install only the skills.
---

There are two ways to install grclanker today:

- **Release bundle.** The one-line installer fetches the newest GitHub release bundle. That is currently the `v0.0.1` pre-release, which ships the CMVP and KEV/EPSS tool surface (8 tools).
- **Source checkout.** Everything on `main` since that release, including the 35 platform integrations, needs a source checkout until the next release is cut.

If you just want the shortest install-to-first-run path, use the [Quick Start](/docs/getting-started/quick-start). This page is the full reference for both paths, pinned versions, skills-only installs, and troubleshooting.

> grclanker is primarily tested on macOS and Linux. Windows support is best-effort and is not a priority for this experimental release. If you want the least-friction path, use macOS or Linux.

## What the current release includes

The `v0.0.1` bundle gives you the interactive CLI, `grclanker setup`, `grclanker env doctor`, `grclanker env smoke-test`, `grclanker env exec`, and the `investigate`, `audit`, `assess`, and `validate` workflows, backed by these tools:

- `cmvp_search_modules`, `cmvp_search_historical`, `cmvp_search_in_process`, `cmvp_get_module`
- `kevs_search`, `kevs_recent`, `kevs_get_epss`, `kevs_check_ransomware`

These are on `main` but not in the `v0.0.1` bundle:

- 241 domain tools, including the 35 platform integrations (AWS, Okta, GitHub, and the rest of the [integrations](/docs/integrations/aws/) section) plus the FedRAMP, OSCAL, and SCF tools
- `grclanker tools`, which lists every bundled tool
- `grclanker flue run`, which runs the same agent under the [Flue runtime](/docs/getting-started/flue-runtime/)
- `grclanker env list`, `grclanker setup --compute <kind>`, and `--compute <kind>` on `investigate` and `audit`

To use any of those now, [install from source](#install-from-source).

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
- Scans the GitHub release list for the newest release that has a bundle for your platform and downloads it.
- Verifies the archive against the release's `SHA256SUMS.txt`.
- Replaces `~/.local/share/grclanker` with the unpacked bundle. The bundle includes its own Node.js runtime, so you do not need Node installed.
- Links `grclanker` into `~/.local/bin`. On Windows it writes a `grclanker.cmd` launcher there instead.
- Warns if `~/.local/bin` is not on your `PATH`. On macOS and Linux it prints the `export PATH=...` line to add to your shell profile.

grclanker keeps its settings and runtime state under `~/.grclanker/agent`, separate from the install directory, so reinstalling does not reset your setup.

## Pinned versions and install locations

Pin a release explicitly:

```bash
curl -fsSL https://grclanker.com/install | bash -s -- 0.0.1
```

Windows PowerShell (best effort):

```powershell
powershell -ExecutionPolicy Bypass -c "& ([scriptblock]::Create((irm https://grclanker.com/install.ps1))) -Version 0.0.1"
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

A source checkout gives you everything on `main`. You need `git`, `npm`, and Node.js 22.19 or newer, the `engines` floor in `cli/package.json`. The Pi and Flue runtime packages the CLI depends on require it.

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

When run from a checkout, the installer uses the newest matching bundle in `cli/release/` instead of downloading one, and verifies it against the `SHA256SUMS.txt` written next to it. The install banner still reads `v0.0.1`, because that is the version in `cli/package.json` until the next release.

To update a source install, run `git pull`, then repeat `npm --prefix cli ci` and `npm --prefix cli run build` (and `build:bundle` plus `bash public/install` if you use the bundle layout).

## Configure grclanker for local-only use

Install and model setup are separate on purpose.

If you want grclanker to stay local-first instead of using a hosted provider, do this after install:

```bash
ollama serve
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

`@grclanker/cli` is not published to npm, so `npm install -g @grclanker/cli` and `bun install -g @grclanker/cli` fail. The installer still prints those two commands as fallbacks when it cannot download a bundle; use a [source checkout](#install-from-source) instead.

## Verify the install

```bash
grclanker --help
grclanker setup
```

If the help output appears and setup starts, the install is healthy. On a source install, `grclanker tools` also lists every registered tool.

## Troubleshooting

- If `grclanker` resolves to a different install (for example an `npm link` from a source checkout), run `which -a grclanker` and `hash -r`, or launch `~/.local/bin/grclanker` directly. The installer warns when another `grclanker` is already on your `PATH`.
- If `grclanker tools` or `grclanker flue run` prints `Unknown command`, you are running the `v0.0.1` bundle. Those commands need a [source checkout](#install-from-source) until the next release.
- If local-first setup fails, check that Ollama is serving on `http://localhost:11434/v1`.
- If `gemma4` is missing, run `ollama pull gemma4` and rerun `grclanker setup`.
- If you do not want local-first, rerun `grclanker setup` and choose `Hosted`.

On Windows, expect rough edges. The recommended path for now is macOS or Linux.
