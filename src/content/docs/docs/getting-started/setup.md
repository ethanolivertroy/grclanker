---
title: Setup
description: Configure grclanker for local-first Ollama + Gemma 4 or for a hosted provider path, then choose and validate a compute backend.
---

Run the setup wizard any time you want to configure or reconfigure the companion:

```bash
grclanker setup
```

On first launch, grclanker will run setup automatically if no model configuration exists yet.

Setup now covers three separate decisions:

- model/provider selection
- compute backend selection
- skill visibility

That split is intentional. The model decides who answers. The compute backend decides where `bash`, file tools, and search tools execute. Skill visibility decides whether grclanker stays limited to its bundled GRC skills or also discovers project/local Pi skill directories.

## Recommended path: local-first

The recommended first local configuration is:

- Backend: Ollama-compatible local endpoint
- Default endpoint: `http://localhost:11434/v1`
- Default model example: `gemma4`

Before setup, make sure the local endpoint is actually running:

```bash
ollama serve
ollama pull gemma4
```

Then run:

```bash
grclanker setup
```

Choose `local-first` when prompted.

### What the wizard saves

For the local-first path, grclanker writes:

- `~/.grclanker/agent/settings.json` with:
  - `modelMode: "local"`
  - `providerKind: "ollama"`
  - `providerBaseUrl: "http://localhost:11434/v1"`
  - `defaultProvider: "ollama"`
  - `defaultModel: "gemma4"`
- `~/.grclanker/agent/models.json` with an Ollama-compatible `openai-completions` provider entry.

Local-first is fail-closed during setup. If the endpoint is unreachable, or if `gemma4` is not installed there, setup stops and tells you exactly what to fix instead of silently falling back to a hosted model.

## Hosted path

If you do not want the local-first path, run:

```bash
grclanker setup
```

Choose `hosted` and pick one of the current hosted providers:

- `openai`
- `anthropic`
- `google`

The wizard saves the provider and default model explicitly so the session is not ambiguous. grclanker then uses the provider credentials you already have configured for Pi-compatible usage.

## Compute backend selection

The setup wizard also prompts for a preferred compute backend:

- `host`
- `sandbox-runtime`
- `docker`
- `parallels-vm`

That part is separate from local-first versus hosted. You can pair either model path with any supported compute backend.

For Parallels specifically, setup now treats the sandbox source as either a dedicated template or a stopped base VM:

- it lists detected VMs
- it lists detected templates when they exist
- it recommends templates first for Windows, Linux, and macOS sandbox automation
- it lets you choose `template` or `base-vm`
- it lets you select by number or exact name
- it saves a disposable clone prefix
- it defaults the guest workspace path to auto-detect unless you need an override

After setup, always verify the selected backend:

```bash
grclanker env doctor
grclanker env smoke-test
```

If you need the backend-specific details, use the dedicated [Compute Backends](/docs/getting-started/compute-backends/) guide.

## Skill visibility

The setup wizard now also asks which skills grclanker should expose by default:

- `Bundled grclanker skills only`
- `Bundled + project/local Pi skills`

The recommended default is `Bundled grclanker skills only`.

That mode keeps grclanker focused on its bundled GRC workflows and prevents repo-local skill packs such as `.agents/skills` from unexpectedly showing up in `/skill`.

If you opt into `Bundled + project/local Pi skills`, Pi-style discovery is re-enabled for:

- `.agents/skills/` in the current repo and parent directories
- `.pi/skills/` in the current repo
- local Pi skill directories under your home directory

## Re-running setup

You can rerun setup at any time:

```bash
grclanker setup
```

That is the supported way to switch between local-first and hosted mode in `0.0.1`.
