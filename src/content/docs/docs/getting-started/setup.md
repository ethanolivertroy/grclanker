---
title: Setup
description: Configure grclanker for local-first Ollama + Gemma 4 or for a hosted provider path, then choose and validate a compute backend.
---

Run the setup wizard any time you want to configure or reconfigure the companion:

```bash
grclanker setup
```

On first launch, grclanker runs setup automatically if no model configuration exists yet. Automatic setup needs an interactive terminal. Without one, grclanker exits and asks you to run `grclanker setup` first.

`grclanker setup` needs a terminal too. To configure a machine without one, write the fields listed under [What the wizard saves](#what-the-wizard-saves) into `~/.grclanker/agent/settings.json` yourself. Local-first also needs the `models.json` provider entry. [Configuration](/docs/getting-started/configuration/) shows both files.

Setup covers three separate decisions:

- model/provider selection
- compute backend selection
- skill visibility

That split is intentional:

- The model decides who answers.
- The compute backend decides where `bash`, file tools, and search tools execute.
- Skill visibility decides whether grclanker stays limited to its bundled GRC skills or also discovers project/local Pi skill directories.

## Recommended path: local-first

The recommended first local configuration is:

- Backend: Ollama-compatible local endpoint
- Default endpoint: `http://localhost:11434/v1`
- Default model example: `gemma4`

Before setup, make sure the local endpoint is actually running with a large enough [context window](#context-length). Start the server in its own terminal and leave it running:

```bash
OLLAMA_CONTEXT_LENGTH=128000 ollama serve
```

Then, in a second terminal:

```bash
ollama pull gemma4
grclanker setup
```

Choose `Local-first` when prompted, then confirm or change the local endpoint.

### Context length

grclanker sends every tool definition with every request, about 100k tokens for the 241 domain tools and 7 compute tools. Ollama picks a default context window from your GPU memory: 4k tokens under 24 GiB, 32k from 24 to 48 GiB, and 256k at 48 GiB or more. Below 48 GiB, the default is too small to hold the tool definitions.

Give Ollama a larger window in one of these ways:

- Start the server with `OLLAMA_CONTEXT_LENGTH=128000 ollama serve`.
- In the Ollama app, raise the context length slider in its settings.
- If the Linux installer set Ollama up as a systemd service, add `Environment="OLLAMA_CONTEXT_LENGTH=128000"` to the service with `systemctl edit ollama.service`, then restart it. Ollama's FAQ has the [steps](https://docs.ollama.com/faq#setting-environment-variables-on-linux).

A larger window needs more memory. While a model is loaded, `ollama ps` shows the window it got in the `CONTEXT` column. Ollama's [context length guide](https://docs.ollama.com/context-length) covers the details.

### What the wizard saves

For the local-first path, grclanker writes:

- `~/.grclanker/agent/settings.json` with:
  - `modelMode: "local"`
  - `providerKind: "ollama"`
  - `providerBaseUrl: "http://localhost:11434/v1"`
  - `defaultProvider: "ollama"`
  - `defaultModel: "gemma4"`
- `~/.grclanker/agent/models.json` with an Ollama-compatible `openai-completions` provider entry.

Local-first is fail-closed during setup. If the endpoint is unreachable, setup stops and prints the `ollama serve` and `ollama pull` steps instead of silently falling back to a hosted model.

If the endpoint answers but the model you picked is not installed there, setup offers one of the installed local models instead (Gemma tags first) or asks you to pull the model or enter another one. It never switches to a hosted provider.

## Hosted path

If you do not want the local-first path, run:

```bash
grclanker setup
```

Choose `Hosted` and pick one of the current hosted providers:

- `openai` (default model `gpt-5.2`)
- `anthropic` (default model `claude-sonnet-4-20250514`)
- `google` (default model `gemini-2.5-pro`)

The wizard saves the provider and default model explicitly so the session is not ambiguous.

grclanker then uses the credentials the embedded Pi runtime already knows how to read, from either of these:

- The provider's environment variable (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `GEMINI_API_KEY`).
- A key stored with `/login` inside a grclanker session, which lands in `~/.grclanker/agent/auth.json`.

## Compute backend selection

After the model step, the wizard asks whether to configure advanced compute backend settings. Answer no to keep the current backend (`host` on a fresh install). Answer yes to pick a backend from the full list:

- `host`
- `sandbox-runtime`
- `docker`
- `parallels-vm`
- `modal`
- `runpod-pod`
- `runpod-serverless`
- `cloudflare-sandbox` and `vercel-sandbox` (listed, but not yet available)

Each entry shows whether the backend is detected on this machine. Picking one that is not detected asks before saving it anyway.

Compute backend selection is separate from local-first versus hosted. You can pair either model path with any supported compute backend.

To save a backend without the interactive wizard, pass it directly:

```bash
grclanker setup --compute docker
```

For Parallels specifically, setup treats the sandbox source as either a dedicated template or a stopped base VM:

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

The older `v0.0.1` release bundle predates the Modal and RunPod backends and `setup --compute`. Its wizard offers only `host`, `sandbox-runtime`, `docker`, and `parallels-vm`. Rerun the installer to get `v0.1.3` and the full list.

## Skill visibility

The setup wizard also asks which skills grclanker should expose by default:

- `Bundled grclanker skills only`
- `Bundled + project/local Pi skills`

The recommended default is `Bundled grclanker skills only`.

That mode keeps grclanker focused on its bundled GRC workflows and prevents repo-local skill packs such as `.agents/skills` from unexpectedly showing up in `/skill`.

If you opt into `Bundled + project/local Pi skills`, Pi-style discovery is re-enabled for:

- `.agents/skills/` in the current directory and its parents, up to the git repository root
- `.grclanker/skills/` in the current directory
- `~/.agents/skills/` in your home directory
- `~/.grclanker/agent/skills/`, where grclanker also keeps its bundled skills

## Re-running setup

You can rerun setup at any time:

```bash
grclanker setup
```

That is the supported way to switch between local-first and hosted mode.
