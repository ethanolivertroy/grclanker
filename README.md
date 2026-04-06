# grclanker

`grclanker` is an experimental open source AI GRC CLI built on top of Pi.

The current public release starts with CMVP, KEV, EPSS, control mapping, posture triage, and spec-driven build workflows. That is the opening surface, not the full intended scope of the project.

This first public CLI release is `0.0.1`. It is intentionally experimental.

macOS and Linux are the recommended platforms for `0.0.1`. Windows support exists, but it is best-effort and not a priority for this first experimental release.

## Install

Recommended bundle install:

```bash
curl -fsSL https://grclanker.com/install | bash
```

Windows PowerShell (best effort):

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://grclanker.com/install.ps1 | iex"
```

Package-manager fallback:

```bash
npm install -g @grclanker/cli
bun install -g @grclanker/cli
```

Installation docs:

- `https://grclanker.com/docs/getting-started/installation`
- `https://grclanker.com/docs/getting-started/setup`

## Setup

After install, run:

```bash
grclanker setup
```

The recommended path is local-first:

```bash
ollama serve
ollama pull gemma4
grclanker setup
```

That configures grclanker to use a local Ollama-compatible endpoint with Gemma 4 instead of silently defaulting to a hosted model.

If you do not want the local-first path, the setup wizard can also save an explicit hosted provider/model choice.

Inspect local backend readiness:

```bash
grclanker env doctor
grclanker env smoke-test
grclanker env exec -- pwd
```

If you choose `docker` or `parallels-vm` during setup, the wizard now also captures the container image or Parallels sandbox source settings needed for backend execution.

If you choose `sandbox-runtime`, grclanker reads sandbox policy from:

- `~/.grclanker/sandbox.json`
- `<repo>/.grclanker/sandbox.json`

## Compute Backends

`0.0.1` is still a local-shell CLI release. Planned execution backends are tracked in [specs/grclanker-compute-backends.spec.md](./specs/grclanker-compute-backends.spec.md).

The current recommendation is:

- Phase 1: `sandbox-runtime`, Docker, and Parallels
- Phase 2: Modal and RunPod
- Phase 3: Vercel Sandbox or Cloudflare Sandbox for hosted CPU-only isolation

Current MVP behavior:

- Docker and Parallels now route Pi's `bash`, `read`, `write`, `edit`, `ls`, `grep`, and `find` tools, plus user `!` commands, through the selected backend.
- `sandbox-runtime` now routes `bash`, `grep`, and `find` through the sandbox and enforces the same filesystem policy for `read`, `write`, `edit`, and `ls`.
- `env smoke-test` now validates both file-tool behavior and backend-native search behavior.
- The Parallels path is intentionally safer than directly reusing one of your existing VMs: grclanker prefers deploying disposable sandboxes from a dedicated Parallels template, with stopped-base cloning as a fallback, and attaches only the repo share to the sandbox it creates.
- This is intentionally more explicit than Feynman's current Docker badge logic: grclanker validates runtime readiness and only claims a backend when it can actually be used.

## What You Can Do With It

```bash
grclanker "what is the CMVP certificate for BoringCrypto?"
grclanker investigate "CVE-2024-3094"
grclanker audit "map our vuln evidence to FedRAMP RA-5"
grclanker "read specs/aws-sec-inspector.spec.md and build the tool"
```

Built-in workflow rails:

- `/investigate`
- `/audit`
- `/assess`
- `/validate`

What ships in `0.0.1`:

- 8 domain tools across CMVP, KEV, EPSS, recent exploited-vulnerability review, and ransomware-linked KEV checks
- 2 bundled agent personas: `auditor` and `verifier`
- 4 workflow commands
- Dedicated runtime identity and state under `~/.grclanker/agent`
- A real setup command for local-first or hosted model configuration

## Skills Only

User-scoped Codex skill:

```bash
curl -fsSL https://grclanker.com/install-skills | bash
```

Repo-local skill:

```bash
curl -fsSL https://grclanker.com/install-skills | bash -s -- --repo
```

Windows PowerShell (best effort):

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://grclanker.com/install-skills.ps1 | iex"
```

The skills-only installers download just the `skills/` tree. They do not install the bundled runtime.

## Specs

The specs are still here, but they are not the whole story anymore. They are the build surface the CLI can work on directly.

Browse the catalog:

- Website: `https://grclanker.com/specs`
- Raw base: `https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs`

Grab one directly:

```bash
curl -O https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs/aws-sec-inspector.spec.md
```

Or tell the CLI to use one:

```bash
grclanker "read specs/aws-sec-inspector.spec.md and build the tool"
```

The intended flow is not “pick between the specs and the CLI.” The intended flow is install the CLI, configure it, and then point it at a spec when you want the repo’s build plans executed.

The catalog currently covers cloud infrastructure, IAM, security tooling, vulnerability platforms, observability, SaaS apps, and developer platforms.

## Experimental Release Bundles

The release installers look for GitHub Release assets named like:

- `grclanker-<version>-darwin-arm64.tar.gz`
- `grclanker-<version>-darwin-x64.tar.gz`
- `grclanker-<version>-linux-arm64.tar.gz`
- `grclanker-<version>-linux-x64.tar.gz`
- `grclanker-<version>-win32-arm64.zip`
- `grclanker-<version>-win32-x64.zip`

Build them locally:

```bash
cd cli
npm install
npm run build:bundle -- --all
```

Artifacts land in `cli/release/`.

## Experimental Means Experimental

- Expect rough edges.
- Expect fast iteration.
- Expect breaking changes before `0.1.x`.

Built by [Ethan Troy](https://ethantroy.dev)
