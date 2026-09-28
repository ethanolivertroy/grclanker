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

List the bundled GRC and compute tools:

```bash
grclanker tools
```

Regenerate the website tool catalog from the bundled extension registry:

```bash
npm run sync:tool-catalog
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

## Cursor Agent SDK Runtime

The same GRC tool surface can run as a Cursor Agent SDK agent built on [`@cursor/july`](https://www.npmjs.com/package/@cursor/july) (the `agent-sdk` CLI). The agent project lives in `cli/agent-sdk/` and is an adapter over the bundled extension, not a second implementation:

- all 241 domain tools are exposed as Agent SDK server tools under their native names, with TypeBox parameter schemas converted to plain JSON Schema at the adapter boundary and arguments validated with the same `prepareArguments` shims and Pi validator the CLI uses
- `SYSTEM.md` becomes the always-on instructions, the `/investigate`, `/audit`, `/assess`, and `/validate` prompts become on-demand skills, the bundled `crypto-validation` skill is exposed as a skill, and the `auditor` and `verifier` personas become subagents
- Pi's compute-backend tools (`bash`, `read`, `write`, `edit`, `ls`, `find`, `grep`) are not exposed; the Cursor harness supplies its own shell and file tools
- the 199 query tools declare `effect: "read"` for Agent SDK dry runs (FedRAMP lookups keep their catalog cache in memory during a dry run and leave `~/.grclanker`, or `GRCLANKER_HOME`, untouched), and the 42 writers (exports, generators, the evidence collector, OSCAL workspace commands) require human approval before a model-initiated call runs

Run it from a source checkout (`@cursor/july` is a CLI devDependency, so `npm --prefix cli install` provides `agent-sdk`):

```bash
npm --prefix cli run agent-sdk:validate
npm --prefix cli run agent-sdk:info
npm --prefix cli run agent-sdk:call -- kevs_search --input '{"query":"CVE-2024-3094"}'
npm --prefix cli run agent-sdk:dev
```

`validate`, `info`, and `call` need no Cursor credential. Model turns (`agent-sdk:dev`, `agent-sdk:run`) need one: run `npx agent-sdk login` inside `cli/` or export `CURSOR_API_KEY`. The Agent SDK default model applies unless `GRCLANKER_AGENT_SDK_MODEL` names a Cursor model id. When a domain tool changes, regenerate the per-tool entry files with `npm --prefix cli run sync:agent-sdk-tools`; `npm --prefix cli run test:cli` fails if the entries drift, and `npm --prefix cli run test:agent-sdk:validate` runs the real `agent-sdk validate` and `info` discovery. See [Cursor Agent SDK](https://grclanker.com/docs/getting-started/agent-sdk) for details.

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

- 241 domain tools across AWS, Azure, GCP, OCI, Cloudflare, Webex, Zoom, Ansible AAP, CMVP, KEV/EPSS, FedRAMP, SCF, OSCAL, GitHub, Google Workspace, Slack, Okta, Duo, Vanta, Box, CrowdStrike, Datadog, Elastic, KnowBe4, LaunchDarkly, MuleSoft, New Relic, PagerDuty, Palo Alto Networks, Qualys, Salesforce, ServiceNow, Snowflake, Splunk, Sumo Logic, Tenable, Veracode, Zendesk, Zscaler, and operator evidence workflows
- 7 compute backend tools (`bash`, `read`, `write`, `edit`, `ls`, `find`, `grep`) routed through the selected compute backend
- `grclanker tools` to list the bundled tool inventory from the same extension registration path the agent uses, and the generated [tool catalog](https://grclanker.com/docs/tools/catalog) for the same list on the website
- 2 bundled agent personas: `auditor` and `verifier`
- 4 workflow commands
- Dedicated runtime identity and state under `~/.grclanker/agent`
- A real setup command for local-first or hosted model configuration

## Run Under Flue

grclanker can also run as a [Flue Framework](https://flueframework.com/) agent. The adapter in `cli/flue/` mounts the same 241 domain tools, the shipped system prompt, the `/investigate`, `/audit`, `/assess`, and `/validate` prompts (as Flue skills), and the `auditor` and `verifier` personas (as Flue subagents). Tool schemas are converted from TypeBox JSON Schema to Valibot at the adapter boundary; the tool implementations are untouched.

Bundled runner (built on Flue's `start()` API, no extra install):

```bash
export ANTHROPIC_API_KEY=...
grclanker flue run --message "Is BoringCrypto FIPS validated?"
grclanker flue run --message "Now check KEV exposure" --id fips-review --json
```

Official Flue CLI (from a repo checkout, in the `cli/` directory after `npm install`, Node 22.19 or newer):

```bash
npx flue run flue/agent.ts --message "Is BoringCrypto FIPS validated?"
```

`@flue/cli` is a devDependency of the CLI package on purpose: the CLI must share the project's `@flue/runtime` install. Running a separately downloaded copy (for example `npx @flue/cli run ...` without the local install) loads a second runtime and fails with an internal hook error.

Configuration:

- `GRCLANKER_FLUE_MODEL` sets the `provider/model` specifier. Without it, the `grclanker setup` choice is reused (hosted, or local-first: the Ollama entry from `~/.grclanker/agent/models.json` is registered with Flue through `setProvider()`), otherwise `anthropic/claude-sonnet-4-6`. Hosted provider API keys come from the environment, as in any Flue project.
- `GRCLANKER_FLUE_SANDBOX=none` disables the local sandbox that provides file and shell tools for the current directory.
- Conversations persist in `~/.grclanker/flue/conversations.db`, verbatim, raw tool arguments and credentials included (Flue offers no pre-persistence redaction). Pass `--db <path>` or `--db :memory:` to change that; use `:memory:` in CI. `flue run` writes `node_modules/.cache/flue/run.db` instead, which must not end up in a CI cache.

Limitations: the Pi compute backends (`host`, `sandbox-runtime`, Docker, Parallels) do not apply; Flue's own sandbox model is used instead. Flue validates the raw model arguments against each tool's schema (coercing typed values) before the tool's own normalizer runs, and tool output reaches the model as a JSON string. See [`/docs/getting-started/flue-runtime`](https://grclanker.com/docs/getting-started/flue-runtime) for the exact behavior.

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
- Raw base: `https://raw.githubusercontent.com/hackIDLE/grclanker/main/specs`

Grab one directly:

```bash
curl -O https://raw.githubusercontent.com/hackIDLE/grclanker/main/specs/aws-sec-inspector.spec.md
```

Or tell the CLI to use one:

```bash
grclanker "read specs/aws-sec-inspector.spec.md and build the tool"
```

The intended flow is not “pick between the specs and the CLI.” The intended flow is install the CLI, configure it, and then point it at a spec when you want the repo’s build plans executed.

The catalog currently covers cloud infrastructure, IAM, security tooling, vulnerability platforms, observability, SaaS apps, developer platforms, and community-contributed specs.

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
