# grclanker

`grclanker` is an experimental open source AI GRC CLI built on top of Pi.

The first public release, the `0.0.1` pre-release bundle, starts with CMVP, KEV, and EPSS lookups plus the control mapping, posture triage, and spec-driven build workflows. `main` has grown well past that: 241 domain tools across cloud, identity, SaaS, and compliance frameworks (see [What ships](#what-ships)). Neither is the full intended scope of the project.

`0.0.1` is intentionally experimental.

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

The installers download the newest GitHub release bundle, which today is the `v0.0.1` pre-release. That bundle registers 8 domain tools (`cmvp_*` and `kevs_*`) and supports `setup`, `env doctor`, `env smoke-test`, `env exec`, and the four workflow commands. `grclanker tools`, `grclanker env list`, `grclanker flue run`, and `--compute` are only on `main` until the next release bundle is cut.

`@grclanker/cli` is not published to npm yet, so `npm install -g @grclanker/cli` and `bun install -g @grclanker/cli` do not work.
If no release bundle fits your platform, use the source-checkout path below.

Run `main` from a source checkout (Node 22.19 or newer):

```bash
git clone https://github.com/ethanolivertroy/grclanker.git
cd grclanker
npm --prefix cli ci
npm --prefix cli run build
node cli/bin/grclanker.js tools
```

`cli/bin/grclanker.js` is the same launcher the `grclanker` bin points at; `alias grclanker="node $PWD/cli/bin/grclanker.js"` makes the commands below work as written.

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

Inspect local backend readiness (`env list` is `main` only):

```bash
grclanker env doctor
grclanker env smoke-test
grclanker env exec -- pwd
grclanker env list
```

List the bundled GRC and compute tools (`main` only):

```bash
grclanker tools
grclanker tools --json
grclanker tools kevs_search
```

Regenerate the website tool catalog from the bundled extension registry (from the repo root):

```bash
npm run sync:tool-catalog
```

If you choose `docker` or `parallels-vm` during setup, the wizard now also captures the container image or Parallels sandbox source settings needed for backend execution.

If you choose `sandbox-runtime`, grclanker reads sandbox policy from:

- `~/.grclanker/sandbox.json`
- `<repo>/.grclanker/sandbox.json`

## Compute Backends

The default backend is `host`, the local shell. The backend plan is tracked in [specs/grclanker-compute-backends.spec.md](./specs/grclanker-compute-backends.spec.md):

- Phase 1: `sandbox-runtime`, Docker, and Parallels (in the `0.0.1` bundle)
- Phase 2: Modal, RunPod pods, and RunPod serverless (on `main`)
- Phase 3: Vercel Sandbox or Cloudflare Sandbox for hosted CPU-only isolation (reserved kinds on `main` that fail fast; not wired in yet)

Current behavior:

- Docker and Parallels route Pi's `bash`, `read`, `write`, `edit`, `ls`, `grep`, and `find` tools, plus user `!` commands, through the selected backend.
- `sandbox-runtime` routes `bash`, `grep`, and `find` through the sandbox and enforces the same filesystem policy for `read`, `write`, `edit`, and `ls`.
- On `main`, `runpod-pod` copies the repo's tracked files into a pod you already own and runs the full tool surface over SSH. `modal` and `runpod-serverless` are one-shot: only `bash` runs remotely, and the file tools stay on the local workspace.
- On `main`, `grclanker setup --compute <kind>` saves a preferred backend. To override it for one run, put `--compute <kind>` after a workflow command or an `env smoke-test` / `env exec` subcommand, for example `grclanker investigate --compute docker` or `grclanker env smoke-test --compute host`. The flag is not accepted on its own (`grclanker --compute docker` exits with `Unknown command`), and `env doctor` and `env list` ignore it.
- `env smoke-test` validates both file-tool behavior and backend-native search behavior.
- The Parallels path is intentionally safer than directly reusing one of your existing VMs: grclanker prefers deploying disposable sandboxes from a dedicated Parallels template, with stopped-base cloning as a fallback, and attaches only the repo share to the sandbox it creates.
- grclanker validates runtime readiness and only claims a backend when it can actually be used.

See [Compute Backends](https://grclanker.com/docs/getting-started/compute-backends) for the full matrix.

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
npm --prefix cli run agent-sdk:call -- kevs_search --input '{"query":"CVE-2021-44228"}'
npm --prefix cli run agent-sdk:dev
```

`validate`, `info`, and `call` need no Cursor credential. Model turns (`agent-sdk:dev`, `agent-sdk:run`) need one: run `npx agent-sdk login` inside `cli/` or export `CURSOR_API_KEY`. The Agent SDK default model applies unless `GRCLANKER_AGENT_SDK_MODEL` names a Cursor model id. When a domain tool changes, regenerate the per-tool entry files with `npm --prefix cli run sync:agent-sdk-tools`; `npm --prefix cli run test:cli` fails if the entries drift, and `npm --prefix cli run test:agent-sdk:validate` runs the real `agent-sdk validate` and `info` discovery. See [Cursor Agent SDK](https://grclanker.com/docs/getting-started/agent-sdk) for details.

## What You Can Do With It

`grclanker` with no arguments opens an interactive session; ask in plain language, for example:

```text
is CVE-2021-44228 in the CISA KEV catalog, and what is its EPSS score?
investigate CVE-2021-44228
map our vuln evidence to FedRAMP RA-5
```

CMVP questions such as "is BoringCrypto FIPS validated?" are in scope too, through the `cmvp_*` tools.

On `main`, the native cloud and SaaS tools answer directly in the same session, for example:

```text
check my AWS audit access, then assess identity posture and export an audit bundle
```

On `main`, `grclanker "..."` sends a quoted prompt straight to the agent, and a workflow command takes its subject, for example `grclanker investigate "CVE-2021-44228"`. The `v0.0.1` bundle answers `Unknown command` to the quoted form and drops workflow subjects.

Built-in workflow rails, as slash commands inside a session or as `grclanker investigate`, `grclanker audit`, `grclanker assess`, and `grclanker validate` to open a session that starts with that workflow (then name the vendor, CVE, or framework):

- `/investigate`
- `/audit`
- `/assess`
- `/validate`

### What ships

In the `0.0.1` release bundle:

- 8 domain tools: `cmvp_search_modules`, `cmvp_search_historical`, `cmvp_search_in_process`, `cmvp_get_module`, `kevs_search`, `kevs_recent`, `kevs_check_ransomware`, and `kevs_get_epss`
- 7 compute backend tools (`bash`, `read`, `write`, `edit`, `ls`, `find`, `grep`) routed through the selected compute backend
- 2 bundled agent personas: `auditor` and `verifier`
- 4 workflow commands
- Dedicated runtime identity and state under `~/.grclanker/agent`
- A real setup command for local-first or hosted model configuration

What `main` adds (run it from a source checkout until the next release bundle):

- 241 domain tools across AWS, Azure, GCP, OCI, Cloudflare, Webex, Zoom, Ansible AAP, CMVP, KEV/EPSS, FedRAMP, SCF, OSCAL, GitHub, Google Workspace, Slack, Okta, Duo, Vanta, Box, CrowdStrike, Datadog, Elastic, KnowBe4, LaunchDarkly, MuleSoft, New Relic, PagerDuty, Palo Alto Networks, Qualys, Salesforce, ServiceNow, Snowflake, Splunk, Sumo Logic, Tenable, Veracode, Zendesk, Zscaler, and operator evidence workflows
- `grclanker tools` to list the bundled tool inventory from the same extension registration path the agent uses, and the generated [tool catalog](https://grclanker.com/docs/tools/catalog) for the same list on the website
- The Modal and RunPod compute backends, `grclanker env list`, and the `--compute` flag on `setup`, the workflow commands, `env smoke-test`, and `env exec`
- The [Cursor Agent SDK](#cursor-agent-sdk-runtime) and [Flue](#run-under-flue) runtimes

## Run Under Flue

grclanker can also run as a [Flue Framework](https://flueframework.com/) agent. The adapter in `cli/flue/` mounts the same 241 domain tools, the shipped system prompt, the `/investigate`, `/audit`, `/assess`, and `/validate` prompts (as Flue skills), and the `auditor` and `verifier` personas (as Flue subagents). Tool schemas are converted from TypeBox JSON Schema to Valibot at the adapter boundary; the tool implementations are untouched.

Bundled runner (built on Flue's `start()` API, no extra install; `main` only, so run it from a source checkout until the next release bundle):

```bash
export ANTHROPIC_API_KEY=...
grclanker flue run --message "Is CVE-2021-44228 in the CISA KEV catalog?"
grclanker flue run --message "Now get its EPSS score" --id log4shell-review --json
```

Official Flue CLI (from a repo checkout, in the `cli/` directory after `npm install`, Node 22.19 or newer):

```bash
npx flue run flue/agent.ts --message "Is CVE-2021-44228 in the CISA KEV catalog?"
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

The skills-only installers download a single file, `skills/grclanker/SKILL.md`, into `~/.codex/skills/grclanker/` (the default, also `--user`) or `.agents/skills/grclanker/` under the current directory (`--repo`). They do not install the bundled runtime.

## Specs

The specs are still here, but they are not the whole story anymore. They are the build surface the CLI can work on directly.

Browse the catalog:

- Website: `https://grclanker.com/specs`
- Raw base: `https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs`

Grab one directly:

```bash
curl -O https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs/aws-sec-inspector.spec.md
```

Or point a `grclanker` session at one (the path is relative to where you started the session):

```text
read aws-sec-inspector.spec.md and build the tool
```

Some specs now describe integrations that `main` already ships as native tools. The AWS spec, for example, is the contract behind the `aws_*` tools, so on `main` you can run those directly and use the spec when you want another implementation built against the same contract.

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

plus a `SHA256SUMS.txt`. When that file has an entry for the downloaded archive, the installers check the archive's SHA-256 against it and abort on a mismatch. When the file cannot be fetched, has no entry for the archive, no `sha256sum` or `shasum` is available (`install` only), or a custom `GRCLANKER_ASSET_URL` is set, they print a warning and install without verifying.

Build them locally:

```bash
cd cli
npm install
npm run build:bundle -- --all
```

Artifacts and `SHA256SUMS.txt` land in `cli/release/` (override with `--output-dir <dir>`; drop `--all` to build only the host platform, or pass `--target <platform-arch>`).

## Experimental Means Experimental

- Expect rough edges.
- Expect fast iteration.
- Expect breaking changes before `0.1.x`.

## License

`grclanker` is licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for attribution.

Built by [Ethan Troy](https://ethantroy.dev)
