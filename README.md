# grclanker

grclanker is an experimental open source AI GRC CLI built on [Pi](https://github.com/earendil-works/pi) 1.1 (`@earendil-works/pi-coding-agent` and `@earendil-works/pi-ai` 1.1.0). The current release is [`v0.1.2`](https://github.com/ethanolivertroy/grclanker/releases/tag/v0.1.2). It is early: minor versions can break before 1.0.

macOS and Linux are the platforms with release bundles. Windows support is best effort. Linux musl hosts, including Alpine, have no bundle. Use a source checkout there.

## Install

On macOS or Linux:

```bash
curl -fsSL https://grclanker.com/install | bash
```

On Windows PowerShell (best effort):

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://grclanker.com/install.ps1 | iex"
```

The installer downloads the newest GitHub release bundle, today `v0.1.2`. The bundle includes its own Node.js 24.22.0 runtime. Pin that release on macOS or Linux with:

```bash
curl -fsSL https://grclanker.com/install | bash -s -- 0.1.2
```

An official GitHub download or a `GRCLANKER_RELEASE_BASE_URL` install checks the archive against `SHA256SUMS.txt` and aborts when that file cannot be fetched, has no entry for the archive, the entry is not a SHA-256 digest, the digest does not match, or (the shell installer only) neither `sha256sum` nor `shasum` is available. A custom `GRCLANKER_ASSET_URL` prints a warning and installs without verifying. The [installation guide](https://grclanker.com/docs/getting-started/installation/) has the Windows pin command, the local-archive rules, and the `GRCLANKER_VERSION`, `GRCLANKER_INSTALL_DIR`, and `GRCLANKER_BIN_DIR` overrides.

`@grclanker/cli` is not on npm. `npm install -g @grclanker/cli` and `bun install -g @grclanker/cli` fail.

### From source

A checkout of `main` runs changes that are not in the release bundle yet. You need git, npm, and Node.js 22.19 or newer, the `engines` floor in `cli/package.json`.

```bash
git clone https://github.com/ethanolivertroy/grclanker.git
cd grclanker
npm --prefix cli ci
npm --prefix cli run build
cd cli
npm link
cd ..
grclanker tools
```

`grclanker tools` should report `241 domain tools + 7 compute backend tools`. `npm link` has to run from inside `cli/`, where it puts the `cli/bin/grclanker.js` launcher on your `PATH`. `npm --prefix cli link` does not, because `--prefix` also redirects npm's global link directory into the checkout.

## Quick start

The release installer links `grclanker` into `~/.local/bin`. A source checkout does the same with the `npm link` step above. The commands below use that name.

Install [Ollama](https://ollama.com/download) yourself. The grclanker installer does not install it. If Ollama is not already serving, start it and leave that terminal running:

```bash
ollama serve
```

In a second terminal:

```bash
ollama pull gemma4
grclanker setup
```

Choose Local-first. Setup uses `http://localhost:11434/v1`. If that endpoint is down, or the model you name is not installed, setup stops. It does not switch you to a hosted model. The wizard can also save an explicit hosted provider and model. See [Setup](https://grclanker.com/docs/getting-started/setup/).

Then:

```bash
grclanker
grclanker tools
grclanker "Is CVE-2021-44228 in the CISA KEV catalog, and what is its EPSS score?"
grclanker investigate "CVE-2021-44228"
```

`grclanker` with no arguments opens an interactive session. A quoted argument is a prompt. `investigate`, `audit`, `assess`, and `validate` open a session that starts on that workflow, and each one takes a subject. The `v0.0.1` bundle rejects the quoted form and drops workflow subjects.

Inside a session the same four workflows are slash commands. Guides: [Investigate](https://grclanker.com/docs/workflows/investigate/), [Audit](https://grclanker.com/docs/workflows/audit/), [Assess](https://grclanker.com/docs/workflows/assess/), [Validate](https://grclanker.com/docs/workflows/validate/).

## What ships in v0.1.2

- 241 domain tools. `grclanker tools` and the [tool catalog](https://grclanker.com/docs/tools/catalog/) list the same set.
- 7 compute backend tools: `bash`, `read`, `write`, `edit`, `ls`, `find`, and `grep`.
- 4 workflows, and 2 personas: `auditor` and `verifier`.
- `grclanker flue run` in the release bundle.
- A Cursor Agent SDK project, from a source checkout.
- Runtime state under `~/.grclanker/agent`.

[What's New](https://grclanker.com/docs/changelog/) covers `v0.1.2`: the FedRAMP tools follow the October 2026 rules, and the `sandbox-runtime` backend is updated. The tool count is unchanged from `v0.1.1`.

### Platform integrations

35 integrations, 212 tools. Each count is the number of `grclanker tools` entries with that prefix.

| Integration | Tools |
| --- | --- |
| [Ansible Automation Platform](https://grclanker.com/docs/integrations/ansible/) | 5 `ansible_*` |
| [AWS](https://grclanker.com/docs/integrations/aws/) | 7 `aws_*` |
| [Azure](https://grclanker.com/docs/integrations/azure/) | 7 `azure_*` |
| [Box](https://grclanker.com/docs/integrations/box/) | 6 `box_*` |
| [Cloudflare](https://grclanker.com/docs/integrations/cloudflare/) | 5 `cloudflare_*` |
| [CrowdStrike Falcon](https://grclanker.com/docs/integrations/crowdstrike/) | 7 `crowdstrike_*` |
| [Datadog](https://grclanker.com/docs/integrations/datadog/) | 6 `datadog_*` |
| [Duo Security Inspector](https://grclanker.com/docs/integrations/duo/) | 6 `duo_*` |
| [Elastic](https://grclanker.com/docs/integrations/elastic/) | 7 `elastic_*` |
| [GitHub](https://grclanker.com/docs/integrations/github/) | 7 `github_*` |
| [Google Cloud Platform](https://grclanker.com/docs/integrations/gcp/) | 7 `gcp_*` |
| [Google Workspace](https://grclanker.com/docs/integrations/gws/) | 6 `gws_*` |
| [Google Workspace CLI operator bridge](https://grclanker.com/docs/integrations/gws-ops/) | 5 `gws_ops_*` |
| [KnowBe4](https://grclanker.com/docs/integrations/knowbe4/) | 6 `knowbe4_*` |
| [LaunchDarkly](https://grclanker.com/docs/integrations/launchdarkly/) | 7 `launchdarkly_*` |
| [MuleSoft Anypoint Platform](https://grclanker.com/docs/integrations/mulesoft/) | 6 `mulesoft_*` |
| [New Relic](https://grclanker.com/docs/integrations/newrelic/) | 6 `newrelic_*` |
| [Okta](https://grclanker.com/docs/integrations/okta/) | 6 `okta_*` |
| [Oracle Cloud Infrastructure](https://grclanker.com/docs/integrations/oci/) | 6 `oci_*` |
| [PagerDuty](https://grclanker.com/docs/integrations/pagerduty/) | 7 `pagerduty_*` |
| [Palo Alto Networks](https://grclanker.com/docs/integrations/paloalto/) | 6 `paloalto_*` |
| [Qualys](https://grclanker.com/docs/integrations/qualys/) | 6 `qualys_*` |
| [Salesforce](https://grclanker.com/docs/integrations/salesforce/) | 6 `salesforce_*` |
| [ServiceNow](https://grclanker.com/docs/integrations/servicenow/) | 6 `servicenow_*` |
| [Slack](https://grclanker.com/docs/integrations/slack/) | 7 `slack_*` |
| [Snowflake](https://grclanker.com/docs/integrations/snowflake/) | 6 `snowflake_*` |
| [Splunk](https://grclanker.com/docs/integrations/splunk/) | 7 `splunk_*` |
| [Sumo Logic](https://grclanker.com/docs/integrations/sumologic/) | 6 `sumologic_*` |
| [Tenable](https://grclanker.com/docs/integrations/tenable/) | 6 `tenable_*` |
| [Vanta Auditor API](https://grclanker.com/docs/integrations/vanta/) | 3 `vanta_*` |
| [Veracode](https://grclanker.com/docs/integrations/veracode/) | 7 `veracode_*` |
| [Webex](https://grclanker.com/docs/integrations/webex/) | 5 `webex_*` |
| [Zendesk](https://grclanker.com/docs/integrations/zendesk/) | 6 `zendesk_*` |
| [Zoom](https://grclanker.com/docs/integrations/zoom/) | 5 `zoom_*` |
| [Zscaler](https://grclanker.com/docs/integrations/zscaler/) | 5 `zscaler_*` |

The Google Workspace CLI operator bridge (`gws_ops_*`) shells out to an installed [`gws`](https://github.com/googleworkspace/cli) binary. The Google Workspace tools (`gws_*`) call the APIs directly.

### Reference data

These five families are the other 29 domain tools. They are not tenant integrations.

| Family | Tools | Guide |
| --- | --- | --- |
| CMVP | 4 `cmvp_*` | [Tool catalog](https://grclanker.com/docs/tools/catalog/) |
| KEV / EPSS | 4 `kevs_*` | [Tool catalog](https://grclanker.com/docs/tools/catalog/) |
| FedRAMP | 10 `fedramp_*` | [FedRAMP](https://grclanker.com/docs/fedramp/) |
| OSCAL | 7 `oscal_*` | [OSCAL workspaces](https://grclanker.com/docs/guides/oscal-workspaces/) |
| SCF | 4 `scf_*` | [SCF crosswalks](https://grclanker.com/docs/guides/scf-crosswalks/) |

212 platform tools and 29 reference tools are the 241 domain tools.

## Compute backends

The default backend is `host`, the local shell. `grclanker setup --compute <kind>` saves a preference. For one run, put `--compute <kind>` on a workflow command, a quoted prompt, `env smoke-test`, or `env exec`. Examples: `grclanker investigate --compute docker` and `grclanker env smoke-test --compute host`. `grclanker --compute docker` is an unknown command. `env doctor` and `env list` ignore the flag.

| Kind | State | What runs there |
| --- | --- | --- |
| `host` | shipped | The local shell. |
| `sandbox-runtime` | shipped | `bash`, `grep`, and `find` in the sandbox. `read`, `write`, `edit`, and `ls` stay local and follow the same filesystem policy. |
| `docker` | shipped | `bash`, `read`, `write`, `edit`, `ls`, `grep`, and `find` in a local container. |
| `parallels-vm` | shipped | Those same seven tools, in a disposable Parallels sandbox. grclanker prefers a dedicated template and falls back to cloning a stopped base VM. It attaches the repo share. |
| `modal` | shipped | One-shot `bash`. File tools stay on the local workspace. |
| `runpod-pod` | shipped | The seven tools over SSH, on a pod you already own. grclanker copies the repo's tracked files into that pod. |
| `runpod-serverless` | shipped | One-shot `bash`. File tools stay on the local workspace. |
| `vercel-sandbox`, `cloudflare-sandbox` | reserved | A request for either kind fails immediately. |

`sandbox-runtime` reads `~/.grclanker/sandbox.json`, then `.grclanker/sandbox.json` in the current directory. The project file wins. `GRCLANKER_HOME` moves the home directory off `~/.grclanker`.

`grclanker env list` shows which kinds this machine can run. `env doctor` checks the saved backend. `env smoke-test` checks file tools and backend-native search. The [compute backends](https://grclanker.com/docs/getting-started/compute-backends/) page is the full matrix.

## Cursor Agent SDK

From a source checkout, the same 241 domain tools can run as a Cursor Agent SDK agent. The project is `cli/agent-sdk/`, an adapter over the bundled extension, built on [`@cursor/bdk`](https://www.npmjs.com/package/@cursor/bdk). It does not expose `bash`, `read`, `write`, `edit`, `ls`, `find`, or `grep`. The Cursor harness supplies its own shell and file tools.

199 tools declare `effect: "read"`. The other 42 write files (exports, generators, the Google Workspace operator evidence collector, and OSCAL workspace commands) and wait for a person to approve a model-initiated call.

`@cursor/bdk` is a CLI devDependency. `npm --prefix cli ci` installs it:

```bash
npm --prefix cli run agent-sdk:validate
npm --prefix cli run agent-sdk:info
npm --prefix cli run agent-sdk:call -- kevs_search --input '{"query":"CVE-2021-44228"}'
```

`validate`, `info`, and `call` need no Cursor credential. Model turns (`agent-sdk:dev`, `agent-sdk:run`) need one: run `npx bdk login` inside `cli/`, or export `CURSOR_API_KEY`. See [Cursor Agent SDK](https://grclanker.com/docs/getting-started/agent-sdk/).

## Flue

The release bundle can run the same 241 domain tools, the four workflow prompts, and the `auditor` and `verifier` personas under the [Flue Framework](https://flueframework.com/).

```bash
grclanker flue run --message "Is CVE-2021-44228 in the CISA KEV catalog?"
```

From a checkout, on Node.js 22.19 or newer, run the official CLI from `cli/`:

```bash
cd cli
npm ci
npx flue run flue/agent.ts --message "Is CVE-2021-44228 in the CISA KEV catalog?"
```

`@flue/cli` is a devDependency so it shares this repo's `@flue/runtime`. A separately downloaded `npx @flue/cli` loads a second runtime and fails.

`GRCLANKER_FLUE_MODEL` sets the `provider/model` specifier. Without it, Flue reuses the `grclanker setup` choice, or `anthropic/claude-sonnet-4-6` when setup has not chosen one. Hosted provider API keys come from the environment. `GRCLANKER_FLUE_SANDBOX=none` turns off Flue's local file and shell sandbox. Pi compute backends do not apply here.

Flue stores conversations verbatim in `~/.grclanker/flue/conversations.db`, including raw tool arguments and credentials. Pass `--db <path>` or `--db :memory:` to change that. Use `:memory:` in CI. See [Flue runtime](https://grclanker.com/docs/getting-started/flue-runtime/).

## Skills only

User-scoped Codex skill, into `~/.codex/skills/grclanker/`:

```bash
curl -fsSL https://grclanker.com/install-skills | bash
```

Repo-local skill, into `.agents/skills/grclanker/` under the current directory:

```bash
curl -fsSL https://grclanker.com/install-skills | bash -s -- --repo
```

Windows PowerShell (best effort):

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://grclanker.com/install-skills.ps1 | iex"
```

These installers download `skills/grclanker/SKILL.md` from `main`. They do not install the CLI.

## Specs

The repo has 35 specs in [`specs/`](specs/). Browse them at [grclanker.com/specs](https://grclanker.com/specs/), or fetch one raw file:

```bash
curl -O https://raw.githubusercontent.com/ethanolivertroy/grclanker/main/specs/aws-sec-inspector.spec.md
```

A release bundle does not include `specs/`. From a source checkout, start grclanker at the repo root and give it a spec path. See [Using specs as inputs](https://grclanker.com/docs/specs/using-specs-as-inputs/).

## Release bundles

The installers look for these GitHub release assets, plus `SHA256SUMS.txt`:

- `grclanker-<version>-darwin-arm64.tar.gz`
- `grclanker-<version>-darwin-x64.tar.gz`
- `grclanker-<version>-linux-arm64.tar.gz` (glibc)
- `grclanker-<version>-linux-x64.tar.gz` (glibc)
- `grclanker-<version>-win32-arm64.zip`
- `grclanker-<version>-win32-x64.zip`

A local archive prints a warning and installs without verifying when no `SHA256SUMS.txt` sits beside it. When that file is present, a missing entry, a digest that is not SHA-256, or a mismatch aborts the install, and the shell installer also aborts if neither `sha256sum` nor `shasum` is available.

Build them from a checkout:

```bash
cd cli
npm install
npm run build:bundle -- --all
```

`build:bundle` packages Node.js 24.22.0. `GRCLANKER_NODE_VERSION` overrides that. Artifacts and `SHA256SUMS.txt` land in `cli/release/`. Drop `--all` to build only the host platform, or pass `--target <platform-arch>`. `--output-dir <dir>` changes the destination.

## Contributing

Bugs and feature requests use the [issue templates](.github/ISSUE_TEMPLATE/). Repository layout, commands, and how to add an integration are in [AGENTS.md](AGENTS.md). The short contributor path is [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Read [SECURITY.md](SECURITY.md) before you report a vulnerability. Do not open a public issue for one.

## License

grclanker is licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for attribution.

Built by [Ethan Troy](https://ethantroy.dev).
