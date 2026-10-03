---
title: What's New
description: What the next grclanker release contains, and what shipped in v0.0.1.
---

## Next release (unreleased)

Everything in this section is on the `main` branch and is not in the `v0.0.1` bundle. The one-line installer still ships `v0.0.1` until the next release is published. To run this work today, build from source with Node.js 22.19 or newer:

```bash
git clone https://github.com/ethanolivertroy/grclanker.git
cd grclanker
npm --prefix cli ci
npm --prefix cli run build
node cli/bin/grclanker.js tools
```

`grclanker tools` should report `241 domain tools + 7 compute backend tools`. See [Installation](/docs/getting-started/installation/#install-from-source) for linking and bundle builds.

### Tools and integrations

- 241 domain tools, up from 8 in `v0.0.1`. The [tool catalog](/docs/tools/catalog/) lists them by domain.
- 35 vendor integrations with native checks, assessments, or evidence exports, each with an [integration guide](/docs/integrations/aws/):
  - Cloud: AWS, Azure, Google Cloud, Oracle Cloud Infrastructure, Cloudflare
  - Identity: Okta, Duo, Google Workspace, and the Google Workspace CLI operator bridge
  - Collaboration and business apps: Slack, Zoom, Webex, Box, Zendesk, Salesforce, ServiceNow, KnowBe4
  - Security and network: CrowdStrike Falcon, Palo Alto Networks, Zscaler
  - Vulnerability and application security: Qualys, Tenable, Veracode
  - Monitoring and operations: Datadog, New Relic, Splunk, Sumo Logic, Elastic, PagerDuty
  - Developer and data platforms: GitHub, LaunchDarkly, Ansible Automation Platform, MuleSoft Anypoint Platform, Snowflake
  - GRC platforms: Vanta audit export
- FedRAMP tools grounded in the official Consolidated Rules: source checks, rule, process, and KSI lookups, a readiness brief, artifact planning, ADS bundle generation, and a trust-center site generator. Generated [FedRAMP reference docs](/docs/fedramp/) track the 2026 rules.
- SCF control and crosswalk lookups, and trestle-backed OSCAL workspaces that create, import, and validate models and assemble SSPs.
- KEV search returns at most 50 results and says when it truncated, and KEV output includes the date of each EPSS score.

### CLI

- `grclanker "<prompt>"` sends a free-form prompt, and `grclanker investigate <subject>` (or `audit`, `assess`, `validate`) starts a workflow with its subject filled in. Inside a session, `/investigate <subject>` does the same.
- `--compute <kind>` picks a compute backend for one prompt or workflow run, and `grclanker setup --compute <kind>` saves a default. `--` passes the rest of the line through literally.
- New commands: `grclanker tools`, `grclanker flue run`, and `grclanker env list`.
- Runs on Pi 1.0: `@earendil-works/pi-coding-agent` and `@earendil-works/pi-ai` 1.0.0, up from 0.65 in `v0.0.1`. The terminal UI now opens fullscreen. To keep your terminal's normal scrollback, add `"tuiMode": "regular"` to `~/.grclanker/agent/settings.json`.

### Runtimes

- [Cursor Agent SDK](/docs/getting-started/agent-sdk/): a source-checkout project built on `@cursor/bdk`, Cursor's Bot Development Kit (formerly `@cursor/july`), that serves all 241 tools. 199 read-only tools run in dry-run sessions, the 42 writers wait for human approval, and credential arguments are redacted from validation and execution errors.
- [Flue Runtime](/docs/getting-started/flue-runtime/): `grclanker flue run` and the official Flue CLI run the same agent, prompts, and tools. Activity logs redact credential-shaped arguments, and the verifier subagent can check findings against the CMVP, KEV, EPSS, and SCF tools.
- [Compute backends](/docs/getting-started/compute-backends/): Modal, RunPod Pod, and RunPod Serverless join host, sandbox-runtime, Docker, and Parallels VM.

### Specs

- The repository holds 35 specs: one for every vendor integration except Vanta, plus one for the compute backends. v0.0.1 carried 32 `spec-only` roadmap specs with no native tools behind them.
- 11 specs are generated from the executable tool registry: AWS, Webex, Okta, Duo, Google Workspace, Slack, Zoom, Box, Zendesk, Salesforce, and ServiceNow. A generated shared integration contract sits beside them, and CI fails when a generated spec drifts from the code.
- Browse every spec at [/specs](/specs) or read [Using Specs as Inputs](/docs/specs/using-specs-as-inputs/).

### Security and hardening

- Error text is scrubbed of credential-shaped values before it reaches the model, including quoted, lowercase, escaped, flag, cookie, and letters-only Bearer forms.
- Pagination links on a different origin no longer receive credentials, and GitHub tokens go only to the configured GraphQL origin.
- Evidence exports redact credentials, capped pagination is marked truncated instead of complete, and malformed success responses from CrowdStrike and Webex are rejected instead of read as empty data.
- Evidence exporters allocate a new bundle path on each rerun instead of overwriting an earlier bundle, and Vanta exports stay isolated even when runs overlap. Duo bundles are written owner-only.
- Config files are read with a 1 MiB cap, FIFOs and devices are refused, and parse errors are built from fixed text so a malformed line cannot leak a credential.
- RunPod staging uploads only git-tracked files and never the `.env` family.
- Integration fixes: OCI Cloud Guard problems are parsed from the real response shape, Palo Alto honors `verify_tls` in config files, the Google Workspace operator bridge reports a partial bundle when `gws` lacks Alert Center, Zscaler reports explicitly configured files that are missing, and the default CMVP endpoint works again.
- Tool schemas now match what the runtime accepts: AWS and LaunchDarkly list arguments, the Salesforce inline JWT key, and Snowflake tuning inputs. A registry lint checks tool and parameter descriptions, and MuleSoft and Zendesk details no longer embed raw snapshots.

### Release and CI

- Release bundles for six platforms are reproducible: fixed archive timestamps and ordering, a strict `SHA256SUMS.txt` check, GitHub build provenance attestations, and a publisher that refuses to overwrite an existing release.
- Every pull request runs the CLI tests, TypeScript checks, the credential leak probe, the generated-spec drift check, Agent SDK registry validation, and the site build. Dependency review runs on pull requests, and Dependabot keeps pinned GitHub Actions current.
- The FedRAMP sync workflow pins its actions, drops persisted credentials, and runs the tests before it opens a pull request.

### Site and docs

- grclanker.com runs on Cloudflare Workers static assets, deployed by Workers Builds from `main`, with preview URLs on pull requests.
- The site serves canonical `grclanker.com` URLs and a sitemap, and its build fails on broken internal links.
- Accessibility fixes for WCAG 2.2 AA: focus handling in dialogs and the mobile menu, higher-contrast colors including the spec viewer, and screen reader announcements for search results and copy buttons.
- Install, runtime, workflow, and integration guides were corrected against the CLI, and the installers print source-build steps when no bundle fits your platform.

### License

- grclanker is licensed under the [Apache License 2.0](https://github.com/ethanolivertroy/grclanker/blob/main/LICENSE), with a [NOTICE](https://github.com/ethanolivertroy/grclanker/blob/main/NOTICE) file. v0.0.1 shipped without a license file.

### Requirements

- Source installs need Node.js 22.19 or newer, up from 20.19. The release bundle carries its own Node.js runtime.

Full history: [v0.0.1...main](https://github.com/ethanolivertroy/grclanker/compare/v0.0.1...main).

## v0.0.1 (April 6, 2026)

The first experimental prerelease.

- Bundled installers for macOS, Linux, and Windows (best effort), plus a skills-only installer.
- `grclanker setup` with an explicit local-first path (Ollama, with Gemma 4 as the example model) or a hosted provider, and no silent fallback between them.
- Four workflows: `/investigate`, `/audit`, `/assess`, and `/validate`. Workflows take their subject in the first message of the session.
- 8 tools: `cmvp_search_modules`, `cmvp_search_historical`, `cmvp_search_in_process`, `cmvp_get_module`, `kevs_search`, `kevs_recent`, `kevs_get_epss`, and `kevs_check_ransomware`.
- `grclanker env doctor`, `env smoke-test`, and `env exec` for the host, sandbox-runtime, Docker, and Parallels VM backends.
- Runtime state under `~/.grclanker/agent`.

[Release notes and bundles](https://github.com/ethanolivertroy/grclanker/releases/tag/v0.0.1).
