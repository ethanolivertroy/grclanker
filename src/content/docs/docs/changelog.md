---
title: What's New
description: What shipped in grclanker v0.1.1, v0.1.0, and v0.0.1.
---

## v0.1.1 (October 10, 2026)

A security and dependency update to `v0.1.0`. The tool surface is unchanged. Install or upgrade with:

```bash
curl -fsSL https://grclanker.com/install | bash
grclanker tools
```

`grclanker tools` still reports `241 domain tools + 7 compute backend tools`.

### Security

- CLI dependency updates clear 27 of 29 `npm audit` advisories (1 critical, 15 high, and 13 moderate before; 2 high after). The critical `shell-quote` command injection is gone (`shell-quote` 1.12.0), and so is the MCP SDK OAuth credential leak (`@modelcontextprotocol/sdk` 1.32.1). `undici` moves from 7.29.0 to 8.10.2.
- The 2 left are both `node-forge`: npm counts GHSA-86w9-cpqp-85rv once for `node-forge` and once for `@anthropic-ai/sandbox-runtime`, which pulls it in. No patched `node-forge` exists, and npm's only suggested fix downgrades sandbox-runtime to 0.0.50, so they stay until upstream ships a fix.
- Site build dependencies clear all 7 site `npm audit` advisories: Astro 7.3.7 on Vite 8.3.3, wrangler 4.148, and a `sharp` override for the librsvg advisory. These were build-time only, since the site is static.

### Runtimes

- Runs on Pi 1.1: `@earendil-works/pi-coding-agent` and `@earendil-works/pi-ai` 1.1.0, up from 1.0.0 in `v0.1.0`.
- The Flue runtime moves to 2.2.2. Flue no longer turns a `null` for an optional tool argument into `0`, `false`, or an empty string; it drops it, as the Pi CLI does.
- The [Cursor Agent SDK](/docs/getting-started/agent-sdk/) project moves to `@cursor/bdk` 0.2.21, up from 0.2.18. Its agent folder is now `cli/agent-sdk/bot/` instead of `cli/agent-sdk/agent/`, the layout the BDK docs use, and the root agent relies on the default local runtime instead of setting it. It still serves all 241 tools: 199 read-only and 42 approval-gated writers.
### Installer

- `grclanker.com/install` and `install.ps1` fall back to the `releases/latest` redirect when the GitHub API rate limit (60 requests an hour per IP) is used up. Before, the shell installer aborted with a misleading `Release bundle unavailable` and the PowerShell installer threw `API rate limit exceeded`, which shared NATs, CI runners, and corporate networks could hit.
- Both installers skip drafts and prereleases when they resolve the latest release, so a tag such as `v0.2.0-rc.1` never becomes the default install.
- The site serves the installers from `main`, so both fixes have been live since before this release.

### Release and CI

- Dependabot now opens weekly npm update PRs for the CLI and the site, not only for GitHub Actions. Minor and patch updates and security updates arrive as grouped PRs, and `@cursor/bdk` and Pi bumps arrive together in their own group for deliberate review.

### Docs and site

- The homepage screenshot shows the `v0.1.1` start screen.
- The [Flue Runtime](/docs/getting-started/flue-runtime/) page describes the new handling of `null` optional arguments.
- The CLI package description now describes the shipped CLI instead of the `v0.0.1` CMVP, KEV, and EPSS lookups.

### Upgrade notes

- Rerun the installer to upgrade. Settings and runtime state under `~/.grclanker/agent` are kept.
- Source checkouts should rerun `npm --prefix cli ci`, since the CLI lockfile changed.
- If you drive grclanker through Flue and pass `null` for optional arguments, expect the argument to be omitted rather than coerced.

Full history: [v0.1.0...v0.1.1](https://github.com/ethanolivertroy/grclanker/compare/v0.1.0...v0.1.1). [Release notes and bundles](https://github.com/ethanolivertroy/grclanker/releases/tag/v0.1.1).

## v0.1.0 (October 3, 2026)

The first full release, and the first bundle since `v0.0.1` (an experimental prerelease). The one-line installer now ships everything below. Install or upgrade with:

```bash
curl -fsSL https://grclanker.com/install | bash
grclanker tools
```

`grclanker tools` should report `241 domain tools + 7 compute backend tools`. See [Installation](/docs/getting-started/installation/) for Windows, pinned versions, and source checkouts.

### Tools and integrations

- 241 native domain tools, up from 8 in `v0.0.1`. The [tool catalog](/docs/tools/catalog/) lists them by domain.
- Two batches of spec-driven integrations: batch 1 added Box, CrowdStrike Falcon, Datadog, Elastic, KnowBe4, LaunchDarkly, MuleSoft, PagerDuty, Palo Alto Networks, Salesforce, ServiceNow, Snowflake, Splunk, Sumo Logic, Tenable, Veracode, and Zendesk, and batch 2 added New Relic, Qualys, and Zscaler.
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
- The session header counts the tools the agent can call (248: 241 domain tools and 7 compute tools).
- The footer status line separates its segments with ` · `, so the compute backend and the tool count no longer run together (`compute: bash runs directly on the local host shell · 241 domain tools ready`).

### Runtimes

- [Cursor Agent SDK](/docs/getting-started/agent-sdk/): a source-checkout project built on `@cursor/bdk`, Cursor's Bot Development Kit (formerly `@cursor/july`), that serves all 241 tools. 199 read-only tools run in dry-run sessions, the 42 writers wait for human approval, and credential arguments are redacted from validation and execution errors.
- [Flue Runtime](/docs/getting-started/flue-runtime/): `grclanker flue run` and the official Flue CLI run the same agent, prompts, and tools. Activity logs redact credential-shaped arguments, and the verifier subagent can check findings against the CMVP, KEV, EPSS, and SCF tools.
- [Compute backends](/docs/getting-started/compute-backends/): Modal, RunPod Pod, and RunPod Serverless join host, sandbox-runtime, Docker, and Parallels VM.

### Specs

- The repository holds 35 specs: one for every vendor integration except Vanta, plus one for the compute backends. v0.0.1 carried 32 `spec-only` roadmap specs with no native tools behind them.
- 17 specs are generated from the executable tool registry: AWS and Webex first, then two batches, identity and collaboration (Okta, Duo, Google Workspace, Slack, Zoom, Box, Zendesk, Salesforce, ServiceNow) and cloud and network (Azure, Google Cloud, Oracle Cloud Infrastructure, Cloudflare, Palo Alto Networks, Zscaler). A generated shared integration contract sits beside them, and CI fails when a generated spec drifts from the code.
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

- Release bundles for six platforms (macOS, Linux, and Windows, each on arm64 and x64) are reproducible: fixed archive timestamps and ordering, a strict `SHA256SUMS.txt` check, GitHub build provenance attestations, and a publisher that refuses to overwrite an existing release.
- A plain version tag such as `v0.1.0` publishes a full release marked as the latest; a tag with a suffix such as `v0.2.0-rc.1` still publishes an experimental prerelease.
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

Full history: [v0.0.1...v0.1.0](https://github.com/ethanolivertroy/grclanker/compare/v0.0.1...v0.1.0). [Release notes and bundles](https://github.com/ethanolivertroy/grclanker/releases/tag/v0.1.0).

## v0.0.1 (April 6, 2026)

The first experimental prerelease.

- Bundled installers for macOS, Linux, and Windows (best effort), plus a skills-only installer.
- `grclanker setup` with an explicit local-first path (Ollama, with Gemma 4 as the example model) or a hosted provider, and no silent fallback between them.
- Four workflows: `/investigate`, `/audit`, `/assess`, and `/validate`. Workflows take their subject in the first message of the session.
- 8 tools: `cmvp_search_modules`, `cmvp_search_historical`, `cmvp_search_in_process`, `cmvp_get_module`, `kevs_search`, `kevs_recent`, `kevs_get_epss`, and `kevs_check_ransomware`.
- `grclanker env doctor`, `env smoke-test`, and `env exec` for the host, sandbox-runtime, Docker, and Parallels VM backends.
- Runtime state under `~/.grclanker/agent`.

[Release notes and bundles](https://github.com/ethanolivertroy/grclanker/releases/tag/v0.0.1).
