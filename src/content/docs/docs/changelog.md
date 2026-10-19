---
title: What's New
description: "The grclanker changelog: what shipped in v0.1.3, v0.1.2, v0.1.1, v0.1.0, and v0.0.1."
---

## v0.1.3 (October 19, 2026)

Adds an experimental, opt-in durable mode, moves the CLI to Pi 1.3.0 and the release bundles to Node.js 24.22.0, makes exports atomic, and fixes checks that could pass on incomplete evidence. The tool surface is unchanged. Install or upgrade with:

```bash
curl -fsSL https://grclanker.com/install | bash
grclanker tools
```

`grclanker tools` still reports `241 domain tools + 7 compute backend tools`.

### Durable mode (experimental, opt-in)

- [`grclanker durable`](/docs/getting-started/durable-runtime/) runs the GRC agent under Pi Durable 1.3.0, which writes the conversation and each tool round to SQLite as the run goes. A run that crashes, is killed, or is stopped with Ctrl-C can be resumed instead of started over.
- It is opt-in: nothing changes unless you run it. The interactive CLI, the Cursor Agent SDK project, and the Flue runtime do not use it. `run` and `resume` print `grclanker durable (experimental)` to stderr, the terminal app shows it at the top of the screen, and the `--json` report carries `"experimental": true`. Commands, output, and the session format may change between releases.
- `grclanker durable run --message <text>` starts or continues a session. Add `--session <id>` to name it, `--request-id <id>` to make the request idempotent, `--model <provider/model>` to pick a model, and `--json` for a report.
- `grclanker durable resume --session <id>` finishes whatever an earlier process left unsettled. Finished tool calls keep their results, interrupted read-only tools run again, and an interrupted tool that can write is reported and never rerun. Rerunning `run` with a settled `--request-id` returns the stored answer without calling the model or any tool.
- [`grclanker durable tui`](/docs/getting-started/durable-runtime/#terminal-app) opens a session in a terminal app adapted from Pi's experimental durable app, with grclanker's banner, theme, and assessment summary. A session moves between the app, `run`, and `resume`, one process at a time.
- Each session is a directory under `~/.grclanker/durable/sessions/<id>/`, guarded by a lock the operating system drops on any exit. The model comes from `--model`, then `GRCLANKER_DURABLE_MODEL`, then the `grclanker setup` choice.
- Only the 241 domain tools are available. There are no compute backends, workflow prompts, skills, or subagents. The session database keeps the whole conversation, so treat `~/.grclanker/durable/sessions/` like a credential store. See [Limitations](/docs/getting-started/durable-runtime/#limitations).

### Exports and stopped runs

- Every `*_export_*` tool, `gws_ops_collect_evidence_bundle`, `fedramp_generate_ads_bundle`, and `fedramp_generate_ads_site` build their bundle in a hidden staging directory under the output root and move it into place once every file is written. An export that fails, is killed, or is stopped no longer leaves a half-written bundle. Output paths, names, rerun suffixes (`-2`, `-3`), and contents are unchanged. The FedRAMP catalog cache is replaced in one rename.
- Every domain tool honors the abort signal its runtime passes. Stopping a durable command or closing the terminal app cancels in-flight API requests, ends retry and rate-limit waits, and kills child processes: `az` and `gcloud` credential lookups, `gws`, and `trestle`. A collector ends at the read the abort interrupted, a worker pool hands out no further item, and a ZIP archive stops at once. An export stopped partway writes nothing under its output root.
- Runs that are not stopped behave and write exactly as before.

### Assessments

- [Cloudflare](/docs/integrations/cloudflare/): six checks no longer pass on evidence that only supports a review. CF-IAM-02 counts every permission group whose name does not end in Read as write-capable, so groups such as Cache Purge count. CF-IAM-03 warns on members whose `two_factor_authentication_enabled` is not `true`. CF-IAM-06 warns on active tokens with a future expiry that were never used. CF-TRF-04 warns on any failed audit action. CF-TRF-05 warns on allow-mode IP access rules. CF-TRF-06 no longer counts `quarantine` as blocking.
- [Zscaler](/docs/integrations/zscaler/): a check that passed on a truncated ZIA inventory now warns with the pages seen versus the total (ZS-03, ZS-04, ZS-05, ZS-07, ZS-14, ZS-16, ZS-17, ZS-20, and ZS-25). `evidence.partial_inventory` is true whenever an inventory a finding depends on is truncated, and fail and manual findings name truncated inventories too.
- [Vanta](/docs/integrations/vanta/): a missing `endCursor`, a repeated cursor, a 404 after an earlier page, or the 500-page cap fails the list call instead of returning a partial list. Evidence URL pagination failures go to `_errors.log`.
- [CrowdStrike](/docs/integrations/crowdstrike/): when the user details lookup returns fewer users than the UUIDs sent, the user list is marked partial and CS-16 and CS-17 cap at warn.
- [KnowBe4](/docs/integrations/knowbe4/): a list stops at a page holding an entry that is not a JSON object and is marked partial, with the page named, instead of ending early as complete.
- [Snowflake](/docs/integrations/snowflake/): SNOWFLAKE-02 warns and names the policies when some network policies have an empty `ALLOWED_IP_LIST`.
- [Zoom](/docs/integrations/zoom/): ZOOM-COLLAB-01 warns when a non-empty trusted-domain list is truncated.
- [MuleSoft](/docs/integrations/mulesoft/), [PagerDuty](/docs/integrations/pagerduty/), [New Relic](/docs/integrations/newrelic/), and [Salesforce](/docs/integrations/salesforce/): a 200 response that omits its documented collection fails the read. A real empty array is still an empty inventory.
- [KEV / EPSS](/docs/integrations/kevs/): `kevs_recent` and `kevs_check_ransomware` treat a `limit` below 1 as the default (10 and 20), and `kevs_recent` treats a negative `days` as the default 30, instead of reporting no matches.
- FedRAMP process search returns a process with both 20x and Rev5 requirement buckets under a Rev5 filter.

### Runtimes

- The CLI moves to Pi 1.3.0 (`@earendil-works/pi-coding-agent` and `@earendil-works/pi-ai`), up from 1.1.0. Malformed final tool-call JSON now fails validation instead of running with partial fields.
- Release bundles ship Node.js 24.22.0 LTS, up from 22.23.3, and CI runs on Node 24. Source checkouts still need Node.js 22.19 or newer.
- The [Flue runtime](/docs/getting-started/flue-runtime/) moves to Flue 2.3.0, up from 2.2.2.
- The [`sandbox-runtime` backend](/docs/getting-started/compute-backends/#sandbox-runtime) moves to sandbox-runtime 0.0.79, up from 0.0.78. Deny rules apply through folder names that contain glob characters, Linux write-denies names such as `.bashrc` and `.git/config` one level below the working directory, and a sandboxed command's first network call is no longer sometimes refused on Linux.
- The [Cursor Agent SDK](/docs/getting-started/agent-sdk/) project stays on `@cursor/bdk` 0.2.26 and still serves all 241 tools: 199 read-only and 42 approval-gated writers.

### Security

- [Flue](/docs/getting-started/flue-runtime/#output-and-redaction) tool errors, both returned and thrown, are scrubbed of credential arguments before the model sees them. The runner scrubs the final reply and failure text of secrets from tool inputs, including encoded forms, and a resumed `flue run --id` rebuilds that list from the stored conversation.
- Vanta authentication and API errors redact the client id, client secret, and access token before the text is shortened, and an off-HTTPS download redirect records only the destination host and path.
- A malformed `settings.json` or `models.json`, or JSON that is not an object, is left on disk and reported with a fixed error that does not quote the file. Local setup reads `models.json` before writing either file, and a broken `sandbox.json` fails closed instead of dropping your deny rules. `GRCLANKER_HOME` is refused when it reaches `.pi` through a symlink.
- OSCAL workspace names must be a single path segment. FedRAMP bundle writes check the destination before creating directories. RunPod pod staging skips and refuses paths that leave the repository through a symlink, and refuses `..` in a plan.
- The installers stop when an official download's `SHA256SUMS.txt` cannot be fetched, has no entry for the archive, is not a SHA-256 digest, or does not match. Local bundle selection compares versions itself, so macOS's BSD `sort` no longer aborts the install. Linux musl hosts get source-build instructions, and Windows zip extraction rejects `..`, absolute, and drive-letter entries before it replaces an install.
- `npm audit` is unchanged from `v0.1.2`. The CLI has 2 high advisories, both GHSA-86w9-cpqp-85rv in `node-forge`, counted once directly and once through `@anthropic-ai/sandbox-runtime`. No patched `node-forge` exists yet. The site has none.

### Docs and site

- Spec pages open as documents, set like docs pages with section links and an "On this page" list. The raw markdown is on a Markdown source tab. Each spec links its setup guide, and each guide links back.
- 63 vendor reference links on 9 pages that opened an error page now point at the page they name.
- Docs search finds body text, hyphenated IDs such as `SRG-APP-000148`, and the identifiers integration and FedRAMP pages mention. It ranks title matches first and corrects one-letter typos.
- New guides: [FedRAMP readiness](/docs/guides/fedramp-readiness/), [OSCAL workspaces](/docs/guides/oscal-workspaces/), [SCF crosswalks](/docs/guides/scf-crosswalks/), [KEV / EPSS](/docs/integrations/kevs/), and the [Durable Runtime](/docs/getting-started/durable-runtime/). Every integration page has a Run it section, and evidence-handling internals move to a closing section.
- The docs landing page maps every docs section, the sidebar is grouped, and headings have section links. Quick Start offers the hosted path, and Compute Backends leads with choosing a backend.
- Docs and spec pages print black on white without the site's navigation. Tables too wide for the docs column stack on desktop, as they already did on phones.
- Keyboard and screen reader fixes: a skip link to the article, focus kept clear of the sticky header, named navigation controls, announced search results, and fixed contrast.
- Site images are regenerated in the inked Frappe style, and docs pages no longer download hero images they never show.

### Upgrade notes

- Rerun the installer to upgrade. Settings and runtime state under `~/.grclanker/agent` are kept.
- Source checkouts should rerun `npm --prefix cli ci`, since the CLI lockfile changed.
- Some findings change: expect `warn` where `v0.1.2` reported `pass` on the incomplete Cloudflare, Zscaler, CrowdStrike, KnowBe4, Snowflake, and Zoom evidence above, and a failed read where Vanta pagination is incomplete or a MuleSoft, PagerDuty, New Relic, or Salesforce listing omits its collection.
- **Durable sessions and the next pi-durable.** This release pins pi-durable 1.3.0. The next pi-durable release migrates a SQLite session to schema version 2 when it opens it, and pi-durable 1.3.0 or earlier cannot open a migrated session. Once a later grclanker release ships that version, a durable session it opens can no longer be opened by `v0.1.3`, so downgrading would strand it. If you might go back, copy `~/.grclanker/durable/sessions/` before opening your sessions with the newer release.

Full history: [v0.1.2...v0.1.3](https://github.com/ethanolivertroy/grclanker/compare/v0.1.2...v0.1.3). [Release notes and bundles](https://github.com/ethanolivertroy/grclanker/releases/tag/v0.1.3).

## v0.1.2 (October 17, 2026)

Updates the FedRAMP tools to the October 2026 Consolidated Rules and moves the `sandbox-runtime` backend to sandbox-runtime 0.0.78. The tool surface is unchanged. Install or upgrade with:

```bash
curl -fsSL https://grclanker.com/install | bash
grclanker tools
```

`grclanker tools` still reports `241 domain tools + 7 compute backend tools`.

### FedRAMP

- The [FedRAMP docs](/docs/fedramp/) are regenerated from Consolidated Rules `2026.10.13.01`, published October 13. `FRC-CSX-MOT` is gone, leaving 245 requirements.
- The CLI fetches the official rules at runtime, so `v0.1.1` already returned the October rule text. The tool changes below are new.
- `fedramp_get_requirement` shows each requirement's notification forms, mapped Rev5 controls, upstream note, and full update history. Before, it showed only the newest update.
- `fedramp_search_frmr` matches control IDs in requirement search, as KSI search already did, so `ra-5` finds the vulnerability detection and response rules.
- `fedramp_generate_ads_bundle` and `fedramp_generate_ads_site` add the `FRC-CSO-JSN` hosting requirements to their READMEs and approval checklist: `Content-Type: application/json`, `X-Content-Type-Options: nosniff`, and CORS for cross-origin reads.
- The FedRAMP cache schema moves from version 2 to 3. The first run after upgrading discards older caches instead of serving them for up to 24 hours.
- The generated FedRAMP pages list each requirement's notification forms, mapped Rev5 controls, and full update history. Their paragraphs no longer run together, and each page has a single title heading.

### Compute backends

- The `sandbox-runtime` backend moves to sandbox-runtime 0.0.78, up from 0.0.61. On Linux, 0.0.78 mounts placeholders over protected files and folders that do not exist yet, such as `.bashrc`, `.gitconfig`, and `.vscode`, for every sandboxed command.
  - `grep` no longer fails when ripgrep skipped only those placeholders. A bad regex, a missing `rg`, or an unreadable search path still fails.
  - `find` leaves the placeholders out of its results.
  - The local backend releases each sandboxed command when it exits, on success, failure, or timeout, so sandbox-runtime removes its placeholders from the project.
- `grclanker env exec` and `grclanker env smoke-test` on `sandbox-runtime` exit when done. Before, a successful run printed its result and then never exited.

### Runtimes

- The [Cursor Agent SDK](/docs/getting-started/agent-sdk/) project moves to `@cursor/bdk` 0.2.26, up from 0.2.21. `zod` is now a CLI devDependency, because bdk 0.2.24 made it a peer dependency. The project still serves all 241 tools: 199 read-only and 42 approval-gated writers.
- Pi 1.1 and Flue 2.2.2 are unchanged.

### Docs and site

- grclanker.com moves from Astro to a static Next.js site, with Fumadocs rendering the docs. URLs are unchanged.
- Search covers every docs page, every spec, and the CLI, Specs, and About pages, with results labeled Docs, Spec, or Page. Press `/` or Cmd/Ctrl+K to open it.
- Docs body text uses a sans-serif font. Headings, labels, and code stay in Berkeley Mono.
- On phones, wide tables stack into labeled cards and long inline code wraps.
- The hand-written docs are rewritten in shorter paragraphs, with the same commands, tool names, and facts. Fifteen integration pages now say exactly when an unreadable endpoint yields `manual` and when it only caps a `pass` at `warn`.

### Security

- `npm audit` is unchanged from `v0.1.1`. The CLI has 2 high advisories, both GHSA-86w9-cpqp-85rv in `node-forge`, counted once directly and once through `@anthropic-ai/sandbox-runtime`. No patched `node-forge` exists yet. The site has none.

### Upgrade notes

- Rerun the installer to upgrade. Settings and runtime state under `~/.grclanker/agent` are kept.
- Source checkouts should rerun `npm --prefix cli ci`, since the CLI lockfile changed.
- On the [`sandbox-runtime` backend](/docs/getting-started/compute-backends/#sandbox-runtime), an allow-listed hostname that resolves to a loopback, link-local, or cloud metadata address, or to one of your machine's own addresses, is now refused. Intranet hostnames on private ranges still work. To allow a refused address, add the IP address itself to `network.allowedDomains`.

Full history: [v0.1.1...v0.1.2](https://github.com/ethanolivertroy/grclanker/compare/v0.1.1...v0.1.2). [Release notes and bundles](https://github.com/ethanolivertroy/grclanker/releases/tag/v0.1.2).

## v0.1.1 (October 10, 2026)

A security and dependency update to `v0.1.0`. The tool surface is unchanged. Install or upgrade with:

```bash
curl -fsSL https://grclanker.com/install | bash
grclanker tools
```

`grclanker tools` still reports `241 domain tools + 7 compute backend tools`.

### Security

- CLI dependency updates clear 27 of 29 `npm audit` advisories, from 1 critical, 15 high, and 13 moderate before to 2 high after.
  - The critical `shell-quote` command injection is gone (`shell-quote` 1.12.0).
  - The MCP SDK OAuth credential leak is also gone (`@modelcontextprotocol/sdk` 1.32.1).
  - `undici` moves from 7.29.0 to 8.10.2.
- The 2 left are both `node-forge`: npm counts GHSA-86w9-cpqp-85rv once for `node-forge` and once for `@anthropic-ai/sandbox-runtime`, which pulls it in. No patched `node-forge` exists, and npm's only suggested fix downgrades sandbox-runtime to 0.0.50, so they stay until upstream ships a fix.
- Site build dependencies clear all 7 site `npm audit` advisories: Astro 7.3.7 on Vite 8.3.3, wrangler 4.148, and a `sharp` override for the librsvg advisory. These were build-time only, since the site is static.

### Runtimes

- Runs on Pi 1.1: `@earendil-works/pi-coding-agent` and `@earendil-works/pi-ai` 1.1.0, up from 1.0.0 in `v0.1.0`.
- The Flue runtime moves to 2.2.2. Flue no longer turns a `null` for an optional tool argument into `0`, `false`, or an empty string. It drops the argument, as the Pi CLI does.
- The [Cursor Agent SDK](/docs/getting-started/agent-sdk/) project moves to `@cursor/bdk` 0.2.21, up from 0.2.18.
  - Its agent folder is now `cli/agent-sdk/bot/` instead of `cli/agent-sdk/agent/`, the layout the BDK docs use.
  - The root agent relies on the default local runtime instead of setting it.
  - The project still serves all 241 tools: 199 read-only and 42 approval-gated writers.

### Installer

- `grclanker.com/install` and `install.ps1` fall back to the `releases/latest` redirect when the GitHub API rate limit (60 requests an hour per IP) is used up. Shared NATs, CI runners, and corporate networks could hit the rate limit. Before, the shell installer aborted with a misleading `Release bundle unavailable`, and the PowerShell installer threw `API rate limit exceeded`.
- Both installers skip drafts and prereleases when they resolve the latest release, so a tag such as `v0.2.0-rc.1` never becomes the default install.
- The site serves the installers from `main`, so both fixes have been live since before this release.

### Release and CI

- Dependabot now opens weekly npm update PRs for the CLI and the site, not only for GitHub Actions. Minor and patch updates and security updates arrive as grouped PRs. `@cursor/bdk` and Pi bumps arrive together in their own group for deliberate review.

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
- Two batches of spec-driven integrations:
  - Batch 1 added Box, CrowdStrike Falcon, Datadog, Elastic, KnowBe4, LaunchDarkly, MuleSoft, PagerDuty, Palo Alto Networks, Salesforce, ServiceNow, Snowflake, Splunk, Sumo Logic, Tenable, Veracode, and Zendesk.
  - Batch 2 added New Relic, Qualys, and Zscaler.
- 35 vendor integrations with native checks, assessments, or evidence exports, each with an [integration guide](/docs/integrations/aws/):
  - Cloud: AWS, Azure, Google Cloud, Oracle Cloud Infrastructure, Cloudflare
  - Identity: Okta, Duo, Google Workspace, and the Google Workspace CLI operator bridge
  - Collaboration and business apps: Slack, Zoom, Webex, Box, Zendesk, Salesforce, ServiceNow, KnowBe4
  - Security and network: CrowdStrike Falcon, Palo Alto Networks, Zscaler
  - Vulnerability and application security: Qualys, Tenable, Veracode
  - Monitoring and operations: Datadog, New Relic, Splunk, Sumo Logic, Elastic, PagerDuty
  - Developer and data platforms: GitHub, LaunchDarkly, Ansible Automation Platform, MuleSoft Anypoint Platform, Snowflake
  - GRC platforms: Vanta audit export
- FedRAMP tools grounded in the official Consolidated Rules:
  - Source checks
  - Rule, process, and KSI lookups
  - A readiness brief
  - Artifact planning
  - ADS bundle generation
  - A trust-center site generator
- Generated [FedRAMP reference docs](/docs/fedramp/) track the 2026 rules.
- SCF control and crosswalk lookups, and trestle-backed OSCAL workspaces that create, import, and validate models and assemble SSPs.
- KEV search returns at most 50 results and says when it truncated, and KEV output includes the date of each EPSS score.

### CLI

- `grclanker "<prompt>"` sends a free-form prompt. `grclanker investigate <subject>` (or `audit`, `assess`, `validate`) starts a workflow with its subject filled in. Inside a session, `/investigate <subject>` does the same.
- `--compute <kind>` picks a compute backend for one prompt or workflow run. `grclanker setup --compute <kind>` saves a default. `--` passes the rest of the line through literally.
- New commands: `grclanker tools`, `grclanker flue run`, and `grclanker env list`.
- Runs on Pi 1.0: `@earendil-works/pi-coding-agent` and `@earendil-works/pi-ai` 1.0.0, up from 0.65 in `v0.0.1`. The terminal UI now opens fullscreen. To keep your terminal's normal scrollback, add `"tuiMode": "regular"` to `~/.grclanker/agent/settings.json`.
- The session header counts the tools the agent can call (248: 241 domain tools and 7 compute tools).
- The footer status line separates its segments with ` · `, so the compute backend and the tool count no longer run together (`compute: bash runs directly on the local host shell · 241 domain tools ready`).

### Runtimes

- [Cursor Agent SDK](/docs/getting-started/agent-sdk/): a source-checkout project built on `@cursor/bdk`, Cursor's Bot Development Kit (formerly `@cursor/july`), that serves all 241 tools.
  - 199 read-only tools run in dry-run sessions.
  - The 42 writers wait for human approval.
  - Credential arguments are redacted from validation and execution errors.
- [Flue Runtime](/docs/getting-started/flue-runtime/): `grclanker flue run` and the official Flue CLI run the same agent, prompts, and tools. Activity logs redact credential-shaped arguments. The verifier subagent can check findings against the CMVP, KEV, EPSS, and SCF tools.
- [Compute backends](/docs/getting-started/compute-backends/): Modal, RunPod Pod, and RunPod Serverless join host, sandbox-runtime, Docker, and Parallels VM.

### Specs

- The repository holds 35 specs: one for every vendor integration except Vanta, plus one for the compute backends. v0.0.1 carried 32 `spec-only` roadmap specs with no native tools behind them.
- 17 specs are generated from the executable tool registry: AWS and Webex first, then two batches.
  - Identity and collaboration: Okta, Duo, Google Workspace, Slack, Zoom, Box, Zendesk, Salesforce, ServiceNow
  - Cloud and network: Azure, Google Cloud, Oracle Cloud Infrastructure, Cloudflare, Palo Alto Networks, Zscaler
- A generated shared integration contract sits beside the generated specs, and CI fails when a generated spec drifts from the code.
- Browse every spec at [/specs](/specs) or read [Using Specs as Inputs](/docs/specs/using-specs-as-inputs/).

### Security and hardening

- Error text is scrubbed of credential-shaped values before it reaches the model, including quoted, lowercase, escaped, flag, cookie, and letters-only Bearer forms.
- Pagination links on a different origin no longer receive credentials, and GitHub tokens go only to the configured GraphQL origin.
- Evidence exports redact credentials. Capped pagination is marked truncated instead of complete. Malformed success responses from CrowdStrike and Webex are rejected instead of read as empty data.
- Evidence exporters allocate a new bundle path on each rerun instead of overwriting an earlier bundle. Vanta exports stay isolated even when runs overlap. Duo bundles are written owner-only.
- Config files are read with a 1 MiB cap, and FIFOs and devices are refused. Parse errors are built from fixed text so a malformed line cannot leak a credential.
- RunPod staging uploads only git-tracked files and never the `.env` family.
- Integration fixes:
  - OCI Cloud Guard problems are parsed from the real response shape.
  - Palo Alto honors `verify_tls` in config files.
  - The Google Workspace operator bridge reports a partial bundle when `gws` lacks Alert Center.
  - Zscaler reports explicitly configured files that are missing.
  - The default CMVP endpoint works again.
- Tool schemas now match what the runtime accepts: AWS and LaunchDarkly list arguments, the Salesforce inline JWT key, and Snowflake tuning inputs. A registry lint checks tool and parameter descriptions. MuleSoft and Zendesk details no longer embed raw snapshots.

### Release and CI

- Release bundles for six platforms (macOS, Linux, and Windows, each on arm64 and x64) are reproducible:
  - Fixed archive timestamps and ordering
  - A strict `SHA256SUMS.txt` check
  - GitHub build provenance attestations
  - A publisher that refuses to overwrite an existing release
- A plain version tag such as `v0.1.0` publishes a full release marked as the latest. A tag with a suffix such as `v0.2.0-rc.1` still publishes an experimental prerelease.
- Every pull request runs the CLI tests, TypeScript checks, the credential leak probe, the generated-spec drift check, Agent SDK registry validation, and the site build. Dependency review runs on pull requests. Dependabot keeps pinned GitHub Actions current.
- The FedRAMP sync workflow pins its actions, drops persisted credentials, and runs the tests before it opens a pull request.

### Site and docs

- grclanker.com runs on Cloudflare Workers static assets, deployed by Workers Builds from `main`, with preview URLs on pull requests.
- The site serves canonical `grclanker.com` URLs and a sitemap, and its build fails on broken internal links.
- Accessibility fixes for WCAG 2.2 AA:
  - Focus handling in dialogs and the mobile menu
  - Higher-contrast colors, including the spec viewer
  - Screen reader announcements for search results and copy buttons
- Install, runtime, workflow, and integration guides were corrected against the CLI. The installers print source-build steps when no bundle fits your platform.

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
