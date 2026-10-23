---
title: What's New
description: "The grclanker changelog: what shipped in v0.1.4, v0.1.3, v0.1.2, v0.1.1, v0.1.0, and v0.0.1."
---

## v0.1.4 (October 23, 2026)

Rides out rate limits and brief outages: 32 integrations and the KEV, EPSS, CMVP, SCF, and FedRAMP tools now retry rate limits, server errors, and timeouts, and a read that still fails is reported as unread, so no check passes on partial data. Access checks say so when a vendor rejects your credentials, the first run is smoother, and installs are safer: a failed upgrade puts the previous install or skill back, and every release bundle now runs on its own operating system before it is published. `kevs_search` puts an exact CVE ID first, and the Zendesk, LaunchDarkly, AWS, and SCF tools now do what their docs say. The tool surface is unchanged. Install or upgrade with:

```bash
curl -fsSL https://grclanker.com/install | bash
grclanker tools
```

`grclanker tools` still reports `241 domain tools + 7 compute backend tools`.

### Retries and incomplete reads

- 32 integrations now retry a rate limit, a server error, a timeout, or a network failure before giving up, three to five attempts in all by default. The 32 are Ansible Automation Platform, AWS, Azure, Box, Cloudflare, CrowdStrike, Datadog, Duo, Elastic, GitHub, Google Cloud, Google Workspace, KnowBe4, LaunchDarkly, MuleSoft, New Relic, Okta, PagerDuty, Palo Alto Networks, Qualys, Salesforce, ServiceNow, Slack, Snowflake, Splunk, Tenable, Vanta, Veracode, Webex, Zendesk, Zoom, and Zscaler. Before, Ansible Automation Platform, Azure, Cloudflare, Google Cloud, and Vanta retried nothing, and Duo, Okta, Slack, Webex, and Zoom retried only a rate limit. Each integration page gives its own limits.
- [Azure](/docs/integrations/azure/#retries-and-timeouts) and [Google Cloud](/docs/integrations/gcp/#retries-and-timeouts) give every request, token requests included, up to 4 attempts, and retry a 429, 500, 502, 503, or 504, a request that got no response, and an attempt still unanswered after 30 seconds. [AWS](/docs/integrations/aws/#retries-and-timeouts) already retried through the AWS SDK and still leaves the retry mode and the attempt limit to it: the SDK reads `AWS_RETRY_MODE` and `AWS_MAX_ATTEMPTS` first, then `retry_mode` and `max_attempts` in the selected profile, and otherwise uses standard mode with 3 attempts. That holds for every client the tools build, including the STS and SSO clients the credential providers create. Even when the settings allow a single attempt, a refused connection or a DNS failure is reported as unanswered, with a network next step, not as a permission refusal. When a read runs out of retries, Azure findings and the three access checks say the result is incomplete and recommend waiting for the service or restoring network access instead of a grant. The Azure and Google Cloud access checks still set their status from readable probes alone, so `healthy` can appear beside that note.
- Box, CrowdStrike, Datadog, Google Workspace, LaunchDarkly, MuleSoft, PagerDuty, Qualys, Salesforce, ServiceNow, Snowflake, Splunk, Tenable, Veracode, and Zendesk retry every status of 500 and above. The other 17, including Azure, Google Cloud, AWS, Okta, Zscaler, and Ansible Automation Platform, retry 500, 502, 503, and 504 but no other server error, so an answer such as 501 or 505 is sent once and fails the read.
- Each wait follows the delay the server asks for, usually in a `Retry-After` header, or else backs off, and every wait is capped, at 15 to 60 seconds depending on the integration. When a server asks for longer than the cap, Ansible Automation Platform, Azure, Cloudflare, Duo, GitHub, Google Cloud, Google Workspace, LaunchDarkly, MuleSoft, Palo Alto Networks, Salesforce, Slack, Splunk, Vanta, Webex, Zoom, and Zscaler fail the read at once, and the error names the wait the server asked for, since a retry before then is likely to be refused again. The others wait the capped time and retry, except AWS, whose waits are the AWS SDK's own backoff: the SDK honors a `Retry-After` or `x-amz-retry-after` header only up to 5 seconds past that delay. Before, Duo, GitHub, Palo Alto Networks, and Salesforce slept through whatever wait a server asked for. A requested wait too far off to represent as a date, which made GitHub, Slack, Zoom, and Webex fail with a bare `RangeError: Invalid time value`, now gets each client's own error, which says the wait ends past the latest representable date.
- GitHub, Okta, Google Workspace, Vanta, Azure, Google Cloud, and AWS requests had no time limit of their own, so a stalled request waited until the tool call was stopped. Each attempt now gets 30 seconds, and an AWS attempt also gets 10 seconds to connect. In most of the 32 integrations, Azure and Google Cloud included, the timeout also covers reading the response body, so a body that stalls after the headers is retried like any other timeout. AWS's 30 seconds run until the service starts answering.
- When the attempts run out, the error names the request, the last status or failure, and the attempt count, for example `Zoom request failed for GET /v2/users after 4 attempts: timed out after 30000 ms`. The data that request was reading is reported as unread, never as empty or complete, even when the failure lands on a later page, so no check passes on a partial inventory. A stopped tool call is not retried, and stopping during a retry wait ends it at once.
- The KEV, EPSS, CMVP, SCF, and FedRAMP tools retry the public feeds they read, up to 4 attempts of 30 seconds each, and label what is missing when the retries run out. `kevs_get_epss` shows `Unavailable` instead of `Not scored` for CVE IDs whose EPSS batch failed and adds `(incomplete)` to its heading, and when every batch fails it returns an error instead of `No EPSS scores found`. `kevs_search` and `kevs_recent` show EPSS as `Unavailable` where the EPSS line used to be missing. `scf_get_control` names each evidence request that failed. FedRAMP results say when the GitHub metadata could not be read, and an empty `fedramp_search_frmr` result says when it came from a stale cache. The [KEV / EPSS](/docs/integrations/kevs/) page and the [SCF crosswalks](/docs/guides/scf-crosswalks/) and [FedRAMP readiness](/docs/guides/fedramp-readiness/) guides give the details.
- Checks that passed on partial data no longer do. [Splunk](/docs/integrations/splunk/) SPLUNK-AUD-17 now warns when a later page of `audit.conf` returns 404. Before, it read the file as absent and passed on the documented default. [Okta](/docs/integrations/okta/) OKTA-INTEG-004 is Partial beside a contextual policy rule, or Manual without one, when the network zone read fails, and [Duo](/docs/integrations/duo/) DUO-AUTH-010 stops at Partial when the WebAuthn credential inventory failed or stopped early and an enrolled user has a WebAuthn credential. Before, both could pass. [Cloudflare](/docs/integrations/cloudflare/) CF-TRF-06 (Gateway rules) and CF-TRF-02 (page rules) no longer pass when the response says it holds only some of the rules or pages. [Azure](/docs/integrations/azure/) AZURE-MON-06 now stops at `warn` when the diagnostic settings list is truncated, as it already did for a truncated workspace list.
- When an evidence download or file listing fails, [`vanta_export_audit`](/docs/integrations/vanta/#retries-and-incomplete-packages) reports `as an incomplete package` with a reason. `_audit_info.json` carries `complete: false` and an `incomplete_evidence` list, and each item in `metadata.json` and `_index.csv` carries an `export_status` of `complete`, `files_missing`, or `urls_unknown`. A download that sends nothing for 30 seconds or breaks off partway is recorded, and its partial file is removed. Before, such an export read as a normal export with a warning count.
- [Tenable](/docs/integrations/tenable/#retries-and-timeouts) retries status polls and chunk downloads, and a chunk's timeout restarts as each piece of the body arrives, so a large chunk that keeps arriving is not cut off. Each attempt may run 20 times `TENABLE_TIMEOUT`, 10 minutes at the default. The request that starts an export is not resent after a timeout or network failure, because Tenable may already have started that export. That export is then unreadable and its controls are `manual`. A chunk that fails on every attempt marks the export truncated, so no control passes on the chunks that did arrive.
- Token requests are retried too. [Box](/docs/integrations/box/) and Okta sign a fresh client assertion for each token attempt, since both refuse a reused one, and Duo signs each attempt again with a new `Date`. A prebuilt [Okta](/docs/integrations/okta/) assertion, passed as `client_assertion` or `OKTA_CLIENT_CLIENTASSERTION`, can be used only once, so it is sent once. If that attempt fails in a way that would otherwise be retried, the error says it was not retried and to rerun with a fresh assertion or with a private key in its place. After its one token refresh on a 401, GitHub reuses the refreshed installation token instead of minting another on every retry. A [Zoom](/docs/integrations/zoom/) token exchange or [Webex](/docs/integrations/webex/) refresh grant that fails is not sent again in the same tool call, so a token endpoint that stays down costs one round of retries instead of one per surface, and concurrent Webex reads share one grant. Azure reads that start together share one token request per resource, and Google Cloud access probes share one token exchange, retries included. [Ansible Automation Platform](/docs/integrations/ansible/#retries) never resends its session login after a timeout, since that could expire the user's oldest session. [Snowflake](/docs/integrations/snowflake/) resends a statement only with its original `requestId` and `retry=true`, so the SQL API runs it once.
- When a [GitHub](/docs/integrations/github/#retries-and-timeouts) rate limit names no wait, the GitHub tools now wait the one minute GitHub asks for, where they waited 250 ms, and a repeat on the same request fails, since GitHub then asks for longer than the 60-second cap. [Google Workspace](/docs/integrations/gws/) retries a 403 whose reason is `userRateLimitExceeded`, `rateLimitExceeded`, or `quotaExceeded`, and one that outlasts the retries is reported as a request error, never as a missing scope or admin role. A direct access token's 401 is final instead of being resent four times.
- Once a [PAN-OS](/docs/integrations/paloalto/#retries-and-rate-limits) device gives no answer after its retries, its remaining reads in that tool call fail at once without being sent, with `was not attempted because <device> did not answer an earlier request`. An offline device costs about 2 minutes per collection, and other devices are unaffected.

### Access checks name rejected credentials

- When a vendor refuses the credentials themselves, 29 access checks now report `failed` and name the settings to fix. Before, they reported `limited` and asked for permissions, scopes, or roles that would not have helped. The 29 are Azure, Box, Cloudflare, CrowdStrike, Duo, Elastic, GitHub, Google Cloud, Google Workspace, KnowBe4, LaunchDarkly, MuleSoft, New Relic, Oracle Cloud Infrastructure, Okta, PagerDuty, Palo Alto Networks, Qualys, Salesforce, ServiceNow, Snowflake, Splunk, Sumo Logic, Tenable, Veracode, Webex, Zendesk, Zoom, and Zscaler. [Palo Alto Networks](/docs/integrations/paloalto/) reported `degraded` before.
- The next step names the variable. For example, `GitHub rejected the token (every probe returned 401). Set GITHUB_TOKEN / GH_TOKEN or pass api_token with a valid token, then rerun github_check_access.` Each step follows the auth mode in use, names the aliases the resolver also reads, and names the region, cloud, or platform setting wherever a credential sent to the wrong host draws the same refusal. A `failed` result lists no missing permissions, and its notes say permissions were not checked.
- Permission gaps are unchanged. A 403, one readable probe, or a failure that is not a credential refusal, such as a 429 or a 5xx, keeps the `healthy`, `limited`, or `degraded` result from `v0.1.3`. The new messages hold only fixed text, setting names, and status or vendor error codes, never response text.
- A rejected [Slack](/docs/integrations/slack/) token names `SLACK_USER_TOKEN` and its alias `SLACK_TOKEN`, or `SLACK_BOT_TOKEN` when only a bot token is set. [Datadog](/docs/integrations/datadog/) no longer lists all 17 permissions as missing when it rejects the API or application key. When [AWS](/docs/integrations/aws/) finds no credentials, the error says to set `AWS_PROFILE` or run `aws sso login`. A [GitHub](/docs/integrations/github/) App installation token request that returns 404 reports `failed` and says the installation ID is wrong or the App is not installed.

### First run

- `grclanker --version` prints the version, as do `-v` and `grclanker version`. `grclanker help` works like `--help`.
- `grclanker --session <id>`, the command grclanker prints when you leave a session, reopens that session. `v0.1.3` rejected it as an unknown option. `/resume` inside a session works as before.
- Started from a script or CI job before setup has run, `grclanker` exits `1` with `grclanker is not configured yet, and first-run setup needs an interactive terminal.`, and `grclanker setup` exits `1` and says no model was configured. Both point to the settings file and the [Configuration](/docs/getting-started/configuration/) guide. Before, the first launch printed a stack trace, and setup exited `0` without saving anything.
- Local-first setup says to start Ollama with `OLLAMA_CONTEXT_LENGTH=128000`, since grclanker sends about 100k tokens of tool definitions with each request and Ollama's default [context length](/docs/getting-started/setup/#context-length) is too small to hold them. Hosted setup names the API key variable grclanker reads: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `GEMINI_API_KEY`.
- When [`grclanker flue run`](/docs/getting-started/flue-runtime/) stops at `Provider is not configured: <provider>`, it now names the API key variable to set, or says to point `GRCLANKER_FLUE_MODEL` at a provider you have a key for.

### KEV

- [`kevs_search`](/docs/integrations/kevs/) puts the entry whose CVE ID equals the query first. Before, catalog order could put another entry ahead of it: asking for `CVE-2021-44228` with `limit: 1` returned `CVE-2021-45046`, whose description cites it, and `CVE-2022-2294` returned `CVE-2022-22948`.
- When `limit` leaves entries out, `kevs_search` and `kevs_recent` replies start with `Showing N of M`, and `details.total_matches` carries the full count. Before, the heading counted only the rows shown. Replies that show every match are unchanged.

### Tools match their docs

- [Zendesk](/docs/integrations/zendesk/): ZD-05 fails when mobile app access is on and the mobile app session timeout is 0 (never expires) or more than three times the threshold, as the docs say. Before, only the agent timeout could fail the check, and a mobile timeout like that only warned. Exactly three times the threshold still warns.
- [LaunchDarkly](/docs/integrations/launchdarkly/): caveats for a truncated listing name only arguments that raise that listing's cap. Team roles, members in access control, custom roles in environment governance, and environments in flag hygiene and monitoring are read at a fixed cap, so those caveats now say to review the uncollected items manually. Before, they advised `role_limit`, `member_limit`, or `environment_limit`, and a rerun with a higher value returned the same truncated result.
- [AWS](/docs/integrations/aws/) names the IAM actions S3 needs: `s3:ListAllMyBuckets`, `s3:GetBucketPublicAccessBlock`, and `s3:GetEncryptionConfiguration`. Before, its permission list held the API operation names `s3:ListBuckets`, `s3:GetPublicAccessBlock`, and `s3:GetBucketEncryption`, so a policy built from that list did not allow those calls. `aws_check_access` records `s3:ListAllMyBuckets` for its S3 probe, and error lines still name the API call that failed.
- [SCF](/docs/guides/scf-crosswalks/): `scf_get_crosswalk` advertises its real default of 10 rows in each direction, and a call that skips argument preparation now uses 10 instead of 8.
- [Okta](/docs/integrations/okta/): CI checks the FedRAMP assessment results in `okta_export_audit_bundle` against the NIST OSCAL 1.1.2 assessment-results schema, using bundles from six fixture orgs. The builder now leaves out empty `observations` and `findings` lists, which the schema rejects. No bundle produced them, so bundle output is unchanged.

### Durable mode and stopped exports

- [`grclanker durable`](/docs/getting-started/durable-runtime/#sessions-and-the-lock) reads a session's schema version over a read-only connection before Pi Durable opens it. A session at a newer schema version exits `1` with `Session "<id>" was written by a newer grclanker`, both schema versions, and `The session was not changed.` instead of a stack trace. A `session.sqlite` that is not a SQLite database gets its own message. Neither file is opened for writing.
- [Vanta](/docs/integrations/vanta/): a stop that lands while `vanta_export_audit` is downloading an evidence file now settles only after that file is closed, so the export's staging directory is removed cleanly.

### Installers and bundles

- Both installers move the previous install aside, extract into a fresh directory, and put the previous install back if extraction fails, then exit non-zero with `Could not extract <bundle>, so the previous install was restored` (shell) or `Extraction failed, so the previous install was restored.` (PowerShell). Before, a corrupt archive, a full disk, or an interrupted extraction could leave no working `grclanker`.
- The shell installer stops with `Could not list the entries in <bundle>, so nothing was installed` when `tar` cannot list a bundle, before it moves anything. Before, a truncated bundle passed the entry check on a partial listing.
- The [skills-only installers](/docs/getting-started/installation/#skills-only), `install-skills` and `install-skills.ps1`, download `SKILL.md` beside the installed copy, check that it is the grclanker skill, and only then replace the installed one. A cut-off download, a sign-in page, or a missing version exits non-zero with `Could not download <url>, so nothing was changed` or `<url> did not return a grclanker SKILL.md, so nothing was changed`, and a failed first install leaves no empty skill directory. Before, a cut-off download left part of the file, a sign-in page replaced the skill with HTML, and the installers could still exit `0`.
- `install.ps1` extracts the bundle's 39,020 files with one .NET `ZipFile` call instead of `Expand-Archive`. The Windows PowerShell 5.1 install job in CI went from 3m30s to 1m26s.
- Every bundle carries the Apache-2.0 `LICENSE` and `NOTICE` under `app/`. The `v0.1.3` bundles did not.
- The site serves the installers from `main`, so these changes are already live: the three CLI installer changes since October 22 and the skills installer change since October 23. The license files arrive with the `v0.1.4` bundles.

### Release pipeline

- Bundles are cross-built on Linux. The release workflow now installs each of the six with the real installer on a native runner: macOS on Apple silicon and Intel, Linux on arm64 and x64, and Windows on arm64 and x64 under both Windows PowerShell 5.1 and PowerShell 7. Each install has to verify its checksum, run a Node.js built for its platform, and print the same tool count as the Linux build. A release gate refuses to publish unless every check passes, and `v0.1.4` is the first release published through it.
- Pull requests and pushes to `main` that touch the bundle builder, the installers, or the CLI entry run the same checks and publish nothing. The checks also run on `main` every Monday, so a retired or broken runner image fails a run nobody is waiting on instead of the next release. Scheduled runs publish nothing.
- The MuleSoft, Oracle Cloud Infrastructure, Palo Alto Networks, Qualys, Snowflake, Sumo Logic, Tenable, Veracode, Webex, and Zscaler live smoke scripts exit `1` with the access check's next step when it reports `failed`, instead of running assessments against a tenant they cannot read and reporting a pass.
- The Box, Google Cloud, ServiceNow, and Slack live smoke scripts skipped when set up with a credential their tool accepts, such as `BOX_TOKEN`, `GOOGLE_ACCESS_TOKEN` with `GCLOUD_PROJECT`, `SERVICENOW_INSTANCE_URL`, `SLACK_TOKEN`, or Slack's default config file. They now run, and their skip messages list every credential that counts.
- CI splits the CLI tests into three shards balanced by measured run time, and stops with an error when PowerShell is missing instead of skipping the 16 PowerShell installer tests. The checks are unchanged.

### Docs and site

- Phones get right-sized images, and the homepage drops from 714 KB to 424 KB. Hashed scripts are cached for a year, fonts for 30 days, and images for a day, and fonts start loading with the page. Homepage card titles now keep at least 4.6:1 contrast over every brand picture, and the hero's links are underlined instead of told apart by color alone.
- The README and [Quick Start](/docs/getting-started/quick-start/) run `grclanker tools` before the first session and explain how to leave and resume one. [Installation](/docs/getting-started/installation/#first-interactive-session) and [Setup](/docs/getting-started/setup/#context-length) document Ollama's context length and the first session's download of `fd` and `rg`, with `PI_OFFLINE=1` for machines without internet access.
- The pages for 21 integrations and [Compute Backends](/docs/getting-started/compute-backends/) now describe what the shipped tools do, including Salesforce's `private_key` argument, Snowflake's polling and retry settings, Azure's `healthy` threshold of six of eight readable probes, 13 rows of the Qualys verdict table, LaunchDarkly's fixed caps, the status codes Zscaler retries, and each live smoke script's skip and exit rules. The Palo Alto Networks spec names `~/.grclanker/paloalto.json`, the file the tools read, as the default config file.
- The site build fails when a docs page or the README names a tool the CLI does not define, or sets or lists an environment variable the code never mentions.
- The homepage counts the experimental durable runtime as a fourth runtime path.
- Integration pages describe the `failed` access status and the next step each check prints.
- The pages for the 32 integrations that retry, the KEV / EPSS page, and the SCF and FedRAMP guides describe the retry limits, the error text, and what a read that runs out of retries does to a verdict.

### Security

- `hono` 4.13.13, up from 4.13.8, fixes GHSA-5r4p-p66f-jhc7 (medium). The bundle carries `hono` through the Flue runtime.
- `ip-address` 10.7.4, up from 10.7.2, fixes GHSA-rxp7-6hxx-x8q5 (medium), published October 22. The bundle carries `ip-address` through `@earendil-works/pi-ai`.
- Source checkouts pin `@modelcontextprotocol/server` to 2.3.1, which fixes GHSA-jm63-cq47-j5jp, GHSA-46jr-4wx8-v453, and GHSA-rvq5-wwqv-78pq. It is a development dependency and is not in the bundle.
- `npm audit` for the CLI still reports the 2 high advisories from `v0.1.3`, both GHSA-86w9-cpqp-85rv in `node-forge`, counted once directly and once through `@anthropic-ai/sandbox-runtime`. No patched `node-forge` exists yet. The site has none.

### Upgrade notes

- Rerun the installer to upgrade. Settings and runtime state under `~/.grclanker/agent` are kept.
- Source checkouts should rerun `npm --prefix cli ci`, since the CLI lockfile changed.
- **Slower failures from hosts that never answer.** Timeouts are now retried, so a host that accepts connections but never answers costs up to five timeouts by default, plus the waits between them, before a read is reported as failed: up to about three minutes at a 30-second timeout. Most integrations take a timeout setting, and Box, Datadog, Qualys, Salesforce, ServiceNow, Snowflake, and Zscaler also take a retry count. AWS takes its attempt limit from `AWS_MAX_ATTEMPTS` or the profile's `max_attempts`. Each integration page lists them.
- **Error text.** An error for a request that ran out of retries now names the attempt count, such as `after 4 attempts`, and Box and Zendesk errors no longer include the query string. Anything that matches the old error text needs the new wording.
- **Results that change.** Expect `warn` for Splunk SPLUNK-AUD-17 and Azure AZURE-MON-06, Partial or Manual for Okta OKTA-INTEG-004, Partial for Duo DUO-AUTH-010, and no pass for Cloudflare CF-TRF-06 and CF-TRF-02 where `v0.1.3` passed on data it could not fully read. `kevs_get_epss` shows `Unavailable` instead of `Not scored` for a CVE ID whose EPSS batch failed. In a Vanta export package, an item whose file list could not be read has `files: null` instead of `[]`, and new `complete`, `incomplete_evidence`, and `export_status` fields say what is missing.
- **Tenable.** An attempt still receiving its response after 20 times `TENABLE_TIMEOUT` now fails and marks the export truncated, where `v0.1.3` kept reading. For a slow link, raise `TENABLE_TIMEOUT`, up to 600 seconds, which raises the cap with it.
- **AWS profiles.** A profile chosen with the `profile` argument now applies all of its client settings, the same way `AWS_PROFILE` does: its `retry_mode` and `max_attempts`, and settings such as `use_fips_endpoint`, `use_dualstack_endpoint`, and the S3 checksum settings. Before, those settings came from `AWS_PROFILE` or the default profile. `endpoint_url` still comes from `AWS_PROFILE` or the default profile.
- Expect `failed` where `v0.1.3` reported `limited`, or `degraded` for Palo Alto Networks, when a vendor rejects the credentials. Scripts and reports that read the access status should treat `failed` as a credential problem. Accepted credentials report as before.
- Expect `fail` where `v0.1.3` reported `warn` for Zendesk ZD-05 when mobile app access is on and the mobile app session timeout is 0 or more than three times the threshold.
- If you built an IAM policy from the S3 actions the AWS tools listed in `v0.1.3`, replace `s3:ListBuckets`, `s3:GetPublicAccessBlock`, and `s3:GetBucketEncryption` with `s3:ListAllMyBuckets`, `s3:GetBucketPublicAccessBlock`, and `s3:GetEncryptionConfiguration`.
- `kevs_search` and `kevs_recent` replies cut by `limit` start with `Showing N of M` instead of `Found N` or `N KEV entries added`. Anything that parses those headings should read `details.total_matches` instead.
- **Durable sessions.** This release still pins pi-durable 1.3.0, so the `v0.1.3` note about the next pi-durable still applies: once a later release migrates a session, neither `v0.1.3` nor `v0.1.4` can open it. `v0.1.4` refuses it with a message and leaves the file unchanged. If you might go back, copy `~/.grclanker/durable/sessions/` before opening your sessions with a newer release.

Full history: [v0.1.3...v0.1.4](https://github.com/ethanolivertroy/grclanker/compare/v0.1.3...v0.1.4). [Release notes and bundles](https://github.com/ethanolivertroy/grclanker/releases/tag/v0.1.4).

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
