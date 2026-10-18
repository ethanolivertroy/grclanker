---
title: Google Workspace CLI operator bridge
description: Optional read-only bridge that runs a curated set of googleworkspace/cli (gws) investigation commands and packages the results as operator evidence.
---

The operator bridge (`gws_ops_*` tools) shells out to the external [`gws` CLI](https://github.com/googleworkspace/cli) when it is already installed and authenticated. It offers five curated read-only workflows, records the exact commands it previews or attempts, and packages structured output as evidence.

The bridge never accepts arbitrary `gws` arguments and never runs a write method. It does not replace the native [Google Workspace inspector](/docs/integrations/gws), which remains the framework-mapped assessment path.

Spec: `specs/gws-operator-bridge.spec.md`. Implementation: `cli/extensions/grc-tools/gws-ops.ts`. Tests: `cli/tests/gws-ops.test.mjs`.

## Setup

Install and authenticate `gws` following the [googleworkspace/cli README](https://github.com/googleworkspace/cli#readme):

```bash
npm install -g @googleworkspace/cli      # or: brew install googleworkspace-cli
gws auth setup                            # one-time Google Cloud project and OAuth setup (needs gcloud)
gws auth login                            # subsequent logins and scope selection
```

The bridge inherits the CLI's credential precedence and adds only two knobs:

| Setting | Source | Effect |
| --- | --- | --- |
| `gws_bin` argument, then `GRCLANKER_GWS_BIN`, then `PATH` | grclanker | Which `gws` binary to run |
| `config_dir` argument | grclanker | Exported to the child as `GOOGLE_WORKSPACE_CLI_CONFIG_DIR` for that command only |
| `GOOGLE_WORKSPACE_CLI_TOKEN` | inherited | Pre-obtained access token, highest priority in the CLI ([README, Environment Variables](https://github.com/googleworkspace/cli#readme)) |
| `GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE` | inherited | OAuth or service-account credentials JSON, second priority |
| stored `gws auth login` credentials | inherited | Third priority, encrypted at rest by the CLI |

Every other `GOOGLE_WORKSPACE_CLI_*` variable in grclanker's environment is passed through unchanged. `cli/tests/gws-ops.test.mjs` asserts this precedence.

## Run it

With `gws` installed and signed in, start `grclanker` and ask in plain words. The agent calls the matching tools, for example:

```text
Check that the gws CLI works for grclanker.
List recent Alert Center alerts.
Trace Google Workspace admin activity for the last 30 days.
Collect a Google Workspace operator evidence bundle.
```

The [assess](/docs/workflows/assess/) and [audit](/docs/workflows/audit/) workflows use these tools for operator-side investigation and raw evidence, starting with `gws_ops_check_cli`. For framework-mapped findings, use the [Google Workspace](/docs/integrations/gws/) tools.

## Workflows

| Tool | Underlying command | Read-only? | Output |
| --- | --- | --- | --- |
| `gws_ops_check_cli` | `gws --version`, then `gws admin-reports activities list --params '{"userKey":"all","applicationName":"admin","maxResults":1,"startTime":"<7 days ago>"}'` | yes | Executable path, version, probe status |
| `gws_ops_investigate_alerts` | `gws alertcenter:v1beta1 alerts list --params '{"pageSize":<max_results>,"filter":"<filter>"}'` | yes | Alert records (`alertId`, `type`, `source`, `createTime`, `metadata.status`, `metadata.severity`, `metadata.assignee`) |
| `gws_ops_trace_admin_activity` | `gws admin-reports activities list --params '{"userKey":"all","applicationName":"admin","maxResults":<n>,"startTime":"<lookback>"}'` | yes | Activity records (`id.time`, `id.uniqueQualifier`, `actor.email`, `events[].name`, `ipAddress`) |
| `gws_ops_review_tokens` | Same as above with `"applicationName":"token"` | yes | Token and OAuth activity records with `actor.applicationInfo.applicationName` |
| `gws_ops_collect_evidence_bundle` | Attempts the three commands above; an unsupported Alert Center command is recorded as unavailable | yes | `raw/`, `analysis/`, `commands.json`, `summary.md`, `README.md`, and a zip |

### Dry runs and call status

Every workflow accepts `dry_run: true` to print the exact command without executing it.

A dry run renders `null` for every field a real call would derive from records: `count`, `complete`, `next_page_token`, `records`, and the raw response. These fields sit beside `status: not collected: dry run previewed the command and did not execute it, so no records were requested`.

A dry run never reports `count: 0` or `records: []` for a call that did not happen.

An executed call carries the counts plus a `status` that takes one of two forms:

- `complete: the CLI response carried no nextPageToken, so the N record(s) are the whole population for this query`
- `partial: at least N; the CLI response carried a nextPageToken after N record(s), so more records exist beyond this page`

The evidence bundle is also partial when the exact unsupported Alert Center response is encountered. Its alert count and records are `null`, not zero or an empty list.

### Limits and defaults

`max_results` defaults to 50 and is clamped to 1-250. `lookback_days` defaults to 14 and is clamped to 1-90.

When a request exceeds 250 (for example 1000, the `activities.list` maximum), the notes state the requested value and the clamp rather than silently reporting 250.

## Result semantics

The bridge applies the inspector's verdict-safety rules that are meaningful for a CLI wrapper:

- A non-zero exit is an explicit `GwsCliCommandError` whose kind follows the CLI's documented exit codes: 1 API error, 2 auth error, 3 validation error, 4 discovery error, 5 internal error ([README, Exit Codes](https://github.com/googleworkspace/cli#exit-codes)).
  - The only bundle-level exception is the exact exit 3 unknown-service response for `alertcenter`, which becomes explicit unavailable evidence.
  - Every other Alert Center failure and every core admin or token failure remains fatal.
- A missing binary is reported with install guidance.
- A zero exit whose stdout is not JSON (or NDJSON from `--page-all`) is an explicit error. Only `gws --version` may print plain text.
- Every result carries `complete` and `next_page_token`. When the last page in the response has a `nextPageToken`, `complete` is `false` and the notes say so. A single page is never presented as the whole population.
- `--page-all` NDJSON output (one JSON object per page, per the README pagination table) is aggregated across pages, and completeness follows the last page.
- The evidence bundle runs the alert, admin, and token commands before it writes anything.
  - A failure in the admin or token command fails the whole bundle and writes no files. So does any Alert Center failure other than the unknown-service response described in the caveat below.
  - On a `gws` build without the `alertcenter` alias, the bundle still writes its files, records alerts as unavailable, and reports itself as partial.
- The evidence bundle allocates `gws-operator-evidence`, then `-2` through `-6`, under `output_dir` (default `./export/gws-ops`).
  - It names the zip after the allocated directory and never overwrites an earlier directory or zip.
  - It fails once all six names are taken.
  - Output paths are validated against traversal and symlinked parents.
- [Bundle secret hygiene](#bundle-secret-hygiene) and [error text hygiene](#error-text-hygiene), each described in its own section.

## Alert Center caveat

No `alertcenter` alias is registered in the `gws` source consulted for this release, so `gws alertcenter:v1beta1 alerts list` fails with a validation error (exit 3) on such a build.

The published `gws` source registers service aliases in `crates/google-workspace/src/services.rs` (for example `admin-reports` and `reports` for `admin/reports_v1`). `parse_service_and_version` in `crates/google-workspace-cli/src/main.rs` resolves the `<service>:<version>` form through that alias table.

The standalone alert investigation surfaces that explicit error and points to `gws_assess_monitoring`, which calls the Alert Center API natively.

The evidence bundle recognizes only that exact unknown-service response. On that response, it:

- Marks alerts unsupported and unavailable with null records and count.
- Continues its core admin and token commands.
- Reports the bundle as partial.

All other failures remain fatal.

If a future `gws` release adds the alias, the command works unchanged.

## Live smoke

```bash
npm --prefix cli run test:gws-ops:live
```

The script runs:

- `gws_ops_check_cli`
- The admin and token traces
- The alert investigation (skipped with the validation message above when the alias is missing)
- A dry run of the evidence bundle

When `gws` is not installed or not authenticated, the script prints a skip message and exits 0.

## Limitations

- The bridge is optional. It does no framework mapping and produces no Pass, Partial, or Fail verdicts. Use the native inspector for compliance findings.
- Only the five workflows above are exposed. Arbitrary `gws` passthrough is refused by design.
- `gws_ops_review_tokens` reviews token activity telemetry. It does not clone a tenant-wide token inventory (the inspector's `gws_assess_integrations` does that).
- Real smoke testing requires an installed and authenticated `gws` binary.

## How the tools handle evidence

This section is reference for reviewing tool results and evidence bundles: how credentials are kept out of them and out of error text. You don't need it to set up or run the integration.

### Bundle secret hygiene

No capture is written verbatim. `raw/<category>.json` holds the CLI response projected page by page to the documented fields in the command reference below. Alert Center `data` payloads, `events[].parameters[]`, `actor.key`, `securityInvestigationToolLink`, and undocumented keys are dropped.

Both `raw/` and the normalized records then pass through the inspector's `redactSecrets` (normalized key names, `{name, value}` pairs, URL query strings). They also pass through a scrub of every `GOOGLE_WORKSPACE_CLI_*` token or secret value from the environment. As a result, a CLI that echoes its own credential cannot leak it into evidence.

The recorded command in `commands.json` lets an operator re-run for parameter detail.

### Error text hygiene

The CLI's stderr and every error string the bridge builds pass through one function, `scrubCliText` in `cli/extensions/grc-tools/gws-ops.ts`. It applies the inspector's text scrubber and then replaces every `GOOGLE_WORKSPACE_CLI_*` token or secret value from the environment.

The inspector's text scrubber covers bearer credentials, `ya29.` and `1//` tokens, `AIza` keys, `GOCSPX-` secrets, JWTs, PEM blocks, `key=value` and `key: value` credential pairs, and URL query strings.

No consumer of the bridge can receive an unscrubbed string, because:

- `GwsCliCommandError` scrubs its own message in the constructor.
- The access probe scrubs the stderr it reports.
- A zero exit whose stdout is not JSON is described without repeating that stdout.
- Every tool error result is scrubbed once more where it is built.

`cli/tests/gws-ops.test.mjs` plants an env token, a `Bearer ya29.` value, and an `access_token=` pair in stderr. It asserts none reaches the thrown error, the tool result, or the probe.

The `--version` output is the one CLI-produced string that reaches a tool result without a JSON projection. It passes through `scrubCliText`, and then only its first line is matched against the documented `gws <version>` line. The binary prints two lines, `gws <version>` and a fixed disclaimer.

`gws_ops_check_cli` renders:

- The numeric core alone (`gws 0.22.5`). A pre-release or build suffix is accepted but never rendered.
- The version number plus a note, when the first line is not the documented one but a version number sits in the output.
- A descriptor giving only the output length, when no version number is present.

As a result, nothing the binary prints beyond `major.minor.patch` can reach the tool text or JSON.

## Command reference

| Command | Documentation | Flags used | Fields read |
| --- | --- | --- | --- |
| `gws --version` | [README, Quick Start](https://github.com/googleworkspace/cli#readme); `crates/google-workspace-cli/src/main.rs` | none | two plain-text lines: `gws <version>`, then the fixed disclaimer added in 0.3.5 |
| `gws admin-reports activities list --params <json>` | [README command shape](https://github.com/googleworkspace/cli#readme); parameters from [activities.list](https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list) | `--params` with `userKey`, `applicationName`, `maxResults` (documented maximum 1000; the bridge caps at 250), `startTime` | `items[].id.time`, `id.uniqueQualifier`, `actor.email`, `actor.callerType`, `actor.applicationInfo.applicationName`, `events[].name`, `ipAddress`, `nextPageToken` |
| `gws alertcenter:v1beta1 alerts list --params <json>` | `<api>:<version>` form: `parse_service_and_version` splits off the version suffix, but `resolve_service` still rejects any API absent from the `SERVICES` table, so this command fails with exit 3 on a build without an `alertcenter` alias (see the Alert Center caveat above); parameters from [alerts.list](https://developers.google.com/workspace/admin/alertcenter/reference/rest/v1beta1/alerts/list) | `--params` with `pageSize`, optional `filter` | `alerts[].alertId`, `type`, `source`, `createTime`, `updateTime`, `metadata.status`, `metadata.severity`, `metadata.assignee`, `nextPageToken` |
| `--page-all` (operator-run, parsed when present) | [README, Pagination](https://github.com/googleworkspace/cli#readme) | one JSON object per page (NDJSON) | aggregated `items[]` or `alerts[]`, last page `nextPageToken` |
