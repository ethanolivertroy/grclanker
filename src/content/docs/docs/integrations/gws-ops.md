---
title: Google Workspace CLI operator bridge
description: Optional read-only bridge that runs a curated set of googleworkspace/cli (gws) investigation commands and packages the results as operator evidence.
---

The operator bridge (`gws_ops_*` tools) shells out to the external [`gws` CLI](https://github.com/googleworkspace/cli) when it is already installed and authenticated. It runs five curated read-only workflows, records the exact command it executed, and packages the structured output as evidence. It never accepts arbitrary `gws` arguments, never runs a write method, and does not replace the native [Google Workspace inspector](/docs/integrations/gws), which remains the framework-mapped assessment path.

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

Every other `GOOGLE_WORKSPACE_CLI_*` variable in grclanker's environment is passed through unchanged; `cli/tests/gws-ops.test.mjs` asserts this precedence.

## Workflows

| Tool | Underlying command | Read-only? | Output |
| --- | --- | --- | --- |
| `gws_ops_check_cli` | `gws --version`, then `gws admin-reports activities list --params '{"userKey":"all","applicationName":"admin","maxResults":1,"startTime":"<7 days ago>"}'` | yes | Executable path, version, probe status |
| `gws_ops_investigate_alerts` | `gws alertcenter:v1beta1 alerts list --params '{"pageSize":<max_results>,"filter":"<filter>"}'` | yes | Alert records (`alertId`, `type`, `source`, `createTime`, `metadata.status`, `metadata.severity`, `metadata.assignee`) |
| `gws_ops_trace_admin_activity` | `gws admin-reports activities list --params '{"userKey":"all","applicationName":"admin","maxResults":<n>,"startTime":"<lookback>"}'` | yes | Activity records (`id.time`, `id.uniqueQualifier`, `actor.email`, `events[].name`, `ipAddress`) |
| `gws_ops_review_tokens` | Same as above with `"applicationName":"token"` | yes | Token and OAuth activity records with `actor.applicationInfo.applicationName` |
| `gws_ops_collect_evidence_bundle` | The three commands above | yes | `raw/`, `analysis/`, `commands.json`, `summary.md`, `README.md`, and a zip |

Every workflow accepts `dry_run: true` to print the exact command without executing it. `max_results` is clamped to 1-250 and `lookback_days` to 1-90.

## Result semantics

The bridge applies the inspector's verdict-safety rules that are meaningful for a CLI wrapper:

- A non-zero exit is an explicit `GwsCliCommandError` whose kind follows the CLI's documented exit codes: 1 API error, 2 auth error, 3 validation error, 4 discovery error, 5 internal error ([README, Exit Codes](https://github.com/googleworkspace/cli#exit-codes)). A missing binary is reported with install guidance.
- A zero exit whose stdout is not JSON (or NDJSON from `--page-all`) is an explicit error; only `gws --version` may print plain text.
- Every result carries `complete` and `next_page_token`. When the last page in the response has a `nextPageToken`, `complete` is `false` and the notes say so; a single page is never presented as the whole population.
- `--page-all` NDJSON output (one JSON object per page, per the README pagination table) is aggregated across pages and completeness follows the last page.
- The evidence bundle allocates `gws-operator-evidence`, then `-2`, `-3`, and so on under `output_dir` (default `./export/gws-ops`), names the zip after the allocated directory, and never overwrites an earlier directory or zip. Output paths are validated against traversal and symlinked parents.

## Alert Center caveat

The published `gws` source registers service aliases in `crates/google-workspace/src/services.rs` (for example `admin-reports` and `reports` for `admin/reports_v1`), and `parse_service_and_version` in `crates/google-workspace-cli/src/main.rs` resolves the `<service>:<version>` form through that alias table. No `alertcenter` alias is registered in the source consulted for this release, so `gws alertcenter:v1beta1 alerts list` fails with a validation error (exit 3) on such a build. The bridge surfaces that as an explicit error that names the cause and points to `gws_assess_monitoring`, which calls the Alert Center API natively. If a future `gws` release adds the alias, the command works unchanged.

## Live smoke

```bash
npm --prefix cli run test:gws-ops:live
```

Runs `gws_ops_check_cli`, the admin and token traces, the alert investigation (skipped with the validation message above when the alias is missing), and a dry run of the evidence bundle. When `gws` is not installed or not authenticated, the script prints a skip message and exits 0.

## Limitations

- The bridge is optional; it does no framework mapping and produces no Pass, Partial, or Fail verdicts. Use the native inspector for compliance findings.
- Only the five workflows above are exposed. Arbitrary `gws` passthrough is refused by design.
- `gws_ops_review_tokens` reviews token activity telemetry; it does not clone a tenant-wide token inventory (the inspector's `gws_assess_integrations` does that).
- Real smoke testing requires an installed and authenticated `gws` binary.

## Command reference

| Command | Documentation | Flags used | Fields read |
| --- | --- | --- | --- |
| `gws --version` | [README, Quick Start](https://github.com/googleworkspace/cli#readme) | none | plain-text version line |
| `gws admin-reports activities list --params <json>` | [README command shape](https://github.com/googleworkspace/cli#readme); parameters from [activities.list](https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list) | `--params` with `userKey`, `applicationName`, `maxResults` (documented maximum 1000; the bridge caps at 250), `startTime` | `items[].id.time`, `id.uniqueQualifier`, `actor.email`, `actor.callerType`, `actor.applicationInfo.applicationName`, `events[].name`, `ipAddress`, `nextPageToken` |
| `gws alertcenter:v1beta1 alerts list --params <json>` | `<api>:<version>` form from `parse_service_and_version`; parameters from [alerts.list](https://developers.google.com/workspace/admin/alertcenter/reference/rest/v1beta1/alerts/list) | `--params` with `pageSize`, optional `filter` | `alerts[].alertId`, `type`, `source`, `createTime`, `updateTime`, `metadata.status`, `metadata.severity`, `metadata.assignee`, `nextPageToken` |
| `--page-all` (operator-run, parsed when present) | [README, Pagination](https://github.com/googleworkspace/cli#readme) | one JSON object per page (NDJSON) | aggregated `items[]` or `alerts[]`, last page `nextPageToken` |
