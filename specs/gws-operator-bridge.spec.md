---
slug: "gws-operator-bridge"
name: "Google Workspace CLI Operator Bridge"
vendor: "Google"
category: "identity-access-management"
language: "typescript"
status: "implemented"
version: "1.0"
last_updated: "2026-09-21"
source_repo: "https://github.com/hackIDLE/grclanker"
---

# gws-operator-bridge: Architecture Specification

Implemented in grclanker as a companion to the native Google Workspace audit family:

- `gws_ops_check_cli`
- `gws_ops_investigate_alerts`
- `gws_ops_trace_admin_activity`
- `gws_ops_review_tokens`
- `gws_ops_collect_evidence_bundle`

## Overview

This slice adds a **read-only operator bridge** to the external `gws` CLI from `googleworkspace/cli`. It is intentionally separate from grclanker’s native Google Workspace compliance tools:

- The native GWS tools remain the authoritative assessment and framework-mapping path.
- The operator bridge is an optional convenience layer for ad hoc investigation and evidence collection when `gws` is already installed and authenticated.

## Scope

The first release is intentionally bounded:

- Read-only only
- GRC operator workflows only
- Curated commands only
- No arbitrary passthrough shelling to `gws`
- No write helpers like Gmail send, Docs write, Drive upload, or Calendar create

## Current Workflows

### `gws_ops_check_cli`

Checks whether `gws` is installed, reports the active CLI version, and previews or runs a harmless read-only Admin Reports probe.

### `gws_ops_investigate_alerts`

Uses the `gws` CLI to query Alert Center data and returns structured alert summaries plus the exact underlying command.

### `gws_ops_trace_admin_activity`

Uses the `gws` CLI to query recent Admin Reports activity for privileged changes.

### `gws_ops_review_tokens`

Uses the `gws` CLI to review token and OAuth activity telemetry. This is intentionally activity-first rather than a full tenant-wide token inventory clone.

### `gws_ops_collect_evidence_bundle`

Runs the curated alert, admin-activity, and token-activity workflows, then writes:

- raw structured CLI output
- normalized summaries
- executed commands
- a zipped operator evidence bundle

## Auth And Runtime

The bridge inherits `gws` auth/config behavior rather than duplicating it. The expected precedence remains owned by the upstream CLI:

1. `GOOGLE_WORKSPACE_CLI_TOKEN`
2. `GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE`
3. upstream encrypted credentials
4. upstream plaintext fallback

grclanker adds only:

- `GRCLANKER_GWS_BIN` for the binary path
- `config_dir` tool override mapped to `GOOGLE_WORKSPACE_CLI_CONFIG_DIR`

### grclanker implementation

- Source: `cli/extensions/grc-tools/gws-ops.ts`; tests: `cli/tests/gws-ops.test.mjs`; live smoke: `cli/scripts/gws-ops-live-smoke.mjs` (`npm --prefix cli run test:gws-ops:live`); guide: `src/content/docs/docs/integrations/gws-ops.md`.
- Command shapes (`gws <service> <resource> <method> --params '<json>'`, `--version`, `--page-all` NDJSON), exit codes 0 to 5, and the environment variables above are taken from the published googleworkspace/cli README; the `admin-reports` alias and the `<api>:<version>` form are confirmed against `crates/google-workspace/src/services.rs` and `crates/google-workspace-cli/src/main.rs`.
- Tests assert the `gws_bin` > `GRCLANKER_GWS_BIN` > `PATH` binary precedence, the `config_dir` to `GOOGLE_WORKSPACE_CLI_CONFIG_DIR` mapping, and that inherited `GOOGLE_WORKSPACE_CLI_TOKEN` and `GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE` values reach the child process untouched.

## Status

**Implemented in grclanker (TypeScript)** as an optional operator workflow layer. Real smoke testing depends on having `gws` installed and authenticated against a tenant; the live smoke skips cleanly otherwise.

### What shipped

- 5 of 5 workflows: `gws_ops_check_cli`, `gws_ops_investigate_alerts`, `gws_ops_trace_admin_activity`, `gws_ops_review_tokens`, `gws_ops_collect_evidence_bundle`, each with `dry_run` previews and the exact executed command in the result.
- Arbitrary passthrough is refused; only the curated read-only commands are built.
- Verdict-safety rules applied to the bridge: a non-zero exit is an explicit error mapped from the documented exit codes (rule 1); a zero exit with non-JSON output is an explicit error, except `--version` (rule 1); every result carries `complete` and `nextPageToken` so a page with a trailing token is recorded as a partial view (rules 5 and 7); `--page-all` NDJSON pages aggregate with completeness taken from the last page (rule 7); the evidence bundle allocates `-2`, `-3` and never overwrites an earlier directory or zip (rule 8).
- Normalized records read only documented fields: Alert Center `alertId`, `type`, `source`, `createTime`, `updateTime`, `metadata.status`, `metadata.severity`, `metadata.assignee`; Reports `id.time`, `id.uniqueQualifier`, `actor.email`, `actor.callerType`, `actor.applicationInfo.applicationName`, `events[].name`, `ipAddress`.
- Bundle secret hygiene (rule 9): `raw/<category>.json` is never the verbatim CLI stdout. Each page is projected to the documented Alert Center and Reports fields above (dropping `data`, `events[].parameters[]`, `actor.key`, `securityInvestigationToolLink`, and undocumented keys), then `raw/` and the records pass through the inspector's `redactSecrets` and a scrub of every `GOOGLE_WORKSPACE_CLI_*` token or secret value present in the environment. An end-to-end test drives a scripted `gws` that echoes its own `GOOGLE_WORKSPACE_CLI_TOKEN` and secret-bearing records, then greps every bundle file and zip entry.

### Deviations and caveats

- The googleworkspace/cli source consulted for this release registers no `alertcenter` service alias, and `parse_service_and_version` resolves the `<service>:<version>` form through the alias table, so `gws alertcenter:v1beta1 alerts list` fails with a validation error (exit 3) on such a build. `gws_ops_investigate_alerts` reports that as an explicit error naming the cause and pointing to `gws_assess_monitoring`; the command is left in place so a build that adds the alias works unchanged.
- `max_results` is clamped to 250 even though `activities.list` allows 1000, keeping operator output bounded; a trailing `nextPageToken` is reported instead of silently dropping records, and when the requested value exceeded 250 the notes state the requested value and the clamp (for example `Max results: 250 (requested 1000, clamped to the bridge limit of 250; ...)`).

### What remains

- No further scope is planned for this slice; write helpers stay out of scope by design.
