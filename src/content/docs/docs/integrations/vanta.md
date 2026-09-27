---
title: Vanta Auditor API
description: Validate Vanta auditor access, list visible audits, and export one audit into an offline evidence package.
---

The Vanta integration uses the read-only Auditor API. It validates an auditor OAuth client, lists audits visible to that client, and exports evidence for one audit. API calls do not change the Vanta tenant. The exporter writes only to the local output directory.

## Setup

Create Auditor API credentials in Vanta with the audit and auditor read scopes, then set:

```bash
export VANTA_CLIENT_ID="..."
printf 'Vanta client secret: '
IFS= read -rs VANTA_CLIENT_SECRET
printf '\n'
export VANTA_CLIENT_SECRET
```

The silent `read` keeps the secret value out of interactive Bash and Zsh history. A protected environment file or secret manager that injects the variable into the process is also appropriate. The tools accept `client_id` and `client_secret` arguments, but passing the secret as a tool argument can expose it to prompts, traces, or session storage.

## Tools

| Tool | Behavior |
| --- | --- |
| `vanta_check_access` | Validates credentials, probes the Auditor API, and reports whether any audits are visible. |
| `vanta_list_audits` | Lists visible audits and can filter locally by customer, organization, framework, or audit ID. |
| `vanta_export_audit` | Exports one audit into control folders, metadata, a CSV index, downloaded evidence files, and a zip archive. |

Use the access check first, then list audits to obtain the `audit_id`:

```text
vanta_check_access
vanta_list_audits
vanta_export_audit {"audit_id":"audit_123"}
```

## Export layout

The default output root is `./export/vanta`. The audit directory name is deterministic: customer, framework, and the first eight characters of the audit ID. Re-exporting the same audit to the same root reuses that directory and replaces the paired zip. Choose a different `output_dir` or move the completed package first when prior exports must be preserved.

An export contains:

- `_audit_info.json` with audit metadata and package totals
- `_index.csv` with one row per evidence item
- one directory per related control, each with `metadata.json`
- `_Unassigned/` for evidence without a related control
- downloaded evidence files when Vanta provides a downloadable URL
- `_errors.log` when individual downloads fail
- a zip archive paired with the output directory

Directories use mode `0700` and files use `0600`. The exporter rejects symlinked output paths and symlinks found during its pre-archive scan. Treat the package as sensitive audit evidence and store or share it accordingly.

## Live smoke

```bash
npm --prefix cli run test:vanta:live
```

The smoke test skips when `VANTA_CLIENT_ID` or `VANTA_CLIENT_SECRET` is missing. With credentials, it checks access and exports the newest visible audit, or the audit named by `VANTA_AUDIT_ID`. Set `VANTA_SMOKE_OUTPUT_DIR` to keep the package in a chosen directory.

## Limitations

- The integration exposes the Auditor API only. It does not manage Vanta controls, tests, users, or integrations.
- Visibility is limited to audits granted to the OAuth client.
- A partial download still produces the package and records each failure in `_errors.log`.
