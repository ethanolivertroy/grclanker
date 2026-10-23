---
title: Vanta Auditor API
description: Validate Vanta auditor access, list visible audits, and export one audit into an offline evidence package.
---

The Vanta integration uses the read-only Auditor API. It validates an auditor OAuth client, lists audits visible to that client, and exports evidence for one audit.

API calls do not change the Vanta tenant. The exporter writes only to the local output directory.

## Setup

Create Auditor API credentials in Vanta with the audit and auditor read scopes. The token request asks for `auditor-api.audit:read auditor-api.auditor:read`. Then set:

```bash
export VANTA_CLIENT_ID="..."
printf 'Vanta client secret: '
IFS= read -rs VANTA_CLIENT_SECRET
printf '\n'
export VANTA_CLIENT_SECRET
```

The silent `read` keeps the secret value out of interactive Bash and Zsh history. A protected environment file or secret manager that injects the variable into the process is also appropriate.

The tools accept `client_id` and `client_secret` arguments, but passing the secret as a tool argument can expose it to prompts, traces, or session storage.

## Run it

After setup, start `grclanker` and ask in plain words. The agent calls the matching tools. Vanta has no assessment tools, so ask for audits and an export:

```text
Check whether my Vanta auditor credentials can see any audits.
List my Vanta audits for SOC 2.
Export the Vanta audit for Acme Corp's SOC 2 report.
```

The [audit](/docs/workflows/audit/) workflow takes the same path, for example `grclanker audit "the Acme Corp SOC 2 audit in Vanta"`: `vanta_check_access`, then `vanta_list_audits` and `vanta_export_audit`.

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

The default output root is `./export/vanta`. The base audit directory name is deterministic: customer, framework, and the first eight characters of the audit ID.

Each export atomically claims the first available directory, adding a unique numeric suffix such as `_1` or `_2` when needed. The paired zip is created exclusively, so sequential or concurrent exports do not reuse or overwrite prior packages.

An export contains:

- `_audit_info.json` with audit metadata, package totals, and whether the package is complete
- `_index.csv` with one row per evidence item, including its `export_status`
- one directory per related control, each with `metadata.json`
- `_Unassigned/` for evidence without a related control
- downloaded evidence files when Vanta provides a downloadable URL
- `_errors.log` when a file URL listing or a download fails
- a zip archive paired with the output directory

Directories use mode `0700` and files use `0600`. The exporter rejects symlinked output paths and symlinks found during its pre-archive scan. Treat the package as sensitive audit evidence and store or share it accordingly.

## Retries and incomplete packages

Every Auditor API request, the token request included, is retried when it gets a 429, 500, 502, 503, or 504 answer, times out, or loses its connection. A request makes at most four attempts, and each attempt's 30-second timeout runs until the response body is read.

- Between attempts the client waits as long as the answer's `Retry-After` asks, in seconds or as an HTTP date. Without one, it waits 0.5, 1, then 2 seconds.
- A `Retry-After` longer than 30 seconds is not waited out. The request fails at once and its error names the wait, for example `Vanta API request failed for /audits (429 Too Many Requests): the server asked to retry after 120 s, more than the 30 s limit`, followed by the shortened response body.
- When the retries run out, the error names the attempts, for example `Vanta API request failed for /audits (503 Service Unavailable) after 4 attempts` or `Vanta API request failed for /audits after 4 attempts: timed out after 30000 ms`.
- A listing whose later page still fails after the retries fails the whole request, so no partial list of audits or evidence is returned. If the audit's evidence list cannot be read, the export fails and writes no package.

Evidence downloads are retried the same way up to the response headers of each redirect hop. A download body that has started is not retried: a body that sends no data for 30 seconds or breaks off is recorded as `Download stalled: no data for 30000 ms` or `Download failed partway: <reason>`, and the partly written file is removed.

An evidence item whose file URL listing or downloads still fail leaves a package that says it is incomplete:

- The tool reports `Exported Vanta audit "<customer> - <framework>" as an incomplete package.`, then a `The package is incomplete: ...` line that counts the gaps, and lists up to 10 of the affected evidence items. Its structured result carries `complete: false` and the same line as `incomplete_reason`.
- `_audit_info.json` sets `complete` to `false` and carries `evidence_items_with_unknown_urls`, `evidence_items_with_missing_files`, `files_not_downloaded`, and an `incomplete_evidence` list with each item's `id`, `name`, `export_status`, `missing_files`, and `reason`.
- Each evidence item in a control's `metadata.json` carries an `export_status` of `complete`, `files_missing`, or `urls_unknown`. A `files_missing` item lists its `missing_files`. A `urls_unknown` item has `files: null` rather than an empty list, because its files are unknown rather than absent. Both carry an `export_error`.
- In `_index.csv`, the `export_status` column carries the same value, and `file_count` is `unknown` for an item whose URL listing failed.
- `_errors.log` records each failed listing and download.

## Live smoke

```bash
npm --prefix cli run test:vanta:live
```

The smoke test skips when `VANTA_CLIENT_ID` or `VANTA_CLIENT_SECRET` is missing. With credentials, it checks access and exports the newest visible audit, or the audit named by `VANTA_AUDIT_ID`. Set `VANTA_SMOKE_OUTPUT_DIR` to keep the package in a chosen directory.

## Limitations

- The integration exposes the Auditor API only. It does not manage Vanta controls, tests, users, or integrations.
- Visibility is limited to audits granted to the OAuth client.
- A failed download or file URL listing still produces the package, marked incomplete as described in [Retries and incomplete packages](#retries-and-incomplete-packages), with each failure recorded in `_errors.log`.
- Incomplete Auditor API pagination fails the request. A missing `endCursor`, a repeated cursor, a later 404 (including after a page that returned no items), a later page that still fails after the retries, or the 500-page cap does not return the pages already read as a complete list. When evidence URL pagination fails, the evidence item is recorded in `_errors.log` and marked `urls_unknown`, so its files are not treated as absent.
- Authentication and API error text redacts the client id, client secret, and access token before the response body is shortened for display.
- A download that redirects off HTTPS records the destination host and path in `_errors.log` and omits userinfo and the query string, so a signed URL is not written into the package.
