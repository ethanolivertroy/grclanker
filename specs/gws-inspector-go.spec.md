---
slug: "gws-inspector-go"
name: "Google Workspace Inspector"
vendor: "Google"
category: "identity-access-management"
language: "typescript"
status: "implemented"
version: "1.0"
last_updated: "2026-09-21"
source_repo: "https://github.com/hackIDLE/grclanker"
---

# gws-inspector-go: Architecture Specification

Implemented in grclanker as the first Google Workspace tool family:

- `gws_check_access`
- `gws_assess_identity`
- `gws_assess_admin_access`
- `gws_assess_integrations`
- `gws_assess_monitoring`
- `gws_export_audit_bundle`

The current grclanker implementation keeps the original multi-framework audit intent, but the first slice is intentionally bounded to the stable Google Workspace surfaces that are well suited to read-only GRC assessment:

- Admin SDK Directory API for users, roles, and role assignments
- Admin SDK Reports API for login, admin, and token audit activity
- Alert Center API for tenant security alerts
- Cloud Identity Policy API for the organization-level 2-step verification policy
- Per-user token inventory for bounded third-party OAuth review

The v1 auth path centers on service-account-based domain-wide delegated access, with optional direct bearer-token support for smoke tests or externally managed auth flows.

### grclanker implementation

- Source: `cli/extensions/grc-tools/gws.ts`; tests: `cli/tests/gws.test.mjs`; live smoke: `cli/scripts/gws-live-smoke.mjs` (`npm --prefix cli run test:gws:live`); guide: `src/content/docs/docs/integrations/gws.md`.
- 19 controls: `GWS-ID-001..005`, `GWS-ADMIN-001..005`, `GWS-INTEG-001..004`, `GWS-MON-001..005`, each mapped to the eight frameworks below.
- Every request and every field read is traceable to the Admin SDK Directory, Reports, Alert Center, or Cloud Identity reference pages cited in the module header and the guide's endpoint table.
- Verdicts follow eight safety rules with a regression test each: unreadable endpoints and empty inventories never pass, undated items are bucketed separately, partial views cap at Partial with seen counts, only documented enabling flags count, pagination runs to completion or records truncation, and re-running the export never overwrites.

## Overview

Go implementation of gws-inspector: a multi-framework compliance audit tool for Google Workspace. This is a port of the Python `gws-inspector` package, providing a single-binary distribution with no runtime dependencies.

## Reference Implementation

The Python implementation is the source of truth: [github.com/hackIDLE/gws-inspector-py](https://github.com/hackIDLE/gws-inspector-py)

## Architecture

Mirror the Python package structure:

```
cmd/
└── gws-inspector/
    └── main.go                 # CLI entry point (cobra or kong)

internal/
├── auth/
│   └── auth.go                 # Service account + OAuth2 authentication
├── client/
│   └── client.go               # GWSClient: wraps multiple Google API services
├── collector/
│   └── collector.go            # GWSDataCollector → GWSData
├── models/
│   ├── finding.go              # ComplianceFinding
│   ├── data.go                 # GWSData (in-memory data bus)
│   └── analysis.go             # Intermediate analysis types
├── engine/
│   └── engine.go               # AuditEngine: collect → analyze → report → archive
├── output/
│   └── output.go               # OutputManager
├── analyzers/
│   ├── registry.go             # Framework registry pattern
│   ├── common.go               # Shared analysis functions
│   ├── fedramp.go              # FedRAMP (NIST 800-53)
│   ├── cmmc.go                 # CMMC 2.0 (NIST 800-171)
│   ├── soc2.go                 # SOC 2
│   ├── stig.go                 # DISA STIG
│   ├── irap.go                 # IRAP (ISM + Essential Eight)
│   ├── ismap.go                # ISMAP (ISO 27001)
│   ├── pci_dss.go              # PCI-DSS 4.0.1
│   └── cis.go                  # CIS Google Workspace Benchmark
└── reporters/
    ├── registry.go
    ├── executive.go
    ├── matrix.go
    ├── validation.go
    ├── fedramp.go, cmmc.go, soc2.go, stig.go
    ├── irap.go, ismap.go, pci_dss.go
    └── cis.go
```

## Key Dependencies

```go
require (
    golang.org/x/oauth2
    google.golang.org/api v0.200+
    github.com/spf13/cobra         // or alecthomas/kong
)
```

Google API packages:
- `google.golang.org/api/admin/directory/v1`
- `google.golang.org/api/admin/reports/v1`
- `google.golang.org/api/alertcenter/v1beta1`
- `google.golang.org/api/cloudidentity/v1`
- `google.golang.org/api/chromepolicy/v1`

## Google APIs (6 services)

| API | Go Package | Purpose |
|-----|-----------|---------|
| Admin Directory | `admin/directory/v1` | Users, groups, OUs, roles, domains, mobile devices |
| Admin Reports | `admin/reports/v1` | Audit logs (admin, login, drive, token) |
| Policy API | TBD (may need raw HTTP) | 2SV, passwords, sessions, security settings per OU |
| Alert Center | `alertcenter/v1beta1` | Security alerts |
| Chrome Policy | `chromepolicy/v1` | Browser policies per OU |
| Cloud Identity | `cloudidentity/v1` | Device management |

## Compliance Frameworks (8)

1. FedRAMP (NIST 800-53)
2. CMMC 2.0 (NIST 800-171)
3. SOC 2
4. DISA STIG (CIS-mapped)
5. IRAP (ISM + Essential Eight)
6. ISMAP (ISO 27001)
7. PCI-DSS 4.0.1
8. CIS Google Workspace Benchmark v1.2.0

## Security Controls (19 checks)

Identical to the Python implementation; see the Python repo's plan for the full control-to-framework matrix.

## CLI Interface

```bash
gws-inspector -c credentials.json -a admin@example.com -d example.com
gws-inspector -c credentials.json -a admin@example.com -d example.com --frameworks fedramp,cmmc
```

Flags:
- `-c, --credentials`: service account JSON or OAuth client secrets
- `-a, --admin-email`: admin email for delegation
- `-d, --domain`: Google Workspace domain
- `--oauth`: use OAuth flow
- `--frameworks`: comma-separated framework list
- `-o, --output-dir`: custom output dir
- `-V, --version`

Environment variables: `GWS_CREDENTIALS_FILE`, `GWS_ADMIN_EMAIL`, `GWS_DOMAIN`

## Build

```bash
go build -o gws-inspector ./cmd/gws-inspector
```

## Status

**Implemented in grclanker (TypeScript).** The Go port described above was superseded by the native grclanker implementation in `cli/extensions/grc-tools/gws.ts`; the Python package remains the conceptual reference for the control set.

### What shipped

- 19 of 19 controls across `gws_assess_identity` (5), `gws_assess_admin_access` (5), `gws_assess_integrations` (4), and `gws_assess_monitoring` (5), plus `gws_check_access` and `gws_export_audit_bundle`.
- `GWS-ID-005` (2-step verification enforced by organization policy) reads the Cloud Identity Policy API (`policies.list` filtered to `settings/security.two_step_verification*`) and evaluates `enforcedFrom`, `allowEnrollment`, and `allowedSignInFactorSet` from the published settings catalog.
- Auth: service-account domain-wide delegation (`GWS_CREDENTIALS_FILE` or `GWS_CREDENTIALS_JSON` plus `GWS_ADMIN_EMAIL`) and direct `GWS_ACCESS_TOKEN`. The Policy API scope is requested with a separate token so tenants without it keep the other 18 controls automated.
- Bundle layout: `core_data/` (one `{status, endpoint, data, seen, pages, truncated}` object per listing, projected to the documented fields the verdicts read and then redacted; a failed or never-attempted read writes `error` and `errorKind` with `data`, `seen`, `pages`, and `truncated` all null), `analysis/` (`findings.json` plus per-category JSON and Markdown), `compliance/` (`executive_summary.md`, `unified_compliance_matrix.md`, one report per framework), `QUICK_REFERENCE.md`, `_errors.log` on partial collection, and a zip named after the allocated directory; reruns allocate `-2`, `-3`.
- The `--frameworks` flag from the CLI interface above maps to the `frameworks` argument of `gws_export_audit_bundle`.
- Verdict-safety rules 1 to 11 applied to every finding, with a regression test per rule and a four-fixture false-pass self-check (all 403, all empty, partial inventory, compliant tenant) in `cli/tests/gws.test.mjs`.
- Rule 1 per item: the token inventory records every failed per-user `tokens.list` read with the user, and GWS-INTEG-001, GWS-INTEG-002, and GWS-INTEG-003 name the failed users and the endpoint in every branch; GWS-INTEG-002 renders its privileged counts as lower bounds when a privileged read failed and stays below Pass. `roles.list` and `roleAssignments.list` order the token sample privileged-first, so when either is unreadable GWS-INTEG-001 and GWS-INTEG-003 cap at Partial and name that endpoint in the summary.
- Rule 9 (bundle secret hygiene) projects every `core_data/` object to documented fields, never stores Alert Center `data` or `events[].parameters[]`, and redacts credential-like keys on normalized names and `{name, value}` pairs. Findings and collection errors are redacted as objects before rendering, and every bundle file (`core_data/`, `analysis/`, `compliance/`, `QUICK_REFERENCE.md`, `_errors.log`) passes through one text scrubber on its way to disk: the query string and fragment of every URL, bare or embedded in prose, are removed; well-known credential shapes and `key=value` or `key: value` pairs naming a credential are replaced; and the run's own bearer token, service-account key, and every token minted during the run (kept in the scrub set after a 401 evicts it from the cache) are replaced wherever they appear. API error bodies are reduced at the client to the HTTP status plus documented identifiers (`error.status`, `errors[].reason`, `details[].reason`, RFC 6749 `error`) that are bare `[A-Za-z][A-Za-z0-9_]*` values of at most 63 characters; the HTTP reason phrase comes from a fixed RFC 9110 table, the free-text `message` is never stored, and `_errors.log` names the failing endpoint per line. Third-party OAuth `displayText` is scrubbed and paired with `clientId` in the GWS-INTEG-002 evidence. An end-to-end test exports a bundle from fixtures carrying a planted secret in every carrier, including a mid-prose URL query in `displayText`, a failing endpoint whose error body carries planted values through the real client, and the run's own non-Google-shaped bearer echoed into `User.orgUnitPath` and `Alert.source` so the final write-time scrub has a negative control, and greps every file and zip entry; a second export through the real client rotates a service-account token on a 401 and confirms the evicted token is scrubbed.
- Rule 10 (truncation on every cap exit) gives roles (1000) and role assignments (10000) finite caps, ends a listing whose `nextPageToken` stops advancing or exceeds 1000 pages as `truncated: true`, and caps GWS-ID-001, GWS-ID-004, GWS-ADMIN-001 to 003, GWS-ADMIN-005, and GWS-INTEG-002 at Partial whenever the user, role, or role-assignment listing was truncated.
- Rule 11 (unreadable or never-collected data renders null, never 0 or []): every snapshot count in the four assessment summaries goes through one helper (`snapshotCount` in `gws.ts`) that writes the value beside a `<field>_status` companion reading `complete`, `partial: at least N`, `unreadable`, or `not collected`, each naming the endpoint and the projected error; a count derived from several inventories is only as readable as its weakest source and is null when any of them failed or was never collected. `users_seen_partial_view` reads from the users.list collection status (`no`, `yes`, or `unreadable (...)`). Evidence lines go through the same helper family (`countLine`), so GWS-INTEG-001, GWS-INTEG-002, and GWS-INTEG-003 render `at least N (Directory tokens.list failed for K of S sampled users (user: error))` whenever any per-user read failed and `unreadable (...)` when none succeeded. `core_data/` files write the explicit marker described under the bundle layout, and `token_inventory.json` sets `truncated` to null whenever any per-user read failed. The regression sweep runs 34 denial scenarios (users, roles, role assignments, three Reports applications, alerts, policies, and tokens.list for every user, the privileged user, and the token holder, each as 403, 401, and a transport error, plus the never-collected Policy API dataset) over every finding line, snapshot field, and `core_data/` file with two generic guards, `assertNoFabricatedValues` and `assertStatusesMatchRequests`, against a fixture collector that records every endpoint it was asked to read.

### Deviations from this spec

- Language is TypeScript inside grclanker, not a standalone Go binary; the `cmd/` and `internal/` layout above is historical.
- Of the six Google APIs listed, four are called (Directory, Reports, Alert Center, Cloud Identity Policy API). Chrome Policy (`chromepolicy/v1`) and Cloud Identity device management are not called because no shipped control depends on them.
- `roles.list` is requested with `maxResults=100`, the documented maximum, rather than a shared page size.
- Alert status is read from `metadata.status` (`NOT_STARTED`, `IN_PROGRESS`, `CLOSED`) per the Alert Center Alert resource; there is no top-level state field.
- `RoleAssignment.assigneeType` is documented as `USER` or `GROUP`; comparisons are case-insensitive.
- Alert Center `pageSize` has no documented maximum; grclanker requests 100 per page and follows `nextPageToken`.

### Deferred

- Installed-app OAuth (`--oauth` with client secrets and a stored refresh token) is not implemented; the delegated service account and access-token modes cover the automated paths. Reason: it did not fit the delivery budget for this release and requires an interactive loopback flow that the other integrations do not yet share.
- Chrome Policy API and Cloud Identity device controls (no spec control names them yet).
- Group membership expansion for `GWS-ADMIN-005`; group-based admin grants render Manual for a membership review.
