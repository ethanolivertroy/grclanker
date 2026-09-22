---
slug: "zoom-sec-inspector"
name: "Zoom Security Inspector"
vendor: "Zoom"
category: "saas-collaboration"
language: "typescript"
status: "implemented"
version: "1.0"
last_updated: "2026-09-21"
source_repo: "https://github.com/hackIDLE/grclanker"
---

# Zoom Security Inspector

## 1. Overview

A security compliance inspection tool for **Zoom for Government** and Zoom Workplace environments. Audits account-level and user-level security settings, meeting policies, recording controls, authentication enforcement, and communication restrictions against enterprise security baselines and government compliance frameworks.

Targets Zoom accounts using the Zoom REST API v2 to evaluate configuration posture, identify misconfigurations, and generate compliance-mapped findings.

## 2. APIs & SDKs

### Zoom REST API v2

Base URL: `https://api.zoom.us/v2` (commercial) / `https://api.zoomgov.com/v2` (GovCloud)

| Endpoint | Purpose |
|----------|---------|
| `GET /accounts/{accountId}/settings` | Account-level security and meeting settings |
| `GET /accounts/{accountId}/lock_settings` | Locked (enforced) settings at account level |
| `GET /users` | List all users, pagination |
| `GET /users/{userId}/settings` | Per-user meeting, recording, telephony settings |
| `GET /users/{userId}/token` | User ZAK token info |
| `GET /roles` | List all custom roles |
| `GET /roles/{roleId}` | Role detail and privileges |
| `GET /roles/{roleId}/members` | Members assigned to a role |
| `GET /groups` | List all groups |
| `GET /groups/{groupId}/settings` | Group-level setting overrides |
| `GET /groups/{groupId}/lock_settings` | Locked settings at group level |
| `GET /report/meetings` | Meeting usage reports |
| `GET /report/operationlogs` | Admin operation/audit logs |
| `GET /im/groups` | IM (chat) group configuration |
| `GET /im/groups/{imGroupId}` | IM group detail and members |
| `GET /accounts/{accountId}/managed_domains` | Managed/associated domains |
| `GET /accounts/{accountId}/trusted_domains` | Trusted external domains |
| `GET /phone/call_handling/settings` | Zoom Phone call handling settings |
| `GET /phone/recording` | Zoom Phone recording policies |

### Rate Limits

- Per-second rate limits vary by endpoint category (heavy: 1 req/s, medium: 10 req/s, light: 30 req/s)
- Daily rate limits apply to report endpoints (60 requests/day for some)
- Response header `X-RateLimit-Remaining` for tracking

### SDKs & Tools

| Tool | Type | Notes |
|------|------|-------|
| `zoom-python` | Community Python SDK | Wraps REST API v2, not officially maintained |
| `zoomus` | Community Python SDK | Alternative community wrapper |
| Zoom CLI | Official CLI | Limited to meeting/webinar management |
| `httpx` / `requests` | HTTP client | Direct API calls recommended for reliability |

## 3. Authentication

### Server-to-Server OAuth (Recommended)

- Created in Zoom App Marketplace as "Server-to-Server OAuth" app type
- Provides `account_id`, `client_id`, `client_secret`
- Token endpoint: `POST https://zoom.us/oauth/token` with basic auth (`client_id:client_secret`) and an `application/x-www-form-urlencoded` body `grant_type=account_credentials&account_id={account_id}` (no query parameters)
- Tokens expire in 1 hour, must be refreshed
- Scopes required: `account:read:admin`, `user:read:admin`, `group:read:admin`, `role:read:admin`, `report:read:admin`, `im:read:admin`, `phone:read:admin`
- Best for automated/headless inspection

### OAuth 2.0 (User-Level)

- Authorization Code flow for interactive use
- Redirect URI required
- Scopes granted per-user

### JWT (Deprecated)

- Deprecated June 2023, removed September 2023
- Should not be used; detect and warn if configured

### Configuration

```
ZOOM_ACCOUNT_ID=<account_id>
ZOOM_CLIENT_ID=<client_id>
ZOOM_CLIENT_SECRET=<client_secret>
ZOOM_BASE_URL=https://api.zoom.us/v2       # or https://api.zoomgov.com/v2
```

### grclanker implementation

The grclanker CLI ships this spec as the native tool family in `cli/extensions/grc-tools/zoom.ts`: `zoom_check_access`, `zoom_assess_identity`, `zoom_assess_collaboration_governance`, `zoom_assess_meeting_security`, and `zoom_export_audit_bundle`. Credentials resolve from tool arguments, then the environment variables above (plus `ZOOM_TOKEN` for a pre-issued bearer token, `ZOOM_OAUTH_BASE_URL`, `ZOOM_TIMEOUT`, and `ZOOM_CONFIG_FILE`), then a JSON config file at `ZOOM_CONFIG_FILE`, `./.zoom.json`, `./.grclanker-zoom.json`, `~/.zoom.json`, `~/.grclanker-zoom.json`, or `~/.config/grclanker/zoom.json`. Only Server-to-Server OAuth is implemented; the user-level OAuth flow is out of scope for the CLI and JWT is not supported. The integration guide with the endpoint table lives at `src/content/docs/docs/integrations/zoom.md`, tests in `cli/tests/zoom.test.mjs`, and the live smoke script at `cli/scripts/zoom-live-smoke.mjs` (`npm --prefix cli run test:zoom:live`).

## 4. Security Controls

| # | Control | API Source | Severity |
|---|---------|-----------|----------|
| 1 | Meeting password enforcement enabled | `/accounts/{id}/settings` → `schedule_meeting.require_password_for_scheduling_new_meetings` | Critical |
| 2 | Waiting room enabled by default | `/accounts/{id}/settings` → `in_meeting.waiting_room` | Critical |
| 3 | Screen sharing restricted to host only | `/accounts/{id}/settings` → `in_meeting.screen_sharing` | High |
| 4 | Recording consent notification enabled | `/accounts/{id}/settings` → `recording.recording_disclaimer` | High |
| 5 | SSO enforcement for all users | `/users` → `login_type` field analysis | Critical |
| 6 | Two-factor authentication for admins | `/users/{id}/settings` → `feature.two_factor_auth` | Critical |
| 7 | End-to-end encryption available and default | `/accounts/{id}/settings` → `in_meeting.e2e_encryption` | High |
| 8 | Chat encryption enabled | `/accounts/{id}/settings` → `in_meeting.chat` encryption settings | Medium |
| 9 | File transfer in meetings restricted | `/accounts/{id}/settings` → `in_meeting.file_transfer` | Medium |
| 10 | Cloud recording auto-delete policy configured | `/accounts/{id}/settings` → `recording.auto_delete_cmr` | High |
| 11 | Cloud recording auto-delete days ≤ retention policy | `/accounts/{id}/settings` → `recording.auto_delete_cmr_days` | Medium |
| 12 | External contacts restricted | `/accounts/{id}/settings` → `in_meeting.allow_participants_to_rename` | Medium |
| 13 | Vanity URL configured and secured | `/accounts/{id}/settings` → account vanity URL | Low |
| 14 | Managed domains verified | `/accounts/{id}/managed_domains` | High |
| 15 | IM group restrictions enforced | `/im/groups` → group settings analysis | Medium |
| 16 | Sign-in methods restricted (no personal email) | `/users` → `login_type` analysis | High |
| 17 | Session timeout configured ≤ organizational policy | `/accounts/{id}/settings` → `security.session_duration` | Medium |
| 18 | Data routing control enabled (GovCloud/data residency) | `/accounts/{id}/settings` → `in_meeting.data_center_regions` | Critical |
| 19 | Zoom Phone recording policies enforced | `/phone/recording` | High |
| 20 | Local recording disabled or restricted | `/accounts/{id}/settings` → `recording.local_recording` | High |
| 21 | Meeting password locked at account level | `/accounts/{id}/lock_settings` → password settings | Critical |
| 22 | Embed password in join link disabled | `/accounts/{id}/settings` → `schedule_meeting.embed_password_in_join_link` | Medium |
| 23 | Only authenticated users can join meetings | `/accounts/{id}/settings` → `schedule_meeting.meeting_authentication` | High |
| 24 | Admin operation log retention verified | `/report/operationlogs` | Medium |
| 25 | Personal Meeting ID (PMI) usage restricted | `/accounts/{id}/settings` → `schedule_meeting.use_pmi_for_scheduled_meetings` | Medium |

## 5. Compliance Framework Mappings

| Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | STIG | IRAP | ISMAP |
|---------|---------|------|-------|-----|---------|------|------|-------|
| 1. Meeting password enforcement | AC-3 | AC.L2-3.1.1 | CC6.1 | 5.2 | 8.3.1 | SRG-APP-000033 | ISM-0974 | 8.1.1 |
| 2. Waiting room enabled | AC-3 | AC.L2-3.1.2 | CC6.1 | 5.2 | 7.1.1 | SRG-APP-000033 | ISM-0974 | 8.1.1 |
| 3. Screen sharing restricted | AC-3 | AC.L2-3.1.5 | CC6.1 | 5.3 | 7.1.2 | SRG-APP-000038 | ISM-1146 | 8.1.2 |
| 4. Recording consent | AU-14 | AU.L2-3.3.1 | CC7.2 | 8.1 | 10.1 | SRG-APP-000092 | ISM-0580 | 12.1.1 |
| 5. SSO enforcement | IA-2 | IA.L2-3.5.1 | CC6.1 | 4.1 | 8.3.1 | SRG-APP-000148 | ISM-1557 | 8.2.1 |
| 6. 2FA for admins | IA-2(1) | IA.L2-3.5.3 | CC6.1 | 4.5 | 8.3.2 | SRG-APP-000149 | ISM-1401 | 8.2.2 |
| 7. E2E encryption | SC-8(1) | SC.L2-3.13.8 | CC6.7 | 14.4 | 4.1 | SRG-APP-000441 | ISM-0487 | 10.1.1 |
| 8. Chat encryption | SC-8 | SC.L2-3.13.1 | CC6.7 | 14.4 | 4.1 | SRG-APP-000439 | ISM-0487 | 10.1.1 |
| 9. File transfer restricted | SC-7 | SC.L2-3.13.6 | CC6.6 | 13.1 | 1.3.1 | SRG-APP-000383 | ISM-1284 | 10.2.1 |
| 10. Cloud recording auto-delete | SI-12 | MP.L2-3.8.3 | CC6.5 | 3.1 | 3.1 | SRG-APP-000504 | ISM-0261 | 7.1.1 |
| 11. Recording retention days | SI-12 | MP.L2-3.8.3 | CC6.5 | 3.1 | 3.1 | SRG-APP-000504 | ISM-0261 | 7.1.1 |
| 12. External contacts restricted | AC-4 | AC.L2-3.1.3 | CC6.6 | 13.4 | 1.3.4 | SRG-APP-000039 | ISM-1284 | 8.1.3 |
| 13. Vanity URL secured | IA-8 | IA.L2-3.5.2 | CC6.1 | 4.1 | 8.1.1 | SRG-APP-000153 | ISM-1557 | 8.2.1 |
| 14. Managed domains verified | IA-8 | IA.L2-3.5.2 | CC6.1 | 4.1 | 8.1.1 | SRG-APP-000153 | ISM-1557 | 8.2.1 |
| 15. IM group restrictions | AC-4 | AC.L2-3.1.3 | CC6.6 | 13.4 | 7.1.2 | SRG-APP-000039 | ISM-1284 | 8.1.3 |
| 16. Sign-in methods restricted | IA-5 | IA.L2-3.5.7 | CC6.1 | 4.1 | 8.2.1 | SRG-APP-000170 | ISM-1557 | 8.2.3 |
| 17. Session timeout | AC-12 | AC.L2-3.1.10 | CC6.1 | 5.6 | 8.1.8 | SRG-APP-000295 | ISM-1164 | 8.3.1 |
| 18. Data routing control | SC-7 | SC.L2-3.13.1 | CC6.6 | 13.1 | 1.3.1 | SRG-APP-000383 | ISM-1037 | 10.2.1 |
| 19. Phone recording policies | AU-14 | AU.L2-3.3.1 | CC7.2 | 8.1 | 10.1 | SRG-APP-000092 | ISM-0580 | 12.1.1 |
| 20. Local recording restricted | AC-3 | MP.L2-3.8.1 | CC6.1 | 3.1 | 3.4.1 | SRG-APP-000033 | ISM-0261 | 7.1.2 |
| 21. Password locked at account | AC-3 | AC.L2-3.1.1 | CC6.1 | 5.2 | 8.3.1 | SRG-APP-000033 | ISM-0974 | 8.1.1 |
| 22. Embed password in link disabled | IA-5 | IA.L2-3.5.10 | CC6.1 | 5.2 | 8.2.1 | SRG-APP-000170 | ISM-0974 | 8.2.3 |
| 23. Authenticated users only | IA-2 | IA.L2-3.5.1 | CC6.1 | 4.1 | 8.3.1 | SRG-APP-000148 | ISM-1557 | 8.2.1 |
| 24. Audit log retention | AU-11 | AU.L2-3.3.1 | CC7.2 | 8.3 | 10.7 | SRG-APP-000515 | ISM-0859 | 12.1.2 |
| 25. PMI usage restricted | AC-3 | AC.L2-3.1.5 | CC6.1 | 5.3 | 8.1.1 | SRG-APP-000038 | ISM-0974 | 8.1.2 |

## 6. Existing Tools

| Tool | Type | Notes |
|------|------|-------|
| Zoom Admin Dashboard | Built-in | Manual review of settings, no automation |
| ScoutSuite | Open source | Multi-cloud; no Zoom provider |
| Prowler | Open source | AWS/Azure/GCP focus; no Zoom |
| Drata / Vanta | Commercial SaaS | Zoom integration for compliance, closed source |
| Resmo | Commercial SaaS | Zoom asset inventory, limited security checks |
| **No open-source Zoom security inspector exists** | Gap | This tool fills the gap |

## 7. Architecture

```
zoom-sec-inspector/
├── cmd/
│   └── zoom-sec-inspector/
│       └── main.go                 # Entry point, CLI parsing
├── internal/
│   ├── auth/
│   │   ├── oauth.go                # Server-to-Server OAuth token management
│   │   └── config.go               # Credential loading, validation
│   ├── client/
│   │   ├── zoom.go                 # HTTP client with rate limiting, retries
│   │   ├── accounts.go             # Account settings API calls
│   │   ├── users.go                # User listing and settings
│   │   ├── groups.go               # Group and IM group calls
│   │   ├── roles.go                # Role enumeration
│   │   ├── reports.go              # Report and audit log calls
│   │   └── phone.go                # Zoom Phone API calls
│   ├── analyzers/
│   │   ├── analyzer.go             # Analyzer interface definition
│   │   ├── meeting_security.go     # Controls 1-3, 21-23, 25
│   │   ├── authentication.go       # Controls 5, 6, 16
│   │   ├── encryption.go           # Controls 7, 8
│   │   ├── recording.go            # Controls 4, 10, 11, 19, 20
│   │   ├── communication.go        # Controls 9, 12, 15
│   │   ├── account_hygiene.go      # Controls 13, 14, 17, 24
│   │   └── data_residency.go       # Control 18
│   ├── models/
│   │   ├── settings.go             # Account/user/group settings structs
│   │   ├── finding.go              # Security finding with severity, mapping
│   │   └── compliance.go           # Framework mapping definitions
│   └── reporters/
│       ├── reporter.go             # Reporter interface
│       ├── json.go                 # JSON output
│       ├── csv.go                  # CSV output
│       ├── html.go                 # HTML dashboard report
│       └── sarif.go                # SARIF for CI/CD integration
├── pkg/
│   └── version/
│       └── version.go              # Build version info
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile
├── spec.md
└── README.md
```

## 8. CLI Interface

```
zoom-sec-inspector [flags]

Flags:
  --account-id string       Zoom account ID (or ZOOM_ACCOUNT_ID env)
  --client-id string        OAuth client ID (or ZOOM_CLIENT_ID env)
  --client-secret string    OAuth client secret (or ZOOM_CLIENT_SECRET env)
  --base-url string         API base URL (default: https://api.zoom.us/v2)
  --govcloud                Use ZoomGov base URL (https://api.zoomgov.com/v2)
  --controls string         Comma-separated control IDs to run (default: all)
  --skip-controls string    Comma-separated control IDs to skip
  --severity string         Minimum severity to report: critical,high,medium,low (default: low)
  --format string           Output format: json,csv,html,sarif (default: json)
  --output string           Output file path (default: stdout)
  --include-users           Include per-user setting analysis (slower)
  --include-groups          Include per-group setting analysis
  --concurrency int         Max concurrent API requests (default: 5)
  --timeout duration        HTTP request timeout (default: 30s)
  --verbose                 Enable verbose/debug logging
  --version                 Print version and exit
  --help                    Show help
```

### Example Usage

```bash
# Full inspection with JSON output
zoom-sec-inspector --govcloud --format json --output report.json

# Critical controls only, HTML report
zoom-sec-inspector --severity critical --format html --output dashboard.html

# Specific controls with user analysis
zoom-sec-inspector --controls 1,2,5,6,18 --include-users --format json
```

## 9. Build Sequence

```bash
# 1. Initialize module
go mod init github.com/hackIDLE/zoom-sec-inspector

# 2. Define models and interfaces
#    - internal/models/finding.go (Finding struct, Severity enum)
#    - internal/models/compliance.go (framework mapping tables)
#    - internal/analyzers/analyzer.go (Analyzer interface)
#    - internal/reporters/reporter.go (Reporter interface)

# 3. Implement authentication
#    - internal/auth/config.go (env/flag loading)
#    - internal/auth/oauth.go (S2S OAuth token refresh)

# 4. Build API client
#    - internal/client/zoom.go (base client, rate limiter)
#    - internal/client/accounts.go, users.go, groups.go, etc.

# 5. Implement analyzers (one per control group)
#    - internal/analyzers/meeting_security.go
#    - internal/analyzers/authentication.go
#    - ... (all 7 analyzer files)

# 6. Implement reporters
#    - internal/reporters/json.go, csv.go, html.go, sarif.go

# 7. Wire CLI entry point
#    - cmd/zoom-sec-inspector/main.go

# 8. Test and build
go test ./...
go build -ldflags "-X pkg/version.Version=$(git describe --tags)" \
  -o bin/zoom-sec-inspector ./cmd/zoom-sec-inspector/
```

## 10. Status

Implemented in grclanker as of 2026-09-21 (`cli/extensions/grc-tools/zoom.ts`, TypeScript). The Go architecture in sections 7 to 9 describes the original standalone design; the CLI exposes the same controls as native agent tools instead of a `zoom-sec-inspector` binary.

### What shipped

- 25 of 25 controls have a finding: ZOOM-ID-01 to 07 (`zoom_assess_identity`), ZOOM-COLLAB-01 to 08 (`zoom_assess_collaboration_governance`), ZOOM-MTG-01 to 10 (`zoom_assess_meeting_security`). 23 are automatable; controls 8 and 13 are manual by design (see deviations).
- Server-to-Server OAuth (form-encoded `grant_type=account_credentials` and `account_id` body under basic auth, as the S2S page documents) with automatic token refresh, `next_page_token` pagination to completion with truncation tracking, 429 retries (the rate-limits page names no header, so `Retry-After` is honored as a defensive fallback with a one-second default wait), and JSON config-file discovery.
- Verdict safety: denied or errored surfaces render manual and name the endpoint and scope; empty inventories render manual or warn per control intent and never pass; partial inventories (user cap, truncated pages, `total_records` above the returned list) render warn with seen and total counts; compliant but unlocked settings render warn where the control requires enforcement; sampled group overrides downgrade account-level passes; undated operation log entries are bucketed and cap at warn.
- Multi-inventory corollary: a finding that depends on more than one inventory demotes when any of them is unreadable, even when the failure is disclosed elsewhere, and its summary names the unreadable dataset and endpoint. Every settings and lock view read per sampled group (base and `option=meeting_security`) is retained; a denied `GET /groups/{groupId}/settings?option=meeting_security` demotes all 13 group-dependent findings to warn naming the group and endpoint, and a denied `GET /roles` demotes ZOOM-ID-02 to warn (admin role inventory evidence) instead of rendering an empty `admin_roles`. Group lock views are disclosed in the errors arrays but do not demote because no verdict reads group lock state yet. A table-driven test makes each of 20 surfaces unreadable in turn and asserts exactly the findings that read it demote and name it.
- Truncation on every cap exit: the pagination loop reports `truncated` on the item limit, the 500-page cap, a repeated `next_page_token`, or a token that stops yielding items; `/roles`, `/im/groups`, and managed domains are complete only when `total_records` is present and matches (a missing total renders as an unknown total); `/trusted_domains` is a single documented array with no total and is complete by contract. Every finding that depends on a truncated list (users, roles, role members, groups, operation logs, IM groups, managed domains) demotes and states seen versus total.
- Bundle secret hygiene: every collected surface is sanitized once at collection time (credential-bearing keys such as `host_key`, `pmi_password`, tokens, secrets, certificates, and API keys keep their name with a `[REDACTED]` marker; passcode and token URL query parameters are blanked; the Server-to-Server OAuth client id, client secret, and token values are scrubbed from strings and error text). The bundle projects settings and lock settings to the exact paths the verdicts read (listed in `metadata.json`), projects list snapshots to the record fields the verdicts read, drops operation log `operation_detail` free text, and scrubs every written file, so no verbatim configuration dump or credential reaches `core_data/`, `analysis/`, `compliance/`, `QUICK_REFERENCE.md`, or the zip.
- Error-body hygiene (rule 9, error-path class): a non-JSON response body is never placed in an error string; the client substitutes HTTP status, method and endpoint, content type, and byte length, echoes only the documented JSON error fields, and routes every error string through the exported `scrubErrorText` (the `ZoomApiError` constructor, the collector error-to-text helper, and again at the bundle write sink). The scrub covers embedded-URL query and `name=value` fragment removal, `Bearer` and `Basic` values, `Cookie` and `Set-Cookie` values, credential name-value pairs (API key, session id, access, refresh, and id tokens, client secret, password, quoted or not), and a long-token rule for free-text JSON message fields; the sink and data values skip only the long-token heuristic because opaque Zoom identifiers are evidence. Denied surfaces now disclose the scrubbed Zoom detail alongside the status and endpoint. The JSON config file loader (`readConfigFile`) is a guarded read and a guarded parse: read failures throw `Unable to read Zoom config file <path> (<code>)` with the Node error code only when it matches `^E[A-Z0-9_]{1,30}$`, parse failures throw `Unable to parse Zoom config file: invalid JSON in <path>` without the `SyntaxError` message (whose 10-character source window would carry the start of an unquoted credential value), and the assignment scrub lists `client_id` and `clientId` because `credentialValues()` treats the client id as a secret.
- `zoom_export_audit_bundle` writes `core_data/` (projected and redacted), `analysis/`, `compliance/` (executive summary, unified matrix, one report per framework in section 5), `QUICK_REFERENCE.md`, `_errors.log` only on partial collection failure, and a zip named after the allocated directory; reruns allocate `-2`, `-3` and never overwrite.
- Self-check results with fixture (d) built strictly from documented shapes: (a) all denied: 25 manual, 0 pass; (b) all empty: 24 manual, 1 warn (ZOOM-COLLAB-05, an empty operation log is a retention warning by intent), 0 pass; (c) partial inventory: 19 warn, 6 manual, 0 pass; (d) documented compliant: 23 pass, 2 manual (ZOOM-ID-07 vanity URL and ZOOM-COLLAB-08 chat encryption, manual by design).
- Sign-in method classification: every `login_types` code documented on `GET /users` and `GET /users/{userId}` is classified (third-party OAuth 0, 1, 21, 23, 24, 27, 98 and Zoom-held passwords 11, 100 fail ZOOM-ID-05; 97 mobile device and 99 API user are documented but neither SSO nor a personal provider and cap at warn; undocumented codes cap at warn; only 101 passes).
- Tests: `cli/tests/zoom.test.mjs` covers the four-fixture false-pass self-check (all denied, all empty, partial, documented compliant), exact key paths for every setting a verdict reads, pagination, rate limiting, config discovery, the bundle layout, a cap-exit test per collection loop driven through the real client over a fake HTTP transport, a secret-hygiene test that plants fake secrets in every collected object and inspects every bundle file and every zip entry, a unit test on `scrubErrorText`, and a table-driven error-body walk that derives every request from the client and fails each one in three body shapes (including `POST /oauth/token`), scanning findings, summaries, errors arrays, bundle files, zip entries, and thrown errors for canaries. `npm --prefix cli run test:zoom:live` runs a live smoke against a real account when credentials are present.

### Deviations from this spec (docs win)

- Control 2: the account-level waiting room flag is `meeting_security.waiting_room` (settings `option=meeting_security`), not `in_meeting.waiting_room`.
- Control 4: `recording.recording_disclaimer` is marked deprecated in the account settings reference; the verdict reads `recording.recording_notification_for_zoom_client.disclaimer_to_participants` and only falls back to the deprecated boolean when the replacement is absent.
- Control 6: admin 2FA is read from the account `security.sign_in_with_two_factor_auth` (`all`, `role`, `group`, `none`) and `sign_in_with_two_factor_auth_roles` under `option=security`, not from `GET /users/{userId}/settings`, which documents no 2FA field.
- Control 8: the account settings reference documents no Team Chat encryption setting under `chat`; encryption indicators exist only as per-message metadata in the Team Chat API, so ZOOM-COLLAB-08 is manual with the citation in its summary.
- Control 12: the documented settings are `chat.allow_users_to_add_contacts` and `chat.allow_users_to_chat_with_others` (`enable` plus `selected_option` 1 to 4); trusted domains remain a supporting finding (ZOOM-COLLAB-01).
- Control 13: no account vanity URL field is documented on `GET /accounts/{accountId}/settings`; only per-user `vanity_url` exists on `GET /users/{userId}`, so ZOOM-ID-07 is manual with the citation in its summary.
- Control 17: the documented fields are `security.sign_again_period_for_inactivity_on_client` and `security.sign_again_period_for_inactivity_on_web` (minutes, 0 disables), under `option=security`.
- Control 22: the `GET /accounts/{accountId}/settings` response documents `embed_password_in_join_link` only under `meeting_security` (settings `option=meeting_security`); `schedule_meeting.embed_password_in_join_link` exists only in the `lock_settings` response. ZOOM-MTG-06 reads `meeting_security.embed_password_in_join_link` and the `meeting_security.embed_password_in_join_link` lock (both documented), not the `schedule_meeting` path asserted in section 4.
- Control 16: the `GET /users` `login_types` enum is `[0, 1, 23, 24, 27, 97, 98, 100, 101]` while its description omits 23 and 98 and describes 99, which is absent from the enum; `GET /users/{userId}` describes 98 (RingCentral OAuth), 99 (API user), and the China-only 11, 21, and 23 (Alipay). The classification above cites both pages.
- Control 19: `GET /phone/recording` and `GET /phone/call_handling/settings` are not in the Zoom Phone reference as account policy reads; the verdict uses `GET /phone/account_settings?setting_types=auto_call_recording,ad_hoc_call_recording`.
- `GET /report/operationlogs` requires `from` and `to` (yyyy-mm-dd); the CLI queries a 30-day window.
- Not used: `GET /users/{userId}/settings`, `GET /users/{userId}/token`, `GET /roles/{roleId}`, `GET /report/meetings`, `GET /im/groups/{imGroupId}`. No shipped control depends on them.
- Scope naming: the IM groups endpoint documents `imgroup:read:admin` (classic) and `contact_group:read:list_groups:admin` (granular), not `im:read:admin`. The Team Chat reference (`https://developers.zoom.us/docs/api/chat/`) has no stable per-operation anchor; its OpenAPI document carries `GET /im/groups`. Managed and trusted domains require master-account granular scopes (`account:read:managed_domains:master`, `account:read:trusted_domains:master`).

### What remains

- Out of scope for this pass: user-level OAuth (section 3), SARIF, CSV, and HTML reporters (section 7), the standalone Go binary and CLI flags (sections 8 and 9).
- Deferred: per-user setting drift via `GET /users/{userId}/settings` (only account and group levels are inspected), Zoom Phone call handling policies, and `GET /report/meetings` usage analytics.
