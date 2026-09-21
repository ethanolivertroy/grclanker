---
slug: "zendesk-sec-inspector"
name: "Zendesk Security Inspector"
vendor: "Zendesk"
category: "saas-collaboration"
language: "typescript"
status: "implemented"
version: "1.0"
last_updated: "2026-09-21"
source_repo: "https://github.com/hackIDLE/grclanker"
---

# Zendesk Security Inspector

## 1. Overview

A security compliance inspection tool for **Zendesk** customer service platforms (Support, Guide, Chat, Talk). Audits authentication settings, agent access controls, data protection configurations, audit logging, API token management, and application security against enterprise security baselines and compliance frameworks.

Zendesk handles sensitive customer data (PII, support tickets, HIPAA-protected information in healthcare contexts); misconfigurations can lead to data exposure, unauthorized access, or compliance violations. This tool uses the Zendesk REST API to evaluate security posture.

### grclanker implementation

The shipped implementation lives in `cli/extensions/grc-tools/zendesk.ts` and registers six read-only native tools:

- `zendesk_check_access`: probes the 20 Support API read surfaces the assessments depend on and reports which admin-only or Enterprise-only surfaces the credential cannot read.
- `zendesk_assess_authentication`: controls 1-5 and 21.
- `zendesk_assess_access_control`: controls 6-8, 13, and 14.
- `zendesk_assess_data_protection`: controls 9-12 and 18-20.
- `zendesk_assess_integrations`: controls 15-17 and 22-25.
- `zendesk_export_audit_bundle`: runs the access check and all four assessments, then writes `core_data/`, `analysis/`, `compliance/` (executive summary, unified matrix, one report per framework in section 5), `QUICK_REFERENCE.md`, `_errors.log` on partial collection, and a paired `.zip`.

Every finding carries `{id, control, title, severity, status, summary, evidence, mappings}` with `status` in `pass | warn | fail | manual`. Authentication controls read the admin-only `/api/v2/security_settings` endpoint, deletion policies read `/api/v2/deletion_schedules`, and API token hygiene enumerates token events from `/api/v2/audit_logs?filter[source_type]=apitoken`. Controls whose settings are not exposed by the published API (HIPAA mode, allowed attachment types, anonymous ticket submission) render as `manual` findings that name the Admin Center evidence to collect. See `src/content/docs/docs/integrations/zendesk.md` for the setup guide and the control coverage table.

## 2. APIs & SDKs

### Zendesk REST API

Base URL: `https://{subdomain}.zendesk.com/api/v2`

| Endpoint | Purpose |
|----------|---------|
| `GET /api/v2/users.json` | List all users (agents, admins, end-users) |
| `GET /api/v2/users/{id}.json` | User detail including role, suspension status |
| `GET /api/v2/users/{id}/identities.json` | User email/social identities |
| `GET /api/v2/groups.json` | Agent groups |
| `GET /api/v2/group_memberships.json` | Agent-to-group assignments |
| `GET /api/v2/organizations.json` | Customer organizations |
| `GET /api/v2/organization_memberships.json` | User-to-org assignments |
| `GET /api/v2/audit_logs.json` | Admin audit trail (Enterprise only) |
| `GET /api/v2/account/settings.json` | Account-wide security/feature settings |
| `GET /api/v2/security_settings` | Team member and end-user authentication, password policies, IP restrictions, session timeouts (admin only) |
| `GET /api/v2/deletion_schedules` | Data deletion schedules by object (admin only) |
| `GET /api/v2/slas/policies.json` | SLA policy definitions |
| `GET /api/v2/ticket_forms.json` | Ticket form configurations |
| `GET /api/v2/ticket_fields.json` | Custom ticket fields |
| `GET /api/v2/apps/installations.json` | Installed marketplace apps |
| `GET /api/v2/apps/owned.json` | Custom/private apps |
| `GET /api/v2/custom_roles.json` | Custom agent roles (Enterprise) |
| `GET /api/v2/oauth/clients.json` | OAuth client applications |
| `GET /api/v2/oauth/tokens.json` | Active OAuth tokens |
| `GET /api/v2/channels/voice/phone_numbers.json` | Talk phone numbers |
| `GET /api/v2/sharing_agreements.json` | Ticket sharing agreements |
| `GET /api/v2/triggers.json` | Business rule triggers |
| `GET /api/v2/automations.json` | Timed automations |
| `GET /api/v2/targets.json` | External notification targets |
| `GET /api/v2/brands.json` | Brand configurations |
| `GET /api/v2/suspended_tickets.json` | Suspended ticket queue |

### Rate Limits

- Default: 400 requests/minute (Team), 700 (Professional/Enterprise)
- Response headers: `X-Rate-Limit`, `X-Rate-Limit-Remaining`, `Retry-After`
- Pagination: cursor-based (`after_cursor`) or offset-based (`page[after]`)

### SDKs & Tools

| Tool | Type | Notes |
|------|------|-------|
| `zenpy` | Community Python SDK | Widely used, wraps REST API |
| `go-zendesk` | Community Go SDK | Partial API coverage |
| Zendesk CLI (`zcli`) | Official CLI | App development focused, limited admin API |
| `terraform-provider-zendesk` | Community Terraform | Infrastructure-as-code for Zendesk config |

## 3. Authentication

### API Token Authentication (Recommended for Inspection)

- Generated in Zendesk Admin Center: Apps and integrations → APIs → Zendesk API
- Format: `{email}/token:{api_token}` as Basic Auth
- Header: `Authorization: Basic base64({email}/token:{api_token})`
- Read-only access sufficient for inspection
- Multiple tokens supported; each can be individually revoked

### OAuth 2.0

- App registration in Zendesk Admin Center
- Authorization Code flow
- Scopes: `read`, `write`, `impersonate`
- Token endpoint: `https://{subdomain}.zendesk.com/oauth/tokens`

### Basic Authentication

- Username/password (discouraged, requires password access)
- Header: `Authorization: Basic base64({email}:{password})`

### Configuration

```
ZENDESK_SUBDOMAIN=<subdomain>
ZENDESK_EMAIL=<admin_email>
ZENDESK_API_TOKEN=<api_token>
```

## 4. Security Controls

| # | Control | API Source | Severity |
|---|---------|-----------|----------|
| 1 | SSO enforcement enabled | `/api/v2/account/settings.json` → `active_features.sso` | Critical |
| 2 | Two-factor authentication required for agents | `/api/v2/account/settings.json` → `security.require_two_factor_auth` | Critical |
| 3 | Password policy meets complexity requirements | `/api/v2/account/settings.json` → `security.password_policy` | High |
| 4 | IP restrictions configured for agent access | `/api/v2/account/settings.json` → `security.ip_restrictions` | High |
| 5 | Session timeout configured and reasonable | `/api/v2/account/settings.json` → `security.session_expiration` | Medium |
| 6 | Agent roles follow least privilege | `/api/v2/users.json` → role analysis + `/api/v2/custom_roles.json` | Critical |
| 7 | No excessive admin accounts | `/api/v2/users.json` → `role = 'admin'` count | High |
| 8 | Group-based access controls configured | `/api/v2/groups.json` + `/api/v2/group_memberships.json` | Medium |
| 9 | Audit logging enabled and accessible | `/api/v2/audit_logs.json` → verify records | High |
| 10 | Audit log retention meets compliance requirements | `/api/v2/audit_logs.json` → oldest record analysis | Medium |
| 11 | HIPAA compliance mode enabled (if applicable) | `/api/v2/account/settings.json` → HIPAA flags | Critical |
| 12 | Data deletion/redaction policies configured | `/api/v2/account/settings.json` → data retention | High |
| 13 | API tokens are minimal and reviewed | Token enumeration via admin audit | High |
| 14 | OAuth application permissions are scoped | `/api/v2/oauth/clients.json` → scope review | High |
| 15 | Marketplace apps reviewed for permissions | `/api/v2/apps/installations.json` → permission analysis | Medium |
| 16 | Private/custom apps have appropriate scope | `/api/v2/apps/owned.json` | Medium |
| 17 | Sandbox environment used for testing | Account settings → sandbox status | Low |
| 18 | CDN security (attachment hosting) configured | `/api/v2/account/settings.json` → attachment settings | Medium |
| 19 | File attachment restrictions configured | `/api/v2/account/settings.json` → attachment types/sizes | Medium |
| 20 | Suspended ticket handling automated | `/api/v2/suspended_tickets.json` → queue size, age | Low |
| 21 | End-user authentication required (no anonymous tickets) | `/api/v2/account/settings.json` → `end_user` auth settings | High |
| 22 | Brand security settings consistent across brands | `/api/v2/brands.json` → cross-brand comparison | Medium |
| 23 | External sharing agreements reviewed | `/api/v2/sharing_agreements.json` | Medium |
| 24 | External notification targets use HTTPS | `/api/v2/targets.json` → URL scheme | High |
| 25 | Triggers/automations do not send data to external URLs | `/api/v2/triggers.json` + `/api/v2/automations.json` | High |

## 5. Compliance Framework Mappings

| Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | STIG | IRAP | ISMAP |
|---------|---------|------|-------|-----|---------|------|------|-------|
| 1. SSO enforcement | IA-2 | IA.L2-3.5.1 | CC6.1 | 4.1 | 8.3.1 | SRG-APP-000148 | ISM-1557 | 8.2.1 |
| 2. 2FA for agents | IA-2(1) | IA.L2-3.5.3 | CC6.1 | 4.5 | 8.3.2 | SRG-APP-000149 | ISM-1401 | 8.2.2 |
| 3. Password policy | IA-5(1) | IA.L2-3.5.7 | CC6.1 | 5.1 | 8.2.3 | SRG-APP-000164 | ISM-0421 | 8.2.3 |
| 4. IP restrictions | SC-7 | SC.L2-3.13.6 | CC6.6 | 4.4 | 1.3.2 | SRG-APP-000383 | ISM-1284 | 10.2.2 |
| 5. Session timeout | AC-12 | AC.L2-3.1.10 | CC6.1 | 5.6 | 8.1.8 | SRG-APP-000295 | ISM-1164 | 8.3.1 |
| 6. Least privilege roles | AC-6(1) | AC.L2-3.1.5 | CC6.3 | 6.1 | 7.1.1 | SRG-APP-000340 | ISM-1508 | 8.1.2 |
| 7. Admin count restricted | AC-6(5) | AC.L2-3.1.5 | CC6.3 | 6.2 | 7.1.2 | SRG-APP-000340 | ISM-1508 | 8.1.3 |
| 8. Group access controls | AC-3 | AC.L2-3.1.2 | CC6.1 | 6.1 | 7.1.1 | SRG-APP-000033 | ISM-1508 | 8.1.1 |
| 9. Audit logging active | AU-2 | AU.L2-3.3.1 | CC7.2 | 8.1 | 10.1 | SRG-APP-000089 | ISM-0580 | 12.1.1 |
| 10. Audit log retention | AU-11 | AU.L2-3.3.1 | CC7.2 | 8.3 | 10.7 | SRG-APP-000515 | ISM-0859 | 12.1.2 |
| 11. HIPAA compliance mode | SC-28 | SC.L2-3.13.16 | CC6.1 | 14.7 | 3.4 | SRG-APP-000231 | ISM-0457 | 10.1.2 |
| 12. Data deletion policies | SI-12 | MP.L2-3.8.3 | CC6.5 | 3.1 | 3.1 | SRG-APP-000504 | ISM-0261 | 7.1.1 |
| 13. API token management | IA-5(1) | IA.L2-3.5.10 | CC6.1 | 4.4 | 8.2.4 | SRG-APP-000174 | ISM-1557 | 8.2.4 |
| 14. OAuth permissions scoped | AC-6 | AC.L2-3.1.1 | CC6.3 | 6.1 | 7.1.1 | SRG-APP-000033 | ISM-1508 | 8.1.1 |
| 15. App permissions reviewed | CM-7 | CM.L2-3.4.7 | CC6.6 | 13.5 | 2.2.2 | SRG-APP-000141 | ISM-1284 | 6.1.1 |
| 16. Custom app scope | CM-7 | CM.L2-3.4.7 | CC6.6 | 13.5 | 2.2.2 | SRG-APP-000141 | ISM-1284 | 6.1.1 |
| 17. Sandbox for testing | CM-3 | CM.L2-3.4.3 | CC8.1 | 2.3 | 6.4.1 | SRG-APP-000128 | ISM-1211 | 6.2.1 |
| 18. CDN security | SC-8 | SC.L2-3.13.1 | CC6.7 | 14.4 | 4.1 | SRG-APP-000439 | ISM-0487 | 10.1.1 |
| 19. Attachment restrictions | SC-7 | SC.L2-3.13.6 | CC6.6 | 13.1 | 1.3.1 | SRG-APP-000383 | ISM-1284 | 10.2.1 |
| 20. Suspended ticket handling | SI-4 | SI.L2-3.14.6 | CC7.2 | 8.5 | 10.6.1 | SRG-APP-000095 | ISM-0580 | 12.1.3 |
| 21. End-user authentication | IA-2 | IA.L2-3.5.1 | CC6.1 | 4.1 | 8.3.1 | SRG-APP-000148 | ISM-1557 | 8.2.1 |
| 22. Brand security consistency | CM-2 | CM.L2-3.4.1 | CC6.1 | 2.1 | 2.2 | SRG-APP-000128 | ISM-1211 | 6.1.1 |
| 23. Sharing agreements reviewed | AC-4 | AC.L2-3.1.3 | CC6.6 | 13.4 | 7.1.2 | SRG-APP-000039 | ISM-1284 | 8.1.3 |
| 24. HTTPS notification targets | SC-8(1) | SC.L2-3.13.8 | CC6.7 | 14.4 | 4.1 | SRG-APP-000441 | ISM-0487 | 10.1.1 |
| 25. No data exfil via triggers | AC-4 | AC.L2-3.1.3 | CC6.6 | 13.4 | 1.3.4 | SRG-APP-000039 | ISM-1284 | 8.1.3 |

## 6. Existing Tools

| Tool | Type | Notes |
|------|------|-------|
| Zendesk Admin Center | Built-in | Manual security settings review |
| Zendesk Audit Log | Built-in (Enterprise) | Raw audit data, no analysis |
| Zendesk Security Dashboard | Built-in | Basic posture overview |
| Terraform Zendesk Provider | Community IaC | Config-as-code, not audit-focused |
| Drata / Vanta | Commercial SaaS | Zendesk integration for SOC 2 |
| Oomnitza / Productiv | Commercial SaaS | SaaS management, limited security checks |
| **No open-source Zendesk security inspector exists** | Gap | This tool fills the gap |

## 7. Architecture

```
zendesk-sec-inspector/
├── cmd/
│   └── zendesk-sec-inspector/
│       └── main.go                     # Entry point, CLI parsing
├── internal/
│   ├── auth/
│   │   ├── token.go                    # API token authentication
│   │   ├── oauth.go                    # OAuth 2.0 flow
│   │   └── config.go                   # Credential loading, validation
│   ├── client/
│   │   ├── zendesk.go                 # HTTP client with rate limiting, pagination
│   │   ├── users.go                    # User, identity, group calls
│   │   ├── account.go                 # Account settings calls
│   │   ├── audit.go                   # Audit log calls
│   │   ├── apps.go                    # App installation and OAuth calls
│   │   ├── tickets.go                 # Ticket forms, fields, suspended tickets
│   │   ├── automations.go            # Triggers, automations, targets
│   │   ├── brands.go                  # Brand configuration calls
│   │   └── sharing.go                # Sharing agreement calls
│   ├── analyzers/
│   │   ├── analyzer.go                # Analyzer interface definition
│   │   ├── authentication.go          # Controls 1, 2, 3, 21
│   │   ├── network_security.go        # Controls 4, 5
│   │   ├── access_control.go          # Controls 6, 7, 8
│   │   ├── audit_logging.go           # Controls 9, 10
│   │   ├── data_protection.go         # Controls 11, 12, 18, 19
│   │   ├── api_security.go            # Controls 13, 14
│   │   ├── app_security.go            # Controls 15, 16, 17
│   │   └── external_comms.go          # Controls 20, 22, 23, 24, 25
│   ├── models/
│   │   ├── finding.go                 # Security finding with severity, mapping
│   │   ├── compliance.go              # Framework mapping definitions
│   │   ├── account.go                 # Account settings structs
│   │   ├── user.go                    # User, identity, role structs
│   │   └── app.go                     # App installation, OAuth structs
│   └── reporters/
│       ├── reporter.go                # Reporter interface
│       ├── json.go                    # JSON output
│       ├── csv.go                     # CSV output
│       ├── html.go                    # HTML dashboard report
│       └── sarif.go                   # SARIF for CI/CD integration
├── pkg/
│   └── version/
│       └── version.go                 # Build version info
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile
├── spec.md
└── README.md
```

## 8. CLI Interface

```
zendesk-sec-inspector [flags]

Flags:
  --subdomain string        Zendesk subdomain (or ZENDESK_SUBDOMAIN env)
  --email string            Admin email for API auth (or ZENDESK_EMAIL env)
  --api-token string        API token (or ZENDESK_API_TOKEN env)
  --controls string         Comma-separated control IDs to run (default: all)
  --skip-controls string    Comma-separated control IDs to skip
  --severity string         Minimum severity: critical,high,medium,low (default: low)
  --format string           Output format: json,csv,html,sarif (default: json)
  --output string           Output file path (default: stdout)
  --check-hipaa             Include HIPAA-specific controls
  --include-end-users       Include end-user analysis (slower, large datasets)
  --admin-threshold int     Max admins before flagging (default: 5)
  --suspended-ticket-age int  Days before flagging old suspended tickets (default: 30)
  --concurrency int         Max concurrent API requests (default: 8)
  --timeout duration        HTTP request timeout (default: 30s)
  --verbose                 Enable verbose/debug logging
  --version                 Print version and exit
  --help                    Show help
```

### Example Usage

```bash
# Full inspection with JSON output
zendesk-sec-inspector --subdomain mycompany --email admin@company.com \
  --api-token "$ZD_TOKEN" --format json --output report.json

# Critical controls with HIPAA checks
zendesk-sec-inspector --severity critical --check-hipaa --format html --output dashboard.html

# App and API security audit only
zendesk-sec-inspector --controls 13,14,15,16,24,25 --format json

# CI/CD pipeline with SARIF output
zendesk-sec-inspector --format sarif --output results.sarif
```

## 9. Build Sequence

```bash
# 1. Initialize module
go mod init github.com/hackIDLE/zendesk-sec-inspector

# 2. Define models and interfaces
#    - internal/models/finding.go (Finding struct, Severity enum)
#    - internal/models/compliance.go (framework mapping tables)
#    - internal/analyzers/analyzer.go (Analyzer interface)
#    - internal/reporters/reporter.go (Reporter interface)

# 3. Implement authentication
#    - internal/auth/config.go (env/flag loading)
#    - internal/auth/token.go (API token Basic auth encoding)

# 4. Build API client
#    - internal/client/zendesk.go (base client, rate limiter, paginator)
#    - internal/client/users.go, account.go, audit.go, etc.

# 5. Implement analyzers
#    - internal/analyzers/authentication.go
#    - internal/analyzers/network_security.go
#    - ... (all 8 analyzer files)

# 6. Implement reporters
#    - internal/reporters/json.go, csv.go, html.go, sarif.go

# 7. Wire CLI entry point
#    - cmd/zendesk-sec-inspector/main.go

# 8. Test and build
go test ./...
go build -ldflags "-X pkg/version.Version=$(git describe --tags)" \
  -o bin/zendesk-sec-inspector ./cmd/zendesk-sec-inspector/
```

## 10. Status

Implemented in grclanker as TypeScript native tools (`cli/extensions/grc-tools/zendesk.ts`) with mocked regression coverage in `cli/tests/zendesk.test.mjs` and an optional live smoke (`npm --prefix cli run test:zendesk:live`). The original Go CLI layout in sections 7-9 is retained as design history; the grclanker tools replace it.

### What shipped

- API token (`{email}/token:{api_token}` Basic) and OAuth bearer authentication, resolved from explicit arguments, then `ZENDESK_SUBDOMAIN`, `ZENDESK_EMAIL`, `ZENDESK_API_TOKEN`, `ZENDESK_OAUTH_TOKEN` (or `ZENDESK_ACCESS_TOKEN`), `ZENDESK_BASE_URL`, `ZENDESK_TIMEOUT`, then a JSON config file (`ZENDESK_CONFIG_FILE` or `~/.zendesk/config.json`).
- A client that follows cursor pagination (`page[size]`, `links.next` until null regardless of `meta.has_more`, with `include_boundary_indicators=true` on Users and Groups) and offset pagination (`page`, `per_page`, `next_page`, continuing past a full page even when `next_page` is absent) to completion or records truncation, deduplicates items across pages, retries 429 honoring `Retry-After` and 5xx with backoff, applies timeouts, and redacts tokens from error messages. Custom roles, app installations, owned apps, targets, and sharing agreements are paged with offset pagination rather than read as a single page.
- All 25 controls rendered as findings. Controls 1-10, 12-18, 20-25 are verified from documented API fields; controls 11 and 19 are `manual` because neither the Account Settings nor the Security Settings reference exposes a HIPAA or allowed attachment type field; controls 13, 15, 16, 23 stay `manual` whenever an inventory exists because the review itself is a human activity; the anonymous ticket submission portion of control 21 stays manual because no reference publishes it.
- Verdict safety: forbidden, missing, or errored endpoints render `manual`; empty inventories pass only where emptiness is compliant and the summary states the count; truncated inventories and undated items downgrade to `warn`; a non-admin credential (or a failed `/users/me` lookup) caps every verdict at `warn`; reruns of the export allocate a new directory and a matching zip name.

### Deviations from this spec, following the official documentation

- Section 3 lists Basic email and password authentication. Zendesk retired password access for the API (announced end date January 12, 2026), so the implementation supports only API tokens and OAuth bearer tokens.
- Section 4 cites `active_features.sso`, `security.require_two_factor_auth`, `security.password_policy`, `security.ip_restrictions`, `security.session_expiration`, and end-user authentication settings under `/api/v2/account/settings`. The published Account Settings reference documents none of those keys; the equivalent fields live on the documented admin-only `GET /api/v2/security_settings` endpoint (Account Configuration > Security Settings), which the implementation reads instead: control 1 from `authentication.agent.{enforce_sso, zendesk_login, remote_login, google_login, office_365_login, sso_auto_redirect, remote_bypass}`, control 2 from `authentication.agent.two_factor_enforce` combined with the per-user `two_factor_auth_enabled` flag across all active agents and admins, control 3 from `authentication.agent.security_policy_name` and `authentication.agent.password.{password_length, password_complexity, password_history_length, password_duration, failed_attempts_allowed, password_in_mixed_case, disallow_local_part_from_email, max_sequence}`, control 4 from `ip.{ip_restriction_enabled, ip_ranges, enable_agent_ip_restrictions}`, control 5 from `agent_session_timeout`, `end_user_session_timeout`, `maximum_session_duration`, `maximum_session_duration_enabled`, `mobile_app_access`, and `mobile_app_session_timeout`, and control 21 from `authentication.end_user.{zendesk_login, enforce_sso, google_login, facebook_login, office_365_login, security_policy_name}`.
- Control 11 cites HIPAA flags under `/api/v2/account/settings`. Neither the Account Settings nor the Security Settings reference publishes a HIPAA or Advanced Data Privacy and Protection field, so control 11 is a `manual` finding.
- Control 12 cites data retention under `/api/v2/account/settings`. The documented source is the admin-only `GET /api/v2/deletion_schedules` endpoint (Business Rules > Deletion Schedules), which the implementation evaluates by `object` (`zen:ticket`, `zen:user`, `zen:attachment`, `zen:bot_only_conversation`, custom objects), `active`, `default`, and `conditions`, alongside `settings.tickets.agent_ticket_deletion` and the custom roles allowed to redact or manage deletion schedules.
- Control 13 (API tokens) names token enumeration via the admin audit as its source. The implementation reads the documented `settings.api.api_token_access` flag (passes only when it is `false`) and enumerates token creation and deletion events from `GET /api/v2/audit_logs?filter[source_type]=apitoken` (Enterprise plan) to reconstruct outstanding tokens and their age; the token inventory endpoint itself is not part of the published reference and is not called. Zendesk is retiring API tokens (unused tokens deactivated from July 28, 2026; all API tokens stop working April 30, 2027).
- The "Anybody can submit tickets" portion of control 21 is not published by any reference and stays a manual capture named in the finding summary.
- Control 24 reviews `/api/v2/webhooks` (the successor to targets) alongside `/api/v2/targets`; control 25 resolves `notification_webhook`, `notification_target`, and `share_ticket` trigger and automation actions.
- Control 18 uses the documented `settings.tickets.private_attachments` flag as the verifiable attachment hosting control.

### What remains

- Help Center (Guide) article and section visibility is not inspected; brand `help_center_state` is the only Guide-related signal read.
- Talk, Chat, and Sell settings are out of scope for the current tools and are not represented as controls in this spec's table.
- The live smoke has not been run against a production account in CI; run `npm --prefix cli run test:zendesk:live` with admin credentials to validate a real tenant.
