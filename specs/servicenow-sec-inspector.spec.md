---
slug: "servicenow-sec-inspector"
name: "ServiceNow Security Inspector"
vendor: "ServiceNow"
category: "saas-collaboration"
language: "typescript"
status: "implemented"
version: "1.0"
last_updated: "2026-09-21"
source_repo: "https://github.com/hackIDLE/grclanker"
---

# servicenow-sec-inspector

## 1. Overview

A security compliance inspection tool for **ServiceNow** instances that audits platform security configurations, access control rules (ACLs), user and role management, session policies, authentication settings, encryption configurations, and audit logging. The tool connects to ServiceNow's Table API, CMDB API, and system property endpoints to evaluate instance hardening, script execution restrictions, integration user permissions, update set hygiene, and GRC module configurations. Results are output as structured compliance reports mapped to FedRAMP, CMMC, SOC 2, CIS, PCI-DSS, STIG, IRAP, and ISMAP controls.

## 2. APIs & SDKs

### ServiceNow APIs

| API | Base URL | Purpose |
|-----|----------|---------|
| **Table API** | `https://{instance}.service-now.com/api/now/table/` | CRUD operations on any ServiceNow table |
| **CMDB API** | `https://{instance}.service-now.com/api/now/cmdb/` | Configuration Management Database |
| **Aggregate API** | `https://{instance}.service-now.com/api/now/stats/` | Aggregate queries (count, avg, sum) |
| **Attachment API** | `https://{instance}.service-now.com/api/now/attachment/` | File attachment management |
| **Import Set API** | `https://{instance}.service-now.com/api/now/import/` | Data import operations |
| **Scripted REST API** | `https://{instance}.service-now.com/api/{scope}/{api_id}` | Custom scripted REST endpoints |

### Key Tables for Security Auditing

**Access Control:**
- `sys_security_acl` — Access Control List rules
- `sys_security_acl_role` — ACL-to-role associations
- `sys_user_role` — Role definitions
- `sys_user_has_role` — User-to-role assignments
- `sys_user_group` — User groups
- `sys_user_grmember` — Group membership
- `sys_user` — User accounts
- `sys_user_preference` — User preferences

**Authentication and Sessions:**
- `sys_properties` — System properties (glide.security.*, etc.)
- `ldap_server_config` — LDAP/AD integration configuration
- `sso_properties` — SSO/SAML configuration
- `oauth_entity` — OAuth application registrations
- `sys_certificate` — Certificate management
- `sys_auth_profile` — Authentication profiles
- `mfa_policy` — Multi-factor authentication policies

**Audit and Logging:**
- `sys_audit` — Record-level audit trail
- `syslog` — System log events
- `syslog_transaction` — Transaction logs
- `sys_audit_delete` — Deletion audit records
- `sys_login` — Login attempt records

**Security Incident Response (SIR):**
- `sn_si_incident` — Security incidents
- `sn_si_task` — Security incident tasks

**GRC (Governance, Risk, Compliance):**
- `sn_grc_policy` — GRC policies
- `sn_grc_control` — GRC controls
- `sn_grc_profile` — Compliance profiles
- `sn_compliance_policy` — Compliance policies

**Instance Configuration:**
- `sys_update_set` — Update sets (change management)
- `sys_script` — Business rules
- `sys_script_include` — Script includes
- `sys_ui_policy` — UI policies
- `sys_ws_operation` — REST API operations
- `sys_rest_message` — Outbound REST integrations
- `ecc_queue` — MID Server queue
- `sys_cluster_state` — Instance cluster/node status
- `sys_plugins` — Installed plugins

### SDKs

| SDK | Language | Package |
|-----|----------|---------|
| **pysnow** | Python | `pip install pysnow` (community, popular) |
| **servicenow-sdk** | Python | Community ServiceNow client |
| **sn-rest-client** | Node.js | ServiceNow REST API client |
| **ServiceNow CLI** | CLI | `now-cli` (ServiceNow official for app development) |

## 3. Authentication

### Basic Authentication

```
Authorization: Basic base64(username:password)
```

Used with a dedicated service account with appropriate roles.

### OAuth 2.0

ServiceNow supports OAuth 2.0 with the following grant types:
- **Authorization Code** — For interactive user authentication
- **Client Credentials** — For server-to-server (recommended for this tool)
- **Resource Owner Password** — Username/password via OAuth token endpoint

```bash
# Token request (Resource Owner Password grant)
curl -X POST "https://{instance}.service-now.com/oauth_token.do" \
  -d "grant_type=password&client_id={client_id}&client_secret={client_secret}&username={user}&password={pass}"
```

### Mutual TLS (mTLS)

For high-security environments, ServiceNow supports certificate-based authentication via mutual TLS.

### Required Roles

The service account must have the following roles:
- `security_admin` — Access to ACL rules and security properties
- `admin` (read-only preferred) — System properties and configuration tables
- `itil` — Read access to ITSM tables
- `sn_grc.reader` — GRC module read access (if licensed)
- `sn_si.read` — Security Incident Response read access (if licensed)

### Configuration

```
SERVICENOW_INSTANCE=mycompany
SERVICENOW_URL=https://mycompany.service-now.com
SERVICENOW_USERNAME=api_audit_user
SERVICENOW_PASSWORD=...
SERVICENOW_CLIENT_ID=...          # For OAuth
SERVICENOW_CLIENT_SECRET=...      # For OAuth
SERVICENOW_AUTH_METHOD=oauth       # basic, oauth, or mtls
```

## 4. Security Controls

1. **Instance security properties** — Audit critical `glide.security.*` system properties: `glide.security.use_csrf_token` (CSRF protection), `glide.security.strict_elevate_privilege` (privilege elevation), `glide.security.file.mime_type.validation` (file upload validation), `glide.ui.session_timeout` (session timeout)
2. **ACL rule completeness** — Enumerate all ACL rules; flag tables without ACL protection, wildcard ACLs, and ACLs with empty conditions (unrestricted access)
3. **Role hierarchy audit** — Map the complete role hierarchy; flag roles that inherit `admin` or `security_admin`; verify custom roles follow least privilege
4. **User access review** — Enumerate all active users with roles; flag users with `admin` role, users with no login in 90+ days, and accounts with multiple high-privilege roles
5. **Session timeout configuration** — Verify `glide.ui.session_timeout` is set appropriately (recommended: 30 minutes or less); verify `glide.ui.session_timeout.warn` provides adequate warning
6. **Password policy enforcement** — Audit password policy properties: `glide.security.password.min_length`, `glide.security.password.max_length`, `glide.security.password.upper`, `glide.security.password.lower`, `glide.security.password.digit`, `glide.security.password.special`
7. **MFA enforcement** — Verify multi-factor authentication is enabled and required for all users (or at minimum for admin roles); audit MFA policy configuration
8. **LDAP/SSO integration** — Verify LDAP or SAML SSO is configured and active; audit SSO certificate expiration; verify local authentication fallback is restricted
9. **Encryption at rest** — Verify column-level encryption is enabled for sensitive fields; audit `sys_encryption_context` and encrypted field configurations
10. **Audit logging configuration** — Verify record-level auditing is enabled for critical tables (sys_user, sys_security_acl, sys_properties); verify audit record retention period
11. **Table-level access controls** — Audit per-table ACLs for sensitive tables (sys_user, sys_properties, sys_script, syslog); verify read/write/delete operations are restricted
12. **Script execution restrictions** — Audit `glide.script.block.server.globals` and script sandboxing properties; flag business rules with `gs.setRedirect()` or `eval()` usage
13. **Instance hardening** — Verify hardening properties: `glide.security.strict.updates` (prevent unauthorized updates), `glide.ui.escape_html_list_field` (XSS prevention), `glide.html.sanitize_all_fields` (input sanitization)
14. **Integration user permissions** — Enumerate integration users (web service, SOAP, REST); verify they have minimal required roles; flag integration users with `admin` role
15. **Update set management** — Audit update sets in non-production states; flag update sets with security-sensitive changes (ACL modifications, role changes, script changes)
16. **Debug mode verification** — Verify debug properties are disabled: `glide.security.debug`, `glide.security.acl.debug`, `glide.war`, `glide.ui.debug_*`
17. **IP access restrictions** — Verify IP-based access restrictions are configured for admin access; audit `glide.ip.access.control` and IP address access control lists
18. **Email security** — Audit email properties: DKIM signing, TLS enforcement for outbound email, email notification security headers
19. **Mid Server security** — Verify MID Server configurations: validated status, mutual auth enabled, auto-upgrade policy, allowed host list
20. **Plugin inventory and licensing** — Audit installed plugins; flag unnecessary or insecure plugins; verify security-relevant plugins are active (Security Incident Response, GRC, Vulnerability Response)

## 5. Compliance Framework Mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | STIG | IRAP | ISMAP |
|---|---------|---------|------|-------|-----|---------|------|------|-------|
| 1 | Instance security properties | CM-6 | 3.4.2 | CC6.1 | 5.1 | 2.2.1 | SRG-APP-000384 | ISM-1624 | CPS.CM-6 |
| 2 | ACL rule completeness | AC-3 | 3.1.2 | CC6.1 | — | 7.1.1 | SRG-APP-000033 | ISM-0405 | CPS.AC-3 |
| 3 | Role hierarchy audit | AC-6(1) | 3.1.5 | CC6.3 | — | 7.1.1 | SRG-APP-000340 | ISM-1507 | CPS.AC-6 |
| 4 | User access review | AC-2(3) | 3.1.12 | CC6.2 | 5.3 | 8.1.4 | SRG-APP-000025 | ISM-1591 | CPS.AC-2 |
| 5 | Session timeout configuration | AC-12 | 3.1.10 | CC6.1 | 16.4 | 8.2.8 | SRG-APP-000295 | ISM-1164 | CPS.AC-7 |
| 6 | Password policy enforcement | IA-5(1) | 3.5.7 | CC6.1 | 5.2 | 8.3.6 | SRG-APP-000164 | ISM-0421 | CPS.IA-5 |
| 7 | MFA enforcement | IA-2(1) | 3.5.3 | CC6.1 | 6.3 | 8.4.2 | SRG-APP-000149 | ISM-1504 | CPS.AT-2 |
| 8 | LDAP/SSO integration | IA-2(12) | 3.5.3 | CC6.1 | 16.2 | 8.4.1 | SRG-APP-000395 | ISM-1546 | CPS.IA-2 |
| 9 | Encryption at rest | SC-28 | 3.13.16 | CC6.1 | — | 3.4.1 | SRG-APP-000429 | ISM-0457 | CPS.SC-28 |
| 10 | Audit logging configuration | AU-3 | 3.3.1 | CC7.2 | 8.5 | 10.2.1 | SRG-APP-000095 | ISM-0580 | CPS.AU-3 |
| 11 | Table-level access controls | AC-3(7) | 3.1.2 | CC6.1 | — | 7.1.2 | SRG-APP-000033 | ISM-0405 | CPS.AC-3 |
| 12 | Script execution restrictions | CM-7(2) | 3.4.8 | CC6.8 | — | 6.2.4 | SRG-APP-000141 | ISM-1624 | CPS.CM-7 |
| 13 | Instance hardening | CM-6(1) | 3.4.2 | CC6.1 | — | 2.2.1 | SRG-APP-000384 | ISM-1624 | CPS.CM-6 |
| 14 | Integration user permissions | AC-6(10) | 3.1.7 | CC6.3 | — | 7.1.2 | SRG-APP-000343 | ISM-0988 | CPS.AC-6 |
| 15 | Update set management | CM-3 | 3.4.3 | CC8.1 | — | 6.5.1 | SRG-APP-000380 | ISM-1624 | CPS.CM-3 |
| 16 | Debug mode verification | CM-7 | 3.4.7 | CC6.1 | — | 2.2.1 | SRG-APP-000141 | ISM-1624 | CPS.CM-7 |
| 17 | IP access restrictions | AC-17(1) | 3.1.12 | CC6.6 | — | 1.3.1 | SRG-APP-000142 | ISM-1528 | CPS.AC-17 |
| 18 | Email security | SC-8 | 3.13.8 | CC6.7 | — | 4.1.1 | SRG-APP-000411 | ISM-0572 | CPS.SC-8 |
| 19 | Mid Server security | SC-7(7) | 3.13.6 | CC6.6 | — | 1.3.2 | SRG-APP-000001 | ISM-1528 | CPS.SC-7 |
| 20 | Plugin inventory/licensing | CM-7(4) | 3.4.8 | CC6.8 | — | 2.2.1 | SRG-APP-000386 | ISM-1624 | CPS.CM-7 |

## 6. Existing Tools

| Tool | Description | Limitations |
|------|-------------|-------------|
| **ServiceNow Instance Security Center** | Built-in security dashboard (Paris+ releases) | Limited to ServiceNow UI; no external compliance mapping; requires separate license |
| **ServiceNow Security Best Practice** | KB articles and hardening guides | Manual checklist, no automated scanning |
| **Qualys WAS** | Web application scanning of ServiceNow instances | Tests web vulnerabilities, not platform configuration |
| **ServiceNow AES (Application Engine Studio)** | Application security testing | Focused on custom app security, not platform hardening |
| **AppOmni** | SaaS security posture for ServiceNow | Commercial; limited open-source alternative |
| **Obsidian Security** | SaaS security posture management | Commercial; ServiceNow is one of many platforms |

**Gap:** No open-source tool performs comprehensive ServiceNow instance security configuration auditing against multiple compliance frameworks. Existing tools are either built into ServiceNow (requiring license and manual review), commercial SaaS platforms, or focused on web vulnerability scanning rather than platform configuration posture.

### grclanker implementation

The spec is implemented natively in the grclanker CLI (`cli/extensions/grc-tools/servicenow.ts`) as read-only tools over the Table API and Aggregate API:

- `servicenow_check_access`: probes 25 audit tables and reports readable, forbidden, ACL-filtered, and unreadable surfaces
- `servicenow_assess_identity_access`: controls 3, 4, 6, 7, 8, 14
- `servicenow_assess_platform_hardening`: controls 1, 5, 12, 13, 16, 17, 18
- `servicenow_assess_access_control`: controls 2, 11
- `servicenow_assess_operations_governance`: controls 9, 10, 15, 19, 20
- `servicenow_export_audit_bundle`: raw snapshots, normalized findings, executive summary, unified compliance matrix, per-framework reports, and a paired zip archive

The integration guide lives at `src/content/docs/docs/integrations/servicenow.md`; regression tests at `cli/tests/servicenow.test.mjs`; live smoke at `npm --prefix cli run test:servicenow:live`.

## 7. Architecture

```
servicenow-sec-inspector/
├── cmd/
│   └── servicenow-sec-inspector/
│       └── main.go                  # CLI entrypoint
├── internal/
│   ├── client/
│   │   ├── table.go                 # Table API client with query builder
│   │   ├── aggregate.go             # Aggregate API client (counts, stats)
│   │   ├── auth.go                  # Authentication (Basic, OAuth, mTLS)
│   │   └── ratelimit.go             # Rate limiter (ServiceNow: instance-dependent)
│   ├── analyzers/
│   │   ├── properties.go            # Controls 1, 13, 16: Security properties and hardening
│   │   ├── acl.go                   # Controls 2, 11: ACL rules and table access
│   │   ├── roles.go                 # Control 3: Role hierarchy audit
│   │   ├── users.go                 # Control 4: User access review
│   │   ├── sessions.go              # Control 5: Session timeout
│   │   ├── password.go              # Control 6: Password policy
│   │   ├── mfa.go                   # Control 7: MFA enforcement
│   │   ├── sso.go                   # Control 8: LDAP/SSO integration
│   │   ├── encryption.go            # Control 9: Encryption at rest
│   │   ├── auditlog.go              # Control 10: Audit logging
│   │   ├── scripts.go               # Control 12: Script execution restrictions
│   │   ├── integrations.go          # Control 14: Integration user permissions
│   │   ├── updatesets.go            # Control 15: Update set management
│   │   ├── ipaccess.go              # Control 17: IP access restrictions
│   │   ├── email.go                 # Control 18: Email security
│   │   ├── midserver.go             # Control 19: MID Server security
│   │   └── plugins.go              # Control 20: Plugin inventory
│   ├── reporters/
│   │   ├── json.go                  # JSON output reporter
│   │   ├── csv.go                   # CSV output reporter
│   │   ├── markdown.go              # Markdown report with compliance matrix
│   │   ├── html.go                  # HTML dashboard report
│   │   └── sarif.go                 # SARIF format for CI/CD integration
│   ├── compliance/
│   │   ├── mapper.go                # Maps findings to framework controls
│   │   ├── fedramp.go               # FedRAMP control definitions
│   │   ├── cmmc.go                  # CMMC control definitions
│   │   ├── soc2.go                  # SOC 2 trust criteria
│   │   ├── cis.go                   # CIS Benchmark references
│   │   ├── pcidss.go                # PCI-DSS requirements
│   │   ├── stig.go                  # DISA STIG rules
│   │   ├── irap.go                  # IRAP ISM controls
│   │   └── ismap.go                 # ISMAP control references
│   ├── models/
│   │   ├── finding.go               # Finding severity, evidence, remediation
│   │   ├── control.go               # Security control definition
│   │   └── report.go                # Aggregate report model
│   └── tui/
│       ├── app.go                   # Bubble Tea TUI application
│       ├── views/
│       │   ├── dashboard.go         # Summary dashboard view
│       │   ├── controls.go          # Control detail drill-down
│       │   └── compliance.go        # Framework compliance matrix view
│       └── components/
│           ├── table.go             # Sortable findings table
│           ├── progress.go          # Scan progress indicator
│           └── severity.go          # Severity badge rendering
├── pkg/
│   └── version/
│       └── version.go               # Build version info
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile
├── .goreleaser.yaml
└── spec.md
```

### Key Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/spf13/cobra` | CLI framework |
| `github.com/charmbracelet/bubbletea` | Terminal UI framework |
| `github.com/charmbracelet/lipgloss` | TUI styling |
| `golang.org/x/oauth2` | OAuth 2.0 client for ServiceNow auth |

## 8. CLI Interface

```
servicenow-sec-inspector [command] [flags]

Commands:
  scan          Run security compliance scan against ServiceNow instance
  report        Generate compliance report from scan results
  version       Print version information

Global Flags:
  --instance string     ServiceNow instance name [$SERVICENOW_INSTANCE]
  --url string          ServiceNow instance URL [$SERVICENOW_URL]
  --username string     ServiceNow username [$SERVICENOW_USERNAME]
  --password string     ServiceNow password [$SERVICENOW_PASSWORD]
  --client-id string    OAuth client ID [$SERVICENOW_CLIENT_ID]
  --client-secret string OAuth client secret [$SERVICENOW_CLIENT_SECRET]
  --auth-method string  Authentication method: basic, oauth, mtls (default "basic")
  --output string       Output format: json, csv, markdown, html, sarif (default "json")
  --output-dir string   Directory for report output (default "./results")
  --severity string     Minimum severity to report: critical, high, medium, low, info (default "low")
  --controls string     Comma-separated list of control numbers to run (default: all)
  --quiet               Suppress progress output
  --no-color            Disable colored output
  --tui                 Launch interactive terminal UI

Scan Flags:
  --skip-grc            Skip GRC module checks (if not licensed)
  --skip-sir            Skip Security Incident Response checks (if not licensed)
  --skip-midserver      Skip MID Server checks
  --page-size int       Table API page size (default 100)
  --parallel int        Number of parallel API calls (default 4)
  --timeout duration    API call timeout (default 30s)

Examples:
  # Full instance security audit with JSON output
  servicenow-sec-inspector scan --instance mycompany --username admin --password ...

  # OAuth authentication with markdown report
  servicenow-sec-inspector scan --url https://mycompany.service-now.com \
    --auth-method oauth --client-id ... --client-secret ... --output markdown

  # Audit specific controls
  servicenow-sec-inspector scan --controls 1,2,5,6,7,10 --output markdown

  # Interactive TUI mode
  servicenow-sec-inspector scan --tui

  # CI/CD pipeline with SARIF output
  servicenow-sec-inspector scan --output sarif --severity high
```

## 9. Build Sequence

```bash
# 1. Initialize module
go mod init github.com/hackIDLE/servicenow-sec-inspector

# 2. Add dependencies
go get github.com/spf13/cobra
go get github.com/charmbracelet/bubbletea
go get github.com/charmbracelet/lipgloss
go get golang.org/x/oauth2

# 3. Build
go build -ldflags "-X pkg/version.Version=$(git describe --tags)" \
  -o bin/servicenow-sec-inspector ./cmd/servicenow-sec-inspector/

# 4. Test
go test ./...

# 5. Lint
golangci-lint run

# 6. Docker
docker build -t servicenow-sec-inspector .

# 7. Release
goreleaser release --snapshot
```

## 10. Status

Implemented in grclanker as of 2026-09-21 (TypeScript, `cli/extensions/grc-tools/servicenow.ts`). The standalone Go CLI, Docker image, and goreleaser flow described in sections 7 through 9 were not built; the grclanker tools replace them.

### What shipped

- Six read-only tools (see "grclanker implementation" in section 6) covering all 20 security controls, each finding carrying the eight framework mappings from section 5.
- Basic auth, OAuth 2.0 client credentials and password grants (with refresh token reuse), and pre-issued bearer tokens; configuration precedence of arguments, then environment variables, then a YAML config file.
- Table API pagination through `sysparm_offset` and `Link rel="next"` with `X-Total-Count` and Aggregate API counts used to detect ACL-filtered or truncated inventories; 429 and 5xx retry with backoff; credential redaction in errors.
- Evidence-gated verdicts: forbidden, filtered, errored, empty, or partial inputs never pass; absent system properties are never assumed to hold their defaults; rows without dates are bucketed separately.
- Audit bundle export with `core_data/`, `analysis/`, `compliance/` (executive summary, unified matrix, eight framework reports), `QUICK_REFERENCE.md`, `_errors.log` on partial collection, and a zip archive paired with a non-overwriting output directory.
- Regression tests including false-pass self-checks (all endpoints 403, all inventories empty, partial inventories), and a live smoke script.

### Deviations from this spec, following the official documentation

- Control 5: the pass threshold defaults to 60 minutes, the value recommended by the Instance Security Hardening Settings documentation for `glide.ui.session_timeout` (fallback 30 when unset); the 30 minute value suggested above is available through `max_session_timeout_minutes`. `glide.ui.session_timeout.warn` is not evaluated because it is not a documented property; `glide.ui.rotate_sessions` and `glide.ui.user_cookie.max_life_span_in_days` are read instead.
- Control 6: the `glide.security.password.*` properties listed above do not exist in the documented platform. Enforcement is read from `glide.enable.password_policy`, `glide.apply.password_policy.on_login`, and `glide.login.no_blank_password`, and the rules from the `password_policy` table (Default record).
- Control 7: `glide.authenticate.multifactor` and `glide.authenticate.multifactor.email.otp.enabled` are read; per-user enforcement uses `sys_user.enable_multifactor_authn`. MFA authentication policies are not exposed through the Table API and are left to manual review.
- Control 10: there is no global `glide.sys.audit_enabled` property. Auditing is per table through the `audit` flag on `sys_dictionary` collection records, so the tool reads those rows for the critical tables and counts recent `sys_audit` rows. Retention is not exposed and renders as manual.
- Control 12: `glide.script.block.server.globals` is not a documented property; `glide.script.use.sandbox`, `glide.script.allow.ajaxevaluate`, `glide.script.secure.ajaxgliderecord`, and `glide.script.ccsi.ispublic` are read instead, plus active business rules containing `eval(`.
- Control 16: debug detection queries every `sys_properties` row whose name contains `debug` with value `true` rather than a fixed list, because several names above (for example `glide.war`) are not documented debug flags.
- Control 17: `glide.ip.access.control` is not a documented property. Following the "Restrict access to specific IP ranges plugin" hardening page, the tool checks that the IP Range Based Authentication plugin (`com.snc.ipauthenticator`) is active in `sys_plugins` and that at least one active IP Address Access Controls (`ip_access`) record exists, then reads `glide.ip.authenticate.strict`. An `Invalid table` response for `ip_access` is treated as the plugin not being activated (fail), not as a read failure.
- Control 18: TLS on outbound email is read from the documented Email Account field Connection Security (`sys_email_account.connection_security`, choices None, STARTTLS, SSL/TLS), with the legacy `enable_ssl` and `enable_tls` booleans as a fallback on older schemas. None fails, STARTTLS warns (the documentation warns it may expose data), SSL/TLS is compliant, and an account whose value is not returned is reported as unverified rather than as a failure.
- Control 1: `glide.security.strict_elevate_privilege` is not read (undocumented); the CSRF, strict CSRF validation, MIME type validation, `glide.security.diag_txns_acl`, and strict user image upload properties are read.
- Authentication: mutual TLS is recognized but rejected because the runtime HTTP client cannot present client certificates.
- The CMDB, Attachment, Import Set, and Scripted REST APIs listed in section 2 are not used; every read goes through the Table API or Aggregate API.

### What remains

- Instance Security Center hardening score, Instance Scan results, Edge Encryption, DKIM, MID Server mutual authentication and allow lists, MFA policy contexts, and audit retention are reported as manual evidence; ServiceNow does not expose them through the Table API in a form the tool can verify.
- Mutual TLS support depends on a client-certificate capable HTTP transport.
- Live validation against a production instance is limited to the smoke script; wider tenant coverage may surface additional property or table name variations by release.
