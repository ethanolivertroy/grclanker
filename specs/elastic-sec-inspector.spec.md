---
slug: "elastic-sec-inspector"
name: "Elastic Security Inspector"
vendor: "Elastic"
category: "monitoring-logging-observability"
language: "typescript"
status: "implemented"
version: "1.0"
last_updated: "2026-09-21"
source_repo: "https://github.com/hackIDLE/grclanker"
legacy_repo: "https://github.com/hackIDLE/elastic-sec-inspector"
reference_docs: "https://www.elastic.co/docs/api/doc/elasticsearch/"
---

# Elastic Security Inspector — Architecture Specification

## 1. Overview

**elastic-sec-inspector** is a security compliance inspection tool for Elastic Cloud and self-managed Elasticsearch/Kibana deployments. It audits authentication realms, TLS configurations, role-based access controls, field/document-level security, API key management, audit logging, and cluster security settings via the Elasticsearch Security API and Kibana API. The tool produces structured findings mapped to major compliance frameworks, enabling security teams to identify misconfigurations and maintain continuous compliance posture.

Written in Go with a hybrid CLI/TUI architecture, it supports both automated pipeline execution (JSON/SARIF output) and interactive exploration of findings.

### grclanker implementation

The shipped implementation is native TypeScript inside grclanker (`cli/extensions/grc-tools/elastic.ts`) rather than the standalone Go binary described below. It registers seven read-only tools:

| Tool | Spec controls |
|------|---------------|
| `elastic_check_access` | Probes every read surface across Elasticsearch, Kibana, and Elastic Cloud and reports missing cluster and index privileges |
| `elastic_assess_identity` | 1, 9, 10, 13, 14 |
| `elastic_assess_access_control` | 6, 7, 8 |
| `elastic_assess_transport_security` | 2, 3, 4, 5 |
| `elastic_assess_cluster_hardening` | 11, 12, 17, 18, 19, 20, 22, 23 |
| `elastic_assess_kibana` | 15, 16, 21 |
| `elastic_export_audit_bundle` | All 23, written as `core_data/`, `analysis/`, `compliance/`, `QUICK_REFERENCE.md`, `_errors.log`, and a zip archive |

Findings use the ids `ELASTIC-01` through `ELASTIC-23`, carry the Section 5 framework mappings, and use the statuses `pass`, `warn`, `fail`, and `manual`. Tests live in `cli/tests/elastic.test.mjs`, the live smoke path in `cli/scripts/elastic-live-smoke.mjs` (`npm --prefix cli run test:elastic:live`), and the operator guide in `src/content/docs/docs/integrations/elastic.md`.

## 2. APIs & SDKs

### Elasticsearch Security API

| Endpoint | Purpose |
|----------|---------|
| `GET /_security/user` | List all native and mapped users |
| `GET /_security/user/{username}` | User details, roles, metadata |
| `GET /_security/role` | List all roles with privileges |
| `GET /_security/role/{name}` | Role details, indices, cluster privs |
| `GET /_security/role_mapping` | Role mapping rules (LDAP, SAML, OIDC) |
| `GET /_security/role_mapping/{name}` | Specific role mapping details |
| `GET /_security/api_key?owner=false` | All API keys in the cluster |
| `GET /_security/privilege` | Application privileges |
| `GET /_security/saml/metadata/{realm}` | SAML realm metadata |
| `GET /_cluster/settings?include_defaults=true` | Cluster security settings |
| `GET /_nodes/settings` | Node-level security settings |
| `GET /_ssl/certificates` | TLS certificate inventory |
| `GET /_license` | License level (security features gated) |
| `GET /_xpack/usage` | X-Pack feature usage statistics |
| `GET /_xpack/security` | Security feature enablement status |

### Kibana API

| Endpoint | Purpose |
|----------|---------|
| `GET /api/spaces/space` | List Kibana spaces |
| `GET /api/spaces/space/{id}` | Space details and disabled features |
| `GET /api/security/role` | Kibana roles and space privileges |
| `GET /api/fleet/agent_policies` | Fleet agent policy configurations |
| `GET /api/fleet/outputs` | Fleet output (Elasticsearch) configs |
| `GET /api/fleet/enrollment_api_keys` | Fleet enrollment key inventory |
| `GET /api/saved_objects/_find?type=config` | Kibana configuration objects |
| `GET /api/status` | Kibana security status |

### Elastic Cloud API (for Elastic Cloud deployments)

| Endpoint | Purpose |
|----------|---------|
| `GET /api/v1/deployments` | Deployment inventory |
| `GET /api/v1/deployments/{id}` | Deployment configuration details |
| `GET /api/v1/deployments/{id}/activity` | Deployment activity/audit trail |

**Base URLs:**
- Elasticsearch: `https://<cluster-host>:9200` or `https://<deployment-id>.es.<region>.cloud.es.io:9243`
- Kibana: `https://<cluster-host>:5601` or `https://<deployment-id>.kb.<region>.cloud.es.io:9243`
- Elastic Cloud: `https://api.elastic-cloud.com`

### SDKs and Libraries

| Name | Language | Notes |
|------|----------|-------|
| `go-elasticsearch` | Go | Official Go client for Elasticsearch |
| `elasticsearch-py` | Python | Official Python client |
| `elastic-cloud-cli` (ecctl) | Go | Official Elastic Cloud CLI |
| Terraform Provider (`ec`) | HCL | Official Elastic Cloud IaC provider |

## 3. Authentication

### Basic Authentication

```
Authorization: Basic base64(username:password)
```

- Used for native realm users
- Requires user with `superuser` or `monitoring_user` + `security_admin` roles

### API Key Authentication

```
Authorization: ApiKey base64(id:api_key)
```

- Recommended for automated scanning
- Create with appropriate cluster and index privileges

### OAuth/SAML/OIDC Token

```
Authorization: Bearer <access-token>
```

- Used when authenticating through external identity providers

### Elastic Cloud API Key

```
Authorization: ApiKey <cloud-api-key>
```

- For Elastic Cloud deployment-level queries

### Required Privileges

| Privilege | Scope | Purpose |
|-----------|-------|---------|
| `monitor` | Cluster | Cluster health, settings, node info |
| `manage_security` | Cluster | Read users, roles, role mappings, API keys |
| `manage_pipeline` | Cluster | Ingest pipeline configurations |
| `read_security` | Cluster | Read-only security configuration |
| `monitor_snapshot` | Cluster | Snapshot repository and policy info |
| `read` | `.security*` | Direct security index access (if needed) |

### Configuration

```bash
export ELASTIC_URL="https://your-cluster:9200"
export ELASTIC_USERNAME="inspector-user"
export ELASTIC_PASSWORD="your-password"
# Or use API key:
export ELASTIC_API_KEY="base64-encoded-id:key"
# For Kibana checks:
export KIBANA_URL="https://your-kibana:5601"
# For Elastic Cloud:
export ELASTIC_CLOUD_API_KEY="your-cloud-api-key"
```

Alternatively, configure via `~/.elastic-sec-inspector/config.yaml` or CLI flags.

## 4. Security Controls

1. **Authentication Realm Configuration** — Verify at least one secure authentication realm (SAML, OIDC, LDAP, PKI) is configured beyond the native realm.
2. **TLS/SSL Enforcement (Transport)** — Ensure TLS is enabled and enforced on the transport layer (node-to-node communication).
3. **TLS/SSL Enforcement (HTTP)** — Verify TLS is enabled on the HTTP layer (client-to-cluster communication).
4. **Minimum TLS Version** — Confirm minimum TLS protocol version is set to TLSv1.2 or higher.
5. **Certificate Expiration** — Detect TLS certificates approaching expiration (< 30 days) or already expired.
6. **Role-Based Access Control** — Audit roles for overly permissive cluster and index privileges; detect `superuser` role overuse.
7. **Field-Level Security** — Verify sensitive indices have field-level security restrictions on PII/sensitive fields.
8. **Document-Level Security** — Check that multi-tenant indices enforce document-level security for data isolation.
9. **API Key Management** — Enumerate API keys; detect keys without expiration, keys older than 90 days, inactive keys.
10. **API Key Privilege Scope** — Audit API key privileges for least-privilege; detect keys with `superuser` equivalent permissions.
11. **Audit Logging Enabled** — Confirm audit logging is enabled with appropriate event categories (authentication, access_denied, security_config_change).
12. **Audit Log Output** — Verify audit logs are configured to write to a persistent, tamper-resistant destination (not just local log file).
13. **SAML/OIDC SSO Configuration** — Validate external SSO realm configuration for proper attribute mapping and role assignment.
14. **Anonymous Access Disabled** — Ensure anonymous access is disabled or restricted to non-sensitive operations.
15. **Kibana Space Isolation** — Verify Kibana spaces enforce proper feature and data isolation between teams.
16. **Kibana Role Privileges** — Audit Kibana roles for overly broad space and feature privileges.
17. **Index Lifecycle Policies** — Confirm ILM policies enforce appropriate retention, rollover, and deletion for compliance.
18. **Snapshot Encryption** — Verify snapshot repositories use encrypted storage and snapshot lifecycle policies exist.
19. **Cluster Security Settings** — Check cluster-level security settings (password hashing, token service, etc.) are properly configured.
20. **Watcher/Alerting Security** — Audit Watcher actions for secure webhook destinations and credential handling.
21. **Fleet Agent Policy Security** — Verify Fleet agent policies enforce TLS, proper output configuration, and enrollment key management.
22. **Ingest Pipeline Security** — Check ingest pipelines for processors that may expose sensitive data (e.g., script processor, set processor with hardcoded values).
23. **License Level Verification** — Confirm the license level supports required security features (Platinum/Enterprise for SAML, field-level security, etc.).

## 5. Compliance Framework Mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | STIG | IRAP | ISMAP |
|---|---------|---------|------|-------|-----|---------|------|------|-------|
| 1 | Auth Realm Config | IA-2 | AC.L2-3.1.1 | CC6.1 | 1.1 | 8.3.1 | SRG-APP-000148 | ISM-1557 | CPS-04 |
| 2 | TLS Transport Layer | SC-8 | SC.L2-3.13.8 | CC6.7 | 3.1 | 4.1 | SRG-APP-000219 | ISM-0490 | CPS-09 |
| 3 | TLS HTTP Layer | SC-8 | SC.L2-3.13.8 | CC6.7 | 3.2 | 4.1 | SRG-APP-000219 | ISM-0490 | CPS-09 |
| 4 | Minimum TLS Version | SC-8(1) | SC.L2-3.13.8 | CC6.7 | 3.3 | 4.1 | SRG-APP-000219 | ISM-1369 | CPS-09 |
| 5 | Certificate Expiration | SC-17 | SC.L2-3.13.10 | CC6.7 | 3.4 | 4.1 | SRG-APP-000175 | ISM-0490 | CPS-09 |
| 6 | Role-Based Access | AC-2 | AC.L2-3.1.1 | CC6.3 | 6.1 | 7.2.1 | SRG-APP-000033 | ISM-0432 | CPS-07 |
| 7 | Field-Level Security | AC-3 | AC.L2-3.1.2 | CC6.3 | 6.2 | 7.2.2 | SRG-APP-000033 | ISM-0405 | CPS-07 |
| 8 | Document-Level Security | AC-3 | AC.L2-3.1.2 | CC6.3 | 6.3 | 7.2.2 | SRG-APP-000033 | ISM-0405 | CPS-07 |
| 9 | API Key Management | IA-5 | IA.L2-3.5.2 | CC6.1 | 5.1 | 8.6.1 | SRG-APP-000175 | ISM-1590 | CPS-05 |
| 10 | API Key Privilege Scope | AC-6 | AC.L2-3.1.5 | CC6.3 | 5.2 | 7.2.1 | SRG-APP-000340 | ISM-0432 | CPS-07 |
| 11 | Audit Logging Enabled | AU-2 | AU.L2-3.3.1 | CC7.2 | 8.1 | 10.2.1 | SRG-APP-000089 | ISM-0580 | CPS-10 |
| 12 | Audit Log Output | AU-9 | AU.L2-3.3.8 | CC7.2 | 8.2 | 10.5.1 | SRG-APP-000125 | ISM-0859 | CPS-10 |
| 13 | SAML/OIDC SSO | IA-2 | AC.L2-3.1.1 | CC6.1 | 1.2 | 8.3.1 | SRG-APP-000148 | ISM-1557 | CPS-04 |
| 14 | Anonymous Access | AC-14 | AC.L2-3.1.1 | CC6.1 | 1.3 | 7.2.3 | SRG-APP-000033 | ISM-0432 | CPS-07 |
| 15 | Kibana Space Isolation | AC-4 | AC.L2-3.1.3 | CC6.6 | 6.4 | 7.2.3 | SRG-APP-000039 | ISM-1148 | CPS-11 |
| 16 | Kibana Role Privileges | AC-6 | AC.L2-3.1.5 | CC6.3 | 6.5 | 7.2.2 | SRG-APP-000340 | ISM-0432 | CPS-07 |
| 17 | Index Lifecycle Policies | AU-11 | AU.L2-3.3.1 | CC7.4 | 8.3 | 3.1 | SRG-APP-000515 | ISM-0859 | CPS-10 |
| 18 | Snapshot Encryption | SC-28 | SC.L2-3.13.16 | CC6.7 | 3.5 | 3.4 | SRG-APP-000231 | ISM-0457 | CPS-09 |
| 19 | Cluster Security Settings | CM-6 | CM.L2-3.4.2 | CC8.1 | 10.1 | 2.2 | SRG-APP-000386 | ISM-0380 | CPS-12 |
| 20 | Watcher Security | AU-5 | AU.L2-3.3.4 | CC7.3 | 8.4 | 10.6.1 | SRG-APP-000108 | ISM-0580 | CPS-10 |
| 21 | Fleet Agent Policies | CM-6 | CM.L2-3.4.2 | CC8.1 | 10.2 | 2.2 | SRG-APP-000386 | ISM-0380 | CPS-12 |
| 22 | Ingest Pipeline Security | SC-28 | SC.L2-3.13.16 | CC6.7 | 3.6 | 3.4.1 | SRG-APP-000231 | ISM-0457 | CPS-09 |
| 23 | License Level Verification | CM-8 | CM.L2-3.4.1 | CC8.1 | 10.3 | 6.3.2 | SRG-APP-000456 | ISM-1490 | CPS-12 |

## 6. Existing Tools

| Tool | Type | Limitations |
|------|------|-------------|
| Elastic Security (SIEM) | Built-in | Detects threats in log data, not cluster-level security posture |
| Elasticsearch Audit Log | Built-in | Raw event log, no compliance analysis or reporting |
| ElastAlert | Alerting | Alert on log patterns, not security configuration assessment |
| ecctl (Elastic Cloud CLI) | CLI | Cloud deployment management, no security posture analysis |
| SearchGuard Compliance | Plugin | Third-party; limited to SearchGuard-specific features |
| CIS Elasticsearch Benchmark | Guide | Manual checklist, no automated scanning |

**Gap:** No existing tool provides automated security posture assessment of Elasticsearch/Kibana configurations — including field/document-level security, realm configuration, and Fleet policies — mapped to compliance frameworks. elastic-sec-inspector fills this gap.

## 7. Architecture

```
elastic-sec-inspector/
├── cmd/
│   └── elastic-sec-inspector/
│       └── main.go                 # Entrypoint, CLI bootstrap
├── internal/
│   ├── analyzers/
│   │   ├── analyzer.go             # Analyzer interface and registry
│   │   ├── authn.go                # Authentication realm checks
│   │   ├── tls.go                  # TLS transport/HTTP, min version, certs
│   │   ├── rbac.go                 # Role-based access, field/doc-level security
│   │   ├── apikeys.go              # API key management and privilege audit
│   │   ├── audit.go                # Audit logging enabled and output config
│   │   ├── sso.go                  # SAML/OIDC SSO configuration
│   │   ├── anonymous.go            # Anonymous access checks
│   │   ├── spaces.go               # Kibana space isolation
│   │   ├── kibanaroles.go          # Kibana role privilege audit
│   │   ├── lifecycle.go            # Index lifecycle policy checks
│   │   ├── snapshots.go            # Snapshot encryption and policies
│   │   ├── cluster.go              # Cluster security settings
│   │   ├── watcher.go              # Watcher action security
│   │   ├── fleet.go                # Fleet agent policy security
│   │   ├── ingest.go               # Ingest pipeline security
│   │   └── license.go              # License level verification
│   ├── client/
│   │   ├── client.go               # Unified client (ES + Kibana + Cloud)
│   │   ├── elasticsearch.go        # Elasticsearch API client
│   │   ├── kibana.go               # Kibana API client
│   │   ├── cloud.go                # Elastic Cloud API client
│   │   ├── auth.go                 # Multi-method auth (basic, API key, token)
│   │   └── tls.go                  # Custom TLS config (CA certs, skip verify)
│   ├── config/
│   │   ├── config.go               # Configuration loading and validation
│   │   └── redact.go               # Credential redaction for logging
│   ├── models/
│   │   ├── user.go                 # User and role mapping models
│   │   ├── role.go                 # Role, privilege, field/doc security models
│   │   ├── apikey.go               # API key model
│   │   ├── certificate.go          # TLS certificate model
│   │   ├── cluster.go              # Cluster settings model
│   │   └── finding.go              # Finding severity/status model
│   ├── reporters/
│   │   ├── reporter.go             # Reporter interface
│   │   ├── json.go                 # JSON output
│   │   ├── sarif.go                # SARIF 2.1.0 output
│   │   ├── csv.go                  # CSV output
│   │   ├── table.go                # Terminal table output
│   │   └── html.go                 # HTML report with charts
│   └── tui/
│       ├── app.go                  # Bubble Tea TUI application
│       ├── views.go                # Finding detail views
│       └── styles.go               # Lip Gloss styling
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile
├── spec.md
└── README.md
```

### Key Design Decisions

- **Multi-target support**: Works with Elastic Cloud, self-managed, and ECK (Kubernetes) deployments
- **License-aware**: Pre-flight license check determines which security features are available (Basic vs Platinum vs Enterprise)
- **Custom TLS handling**: Supports custom CA certificates, client certificates, and TLS skip-verify for self-managed clusters
- **Dual API layer**: Elasticsearch Security API for cluster-level checks, Kibana API for UI/space-level checks

## 8. CLI Interface

```
elastic-sec-inspector [command] [flags]

Commands:
  scan        Run all or selected security analyzers
  list        List available analyzers and their descriptions
  version     Print version information

Scan Flags:
  --url string             Elasticsearch URL (env: ELASTIC_URL)
  --username string        Username for basic auth (env: ELASTIC_USERNAME)
  --password string        Password for basic auth (env: ELASTIC_PASSWORD)
  --api-key string         API key (base64 id:key) (env: ELASTIC_API_KEY)
  --kibana-url string      Kibana URL (env: KIBANA_URL)
  --cloud-api-key string   Elastic Cloud API key (env: ELASTIC_CLOUD_API_KEY)
  --ca-cert string         Path to CA certificate for TLS verification
  --client-cert string     Path to client certificate for mTLS
  --client-key string      Path to client key for mTLS
  --insecure               Skip TLS verification (not recommended)
  --analyzers strings      Run specific analyzers (comma-separated)
  --exclude strings        Exclude specific analyzers
  --severity string        Minimum severity to report: critical,high,medium,low,info
  --format string          Output format: table,json,sarif,csv,html (default "table")
  --output string          Output file path (default: stdout)
  --tui                    Launch interactive TUI
  --no-color               Disable colored output
  --config string          Path to config file (default "~/.elastic-sec-inspector/config.yaml")
  --timeout duration       API request timeout (default 30s)
  --verbose                Enable verbose logging
```

### Usage Examples

```bash
# Full scan of Elastic Cloud deployment
elastic-sec-inspector scan --url https://my-deploy.es.us-east-1.aws.cloud.es.io:9243

# Self-managed cluster with custom CA
elastic-sec-inspector scan --url https://es-cluster:9200 --ca-cert /path/to/ca.pem

# TLS and authentication checks only
elastic-sec-inspector scan --analyzers tls,authn,sso

# Include Kibana checks
elastic-sec-inspector scan --url https://es:9200 --kibana-url https://kibana:5601

# Generate SARIF for CI/CD
elastic-sec-inspector scan --format sarif --output results.sarif

# Interactive TUI
elastic-sec-inspector scan --tui
```

## 9. Build Sequence

```bash
# Prerequisites
go 1.22+

# Clone and build
git clone https://github.com/hackIDLE/elastic-sec-inspector.git
cd elastic-sec-inspector
go mod download
go build -ldflags "-s -w -X main.version=$(git describe --tags --always)" \
  -o bin/elastic-sec-inspector ./cmd/elastic-sec-inspector/

# Run tests
go test ./...

# Build Docker image
docker build -t elastic-sec-inspector .

# Run via Docker
docker run --rm \
  -e ELASTIC_URL \
  -e ELASTIC_USERNAME \
  -e ELASTIC_PASSWORD \
  elastic-sec-inspector scan --format json
```

### Makefile Targets

```
make build       # Build binary
make test        # Run tests
make lint        # Run golangci-lint
make docker      # Build Docker image
make release     # Build for all platforms (linux/darwin/windows, amd64/arm64)
```

## 10. Status

**Implemented in grclanker (2026-09-21).** The Elastic inspector ships as native TypeScript tools in `cli/extensions/grc-tools/elastic.ts`; the Go/TUI architecture in Sections 7 through 9 is preserved as historical design context for the original standalone concept.

### What shipped

- Configuration resolution with the precedence explicit arguments, then environment variables (`ELASTIC_URL`/`ELASTICSEARCH_URL`, `ELASTIC_API_KEY`, `ELASTIC_USERNAME`/`ELASTIC_PASSWORD`, `ELASTIC_BEARER_TOKEN`, `KIBANA_URL`, `KIBANA_SPACE_ID`, `ELASTIC_CLOUD_API_KEY`, `ELASTIC_CLOUD_API_URL`, `ELASTIC_TIMEOUT`), then `~/.elastic-sec-inspector/config.yaml` (or `ELASTIC_SEC_INSPECTOR_CONFIG`). All four Section 3 auth modes are supported: `ApiKey` (with automatic base64 encoding of `id:key`), `Basic`, `Bearer`, and Elastic Cloud `ApiKey`.
- One client for Elasticsearch, Kibana (`kbn-xsrf: true`, space-aware `/s/{space}/api/...` paths), and Elastic Cloud with 429/502/503/504 retry and exponential backoff honoring `Retry-After`, request timeouts, transient network retry, and redaction of credentials in every error message and snapshot.
- Documented pagination for every list surface: `search_after` with `_sort` for `POST /_security/_query/api_key`, `from`/`size` for `POST /_watcher/_query/watches`, `page`/`perPage` for Fleet, and `page`/`per_page` for detection and alerting rules.
- `elastic_check_access`, five `elastic_assess_<area>` tools, and `elastic_export_audit_bundle`, together covering all 23 Section 4 controls with the Section 5 mappings on every finding. Verdicts never pass on missing or partial evidence: unreadable or forbidden endpoints yield `manual` findings that name the cause and the evidence a human must collect, empty inventories are judged per control (`fail` or `manual`, stated in the summary) and pass only where the control concerns existing items, scoped-out or unlicensed controls render as "not applicable" `manual` findings, undated items are bucketed and cap the verdict at `warn`, partial views (own API keys only, truncated pages, unresponsive nodes, single-node certificate reports, single-space Kibana inventories) cap the verdict and report seen and total counts, and every enabling flag (`xpack.security.enabled`, TLS `enabled` and `verification_mode`, `xpack.security.audit.enabled`, realm `enabled`, anonymous roles, license type and status) is read before a `pass`, with transient over persistent over node over default precedence.
- Re-running the export allocates a fresh directory and derives the archive name from it, so a prior bundle is never overwritten.
- 45 mocked Node tests (including regression tests for each verdict-safety rule and three false-pass self-checks) plus a live smoke script that skips cleanly without credentials.

### Deviations from this spec (official documentation wins)

- `GET /_security/api_key?owner=false` was replaced by `POST /_security/_query/api_key?with_limited_by=true`, the documented paginated endpoint that also exposes owner privileges for keys that inherit them.
- `GET /_xpack/security` is not a documented endpoint; feature enablement comes from `GET /_xpack` (`features.security`) and `GET /_xpack/usage`.
- `GET /api/saved_objects/_find?type=config` is deprecated in current Kibana and is not used. Kibana status comes from `GET /api/status`.
- `GET /_security/privilege` and `GET /_security/saml/metadata/{realm}` are not collected: application privileges do not feed any Section 4 control, and SAML metadata requires realm names that are only visible in settings. SSO checks (control 13) use non-secret realm settings from `GET /_nodes/settings?flat_settings=true` plus role mappings.
- Per-item endpoints (`/_security/user/{username}`, `/_security/role/{name}`, `/_security/role_mapping/{name}`, `/api/spaces/space/{id}`, `/api/v1/deployments/{id}`, `/api/v1/deployments/{id}/activity`) are not called because the list endpoints already return the full objects; only `GET /api/v1/deployments` is collected from Elastic Cloud, as inventory.
- Added surfaces not in Section 2 that the controls require: `GET /_security/_authenticate`, `POST /_security/user/_has_privileges`, `GET /_ilm/status`, `GET /_ilm/policy`, `GET /_slm/status`, `GET /_slm/policy`, `GET /_snapshot/_all`, `POST /_watcher/_query/watches`, `GET /_ingest/pipeline`, `GET /api/fleet/fleet_server_hosts`, `GET /api/detection_engine/rules/_find`, `GET /api/alerting/rules/_find`, and `GET /api/actions/connectors`.
- Section 3 lists `manage_security` and `manage_pipeline`; the implementation asks for the read-only equivalents (`read_security`, `read_pipeline`) plus `manage_api_key`, `read_ilm`, `read_slm`, `monitor_snapshot`, and `monitor_watcher`, and reports whichever are missing.
- Cluster defaults are read with `GET /_cluster/settings?include_defaults=true&flat_settings=true` and node values with `GET /_nodes/settings?flat_settings=true`, because per-node settings are where realm, TLS, and audit configuration actually live.

### What remains

- Control 12 (audit log output) can only confirm that auditing is enabled and writes to the `logfile` output; forwarding to a tamper-resistant destination is a permanent manual evidence item.
- Control 18 verifies encryption only for GCS, Azure, and S3 with `server_side_encryption`; other repository types need manual storage encryption evidence.
- Controls 7 and 8 need `sensitive_index_patterns` and `tenant_index_patterns` to move beyond a warning, since the API cannot identify which indices hold sensitive or tenant data.
- No SARIF, CSV, HTML, or TUI output; grclanker's bundle export (JSON, Markdown, zip) is the reporting surface.
- Custom CA, client certificate (mTLS), and skip-verify options from Section 8 are not exposed; the Node runtime trust store is used.
- Live validation against a real Elastic Cloud deployment and a self-managed 8.x cluster is still pending.
