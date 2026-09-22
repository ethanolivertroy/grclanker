---
slug: "oci-sec-inspector"
name: "OCI Security Inspector"
vendor: "Oracle"
category: "cloud-infrastructure"
language: "typescript"
status: "implemented"
version: "1.0"
last_updated: "2026-09-21"
source_repo: "https://github.com/hackIDLE/grclanker"
---

# OCI Security Inspector - Architecture Specification

## 1. Overview

OCI Security Inspector is a security compliance inspection tool for Oracle Cloud Infrastructure (OCI). It audits IAM policies, networking configurations, Cloud Guard posture, vault key management, audit logging, and bastion access controls across OCI tenancies and compartments. The tool produces structured findings mapped to major compliance frameworks, enabling continuous compliance monitoring for organizations running workloads on OCI.

Written in Go with a hybrid CLI/TUI architecture, it performs read-only inspection of OCI resources using official REST APIs and produces machine-readable JSON and human-readable reports.

### grclanker implementation

The shipped implementation lives in `cli/extensions/grc-tools/oci.ts` as six native tools (`oci_check_access`, `oci_assess_identity`, `oci_assess_logging_detection`, `oci_assess_tenancy_guardrails`, `oci_assess_compute_and_storage`, `oci_export_audit_bundle`). It keeps the OCI CLI (API-key profile from `~/.oci/config`) as the authenticated transport and implements assessment, verdict-safety, and export natively. Every command, flag, and field is cited to the OCI CLI command reference and the REST API reference in `OCI_SURFACE_DOCS`. The integration guide is `src/content/docs/docs/integrations/oci.md`.

## 2. APIs & SDKs

### OCI REST APIs

| Service | Base Path | Key Endpoints | Purpose |
|---------|-----------|---------------|---------|
| IAM | `/20160918` | `/users`, `/groups`, `/policies`, `/compartments`, `/authenticationPolicies`, `/identityProviders`, `/mfaTotpDevices` | Identity, access policies, MFA |
| Audit | `/20190901` | `/auditEvents` | Audit log retrieval and retention config |
| Cloud Guard | `/20200131` | `/detectorRecipes`, `/problems`, `/responderRecipes`, `/targets`, `/managedLists` | Threat detection posture |
| Bastion | `/20210331` | `/bastions`, `/sessions` | Bastion host and session management |
| Networking (VCN) | `/20160918` | `/vcns`, `/subnets`, `/securityLists`, `/networkSecurityGroups`, `/nsgSecurityRules`, `/internetGateways`, `/routeTables` | Network security posture |
| Vault (KMS) | `/20180608` | `/vaults`, `/keys`, `/keyVersions` | Key management and rotation |
| Object Storage | `/20160918` (namespace) | `/n/{namespace}/b` (buckets), `/n/{namespace}/b/{bucket}/preauthenticatedRequests` | Bucket public access, PAR audit |
| Compute | `/20160918` | `/instances`, `/images`, `/vnicAttachments` | Instance metadata service version |
| Block Storage | `/20160918` | `/volumes`, `/bootVolumes`, `/volumeBackupPolicies` | Volume encryption settings |
| Budget | `/20190111` | `/budgets`, `/alertRules` | Cost alerting configuration |
| OS Management | `/20190801` | `/managedInstances`, `/scheduledJobs` | Patch compliance |
| Events | `/20181201` | `/rules` | Event rule configuration |

### SDKs and Libraries

| SDK | Language | Package | Notes |
|-----|----------|---------|-------|
| OCI SDK for Go | Go | `github.com/oracle/oci-go-sdk/v65` | Official Oracle SDK; used for all API calls |
| OCI CLI | Python | `oci-cli` (pip) | Reference for API behavior and testing |
| OCI Terraform Provider | Go | `github.com/oracle/terraform-provider-oci` | Reference for resource models |

### API Rate Limits

- Most OCI APIs enforce per-tenancy rate limits (varies by service, typically 10-20 requests/second)
- List operations return paginated results via `opc-next-page` header
- SDK handles retries with exponential backoff via `common.ConfigureClientWithRetries`

## 3. Authentication

### Supported Authentication Methods

| Method | Config Source | Use Case |
|--------|-------------|----------|
| API Key Signing | `~/.oci/config` profile (tenancy, user, fingerprint, key_file, region) | Developer workstations, CI/CD |
| Instance Principal | Instance metadata service (automatic) | Running on OCI compute instances |
| Resource Principal | `OCI_RESOURCE_PRINCIPAL_*` environment variables | OCI Functions, Container Instances |
| Session Token | `~/.oci/config` with `security_token_file` | OCI CLI session-based auth |
| Delegation Token | `OCI_DELEGATION_TOKEN_FILE` environment variable | Cloud Shell |

### API Key Signing Details

OCI uses RSA key pair signing (not bearer tokens). Each API request is signed with:
- HTTP method, path, date, host, and content headers
- Signing algorithm: `rsa-sha256`
- Key: User's PEM private key (2048-bit or 4096-bit RSA)
- The `Authorization` header follows the HTTP Signature scheme

### Required IAM Policies (Minimum Permissions)

```
Allow group SecurityInspectors to inspect all-resources in tenancy
Allow group SecurityInspectors to read audit-events in tenancy
Allow group SecurityInspectors to read cloud-guard-family in tenancy
Allow group SecurityInspectors to read bastion-family in tenancy
Allow group SecurityInspectors to read vaults in tenancy
Allow group SecurityInspectors to read keys in tenancy
Allow group SecurityInspectors to read buckets in tenancy
Allow group SecurityInspectors to read budget-family in tenancy
```

### Configuration Precedence

1. CLI flags (`--config-file`, `--profile`, `--region`)
2. Environment variables (`OCI_CONFIG_FILE`, `OCI_CLI_PROFILE`, `OCI_REGION`)
3. Default config file `~/.oci/config` with `[DEFAULT]` profile

## 4. Security Controls

1. **IAM password policy strength** - Verify authentication policy enforces minimum length (14+), complexity, and expiration (90 days max)
2. **MFA enforcement for console users** - Check that all IAM users with console access have MFA TOTP devices enrolled and activated
3. **API key age and rotation** - Identify API keys older than 90 days; flag keys older than 180 days as critical
4. **Customer secret key rotation** - Verify S3-compatible access keys are rotated within 90-day windows
5. **Auth token rotation** - Check SWIFT/auth token age does not exceed 90 days
6. **IAM policy least privilege** - Analyze policy statements for overly broad permissions (`manage all-resources`, wildcards in resource types)
7. **Compartment structure depth** - Verify tenancy uses compartment hierarchy (not flat) for resource isolation
8. **Cloud Guard enabled and active** - Confirm Cloud Guard is enabled in the root compartment with detector recipes assigned to targets
9. **Cloud Guard open problems** - Enumerate unresolved Cloud Guard problems by severity (CRITICAL, HIGH, MEDIUM, LOW)
10. **Responder recipe activation** - Verify Cloud Guard responder recipes are in ACTIVE state with appropriate responder rules enabled
11. **Audit log retention** - Verify audit retention period is set to 365 days (maximum)
12. **Event rules for critical operations** - Confirm event rules exist for IAM changes, network changes, and policy modifications
13. **Security list ingress rules** - Analyze security lists for overly permissive ingress (0.0.0.0/0 on sensitive ports: 22, 3389, 1433, 3306, 5432)
14. **NSG rules analysis** - Check network security group rules for unrestricted inbound access from any source
15. **Internet gateway exposure** - Identify VCNs with internet gateways and verify associated subnets have appropriate security lists
16. **Bastion session controls** - Verify bastion service configurations enforce maximum session TTL and restrict allowed CIDR blocks
17. **Bastion active sessions** - Enumerate active bastion sessions and flag long-running or unusual sessions
18. **Vault key rotation** - Check that KMS master encryption keys have been rotated within the last 365 days
19. **Vault key algorithm strength** - Verify vault keys use AES-256 or RSA-4096 (flag weaker algorithms)
20. **Object Storage public access** - Identify buckets with `publicAccessType` set to `ObjectRead` or `ObjectReadWithoutList`
21. **Pre-authenticated request audit** - List active pre-authenticated requests (PARs) and flag those with no expiration or distant expiration dates
22. **Block volume encryption** - Verify all block volumes and boot volumes use customer-managed encryption keys (not Oracle-managed)
23. **Instance metadata service v2** - Check that compute instances require IMDSv2 (`areLegacyImdsEndpointsDisabled: true`)
24. **Budget alert rules** - Verify at least one budget with alert rules exists at the tenancy or compartment level
25. **OS Management patching compliance** - Check managed instances for outstanding security patches and update compliance status

## 5. Compliance Framework Mappings

| # | Control | FedRAMP | CMMC | SOC 2 | CIS OCI | PCI-DSS | STIG | IRAP | ISMAP |
|---|---------|---------|------|-------|---------|---------|------|------|-------|
| 1 | IAM password policy | IA-5 | L2 3.5.7 | CC6.1 | 1.1 | 8.3.6 | SRG-APP-000166 | ISM-0421 | AM-03 |
| 2 | MFA enforcement | IA-2(1) | L2 3.5.3 | CC6.1 | 1.2 | 8.4.2 | SRG-APP-000149 | ISM-1401 | AM-04 |
| 3 | API key rotation | IA-5(1) | L2 3.5.8 | CC6.1 | 1.7 | 8.6.3 | SRG-APP-000174 | ISM-1590 | AM-05 |
| 4 | Customer secret key rotation | IA-5(1) | L2 3.5.8 | CC6.1 | 1.8 | 8.6.3 | SRG-APP-000174 | ISM-1590 | AM-05 |
| 5 | Auth token rotation | IA-5(1) | L2 3.5.8 | CC6.1 | 1.9 | 8.6.3 | SRG-APP-000174 | ISM-1590 | AM-05 |
| 6 | Policy least privilege | AC-6 | L2 3.1.5 | CC6.3 | 1.14 | 7.2.1 | SRG-APP-000340 | ISM-0432 | AC-01 |
| 7 | Compartment structure | AC-4 | L2 3.13.1 | CC6.1 | 1.3 | 1.3.1 | SRG-APP-000039 | ISM-1416 | AC-02 |
| 8 | Cloud Guard enabled | SI-4 | L2 3.14.6 | CC7.2 | 3.1 | 11.5.1 | SRG-APP-000516 | ISM-0120 | SO-01 |
| 9 | Cloud Guard open problems | SI-4(5) | L2 3.14.7 | CC7.3 | 3.2 | 11.5.1.1 | SRG-APP-000516 | ISM-0123 | SO-02 |
| 10 | Responder recipe activation | IR-4 | L2 3.6.1 | CC7.4 | 3.3 | 12.10.5 | SRG-APP-000516 | ISM-0125 | IR-01 |
| 11 | Audit log retention | AU-11 | L2 3.3.1 | CC7.2 | 3.4 | 10.7.1 | SRG-APP-000515 | ISM-0859 | LG-01 |
| 12 | Event rules | AU-12 | L2 3.3.1 | CC7.2 | 3.5 | 10.6.1 | SRG-APP-000492 | ISM-0580 | LG-02 |
| 13 | Security list ingress | SC-7 | L2 3.13.1 | CC6.6 | 2.1 | 1.3.1 | SRG-APP-000142 | ISM-1416 | NW-01 |
| 14 | NSG rules analysis | SC-7 | L2 3.13.1 | CC6.6 | 2.2 | 1.3.2 | SRG-APP-000142 | ISM-1416 | NW-01 |
| 15 | Internet gateway exposure | SC-7(5) | L2 3.13.6 | CC6.6 | 2.3 | 1.3.1 | SRG-APP-000383 | ISM-1417 | NW-02 |
| 16 | Bastion session controls | AC-17 | L2 3.1.12 | CC6.1 | 2.8 | 8.6.1 | SRG-APP-000190 | ISM-1506 | AC-03 |
| 17 | Bastion active sessions | AC-17(1) | L2 3.1.12 | CC6.2 | 2.9 | 8.6.1 | SRG-APP-000190 | ISM-1506 | AC-03 |
| 18 | Vault key rotation | SC-12(1) | L2 3.13.10 | CC6.1 | 4.1 | 3.6.4 | SRG-APP-000514 | ISM-0490 | CR-01 |
| 19 | Vault key algorithm strength | SC-13 | L2 3.13.11 | CC6.1 | 4.2 | 3.6.1 | SRG-APP-000514 | ISM-0457 | CR-02 |
| 20 | Object Storage public access | AC-3 | L2 3.1.1 | CC6.1 | 5.1 | 1.3.6 | SRG-APP-000033 | ISM-0405 | DS-01 |
| 21 | Pre-authenticated request audit | AC-3 | L2 3.1.2 | CC6.1 | 5.2 | 7.2.2 | SRG-APP-000033 | ISM-0405 | DS-02 |
| 22 | Block volume encryption | SC-28 | L2 3.13.16 | CC6.1 | 4.3 | 3.4.1 | SRG-APP-000429 | ISM-1080 | CR-03 |
| 23 | Instance metadata v2 | CM-7 | L2 3.4.7 | CC6.1 | 2.10 | 2.2.1 | SRG-APP-000141 | ISM-1418 | CM-01 |
| 24 | Budget alert rules | SA-10 | L2 3.12.4 | CC3.1 | 6.1 | 12.5.2 | SRG-APP-000516 | ISM-1211 | GM-01 |
| 25 | OS Management patching | SI-2 | L2 3.14.1 | CC7.1 | 7.1 | 6.3.3 | SRG-APP-000456 | ISM-1143 | VM-01 |

## 6. Existing Tools

| Tool | Type | Coverage | Limitations |
|------|------|----------|-------------|
| **OCI Cloud Guard** | Native service | Threat detection, configuration drift | Requires Cloud Guard enablement; limited custom rules; no offline/export capability |
| **OCI Security Zones** | Native service | Preventive controls for compartments | Binary allow/deny only; no audit reporting; limited to zone-enabled compartments |
| **Oracle Cloud Compliance** | Native service | Compliance posture dashboard | Console-only; no CLI/API export; limited framework mappings |
| **Steampipe OCI Plugin** | Open source | SQL-based querying of OCI resources | Requires Steampipe runtime; no built-in compliance logic; query-only |
| **Prowler (OCI support)** | Open source | Multi-cloud security assessment | OCI support is limited and newer; fewer OCI-specific checks than AWS |
| **ScoutSuite** | Open source | Multi-cloud auditing | OCI support is experimental; limited service coverage |
| **oci-auditing (custom scripts)** | Community | Various OCI audit scripts | Fragmented; no unified reporting; maintenance varies |

### Differentiation

OCI Security Inspector provides a unified, Go-based CLI tool with deep OCI API coverage, structured findings output, and direct compliance framework mappings across eight frameworks. Unlike Cloud Guard (which requires OCI console access), this tool runs externally and produces portable compliance reports.

## 7. Architecture

```
oci-sec-inspector/
├── cmd/
│   └── oci-sec-inspector/
│       └── main.go                   # Entry point, CLI parsing, TUI initialization
├── internal/
│   ├── analyzers/
│   │   ├── analyzer.go               # Analyzer interface and registry
│   │   ├── iam.go                    # Controls 1-6: IAM password policy, MFA, key rotation, policies
│   │   ├── compartment.go            # Control 7: Compartment structure analysis
│   │   ├── cloudguard.go             # Controls 8-10: Cloud Guard status, problems, responders
│   │   ├── audit.go                  # Controls 11-12: Audit retention, event rules
│   │   ├── networking.go             # Controls 13-15: Security lists, NSGs, internet gateways
│   │   ├── bastion.go                # Controls 16-17: Bastion config and session analysis
│   │   ├── vault.go                  # Controls 18-19: Key rotation, algorithm strength
│   │   ├── storage.go                # Controls 20-22: Object Storage, PARs, block volume encryption
│   │   ├── compute.go                # Control 23: IMDSv2 enforcement
│   │   ├── budget.go                 # Control 24: Budget alert rules
│   │   └── osmanagement.go           # Control 25: Patch compliance
│   ├── reporters/
│   │   ├── reporter.go               # Reporter interface
│   │   ├── json.go                   # JSON output (findings array, SARIF-compatible option)
│   │   ├── csv.go                    # CSV tabular output
│   │   ├── html.go                   # Styled HTML report with severity breakdown
│   │   └── compliance.go             # Compliance matrix report (framework-mapped)
│   ├── client/
│   │   ├── oci.go                    # OCI SDK client wrapper, auth provider selection
│   │   ├── pagination.go             # Generic paginated list helper
│   │   └── ratelimit.go              # Per-service rate limiter
│   ├── config/
│   │   ├── config.go                 # Configuration struct and loader
│   │   └── defaults.go               # Default thresholds (key age, retention days, etc.)
│   ├── models/
│   │   ├── finding.go                # Finding struct (severity, control, resource, evidence)
│   │   ├── severity.go               # Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO
│   │   └── compliance.go             # Compliance mapping structs
│   └── tui/
│       ├── app.go                    # Bubble Tea TUI application
│       ├── views.go                  # TUI view components
│       └── styles.go                 # Lip Gloss styling
├── pkg/
│   └── version/
│       └── version.go                # Build version, commit, date (ldflags)
├── configs/
│   ├── controls.yaml                 # Control definitions and framework mappings
│   └── thresholds.yaml               # Configurable thresholds (key age, scan intervals)
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile
├── spec.md
└── README.md
```

### Key Design Decisions

- **OCI Go SDK**: Uses `github.com/oracle/oci-go-sdk/v65` for all API interactions with native auth provider support
- **Compartment recursion**: Analyzers walk the full compartment tree by default; `--compartment-ocid` limits scope
- **Parallel execution**: Analyzers run concurrently across compartments using worker pools (`--concurrency` flag)
- **Finding model**: Each finding includes resource OCID, compartment path, severity, control ID, evidence, and remediation guidance

## 8. CLI Interface

```
oci-sec-inspector [command] [flags]

Commands:
  scan          Run security inspection across OCI tenancy
  report        Generate report from saved scan results
  list          List available controls, frameworks, or compartments
  version       Print version information

Scan Flags:
  --config-file string        OCI config file path (default "~/.oci/config")
  --profile string            OCI config profile name (default "DEFAULT")
  --region string             OCI region override (default: from config)
  --compartment-ocid string   Limit scan to specific compartment (default: tenancy root)
  --recurse                   Recursively scan child compartments (default: true)
  --controls string           Comma-separated control IDs to run (default: all)
  --exclude-controls string   Comma-separated control IDs to skip
  --severity string           Minimum severity to report: CRITICAL,HIGH,MEDIUM,LOW,INFO (default: LOW)
  --concurrency int           Number of parallel analyzer workers (default: 5)
  --timeout duration          Maximum scan duration (default: 30m)

Output Flags:
  --output string             Output format: json, csv, html, compliance, table (default: table)
  --output-file string        Write output to file (default: stdout)
  --sarif                     Output in SARIF format for CI integration
  --quiet                     Suppress progress output, print only results

Global Flags:
  --log-level string          Log level: debug, info, warn, error (default: info)
  --no-color                  Disable colored output
  --tui                       Launch interactive TUI mode
```

### Usage Examples

```bash
# Full tenancy scan with JSON output
oci-sec-inspector scan --output json --output-file findings.json

# Scan specific compartment, networking controls only
oci-sec-inspector scan --compartment-ocid ocid1.compartment.oc1..xxx \
  --controls 13,14,15 --output table

# High severity and above, using non-default profile
oci-sec-inspector scan --profile PROD --severity HIGH --output html \
  --output-file report.html

# Interactive TUI mode
oci-sec-inspector --tui

# List available controls
oci-sec-inspector list controls

# Generate compliance matrix from previous scan
oci-sec-inspector report --input findings.json --output compliance \
  --frameworks fedramp,pci-dss
```

## 9. Build Sequence

```bash
# 1. Initialize Go module
go mod init github.com/hackIDLE/oci-sec-inspector

# 2. Add dependencies
go get github.com/oracle/oci-go-sdk/v65@latest
go get github.com/spf13/cobra@latest
go get github.com/charmbracelet/bubbletea@latest
go get github.com/charmbracelet/lipgloss@latest
go get gopkg.in/yaml.v3@latest
go get go.uber.org/zap@latest

# 3. Build
go build -ldflags "-X pkg/version.Version=$(git describe --tags --always) \
  -X pkg/version.Commit=$(git rev-parse HEAD) \
  -X pkg/version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o bin/oci-sec-inspector ./cmd/oci-sec-inspector

# 4. Run tests
go test ./... -v -race -coverprofile=coverage.out

# 5. Lint
golangci-lint run ./...

# 6. Docker build
docker build -t oci-sec-inspector:latest .

# 7. Cross-compile
GOOS=linux GOARCH=amd64 go build -o bin/oci-sec-inspector-linux-amd64 ./cmd/oci-sec-inspector
GOOS=darwin GOARCH=arm64 go build -o bin/oci-sec-inspector-darwin-arm64 ./cmd/oci-sec-inspector
GOOS=windows GOARCH=amd64 go build -o bin/oci-sec-inspector-windows-amd64.exe ./cmd/oci-sec-inspector
```

### Makefile Targets

| Target | Description |
|--------|-------------|
| `make build` | Build binary for current platform |
| `make test` | Run tests with race detection |
| `make lint` | Run golangci-lint |
| `make docker` | Build Docker image |
| `make release` | Cross-compile for linux/darwin/windows |
| `make clean` | Remove build artifacts |

## 10. Status

Implemented in grclanker (TypeScript) on 2026-09-21; the Go/TUI architecture in sections 7-9 remains the original design reference and was not built.

### Shipped

- 21 findings across four assess tools covering controls 1-23: OCI-IAM-01..06, OCI-LOG-01..06 (OCI-LOG-04 is supporting audit-event evidence), OCI-GRD-01..06, OCI-CMP-01..03.
- Verdict safety: unreadable or denied surfaces (including the documented `NotAuthorizedOrNotFound` response) render `manual`; empty inventories never pass by default; compartment caps, denied compartments, item caps, and undated items withhold `pass`; every enabling flag is read explicitly; the CLI `--all` flag pages to completion; bundle reruns allocate `-2`, `-3` and never overwrite. A finding that reads more than one inventory demotes when any of them is incomplete (OCI-GRD-02 and OCI-GRD-03 consult the security list inventory for their vacuous-empty verdict and warn when it is partial), and every demoted summary names the failing CLI command and the compartments it could not read; a table-driven test makes each of the 33 client surfaces unreadable in turn (fully and per compartment) and asserts the dependent findings drop below pass and name the surface while unrelated findings keep passing.
- Evidence bundle with `core_data/`, `analysis/`, `compliance/` (executive summary, unified matrix, one report per framework in section 5), `QUICK_REFERENCE.md`, and `_errors.log` on partial collection.
- Bundle secret hygiene: credential-bearing fields (`accessUri`, `keyValue`, `token`, `key`, secrets, passwords, private keys, key material, wrapped keys, `userData`, `authorization`) are replaced with `[redacted]` at finding creation, PEM blocks, PAR URIs, the OCI request-signing `Signature` parameter list, standalone `keyId`/`signingKeyId`/`signature` values (assignment and JSON-colon forms), and `token`/`secret`/`password`/`pass_phrase`/`key_file`/`access_uri` assignments are scrubbed from all strings including CLI errors, raw compartment snapshots are projected to the four documented fields the verdicts read, and the config file path is redacted from `metadata.json` and `access.json`; a regression test writes a bundle from `FAKE_`-marked fixtures and asserts no marker survives in any file or zip entry.
- Cap truncation: `max_compartments`, `max_keys`, `max_policies`, and `max_buckets` each record the cap hit, report seen versus total, and withhold `pass`; one regression test per cap drives it to the cap.
- CLI error text: a failing `oci` process never has its stderr or stdout echoed. The runner raises `OciCommandError`, whose message keeps only the documented `ServiceError` fields (`status`, `code`, `message`, `opc-request-id`) after scrubbing, or otherwise a descriptor with the command words, exit code, and stderr and stdout byte counts. One exported scrub, `scrubErrorText`, runs once where every error string is created (the `OciCommandError` constructor and `errorMessage`), before the 500-character `ServiceError` message cap and the 1000-character `errorMessage` cap so no fragment of a secret can straddle a cap; it strips embedded URL queries and fragments, Bearer, Basic, cookie, api key, session, access, refresh, and id token, client secret, password, `Signature`, and `keyId` shapes (quoted or not), and any unlabeled run of 16 or more token characters that contains a digit or a `+` in free text, while `kmsKeyId`, `masterKeyId`, `--key-id`, and OCIDs stay readable. The bundle sink is a second layer in data mode: `scrubAssessmentForBundle` and the export path apply `redactSensitiveText` (the same patterns with the long-token rule off) to every finding summary, errors array entry, and access-check error, so identifiers such as a compartment named `prod-us-east-2026` survive in `_errors.log`, the per-area errors arrays, and the executive summary while `token=` shapes are still redacted there. An `opc-request-id` is disclosed only when it matches a documented layout, the CLI's `32hex(/32hex){0,2}` form or the UUID form shown in `usingapi.htm`; any other value behind the label is dropped from the disclosure. Residuals: a value that matches a documented layout and is deliberately placed directly behind an `opc-request-id=` label stays readable (no OCI secret has the bare 32-hex shape; the identity-domain OAuth client secret has the UUID shape), which is exfiltration rather than accidental echo; an unlabeled token of 16 or more characters with no digit or `+` is not redacted by the long-token rule; the in-memory errors arrays and assessment summary statuses wrap compartment names (and, in one informational line, vault display names) around each cause verbatim as tenant data, and the sink redacts assignment shapes inside them for the bundle. A table-driven walk drives all 33 client surfaces through three failure shapes and asserts no canary reaches a finding, summary, errors array, bundle file, zip entry, or thrown error, and that each failure is disclosed.
- Live smoke script `cli/scripts/oci-live-smoke.mjs` (`npm --prefix cli run test:oci:live`).

### Deviations from this spec (docs win over spec)

- Control 1 expiration: the IAM `PasswordPolicy` datatype exposes no expiration setting, so expiration is a separate always-manual finding (OCI-IAM-06); length and complexity are judged from the documented fields.
- Control 2 uses the documented `User.isMfaActivated` field instead of enumerating TOTP devices per user.
- Control 9 uses `ProblemSummary.riskLevel` and `lifecycleDetail=OPEN` (the API has no `severity` field on problems).
- Control 19 key length lives on `Key.keyShape` (GetKey), not on `KeySummary`, so every ENABLED key is fetched with `oci kms management key get --key-id --endpoint` (capped by `max_keys`). `KeyShape.length` is documented in bytes (AES 16/24/32, RSA 256/384/512, ECDSA 32/48/66): AES below 32 bytes and RSA below 512 bytes fail. The control text names only AES-256 and RSA-4096, so ECDSA keys pass on any documented `curveId` (NIST_P256, NIST_P384, NIST_P521) and fail when the curve is missing or undocumented. A denied key get renders the key inventory partial: warn when some keys were read, manual when none were.
- Control 16: a bastion whose `clientCidrBlockAllowList` contains `0.0.0.0/0` or `::/0` and whose `maxSessionTtlInSeconds` exceeds 3 hours fails; either condition alone warns.
- Control 14: `SecurityRule.isValid` is read into the NSG evidence (count of rules with `isValid=false`, flag on each permissive rule).
- `OCI-LOG-04` (audit event visibility) is supporting evidence for control 11, not a numbered control, so it carries no framework mappings.
- Controls 6, 12, 13, 14, 15, 16, 18, 20, 22, 23: the list APIs have no subtree parameter, so resources are listed per accessible compartment up to `max_compartments`.
- Control 20: `BucketSummary` omits `publicAccessType`, so each bucket is fetched with `GetBucket` up to `max_buckets`.
- Control 16: `BastionSummary` omits TTL and CIDR fields, so each bastion is fetched with `GetBastion`.
- Control 21: `timeExpires` is present on every PAR by API contract; "no expiration" cannot occur and long-lived PARs (more than 30 days out) warn instead.
- Output formats: SARIF and the JSON/CSV/HTML CLI outputs are out of scope; findings are JSON in `analysis/findings.json`.

### Deferred

- Control 24 budgets and alert rules (`oci budgets budget budget list`, `oci budgets budget alert-rule list`).
- Control 25 OS Management patching: the current API reference index lists only OS Management Hub (`osmh`, `/20220901`); the legacy OS Management Service (`/20190801`) is no longer in the reference and should not be targeted.
- Auth modes: session token (`security_token_file`), instance principal, resource principal, delegation token.
- Unfolding controls 3-5 (OCI-IAM-03), 16-17 (OCI-GRD-04), 18-19 (OCI-GRD-05), and 20-21 (OCI-GRD-06) into one finding each; today each folded control is judged and reported as separate evidence buckets inside the shared finding.
