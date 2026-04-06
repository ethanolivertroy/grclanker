---
slug: "snowflake-sec-inspector"
name: "Snowflake Security Inspector"
vendor: "Snowflake"
category: "cloud-infrastructure"
language: "go"
status: "spec-only"
version: "1.0"
last_updated: "2026-03-29"
source_repo: "https://github.com/hackIDLE/snowflake-sec-inspector"
---

# Snowflake Security Inspector

## 1. Overview

A security compliance inspection tool for **Snowflake** data platform environments. Audits identity and access management, network security, data protection policies, encryption configuration, and audit logging against enterprise security baselines and regulatory compliance frameworks.

Snowflake exposes its configuration through SQL queries against the `ACCOUNT_USAGE` and `INFORMATION_SCHEMA` schemas rather than a traditional REST API. This tool connects via the Snowflake Connector for Python (or Go driver) and executes read-only queries to evaluate security posture.

## 2. APIs & SDKs

### SQL-Based Configuration API

Snowflake security configuration is queried through system views and account-level metadata. The inspector requires the `ACCOUNTADMIN` role or a custom role with `IMPORTED PRIVILEGES` on the `SNOWFLAKE` shared database.

#### ACCOUNT_USAGE Schema (snowflake.account_usage)

| View / Table | Purpose |
|--------------|---------|
| `USERS` | All users, auth types, disabled status, last login, MFA status |
| `ROLES` | All roles including system and custom |
| `GRANTS_TO_USERS` | Role grants to users |
| `GRANTS_TO_ROLES` | Role-to-role grants (hierarchy) and privilege grants |
| `LOGIN_HISTORY` | Login attempts, success/failure, client type, IP |
| `ACCESS_HISTORY` | Object access patterns (reads/writes) |
| `QUERY_HISTORY` | All executed queries with metadata |
| `SESSIONS` | Active and historical sessions |
| `NETWORK_POLICIES` | Network policy definitions (IP allow/block lists) |
| `NETWORK_POLICY_REFERENCES` | Network policy assignments to accounts/users |
| `MASKING_POLICIES` | Dynamic data masking policy definitions |
| `MASKING_POLICY_REFERENCES` | Masking policy assignments to columns |
| `ROW_ACCESS_POLICIES` | Row-level security policy definitions |
| `ROW_ACCESS_POLICY_REFERENCES` | Row access policy assignments to tables |
| `WAREHOUSES` | Warehouse configurations |
| `DATABASES` | Database metadata and configurations |
| `STAGES` | Stage definitions (internal/external) |
| `STORAGE_INTEGRATIONS` | External storage integration configs |
| `POLICY_REFERENCES` | Unified view of all policy assignments |

#### INFORMATION_SCHEMA Queries

| Query Target | Purpose |
|--------------|---------|
| `SHOW PARAMETERS IN ACCOUNT` | Account-level parameter settings |
| `SHOW NETWORK POLICIES` | Active network policies |
| `SHOW INTEGRATIONS` | Security, storage, API integrations |
| `SHOW SHARES` | Data sharing configurations |
| `SHOW REPLICATION ACCOUNTS` | Replication/failover config |
| `SYSTEM$ALLOWLIST()` | PrivateLink allowlist |

### Rate Limits & Latency

- `ACCOUNT_USAGE` views have up to 45-minute latency for recent changes
- `INFORMATION_SCHEMA` provides real-time data but limited history
- No API rate limits per se, but concurrent query limits apply per warehouse
- Use `X-SMALL` warehouse to minimize compute cost

### SDKs & Tools

| Tool | Type | Notes |
|------|------|-------|
| `snowflake-connector-python` | Official Python SDK | Full SQL + metadata access |
| `gosnowflake` | Official Go driver | database/sql compatible |
| SnowSQL | Official CLI | Interactive/batch SQL execution |
| `snowflake-sqlalchemy` | Official SQLAlchemy dialect | ORM-style access |

## 3. Authentication

### Key Pair Authentication (Recommended)

- RSA key pair (2048-bit minimum, 4096 recommended)
- Private key stored locally, public key registered with Snowflake user
- No password transmitted; most secure for automation
- Supports encrypted private keys with passphrase

### Username/Password + MFA

- Basic authentication with optional TOTP MFA
- Not recommended for automated tools
- MFA prompt blocks non-interactive execution

### OAuth 2.0

- External OAuth (Azure AD, Okta, etc.) or Snowflake OAuth
- Requires OAuth integration configuration in Snowflake
- Access token passed as bearer token

### SSO/SAML

- Federated authentication through IdP
- Browser-based flow, not suitable for headless inspection

### Configuration

```
SNOWFLAKE_ACCOUNT=<account_identifier>       # e.g., xy12345.us-east-1
SNOWFLAKE_USER=<username>
SNOWFLAKE_PRIVATE_KEY_PATH=<path/to/rsa_key.p8>
SNOWFLAKE_PRIVATE_KEY_PASSPHRASE=<passphrase>  # if key is encrypted
SNOWFLAKE_ROLE=ACCOUNTADMIN                     # or custom role
SNOWFLAKE_WAREHOUSE=SECURITY_AUDIT_WH           # X-SMALL recommended
SNOWFLAKE_DATABASE=SNOWFLAKE                     # for ACCOUNT_USAGE
```

## 4. Security Controls

| # | Control | Query Source | Severity |
|---|---------|-------------|----------|
| 1 | Network policy configured and applied to account | `SHOW NETWORK POLICIES` + `NETWORK_POLICY_REFERENCES` | Critical |
| 2 | Network policy IP allowlist is restrictive (not 0.0.0.0/0) | `NETWORK_POLICIES` → `allowed_ip_list` | Critical |
| 3 | MFA enforced for all human users | `USERS` → `ext_authn_duo`, `HAS_MFA` | Critical |
| 4 | Password policy meets complexity requirements | `SHOW PARAMETERS` → `PASSWORD_POLICY` objects | High |
| 5 | Key pair authentication used for service accounts | `USERS` → `has_rsa_public_key` for service users | High |
| 6 | SSO/SAML integration configured | `SHOW INTEGRATIONS` → type `SAML2` | High |
| 7 | Role hierarchy follows least privilege | `GRANTS_TO_ROLES` → graph analysis | Critical |
| 8 | ACCOUNTADMIN role has minimal members | `GRANTS_TO_USERS` → role = `ACCOUNTADMIN` | Critical |
| 9 | ACCOUNTADMIN not used for routine queries | `QUERY_HISTORY` → role analysis | High |
| 10 | RBAC: No direct object grants to users (use roles) | `GRANTS_TO_USERS` vs `GRANTS_TO_ROLES` | Medium |
| 11 | Failed login monitoring (excessive failures) | `LOGIN_HISTORY` → `IS_SUCCESS = 'NO'` aggregation | High |
| 12 | Stale users disabled (no login > 90 days) | `USERS` → `LAST_SUCCESS_LOGIN` | Medium |
| 13 | Query history retention configured | `SHOW PARAMETERS` → `DATA_RETENTION_TIME_IN_DAYS` | Medium |
| 14 | Dynamic data masking policies applied to sensitive columns | `MASKING_POLICY_REFERENCES` | High |
| 15 | Row access policies applied to sensitive tables | `ROW_ACCESS_POLICY_REFERENCES` | High |
| 16 | Object-level grants audited (no PUBLIC grants on sensitive objects) | `GRANTS_TO_ROLES` → role = `PUBLIC` | High |
| 17 | `REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION` enabled | `SHOW PARAMETERS IN ACCOUNT` | High |
| 18 | `PREVENT_UNLOAD_TO_INTERNAL_STAGES` or stage restrictions | `SHOW PARAMETERS IN ACCOUNT` | Medium |
| 19 | Time Travel retention ≥ 1 day for critical databases | `DATABASES` → `retention_time` | Medium |
| 20 | Tri-Secret Secure (customer-managed key + Snowflake key) | Account-level encryption config | High |
| 21 | Customer-managed keys (CMK) configured via AWS KMS / Azure Key Vault | `SYSTEM$GET_SNOWFLAKE_PLATFORM_INFO()` | High |
| 22 | Data sharing: outbound shares reviewed | `SHOW SHARES` → `kind = 'OUTBOUND'` | Medium |
| 23 | External functions and API integrations reviewed | `SHOW INTEGRATIONS` → type `API` | Medium |
| 24 | Warehouse auto-suspend configured (cost + session control) | `WAREHOUSES` → `auto_suspend` | Low |
| 25 | Session policies configured (timeout, idle) | `SHOW PARAMETERS` → `SESSION_POLICY` | Medium |

## 5. Compliance Framework Mappings

| Control | FedRAMP | CMMC | SOC 2 | CIS | PCI-DSS | STIG | IRAP | ISMAP |
|---------|---------|------|-------|-----|---------|------|------|-------|
| 1. Network policy configured | SC-7 | SC.L2-3.13.1 | CC6.6 | 4.1 | 1.3.1 | SRG-APP-000383 | ISM-1284 | 10.2.1 |
| 2. IP allowlist restrictive | SC-7(5) | SC.L2-3.13.6 | CC6.6 | 4.4 | 1.3.2 | SRG-APP-000383 | ISM-1284 | 10.2.2 |
| 3. MFA enforced | IA-2(1) | IA.L2-3.5.3 | CC6.1 | 4.5 | 8.3.2 | SRG-APP-000149 | ISM-1401 | 8.2.2 |
| 4. Password complexity | IA-5(1) | IA.L2-3.5.7 | CC6.1 | 5.1 | 8.2.3 | SRG-APP-000164 | ISM-0421 | 8.2.3 |
| 5. Key pair for service accounts | IA-5(2) | IA.L2-3.5.10 | CC6.1 | 4.6 | 8.6.1 | SRG-APP-000177 | ISM-1557 | 8.2.4 |
| 6. SSO/SAML configured | IA-2(12) | IA.L2-3.5.1 | CC6.1 | 4.1 | 8.3.1 | SRG-APP-000148 | ISM-1557 | 8.2.1 |
| 7. Least privilege roles | AC-6(1) | AC.L2-3.1.5 | CC6.3 | 6.1 | 7.1.1 | SRG-APP-000340 | ISM-1508 | 8.1.2 |
| 8. ACCOUNTADMIN minimal | AC-6(5) | AC.L2-3.1.5 | CC6.3 | 6.2 | 7.1.2 | SRG-APP-000340 | ISM-1508 | 8.1.3 |
| 9. ACCOUNTADMIN not routine | AC-6(2) | AC.L2-3.1.6 | CC6.3 | 6.2 | 7.1.2 | SRG-APP-000343 | ISM-1508 | 8.1.3 |
| 10. No direct user grants | AC-6 | AC.L2-3.1.1 | CC6.3 | 6.1 | 7.1.1 | SRG-APP-000033 | ISM-1508 | 8.1.1 |
| 11. Failed login monitoring | SI-4 | AU.L2-3.3.1 | CC7.2 | 8.5 | 10.2.4 | SRG-APP-000095 | ISM-0580 | 12.1.1 |
| 12. Stale users disabled | AC-2(3) | AC.L2-3.1.1 | CC6.2 | 4.2 | 8.1.4 | SRG-APP-000025 | ISM-1631 | 8.1.4 |
| 13. Query history retention | AU-11 | AU.L2-3.3.1 | CC7.2 | 8.3 | 10.7 | SRG-APP-000515 | ISM-0859 | 12.1.2 |
| 14. Data masking policies | SC-28 | SC.L2-3.13.16 | CC6.1 | 14.7 | 3.4 | SRG-APP-000231 | ISM-0457 | 10.1.2 |
| 15. Row access policies | AC-3 | AC.L2-3.1.2 | CC6.1 | 14.6 | 7.1.1 | SRG-APP-000033 | ISM-0508 | 8.1.1 |
| 16. No PUBLIC grants | AC-6 | AC.L2-3.1.1 | CC6.3 | 6.1 | 7.1.1 | SRG-APP-000033 | ISM-1508 | 8.1.1 |
| 17. Storage integration required | AC-3 | AC.L2-3.1.2 | CC6.1 | 14.2 | 3.4.1 | SRG-APP-000033 | ISM-1284 | 8.1.1 |
| 18. Stage unload restricted | AC-4 | AC.L2-3.1.3 | CC6.6 | 14.2 | 3.4.1 | SRG-APP-000039 | ISM-1284 | 8.1.3 |
| 19. Time Travel retention | CP-9 | RE.L2-3.8.9 | CC6.5 | 3.1 | 3.1 | SRG-APP-000504 | ISM-1515 | 7.1.1 |
| 20. Tri-Secret Secure | SC-12(1) | SC.L2-3.13.10 | CC6.7 | 14.4 | 3.5.2 | SRG-APP-000514 | ISM-0487 | 10.1.1 |
| 21. Customer-managed keys | SC-12(1) | SC.L2-3.13.10 | CC6.7 | 14.4 | 3.5.2 | SRG-APP-000514 | ISM-0487 | 10.1.1 |
| 22. Outbound shares reviewed | AC-4 | AC.L2-3.1.3 | CC6.6 | 13.4 | 7.1.2 | SRG-APP-000039 | ISM-1284 | 8.1.3 |
| 23. External integrations reviewed | CM-7 | CM.L2-3.4.7 | CC6.6 | 13.5 | 2.2.2 | SRG-APP-000141 | ISM-1284 | 6.1.1 |
| 24. Warehouse auto-suspend | AC-12 | AC.L2-3.1.10 | CC6.1 | 5.6 | 8.1.8 | SRG-APP-000295 | ISM-1164 | 8.3.1 |
| 25. Session policies | AC-12 | AC.L2-3.1.11 | CC6.1 | 5.6 | 8.1.8 | SRG-APP-000295 | ISM-1164 | 8.3.1 |

## 6. Existing Tools

| Tool | Type | Notes |
|------|------|-------|
| Snowflake Security Dashboard | Built-in (Snowsight) | Manual review, limited automation |
| Snowflake Trust Center | Built-in | CIS benchmark scanner (Enterprise+ only) |
| Prowler | Open source | Has Snowflake provider (limited checks) |
| ScoutSuite | Open source | No Snowflake provider |
| Steampipe + Snowflake plugin | Open source | SQL-based queries against Snowflake config |
| Lacework / Wiz / Orca | Commercial CSPM | Snowflake integration varies |
| dbt + custom tests | Open source framework | Can model security checks but not purpose-built |

## 7. Architecture

```
snowflake-sec-inspector/
├── cmd/
│   └── snowflake-sec-inspector/
│       └── main.go                     # Entry point, CLI parsing
├── internal/
│   ├── auth/
│   │   ├── keypair.go                  # RSA key pair authentication
│   │   ├── password.go                 # Username/password auth
│   │   └── config.go                   # Credential loading, validation
│   ├── client/
│   │   ├── snowflake.go                # Connection management, query execution
│   │   ├── account_usage.go            # ACCOUNT_USAGE view queries
│   │   ├── information_schema.go       # INFORMATION_SCHEMA queries
│   │   ├── show_commands.go            # SHOW PARAMETERS/POLICIES/INTEGRATIONS
│   │   └── system_functions.go         # SYSTEM$ function calls
│   ├── analyzers/
│   │   ├── analyzer.go                 # Analyzer interface definition
│   │   ├── network.go                  # Controls 1, 2
│   │   ├── authentication.go           # Controls 3, 4, 5, 6
│   │   ├── access_control.go           # Controls 7, 8, 9, 10, 16
│   │   ├── monitoring.go              # Controls 11, 12, 13
│   │   ├── data_protection.go          # Controls 14, 15, 17, 18
│   │   ├── encryption.go              # Controls 20, 21
│   │   ├── data_governance.go          # Controls 19, 22, 23
│   │   └── session_management.go       # Controls 24, 25
│   ├── models/
│   │   ├── finding.go                  # Security finding with severity, mapping
│   │   ├── compliance.go               # Framework mapping definitions
│   │   ├── account.go                  # Account config structs
│   │   └── grants.go                   # Role/grant graph model
│   └── reporters/
│       ├── reporter.go                 # Reporter interface
│       ├── json.go                     # JSON output
│       ├── csv.go                      # CSV output
│       ├── html.go                     # HTML dashboard report
│       └── sarif.go                    # SARIF for CI/CD integration
├── queries/
│   ├── account_usage.sql               # Reusable SQL query templates
│   ├── parameters.sql                  # Account parameter queries
│   └── grants.sql                      # Grant/role hierarchy queries
├── pkg/
│   └── version/
│       └── version.go                  # Build version info
├── go.mod
├── go.sum
├── Makefile
├── Dockerfile
├── spec.md
└── README.md
```

## 8. CLI Interface

```
snowflake-sec-inspector [flags]

Flags:
  --account string          Snowflake account identifier (or SNOWFLAKE_ACCOUNT env)
  --user string             Snowflake username (or SNOWFLAKE_USER env)
  --private-key string      Path to RSA private key file (or SNOWFLAKE_PRIVATE_KEY_PATH env)
  --passphrase string       Private key passphrase (or SNOWFLAKE_PRIVATE_KEY_PASSPHRASE env)
  --password string         Password for username/password auth (or SNOWFLAKE_PASSWORD env)
  --role string             Snowflake role (default: ACCOUNTADMIN)
  --warehouse string        Warehouse for queries (default: COMPUTE_WH)
  --controls string         Comma-separated control IDs to run (default: all)
  --skip-controls string    Comma-separated control IDs to skip
  --severity string         Minimum severity: critical,high,medium,low (default: low)
  --format string           Output format: json,csv,html,sarif (default: json)
  --output string           Output file path (default: stdout)
  --stale-user-days int     Days since last login to flag as stale (default: 90)
  --failed-login-threshold int  Failed logins to trigger alert (default: 10)
  --timeout duration        Query timeout (default: 60s)
  --verbose                 Enable verbose/debug logging
  --version                 Print version and exit
  --help                    Show help
```

### Example Usage

```bash
# Full inspection using key pair auth
snowflake-sec-inspector --account xy12345.us-east-1 --user SECURITY_AUDITOR \
  --private-key ~/.ssh/snowflake_rsa_key.p8 --format json --output report.json

# Critical controls only, HTML report
snowflake-sec-inspector --severity critical --format html --output dashboard.html

# Specific controls with custom thresholds
snowflake-sec-inspector --controls 3,7,8,11,14 --stale-user-days 60 \
  --failed-login-threshold 5 --format json
```

## 9. Build Sequence

```bash
# 1. Initialize module
go mod init github.com/hackIDLE/snowflake-sec-inspector

# 2. Add Snowflake driver dependency
go get github.com/snowflakedb/gosnowflake

# 3. Define models and interfaces
#    - internal/models/finding.go (Finding struct, Severity enum)
#    - internal/models/compliance.go (framework mapping tables)
#    - internal/models/grants.go (role graph model)
#    - internal/analyzers/analyzer.go (Analyzer interface)
#    - internal/reporters/reporter.go (Reporter interface)

# 4. Implement authentication
#    - internal/auth/config.go (env/flag loading)
#    - internal/auth/keypair.go (RSA key loading, JWT generation)

# 5. Build SQL client layer
#    - internal/client/snowflake.go (connection, query runner)
#    - internal/client/account_usage.go (ACCOUNT_USAGE queries)
#    - internal/client/show_commands.go (SHOW commands)
#    - queries/*.sql (SQL templates)

# 6. Implement analyzers
#    - internal/analyzers/network.go
#    - internal/analyzers/authentication.go
#    - ... (all 8 analyzer files)

# 7. Implement reporters
#    - internal/reporters/json.go, csv.go, html.go, sarif.go

# 8. Wire CLI entry point
#    - cmd/snowflake-sec-inspector/main.go

# 9. Test and build
go test ./...
go build -ldflags "-X pkg/version.Version=$(git describe --tags)" \
  -o bin/snowflake-sec-inspector ./cmd/snowflake-sec-inspector/
```

## 10. Status

Not yet implemented. Spec only.
