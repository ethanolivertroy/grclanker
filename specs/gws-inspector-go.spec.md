---
slug: "gws-inspector-go"
name: "Google Workspace Inspector"
vendor: "Google"
category: "identity-access-management"
language: "go"
status: "spec-only"
version: "1.0"
last_updated: "2026-03-29"
source_repo: "https://github.com/hackIDLE/gws-inspector-go"
---

# gws-inspector-go — Architecture Specification

## Overview

Go implementation of gws-inspector — a multi-framework compliance audit tool for Google Workspace. This is a port of the Python `gws-inspector` package, providing a single-binary distribution with no runtime dependencies.

## Reference Implementation

The Python implementation is the source of truth: [github.com/ethanolivertroy/gws-inspector](https://github.com/ethanolivertroy/gws-inspector)

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
│   └── client.go               # GWSClient — wraps multiple Google API services
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

Identical to the Python implementation — see the Python repo's plan for the full control-to-framework matrix.

## CLI Interface

```bash
gws-inspector -c credentials.json -a admin@example.com -d example.com
gws-inspector -c credentials.json -a admin@example.com -d example.com --frameworks fedramp,cmmc
```

Flags:
- `-c, --credentials` — service account JSON or OAuth client secrets
- `-a, --admin-email` — admin email for delegation
- `-d, --domain` — Google Workspace domain
- `--oauth` — use OAuth flow
- `--frameworks` — comma-separated framework list
- `-o, --output-dir` — custom output dir
- `-V, --version`

Environment variables: `GWS_CREDENTIALS_FILE`, `GWS_ADMIN_EMAIL`, `GWS_DOMAIN`

## Build

```bash
go build -o gws-inspector ./cmd/gws-inspector
```

## Status

**Not yet implemented.** This repo contains only this specification. The Python implementation should be used as the reference for porting.
