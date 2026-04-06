---
name: crypto-validation
description: Validate cryptographic module FIPS compliance and check for known vulnerabilities. Use when assessing whether an organization's cryptographic implementations meet federal validation requirements (FIPS 140-2/140-3, NIST SC-13, FedRAMP cryptographic module guidance).
---

# Cryptographic Module Validation

## When to Use

- User asks about FIPS validation status of a crypto module or vendor
- User needs to verify cryptographic compliance for FedRAMP/CMMC/federal systems
- User asks about the security of a specific cryptographic library (OpenSSL, BoringSSL, etc.)
- User needs to check if crypto modules have known exploited vulnerabilities

## Workflow

1. **Search active modules** — Use `cmvp_search_modules` with vendor/module name
2. **Check historical** — If not found active, use `cmvp_search_historical` for expired/revoked certs
3. **Check pipeline** — Use `cmvp_search_in_process` for modules awaiting validation
4. **Cross-reference vulnerabilities** — Use `kevs_search` with the vendor/product
5. **Score exploit risk** — Use `kevs_get_epss` for any CVEs found
6. **Map to controls** — Reference NIST SP 800-53 SC-13 (Cryptographic Protection)

## Key Controls

- **NIST SC-13**: Cryptographic Protection — requires FIPS-validated cryptography
- **NIST SC-12**: Cryptographic Key Establishment and Management
- **FedRAMP**: References NIST SP 800-175B for crypto module requirements
- **CMMC**: SC.L2-3.13.11 — Employ FIPS-validated cryptography

## Output Should Include

- Certificate number(s) and validation status
- FIPS standard (140-2 vs 140-3) and overall security level
- Sunset/expiration dates
- Any KEV entries for the vendor/product
- EPSS scores for discovered CVEs
- Gap assessment against SC-13 requirements
