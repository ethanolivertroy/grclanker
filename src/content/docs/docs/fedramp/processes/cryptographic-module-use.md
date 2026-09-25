---
title: Cryptographic Module Use — FedRAMP Process
description: Official Consolidated Rules summary for the CMU FedRAMP process, including applicability and requirements.
---

> Generated from the official [FedRAMP/rules](https://github.com/FedRAMP/rules) GitHub repo.
> Source path: [`fedramp-consolidated-rules.json`](https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json) on `main` at blob `7d628b63fdd9`.
> Consolidated Rules version: `2026.07.02.02` · upstream `last_updated`: `2026-07-02`.
> Supporting narrative documentation is available from the official `FedRAMP/2026-markdown` repository.

# Cryptographic Module Use

Short name: `CMU` · Process ID: `CMU` · Web slug: `cryptographic-module-use`

Applies to: `both`
Status: `stable`


Official page: [https://www.fedramp.gov/2026/reference/cryptographic-module-use/](https://www.fedramp.gov/2026/reference/cryptographic-module-use/)

## Effective Status

- 20x: required · Consolidated Rules for 2026 · obtain 2026-07-04 · grace through 2027-01-01
- Rev5: required · Consolidated Rules for 2026 · obtain 2027-01-01 · grace through 2027-06-01
- Shared requirements: 3

## Purpose

The Cryptographic Module Use rules clarify how providers should select and use cryptographic modules. These rules allow risk-based decisions for some services while still encouraging validated cryptographic modules whenever they are technically feasible and reasonable.

## Rule Subsets

- `CSO` — Cloud Service Provider Responsibilities: These rules apply to providers for FedRAMP Certifications. · types: 20x, Rev5 · classes: B, C, D

## Requirements and Recommendations

## BOTH

### `CMU-CSO-CAT` SHOULD — Configuration of Agency Tenants

Providers SHOULD configure agency tenants by default to use cryptographic services that use cryptographic modules or update streams of cryptographic modules with active validations under the NIST Cryptographic Module Validation Program when such modules are available.

Terms: `Agency`, `Provider`, `Validation`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CMU-CSO-CMD` MUST — Cryptographic Module Documentation

Providers MUST document the cryptographic modules used in each service (or groups of services that use the same modules) where cryptographic services are used to protect federal customer data, including whether these modules are validated under the NIST Cryptographic Module Validation Program or are update streams of such modules.

Terms: `Federal Customer Data`, `Provider`, `Validation`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CMU-CSO-UVM` VARIES BY CLASS — Using Validated Cryptographic Modules

Varies by certification class:

- **Class A MAY:** Providers with Class A Certifications MAY use cryptographic modules or update streams of cryptographic modules with active validations under the NIST Cryptographic Module Validation Program when using cryptographic services to protect federal customer data.
- **Class B MAY:** Providers with Class B Certifications MAY use cryptographic modules or update streams of cryptographic modules with active validations under the NIST Cryptographic Module Validation Program when using cryptographic services to protect federal customer data.
- **Class C SHOULD:** Providers with Class C Certifications SHOULD use cryptographic modules or update streams of cryptographic modules with active validations under the NIST Cryptographic Module Validation Program when using cryptographic services to protect federal customer data.
- **Class D MUST:** Providers with Class D Certifications MUST use cryptographic modules or update streams of cryptographic modules with active validations under the NIST Cryptographic Module Validation Program when using cryptographic services to protect federal customer data.

Terms: `Federal Customer Data`, `Provider`, `Validation`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.
