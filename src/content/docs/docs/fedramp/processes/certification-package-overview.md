---
title: Certification Package Overview — FedRAMP Process
description: Official Consolidated Rules summary for the CPO FedRAMP process, including applicability and requirements.
---

> Generated from the official [FedRAMP/rules](https://github.com/FedRAMP/rules) GitHub repo.
> Source path: [`fedramp-consolidated-rules.json`](https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json) on `main` at blob `7d628b63fdd9`.
> Consolidated Rules version: `2026.07.02.02` · upstream `last_updated`: `2026-07-02`.
> Supporting narrative documentation is available from the official `FedRAMP/2026-markdown` repository.

# Certification Package Overview

Short name: `CPO` · Process ID: `CPO` · Web slug: `certification-package-overview`

Applies to: `both`, `20x`, `rev5`
Status: `stable`


Official page: [https://www.fedramp.gov/2026/reference/certification-package-overview/](https://www.fedramp.gov/2026/reference/certification-package-overview/)

## Effective Status

- 20x: required · Consolidated Rules for 2026 · obtain 2026-07-04 · grace through 2027-01-01
- Rev5: required · Consolidated Rules for 2026 · obtain 2027-01-01 · grace through 2027-01-01
- Shared requirements: 2

## Purpose

The Certification Package Overview rules outline the expectations for a simple overview of the cloud service offering that must be included within a FedRAMP Certification Package. This overview replaces the historically required base System Security Plan for FedRAMP Rev5 and is intended to provide a clear, concise, and consistent summary of the offering and the information included in the package to help customers understand the offering at a high level.

## Rule Subsets

- `CSF` — Rev5-Specific Provider Responsibilities: These rules apply to providers for FedRAMP Rev5 Certifications. · types: Rev5 · classes: A, B, C, D
- `CSO` — General Provider Responsibilities: These rules apply to providers for FedRAMP Certifications of any type. · types: 20x, Rev5 · classes: B, C, D
- `CSX` — 20x-Specific Provider Responsibilities: These rules apply to providers for FedRAMP 20x Certifications. · types: 20x · classes: A, B, C, D

## Requirements and Recommendations

## BOTH

### `CPO-CSO-MTD` MUST — Certification Package Overview Metadata

Providers MUST also include the following basic metadata in their Certification Package Overview:

Checklist items:
- Name, title, and contact information of official that is responsible and accountable for the FedRAMP Certification Package
- Version
- Date and time of last update
- Source of update

Terms: `Certification Package`, `Provider`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CPO-CSO-OVR` MUST — Overview of the Cloud Service Offering

Providers MUST supply a Certification Package Overview within their FedRAMP Certification Package, in both human-readable and JSON formats, that includes at least all of the information required by the following rules:

Checklist items:
- Certification Package Overview: CPO-CSO-MTD (Certification Package Overview Metadata)
- Certification Data Sharing: CDS-CSO-PUB (Public Information)
- Certification Data Sharing: CDS-CSO-SVC (Public Service List)
- Certification Data Sharing: CDS-CSO-IRP (Include Relevant Policies)
- Minimum Assessment Scope: MAS-CSO-IIR (Identify Information Resources)
- Minimum Assessment Scope: MAS-CSO-FLO (Information Flows and Security Categories)
- Minimum Assessment Scope: MAS-CSO-TPR (Third-Party Information Resources)
- Using Cryptographic Modules: CMU-CSO-CMD (Cryptographic Module Documentation)
- Independent Verification and Validation: IVV-CSO-ICP (Inclusion in Certification Package)

Terms: `Certification Class`, `Certification Data`, `Certification Package`, `Information Resource`, `Initial Incident Report (IIR)`, `Provider`, `Security Category`, `Third-Party Information Resource`, `Validation`, `Verification`

Affects: Providers

Note: For FedRAMP Rev5, the Certification Package Overview replaces the historically required System Security Plan (not including appendices).
This list of rules may not apply to all FedRAMP Certification Classes or Types - if a rule does not apply then the information is not required.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

## 20X

### `CPO-CSX-CPM` VARIES BY CLASS — Certification Package Maintenance for 20x

Varies by certification class:

- **Class A SHOULD:** Providers with 20x Class A Certifications SHOULD persistently maintain their FedRAMP Certification Package to ensure it is up to date and complete at least once every 3 months.
- **Class B MUST:** Providers with 20x Class B Certifications MUST persistently maintain their FedRAMP Certification Package to ensure it is up to date and complete at least once every month.
- **Class C MUST:** Providers with 20x Class C Certifications MUST persistently maintain their FedRAMP Certification Package to ensure it is up to date and complete at least once every 2 weeks.
- **Class D MUST:** Providers with 20x Class D Certifications MUST persistently maintain their FedRAMP Certification Package to ensure it is up to date and complete at least once every week.

Terms: `Certification Package`, `Persistently`, `Provider`

Affects: Providers

Note: Providers are expected to maintain their FedRAMP Certification Package using automation as changes occur to ensure they are never out of date.
This rule does not require or expect persistent human review of all materials in this cadence.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

## REV5

### `CPO-CSF-CPM` VARIES BY CLASS — Certification Package Maintenance for Rev5

Varies by certification class:

- **Class A SHOULD:** Providers with Rev5 Class A Certifications SHOULD persistently maintain their FedRAMP Certification Package to ensure it is up to date and complete at least once every year.
- **Class B MUST:** Providers with Rev5 Class B Certifications MUST persistently maintain their FedRAMP Certification Package to ensure it is up to date and complete at least once every year.
- **Class C MUST:** Providers with Rev5 Class C Certifications MUST persistently maintain their FedRAMP Certification Package to ensure it is up to date and complete at least once every year.
- **Class D MUST:** Providers with Rev5 Class D Certifications MUST persistently maintain their FedRAMP Certification Package to ensure it is up to date and complete at least once every six months.

Terms: `Certification Package`, `Persistently`, `Provider`, `Significant Change`, `Transformative Change`

Affects: Providers

Note: This maximum timeframe for Rev5 is the absolutely poorest worst case for horrible customer experience and is based on legacy FedRAMP Rev5 allowing providers to leave their packages unmaintained for up to a year. Rev5 providers should maintain their packages far more frequently than this requirement to ensure potential customers have access to up-to-date information, updating it at least after every transformative significant change.
FedRAMP 20x Certifications expect providers to maintain their FedRAMP Certification Packages as changes occur to ensure they are never out of date.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.
