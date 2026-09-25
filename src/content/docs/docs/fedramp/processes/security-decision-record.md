---
title: Security Decision Record — FedRAMP Process
description: Official Consolidated Rules summary for the SDR FedRAMP process, including applicability and requirements.
---

> Generated from the official [FedRAMP/rules](https://github.com/FedRAMP/rules) GitHub repo.
> Source path: [`fedramp-consolidated-rules.json`](https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json) on `main` at blob `7d628b63fdd9`.
> Consolidated Rules version: `2026.07.02.02` · upstream `last_updated`: `2026-07-02`.
> Supporting narrative documentation is available from the official `FedRAMP/2026-markdown` repository.

# Security Decision Record

Short name: `SDR` · Process ID: `SDR` · Web slug: `security-decision-record`

Applies to: `both`, `20x`, `rev5`
Status: `stable`


Official page: [https://www.fedramp.gov/2026/reference/security-decision-record/](https://www.fedramp.gov/2026/reference/security-decision-record/)

## Effective Status

- 20x: required · Consolidated Rules for 2026 · obtain 2026-07-04 · grace through 2027-01-01
- Rev5: required · Consolidated Rules for 2026 · obtain 2027-01-01 · grace through 2027-08-01
- Shared requirements: 2

## Purpose

The Security Decision Record replaced a traditional System Security Plan with a persistently maintained, verified, and validated record of the security decisions made by the cloud service provider over the lifecycle of their cloud service offering.

## Rule Subsets

- `CSF` — Rev5-Specific Provider Responsibilities: These rules apply to providers for FedRAMP Rev5 Certifications. · types: Rev5 · classes: B, C, D
- `CSO` — General Provider Responsibilities: These rules apply to providers for FedRAMP Certifications of any type. · types: 20x, Rev5 · classes: B, C, D
- `CSX` — 20x-Specific Provider Responsibilities: These rules apply to providers for FedRAMP 20x Certifications. · types: 20x · classes: B, C, D

## Requirements and Recommendations

## BOTH

### `SDR-CSO-FRR` MUST — FedRAMP Rules

Providers MUST supply a Security Decision Record, in both human-readable and JSON formats, that includes at least all of the following information for each applicable FedRAMP rule:

Checklist items:
- Explanation of how the rule is followed, or an explanation of the reason and resulting risk to customers for not following the rule.
- Verification that the implementation is appropriate for the rule, or that the reason for not implementing is accepted by a senior official.
- Validation that the implementation is in place and working as intended, or that the reason for not implementing is accepted by a senior official.
- Independent verification.
- Independent validation.
- Any responses or clarifications to the comments in the independent verification or validation.
- Rule-specific artifacts (if applicable).

Terms: `Artifacts`, `Provider`, `Security Decision Record (SDR)`, `Validation`, `Verification`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `SDR-CSO-MTD` MUST — Security Decision Record Metadata

Providers MUST also include the following basic metadata in their Security Decision Record:

Checklist items:
- Version
- Date and time of last update
- Source of update

Terms: `Provider`, `Security Decision Record (SDR)`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

## 20X

### `SDR-CSX-KMT` VARIES BY CLASS — Key Security Indicator Metrics

Varies by certification class:

- **Class A MAY:** Providers with 20x Class A Certifications MAY also include historical metrics in their Security Decision Record.
- **Class B MUST:** Providers with 20x Class B Certifications MUST also include historical metrics in their Security Decision Record, supplying at least the following information for each applicable Key Security Indicator:
- **Class C MUST:** Providers with 20x Class C Certifications MUST also include historical metrics in their Security Decision Record, supplying at least the following information for each applicable Key Security Indicator:
- **Class D MUST:** Providers with 20x Class D Certifications MUST significantly supersede the minimum requirements for lower Classes, with specifics to be set during the 20x Phase 4 Pilot.

Checklist items:
- Class B: Summary of each metric over the past 30 days
- Class B: Summary of metric up to the past year (where available)
- Class C: Summary of each metric over the past 30 days
- Class C: Summary of metric up to the past year (where available)
- Class C: All daily metric data up to the past year (where available)

Terms: `Provider`, `Security Decision Record (SDR)`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `SDR-CSX-KSI` MUST — Key Security Indicators

Providers MUST also include short and simple high-level summaries of at least the following for each applicable Key Security Indicator:

Checklist items:
- Explanation of measures (and their objectives) that demonstrate the Key Security Indicator, or an explanation of the reason and resulting risk to customers for not having measures available for that Key Security Indicator.
- Explanation of the cycle for any measures that are implemented persistently (if applicable).
- Verification that the measures demonstrate the Key Security Indicator, or that the reason for not having them is accepted.
- Verification that the automation in place is accurate and sufficient to demonstrate appropriate measures for the Key Security Indicator, or that automation is not necessary for each measure.
- Validation that the measures are accurately produced and are in place and working as intended, or that the reason for not having them is valid.

Terms: `Persistently`, `Provider`, `Validation`, `Verification`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

## REV5

### `SDR-CSF-CTF` MUST — Rev5 Controls

Providers MUST also include short and simple high-level summaries of at least the following for each applicable Rev5 Control:

Checklist items:
- Any organization-defined parameter values.
- Implementation status, one of Implemented, Partially Implemented, Planned, Alternative Implementation, or Not Applicable.
- The mechanisms or activities that address the control, including inheritance from another cloud service offering if applicable.
- The verification that is in place to ensure the implementation is appropriate for the control.
- The validation that is in place to ensure the implementation is working as intended.
- Independent verification.
- Independent validation.
- Any responses or clarifications to the comments in the independent verification or validation.
- Control-specific artifacts (if applicable).

Terms: `Artifacts`, `Cloud Service Offering`, `Provider`, `Validation`, `Verification`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.
