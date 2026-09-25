---
title: Marketplace Listing — FedRAMP Process
description: Official Consolidated Rules summary for the MKT FedRAMP process, including applicability and requirements.
---

> Generated from the official [FedRAMP/rules](https://github.com/FedRAMP/rules) GitHub repo.
> Source path: [`fedramp-consolidated-rules.json`](https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json) on `main` at blob `7d628b63fdd9`.
> Consolidated Rules version: `2026.07.02.02` · upstream `last_updated`: `2026-07-02`.
> Supporting narrative documentation is available from the official `FedRAMP/2026-markdown` repository.

# Marketplace Listing

Short name: `MKT` · Process ID: `MKT` · Web slug: `marketplace-listing`

Applies to: `both`
Status: `stable`


Official page: [https://www.fedramp.gov/2026/reference/marketplace-listing/](https://www.fedramp.gov/2026/reference/marketplace-listing/)

## Effective Status

- 20x: required · Consolidated Rules for 2026 · obtain 2026-07-04 · grace through 2026-07-04
- Rev5: required · Consolidated Rules for 2026 · obtain 2026-07-04 · grace through 2026-07-04
- Shared requirements: 12

## Purpose

The Marketplace Listing rules define how FedRAMP decides which cloud service offerings, assessors, and advisors may be listed in the FedRAMP Marketplace. These rules help agencies and other customers rely on the Marketplace as a consistent source of eligible services and supporting organizations, while requiring listed organizations to supply accurate, accessible, and machine-readable information.

## Rule Subsets

- `CAS` — General Advisor Responsibilities: These rules apply to consulting and advisory services seeking a listing in the FedRAMP Marketplace.
- `CSO` — General Provider Responsibilities: These rules apply to providers seeking a listing in the FedRAMP Marketplace. · types: 20x, Rev5 · classes: A, B, C, D
- `FRP` — FedRAMP Responsibilities: These rules apply to FedRAMP activities related to the FedRAMP Marketplace. · types: 20x, Rev5 · classes: A, B, C, D
- `IAS` — General Assessor Responsibilities: These rules apply to independent assessment services seeking a listing in the FedRAMP Marketplace.
- `IIP` — Provider Responsibilities for Initial Implementation Phase Listings: FedRAMP allows cloud service providers that are actively preparing to obtain a FedRAMP Certification to apply for listing in the FedRAMP Marketplace. All cloud service providers must obtain a Initial Implementation Phase Marketplace Listing before they can apply for FedRAMP Certification. These rules apply to providers seeking a Initial Implementation Phase listing in the FedRAMP Marketplace. · types: 20x, Rev5

## Requirements and Recommendations

## BOTH

### `MKT-CAS-LRQ` MUST — Listing Requests for Advisors

Advisors MUST complete the Advisor Listing Request Form to request listing in the FedRAMP Marketplace.

Terms: `Advisor`

Affects: Advisors

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `MKT-CAS-RFR` MUST — Advisor Responses to FedRAMP

Advisors MUST reply to all requests from @fedramp.gov or @gsa.gov email addresses sent to the contact information provided in their advisor listing within 5 business days.

Terms: `Advisor`

Affects: Advisors

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `MKT-CAS-WEB` MUST — Website Requirements for Advisors

Advisors MUST have an appropriate web site that publicly supplies at least the following information in consistent machine-readable and human-readable formats:

Checklist items:
- General description of the consulting or advisory service
- Contact information
- Types of consulting or advisory services offered
- Optional: Positive attestations from customers or customer references

Terms: `Advisor`, `Machine-Readable`

Affects: Advisors

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `MKT-CSO-MLR` MUST — Marketplace Listing Requirements

Providers MUST address at least these FedRAMP rules to apply for a new FedRAMP Marketplace listing OR to request updates to an existing listing:

Checklist items:
- Certification Data Sharing: CDS-CSO-PUB (Public Information)

Terms: `Certification Data`, `Provider`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `MKT-CSO-PML` MUST — Provider Marketplace Listing Requests

Providers MUST notify FedRAMP using the FedRAMP Marketplace Providing Listing Request Form to request a listing in the FedRAMP Marketplace.

Terms: `Provider`

Affects: Providers

Note: FedRAMP does not accept applications for a FedRAMP Marketplace Listing via email!

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `MKT-FRP-SOF` MUST NOT — Scope of FedRAMP

FedRAMP MUST NOT list cloud service offerings in the Marketplace or perform any FedRAMP Certification activities unless it determines the cloud service offering is within the scope of FedRAMP.

Terms: `Cloud Service Offering`

Affects: FedRAMP

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `MKT-IAS-LRQ` MUST — Listing Requests for Assessors

Assessors MUST complete the Assessor Listing Request Form to request listing in the FedRAMP Marketplace.

Terms: `Assessor`

Affects: Assessors

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `MKT-IAS-OFR` MUST — Only FedRAMP Recognized Assessors

Assessors MUST obtain and maintain FedRAMP Recognition to be listed in the FedRAMP Marketplace.

Terms: `Assessor`, `FedRAMP Recognized`

Affects: Assessors

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `MKT-IAS-WEB` MUST — Website Requirements for Assessors

Assessors MUST have an appropriate web site that publicly supplies at least the following information in human-readable and JSON formats:

Checklist items:
- General description of the independent assessment service
- Contact information
- Types of independent services offered
- Optional: Positive attestations from customers or customer references

Terms: `Assessor`

Affects: Assessors

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `MKT-IIP-AGU` MUST — Agency Use Cases

Providers MUST demonstrate that a cloud service offering is intended for one of the following use cases:

Checklist items:
- Direct Use: The product will be used directly by agency customers for integration into a federal information system that falls within the scope of 44 USC § 3506 and will receive an agency Authorization to Operate.
- Indirect Use: The product will be included as a third-party information resource in other cloud service offerings that are directly used by agency customers.

Terms: `Agency`, `Cloud Service Offering`, `Information Resource`, `Provider`, `Third-Party Information Resource`

Affects: Providers

Note: FedRAMP will not list products or services that are outside the explicit statutory scope of FedRAMP; See MKT-FRP-SOF (Scope of FedRAMP).
Services used by private companies to meet other compliance requirements (such as CMMC) that do not also meet one of the above use cases are outside the scope of FedRAMP.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `MKT-IIP-DCP` MUST — Demonstrating Continuous Progress

Providers MUST demonstrate continuous progress towards a FedRAMP Certification, documented in their Trust Center or website and updated at least quarterly; progress is measured by the provider against documented goals and milestones.

Terms: `Provider`, `Trust Center`

Affects: Providers

Note: This is an opportunity for a business to showcase its goals and progress, and should be seen as a marketing and customer experience challenge instead of a compliance challenge.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `MKT-IIP-DLA` MUST — Deadline for Assessment

Providers MUST demonstrate that an assessment for a FedRAMP Certification Class B, C, or D has been scheduled within 2 years of initial listing in the Initial Implementation Phase.

Terms: `Certification Class`, `Provider`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.
