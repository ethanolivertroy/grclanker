---
title: Certification Data Sharing — FedRAMP Process
description: Official Consolidated Rules summary for the CDS FedRAMP process, including applicability and requirements.
---

> Generated from the official [FedRAMP/rules](https://github.com/FedRAMP/rules) GitHub repo.
> Source path: [`fedramp-consolidated-rules.json`](https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json) on `main` at blob `7d628b63fdd9`.
> Consolidated Rules version: `2026.07.02.02` · upstream `last_updated`: `2026-07-02`.
> Supporting narrative documentation is available from the official `FedRAMP/2026-markdown` repository.

# Certification Data Sharing

Short name: `CDS` · Process ID: `CDS` · Web slug: `certification-data-sharing`

Applies to: `both`, `rev5`
Status: `stable`


Official page: [https://www.fedramp.gov/2026/reference/certification-data-sharing/](https://www.fedramp.gov/2026/reference/certification-data-sharing/)

## Effective Status

- 20x: required · Consolidated Rules for 2026 · obtain 2026-07-04 · grace through 2027-01-01
- Rev5: required · Consolidated Rules for 2026 · obtain 2027-01-01 · grace through 2028-02-01
- Shared requirements: 20

## Purpose

The Certification Data Sharing rules allow providers to store and share FedRAMP Certification Data through the platform they choose as long as it follows FedRAMP rules for access, accuracy, and transparency. This helps customers and the public review consistent, current security and compliance information while recognizing that the information usually remains the provider's intellectual property and is not federal information.

## Rule Subsets

- `CSF` — Rev5-Specific Provider Responsibilities: These rules apply to providers for FedRAMP Rev5 Certifications. · types: Rev5 · classes: B, C, D
- `CSO` — General Provider Responsibilities: These rules apply to providers for FedRAMP Certifications of any type. · types: 20x, Rev5 · classes: B, C, D
- `TRC` — FedRAMP-Compatible Trust Centers: These rules apply to trust centers that are FedRAMP-compatible. · types: 20x, Rev5 · classes: B, C, D
- `UTC` — Using a Trust Center: These rules apply to providers that are using a FedRAMP-compatible trust center instead of USDA Connect; they DO NOT apply to providers using USDA Connect. · types: 20x, Rev5 · classes: B, C, D

## Requirements and Recommendations

## BOTH

### `CDS-CSO-AVR` VARIES BY CLASS — Availability Reporting

Varies by certification class:

- **Class A SHOULD:** Providers with Class A Certifications SHOULD maintain a web service, available to all necessary parties, that indicates current and historical availability of core services within the cloud service offering over at least the past 30 days, including availability incidents, in both human-readable and machine-readable formats; this service SHOULD be available even if the primary cloud service offering is unavailable.
- **Class B MUST:** Providers with Class B Certifications MUST maintain a web service, available to all necessary parties, that indicates current and historical availability of core services within the cloud service offering over at least the past 30 days, including availability incidents, in both human-readable and machine-readable formats; this service MUST be available even if the primary cloud service offering is unavailable.
- **Class C MUST:** Providers with Class C Certifications MUST maintain a web service, available to all necessary parties, that indicates current and historical availability of core services within the cloud service offering over at least the past 30 days, including availability incidents, in both human-readable and machine-readable formats; this service MUST be available even if the primary cloud service offering is unavailable.
- **Class D MUST:** Providers with Class D Certifications MUST maintain a web service, available to all necessary parties, that indicates current and historical availability of core services within the cloud service offering over at least the past 30 days, including availability incidents, in both human-readable and machine-readable formats; this service MUST be available even if the primary cloud service offering is unavailable.

Terms: `All Necessary Parties`, `Cloud Service Offering`, `Incident`, `Machine-Readable`, `Provider`

Affects: Providers

Note: This service may be separate from the trust center.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CDS-CSO-CBF` MUST — Consistency Between Formats

Providers MUST use automation to ensure information remains consistent between human-readable and machine-readable formats when FedRAMP Certification Data is provided in both formats.

Terms: `Certification Data`, `Machine-Readable`, `Provider`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CDS-CSO-FID` MUST — Always Include FedRAMP ID

Providers MUST always include the FedRAMP ID of the related cloud service offering in all FedRAMP Certification Data once assigned, including all reports, notifications, and other communication that results from FedRAMP rules.

Terms: `Certification Data`, `Cloud Service Offering`, `Provider`

Affects: Providers

Note: The FedRAMP ID is supplied by FedRAMP after a cloud service offering is registered to be listed on the FedRAMP Marketplace - providers will need to use a placeholder until the FedRAMP ID is assigned.
Many providers have multiple cloud service offerings or use internal names that don't align to public materials; using the FedRAMP ID ensures we can easily align the communication with a specific cloud service offering.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CDS-CSO-FRC` MUST — FedRAMP Certification Reports

Providers MUST include FedRAMP Certification Reports with their FedRAMP Certification Data without inappropriate modifications, and make such reports available within 2 weeks of receiving the materials from FedRAMP.

Terms: `Agency`, `Certification Data`, `Certification Path`, `Cloud Service Offering`, `Provider`

Affects: Providers

Structured timeframe: `2` weeks

Note: FedRAMP provides Certification Reports for all cloud service offerings following the Program Certification path as part of the initial and ongoing FedRAMP Certification process, and may provide Certification Reports for cloud service offerings following the Agency Certification path.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CDS-CSO-HAD` MUST — Historical FedRAMP Certification Data

Providers MUST supply snapshots of FedRAMP Certification Data aligned to Ongoing Certification Reports to all necessary parties; these snapshots MUST be available for the duration of FedRAMP Certification.

Terms: `All Necessary Parties`, `Certification Data`, `FedRAMP Certification Report`, `Ongoing Certification`, `Ongoing Certification Report (OCR)`, `Provider`

Affects: Providers

Note: Historical snapshots do not need to be reconstructed for periods before the provider's first Ongoing Certification Report, but should be maintained for all subsequent Ongoing Certification Reports.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CDS-CSO-IRP` MUST — Include Relevant Policies

Providers MUST supply all relevant policies and procedures in the FedRAMP Certification Data, including a human-readable and machine-readable reference that explains at least the following about each included policy and procedure:

Checklist items:
- Name of policy or procedure
- Name of file, document, web page, etc.
- Brief summary of policy or procedure
- Word count of document
- Current version
- Date of last update
- Related FedRAMP Practices (if applicable)

Terms: `Certification Data`, `FedRAMP Practices`, `Machine-Readable`, `Provider`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CDS-CSO-PSM` VARIES BY CLASS — Per-Service Certification Materials

Varies by certification class:

- **Class A MAY:** Providers with Class A Certifications MAY supply per-service FedRAMP Certification materials.
- **Class B MAY:** Providers with Class B Certifications MAY supply per-service FedRAMP Certification materials.
- **Class C MAY:** Providers with Class C Certifications MAY supply per-service FedRAMP Certification materials.
- **Class D MUST:** Providers with Class D Certifications MUST supply per-service FedRAMP Certification materials.

Terms: `Agency`, `Provider`

Affects: Providers

Note: Providers determine what they consider to be separate services, based on maximizing the customer experience for agencies who may only adopt some services and not others.
Providers are encouraged to provide a single comprehensive set of materials for all shared aspects of the service offering and only provide separate materials for unique aspects of each service to minimize the burden on providers and agencies.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CDS-CSO-PUB` MUST — Public Information

Providers MUST publicly share up-to-date information about the cloud service offering in both human-readable and JSON formats, including at least the following information that is available and applicable:

Checklist items:
- FedRAMP ID
- Service Model
- Deployment Model
- Business Category
- UEI Number
- Sales Contact Information
- Security Contact Information
- Product Website Link
- Link to Product Logo
- Overall Service Description
- Detailed list of specific services and their security categories (see CDS-CSO-SVC (Public Service List) (Service List))
- Link to Secure Configuration Guidance
- Overview of documentation supplied by the provider for the cloud service offering
- Link to Trust Center landing page that includes instructions on accessing information in the trust center
- Next Ongoing Certification Report date (see CCM-OCR-NRD (Next Report Date))
- Current FedRAMP Recognized independent assessment service

Terms: `Cloud Service Offering`, `FedRAMP Certification Report`, `FedRAMP Recognized`, `Ongoing Certification`, `Ongoing Certification Report (OCR)`, `Provider`, `Security Category`, `Trust Center`

Affects: Providers

Note: Generally, this information should be available on a public webpage or publicly shared in a FedRAMP-compatible trust center.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CDS-CSO-RIS` MUST — Responsible Information Sharing

Providers MUST provide sufficient information in FedRAMP Certification Data to support agency authorization decisions but SHOULD NOT include sensitive information that would likely enable a threat actor to gain unauthorized access, cause harm, disrupt operations, or otherwise have a negative adverse impact on the cloud service offering.

Terms: `Agency`, `Certification Data`, `Cloud Service Offering`, `Likely`, `Provider`

Affects: Providers

Note: This is not a license to exclude accurate risk information, but specifics that would likely lead to compromise should be abstracted. A breach of confidentiality with FedRAMP Certification Data should be anticipated by a secure cloud service provider.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CDS-CSO-RPS` MAY — Responsible Public Package Sharing

Providers MAY responsibly share some or all of the information in a FedRAMP Certification Package publicly or with other parties if the provider determines doing so will NOT likely have an adverse effect on the cloud service offering.

Terms: `Certification Package`, `Cloud Service Offering`, `Likely`, `Provider`, `Responsibly`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CDS-CSO-SVC` MUST — Public Service List

Providers MUST publicly share a detailed list of specific services and their security categories that are included in the cloud service offering using clear feature or service names that align with standard public marketing materials; this list MUST be complete enough for a potential customer to determine which services are and are not included in the FedRAMP Minimum Assessment Scope without requesting access to underlying FedRAMP Certification Data.

Terms: `Certification Data`, `Cloud Service Offering`, `Provider`, `Security Category`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CDS-CSO-UTC` MUST — Use Trust Centers

Providers MUST use a FedRAMP-compatible trust center to store and share FedRAMP Certification Data with all necessary parties.

Terms: `All Necessary Parties`, `Certification Data`, `Provider`, `Trust Center`

Affects: Providers

Note: Rules for FedRAMP-Compatible Trust Centers are explained in the Certification Data Sharing Rules under the FedRAMP-Compatible Trust Centers section (id: CDS-TRC).

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CDS-TRC-AAI` MUST — Agency Access Inventory

Trust centers MUST maintain an inventory and history of federal agency users or systems with access to FedRAMP Certification Data and MUST make this information available to FedRAMP upon request.

Terms: `Agency`, `Certification Data`, `Trust Center`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CDS-TRC-ACL` MUST — Access Logging

Trust centers MUST log access to FedRAMP Certification Data and store summaries of access for at least six months; such information, as it pertains to specific parties, SHOULD be made available upon request by those parties.

Terms: `Certification Data`, `Trust Center`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CDS-TRC-HMR` SHOULD — Human and Machine-Readable Certification Data

Trust centers SHOULD make FedRAMP Certification Data available to view and download in both human-readable and machine-readable formats.

Terms: `Certification Data`, `Machine-Readable`, `Trust Center`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CDS-TRC-PAC` MUST — Programmatic Access

Trust centers MUST provide documented programmatic access to all FedRAMP Certification Data, including programmatic access to human-readable materials.

Terms: `Certification Data`, `Trust Center`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CDS-TRC-SSM` SHOULD — Self-Service Access Management

Trust centers SHOULD include features that encourage all necessary parties to provision and manage access to FedRAMP Certification Data for their users and services directly.

Terms: `All Necessary Parties`, `Certification Data`, `Trust Center`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CDS-TRC-USH` MUST — Uninterrupted Sharing

Trust centers MUST share FedRAMP Certification Data with all necessary parties without interruption.

Terms: `All Necessary Parties`, `Certification Data`, `Trust Center`

Affects: Providers

Note: "Without interruption" means that parties should not have to request manual approval each time they need to access FedRAMP Certification Data or go through a complicated process. The preferred way of ensuring access without interruption is to use on-demand just-in-time access provisioning.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CDS-UTC-AAD` MUST — Agency Access Denial

Providers MUST notify FedRAMP within 5 business days of denying an agency access request for FedRAMP Certification Data.

Terms: `Agency`, `Certification Data`, `Provider`

Affects: Providers

Structured timeframe: `5` bizdays

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CDS-UTC-AGA` SHOULD — Agency Access

Providers SHOULD supply access to the FedRAMP Certification Package with agencies upon request.

Terms: `Agency`, `Certification Package`, `Provider`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

## REV5

### `CDS-CSF-TCM` MUST — Trust Center Migration

Providers MUST notify all necessary parties when migrating to a trust center and MUST provide information in their existing USDA Connect Community Portal secure folders explaining how to use the trust center to obtain FedRAMP Certification Data.

Terms: `All Necessary Parties`, `Certification Data`, `Provider`, `Trust Center`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.
