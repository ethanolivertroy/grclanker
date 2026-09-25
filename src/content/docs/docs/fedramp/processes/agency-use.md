---
title: Agency Use of FedRAMP Certified Cloud Services — FedRAMP Process
description: Official Consolidated Rules summary for the AGU FedRAMP process, including applicability and requirements.
---

> Generated from the official [FedRAMP/rules](https://github.com/FedRAMP/rules) GitHub repo.
> Source path: [`fedramp-consolidated-rules.json`](https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json) on `main` at blob `7d628b63fdd9`.
> Consolidated Rules version: `2026.07.02.02` · upstream `last_updated`: `2026-07-02`.
> Supporting narrative documentation is available from the official `FedRAMP/2026-markdown` repository.

# Agency Use of FedRAMP Certified Cloud Services

Short name: `AGU` · Process ID: `AGU` · Web slug: `agency-use`

Applies to: `both`
Status: `placeholder`


Official page: [https://www.fedramp.gov/2026/reference/agency-use/](https://www.fedramp.gov/2026/reference/agency-use/)

## Effective Status

- 20x: required · Consolidated Rules for 2026 · obtain 2026-07-04 · grace through 2026-07-04
- Rev5: required · Consolidated Rules for 2026 · obtain 2026-07-04 · grace through 2026-07-04
- Shared requirements: 20

## Purpose

The Agency Use rules summarize the many demands made on agencies by the FedRAMP Authorization Act and OMB Memorandum M-24-15 in a simple, clear, easy-to-follow set of FedRAMP-style rules. These rules align agency policies, authorization letters, machine-readable tools, secure configuration review, continuous monitoring, and communication with FedRAMP so certifications can be reused consistently across government.

## Rule Subsets

- `AGC` — General Agency Responsibilities: These rules apply to agencies based on the FedRAMP Authorization Act, OMB M-24-15, and related FedRAMP policies. · types: 20x, Rev5 · classes: A, B, C, D
- `SPN` — Agency Sponsored Certifications: These rules apply when an agency sponsors a FedRAMP Rev5 Certification after completing an agency authorization. · types: Rev5 · classes: B, C, D
- `USE` — Use of FedRAMP Certifications: These rules apply when agencies use FedRAMP Certifications to make agency authorization decisions. · types: 20x, Rev5 · classes: A, B, C, D

## Requirements and Recommendations

## BOTH

### `AGU-AGC-AIP` MUST — Agency Internal Policies

Agencies MUST maintain agency-wide policy that aligns with the requirements in OMB Memorandum M-24-15.

Terms: `Agency`

Affects: Agencies

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AGU-AGC-GRC` MUST — Governance, Risk, and Compliance Tools

Agencies MUST ensure that internal governance, risk, compliance, and inventory tools can produce and ingest machine-readable artifacts using formats identified by FedRAMP, including at least:

Checklist items:
- Open Security Controls Assessment Language (OSCAL)
- JSON

Terms: `Agency`, `Artifacts`, `Machine-Readable`

Affects: Agencies

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AGU-AGC-LIA` SHOULD — Agency Liaison Program

Agencies SHOULD assign at least 1 federal employee to be an active participant in the FedRAMP Agency Liaison program.

Terms: `Agency`

Affects: Agencies

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AGU-AGC-NAA` MUST — Notify FedRAMP After Authorization

Agencies MUST notify FedRAMP upon authorizing the use of a cloud service within the scope of FedRAMP, supplying at least the following information:

Checklist items:
- A copy of the agency's Authorization to Operate letter for the information system leveraging the cloud service, following agency policy and templates.
- All other supplemental information requested in the Submit an ATO Letter form by FedRAMP.

Terms: `Agency`

Affects: Agencies

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AGU-AGC-NAI` MUST — Notify Additional Information Requests

Agencies MUST notify FedRAMP after requesting any additional information or materials from a FedRAMP Certified cloud service offering beyond those required by FedRAMP.

Terms: `Agency`, `Cloud Service Offering`, `FedRAMP Certified`

Affects: Agencies

Note: Agencies are expected to notify FedRAMP under OMB Memorandum M-24-15 section IV (a).

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AGU-AGC-NAR` MUST NOT — No Additional Security Requirements

Agencies MUST NOT require additional information or materials from FedRAMP Certified cloud service offerings beyond those required by FedRAMP UNLESS the head of the agency or an authorized delegate determines there is a demonstrable need and notifies FedRAMP; this does not apply to seeking clarification or asking general questions about FedRAMP Certification Data.

Terms: `Agency`, `Certification Data`, `Cloud Service Offering`, `FedRAMP Certified`

Affects: Agencies

Note: This is related to the Presumption of Adequacy for a FedRAMP Certification and notification is mandated by OMB Memorandum M-24-15 section IV (a).

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AGU-AGC-SIN` SHOULD — Shared FedRAMP Inbox

Agencies SHOULD establish and maintain a dedicated shared FedRAMP agency inbox to serve as the official point of contact for communications between FedRAMP and the agency.

Terms: `Agency`

Affects: Agencies

Note: A shared FedRAMP agency inbox may follow an agency-specific format such as agency-fedramp@agency.gov.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AGU-AGC-TPP` MUST NOT — No Certification Type or Path Preferences

Agencies MUST NOT require cloud service offerings to obtain or maintain a specific FedRAMP Certification Type or FedRAMP Certification Path, UNLESS the head of the agency or an authorized delegate determines there is a demonstrable need and notifies FedRAMP.

Terms: `Agency`, `Certification Path`, `Certification Type`, `Cloud Service Offering`, `FedRAMP Certified`

Affects: Agencies

Note: This is related to the Presumption of Adequacy for a FedRAMP Certification and notification is mandated by OMB Memorandum M-24-15 section IV (a).

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AGU-AGC-WKG` SHOULD — FedRAMP Working Groups

Agencies SHOULD participate in FedRAMP working groups, communities of practice, and stakeholder engagements to supply feedback and align practices across government.

Terms: `Agency`

Affects: Agencies

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AGU-SPN-MRC` MUST — Most Recent Consolidated Rules

Agencies MUST follow the most recent FedRAMP Consolidated Rules when initiating agency-sponsored FedRAMP Certification.

Terms: `Agency`

Affects: Agencies

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AGU-USE-ABU` MUST — Authorization Before Use

Agencies MUST complete the Authorization to Operate process for federal information systems that use FedRAMP Certified cloud service offerings.

Terms: `Agency`, `Cloud Service Offering`, `FedRAMP Certified`

Affects: Agencies

Note: FedRAMP provides technical assistance to help agencies navigate this process.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AGU-USE-AFR` MUST — Accept FedRAMP Rules

Agencies MUST allow FedRAMP Certified cloud service offerings to follow FedRAMP rules.

Terms: `Agency`, `Cloud Service Offering`, `FedRAMP Certified`

Affects: Agencies

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AGU-USE-CLA` SHOULD NOT — Using FedRAMP Class A Certifications

Agencies SHOULD NOT authorize the use of a FedRAMP Class A Certified cloud service offering for more than 12 months UNLESS the cloud service offering is actively seeking a FedRAMP Class B, C, or D Certification.

Terms: `Agency`, `Cloud Service Offering`, `FedRAMP Certified`

Affects: Agencies

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AGU-USE-DSO` SHOULD — Designate Senior Official

Agencies SHOULD designate a federal senior information security official to review Ongoing Certification Reports and represent the agency at Quarterly Reviews for cloud service offerings included in agency information systems.

Terms: `Agency`, `Cloud Service Offering`, `Ongoing Certification`, `Quarterly Review`

Affects: Agencies

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AGU-USE-NFC` MUST — Notify FedRAMP of Monitoring Concerns

Agencies MUST notify FedRAMP if information presented in an Ongoing Certification Report, Quarterly Review, or other FedRAMP Certification Data causes significant concerns for the authorizing official that would likely result in rescission of their Authorization to Operate.

Terms: `Agency`, `Certification Data`, `FedRAMP Certification Report`, `Likely`, `Ongoing Certification`, `Ongoing Certification Report (OCR)`, `Quarterly Review`

Affects: Agencies

Note: Agencies are expected to notify FedRAMP under OMB Memorandum M-24-15 section IV (a).

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AGU-USE-NPC` SHOULD — Notify Provider of Concerns

Agencies SHOULD formally notify the cloud service provider if information presented in an Ongoing Certification Report, Quarterly Review, or other FedRAMP Certification Data causes significant concerns for the authorizing official that would likely result in rescission of their Authorization to Operate.

Terms: `Agency`, `Certification Data`, `FedRAMP Certification Report`, `Likely`, `Ongoing Certification`, `Ongoing Certification Report (OCR)`, `Provider`, `Quarterly Review`

Affects: Agencies

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AGU-USE-RCF` MUST — Resolve Certification Package Conflicts

Agencies MUST collaborate with FedRAMP when discrepancies or conflicts arise between agency-specific security determinations and the FedRAMP Certification Package.

Terms: `Agency`, `Certification Package`

Affects: Agencies

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AGU-USE-RIR` SHOULD — Review All Information Resources

Agencies SHOULD consider third-party information resources used by the cloud service offering during initial and ongoing authorization activities.

Terms: `Agency`, `Cloud Service Offering`, `Information Resource`, `Third-Party Information Resource`

Affects: Agencies

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AGU-USE-ROR` SHOULD — Review Ongoing Certification Reports

Agencies SHOULD review each Ongoing Certification Report to understand how changes to the cloud service offering may impact the risk tolerance documented in the agency Authorization to Operate for the federal information system that includes the cloud service offering in its boundary.

Terms: `Agency`, `Cloud Service Offering`, `FedRAMP Certification Report`, `Ongoing Certification`, `Ongoing Certification Report (OCR)`

Affects: Agencies

Note: This agency review supports agency responsibilities under 44 USC § 35, OMB Circular A-130, FIPS-200, and OMB Memorandum M-24-15.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `AGU-USE-RSG` MUST — Review Secure Configuration Guides

Agencies MUST review the Secure Configuration Guides supplied by Providers and configure relevant security settings.

Terms: `Agency`, `Provider`

Affects: Agencies

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.
