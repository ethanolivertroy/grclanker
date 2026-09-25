---
title: Collaborative Continuous Monitoring — FedRAMP Process
description: Official Consolidated Rules summary for the CCM FedRAMP process, including applicability and requirements.
---

> Generated from the official [FedRAMP/rules](https://github.com/FedRAMP/rules) GitHub repo.
> Source path: [`fedramp-consolidated-rules.json`](https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json) on `main` at blob `7d628b63fdd9`.
> Consolidated Rules version: `2026.07.02.02` · upstream `last_updated`: `2026-07-02`.
> Supporting narrative documentation is available from the official `FedRAMP/2026-markdown` repository.

# Collaborative Continuous Monitoring

Short name: `CCM` · Process ID: `CCM` · Web slug: `collaborative-continuous-monitoring`

Applies to: `both`
Status: `stable`


Official page: [https://www.fedramp.gov/2026/reference/collaborative-continuous-monitoring/](https://www.fedramp.gov/2026/reference/collaborative-continuous-monitoring/)

## Effective Status

- 20x: required · Consolidated Rules for 2026 · obtain 2026-07-04 · grace through 2027-01-01
- Rev5: required · Consolidated Rules for 2026 · obtain 2027-01-01 · grace through 2027-10-01
- Shared requirements: 21

## Purpose

The Collaborative Continuous Monitoring rules help agencies use shared, current authorization information from providers as part of each agency's own Information Security Continuous Monitoring strategy. These rules reduce unnecessary manual burden by encouraging automated monitoring and review while allowing each agency to make its own risk-based decisions about ongoing authorization.

## Rule Subsets

- `AGM` — Agency Guidance: These rules for agencies apply to all agencies using a FedRAMP Certification. · types: 20x, Rev5 · classes: B, C, D
- `OCR` — Ongoing Certification Reports: These rules for Ongoing Certification Reports apply to providers with any type of FedRAMP Certification. · types: 20x, Rev5 · classes: B, C, D
- `QTR` — Quarterly Reviews: These rules for Quarterly Reviews apply to providers with any type of FedRAMP Certification. · types: 20x, Rev5 · classes: B, C, D

## Requirements and Recommendations

## BOTH

### `CCM-AGM-CSC` SHOULD — Consider Security Category

Agencies SHOULD consider the Security Category noted in their Authorization to Operate of the federal information system that includes the cloud service offering in its boundary and assign appropriate information security resources for reviewing Ongoing Certification Reports, attending Quarterly Reviews, and other ongoing FedRAMP Certification Data.

Terms: `Agency`, `Certification Data`, `Cloud Service Offering`, `Ongoing Certification`, `Quarterly Review`, `Security Category`

Affects: Agencies

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CCM-AGM-NAR` MUST NOT — No Additional Requirements

Agencies MUST NOT place additional security requirements on cloud service providers beyond those required by FedRAMP UNLESS the head of the agency or an authorized delegate makes a determination that there is a demonstrable need for such; this does not apply to seeking clarification or asking general questions about FedRAMP Certification Data.

Terms: `Agency`, `Certification Data`, `FedRAMP Certified`, `Provider`

Affects: Agencies

Note: This is a statutory requirement in 44 USC § 3613 (e) related to the Presumption of Adequacy for a FedRAMP Certification.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CCM-AGM-NFA` MUST — Notify FedRAMP After Requests

Agencies MUST notify FedRAMP after requesting any additional information or materials from a cloud service provider beyond those FedRAMP requires by sending an email to info@fedramp.gov.

Terms: `Agency`, `Provider`

Affects: Agencies

Note: Agencies are required to notify FedRAMP by OMB Memorandum M-24-15 section IV (a).

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CCM-AGM-ROR` MUST — Review Ongoing Reports

Agencies MUST review each Ongoing Certification Report to understand how changes to the cloud service offering may impact the previously agreed-upon risk tolerance documented in the agency's Authorization to Operate of a federal information system that includes the cloud service offering in its boundary.

Terms: `Agency`, `Cloud Service Offering`, `FedRAMP Certification Report`, `Ongoing Certification`, `Ongoing Certification Report (OCR)`

Affects: Agencies

Note: This is required by 44 USC § 35, OMB A-130, FIPS-200, and M-24-15.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CCM-OCR-AFS` MUST — Anonymized Feedback Summary

Providers MUST supply an anonymized and desensitized summary of the feedback, questions, and answers about each Ongoing Certification Report as an addendum to the Ongoing Certification Report OR in the next Ongoing Certification Report.

Terms: `Agency`, `FedRAMP Certification Report`, `Ongoing Certification`, `Ongoing Certification Report (OCR)`, `Provider`

Affects: Providers

Note: This is intended to encourage sharing of information and decrease the burden on the cloud service provider - providing this summary will reduce duplicate questions from agencies and ensure FedRAMP has access to this information. It is generally in the provider's interest to update this addendum frequently throughout the quarter.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CCM-OCR-AVL` MUST — Report Availability

Providers MUST supply an Ongoing Certification Report to all necessary parties every 3 months, covering the entire period since the previous summary, in a consistent format that is human readable; this report MUST include high-level summaries of at least the following information:

Checklist items:
- Changes to FedRAMP Certification Data
- Planned changes to FedRAMP Certification Data during at least the next 3 months
- Accepted vulnerabilities
- Transformative changes
- Updated recommendations or best practices for security, configuration, usage, or similar aspects of the cloud service offering
- A list of all agencies that are directly using the product
- FedRAMP Reportable Incidents or an attestation that no such incidents occurred
- Lessons learned and changes planned or made as a result of FedRAMP Reportable Incidents (if such occurred)

Terms: `Accepted Vulnerability`, `Agency`, `All Necessary Parties`, `Certification Data`, `Cloud Service Offering`, `FedRAMP Certification Report`, `FedRAMP Reportable Incident`, `Incident`, `Ongoing Certification`, `Ongoing Certification Report (OCR)`, `Provider`, `Transformative Change`, `Vulnerability`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CCM-OCR-FBM` MUST — Feedback Mechanism

Providers MUST supply an asynchronous mechanism for all necessary parties to provide feedback or ask questions about each Ongoing Certification Report.

Terms: `All Necessary Parties`, `FedRAMP Certification Report`, `Ongoing Certification`, `Ongoing Certification Report (OCR)`, `Provider`

Affects: Providers

Note: This could be email by default but providers are encouraged to consider something more interactive as appropriate.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CCM-OCR-LSI` MUST NOT — Limit Sensitive Information

Providers MUST NOT irresponsibly disclose sensitive information in an Ongoing Certification Report that would likely have an adverse effect on the cloud service offering.

Terms: `Cloud Service Offering`, `FedRAMP Certification Report`, `Likely`, `Ongoing Certification`, `Ongoing Certification Report (OCR)`, `Provider`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CCM-OCR-NRD` MUST — Next Report Date

Providers MUST supply the target date for their next Ongoing Certification Report with other public FedRAMP Certification Data.

Terms: `Certification Data`, `FedRAMP Certification Report`, `Ongoing Certification`, `Ongoing Certification Report (OCR)`, `Provider`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CCM-OCR-RPS` MAY — Responsible Public Certification Report Sharing

Providers MAY responsibly supply some or all of the information an Ongoing Certification Report to the public or other parties if the provider determines doing so will NOT likely have an adverse effect on the cloud service offering.

Terms: `Cloud Service Offering`, `FedRAMP Certification Report`, `Likely`, `Ongoing Certification`, `Ongoing Certification Report (OCR)`, `Provider`, `Responsibly`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CCM-OCR-SOR` SHOULD — Spread Out Reports

Providers SHOULD establish a regular 3 month cycle for Ongoing Certification Reports that is spread out from the beginning, middle, or end of each quarter.

Terms: `Agency`, `Ongoing Certification`, `Provider`, `Regularly`

Affects: Providers

Note: This recommendation is intended to discourage hundreds of cloud service providers from releasing their Ongoing Certification Reports during the first or last week of each quarter because that is the easiest way for a single provider to track this deliverable; the result would overwhelm agencies with many cloud services. Widely used cloud service providers are encouraged to work with their customers to identify ideal timeframes for this cycle.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CCM-QTR-ACT` SHOULD — Additional Content

Providers SHOULD supply additional information in Quarterly Reviews that the provider determines is of interest, use, or otherwise relevant to agencies.

Terms: `Agency`, `Provider`, `Quarterly Review`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CCM-QTR-MTG` VARIES BY CLASS — Quarterly Review Meeting

Varies by certification class:

- **Class A MAY:** Providers with Class A Certifications MAY host a synchronous Quarterly Review every 3 months, open to all necessary parties, to review aspects of the most recent Ongoing Certification Reports that the provider determines are of the most relevance to agencies.
- **Class B SHOULD:** Providers with Class B Certifications SHOULD host a synchronous Quarterly Review every 3 months, open to all necessary parties, to review aspects of the most recent Ongoing Certification Reports that the provider determines are of the most relevance to agencies.
- **Class C MUST:** Providers with Class C Certifications MUST host a synchronous Quarterly Review every 3 months, open to all necessary parties, to review aspects of the most recent Ongoing Certification Reports that the provider determines are of the most relevance to agencies.
- **Class D MUST:** Providers with Class D Certifications MUST host a synchronous Quarterly Review every 3 months, open to all necessary parties, to review aspects of the most recent Ongoing Certification Reports that the provider determines are of the most relevance to agencies.

Terms: `Agency`, `All Necessary Parties`, `Ongoing Certification`, `Provider`, `Quarterly Review`

Affects: Providers

Structured timeframe: `3` months

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CCM-QTR-NID` MUST NOT — No Irresponsible Disclosure

Providers MUST NOT irresponsibly disclose sensitive information in a Quarterly Review that would likely have an adverse effect on the cloud service offering.

Terms: `Cloud Service Offering`, `Likely`, `Provider`, `Quarterly Review`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CCM-QTR-NRD` MUST — Next Review Date

Providers MUST publicly supply the target date for their next Quarterly Review with other public FedRAMP Certification Data.

Terms: `Certification Data`, `Provider`, `Quarterly Review`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CCM-QTR-REG` MUST — Meeting Registration Info

Providers MUST supply either a registration link or a downloadable calendar file with meeting information for Quarterly Reviews to all necessary parties.

Terms: `All Necessary Parties`, `Provider`, `Quarterly Review`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CCM-QTR-RTP` SHOULD NOT — Restrict Third Parties

Providers SHOULD NOT invite third parties to attend Quarterly Reviews intended for agencies unless they have specific relevance.

Terms: `Agency`, `Assessor`, `Likely`, `Provider`, `Quarterly Review`

Affects: Providers

Note: This is because agencies are less likely to actively participate in meetings with third parties; the cloud service provider's independent assessor should be considered relevant by default.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CCM-QTR-RTR` SHOULD — Record/Transcribe Reviews

Providers SHOULD record or transcribe Quarterly Reviews and supply them to all necessary parties.

Terms: `All Necessary Parties`, `Provider`, `Quarterly Review`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CCM-QTR-SAR` SHOULD — Schedule Around Reports

Providers SHOULD regularly schedule Quarterly Reviews to occur at least 3 business days after releasing an Ongoing Certification Report AND within 10 business days of such release.

Terms: `FedRAMP Certification Report`, `Ongoing Certification`, `Ongoing Certification Report (OCR)`, `Provider`, `Quarterly Review`, `Regularly`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CCM-QTR-SCR` MAY — Share Content Responsibly

Providers MAY responsibly supply content prepared for a Quarterly Review to the public or other parties if the provider determines doing so will NOT likely have an adverse effect on the cloud service offering.

Terms: `Cloud Service Offering`, `Likely`, `Provider`, `Quarterly Review`, `Responsibly`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `CCM-QTR-SRR` MAY — Share Recordings Responsibly

Providers MAY responsibly supply recordings or transcriptions of Quarterly Reviews to the public or other parties ONLY if the provider removes all agency information (comments, questions, names, etc.) AND determines doing so will NOT likely have an adverse effect on the cloud service offering.

Terms: `Agency`, `Cloud Service Offering`, `Likely`, `Provider`, `Quarterly Review`, `Responsibly`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.
