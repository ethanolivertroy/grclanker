---
title: FedRAMP Certification — FedRAMP Process
description: Official Consolidated Rules summary for the FRC FedRAMP process, including applicability and requirements.
---

> Generated from the official [FedRAMP/rules](https://github.com/FedRAMP/rules) GitHub repo.
> Source path: [`fedramp-consolidated-rules.json`](https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json) on `main` at blob `7d628b63fdd9`.
> Consolidated Rules version: `2026.07.02.02` · upstream `last_updated`: `2026-07-02`.
> Supporting narrative documentation is available from the official `FedRAMP/2026-markdown` repository.

# FedRAMP Certification

Short name: `FRC` · Process ID: `FRC` · Web slug: `fedramp-certification`

Applies to: `both`, `20x`, `rev5`
Status: `stable`


Official page: [https://www.fedramp.gov/2026/reference/fedramp-certification/](https://www.fedramp.gov/2026/reference/fedramp-certification/)

## Effective Status

- 20x: required · Consolidated Rules for 2026 · obtain 2026-07-04 · grace through 2027-01-01
- Rev5: required · Consolidated Rules for 2026 · obtain 2027-01-01 · grace through 2027-01-01
- Shared requirements: 21

## Purpose

This ruleset explains how cloud service offerings obtain and maintain FedRAMP Certification across certification classes and paths.

## Rule Subsets

- `APP` — Applying for FedRAMP Certification: These rules apply to cloud service providers who have met all other relevant rules and are ready to apply for any FedRAMP Certification. · types: 20x, Rev5 · classes: A, B, C, D
- `APS` — Applying for FedRAMP Certification with an Agency Sponsor: These rules apply to cloud service providers with an Agency Sponsor who have met all other relevant rules and are ready to apply for any FedRAMP Certification. · types: Rev5 · classes: B, C, D
- `CCL` — Changing Certification Class: These rules apply to cloud service providers when changing their FedRAMP Certification Class. · types: Rev5 · classes: A, B, C, D
- `CLA` — FedRAMP Class A Certification Rules: These are specific rules that apply to providers seeking FedRAMP Class A Certifications. · types: 20x, Rev5 · classes: A
- `CSF` — Rev5-Specific Provider Responsibilities: These rules apply to providers for FedRAMP Rev5 Certifications. · types: Rev5 · classes: B, C, D
- `CSO` — General Provider Responsibilities: These rules apply to cloud service providers obtaining and maintaining any FedRAMP Certification. · types: 20x, Rev5 · classes: A, B, C, D
- `CSX` — 20x-Specific Provider Responsibilities: These rules apply to providers for FedRAMP 20x Certifications. · types: 20x · classes: B, C, D

## Requirements and Recommendations

## BOTH

### `FRC-APP-AFC` MUST — Applying for FedRAMP Certification

Providers MUST complete the FedRAMP Certification Application Form in full to request an initial assessment by FedRAMP.

Terms: `Provider`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `FRC-APP-FCP` MUST — Fresh FedRAMP Certification Package

Providers MUST supply a fresh initial FedRAMP Certification Package that shows the current status of the cloud service offering as verified and validated by the provider within the previous 7 days.

Terms: `Certification Package`, `Cloud Service Offering`, `Provider`, `Validation`, `Verification`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `FRC-APP-FIA` VARIES BY CLASS — Fresh Independent Assessment

Varies by certification class:

- **Class A MAY:** Providers seeking Class A Certification MAY supply a fresh initial FedRAMP independent assessment that was completed by a FedRAMP Recognized independent assessment service within the previous 3 months.
- **Class B MUST:** Providers seeking Class B Certification MUST supply a fresh initial FedRAMP independent assessment that was completed by a FedRAMP Recognized independent assessment service within the previous 3 months.
- **Class C MUST:** Providers seeking Class C Certification MUST supply a fresh initial FedRAMP independent assessment that was completed by a FedRAMP Recognized independent assessment service within the previous 3 months.
- **Class D MUST:** Providers seeking Class D Certification MUST supply a fresh initial FedRAMP independent assessment that was completed by a FedRAMP Recognized independent assessment service within the previous 3 months.

Terms: `FedRAMP Independent Assessment`, `FedRAMP Recognized`, `Provider`

Affects: Providers

Structured timeframe: `3` months

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `FRC-APP-MLF` MUST — Marketplace Listing First

Providers MUST be listed in the FedRAMP Marketplace before applying for FedRAMP Certification, including:

Checklist items:
- FedRAMP Marketplace: MKT-CSO-MLR (Marketplace Listing Requirements),
- FedRAMP Marketplace: MKT-CSO-PML (Provider Marketplace Listing Requests)
- FedRAMP Marketplace: MKT-IIP-AGU (Agency Use Cases)
- FedRAMP Marketplace: MKT-IIP-DCP (Demonstrating Continuous Progress)

Terms: `Agency`, `Provider`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `FRC-APP-NTP` MUST NOT — No Third-Party Applicants

Providers MUST NOT use a third party to apply for a FedRAMP Certification on their behalf; this includes independent assessment services.

Terms: `Provider`

Affects: Providers

Note: FedRAMP previously allowed independent assessment services to submit applications on behalf of providers, but this caused confusion about who was responsible for the application and the information in it. Providers should apply directly to ensure clear accountability.
Providers may use third parties to help them prepare their application and assessment materials for submission.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `FRC-APP-USA` MAY — Updating Stale Assessments

Providers MAY freshen a stale initial independent verification and validation assessment by having a FedRAMP Recognized independent assessment service review any changes between the original assessment and the current status of the cloud service offering in place of a full re-assessment, UNLESS the stale assessment is more than 9 months old.

Terms: `Cloud Service Offering`, `FedRAMP Recognized`, `Provider`, `Validation`, `Verification`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `FRC-APS-ATO` MUST — Agency Authorization to Operate

Providers seeking a FedRAMP Rev5 Agency Certification MUST have completed the Authorization to Operate (ATO) process with their agency sponsor for the cloud service offering, concluding with a formal signed ATO letter that the agency has sent over official government channels to FedRAMP.

Terms: `Agency`, `Cloud Service Offering`, `Provider`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `FRC-CCL-DCC` MUST — Downgrading Certification Class

Providers MUST apply for a new FedRAMP Certification to downgrade their Certification Class.

Terms: `All Necessary Parties`, `Certification Class`, `Provider`

Affects: Providers

Note: Downgrade paths include moving from D to C, B, or A; C to B or A; or B to A.
FRC-CCL-DNP (Downgrade Notification Period) applies - please DO NOT downgrade Certification Class with providing advance notification to all necessary parties!

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `FRC-CCL-DNP` SHOULD — Downgrade Notification Period

Providers SHOULD notify all necessary parties at least 120 days in advance of an intended downgrade or cancellation of FedRAMP Certification.

Terms: `Agency`, `All Necessary Parties`, `Provider`

Affects: Providers

Note: Downgrading or canceling FedRAMP Certification will have severe negative consequences for the provider and their agency customers and should only be done after careful consideration and planning... but if it must be done, notify all necessary parties as soon as possible.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `FRC-CCL-UCC` MUST — Upgrading Certification Class

Providers MUST apply for a new FedRAMP Certification to upgrade their Certification Class; all applicable requirements MUST be met in advance.

Terms: `Certification Class`, `Provider`

Affects: Providers

Note: Upgrade paths include moving from A to B, C, or D; B to C or D; and C to D.
The preferred path is to incrementally update the implementation and assurance commitments within the current Certification Class until the provider has met all requirements for the target Certification Class, then apply for the new Certification Class.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `FRC-CLA-ASF` MUST — Approved Alternative Security Frameworks

Providers seeking a FedRAMP Class A Certification MUST have completed a certification or equivalent process, including an independent assessment if applicable, from one of the following alternative security frameworks within the past 12 months:

Checklist items:
- FedRAMP Rev5 (including FedRAMP Ready) at any historical Impact Level
- SOC 2 Type II
- GovRAMP at any Impact Level

Terms: `Provider`, `Security Category`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `FRC-CLA-EAM` MUST — External Assessment Materials

Providers seeking a FedRAMP Class A Certification MUST supply the following materials from their alternative security framework assessment to all necessary parties:

Checklist items:
- SOC 2 Type II: Complete report, bridge or gap letter (if applicable), verified audit engagement documentation, estimated schedule for upcoming report, supplemental compliance evidence (if applicable)
- FedRAMP Ready: Readiness Assessment Report, Security Assessment Plan, and any other materials required by FedRAMP.
- GovRAMP: Readiness Assessment Report, Security Assessment Plan, and any other materials required by GovRAMP.

Terms: `All Necessary Parties`, `Provider`, `Verification`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `FRC-CLA-IVV` MAY — Optional Independent Verification and Validation

Providers seeking a FedRAMP Class A Certification MAY have the FedRAMP Certification Package independently verified and validated by a FedRAMP Recognized assessor before submission to FedRAMP.

Terms: `Assessor`, `Certification Package`, `FedRAMP Recognized`, `Provider`, `Validation`, `Verification`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `FRC-CLA-MFR` MUST — Mandatory FedRAMP Rules for Class A

Providers seeking a Class A FedRAMP Certification MUST address all rules in this FedRAMP Class A Certification subset (FRC-CLA) AND the following additional FedRAMP Class A rules; the appropriate artifacts or information mapping for all rules MUST be supplied in the FedRAMP Certification Package.

Checklist items:
- FedRAMP Certification: FRC-CSO-PKG (FedRAMP Certification Package)
- FedRAMP Certification: FRC-CSO-JSN (FedRAMP JSON Schemas)
- FedRAMP Certification: FRC-CSO-POP (Pick One Program Certification Type)
- Minimum Assessment Scope: MAS-CSO-IIR (Identify Information Resources)
- Certification Data Sharing: CDS-CSO-PUB (Public Information)
- Certification Data Sharing: CDS-CSO-UTC (Use Trust Centers)
- Certification Data Sharing: CDS-UTC-AAD (Agency Access Denial)
- Addressing FedRAMP Communication: AFC-CSO-INB (Maintain a FedRAMP Security Inbox)
- Addressing FedRAMP Communication: AFC-CSO-RCV (Receive Email Without Disruption)
- Addressing FedRAMP Communication: AFC-CSO-CRA (Complete Required Actions)
- Incident Evaluation and Communication: IEC-CSO-EFR (Evaluate FedRAMP Reportability)
- Incident Evaluation and Communication: IEC-CSO-FIR (Final Incident Report)
- Vulnerability Detection and Response: VDR-CSO-DET (Vulnerability Detection)
- Collaborative Continuous Monitoring: CCM-OCR-AVL (Report Availability)
- Collaborative Continuous Monitoring: CCM-OCR-NRD (Next Report Date)
- Independent Verification and Validation: IVV-CSX-AIA (Annual Independent Assessments for 20x)
- Key Security Indicators: KSI-CMT-LMC (Logging Changes)
- Key Security Indicators: KSI-CNA-RNT (Restricting Network Traffic)
- Key Security Indicators: KSI-CED-RAT (Reviewing All Training)
- Key Security Indicators: KSI-IAM-AAM (Automating Account Management)
- Key Security Indicators: KSI-IAM-APM (Adopting Passwordless Methods)
- Key Security Indicators: KSI-INR-RIR (Reviewing Incident Response Procedures)
- Key Security Indicators: KSI-SVC-SIN (Securing Information)

Terms: `Agency`, `Artifacts`, `Certification Data`, `Certification Package`, `Certification Type`, `FedRAMP Security Inbox`, `Final Incident Report (FIR)`, `Incident`, `Information Resource`, `Initial Incident Report (IIR)`, `Ongoing Certification Report (OCR)`, `Provider`, `Trust Center`, `Validation`, `Verification`, `Vulnerability`, `Vulnerability Detection`, `Vulnerability Response`

Affects: Providers

Note: Some of these specific FedRAMP rules may not have similar counterparts in external frameworks and providers will need to implement new processes to follow these rules.
In general, for each of these FedRAMP requirements, providers should include a sufficiently detailed summary that reviewers will not need to dig into the related security framework materials to understand the related decisions - just saying "see SOC 2 report" is not particularly helpful.
Information about how the provider addresses the included Key Security Indicators are required for both Rev5 and 20x Class A Certifications.

Recent update: 2026-07-01 — Removed reference to Independent Verification and Validation: IVV-CSF-AIA (Annual Independent Assessments for Rev5); Removed CDS-CSO-AVR (Availability Reporting) since this rule is defined as SHOULD and included in FRC-CLA-RFR (Recommended FedRAMP Rules for Class A)

### `FRC-CLA-OFR` MAY — Address Optional FedRAMP Rules for Class A

Providers seeking a Class A FedRAMP Certification MAY address the following additional optional FedRAMP Class A rules (if applicable):

Checklist items:
- Collaborative Continuous Monitoring: CCM-QTR-MTG (Quarterly Review Meeting)
- Certification Data Sharing: CDS-CSO-PSM (Per-Service Certification Materials)
- Cryptographic Module Use: CMU-CSO-UVM (Using Validated Cryptographic Modules)
- FedRAMP Certification: FRC-APP-FIA (Fresh Independent Assessment)
- Independent Verification and Validation: IVV-CSO-FIA (FedRAMP Independent Assessments)
- Security Decision Record: SDR-CSX-KMT (Key Security Indicator Metrics)
- Vulnerability Evaluation and Reporting: VER-TFR-IRI (Internet-Reachable Incidents)
- Vulnerability Evaluation and Reporting: VER-TFR-MRH (Historical Activity)
- Vulnerability Evaluation and Reporting: VER-TFR-NRI (Non-Internet-Reachable Incidents)

Terms: `Certification Data`, `FedRAMP Independent Assessment`, `Incident`, `Provider`, `Quarterly Review`, `Security Decision Record (SDR)`, `Validation`, `Verification`, `Vulnerability`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `FRC-CLA-RFR` SHOULD — Recommended FedRAMP Rules for Class A

Providers seeking a Class A FedRAMP Certification SHOULD address the following additional recommended FedRAMP Class A rules (if applicable):

Checklist items:
- Certification Data Sharing: CDS-CSO-AVR (Availability Reporting)
- Certification Package Overview: CPO-CSF-CPM (Certification Package Maintenance for Rev5)
- Certification Package Overview: CPO-CSX-CPM (Certification Package Maintenance for 20x)
- Incident Evaluation and Communication: IEC-CSO-IIR (Initial Incident Report)
- Incident Evaluation and Communication: IEC-CSO-OIR (Ongoing Incident Reports)
- Vulnerability Detection and Response: VDR-TFR-MVX (Persistent Machine Verification and Validation for 20x)
- Vulnerability Detection and Response: VDR-TFR-PCD (Persistently Complete Detection)
- Vulnerability Detection and Response: VDR-TFR-PDD (Persistent Drift Detection)
- Vulnerability Detection and Response: VDR-TFR-PSD (Persistent Sample Detection)
- Vulnerability Detection and Response: VDR-TFR-PVR (Mitigation and Remediation Expectations)
- Vulnerability Evaluation and Reporting: VER-TFR-EVU (Evaluate Vulnerabilities Quickly)

Terms: `Certification Data`, `Certification Package`, `Drift`, `Incident`, `Initial Incident Report (IIR)`, `Ongoing Incident Report (OIR)`, `Persistently`, `Provider`, `Validation`, `Verification`, `Vulnerability`, `Vulnerability Detection`, `Vulnerability Response`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `FRC-CSO-FCP` MUST — FedRAMP Certification Profile

Providers MUST identify a target FedRAMP Certification Profile and apply all relevant FedRAMP Practices to the cloud service offering.

Terms: `Certification Profile`, `Cloud Service Offering`, `FedRAMP Practices`, `Handle`, `Information Resource`, `Provider`, `Security Category`, `Third-Party Information Resource`

Affects: Providers

Note: Information resources (including third-party information resources) MAY vary by security category as appropriate to the type of information handled by or impacted by the information resource.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `FRC-CSO-JSN` MUST — FedRAMP JSON Schemas

Providers MUST supply machine-readable information in JSON documents that are valid against the corresponding JSON schema when a rule contains a FedRAMP JSON schema, UNLESS otherwise specified in the rule.

Terms: `Machine-Readable`, `Provider`

Affects: Providers

Note: FedRAMP JSON schemas are designed to be lightweight and flexible to establish a minimum set of structured information while allowing providers to improve on the format and structure of the information as needed to meet their needs and the needs of their customers.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `FRC-CSO-MRA` MUST — Maintain Responsibility and Accountability

Providers MUST maintain responsibility and accountability for the accuracy and completeness of all information in the FedRAMP Certification Package, especially when they engage a third party (such as an independent assessor, advisory service, or external tools) to supply information on their behalf.

Terms: `Assessor`, `Certification Package`, `Provider`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `FRC-CSO-PKG` MUST — FedRAMP Certification Package

Providers seeking a Certification MUST supply a complete FedRAMP Certification Package to FedRAMP for initial certification; the FedRAMP Certification Package MUST include at least the following information:

Checklist items:
- A Certification Package Overview
- A Security Decision Record
- A real or example Ongoing Certification Report following CCM-OCR-AVL (Report Availability)

Terms: `Certification Package`, `FedRAMP Certification Report`, `Initial Certification`, `Ongoing Certification`, `Ongoing Certification Report (OCR)`, `Provider`, `Security Decision Record (SDR)`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `FRC-CSO-POP` MUST NOT — Pick One Program Certification Type

Providers MUST NOT seek both FedRAMP Rev5 Program Certification and FedRAMP 20x Program Certification for the same cloud service offering; pick one type.

Terms: `Agency`, `Cloud Service Offering`, `Provider`

Affects: Providers

Note: This rule does not prevent a provider from seeking and maintaining a FedRAMP Rev5 Agency Certification and a FedRAMP 20x Program Certification for the same cloud service offering, however, doing so is strongly discouraged due to the increased complexity and risk of confusion for all parties.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

## 20X

### `FRC-CSX-MAS` SHOULD — Application within MAS

Providers SHOULD apply ALL Key Security Indicators to ALL aspects of their cloud service offering that are within the FedRAMP Minimum Assessment Scope.

Terms: `Cloud Service Offering`, `Provider`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `FRC-CSX-MOT` VARIES BY CLASS — Metrics Over Time for Key Security Indicators

Varies by certification class:

- **Class A MAY:** Providers seeking 20x Class A Certification MAY supply historical metrics for Key Security Indicators.
- **Class B SHOULD:** Providers seeking 20x Class B Certification SHOULD supply historical metrics for Key Security Indicators.
- **Class C MUST:** Providers seeking 20x Class C Certification MUST supply historical metrics including status from persistent validation over at least the past 6 months for all Key Security Indicators.
- **Class D MUST:** Providers seeking 20x Class D Certification MUST provide historical metrics including status from persistent validation over at least the past 18 months for all Key Security Indicators.

Terms: `Initial Certification`, `Persistently`, `Provider`, `Validation`

Affects: Providers

Note: For initial FedRAMP Certification, providers will need to have mechanisms in place and agree to meet this requirement in the event the cloud service has not been operating with related metrics available for the required period prior to applying for initial certification.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `FRC-CSX-VVK` VARIES BY CLASS — Automated Verification and Validation of Key Security Indicators

Varies by certification class:

- **Class A MAY:** Providers seeking 20x Class A Certification MAY implement automated methods to persistently verify and validate the accuracy and completeness of Key Security Indicators.
- **Class B SHOULD:** Providers seeking 20x Class B Certification SHOULD implement automated methods to persistently verify and validate the accuracy and completeness of Key Security Indicators with at least 1 automated method for each Key Security Indicator.
- **Class C MUST:** Providers seeking 20x Class C Certification MUST implement automated methods to persistently verify and validate the accuracy and completeness of Key Security Indicators with at least 2 automated methods for each Key Security Indicator.
- **Class D MUST:** Providers seeking 20x Class D Certification MUST implement automated methods to persistently verify and validate the accuracy and completeness of Key Security Indicators with at least 4 automated methods for each Key Security Indicator.

Terms: `Persistently`, `Provider`, `Validation`, `Verification`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `FRC-CSX-VVR` VARIES BY CLASS — Automated Verification and Validation of FedRAMP Rules

Varies by certification class:

- **Class A MAY:** Providers seeking 20x Class A Certification MAY implement automated methods to persistently verify and validate the accuracy and completeness of the Security Decision Record for FedRAMP rules when applicable.
- **Class B SHOULD:** Providers seeking 20x Class B Certification SHOULD implement automated methods to persistently verify and validate the accuracy and completeness of the Security Decision Record for FedRAMP rules when applicable.
- **Class C SHOULD:** Providers seeking 20x Class C Certification SHOULD implement automated methods to persistently verify and validate the accuracy and completeness of the Security Decision Record for FedRAMP rules when applicable.
- **Class D SHOULD:** Providers seeking 20x Class D Certification SHOULD implement automated methods to persistently verify and validate the accuracy and completeness of the Security Decision Record for FedRAMP rules when applicable.

Terms: `Persistently`, `Provider`, `Security Decision Record (SDR)`, `Validation`, `Verification`

Affects: Providers

Note: Different rules will be easy to automate for different providers, depending on the implementation, so FedRAMP generally leaves this implementation up to providers based on what makes the most sense for their own business and approach.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

## REV5

### `FRC-CSF-ACP` MUST — Assign Control Parameters

Providers MUST assign all organization-defined control parameters, following FedRAMP Rev5 Controls Guidance, and ensure that all control parameter assignments are documented in the Security Decision Record (SDR).

Terms: `Provider`, `Security Decision Record (SDR)`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `FRC-CSF-BSL` MUST — FedRAMP Rev5 Baselines

Varies by certification class:

- **Class B MUST:** Providers seeking FedRAMP Rev5 Class B Certification MUST include at least the following NIST SP 800-53 Rev. 5 controls in their Security Decision Record:
- **Class C MUST:** Providers seeking FedRAMP Rev5 Class C Certification MUST include at least the following NIST SP 800-53 Rev. 5 controls in their Security Decision Record:
- **Class D MUST:** Providers seeking FedRAMP Rev5 Class D Certification MUST include at least the following NIST SP 800-53 Rev. 5 controls in their Security Decision Record:

Terms: `Provider`, `Security Decision Record (SDR)`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `FRC-CSF-FFG` MUST — Follow FedRAMP Rev5 Controls Guidance

Providers MUST follow FedRAMP Rev5 Controls Guidance for the implementation and documentation of all applicable controls.

Terms: `Provider`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `FRC-CSF-RDY` MUST — FedRAMP Ready Conversion

Providers with FedRAMP Rev5 Ready status MUST convert to a FedRAMP Certification by whichever of the follow dates is later: the expiration of their annual assessment or November 17, 2026 (the legacy FedRAMP Ready status will be entirely removed on December 31, 2027).

Terms: `Provider`

Affects: Providers

Note: The simplest conversion in most cases would be to a FedRAMP 20x Class A Certification.
Cloud services that do not wish to convert or do not meet conversion criteria will be renamed Legacy FedRAMP Ready and otherwise retired from FedRAMP Ready.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.
