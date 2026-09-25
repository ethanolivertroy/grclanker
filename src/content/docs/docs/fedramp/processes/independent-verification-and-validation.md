---
title: Independent Verification and Validation — FedRAMP Process
description: Official Consolidated Rules summary for the IVV FedRAMP process, including applicability and requirements.
---

> Generated from the official [FedRAMP/rules](https://github.com/FedRAMP/rules) GitHub repo.
> Source path: [`fedramp-consolidated-rules.json`](https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json) on `main` at blob `7d628b63fdd9`.
> Consolidated Rules version: `2026.07.02.02` · upstream `last_updated`: `2026-07-02`.
> Supporting narrative documentation is available from the official `FedRAMP/2026-markdown` repository.

# Independent Verification and Validation

Short name: `IVV` · Process ID: `IVV` · Web slug: `independent-verification-and-validation`

Applies to: `both`, `20x`, `rev5`
Status: `stable`


Official page: [https://www.fedramp.gov/2026/reference/independent-verification-and-validation/](https://www.fedramp.gov/2026/reference/independent-verification-and-validation/)

## Effective Status

- 20x: required · Consolidated Rules for 2026 · obtain 2026-07-04 · grace through 2027-01-01
- Rev5: required · Consolidated Rules for 2026 · obtain 2027-01-01 · grace through 2027-01-01
- Shared requirements: 15

## Purpose

This ruleset explains the expectations for independent verification and validation assessments.

## Rule Subsets

- `CSF` — Rev5-Specific Provider Responsibilities: These rules apply to providers for FedRAMP Rev5 Certifications. · types: Rev5 · classes: B, C, D
- `CSO` — General Provider Responsibilities: These rules apply to cloud service providers obtaining and maintaining any FedRAMP Certification. · types: 20x, Rev5 · classes: B, C, D
- `CSX` — 20x-Specific Provider Responsibilities: These rules apply to providers for FedRAMP 20x Certifications. · types: 20x · classes: B, C, D
- `IAS` — General Independent Assessor Responsibilities: These rules apply to independent assessment services supporting all FedRAMP Certification types. · types: 20x, Rev5 · classes: B, C, D

## Requirements and Recommendations

## BOTH

### `IVV-CSO-DUS` MUST — Document Use of Representative Samples

Providers MUST document and explain the use of representative samples during verification and validation when using representative samples as allowed by IVV-CSO-USR (Use Representative Samples).

Terms: `Provider`, `Validation`, `Verification`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `IVV-CSO-FIA` VARIES BY CLASS — FedRAMP Independent Assessments

Varies by certification class:

- **Class A MAY:** Providers with Class A Certifications MAY persistently complete an independent verification and validation assessment of all applicable FedRAMP rules with a FedRAMP Recognized independent assessment service OR FedRAMP at least once per year; this is a FedRAMP independent assessment.
- **Class B MUST:** Providers with Class B Certifications MUST persistently complete an independent verification and validation assessment of all applicable FedRAMP rules with a FedRAMP Recognized independent assessment service OR FedRAMP at least once per year; this is a FedRAMP independent assessment.
- **Class C MUST:** Providers with Class C Certifications MUST persistently complete an independent verification and validation assessment of all applicable FedRAMP rules with a FedRAMP Recognized independent assessment service OR FedRAMP at least once per year; this is a FedRAMP independent assessment.
- **Class D MUST:** Providers with Class D Certifications MUST persistently complete an independent verification and validation assessment of all applicable FedRAMP rules with a FedRAMP Recognized independent assessment service OR FedRAMP at least once per year; this is a FedRAMP independent assessment.

Terms: `Certification Class`, `FedRAMP Independent Assessment`, `FedRAMP Recognized`, `Persistently`, `Provider`, `Validation`, `Verification`

Affects: Providers

Structured timeframe: `1` years

Note: The first such completed assessment is typically called an "initial assessment" while following assessments are called "annual assessments."
The specific requirements for independent verification and validation assessments are documented by the FedRAMP Certification Class and Type.
The option for assessment by FedRAMP directly is limited to cloud services that are explicitly prioritized by FedRAMP, in consultation with the FedRAMP Board and the federal Chief Information Officers Council; this is _extremely_ rare.
FedRAMP Recognized independent assessment services are listed on the FedRAMP Marketplace.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `IVV-CSO-ICP` MUST — Inclusion in Certification Package

Providers MUST supply the results of FedRAMP independent assessments in their FedRAMP Certification Package without inappropriate modification.

Terms: `Certification Package`, `FedRAMP Independent Assessment`, `Provider`, `Verification`

Affects: Providers

Note: Inappropriate modification in this context means changing the underlying intent/etc. of the content provided by the independent assessment service - the content itself may be modified for presentation, formatting, etc. as needed.
This rule is related to IVV-IAS-VIP (Verify Inclusion in Certification Package).

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `IVV-CSO-RAA` MAY — Receiving Assessor Advice

Providers MAY ask for and accept advice from their assessor during assessment regarding techniques and procedures that will improve their security posture or the effectiveness, clarity, and accuracy of their verification, validation and reporting procedures, UNLESS doing so is likely to compromise the objectivity and integrity of the assessment.

Terms: `Assessor`, `Likely`, `Provider`, `Validation`, `Verification`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `IVV-CSO-SEE` MUST — Supply Evidence of Effectiveness

Providers MUST supply evidence to all necessary assessors of the effectiveness of the measures that have been implemented to meet FedRAMP Practices; this evidence is the result of validation.

Terms: `All Necessary Assessors`, `Assessor`, `FedRAMP Practices`, `Provider`, `Validation`

Affects: Providers

Note: For example, after verifying that firewalls are configured to block traffic following IVV-CSO-SEI (Supply Evidence of Implementation), the provider would validate that traffic is actually being blocked and supply evidence of that validation to assessors (such as by allowing them to see metrics on the traffic that is blocked vs not).

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `IVV-CSO-SEI` MUST — Supply Evidence of Implementation

Providers MUST supply evidence to all necessary assessors of the implementation of the measures that have been documented to meet FedRAMP Practices; this evidence is the result of verification.

Terms: `All Necessary Assessors`, `Assessor`, `FedRAMP Practices`, `Provider`, `Verification`

Affects: Providers

Note: For example, if the documentation says that firewall rules are used to block traffic then the cloud service provider would verify that firewall rules are in place to block traffic and supply that evidence to assessors (preferably by allowing them to see how firewall configurations are deployed from a source of truth).

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `IVV-CSO-STE` SHOULD — Supply Technical Explanations

Providers SHOULD supply all necessary assessors with technical explanations, demonstrations, and other relevant supporting information about the technical capabilities they employ to address FedRAMP rules; this SHOULD be supplied as necessary to ensure the assessor can effectively complete verification and validation.

Terms: `All Necessary Assessors`, `Assessor`, `Provider`, `Validation`, `Verification`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `IVV-CSO-USR` MAY — Use Representative Samples

Providers MAY use representative samples as appropriate during verification and validation.

Terms: `Persistently`, `Provider`, `Validation`, `Verification`

Affects: Providers

Note: Many modern cloud services using effective automation do not need to use representative sampling and are capable of persistently verifying and validating the majority of their security measures automatically.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `IVV-IAS-EPX` SHOULD — Engage Provider Experts

Assessors SHOULD engage provider experts in discussion to understand the decisions made by the provider and inform expert qualitative assessment, and SHOULD perform independent research to test such information as part of the expert qualitative assessment process.

Terms: `Assessor`, `Provider`

Affects: Assessors

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `IVV-IAS-OSA` MUST — Overall Summary of Assessment

Assessors MUST supply the provider with an overall summary of the verification and validation assessment results, including any resulting failures or areas of dispute; this summary will be included by the provider in the FedRAMP Certification Package Overview for the cloud service offering.

Terms: `Assessor`, `Certification Package`, `Cloud Service Offering`, `Provider`, `Validation`, `Verification`

Affects: Assessors

Note: FedRAMP does not supply a template for this summary and encourages independent assessment services to optimize for the best customer experience in the creation of these materials.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `IVV-IAS-SHA` MAY — Sharing Advice

Assessors MAY share advice with providers they are assessing about techniques and procedures that will improve the provider's security posture or the effectiveness, clarity, and accuracy of their verification, validation and reporting procedures, UNLESS doing so is likely to compromise the objectivity and integrity of the assessment.

Terms: `Assessor`, `Likely`, `Provider`, `Validation`, `Verification`

Affects: Assessors

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `IVV-IAS-SUM` MUST — Assessment Summary

Assessors MUST supply the provider with a high-level summary of their assessment process and findings for each FedRAMP Practice; this summary will be included by the provider in the FedRAMP Security Decision Record for the cloud service offering.

Terms: `Assessor`, `Cloud Service Offering`, `FedRAMP Practices`, `Provider`, `Security Decision Record (SDR)`

Affects: Assessors

Note: FedRAMP does not require a separate Security Assessment Plan or Security Assessment Report for FedRAMP 20x or FedRAMP Rev5 Certifications; this information is expected to be included in the Security Decision Record by the cloud service provider.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `IVV-IAS-VEF` MUST — Validate Effectiveness

Assessors MUST validate the effectiveness of the implemented measures to ensure they have the intended outcome for meeting FedRAMP Practices.

Terms: `Assessor`, `FedRAMP Practices`, `Validation`

Affects: Assessors

Note: This requires reviewing the actual measures themselves at a technical level, such as reviewing underlying code as appropriate; don't simply review documentation or screenshots.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `IVV-IAS-VIM` MUST — Verify Implementation

Assessors MUST verify that the measures implemented by the cloud service offering matches the measures they documented to meet FedRAMP Practices.

Terms: `Assessor`, `Cloud Service Offering`, `FedRAMP Practices`, `Verification`

Affects: Assessors

Note: This requires reviewing the actual measures themselves at a technical level, such as reviewing underlying code as appropriate; don't simply review documentation or screenshots.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `IVV-IAS-VIP` MUST — Verify Inclusion in Certification Package

Assessors MUST verify that information supplied during a FedRAMP independent assessment is included in the FedRAMP Certification Package by the provider without inappropriate modification.

Terms: `Assessor`, `Certification Package`, `FedRAMP Independent Assessment`, `Provider`, `Verification`

Affects: Assessors

Note: This rule is related to IVV-CSO-ICP (Inclusion in Certification Package).

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

## 20X

### `IVV-CSX-AIA` MUST — Annual Independent Assessments for 20x

Varies by certification class:

- **Class A MUST:** Providers with 20x Class A Certifications MUST meet the expectations of their underlying alternative security framework as part of their persistent independent verification and validation assessment.
- **Class B MUST:** Providers with 20x Class B Certifications MUST include all Key Security Indicators in a FedRAMP independent assessment at least once per year.
- **Class C MUST:** Providers with 20x Class C Certifications MUST include all Key Security Indicators in a FedRAMP independent assessment at least once per year.
- **Class D MUST:** Providers with 20x Class D Certifications MUST include all Key Security Indicators in a FedRAMP independent assessment at least once per year.

Terms: `FedRAMP Independent Assessment`, `Persistently`, `Provider`, `Validation`, `Verification`

Affects: Providers

Structured timeframe: `1` years

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

## REV5

### `IVV-CSF-ACF` MUST — Assessment of Rev5 Controls with Findings

Providers MUST have Rev5 Controls with negative findings from the previous FedRAMP independent assessment included in the next FedRAMP independent assessment.

Terms: `FedRAMP Independent Assessment`, `Provider`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `IVV-CSF-AIA` MUST — Annual Independent Assessments for Rev5

Varies by certification class:

- **Class B MUST:** Providers with Rev5 Class B Certifications MUST include the following Rev5 Controls in a FedRAMP independent assessment at least once per year:
- **Class C MUST:** Providers with Rev5 Class C Certifications MUST include the following Rev5 Controls in a FedRAMP independent assessment at least once per year:
- **Class D MUST:** Providers with Rev5 Class D Certifications MUST include the following Rev5 Controls in a FedRAMP independent assessment at least once per year:

Terms: `FedRAMP Independent Assessment`, `Provider`

Affects: Providers

Structured timeframe: `1` years

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `IVV-CSF-MCA` MUST — Mandatory Control Assessment

Providers MUST have all applicable Rev5 Controls included in FedRAMP independent assessments every 3 years but are not required to have all Rev5 Controls included in the same FedRAMP independent assessment.

Terms: `FedRAMP Independent Assessment`, `Provider`

Affects: Providers

Note: Traditionally this has been done by reviewing a rotating selection of Rev5 Controls at each annual assessment, however this requirement is a ceiling and not a floor. See IVV-CSF-PCA (Preferred Control Assessment) for FedRAMP's recommended approach to Rev5 control assessments.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `IVV-CSF-PCA` SHOULD — Preferred Control Assessment

Providers SHOULD include all applicable Rev5 Controls in each FedRAMP independent assessment.

Terms: `FedRAMP Independent Assessment`, `Provider`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.
