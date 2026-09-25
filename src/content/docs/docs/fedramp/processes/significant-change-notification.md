---
title: Significant Change Notification — FedRAMP Process
description: Official Consolidated Rules summary for the SCN FedRAMP process, including applicability and requirements.
---

> Generated from the official [FedRAMP/rules](https://github.com/FedRAMP/rules) GitHub repo.
> Source path: [`fedramp-consolidated-rules.json`](https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json) on `main` at blob `7d628b63fdd9`.
> Consolidated Rules version: `2026.07.02.02` · upstream `last_updated`: `2026-07-02`.
> Supporting narrative documentation is available from the official `FedRAMP/2026-markdown` repository.

# Significant Change Notification

Short name: `SCN` · Process ID: `SCN` · Web slug: `significant-change-notification`

Applies to: `both`
Status: `stable`


Official page: [https://www.fedramp.gov/2026/reference/significant-change-notification/](https://www.fedramp.gov/2026/reference/significant-change-notification/)

## Effective Status

- 20x: required · Consolidated Rules for 2026 · obtain 2026-07-04 · grace through 2027-01-01
- Rev5: required · Consolidated Rules for 2026 · obtain 2027-01-01 · grace through 2027-06-01
- Shared requirements: 17

## Purpose

The Significant Change Notification rules supply a simple framework allowing providers to make significant changes to their own products while keeping agency customers in the loop. These rules organize significant changes into clear categories so agencies can understand the expected risk and make authorization decisions accordingly.

## Rule Subsets

- `ADP` — Adaptive Changes: These rules apply to all adaptive significant changes. · types: 20x, Rev5 · classes: B, C, D
- `CSO` — General Provider Responsibilities: These rules apply to providers with FedRAMP Certifications of any type. · types: 20x, Rev5 · classes: B, C, D
- `FRP` — FedRAMP Responsibilities: These rules apply to FedRAMP. · types: 20x, Rev5 · classes: B, C, D
- `RTR` — Routine Recurring Changes: These rules apply to all routine recurring significant changes. · types: 20x, Rev5 · classes: B, C, D
- `TRF` — Transformative Changes: These rules apply to all transformative significant changes. · types: 20x, Rev5 · classes: B, C, D

## Requirements and Recommendations

## BOTH

### `SCN-ADP-NTF` MUST — Notification Requirements

Providers MUST notify all necessary parties within 10 business days after finishing adaptive changes, also including the following information:

Checklist items:
- Summary of any new risks identified and/or vulnerabilities resulting from the change (if applicable)

Terms: `Adaptive Change`, `All Necessary Parties`, `Provider`, `Regularly`, `Significant Change`, `Vulnerability`

Affects: Providers

Structured timeframe: `10` bizdays

Note: Activities that match the adaptive significant change type are a frequent and normal part of iteratively improving a service by deploying new functionality or modifying existing functionality in a way that is typically transparent to customers and does not introduce significant new security risks.
In general, most changes that do not happen regularly will be adaptive changes. This change type deliberately covers a wide range of activities in a way that requires assessment and consideration.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `SCN-CSO-ARI` MAY — Additional Relevant Information

Providers MAY include additional relevant information in Significant Change Notifications.

Terms: `Provider`, `Significant Change`

Affects: Providers

Note: This allows providers to convey whatever additional information they think is relevant without worrying about negative consequences from not following an exact template.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `SCN-CSO-EMG` MAY — Emergency Changes

Providers MAY execute significant changes (including transformative changes) during an emergency or incident without following the Significant Change Notification rules in advance. In such emergencies, providers MUST follow all relevant procedures, notify all necessary parties, retroactively provide all Significant Change Notification materials, and complete appropriate assessment after the incident.

Terms: `All Necessary Parties`, `Certification Package`, `Incident`, `Provider`, `Significant Change`, `Transformative Change`

Affects: Providers

Note: Procedures for emergency changes should be documented in the FedRAMP Certification Package.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `SCN-CSO-EVA` MUST — Evaluate Changes

Providers MUST evaluate all potential significant changes to determine the type of significant change and follow the appropriate Significant Change Notification rules.

Checklist items:
- Is it a significant change? --> Continue evaluation and follow the Significant Change Notification rules.
- If it is, is it an FedRAMP Certification class change?  --> This requires a new assessment and cannot be done under the Significant Change Notification rules.
- If it is not, is it a routine recurring change? --> Follow the Routine Recurring Change rules (SCN-RTR Routine Recurring Changes).
- If it is not, is it a transformative change? --> Follow the Transformative Change rules (SCN-TRF Transformative Changes).
- If it is not, then it is an adaptive change --> Follow the Adaptive Change rules (SCN-ADP Adaptive Changes).

Terms: `Adaptive Change`, `Certification Class`, `Certification Class Change`, `Provider`, `Routine Recurring Change`, `Significant Change`, `Transformative Change`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `SCN-CSO-HIS` MUST — Historical Notifications

Providers MUST keep 12 months of historical Significant Change Notifications available with their FedRAMP Certification Data.

Terms: `Certification Data`, `Provider`, `Significant Change`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `SCN-CSO-HRM` MUST — Human and Machine-Readable Notifications

Providers MUST make ALL Significant Change Notifications and related audit records available in human-readable and JSON formats.

Terms: `Provider`, `Significant Change`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `SCN-CSO-INF` MUST — Required Information

Providers MUST include at least the following information in Significant Change Notifications:

Checklist items:
- Service Offering FedRAMP ID
- Assessor Name (if applicable)
- Related Vulnerability (if applicable)
- Significant Change type and explanation of categorization
- Short description of change
- Reason for change
- Summary of customer impact, including changes to services and customer configuration responsibilities
- Plan and timeline for the change, including for the verification, assessment, and/or validation of impacted Key Security Indicators or Rev5 Controls
- Copy of the business or security impact analysis
- Name and title of approver

Terms: `Assessor`, `Provider`, `Significant Change`, `Validation`, `Verification`, `Vulnerability`

Affects: Providers

Note: Structure of the information may vary depending on how the provider tracks this internally.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `SCN-CSO-MAR` MUST — Maintain Audit Records

Providers MUST maintain auditable records of the significant change evaluation activities required by SCN-CSO-EVA (Evaluate Changes) and make them available to FedRAMP as requested.

Terms: `Certification Package`, `Provider`, `Significant Change`

Affects: Providers

Note: These audit records must be available to FedRAMP on request; these records do not need to be included in the FedRAMP Certification Package by default and do not need to be emailed to FedRAMP continuously.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `SCN-CSO-NOM` MAY — Notification Mechanisms

Providers MAY notify necessary parties in a variety of ways as long as the mechanism for notification is clearly documented in the FedRAMP Certification Package and easily accessible.

Terms: `Agency`, `Certification Package`, `Provider`

Affects: Providers

Note: The sharing mechanism should be designed based on the needs of the provider and their customers and may vary between providers.
The default sharing mechanism for most providers during the SCN beta was to send an email to agency customers and upload a copy of the notification to the provider's secure sharing location.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `SCN-FRP-CAP` MAY — Corrective Action Plan Conditions

FedRAMP MAY require providers to delay significant changes beyond the standard Significant Change Notification period and/or submit significant changes for approval in advance as a condition of a formal FedRAMP Corrective Action Plan or other agreement.

Terms: `Provider`, `Significant Change`

Affects: FedRAMP

Note: The circumstances and conditions of such a Corrective Action Plan will vary and be documented in the Correcive Action Plan.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `SCN-RTR-NNR` SHOULD NOT — No Notification Requirements

Providers SHOULD NOT make formal Significant Change Notifications for routine recurring changes; this type of change is exempted from notification requirements.

Terms: `Incident`, `Provider`, `Regularly`, `Routine Recurring Change`, `Significant Change`, `Vulnerability`

Affects: Providers

Note: Activities that match the routine recurring significant change type are performed regularly and routinely by cloud service providers to address flaws or vulnerabilities, address incidents, and generally perform the typical maintenance and service delivery changes expected during day-to-day operations.
These changes leverage mature processes and capabilities to identify, mitigate, and remediate risks as part of the change. They are often entirely automated and may occur without human intervention, even though they have an impact on security of the service.
If the activity does not occur regularly and routinely then it cannot be a significant change of this type (e.g., replacing all physical firewalls to remediate a vulnerability is obviously not regular or routine).

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `SCN-TRF-NAF` MUST — Notification After Finishing

Providers MUST notify all necessary parties within 5 business days after finishing transformative changes, including updates to all previously sent information.

Terms: `All Necessary Parties`, `Provider`, `Transformative Change`

Affects: Providers

Structured timeframe: `5` bizdays

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `SCN-TRF-NAV` MUST — Notification After Verification

Providers MUST notify all necessary parties within 5 business days after completing the verification, assessment, and/or validation of transformative changes, also including the following information:

Checklist items:
- Updates to all previously sent information
- Summary of any new risks identified and/or vulnerabilities resulting from the change (if applicable)
- Copy of the security assessment report (if applicable)

Terms: `All Necessary Parties`, `Provider`, `Transformative Change`, `Validation`, `Verification`, `Vulnerability`

Affects: Providers

Structured timeframe: `5` bizdays

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `SCN-TRF-NFP` MUST — Notification of Final Plans

Providers MUST notify all necessary parties of final plans for transformative changes at least 10 business days before starting transformative changes, including updates to all previously sent information.

Terms: `All Necessary Parties`, `Provider`, `Transformative Change`

Affects: Providers

Structured timeframe: `10` bizdays

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `SCN-TRF-NIP` MUST — Notification of Initial Plans

Providers MUST notify all necessary parties of initial plans for transformative changes at least 30 business days before starting transformative changes, including a summary of any likely security impacts or changes in risk.

Terms: `All Necessary Parties`, `Likely`, `Provider`, `Transformative Change`

Affects: Providers

Structured timeframe: `30` bizdays

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `SCN-TRF-TPR` SHOULD — Third-Party Review

Providers SHOULD engage a third-party assessor to review the scope and impact of the planned change before starting transformative changes if human validation is necessary; such reviews SHOULD be limited to security decisions that require human validation.

Terms: `Assessor`, `Cloud Service Offering`, `Provider`, `Significant Change`, `Transformative Change`, `Validation`

Affects: Providers

Note: Activities that match the transformative significant change type are rare for a cloud service offering, adjusted for the size, scale, and complexity of the service. Small cloud service offerings may go years without transformative changes, while hyperscale providers may release multiple transformative changes per year.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `SCN-TRF-UPD` MUST — Update Documentation

Providers MUST publish updated service documentation and other materials to reflect transformative changes within 30 business days after finishing transformative changes.

Terms: `Certification Package`, `Provider`, `Transformative Change`

Affects: Providers

Structured timeframe: `30` bizdays

Note: This requirement is focused on service documentation like user guides, information listed in the marketplace, and other such materials; it does not require updating the system security plan or FedRAMP Certification Package.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.
