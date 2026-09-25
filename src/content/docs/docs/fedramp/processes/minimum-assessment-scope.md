---
title: Minimum Assessment Scope — FedRAMP Process
description: Official Consolidated Rules summary for the MAS FedRAMP process, including applicability and requirements.
---

> Generated from the official [FedRAMP/rules](https://github.com/FedRAMP/rules) GitHub repo.
> Source path: [`fedramp-consolidated-rules.json`](https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json) on `main` at blob `7d628b63fdd9`.
> Consolidated Rules version: `2026.07.02.02` · upstream `last_updated`: `2026-07-02`.
> Supporting narrative documentation is available from the official `FedRAMP/2026-markdown` repository.

# Minimum Assessment Scope

Short name: `MAS` · Process ID: `MAS` · Web slug: `minimum-assessment-scope`

Applies to: `both`
Status: `stable`


Official page: [https://www.fedramp.gov/2026/reference/minimum-assessment-scope/](https://www.fedramp.gov/2026/reference/minimum-assessment-scope/)

## Effective Status

- 20x: required · Consolidated Rules for 2026 · obtain 2026-07-04 · grace through 2027-01-01
- Rev5: required · Consolidated Rules for 2026 · obtain 2027-01-01 · grace through 2027-01-01
- Shared requirements: 5

## Purpose

The Minimum Assessment Scope rules help providers define assessment boundaries narrowly enough to avoid unnecessary review of components that do not affect the offering's security. These rules still ensure the assessment includes the resources and connections needed to understand the offering's confidentiality, integrity, and availability.

## Rule Subsets

- `CSO` — General Provider Responsibilities: These rules apply to providers for any type of FedRAMP Certification. · types: 20x, Rev5 · classes: B, C, D

## Requirements and Recommendations

## BOTH

### `MAS-CSO-FLO` MUST — Information Flows and Security Categories

Providers MUST clearly identify, document, and explain information flows and security categories for ALL information resources or sets of information resources in the cloud service offering.

Terms: `Cloud Service Offering`, `Handle`, `Information Resource`, `Provider`, `Security Category`, `Third-Party Information Resource`

Affects: Providers

Note: Information resources (including third-party information resources) MAY vary by security category as appropriate to the type of information handled by or impacted by the information resource.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `MAS-CSO-IIR` MUST — Identify Information Resources

Providers MUST identify a set of information resources to assess for FedRAMP Certification that includes all information resources that are likely to handle federal customer data or likely to impact the confidentiality, integrity, or availability of federal customer data handled by the cloud service offering; this set of information resources is the cloud service offering.

Terms: `Agency`, `Certification Package`, `Cloud Service Offering`, `Federal Customer Data`, `Handle`, `Information Resource`, `Likely`, `Provider`

Affects: Providers

Note: Certain categories of cloud computing products and services are specified as entirely outside the scope of FedRAMP by the Director of the Office of Management and Budget. All such products and services are therefore not included in the cloud service offering for FedRAMP. For more, see https://fedramp.gov/scope.
Software produced by cloud service providers that is delivered separately for installation on agency systems and not operated in a shared responsibility model (typically including agents, application clients, mobile applications, etc. that are not fully managed by the cloud service provider) is not a cloud computing product or service and is entirely outside the scope of FedRAMP under the FedRAMP Certification Act. All such software is therefore not included in the cloud service offering for FedRAMP. For more, see https://fedramp.gov/scope.
All aspects of the cloud service offering are determined and maintained by the cloud service provider in accordance with related FedRAMP Certification rules and documented by the cloud service provider in their FedRAMP Certification Package.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `MAS-CSO-MDI` MUST — Metadata Inclusion

Providers MUST include metadata (including metadata about federal customer data) in the Minimum Assessment Scope ONLY IF MAS-CSO-IIR (Identify Information Resources) APPLIES.

Terms: `Federal Customer Data`, `Information Resource`, `Initial Incident Report (IIR)`, `Provider`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `MAS-CSO-SUP` MAY — Supplemental Information

Providers MAY include additional materials about other information resources that are not part of the cloud service offering in a FedRAMP Certification Package supplement; these resources will not be FedRAMP Certified and MUST be clearly marked and separated from the cloud service offering.

Terms: `Agency`, `Certification Package`, `Cloud Service Offering`, `FedRAMP Certified`, `Information Resource`, `Provider`

Affects: Providers

Note: This is intended to allow inclusion of things like security materials for apps, supplemental marketing collateral, and other information that is not part of the cloud service offering but may be useful to agencies.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `MAS-CSO-TPR` MUST — Third-Party Information Resources

Providers MUST address the potential impact to federal customer data from third-party information resources used by the cloud service offering, ONLY IF MAS-CSO-IIR (Identify Information Resources) APPLIES, by documenting the following information about each applicable third-party information resource:

Checklist items:
- General usage and configuration
- Explanation or justification for use
- Mitigation measures in place to reduce the potential impact to federal customer data
- Compensating controls in place to reduce the potential impact to federal customer data

Terms: `Cloud Service Offering`, `Federal Customer Data`, `Information Resource`, `Initial Incident Report (IIR)`, `Provider`, `Third-Party Information Resource`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.
