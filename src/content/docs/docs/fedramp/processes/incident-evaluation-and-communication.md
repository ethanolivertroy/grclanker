---
title: Incident Evaluation and Communication — FedRAMP Process
description: Official Consolidated Rules summary for the IEC FedRAMP process, including applicability and requirements.
---

> Generated from the official [FedRAMP/rules](https://github.com/FedRAMP/rules) GitHub repo.
> Source path: [`fedramp-consolidated-rules.json`](https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json) on `main` at blob `7d628b63fdd9`.
> Consolidated Rules version: `2026.07.02.02` · upstream `last_updated`: `2026-07-02`.
> Supporting narrative documentation is available from the official `FedRAMP/2026-markdown` repository.

# Incident Evaluation and Communication

Short name: `IEC` · Process ID: `IEC` · Web slug: `incident-evaluation-and-communication`

Applies to: `both`
Status: `stable`


Official page: [https://www.fedramp.gov/2026/reference/incident-evaluation-and-communication/](https://www.fedramp.gov/2026/reference/incident-evaluation-and-communication/)

## Effective Status

- 20x: required · Consolidated Rules for 2026 · obtain 2026-07-04 · grace through 2027-01-01
- Rev5: required · Consolidated Rules for 2026 · obtain 2027-01-01 · grace through 2027-06-01
- Shared requirements: 8

## Purpose

The Incident Evaluation and Communication rules explain how providers must communicate incident information to FedRAMP and government customers when they are affected by an incident or likely to be affected by an incident.

## Rule Subsets

- `CSO` — General Provider Responsibilities: These rules apply to providers with FedRAMP Certifications of any type. · types: 20x, Rev5 · classes: B, C, D
- `FRP` — FedRAMP Responsibilities: These rules apply to FedRAMP. · types: 20x, Rev5 · classes: B, C, D

## Requirements and Recommendations

## BOTH

### `IEC-CSO-AIR` SHOULD — Automated Incident Reporting

Providers SHOULD use automation to minimize human intervention in the process of reporting FedRAMP Reportable Incidents to all affected parties.

Terms: `All Affected Parties`, `FedRAMP Reportable Incident`, `Incident`, `Provider`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `IEC-CSO-DPR` MUST — Default PAIN Rating

Providers MUST treat FedRAMP Reportable Incidents as if they have a Potential Agency Impact N-rating (PAIN) of 5 UNLESS they promptly estimate the PAIN rating following the rule in IEC-CSO-EFI (Estimate Federal Impact).

Terms: `Agency`, `FedRAMP Reportable Incident`, `Incident`, `Potential Agency Impact`, `Promptly`, `Provider`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `IEC-CSO-EFI` SHOULD — Estimate Federal Impact

Providers SHOULD promptly estimate the likely adverse impact of an incident on agency customers to assign a Potential Agency Impact N-rating; this step is called Incident Rating.

Checklist items:
- **N1** for a likely minimal customer effect on 1 or more agencies.
- **N2** for a likely narrow customer effect on 1 or more agencies.
- **N3** for a likely disruptive customer effect on 1 agency.
- **N4** for a likely debilitating customer effect on 1 agency or a likely disruptive customer effect on more than 1 agency.
- **N5** for a likely debilitating customer effect on more than 1 agency.

Terms: `Agency`, `Debilitating Customer Effect`, `Disruptive Customer Effect`, `Incident`, `Likely`, `Minimal Customer Effect`, `Narrow Customer Effect`, `Potential Agency Impact`, `Promptly`, `Provider`

Affects: Providers

Note: All incidents must be assigned a default PAIN-5 as required by IEC-CSO-DPR (Default PAIN Rating) if this step is not completed.

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `IEC-CSO-EFR` MUST — Evaluate FedRAMP Reportability

Providers MUST promptly evaluate incidents to determine if they affect confidentiality or integrity of federal customer data or are likely to affect confidentiality or integrity of federal customer data; such incidents are FedRAMP Reportable Incidents and must be reported following the FedRAMP Incident Evaluation and Communication rules.

Terms: `FedRAMP Reportable Incident`, `Federal Customer Data`, `Incident`, `Likely`, `Promptly`, `Provider`

Affects: Providers

Recent update: 2026-07-02 — Update terminology from "Response" to "Communication" in FedRAMP Incident Evaluation rules.

### `IEC-CSO-FIR` MUST — Final Incident Report

Varies by certification class:

- **Class A MUST:** Providers with Class A Certifications MUST responsibly notify all affected parties by providing a Final Incident Report once the incident has been resolved and recovery is complete, including final updates to all previously reported information.
- **Class B MUST:** Providers with Class B Certifications MUST responsibly notify all affected parties by providing a Final Incident Report once the incident has been resolved and recovery is complete, including final updates to all previously reported information.
- **Class C MUST:** Providers with Class C Certifications MUST responsibly notify all affected parties by providing a Final Incident Report once the incident has been resolved and recovery is complete, including final updates to all previously reported information.
- **Class D MUST:** Providers with Class D Certifications MUST responsibly notify all affected parties by providing a Final Incident Report once the incident has been resolved and recovery is complete, including final updates to all previously reported information.

Terms: `All Affected Parties`, `Final Incident Report (FIR)`, `Incident`, `Provider`, `Responsibly`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `IEC-CSO-IIR` VARIES BY CLASS — Initial Incident Report

Varies by certification class:

- **Class A SHOULD:** Providers with Class A Certifications SHOULD responsibly notify all affected parties after identifying FedRAMP Reportable Incidents by providing an Initial Incident Report with as much of the following information that is available at the time of reporting and/or the current relevant status for each item:
- **Class B MUST:** Providers with Class B Certifications MUST responsibly notify all affected parties after identifying FedRAMP Reportable Incidents by providing an Initial Incident Report with as much of the following information that is available at the time of reporting and/or the current relevant status for each item:
- **Class C MUST:** Providers with Class C Certifications MUST responsibly notify all affected parties after identifying FedRAMP Reportable Incidents by providing an Initial Incident Report with as much of the following information that is available at the time of reporting and/or the current relevant status for each item:
- **Class D MUST:** Providers with Class D Certifications MUST responsibly notify all affected parties after identifying FedRAMP Reportable Incidents by providing an Initial Incident Report with as much of the following information that is available at the time of reporting and/or the current relevant status for each item:

Checklist items:
- Class A: Contact information for the federal incident response coordinator
- Class A: Provider's internally assigned tracking identifier
- Class A: Description of the incident
- Class A: Timeline of the incident, including start time, time and source of detection, time of completed FedRAMP Reportable Incident evaluation, and other major incident milestones determined by the provider
- Class A: Historically and currently estimated Potential Agency Impact N-rating (PAIN) of the incident, including an explanation of the evaluation following the requirements in IEC-CSO-EFI (Estimate Federal Impact) (if applicable)
- Class A: Functional impact to federal agency customers (include impact to confidentiality and/or integrity and the impacted federal customer data types)
- Class A: Estimated recovery plan, milestones, and timelines
- Class A: List of likely affected customer agencies
- Class B: Contact information for the federal incident response coordinator.
- Class B: Provider's internally assigned tracking identifier
- Class B: Description of the incident
- Class B: Timeline of the incident, including start time, time and source of detection, time of completed FedRAMP Reportable Incident evaluation, and other major incident milestones determined by the provider
- Class B: Historically and currently estimated Potential Agency Impact N-rating (PAIN) of the incident, including an explanation of the evaluation following the requirements in IEC-CSO-EFI (Estimate Federal Impact) (if applicable)
- Class B: Functional impact to federal agency customers (include impact to confidentiality and/or integrity and the impacted federal customer data types)
- Class B: Estimated recovery plan, milestones, and timelines
- Class B: List of likely affected customer agencies
- Class C: Contact information for the federal incident response coordinator.
- Class C: Provider's internally assigned tracking identifier
- Class C: Description of the incident
- Class C: Timeline of the incident, including start time, time and source of detection, time of completed FedRAMP Reportable Incident evaluation, and other major incident milestones determined by the provider
- Class C: Historically and currently estimated Potential Agency Impact N-rating (PAIN) of the incident, including an explanation of the evaluation following the requirements in IEC-CSO-EFI (Estimate Federal Impact) (if applicable)
- Class C: Functional impact to federal agency customers (include impact to confidentiality and/or integrity and the impacted federal customer data types)
- Class C: Estimated recovery plan, milestones, and timelines
- Class C: List of likely affected customer agencies
- Class D: Contact information for the federal incident response coordinator.
- Class D: Provider's internally assigned tracking identifier
- Class D: Description of the incident
- Class D: Timeline of the incident, including start time, time and source of detection, time of completed FedRAMP Reportable Incident evaluation, and other major incident milestones determined by the provider
- Class D: Historically and currently estimated Potential Agency Impact N-rating (PAIN) of the incident, including an explanation of the evaluation following the requirements in IEC-CSO-EFI (Estimate Federal Impact) (if applicable)
- Class D: Functional impact to federal agency customers (include impact to confidentiality and/or integrity and the impacted federal customer data types)
- Class D: Estimated recovery plan, milestones, and timelines
- Class D: List of likely affected customer agencies

Terms: `All Affected Parties`, `FedRAMP Reportable Incident`, `Incident`, `Initial Incident Report (IIR)`, `Provider`, `Responsibly`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `IEC-CSO-OIR` VARIES BY CLASS — Ongoing Incident Reports

Varies by certification class:

- **Class A SHOULD:** Providers with Class A Certifications SHOULD responsibly notify all affected parties of ongoing activity as new information becomes available during incident response for FedRAMP Reportable Incidents, including updates (or lack of updates) to all previously reported information and as much of the the following additional information that is available and/or the current relevant status for each item:
- **Class B MUST:** Providers with Class B Certifications MUST responsibly notify all affected parties of ongoing activity as new information becomes available during incident response for FedRAMP Reportable Incidents, including updates (or lack of updates) to all previously reported information and as much of the the following additional information that is available and/or the current relevant status for each item:
- **Class C MUST:** Providers with Class C Certifications MUST responsibly notify all affected parties of ongoing activity as new information becomes available during incident response for FedRAMP Reportable Incidents, including updates (or lack of updates) to all previously reported information and as much of the the following additional information that is available and/or the current relevant status for each item:
- **Class D MUST:** Providers with Class D Certifications MUST responsibly notify all affected parties of ongoing activity as new information becomes available during incident response for FedRAMP Reportable Incidents, including updates (or lack of updates) to all previously reported information and as much of the the following additional information that is available and/or the current relevant status for each item:

Checklist items:
- Class A: Observed incident activity
- Class A: Indicators of compromise
- Class A: Related Common Vulnerabilities and Exposures (CVE) identifier (if applicable)
- Class A: Root cause
- Class A: Response and recovery activities
- Class B: Observed incident activity
- Class B: Indicators of compromise
- Class B: Related Common Vulnerabilities and Exposures (CVE) identifier, if applicable
- Class B: Root cause
- Class B: Response and recovery activities
- Class C: Observed incident activity
- Class C: Indicators of compromise
- Class C: Related Common Vulnerabilities and Exposures (CVE) identifier, if applicable
- Class C: Root cause
- Class C: Response and recovery activities
- Class D: Observed incident activity
- Class D: Indicators of compromise
- Class D: Related Common Vulnerabilities and Exposures (CVE) identifier, if applicable
- Class D: Root cause
- Class D: Response and recovery activities

Terms: `All Affected Parties`, `FedRAMP Reportable Incident`, `Incident`, `Provider`, `Responsibly`, `Vulnerability Response`

Affects: Providers

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `IEC-FRP-ORV` MUST — Ongoing Review

FedRAMP MUST periodically review FedRAMP Incident Evaluation and Communication implementation with providers based on lack of reporting or other information.

Terms: `Incident`, `Provider`

Affects: FedRAMP

Recent update: 2026-07-02 — Update terminology from "Response" to "Communication" in FedRAMP Incident Evaluation rules.
