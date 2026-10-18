---
title: "Service Configuration"
description: "Official Consolidated Rules summary for the SVC FedRAMP key security indicator domain."
---

> Generated from the official [FedRAMP/rules](https://github.com/FedRAMP/rules) GitHub repo.
>
> Source path: [`fedramp-consolidated-rules.json`](https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json) on `main` at blob `4ed99953efa5`.
>
> Consolidated Rules version: `2026.10.13.01` · upstream `last_updated`: `2026-10-13`.
>
> Supporting narrative documentation is available from the official `FedRAMP/2026-markdown` repository.

Domain code: `SVC` · Domain ID: `KSI-SVC` · Web slug: `service-configuration`

## Indicators

### `KSI-SVC-ACM`: Automating Configuration Management

The configuration of machine-based information resources is managed using automation and persistently reviewed for drift.

Mapped Rev5 controls: `ac-2.4`, `ac-6.8`, `cm-2`, `cm-2.2`, `cm-2.3`, `cm-6`, `cm-7.1`, `pl-10`, `pl-9`, `sa-5`, `sc-45`, `sc-45.1`, `sc-7.18`, `si-5`, `sr-10`

Terms: `Drift`, `Information Resource`, `Machine-Based (Information Resources)`, `Persistently`

Updates:
- 2026-10-13: Updated control mappings: added ac-6.8, sc-45, sc-45.1, sc-7.18.
- 2026-06-24: Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-SVC-ASM`: Automating Secret Management

Management, protection, and regular rotation of digital keys, certificates, and other secrets is automated and persistently reviewed.

Mapped Rev5 controls: `ac-17.2`, `ia-5.2`, `ia-5.6`, `sc-12`, `sc-12.1`, `sc-17`

Terms: `Persistently`, `Regularly`

Updates:
- 2026-10-13: Updated control mappings: added sc-12.1.
- 2026-06-24: Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-SVC-EIS`: Evaluating and Improving Security

Information resources are persistently evaluated for opportunities to improve security and those improvements are persistently made.

Mapped Rev5 controls: `ca-7.4`, `cm-12.1`, `cm-5.5`, `cm-7.1`, `ir-9.4`, `pl-8`, `ra-3`, `sc-39`, `sc-7`, `si-2.2`, `si-4`, `sr-10`

Terms: `Information Resource`, `Persistently`

Updates:
- 2026-10-13: Updated control mappings: added ca-7.4, cm-5.5, ir-9.4, ra-3; removed ma-2.
- 2026-06-24: Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-SVC-PRR`: Preventing Residual Risk

Varies by certification class:

- **Class B:** **Optional:** Plans, procedures, and the state of information resources are persistently reviewed after making changes to limit and remove unwanted residual elements that would likely negatively affect the confidentiality, integrity, or availability of federal customer data.
- **Class C:** Plans, procedures, and the state of information resources are persistently reviewed after making changes to limit and remove unwanted residual elements that would likely negatively affect the confidentiality, integrity, or availability of federal customer data.

Mapped Rev5 controls: `ac-19`, `ir-9.4`, `sc-12.1`, `sc-4`, `sc-7.18`

Terms: `Federal Customer Data`, `Information Resource`, `Likely`, `Persistently`

Updates:
- 2026-10-13: Updated control mappings: added ac-19, ir-9.4, sc-12.1, sc-7.18.
- 2026-06-24: Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-SVC-RUD`: Removing Unwanted Data

Varies by certification class:

- **Class B:** **Optional:** Unwanted federal customer data is removed promptly when requested by an agency in alignment with customer agreements, including from backups if appropriate; this typically applies when a customer spills information or when a customer seeks to remove information from a service due to a change in usage.
- **Class C:** Unwanted federal customer data is removed promptly when requested by an agency in alignment with customer agreements, including from backups if appropriate; this typically applies when a customer spills information or when a customer seeks to remove information from a service due to a change in usage.

Mapped Rev5 controls: `ir-9`, `si-12.3`, `si-18.4`, `si-8`, `si-8.2`

Terms: `Federal Customer Data`, `Promptly`

Updates:
- 2026-10-13: Updated control mappings: added ir-9, si-8, si-8.2.
- 2026-06-24: Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-SVC-SIN`: Securing Information

Information is encrypted or otherwise secured from unwanted access or modification.

Mapped Rev5 controls: `ac-11`, `ac-11.1`, `ac-17.2`, `ac-19.5`, `ac-21`, `cp-9.8`, `ir-9.4`, `sc-13`, `sc-20`, `sc-21`, `sc-22`, `sc-23`, `sc-28`, `sc-28.1`, `sc-4`, `sc-7.18`, `sc-8`, `sc-8.1`, `si-4.18`

Updates:
- 2026-10-13: Updated control mappings: added ac-11, ac-11.1, ac-19.5, ac-21, ir-9.4, sc-4, sc-7.18, si-4.18; removed ac-1.
- 2026-06-24: Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-SVC-VCM`: Validating Communications

Varies by certification class:

- **Class B:** **Optional:** The authenticity and integrity of communications between machine-based information resources is persistently validated using automation.
- **Class C:** The authenticity and integrity of communications between machine-based information resources is persistently validated using automation.

Mapped Rev5 controls: `ac-10`, `ac-17.4`, `ac-18`, `ac-19`, `sc-23`, `si-4.22`, `si-7.1`

Terms: `Information Resource`, `Machine-Based (Information Resources)`, `Persistently`, `Validation`

Updates:
- 2026-10-13: Updated control mappings: added ac-10, ac-17.4, ac-18, ac-19, si-4.22.
- 2026-06-24: Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-SVC-VRI`: Validating Resource Integrity

Use cryptographic methods to validate the integrity of machine-based information resources.

Mapped Rev5 controls: `ac-17.4`, `ac-18`, `ac-19`, `au-9.3`, `cm-14`, `cm-2.2`, `cm-8.3`, `sc-13`, `sc-23`, `si-7`, `si-7.1`, `si-7.15`, `sr-10`, `sr-11`

Terms: `Information Resource`, `Machine-Based (Information Resources)`, `Validation`

Updates:
- 2026-10-13: Updated control mappings: added ac-17.4, ac-18, ac-19, au-9.3, cm-14, si-7.15, sr-11.
- 2026-06-24: Official launch of the FedRAMP Consolidated Rules for 2026.
