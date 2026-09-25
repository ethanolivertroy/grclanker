---
title: Service Configuration — FedRAMP KSI Domain
description: Official Consolidated Rules summary for the SVC FedRAMP key security indicator domain.
---

> Generated from the official [FedRAMP/rules](https://github.com/FedRAMP/rules) GitHub repo.
> Source path: [`fedramp-consolidated-rules.json`](https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json) on `main` at blob `7d628b63fdd9`.
> Consolidated Rules version: `2026.07.02.02` · upstream `last_updated`: `2026-07-02`.
> Supporting narrative documentation is available from the official `FedRAMP/2026-markdown` repository.

# Service Configuration

Domain code: `SVC` · Domain ID: `KSI-SVC` · Web slug: `service-configuration`

## Indicators

### `KSI-SVC-ACM` — Automating Configuration Management

The configuration of machine-based information resources is managed using automation and persistently reviewed for drift.

Mapped Rev5 controls: `ac-2.4`, `cm-2`, `cm-2.2`, `cm-2.3`, `cm-6`, `cm-7.1`, `pl-9`, `pl-10`, `sa-5`, `si-5`, `sr-10`

Terms: `Drift`, `Information Resource`, `Machine-Based (Information Resources)`, `Persistently`

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-SVC-ASM` — Automating Secret Management

Management, protection, and regular rotation of digital keys, certificates, and other secrets is automated and persistently reviewed.

Mapped Rev5 controls: `ac-17.2`, `ia-5.2`, `ia-5.6`, `sc-12`, `sc-17`

Terms: `Persistently`, `Regularly`

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-SVC-EIS` — Evaluating and Improving Security

Information resources are persistently evaluated for opportunities to improve security and those improvements are persistently made.

Mapped Rev5 controls: `cm-7.1`, `cm-12.1`, `ma-2`, `pl-8`, `sc-7`, `sc-39`, `si-2.2`, `si-4`, `sr-10`

Terms: `Information Resource`, `Persistently`

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-SVC-PRR` — Preventing Residual Risk

Varies by certification class:

- **Class B:** **Optional:** Plans, procedures, and the state of information resources are persistently reviewed after making changes to limit and remove unwanted residual elements that would likely negatively affect the confidentiality, integrity, or availability of federal customer data.
- **Class C:** Plans, procedures, and the state of information resources are persistently reviewed after making changes to limit and remove unwanted residual elements that would likely negatively affect the confidentiality, integrity, or availability of federal customer data.

Mapped Rev5 controls: `sc-4`

Terms: `Federal Customer Data`, `Information Resource`, `Likely`, `Persistently`

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-SVC-RUD` — Removing Unwanted Data

Varies by certification class:

- **Class B:** **Optional:** Unwanted federal customer data is removed promptly when requested by an agency in alignment with customer agreements, including from backups if appropriate; this typically applies when a customer spills information or when a customer seeks to remove information from a service due to a change in usage.
- **Class C:** Unwanted federal customer data is removed promptly when requested by an agency in alignment with customer agreements, including from backups if appropriate; this typically applies when a customer spills information or when a customer seeks to remove information from a service due to a change in usage.

Mapped Rev5 controls: `si-12.3`, `si-18.4`

Terms: `Agency`, `Federal Customer Data`, `Promptly`

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-SVC-SIN` — Securing Information

Information is encrypted or otherwise secured from unwanted access or modification.

Mapped Rev5 controls: `ac-1`, `ac-17.2`, `cp-9.8`, `sc-8`, `sc-8.1`, `sc-13`, `sc-20`, `sc-21`, `sc-22`, `sc-23`, `sc-28`, `sc-28.1`

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-SVC-VCM` — Validating Communications

Varies by certification class:

- **Class B:** **Optional:** The authenticity and integrity of communications between machine-based information resources is persistently validated using automation.
- **Class C:** The authenticity and integrity of communications between machine-based information resources is persistently validated using automation.

Mapped Rev5 controls: `sc-23`, `si-7.1`

Terms: `Information Resource`, `Machine-Based (Information Resources)`, `Persistently`, `Validation`

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-SVC-VRI` — Validating Resource Integrity

Use cryptographic methods to validate the integrity of machine-based information resources.

Mapped Rev5 controls: `cm-2.2`, `cm-8.3`, `sc-13`, `sc-23`, `si-7`, `si-7.1`, `sr-10`

Terms: `Information Resource`, `Machine-Based (Information Resources)`, `Validation`

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.
