---
title: "Monitoring, Logging, and Auditing: FedRAMP KSI Domain"
description: "Official Consolidated Rules summary for the MLA FedRAMP key security indicator domain."
---

> Generated from the official [FedRAMP/rules](https://github.com/FedRAMP/rules) GitHub repo.
>
> Source path: [`fedramp-consolidated-rules.json`](https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json) on `main` at blob `4ed99953efa5`.
>
> Consolidated Rules version: `2026.10.13.01` · upstream `last_updated`: `2026-10-13`.
>
> Supporting narrative documentation is available from the official `FedRAMP/2026-markdown` repository.

Domain code: `MLA` · Domain ID: `KSI-MLA` · Web slug: `monitoring-logging-and-auditing`

## Indicators

### `KSI-MLA-ALA`: Authorizing Log Access

Varies by certification class:

- **Class B:** **Optional:** A least-privileged, role and attribute-based, and just-in-time access authorization model is used and persistently reviewed for access to log data based on organizationally defined data sensitivity.
- **Class C:** A least-privileged, role and attribute-based, and just-in-time access authorization model is used and persistently reviewed for access to log data based on organizationally defined data sensitivity.

Mapped Rev5 controls: `au-12.3`, `au-6.7`, `si-11`

Terms: `Persistently`

Updates:
- 2026-10-13: Updated control mappings: added au-12.3, au-6.7.
- 2026-06-24: Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-MLA-EVC`: Evaluating Configurations

The configuration of machine-based information resources, especially infrastructure as code, is persistently evaluated and tested.

Mapped Rev5 controls: `ac-19`, `ca-7`, `cm-2`, `cm-6`, `cm-6.1`, `ra-3`, `si-7.7`

Terms: `Information Resource`, `Machine-Based (Information Resources)`, `Persistently`

Updates:
- 2026-10-13: Updated control mappings: added ac-19, cm-6.1, ra-3.
- 2026-06-24: Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-MLA-LET`: Logging Event Types

A list of information resources and event types that will be logged, monitored, and audited is maintained and persistently reviewed to ensure these activities occur.

Mapped Rev5 controls: `ac-17.1`, `ac-2.4`, `ac-20.1`, `ac-6.9`, `au-10`, `au-12`, `au-2`, `au-7`, `au-7.1`, `cm-5.1`, `ir-9.4`, `si-4.19`, `si-4.20`, `si-4.4`, `si-4.5`, `si-7.7`

Terms: `Information Resource`, `Persistently`

Updates:
- 2026-10-13: Updated control mappings: added au-10, au-7, cm-5.1, ir-9.4, si-4.19, si-4.20.
- 2026-06-24: Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-MLA-OSM`: Operating SIEM Capability

A Security Information and Event Management (SIEM) or similar system(s) is used and persistently reviewed for centralized, tamper-resistant logging of events, activities, and changes.

Mapped Rev5 controls: `ac-17.1`, `ac-20.1`, `au-11`, `au-12.1`, `au-2`, `au-3`, `au-3.1`, `au-4`, `au-5`, `au-5.1`, `au-6.1`, `au-6.3`, `au-6.4`, `au-6.5`, `au-7`, `au-7.1`, `au-8`, `au-9`, `ir-4.1`, `si-4.16`, `si-4.2`, `si-4.4`

Terms: `Persistently`

Updates:
- 2026-10-13: Updated control mappings: added au-12.1, au-5.1, au-6.4, au-6.5, si-4.16; removed si-7.7.
- 2026-06-24: Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-MLA-RVL`: Reviewing Logs

Logs are persistently reviewed and audited.

Mapped Rev5 controls: `ac-2.4`, `ac-6.9`, `au-2`, `au-6`, `au-6.1`, `au-7`, `ra-5.8`, `si-4`, `si-4.19`, `si-4.4`

Terms: `Persistently`

Updates:
- 2026-10-13: Updated control mappings: added au-7, ra-5.8, si-4.19.
- 2026-06-24: Official launch of the FedRAMP Consolidated Rules for 2026.
