---
title: Monitoring, Logging, and Auditing — FedRAMP KSI Domain
description: Official Consolidated Rules summary for the MLA FedRAMP key security indicator domain.
---

> Generated from the official [FedRAMP/rules](https://github.com/FedRAMP/rules) GitHub repo.
> Source path: [`fedramp-consolidated-rules.json`](https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json) on `main` at blob `7d628b63fdd9`.
> Consolidated Rules version: `2026.07.02.02` · upstream `last_updated`: `2026-07-02`.
> Supporting narrative documentation is available from the official `FedRAMP/2026-markdown` repository.

# Monitoring, Logging, and Auditing

Domain code: `MLA` · Domain ID: `KSI-MLA` · Web slug: `monitoring-logging-and-auditing`

## Indicators

### `KSI-MLA-ALA` — Authorizing Log Access

Varies by certification class:

- **Class B:** **Optional:** A least-privileged, role and attribute-based, and just-in-time access authorization model is used and persistently reviewed for access to log data based on organizationally defined data sensitivity.
- **Class C:** A least-privileged, role and attribute-based, and just-in-time access authorization model is used and persistently reviewed for access to log data based on organizationally defined data sensitivity.

Mapped Rev5 controls: `si-11`

Terms: `Persistently`

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-MLA-EVC` — Evaluating Configurations

The configuration of machine-based information resources, especially infrastructure as code, is persistently evaluated and tested.

Mapped Rev5 controls: `ca-7`, `cm-2`, `cm-6`, `si-7.7`

Terms: `Information Resource`, `Machine-Based (Information Resources)`, `Persistently`

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-MLA-LET` — Logging Event Types

A list of information resources and event types that will be logged, monitored, and audited is maintained and persistently reviewed to ensure these activities occur.

Mapped Rev5 controls: `ac-2.4`, `ac-6.9`, `ac-17.1`, `ac-20.1`, `au-2`, `au-7.1`, `au-12`, `si-4.4`, `si-4.5`, `si-7.7`

Terms: `Information Resource`, `Persistently`

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-MLA-OSM` — Operating SIEM Capability

A Security Information and Event Management (SIEM) or similar system(s) is used and persistently reviewed for centralized, tamper-resistant logging of events, activities, and changes.

Mapped Rev5 controls: `ac-17.1`, `ac-20.1`, `au-2`, `au-3`, `au-3.1`, `au-4`, `au-5`, `au-6.1`, `au-6.3`, `au-7`, `au-7.1`, `au-8`, `au-9`, `au-11`, `ir-4.1`, `si-4.2`, `si-4.4`, `si-7.7`

Terms: `Persistently`

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-MLA-RVL` — Reviewing Logs

Logs are persistently reviewed and audited.

Mapped Rev5 controls: `ac-2.4`, `ac-6.9`, `au-2`, `au-6`, `au-6.1`, `si-4`, `si-4.4`

Terms: `Persistently`

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.
