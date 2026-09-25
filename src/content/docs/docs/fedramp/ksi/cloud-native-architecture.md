---
title: Cloud Native Architecture — FedRAMP KSI Domain
description: Official Consolidated Rules summary for the CNA FedRAMP key security indicator domain.
---

> Generated from the official [FedRAMP/rules](https://github.com/FedRAMP/rules) GitHub repo.
> Source path: [`fedramp-consolidated-rules.json`](https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json) on `main` at blob `7d628b63fdd9`.
> Consolidated Rules version: `2026.07.02.02` · upstream `last_updated`: `2026-07-02`.
> Supporting narrative documentation is available from the official `FedRAMP/2026-markdown` repository.

# Cloud Native Architecture

Domain code: `CNA` · Domain ID: `KSI-CNA` · Web slug: `cloud-native-architecture`

## Indicators

### `KSI-CNA-DFP` — Defining Functionality and Privileges

The functionality and privileges for infrastructure and services are strictly defined.

Mapped Rev5 controls: `cm-2`, `si-3`

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-CNA-EIS` — Enforcing Intended State

Varies by certification class:

- **Class B:** **Optional:** Automated services are used to persistently assess the security of all machine-based information resources and automatically enforce their intended operational state.
- **Class C:** Automated services are used to persistently assess the security of all machine-based information resources and automatically enforce their intended operational state.

Mapped Rev5 controls: `ca-2.1`, `ca-7.1`

Terms: `Information Resource`, `Machine-Based (Information Resources)`, `Persistently`

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-CNA-IBP` — Implementing Best Practices

The use and configuration of third-party machine-based information resources is persistently compared against the original provider's best practices and guidance.

Mapped Rev5 controls: `ac-17.3`, `cm-2`, `pl-10`

Terms: `Information Resource`, `Machine-Based (Information Resources)`, `Persistently`, `Provider`

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-CNA-MAT` — Minimizing Attack Surface

Machine-based information resources are persistently reviewed to ensure they have a minimal attack surface and that lateral movement is minimized if compromised.

Mapped Rev5 controls: `ac-17.3`, `ac-18.1`, `ac-18.3`, `ac-20.1`, `ca-9`, `sc-7.3`, `sc-7.4`, `sc-7.5`, `sc-7.8`, `sc-8`, `sc-10`, `si-10`, `si-11`, `si-16`

Terms: `Information Resource`, `Machine-Based (Information Resources)`, `Persistently`

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-CNA-OFA` — Optimizing for Availability

Machine-based information resources are persistently reviewed to ensure they are appropriately optimized for high availability and rapid recovery.

Terms: `Information Resource`, `Machine-Based (Information Resources)`, `Persistently`

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-CNA-RNT` — Restricting Network Traffic

Machine-based information resources are persistently reviewed to ensure they are appropriately configured to limit inbound and outbound network traffic.

Mapped Rev5 controls: `ac-17.3`, `ca-9`, `cm-7.1`, `sc-7.5`, `si-8`

Terms: `Information Resource`, `Machine-Based (Information Resources)`, `Persistently`

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-CNA-RVP` — Reviewing Protections

The effectiveness of protection against denial of service attacks and other unwanted activity for machine-based information resources is persistently reviewed.

Mapped Rev5 controls: `sc-5`, `si-8`, `si-8.2`

Terms: `Information Resource`, `Machine-Based (Information Resources)`, `Persistently`

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-CNA-ULN` — Using Logical Networking

Logical networking and related capabilities are used and persistently reviewed to enforce traffic flow controls.

Mapped Rev5 controls: `ac-12`, `ac-17.3`, `ca-9`, `sc-4`, `sc-7`, `sc-7.7`, `sc-8`, `sc-10`

Terms: `Persistently`

Recent update: 2026-06-24 — Official launch of the FedRAMP Consolidated Rules for 2026.
