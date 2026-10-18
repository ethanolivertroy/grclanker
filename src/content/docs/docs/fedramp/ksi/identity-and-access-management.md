---
title: "Identity and Access Management"
description: "Official Consolidated Rules summary for the IAM FedRAMP key security indicator domain."
---

> Generated from the official FedRAMP Consolidated Rules `2026.10.13.01`, last updated upstream on 2026-10-13. [Source details](#source)

## At a Glance

- Applies to: 20x only
- Indicators: 6
- Status: `stable`
- Domain ID: `KSI-IAM`

## Indicators

### `KSI-IAM-AAM`: Automating Account Management

The lifecycle and privileges of all accounts, roles, and groups are securely managed using automation.

Mapped Rev5 controls: `ac-2.13`, `ac-2.2`, `ac-2.3`, `ac-6.7`, `ia-12`, `ia-12.2`, `ia-12.3`, `ia-12.5`, `ia-4.4`, `ia-8.4`

Updates:
- 2026-10-13: Updated control mappings: added ia-8.4.
- 2026-06-24: Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-IAM-APM`: Adopting Passwordless Methods

Secure passwordless methods are used for user authentication and authorization when feasible, otherwise strong passwords with phishing-resistant MFA is used.

Mapped Rev5 controls: `ac-2`, `ac-3`, `ia-2`, `ia-2.1`, `ia-2.2`, `ia-2.6`, `ia-2.8`, `ia-5`, `ia-5.1`, `ia-5.2`, `ia-5.6`, `ia-5.8`, `ia-6`, `ia-8`, `ia-8.2`, `ia-8.4`, `sc-23`

Updates:
- 2026-10-13: Updated control mappings: added ia-2.6, ia-5.8, ia-8.2, ia-8.4.
- 2026-06-24: Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-IAM-ELP`: Ensuring Least Privilege

Identity and access management measures are used and persistently reviewed to ensure each user or device can only access the resources they need.

Mapped Rev5 controls: `ac-12`, `ac-14`, `ac-17`, `ac-17.1`, `ac-17.2`, `ac-17.3`, `ac-18.4`, `ac-2.11`, `ac-2.5`, `ac-2.6`, `ac-2.7`, `ac-2.9`, `ac-20`, `ac-20.1`, `ac-21`, `ac-3`, `ac-4`, `ac-6`, `ac-6.3`, `ac-6.8`, `au-12.3`, `au-6.7`, `cm-2.7`, `cm-5.1`, `cm-5.5`, `cm-7.2`, `cm-9`, `ia-11`, `ia-2`, `ia-3`, `ia-4`, `ia-4.4`, `ia-5.2`, `ia-5.6`, `ir-4.6`, `ir-9.4`, `ps-2`, `ps-3`, `ps-4`, `ps-5`, `ps-6`, `ra-5.5`, `sc-2`, `sc-20`, `sc-21`, `sc-22`, `sc-23`, `sc-3`, `sc-39`, `sc-4`, `si-3`, `si-4.19`

Terms: `Persistently`

Updates:
- 2026-10-13: Updated control mappings: added ac-18.4, ac-2.11, ac-2.7, ac-2.9, ac-21, ac-6.3, ac-6.8, au-12.3, au-6.7, cm-5.1, cm-5.5, cm-7.2, ir-4.6, ir-9.4, ra-5.5, sc-2, sc-3, si-4.19.
- 2026-06-24: Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-IAM-JIT`: Authorizing Just-in-Time

A least-privileged, role and attribute-based, and just-in-time security authorization model is used and persistently reviewed for all user and non-user accounts and services.

Mapped Rev5 controls: `ac-17`, `ac-17.4`, `ac-2`, `ac-2.1`, `ac-2.11`, `ac-2.2`, `ac-2.3`, `ac-2.4`, `ac-2.6`, `ac-2.7`, `ac-20.1`, `ac-21`, `ac-3`, `ac-4`, `ac-5`, `ac-6`, `ac-6.1`, `ac-6.10`, `ac-6.2`, `ac-6.3`, `ac-6.5`, `ac-6.7`, `ac-6.8`, `ac-6.9`, `ac-7`, `au-10`, `au-12.3`, `au-9.4`, `ca-3.6`, `cm-5`, `cm-5.1`, `cm-5.5`, `cm-7`, `cm-7.2`, `cm-7.5`, `cm-9`, `ia-4`, `ia-4.4`, `ia-7`, `ir-4.6`, `ps-2`, `ps-3`, `ps-4`, `ps-5`, `ps-6`, `ps-9`, `ra-5.5`, `sc-2`, `sc-23`, `sc-3`, `sc-39`

Terms: `Persistently`

Updates:
- 2026-10-13: Updated control mappings: added ac-17.4, ac-2.11, ac-2.7, ac-21, ac-6.3, ac-6.8, au-10, au-12.3, ca-3.6, cm-5.1, cm-5.5, ir-4.6, sc-3.
- 2026-06-24: Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-IAM-SNU`: Securing Non-User Authentication

Appropriately secure authentication methods are used and persistently reviewed for non-user accounts and services.

Mapped Rev5 controls: `ac-2`, `ac-2.2`, `ac-2.9`, `ac-4`, `ac-6.5`, `au-10`, `ia-2.5`, `ia-3`, `ia-5.2`, `ra-5.5`

Terms: `Persistently`

Updates:
- 2026-10-13: Updated control mappings: added ac-2.9, au-10, ia-2.5.
- 2026-06-24: Official launch of the FedRAMP Consolidated Rules for 2026.

### `KSI-IAM-SUS`: Responding to Suspicious Activity

Accounts with privileged access are disabled or otherwise secured in response to suspicious activity.

Mapped Rev5 controls: `ac-2`, `ac-2.1`, `ac-2.11`, `ac-2.12`, `ac-2.13`, `ac-2.3`, `ac-7`, `au-6.5`, `cm-5.1`, `cm-6.2`, `ir-4.2`, `ir-4.6`, `ps-4`, `ps-8`, `si-4`, `si-4.1`, `si-4.19`, `si-4.20`, `si-4.22`, `si-4.4`

Terms: `Vulnerability Response`

Updates:
- 2026-10-13: Updated control mappings: added ac-2.11, ac-2.12, au-6.5, cm-5.1, cm-6.2, ir-4.2, ir-4.6, si-4, si-4.1, si-4.19, si-4.20, si-4.22, si-4.4.
- 2026-06-24: Official launch of the FedRAMP Consolidated Rules for 2026.

## Source

- Generated from the official [FedRAMP/rules](https://github.com/FedRAMP/rules) GitHub repo.
- Source path: [`fedramp-consolidated-rules.json`](https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json) on `main` at blob `4ed99953efa5`.
- Consolidated Rules version: `2026.10.13.01` · upstream `last_updated`: `2026-10-13`.
- Supporting narrative documentation is available from the official `FedRAMP/2026-markdown` repository.
