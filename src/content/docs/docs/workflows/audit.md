---
title: Audit
description: Map gathered evidence to a requested framework and classify control status.
---

`/audit` is the workflow rail for turning evidence into framework language. It loads the shipped `cli/prompts/audit.md` prompt.

## Use it for

- mapping vulnerability and cryptography evidence to controls
- classifying each control as Satisfied, Partially Satisfied, Not Satisfied, or Unable to Assess
- producing a control-by-control readout and remediation plan instead of a generic summary

## Start it

Inside a grclanker session, send `/audit` on its own, then describe the scope in your next message, for example:

```text
/audit
Map our vulnerability evidence for the payments service to FedRAMP RA-5 and SI-2.
```

From the shell, `grclanker audit` opens a session that starts with the same prompt. Text typed after `/audit` on the same line is dropped in this release because the shipped prompt has no argument placeholder, so put the scope in its own message.

## What the prompt does

1. Scope lock: confirms the target, the frameworks in scope, the evidence boundary (documentation, live configuration, or both), and the output format.
2. Evidence collection: CMVP and KEV/EPSS lookups; the FedRAMP source, readiness, and ADS tools when FedRAMP is in scope; each integration's `*_check_access` tool followed by its `*_assess_*` tools or `*_export_audit_bundle` for the platform in scope; `vanta_list_audits` and `vanta_export_audit` for a Vanta audit; the `scf_*` tools for control language and crosswalks; and the `oscal_*` tools when the deliverable must become OSCAL.
3. Control mapping: at minimum SC-13, SC-12, SI-2, and RA-5, each with one of the four classifications above.
4. Prioritization by exploitability, compliance impact, operational blast radius, and remediation effort, using EPSS and KEV status where vulnerability data exists.

## Output shape

The prompt asks for:

- an audit summary: what was assessed and the overall posture
- control-by-control findings, each with its evidence
- critical gaps, highest risk first
- a remediation plan with concrete next actions and rough effort

When evidence is missing, it should say exactly what is missing and which artifact would close the gap, and mark unknowns as unknowns rather than inferring compliance.
