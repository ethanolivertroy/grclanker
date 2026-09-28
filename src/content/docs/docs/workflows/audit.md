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

Inside a grclanker session, put the scope after the command:

```text
/audit Map our vulnerability evidence for the payments service to FedRAMP RA-5 and SI-2.
```

From the shell, `grclanker audit "<scope>"` opens a session that starts with the same prompt and the scope filled in. Run `grclanker audit` on its own to describe the scope in your first message instead.

In the `v0.0.1` release bundle, text after `/audit` and arguments after `grclanker audit` are dropped, so send the scope in its own message there.

## What the prompt does

1. Scope lock: confirms the target, the frameworks in scope, the evidence boundary (documentation, live configuration, or both), and the output format.
2. Evidence collection:
   - CMVP and KEV/EPSS lookups, plus the FedRAMP source, readiness, and ADS tools when FedRAMP is in scope.
   - For the platform in scope, the integration's `*_check_access` tool, then its `*_assess_*` tools or `*_export_audit_bundle`.
   - Two integrations differ. For operator-side Google Workspace investigation or raw evidence collection with the `gws` CLI installed, the prompt uses `gws_ops_check_cli`, then `gws_ops_investigate_alerts`, `gws_ops_trace_admin_activity`, or `gws_ops_review_tokens`, or `gws_ops_collect_evidence_bundle` for a separate operator evidence bundle. Vanta has no assessment tools: a Vanta audit starts with `vanta_check_access`, then uses `vanta_list_audits` and `vanta_export_audit` to pull an offline evidence package.
   - The `scf_*` tools for control language and crosswalks, and the `oscal_*` tools when the deliverable must become OSCAL.
3. Control mapping: at minimum SC-13, SC-12, SI-2, and RA-5, each with one of the four classifications above.
4. Prioritization by exploitability, compliance impact, operational blast radius, and remediation effort, using EPSS and KEV status where vulnerability data exists.

## Output shape

The prompt asks for:

- an audit summary: what was assessed and the overall posture
- control-by-control findings, each with its evidence
- critical gaps, highest risk first
- a remediation plan with concrete next actions and rough effort

When evidence is missing, it should say exactly what is missing and which artifact would close the gap, and mark unknowns as unknowns rather than inferring compliance.
