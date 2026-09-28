---
title: Assess
description: Produce an evidence-backed posture readout with a posture rating, top risks, and next actions.
---

`/assess` is the rail for a broader posture readout when you want prioritization, not just mapping. It loads the shipped `cli/prompts/assess.md` prompt.

## Use it for

- an overall posture rating for a vendor, product, module, or environment
- top-risk ordering
- next actions
- pulling multiple evidence points into one posture snapshot

## Start it

Inside a grclanker session, put the subject after the command:

```text
/assess Our crypto and vulnerability posture for the payments service.
```

From the shell, `grclanker assess "<subject>"` opens a session that starts with the same prompt and the subject filled in. Run `grclanker assess` on its own to name the system in your first message instead.

In the `v0.0.1` release bundle, text after `/assess` and arguments after `grclanker assess` are dropped, so send the subject in its own message there.

## What the prompt does

1. Baseline: what system is being assessed, which frameworks matter most, and whether the focus is cryptography, vulnerabilities, or general posture.
2. Signal gathering:
   - CMVP status (active and historical), KEV exposure, EPSS likelihood, and ransomware linkage, plus the FedRAMP tools when FedRAMP framing matters.
   - For each platform in scope, the integration's `*_check_access` tool, then its `*_assess_*` tools or `*_export_audit_bundle`.
   - Two integrations differ. For operator-side Google Workspace investigation or raw evidence collection with the `gws` CLI installed, the prompt switches from the posture tools to `gws_ops_check_cli` and the focused `gws_ops_*` tools: `gws_ops_investigate_alerts`, `gws_ops_trace_admin_activity`, `gws_ops_review_tokens`, and `gws_ops_collect_evidence_bundle` for a separate operator evidence bundle. To reconcile posture claims with a Vanta audit, it uses `vanta_check_access`, then `vanta_list_audits` and `vanta_export_audit`; Vanta has no assessment tools.
   - SCF control language, and the OSCAL tools when the assessment must roll into OSCAL artifacts.
3. Posture classification: Strong, Mixed, At Risk, or Critical, justified with evidence.
4. Findings grouped into cryptographic assurance, exploit exposure, framework impact, and operational risk, calling out expired certifications, missing validation, overdue KEV remediation, and high-EPSS CVEs.

## Output shape

The prompt asks for:

- an executive posture summary
- an evidence table with certificate numbers, CVEs, dates, and sources
- the top 3 risks
- the top 3 next actions
