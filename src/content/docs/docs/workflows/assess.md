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

Inside a grclanker session, send `/assess` on its own, then name the system in your next message, for example:

```text
/assess
Our crypto and vulnerability posture for the payments service.
```

From the shell, `grclanker assess` opens a session that starts with the same prompt. Text typed after `/assess` on the same line is dropped in this release because the shipped prompt has no argument placeholder, so put the subject in its own message.

## What the prompt does

1. Baseline: what system is being assessed, which frameworks matter most, and whether the focus is cryptography, vulnerabilities, or general posture.
2. Signal gathering: CMVP status (active and historical), KEV exposure, EPSS likelihood, and ransomware linkage; the FedRAMP tools when FedRAMP framing matters; each integration's `*_check_access` tool followed by its `*_assess_*` tools or `*_export_audit_bundle`; Vanta audits; SCF control language; and the OSCAL tools when the assessment must roll into OSCAL artifacts.
3. Posture classification: Strong, Mixed, At Risk, or Critical, justified with evidence.
4. Findings grouped into cryptographic assurance, exploit exposure, framework impact, and operational risk, calling out expired certifications, missing validation, overdue KEV remediation, and high-EPSS CVEs.

## Output shape

The prompt asks for:

- an executive posture summary
- an evidence table with certificate numbers, CVEs, dates, and sources
- the top 3 risks
- the top 3 next actions
