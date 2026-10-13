---
title: Investigate
description: Trace crypto status, KEV exposure, EPSS likelihood, and ransomware linkage from one workflow rail.
---

`/investigate` is the workflow rail for a focused exposure or validation question about a vendor, product, or module. It loads the shipped `cli/prompts/investigate.md` prompt, which keeps the companion on the evidence-gathering path.

## Start it

Inside a grclanker session, put the subject after the command:

```text
/investigate BoringCrypto
```

From the shell, `grclanker investigate "<subject>"` opens a session that starts with the same prompt and the subject filled in. Run `grclanker investigate` on its own to name the subject in your first message instead.

In the older `v0.0.1` release bundle, text after `/investigate` and arguments after `grclanker investigate` are dropped, so upgrade to `v0.1.1` or send the subject in its own message there.

## What the prompt asks for

1. CMVP validation: active modules (`cmvp_search_modules`), historical or expired modules (`cmvp_search_historical`), and modules in the validation pipeline (`cmvp_search_in_process`).
2. Vulnerability intelligence: KEV matches for the vendor or product (`kevs_search`), EPSS scores for any CVEs found (`kevs_get_epss`), ransomware linkage (`kevs_check_ransomware`), and recently added KEVs (`kevs_recent`).
3. Control mapping to NIST SC-13, SC-12, and SI-2, each classified as Satisfied, Partially Satisfied, Not Satisfied, or Unable to Assess.
4. Recommendations.

## What good output looks like

The prompt asks for:

- a risk summary of the cryptographic and vulnerability posture
- critical gaps: expired certificates, overdue KEV remediations, high-EPSS CVEs
- action items ordered by risk, with effort estimates

Along the way it should report certificate numbers, validation status, FIPS standard, security level, sunset dates, CVE IDs, EPSS probabilities, ransomware association, and remediation due dates, and say plainly when a tool returned nothing.
