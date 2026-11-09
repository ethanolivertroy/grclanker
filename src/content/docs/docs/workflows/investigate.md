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

## What the prompt asks for

1. CMVP validation: active modules (`cmvp_search_modules`), historical or expired modules (`cmvp_search_historical`), and modules in the validation pipeline (`cmvp_search_in_process`). Empty phrase searches are broadened before reporting their limits; in-process records are not validated modules.
2. Vulnerability intelligence: KEV matches for the vendor or product (`kevs_search`), EPSS scores for any CVEs found (`kevs_get_epss`), ransomware linkage (`kevs_check_ransomware`), and recently added KEVs (`kevs_recent`).
3. Control mapping to NIST SC-13, SC-12, and SI-2 where relevant, each classified as Satisfied, Partially Satisfied, Not Satisfied, or Unable to Assess. Missing evidence is not proof that a control is absent.
4. Recommendations.

## What good output looks like

The prompt asks for:

- a risk summary of the cryptographic and vulnerability posture
- supported gaps: expired certificates, overdue remediation against an applicable deadline, and high-EPSS CVEs linked to the subject
- action items ordered by risk, with effort estimates only when their assumptions can be stated

Along the way it should report certificate numbers, validation status, FIPS standard, security level, sunset dates, CVE IDs, dated EPSS probabilities, ransomware association, and remediation due dates. Public vulnerability matches require product and version evidence before they establish an asset's exposure. A CISA due date does not establish that the organization adopted that deadline or missed it.

The answer should separate observed facts, missing evidence, assumptions, and proposed actions. A tool's empty result describes the query and catalog searched; it does not prove that no record or vulnerability exists. Framework mappings must come from retrieved evidence and should be looked up again if the source is uncertain after compaction or session restoration.
