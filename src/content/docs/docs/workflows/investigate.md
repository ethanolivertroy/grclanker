---
title: Investigate
description: Trace crypto status, KEV exposure, EPSS likelihood, and ransomware linkage from one workflow rail.
---

`/investigate` is the current workflow rail for asking a focused exposure or validation question and keeping the companion on the evidence-gathering path.

## Use it for

- crypto validation status
- KEV checks
- EPSS likelihood
- ransomware-linked KEV review
- product, vendor, module, or CVE triage

## Examples

```text
/investigate BoringCrypto
/investigate CVE-2024-3094
/investigate whether vendor X appears in KEV and how exploitable that issue is
```

## What good output looks like

A strong answer should come back with concrete evidence, not hand-wavy posture language:

- exact cert or advisory identifiers
- current status
- confidence notes
- missing evidence called out plainly
