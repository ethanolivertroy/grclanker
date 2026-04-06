---
title: Assess
description: Produce an evidence-backed posture readout with risks, ordering, and confidence notes.
---

`/assess` is the rail for a broader posture readout when you want prioritization, not just mapping.

## Use it for

- top-risk ordering
- confidence notes
- remediation sequence
- pulling multiple evidence points into one posture snapshot

## Examples

```text
/assess our crypto and vulnerability posture for this service
/assess the evidence and tell me what to fix first
```

## Output shape

The current release should answer with:

- the highest-risk issues first
- why those issues rank that way
- what evidence is strong vs weak
- what to remediate next
