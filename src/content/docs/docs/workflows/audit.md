---
title: Audit
description: Map gathered evidence to a requested framework and classify control status.
---

`/audit` is the workflow rail for turning evidence into framework language.

## Use it for

- mapping vulnerability evidence to controls
- classifying satisfied, partial, absent, or unverifiable
- generating a tighter control-oriented readout instead of a generic summary

## Examples

```text
/audit map our vuln evidence to FedRAMP RA-5
/audit classify this crypto evidence against NIST 800-53 SC-13
```

## Output shape

The current release is strongest when the answer includes:

- the requested framework and control identifiers
- the evidence used
- a clear classification
- the reason for that classification
- any evidence gaps that block a stronger conclusion
