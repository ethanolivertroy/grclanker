---
title: Validate
description: Answer a narrow FIPS validation question cleanly and directly.
---

`/validate` is the narrow rail for “is this module validated or not?” style questions.

## Use it for

- active vs historical CMVP status
- module-level validation checks
- quick answers that still need evidence

## Examples

```text
/validate BoringCrypto
/validate whether this module is active, historical, in process, or absent
```

## Output shape

The ideal answer is short and exact:

- certificate number if one exists
- standard generation when known
- status
- the caveat that the exact tested configuration still matters
