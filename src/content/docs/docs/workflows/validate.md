---
title: Validate
description: Answer a narrow FIPS validation question cleanly and directly.
---

`/validate` is the narrow rail for "is this module validated or not?" questions. It loads the shipped `cli/prompts/validate.md` prompt.

## Use it for

- active vs historical CMVP status
- module-level validation checks
- quick answers that still need evidence

## Start it

Inside a grclanker session, put the subject after the command:

```text
/validate BoringCrypto
```

From the shell, `grclanker validate "<subject>"` opens a session that starts with the same prompt and the subject filled in. The subject is the vendor, product, library, or appliance to check. Run `grclanker validate` on its own to name it in your first message instead.

In the older `v0.0.1` release bundle, text after `/validate` and arguments after `grclanker validate` are dropped, so upgrade to `v0.1.1` or send the subject in its own message there.

## What the prompt does

1. Active validation: `cmvp_search_modules`, then `cmvp_get_module` for promising certificate numbers.
2. Historical and drift check: `cmvp_search_historical` and `cmvp_search_in_process`, to decide whether the subject is actively validated, previously validated but expired, in process, or not found.
3. Compliance interpretation against SC-13 and SC-12, including the precise implication when validation is missing.

## Output shape

The answer should be short and exact:

- the validation status in one sentence
- evidence: certificate IDs and URLs, with module name, vendor, FIPS standard, overall level, validation date, and sunset date
- the compliance impact
- the recommended next step

The prompt forbids claiming a module is FIPS validated unless the certificate record was found.
