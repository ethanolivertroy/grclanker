---
title: Validate
description: Answer a narrow FIPS validation question cleanly and directly.
---

`/validate` checks CMVP records for a narrow module-validation question. It loads the shipped `cli/prompts/validate.md` prompt.

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

## What the prompt does

1. Active validation: `cmvp_search_modules`, then `cmvp_get_module` for promising certificate numbers.
2. Historical and drift check: `cmvp_search_historical` and `cmvp_search_in_process`, to report the status of matching records. If a phrase search returns no matches, broaden it to the vendor or module name before reporting what was not found in the searched catalogs. An in-process record is not a validation.
3. Compliance interpretation against SC-13 and SC-12 where the evidence supports it. A certificate establishes the listed module's validation, not that a deployment uses its approved version, operating environment, or configuration. Missing deployment evidence remains Unable to Assess.

## Output shape

The answer should be short and exact:

- the matching record's validation status, or a query-qualified statement that no record was found
- evidence: certificate IDs and URLs, with module name, vendor, FIPS standard, overall level, validation date, and sunset date
- the compliance impact
- the recommended next step

The prompt forbids claiming a module is FIPS validated unless the certificate record was found. It also forbids inferring a predecessor or supersession relationship from a shared vendor, module name, or certificate number alone. Recommendations should name the evidence needed next. Ground operational steps in applicable documentation and state assumptions for any effort estimate.
