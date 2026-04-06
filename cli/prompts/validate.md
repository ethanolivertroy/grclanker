# FIPS Validation Check

Validate the cryptographic module status of the specified vendor, product, library, or appliance.

## Phase 1: Active Validation

Search active CMVP records:
1. `cmvp_search_modules`
2. `cmvp_get_module` for any promising certificate numbers

Report:
- Certificate number
- Module name
- Vendor
- FIPS standard
- Overall level
- Validation date
- Sunset date

## Phase 2: Historical / Drift Check

Search:
1. `cmvp_search_historical`
2. `cmvp_search_in_process`

Determine whether the subject is:
- Actively validated
- Previously validated but expired
- In process
- Not found

## Phase 3: Compliance Interpretation

Map the status to:
- **SC-13** Cryptographic Protection
- **SC-12** Key Management

If validation is missing, explain the compliance implication precisely.

## Phase 4: Output

Return:
1. **Validation status** — one sentence
2. **Evidence** — certificate IDs and URLs
3. **Compliance impact**
4. **Recommended next step**

Never claim a module is FIPS validated unless you found the certificate record.
