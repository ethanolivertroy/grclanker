# FIPS Validation Check

Subject: $ARGUMENTS

Validate the cryptographic module status of the specified vendor, product, library, or appliance.

Keep catalog evidence separate from deployment evidence. Record the exact query, catalog, and certificate used; a public module record alone does not establish how the subject is deployed.

## Phase 1: Active Validation

Search active CMVP records:
1. `cmvp_search_modules`
2. `cmvp_get_module` for any promising certificate numbers

Searches match one phrase. If a full product/version query returns nothing, retry a broader vendor or module name before concluding that no matching record was found. Distinguish total catalog size, total matches, and records returned.

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

Qualify "Not found" by the queries and catalogs actually read. An empty phrase search does not establish that the vendor has no historical predecessors or validated modules. Report the record's status precisely; in-process is not validated. Do not claim direct supersession between certificates without an explicit source for that relationship.

## Phase 3: Compliance Interpretation

Map the status to:
- **SC-13** Cryptographic Protection
- **SC-12** Key Management

If validation or deployment evidence is missing, identify that gap. Use Unable to Assess for deployment-specific SC-13 or SC-12 outcomes that the available evidence cannot establish. A certificate does not prove approved operating configuration or key-management practices. Do not invent operational checks, product requirements, or effort estimates; proposals need applicable documentation and estimates need stated assumptions.

## Phase 4: Output

Return:
1. **Validation status** — one sentence
2. **Evidence** — certificate IDs and URLs
3. **Compliance impact**
4. **Recommended next step**

Never claim a module is FIPS validated unless you found the certificate record.
