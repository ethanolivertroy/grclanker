# Vulnerability Investigation

Investigate the cryptographic and vulnerability posture of the specified vendor, product, or module.

## Phase 1: Cryptographic Module Validation

Search NIST CMVP for the subject:
1. Search active FIPS validated modules (`cmvp_search_modules`)
2. Search historical/expired modules (`cmvp_search_historical`)
3. Check if any modules are in the validation pipeline (`cmvp_search_in_process`)

Report: certificate numbers, validation status, FIPS standard, security level, sunset dates.

## Phase 2: Vulnerability Intelligence

Check for known exploited vulnerabilities:
1. Search CISA KEV catalog (`kevs_search`) for the vendor/product
2. Get EPSS scores (`kevs_get_epss`) for any CVEs found
3. Check for ransomware linkage (`kevs_check_ransomware`)
4. List any recently added KEVs for the vendor (`kevs_recent`)

Report: CVE IDs, EPSS exploit probabilities, ransomware association, remediation due dates.

## Phase 3: Compliance Assessment

Map findings to compliance controls:
- **NIST SC-13** (Cryptographic Protection): Are modules FIPS validated?
- **NIST SC-12** (Key Management): Are key management practices covered?
- **NIST SI-2** (Flaw Remediation): Are known vulnerabilities patched by due date?

Classify each control: Satisfied / Partially Satisfied / Not Satisfied / Unable to Assess.

## Phase 4: Recommendations

Synthesize findings into:
1. **Risk summary** — Overall cryptographic and vulnerability posture
2. **Critical gaps** — Any expired certs, overdue KEV remediations, high-EPSS CVEs
3. **Action items** — Prioritized by risk, with effort estimates
