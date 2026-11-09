# Vulnerability Investigation

Subject: $ARGUMENTS

Investigate the cryptographic and vulnerability posture of the specified vendor, product, or module.

Apply the phases relevant to the subject. Separate public reference records from evidence about the deployed asset; do not infer product/version or configuration details that were not supplied.

## Phase 1: Cryptographic Module Validation

Search NIST CMVP for the subject:
1. Search active FIPS validated modules (`cmvp_search_modules`)
2. Search historical/expired modules (`cmvp_search_historical`)
3. Check if any modules are in the validation pipeline (`cmvp_search_in_process`)

Report: certificate numbers, validation status, FIPS standard, security level, sunset dates.
If a narrow phrase search is empty, broaden the vendor/module query. Qualify no-match conclusions by the query and catalog; do not infer absent predecessors or certificate supersession. A pipeline entry is not a validation.

## Phase 2: Vulnerability Intelligence

Check for known exploited vulnerabilities:
1. Search CISA KEV catalog (`kevs_search`) for the vendor/product
2. Get EPSS scores (`kevs_get_epss`) for any CVEs found
3. Check for ransomware linkage (`kevs_check_ransomware`)
4. List recent catalog entries (`kevs_recent`) when relevant; verify each entry's vendor/product before associating it with the subject, since this tool's results are catalog-wide

Report: CVE IDs, EPSS exploit probabilities, ransomware association, remediation due dates.
Include EPSS score dates. Match product/version or deployment evidence before declaring an asset affected. Treat CISA due dates separately from an organization-specific remediation SLA.

## Phase 3: Compliance Assessment

Map findings to compliance controls:
- **NIST SC-13** (Cryptographic Protection): Are modules FIPS validated?
- **NIST SC-12** (Key Management): Are key management practices covered?
- **NIST SI-2** (Flaw Remediation): Are known vulnerabilities patched by due date?

Classify each control: Satisfied / Partially Satisfied / Not Satisfied / Unable to Assess.
Use Unable to Assess when required deployment or implementation evidence is missing. Public module validation alone does not establish approved operation or key management, and missing evidence does not establish an absent control.

## Phase 4: Recommendations

Synthesize findings into:
1. **Risk summary** — Overall cryptographic and vulnerability posture
2. **Critical gaps** — Any expired certs, overdue KEV remediations, high-EPSS CVEs
3. **Action items** — Prioritized proposals; give effort estimates only with sufficient context and stated assumptions
