# Posture Assessment

Assess the overall security and compliance posture of the specified vendor, product, module, or environment.

## Phase 1: Baseline

Establish:
1. What system is being assessed
2. Which frameworks matter most
3. Whether the focus is cryptography, vulnerabilities, or general posture

## Phase 2: Signal Gathering

Use the GRC tools to gather high-signal evidence:
1. CMVP certificate status
2. Historical or expired modules
3. KEV exposure
4. EPSS likelihood for any matched CVEs
5. Ransomware linkage where applicable
6. If FedRAMP or FedRAMP 20x framing matters, use `fedramp_check_sources`, `fedramp_search_frmr`, `fedramp_get_process`, `fedramp_get_requirement`, and `fedramp_get_ksi` so the posture narrative stays grounded in the official FedRAMP GitHub sources
7. If you need a practical provider or trust-center brief for a FedRAMP process or KSI, use `fedramp_assess_readiness`
8. If you need a concrete publication and evidence plan for a FedRAMP process or KSI, use `fedramp_plan_process_artifacts`
9. If the posture work is really about ADS or trust-center rollout, use `fedramp_plan_ads_package`
10. If the team is ready for a scaffold instead of another plan, use `fedramp_generate_ads_bundle`
11. If the team needs a public ADS trust-center site they can host in AWS, Azure, or GCP, use `fedramp_generate_ads_site`
12. If the subject is a Duo tenant, start with `duo_check_access`, then use the focused Duo assessment tools or `duo_export_audit_bundle` to ground posture claims in collected tenant evidence
13. If the subject is an Okta tenant, start with `okta_check_access`, then use the focused Okta assessment tools or `okta_export_audit_bundle` to ground posture claims in collected tenant evidence
14. SCF control language, crosswalks, and evidence-request guidance when framework interpretation matters
15. If the assessment needs to roll into OSCAL artifacts, use the OSCAL trestle tools to scaffold or validate the SSP, SAR, or POA&M workspace content

## Phase 3: Posture Classification

Summarize the subject as:
- Strong
- Mixed
- At Risk
- Critical

Justify the classification using evidence, not adjectives.

## Phase 4: Findings

Organize findings into:
1. **Cryptographic assurance**
2. **Exploit exposure**
3. **Framework impact**
4. **Operational risk**

Call out expired certifications, missing validation, overdue KEV remediation, and high-EPSS CVEs.

## Phase 5: Output

Return:
1. **Executive posture summary**
2. **Evidence table** — certificate numbers, CVEs, dates, and sources
3. **Top 3 risks**
4. **Top 3 next actions**
5. If requested, note the next OSCAL artifact to update: SSP, assessment results, or POA&M

Be direct. If the evidence is thin, say the assessment confidence is low.
