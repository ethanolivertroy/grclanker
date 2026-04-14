# Compliance Audit

Run a structured compliance audit for the specified system, product, or deployment.

## Phase 1: Scope Lock

Confirm:
1. Target environment, product, or vendor
2. Framework(s) in scope
3. Evidence boundary: documentation only, live config only, or both
4. Required output format: executive summary, control matrix, or remediation plan

## Phase 2: Evidence Collection

Use the available GRC tools first:
1. Search CMVP validation status where cryptography is in scope
2. Search KEV and EPSS data for active exploit pressure
3. If FedRAMP or FedRAMP 20x is in scope, start with `fedramp_check_sources`, then use `fedramp_search_frmr`, `fedramp_get_process`, `fedramp_get_requirement`, and `fedramp_get_ksi` to ground your interpretation in the official FedRAMP GitHub sources
4. When you need a practical operator brief instead of raw source data, use `fedramp_assess_readiness` on the relevant process or KSI
5. When you need to turn a FedRAMP process into a concrete publishing and evidence plan, use `fedramp_plan_process_artifacts`
6. If the scope centers on Authorization Data Sharing or trust-center rollout, use `fedramp_plan_ads_package`
7. If you want a working ADS starter scaffold instead of only a plan, use `fedramp_generate_ads_bundle`
8. If the team needs a public, customer-owned trust-center site they can deploy to AWS, Azure, or GCP, use `fedramp_generate_ads_site`
9. If the scope is a Duo tenant, start with `duo_check_access`, then run the focused Duo assessment that matches the question before falling back to `duo_export_audit_bundle`
10. If the scope is an Okta tenant, start with `okta_check_access`, then run the focused assessment that matches the question before falling back to `okta_export_audit_bundle`
11. If the scope is a Vanta audit, start with `vanta_check_access`, then use `vanta_list_audits` and `vanta_export_audit` to pull an offline evidence package before classifying controls
12. If you need control language, crosswalk mappings, or artifact guidance, use `scf_search_controls`, `scf_get_control`, `scf_get_crosswalk`, and `scf_get_evidence_request`
13. If the deliverable needs to become a portable OSCAL artifact, start with `oscal_check_trestle`, then use `oscal_init_workspace`, `oscal_import_model` or `oscal_create_model`, and the SSP helpers as needed
14. Collect certificate numbers, CVE IDs, due dates, and source URLs inline

If evidence is missing, say exactly what is missing and what artifact would close the gap.

## Phase 3: Control Mapping

Map findings explicitly to the requested framework. At minimum, evaluate:
- **SC-13 / cryptographic protection**
- **SC-12 / key management**
- **SI-2 / flaw remediation**
- **RA-5 / vulnerability monitoring**

For each control, classify:
- Satisfied
- Partially Satisfied
- Not Satisfied
- Unable to Assess

## Phase 4: Prioritization

Rank issues by:
1. Exploitability
2. Compliance impact
3. Operational blast radius
4. Remediation effort

Use EPSS and KEV status when vulnerability data exists.

## Phase 5: Deliverable

Return:
1. **Audit summary** — what was assessed and overall posture
2. **Control-by-control findings** — with evidence
3. **Critical gaps** — highest-risk issues first
4. **Remediation plan** — concrete next actions with rough effort

Do not infer compliance without evidence. Mark unknowns as unknowns.
