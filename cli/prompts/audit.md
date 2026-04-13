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
3. If the scope is a Vanta audit, start with `vanta_check_access`, then use `vanta_list_audits` and `vanta_export_audit` to pull an offline evidence package before classifying controls
4. Collect certificate numbers, CVE IDs, due dates, and source URLs inline

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
