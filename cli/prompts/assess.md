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

Be direct. If the evidence is thin, say the assessment confidence is low.
