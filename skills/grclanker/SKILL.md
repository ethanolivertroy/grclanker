---
name: grclanker
description: Investigate FIPS validation status, KEV exposure, EPSS likelihood, and framework-mapped GRC posture. Use when you need evidence-backed CMVP/KEV/EPSS analysis or want to turn a grclanker spec into implementation work.
---

# grclanker

Use this skill when the task is about cryptographic validation, exploited-vulnerability triage, or evidence-backed compliance posture work.

## Default Workflow

1. Clarify the subject.
   Capture the product, module, vendor, CVE, framework, or control family first.
2. Gather evidence.
   Prefer certificate IDs, module names, CVE IDs, KEV entries, EPSS scores, due dates, and concrete control references.
3. Classify the outcome.
   Use explicit states such as active, historical, in process, absent, satisfied, partially satisfied, not satisfied, or unable to verify.
4. Recommend next actions.
   Rank remediation by risk and effort, not discovery order.

## Evidence Rules

- Never claim a module is FIPS validated without a certificate number or CMVP record.
- Never claim a vulnerability is actively exploited without a KEV entry or equivalent source.
- Include EPSS data when exploit probability matters.
- Map findings to concrete controls such as NIST 800-53, FedRAMP, CMMC, SOC 2, or ISO 27001 when the user asks for compliance posture.
- Mark uncertainty explicitly instead of filling gaps with inference.

## Suggested Modes

- `validate`: narrow FIPS question for a module, library, vendor, or certificate.
- `investigate`: combine crypto status, KEV exposure, EPSS, and ransomware linkage.
- `audit`: map gathered evidence to a requested framework and identify gaps.
- `assess`: produce a posture summary with top risks and a remediation order.

## grclanker Repo Handoff

- CLI install:
  `curl -fsSL https://grclanker.com/install | bash`
- Skills-only install:
  `curl -fsSL https://grclanker.com/install-skills | bash`
- Raw spec library:
  `https://raw.githubusercontent.com/hackIDLE/grclanker/main/specs/<slug>.spec.md`

When a task is implementation-oriented, pull the relevant `spec.md` file and treat it as the source of truth for build sequence, APIs, auth flow, control mappings, and CLI design.
