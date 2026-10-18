## Purpose

Veracode Security Inspector gives auditors a read-only view of a Veracode Application Security Platform account: whether every application is scanned recently, successfully, and as often as its policies and business criticality require, whether Dynamic Analysis scans are authenticated and crawl their targets, whether applications pass their assigned policies, whether open flaws are fixed within their age limits with mitigations reviewed and false positive rates and flaw density under their ceilings, whether third-party libraries carry high-severity vulnerabilities or high-risk licenses and every application is covered by SCA, and who can see and administer the portfolio.

## Rationale

Veracode answers a refusal, an unlicensed product, and an empty account in ways a naive reader could mistake for a clean result. Dynamic Analysis and agent-based SCA are licensed separately, and a 401, 403, or 404 from either API usually means the product is unlicensed or the API user lacks its role. A portable implementation must keep those cases visible, so a refused or failed read never counts as an empty list, and an empty application, policy, workspace, analysis, user, role, or finding inventory is reported as unverifiable rather than compliant, except where the known runtime gaps say otherwise.

Most evidence comes from HAL lists walked page by page and from per-application, per-workspace, and per-analysis reads over a bounded sample. A walk that stops at its page cap, repeats a page, or keeps fewer records than the reported total_elements is partial, and a sample smaller than its population leaves part of the account unread. Either condition caps the checks built on that evidence, so a pass is reported only when everything it depends on was read in full.

## Runtime behavior

- The tool only reads. Every request is a GET signed with VERACODE-HMAC-SHA-256 from the API key ID and secret.
- Sampled reads cover the first max_applications applications (100 by default) for sandboxes, findings, summary reports, and linked SCA projects, the first max_workspaces SCA workspaces (25 by default), the first max_analyses Dynamic Analysis analyses (25 by default) with at most 10 scans each, and at most 200 active API accounts for credential records.
- The policy compliance assessment reads no per-application data, so its max_applications argument has no effect.
- Flaw age limits are fixed by severity at 30 days for Very High, 60 for High, 90 for Medium, and 180 for Low, and cannot be configured.
- The organization-wide team list is read with all_for_org=true. When Veracode refuses that, only the teams the API user belongs to are listed, and that view is treated as partial.
- Prescan module selection, Pipeline Scan and IDE scan use, and Collections compliance are not exposed by the REST APIs the tool reads, so VERACODE-11, VERACODE-14, and VERACODE-20 always return manual and name the evidence a reviewer must collect from the Veracode Platform.
- Dynamic Analysis scan configurations are kept only as a summary: authentication method names, crawl settings, the allowed host count, and a scrubbed target URL.

## Non-goals

- Changing Veracode settings, starting scans, approving mitigations, or issuing any administrative write request
- Reading the XML APIs, Pipeline Scan or IDE scan results, or the Collections API
- Judging the accuracy of individual findings or the substance of mitigation justifications beyond whether one is present
- Treating a refused read, an unlicensed product, or an empty inventory as a compliant result
- Reproducing a particular programming language, package layout, or command-line framework

## Portable implementation guidance

Keep the request signer, API client, pagination, sampling, evidence projection, verdict evaluation, and bundle writer as separable concerns. Count from the full collected arrays at the decision point rather than from evidence previews. Keep each dataset's read state (read, refused, not requested because the inventory it depends on was refused, or partial) next to its records, along with how many applications, workspaces, analyses, and API accounts were sampled out of how many, so every finding can say which sources it depended on and why a pass was capped.
