## Purpose

KnowBe4 Security Inspector gives auditors a read-only view of a KnowBe4 Security Awareness Training account. It covers four areas:

- Phishing program: whether simulated phishing runs often and on a regular schedule, meets its coverage and targeting minimums for active users, keeps the phish-prone percentage under its ceiling and baseline without a rise of more than half a point across the trend window, and draws reports from the people it tests.
- Training program: whether training campaigns close with high completion, new users enroll within the grace period, users who fail a phishing test receive remedial training, assigned content stays current, and required compliance topics are assigned and completed.
- User risk: whether risk scores stay low and even, every active group sees both phishing and training, and long-standing users show recent activity.
- Account governance: how many people administer the account, whether any of them sit outside its domains, and whether callback (vishing) tests run.

## Rationale

The Reporting API pages by page number and returns no total, Link header, or cursor, so a short page is the only sign that a list has ended. Every walk also stops at a record cap, and at a page holding an entry that is not a JSON object, since that entry may be a record no check can read. Either stop marks the list partial, so a check built on that list cannot pass: where it would have passed, it reports warn. A fail that rests on something being absent from a partial list, such as a group with no training or a user with no recorded activity, is reported as warn instead.

Recipient-level checks read a sample: by default, the recipient lists of the newest 12 security tests in the window. Coverage and remedial training cannot pass unless the recipients of every test that ran in the lookback window were read in full.

PhishER is a separate product with its own API key. Without the key the tool does not read it, and the report rate check rests on the security test counters alone. With the key, a refused PhishER read keeps that check from passing. The Reporting API exposes no SSO or admin MFA settings, no record of report reviews, and no USB drive tests, so those three checks always return manual and name the console evidence a reviewer needs.

## Runtime behavior

- The tool only reads. Every Reporting API request is a GET, and the PhishER requests are GraphQL queries, which change nothing.
- Users stop at user_limit (5000), training enrollments at enrollment_limit (20000), PhishER messages at phisher_message_limit (1000), and every other list, including each sampled test's recipient list, at 20000 records.
- Training campaigns are read 10 per page, other Reporting API lists 500 per page, and PhishER messages 200 per page.
- A refused or failed read never counts as an empty list. A check whose decision needs that read is manual, and a check that uses it only as supporting evidence cannot pass.
- When every probe returns 401, the access check reports failed: KnowBe4 refused the token itself, and a token sent to another region's host draws the same 401, so the next step names the token setting and the region or base URL setting that picked the host.
- The account record is cut to its listed fields, and user records lose their comment, custom field, and custom date values before they reach evidence, decision facts, or the bundle. With redact_pii, the export also hashes email and reporter values and masks names, phone numbers, IP addresses, and message subjects.
- The phish-prone baseline is the first three tests that ran, used only once at least four have run, and the trend needs at least four tests in twice the lookback window. Neither count can be configured.

## Non-goals

- Changing KnowBe4 settings, launching or editing campaigns, enrolling users, or issuing any administrative write request
- Judging the content or difficulty of phishing templates and training modules
- Verifying SSO enforcement, report review cadence, or USB drive tests, which the Reporting API does not expose
- Reconciling the KnowBe4 user list against an authoritative directory such as an identity provider or HR system
- Treating a refused read or an unconfigured PhishER key as a compliant result
- Reproducing a particular programming language, package layout, or command-line framework

## Portable implementation guidance

Keep the API client, pagination, recipient sampling, evidence projection, verdict evaluation, and bundle writer as separable concerns. Count from the full collected arrays at the decision point rather than from evidence previews. Keep each dataset's read state (read, refused, not requested, not configured, or partial) next to its records, along with the sampled and unsampled security test IDs, so every finding can say which sources it depended on and why a pass was capped.
