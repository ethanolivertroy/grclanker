## Purpose

Webex Security Inspector gives auditors a read-only, evidence-based view of a Webex organization's identity, collaboration, meeting, hybrid-service, and device posture. It combines the settings that Webex exposes through documented read interfaces with explicit manual evidence requests for settings that remain available only in Control Hub.

## Rationale

Webex security evidence is split across organization, meeting, messaging, calling, and compliance surfaces. Token type, tenant plan, delegated scopes, and per-site configuration all affect what a collector can see. A portable implementation must preserve that uncertainty instead of treating an inaccessible or credential-scoped view as a compliant empty tenant.

The contract favors documented reads over guessed fields or write interfaces. This is especially important for SSO, organization-wide MFA, data loss prevention, calling encryption, device blocking, and other controls whose administrative state is not exposed by a public read operation.

## Non-goals

- Changing Webex settings or issuing any administrative write request
- Claiming complete organization coverage from bot-scoped rooms or webhooks
- Replacing reviewer judgment for settings that have no documented read interface
- Providing a general Webex administration client
- Reproducing a particular programming language, package layout, or command-line framework

## Portable implementation guidance

Keep the API client, evidence projection, verdict evaluation, and bundle writer as separable concerns. Preserve the relationship between a finding and every source it depends on, including the token-type probe and the site list. Assess each meeting site independently before combining results. When Webex returns a credential-scoped inventory, state that scope in the evidence even if every visible record is compliant.
