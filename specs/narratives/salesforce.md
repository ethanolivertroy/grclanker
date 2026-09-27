## Purpose

Inspect Salesforce organization security, identity permissions, data protection, and monitoring configuration through read-only REST, Tooling, and Metadata API evidence.

## Design guidance

Keep the three API surfaces and their permissions distinct. Population sanity checks are mandatory for user, profile, permission-set, and MFA conclusions. A zero-row response from a permission-limited view is unknown, not compliant.
