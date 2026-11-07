# Credential policies

Integration modules instantiate a shared policy instead of copying a parser. Each instance owns its configured-secret registry; credentials registered by one integration never enter another integration's registry.

- `createSnapshotCredentialScrubber`: cloud, Ansible, and Duo carrier rules plus bounded snapshot traversal.
- `createPairCredentialScrubber`: quote-aware credential pairs, bounded remembered secrets, and separate error/data passes. Opaque authorization schemes such as Veracode HMAC are declared by name.
- `createPemCredentialScrubber`: error carriers plus an evidence mode that retains public certificates, public keys, and certificate requests.

These policies preserve the existing families' different evidence semantics. Change the relevant shared policy and its existing canary tests when adding a carrier. Vendor-specific projection and PII rules remain with the integration. Filesystem containment, permissions, and publication belong to `../secure-output.ts` and `../atomic-output.ts`.
