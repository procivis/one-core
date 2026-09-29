The `basic-*.did.jsonl` and `deactivate.did.jsonl` files in this directory are unmodified TypeScript vectors from
the [did:webvh interoperability test suite](https://github.com/decentralized-identity/didwebvh-test-suite),
under its Apache-2.0 license (also included at the repository root). They were
retrieved on 2026-09-29 from `vectors/<scenario>/ts/did.jsonl` on the `main` branch.

The included scenarios are `basic-create` (stored as `basic-create.did.jsonl`),
`basic-update`, and `deactivate`.

`bcs-issuer.did.jsonl` is a snapshot of the public BCS issuer DID log retrieved on
2026-09-29 from
`https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/5f8a3c95-1772-4ebf-ada0-c88bafb258e1/did.jsonl`.
It has two entries: an initial key commitment and a subsequent committed key
rotation. The first entry omits `witness` and `watchers`.

The `failure/*.jsonl` files are locally generated negative vectors, following
the TDW failure-vector convention. They use the deterministic WEBVH test key,
DID ID `11111111-2222-3333-4444-555555555555`, and a fixed first-entry time
of `2000-01-01T00:00:00Z`.
