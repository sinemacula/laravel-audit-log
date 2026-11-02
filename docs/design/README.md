# Design Notes

These notes document the package's record, definition, storage and integrity contracts that are easy to miss if you
only read the quick-start material or skim the test suite.

Each note is intentionally short and follows the same structure:

- `Purpose`
- `Invariants`
- `Success Path`
- `Failure / Edge Cases`
- `Implementation Anchors`
- `Authoritative Tests`
- `Change Triggers`

The current note set is:

- `record-model.md`: the captured record, its envelope and versions, references and absent values, codes, outcomes,
  origin and provenance, normalisation and sanitising, the reserved metadata, and the builder's single use.
- `event-definitions.md`: a code's version, category and field rules, the path grammar and precedence, encryption
  owners, the permissive default and the registration rules.
- `vocabulary.md`: the reserved code prefixes and how they map to the OWASP Logging Vocabulary.
- `storage.md`: the entries table, its columns, indexes and engine options, the storage and maintenance connections,
  the grants, the read-only model and how the store inserts in a savepoint and resolves a duplicate.
- `integrity.md`: the per-row signature, the canonical encoding it covers, the key ring derived from `app.key` or
  managed, and what verifying a row answers.
- `outcomes.md`: what storing a record returns or raises for each way a write can end, and what the host transaction is
  left as.

These documents are secondary to the code and tests, not a replacement for them. If a note and a cited test disagree,
the test should be treated as authoritative until the mismatch is resolved.
