# Design Notes

These notes document the package's record and definition contracts that are easy to miss if you only read the
quick-start material or skim the test suite.

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

These documents are secondary to the code and tests, not a replacement for them. If a note and a cited test disagree,
the test should be treated as authoritative until the mismatch is resolved.
