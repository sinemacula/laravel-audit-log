# Design Notes

These notes document the package's record, definition, redaction, storage, integrity, delivery, context and testing
contracts that are easy to miss if you only read the quick-start material or skim the test suite. Task-oriented guides
are in `docs/guides`.

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
  origin and provenance, normalisation and sanitising, the reserved metadata, the builder's single use, and how a record
  comes back from its envelope.
- `event-definitions.md`: a code's version, category and field rules, the path grammar and precedence, encryption
  owners, the permissive default and the registration rules.
- `vocabulary.md`: the reserved code prefixes and how they map to the OWASP Logging Vocabulary, the codes the package
  captures from Laravel's authentication events and Gate denials, and the codes of a watched model's changes.
- `storage.md`: the entries table, its columns, indexes and engine options, the outbox and receipt tables and their
  connections, the checkpoints, members and integrity state tables, the storage and maintenance connections, the
  read-only model, how the store inserts in a savepoint and resolves a duplicate, and the grants and append-only
  triggers for each engine as executable SQL.
- `integrity.md`: the per-row signature, the canonical encoding it covers, the key ring derived from `app.key` or
  managed, what verifying a row answers, and that a replay verifies and never re-signs; the signed membership seals and
  their chain, the recent pass and the sweep, the anchors and their conditions, what verification checks and reports in
  each status and finding, pruning, the schedule, the alert and the progress, and the lifetimes of the keys.
- `outcomes.md`: what storing a record returns or raises for each way a write can end, what the host transaction is left
  as, and what each timing, delivery mode and failure guarantees, captured records and model changes included.
- `delivery.md`: the pipeline, the outbox and its drain, claims and receipts, the spill channel and replay, the stores
  and what each can promise, how a captured record reports its failure, the bundle a bulk operation travels as, and the
  formatters.
- `event-model.md`: what `AuditRecorded`, `AuditWriteFailed`, `AuditCaptureFailed` and `IntegrityCheckFailed` carry
  and when, by mode and by command, what a listener's failure does, and what the recursion guard refuses.
- `context-resolution.md`: the capture pipeline, what contributors may fill, how the actor is read without loading a
  user, the execution frames, when an inbound request id or trace id is believed, and what travels into a queued job.
- `redaction.md`: what a record keeps of what it is given: key matching, the field rules at capture, the hash domains,
  the byte budgets and omission diagnostics, the encryption seam and the IP modes.
- `threat-model.md`: what minimising does not promise: the limits of key matching, what a leaked key gives up, what
  remains in a stack trace or a note, and the spill and the outbox as personal data; and what integrity does not
  promise: no non-repudiation, fabricated and uncaptured records, deletion before a seal, the tail, a held key, the
  exposure no timer bounds, and that installing the package is not compliance.
- `testing-helpers.md`: the fake store and its assertions, what runs with it and what it does not model, a failing fake
  under each mode, and how Laravel's test helpers change what a record holds.

These documents are secondary to the code and tests, not a replacement for them. If a note and a cited test disagree,
the test should be treated as authoritative until the mismatch is resolved.
