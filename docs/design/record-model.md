# Record Model

## Purpose

This note records what a captured record is: the envelope every later stage stores, signs and reads back, the values it
may hold, how a code, an outcome and the references in it are validated, how a payload is normalised and sanitised
before it is kept, and how the builder that describes a record is used once. The record is the contract every storage,
integrity, export and read path builds on, so its keys, their types and what an absent value means are fixed here and
pinned by a golden fixture; a change to any of them is a new record version, never an edit of the old one.

## Invariants

- A record has two stages. The captured record (`AuditRecord`) holds everything known when the activity is recorded and
  is what `PendingRecord::record()` returns. The delivery pipeline later finalises it once, adding the time it was
  recorded and its integrity fields; that finalised record is not part of this note.
- The captured record holds scalars only: strings, integers, booleans, `null`, lists and maps. Enums are kept as their
  values, references as type and id pairs, and the time as a string; every ambient value is resolved before the record
  is built, and no object, enum or model is ever in it.
- Its `id` is a UUID version 7 made from the time it occurred, so records captured in one millisecond still sort in the
  order they were captured. `occurred_at` is ISO-8601 in UTC with microseconds (`2026-10-31T23:34:56.789012Z`).
- Three versions are kept apart. `record_version` is the envelope's format, `RecordVersion::CURRENT` (1); the event
  version is the payload contract of the code's definition (see `event-definitions.md`); the integrity version belongs
  to the finalised record. `RecordVersion::check()` refuses any record version this release does not support with an
  `\UnexpectedValueException`: an old row is never rewritten, and a newer one is never guessed at.
- An event code is lower-case dotted segments (`invoice.approved`), each a letter followed by letters, digits or
  underscores, in at least two segments and at most 191 bytes (`EventCode::MAX_BYTES`). It is a string or the value of
  a string-backed enum case, never derived from a class name. The `audit_log.` prefix (`EventCode::RESERVED_PREFIX`) is
  the package's own, and a caller's code under it is refused; see `vocabulary.md` for the other reserved prefixes.
- The outcome is `success` by default (`Outcome::SUCCESS`); `failed()` sets `failure` and `denied()` sets `denied`,
  each with an optional reason, and `succeeded()` clears the reason. A reason is a machine-readable code of 1 to 64
  characters (lower-case letters, digits, `_`, `.`, `:` or `-`, starting with a letter or a digit) or a string-backed
  enum case, validated and never truncated.
- A reference (`Reference`) is a type and an id, each 1 to 191 characters of clean text, kept exactly: never trimmed,
  case-folded or truncated, and an integer id becomes its decimal string. `Reference::to()` takes a model's morph
  class, falling back to its class name when an enforced morph map does not list it, and its key; it never reads the
  model's attributes. A model without a key is refused, so an unsaved model is never referenced.
- In the envelope a reference is a pair of columns (`actor_type` and `actor_id`, and likewise for the subject, the
  principal and the tenant), both set or both `null`, never an empty string.
- `by(null)` is an explicit "no actor" and differs from not calling `by()`: a contributor fills an actor only when none
  was given, so `by(null)` stays `null` while an unset actor may be filled. `asPrincipal(null)` and `forTenant(null)`
  work the same way. Explicit values beat filled ones in either order, and the first contributor to fill a field wins.
- A captured record always has an origin: `http`, `console` or `queue` (`Origin`). Its provenance is always `captured`
  (`Provenance::CAPTURED`), which says the application asserted the activity, not that the claim is true; `imported`
  belongs to records another source asserted. No public method takes a provenance, and the import fields
  (`source_record_id`, `import_batch_id`) of a captured record are `null`.
- `properties._audit` belongs to the package: it holds the `note` and, once redaction exists, the `omitted` diagnostic.
  A caller's key beginning `_audit`, at any depth and after its key is cleaned, is refused.
- A note (`withNote()`) is cleaned and cut to `PendingRecord::NOTE_MAX_BYTES` (1024) bytes on a character boundary. A
  note without an owner is stored at `properties._audit.note`, after the caller's keys, in plaintext, and cannot be
  erased. A note with an owner (`KeyOwner::ACTOR`, `KeyOwner::SUBJECT`, a model or a reference) is never stored in
  plaintext: until the pipeline that encrypts it to its owner exists, it is not stored at all. A note is free text,
  and nothing claims it holds no personal data or secrets.
- Setting one field twice keeps the last value given (the code, the references, the outcome and reason, the note and
  its owner); `withProperties()` merges at the top level, later keys replacing earlier ones. Different calls never
  interact, so the record does not depend on the order they are made in.
- A builder is used once. `record()` hands it to its recorder, which builds the record; afterwards every call on it,
  `record()` included, is a `\LogicException`. A builder made without a recorder can be described but not recorded.
  Nothing is written without `record()`.
- A builder has one timing (`after_commit`, `immediate` or `transactional`), and `failClosed()` never combines with
  `afterCommit()`. What each timing does when the record is written belongs to the write path.
- A programming error (an invalid code, reason, reference, identifier or payload, a reused builder, a conflicting
  timing) is an SPL exception, `\InvalidArgumentException` or `\LogicException`, thrown whatever the configured
  failure policy: it is the caller's bug, not a write failure to contain.

## Success Path

- The application names a code with `event()`, then describes the activity in any order: `on()` the subject, `by()`
  the actor, `asPrincipal()`, `forTenant()`, `usingCredential()` with a credential's id (never a secret),
  `correlatedWith()` a namespaced id such as `app:ticket-123`, `withProperties()`, `withNote()`, and an outcome.
- Each value is validated and normalised as it is given, so the builder's properties and context hold only strings,
  integers, booleans, `null`, lists and maps, and every other field a validated value.
- The package's contributors fill the gaps the application left: the actor, principal and tenant, the guard, the
  session reference, the request and trace ids, the IP address and user agent, the origin and the context.
- `record()` hands the builder to the recorder, which builds the `AuditRecord` from it with the code's event version
  and category, the time it occurred and the application's source id and region, and returns it.

## Failure / Edge Cases

- An event code that is not a string or a string-backed enum case, longer than 191 bytes, outside the grammar, or
  under the reserved `audit_log.` prefix: `\InvalidArgumentException`. The length is checked before the grammar, and
  the grammar before the prefix, so each code has one refusal; `audit_logs.pruned` is an ordinary code.
- A reason that is not a machine-readable code, or an enum reason not backed by strings: `\InvalidArgumentException`,
  and the outcome is left as it was.
- A reference type or id that is empty, longer than 191 characters or not clean text, a model without a key, or a
  model whose key is neither a string, an integer nor a UUID: `\InvalidArgumentException`.
- A credential id, correlation id, guard name, session reference, request id, IP address or connection name that is
  empty, too long for its column or not clean text, a correlation id with no `<namespace>:` prefix, or a trace id that
  is not 32 lower-case hexadecimal digits or is all zero: `\InvalidArgumentException`. Identifiers are validated, never
  cleaned or cut. A user agent is cleaned and cut to 512 bytes instead, and one that cleans to nothing is `null`.
- Properties or context given as a non-empty list, or properties with a key beginning `_audit` at any depth:
  `\InvalidArgumentException`, and nothing of that call is merged. `[]` adds nothing. Only the properties reserve
  `_audit`: the context keeps such keys as given.
- A note that is empty once cleaned, or owned by an unsaved model: `\InvalidArgumentException`. A note never replaces
  the code, which stays required.
- A second, different timing, or `failClosed()` with `afterCommit()` in either order: `\LogicException`. Repeating the
  same timing, or `failClosed()`, changes nothing.
- `record()` on a used builder, or on one made without a recorder; building a record from a builder with no code, or
  with no origin: `\LogicException`.
- A source id longer than 64 characters or a source region longer than 32, empty or not clean text:
  `\InvalidArgumentException`.
- A record version other than 1 read back: `\UnexpectedValueException`.
- A value the normaliser cannot represent is kept as a marker, never refused: `[UNSERIALISABLE]`, `[NONFINITE]` or
  `[TRUNCATED]`. Keys that collide once cleaned keep the first value, and the collisions are counted, with the schema
  paths of the first 32 kept and never a value.

## Envelope

`AuditRecord::toArray()` gives exactly these 32 keys, in this order, which is the order of the entries table without
its finalisation columns. `tests/Fixtures/Records/audit-record-v1.json` is the golden version 1 record.

| Key                | Type    | Meaning                                                    | `null` when                  |
|--------------------|---------|------------------------------------------------------------|------------------------------|
| `id`               | string  | UUID version 7 of the record                               | never                        |
| `record_version`   | int     | the envelope's format, 1                                   | never                        |
| `event`            | string  | the event code                                             | never                        |
| `event_version`    | int     | the payload contract's version, from the code's definition | never                        |
| `category`         | string  | the category slug, from the code's definition              | never                        |
| `outcome`          | string  | `success`, `failure` or `denied`                           | never                        |
| `reason`           | ?string | the machine-readable reason                                | no reason was given          |
| `actor_type`       | ?string | who did it: the reference's type                           | there is no actor            |
| `actor_id`         | ?string | who did it: the reference's id                             | there is no actor            |
| `subject_type`     | ?string | what it was done to: the reference's type                  | there is no subject          |
| `subject_id`       | ?string | what it was done to: the reference's id                    | there is no subject          |
| `principal_type`   | ?string | who the actor acted as: the reference's type               | there is no principal        |
| `principal_id`     | ?string | who the actor acted as: the reference's id                 | there is no principal        |
| `tenant_type`      | ?string | the isolation boundary: the reference's type               | there is no tenant           |
| `tenant_id`        | ?string | the isolation boundary: the reference's id                 | there is no tenant           |
| `credential_id`    | ?string | the id of the credential used, never a secret              | none was given               |
| `guard`            | ?string | the guard the actor was authenticated by                   | none was filled              |
| `session_id`       | ?string | an application-owned, non-secret session reference         | none was filled              |
| `request_id`       | ?string | the request's id                                           | none was filled              |
| `trace_id`         | ?string | the W3C trace id                                           | none was filled              |
| `correlation_id`   | ?string | a namespaced id, such as `app:ticket-123`                  | none was given               |
| `origin`           | ?string | `http`, `console` or `queue`                               | never for a captured record  |
| `provenance`       | string  | `captured` or `imported`                                   | never                        |
| `source_id`        | string  | the application that captured it                           | never                        |
| `source_region`    | ?string | the region it was captured in                              | none is configured           |
| `source_record_id` | ?string | the id an imported record had at its source                | always for a captured record |
| `import_batch_id`  | ?string | the import an imported record came in                      | always for a captured record |
| `ip`               | ?string | the client's IP address                                    | none was filled              |
| `user_agent`       | ?string | the client's user agent, cleaned and capped                | none was filled              |
| `context`          | ?map    | where it happened (route, command, job), normalised        | nothing was filled           |
| `properties`       | ?map    | the caller's properties, normalised, then `_audit`         | nothing remains              |
| `occurred_at`      | string  | when it happened, ISO-8601 UTC with microseconds           | never                        |

## Normalisation

`ValueNormaliser::normalise()` applies the first rule that matches, once, when a value is given. Models come first,
because a model is also `Stringable` and `JsonSerializable`, and its string form serialises its attributes.

| #  | Value                                                                                             | Becomes                                                                                |
|----|---------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------|
| 1  | an Eloquent model                                                                                 | its reference's `{type, id}` shape; an unsaved model is refused                        |
| 2  | a `Reference`                                                                                     | its `{type, id}` shape                                                                 |
| 3  | a backed enum case                                                                                | its value, normalised as a string or an integer                                        |
| 4  | a pure enum case                                                                                  | its name                                                                               |
| 5  | a date                                                                                            | ISO-8601 in UTC with microseconds                                                      |
| 6  | a ramsey UUID or a Symfony UID                                                                    | its string, sanitised, if of its library's own classes; otherwise `[UNSERIALISABLE]`   |
| 7  | a boolean, `null` or a string                                                                     | itself; a string is sanitised                                                          |
| 8  | an integer                                                                                        | itself within ±(2^53 − 1), otherwise its decimal string                                |
| 9  | a float                                                                                           | finite: its shortest round-trip decimal string, `-0.0` as `0`; otherwise `[NONFINITE]` |
| 10 | an array deeper than eight levels                                                                 | `[TRUNCATED]`                                                                          |
| 11 | a list                                                                                            | a list of each element normalised (`[]` is an empty list)                              |
| 12 | any other array                                                                                   | a map of each cleaned key to its value normalised; a colliding key keeps the first     |
| 13 | anything else (`Stringable`, `JsonSerializable`, `Arrayable`, closures, other objects, resources) | `[UNSERIALISABLE]`, never cast or called                                               |

- Floats are formatted as ECMAScript formats numbers, without reading `precision` or `serialize_precision`:
  positional from 1e-6 to below 1e21 (`0.1`, `100`, `0.30000000000000004`), otherwise `1e+21` or `5e-324`.
- The outermost array is the first level, so a self-referencing array ends in `[TRUNCATED]` rather than recursing.
- A map whose keys are `0` to `n − 1` in order is a list in PHP and encodes as one; field rules still reach it,
  because a literal digit in a path matches a list index.
- Sanitising (`TextSanitizer`) repairs invalid UTF-8 byte by byte to U+FFFD, turns each whitespace control (U+0009 to
  U+000D) into one space, and strips every other control character (NUL, the rest of C0, DEL and C1) and the bidi
  embeddings, overrides and isolates (U+202A to U+202E, U+2066 to U+2069). Combining marks, zero-width characters and
  emoji sequences are kept, there is no Unicode normalisation, and a cap cuts on a character boundary. The repair never
  depends on a runtime setting.

## Implementation Anchors

- `src/Records/AuditRecord.php`: `fromPending()`, `toArray()`.
- `src/Records/PendingRecord.php`: `record()`, `NOTE_MAX_BYTES`; `src/Records/PendingSnapshot.php`.
- `src/Records/Concerns/DescribesTheActivity.php`, `src/Records/Concerns/SetsTheOutcome.php`,
  `src/Records/Concerns/ChoosesDelivery.php`, `src/Records/Concerns/FillsAmbientContext.php`.
- `src/Records/EventCode.php`: `MAX_BYTES`, `RESERVED_PREFIX`; `src/Records/RecordVersion.php`: `CURRENT`, `check()`.
- `src/Records/Reference.php`: `of()`, `to()`.
- `src/Records/Enums/Outcome.php`, `src/Records/Enums/Origin.php`, `src/Records/Enums/Provenance.php`,
  `src/Records/Enums/Timing.php`.
- `src/Support/ValueNormaliser.php`, `src/Support/Normalised.php`, `src/Support/TextSanitizer.php`.

## Authoritative Tests

- `tests/Unit/Records/AuditRecordTest.php` `testIsFinalAndReadonlyWithOnlyOneNamedConstructor`,
  `testEveryLeafOfTheEnvelopeIsAScalarOrNull`, `testTheEnvelopeKeysArePinned`, `testTheGoldenV1RecordDecodesUnchanged`,
  `testTheIdIsAUuidVersion7`, `testRecordsCapturedInOneMillisecondSortInCaptureOrder`,
  `testOccurredAtIsUtcWithMicroseconds`, `testTheEventVersionAndCategoryAreTheCallers`,
  `testProvenanceIsCapturedAndTheImportFieldsAreNull`, `testReferencesArePairsOrAbsent`,
  `testTheNoteIsStoredUnderTheReservedMetadata`, `testAnOwnedNoteIsNeverStoredInPlaintext`,
  `testABuilderWithoutAnOriginIsALogicError`
- `tests/Unit/Records/RecordVersionTest.php` `testTheCurrentVersionIsOneAndSupported`, `testAnUnknownVersionIsRefused`
- `tests/Unit/Records/EventCodeTest.php` `testRefusesAnInvalidCode`, `testTheLengthIsCheckedFirstAndInBytes`,
  `testRefusesTheReservedPrefix`, `testAcceptsCodesThatOnlyResembleTheReservedPrefix`
- `tests/Unit/Records/Enums/OutcomeTest.php`, `tests/Unit/Records/Enums/OriginTest.php`,
  `tests/Unit/Records/Enums/ProvenanceTest.php`: the stored values
- `tests/Unit/Records/ReferenceTest.php` `testOfKeepsTheIdExactly`,
  `testToFallsBackToTheClassNameUnderAnEnforcedMapThatOmitsIt`, `testToRefusesAnUnsavedModel`,
  `testToNeverReadsTheModelsAttributes`
- `tests/Unit/Records/Concerns/DescribesTheActivityTest.php` `testByNullAndNoByGiveDifferentRecords`,
  `testWithPropertiesMergesLaterKeysOverEarlier`, `testWithPropertiesRefusesAReservedKeyAtAnyDepth`,
  `testWithNoteSanitisesAndCapsTheText`, `testWithNoteRefusesEmptyText`, `testCorrelatedWithRefusesAnInvalidId`
- `tests/Unit/Records/Concerns/SetsTheOutcomeTest.php` `testTheOutcomeIsSuccessByDefault`,
  `testRefusesAReasonThatIsNotAMachineCode`, `testTheLastOutcomeWins`
- `tests/Unit/Records/Concerns/ChoosesDeliveryTest.php` `testASecondDifferentTimingIsALogicError`,
  `testFailClosedAfterCommitIsALogicError`
- `tests/Unit/Records/Concerns/FillsAmbientContextTest.php` `testAFillerNeverReplacesAGivenField`,
  `testAnExplicitValueReplacesAFilledOne`, `testFillersRefuseValuesOutsideTheirColumns`
- `tests/Unit/Records/PendingRecordTest.php` `testNothingIsRecordedWithoutRecord`, `testASecondRecordIsALogicError`,
  `testRecordWithoutARecorderIsALogicError`, `testNoPublicMethodAcceptsAProvenance`,
  `testPermutedCallOrdersGiveEqualRecords`, `testProgrammingErrorsAreSplExceptions`
- `tests/Unit/Support/ValueNormaliserTest.php` `testAModelBecomesItsReferenceNeverItsAttributes`,
  `testAModelIsNeverSerialisedOrQueried`, `testAUidOfAnotherClassIsNeverCalled`, `testAUidsStringIsSanitised`,
  `testAFiniteFloatBecomesItsShortestRoundTripString`, `testFloatsIgnoreThePrecisionSettings`,
  `testTheNinthLevelIsTruncated`, `testCollidingKeysKeepTheFirstAndAreDiagnosed`, `testOtherValuesAreUnserialisable`
- `tests/Unit/Support/TextSanitizerTest.php` `testRepairsInvalidUtf8`, `testStripsControlsAndBidiControls`,
  `testWhitespaceControlsBecomeSpaces`, `testCutsAtAByteCapWithoutSplittingACharacter`

## Change Triggers

Update this note when any of the following change:

- the envelope's keys, their order or their types
- an enum case or its stored value
- the event code grammar, its length or its reserved prefix
- the reason grammar or an identifier's length
- a normalisation or sanitising rule, or a marker's text
- the note cap, or where a note is stored
- what the builder refuses, or when it is used up
