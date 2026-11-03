# Threat Model

## Purpose

Key matching cannot find a secret in free text or under an innocuous key; event definitions, which allowlist fields, are
the remedy. This note records the rest of what minimising does and does not promise: which leaks it closes, which it
leaves open, what falls once a key does, and what the stores a failed or waiting record passes through can give away.
Whoever decides what an application records should read it first: a secret that reaches a row through one of these gaps
stays there for as long as the row is kept. How each step works is in `redaction.md`, and how a record travels is in
`delivery.md`.

## Invariants

- Minimising happens at capture, so nothing raw rests in a deferred callback, event or row. A record written after
  commit already holds its minimised values while it waits, and everything given a record receives the minimised one. If
  minimising fails, nothing is stored unminimised.
- A built-in secret is never un-redacted: `retain` on `password` stores `[REDACTED]`, and `redaction.keys` can only add.
- An `ENCRYPT` field with no key is dropped, and so is one with no owner or a failed encrypter, and it is never stored
  in plaintext. An owned note and an encrypted address are held to the same rule.
- Diagnostics never hold a value or a dynamic key. `properties._audit.omitted` holds a count and masked paths, and a
  failure message or a reported exception names a setting, a type or a class, with no value or key in its frames.
- A hash is a pseudonym and not an anonymisation. A pseudonymised value, an identifier hash or a hashed address remains
  personal data for as long as the key exists.
- The references in the columns, such as `actor_id` and `subject_id`, are stored as given, since a log that names no one
  is no evidence. Minimising is about what the payload keeps, not who it names.

## Success Path

1. Every code that carries anything sensitive has a registered definition, which drops whatever no rule names, so a new
   field is not stored until someone decides it should be:

   ```php
   EventDefinition::for('invoice.approved')->retain('amount', 'currency')->pseudonymise('approver_email');
   ```

2. `definitions.require_registered` makes a code with no definition a programming error, so none is missed.
3. `redaction.key` holds a dedicated key, kept apart from `app.key` and, where it matters, `redaction.ip` is set to
   something less than `full`, which is the default.
4. An encrypted field names its owner, and the application binds a `Contracts\FieldEncrypter` holding the owners' keys.
5. `php artisan audit-log:check` reports a malformed setting before a deploy.

## Failure / Edge Cases

- With no definition registered, a code takes the permissive default, so only key matching stands between its payload
  and the row. Recording works with no set-up, and that is its cost.
- An encrypter that throws or returns something malformed loses the value and keeps the record, and the report names
  only its class. The value's loss is visible in `omitted`, so a gap in the row can be told from an empty field.
- A leak of the database alone gives references, retained values, any address stored in `full`, hashes and envelopes,
  but neither keys nor plaintext of what was hashed or sealed. A leak of the database with the key gives what the next
  section says.
- Reading the queue's storage gives the identifiers and the actor's reference, as `context-resolution.md` says, and no
  property, because a record's payload never travels in the job's hidden Context.

## Limits Of Key Matching

- **Free text.** A value is never searched. A token pasted into a `comment`, an error message or a URL query is kept
  under a key that says nothing of it.
- **Innocuous keys.** A secret under `value`, `data` or `x` is kept, because only a key's tokens are compared.
- **Joined words.** Every character that is not a letter, a mark or a digit splits a key, as does each boundary between
  a letter and a digit and each camel-case boundary, and format characters are removed first. Only words joined with no
  boundary and not listed, such as `mypassword`, are missed. `redaction.keys` can name such a key, and a definition can
  drop it.
- **Look-alikes.** Tokens are compared exactly, with no Unicode normalisation, so a key holding a combining mark or a
  letter of another script that looks like a Latin one is not matched. Only a definition's allowlist closes this.
- **Exempt containers.** An exemption assumes non-secret metadata, so `token_id` and `secret_at` are kept as they are
  and an exempt container's scalar values are kept, whatever they hold. Only an explicit field rule overrides them.
- **Notes.** A note is free text, and is never claimed free of secrets or of personal data. A note with no owner is
  stored in plaintext and cannot be erased, so anything that might be personal goes under an owner.
- **Keys themselves.** A key the matcher does not catch is kept with its value, so a dynamic key of up to 1024 bytes,
  which could be an email address, is stored under a permissive definition. It is masked only in the diagnostics. A
  longer key is removed with its branch, so a client cannot exhaust a request's memory or fail an insert with one, and
  the omission says only that it went.
- **Other fields.** Matching reads the keys of `properties` and `context` only. The user agent is cleaned and capped,
  not searched, and a reason, a credential id or a correlation id is validated as given. None of them should hold a
  secret.
- **The facade's frame.** Arguments to `AuditLog::record()` pass through the framework's facade frame, which no
  attribute can mark, so a stack trace kept with `zend.exception_ignore_args` off can hold them. PHP's production
  setting leaves it on, and the builder avoids the frame, as `AuditLog::event()->withProperties()` calls a method marked
  `#[\SensitiveParameter]` directly.

## Keys And Brute Force

A guessable identifier falls to brute force once the key leaks. An email address, a phone number or an IPv4 address
comes from a small enough space to try each one against a stolen key, so a keyed hash protects it only as long as the
key stays secret.

- A key from `app.key` falls with it, along with everything else that key protects. A dedicated `redaction.key` allows
  independent operation: it can live in another secret store and change on its own schedule, and a leaked `app.key` then
  says nothing about these hashes.
- Failed sign-ins correlate with each other, because one identifier under one key gives one hash, which is how a run of
  failures and a lockout are tied together without keeping the address.
- A pseudonym never equals an identifier hash or an IP hash, because an identifier, a field and an address are hashed
  under three domain keys, so the same value gives three unrelated hashes. Within the field domain the same value does
  give the same hash in any field of any code, so a field needing no linkage should use `drop` or `encrypt`.
- A key change is visible through the fingerprint at the start of every hash. Earlier rows keep their hashes and are not
  rewritten, so they no longer correlate with new ones, and the differing fingerprint says why. This includes a rotated
  `app.key` when no `redaction.key` is set, since `app.previous_keys` is not read.

## Spill And Outbox

The spill and the outbox hold personal data. Each holds a whole record as it was minimised, its references, its address
and its properties included, so each is a personal data store of its own, with its own readers and its own retention,
and neither is reached by anything that later prunes or erases a row. Log files and database backups are often shipped
off the server, to a log aggregator, a backup provider or a support bundle, so the question is who can read those, and
not only who can read this server.

- A spill line is not encrypted. It is the record in canonical JSON, on purpose: it has to be readable when the store is
  down and the key ring may be what failed. The documented channel is a dedicated file at `0600`, and any other channel
  shares the line with whatever else it feeds.
- What a log's readers can see goes past the file, through the channel's own handlers. A spill line is written past
  Laravel's log wrapper, so no `MessageLogged` listener sees a spill line and no error tracker's breadcrumb or debug
  recorder holds it beside the report that follows. A default channel's `stack` may still send `critical` lines to an
  alerting tool, so a spill on the default channel can post a record to a chat room, and `audit-log:check` says so of
  any channel but the documented one, and of a documented one whose file group or others can read.
- The outbox's encryption protects a database copy and not a compromised application holding the key. A dump, a replica
  or a backup of the row gives nothing without `app.key`, but anything that can run as the application can decrypt it,
  and the row can be read for as long as an old key stays in `app.previous_keys`.
- A receipt and an outbox row's own columns hold ids, times, destination ids and the class of a failure. They hold no
  value of the record and no failure's message, so reading them says that a record exists and what became of it.
- Failure paths hold less than the stores do. A report, an exception and `AuditWriteFailed` hold the record's id and
  code and the classes involved, never a driver's message or a statement's bindings, so an error tracker holds a spill
  line only if it is itself a handler of the spill channel, and not through the failure.
- What signing establishes is narrow. A line that verifies was signed by a holder of the integrity key and has not
  changed since, so editing a log cannot inject a record through a replay, and an unsigned line is never replayed. It
  does not establish that the activity happened, only that the application said so, or that the transaction around it
  committed: an immediate record's line can outlive an enclosing rollback, as evidence of an attempt. Nor does it show a
  file is complete, since a line deleted from one leaves nothing to find. Replaying an old line adds nothing, but only
  because the store already holds its id.

## Implementation Anchors

- `src/Stores/FailureSpill.php`: `line()`; `src/Delivery/OutboxWriter.php`: `write()`; `src/Delivery/SpillReader.php`;
  `src/Records/EnvelopeCodec.php`: `decode()`; `src/Stores/WriteDiagnostics.php`.
- `src/Privacy/RecordMinimiser.php`: `minimise()`; `src/Recorder.php`: `record()`, `event()`.
- `src/Privacy/KeyCeiling.php`: `MAX_BYTES`; `src/Privacy/KeyTokenizer.php`: `tokens()`; `src/Privacy/Redactor.php`:
  `SURVIVORS`, `EXEMPT_FINAL_TOKENS`, `SENSITIVE_UNITS`.
- `src/Privacy/IdentifierHasher.php`: `IDENTIFIER_INFO`, `FIELD_INFO`, `IP_INFO`; `src/Privacy/RedactionSettings.php`:
  `rootKey()`.
- `src/Privacy/EnvelopeSealer.php`: `seal()`; `src/Privacy/FieldEncryptionFailedException.php`: `for()`;
  `src/Contracts/FieldEncrypter.php`: `encrypt()`.
- `src/Privacy/PathMasker.php`: `property()`, `context()`; `src/Privacy/OmissionLog.php`: `toArray()`.
- `src/Records/Concerns/DescribesTheActivity.php`: `withProperties()`, `withNote()`, `withIdentifier()`.

## Authoritative Tests

- `tests/Unit/Documentation/DocumentationTest.php` `testTheThreatModelStatesTheLimitsOfKeyMatching`,
  `testTheThreatModelOpensWithThoseLimits`, `testTheThreatModelStatesTheBruteForceLimit`
- `tests/Unit/Privacy/RedactorTest.php` `testTheMatcherTable`, `testAnExemptKeysScalarsAreKept`,
  `testConfiguringUnitsRemovesNoBuiltIn`
- `tests/Unit/Privacy/FieldPolicyTest.php` `testRetainOnARedactedValueStaysRedacted`,
  `testNoEncrypterDropsAndDiagnoses`, `testANoOwnerFieldIsDroppedAndDiagnosed`,
  `testAThrowingEncrypterDropsAndDiagnoses`, `testNoValueOrDynamicKeyReachesTheLog`
- `tests/Unit/Privacy/IdentifierHasherTest.php` `testTheThreeDomainsNeverAgree`,
  `testAPseudonymNeverEqualsAnIdentifierHash`, `testTheFingerprintChangesWithTheKey`
- `tests/Unit/Privacy/IpMinimiserTest.php` `testAnIpHashIsNeverAnIdentifierHash`
- `tests/Unit/Privacy/SensitiveParametersTest.php` `testEveryRawValueParameterIsSensitive`,
  `testThePrivacyLayersRawParametersAreAllSensitive`
- `tests/Unit/Privacy/RecordMinimiserTest.php` `testAFailureMessageHoldsNoPayload`,
  `testARawCollisionKeyNeverReachesTheDiagnostics`
- `tests/Unit/Records/Concerns/DescribesTheActivityTest.php` `testThePropertiesAndNoteAreMarkedSensitive`
- `tests/Feature/RecorderTest.php` `testTheRecorderPropertiesParameterIsSensitive`
- `tests/Feature/Privacy/NoSecretAnywhereTest.php` `testTheReturnedRecordHoldsNoSecret`,
  `testTheStoredRowHoldsNoSecret`, `testNoPackageEventHoldsASecret`, `testNoLogLineHoldsASecret`,
  `testNoReportHoldsASecret`, `testADeferredCaptureHoldsNoSecret`, `testAFailedWriteHoldsNoSecret`,
  `testAMinimiserFailureHoldsNoSecret`, `testAContainedFailureNamesOnlyTheEncrypterClass`,
  `testAContainedFailureHasNoPrevious`, `testADynamicKeyIsInNoFrameOfAReportedFailure`,
  `testADynamicKeyIsInNoFrameOfAThrownFailure`, `testASecretInAKeyPastTheCeilingIsInNoRecordOrRow`,
  `testAGarbageIpHoldingASecretIsInNoRecordOrRow`, `testAGarbageIpHoldingASecretIsInNoFailure`
- `tests/Feature/Privacy/CaptureMinimisationTest.php` `testNothingUnminimisedIsStoredWhenMinimisingFails`,
  `testFailedSignInsCorrelateByIdentifierHash`, `testAPseudonymisedFieldDoesNotCorrelateWithAnIdentifierHash`
- `tests/Integration/Privacy/IdentifierCorrelationTest.php` `testFiveFailuresThenALockoutShareOneHash`,
  `testAChangedKeyChangesTheFingerprint`
- `tests/Unit/Documentation/DocumentationTest.php` `testTheSpillAndOutboxArePersonalData`
- `tests/Feature/Delivery/NoPayloadInFailuresTest.php` `testTheSpillHoldsOnlyTheMinimisedValues`,
  `testTheOutboxHoldsNoPlaintext`, `testAReceiptHoldsNoPayload`, `testAPlantedSecretIsInNoReport`,
  `testAPlantedSecretIsInNoEvent`
- `tests/Feature/Delivery/ReplayerTest.php` `testATamperedLineIsSkippedAndCounted`,
  `testAnUnsignedLineIsSkippedAndCounted`

## Change Triggers

Update this note when any of the following change:

- what key matching reads, or a limit it has
- when minimising happens, or what can still hold a raw value
- what a definition must do for a field to be allowlisted
- which key a hash derives from, or which domains exist
- what a failed encrypter costs, or what is reported of it
- what a diagnostic may hold
- what the spill or the outbox holds, or how either is protected
- what signing a line establishes
