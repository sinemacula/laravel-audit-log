# Threat Model

## Purpose

Key matching cannot find a secret in free text or under an innocuous key; event definitions, which allowlist fields, are
the remedy. This note records the rest of what minimising does and does not promise: which leaks it closes, which it
leaves open, what falls once a key does, and what the stores a failed or waiting record passes through can give away.
Whoever decides what an application records should read it first: a secret that reaches a row through one of these gaps
stays there for as long as the row is kept. How each step works is in `redaction.md`, and how a record travels is in
`delivery.md`.

It also records what the log's integrity does not promise. Signing, sealing and anchoring make a change to a stored
record detectable; they do not make a record true, show that everything that happened was recorded, or hold against
whoever holds the integrity key. How each of them works is in `integrity.md`.

And it records what the access policy that guards the trail does not promise. The policy decides what a read through
the package shows and every such read is recorded, but it is PHP: it cannot see a query that never passes through the
package. How the trail is read is in `reading.md`.

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
- Verification detects a change and neither prevents nor repairs one; the grants and triggers in `storage.md` are what
  refuse one. A row's HMAC, a seal's signature and a prune record's are all made under the integrity key ring, and a
  seal key is derived from the ring key it names, so whoever holds the ring can make each of them; only an anchor holds
  evidence outside the application's reach.
- Every integrity failure is reported by its class, a finding and ids alone: `IntegrityCheckFailed`, its exception and
  the commands' output hold no value of an entry, no key and no failure's message.

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
- A writer of the database without the integrity key can still change or delete rows. A change to a sealed entry, a seal
  or a member, and a deletion of any of them, is found by the next verification, except a deletion of the newest seals
  with their members and entries, which only the anchor finds. A row it inserts is found too: an entry with a junk HMAC
  is sealed and then fails, a copy of a seal stored outside the chain at a sequence below 1 is found with the member
  rows tied to it, and an unsealed entry dated so far ahead that no seal takes it is found rather than pending for good.
  Marking a seal unreadable to hide the deletion of its segment breaks the next seal's link, and the receipt columns it
  may edit decide nothing, since the anchor's own head says which seals it holds.

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

## Limits Of Integrity

Signing, sealing and anchoring are evidence that the log has not changed since it was written, and nothing more. Each
limit below holds however the package is configured.

- **Not non-repudiation.** An HMAC is not non-repudiation. The key that verifies a row or a seal is the key that made
  it, so a signature shows that the log is as a holder of the key wrote it, never which holder, and cannot show a third
  party that the application, rather than someone else with the key, wrote it.
- **Fabrication.** A compromised writer can still add fabricated records. Whatever runs as the application records
  through the same path, and its records are signed and sealed like any other: a seal shows they have not changed since,
  not that they were honest.
- **What was never captured.** No seal proves that an uncaptured event happened. A seal holds what was recorded; an
  activity the application never recorded, or a record lost before it was stored, leaves nothing to find.
- **Before the seal.** A row deleted before its membership commits is undetectable: no seal names it, so nothing says it
  was there. The guarantee is that deletion is detectable once membership is committed, and the gap is the time an entry
  waits for its seal.
- **The tail.** Deleting the newest seals, with their members and entries, leaves a shorter chain that verifies, so tail
  loss needs an independently retained witness: the anchor, whose head the local log must reach. Without one, a
  truncated tail is undetectable.
- **The key.** Anyone holding the integrity key can forge seals: rewrite entries, members and seals together, sign them
  again and pass verification. Only an anchor's earlier witness limits that, for the seals it held before the forgery,
  which can then no longer be replaced.
- **Exposure.** Anchoring bounds exposure without removing it: rows not yet sealed and seals not yet anchored can still
  be rewritten by whoever holds the database and the key. No timer bounds that exposure: a stopped scheduler or a
  backlog extends it. The package records the progress of sealing, the sweep, anchoring and verification instead, for
  monitoring to alert on when it goes stale.
- **Compliance.** Installing the package is not compliance. It supplies evidence and the checks of it; deciding what is
  recorded, how long it is kept, who can read it and its keys, how the anchor is configured, and who answers an alert
  remain the operator's.

## Limits Of A PHP Access Policy

The access policy, its scope and the record of every read hold for reads made through the trail, and nothing more. Each
limit below holds however the policy is written.

- **Direct access.** A PHP policy cannot stop direct SQL, a replica dump or a backup. Whoever holds credentials to the
  storage connection, a replica or a backup reads every entry without asking the policy and without being recorded, so
  database roles and the database's own auditing must cover them: the writer's grants in `storage.md`, a reader role
  that is not the application's, and the engine's own logging of who connected and what they read.
- **The model.** Reading `AuditEntry` directly bypasses the trail, as any query does: the policy is not asked, no scope
  narrows it, and nothing records it. The model is there for pruning, and an application that reads it in a portal has
  stepped outside the access control this note describes.
- **Timing.** A denied scope, and one the caller's filters cannot meet, run no statement and return the same empty
  result as a trail with nothing in it, so neither the result nor an error tells a viewer whether an entry exists. A
  read that runs a statement takes as long as its plan does, and plans differ with the data. Plan-dependent timing is
  not constant, and a viewer able to time many reads can learn something of what lies beyond its scope.
- **The viewer.** The application authenticates the viewer. A `Reference` given as the viewer, and the console's
  `--viewer-type` and `--viewer-id`, assert who is reading and prove nothing, so anyone who can run code or artisan can
  read as any viewer the policy allows.
- **The scope.** `onlyAbout()` selects entries by their actor or subject, and an entry about one person can name others
  in its properties, its principal or its tenant. A scope is a selection, not a review of what the entries hold.
- **The record.** A read is refused when its record cannot be written, so every read the trail answers is recorded.
  What a viewer does with what it was shown, once it has left the package, is beyond any record.

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
- `src/Integrity/SealSigner.php`: `sealKey()`; `src/Integrity/Verifier.php`: `verify()`;
  `src/Contracts/CheckpointAnchor.php`: `latest()`; `src/Database/IntegrityProgress.php`.
- `src/Contracts/AuditAccessPolicy.php`: `scope()`; `src/Access/ScopeCompiler.php`: `isEmpty()`;
  `src/Querying/AccessRecorder.php`: `record()`; `src/Models/AuditEntry.php`.

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
- `tests/Unit/Documentation/DocumentationTest.php` `testTheThreatModelStatesEachLimitOfIntegrity`
- `tests/Feature/Integrity/TamperingTest.php` `testAPreSealDeletionIsUndetectable`,
  `testTailTruncationWithoutAnAnchorIsUndetectable`, `testTailTruncationWithLocalReceiptsClearedIsTampered`,
  `testAForgedChainWithTheKeyAndNoAnchorVerifies`, `testAForgedChainWithTheKeyIsCaughtByTheAnchor`,
  `testAForgedChainCannotBeAnchoredOverTheOneHeld`, `testAnInsertedEntryWithoutTheKeyIsSealedThenTampered`,
  `testAPhantomSealAtSequenceZeroIsFound`, `testAFarFutureEntryIsNeverPendingForGood`,
  `testMarkingASealUnreadableNeverHidesItsDeletedSegment`, `testEditingTheAnchorColumnsChangesNothing`
- `tests/Feature/Integrity/IntegrityAlertingTest.php` `testTheEventIsPayloadFree`
- `tests/Feature/Integrity/SealerTest.php` `testTheLastRunIsRecordedEvenWithNothingToSeal`
- `tests/Unit/Documentation/DocumentationTest.php` `testTheThreatModelStatesTheLimitsOfAPhpPolicy`
- `tests/Feature/Querying/AccessControlTest.php` `testAGuessedTenantGivesTheSameEmptyResultAsAnUnknownOne`
- `tests/Feature/Querying/TrailReaderTest.php` `testADeniedScopeMakesNoQuery`

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
- what sealing, anchoring or verification leaves undetectable, or what a held key can forge
- what the access policy can see, what bypasses it, or what a read's timing can tell
