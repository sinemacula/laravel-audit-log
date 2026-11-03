# Event Model

## Purpose

This note records what the package's own events are: what each carries, when each is dispatched in each delivery mode,
what a listener's failure does, and what the write guard refuses around them. Alerting and monitoring attach to these
events, so their shape and timing are a contract, and an event that held a value of a record would copy personal data
into every listener and every queue that handles one. Tasks a listener can do are in `docs/guides/events.md`.

## Invariants

- Every event the package dispatches implements `Contracts\AuditLogEvent`, so a listener can tell them apart and the
  package never maps one of its own events to a record of itself.
- `Events\AuditRecorded` means the store accepted a record. It carries the record's `id`, `code` and `category`, and
  nothing else.
- `Events\AuditWriteFailed` means a record could not be written. It carries the record's `id` and `code`, the `store`
  class and the `exception` class, and nothing else. Each class is named as `get_debug_type()` names it, so an anonymous
  class holds no file path.
- Neither holds a value of the record, and neither holds the text of an exception, whose message can hold the row. So
  neither can carry anything into a listener, a queue payload or `failed_jobs` that a reader of the record would need
  permission for, beyond the id and the code.
- `Events\IntegrityCheckFailed` means sealing or verification found the log altered, incomplete or unverifiable, a
  `--strict` verification found a seal the anchor does not confirm, or a verification stopped before it could say. It
  carries the `command` (`seal` or `verify`), the `integrity` and `anchoring` maps, the `finding`, the `firstBadId`,
  the `head` and `remoteHead` sequences and whether the run was `complete`, and nothing else: no value of an entry and
  no text of an exception.
- Both of its maps always list every status by its value, zero-filled and in enum order, from sealing and verification
  alike. `integrity` counts segments (`valid`, `pruned`, `incomplete`, `unverifiable`, `tampered`) and `anchoring`
  counts segments (`anchored`, `unanchored`, `unavailable`, `contradicted`); a seal run's alarm counts its one failing
  condition once, so entries it skipped as malformed count 1 under `unverifiable`, never one per entry.
- `firstBadId` is a lower-case UUID or `null`: an id read from a table that was altered, which may hold a line break or
  a control character, is dropped before the event is dispatched, and the reported exception writes it `none`.
- It is dispatched by `audit-log:verify` for a run that fails at its strictness or stops (with no `finding`, `complete`
  `false`), and by `audit-log:seal` for a refused head, entries that cannot be sealed, an anchor conflict and a refused
  seal, each never `complete` and with no head. It is not dispatched for a seal run stopped by anything else, a
  malformed anchor setting among them, which is reported as an `Integrity\SealFailedException` alone, nor for an
  anchor that is only unavailable, which warns. Each dispatch is followed by the report of an
  `Integrity\IntegrityCheckFailedException` built from the event, or the stopped run's, through
  `Console\IntegrityAlarm`.
- Accepted is not always durable. For a `transactional()` write, or a write inside a transaction still open on the
  storage connection, the record is durable only when that transaction commits, and `outcomes.md` says when that is.
- Each event is dispatched outside the write it describes, so a listener never takes part in that write.
- The events are the same in both modes. What changes is the process and the moment:

  | Path                 | `AuditRecorded`                                          | `AuditWriteFailed`                                              |
  |----------------------|----------------------------------------------------------|-----------------------------------------------------------------|
  | `sync`               | After the store returns, in the process that recorded    | After the spill and any report, in the process that recorded    |
  | `outbox`, the insert | Never: an insert in the outbox dispatches nothing        | On a failed insert, at once, even before a commit that may fail |
  | `outbox`, the drain  | After the store call and the row's delete, in the drain  | At the final attempt only, in the drain                         |
  | `audit-log:replay`   | After each record a spill replay stores, or as the drain | As the drain on `--outbox`, and never for a spill line          |

## Success Path

1. In `sync` mode the store returns and `AuditRecorded` is dispatched, after a commit for a record that waited for one.
2. In `outbox` mode the insert dispatches nothing. A drain delivers the row to every destination, deletes it, and only
   then dispatches `AuditRecorded`, only when that delete changed a row, so a stale worker dispatches nothing.
3. A spill replay dispatches `AuditRecorded` for each record the store accepts, and a dry run dispatches nothing.
4. A listener registered with Laravel's dispatcher receives the event, and a queued listener is queued as any other.
5. An integrity run that fails dispatches `IntegrityCheckFailed` once, after it has printed its verdict, and then
   reports its `IntegrityCheckFailedException`.

## Failure / Edge Cases

- A crash between delete and dispatch loses an `AuditRecorded`, and never the record. In `sync` mode a process that dies
  between the store's return and the dispatch loses it in the same way, so the event is a signal and not a ledger.
- One id can be dispatched twice. A spill line replayed twice is stored once and dispatched each time, since the store's
  idempotent success is a success, so a listener that counts or alerts should be keyed on the id.
- A record dropped by a rollback and a failed write dispatch no `AuditRecorded`.
- A failed write under the `report` rule goes spill, report, event, and under a strict rule spill, event, throw, each on
  its own, so a spill that fails still leaves the event. A transactional record leaves no spill and still dispatches the
  event.
- A row that cannot be read at all, undecryptable, failing verification or abandoned past its attempts, has no code to
  name, so it is failed and reported by its id and dispatches no `AuditWriteFailed`.
- A drain's transient failure dispatches nothing, since a retry is expected to succeed; the class is on the row and the
  receipt.
- An `AuditWriteFailed` on the in-transaction outbox path goes out at once, so a host that then rolls back has still
  dispatched it, while its spill is discarded.
- A synchronous `AuditRecorded` listener's exception is reported and goes no further: not to the caller, not into
  another write and not to a later after-commit callback. A reporter that fails too is ignored. Laravel stops a dispatch
  at the first listener that throws, so the listeners behind it do not run for that record.
- An `AuditWriteFailed` listener's exception is contained the same way, in its own step, and stops neither the spill nor
  the report.
- An `IntegrityCheckFailed` listener's exception is reported as it threw and goes no further: the run's
  `IntegrityCheckFailedException` is still reported after it, and the run still exits 1. A reporter that fails too is
  ignored, since the failure is already printed. Laravel stops the dispatch at the first listener that throws, so the
  listeners behind it do not run for that alarm.
- The exception to both: a deadlock or a lost connection raised by a listener, or by the reporter of a listener's
  failure, on a connection with a transaction open has ended that transaction without Laravel knowing, whichever
  connection it is, so it propagates sanitised, as a `DeadlockException` Laravel can still retry or a
  `Stores\AuditWriteFailedException`. One on a connection with none open is contained, and a failure that names no
  connection counts when any is open. A lost connection is only ever a database failure, so a listener's cURL or Redis
  error is contained whatever its message says.
- The recursion guard, `Runtime\WriteGuard`, is active while a store runs and while a failure is handled, the reporter,
  the spill channel, the drain's failure and every `AuditWriteFailed` listener included. A record made there is not
  written: an ordinary record comes back unwritten and one report of a `\LogicException` says so, repeats inside one
  window being suppressed, and a `failClosed()` or `transactional()` record throws that `\LogicException`, because
  returning would break its guarantee. The guard is released in `finally`.
- The guard does not cover a contributor or an `AuditRecorded` listener, because a listener recording another code on
  success is a legitimate pattern. One that records unconditionally recurses, and it is the application's to stop.

## Implementation Anchors

- `src/Contracts/AuditLogEvent.php`; `src/Events/AuditRecorded.php`; `src/Events/AuditWriteFailed.php`;
  `src/Events/IntegrityCheckFailed.php`.
- `src/Console/IntegrityAlarm.php`: `raise()`, `report()`; `src/Integrity/IntegrityCheckFailedException.php`: `of()`,
  `stopped()`; `src/Integrity/VerificationSummary.php`: `toEvent()`; `src/Console/SealCommand.php`,
  `src/Console/VerifyCommand.php`.
- `src/Delivery/RecordedNotifier.php`: `notify()`; `src/Delivery/FailureHandler.php`: `handle()`.
- `src/Delivery/OutboxDrainer.php`: `drain()`; `src/Delivery/Replayer.php`: `spill()`.
- `src/Runtime/WriteGuard.php`: `during()`, `isActive()`.

## Authoritative Tests

- `tests/Unit/Events/AuditRecordedTest.php` `testCarriesTheIdCodeAndCategory`, `testCarriesNothingElse`,
  `testIsAnAuditLogEvent`
- `tests/Unit/Events/AuditWriteFailedTest.php` `testCarriesTheFourFieldsAndNothingElse`, `testIsAPackageEvent`
- `tests/Unit/Events/IntegrityCheckFailedTest.php` `testCarriesItsFieldsAndNothingElse`, `testCarriesAStoppedRun`,
  `testIsAnAuditLogEvent`
- `tests/Unit/Integrity/IntegrityCheckFailedExceptionTest.php` `testTheMessageIsPinned`,
  `testAnIdThatIsNoUuidIsNeverNamed`
- `tests/Feature/Console/IntegrityAlarmTest.php` `testDispatchesTheEventThenReportsIt`,
  `testAListenerThatFailsIsReportedAndHidesNothing`, `testAReporterThatFailsStopsNothing`,
  `testAnIdThatIsNoUuidNeverReachesAListener`
- `tests/Feature/Integrity/IntegrityAlertingTest.php` `testEveryMapHoldsEveryStatus`,
  `testAListenerThatThrowsDoesNotHideTheFailure`
- `tests/Feature/Console/SealCommandTest.php` `testASkippedEntryAlarms`, `testAMalformedAnchorSettingStillSeals`
- `tests/Feature/Console/VerifyCommandTest.php` `testAStoppedRunAlarms`, `testAMalformedAnchorSettingAlarms`
- `tests/Feature/Recording/AuditRecordedDispatchTest.php` `testDispatchedAfterAWrite`,
  `testCarriesOnlyTheIdCodeAndCategory`, `testAThrowingListenerIsReportedAndTheRowExists`,
  `testAThrowingListenerNeverReachesTheCaller`, `testDispatchedForAWriteLaterRolledBack`,
  `testNotDispatchedForADroppedRecord`, `testNotDispatchedForAFailedWrite`, `testAQueuedListenerFollowsLaravelsHandling`
- `tests/Feature/Delivery/RecordedNotifierTest.php` `testAThrowingListenerIsReportedAndContained`,
  `testAThrowingReporterIsContained`, `testAHostFatalListenerFailureInsideAHostPropagatesSanitised`,
  `testAHostFatalListenerFailureWithNoHostIsContained`, `testAReporterRecordingOnAListenerFailureDoesNotLoop`
- `tests/Feature/Delivery/FailureHandlerTest.php` `testReportDoesEachStepAndContinues`, `testTheSpillGoesFirst`,
  `testAThrowingListenerStopsNothingElse`, `testAHostFatalSecondaryFailurePropagatesSanitised`,
  `testThrowEmitsTheEventAndNeverASpill`
- `tests/Feature/Delivery/OutboxWriterTest.php` `testDispatchesNoAuditRecorded`, `testDiagnosticsGoOutAtOnce`
- `tests/Feature/Delivery/OutboxDrainerTest.php` `testAuditRecordedFollowsTheDelete`,
  `testAuditRecordedIsNotDispatchedForAFailure`, `testAThrowingAuditRecordedListenerKeepsTheRowDeleted`,
  `testTheFinalFailureDispatchesAuditWriteFailed`, `testATransientFailureIsNotReported`,
  `testAStaleOwnerDispatchesNoEvent`, `testAnUndecryptableRowIsReportedById`,
  `testTheGuardIsActiveWhileTheFinalFailureIsSaid`
- `tests/Feature/Delivery/ReplayerTest.php` `testAuditRecordedFollowsAReplay`, `testADryRunChangesNothing`
- `tests/Integration/Delivery/DrainCrashBoundariesTest.php` `testACrashAtEveryBoundaryRecovers`
- `tests/Feature/Delivery/RecordDeliveryTest.php` `testARecordInsideAStoreIsRefusedReportedAndReturned`,
  `testARecordInsideAnAuditWriteFailedListenerIsRefusedAndReported`, `testAReporterRecordingIsRefusedWithoutRecursing`,
  `testASpillChannelRecordingIsRefused`, `testARecordInsideTheDrainsAuditWriteFailedListenerIsRefused`,
  `testAFailClosedRecordInsideAStoreThrows`, `testATransactionalRecordInsideAStoreThrows`,
  `testRepeatedRefusalsReportOnce`, `testTheGuardCoversOnlyTheStore`, `testAnAuditRecordedListenerMayRecordAnotherCode`
- `tests/Unit/Runtime/WriteGuardTest.php` `testReleasesWhenTheWorkThrows`,
  `testNestedWorkKeepsItActiveUntilTheOutermostEnds`, `testTheFirstRefusalIsTheOnlyFirst`
- `tests/Feature/Delivery/NoPayloadInFailuresTest.php` `testAPlantedSecretIsInNoEvent`
- `tests/Unit/Documentation/DocumentationTest.php` `testEveryEventIsInTheEventsTable`

## Change Triggers

Update this note when any of the following change:

- an event's fields, or a package event added or removed
- when an event is dispatched, in either mode or by a replay
- what a listener's failure does, or which failures propagate
- what the write guard covers or refuses
