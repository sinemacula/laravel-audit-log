# Outcomes

## Purpose

This note records what storing a finalised record answers, from the store's side: when `AuditStore::store()` returns,
which exception it raises for each way a write can fail, and what the caller's transaction is left as. A store either
keeps the record exactly once or says why it did not, so every result is listed here and none is silent; the failure
policy that decides what the application does with each of them is not part of the store. It also records, from the
caller's side, what each timing promises: when `record()` has a record written, what its return means, what a failed
write does to the transaction it waited for, and what `AuditRecorded` says.

## Invariants

- `AuditStore::store()` takes a finalised record, never a model, and returns nothing: returning means a row with the
  record's id is stored and holds its captured content.
- A store keeps no state between calls and stores a record at most once. The same id with the same captured content
  is a success; different content is a `Stores\RecordConflictException`; every other failure propagates unchanged.
- `DatabaseAuditStore` answers as the table below says, on every supported engine:

  | What happens                                                                     | What the caller sees                                                                          |
  |----------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
  | The record is stored                                                             | `store()` returns                                                                             |
  | A row under the id verifies and holds the same captured content                  | `store()` returns; the first row is kept, its `recorded_at` and key included                  |
  | A row under the id verifies but holds different captured content                 | `RecordConflictException::differentContent()`                                                 |
  | A row under the id fails verification                                            | `RecordConflictException::unverified()`                                                       |
  | A row under the id is signed under a key the ring does not hold                  | `UnknownKeyException`                                                                         |
  | A row under the id has an unsupported version or is malformed                    | `\UnexpectedValueException`                                                                   |
  | Another unique index is violated, the source identity included                   | the original `UniqueConstraintViolationException`, never a success                            |
  | The row under the id is beyond a PostgreSQL REPEATABLE READ or SERIALIZABLE host | the original `UniqueConstraintViolationException`, never a success                            |
  | Any other statement failure                                                      | its `QueryException`; inside a host transaction the savepoint is rolled back and it is usable |
  | A deadlock or another concurrency error inside a host transaction                | Laravel's `DeadlockException` propagates; the host handles it                                 |
  | A lost connection, or a PostgreSQL host transaction that is already aborted      | the exception propagates; the host handles it                                                 |
  | The storage connection is not a Laravel database connection                      | `\LogicException`                                                                             |

- A success is returned only after a row with the id was read on the writer, verified and found equal in captured
  content; every other path throws.
- The store decides nothing else: it never retries, never spills and never reports a failure itself.

## Success Path

- A new record returns after one insert; inside a host transaction, after one insert in a savepoint, and the host
  commits or rolls the entry back with its own work.
- A record stored again, by a retry or a replay of the same finalised record or by a second finalisation of the same
  captured record, returns without writing.

## Failure / Edge Cases

- A conflict leaves the first row as it was and, inside a host transaction, leaves the transaction usable.
- Two processes racing to store one record each wait on the other's row, then one stores it and the other resolves the
  duplicate as above; with different content, one of them is a conflict.
- The failure policy (report, spill, throw), the spill channel and the `AuditWriteFailed` event belong to the write
  path, so this table grows when the write-failure policy arrives.

## Timing

A record has exactly one timing, and `record()` returns the captured record (`AuditRecord`) whichever it is. The timing
decides when that record is stored, and so what its return promises:

| Timing            | Default for                                              | When it is written                                                         | On the host's rollback                                                            | What `record()` returning means                                             |
|-------------------|----------------------------------------------------------|----------------------------------------------------------------------------|-----------------------------------------------------------------------------------|-----------------------------------------------------------------------------|
| `afterCommit()`   | explicit records: `record()`, `event()` and `accessed()` | at the selected transaction's outermost commit; now when none is selected  | dropped unwritten, by the selected transaction or one around it on its connection | captured and held in memory; already stored only when none was selected     |
| `immediately()`   | captured records (`capture()`) and `failClosed()`        | now, in a savepoint when the storage connection has an open transaction    | rolled back on a shared connection; kept on a dedicated one                       | stored; durable once any transaction open on the storage connection commits |
| `transactional()` | nothing: it is always asked for                          | now, inside the open transaction on the storage connection, in a savepoint | rolled back with it, always                                                       | stored inside that transaction; durable only when it commits                |

- A return from an immediate record means stored only because every write failure propagates for now. Once the failure
  policy lands, a return is a stored insert only with `failClosed()` or `transactional()`.
- A write costs one insert, and a savepoint as well when a transaction is open on the storage connection. A deferred
  record costs nothing until the commit, and a dropped one nothing at all. These budgets cover the default contributors
  and a fresh insert.

### After Commit

- Without a name, the innermost pending transaction on any connection is selected. `afterCommit('billing')` pins that
  connection's innermost: a transaction on another connection neither delays nor cancels the record, and with only
  another connection's transaction open it is written now.
- A name no connection is configured under is an `\InvalidArgumentException` from `record()`, which opens no connection
  and writes nothing.
- Selecting the innermost promises nothing about a transaction around it on another connection. The write happens on
  the innermost's commit, so while a transaction is still open on the storage connection the write is inside it, and
  that transaction's rollback takes it away.
- A dedicated storage connection does not change what is selected: a default record waits for the host's transaction
  and is dropped by its rollback, though nothing would have rolled the row back. To keep a record whatever the host
  does, write it `immediately()` or pin the dedicated connection.
- A connection named with a read or write selector, such as `afterCommit('reporting::write')`, is the connection it
  selects, so the record waits for that connection's transaction and goes with its rollback.
- A transaction the testing manager wraps a test in is never selected, so a record inside only that wrapper is written
  at once. The current manager is read on every record, so one swapped in later is the one consulted.
- `occurred_at` is when the record was captured and `recorded_at` when it was written.
- A record waiting for its commit exists only in memory, so a process that dies between the commit and the write loses
  it. `transactional()`, and the outbox when it arrives, close that gap.

### Immediately and the Savepoint

- The savepoint adds isolation, not durability. It stops a failed audit insert poisoning a healthy host transaction,
  and it keeps nothing past that transaction's rollback.
- For a record to survive a host rollback, `storage.connection` names a dedicated connection and the record is written
  immediately. The host's transaction is not open on that connection, so no savepoint is used.

### Transactional

- `transactional()` needs a transaction already open on the storage connection. Its preconditions are checked when
  `record()` runs, before any contributor. Each refusal is a `\LogicException`, writes nothing and leaves the builder
  usable, so the same builder can be recorded once a transaction is open. It is refused when:
  - it names a connection other than the storage connection, even one with a transaction open, since that needs the
    outbox, which has not arrived yet
  - no transaction is open on the storage connection, even when one is open on the host's and storage is dedicated
  - the storage connection is not a Laravel database connection
- A test's wrapping transaction counts as open, so inside only that wrapper a `transactional()` record is accepted.
- A failed write propagates, and its savepoint leaves the host's transaction usable. The caller must not catch the
  exception and commit, since the business change would then commit without its record; left uncaught, it rolls the
  business change back.
- The check reads the storage connection and never the store, so the atomicity is `DatabaseAuditStore`'s. A custom store
  that writes elsewhere does not share the transaction.

### Fail Closed

- A `failClosed()` record is written immediately unless it is transactional, when it stays transactional and needs the
  transaction. `failClosed()` never combines with `afterCommit()`, whichever is called first (see `record-model.md`).
- A return means the insert succeeded, and it is durable once any transaction open on the storage connection commits.
- Every write failure propagates for now, so `failClosed()` chooses only the timing until the failure policy sets
  it apart from a plain immediate record.

### A Failed Write

- Every write failure propagates, unchanged, to whoever runs the write. The write-failure policy replaces this.
- An immediate or transactional write, or an after-commit write with no transaction selected, fails inside `record()`.
- **An after-commit write failure surfaces after the business data has committed.** The exception comes out of the code
  that committed, `commit()` or `DB::transaction()`, long after `record()` returned. The business data stays committed,
  the connection is out of its transaction and no row exists, so the exception does not mean a rollback, and retrying
  the work repeats what already committed.
- That failure stops the after-commit callbacks registered behind the record, because Laravel runs them in order and
  nothing catches the exception. The callbacks before it have already run.

### AuditRecorded

- `AuditRecorded` means the store accepted the record. It carries the record's id, code and category and nothing else,
  so no value of the record reaches a listener.
- Accepted is not always durable. For a `transactional()` write, or an immediate write inside a transaction, the record
  is durable only when that transaction commits: the event is dispatched before the commit, and a rollback afterwards
  takes the row away. The same goes for an after-commit write made inside a transaction still open on the storage
  connection.
- A record dropped by a rollback and a failed write dispatch nothing.
- It is dispatched outside the write. A synchronous listener's exception is reported and goes no further: not to the
  caller, not into another write and not to a later after-commit callback. A reporter that fails too is ignored. Laravel
  stops a dispatch at the first listener that throws, so the listeners behind it do not run for that record.
- A queued listener is queued as any other, and what becomes of it follows Laravel's normal handling.
- A listener or a contributor that makes a record from inside itself can recurse. The guard against that belongs to the
  write path, and it has not arrived yet.

## Implementation Anchors

- `src/Contracts/AuditStore.php`: `store()`.
- `src/Stores/DatabaseAuditStore.php`: `store()`.
- `src/Stores/RecordConflictException.php`: `differentContent()`, `unverified()`.
- `src/Integrity/UnknownKeyException.php`, `src/Integrity/RecordSigner.php`: `verifies()`, `capturedDigest()`.
- `src/Records/Concerns/ChoosesDelivery.php`: `afterCommit()`, `immediately()`, `transactional()`, `failClosed()`.
- `src/Delivery/RecordDelivery.php`: `check()`, `deliver()`.
- `src/Database/AfterCommit.php`: `run()`.
- `src/Events/AuditRecorded.php`.

## Authoritative Tests

- `tests/Integration/Stores/DatabaseAuditStoreTest.php` `testStoresTheFinalisedRecordAsOneRow`,
  `testTheSameRecordStoredTwiceIsOneRow`, `testTheSameContentWithADifferentRecordedAtKeepsTheFirstRow`,
  `testTheSameContentSignedWithAnotherKeyKeepsTheFirstRow`, `testDifferentContentUnderTheSameIdIsAConflict`,
  `testATamperedRowWithItsOldHmacIsAConflict`, `testAnExistingRowUnderAnUnknownKeyPropagates`,
  `testAMalformedExistingRowPropagates`, `testASourceIdentityViolationPropagatesTheOriginalException`,
  `testAViolationOfAnotherUniqueIndexPropagates`, `testAFailedAuditInsertLeavesAHealthyHostTransactionUsable`,
  `testADuplicateResolvedInsideAHostTransactionLeavesItUsable`, `testAnAlreadyAbortedPostgresHostTransactionPropagates`,
  `testTheStoreCatchesNothingButADuplicate`, `testAConnectionWithoutTransactionsIsRefused`
- `tests/Integration/Stores/ConcurrentDuplicatesTest.php` `testAConcurrentDuplicateWithTheSameContentStoresOneRow`,
  `testAConcurrentDuplicateWithDifferentContentIsAConflict`,
  `testOnMySqlALockWaitTimeoutInsideAHostTransactionPropagates`
- `tests/Integration/Stores/HostTransactionCallbacksTest.php` `testAHostCallbackSurvivesAFailedAuditInsert`,
  `testARolledBackHostDropsItsCallbackAndTheEntry`
- `tests/Unit/Stores/RecordConflictExceptionTest.php` `testDifferentContentNamesTheIdAndKeepsIt`,
  `testAnUnverifiedRowNamesTheIdAndKeepsIt`
- `tests/Integration/Delivery/AfterCommitTimingTest.php` `testWrittenOnCommit`, `testDroppedOnRollback`,
  `testDroppedOnAnInnerRollbackOfTheSelectedTransaction`, `testAnInnerRollbackKeepsARecordOfTheOuterTransaction`,
  `testAnInnerCommitWaitsForTheOuterCommit`, `testDroppedOnAnOuterRollbackAfterAnInnerCommit`,
  `testWrittenNowWithNoTransaction`, `testTheCapturedRecordIsReturnedBeforeItIsWritten`,
  `testOccurredAtIsCaptureTimeAndRecordedAtIsWriteTime`, `testTheDefaultSelectsTheInnermostOnAnyConnection`,
  `testNestedTransactionsOnTwoConnectionsWriteOnTheInnermostsCommit`,
  `testAWriteInsideAnOpenStorageTransactionRollsBackWithIt`, `testPinningWaitsForThatConnectionWhileAnotherIsInnermost`,
  `testPinningWritesNowWhenOnlyAnotherConnectionIsOpen`, `testAPinnedRecordIsDroppedByItsOwnConnectionsRollback`,
  `testPinningAReadOrWriteSelectorStillDefers`, `testARecordPinnedWithASelectorIsDroppedOnRollback`,
  `testAPinnedRecordIgnoresTheOtherConnectionsRollback`, `testPinningAnUnknownConnectionIsRefusedAndWritesNothing`,
  `testAFailedWriteSurfacesAfterTheBusinessDataHasCommitted`, `testAFailedWriteStopsLaterAfterCommitCallbacks`,
  `testTheDedicatedDefaultIsDroppedByAHostRollback`, `testPinningTheDedicatedConnectionIgnoresTheHostsRollback`
- `tests/Integration/Delivery/TestingManagerTimingTest.php` `testTheWrapperIsNotSelected`,
  `testARecordInsideOnlyTheWrapperIsWrittenAtOnce`, `testANestedTransactionDefersToItsCommit`,
  `testANestedRollbackDropsTheRecord`, `testAManagerSwappedAfterTheRecorderIsResolvedIsConsulted`,
  `testTheSameBehaviourUnderLaravelsOwnManager`, `testATransactionalRecordIsAcceptedInsideOnlyTheWrapper`
- `tests/Integration/Delivery/TransactionalTimingTest.php` `testAtomicWithTheHostOnCommit`, `testRolledBackWithTheHost`,
  `testRefusedWithNoOpenTransaction`, `testRefusedWhenTheTransactionIsOnAnotherConnection`,
  `testRefusedNamingAnotherConnection`, `testAcceptedNamingTheStorageConnection`, `testARefusalLeavesTheBuilderUsable`,
  `testAFailedWritePropagatesAndTheHostStaysUsable`, `testAFailedWriteLeftUncaughtRollsBackTheBusinessChange`,
  `testFailClosedTransactionalStaysTransactional`, `testRefusedOnADedicatedConnectionWithOnlyTheHostsTransactionOpen`
- `tests/Integration/Delivery/ImmediateTimingTest.php` `testWrittenNowInsideATransaction`,
  `testRolledBackWithTheHostOnASharedConnection`, `testSurvivesAHostRollbackOnADedicatedConnection`,
  `testAFailedWritePropagatesAndTheHostStaysUsable`, `testFailClosedIsWrittenNow`,
  `testAFailClosedRecordsFailedWriteReachesTheCallerAtTheCall`, `testFailClosedSurvivesOnADedicatedConnection`,
  `testAuditRecordedIsDispatchedBeforeTheHostCommits`
- `tests/Performance/RecorderQueryBudgetTest.php` `testOneExplicitRecordIsOneInsert`,
  `testAnExplicitRecordInATransactionCostsNothingUntilCommit`, `testADroppedRecordCostsNothing`,
  `testATransactionalRecordIsOneInsertAndASavepoint`, `testAnImmediateRecordOutsideATransactionIsOneInsert`,
  `testAnImmediateRecordInsideATransactionAddsOnlyASavepoint`, `testTheBudgetExcludesAQueryingContributor`
- `tests/Feature/Recording/AuditRecordedDispatchTest.php` `testDispatchedAfterAWrite`,
  `testCarriesOnlyTheIdCodeAndCategory`, `testAThrowingListenerIsReportedAndTheRowExists`,
  `testAThrowingListenerNeverReachesTheCaller`, `testDispatchedForAWriteLaterRolledBack`,
  `testNotDispatchedForADroppedRecord`, `testNotDispatchedForAFailedWrite`, `testAQueuedListenerFollowsLaravelsHandling`
- `tests/Feature/Delivery/RecordDeliveryTest.php` `testAThrowingReporterIsContained`,
  `testANotificationFailureNeverCausesAnotherWrite`, `testAThrowingListenerDoesNotStopALaterAfterCommitCallback`,
  `testTransactionalOnAForeignConnectionIsRefused`, `testADeferredWritesFailureReachesTheCommit`

## Change Triggers

Update this note when any of the following change:

- what the store returns, or an exception it raises or lets propagate
- how a duplicate is told from a conflict
- what a failed audit statement leaves the host transaction as
- the failure policy, when it lands
- when a timing writes a record, what a rollback does to it, or what `record()` returning means
- what `transactional()` or `failClosed()` needs or refuses
- what a failed after-commit write does to the commit or to later callbacks
- what `AuditRecorded` carries or means, or how a listener's failure is handled
