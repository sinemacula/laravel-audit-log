# Outcomes

## Purpose

This note records what storing a finalised record answers, from the store's side: when `AuditStore::store()` returns,
which exception it raises for each way a write can fail, and what the caller's transaction is left as. A store either
keeps the record exactly once or says why it did not, so every result is listed here and none is silent; the failure
policy that decides what the application does with each of them is not part of the store.

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
  path, so this table grows there (M5).

## Implementation Anchors

- `src/Contracts/AuditStore.php`: `store()`.
- `src/Stores/DatabaseAuditStore.php`: `store()`.
- `src/Stores/RecordConflictException.php`: `differentContent()`, `unverified()`.
- `src/Integrity/UnknownKeyException.php`, `src/Integrity/RecordSigner.php`: `verifies()`, `capturedDigest()`.

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

## Change Triggers

Update this note when any of the following change:

- what the store returns, or an exception it raises or lets propagate
- how a duplicate is told from a conflict
- what a failed audit statement leaves the host transaction as
- the failure policy, when it lands
