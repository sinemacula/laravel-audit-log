# Storage

## Purpose

This note records where and how entries are kept: the entries table and its columns, indexes and engine options, the
connections the table lives on and is maintained through, the grants each needs, the read model that never writes, and
how the database store inserts a finalised record, resolves a duplicate and leaves a host transaction usable. It also
records the two tables delivery works from, the outbox and the receipts, and the connection each is on. The table is
evidence, so what each column holds, how a time or an id is written and what the store may do to a row are fixed here; a
change to any of them changes what every stored row means.

## Invariants

- The entries table has 36 columns, in the envelope's order: the 32 of the captured record (`id`, `record_version`,
  `event`, `event_version`, `category`, `outcome`, `reason`, the `actor`, `subject`, `principal` and `tenant` type and
  id pairs, `credential_id`, `guard`, `session_id`, `request_id`, `trace_id`, `correlation_id`, `origin`, `provenance`,
  `source_id`, `source_region`, `source_record_id`, `import_batch_id`, `ip`, `user_agent`, `context`, `properties`,
  `occurred_at`), then the four of its finalisation (`recorded_at`, `integrity_version`, `key_id`, `hmac`). Every
  string column has a fixed length (`event` 191, `ip` 255, `user_agent` 512, `hmac` 64 and so on); the references are
  plain string pairs, never `morphs()`, so any key type fits and nothing cascades.
- `id` is the primary key, a UUID version 7 from capture; `id` and `import_batch_id` are written as lower-case UUIDs,
  the form PostgreSQL returns, and `FinalisedRecord` refuses any other form before a record is signed.
- `context` and `properties` are `json`, never `jsonb`: the integrity of a row never depends on an engine keeping the
  text it was given, and the canonical encoding verifies whatever key order the engine returns.
- `occurred_at` and `recorded_at` are `dateTime(6)`, deviating from the family's whole seconds so records made in one
  request sort. Both are UTC, written as `Y-m-d H:i:s.u` by `Stores\RowCodec` only, through `Support\StoredTime`; Carbon
  is never bound into a query, because the grammar's format drops microseconds and the session's time zone would move
  the instant.
- No timestamps and no foreign keys.
- The nine secondary indexes are named after the configured table: `<table>_actor_index`, `_subject_index`,
  `_principal_index`, `_tenant_index`, `_event_index`, `_category_index`, `_correlate_index`, `_occurred_index`, and
  the unique `_source_unique` over `source_id` and `source_record_id`. The longest suffix is 16 characters, so
  `entries.table` is 1 to 47 lower-case letters, digits and underscores that does not start with a digit
  (`Database\EntrySettings`), and `audit-log:check` holds the prefixed name to 47 too, so every name fits PostgreSQL's
  63. Capitals are refused because every engine reports index names in lower case and MySQL's
  `lower_case_table_names` treats a table name's case differently from one server to the next.
- On MySQL the table is `utf8mb4` with the collation `utf8mb4_0900_bin` and the `InnoDB` engine, so every character
  column, identifiers included, is binary and NO PAD: ids that differ only in case or by a trailing space stay
  distinct. MySQL must be 8.4 or later and run in strict mode, so a value that does not fit is refused instead of cut.
  MariaDB is not supported, whether through its own driver or the `mysql` one. Column-level collation is never set,
  because PostgreSQL has no such collation.
- `delivery.outbox.table` (`audit_log_outbox` by default) is on `delivery.outbox.connection`, which is the storage
  connection unless it names another. It has `id`, the record's id as its primary key, `payload` (`longText`, the
  encrypted envelope), `attempts`, `available_at`, `claimed_until`, `claimed_by` (the claim's token), `failed_at`,
  `last_error_class` and `created_at`, with every time `dateTime(6)`. It is indexed for what a drain reads. The row
  exists only until the record is delivered, and a failed row is kept. On the connection the application's transactions
  run on, a row commits exactly when they do.
- `delivery.deliveries_table` (`audit_log_deliveries` by default) is always on the storage connection, beside the
  entries it describes. Its primary key is `entry_id` and `destination`, and it has `attempts`, `first_attempted_at`,
  `delivered_at` and `last_error_class`. A receipt holds nothing of the record and is kept once its record is delivered.
- Both tables follow the entries table where it applies: the table name's grammar, no foreign keys, and on MySQL
  `utf8mb4_0900_bin` and `InnoDB`. Delivery is in `delivery.md`.
- The migrations are published under `audit-log-migrations` and never loaded from the package. Each runs on its own
  table's connection (the entries' `getConnection()` is `StorageConnection::name()`), and a collision guard refuses to
  create a table over an existing one, naming the setting that renames it, such as `entries.table`.
- `storage.connection` is the connection the table lives on (`null` or empty for the default);
  `storage.maintenance_connection` is the one pruning, holds and erasure will run through (`null` or empty for the
  storage connection). Both must reach the same physical database, the maintenance connection with credentials of its
  own; nothing writes through it yet. A value that is neither a connection name nor `null` or empty fails closed.
- Grants: the application's writer needs `SELECT` and `INSERT` on the entries table and nothing else, on every engine.
  The MySQL duplicate lookup inside a transaction is a shared locking read, which needs `SELECT` alone, never
  `FOR UPDATE`. The maintenance user has the privileges its operations need, and nothing runs DDL at runtime. Triggers
  refusing `UPDATE` and `DELETE` are optional and documented with integrity. In outbox mode the writer also needs
  `SELECT`, `INSERT`, `UPDATE` and `DELETE` on the outbox and `SELECT`, `INSERT` and `UPDATE` on the receipts; only the
  entries table stays append-only.
- The read model, `Models\AuditEntry`, takes its table and connection from the settings, has a string key, no
  timestamps and nothing mass assignable, and refuses every model write with `ImmutableEntryException`: `save()`,
  `saveQuietly()`, `update()`, `updateQuietly()`, `push()`, `touch()`, `delete()`, `deleteQuietly()`,
  `forceDelete()`, `incrementOrDecrement()`, and Laravel 13's `saveOrIgnore()` and `incrementOrDecrementEach()`. The
  query builder bypasses the model (on Laravel 12 `incrementEach()` on an entry is forwarded to it), so append-only
  access is enforced by the grants, never by the model.
- `Stores\DatabaseAuditStore` writes one plain insert per record on the storage connection's writer, never
  `insertOrIgnore`, `upsert` or a conflict clause. Outside a transaction it opens none; inside one that Laravel manages
  on the storage connection it inserts in a savepoint of one attempt, which Laravel rolls back when the insert fails.
  The guarantee is narrow: one failed audit statement does not abort a healthy host transaction on the storage
  connection. Deadlocks and other concurrency errors, lost connections and an already-aborted host transaction
  propagate.
- Laravel never releases a savepoint that succeeds, and on PostgreSQL each one is a subtransaction held until the host
  transaction ends, released or not. Past 64 in one transaction PostgreSQL's snapshots overflow and every session of
  the cluster, hot standbys included, slows until it ends, so the records stored in one host transaction are kept well
  under 64.
- A unique violation is caught outside the savepoint, once it is rolled back, and the row under the record's id is read
  on the writer. Success needs a row that verifies and holds the same captured content; it is kept as it is, its
  `recorded_at` and key included. See `outcomes.md` for every result.

## Success Path

- Publish the migrations with `vendor:publish --tag=audit-log-migrations`, set the storage settings, and run `migrate`;
  the table is created on the storage connection under `entries.table`.
- `php artisan audit-log:check` confirms the settings, the connections, the engine, the table's columns, collation and
  indexes, and the signing key, reading only and printing no secret. In outbox mode it checks the outbox and the
  receipts too, each on its own connection.
- A record finalised once is stored with one insert, and inside a host transaction with one savepoint beside it; a
  duplicate costs one more read.
- A dedicated storage connection, reaching the same database under a connection name of its own, keeps the audit
  writes out of the host's transactions: on it the store never needs a savepoint, which is the configuration for an
  application that records many entries in one transaction.

## Failure / Edge Cases

- A malformed `storage.connection`, `storage.maintenance_connection` or `entries.table` fails closed with an
  `\InvalidArgumentException` naming its full key, wherever it is read.
- An existing table under the configured name stops the migration with a `TableAlreadyExistsException` before any
  schema change.
- A non-unique statement failure inside a host transaction propagates its `QueryException`, the savepoint rolled back
  and the host transaction usable; outside one it propagates as thrown, with no lookup after it.
- A storage connection that is not a Laravel database connection, without savepoints, is refused with a
  `\LogicException`.
- A model write on an entry throws `ImmutableEntryException` before any statement runs.

## Seams Left

- `Contracts\AuditStore`, bound to `DatabaseAuditStore` by default, takes other stores; `delivery.md` has those that
  ship.
- Pruning the receipts, which are kept until then.
- Pruning, holds and erasure on the maintenance connection.
- Partitioning the entries table.

## Implementation Anchors

- `database/migrations/2026_11_02_000000_create_audit_log_entries_table.php`,
  `database/migrations/2026_11_02_000100_create_audit_log_outbox_table.php`,
  `database/migrations/2026_11_02_000200_create_audit_log_deliveries_table.php`.
- `src/Database/DeliveryTables.php`: `outboxTable()`, `deliveriesTable()`; `src/Delivery/Outbox.php`,
  `src/Delivery/Receipts.php`.
- `src/Database/StorageConnection.php`: `name()`, `forMaintenance()`; `src/Database/EntrySettings.php`: `table()`;
  `src/Database/MigrationCollisionGuard.php`: `ensureNotExists()`.
- `src/Stores/DatabaseAuditStore.php`: `store()`; `src/Stores/RowCodec.php`; `src/Support/StoredTime.php`.
- `src/Models/AuditEntry.php`, `src/Casts/UtcInstant.php`.
- `src/Console/SchemaChecks.php`, `src/Console/EngineChecks.php`, `src/Console/DeliveryChecks.php`,
  `src/Console/TableShape.php`.
- `src/AuditLogServiceProvider.php`: `registerPublishing()`; `config/audit-log.php`: `storage`, `entries`, `delivery`.

## Authoritative Tests

- `tests/Integration/Migration/EntriesTableSchemaTest.php` `testCreatesEveryColumnWithItsNullability`,
  `testSizesEveryStringColumn`, `testStoresBothTimesToTheMicrosecond`, `testThePayloadColumnsAreJsonNeverJsonb`,
  `testIndexesEveryLookupUnderItsOwnShortName`, `testEveryIndexNameFitsAtTheLongestTableName`,
  `testHasNoTimestampsAndNoForeignKeys`, `testOnMySqlEveryCharacterColumnIsBinaryWithoutPadding`,
  `testOnMySqlTheTableIsInnoDb`, `testIdsDifferingOnlyByATrailingSpaceAreDistinct`
- `tests/Integration/Migration/EntriesMigrationCollisionTest.php`
  `testAnExistingTableStopsTheMigrationNamingTheSettingThatRenamesIt`, `testTheExistingTableIsLeftAsItWas`
- `tests/Unit/Database/MigrationCollisionGuardTest.php` `testEnsureNotExistsThrowsWhenTableExists`
- `tests/Integration/Migration/StorageConnectionMigrationTest.php`
  `testTheMigrationCreatesTheTableOnTheStorageConnection`, `testTheMaintenanceConnectionNeverHoldsTheTable`
- `tests/Feature/Database/StorageConnectionTest.php` `testTheMaintenanceConnectionDefaultsToTheStorageConnection`,
  `testAMaintenanceConnectionThatIsNotANameFailsClosed`
- `tests/Feature/Database/EntrySettingsTest.php` `testRefusesATableThatCannotNameEveryIndex`
- `tests/Feature/Models/AuditEntryTest.php` `testRefusesEveryWriteThroughTheModel`, `testEveryModelWritePathIsAccountedFor`,
  `testQueryBuilderWritesBypassTheModelAsDocumented`
- `tests/Integration/Stores/DatabaseAuditStoreTest.php` `testInsideATransactionTheInsertRunsInASavepoint`,
  `testAFailedAuditInsertLeavesAHealthyHostTransactionUsable`, `testTheStoreCatchesNothingButADuplicate`
- `tests/Integration/Stores/LeastPrivilegeWriterTest.php`
  `testAWriterGrantedOnlyWhatTheStoreNeedsStoresAndResolvesDuplicates`, `testOnMySqlTheLockingReadNeedsOnlySelect`
- `tests/Integration/Stores/StoredEntryRoundTripTest.php` `testTimesStayUtcUnderNonUtcSessionAndApplicationTimeZones`,
  `testMicrosecondsSurviveIncludingTrailingZeros`
- `tests/Performance/StoreQueryBudgetTest.php` `testStoringARecordIsOneInsert`,
  `testStoringInsideATransactionAddsOnlyASavepoint`,
  `testEachRecordInsideOneTransactionHoldsASavepointUntilTheHostCommits`
- `tests/Feature/Console/SchemaChecksTest.php` `testTheShippedMigrationHasNoProblems`
- `tests/Integration/Migration/OutboxTableSchemaTest.php` `testCreatesEveryColumnWithItsNullability`,
  `testTheIdIsThePrimaryKey`, `testThePayloadIsLongText`, `testStoresEveryTimeToTheMicrosecond`,
  `testIndexesWhatTheDrainReads`, `testHasNoForeignKeys`, `testAnExistingTableStopsTheMigrationNamingTheSetting`
- `tests/Integration/Migration/DeliveriesTableSchemaTest.php` `testCreatesEveryColumnWithItsNullability`,
  `testTheKeyIsTheEntryAndTheDestination`, `testAnEntryHasOneReceiptPerDestination`, `testHasNoForeignKeys`,
  `testAnExistingTableStopsTheMigrationNamingTheSetting`
- `tests/Feature/Database/DeliveryTablesTest.php` `testTheTablesHaveTheirDefaults`,
  `testTheOutboxConnectionDefaultsToTheStorageConnection`, `testANamedOutboxConnectionIsUsed`
- `tests/Integration/Delivery/ReceiptsTest.php` `testTheReceiptsAreOnTheStorageConnectionWhenTheOutboxMoves`,
  `testAReceiptHoldsNoPayload`
- `tests/Integration/Delivery/OutboxTest.php` `testTheOutboxIsOnItsOwnConnectionWhenMoved`,
  `testTheInsertReachesTheWriter`
- `tests/Feature/Console/DeliveryChecksTest.php` `testTheOutboxTablesAreNotCheckedInSyncMode`,
  `testAnOutboxOnItsOwnConnectionIsCheckedThere`
- `tests/Feature/Console/EngineChecksTest.php` `testMariaDbThroughTheMySqlDriverIsRefusedThoughLaravelStripsItsVersion`,
  `testOnMySqlTheWriterIsCheckedNotTheReplica`

## Change Triggers

Update this note when any of the following change:

- a column, its type, its length or its nullability, in any of the three tables
- the connection the outbox or the receipts are on
- the precision of `occurred_at` or `recorded_at`
- an index, its name or its columns
- the table name's grammar or its length
- the MySQL collation or engine, or a supported engine or version
- the grants the store or the drain needs
- how the store inserts, opens a savepoint or resolves a duplicate
- a model write path, or one the query builder forwards
