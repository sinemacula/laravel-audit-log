# Storage

## Purpose

This note records where and how entries are kept: the entries table and its columns, indexes and engine options, the
artifacts table beside it, the connections the tables live on and are maintained through, the grants each needs, the
read model that never writes, and how the database store inserts a finalised record, resolves a duplicate and leaves a
host transaction usable. It also records the two tables delivery works from, the outbox and the receipts, and the
connection each is on, the three tables integrity works from, the checkpoints, their members and the integrity state,
the four tables the lifecycle works from, the journal, the holds, the lock and the import batches, the installation's
identity, and the grants and optional triggers that keep the log append-only, for each of the writer, the maintenance
user and the verifier, as SQL the tests run. The table is evidence, so what each column holds, how a time or an id is
written and what the store may do to a row are fixed here; a change to any of them changes what every stored row means.

## Invariants

- The entries table has 37 columns, in the envelope's order: the 33 of the captured record (`id`, `record_version`,
  `event`, `event_version`, `category`, `outcome`, `reason`, the `actor`, `subject`, `principal` and `tenant` type and
  id pairs, `credential_id`, `guard`, `session_id`, `request_id`, `trace_id`, `correlation_id`, `origin`, `provenance`,
  `source_id`, `source_region`, `source_record_id`, `import_batch_id`, `source_digest`, `ip`, `user_agent`, `context`,
  `properties`, `occurred_at`), then the four of its finalisation (`recorded_at`, `integrity_version`, `key_id`,
  `hmac`). Every string column has a fixed length (`event` 191, `ip` 255, `user_agent` 512, `hmac` 64 and so on); the
  references are plain string pairs, never `morphs()`, so any key type fits and nothing cascades.
- `source_digest` (`string(64)`, nullable) is the keyed digest of an imported record's source assertion, which tells a
  repeated import from a conflicting one; it is null on every captured record and not indexed, since duplicates are
  found through `<table>_source_unique`.
- `id` is the primary key, a UUID version 7 from capture; `id` and `import_batch_id` are written as lower-case UUIDs,
  the form PostgreSQL returns, and `FinalisedRecord` refuses any other form before a record is signed.
- `context` and `properties` are `json`, never `jsonb`: the integrity of a row never depends on an engine keeping the
  text it was given, and the canonical encoding verifies whatever key order the engine returns.
- `occurred_at` and `recorded_at` are `dateTime(6)`, deviating from the family's whole seconds so records made in one
  request sort. Both are UTC, written as `Y-m-d H:i:s.u` by `Stores\RowCodec` only, through `Support\StoredTime`; Carbon
  is never bound into a query, because the grammar's format drops microseconds and the session's time zone would move
  the instant.
- No timestamps and no foreign keys.
- The ten secondary indexes are named after the configured table, `<table>` followed by each suffix below, with their
  columns in this order:

  | Suffix             | Columns                                               |
  |--------------------|-------------------------------------------------------|
  | `_actor_index`     | `actor_type`, `actor_id`, `occurred_at`, `id`         |
  | `_subject_index`   | `subject_type`, `subject_id`, `occurred_at`, `id`     |
  | `_principal_index` | `principal_type`, `principal_id`, `occurred_at`, `id` |
  | `_tenant_index`    | `tenant_type`, `tenant_id`, `occurred_at`, `id`       |
  | `_event_index`     | `event`, `occurred_at`, `id`                          |
  | `_category_index`  | `category`, `occurred_at`, `id`                       |
  | `_correlate_index` | `correlation_id`                                      |
  | `_occurred_index`  | `occurred_at`, `id`                                   |
  | `_recorded_index`  | `recorded_at`, `id`                                   |
  | `_source_unique`   | `source_id`, `source_record_id`, unique               |

- Each lookup index of the trail, the actor, subject, principal, tenant, event, category and occurred indexes, ends in
  `occurred_at` and then `id`, the order a page of the trail is read in, so a keyset page reads its index in order and
  is never sorted, entries of one microsecond included; no collation is applied to `id`, which compares in the type the
  migration gives it. Sealing pages through `_recorded_index` over `recorded_at` and `id`, in that order.
- A read that combines conditions, such as a scope of several tenants or a tenant with an actor or a code, uses one
  index and filters the rest of its conditions row by row, so it costs the rows that index matches rather than the rows
  returned; `tests/Integration/Querying/TrailPlansTest.php` reads each engine's plan.
- The longest suffix is 16 characters, so `entries.table` is 1 to 47 lower-case letters, digits and underscores that
  does not start with a digit (`Database\EntrySettings`), and `audit-log:check` holds the prefixed name to 47 too, so
  every name fits PostgreSQL's 63. Capitals are refused because every engine reports index names in lower case and
  MySQL's `lower_case_table_names` treats a table name's case differently from one server to the next.
- On MySQL the table is `utf8mb4` with the collation `utf8mb4_0900_bin` and the `InnoDB` engine, so every character
  column, identifiers included, is binary and NO PAD: ids that differ only in case or by a trailing space stay
  distinct. MySQL must be 8.4 or later and run in strict mode, so a value that does not fit is refused instead of cut.
  MariaDB is not supported, whether through its own driver or the `mysql` one. Column-level collation is never set,
  because PostgreSQL has no such collation.
- `entries.artifacts_table` (`audit_log_artifacts` by default) is always on the storage connection, beside the entries
  that name its rows. It holds one row per bulk operation, in seven columns: `id`, the artifact's own UUID and its
  primary key; `entry_id`, the UUID of the entry whose signed manifest names the artifact, under the unique
  `<table>_entry_unique`, so an entry has at most one artifact; `kind` (`string(16)`, `bulk`); `member_count`
  (`unsignedInteger`); `digest` (`string(64)`, the SHA-256 of the canonical member list in hex); `members`
  (`longText`, the canonical member list encrypted with the application's key); and `created_at` (`dateTime(6)`, the
  entry's `recorded_at`). It follows the entries table: the table name's grammar, no foreign keys, and on MySQL
  `utf8mb4_0900_bin` and `InnoDB`, so an artifact commits with its entry.
- An artifact is written with its entry and never changed. It is kept as long as its entry and deleted only with it, by
  the maintenance user, so the artifacts are append-only evidence as the entries are.
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
- `integrity.checkpoints_table` (`audit_log_checkpoints` by default), `integrity.members_table`
  (`audit_log_checkpoint_members`) and `integrity.state_table` (`audit_log_integrity_state`) are always on the storage
  connection, beside the entries they describe, and no setting moves them (`Database\IntegrityTables`). Each follows
  the entries table: the table name's grammar, no foreign keys, and on MySQL `utf8mb4_0900_bin` and `InnoDB`, so a seal
  and its members commit together.
- The checkpoints table holds one seal per row, in 21 columns: the 17 a seal is inserted with (`id`, `sequence`,
  `log_id`, `previous_id`, `previous_digest`, `member_count`, `members_digest`, `seal_digest`, `first_recorded_at`,
  `last_recorded_at`, `sealed_at`, `signer`, `key_id`, `algorithm_version`, `journal_sequence`, `journal_head`,
  `signature`), then the four anchor columns (`anchor`, `anchor_receipt`, `anchored_at`, `anchor_error_class`).
  `journal_sequence` (a signed `bigInteger`) and `journal_head` (`string(64)`) are the lifecycle journal's head when the
  seal was made, its sequence and its HMAC, both null when the journal was empty, and signed with the seal. Every digest
  and the signature are `string(64)`, as `hmac` is; `sequence` is a signed `bigInteger`, every time `dateTime(6)` and
  `anchor_receipt` `json`. Its indexes are the unique `<table>_sequence_unique`, so two sealers can never both extend
  the head, `<table>_anchored_index` over `anchored_at` and `sequence`, what the anchorer reads, and
  `<table>_journal_index` over `journal_sequence`, the highest commitment to the journal every destructive operation
  checks.
- The anchor columns are the only ones written after a seal is inserted: `Integrity\Anchorer` writes them, a cache of
  the anchor's receipt and never the authority. Nothing else updates or deletes a seal, and nothing updates or deletes
  a member.
- The members table has `checkpoint_id`, `entry_id` and `hmac` (`string(64)`, the entry's HMAC when it was sealed),
  keyed by `<table>_primary` over the seal and the entry, with the unique `<table>_entry_unique` on `entry_id`: an
  entry belongs to at most one seal. A member is written once, with its seal.
- The integrity state table has `name` (`string(64)`, its primary key), `value` (`text`, a JSON map of scalars) and
  `updated_at` (`dateTime(6)`): the operational progress of sealing, anchoring, the sweep and verification
  (`Database\IntegrityProgress`). It is never evidence, so its rows may be updated and deleted and no trigger covers
  it.
- The integrity state table also holds the installation's identity, `installation.id`, a JSON object `{id}` with a UUID
  version 7 (`Database\InstallationIdentity`), which the migration that creates the table seeds. It is written once,
  through the storage connection's writer, with a plain insert that never replaces one, so the first write wins: the
  migration's, or, when the seeded row was lost, the next seal run's or lifecycle operation's. `audit-log:check` only
  reads it, and reports one that is missing. It is never progress, so `IntegrityProgress` never reads or writes it.
  Every lifecycle operation confirms, before it takes the lock, that the maintenance connection reads the same id the
  storage connection does.
- `lifecycle.journal_table` (`audit_log_lifecycle` by default), `lifecycle.holds_table` (`audit_log_holds`),
  `lifecycle.lock_table` (`audit_log_lifecycle_lock`) and `import.batches_table` (`audit_log_import_batches`) are
  always on the storage connection, beside the entries and the seals they describe, and no setting moves them
  (`Database\LifecycleTables`). Each follows the entries table: the table name's grammar, no foreign keys, and on MySQL
  `utf8mb4_0900_bin` and `InnoDB`, so each commits with what it describes.
- The journal holds one signed row per lifecycle event, in 17 columns: `id`, `sequence` (a signed `bigInteger`, 1, 2,
  3 … with no gap, under the unique `<table>_sequence_unique`), `log_id`, `kind`, `operation_id`, `occurred_at`,
  `authority_type`, `authority_id`, `reason`, `external_reference`, `seal_id`, `hold_id`, `payload`, `payload_digest`,
  `previous_hmac`, `key_id` and `hmac`. The payload is canonical JSON as `longText`, never a JSON column, so the digest
  the signature covers is the digest of the bytes stored. It is indexed by `<table>_seal_index`, `<table>_hold_index`
  and `<table>_kind_index` over `kind` and `occurred_at`. A row is written only through the maintenance connection,
  inside the lifecycle lock, and the journal is never updated or deleted, by a prune or anything else.
- The holds table is the projection of the active holds, in 13 columns: `hold_id`, its primary key, `scope`
  (`longText`), `scope_digest`, `basis`, `import_batch_id`, `placed_at`, `review_by`, `authority_type`,
  `authority_id`, `reason`, `external_reference`, `operation_id` and `journal_sequence`, indexed by
  `<table>_review_index` and `<table>_batch_index`. It is a convenience index for listing holds and for
  `audit-log:check`, written only through the maintenance connection: a row is inserted when its hold is placed and
  deleted when it is released or the projection is rebuilt from the journal, and never updated. The holds projection is
  never trusted by a prune, which decides what it keeps from the verified journal alone.
- The lock table holds one row, `id` 1 (`smallInteger`, its primary key), seeded by its migration, with `token`
  (`string(64)`) and `locked_at` (`dateTime(6)`). The lock row is seeded and only updated: the first statement of every
  lifecycle transaction updates it, and nothing inserts another or deletes it.
- The import batches table holds one row per import, in 21 columns: `id`, its primary key, `source_id`,
  `source_region`, `input_format`, `importer_type`, `importer_id`, `reason`, `external_reference`, `file_sha256`,
  `externally_verified` (`boolean`, always written), `hold_id`, `status`, the counts `lines_read`, `imported`,
  `duplicates`, `conflicts` and `rejected` (`integer`), `conflict_ids` (`text`, a canonical JSON list), `started_at`,
  `updated_at` and `finished_at`, indexed by `<table>_status_index` over `status` and `updated_at`. The storage
  connection's writer inserts a batch before its first entry and then updates only its status, counts, conflict ids and
  times. No column is named a reserved word on any engine (`lines_read`, `input_format`), and a batch is never deleted.
- The migrations are published under `audit-log-migrations` and never loaded from the package. Each runs on its own
  table's connection (the entries' `getConnection()` is `StorageConnection::name()`), and a collision guard refuses to
  create a table over an existing one, naming the setting that renames it, such as `entries.table`.
- `storage.connection` is the connection the table lives on (`null` or empty for the default);
  `storage.maintenance_connection` is the connection pruning, holds and the lifecycle journal run through (`null` or
  empty for the storage connection). Both must reach the same physical database, the maintenance connection with
  credentials of its own, which the installation id confirms. A value that is neither a connection name nor `null` or
  empty fails closed.
- Grants: to record, the application's writer needs `SELECT` and `INSERT` on the entries and the artifacts tables and
  nothing else, on every engine. The MySQL duplicate lookup inside a transaction is a shared locking read, which needs
  `SELECT` alone, never `FOR UPDATE`. Sealing, anchoring, the sweep and verification need the grants under Grants And
  Triggers below, where the optional triggers are too; the maintenance user has the privileges its operations need, and
  nothing changes the schema at runtime, except the documented SQLite prune, which drops and recreates the delete
  triggers inside its own transaction. In outbox mode the writer also needs `SELECT`, `INSERT`, `UPDATE` and `DELETE` on
  the outbox and `SELECT`, `INSERT` and `UPDATE` on the receipts; only the entries, the artifacts and the integrity
  evidence stay append-only.
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
  under 64. Captured records count as well: a Gate denial or an authentication event written at once inside a host
  transaction on the storage connection, and a watched model's change inserted into the outbox inside its own
  transaction, each hold one, so busy watched models or Gate capture on PostgreSQL want the storage, or the outbox, on
  a connection of their own.
- A unique violation is caught outside the savepoint, once it is rolled back, and the row under the record's id is read
  on the writer. Success needs a row that verifies and holds the same captured content; it is kept as it is, its
  `recorded_at` and key included. See `outcomes.md` for every result.

## Success Path

- Publish the migrations with `vendor:publish --tag=audit-log-migrations`, set the storage settings, and run `migrate`;
  the table is created on the storage connection under `entries.table`.
- `php artisan audit-log:check` confirms the settings, the connections, the engine, the entries and the artifacts
  tables' columns, collation and indexes, and the signing key, reading only and printing no secret. In outbox mode it
  checks the outbox and the receipts too, each on its own connection.
- A record finalised once is stored with one insert, and inside a host transaction with one savepoint beside it; a
  duplicate costs one more read.
- A dedicated storage connection, reaching the same database under a connection name of its own, keeps the audit
  writes out of the host's transactions: on it the store never needs a savepoint, which is the configuration for an
  application that records many entries in one transaction.
- The artifacts migration creates the artifacts table on the storage connection under `entries.artifacts_table`.
- The integrity migrations create the checkpoints, the members and the integrity state tables on the storage connection.
  Run as the tables' owner once the users exist, the documented grants give a writer what recording, sealing, anchoring,
  the sweep and verification need, and the documented triggers leave every one of them working.
- The lifecycle migrations create the journal, the holds, the lock, with its one row, and the import batches on the
  storage connection.

## Failure / Edge Cases

- A malformed `storage.connection`, `storage.maintenance_connection`, `entries.table` or `entries.artifacts_table`
  fails closed with an `\InvalidArgumentException` naming its full key, wherever it is read.
- An existing table under the configured name stops the migration with a `TableAlreadyExistsException` before any
  schema change, naming the setting that renames it, `lifecycle.journal_table` or `import.batches_table` included.
- A malformed `lifecycle.journal_table`, `lifecycle.holds_table`, `lifecycle.lock_table` or `import.batches_table`
  fails closed with an `\InvalidArgumentException` naming its full key, never its value.
- A maintenance connection that reads no installation id, or another than the storage connection, is refused with an
  `InstallationMismatchException` naming no value; an installation id that is not a JSON object `{id}` of a lower-case
  UUID reads as absent, and is never replaced. A storage connection that reads no installation id is a problem
  `audit-log:check` reports, never one it writes.
- A non-unique statement failure inside a host transaction propagates its `QueryException`, the savepoint rolled back
  and the host transaction usable; outside one it propagates as thrown, with no lookup after it.
- A storage connection that is not a Laravel database connection, without savepoints, is refused with a
  `\LogicException`.
- A model write on an entry throws `ImmutableEntryException` before any statement runs.
- A writer granted only the documented privileges is refused, by the engine, an update or a delete of an artifact, an
  update of an immutable checkpoint column, an update or a delete of a member, a delete of a seal, a `TRUNCATE` of any
  of the package's tables and any DDL, and any write of the journal, the holds or the lock; the maintenance user is
  refused everything but its documented privileges, so it inserts the journal and never updates or deletes a row of it.
- Under the documented triggers, an update of an entry, an artifact, a member, a journal row or a hold, a change to an
  immutable checkpoint or batch column or to the lock's `id`, a delete of a member, a seal, a journal row, a batch or
  the lock, and a delete of an entry, an artifact or a hold by anyone but the maintenance user are refused with an error
  naming the table and the statement, such as `audit_log_entries refuses DELETE`; the tables' owner is refused too.

## Grants And Triggers

The grants are what keep the log append-only; the triggers are an optional second line on the same tables. Two
guarantees are stated apart. Database credentials can still destroy rows: the grants and triggers decide which
credentials can, and the maintenance credentials can delete what pruning deletes. The package's cryptographic evidence
makes an unauthorised destruction detectable, never impossible. Both are the SQL below, which the integration tests run
as written, each block found by the marker line before it. Replace `app_db`, `audit_writer`, `audit_maintenance` and
`audit_verifier` with your database and users. Create the users first, run each block as the tables' owner, and rename
a table in the SQL when its setting renames it.

The role matrix is what the blocks grant, per table and user; "outbox mode" marks the grants the writer needs only
when delivery runs through the outbox, which the blocks leave out:

| Table                          | Writer                                                       | Maintenance                                   | Verifier                     |
|--------------------------------|--------------------------------------------------------------|-----------------------------------------------|------------------------------|
| `audit_log_entries`            | `SELECT`, `INSERT`                                           | `SELECT`, `DELETE`                            | `SELECT`                     |
| `audit_log_artifacts`          | `SELECT`, `INSERT`                                           | `SELECT`, `DELETE`                            | `SELECT`                     |
| `audit_log_outbox`             | outbox mode: `SELECT`, `INSERT`, `UPDATE`, `DELETE`          | `SELECT`, when on the storage database        | none                         |
| `audit_log_deliveries`         | outbox mode: `SELECT`, `INSERT`, `UPDATE`                    | `SELECT`, `DELETE`                            | none                         |
| `audit_log_checkpoints`        | `SELECT`, `INSERT`, `UPDATE` of the four anchor columns      | `SELECT`                                      | `SELECT`                     |
| `audit_log_checkpoint_members` | `SELECT`, `INSERT`                                           | `SELECT`                                      | `SELECT`                     |
| `audit_log_integrity_state`    | `SELECT`, `INSERT`, `UPDATE`, `DELETE`                       | `SELECT`                                      | `SELECT`, `INSERT`, `UPDATE` |
| `audit_log_lifecycle`          | `SELECT`                                                     | `SELECT`, `INSERT`                            | `SELECT`                     |
| `audit_log_holds`              | `SELECT`                                                     | `SELECT`, `INSERT`, `DELETE`                  | `SELECT`                     |
| `audit_log_lifecycle_lock`     | none                                                         | `SELECT`, `UPDATE` of `token` and `locked_at` | none                         |
| `audit_log_import_batches`     | `SELECT`, `INSERT`, `UPDATE` of the status, counts and times | none                                          | none                         |

- The writer, the application's user, is granted `SELECT` and `INSERT` on the entries, the artifacts, the checkpoints
  and the members, `UPDATE` on the checkpoints' four anchor columns alone, and `SELECT`, `INSERT`, `UPDATE` and `DELETE`
  on the integrity state table. That is everything recording, sealing, anchoring and verification need, and the `DELETE`
  is for the sweep, which forgets its cursor when it completes. It also holds `SELECT` on the journal and the holds,
  because sealing reads the journal's head and verification and `audit-log:check` read both, and `SELECT` and `INSERT`
  on the import batches, with `UPDATE` of their status, counts, conflict ids and times alone. A `TRUNCATE` and any
  change to an entry, an artifact, a member or an immutable checkpoint column are refused by the engine; column grants
  exist on MySQL and PostgreSQL only.
- For pruning, holds and the lifecycle journal, the maintenance user is granted `SELECT` and `DELETE` on the entries,
  the artifacts and the deliveries, because pruning deletes an entry's artifact and receipts with it and keeps every
  checkpoint and member; `SELECT` on the checkpoints, the members, the integrity state, for the installation id, and the
  outbox when it is on the storage database; `SELECT` and `INSERT` on the journal; `SELECT`, `INSERT` and `DELETE` on
  the holds; and `SELECT` and `UPDATE` of `token` and `locked_at` alone on the lock.
- There is no DDL for the application user: no documented user holds `DROP`, `TRUNCATE`, `TRIGGER` or `ALTER`, or
  creates anything. On PostgreSQL before 15, also revoke `CREATE` on the `public` schema from `PUBLIC`.
- Verification needs `SELECT` on the entries, the artifacts, the checkpoints, the members, the journal and the holds,
  and the user that runs `audit-log:verify` also needs `SELECT`, `INSERT` and `UPDATE` on the integrity state table,
  where a full run records that it completed. The verifier, an optional third user for scheduled verification, holds
  exactly those; the writer may verify instead, as it holds them too. The verifier role never needs delete-capable
  credentials to read prune evidence, which is read on the storage connection. On PostgreSQL every user also needs
  `CONNECT` on the database and `USAGE` on the schema, which grant no table privilege.
- The triggers refuse every change except a maintenance delete of an entry, an artifact or a hold, an update of a
  seal's anchor columns, of a batch's status, counts, conflict ids and times, and of the lock's token and time. Each
  table gets `<table>_no_update` and `<table>_no_delete`: an entry or an artifact is never updated and only the
  maintenance user deletes one, a member is never updated or deleted, and a seal is never deleted, while an update that
  changes any of its 17 immutable columns is refused and one of the four anchor columns alone is allowed. A journal row
  is never updated or deleted, with no maintenance exception; a hold is never updated and only the maintenance user
  deletes one; a batch is never deleted, and an update that changes its identity, source, importer, file, hold or start
  is refused; the lock row is never deleted, and an update that changes its `id` is refused. Every refusal is an error
  naming the table and the statement.
- On PostgreSQL, the delete trigger allows the maintenance user by `current_user`. On MySQL, `CURRENT_USER()` in a
  trigger is the definer, so the MySQL triggers read `USER()`, compared byte for byte. `USER()` is the name the client
  gave, so on MySQL the grants, not the triggers, are the boundary: install the triggers as a second line, or prefer
  grants alone.
- A row trigger never fires on `TRUNCATE`, so PostgreSQL also gets `<table>_no_truncate`, a statement trigger on each
  of the eight tables. On MySQL `TRUNCATE` needs `DROP`, which no documented user holds, and fires no trigger, so the
  grants alone refuse it.
- The tables' owner can drop the triggers: they guard against the application's users, not against the owner. A
  trigger refuses the owner's own update or delete while it is installed.
- SQLite has no users, so its triggers refuse every update and delete they cover, with no maintenance exception, and
  pruning on SQLite drops and recreates the delete triggers of the entries and the artifacts in the prune's own
  transaction, as the last block shows, so a prune deletes an entry's artifact with it. That prune takes the lifecycle
  lock first: inside the framework's transaction, its first statement updates the lock row, which takes SQLite's write
  lock. The block, run by hand, opens with `BEGIN IMMEDIATE` to take that lock at once. The holds get no delete trigger
  on SQLite, because a release could not delete its row otherwise. A prune that fails before `COMMIT` is rolled back,
  and the rollback restores the triggers. SQLite has no grants at all.

### MySQL

<!-- sql: mysql-grants -->

```sql
GRANT SELECT, INSERT ON app_db.audit_log_entries TO 'audit_writer'@'%';
GRANT SELECT, INSERT ON app_db.audit_log_artifacts TO 'audit_writer'@'%';
GRANT SELECT, INSERT ON app_db.audit_log_checkpoints TO 'audit_writer'@'%';
GRANT UPDATE (anchor, anchor_receipt, anchored_at, anchor_error_class)
    ON app_db.audit_log_checkpoints TO 'audit_writer'@'%';
GRANT SELECT, INSERT ON app_db.audit_log_checkpoint_members TO 'audit_writer'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON app_db.audit_log_integrity_state TO 'audit_writer'@'%';
GRANT SELECT ON app_db.audit_log_lifecycle TO 'audit_writer'@'%';
GRANT SELECT ON app_db.audit_log_holds TO 'audit_writer'@'%';
GRANT SELECT, INSERT ON app_db.audit_log_import_batches TO 'audit_writer'@'%';
GRANT UPDATE (status, lines_read, imported, duplicates, conflicts, rejected, conflict_ids, updated_at, finished_at)
    ON app_db.audit_log_import_batches TO 'audit_writer'@'%';

GRANT SELECT, DELETE ON app_db.audit_log_entries TO 'audit_maintenance'@'%';
GRANT SELECT, DELETE ON app_db.audit_log_artifacts TO 'audit_maintenance'@'%';
GRANT SELECT, DELETE ON app_db.audit_log_deliveries TO 'audit_maintenance'@'%';
GRANT SELECT ON app_db.audit_log_checkpoints TO 'audit_maintenance'@'%';
GRANT SELECT ON app_db.audit_log_checkpoint_members TO 'audit_maintenance'@'%';
GRANT SELECT ON app_db.audit_log_integrity_state TO 'audit_maintenance'@'%';
GRANT SELECT ON app_db.audit_log_outbox TO 'audit_maintenance'@'%';
GRANT SELECT, INSERT ON app_db.audit_log_lifecycle TO 'audit_maintenance'@'%';
GRANT SELECT, INSERT, DELETE ON app_db.audit_log_holds TO 'audit_maintenance'@'%';
GRANT SELECT ON app_db.audit_log_lifecycle_lock TO 'audit_maintenance'@'%';
GRANT UPDATE (token, locked_at) ON app_db.audit_log_lifecycle_lock TO 'audit_maintenance'@'%';

GRANT SELECT ON app_db.audit_log_entries TO 'audit_verifier'@'%';
GRANT SELECT ON app_db.audit_log_artifacts TO 'audit_verifier'@'%';
GRANT SELECT ON app_db.audit_log_checkpoints TO 'audit_verifier'@'%';
GRANT SELECT ON app_db.audit_log_checkpoint_members TO 'audit_verifier'@'%';
GRANT SELECT ON app_db.audit_log_lifecycle TO 'audit_verifier'@'%';
GRANT SELECT ON app_db.audit_log_holds TO 'audit_verifier'@'%';
GRANT SELECT, INSERT, UPDATE ON app_db.audit_log_integrity_state TO 'audit_verifier'@'%';
```

<!-- sql: mysql-triggers -->

```sql
DELIMITER //

CREATE TRIGGER audit_log_entries_no_update BEFORE UPDATE ON audit_log_entries FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log_entries refuses UPDATE';
END//

CREATE TRIGGER audit_log_entries_no_delete BEFORE DELETE ON audit_log_entries FOR EACH ROW
BEGIN
    IF CAST(SUBSTRING_INDEX(USER(), '@', 1) AS BINARY) <> 'audit_maintenance' THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log_entries refuses DELETE';
    END IF;
END//

CREATE TRIGGER audit_log_artifacts_no_update BEFORE UPDATE ON audit_log_artifacts FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log_artifacts refuses UPDATE';
END//

CREATE TRIGGER audit_log_artifacts_no_delete BEFORE DELETE ON audit_log_artifacts FOR EACH ROW
BEGIN
    IF CAST(SUBSTRING_INDEX(USER(), '@', 1) AS BINARY) <> 'audit_maintenance' THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log_artifacts refuses DELETE';
    END IF;
END//

CREATE TRIGGER audit_log_checkpoints_no_update BEFORE UPDATE ON audit_log_checkpoints FOR EACH ROW
BEGIN
    IF NOT (OLD.id <=> NEW.id
        AND OLD.sequence <=> NEW.sequence
        AND OLD.log_id <=> NEW.log_id
        AND OLD.previous_id <=> NEW.previous_id
        AND OLD.previous_digest <=> NEW.previous_digest
        AND OLD.member_count <=> NEW.member_count
        AND OLD.members_digest <=> NEW.members_digest
        AND OLD.seal_digest <=> NEW.seal_digest
        AND OLD.first_recorded_at <=> NEW.first_recorded_at
        AND OLD.last_recorded_at <=> NEW.last_recorded_at
        AND OLD.sealed_at <=> NEW.sealed_at
        AND OLD.signer <=> NEW.signer
        AND OLD.key_id <=> NEW.key_id
        AND OLD.algorithm_version <=> NEW.algorithm_version
        AND OLD.journal_sequence <=> NEW.journal_sequence
        AND OLD.journal_head <=> NEW.journal_head
        AND OLD.signature <=> NEW.signature) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log_checkpoints refuses UPDATE';
    END IF;
END//

CREATE TRIGGER audit_log_checkpoints_no_delete BEFORE DELETE ON audit_log_checkpoints FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log_checkpoints refuses DELETE';
END//

CREATE TRIGGER audit_log_checkpoint_members_no_update BEFORE UPDATE ON audit_log_checkpoint_members FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log_checkpoint_members refuses UPDATE';
END//

CREATE TRIGGER audit_log_checkpoint_members_no_delete BEFORE DELETE ON audit_log_checkpoint_members FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log_checkpoint_members refuses DELETE';
END//

CREATE TRIGGER audit_log_lifecycle_no_update BEFORE UPDATE ON audit_log_lifecycle FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log_lifecycle refuses UPDATE';
END//

CREATE TRIGGER audit_log_lifecycle_no_delete BEFORE DELETE ON audit_log_lifecycle FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log_lifecycle refuses DELETE';
END//

CREATE TRIGGER audit_log_holds_no_update BEFORE UPDATE ON audit_log_holds FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log_holds refuses UPDATE';
END//

CREATE TRIGGER audit_log_holds_no_delete BEFORE DELETE ON audit_log_holds FOR EACH ROW
BEGIN
    IF CAST(SUBSTRING_INDEX(USER(), '@', 1) AS BINARY) <> 'audit_maintenance' THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log_holds refuses DELETE';
    END IF;
END//

CREATE TRIGGER audit_log_lifecycle_lock_no_update BEFORE UPDATE ON audit_log_lifecycle_lock FOR EACH ROW
BEGIN
    IF NOT (OLD.id <=> NEW.id) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log_lifecycle_lock refuses UPDATE';
    END IF;
END//

CREATE TRIGGER audit_log_lifecycle_lock_no_delete BEFORE DELETE ON audit_log_lifecycle_lock FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log_lifecycle_lock refuses DELETE';
END//

CREATE TRIGGER audit_log_import_batches_no_update BEFORE UPDATE ON audit_log_import_batches FOR EACH ROW
BEGIN
    IF NOT (OLD.id <=> NEW.id
        AND OLD.source_id <=> NEW.source_id
        AND OLD.source_region <=> NEW.source_region
        AND OLD.input_format <=> NEW.input_format
        AND OLD.importer_type <=> NEW.importer_type
        AND OLD.importer_id <=> NEW.importer_id
        AND OLD.reason <=> NEW.reason
        AND OLD.external_reference <=> NEW.external_reference
        AND OLD.file_sha256 <=> NEW.file_sha256
        AND OLD.externally_verified <=> NEW.externally_verified
        AND OLD.hold_id <=> NEW.hold_id
        AND OLD.started_at <=> NEW.started_at) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log_import_batches refuses UPDATE';
    END IF;
END//

CREATE TRIGGER audit_log_import_batches_no_delete BEFORE DELETE ON audit_log_import_batches FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit_log_import_batches refuses DELETE';
END//

DELIMITER ;
```

### PostgreSQL

<!-- sql: pgsql-grants -->

```sql
GRANT CONNECT ON DATABASE app_db TO audit_writer, audit_maintenance, audit_verifier;
GRANT USAGE ON SCHEMA public TO audit_writer, audit_maintenance, audit_verifier;

GRANT SELECT, INSERT ON audit_log_entries, audit_log_artifacts, audit_log_checkpoints, audit_log_checkpoint_members
    TO audit_writer;
GRANT UPDATE (anchor, anchor_receipt, anchored_at, anchor_error_class) ON audit_log_checkpoints TO audit_writer;
GRANT SELECT, INSERT, UPDATE, DELETE ON audit_log_integrity_state TO audit_writer;
GRANT SELECT ON audit_log_lifecycle, audit_log_holds TO audit_writer;
GRANT SELECT, INSERT ON audit_log_import_batches TO audit_writer;
GRANT UPDATE (status, lines_read, imported, duplicates, conflicts, rejected, conflict_ids, updated_at, finished_at)
    ON audit_log_import_batches TO audit_writer;

GRANT SELECT, DELETE ON audit_log_entries, audit_log_artifacts, audit_log_deliveries TO audit_maintenance;
GRANT SELECT ON audit_log_checkpoints, audit_log_checkpoint_members, audit_log_integrity_state, audit_log_outbox,
    audit_log_lifecycle_lock TO audit_maintenance;
GRANT SELECT, INSERT ON audit_log_lifecycle TO audit_maintenance;
GRANT SELECT, INSERT, DELETE ON audit_log_holds TO audit_maintenance;
GRANT UPDATE (token, locked_at) ON audit_log_lifecycle_lock TO audit_maintenance;

GRANT SELECT ON audit_log_entries, audit_log_artifacts, audit_log_checkpoints, audit_log_checkpoint_members,
    audit_log_lifecycle, audit_log_holds TO audit_verifier;
GRANT SELECT, INSERT, UPDATE ON audit_log_integrity_state TO audit_verifier;
```

<!-- sql: pgsql-triggers -->

```sql
CREATE OR REPLACE FUNCTION audit_log_refuse() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% refuses %', TG_TABLE_NAME, TG_OP;
END;
$$;

CREATE OR REPLACE FUNCTION audit_log_refuse_delete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_user <> 'audit_maintenance' THEN
        RAISE EXCEPTION '% refuses %', TG_TABLE_NAME, TG_OP;
    END IF;

    RETURN OLD;
END;
$$;

CREATE TRIGGER audit_log_entries_no_update BEFORE UPDATE ON audit_log_entries
    FOR EACH ROW EXECUTE FUNCTION audit_log_refuse();
CREATE TRIGGER audit_log_entries_no_delete BEFORE DELETE ON audit_log_entries
    FOR EACH ROW EXECUTE FUNCTION audit_log_refuse_delete();
CREATE TRIGGER audit_log_entries_no_truncate BEFORE TRUNCATE ON audit_log_entries
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_refuse();

CREATE TRIGGER audit_log_artifacts_no_update BEFORE UPDATE ON audit_log_artifacts
    FOR EACH ROW EXECUTE FUNCTION audit_log_refuse();
CREATE TRIGGER audit_log_artifacts_no_delete BEFORE DELETE ON audit_log_artifacts
    FOR EACH ROW EXECUTE FUNCTION audit_log_refuse_delete();
CREATE TRIGGER audit_log_artifacts_no_truncate BEFORE TRUNCATE ON audit_log_artifacts
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_refuse();

CREATE TRIGGER audit_log_checkpoints_no_update BEFORE UPDATE ON audit_log_checkpoints
    FOR EACH ROW
    WHEN ((OLD.id, OLD.sequence, OLD.log_id, OLD.previous_id, OLD.previous_digest, OLD.member_count,
        OLD.members_digest, OLD.seal_digest, OLD.first_recorded_at, OLD.last_recorded_at, OLD.sealed_at, OLD.signer,
        OLD.key_id, OLD.algorithm_version, OLD.journal_sequence, OLD.journal_head, OLD.signature)
        IS DISTINCT FROM (NEW.id, NEW.sequence, NEW.log_id, NEW.previous_id, NEW.previous_digest, NEW.member_count,
        NEW.members_digest, NEW.seal_digest, NEW.first_recorded_at, NEW.last_recorded_at, NEW.sealed_at, NEW.signer,
        NEW.key_id, NEW.algorithm_version, NEW.journal_sequence, NEW.journal_head, NEW.signature))
    EXECUTE FUNCTION audit_log_refuse();
CREATE TRIGGER audit_log_checkpoints_no_delete BEFORE DELETE ON audit_log_checkpoints
    FOR EACH ROW EXECUTE FUNCTION audit_log_refuse();
CREATE TRIGGER audit_log_checkpoints_no_truncate BEFORE TRUNCATE ON audit_log_checkpoints
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_refuse();

CREATE TRIGGER audit_log_checkpoint_members_no_update BEFORE UPDATE ON audit_log_checkpoint_members
    FOR EACH ROW EXECUTE FUNCTION audit_log_refuse();
CREATE TRIGGER audit_log_checkpoint_members_no_delete BEFORE DELETE ON audit_log_checkpoint_members
    FOR EACH ROW EXECUTE FUNCTION audit_log_refuse();
CREATE TRIGGER audit_log_checkpoint_members_no_truncate BEFORE TRUNCATE ON audit_log_checkpoint_members
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_refuse();

CREATE TRIGGER audit_log_lifecycle_no_update BEFORE UPDATE ON audit_log_lifecycle
    FOR EACH ROW EXECUTE FUNCTION audit_log_refuse();
CREATE TRIGGER audit_log_lifecycle_no_delete BEFORE DELETE ON audit_log_lifecycle
    FOR EACH ROW EXECUTE FUNCTION audit_log_refuse();
CREATE TRIGGER audit_log_lifecycle_no_truncate BEFORE TRUNCATE ON audit_log_lifecycle
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_refuse();

CREATE TRIGGER audit_log_holds_no_update BEFORE UPDATE ON audit_log_holds
    FOR EACH ROW EXECUTE FUNCTION audit_log_refuse();
CREATE TRIGGER audit_log_holds_no_delete BEFORE DELETE ON audit_log_holds
    FOR EACH ROW EXECUTE FUNCTION audit_log_refuse_delete();
CREATE TRIGGER audit_log_holds_no_truncate BEFORE TRUNCATE ON audit_log_holds
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_refuse();

CREATE TRIGGER audit_log_lifecycle_lock_no_update BEFORE UPDATE ON audit_log_lifecycle_lock
    FOR EACH ROW
    WHEN (OLD.id IS DISTINCT FROM NEW.id)
    EXECUTE FUNCTION audit_log_refuse();
CREATE TRIGGER audit_log_lifecycle_lock_no_delete BEFORE DELETE ON audit_log_lifecycle_lock
    FOR EACH ROW EXECUTE FUNCTION audit_log_refuse();
CREATE TRIGGER audit_log_lifecycle_lock_no_truncate BEFORE TRUNCATE ON audit_log_lifecycle_lock
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_refuse();

CREATE TRIGGER audit_log_import_batches_no_update BEFORE UPDATE ON audit_log_import_batches
    FOR EACH ROW
    WHEN ((OLD.id, OLD.source_id, OLD.source_region, OLD.input_format, OLD.importer_type, OLD.importer_id, OLD.reason,
        OLD.external_reference, OLD.file_sha256, OLD.externally_verified, OLD.hold_id, OLD.started_at)
        IS DISTINCT FROM (NEW.id, NEW.source_id, NEW.source_region, NEW.input_format, NEW.importer_type,
        NEW.importer_id, NEW.reason, NEW.external_reference, NEW.file_sha256, NEW.externally_verified, NEW.hold_id,
        NEW.started_at))
    EXECUTE FUNCTION audit_log_refuse();
CREATE TRIGGER audit_log_import_batches_no_delete BEFORE DELETE ON audit_log_import_batches
    FOR EACH ROW EXECUTE FUNCTION audit_log_refuse();
CREATE TRIGGER audit_log_import_batches_no_truncate BEFORE TRUNCATE ON audit_log_import_batches
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_refuse();
```

### SQLite

<!-- sql: sqlite-triggers -->

```sql
CREATE TRIGGER audit_log_entries_no_update BEFORE UPDATE ON audit_log_entries
BEGIN
    SELECT RAISE(ABORT, 'audit_log_entries refuses UPDATE');
END;

CREATE TRIGGER audit_log_entries_no_delete BEFORE DELETE ON audit_log_entries
BEGIN
    SELECT RAISE(ABORT, 'audit_log_entries refuses DELETE');
END;

CREATE TRIGGER audit_log_artifacts_no_update BEFORE UPDATE ON audit_log_artifacts
BEGIN
    SELECT RAISE(ABORT, 'audit_log_artifacts refuses UPDATE');
END;

CREATE TRIGGER audit_log_artifacts_no_delete BEFORE DELETE ON audit_log_artifacts
BEGIN
    SELECT RAISE(ABORT, 'audit_log_artifacts refuses DELETE');
END;

CREATE TRIGGER audit_log_checkpoints_no_update
BEFORE UPDATE OF id, sequence, log_id, previous_id, previous_digest, member_count, members_digest, seal_digest,
    first_recorded_at, last_recorded_at, sealed_at, signer, key_id, algorithm_version, journal_sequence, journal_head,
    signature
ON audit_log_checkpoints
BEGIN
    SELECT RAISE(ABORT, 'audit_log_checkpoints refuses UPDATE');
END;

CREATE TRIGGER audit_log_checkpoints_no_delete BEFORE DELETE ON audit_log_checkpoints
BEGIN
    SELECT RAISE(ABORT, 'audit_log_checkpoints refuses DELETE');
END;

CREATE TRIGGER audit_log_checkpoint_members_no_update BEFORE UPDATE ON audit_log_checkpoint_members
BEGIN
    SELECT RAISE(ABORT, 'audit_log_checkpoint_members refuses UPDATE');
END;

CREATE TRIGGER audit_log_checkpoint_members_no_delete BEFORE DELETE ON audit_log_checkpoint_members
BEGIN
    SELECT RAISE(ABORT, 'audit_log_checkpoint_members refuses DELETE');
END;

CREATE TRIGGER audit_log_lifecycle_no_update BEFORE UPDATE ON audit_log_lifecycle
BEGIN
    SELECT RAISE(ABORT, 'audit_log_lifecycle refuses UPDATE');
END;

CREATE TRIGGER audit_log_lifecycle_no_delete BEFORE DELETE ON audit_log_lifecycle
BEGIN
    SELECT RAISE(ABORT, 'audit_log_lifecycle refuses DELETE');
END;

CREATE TRIGGER audit_log_holds_no_update BEFORE UPDATE ON audit_log_holds
BEGIN
    SELECT RAISE(ABORT, 'audit_log_holds refuses UPDATE');
END;

CREATE TRIGGER audit_log_lifecycle_lock_no_update BEFORE UPDATE OF id ON audit_log_lifecycle_lock
BEGIN
    SELECT RAISE(ABORT, 'audit_log_lifecycle_lock refuses UPDATE');
END;

CREATE TRIGGER audit_log_lifecycle_lock_no_delete BEFORE DELETE ON audit_log_lifecycle_lock
BEGIN
    SELECT RAISE(ABORT, 'audit_log_lifecycle_lock refuses DELETE');
END;

CREATE TRIGGER audit_log_import_batches_no_update
BEFORE UPDATE OF id, source_id, source_region, input_format, importer_type, importer_id, reason, external_reference,
    file_sha256, externally_verified, hold_id, started_at
ON audit_log_import_batches
BEGIN
    SELECT RAISE(ABORT, 'audit_log_import_batches refuses UPDATE');
END;

CREATE TRIGGER audit_log_import_batches_no_delete BEFORE DELETE ON audit_log_import_batches
BEGIN
    SELECT RAISE(ABORT, 'audit_log_import_batches refuses DELETE');
END;
```

<!-- sql: sqlite-prune -->

```sql
BEGIN IMMEDIATE;

UPDATE audit_log_lifecycle_lock SET token = 'manual', locked_at = CURRENT_TIMESTAMP WHERE id = 1;

DROP TRIGGER audit_log_entries_no_delete;
DROP TRIGGER audit_log_artifacts_no_delete;

-- the prune's deletes (artifacts, receipts, then entries) and its journal row go here

CREATE TRIGGER audit_log_entries_no_delete BEFORE DELETE ON audit_log_entries
BEGIN
    SELECT RAISE(ABORT, 'audit_log_entries refuses DELETE');
END;

CREATE TRIGGER audit_log_artifacts_no_delete BEFORE DELETE ON audit_log_artifacts
BEGIN
    SELECT RAISE(ABORT, 'audit_log_artifacts refuses DELETE');
END;

COMMIT;
```

## Seams Left

- `Contracts\AuditStore`, bound to `DatabaseAuditStore` by default, takes other stores; `delivery.md` has those that
  ship.
- Erasure and the owners' keys on the maintenance connection.
- Partitioning the entries table.

## Implementation Anchors

- `database/migrations/2026_11_02_000000_create_audit_log_entries_table.php`,
  `database/migrations/2026_11_02_000600_create_audit_log_artifacts_table.php`,
  `database/migrations/2026_11_02_000100_create_audit_log_outbox_table.php`,
  `database/migrations/2026_11_02_000200_create_audit_log_deliveries_table.php`,
  `database/migrations/2026_11_02_000300_create_audit_log_checkpoints_table.php`,
  `database/migrations/2026_11_02_000400_create_audit_log_checkpoint_members_table.php`,
  `database/migrations/2026_11_02_000500_create_audit_log_integrity_state_table.php`,
  `database/migrations/2026_11_02_000700_create_audit_log_lifecycle_table.php`,
  `database/migrations/2026_11_02_000800_create_audit_log_holds_table.php`,
  `database/migrations/2026_11_02_000900_create_audit_log_lifecycle_lock_table.php`,
  `database/migrations/2026_11_02_001000_create_audit_log_import_batches_table.php`.
- `src/Database/IntegrityTables.php`: `checkpointsTable()`, `membersTable()`, `stateTable()`;
  `src/Database/IntegrityProgress.php`: `put()`, `forget()`.
- `src/Database/LifecycleTables.php`: `journalTable()`, `holdsTable()`, `lockTable()`, `importBatchesTable()`,
  `validate()`.
- `src/Database/InstallationIdentity.php`: `ensure()`, `confirm()`, `check()`, `idThrough()`, `row()`;
  `database/migrations/2026_11_02_000500_create_audit_log_integrity_state_table.php`: the seeded installation id;
  `src/Database/InstallationMismatchException.php`: `absent()`, `mismatched()`.
- `src/Integrity/CheckpointWriter.php`: the seal and member inserts and the journal head they commit to;
  `src/Integrity/Anchorer.php`: the anchor columns; `src/Integrity/JournalVerifier.php`: the journal read on the
  writer.
- `src/Lifecycle/MaintenanceTransaction.php`: `confirm()`, `run()`; `src/Lifecycle/LifecycleLockException.php`,
  `src/Lifecycle/LifecycleContentionException.php`.
- `src/Lifecycle/Journal.php`: `append()`; `src/Lifecycle/JournalReplay.php`; `src/Lifecycle/HoldProjection.php`;
  `src/Lifecycle/HoldKeeper.php`; `src/Lifecycle/JournalPruneLedger.php`.
- `src/Lifecycle/PruneChunk.php`, `src/Lifecycle/PendingDeliveries.php`, `src/Lifecycle/SqliteDeleteTriggers.php`,
  `src/Lifecycle/Pruner.php`; `src/Lifecycle/PruneTombstones.php`.
- `src/Lifecycle/ImportBatches.php`, `src/Lifecycle/ImportWriter.php`, `src/Lifecycle/ImportClassifier.php`;
  `src/Lifecycle/Reconciler.php`; `src/Console/LifecycleChecks.php`.
- `src/Database/DeliveryTables.php`: `outboxTable()`, `deliveriesTable()`; `src/Delivery/Outbox.php`,
  `src/Delivery/Receipts.php`.
- `src/Database/StorageConnection.php`: `name()`, `forMaintenance()`; `src/Database/EntrySettings.php`: `table()`,
  `artifactsTable()`;
  `src/Database/MigrationCollisionGuard.php`: `ensureNotExists()`.
- `src/Stores/DatabaseAuditStore.php`: `store()`; `src/Stores/RecordConflictException.php`: `alreadyPruned()`;
  `src/Stores/RowCodec.php`; `src/Support/StoredTime.php`.
- `src/Models/AuditEntry.php`, `src/Casts/UtcInstant.php`.
- `src/Console/SchemaChecks.php`, `src/Console/EngineChecks.php`, `src/Console/DeliveryChecks.php`,
  `src/Console/IntegrityChecks.php`, `src/Console/TableShape.php`.
- `src/AuditLogServiceProvider.php`: `registerPublishing()`; `config/audit-log.php`: `storage`, `entries`, `delivery`,
  `integrity`, `lifecycle`, `retention`, `import`.
- The grants and triggers above, run as written by `tests/Concerns/RunsDocumentedSql.php`.

## Authoritative Tests

- `tests/Integration/Migration/EntriesTableSchemaTest.php` `testCreatesEveryColumnWithItsNullability`,
  `testSizesEveryStringColumn`, `testStoresBothTimesToTheMicrosecond`, `testThePayloadColumnsAreJsonNeverJsonb`,
  `testIndexesEveryLookupUnderItsOwnShortName`, `testNoIndexAppliesACollationToTheId`,
  `testEveryIndexNameFitsAtTheLongestTableName`, `testHasNoTimestampsAndNoForeignKeys`,
  `testOnMySqlEveryCharacterColumnIsBinaryWithoutPadding`, `testOnMySqlTheTableIsInnoDb`,
  `testIdsDifferingOnlyByATrailingSpaceAreDistinct`
- `tests/Integration/Migration/EntriesMigrationCollisionTest.php`
  `testAnExistingTableStopsTheMigrationNamingTheSettingThatRenamesIt`, `testTheExistingTableIsLeftAsItWas`
- `tests/Unit/Database/MigrationCollisionGuardTest.php` `testEnsureNotExistsThrowsWhenTableExists`
- `tests/Integration/Migration/StorageConnectionMigrationTest.php`
  `testTheMigrationCreatesTheTableOnTheStorageConnection`, `testTheMaintenanceConnectionNeverHoldsTheTable`
- `tests/Feature/Database/StorageConnectionTest.php` `testTheMaintenanceConnectionDefaultsToTheStorageConnection`,
  `testAMaintenanceConnectionThatIsNotANameFailsClosed`
- `tests/Feature/Database/EntrySettingsTest.php` `testRefusesATableThatCannotNameEveryIndex`
- `tests/Feature/Models/AuditEntryTest.php` `testRefusesEveryWriteThroughTheModel`,
  `testEveryModelWritePathIsAccountedFor`, `testQueryBuilderWritesBypassTheModelAsDocumented`
- `tests/Integration/Stores/DatabaseAuditStoreTest.php` `testInsideATransactionTheInsertRunsInASavepoint`,
  `testAFailedAuditInsertLeavesAHealthyHostTransactionUsable`, `testTheStoreCatchesNothingButADuplicate`
- `tests/Integration/Stores/LeastPrivilegeWriterTest.php`
  `testAWriterGrantedOnlyWhatTheStoreNeedsStoresAndResolvesDuplicates`, `testOnMySqlTheLockingReadNeedsOnlySelect`
- `tests/Integration/Stores/StoredEntryRoundTripTest.php` `testTimesStayUtcUnderNonUtcSessionAndApplicationTimeZones`,
  `testMicrosecondsSurviveIncludingTrailingZeros`
- `tests/Performance/StoreQueryBudgetTest.php` `testStoringARecordIsOneInsert`,
  `testStoringInsideATransactionAddsOnlyASavepoint`,
  `testEachRecordInsideOneTransactionHoldsASavepointUntilTheHostCommits`
- `tests/Feature/Console/SchemaChecksTest.php` `testTheShippedMigrationHasNoProblems`,
  `testTheShippedArtifactsMigrationHasNoProblems`, `testAMissingArtifactsColumnIsAProblem`,
  `testAnIndexWithoutItsIdIsReported`, `testAnInstallWithTheOldIndexesReportsEachOfThem`
- `tests/Integration/Querying/TrailPlansTest.php` `testASingleTenantReadUsesTheTenantIndex`,
  `testAnActorReadUsesTheActorIndex`, `testAnEventReadUsesTheEventIndex`, `testAPageReadsNoFilesort`,
  `testAMultiTenantReadUsesAnIndexAndFiltersTheRest`,
  `testASelectiveFilterUnderATenantScopeUsesOneIndexAndFiltersTheRest`
- `tests/Feature/Console/CheckCommandTest.php` `testAMissingArtifactsTableFailsTheSchemaSubject`
- `tests/Integration/Migration/ArtifactsTableSchemaTest.php` `testTheColumnsHaveTheirTypes`, `testTheIdIsThePrimaryKey`,
  `testAnEntryHasOneArtifact`, `testOnMySqlTheTableIsBinaryAndInnoDb`, `testTheTableIsOnTheStorageConnection`,
  `testAnExistingTableIsRefusedNamingTheSetting`, `testARollbackDropsIt`
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
- `tests/Integration/Migration/CheckpointsTableSchemaTest.php` `testCreatesEveryColumnWithItsNullability`,
  `testKeepsTheColumnsInOrder`, `testTheSequenceIsUnique`, `testIndexesWhatTheAnchorerAndTheJournalCheckRead`,
  `testEveryIndexNameFitsAtTheLongestTableName`, `testSizesEveryStringColumn`, `testTheSequenceIsABigInteger`,
  `testStoresEveryTimeToTheMicrosecond`, `testTheReceiptIsJsonNeverJsonb`, `testTheAnchorColumnsAreWrittenAfterTheSeal`,
  `testHasNoForeignKeys`, `testOnMySqlEveryCharacterColumnIsBinaryWithoutPadding`, `testOnMySqlTheTableIsInnoDb`
- `tests/Integration/Migration/CheckpointMembersTableSchemaTest.php` `testCreatesEveryColumnWithItsNullability`,
  `testTheKeyIsTheCheckpointAndTheEntry`, `testIndexesTheEntryAlone`, `testAnEntryBelongsToAtMostOneSeal`,
  `testHasNoForeignKeys`, `testOnMySqlTheTableIsInnoDb`
- `tests/Integration/Migration/IntegrityStateTableSchemaTest.php` `testCreatesEveryColumnWithItsNullability`,
  `testTheNameIsThePrimaryKey`, `testTheValueIsText`, `testStoresTheTimeToTheMicrosecond`, `testHasNoForeignKeys`
- `tests/Integration/Migration/IntegrityMigrationsConnectionTest.php`
  `testTheIntegrityTablesFollowTheStorageConnection`, `testTheyStayOnTheStorageConnectionWhenTheOutboxMoves`
- `tests/Feature/Database/IntegrityTablesTest.php` `testTheTablesHaveTheirDefaults`, `testRefusesAMalformedTable`
- `tests/Unit/Documentation/DocumentedSqlTest.php` `testEachBlockIsMarked`, `testEveryBlockUsesOnlyThePlaceholders`,
  `testTheStorageNoteStatesWhatItMust`, `testTheTriggersCoverEveryImmutableCheckpointColumn`,
  `testEachEngineDocumentsEveryTrigger`, `testTheArtifactTriggersRefuseEveryUpdate`,
  `testTheGrantsAreExactlyTheDocumentedPrivileges`,
  `testNoGrantGivesDdlOrTruncate`, `testTheSqlitePruneRecreatesTheDocumentedDeleteTrigger`,
  `testTheSqlitePruneTakesTheLockFirst`, `testTheTriggersCoverEveryImmutableBatchColumn`,
  `testTheRoleMatrixNamesEveryTableAndUser`, `testEachGrantsBlockGrantsWhatTheRoleMatrixSays`
- `tests/Integration/Integrity/AppendOnlyTriggersTest.php` `testTheDocumentedTriggersInstall`,
  `testAnEntryUpdateIsRefused`, `testAnArtifactUpdateIsRefused`,
  `testAnArtifactDeleteIsRefusedButForTheMaintenanceUser`, `testTheGrantsLimitWhatEachUserDoesToAnArtifact`,
  `testAMemberUpdateAndDeleteAreRefused`, `testAnImmutableCheckpointUpdateIsRefused`,
  `testAnAnchorColumnUpdateIsAllowed`, `testACheckpointDeleteIsRefused`,
  `testTheTriggerRefusesADeleteByAnyoneButTheMaintenanceUser`, `testTheMaintenanceUserMayDeleteAnEntry`,
  `testOnMySqlTheTriggerComparesTheNameExactly`, `testTheDocumentedSqlitePruneDeletesAndRestoresTheTrigger`,
  `testTheDocumentedSqlitePruneDeletesAnArtifactWithItsEntry`, `testAFailedSqlitePruneRolledBackKeepsTheTrigger`,
  `testATruncateIsRefusedOnPostgres`, `testTheStateTableIsNotCovered`,
  `testSealingAndAnchoringStillWorkUnderTheTriggers`
- `tests/Integration/Integrity/LeastPrivilegeSealerTest.php`
  `testAWriterGrantedExactlyTheDocumentedPrivilegesSealsAnchorsAndVerifies`,
  `testAWriterGrantedExactlyTheDocumentedPrivilegesCompletesASweep`,
  `testTheWriterCannotChangeAnImmutableCheckpointColumn`, `testTheWriterCannotDeleteAMemberOrACheckpoint`,
  `testTheWriterCannotTruncateAnyIntegrityTable`, `testTheWriterCannotRunDdl`,
  `testTheMaintenanceUserIsGrantedExactlyItsDocumentedPrivileges`, `testTheWriterReadsTheJournalAndTheHolds`
- `tests/Feature/Database/LifecycleTablesTest.php` `testTheDefaultsApplyWhenNothingIsSet`,
  `testEachNameIsReadFromItsSetting`, `testRefusesAMalformedNameNamingTheKey`, `testValidateReadsEverySetting`
- `tests/Integration/Database/InstallationIdentityTest.php` `testEnsureWritesTheIdOnce`,
  `testTheFirstWriteWinsAndIsNeverReplaced`, `testConfirmPassesThroughOneConnection`, `testConfirmWritesAMissingId`,
  `testConfirmRefusesAMaintenanceConnectionReachingNoId`, `testConfirmRefusesConnectionsReachingDifferentDatabases`,
  `testTheRefusalNamesNoValue`, `testEnsureReturnsTheSeededId`, `testCheckReadsTheIdAndWritesNothing`,
  `testCheckRefusesAMissingIdAndWritesNothing`, `testCheckRefusesAMaintenanceConnectionReachingNoIdOrAnother`,
  `testTheRowIsANewIdAtTheInstant`, `testAMalformedValueReadsAsAbsent`
- `tests/Integration/Migration/IntegrityStateTableSchemaTest.php` `testTheMigrationSeedsTheInstallationIdOnce`,
  `testTheSeededIdIsNeverWrittenTwice`
- `tests/Unit/Database/InstallationMismatchExceptionTest.php` `testEachMessageIsASentenceNamingNoValue`
- `tests/Integration/Migration/LifecycleTableSchemaTest.php` `testEveryColumnHasItsTypeLengthAndNullability`,
  `testTheIndexesAreTheShapesIndexes`, `testTheSequenceIsUnique`, `testTheMigrationRefusesAnExistingTable`,
  `testARenamedTableIsCreatedUnderItsSetting`, `testDownDropsTheTable`
- `tests/Integration/Migration/HoldsTableSchemaTest.php` `testEveryColumnHasItsTypeLengthAndNullability`,
  `testTheIndexesAreTheShapesIndexes`, `testTheMigrationRefusesAnExistingTable`
- `tests/Integration/Migration/LifecycleLockTableSchemaTest.php` `testTheMigrationSeedsTheOneLockRow`,
  `testEveryColumnHasItsTypeLengthAndNullability`, `testTheIndexesAreTheShapesIndexes`
- `tests/Integration/Migration/ImportBatchesTableSchemaTest.php` `testEveryColumnHasItsTypeLengthAndNullability`,
  `testTheIndexesAreTheShapesIndexes`, `testNoColumnIsAReservedWord`
- `tests/Integration/Migration/LifecycleMigrationsConnectionTest.php`
  `testTheLifecycleTablesFollowTheStorageConnection`
- `tests/Integration/Lifecycle/LifecycleTriggersTest.php` `testTheDocumentedTriggersInstall`,
  `testAJournalUpdateIsRefused`, `testAJournalDeleteIsRefusedEvenForTheMaintenanceUser`, `testAHoldUpdateIsRefused`,
  `testAHoldDeleteIsRefusedButForTheMaintenanceUser`, `testOnSqliteAHoldDeleteIsAllowed`,
  `testAnImmutableBatchColumnUpdateIsRefused`, `testABatchCountUpdateIsAllowed`, `testABatchDeleteIsRefused`,
  `testTheLockRowCannotBeDeletedOrRenumbered`, `testTheLockTokenUpdateIsAllowed`, `testATruncateIsRefusedOnPostgres`,
  `testTheGrantsLimitWhatEachUserDoesToTheJournal`, `testTheWriterUpdatesOnlyTheBatchCountsStatusAndTimes`,
  `testTheVerifierReadsTheJournalWithOnlySelect`
- `tests/Integration/Migration/EntriesTableSchemaTest.php` `testTheSourceDigestIsKeptAndNotUnique`,
  `testASourcesRecordIdIsStoredOnce`
- `tests/Integration/Migration/CheckpointsTableSchemaTest.php`
  `testTheJournalHeadIsNullForAnEmptyJournalAndKeptOtherwise`
- `tests/Feature/Integrity/CheckpointWriterTest.php` `testTheHeadIsReadInsideTheSealsTransaction`
- `tests/Feature/Integrity/JournalVerifierTest.php` `testItReadsTheWriter`
- `tests/Feature/Lifecycle/MaintenanceTransactionTest.php` `testTheLockIsTheFirstStatement`,
  `testItRefusesInsideATransactionOnTheMaintenanceConnection`, `testItRefusesInsideATransactionOnTheStorageConnection`,
  `testANestedOperationIsRefused`, `testAMismatchedInstallationRefusesBeforeTheLock`, `testAMissingLockRowRefuses`,
  `testTheWorkRunsOnTheMaintenanceConnection`, `testAConcurrencyFailureIsRetriedThreeTimesThenFails`,
  `testALostConnectionIsNeverRetried`, `testTheTokenNamesTheOperationAndChangesOnEveryAttempt`,
  `testARetriedAttemptRunsTheWorkAfreshAndReturnsOnlyTheCommittedResult`,
  `testOnMySqlTheIsolationIsSetBeforeTheTransaction`, `testOnPostgresTheIsolationIsAsserted`
- `tests/Integration/Lifecycle/LifecycleLockEnginesTest.php` `testASecondOperationWaitsForTheFirstsCommit`,
  `testAReadAfterTheLockSeesARowCommittedWhileWaiting`, `testOnSqliteTheLockIsTakenInsideTheFrameworksTransaction`,
  `testTwoOperationsNeverInterleave`
- `tests/Feature/Lifecycle/JournalTest.php` `testAppendRefusesAHeadThatIsNotTheReplays`,
  `testItWritesOnTheMaintenanceConnection`, `testItRefusesOutsideATransaction`
- `tests/Feature/Lifecycle/JournalPruneLedgerTest.php` `testItReadsTheStorageConnectionsWriter`
- `tests/Feature/Lifecycle/HoldProjectionTest.php` `testTheRebuildEqualsTheLiveProjection`,
  `testDriftNamesMissingExtraAndChangedHolds`
- `tests/Feature/Lifecycle/HoldKeeperTest.php` `testAHoldIsJournalledAndProjectedInOneTransaction`,
  `testAReleaseIsDecidedFromTheChainNotTheProjection`
- `tests/Feature/Lifecycle/PruneChunkTest.php` `testTheDeletesRunOnTheMaintenanceConnection`,
  `testAnAffectedCountMismatchRollsBack`, `testAnOutboxRowWrittenBeforeTheLockKeepsItsEntry`
- `tests/Feature/Lifecycle/PendingDeliveriesTest.php` `testAnOutboxOnTheStorageDatabaseIsReadInTheTransaction`,
  `testAnOutboxOnAnotherConnectionIsReadAfterTheLock`, `testEachIdIsNamedOnceAtMostFiveHundredToAStatement`
- `tests/Feature/Lifecycle/SqliteDeleteTriggersTest.php` `testTheRecreatedTextIsTheDocumentedText`,
  `testOnlyPresentTriggersAreDroppedAndRecreated`, `testARollbackRestoresTheTriggers`, `testOffSqliteNothingRuns`
- `tests/Feature/Lifecycle/PrunerTest.php` `testArtifactsAndReceiptsGoWithTheirEntries`, `testTheRunWritesItsProgress`,
  `testItRefusesInsideATransaction`
- `tests/Integration/Lifecycle/PruneEnginesTest.php` `testOnSqliteTheDocumentedTriggersAreDroppedAndRestored`,
  `testOnMySqlAndPostgresTheMaintenanceUserPrunesUnderTheTriggers`
- `tests/Integration/Lifecycle/PruneRacesTest.php` `testAHoldRacingAPruneNeverLosesAHeldRow`,
  `testAReleaseRacingAPruneIsOrdered`
- `tests/Integration/Lifecycle/PruneTombstonesTest.php` `testASealedMemberAbsentFromTheEntriesIsPruned`,
  `testAnUnsealedIdIsNot`, `testFiveHundredIdsPerStatement`, `testItReadsTheStorageConnectionsWriter`
- `tests/Integration/Stores/PrunedRecordConflictTest.php` `testAUniqueViolationOfAPrunedIdIsAlreadyPruned`,
  `testInsideAHostTransactionAPrunedIdIsAlreadyPruned`, `testAFreshInsertOfAPrunedIdIsNotRefused`
- `tests/Integration/Stores/DatabaseAuditStoreTest.php` `testStoresAnImportedRecordWithItsSourceDigest`
- `tests/Integration/Database/IntegrityProgressTest.php` `testEveryOwnNameIsAccepted`
- `tests/Feature/Lifecycle/ImportBatchesTest.php` `testStartInsertsARunningBatch`,
  `testProgressUpdatesCountsInTheChunksTransaction`, `testCloseOnlyClosesARunningBatch`,
  `testItWritesTheStorageConnectionsWriter`
- `tests/Feature/Lifecycle/ImportWriterTest.php` `testAChunkIsOneTransactionWithNoSavepoint`,
  `testItRefusesInsideATransaction`, `testRowsPerInsertFollowTheEngine`, `testAUniqueViolationReclassifiesOnce`,
  `testTheCountsCommitWithTheRows`
- `tests/Integration/Lifecycle/ImportUniquenessEnginesTest.php` `testTwoConcurrentImportsStoreEachRecordOnce`,
  `testEveryImportedColumnRoundTripsOnEachEngine`
- `tests/Feature/Lifecycle/AuditImporterTest.php`
  `testEntriesAndTheBatchAreOnTheStorageWriterAndTheJournalOnTheMaintenanceConnection`
- `tests/Feature/Lifecycle/ReconcilerTest.php` `testNoJsonPathQueryIsIssued`
- `tests/Feature/Console/LifecycleChecksTest.php` `testEachTableShapeProblemIsReported`,
  `testAMissingLockRowIsAProblem`, `testAMismatchedInstallationIsAProblem`, `testProjectionDriftIsAProblemNamingTheHolds`,
  `testTheJournalIsVerifiedWithoutTheLock`, `testAMissingInstallationIdIsAProblemAndIsNeverWritten`,
  `testTheSeededInstallationIdIsOnlyRead`

## Change Triggers

Update this note when any of the following change:

- a column, its type, its length or its nullability, in any of the package's tables
- an integrity table's columns or indexes
- a lifecycle table's columns, its indexes or its seeded row
- the lifecycle lock protocol: the lock statement, the isolation, what is read after it or what is retried
- what a prune deletes beside an entry, on which connection, or how the SQLite delete triggers are lifted
- how an import inserts, how many rows a statement holds, or what a tombstone check reads
- the role matrix, or the privileges of the writer, the maintenance user or the verifier
- where or how the installation id is written
- the connection the outbox or the receipts are on
- the precision of `occurred_at` or `recorded_at`
- an index, its name or its columns
- the table name's grammar or its length
- the MySQL collation or engine, or a supported engine or version
- the grants the store or the drain needs
- what an artifact holds, or when it is written or deleted
- a grant or a trigger in the documented SQL
- the columns written after a seal is inserted
- how the store inserts, opens a savepoint or resolves a duplicate
- a model write path, or one the query builder forwards
