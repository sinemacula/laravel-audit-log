# Import

An import brings another system's audit records into this installation's entries: a legacy log, a third-party
service, or another installation of this package. Each imported row is this installation's acceptance of what that
source asserted, not activity this application witnessed and not evidence verified outside it. It is signed by this
installation's key ring and sealed in its chain like any entry, marked `imported` with its source, and never dispatched
as `AuditRecorded` nor delivered to a destination.

```bash
php artisan audit-log:import storage/app/crm-audit.ndjson --source=crm-eu --region=eu-west-1 \
    --by-type=App\\Models\\User --by-id=7 --reason=migration.crm --reference=app:ticket-123
```

```php
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportSource;
use SineMacula\Laravel\AuditLog\Records\Reference;

$result = AuditLog::lifecycle()->import(
    ImportSource::fromFile(storage_path('app/crm-audit.ndjson'), 'crm-eu', 'eu-west-1'),
    new Authority(Reference::to($user), 'migration.crm', 'app:ticket-123'),
);
```

The package authorises none of this: the authority is whoever the caller says it is, and `audit-log:import` trusts the
shell, so `--by-type` and `--by-id` assert the operator and prove nothing of who ran it. `--reason` is a reason code and
`--reference` the ticket or case. `--source` names the source that asserted the records, 1 to 64 characters, and is
never this installation's own `source.id`: this installation's own records come back through `audit-log:replay`.
`--region` names the source's region, 1 to 32 characters. `--json` writes the result as one JSON object.

The command exits 0 for a dry run, a complete or a partial import and a close, 1 when the import fails or is refused at
run time, naming the failure by its class, and 2 for an argument or option it refuses, before anything runs. It prints
the batch, its status and counts, the lines rejected per reason, the first conflicting source record ids, the values
dropped, a warning when lines were already past retention on arrival, the hold, and a warning when the import's
records could not be written; never anything of a line's content.

## Formats

| Format                | Read                 | Lines                                                             |
|-----------------------|----------------------|-------------------------------------------------------------------|
| `audit-log-import/v1` | by default           | One JSON object per line, each naming its `format`                |
| `audit-log-export/v1` | with `--from-export` | This package's own NDJSON export lines, from another installation |

A file is NDJSON: one line per record, blank lines skipped, each at most `import.max_line_bytes` (1048576 by default).
A line longer than that is rejected `oversized_line`, and a line that is not a JSON object `malformed_json`.

## The import format

Every line of `audit-log-import/v1` is a JSON object of these fields, and no other:

| Field              | Type             | Rule                                                                                         |
|--------------------|------------------|----------------------------------------------------------------------------------------------|
| `format`           | string           | Required: exactly `audit-log-import/v1`                                                      |
| `source_record_id` | string           | Required: the record's id at the source, 1 to 191 characters with no control characters      |
| `occurred_at`      | string           | Required: an instant, `2026-10-01T09:00:00.000000Z`, at most `import.max_skew_seconds` ahead |
| `event`            | string           | Required: an event code, never under the reserved `audit_log.` prefix                        |
| `outcome`          | string           | Required: `success`, `failure` or `denied`                                                   |
| `reason`           | string or `null` | A reason code, only with `failure` or `denied`                                               |
| `actor`            | object or `null` | `{"type": ..., "id": ...}`, each 1 to 191 characters                                         |
| `subject`          | object or `null` | As `actor`                                                                                   |
| `principal`        | object or `null` | As `actor`                                                                                   |
| `tenant`           | object or `null` | As `actor`                                                                                   |
| `category`         | string or `null` | 1 to 64 lower-case letters, digits or underscores, starting with a letter                    |
| `correlation_id`   | string or `null` | A namespaced id, `<namespace>:<value>`                                                       |
| `properties`       | object or `null` | Any JSON object, no key under the reserved `_audit` prefix                                   |
| `context`          | object or `null` | Any JSON object                                                                              |
| `origin`           | string or `null` | `http`, `console` or `queue`, or `null` when the source does not know                        |
| `ip`               | string or `null` | The client's address, kept as the configured IP mode keeps one                               |

```json
{"format": "audit-log-import/v1", "source_record_id": "crm-1042", "occurred_at": "2026-10-01T09:00:00.000000Z", "event": "invoice.approved", "outcome": "success", "actor": {"type": "user", "id": "42"}, "category": "finance", "properties": {"amount": "1200.00"}}
```

- A line of the format is built as the capture pipeline builds a record, less what an import cannot carry: a code
  registered in the catalogue is built under its definition, its field rules, minimisation and encryption included, and
  no contributor runs, since nothing of the command doing the import is the record's.
- A line is rejected, and counted by its reason, as `malformed_json`, `unsupported_format` (no format, or another one),
  `unsupported_version` (another version of this one), `unknown_field`, `missing_field`, `invalid_field` (a field of
  the wrong type or grammar, or one the record refuses), `reserved_code`, `unregistered_code` (while
  `definitions.require_registered` holds), `invalid_time`, `future_time`, `own_source`, `source_mismatch` or
  `oversized_line`.
- A value shaped as an encrypted envelope, an object of exactly `v`, `k` and `c`, at any depth of `properties` or
  `context`, and an `ip` holding one's JSON, is dropped and counted, in either format, so a source can never plant a
  value the read path would take for this installation's ciphertext.
- An imported row's id is drawn when it is imported, and its source, source record id, region, batch and a keyed
  digest of what the source asserted are kept beside it.

## Importing an export

`--from-export`, or `ImportSource::fromExport()`, reads the NDJSON lines another installation of this package exported,
`audit-log-export/v1`. `--source` is then that installation's `source.id`:

- A record that installation captured must name it as its source (`source_mismatch` otherwise), and its id there is its
  source record id. A record it had itself imported keeps its upstream source and source record id.
- A record whose source, either way, is this installation is `own_source`.
- The exporter's integrity fields, its signature, key and recording time, are another key ring's and are ignored, as
  are its `properties._audit` metadata and the attachment it names, which are not imported.

## Duplicates and conflicts

Each line is identified by its source and its source record id. A line whose identity a row already holds is a
duplicate when its source assertion's digest is the row's, and is skipped; with a different assertion it is a conflict,
counted and listed, and never overwrites the row. The first 100 conflicting source record ids are kept on the batch, in
file order, and printed; fewer when long ids would take the list past 60,000 bytes.

- That guarantee holds while the earlier row survives: a re-import after retention pruned it creates new rows.
- Lines repeated in one file are compared too: the first is imported and a later one is a duplicate or a conflict.
- Two imports of the same records at once are kept apart by the source's unique index. A chunk that meets a row stored
  meanwhile is classified again; should that happen twice, its new lines are counted as conflicts, and a later run of
  the same file imports them, or finds them duplicates. A chunk that deadlocks with another import, or waits too long
  on its locks, is rolled back and tried again after a short random wait, up to four attempts in all.

## Batches

Every import is a batch, a row of `audit_log_import_batches`, with its importer, reason, source, format, the SHA-256 of
the file and its counts. The file is hashed whole before the first entry is written, then read again to import, and a
file that changed between the two reads fails the batch. `externally_verified` is always `false`: the package verified
nothing at the source.

A batch's status is one of:

| Status        | Meaning                                                                                       |
|---------------|-----------------------------------------------------------------------------------------------|
| `running`     | The import is writing the batch's lines                                                       |
| `complete`    | Every line read was imported or was a duplicate of one already imported                       |
| `partial`     | The import reached the end of the file, but some lines were rejected or conflicted            |
| `failed`      | The import stopped on a failure before the end of the file                                    |
| `interrupted` | The batch was closed by hand while it was still running, after the import that ran it stopped |

The lines are written in chunks of `import.chunk`, 500 by default, each in a transaction of its own with the batch's
counts, so a failure keeps the chunks already written. The lifecycle journal opens a batch with `import_started` before
its first entry and closes it with `import_finished`, which is journalled before the batch is marked final, so the
journal always says how a batch ended. A batch left `running` by a process that died is noted by `audit-log:check` once
it has not been written for an hour; `--close` brings it to its end: a batch whose finish was never journalled is
marked `interrupted` and its finish journalled, one whose finish was journalled is marked with that status, and one
whose start never committed is marked `interrupted` with nothing journalled:

```bash
php artisan audit-log:import --close=01932b4e-a000-7000-8000-0000000000e1 --by-type=App\\Models\\User --by-id=7 \
    --reason=migration.crm
```

`AuditLog::lifecycle()->closeImport()` does the same from code. Only a running batch is closed, or a final one whose
start the journal holds with no finish, which has that finish journalled. Each import, and each close that journals a
finish or ends a batch never started, is recorded as `audit_log.imported` once it ends, and `audit-log:reconcile`
writes the record from the journal when it could not be.

## Holds and retention

Imported rows follow retention like any entry, by their category and tenant. `--hold`, or `hold: true`, places a hold
on the batch in the same transaction as its start, before any entry is written, so no prune can reach the batch's
rows before the hold does. `--hold-basis` names its basis, `legal_claim`, `regulatory`, `investigation` or `other`, the
default, and goes only with `--hold`. The hold stays when the import fails, and is recorded as `audit_log.held`.

Lines whose records are already past their category's retention when they arrive are counted and warned of: the next
prune deletes them unless a hold keeps them.

## Dry runs

`--dry-run`, or `dryRun: true`, reads the file, validates, minimises encrypting nothing and classifies each line
against the rows stored, and counts the lines past retention. That count is best effort, in an import as in a dry run:
a retention policy or setting that fails to answer leaves it `null`, reported once, and never stops the import. It
writes nothing: no batch, no journal row, no key, no record. It is a plan, not a promise, since another import may
store the same records first, and lines repeated in different chunks of one file are not compared.
