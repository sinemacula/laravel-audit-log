<?php

declare(strict_types = 1);

return [

    /*
    |---------------------------------------------------------------------------
    | Storage
    |---------------------------------------------------------------------------
    |
    | The connection the package's tables live on, `null` or empty for the
    | default. Pruning, holds and the lifecycle journal run through the
    | maintenance connection (`null` or empty for the storage connection): give
    | it a database user of its own, so the application's user needs only
    | `SELECT` and `INSERT` on the entries table. Moving either connection is a
    | deploy, with a migration and a worker restart.
    |
    | A malformed value anywhere in this file fails closed where it is read, and
    | `audit-log:check` reports it.
    |
    */

    'storage' => [
        'connection'             => env('AUDIT_LOG_STORAGE_CONNECTION'),
        'maintenance_connection' => env('AUDIT_LOG_STORAGE_MAINTENANCE_CONNECTION'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Entries
    |---------------------------------------------------------------------------
    |
    | The entries table and the table of each entry's artifact (bulk subjects,
    | read disclosures, export manifests), both on the storage connection. A
    | table name is 1 to 47 lower-case letters, digits and underscores, not
    | starting with a digit, so every index named after it fits PostgreSQL's 63
    | characters with the table prefix. Set both before migrating: changing one
    | later moves no table.
    |
    */

    'entries' => [
        'table'           => env('AUDIT_LOG_ENTRIES_TABLE', 'audit_log_entries'),
        'artifacts_table' => env('AUDIT_LOG_ENTRIES_ARTIFACTS_TABLE', 'audit_log_artifacts'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Integrity
    |---------------------------------------------------------------------------
    |
    | Entries are signed with HMAC-SHA256 under the `current` key, derived from
    | `app.key` when `keys` is empty, with `app.previous_keys` still verifying
    | rows signed before a rotation. A managed ring maps ids to secrets of at
    | least 32 bytes, or `base64:` encoded, and never falls back to `app.key`.
    | Keep every key as long as its rows, and choose the managed ring before
    | going live: rows signed under a derived key cannot move into it. Read each
    | secret from its own env var:
    |
    |     'keys' => ['k2026' => env('AUDIT_LOG_INTEGRITY_KEY_K2026')],
    |
    | A seal is a signed checkpoint of its entries' ids and HMACs, chained to
    | the one before, so `audit-log:verify` finds an entry or seal changed,
    | removed or added. `log_id` names the chain, `null` or empty for
    | `source.id`. Set it and the tables before the first seal and never change
    | them.
    |
    | Each schedule is a cron expression, or `null` or empty to schedule nothing
    | and run the command elsewhere; a malformed one schedules nothing and is
    | reported, never thrown. `seal.lookback_seconds` must exceed the worst
    | clock skew between servers, and `verify.max_unsealed_age_seconds` must
    | exceed a day, since an entry recorded later than the lookback waits for
    | the daily sweep.
    |
    | `anchor.driver` is `null` to keep the seals in the database alone, or
    | `disk` to write each seal's digest under `anchor.path` on `anchor.disk`
    | (`null` or empty for `filesystems.default`). The anchor holds only on a
    | write-once (WORM) store the application's credentials cannot overwrite or
    | delete. Moving the disk or the path anchors every seal again.
    |
    */

    'integrity' => [
        'keys'              => [],
        'current'           => env('AUDIT_LOG_INTEGRITY_CURRENT'),
        'log_id'            => env('AUDIT_LOG_INTEGRITY_LOG_ID'),
        'checkpoints_table' => env('AUDIT_LOG_INTEGRITY_CHECKPOINTS_TABLE', 'audit_log_checkpoints'),
        'members_table'     => env('AUDIT_LOG_INTEGRITY_MEMBERS_TABLE', 'audit_log_checkpoint_members'),
        'state_table'       => env('AUDIT_LOG_INTEGRITY_STATE_TABLE', 'audit_log_integrity_state'),
        'seal'              => [
            'schedule'         => env('AUDIT_LOG_INTEGRITY_SEAL_SCHEDULE', '*/5 * * * *'),
            'sweep_schedule'   => env('AUDIT_LOG_INTEGRITY_SEAL_SWEEP_SCHEDULE', '15 3 * * *'),
            'batch'            => env('AUDIT_LOG_INTEGRITY_SEAL_BATCH', 5000),
            'max_batches'      => env('AUDIT_LOG_INTEGRITY_SEAL_MAX_BATCHES', 100),
            'lookback_seconds' => env('AUDIT_LOG_INTEGRITY_SEAL_LOOKBACK_SECONDS', 3600),
            'settle_seconds'   => env('AUDIT_LOG_INTEGRITY_SEAL_SETTLE_SECONDS', 0),
            'max_attempts'     => env('AUDIT_LOG_INTEGRITY_SEAL_MAX_ATTEMPTS', 5),
        ],
        'verify' => [
            'schedule'                 => env('AUDIT_LOG_INTEGRITY_VERIFY_SCHEDULE', '45 3 * * *'),
            'max_unsealed_age_seconds' => env('AUDIT_LOG_INTEGRITY_VERIFY_MAX_UNSEALED_AGE_SECONDS', 90000),
        ],
        'anchor' => [
            'driver' => env('AUDIT_LOG_INTEGRITY_ANCHOR_DRIVER', 'null'),
            'disk'   => env('AUDIT_LOG_INTEGRITY_ANCHOR_DISK'),
            'path'   => env('AUDIT_LOG_INTEGRITY_ANCHOR_PATH', 'audit-log-anchors'),
            'batch'  => env('AUDIT_LOG_INTEGRITY_ANCHOR_BATCH', 100),
        ],
    ],

    /*
    |---------------------------------------------------------------------------
    | Lifecycle
    |---------------------------------------------------------------------------
    |
    | The signed, chained journal of every hold, release, prune and import; the
    | active holds, listed for `audit-log:holds` and never trusted for a
    | decision; and the one row every lifecycle transaction locks first. All are
    | on the storage connection; set them before migrating, since changing one
    | later moves no table.
    |
    */

    'lifecycle' => [
        'journal_table' => env('AUDIT_LOG_LIFECYCLE_JOURNAL_TABLE', 'audit_log_lifecycle'),
        'holds_table'   => env('AUDIT_LOG_LIFECYCLE_HOLDS_TABLE', 'audit_log_holds'),
        'lock_table'    => env('AUDIT_LOG_LIFECYCLE_LOCK_TABLE', 'audit_log_lifecycle_lock'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Retention
    |---------------------------------------------------------------------------
    |
    | Days an entry is kept: `categories` per category and `after_days` for any
    | other, each `0` for forever, the default. A prune deletes only sealed
    | entries, and never an `audit_log.trail_exported` entry, a held one or one
    | waiting to be delivered. `preserve` maps a category to the days its
    | entries must stay readable, and a shorter retention is refused. For
    | example:
    |
    |     'categories' => [
    |         'security'          => 730,
    |         'access_management' => 1095,
    |         'audit'             => 0,
    |     ],
    |     'preserve' => ['security' => 365],
    |
    | `audit-log:prune` is scheduled only once something is kept for less than
    | forever or the application binds a policy of its own. A change of
    | `after_days`, `categories` or `preserve` is a new policy version, which
    | the next run journals.
    |
    */

    'retention' => [
        'after_days'  => env('AUDIT_LOG_RETENTION_AFTER_DAYS', 0),
        'categories'  => [],
        'preserve'    => [],
        'batch'       => env('AUDIT_LOG_RETENTION_BATCH', 1000),
        'max_seconds' => env('AUDIT_LOG_RETENTION_MAX_SECONDS', 3000),
        'schedule'    => env('AUDIT_LOG_RETENTION_SCHEDULE', '30 3 * * *'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Import
    |---------------------------------------------------------------------------
    |
    | How `audit-log:import` takes in another system's records.
    | `max_skew_seconds` is how far after the clock an imported entry may claim
    | to have happened, and a line longer than `max_line_bytes` is rejected
    | without being held. Set `batches_table` before migrating.
    |
    */

    'import' => [
        'batches_table'    => env('AUDIT_LOG_IMPORT_BATCHES_TABLE', 'audit_log_import_batches'),
        'chunk'            => env('AUDIT_LOG_IMPORT_CHUNK', 500),
        'max_skew_seconds' => env('AUDIT_LOG_IMPORT_MAX_SKEW_SECONDS', 300),
        'max_line_bytes'   => env('AUDIT_LOG_IMPORT_MAX_LINE_BYTES', 1048576),
    ],

    /*
    |---------------------------------------------------------------------------
    | Actor
    |---------------------------------------------------------------------------
    |
    | The guards the ambient actor is read from, in order, or `null` for the
    | default guard. The first guard holding a user decides, and the actor comes
    | from what it already holds, never from `user()`.
    |
    */

    'actor' => [
        'guards' => null,
    ],

    /*
    |---------------------------------------------------------------------------
    | Context
    |---------------------------------------------------------------------------
    |
    | Whether a request id or a `traceparent` sent by the edge is believed; both
    | flags must be real booleans. Trust needs the flag and a configured
    | `TrustProxies`, which checks only the immediate peer, so the trusted edge
    | must overwrite or validate these headers. A record made in global
    | middleware ahead of `TrustProxies` gets a generated id, kept for the rest
    | of the request.
    |
    */

    'context' => [
        'trust_request_id'  => env('AUDIT_LOG_CONTEXT_TRUST_REQUEST_ID', false),
        'request_id_header' => env('AUDIT_LOG_CONTEXT_REQUEST_ID_HEADER', 'X-Request-Id'),
        'trust_traceparent' => env('AUDIT_LOG_CONTEXT_TRUST_TRACEPARENT', false),
    ],

    /*
    |---------------------------------------------------------------------------
    | Definitions
    |---------------------------------------------------------------------------
    |
    | Whether a code with no registered definition is refused as a programming
    | error rather than taking the permissive definition. It is read on every
    | capture, so a malformed value fails there, never at boot. Turn it on once
    | every code the application records is registered.
    |
    */

    'definitions' => [
        'require_registered' => env('AUDIT_LOG_DEFINITIONS_REQUIRE_REGISTERED', false),
    ],

    /*
    |---------------------------------------------------------------------------
    | Capture
    |---------------------------------------------------------------------------
    |
    | Laravel's authentication events are always listened to.
    | `laravel.except_guards` skips the events of the listed guards, or every
    | event under `['*']`, the only setting that skips an event naming no guard.
    | `laravel.identifier_key` is the one credential a failed sign-in or a
    | lockout is read for, stored as `redaction.identifiers` says.
    |
    | Gate capture is off by default and records denials only.
    | `gate.except_abilities` wins over `gate.only_abilities` (`null` for every
    | ability). Abilities are compared exactly, so name them with literal
    | strings. `gate.reason_codes` lists the codes a denial's response may give
    | that are kept as its reason: the application controls the code, so an
    | unlisted one is never kept.
    |
    | A bulk manifest over `bulk.max_members` subjects or `bulk.max_bytes`
    | encoded is refused, never truncated.
    |
    */

    'capture' => [
        'laravel' => [
            'except_guards'  => [],
            'identifier_key' => env('AUDIT_LOG_CAPTURE_LARAVEL_IDENTIFIER_KEY', 'email'),
        ],
        'gate' => [
            'enabled'          => env('AUDIT_LOG_CAPTURE_GATE_ENABLED', false),
            'only_abilities'   => null,
            'except_abilities' => [],
            'reason_codes'     => [],
        ],
        'bulk' => [
            'max_members' => env('AUDIT_LOG_CAPTURE_BULK_MAX_MEMBERS', 100000),
            'max_bytes'   => env('AUDIT_LOG_CAPTURE_BULK_MAX_BYTES', 4194304),
        ],
    ],

    /*
    |---------------------------------------------------------------------------
    | Reading
    |---------------------------------------------------------------------------
    |
    | The largest page of the trail a caller may ask for; a larger size is
    | refused before any query. A page that names no size holds 50 entries, or
    | `max_per_page` when that is fewer.
    |
    */

    'read' => [
        'max_per_page' => env('AUDIT_LOG_READ_MAX_PER_PAGE', 100),
    ],

    /*
    |---------------------------------------------------------------------------
    | Export
    |---------------------------------------------------------------------------
    |
    | How many entries an export reads per statement inside its snapshot; memory
    | grows with it, never with the export's size.
    |
    */

    'export' => [
        'chunk' => env('AUDIT_LOG_EXPORT_CHUNK', 1000),
    ],

    /*
    |---------------------------------------------------------------------------
    | Source
    |---------------------------------------------------------------------------
    |
    | The deployment a record came from: `id` defaults to a slug of `app.name`
    | and `region` to none. Each record keeps the values it was written with.
    |
    */

    'source' => [
        'id'     => env('AUDIT_LOG_SOURCE_ID'),
        'region' => env('AUDIT_LOG_SOURCE_REGION'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Redaction
    |---------------------------------------------------------------------------
    |
    | `keys` adds key names to the built-in redaction list, which cannot be
    | shortened; key matching is a heuristic, and an event definition that
    | allowlists a code's fields is the remedy. `key` is at least 32 bytes, or
    | `base64:` encoded, or empty to derive it from `app.key`. Changing `key`,
    | `ip` or `identifiers` breaks correlation with earlier rows.
    |
    */

    'redaction' => [
        'keys'              => [],
        'key'               => env('AUDIT_LOG_REDACTION_KEY'),
        'identifiers'       => env('AUDIT_LOG_REDACTION_IDENTIFIERS', 'hash'),
        'ip'                => env('AUDIT_LOG_REDACTION_IP', 'full'),
        'max_bytes'         => env('AUDIT_LOG_REDACTION_MAX_BYTES', 16384),
        'max_context_bytes' => env('AUDIT_LOG_REDACTION_MAX_CONTEXT_BYTES', 4096),
    ],

    /*
    |---------------------------------------------------------------------------
    | Privacy
    |---------------------------------------------------------------------------
    |
    | Each value a definition marks for encryption is sealed under a key of its
    | owner's, one per owner, tenant and category, so erasing an owner destroys
    | its keys and leaves its values unreadable. Set the tables before
    | migrating: changing one later moves no table.
    |
    | Owners' keys are wrapped under the `current` wrapping key, derived from
    | `app.key` when `keys` is empty: separated from every other key `app.key`
    | gives, but not independent of it. Set `keys` and `current` together or
    | neither; a malformed ring never falls back to `app.key`. Keep every
    | wrapping key until `audit-log:rewrap` has moved every owner's key off it.
    | Read each secret from its own env var:
    |
    |     'keys' => ['w2026' => env('AUDIT_LOG_PRIVACY_KEY_W2026')],
    |
    */

    'privacy' => [
        'keys'                 => [],
        'current'              => env('AUDIT_LOG_PRIVACY_CURRENT'),
        'subject_keys_table'   => env('AUDIT_LOG_PRIVACY_SUBJECT_KEYS_TABLE', 'audit_log_subject_keys'),
        'owner_erasures_table' => env('AUDIT_LOG_PRIVACY_OWNER_ERASURES_TABLE', 'audit_log_owner_erasures'),
        'key_uses_table'       => env('AUDIT_LOG_PRIVACY_KEY_USES_TABLE', 'audit_log_key_uses'),
        'rewrap_batch'         => env('AUDIT_LOG_PRIVACY_REWRAP_BATCH', 500),
    ],

    /*
    |---------------------------------------------------------------------------
    | Failure
    |---------------------------------------------------------------------------
    |
    | What a failed write does to the code that recorded it: `report` spills the
    | record, reports the failure, dispatches `AuditWriteFailed` and carries on,
    | and `throw` spills, dispatches and throws. A `failClosed()` record always
    | throws, and a `transactional()` one always throws without spilling. A
    | spill line holds the whole record, so `log_channel` holds personal data:
    | control who can read it and how long it is kept. `audit-log:replay`
    | promises to read only a dedicated file channel using `LineFormatter` with
    | `%message%\n` and no inline-break replacement.
    |
    */

    'failure' => [
        'mode'        => env('AUDIT_LOG_FAILURE_MODE', 'report'),
        'log_channel' => env('AUDIT_LOG_FAILURE_LOG_CHANNEL'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Delivery
    |---------------------------------------------------------------------------
    |
    | `sync` stores a record as it is written, and `outbox` inserts it in the
    | outbox table for `audit-log:drain`, scheduled by the application, to
    | deliver. On the connection the application's transactions run on, an
    | outbox row commits exactly when they do. `outbox.lease_seconds` must
    | outlast a destination's timeout. A row is encrypted with `app.key`, so an
    | old `app.key` must stay in `app.previous_keys` while the outbox needs it.
    | Set the connection and the tables before migrating.
    |
    */

    'delivery' => [
        'mode'   => env('AUDIT_LOG_DELIVERY_MODE', 'sync'),
        'outbox' => [
            'connection'      => env('AUDIT_LOG_DELIVERY_OUTBOX_CONNECTION'),
            'table'           => env('AUDIT_LOG_DELIVERY_OUTBOX_TABLE', 'audit_log_outbox'),
            'lease_seconds'   => env('AUDIT_LOG_DELIVERY_OUTBOX_LEASE_SECONDS', 300),
            'max_attempts'    => env('AUDIT_LOG_DELIVERY_OUTBOX_MAX_ATTEMPTS', 10),
            'backoff_seconds' => env('AUDIT_LOG_DELIVERY_OUTBOX_BACKOFF_SECONDS', 60),
        ],
        'deliveries_table' => env('AUDIT_LOG_DELIVERY_DELIVERIES_TABLE', 'audit_log_deliveries'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Monitor
    |---------------------------------------------------------------------------
    |
    | How old, in minutes, the progress `audit-log:check --freshness` reads may
    | grow before it calls a run stale: `seal_minutes` for sealing,
    | `daily_minutes` for the sweep, full verification and prune, and
    | `outbox_minutes` for the oldest outbox row in outbox mode.
    |
    */

    'monitor' => [
        'seal_minutes'   => env('AUDIT_LOG_MONITOR_SEAL_MINUTES', 30),
        'daily_minutes'  => env('AUDIT_LOG_MONITOR_DAILY_MINUTES', 1560),
        'outbox_minutes' => env('AUDIT_LOG_MONITOR_OUTBOX_MINUTES', 15),
    ],

];
