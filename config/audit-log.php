<?php

declare(strict_types = 1);

return [

    /*
    |---------------------------------------------------------------------------
    | Storage
    |---------------------------------------------------------------------------
    |
    | The connection the package's tables live on (`null` or empty for the
    | default): the model reads them there, the store writes them there, and the
    | published migrations create them there. The maintenance connection is the
    | one pruning, holds and erasure will run through (`null` or empty for the
    | storage connection). It must reach the same database with a user of its
    | own, so the application's user needs only `SELECT` and `INSERT` on the
    | entries table; nothing writes through it yet. A value that is neither a
    | connection name nor `null` or empty fails closed when it is read, and
    | `audit-log:check` reports it, as it does a name `database.connections`
    | does not configure. Keep both fixed while the application runs: moving the
    | tables is a deploy, with a migration the application performs and a
    | worker restart.
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
    | The table the entries live in (`audit_log_entries` by default): 1 to 47
    | lower-case letters, digits and underscores that does not start with a
    | digit, so every index the migration names after it fits PostgreSQL's 63
    | characters, the connection's table prefix included. Any other value fails
    | closed when it is read, and `audit-log:check` reports it. Set it before
    | migrating: changing it later moves no table.
    |
    */

    'entries' => [
        'table' => env('AUDIT_LOG_ENTRIES_TABLE', 'audit_log_entries'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Integrity
    |---------------------------------------------------------------------------
    |
    | Every entry is signed with HMAC-SHA256 under the current key and keeps
    | that key's id. With no keys the key is derived from `app.key`, and the
    | keys derived from `app.previous_keys` still verify the rows signed before
    | a rotation. To manage the keys instead, map each id (1 to 32 letters,
    | digits, dots, underscores or hyphens, starting with a letter or a digit)
    | to a secret of at least 32 bytes, or `base64:` followed by the encoding of
    | one, and name the signing key in `current`. A malformed ring fails closed,
    | never falling back to `app.key`, and `audit-log:check` reports it.
    | Removing a key leaves its rows unverifiable, so keep every key as long as
    | its rows are kept. Choose the managed ring before going live: rows signed
    | under a derived key cannot yet be carried into it. Read each secret from
    | its own env var:
    |
    |     'keys' => ['k2026' => env('AUDIT_LOG_INTEGRITY_KEY_K2026')],
    |
    */

    'integrity' => [
        'keys'    => [],
        'current' => env('AUDIT_LOG_INTEGRITY_CURRENT'),
    ],

];
