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

    /*
    |---------------------------------------------------------------------------
    | Actor
    |---------------------------------------------------------------------------
    |
    | The guards the ambient actor is read from, in order: `null` for the
    | default guard (the default), or a non-empty list of guard names of 1 to 64
    | characters. The first guard holding a user decides, and the actor comes
    | from what it already holds, never from `user()`. Any other value fails
    | closed when it is read, and `audit-log:check` reports it, as it does a
    | name `auth.guards` does not configure. It may change on any deploy.
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
    | Whether a request id or a `traceparent` sent by the edge is believed. Both
    | flags are `false` by default and must be real booleans. Trusting a header
    | needs both its flag and a configured `TrustProxies`, and
    | `isFromTrustedProxy()` checks only the immediate peer, so the trusted edge
    | must overwrite or validate these headers. A record or a dispatch in global
    | middleware ahead of `TrustProxies` runs before the proxy is trusted, so it
    | gets a generated id, kept for the rest of the request. An untrusted,
    | repeated or malformed header is ignored and never kept. `request_id_header`
    | names the request id's header (`X-Request-Id` by default), 1 to 64
    | characters of an RFC 9110 token. A malformed setting fails closed when it
    | is read, and `audit-log:check` reports it. They may change on any deploy.
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
    | Whether a code with no registered definition is refused: `false` by
    | default, so it takes the permissive definition, or `true`, so it is a
    | programming error. It must be a real boolean, read on every capture;
    | anything else fails closed there, never at boot, and `audit-log:check`
    | reports it. Turn it on once every code the application records is
    | registered.
    |
    */

    'definitions' => [
        'require_registered' => env('AUDIT_LOG_DEFINITIONS_REQUIRE_REGISTERED', false),
    ],

    /*
    |---------------------------------------------------------------------------
    | Source
    |---------------------------------------------------------------------------
    |
    | Which deployment a record came from. `id` is 1 to 64 characters with no
    | control characters, kept as given; `null` or empty, the default, takes a
    | slug of `app.name`. `region` is `null` or empty for none, the default, or
    | 1 to 32 characters with no control characters. A malformed value fails
    | closed when it is read, as does an `app.name` that gives no slug, and
    | `audit-log:check` reports each. Each record keeps the values it was
    | written with, so changing them on a deploy leaves earlier rows as they
    | are.
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
    | What a record keeps of what it is given. `keys` are more key names to
    | redact, none by default, merged with the built-ins, each tokenised the way
    | a key is, and no built-in can be removed: matching keys is a heuristic,
    | whose remedy is an event definition that allowlists a code's fields.
    | `identifiers` says how a sign-in identifier is stored, `hash` by default
    | or `drop`. `ip` says how an address is stored, `full` by default,
    | `truncate`, `hash`, `drop` or `encrypt`. `key` is at least 32 bytes, or
    | `base64:` followed by the encoding of one, or empty by default to derive
    | it from `app.key`; changing it visibly breaks correlation with earlier
    | rows. `max_bytes` is the most the encoded properties may hold, from 8192
    | to 16777216 and 16384 by default, and `max_context_bytes` the most the
    | encoded context may hold, from 1024 to 16777216 and 4096 by default.
    | `keys`, `identifiers`, `ip` and both budgets may change on any deploy and
    | affect only later rows, and changing `ip` or `identifiers` breaks
    | correlation across the switch. A malformed value fails closed when it is
    | read, and `audit-log:check` reports it.
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

];
