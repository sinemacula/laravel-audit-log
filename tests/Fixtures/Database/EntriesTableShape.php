<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Database;

/**
 * The shape the shipped entries migration gives its table, written out apart
 * from the package so the tests that pin the migration and the schema checks
 * compare both against one statement of it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EntriesTableShape
{
    /** @var array<string, int> Each string column, by name, with its length in characters. */
    public const array STRING_LENGTHS = [
        'event'            => 191,
        'category'         => 64,
        'outcome'          => 16,
        'reason'           => 64,
        'actor_type'       => 191,
        'actor_id'         => 191,
        'subject_type'     => 191,
        'subject_id'       => 191,
        'principal_type'   => 191,
        'principal_id'     => 191,
        'tenant_type'      => 191,
        'tenant_id'        => 191,
        'credential_id'    => 191,
        'guard'            => 64,
        'session_id'       => 191,
        'request_id'       => 64,
        'trace_id'         => 32,
        'correlation_id'   => 191,
        'origin'           => 16,
        'provenance'       => 16,
        'source_id'        => 64,
        'source_region'    => 32,
        'source_record_id' => 191,
        'ip'               => 255,
        'user_agent'       => 512,
        'key_id'           => 32,
        'hmac'             => 64,
    ];

    /**
     * Disallow instantiation; constant container only.
     */
    private function __construct() {}
}
