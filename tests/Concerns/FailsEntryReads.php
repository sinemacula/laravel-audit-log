<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;

/**
 * Makes reads of the entries table on the storage connection fail.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait FailsEntryReads
{
    /** @var bool Whether a read of the entries table on the storage connection fails. */
    private bool $failEntryReads = false;

    /**
     * Make every storage read of the entries table fail until the flag clears.
     *
     * @return void
     */
    protected function failEntryReads(): void
    {
        $this->failEntryReads = true;

        DB::connection(StorageConnection::name())->beforeExecuting(function (string $query, array $bindings, Connection $connection): void {
            if (!$this->failEntryReads || !str_starts_with($query, 'select') || !str_contains($query, EntrySettings::table())) {
                return;
            }

            throw new QueryException((string) $connection->getName(), $query, $bindings, new \PDOException('SQLSTATE[HY000]: General error: the read failed'));
        });
    }
}
