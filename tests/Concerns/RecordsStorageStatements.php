<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;

/**
 * Records the statements the storage connection runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RecordsStorageStatements
{
    /**
     * Record each statement run on the storage connection from now on.
     *
     * @return \ArrayObject<int, string>
     */
    protected function recordStatements(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $statements */
        $statements = new \ArrayObject;

        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query) use ($statements): void {
            $statements->append($query);
        });

        return $statements;
    }

    /**
     * Record, from now on, every statement the storage connection runs, in
     * lower case.
     *
     * @return \ArrayObject<int, string>
     */
    protected function recordExecutedStatements(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $statements */
        $statements = new \ArrayObject;

        DB::connection(StorageConnection::name())->listen(static function (QueryExecuted $query) use ($statements): void {
            $statements->append(strtolower($query->sql));
        });

        return $statements;
    }
}
