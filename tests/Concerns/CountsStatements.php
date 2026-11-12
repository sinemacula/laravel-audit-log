<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;

/**
 * Collects the SQL of every statement run once asked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait CountsStatements
{
    /**
     * Count every statement run from now on.
     *
     * @return \ArrayObject<int, string>
     */
    private function countStatements(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $statements */
        $statements = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($statements): void {
            $statements[] = $query->sql;
        });

        return $statements;
    }
}
