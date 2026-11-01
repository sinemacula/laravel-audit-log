<?php

declare(strict_types = 1);

namespace Tests\Integration\Database;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversNothing;
use Tests\TestCase;

/**
 * Integration tests for the test harness's database: each test runs on the
 * engine `DB_CONNECTION` names, in a database of its paratest worker's own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class WorkerDatabaseTest extends TestCase
{
    /**
     * The default connection is the engine the environment names.
     *
     * @return void
     */
    public function testRunsOnTheEngineTheEnvironmentNames(): void
    {
        $connection = DB::connection();

        self::assertSame(self::CONNECTION, $connection->getName());
        self::assertSame(getenv('DB_CONNECTION') ?: 'sqlite', $connection->getDriverName());
        self::assertEquals(1, DB::scalar('select 1'));
    }

    /**
     * A persistent engine is reached in the worker's own database, named after
     * its paratest token.
     *
     * @return void
     */
    public function testPersistentEnginesUseTheWorkersOwnDatabase(): void
    {
        $connection = DB::connection();

        if ($connection->getDriverName() === 'sqlite') {
            self::assertSame(':memory:', $connection->getDatabaseName());

            return;
        }

        $token = getenv('TEST_TOKEN');

        self::assertSame(
            (getenv('DB_DATABASE') ?: 'laravel_audit_log_test') . '_' . ($token === false || $token === '' ? '0' : $token),
            $connection->getDatabaseName(),
        );
    }
}
