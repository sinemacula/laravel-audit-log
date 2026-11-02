<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\Events\TransactionRolledBack;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Tests\TestCase;

/**
 * Shared base for deterministic performance-contract tests.
 *
 * Counts what a subject under test asks of the default connection, so the suite
 * can assert structural statement budgets without making flaky wall-clock
 * assertions: every statement the connection is asked to run, counted before it
 * runs, so one that fails counts too (the query log records only those that
 * succeed); every savepoint, a transaction begun inside another; and every
 * rollback, of a transaction or a savepoint. The clock is frozen at a time with
 * microseconds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class PerformanceContractTestCase extends TestCase
{
    /** @var string The frozen time, in UTC. */
    protected const string NOW = '2026-11-01 12:00:00.123456';

    /** @var list<string> The statements captured since the last capture began. */
    private array $statements = [];

    /** @var int The savepoints counted since the last capture began. */
    private int $savepoints = 0;

    /** @var int The rollbacks counted since the last capture began. */
    private int $rollbacks = 0;

    /**
     * Freeze the clock and count what the default connection is asked to do.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(CarbonImmutable::createFromFormat('Y-m-d H:i:s.u', self::NOW, 'UTC'));

        DB::connection()->beforeExecuting(function (string $query): void {
            $this->statements[] = $query;
        });

        Event::listen(TransactionBeginning::class, function (TransactionBeginning $event): void {
            if ($event->connection->transactionLevel() <= 1) {
                return;
            }

            $this->savepoints++;
        });

        Event::listen(TransactionRolledBack::class, function (): void {
            $this->rollbacks++;
        });
    }

    /**
     * Release the frozen clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * Run a subject and assert the exact statement budget: its reads, its
     * writes, its savepoints and its rollbacks. A write is an `insert`,
     * `update`, `delete` or `replace`; every other statement is a read.
     *
     * @template TResult
     *
     * @param  int  $reads
     * @param  int  $writes
     * @param  int  $savepoints
     * @param  int  $rollbacks
     * @param  callable(): TResult  $callback
     * @return TResult
     */
    protected function assertStatementBudget(int $reads, int $writes, int $savepoints, int $rollbacks, callable $callback): mixed
    {
        $result = $this->capture($callback);

        $written    = self::writesIn($this->statements);
        $statements = implode(' | ', $this->statements);

        static::assertSame($reads, count($this->statements) - count($written), "Unexpected read budget. Statements: {$statements}");
        static::assertCount($writes, $written, "Unexpected write budget. Statements: {$statements}");
        static::assertSame($savepoints, $this->savepoints, "Unexpected savepoint budget. Statements: {$statements}");
        static::assertSame($rollbacks, $this->rollbacks, "Unexpected rollback budget. Statements: {$statements}");

        return $result;
    }

    /**
     * Run a subject with the counts started afresh, so what is captured
     * afterwards is what it asked for alone.
     *
     * @template TResult
     *
     * @param  callable(): TResult  $callback
     * @return TResult
     */
    protected function capture(callable $callback): mixed
    {
        $this->statements = [];
        $this->savepoints = 0;
        $this->rollbacks  = 0;

        return $callback();
    }

    /**
     * The statements the last captured subject asked the default connection to
     * run, in order.
     *
     * @return list<string>
     */
    protected function capturedStatements(): array
    {
        return $this->statements;
    }

    /**
     * The writes among the statements the last captured subject asked for.
     *
     * @return list<string>
     */
    protected function capturedWrites(): array
    {
        return self::writesIn($this->statements);
    }

    /**
     * The savepoints the last captured subject began.
     *
     * @return int
     */
    protected function capturedSavepoints(): int
    {
        return $this->savepoints;
    }

    /**
     * The rollbacks the last captured subject made, of a transaction or a
     * savepoint.
     *
     * @return int
     */
    protected function capturedRollbacks(): int
    {
        return $this->rollbacks;
    }

    /**
     * The writes among the statements.
     *
     * @param  list<string>  $statements
     * @return list<string>
     */
    private static function writesIn(array $statements): array
    {
        return array_values(array_filter($statements, static fn (string $statement): bool => preg_match('/^\s*(insert|update|delete|replace)\b/i', $statement) === 1));
    }
}
