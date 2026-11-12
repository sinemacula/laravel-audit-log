<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\Events\TransactionCommitted;
use Illuminate\Database\Events\TransactionRolledBack;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Tests\TestCase;

/**
 * Base for statement-budget tests: counts what a subject asks of the default
 * connection, under a frozen clock. Statements are counted before they run,
 * since the query log keeps only those that succeed.
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

    /** @var int The top-level transactions begun since the last capture began. */
    private int $transactions = 0;

    /** @var int The top-level commits made since the last capture began. */
    private int $commits = 0;

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
                $this->transactions++;

                return;
            }

            $this->savepoints++;
        });

        Event::listen(TransactionRolledBack::class, function (): void {
            $this->rollbacks++;
        });

        Event::listen(TransactionCommitted::class, function (TransactionCommitted $event): void {
            if ($event->connection->transactionLevel() > 0) {
                return;
            }

            $this->commits++;
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
     * Run a subject and assert its exact reads, writes, savepoints and
     * rollbacks; a write is an `insert`, `update`, `delete` or `replace`.
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
     * The reads a commit costs with audit work waiting: one on PostgreSQL,
     * whose commit reports success even after an abort, so it asks first.
     *
     * @return int
     */
    protected function commitQuestionReads(): int
    {
        return DB::connection()->getDriverName() === 'pgsql' ? 1 : 0;
    }

    /**
     * Run a subject and assert the top-level transactions it began and
     * committed, which run on PDO directly and no statement budget sees.
     *
     * @template TResult
     *
     * @param  int  $transactions
     * @param  int  $commits
     * @param  callable(): TResult  $callback
     * @return TResult
     */
    protected function assertTransactionBudget(int $transactions, int $commits, callable $callback): mixed
    {
        $result = $this->capture($callback);

        static::assertSame($transactions, $this->transactions, 'Unexpected top-level transaction budget.');
        static::assertSame($commits, $this->commits, 'Unexpected top-level commit budget.');

        return $result;
    }

    /**
     * Run a subject with the counts reset.
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

        $this->transactions = 0;
        $this->commits      = 0;

        return $callback();
    }

    /**
     * The statements the last captured subject asked for, in order.
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
     * The transaction and savepoint rollbacks the last captured subject made.
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
