<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Delivery\CommitQueue;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;

/**
 * State the commit queue keeps across a long-running process: none is left once
 * each transaction it waited on has ended.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CommitQueue::class)]
final class CommitQueueStateTest extends PerformanceContractTestCase
{
    /** @var string The code every test records. */
    private const string CODE = 'invoice.approved';

    /** @var int The transactions the process runs, every other one rolled back. */
    private const int TRANSACTIONS = 2000;

    /**
     * After thousands of committed and rolled-back transactions the queue holds
     * no flush and no rolled-back work, and each record is written once.
     *
     * @return void
     */
    public function testThousandsOfTransactionsLeaveNoQueuedState(): void
    {
        $queue = app(CommitQueue::class);

        $this->capture(static function (): void {
            for ($transaction = 0; $transaction < self::TRANSACTIONS; $transaction++) {
                DB::connection()->beginTransaction();

                AuditLog::record(self::CODE);
                AuditLog::event(self::CODE)->afterTransaction()->record();

                $transaction % 2 === 0 ? DB::connection()->commit() : DB::connection()->rollBack();
            }
        });

        $written = self::TRANSACTIONS + intdiv(self::TRANSACTIONS, 2);
        $flushes = (new \ReflectionProperty(CommitQueue::class, 'flushes'))->getValue($queue);

        assert($flushes instanceof \WeakMap);

        self::assertSame($queue, app(CommitQueue::class));
        self::assertCount(0, $flushes);
        self::assertSame([], (new \ReflectionProperty(CommitQueue::class, 'rolledBack'))->getValue($queue));
        self::assertCount($written, $this->capturedWrites());
        self::assertSame($written, DB::connection()->table(EntrySettings::table())->count());
    }
}
