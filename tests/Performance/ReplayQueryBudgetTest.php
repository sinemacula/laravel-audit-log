<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Delivery\Outbox;
use SineMacula\Laravel\AuditLog\Delivery\Receipts;
use SineMacula\Laravel\AuditLog\Delivery\Replayer;
use SineMacula\Laravel\AuditLog\Delivery\ReplayResult;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Stores\PlainStore;

/**
 * Statement budget for replaying the outbox: the failed rows are read once and
 * reset and requeued a chunk at a time, before the drain.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Replayer::class)]
#[CoversClass(Outbox::class)]
#[CoversClass(Receipts::class)]
final class ReplayQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithOutbox, SeedsTheOutbox;

    /** @var int Failed rows: one more than a chunk of resets or requeues. */
    private const int FAILED = 501;

    /** @var string When every failed row failed. */
    private const string FAILED_AT = '2026-11-01T11:00:00.000000Z';

    /**
     * A backlog of one more failed row than a chunk is one read of the ids, two
     * resets and two requeues, then the drain and none of them again.
     *
     * @return void
     */
    public function testAFailedBacklogIsOneReadAndTwoStatementsPerChunk(): void
    {
        $store = new PlainStore;

        app()->instance(AuditStore::class, $store);

        foreach (range(1, self::FAILED) as $ignored) {
            $this->enqueue($this->finalisedRecord(), ['failed_at' => self::FAILED_AT, 'attempts' => 10]);
        }

        $result = $this->capture(static fn (): ReplayResult => app(Replayer::class)->outbox(false));
        $kinds  = array_map(self::kindOf(...), $this->capturedStatements());
        $steps  = ['failed ids', 'reset', 'reset', 'requeue', 'requeue'];

        self::assertSame([...$steps, 'drain'], array_slice($kinds, 0, 6));
        self::assertSame([], array_values(array_intersect(array_slice($kinds, 6), $steps)));
        self::assertSame(self::FAILED, $result->replayed());
        self::assertSame(self::FAILED, $store->calls());
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * Which step of the replay the statement is, or `null` for any other.
     *
     * @param  string  $statement
     * @return ?string
     */
    private static function kindOf(string $statement): ?string
    {
        $outbox     = preg_quote(DeliveryTables::outboxTable(), '/');
        $deliveries = preg_quote(DeliveryTables::deliveriesTable(), '/');
        $statement  = str_replace(['"', '`'], '', $statement);

        return match (1) {
            preg_match('/^select id from ' . $outbox . ' where failed_at is not null order by id asc$/', $statement)              => 'failed ids',
            preg_match('/^update ' . $deliveries . ' set attempts = \?, last_error_class = \? where entry_id in \(/', $statement) => 'reset',
            preg_match('/^update ' . $outbox . ' set failed_at = \?, attempts = \?, available_at = \?/', $statement)              => 'requeue',
            preg_match('/^select id from ' . $outbox . ' where failed_at is null /', $statement)                                  => 'drain',
            default                                                                                                               => null,
        };
    }
}
