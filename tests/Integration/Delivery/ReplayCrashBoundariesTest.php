<?php

declare(strict_types = 1);

namespace Tests\Integration\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Delivery\Outbox;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Delivery\Receipts;
use SineMacula\Laravel\AuditLog\Delivery\Replayer;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Stores\StackAuditStore;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\RunsKilledChildren;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\TestCase;

/**
 * Integration tests for a replay killed by `SIGKILL` between its reset, requeue
 * and drain steps, and the replay or drain that recovers it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Replayer::class)]
#[CoversClass(Outbox::class)]
#[CoversClass(Receipts::class)]
final class ReplayCrashBoundariesTest extends TestCase
{
    use InteractsWithAuditStore, InteractsWithOutbox, RunsKilledChildren, SeedsTheOutbox;

    /** @var string When each test starts. */
    private const string NOW = '2026-11-01T12:00:00.123456Z';

    /** @var string When the replays run. */
    private const string LATER = '2026-11-01T13:00:00.654321Z';

    /** @var string The update that resets the undelivered receipts. */
    private const string RESET = '/^update \S*audit_log_deliveries\S* set \S*attempts\S* = 0/';

    /** @var string The update that requeues the failed rows. */
    private const string REQUEUE = '/^update \S*audit_log_outbox\S* set \S*failed_at\S* = null/';

    /** @var string The stack's destination that has the record. */
    private const string DELIVERED = 'database';

    /** @var string The stack's destination that failed. */
    private const string FAILED = 'siem';

    /** @var string The file each destination call is named in. */
    private const string CALLS = 'calls';

    /** @var string The file that, when it exists, says the failing destination is back. */
    private const string SIEM_UP = 'siem-up';

    /**
     * Stop the clock, and keep report output quiet.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->moveClockTo(self::NOW);

        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);
        app(ConfigRepository::class)->set('audit-log.delivery.outbox.max_attempts', 1);
    }

    /**
     * Release the clock, and remove the children's shared files after the
     * migrations roll back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();

        $this->removeChildren();
    }

    /**
     * Rows of `[kill before, kill after, row left failed, failed receipt left
     * reset]`, one per replay boundary.
     *
     * @return iterable<string, array{0: ?string, 1: ?string, 2: bool, 3: bool}>
     */
    public static function provideBoundaries(): iterable
    {
        yield from [
            'before the receipts are reset' => [self::RESET, null, true, false],
            'after the receipts are reset'  => [null, self::RESET, true, true],
            'before the row is requeued'    => [self::REQUEUE, null, true, true],
            'after the row is requeued'     => [null, self::REQUEUE, false, true],
        ];
    }

    /**
     * A kill at each boundary leaves its state without calling any destination.
     *
     * @param  ?string  $before
     * @param  ?string  $after
     * @param  bool  $failed
     * @param  bool  $reset
     * @return void
     */
    #[DataProvider('provideBoundaries')]
    public function testAKillLeavesWhatItsBoundarySays(?string $before, ?string $after, bool $failed, bool $reset): void
    {
        [$id, $delivered] = $this->aFailedRow();

        $this->crash($before, $after);

        $row = $this->outboxRow($id);

        self::assertNotNull($row);
        self::assertSame($failed, $row['failed_at'] !== null);
        self::assertSame($failed ? 1 : 0, $row['attempts']);
        self::assertSame($delivered, $this->receipt($id, self::DELIVERED));
        self::assertSame($reset ? 0 : 1, $this->receipt($id, self::FAILED)['attempts'] ?? null);
        self::assertSame($reset ? null : \DomainException::class, $this->receipt($id, self::FAILED)['last_error_class'] ?? null);
        self::assertSame([self::DELIVERED, self::FAILED], $this->childFileLines(self::CALLS));
    }

    /**
     * Rows of `[kill before, kill after]`: each boundary of a replay.
     *
     * @return iterable<string, array{0: ?string, 1: ?string}>
     */
    public static function provideKills(): iterable
    {
        foreach (self::provideBoundaries() as $name => [$before, $after]) {
            yield $name => [$before, $after];
        }
    }

    /**
     * A second replay recovers from a kill at any boundary.
     *
     * @param  ?string  $before
     * @param  ?string  $after
     * @return void
     */
    #[DataProvider('provideKills')]
    public function testASecondReplayRecovers(?string $before, ?string $after): void
    {
        [$id, $delivered] = $this->aFailedRow();

        $this->crash($before, $after);

        touch($this->childFile(self::SIEM_UP));

        app(Replayer::class)->outbox(false);

        $this->assertRecovered($id, $delivered);
    }

    /**
     * A drain alone recovers a kill after the requeue, since the row is due
     * again.
     *
     * @return void
     */
    public function testADrainRecoversAKillAfterTheRequeue(): void
    {
        [$id, $delivered] = $this->aFailedRow();

        $this->crash(null, self::REQUEUE);

        touch($this->childFile(self::SIEM_UP));

        app(ConfigRepository::class)->set('audit-log.delivery.outbox.max_attempts', 10);

        app(OutboxDrainer::class)->drain(100, true);

        $this->assertRecovered($id, $delivered);
    }

    /**
     * A drain leaves a row a kill left failed, for a replay to requeue.
     *
     * @return void
     */
    public function testADrainLeavesARowAKillLeftFailed(): void
    {
        [$id] = $this->aFailedRow();

        $this->crash(self::REQUEUE, null);

        touch($this->childFile(self::SIEM_UP));

        app(OutboxDrainer::class)->drain(100, true);

        self::assertNotNull($this->outboxRow($id)['failed_at'] ?? null);
        self::assertSame(1, $this->entryCount());
    }

    /**
     * Put the database on a file SQLite can share across a fork.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->useFileDatabaseOnSqlite($app);
    }

    /**
     * Fail a row in a drain through a stack of the database and a failing
     * destination, then move the clock on; return its id and delivered receipt.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @return array{0: string, 1: ?array<string, mixed>}
     */
    private function aFailedRow(): array
    {
        $this->bindTheStack();

        $id = $this->enqueue($this->finalisedRecord());

        self::assertSame(1, app(OutboxDrainer::class)->drain(100, true)->failed());
        self::assertNotNull($this->outboxRow($id)['failed_at'] ?? null);
        self::assertSame(self::NOW, $this->receipt($id, self::DELIVERED)['delivered_at'] ?? null);

        $this->moveClockTo(self::LATER);

        return [$id, $this->receipt($id, self::DELIVERED)];
    }

    /**
     * Run a replay in a child killed at the given point, and assert it was.
     *
     * @param  ?string  $before
     * @param  ?string  $after
     * @return void
     */
    private function crash(?string $before, ?string $after): void
    {
        $this->assertKilled($this->runChild(static function (): void {
            app(Replayer::class)->outbox(false);
        }, $before, $after));
    }

    /**
     * Assert one entry, no row, the delivered receipt unchanged and its
     * destination not called again, and the other destination delivered.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  string  $id
     * @param  ?array<string, mixed>  $delivered
     * @return void
     */
    private function assertRecovered(string $id, ?array $delivered): void
    {
        self::assertSame($id, $this->storedRow($id)['id']);
        self::assertSame(1, $this->entryCount());
        self::assertSame(0, $this->outboxCount());
        self::assertSame($delivered, $this->receipt($id, self::DELIVERED));
        self::assertSame(self::LATER, $this->receipt($id, self::FAILED)['delivered_at'] ?? null);
        self::assertSame(1, array_count_values($this->childFileLines(self::CALLS))[self::DELIVERED]);
    }

    /**
     * Bind a stack of the logging database and a destination that fails until
     * the file says it is back.
     *
     * @return void
     */
    private function bindTheStack(): void
    {
        $connection = StorageConnection::resolvedName();
        $store      = app(DatabaseAuditStore::class);

        app()->instance(AuditStore::class, new StackAuditStore([
            self::DELIVERED => new CallbackStore(function (FinalisedRecord $record) use ($store): void {
                $this->appendToChildFile(self::CALLS, self::DELIVERED);

                $store->store($record);
            }, true, [$connection]),
            self::FAILED => new CallbackStore(function (): void {
                $this->appendToChildFile(self::CALLS, self::FAILED);

                if (!is_file($this->childFile(self::SIEM_UP))) {
                    throw new \DomainException('The SIEM is down.');
                }
            }),
        ]));
    }
}
