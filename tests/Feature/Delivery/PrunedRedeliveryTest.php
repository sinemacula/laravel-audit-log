<?php

declare(strict_types = 1);

namespace Tests\Feature\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Console\VerifyCommand;
use SineMacula\Laravel\AuditLog\Contracts\AuditStore;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\Clock;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Delivery\DrainResult;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Delivery\Replayer;
use SineMacula\Laravel\AuditLog\Delivery\ReplayResult;
use SineMacula\Laravel\AuditLog\Events\AuditRecorded;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\PruneBitmap;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Lifecycle\Pruner;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneTombstones;
use SineMacula\Laravel\AuditLog\Recorder;
use SineMacula\Laravel\AuditLog\Records\FinalisedRecord;
use SineMacula\Laravel\AuditLog\Stores\FailureSpill;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\PrunesByHand;
use Tests\Concerns\SealsEntries;
use Tests\Concerns\SeedsTheOutbox;
use Tests\Fixtures\Integrity\InMemoryPruneLedger;
use Tests\Fixtures\Privacy\RecordingExceptionHandler;
use Tests\Fixtures\Stores\CallbackStore;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Feature tests for the tombstones checked wherever the store is handed a
 * record it did not just mint.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OutboxDrainer::class)]
#[CoversClass(DrainResult::class)]
#[CoversClass(Replayer::class)]
#[CoversClass(ReplayResult::class)]
#[CoversClass(PruneTombstones::class)]
final class PrunedRedeliveryTest extends TestCase
{
    use InteractsWithAuditStore, InteractsWithOutbox, PrunesByHand, SealsEntries, SeedsTheOutbox;

    /** @var string When each test starts, and its records are finalised. */
    private const string NOW = '2026-11-01T12:00:00.000000Z';

    /** @var string When the records are sealed: after each was recorded. */
    private const string SEALED_AT = '2026-11-01 12:30:00';

    /** @var string When the record is pruned. */
    private const string PRUNED_AT = '2026-11-01T13:00:00.000000Z';

    /** @var string When a verification runs: after the prune. */
    private const string VERIFIED_AT = '2026-11-01 14:00:00';

    /** @var string The prune operation that pruned the record. */
    private const string OPERATION_ID = '019a4b2e-a000-7000-8000-000000000001';

    /** @var list<string> The files each test wrote. */
    private array $files = [];

    /** @var string What the last verification printed. */
    private string $printed = '';

    /**
     * Stop the clock, freeze the sealer's, and keep what a report would say out
     * of the output.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->moveClockTo(self::NOW);
        $this->sealAt(self::SEALED_AT);

        app()->instance(ExceptionHandler::class, new RecordingExceptionHandler);
    }

    /**
     * Put the clock back and remove the files the test wrote.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach ($this->files as $file) {
            if (!is_file($file)) {
                continue;
            }

            unlink($file);
        }

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * A due outbox row whose record retention pruned is deleted and counted
     * pruned, and nothing is stored again.
     *
     * @return void
     */
    public function testTheDrainCompletesAPrunedRowAsPruned(): void
    {
        $this->enqueue($this->prunedRecord());

        $result = $this->drain();

        self::assertSame([0, 1, 0, 0, 0, 0], self::drainTally($result));
        self::assertFalse($result->hasFailures());
        self::assertSame(0, $this->outboxCount());
        self::assertSame(0, $this->entryCount());
        self::assertSame(0, $this->receiptCount());
    }

    /**
     * A row whose sealed entry was deleted outside retention is no tombstone:
     * the drain stores it again and the seal verifies whole.
     *
     * @return void
     */
    public function testARowWhoseEntryWasDeletedOutsideRetentionIsStoredAgain(): void
    {
        $record = $this->finalisedRecord();

        $this->store()->store($record);

        self::assertSame(1, $this->sealAll()->entries());
        self::assertSame(1, DB::connection(StorageConnection::name())->table(EntrySettings::table())->where('id', $record->record->id)->delete());

        $this->enqueue($record);

        $result = $this->drain();

        self::assertSame(0, $result->pruned());
        self::assertFalse($result->hasFailures());
        self::assertSame(0, $this->outboxCount());
        self::assertSame(1, $this->entriesUnder($record->record->id));

        app()->instance(CheckpointAnchor::class, new NullAnchor);

        self::assertSame(0, $this->verify());
    }

    /**
     * No destination is called for a pruned row: a store that counts its calls
     * is never asked, and no receipt is written.
     *
     * @return void
     */
    public function testNoDestinationIsCalledForAPrunedRow(): void
    {
        $record = $this->prunedRecord();
        $calls  = 0;

        app()->instance(AuditStore::class, new CallbackStore(static function () use (&$calls): void {
            $calls++;
        }));

        $this->enqueue($record);

        self::assertSame(1, $this->drain()->pruned());
        self::assertSame(0, $calls);
        self::assertSame(0, $this->receiptCount());
    }

    /**
     * No `AuditRecorded` is dispatched for a pruned row, as it is for a row
     * delivered beside it.
     *
     * @return void
     */
    public function testNoAuditRecordedIsDispatchedForAPrunedRow(): void
    {
        $pruned    = $this->prunedRecord();
        $delivered = $this->finalisedRecord();
        $recorded  = [];

        Event::listen(AuditRecorded::class, static function (AuditRecorded $event) use (&$recorded): void {
            $recorded[] = $event->id;
        });

        $this->enqueue($pruned);
        $this->enqueue($delivered);

        $result = $this->drain();

        self::assertSame([1, 1], [$result->delivered(), $result->pruned()]);
        self::assertSame([$delivered->record->id], $recorded);
    }

    /**
     * A row whose claim was lost before its delete is stale, and not counted
     * pruned: another drain owns it.
     *
     * @return void
     */
    public function testAPrunedRowWhoseClaimWasLostIsStale(): void
    {
        $this->enqueue($this->prunedRecord());

        $outbox = $this->outboxConnection();

        DB::connection(StorageConnection::name())->listen(static function (QueryExecuted $query) use ($outbox): void {
            if (!str_contains($query->sql, IntegrityTables::membersTable())) {
                return;
            }

            $outbox->table(DeliveryTables::outboxTable())->update(['claimed_by' => 'another-owner']);
        });

        $result = $this->drain();

        self::assertSame([0, 0, 0, 0, 1, 0], self::drainTally($result));
        self::assertSame(1, $this->outboxCount());
    }

    /**
     * A row whose tombstones cannot be read is retried after its backoff, as
     * any row whose work stops, and is never delivered unchecked.
     *
     * @return void
     */
    public function testARowWhoseTombstonesCannotBeReadIsRetried(): void
    {
        $calls = 0;

        app()->instance(AuditStore::class, new CallbackStore(static function () use (&$calls): void {
            $calls++;
        }));

        $this->enqueue($this->finalisedRecord());

        app(ConfigRepository::class)->set('audit-log.integrity.members_table', 'audit_missing_members');

        try {
            $result = $this->drain();
        } finally {
            app(ConfigRepository::class)->set('audit-log.integrity.members_table', IntegrityTables::DEFAULT_MEMBERS);
        }

        self::assertSame([0, 0, 1, 0, 0, 0], self::drainTally($result));
        self::assertSame(0, $calls);
    }

    /**
     * A verified spill line of a pruned record is counted pruned, never stored
     * and left in the file; the line beside it is replayed.
     *
     * @return void
     */
    public function testASpillReplayCountsAPrunedLineAndStoresNothing(): void
    {
        $pruned = $this->prunedRecord();
        $kept   = $this->finalisedRecord();
        $path   = $this->spillFile($pruned, $kept);
        $before = (string) file_get_contents($path);
        $result = app(Replayer::class)->spill($path, false);

        self::assertSame([1, 0, 1, 0, 0], self::replayTally($result));
        self::assertSame(['line 1: pruned ' . $pruned->record->id, 'line 2: replayed ' . $kept->record->id], $result->events());
        self::assertFalse($result->hasSkippedOrFailed());
        self::assertSame(0, $this->entriesUnder($pruned->record->id));
        self::assertSame(1, $this->entriesUnder($kept->record->id));
        self::assertSame($before, file_get_contents($path));
    }

    /**
     * A spill replay checks tombstones and stores in one lifecycle transaction
     * after the prune lock, so a prune cannot run between them.
     *
     * @return void
     */
    public function testASpillReplayChecksAndStoresBehindTheLifecycleLock(): void
    {
        $record = $this->finalisedRecord();
        $path   = $this->spillFile($record);
        $log    = [];
        $prune  = null;

        DB::connection(StorageConnection::name())->listen(static function (QueryExecuted $query) use (&$log, &$prune): void {
            $sql   = strtolower($query->sql);
            $label = match (true) {
                str_starts_with($sql, 'update') && str_contains($sql, LifecycleTables::lockTable())    => 'lock',
                str_starts_with($sql, 'select') && str_contains($sql, IntegrityTables::membersTable()) => 'tombstones',
                str_starts_with($sql, 'insert') && str_contains($sql, EntrySettings::table())          => 'insert',
                default                                                                                => null,
            };

            if ($label === null) {
                return;
            }

            $log[] = [$label, DB::connection($query->connectionName)->transactionLevel() > 0];

            if ($label !== 'tombstones') {
                return;
            }

            try {
                app(Pruner::class)->run();
                $prune = 'ran';
            } catch (\LogicException) {
                $prune = 'refused';
            }
        });

        $result = app(Replayer::class)->spill($path, false);

        self::assertSame(['line 1: replayed ' . $record->record->id], $result->events());
        self::assertSame([['lock', true], ['tombstones', true], ['insert', true]], $log);
        self::assertSame('refused', $prune);
        self::assertSame(1, $this->entriesUnder($record->record->id));
    }

    /**
     * A dry run counts a pruned line as pruned, not as one it would replay, and
     * changes nothing.
     *
     * @return void
     */
    public function testADryRunCountsAPrunedLine(): void
    {
        $pruned = $this->prunedRecord();
        $kept   = $this->finalisedRecord();
        $result = app(Replayer::class)->spill($this->spillFile($pruned, $kept), true);

        self::assertSame([0, 1, 1, 0, 0], self::replayTally($result));
        self::assertSame(['line 1: pruned ' . $pruned->record->id, 'line 2: would_replay ' . $kept->record->id], $result->events());
        self::assertSame(0, $this->entryCount());
    }

    /**
     * A spill line whose tombstones cannot be read is counted failed by its id
     * and the class of the failure, and stops no other line.
     *
     * @return void
     */
    public function testASpillLineWhoseTombstonesCannotBeReadFails(): void
    {
        $record = $this->finalisedRecord();
        $path   = $this->spillFile($record);

        app(ConfigRepository::class)->set('audit-log.integrity.members_table', 'audit_missing_members');

        try {
            $result = app(Replayer::class)->spill($path, false);
        } finally {
            app(ConfigRepository::class)->set('audit-log.integrity.members_table', IntegrityTables::DEFAULT_MEMBERS);
        }

        self::assertSame([0, 0, 0, 1, 0], self::replayTally($result));
        self::assertStringStartsWith('line 1: failed ' . $record->record->id . ' (', $result->events()[0]);
        self::assertSame(0, $this->entryCount());
    }

    /**
     * An outbox replay requeues a pruned record's failed row, and the drain
     * counts it pruned and deletes it, never storing it.
     *
     * @return void
     */
    public function testAnOutboxReplayOfAPrunedRowCompletesItAsPruned(): void
    {
        $this->enqueue($this->prunedRecord(), ['failed_at' => self::NOW, 'attempts' => 10]);

        $result = app(Replayer::class)->outbox(false);

        self::assertSame([0, 0, 1, 0, 0], self::replayTally($result));
        self::assertFalse($result->hasSkippedOrFailed());
        self::assertSame(0, $this->outboxCount());
        self::assertSame(0, $this->entryCount());
    }

    /**
     * A record captured now is minted now, so the sync path never reads the
     * tombstones: no statement of a fresh write names the members table.
     *
     * @return void
     */
    public function testAFreshCaptureIsNeverChecked(): void
    {
        $this->prunedRecord();

        $statements = [];

        DB::connection(StorageConnection::name())->listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = $query->sql;
        });

        app(Recorder::class)->event('invoice.approved')->immediately()->record();

        self::assertNotSame([], $statements);
        self::assertSame([], array_values(array_filter($statements, static fn (string $sql): bool => str_contains($sql, IntegrityTables::membersTable()))));
    }

    /**
     * A pruned record stored again directly violates no index, so verification
     * reports its seal `resurrected`.
     *
     * @return void
     */
    public function testADirectStoreOfAPrunedRecordIsReportedResurrected(): void
    {
        $record = $this->prunedRecord();
        $seal   = $this->seals()[0];
        $ledger = new InMemoryPruneLedger;

        $ledger->add(app(SealSigner::class)->signPrune(
            (string) $seal['log_id'],
            (string) $seal['id'],
            (string) $seal['seal_digest'],
            1,
            PruneBitmap::encode([0], 1),
            1,
            self::OPERATION_ID,
            self::PRUNED_AT,
        ));

        app()->instance(PruneLedger::class, $ledger);
        app()->instance(CheckpointAnchor::class, new NullAnchor);

        self::assertSame(0, $this->verify());
        self::assertStringContainsString(sprintf('seal 1 %s integrity=pruned ', $seal['id']), $this->printed);

        $this->store()->store($record);

        self::assertSame(1, $this->entriesUnder($record->record->id));
        self::assertSame(1, $this->verify());
        self::assertStringContainsString(sprintf('seal 1 %s integrity=incomplete ', $seal['id']), $this->printed);
        self::assertStringContainsString(sprintf('finding=resurrected first=%s', $record->record->id), $this->printed);
    }

    /**
     * Finalise, store, seal and prune a record as retention would, binding a
     * signed record of the prune.
     *
     * @return \SineMacula\Laravel\AuditLog\Records\FinalisedRecord
     */
    private function prunedRecord(): FinalisedRecord
    {
        $record = $this->finalisedRecord();

        $this->store()->store($record);

        self::assertSame(1, $this->sealAll()->entries());

        $this->pruneByHand($record->record->id);

        return $record;
    }

    /**
     * Run `audit-log:verify` once the log is sealed and pruned, keep what it
     * printed, and return its exit code.
     *
     * @return int
     */
    private function verify(): int
    {
        $kernel = $this->app?->make(Kernel::class);

        assert($kernel instanceof ConsoleKernel);

        $kernel->registerCommand(new VerifyCommand);

        app()->instance(Clock::class, FrozenClock::at(self::VERIFIED_AT));

        $exit          = $kernel->call('audit-log:verify');
        $this->printed = $kernel->output();

        return $exit;
    }

    /**
     * Drain the outbox with the drainer the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\DrainResult
     */
    private function drain(): DrainResult
    {
        return app(OutboxDrainer::class)->drain(100, false);
    }

    /**
     * A spill file of the records' lines, in order, removed when the test ends.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\FinalisedRecord  ...$records
     * @return string
     */
    private function spillFile(#[\SensitiveParameter] FinalisedRecord ...$records): string
    {
        $path = tempnam(sys_get_temp_dir(), 'audit-log-spill');

        self::assertIsString($path);

        $this->files[] = $path;

        file_put_contents($path, implode('', array_map(static fn (FinalisedRecord $record): string => FailureSpill::line($record->toArray()) . "\n", $records)));

        return $path;
    }

    /**
     * The number of entries under the id.
     *
     * @param  string  $id
     * @return int
     */
    private function entriesUnder(string $id): int
    {
        return $this->storageConnection()->table(EntrySettings::table())->where('id', $id)->count();
    }

    /**
     * A drain's counts: delivered, pruned, retried, failed, stale and missed.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\DrainResult  $result
     * @return list<int>
     */
    private static function drainTally(DrainResult $result): array
    {
        return [$result->delivered(), $result->pruned(), $result->retried(), $result->failed(), $result->stale(), $result->missed()];
    }

    /**
     * A replay's counts: replayed, would replay, pruned, failed and deferred.
     *
     * @param  \SineMacula\Laravel\AuditLog\Delivery\ReplayResult  $result
     * @return list<int>
     */
    private static function replayTally(ReplayResult $result): array
    {
        return [$result->replayed(), $result->wouldReplay(), $result->pruned(), $result->failed(), $result->deferred()];
    }
}
