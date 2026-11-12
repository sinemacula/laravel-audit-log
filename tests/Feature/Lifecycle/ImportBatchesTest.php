<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportRejection;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\ImportStatus;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportBatches;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportPlan;
use SineMacula\Laravel\AuditLog\Lifecycle\ImportTally;
use Tests\Concerns\InteractsWithReadWriteSplit;
use Tests\TestCase;

/**
 * Feature tests for the import batches table.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ImportBatches::class)]
final class ImportBatchesTest extends TestCase
{
    use InteractsWithReadWriteSplit;

    /** @var string The batch every test starts. */
    private const string BATCH = '01932b4e-a000-7000-8000-0000000000b1';

    /** @var string When the batch starts. */
    private const string STARTED = '2026-11-02 09:00:00.123456';

    /** @var string The batches migration, run on both sides of a split. */
    private const string MIGRATION = __DIR__ . '/../../../database/migrations/2026_11_02_001000_create_audit_log_import_batches_table.php';

    /**
     * Freeze the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::STARTED, 'UTC'));
    }

    /**
     * Roll back any open transaction, restore the clock and remove any split.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $connection = DB::connection(StorageConnection::name());

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        CarbonImmutable::setTestNow();

        parent::tearDown();

        $this->removeReadWriteSplit();
    }

    /**
     * A started batch is inserted `running` with its counts at nothing.
     *
     * @return void
     */
    public function testStartInsertsARunningBatch(): void
    {
        $this->batches()->start(self::given());

        $row = $this->batches()->find(self::BATCH);

        self::assertNotNull($row);
        self::assertSame('running', $row['status']);
        self::assertSame(['crm-eu', 'eu-west-2', 'audit-log-import/v1', 'App\Models\User', '7', 'case.review', 'app:ticket-123', str_repeat('f', 64), null], [
            $row['source_id'], $row['source_region'], $row['input_format'], $row['importer_type'], $row['importer_id'],
            $row['reason'], $row['external_reference'], $row['file_sha256'], $row['hold_id'],
        ]);
        self::assertFalse((bool) $row['externally_verified']);
        self::assertSame([0, 0, 0, 0, 0], array_map(intval(...), [$row['lines_read'], $row['imported'], $row['duplicates'], $row['conflicts'], $row['rejected']]));
        self::assertNull($row['conflict_ids']);
        self::assertSame(self::STARTED, self::time($row['started_at']));
        self::assertSame(self::STARTED, self::time($row['updated_at']));
        self::assertNull($row['finished_at']);
    }

    /**
     * A batch is started with exactly the columns its import gives.
     *
     * @return void
     */
    public function testStartTakesExactlyTheGivenColumns(): void
    {
        $missing = self::given();

        unset($missing['hold_id']);

        foreach ([$missing, [...self::given(), 'status' => 'complete']] as $batch) {
            try {
                $this->batches()->start($batch);
                self::fail('Expected the batch to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertStringStartsWith('A new import batch is given exactly the columns `id`, `source_id`', $exception->getMessage());
            }
        }

        self::assertNull($this->batches()->find(self::BATCH));
    }

    /**
     * A chunk writes the batch's counts inside its own transaction, and outside
     * one is refused.
     *
     * @return void
     */
    public function testProgressUpdatesCountsInTheChunksTransaction(): void
    {
        $this->batches()->start(self::given());

        $tally = self::tally();

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-02 09:00:05.000000', 'UTC'));

        $connection = DB::connection(StorageConnection::name());

        $connection->beginTransaction();
        $this->batches()->claim($connection, self::BATCH);
        $this->batches()->progress($connection, self::BATCH, $tally);
        $connection->rollBack();

        self::assertSame('0', (string) ($this->batches()->find(self::BATCH)['lines_read'] ?? null));

        $connection->transaction(fn (Connection $connection) => $this->batches()->progress($connection, self::BATCH, $tally));

        $row = $this->batches()->find(self::BATCH);

        self::assertNotNull($row);
        self::assertSame([3, 0, 0, 1, 1], array_map(intval(...), [$row['lines_read'], $row['imported'], $row['duplicates'], $row['conflicts'], $row['rejected']]));
        self::assertSame('["rec-2"]', $row['conflict_ids']);
        self::assertSame('2026-11-02 09:00:05.000000', self::time($row['updated_at']));
        self::assertSame('running', $row['status']);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('An import batch is written by a chunk only inside the chunk\'s own transaction.');

        $this->batches()->progress($connection, self::BATCH, $tally);
    }

    /**
     * A chunk's claim writes only the time, inside its transaction.
     *
     * @return void
     */
    public function testClaimWritesOnlyTheTime(): void
    {
        $this->batches()->start(self::given());

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-02 09:00:07.000000', 'UTC'));

        $connection = DB::connection(StorageConnection::name());

        $connection->transaction(fn (Connection $connection) => $this->batches()->claim($connection, self::BATCH));

        $row = $this->batches()->find(self::BATCH);

        self::assertNotNull($row);
        self::assertSame('2026-11-02 09:00:07.000000', self::time($row['updated_at']));
        self::assertSame('0', (string) $row['lines_read']);

        $this->expectException(\LogicException::class);

        $this->batches()->claim($connection, self::BATCH);
    }

    /**
     * A finished batch takes its final status, counts and time, and is never
     * written again.
     *
     * @return void
     */
    public function testFinishSetsStatusCountsAndTime(): void
    {
        $this->batches()->start(self::given());

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-02 09:10:00.000001', 'UTC'));

        $this->batches()->finish(self::BATCH, ImportStatus::PARTIAL, self::tally());

        $row = $this->batches()->find(self::BATCH);

        self::assertNotNull($row);
        self::assertSame('partial', $row['status']);
        self::assertSame([3, 1, 1], array_map(intval(...), [$row['lines_read'], $row['conflicts'], $row['rejected']]));
        self::assertSame('2026-11-02 09:10:00.000001', self::time($row['finished_at']));
        self::assertSame('2026-11-02 09:10:00.000001', self::time($row['updated_at']));
        self::assertSame(self::STARTED, self::time($row['started_at']));

        try {
            $this->batches()->finish(self::BATCH, ImportStatus::COMPLETE, new ImportTally);
            self::fail('Expected a finished batch to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame('The import batch is no longer running, and is not written to.', $exception->getMessage());
        }

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An import batch finishes in a final status.');

        $this->batches()->finish(self::BATCH, ImportStatus::RUNNING, new ImportTally);
    }

    /**
     * Only a running batch is closed, `interrupted`.
     *
     * @return void
     */
    public function testCloseOnlyClosesARunningBatch(): void
    {
        $this->batches()->start(self::given());

        DB::connection(StorageConnection::name())->transaction(fn (Connection $connection) => $this->batches()->progress($connection, self::BATCH, self::tally()));

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-02 11:00:00.000000', 'UTC'));

        $this->batches()->close(self::BATCH);

        $row = $this->batches()->find(self::BATCH);

        self::assertNotNull($row);
        self::assertSame('interrupted', $row['status']);
        self::assertSame('3', (string) $row['lines_read']);
        self::assertSame('2026-11-02 11:00:00.000000', self::time($row['finished_at']));

        foreach ([self::BATCH, '01932b4e-a000-7000-8000-00000000ffff'] as $batch) {
            try {
                $this->batches()->close($batch);
                self::fail('Expected the close to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('Only a running import batch is closed.', $exception->getMessage());
            }
        }

        $connection = DB::connection(StorageConnection::name());

        $this->expectException(\LogicException::class);

        $connection->transaction(fn (Connection $connection) => $this->batches()->progress($connection, self::BATCH, self::tally()));
    }

    /**
     * Only running batches not written for more than an hour are stale.
     *
     * @return void
     */
    public function testStaleListsOnlyOldRunningBatches(): void
    {
        $older    = '01932b4e-a000-7000-8000-0000000000c1';
        $old      = '01932b4e-a000-7000-8000-0000000000c2';
        $finished = '01932b4e-a000-7000-8000-0000000000c3';

        $this->startAt($old, '2026-11-02 07:00:00.000000');
        $this->startAt($older, '2026-11-02 06:00:00.000000');
        $this->startAt($finished, '2026-11-02 05:00:00.000000');
        $this->batches()->finish($finished, ImportStatus::COMPLETE, new ImportTally);
        $this->startAt(self::BATCH, '2026-11-02 08:00:00.000000');

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-02 09:00:00.000000', 'UTC'));

        self::assertSame([$older, $old], array_column($this->batches()->stale(), 'id'));

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-02 09:00:00.000001', 'UTC'));

        self::assertSame([$older, $old, self::BATCH], array_column($this->batches()->stale(), 'id'));
    }

    /**
     * Every write and read is on the storage connection's writer.
     *
     * @return void
     */
    public function testItWritesTheStorageConnectionsWriter(): void
    {
        $this->useReadWriteSplit();
        $this->migrateBatchesOnTheSplit();

        $this->batches()->start(self::given());

        self::assertSame(1, DB::connection(self::PRIMARY_CONNECTION)->table(LifecycleTables::importBatchesTable())->count());
        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table(LifecycleTables::importBatchesTable())->count());
        self::assertSame('running', $this->batches()->find(self::BATCH)['status'] ?? null);

        CarbonImmutable::setTestNow(new CarbonImmutable('2026-11-02 11:00:00.000000', 'UTC'));

        self::assertSame([self::BATCH], array_column($this->batches()->stale(), 'id'));

        $this->batches()->finish(self::BATCH, ImportStatus::COMPLETE, self::tally());

        self::assertSame('complete', DB::connection(self::PRIMARY_CONNECTION)->table(LifecycleTables::importBatchesTable())->value('status'));
    }

    /**
     * Start the batch of the id given at the time given.
     *
     * @param  string  $id
     * @param  string  $at
     * @return void
     */
    private function startAt(string $id, string $at): void
    {
        CarbonImmutable::setTestNow(new CarbonImmutable($at, 'UTC'));

        $this->batches()->start([...self::given(), 'id' => $id]);
    }

    /**
     * Migrate the batches table on both sides of the split.
     *
     * @return void
     */
    private function migrateBatchesOnTheSplit(): void
    {
        $config    = app(ConfigRepository::class);
        $migration = require self::MIGRATION;

        assert($migration instanceof Migration && method_exists($migration, 'up'));

        foreach ([self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION] as $connection) {
            $config->set('audit-log.storage.connection', $connection);
            $migration->up();
        }

        $config->set('audit-log.storage.connection', self::SPLIT_CONNECTION);
    }

    /**
     * A tally of three lines read: one conflicting and one rejected.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportTally
     */
    private static function tally(): ImportTally
    {
        $tally = new ImportTally;

        $tally->countRead();
        $tally->countRead();
        $tally->countRead();
        $tally->countRejected(ImportRejection::MALFORMED_JSON);
        $tally->countPlan(new ImportPlan([], [], 0, [2 => 'rec-2']));

        return $tally;
    }

    /**
     * The columns an import gives its batch.
     *
     * @return array<string, bool|string|null>
     */
    private static function given(): array
    {
        return [
            'id'                  => self::BATCH,
            'source_id'           => 'crm-eu',
            'source_region'       => 'eu-west-2',
            'input_format'        => 'audit-log-import/v1',
            'importer_type'       => 'App\Models\User',
            'importer_id'         => '7',
            'reason'              => 'case.review',
            'external_reference'  => 'app:ticket-123',
            'file_sha256'         => str_repeat('f', 64),
            'externally_verified' => false,
            'hold_id'             => null,
        ];
    }

    /**
     * A stored time as `Y-m-d H:i:s.u`, whatever fractional digits the engine
     * returns.
     *
     * @param  bool|float|int|string|null  $stored
     * @return ?string
     */
    private static function time(bool|float|int|string|null $stored): ?string
    {
        return is_string($stored) ? (new CarbonImmutable($stored, 'UTC'))->format('Y-m-d H:i:s.u') : null;
    }

    /**
     * The batches the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\ImportBatches
     */
    private function batches(): ImportBatches
    {
        return app(ImportBatches::class);
    }
}
