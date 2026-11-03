<?php

declare(strict_types = 1);

namespace Tests\Integration\Delivery;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Encryption\StringEncrypter;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Delivery\DrainResult;
use SineMacula\Laravel\AuditLog\Delivery\OutboxDrainer;
use SineMacula\Laravel\AuditLog\Delivery\OutboxWriter;
use SineMacula\Laravel\AuditLog\Delivery\RecordDelivery;
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\AuditLog\Integrity\CanonicalEncoder;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use Tests\Concerns\InteractsWithAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\RunsKilledChildren;
use Tests\Concerns\SeedsTheOutbox;
use Tests\TestCase;

/**
 * Integration tests for a process killed by `SIGKILL` around a host's commit,
 * on the engine the suite runs against and with no test wrapper transaction: in
 * outbox mode a record exists exactly when its transaction committed, so a kill
 * after the commit leaves a row a later drain delivers, unchanged, and a
 * rollback or a kill before the commit leaves none. A drain killed mid-way
 * leaves the row for a later one.
 *
 * In sync mode the gap the documentation states is real: an after-commit record
 * is written by a commit callback, so a process that dies between the commit
 * and that callback keeps the business change and loses the record. The outbox
 * closes the gap on its own connection, and an outbox on another connection
 * keeps it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OutboxDrainer::class)]
#[CoversClass(OutboxWriter::class)]
#[CoversClass(RecordDelivery::class)]
final class ProcessDeathTest extends TestCase
{
    use InteractsWithAuditStore, InteractsWithOutbox, RunsKilledChildren, SeedsTheOutbox;

    /** @var string When each test starts. */
    private const string NOW = '2026-11-01T12:00:00.000000Z';

    /** @var int How far past a kill the clock moves, past the default lease, in seconds. */
    private const int PAST_THE_LEASE_SECONDS = 301;

    /** @var string The code every test records. */
    private const string CODE = 'invoice.approved';

    /** @var string A table the host transaction writes to. */
    private const string HOST_TABLE = 'audit_killed_host_writes';

    /** @var string The file a child names each record it captured in. */
    private const string IDS = 'ids';

    /** @var string An outermost commit, with none of its callbacks run yet. */
    private const string COMMIT = '/^commit$/';

    /** @var string An outermost commit, with all of its callbacks run. */
    private const string AFTER_CALLBACKS = '/^after callbacks$/';

    /** @var string The insert of an outbox row. */
    private const string OUTBOX_INSERT = '/^insert into \S*audit_log_outbox/';

    /** @var string The insert of an entry. */
    private const string ENTRY_INSERT = '/^insert into \S*audit_log_entries/';

    /**
     * Stop the clock and create the table the host writes to.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->moveClockTo(self::NOW);

        Schema::dropIfExists(self::HOST_TABLE);

        Schema::create(self::HOST_TABLE, static function (Blueprint $table): void {
            $table->increments('id');
            $table->string('name', 32);
        });
    }

    /**
     * Put the clock and the outbox back, drop the host's table, and remove what
     * the children shared once the migrations have rolled back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->removeMovedOutbox();

        CarbonImmutable::setTestNow();

        Schema::dropIfExists(self::HOST_TABLE);

        parent::tearDown();

        $this->removeChildren();
    }

    /**
     * A process that commits a business change with an after-commit record and
     * is killed at once, before any commit callback has run, leaves the change
     * and one outbox row, and a later drain gives one entry and leaves no row.
     *
     * @return void
     */
    public function testAProcessKilledAfterCommitThenADrainGivesOneRow(): void
    {
        $this->outboxModeOn();

        $this->assertKilled($this->runChild(function (): void {
            DB::transaction(function (): void {
                $this->writeTheBusinessChange();
                $this->capture(AuditLog::event(self::CODE));
            });
        }, killAfter: self::COMMIT));

        $id = $this->capturedId();

        self::assertSame(1, $this->hostRows());
        self::assertNotNull($this->outboxRow($id));
        self::assertSame(1, $this->outboxCount());
        self::assertSame(0, $this->entryCount());

        self::assertSame(0, Artisan::call('audit-log:drain'));

        self::assertSame(0, $this->outboxCount());
        self::assertSame(1, $this->entryCount());
        self::assertSame($id, $this->storedRow($id)['id']);
    }

    /**
     * A transaction the process rolls back before it is killed leaves neither
     * the change nor a row, so a drain has nothing to deliver.
     *
     * @return void
     */
    public function testARolledBackTransactionGivesNoRow(): void
    {
        $this->outboxModeOn();

        $this->assertKilled($this->runChild(function (): void {
            DB::beginTransaction();

            $this->writeTheBusinessChange();
            $this->capture(AuditLog::event(self::CODE));

            DB::rollBack();
        }));

        self::assertCount(1, $this->childFileLines(self::IDS));
        self::assertSame(0, $this->hostRows());
        self::assertSame(0, $this->outboxCount());

        self::assertSame(0, $this->drain()->delivered());
        self::assertSame(0, $this->entryCount());
    }

    /**
     * A process killed once its row is inserted, before its commit, leaves
     * neither the change nor the row: the engine rolls the open transaction
     * back when the process is gone.
     *
     * @return void
     */
    public function testAProcessKilledBeforeCommitGivesNoRow(): void
    {
        $this->outboxModeOn();

        $this->assertKilled($this->runChild(function (): void {
            DB::transaction(function (): void {
                $this->writeTheBusinessChange();
                $this->capture(AuditLog::event(self::CODE));

                self::fail('The process was to be killed at the insert.');
            });
        }, killAfter: self::OUTBOX_INSERT));

        self::assertCount(0, $this->childFileLines(self::IDS));
        self::assertSame(0, $this->hostRows());
        self::assertSame(0, $this->outboxCount());

        self::assertSame(0, $this->drain()->delivered());
        self::assertSame(0, $this->entryCount());
    }

    /**
     * With an inner transaction rolled back and the outer committed, only the
     * outer's record outlives the kill: the inner's row went with its
     * savepoint.
     *
     * @return void
     */
    public function testAnInnerRollbackThenAKillAfterCommitLeavesOnlyTheOuterRow(): void
    {
        $this->outboxModeOn();

        $this->assertKilled($this->runChild(function (): void {
            DB::beginTransaction();

            $this->capture(AuditLog::event(self::CODE));

            DB::beginTransaction();

            $this->capture(AuditLog::event(self::CODE));

            DB::rollBack();
            DB::commit();
        }, killAfter: self::COMMIT));

        [$outer, $inner] = $this->childFileLines(self::IDS);

        self::assertNotNull($this->outboxRow($outer));
        self::assertNull($this->outboxRow($inner));

        self::assertSame(1, $this->drain()->delivered());
        self::assertSame(1, $this->entryCount());
        self::assertSame($outer, $this->storedRow($outer)['id']);
    }

    /**
     * An immediate record with no transaction open commits by itself, so a kill
     * straight after its insert leaves its row for a drain.
     *
     * @return void
     */
    public function testAnImmediateOutboxRowSurvivesAKillAfterItsCommit(): void
    {
        $this->outboxModeOn();

        $this->assertKilled($this->runChild(function (): void {
            $this->capture(AuditLog::event(self::CODE)->immediately());
        }, killAfter: self::OUTBOX_INSERT));

        self::assertSame(1, $this->outboxCount());
        self::assertSame(0, $this->entryCount());

        self::assertSame(1, $this->drain()->delivered());
        self::assertSame(1, $this->entryCount());
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * An immediate record inside a host has not committed when its insert
     * returns, so a kill before the host's commit takes the row with the host.
     *
     * @return void
     */
    public function testAnImmediateRowGoesWithAHostKilledBeforeItsCommit(): void
    {
        $this->outboxModeOn();

        $this->assertKilled($this->runChild(function (): void {
            DB::beginTransaction();

            $this->writeTheBusinessChange();
            $this->capture(AuditLog::event(self::CODE)->immediately());

            self::fail('The process was to be killed at the insert.');
        }, killAfter: self::OUTBOX_INSERT));

        self::assertSame(0, $this->hostRows());
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * With the callbacks run and only then a kill, a sync record is written
     * too: what separates it from the gap above is only where the kill falls.
     *
     * @return void
     */
    public function testASyncRecordIsWrittenWhenTheProcessDiesAfterItsCallbacks(): void
    {
        $this->assertKilled($this->runChild(fn () => $this->commitTheBusinessChangeWithARecord(), killAfter: self::AFTER_CALLBACKS));

        self::assertSame(1, $this->hostRows());
        self::assertSame(1, $this->entryCount());
    }

    /**
     * A transactional record in outbox mode has committed with its host, so a
     * kill straight after the commit, before any callback, leaves the change
     * and the row.
     *
     * @return void
     */
    public function testATransactionalRowSurvivesAKillAfterCommit(): void
    {
        $this->outboxModeOn();

        $this->assertKilled($this->runChild(function (): void {
            DB::transaction(function (): void {
                $this->writeTheBusinessChange();
                $this->capture(AuditLog::event(self::CODE)->transactional());
            });
        }, killAfter: self::COMMIT));

        self::assertSame(1, $this->hostRows());
        self::assertSame(1, $this->outboxCount());
        self::assertSame(0, $this->entryCount());

        self::assertSame(1, $this->drain()->delivered());
        self::assertSame(1, $this->entryCount());
    }

    /**
     * A transactional record in sync mode is an entry inside the host's own
     * transaction, so it needs no callback and no drain to outlive a kill
     * before any callback has run.
     *
     * @return void
     */
    public function testASyncTransactionalEntrySurvivesAKillAfterCommit(): void
    {
        $this->assertKilled($this->runChild(function (): void {
            DB::transaction(function (): void {
                $this->writeTheBusinessChange();
                $this->capture(AuditLog::event(self::CODE)->transactional());
            });
        }, killAfter: self::COMMIT));

        self::assertSame(1, $this->hostRows());
        self::assertSame(0, $this->outboxCount());
        self::assertSame(1, $this->entryCount());
    }

    /**
     * The row a killed process left is delivered as it was finalised there:
     * every column of the entry a later process stores encodes to the bytes of
     * the envelope, with the time and signature the killed process gave it,
     * however hostile its values.
     *
     * @return void
     */
    public function testTheRowDrainsToTheSameBytes(): void
    {
        $this->outboxModeOn();

        $this->assertKilled($this->runChild(function (): void {
            DB::transaction(function (): void {
                $properties = [
                    'amount' => '1200.00',
                    'note'   => "%datetime% \u{1F600} line\r\nbreak",
                    'map'    => ['1' => 'a', '0' => 'b'],
                ];

                $this->capture(AuditLog::event(self::CODE)->withProperties($properties));
            });
        }, killAfter: self::COMMIT));

        $id  = $this->capturedId();
        $row = $this->outboxRow($id);

        self::assertNotNull($row);
        self::assertIsString($row['payload']);

        $envelope = app(StringEncrypter::class)->decryptString($row['payload']);

        self::assertStringContainsString('%datetime%', $envelope);

        // The clock moves on, so a record finalised again would not match
        $this->pastTheLease();

        self::assertSame(1, $this->drain()->delivered());

        $stored = $this->storedRow($id);

        self::assertSame($envelope, CanonicalEncoder::encode($stored));
        self::assertSame(['amount', 'map', 'note'], self::sortedKeysOf($stored['properties']));
        self::assertTrue(app(RecordSigner::class)->verifies($stored));
    }

    /**
     * A drain killed while it delivers a row leaves that row claimed and counts
     * its attempt: another drain leaves it alone until the lease has passed,
     * then delivers it once.
     *
     * @return void
     */
    public function testAKilledDrainLeavesTheRowForALaterOne(): void
    {
        $this->outboxModeOn();

        $this->assertKilled($this->runChild(function (): void {
            DB::transaction(function (): void {
                $this->capture(AuditLog::event(self::CODE));
            });
        }, killAfter: self::COMMIT));

        $id = $this->capturedId();

        $this->assertKilled($this->runChild(function (): void {
            $this->drain();

            self::fail('The drain was to be killed at the insert.');
        }, killBefore: self::ENTRY_INSERT));

        $row = $this->outboxRow($id);

        self::assertSame(1, $row['attempts'] ?? null);
        self::assertNotNull($row['claimed_by'] ?? null);
        self::assertSame(0, $this->entryCount());

        self::assertSame(0, $this->drain()->delivered());
        self::assertSame(1, $this->outboxCount());

        $this->pastTheLease();

        self::assertSame(1, $this->drain()->delivered());
        self::assertSame(0, $this->outboxCount());
        self::assertSame(1, $this->entryCount());
    }

    /**
     * A kill between the commit and its callbacks falls before the write: in
     * sync mode the business change stands and the record is lost, which is the
     * gap the documentation states. In outbox mode the row committed with the
     * change, so the same kill loses nothing.
     *
     * @return void
     */
    public function testASyncRecordIsLostWhenTheProcessDiesBetweenCommitAndWrite(): void
    {
        $this->assertKilled($this->runChild(fn () => $this->commitTheBusinessChangeWithARecord(), killAfter: self::COMMIT));

        self::assertSame(1, $this->hostRows());
        self::assertCount(1, $this->childFileLines(self::IDS));
        self::assertSame(0, $this->entryCount());
        self::assertSame(0, $this->outboxCount());

        $this->outboxModeOn();

        $this->assertKilled($this->runChild(fn () => $this->commitTheBusinessChangeWithARecord(), killAfter: self::COMMIT));

        $id = $this->childFileLines(self::IDS)[1];

        self::assertSame(2, $this->hostRows());
        self::assertNotNull($this->outboxRow($id));

        self::assertSame(1, $this->drain()->delivered());
        self::assertSame($id, $this->storedRow($id)['id']);
    }

    /**
     * The gap remains for an outbox on another connection, whose row a record
     * can only write once the host has committed: the same kill loses it.
     *
     * @return void
     */
    public function testAnOutboxOnAnotherConnectionKeepsTheGap(): void
    {
        $this->outboxModeOn();
        $this->moveOutboxToItsOwnConnection();

        $this->assertKilled($this->runChild(fn () => $this->commitTheBusinessChangeWithARecord(), killAfter: self::COMMIT));

        self::assertSame(1, $this->hostRows());
        self::assertCount(1, $this->childFileLines(self::IDS));
        self::assertSame(0, $this->outboxCount());
    }

    /**
     * Put the default connection on a file on SQLite, so a child and its parent
     * share it.
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
     * In a child: commit a business change with an after-commit record, killed
     * at the kill point set on the child, between the commit and its callbacks.
     *
     * @return void
     */
    private function commitTheBusinessChangeWithARecord(): void
    {
        DB::transaction(function (): void {
            $this->writeTheBusinessChange();
            $this->capture(AuditLog::event(self::CODE));
        });

        self::fail('The process was to be killed between its commit and its callbacks.');
    }

    /**
     * In a child: record the builder and name the record in the shared file, so
     * the parent knows its id whatever then kills the child.
     *
     * @param  \SineMacula\Laravel\AuditLog\Records\PendingRecord  $builder
     * @return void
     */
    private function capture(PendingRecord $builder): void
    {
        $this->appendToChildFile(self::IDS, $builder->record()->id);
    }

    /**
     * Write the host's business change.
     *
     * @return void
     */
    private function writeTheBusinessChange(): void
    {
        DB::table(self::HOST_TABLE)->insert(['name' => 'work']);
    }

    /**
     * The number of business changes that committed.
     *
     * @return int
     */
    private function hostRows(): int
    {
        return DB::table(self::HOST_TABLE)->count();
    }

    /**
     * The id of the one record a child captured.
     *
     * @return string
     */
    private function capturedId(): string
    {
        $ids = $this->childFileLines(self::IDS);

        self::assertCount(1, $ids);

        return $ids[0];
    }

    /**
     * Drain the outbox with the drainer the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Delivery\DrainResult
     *
     * @throws \LogicException
     */
    private function drain(): DrainResult
    {
        return app(OutboxDrainer::class)->drain(100, false);
    }

    /**
     * Move the clock past any lease taken so far.
     *
     * @return void
     */
    private function pastTheLease(): void
    {
        CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(self::PAST_THE_LEASE_SECONDS));
    }

    /**
     * The keys of a decoded JSON column, in order.
     *
     * @phpcsSuppress SlevomatCodingStandard.TypeHints.DisallowMixedTypeHint
     *
     * @param  mixed  $column
     * @return list<array-key>
     */
    private static function sortedKeysOf(mixed $column): array
    {
        $keys = array_keys((array) $column);

        sort($keys);

        return $keys;
    }
}
