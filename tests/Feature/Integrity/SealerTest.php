<?php

declare(strict_types = 1);

namespace Tests\Feature\Integrity;

use Carbon\CarbonInterval;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\Events\TransactionRolledBack;
use Illuminate\Database\QueryException;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Sleep;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\InstallationIdentity;
use SineMacula\Laravel\AuditLog\Database\IntegrityProgress;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\Finding;
use SineMacula\Laravel\AuditLog\Integrity\SealChainException;
use SineMacula\Laravel\AuditLog\Integrity\SealContentionException;
use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;
use SineMacula\Laravel\AuditLog\Integrity\Sealer;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\Concerns\SealsEntries;
use Tests\TestCase;

/**
 * Feature tests for the sealer, on whichever engine the suite runs against: the
 * recent pass starts the lookback before the last seal, or at the beginning;
 * the sweep resumes from its cursor, saved after every window, and clears it
 * once complete; batches follow each other without restarting, up to the most
 * seals a run writes; nothing recorded after the settle bound is sealed; an
 * attempt lost to a concurrent writer is rolled back whole and made again from
 * a fresh head after a bounded jittered wait, and exhaustion is contention; a
 * lost connection and any other failure are never retried; no savepoint is ever
 * used; progress records each seal and the run; each run ensures the
 * installation's id, written once; and keys mixed in a seal or rotated between
 * seals each sign as they should.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Sealer::class)]
final class SealerTest extends TestCase
{
    use SealsEntries;

    /** @var string When each sealer runs, unless a test freezes it elsewhere. */
    private const string SEALED_AT = '2026-11-01 13:00:00';

    /** @var string The connection a competing sealer writes through. */
    private const string COMPETITOR = 'competitor';

    /** @var string How MySQL reports a deadlock. */
    private const string DEADLOCK = 'SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock; try restarting transaction';

    /** @var string How MySQL reports a lock wait timeout. */
    private const string LOCK_TIMEOUT = 'SQLSTATE[HY000]: General error: 1205 Lock wait timeout exceeded; try restarting transaction';

    /** @var string How PostgreSQL reports a statement cancelled by its lock timeout. */
    private const string PG_LOCK_TIMEOUT = 'SQLSTATE[55P03]: Lock not available: 7 ERROR:  canceling statement due to lock timeout';

    /** @var string How SQLite reports a busy snapshot or a locked database. */
    private const string BUSY = 'SQLSTATE[HY000]: General error: 5 database is locked';

    /** @var string A secret of the first key of an explicit ring. */
    private const string SECRET_2025 = 'audit-log seal test key 2025 0123456789';

    /** @var string A secret of the second key of an explicit ring. */
    private const string SECRET_2026 = 'audit-log seal test key 2026 0123456789';

    /**
     * Freeze the sealer's clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->sealAt(self::SEALED_AT);
    }

    /**
     * Roll back any transaction a test left open, stop faking sleep, and close
     * the competitor's connection.
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

        Sleep::fake(false);

        DB::purge(self::COMPETITOR);

        parent::tearDown();
    }

    /**
     * A sealer called inside a transaction on the storage connection refuses
     * before any statement, the recent pass and the sweep alike.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesToRunInsideATransaction(): void
    {
        $this->storeEntries(1);

        $connection = DB::connection(StorageConnection::name());
        $statements = $this->recordStatements();

        $connection->beginTransaction();

        foreach (['seal' => fn () => $this->sealer()->seal(), 'sweep' => fn () => $this->sealer()->sweep()] as $run => $sealing) {
            try {
                $sealing();

                self::fail("Expected the {$run} to be refused.");
            } catch (\LogicException $exception) {
                self::assertSame('Sealing refuses to run inside a transaction on the storage connection, so each seal commits on its own.', $exception->getMessage());
            }
        }

        self::assertSame([], $statements->getArrayCopy());
        self::assertSame(1, $connection->transactionLevel());
    }

    /**
     * A run leaves the installation's id the migrations seed as it is; on an
     * installation that lost it, a run, the recent pass and the sweep alike,
     * writes it on the first run, before its first batch, at the run's time,
     * and never replaces it: every later run reads the same id, and a run with
     * nothing to seal ensures it too.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testARunWritesTheInstallationIdOnce(): void
    {
        $seeded = $this->installationRows();

        $this->sealer()->seal();

        self::assertCount(1, $seeded);
        self::assertEquals($seeded, $this->installationRows());

        DB::connection(StorageConnection::name())->table(IntegrityTables::stateTable())->where('name', InstallationIdentity::NAME)->delete();

        self::assertSame([], $this->installationRows());

        $this->sealer()->seal();

        $rows = $this->installationRows();

        self::assertCount(1, $rows);

        $value = json_decode((string) $rows[0]->value, true, 512, JSON_THROW_ON_ERROR);
        $id    = is_array($value) ? $value['id'] ?? null : null;

        self::assertIsString($id);
        self::assertMatchesRegularExpression(SealEnvelope::UUID_PATTERN, $id);
        self::assertSame('2026-11-01 13:00:00', substr((string) $rows[0]->updated_at, 0, 19));

        $this->storeEntries(2);
        $this->sealer()->seal();
        $this->sealAt('2026-11-01 14:00:00');
        $this->sealer()->sweep();

        self::assertEquals($rows, $this->installationRows());
        self::assertSame($id, app(InstallationIdentity::class)->idThrough(StorageConnection::resolvedName()));
    }

    /**
     * The installation's id is ensured before the run's first batch: its read
     * is the first statement of a run that has nothing to seal.
     *
     * @return void
     */
    public function testTheInstallationIdIsEnsuredBeforeTheFirstBatch(): void
    {
        $this->sealer()->seal();

        /** @var \ArrayObject<int, array{0: string, 1: array<array-key, scalar|null>}> $statements */
        $statements = new \ArrayObject;

        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query, array $bindings) use ($statements): void {
            $statements->append([$query, $bindings]);
        });

        $this->sealer()->sweep();

        [$query, $bindings] = $statements->getArrayCopy()[0] ?? ['', []];

        self::assertStringContainsString(IntegrityTables::stateTable(), $query);
        self::assertSame([InstallationIdentity::NAME], $bindings);
    }

    /**
     * The recent pass starts the lookback before the last seal's latest entry:
     * an unsealed row recorded at that instant is sealed, one recorded a
     * microsecond before it waits, and a later one is sealed.
     *
     * @return void
     */
    public function testTheRecentPassStartsAtTheLookbackBeforeTheHead(): void
    {
        $this->configure(['lookback_seconds' => 600]);
        $this->storeEntryAt('2026-11-01 12:30:00');
        $this->sealer()->seal();

        $older = $this->storeEntryAt('2026-11-01 12:19:59.999999');
        $edge  = $this->storeEntryAt('2026-11-01 12:20:00');
        $later = $this->storeEntryAt('2026-11-01 12:40:00');

        $selects = $this->recordCandidateSelects();
        $result  = $this->sealer()->seal();

        self::assertSame(1, $result->seals());
        self::assertSame(self::sorted([$edge, $later]), $this->membersOf((string) $this->seals()[1]['id']));
        self::assertSame(0, $this->countMembers($older));
        self::assertCount(1, $selects);
        self::assertContains('2026-11-01 12:20:00.000000', $selects->getArrayCopy()[0]);
    }

    /**
     * The recent pass starts the lookback before its own high-water mark, the
     * latest entry time a recent pass sealed, so a sweep's seal of old rows at
     * the head never pulls its window back to them; the mark only moves
     * forward, and a mark that is lost falls back to the head.
     *
     * @return void
     */
    public function testTheRecentPassStartsAtItsOwnHighWaterMark(): void
    {
        $this->configure(['lookback_seconds' => 600]);
        $this->storeEntryAt('2026-11-01 12:30:00');
        $this->sealer()->seal();

        self::assertSame(['last_recorded_at' => '2026-11-01T12:30:00.000000Z'], app(IntegrityProgress::class)->get(IntegrityProgress::SEAL_RECENT));

        $this->storeEntryAt('2026-10-25 08:00:00');
        $this->sealAll();

        self::assertSame('2026-10-25 08:00:00', substr((string) $this->seals()[1]['last_recorded_at'], 0, 19));

        $late    = $this->storeEntryAt('2026-11-01 12:25:00');
        $selects = $this->recordCandidateSelects();

        self::assertSame(1, $this->sealer()->seal()->seals());
        self::assertContains('2026-11-01 12:20:00.000000', $selects->getArrayCopy()[0]);
        self::assertSame([$late], $this->membersOf((string) $this->seals()[2]['id']));
        self::assertSame(['last_recorded_at' => '2026-11-01T12:30:00.000000Z'], app(IntegrityProgress::class)->get(IntegrityProgress::SEAL_RECENT));

        app(IntegrityProgress::class)->forget(IntegrityProgress::SEAL_RECENT);

        $this->storeEntryAt('2026-11-01 12:26:00');
        $fallback = $this->recordCandidateSelects();
        $this->sealer()->seal();

        self::assertContains('2026-11-01 12:15:00.000000', $fallback->getArrayCopy()[0]);
    }

    /**
     * The high-water mark is written only when it moves: a seal whose latest
     * entry is at the mark, or before it, leaves the mark unwritten.
     *
     * @return void
     */
    public function testTheHighWaterMarkIsWrittenOnlyWhenItMoves(): void
    {
        $this->storeEntryAt('2026-11-01 12:30:00');
        $this->sealer()->seal();

        $written = new \ArrayObject;

        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query, array $bindings) use ($written): void {
            if (!(($bindings[0] ?? null) === IntegrityProgress::SEAL_RECENT) || !str_starts_with(strtolower($query), 'insert')) {
                return;
            }

            $written[] = json_decode((string) $bindings[2], true);
        });

        $this->storeEntryAt('2026-11-01 12:30:00');

        self::assertSame(1, $this->sealer()->seal()->seals());
        self::assertSame([], $written->getArrayCopy());

        $this->storeEntryAt('2026-11-01 12:30:00.000001');

        self::assertSame(1, $this->sealer()->seal()->seals());
        self::assertSame([['last_recorded_at' => '2026-11-01T12:30:00.000001Z']], $written->getArrayCopy());
        self::assertSame(['last_recorded_at' => '2026-11-01T12:30:00.000001Z'], app(IntegrityProgress::class)->get(IntegrityProgress::SEAL_RECENT));
    }

    /**
     * Without a high-water mark, the recent pass starts the lookback before the
     * last seal in the chain, never before a seal stored outside it: a phantom
     * alone leaves the pass at the beginning of the table.
     *
     * @return void
     */
    public function testWithoutAMarkTheRecentPassStartsAtTheChainsHead(): void
    {
        $this->configure(['lookback_seconds' => 600]);
        $this->storeEntryAt('2026-11-01 12:30:00');
        $this->sealer()->seal();

        app(IntegrityProgress::class)->forget(IntegrityProgress::SEAL_RECENT);

        $older   = $this->storeEntryAt('2026-11-01 12:19:59.999999');
        $selects = $this->recordCandidateSelects();

        $this->sealer()->seal();

        self::assertContains('2026-11-01 12:20:00.000000', $selects->getArrayCopy()[0]);
        self::assertSame(0, $this->countMembers($older));

        DB::connection(StorageConnection::name())->table(IntegrityTables::checkpointsTable())->update(['sequence' => 0, 'last_recorded_at' => '2099-01-01 00:00:00.000000']);
        app(IntegrityProgress::class)->forget(IntegrityProgress::SEAL_RECENT);

        self::assertSame(1, $this->sealer()->seal()->seals());
        self::assertSame(1, $this->countMembers($older));
    }

    /**
     * Without a seal, the recent pass starts at the beginning of the table,
     * however old its rows.
     *
     * @return void
     */
    public function testWithoutASealTheRecentPassStartsAtTheBeginning(): void
    {
        $ancient = $this->storeEntryAt('2020-01-01 00:00:00');
        $recent  = $this->storeEntryAt('2026-11-01 12:00:00');

        $result = $this->sealer()->seal();

        self::assertSame(1, $result->seals());
        self::assertSame(2, $result->entries());
        self::assertSame(self::sorted([$ancient, $recent]), $this->membersOf((string) $this->seals()[0]['id']));
    }

    /**
     * Batches follow each other without restarting: each reads on strictly
     * after the last row the one before read, and together they seal every row
     * once, in order.
     *
     * @return void
     */
    public function testBatchesFollowEachOtherWithoutRestarting(): void
    {
        $this->configure(['batch' => 100]);

        $ids     = $this->storeEntries(250);
        $selects = $this->recordCandidateSelects();
        $result  = $this->sealer()->seal();
        $seals   = $this->seals();

        self::assertSame(3, $result->seals());
        self::assertSame(250, $result->entries());
        self::assertSame(1, $result->firstSequence());
        self::assertSame(3, $result->lastSequence());
        self::assertSame(self::sorted(array_slice($ids, 0, 100)), $this->membersOf((string) $seals[0]['id']));
        self::assertSame(self::sorted(array_slice($ids, 100, 100)), $this->membersOf((string) $seals[1]['id']));
        self::assertSame(self::sorted(array_slice($ids, 200)), $this->membersOf((string) $seals[2]['id']));
        self::assertCount(3, $selects);
        self::assertNotContains($ids[99], $selects->getArrayCopy()[0]);
        self::assertContains($ids[99], $selects->getArrayCopy()[1]);
        self::assertContains($ids[199], $selects->getArrayCopy()[2]);
        self::assertLessThan(0, strcmp(self::positionIn($selects->getArrayCopy()[1]), self::positionIn($selects->getArrayCopy()[2])));
    }

    /**
     * A run writes at most `integrity.seal.max_batches` seals, and the rows
     * past them wait for the next run.
     *
     * @return void
     */
    public function testStopsAtMaxBatches(): void
    {
        $this->configure(['batch' => 100, 'max_batches' => 2]);

        $ids    = $this->storeEntries(250);
        $result = $this->sealer()->seal();

        self::assertSame(2, $result->seals());
        self::assertSame(200, $result->entries());
        self::assertCount(2, $this->seals());
        self::assertSame(0, $this->countMembers($ids[200]));

        $next = $this->sealer()->seal();

        self::assertSame(1, $next->seals());
        self::assertSame(50, $next->entries());
    }

    /**
     * A sweep window that seals nothing still saves the cursor at its last row,
     * so the next window, and the next sweep, read on after it.
     *
     * @return void
     */
    public function testASweepWindowThatSealsNothingStillMovesTheCursor(): void
    {
        $this->configure(['batch' => 100, 'max_batches' => 1]);

        $ids = $this->storeEntries(250);

        $this->sealer()->seal();

        $cursors = $this->recordCursorWrites();
        $result  = $this->sealer()->sweep();

        self::assertSame(1, $result->seals());
        self::assertFalse($result->isSweepComplete());
        self::assertSame([$ids[99], $ids[199]], array_column($cursors->getArrayCopy(), 'id'));
        $cursor = ['recorded_at' => $this->storedTimeOf($ids[199]), 'id' => $ids[199], 'from_its_time' => false];

        self::assertSame($cursor, app(IntegrityProgress::class)->get(IntegrityProgress::SWEEP_CURSOR));
    }

    /**
     * A sweep over a sealed table reads it to its end in one run, however few
     * seals the run may write, since a window that seals nothing does not
     * count, and completes.
     *
     * @return void
     */
    public function testASweepOverASealedTableReachesItsEnd(): void
    {
        $this->configure(['batch' => 100]);
        $this->storeEntries(450);
        $this->sealAll();

        $this->configure(['batch' => 100, 'max_batches' => 1]);

        $selects = $this->recordCandidateSelects();
        $result  = $this->sealer()->sweep();

        self::assertSame(0, $result->seals());
        self::assertTrue($result->isSweepComplete());
        self::assertCount(5, $selects);
        self::assertNull(app(IntegrityProgress::class)->get(IntegrityProgress::SWEEP_CURSOR));
    }

    /**
     * An interrupted sweep resumes from its cursor, never from the beginning: a
     * row recorded before the cursor since waits for the next complete pass.
     *
     * @return void
     */
    public function testTheSweepResumesFromItsCursor(): void
    {
        $this->configure(['batch' => 100, 'max_batches' => 1]);

        $ids   = $this->storeEntries(250);
        $first = $this->sealer()->sweep();

        self::assertSame(1, $first->seals());
        $cursor = ['recorded_at' => $this->storedTimeOf($ids[99]), 'id' => $ids[99], 'from_its_time' => false];

        self::assertSame($cursor, app(IntegrityProgress::class)->get(IntegrityProgress::SWEEP_CURSOR));

        $behind = $this->storeEntryAt('2026-11-01 11:00:00');
        $second = $this->sealer()->sweep();

        self::assertSame(1, $second->seals());
        self::assertSame(self::sorted(array_slice($ids, 100, 100)), $this->membersOf((string) $this->seals()[1]['id']));
        self::assertSame(0, $this->countMembers($behind));
        $cursor = ['recorded_at' => $this->storedTimeOf($ids[199]), 'id' => $ids[199], 'from_its_time' => false];

        self::assertSame($cursor, app(IntegrityProgress::class)->get(IntegrityProgress::SWEEP_CURSOR));
    }

    /**
     * A complete sweep records its completion and clears its cursor, so the
     * next sweep starts at the beginning and finds a row recorded before where
     * the last one stopped.
     *
     * @return void
     */
    public function testACompleteSweepClearsItsCursor(): void
    {
        $this->configure(['batch' => 100, 'max_batches' => 1]);

        $this->storeEntries(150);

        $progress = app(IntegrityProgress::class);

        self::assertFalse($this->sealer()->sweep()->isSweepComplete());
        self::assertNotNull($progress->get(IntegrityProgress::SWEEP_CURSOR));
        self::assertTrue($this->sealer()->sweep()->isSweepComplete());
        self::assertNull($progress->get(IntegrityProgress::SWEEP_CURSOR));
        self::assertSame(['at' => '2026-11-01T13:00:00.000000Z'], $progress->get(IntegrityProgress::SWEEP_COMPLETED));

        $behind = $this->storeEntryAt('2026-11-01 11:00:00');

        $this->configure(['max_batches' => 100]);

        $result = $this->sealer()->sweep();

        self::assertSame(1, $result->seals());
        self::assertSame([$behind], $this->membersOf((string) $this->seals()[2]['id']));
        self::assertTrue($result->isSweepComplete());
    }

    /**
     * A row recorded longer than the lookback before the last seal is left by
     * the recent pass and found by the sweep.
     *
     * @return void
     */
    public function testTheSweepFindsARowOlderThanTheLookback(): void
    {
        $this->storeEntryAt('2026-11-01 12:30:00');
        $this->sealer()->seal();

        $old = $this->storeEntryAt('2026-11-01 10:00:00');

        self::assertSame(0, $this->sealer()->seal()->seals());
        self::assertSame(0, $this->countMembers($old));

        $result = $this->sealer()->sweep();

        self::assertSame(1, $result->seals());
        self::assertSame([$old], $this->membersOf((string) $this->seals()[1]['id']));
    }

    /**
     * With a settle delay, a seal never holds a row recorded after the run's
     * start less the delay; one recorded at that bound is held.
     *
     * @return void
     */
    public function testASealNeverHoldsARowRecordedAfterTheSettleBound(): void
    {
        $this->configure(['settle_seconds' => 60]);

        $settled  = $this->storeEntryAt('2026-11-01 12:59:00');
        $unsettle = $this->storeEntryAt('2026-11-01 12:59:00.000001');

        $result = $this->sealer()->seal();

        self::assertSame(1, $result->entries());
        self::assertSame([$settled], $this->membersOf((string) $this->seals()[0]['id']));
        self::assertSame(0, $this->countMembers($unsettle));
        self::assertSame('2026-11-01T12:59:00.000000Z', SealEnvelope::fromRow($this->seals()[0])->lastRecordedAt);
    }

    /**
     * The settle delay is optional and off by default: a row recorded at the
     * run's own instant is sealed by it.
     *
     * @return void
     */
    public function testTheSettleDelayIsOptional(): void
    {
        $now = $this->storeEntryAt(self::SEALED_AT);

        self::assertSame(0, app(SealSettings::class)->settleSeconds());
        self::assertSame(1, $this->sealer()->seal()->seals());
        self::assertSame([$now], $this->membersOf((string) $this->seals()[0]['id']));
    }

    /**
     * An attempt that loses to a competing sealer, which seals one of its
     * entries at the same sequence between its selection and its insert, fails
     * on the duplicate, is rolled back whole and is made again from a fresh
     * head and a fresh selection: it chains onto the competitor's seal and
     * seals the rest.
     *
     * @return void
     */
    public function testADuplicateIsRetriedFromAFreshHead(): void
    {
        $ids     = $this->storeEntries(3);
        $selects = $this->recordCandidateSelects();

        $this->competeBeforeTheFirstCheckpoint($ids[0]);

        $result = $this->sealer()->seal();
        $seals  = $this->seals();

        self::assertSame(1, $result->retries());
        self::assertSame(1, $result->seals());
        self::assertCount(2, $selects);
        self::assertCount(2, $seals);
        self::assertSame([$ids[0]], $this->membersOf((string) $seals[0]['id']));
        self::assertSame(self::sorted([$ids[1], $ids[2]]), $this->membersOf((string) $seals[1]['id']));
        self::assertSame($seals[0]['id'], $seals[1]['previous_id']);
        self::assertSame($seals[0]['seal_digest'], $seals[1]['previous_digest']);
        self::assertSame(2, $result->lastSequence());
    }

    /**
     * Rows of `[failure]`: each failure a concurrent writer causes, as its
     * driver raises it.
     *
     * @return iterable<string, array{0: \Closure(): \Illuminate\Database\QueryException}>
     */
    public static function provideConcurrencyFailures(): iterable
    {
        yield from [
            'a deadlock'                => [static fn (): QueryException => self::failure(self::DEADLOCK)],
            'a serialisation failure'   => [static fn (): QueryException => self::serialisationFailure()],
            'a lock timeout'            => [static fn (): QueryException => self::failure(self::LOCK_TIMEOUT)],
            'a PostgreSQL lock timeout' => [static fn (): QueryException => self::failure(self::PG_LOCK_TIMEOUT, '55P03')],
            'a busy snapshot'           => [static fn (): QueryException => self::failure(self::BUSY)],
            'a duplicate'               => [static fn (): QueryException => self::duplicate()],
        ];
    }

    /**
     * Each failure a concurrent writer causes rolls the attempt back to no
     * transaction at all and makes it again, selection included, and the run
     * then seals.
     *
     * @param  \Closure(): \Illuminate\Database\QueryException  $failure
     * @return void
     */
    #[DataProvider('provideConcurrencyFailures')]
    public function testAConcurrencyFailureIsRetried(\Closure $failure): void
    {
        Sleep::fake();

        $this->storeEntries(2);

        $levels = [];

        Event::listen(TransactionRolledBack::class, static function (TransactionRolledBack $event) use (&$levels): void {
            $levels[] = $event->connection->transactionLevel();
        });

        $selects = $this->recordCandidateSelects();

        $this->raiseOnCandidateSelects($failure(), 1);
        $result = $this->sealer()->seal();

        self::assertSame([0], $levels);
        self::assertCount(2, $selects);
        self::assertSame(1, $result->retries());
        self::assertSame(1, $result->seals());
        self::assertSame(2, $result->entries());
    }

    /**
     * A deadlock is retried after a full rollback.
     *
     * @return void
     */
    public function testADeadlockIsRetried(): void
    {
        $this->assertRetriedAfter(self::failure(self::DEADLOCK));
    }

    /**
     * A serialisation failure, known by its SQLSTATE alone, is retried after a
     * full rollback.
     *
     * @return void
     */
    public function testASerialisationFailureIsRetried(): void
    {
        $this->assertRetriedAfter(self::serialisationFailure());
    }

    /**
     * A lock wait timeout is retried after a full rollback.
     *
     * @return void
     */
    public function testALockTimeoutIsRetried(): void
    {
        $this->assertRetriedAfter(self::failure(self::LOCK_TIMEOUT));
    }

    /**
     * PostgreSQL's lock timeout, known by its SQLSTATE alone since Laravel
     * recognises neither its code nor its message, is retried after a full
     * rollback rather than stopping the run.
     *
     * @return void
     */
    public function testAPostgresLockTimeoutIsRetried(): void
    {
        $this->assertRetriedAfter(self::failure(self::PG_LOCK_TIMEOUT, '55P03'));
    }

    /**
     * SQLite's busy snapshot, a locked database, is retried after a full
     * rollback.
     *
     * @return void
     */
    public function testABusySnapshotIsRetried(): void
    {
        $this->assertRetriedAfter(self::failure(self::BUSY));
    }

    /**
     * Each retry waits a jittered delay no longer than the bound of the attempt
     * that failed: 20 milliseconds after the first, doubling after each, up to
     * a second.
     *
     * @return void
     */
    public function testEachRetryWaitsAJitteredBoundedDelay(): void
    {
        Sleep::fake();

        $this->configure(['max_attempts' => 9]);
        $this->storeEntries(1);

        $waits = [];

        Sleep::whenFakingSleep(static function (CarbonInterval $duration) use (&$waits): void {
            $waits[] = $duration->totalMilliseconds;
        });

        $this->raiseOnCandidateSelects(self::failure(self::BUSY), 8);

        $result = $this->sealer()->seal();

        self::assertSame(8, $result->retries());
        self::assertCount(8, $waits);

        foreach ([20, 40, 80, 160, 320, 640, 1000, 1000] as $attempt => $bound) {
            self::assertGreaterThanOrEqual(0, $waits[$attempt], "Retry {$attempt} waited less than nothing.");
            self::assertLessThanOrEqual($bound, $waits[$attempt], "Retry {$attempt} waited past its bound.");
        }

        self::assertSame(20, Sealer::JITTER_BASE_MS);
        self::assertSame(1000, Sealer::JITTER_MAX_MS);
    }

    /**
     * The waits are random within their bound, not fixed at it: over many
     * retries at the greatest bound, they differ.
     *
     * @return void
     */
    public function testTheWaitsAreJittered(): void
    {
        Sleep::fake();

        $this->configure(['max_attempts' => 41]);
        $this->storeEntries(1);

        $waits = [];

        Sleep::whenFakingSleep(static function (CarbonInterval $duration) use (&$waits): void {
            $waits[] = (int) $duration->totalMilliseconds;
        });

        $this->raiseOnCandidateSelects(self::failure(self::BUSY), 40);

        $this->sealer()->seal();

        self::assertCount(40, $waits);
        self::assertGreaterThan(1, count(array_unique(array_slice($waits, 10))));
        self::assertGreaterThan(Sealer::JITTER_BASE_MS, max(array_slice($waits, 10)), 'The bound did not grow past the first.');
    }

    /**
     * When every attempt is lost, the run stops with contention naming the
     * attempts, carrying nothing of the failures, after one selection per
     * attempt and a wait between each two.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testExhaustionThrowsContention(): void
    {
        Sleep::fake();

        $this->configure(['max_attempts' => 3]);
        $this->storeEntries(1);
        $selects = $this->recordCandidateSelects();

        $this->raiseOnCandidateSelects(self::failure(self::DEADLOCK));

        try {
            $this->sealer()->seal();

            self::fail('Expected the run to stop with contention.');
        } catch (SealContentionException $exception) {
            self::assertSame('Sealing gave up after 3 attempts lost to concurrent writers; the next run tries again.', $exception->getMessage());
            self::assertNull($exception->getPrevious());
        }

        self::assertCount(3, $selects);
        Sleep::assertSleptTimes(2);
        self::assertSame([], $this->seals());
        self::assertNull(app(IntegrityProgress::class)->get(IntegrityProgress::SEAL_LAST_RUN));
    }

    /**
     * A single attempt that is lost is contention at once, with no wait.
     *
     * @return void
     */
    public function testOneAttemptLostIsContentionAtOnce(): void
    {
        Sleep::fake();

        $this->configure(['max_attempts' => 1]);
        $this->storeEntries(1);
        $this->raiseOnCandidateSelects(self::duplicate());

        $this->expectException(SealContentionException::class);
        $this->expectExceptionMessage('Sealing gave up after 1 attempts lost to concurrent writers; the next run tries again.');

        try {
            $this->sealer()->seal();
        } finally {
            Sleep::assertNeverSlept();
        }
    }

    /**
     * A lost connection is never retried, because its commit may have happened:
     * it stops the run unchanged after one attempt.
     *
     * @return void
     */
    public function testALostConnectionIsNeverRetried(): void
    {
        Sleep::fake();

        $this->storeEntries(1);

        $failure = self::failure('SQLSTATE[HY000]: General error: 2006 MySQL server has gone away; database is locked');

        $selects = $this->recordCandidateSelects();

        $this->raiseOnCandidateSelects($failure);

        $this->assertStoppedBy($failure, $selects);
    }

    /**
     * Rows of `[failure]`: failures no concurrent writer causes, a data failure
     * whose message happens to hold a phrase of a concurrency error among them.
     *
     * @return iterable<string, array{0: \Closure(): \Throwable}>
     */
    public static function provideOtherFailures(): iterable
    {
        yield from [
            'a missing column'          => [static fn (): \Throwable => self::failure('SQLSTATE[42S22]: Column not found: 1054 Unknown column')],
            'a data failure'            => [static fn (): \Throwable => self::failure('SQLSTATE[22001]: String data, right truncated: database is locked', '22001')],
            'a failure outside the SQL' => [static fn (): \Throwable => new \RuntimeException('The disk is full.')],
        ];
    }

    /**
     * Any other failure stops the run unchanged after one attempt, with no wait
     * and nothing written.
     *
     * @param  \Closure(): \Throwable  $failure
     * @return void
     */
    #[DataProvider('provideOtherFailures')]
    public function testAnyOtherFailurePropagatesUnchanged(\Closure $failure): void
    {
        Sleep::fake();

        $this->storeEntries(1);

        $thrown = $failure();

        $selects = $this->recordCandidateSelects();

        $this->raiseOnCandidateSelects($thrown);

        $this->assertStoppedBy($thrown, $selects);
    }

    /**
     * A refusal to chain onto the last seal is never retried: it stops the run
     * unchanged after one attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChainRefusalIsNeverRetried(): void
    {
        Sleep::fake();

        $this->storeEntries(1);
        $this->sealer()->seal();

        DB::connection(StorageConnection::name())->table(IntegrityTables::checkpointsTable())->update(['sealed_at' => '2026-11-01 13:00:01']);

        $this->storeEntries(1, '2026-11-01 12:30:00');

        $selects = $this->recordCandidateSelects();

        try {
            $this->sealer()->seal();

            self::fail('Expected the run to stop at the head.');
        } catch (SealChainException $exception) {
            self::assertSame(Finding::SEAL_DIGEST, $exception->finding);
        }

        self::assertCount(0, $selects);
        Sleep::assertNeverSlept();
        self::assertCount(1, $this->seals());
    }

    /**
     * No savepoint is ever used: every statement of every attempt runs at the
     * outermost level, a retry included, and every transaction begins there.
     *
     * @return void
     */
    public function testNoSavepointIsEverUsed(): void
    {
        Sleep::fake();

        $this->storeEntries(2);

        $levels = [];
        $begins = [];

        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query, array $bindings, Connection $connection) use (&$levels): void {
            $levels[] = $connection->transactionLevel();
        });

        Event::listen(TransactionBeginning::class, static function (TransactionBeginning $event) use (&$begins): void {
            $begins[] = $event->connection->transactionLevel();
        });

        $this->raiseOnCandidateSelects(self::failure(self::BUSY), 1);

        $result = $this->sealer()->seal();

        self::assertSame(1, $result->retries());
        self::assertSame([1, 1], $begins);
        self::assertSame([], array_values(array_filter($levels, static fn (int $level): bool => $level > 1)));
        self::assertContains(1, $levels);
    }

    /**
     * Progress records each seal once it has committed, outside its
     * transaction, the last one written read back.
     *
     * @return void
     */
    public function testProgressIsWrittenAfterEachSeal(): void
    {
        $this->configure(['batch' => 100]);
        $this->storeEntries(150);

        $written = [];

        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query, array $bindings, Connection $connection) use (&$written): void {
            if (!(($bindings[0] ?? null) === IntegrityProgress::SEAL_LAST) || !str_starts_with(strtolower($query), 'insert')) {
                return;
            }

            $written[] = [$connection->transactionLevel(), json_decode((string) $bindings[2], true)];
        });

        $this->sealer()->seal();

        $seals = $this->seals();

        self::assertSame([
            [0, ['sequence' => 1, 'id' => $seals[0]['id'], 'sealed_at' => '2026-11-01T13:00:00.000000Z']],
            [0, ['sequence' => 2, 'id' => $seals[1]['id'], 'sealed_at' => '2026-11-01T13:00:00.000000Z']],
        ], $written);
        $progress = app(IntegrityProgress::class);

        self::assertSame(['sequence' => 2, 'id' => $seals[1]['id'], 'sealed_at' => '2026-11-01T13:00:00.000000Z'], $progress->get(IntegrityProgress::SEAL_LAST));
        self::assertSame(['at' => '2026-11-01T13:00:00.000000Z', 'seals' => 2, 'entries' => 150, 'sweep' => false], $progress->get(IntegrityProgress::SEAL_LAST_RUN));
    }

    /**
     * A run with nothing to seal is still recorded, so a monitor sees it ran;
     * no seal is.
     *
     * @return void
     */
    public function testTheLastRunIsRecordedEvenWithNothingToSeal(): void
    {
        $progress = app(IntegrityProgress::class);
        $result   = $this->sealer()->seal();

        self::assertSame(0, $result->seals());
        self::assertSame(['at' => '2026-11-01T13:00:00.000000Z', 'seals' => 0, 'entries' => 0, 'sweep' => false], $progress->get(IntegrityProgress::SEAL_LAST_RUN));
        self::assertNull($progress->get(IntegrityProgress::SEAL_LAST));

        $this->sealer()->sweep();

        self::assertSame(['at' => '2026-11-01T13:00:00.000000Z', 'seals' => 0, 'entries' => 0, 'sweep' => true], $progress->get(IntegrityProgress::SEAL_LAST_RUN));
    }

    /**
     * Entries that cannot be sealed are counted in the result, left unsealed,
     * and passed, so the rest seal.
     *
     * @return void
     */
    public function testACandidateThatCannotBeSealedIsCountedAndPassed(): void
    {
        $ids = $this->storeEntries(3);

        DB::connection(StorageConnection::name())->table(EntrySettings::table())->where('id', $ids[0])->update(['hmac' => str_repeat('z', 64)]);

        $result = $this->sealer()->seal();

        self::assertSame(1, $result->skippedEntries());
        self::assertSame(1, $result->seals());
        self::assertSame(2, $result->entries());
        self::assertSame(0, $this->countMembers($ids[0]));
        self::assertSame(1, $this->sealer()->sweep()->skippedEntries());
    }

    /**
     * One seal holds entries signed under different keys of the ring, and is
     * itself signed under the current key.
     *
     * @return void
     */
    public function testAMixedKeySegmentSeals(): void
    {
        $this->useRing(['k2025' => self::SECRET_2025, 'k2026' => self::SECRET_2026], 'k2026');

        $old = $this->storeEntries(2, '2026-11-01 12:00:00', 'k2025');
        $new = $this->storeEntries(2, '2026-11-01 12:10:00', 'k2026');

        $result = $this->sealer()->seal();
        $seal   = $this->seals()[0];

        self::assertSame(1, $result->seals());
        self::assertSame(self::sorted([...$old, ...$new]), $this->membersOf((string) $seal['id']));
        self::assertSame('k2026', $seal['key_id']);
        self::assertSame(['k2025', 'k2026'], DB::connection(StorageConnection::name())->table(EntrySettings::table())->distinct()->orderBy('key_id')->pluck('key_id')->all());
        self::assertTrue(app(SealSigner::class)->verifies(SealEnvelope::fromRow($seal), (string) $seal['signature']));
    }

    /**
     * A rotation between seals signs each seal under the key current when it
     * was made, and both verify while the ring holds both.
     *
     * @return void
     */
    public function testRotationBetweenSealsSignsEachWithItsKey(): void
    {
        $keys = ['k2025' => self::SECRET_2025, 'k2026' => self::SECRET_2026];

        $this->useRing($keys, 'k2025');
        $this->storeEntries(1);
        $this->sealer()->seal();

        $this->useRing($keys, 'k2026');
        $this->storeEntries(1, '2026-11-01 12:10:00');
        $this->sealer()->seal();

        $seals  = $this->seals();
        $signer = app(SealSigner::class);

        self::assertSame(['k2025', 'k2026'], array_column($seals, 'key_id'));
        self::assertTrue($signer->verifies(SealEnvelope::fromRow($seals[0]), (string) $seals[0]['signature']));
        self::assertTrue($signer->verifies(SealEnvelope::fromRow($seals[1]), (string) $seals[1]['signature']));
        self::assertSame($seals[0]['seal_digest'], $seals[1]['previous_digest']);
    }

    /**
     * Give the sealer a competitor: a second connection to the same database,
     * on an engine with more than one writer.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);
        $key    = 'database.connections.' . self::CONNECTION;

        $config->set('database.connections.' . self::COMPETITOR, $config->get($key));
    }

    /**
     * Assert the failure, raised once by the selection, is retried after a full
     * rollback, and the run then seals.
     *
     * @param  \Illuminate\Database\QueryException  $failure
     * @return void
     */
    private function assertRetriedAfter(QueryException $failure): void
    {
        Sleep::fake();

        $this->storeEntries(2);

        $levels = [];

        Event::listen(TransactionRolledBack::class, static function (TransactionRolledBack $event) use (&$levels): void {
            $levels[] = $event->connection->transactionLevel();
        });

        $selects = $this->recordCandidateSelects();

        $this->raiseOnCandidateSelects($failure, 1);
        $result = $this->sealer()->seal();

        self::assertSame([0], $levels, 'The attempt was not rolled back whole.');
        self::assertCount(2, $selects, 'The selection was not made again.');
        self::assertSame(1, $result->retries());
        self::assertSame(1, $result->seals());
        Sleep::assertSleptTimes(1);
    }

    /**
     * Assert the run stops with exactly the failure, after one attempt, with no
     * wait and nothing written.
     *
     * @param  \Throwable  $failure
     * @param  \ArrayObject<int, list<scalar|null>>  $selects
     * @return void
     */
    private function assertStoppedBy(#[\SensitiveParameter] \Throwable $failure, \ArrayObject $selects): void
    {
        try {
            $this->sealer()->seal();

            self::fail('Expected the run to stop.');
        } catch (\Throwable $thrown) {
            self::assertSame($failure, $thrown);
        }

        self::assertCount(1, $selects);
        Sleep::assertNeverSlept();
        self::assertSame([], $this->seals());
        self::assertSame(0, DB::connection(StorageConnection::name())->transactionLevel());
    }

    /**
     * Set sealing settings by their keys under `integrity.seal`.
     *
     * @param  array<string, int>  $settings
     * @return void
     */
    private function configure(array $settings): void
    {
        $config = app(ConfigRepository::class);

        foreach ($settings as $key => $value) {
            $config->set('audit-log.integrity.seal.' . $key, $value);
        }
    }

    /**
     * Raise the failure from the next candidate selections, the number given or
     * all of them, as the statement would raise it.
     *
     * @param  \Throwable  $failure
     * @param  int  $times
     * @return void
     */
    private function raiseOnCandidateSelects(#[\SensitiveParameter] \Throwable $failure, int $times = PHP_INT_MAX): void
    {
        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query) use ($failure, &$times): void {
            if ($times === 0 || !self::isCandidateSelect($query)) {
                return;
            }

            $times--;

            throw $failure;
        });
    }

    /**
     * Record the bindings of every candidate selection from now on, of the
     * recent pass and the sweep alike.
     *
     * @return \ArrayObject<int, list<scalar|null>>
     */
    private function recordCandidateSelects(): \ArrayObject
    {
        /** @var \ArrayObject<int, list<scalar|null>> $selects */
        $selects = new \ArrayObject;

        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query, array $bindings) use ($selects): void {
            if (!self::isCandidateSelect($query)) {
                return;
            }

            $selects->append(array_values($bindings));
        });

        return $selects;
    }

    /**
     * Record every statement from now on.
     *
     * @return \ArrayObject<int, string>
     */
    private function recordStatements(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $statements */
        $statements = new \ArrayObject;

        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query) use ($statements): void {
            $statements->append($query);
        });

        return $statements;
    }

    /**
     * The installation id's rows in the state table, as the engine returns
     * them, read afresh on every call.
     *
     * @return list<\stdClass>
     *
     * @phpstan-impure
     */
    private function installationRows(): array
    {
        return array_values(DB::connection(StorageConnection::name())->table(IntegrityTables::stateTable())->where('name', InstallationIdentity::NAME)->get()->all());
    }

    /**
     * Record each sweep cursor written from now on.
     *
     * @return \ArrayObject<int, array<string, string>>
     */
    private function recordCursorWrites(): \ArrayObject
    {
        /** @var \ArrayObject<int, array<string, string>> $cursors */
        $cursors = new \ArrayObject;

        DB::connection(StorageConnection::name())->beforeExecuting(static function (string $query, array $bindings) use ($cursors): void {
            if (!(($bindings[0] ?? null) === IntegrityProgress::SWEEP_CURSOR) || !str_starts_with(strtolower($query), 'insert')) {
                return;
            }

            /** @var array<string, string> $cursor */
            $cursor = json_decode((string) $bindings[2], true);

            $cursors->append($cursor);
        });

        return $cursors;
    }

    /**
     * Make a competing sealer seal the entry at the next sequence just before
     * this attempt inserts its checkpoint, once.
     *
     * On MySQL and PostgreSQL the competitor commits through its own connection
     * while the attempt is open. SQLite has one writer, so from this process
     * the competitor's seal is written inside the attempt, which makes the
     * insert the same duplicate, and committed again once the attempt has
     * rolled back, as though it had committed first.
     *
     * @param  string  $entryId
     * @return void
     */
    private function competeBeforeTheFirstCheckpoint(string $entryId): void
    {
        $storage     = DB::connection(StorageConnection::name());
        $armed       = true;
        $recommitted = false;

        $storage->beforeExecuting(function (string $query) use (&$armed, &$recommitted, $storage, $entryId): void {
            if (!$armed || preg_match('/^insert into \S*' . IntegrityTables::checkpointsTable() . '\b/', str_replace(['"', '`'], '', $query)) !== 1) {
                return;
            }

            $armed = false;

            if ($storage->getDriverName() !== 'sqlite') {
                $this->sealCompetingly(DB::connection(self::COMPETITOR), $entryId);

                return;
            }

            $this->sealCompetingly($storage, $entryId);

            Event::listen(TransactionRolledBack::class, function () use (&$recommitted, $storage, $entryId): void {
                if ($recommitted) {
                    return;
                }

                $recommitted = true;

                $this->sealCompetingly($storage, $entryId);
            });
        });
    }

    /**
     * Seal the entry through the competing connection, as a competing sealer
     * would: the genesis, holding that one entry.
     *
     * @param  \Illuminate\Database\Connection  $competitor
     * @param  string  $entryId
     * @return void
     */
    private function sealCompetingly(Connection $competitor, string $entryId): void
    {
        $entry = $competitor->table(EntrySettings::table())->where('id', $entryId)->first(['hmac', 'recorded_at']);

        self::assertNotNull($entry);

        $time    = StoredTime::fromStorage((string) $entry->recorded_at);
        $members = [[$entryId, (string) $entry->hmac]];
        $signer  = app(SealSigner::class);
        $seal    = new SealEnvelope(
            logId: app(SealSettings::class)->logId(),
            id: '01932b4e-9000-7000-8000-0000000000aa',
            sequence: 1,
            previousId: null,
            previousDigest: null,
            memberCount: 1,
            membersDigest: SealEnvelope::membersDigest($members),
            firstRecordedAt: $time,
            lastRecordedAt: $time,
            sealedAt: '2026-11-01T12:59:00.000000Z',
            keyId: $signer->signingKeyId(),
        );

        $competitor->table(IntegrityTables::checkpointsTable())->insert($seal->toRow($seal->digest(), $signer->sign($seal)));
        $competitor->table(IntegrityTables::membersTable())->insert(['checkpoint_id' => $seal->id, 'entry_id' => $entryId, 'hmac' => $members[0][1]]);
    }

    /**
     * The number of seals the entry is a member of.
     *
     * @param  string  $entryId
     * @return int
     */
    private function countMembers(string $entryId): int
    {
        return DB::connection(StorageConnection::name())->table(IntegrityTables::membersTable())->where('entry_id', $entryId)->count();
    }

    /**
     * The entry's time as the database returns it.
     *
     * @param  string  $id
     * @return string
     */
    private function storedTimeOf(string $id): string
    {
        $time = DB::connection(StorageConnection::name())->table(EntrySettings::table())->where('id', $id)->value('recorded_at');

        self::assertIsString($time);

        return $time;
    }

    /**
     * Whether the statement is a candidate selection: a read of the entries
     * table, of the recent pass or the sweep.
     *
     * @param  string  $query
     * @return bool
     */
    private static function isCandidateSelect(string $query): bool
    {
        $table = EntrySettings::table();

        return preg_match('/^select .* from \S*' . $table . '\S* as e\b|^select .* from \(select .* from \S*' . $table . '\b/', str_replace(['"', '`'], '', $query)) === 1;
    }

    /**
     * The position a candidate selection reads on after, as its time then its
     * id, for comparing selections' positions.
     *
     * @param  list<scalar|null>  $bindings
     * @return string
     */
    private static function positionIn(array $bindings): string
    {
        self::assertCount(5, $bindings, 'Expected the selection to read after a position.');

        return StoredTime::fromStorage((string) $bindings[1]) . ' ' . $bindings[4];
    }

    /**
     * A failed statement on the storage connection with the driver's message,
     * and the SQLSTATE in its error information when given.
     *
     * @param  string  $message
     * @param  ?string  $state
     * @return \Illuminate\Database\QueryException
     */
    private static function failure(string $message, ?string $state = null): QueryException
    {
        $driver = new \PDOException($message);

        if ($state !== null) {
            $driver->errorInfo = [$state, 0, ''];
        }

        return new QueryException(self::CONNECTION, 'select * from entries', [], $driver);
    }

    /**
     * A serialisation failure known by its SQLSTATE alone, as PostgreSQL raises
     * it: its code is the string `40001`, and no phrase Laravel recognises is
     * in its message.
     *
     * @return \Illuminate\Database\QueryException
     */
    private static function serialisationFailure(): QueryException
    {
        $driver = new class ('SQLSTATE[40001]: Serialization failure: 7 ERROR:  could not serialize access due to concurrent update') extends \PDOException {
            /**
             * Constructor.
             *
             * @param  string  $message
             */
            public function __construct(string $message)
            {
                parent::__construct($message);

                $this->code      = '40001';
                $this->errorInfo = ['40001', 7, ''];
            }
        };

        return new QueryException(self::CONNECTION, 'select * from entries', [], $driver);
    }

    /**
     * A duplicate key, as every engine raises it for a seal or member another
     * sealer wrote first.
     *
     * @return \Illuminate\Database\QueryException
     */
    private static function duplicate(): QueryException
    {
        $driver = new \PDOException('SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry');

        $driver->errorInfo = ['23000', 1062, ''];

        return new UniqueConstraintViolationException(self::CONNECTION, 'insert into checkpoints', [], $driver);
    }

    /**
     * The ids in byte order, as the members are read back.
     *
     * @param  list<string>  $ids
     * @return list<string>
     */
    private static function sorted(array $ids): array
    {
        usort($ids, strcmp(...));

        return $ids;
    }
}
