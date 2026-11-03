<?php

declare(strict_types = 1);

namespace Tests\Integration\Integrity;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Sleep;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\CheckpointAnchor;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\FailureClassifier;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Anchors\NullAnchor;
use SineMacula\Laravel\AuditLog\Integrity\CheckpointWriter;
use SineMacula\Laravel\AuditLog\Integrity\Enums\IntegrityStatus;
use SineMacula\Laravel\AuditLog\Integrity\NullPruneLedger;
use SineMacula\Laravel\AuditLog\Integrity\Sealer;
use SineMacula\Laravel\AuditLog\Integrity\SealResult;
use SineMacula\Laravel\AuditLog\Integrity\SegmentReport;
use SineMacula\Laravel\AuditLog\Integrity\VerificationRange;
use SineMacula\Laravel\AuditLog\Integrity\Verifier;
use Tests\Concerns\RunsKilledChildren;
use Tests\Concerns\SealsEntries;
use Tests\TestCase;

/**
 * Integration tests for sealers racing one another in real processes, on
 * whichever engine the suite runs against: two sealers released together seal
 * every entry once, in one chain with no gap; a sealer that loses the race for
 * a sequence rolls back and seals again from the new head; a writer inserting
 * while seals are made never leaves an entry half sealed, skipped or sealed
 * twice; a recent pass and a sweep share the table safely; and a seal's open
 * transaction never makes a recording wait on MySQL or PostgreSQL, while on
 * SQLite the one writer makes it wait out `busy_timeout`.
 *
 * SQLite runs in WAL mode, as the operations guidance advises, so a sealer's
 * read never blocks another process's commit; a sealer whose snapshot another
 * commit made stale is refused at its first write, and retries. The processes
 * meet on file gates rather than on timing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Sealer::class)]
#[CoversClass(CheckpointWriter::class)]
final class ConcurrentSealersTest extends TestCase
{
    use RunsKilledChildren, SealsEntries;

    /** @var string When every sealer of a test runs. */
    private const string SEALED_AT = '2026-11-01 13:00:00';

    /** @var string When every verification of a test runs: within the allowed age of every entry. */
    private const string VERIFIED_AT = '2026-11-01T14:00:00.000000Z';

    /** @var int The entries one seal holds at most in these tests. */
    private const int BATCH = 100;

    /** @var int The attempts a sealer makes at one seal: the most allowed, so a race lost many times over still ends in a seal. */
    private const int MAX_ATTEMPTS = 100;

    /** @var int How long a recording may wait on a lock before the wait is a failure, in seconds. */
    private const int LOCK_WAIT_SECONDS = 1;

    /** @var int How long SQLite's one writer is waited for by a recording made beside an open seal, in milliseconds. */
    private const int SQLITE_BUSY_MILLISECONDS = 200;

    /** @var int How long the inserting child pauses between its inserts, in microseconds. */
    private const int INSERT_PAUSE_MICROSECONDS = 2000;

    /** @var string The gate that releases the racing sealers together. */
    private const string START = 'start';

    /** @var string The gate a child opens once it has reached where it is held. */
    private const string ARRIVED = 'arrived';

    /** @var string The gate that lets a held child go on. */
    private const string RELEASE = 'release';

    /** @var string The gate the inserting child opens once its last entry has committed. */
    private const string INSERTED = 'inserted';

    /** @var string The gate a held seal opens once it has committed. */
    private const string COMMITTED = 'committed';

    /** @var string The file the inserting child names each entry it stored in. */
    private const string IDS = 'ids';

    /**
     * Seal on a fixed clock, verify on another, and bind no anchor and no prune
     * ledger, so verification checks the seals alone.
     *
     * Xdebug's develop mode keeps every failed statement alive with the frames
     * of its exception, and on SQLite a statement that is never finalised keeps
     * its stale snapshot, so no attempt after a lost race could ever write.
     * There, on SQLite, these tests are skipped; they run whenever develop mode
     * is off.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        if (DB::connection(StorageConnection::name())->getDriverName() === 'sqlite' && self::keepsFailedStatements()) {
            self::markTestSkipped('Xdebug\'s develop mode keeps a failed SQLite statement, and its stale snapshot, alive.');
        }

        $this->sealAt(self::SEALED_AT);

        CarbonImmutable::setTestNow(self::VERIFIED_AT);

        app()->instance(CheckpointAnchor::class, new NullAnchor);
        app()->instance(PruneLedger::class, new NullPruneLedger);

        $config = app(ConfigRepository::class);

        $config->set('audit-log.integrity.seal.batch', self::BATCH);
        $config->set('audit-log.integrity.seal.max_attempts', self::MAX_ATTEMPTS);
    }

    /**
     * Put the clock back, and remove what the children shared once the
     * migrations have rolled back.
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
     * Two sealers in separate processes, released by one gate over 2,000
     * entries in batches of 100, seal every entry exactly once between them:
     * the seals they report add up to the stored chain, its sequences run from
     * 1 with no gap, and every segment verifies as `valid`.
     *
     * @return void
     */
    public function testTwoSealersInSeparateProcessesSealEveryEntryOnce(): void
    {
        $ids = $this->storeManyEntries(2000);

        $first  = $this->startSealer('first');
        $second = $this->startSealer('second');

        $this->openGate(self::START);

        $this->assertKilled($this->waitForChild($first));
        $this->assertKilled($this->waitForChild($second));

        $tallies = [$this->leftTally('first'), $this->leftTally('second')];

        self::assertSame(count($this->seals()), $tallies[0]['seals'] + $tallies[1]['seals']);
        self::assertSame(2000, $tallies[0]['entries'] + $tallies[1]['entries']);

        $this->assertSealedOnceInOneChain($ids);
    }

    /**
     * A sealer held after its selection, before its insert, loses the race when
     * another seals and commits first: its insert of the same sequence is
     * refused, its attempt rolls back whole, and it seals again from the new
     * head, chaining onto the winner's seal the entries stored since, and
     * counting the retry.
     *
     * @return void
     */
    public function testALosingSealerRetriesFromTheNewHead(): void
    {
        $first = $this->storeEntries(3);

        $child = $this->startChild(function (): void {
            $this->holdBeforeTheFirstCheckpointInsert();
            $this->leaveTally('loser', $this->sealer()->seal());
        });

        $this->awaitGate(self::ARRIVED);

        self::assertSame(1, $this->sealer()->seal()->seals());

        $later = $this->storeEntries(2, '2026-11-01 12:30:00.000000');

        $this->openGate(self::RELEASE);

        $this->assertKilled($this->waitForChild($child));

        $loser = $this->leftTally('loser');
        $seals = $this->seals();

        self::assertGreaterThanOrEqual(1, $loser['retries']);
        self::assertSame(1, $loser['seals']);
        self::assertSame(2, $loser['last_sequence']);
        self::assertSame([1, 2], array_map(static fn (array $seal): int => (int) $seal['sequence'], $seals));
        self::assertSame($seals[0]['id'], $seals[1]['previous_id']);
        self::assertSame($seals[0]['seal_digest'], $seals[1]['previous_digest']);
        self::assertSame(self::sorted($first), $this->membersOf((string) $seals[0]['id']));
        self::assertSame(self::sorted($later), $this->membersOf((string) $seals[1]['id']));

        $this->assertEverySegmentValid();
    }

    /**
     * A writer in another process inserting entry after entry while this one
     * seals again and again never leaves an entry half sealed: once a last run
     * has sealed the rest, every entry it stored is a member exactly once, none
     * is skipped, and the chain verifies.
     *
     * @return void
     */
    public function testAnInsertRacingASealerIsNeverHalfSealed(): void
    {
        $child = $this->startChild(function (): void {
            $first = new CarbonImmutable(self::ENTRIES_RECORDED_AT, 'UTC');

            for ($index = 0; $index < 300; $index++) {
                $this->appendToChildFile(self::IDS, $this->storeEntryAt($first->addMilliseconds($index)->format('Y-m-d H:i:s.u')));
                $this->openGate(self::ARRIVED);

                usleep(self::INSERT_PAUSE_MICROSECONDS);
            }

            $this->openGate(self::INSERTED);
        });

        $this->awaitGate(self::ARRIVED);

        $runs = 0;

        do {
            $done = is_file($this->childFile('gate-' . self::INSERTED));

            $this->sealer()->seal();

            $runs++;
        } while (!$done);

        $this->assertKilled($this->waitForChild($child));

        $this->sealer()->seal();

        self::assertGreaterThanOrEqual(2, $runs);
        self::assertCount(300, $this->childFileLines(self::IDS));

        $this->assertSealedOnceInOneChain($this->childFileLines(self::IDS));
    }

    /**
     * A recent pass and a sweep in separate processes, released by one gate,
     * share the table safely: between them every entry is sealed once in one
     * chain, the sweep reaches the end of the table, and the chain verifies.
     *
     * @return void
     */
    public function testARecentPassAndASweepRaceSafely(): void
    {
        $ids = $this->storeManyEntries(1000);

        $recent = $this->startSealer('recent');
        $sweep  = $this->startSealer('sweep', true);

        $this->openGate(self::START);

        $this->assertKilled($this->waitForChild($recent));
        $this->assertKilled($this->waitForChild($sweep));

        $tallies = [$this->leftTally('recent'), $this->leftTally('sweep')];

        self::assertTrue($tallies[1]['sweep_completed']);
        self::assertSame(1000, $tallies[0]['entries'] + $tallies[1]['entries']);
        self::assertSame(count($this->seals()), $tallies[0]['seals'] + $tallies[1]['seals']);

        $this->assertSealedOnceInOneChain($ids);
    }

    /**
     * Sealing takes no application lock that recording waits on. A seal held
     * open in another process after its inserts leaves MySQL and PostgreSQL
     * free to record at once, within a lock wait far shorter than either
     * engine's default; the open seal holds only what it selected, and the
     * entry recorded beside it joins the next seal. SQLite has one writer, so
     * there a recording made beside the open seal waits out `busy_timeout` and
     * is refused as a locked database, and once the seal commits the same
     * recording succeeds.
     *
     * @return void
     */
    public function testSealingNeverBlocksRecordingOnMySqlAndPostgres(): void
    {
        $sealed = $this->storeEntries(2);

        $child = $this->startChild(function (): void {
            $this->holdAfterTheMembersInsert();
            $this->sealer()->seal();
        });

        $this->awaitGate(self::ARRIVED);

        $connection = DB::connection(StorageConnection::name());
        $beside     = $connection->getDriverName() === 'sqlite'
            ? $this->recordBesideTheOneWriter($connection)
            : $this->recordWithoutWaiting($connection);

        $this->openGate(self::RELEASE);

        $this->assertKilled($this->waitForChild($child));

        $seals = $this->seals();

        self::assertCount(1, $seals);
        self::assertSame(self::sorted($sealed), $this->membersOf((string) $seals[0]['id']));
        self::assertSame(1, $this->sealer()->seal()->seals());
        self::assertSame([$beside], $this->membersOf((string) $this->seals()[1]['id']));

        $this->assertEverySegmentValid();
    }

    /**
     * On PostgreSQL with `lock_timeout` set, a seal attempt that waits behind
     * another sealer's uncommitted seal of the same sequence past the timeout
     * is cancelled (SQLSTATE `55P03`), rolled back whole and made again, never
     * a stopped run: once the other seal commits, the retry reads it as the
     * head and finds nothing left to seal.
     *
     * @return void
     */
    public function testAPostgresLockTimeoutIsRetried(): void
    {
        $connection = DB::connection(StorageConnection::name());

        if ($connection->getDriverName() !== 'pgsql') {
            self::markTestSkipped('Only PostgreSQL cancels a statement by its lock timeout as SQLSTATE 55P03.');
        }

        $this->storeEntries(2);

        $child = $this->startChild(function (): void {
            $this->holdAfterTheMembersInsert();
            $this->sealer()->seal();
        });

        $this->awaitGate(self::ARRIVED);

        $connection->statement('set lock_timeout = \'200ms\'');

        Sleep::fake();
        Sleep::whenFakingSleep(function (): void {
            $this->openGate(self::RELEASE);
            $this->awaitGate(self::COMMITTED);
        });

        $result = $this->sealer()->seal();

        $this->assertKilled($this->waitForChild($child));

        self::assertSame(1, $result->retries());
        self::assertSame(0, $result->seals());
        self::assertCount(1, $this->seals());

        $this->assertEverySegmentValid();
    }

    /**
     * Put the database on a file SQLite can share across a fork, in WAL mode.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->useFileDatabaseOnSqlite($app);

        $config = app(ConfigRepository::class);
        $key    = 'database.connections.' . self::CONNECTION;

        if ($config->get($key . '.driver') !== 'sqlite') {
            return;
        }

        $config->set($key . '.journal_mode', 'wal');
    }

    /**
     * On MySQL or PostgreSQL, record an entry beside the open seal with a lock
     * wait of one second, which a lock taken by sealing would exceed, and
     * return its id.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return string
     */
    private function recordWithoutWaiting(Connection $connection): string
    {
        $connection->statement($connection->getDriverName() === 'mysql'
            ? 'set session innodb_lock_wait_timeout = ' . self::LOCK_WAIT_SECONDS
            : 'set lock_timeout = \'' . self::LOCK_WAIT_SECONDS . 's\'');

        $id = $this->storeEntryAt('2026-11-01 12:30:00');

        self::assertSame(0, $connection->table(IntegrityTables::checkpointsTable())->count(), 'The open seal was visible before it committed.');
        self::assertTrue($connection->table(EntrySettings::table())->where('id', $id)->exists());

        return $id;
    }

    /**
     * On SQLite, record an entry beside the open seal with a short
     * `busy_timeout`: the recording waits that long for the one writer and is
     * refused as a locked database, storing nothing. Return the id the
     * recording is made under once the seal is released to commit.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return string
     */
    private function recordBesideTheOneWriter(Connection $connection): string
    {
        $id = '01932b4e-8a40-7000-8000-00000000beef';

        $connection->statement('pragma busy_timeout = ' . self::SQLITE_BUSY_MILLISECONDS);

        $started = hrtime(true);
        $failure = rescue(fn (): string => $this->storeEntryAt('2026-11-01 12:30:00', $id), static fn (\Throwable $exception): \Throwable => $exception, false);

        self::assertInstanceOf(QueryException::class, $failure, 'A recording beside an open seal on SQLite waits for the one writer and is refused.');
        self::assertTrue(app(FailureClassifier::class)->isConcurrencyError($failure));
        self::assertGreaterThanOrEqual(self::SQLITE_BUSY_MILLISECONDS * 1000000, hrtime(true) - $started);

        $this->openGate(self::RELEASE);
        $this->awaitGate(self::COMMITTED);

        self::assertFalse($connection->table(EntrySettings::table())->where('id', $id)->exists());

        $connection->statement('pragma busy_timeout = ' . self::BUSY_TIMEOUT_MILLISECONDS);

        return $this->storeEntryAt('2026-11-01 12:30:00', $id);
    }

    /**
     * Start a sealer in a child process, a recent pass or a sweep, held until
     * the start gate opens, that leaves its tally under the name.
     *
     * @param  string  $name
     * @param  bool  $sweep
     * @return int
     */
    private function startSealer(string $name, bool $sweep = false): int
    {
        return $this->startChild(function () use ($name, $sweep): void {
            $sealer = $this->sealer();

            $this->awaitGate(self::START);
            $this->leaveTally($name, $sweep ? $sealer->sweep() : $sealer->seal());
        });
    }

    /**
     * In a child: hold this process just before its first checkpoint insert,
     * once its selection is made inside the seal's transaction, until it is
     * released, having said it arrived. A retry's insert is not held.
     *
     * @return void
     */
    private function holdBeforeTheFirstCheckpointInsert(): void
    {
        $held    = false;
        $pattern = '/^insert into \W?' . preg_quote(IntegrityTables::checkpointsTable(), '/') . '\W/';

        DB::connection(StorageConnection::name())->beforeExecuting(function (string $query) use (&$held, $pattern): void {
            if ($held || preg_match($pattern, $query) !== 1) {
                return;
            }

            $held = true;

            $this->openGate(self::ARRIVED);
            $this->awaitGate(self::RELEASE);
        });
    }

    /**
     * In a child: hold this process inside the seal's transaction once its
     * members are inserted, until it is released, having said it arrived; on
     * release, say the seal has committed once it has.
     *
     * @return void
     */
    private function holdAfterTheMembersInsert(): void
    {
        $pattern = '/^insert into \W?' . preg_quote(IntegrityTables::membersTable(), '/') . '\W/';

        DB::listen(function (QueryExecuted $event) use ($pattern): void {
            if (preg_match($pattern, $event->sql) !== 1) {
                return;
            }

            $this->openGate(self::ARRIVED);
            $this->awaitGate(self::RELEASE);

            DB::connection(StorageConnection::name())->afterCommit(fn () => $this->openGate(self::COMMITTED));
        });
    }

    /**
     * Store the number of entries, a microsecond apart, in one transaction,
     * which on a file database is far quicker than a commit each, and return
     * their ids.
     *
     * @param  int  $count
     * @return list<string>
     */
    private function storeManyEntries(int $count): array
    {
        /** @var list<string> */
        return DB::connection(StorageConnection::name())->transaction(fn (): array => $this->storeEntries($count));
    }

    /**
     * Assert every entry given is a member of exactly one seal and no other
     * entry is, that the seals' sequences run from 1 with no gap, and that
     * every segment verifies.
     *
     * @param  list<string>  $ids
     * @return void
     */
    private function assertSealedOnceInOneChain(array $ids): void
    {
        $members = DB::connection(StorageConnection::name())->table(IntegrityTables::membersTable())->orderBy('entry_id')->pluck('entry_id')->all();

        self::assertSame(self::sorted($ids), $members);

        $sequences = array_map(static fn (array $seal): int => (int) $seal['sequence'], $this->seals());

        self::assertSame(range(1, count($sequences)), $sequences);

        $this->assertEverySegmentValid();
    }

    /**
     * Assert a verification of the whole log, by the verifier the container
     * builds, passes with every seal's segment `valid`.
     *
     * @return void
     */
    private function assertEverySegmentValid(): void
    {
        $statuses = [];
        $summary  = app(Verifier::class)->verify(VerificationRange::whole(), static function (SegmentReport $report) use (&$statuses): void {
            $statuses[$report->sequence] = $report->integrity->value;
        });

        $count = count($this->seals());

        self::assertFalse($summary->fails(false));
        self::assertSame($count, $summary->head);
        self::assertSame(array_fill(1, $count, IntegrityStatus::VALID->value), $statuses);
    }

    /**
     * Leave the sealer's tally, under the name, for the parent to read.
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\AuditLog\Integrity\SealResult  $result
     * @return void
     */
    private function leaveTally(string $name, SealResult $result): void
    {
        file_put_contents($this->childFile("tally-{$name}"), json_encode([
            'seals'           => $result->seals(),
            'entries'         => $result->entries(),
            'retries'         => $result->retries(),
            'last_sequence'   => $result->lastSequence(),
            'sweep_completed' => $result->isSweepComplete(),
        ], JSON_THROW_ON_ERROR));
    }

    /**
     * The tally a child left under the name.
     *
     * @param  string  $name
     * @return array{seals: int, entries: int, retries: int, last_sequence: ?int, sweep_completed: bool}
     */
    private function leftTally(string $name): array
    {
        /** @var array{seals: int, entries: int, retries: int, last_sequence: ?int, sweep_completed: bool} */
        return json_decode((string) file_get_contents($this->childFile("tally-{$name}")), true, flags: JSON_THROW_ON_ERROR);
    }

    /**
     * Whether Xdebug runs in develop mode, which keeps the frames of each
     * exception, and so the statement that failed, alive.
     *
     * @return bool
     */
    private static function keepsFailedStatements(): bool
    {
        return function_exists('xdebug_info') && in_array('develop', xdebug_info('mode'), true);
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
