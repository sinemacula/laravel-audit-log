<?php

declare(strict_types = 1);

namespace Tests\Integration\Querying;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Querying\ExportSnapshot;
use Tests\Concerns\RunsKilledChildren;
use Tests\Concerns\SealsEntries;
use Tests\TestCase;

/**
 * Integration tests for the snapshot an export is read in, on whichever engine
 * the suite runs against, racing a writer in another process: a row committed
 * once the snapshot has read is never read by it, the bound agrees with every
 * row read after it, the session issues nothing but its begin, its reads and
 * its commit, and a writer commits while the snapshot is open.
 *
 * SQLite runs on a file in WAL mode, set before any child starts, as the
 * operations guidance advises: in rollback-journal mode the snapshot's shared
 * lock would hold back the child's commit until the snapshot closed. The
 * processes meet on file gates, never on timing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExportSnapshot::class)]
final class ExportSnapshotEnginesTest extends TestCase
{
    use RunsKilledChildren, SealsEntries;

    /** @var string The gate this process opens once the snapshot has read. */
    private const string READ = 'read';

    /** @var string The gate the child opens once its row is committed. */
    private const string COMMITTED = 'committed';

    /** @var string When the entries stored before a snapshot are recorded. */
    private const string BEFORE = '2026-11-01 12:00:00.000000';

    /** @var string When the entry a writer commits during a snapshot is recorded: after every other. */
    private const string DURING = '2026-11-01 13:00:00.000000';

    /**
     * Remove what the children shared once the migrations have rolled back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        parent::tearDown();

        $this->removeChildren();
    }

    /**
     * A row another process commits once the snapshot's first statement has run
     * is not read by a second statement in the snapshot, and is there once the
     * snapshot has closed.
     *
     * @return void
     */
    public function testARowCommittedAfterTheSnapshotIsNotRead(): void
    {
        $this->storeEntries(2, self::BEFORE);

        $child = $this->startChild(function (): void {
            $this->awaitGate(self::READ);
            $this->storeEntryAt(self::DURING);
            $this->openGate(self::COMMITTED);
        });

        $snapshot = ExportSnapshot::open(app('db'));

        self::assertCount(2, $this->idsIn($snapshot->connection()));

        $this->openGate(self::READ);
        $this->awaitGate(self::COMMITTED);

        self::assertCount(2, $this->idsIn($snapshot->connection()));

        $snapshot->close();

        $this->assertKilled($this->waitForChild($child));

        self::assertCount(3, $this->idsIn(DB::connection(StorageConnection::name())));
    }

    /**
     * The bound, the greatest recorded time and id, selected as the snapshot's
     * first statement, is the last of the rows read after it in the snapshot,
     * whichever moment the engine takes its snapshot at, though another process
     * commits a row between the snapshot's begin and its bound, and another
     * once the bound is read.
     *
     * @return void
     */
    public function testTheBoundIsSelectedInsideTheSnapshot(): void
    {
        $this->storeEntries(2, self::BEFORE);

        $child = $this->startChild(function (): void {
            $this->awaitGate('begun');
            $this->storeEntryAt('2026-11-01 12:30:00.000000');
            $this->openGate('first');
            $this->awaitGate(self::READ);
            $this->storeEntryAt(self::DURING);
            $this->openGate(self::COMMITTED);
        });

        $snapshot = ExportSnapshot::open(app('db'));

        $this->openGate('begun');
        $this->awaitGate('first');

        $bound = $this->boundIn($snapshot->connection());

        $this->openGate(self::READ);
        $this->awaitGate(self::COMMITTED);

        $ids = $this->idsIn($snapshot->connection());

        self::assertSame([$bound], array_slice($ids, -1));
        self::assertSame($bound, $this->boundIn($snapshot->connection()));

        $snapshot->close();

        $this->assertKilled($this->waitForChild($child));

        self::assertNotSame($bound, $this->boundIn(DB::connection(StorageConnection::name())));
    }

    /**
     * The session runs nothing but its engine's begin, `select`s and its
     * `COMMIT`, so it never writes, and a SQLite reader never takes a writer's
     * lock.
     *
     * @return void
     */
    public function testTheSessionIssuesNoWrite(): void
    {
        $this->storeEntries(2, self::BEFORE);

        $statements = [];

        Event::listen(QueryExecuted::class, static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = [$query->connectionName, $query->sql];
        });

        $snapshot = ExportSnapshot::open(app('db'));
        $session  = $snapshot->connection();
        $name     = $session->getName();

        $this->boundIn($session);
        $this->idsIn($session);

        $snapshot->close();

        $mine   = array_filter($statements, static fn (array $statement): bool => $statement[0] === $name);
        $run    = array_values(array_map(static fn (array $statement): string => $statement[1], $mine));
        $begins = ExportSnapshot::BEGIN[$session->getDriverName()] ?? [];
        $reads  = array_slice($run, count($begins), -1);

        self::assertSame($begins, array_slice($run, 0, count($begins)));
        self::assertSame(['COMMIT'], array_slice($run, -1));
        self::assertCount(2, $reads);

        foreach ($reads as $read) {
            self::assertStringStartsWith('select ', $read);
        }
    }

    /**
     * While the snapshot is open, having read, a writer on another connection
     * commits at once: MySQL and PostgreSQL never block a writer on a reader,
     * and SQLite in WAL mode does not either. The snapshot still reads the rows
     * it began with.
     *
     * @return void
     */
    public function testAWriterCommitsWhileTheSnapshotIsOpen(): void
    {
        $this->storeEntries(2, self::BEFORE);

        $snapshot = ExportSnapshot::open(app('db'));

        self::assertCount(2, $this->idsIn($snapshot->connection()));

        $this->storeEntryAt(self::DURING);

        self::assertCount(3, $this->idsIn(DB::connection(StorageConnection::name())));
        self::assertCount(2, $this->idsIn($snapshot->connection()));

        $snapshot->close();
    }

    /**
     * Put the database on a file SQLite can share across a fork, in WAL mode,
     * before any child starts.
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
     * The ids of every entry the connection reads, ascending by recorded time
     * and then id, as an export reads them.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return list<string>
     */
    private function idsIn(Connection $connection): array
    {
        /** @var list<string> */
        return $connection->table(EntrySettings::table())->orderBy('recorded_at')->orderBy('id')->pluck('id')->all();
    }

    /**
     * The id of the greatest entry by recorded time and then id the connection
     * reads: the bound of an export.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return string
     */
    private function boundIn(Connection $connection): string
    {
        $bound = $connection->table(EntrySettings::table())->orderByDesc('recorded_at')->orderByDesc('id')->value('id');

        self::assertIsString($bound);

        return $bound;
    }
}
