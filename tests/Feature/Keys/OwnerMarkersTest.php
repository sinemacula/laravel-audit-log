<?php

declare(strict_types = 1);

namespace Tests\Feature\Keys;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\KeyTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\MarkerTransition;
use SineMacula\Laravel\AuditLog\Keys\OwnerMarker;
use SineMacula\Laravel\AuditLog\Keys\OwnerMarkers;
use SineMacula\Laravel\AuditLog\Records\Reference;
use Tests\Concerns\InteractsWithReadWriteSplit;
use Tests\TestCase;

/**
 * Feature tests for the owner markers on the storage connection: an owner's
 * latest marker read by journal sequence alone, in one statement through the
 * writer, never another owner's, none for an owner with no marker, and a marker
 * inserted as its row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OwnerMarkers::class)]
final class OwnerMarkersTest extends TestCase
{
    use InteractsWithReadWriteSplit;

    /** @var string The markers table's migration. */
    private const string MIGRATION = __DIR__ . '/../../../database/migrations/2026_11_02_001200_create_audit_log_owner_erasures_table.php';

    /**
     * Close the split's connections and delete their files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->removeReadWriteSplit();

        parent::tearDown();
    }

    /**
     * The latest marker is the one of the greatest journal sequence, whatever
     * order the markers were written in and whatever their times and ids say,
     * read in one statement.
     *
     * @return void
     */
    public function testTheLatestIsByJournalSequence(): void
    {
        $owner = Reference::of('App\Models\User', '42');

        $this->insertMarker('01932b4e-e000-7000-8000-000000000009', $owner, MarkerTransition::ERASED, 2, 9, '2026-11-03T12:00:00.000000Z');
        $this->insertMarker('01932b4e-e000-7000-8000-000000000001', $owner, MarkerTransition::REINSTATED, 2, 12, '2026-11-01T12:00:00.000000Z');
        $this->insertMarker('01932b4e-e000-7000-8000-000000000005', $owner, MarkerTransition::ERASED, 1, 4, '2026-11-04T12:00:00.000000Z');

        $statements = $this->countStatements();
        $latest     = self::markers()->latest(DB::connection(StorageConnection::name()), $owner);

        self::assertNotNull($latest);
        self::assertSame('01932b4e-e000-7000-8000-000000000001', $latest->id);
        self::assertSame(MarkerTransition::REINSTATED, $latest->transition);
        self::assertSame(12, $latest->journalSequence);
        self::assertSame(2, $latest->generationFloor);
        self::assertSame(1, $statements->count);
    }

    /**
     * An owner with no marker has none.
     *
     * @return void
     */
    public function testAnOwnerWithNoMarkerHasNone(): void
    {
        self::assertNull(self::markers()->latest(DB::connection(StorageConnection::name()), Reference::of('App\Models\User', '42')));
    }

    /**
     * Another owner's markers are never read: one of another id, and one of
     * another type with the same id.
     *
     * @return void
     */
    public function testAnotherOwnersMarkersAreNotRead(): void
    {
        $this->insertMarker('01932b4e-e000-7000-8000-000000000001', Reference::of('App\Models\User', '43'), MarkerTransition::ERASED, 1, 5, '2026-11-01T12:00:00.000000Z');
        $this->insertMarker('01932b4e-e000-7000-8000-000000000002', Reference::of('App\Models\Team', '42'), MarkerTransition::ERASED, 1, 6, '2026-11-01T12:00:00.000000Z');
        $this->insertMarker('01932b4e-e000-7000-8000-000000000003', Reference::of('App\Models\User', '42'), MarkerTransition::REINSTATED, 0, 2, '2026-11-01T12:00:00.000000Z');

        $latest = self::markers()->latest(DB::connection(StorageConnection::name()), Reference::of('App\Models\User', '42'));

        self::assertNotNull($latest);
        self::assertSame('01932b4e-e000-7000-8000-000000000003', $latest->id);
        self::assertNull(self::markers()->latest(DB::connection(StorageConnection::name()), Reference::of('App\Models\User', '44')));
    }

    /**
     * A marker is inserted as its row, and read back as the marker it was.
     *
     * @return void
     */
    public function testAMarkerIsInsertedAsItsRow(): void
    {
        $owner  = Reference::of('App\Models\User', '42');
        $marker = new OwnerMarker('01932b4e-e000-7000-8000-000000000001', $owner, MarkerTransition::ERASED, 7, 3, '2026-11-01T12:00:00.123456Z');

        self::markers()->insert(DB::connection(StorageConnection::name()), $marker);

        $stored = (array) DB::connection(StorageConnection::name())->table(KeyTables::ownerErasuresTable())->first();

        self::assertEquals($marker, OwnerMarker::fromRow($stored));
        self::assertEquals($marker, self::markers()->latest(DB::connection(StorageConnection::name()), $owner));
    }

    /**
     * Over a read/write split the latest marker is read through the writer, so
     * a replica lagging an erasure never lets a key be created for the owner.
     *
     * @return void
     */
    public function testTheLatestIsReadThroughTheWriter(): void
    {
        $this->useReadWriteSplit();

        $migration = require self::MIGRATION;
        $config    = app(ConfigRepository::class);

        foreach ([self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION] as $connection) {
            $config->set('audit-log.storage.connection', $connection);
            $migration->up();
        }

        $config->set('audit-log.storage.connection', self::SPLIT_CONNECTION);

        $owner = Reference::of('App\Models\User', '42');

        $marker = new OwnerMarker('01932b4e-e000-7000-8000-000000000001', $owner, MarkerTransition::ERASED, 1, 1, '2026-11-01T12:00:00.000000Z');

        self::markers()->insert(DB::connection(self::PRIMARY_CONNECTION), $marker);

        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table(KeyTables::ownerErasuresTable())->count());
        self::assertTrue(self::markers()->latest(DB::connection(self::SPLIT_CONNECTION), $owner)?->isErasure());
    }

    /**
     * The markers the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Keys\OwnerMarkers
     */
    private static function markers(): OwnerMarkers
    {
        return app(OwnerMarkers::class);
    }

    /**
     * Insert a marker on the storage connection.
     *
     * @param  string  $id
     * @param  \SineMacula\Laravel\AuditLog\Records\Reference  $owner
     * @param  \SineMacula\Laravel\AuditLog\Integrity\Enums\MarkerTransition  $transition
     * @param  int  $floor
     * @param  int  $sequence
     * @param  string  $createdAt
     * @return void
     */
    private function insertMarker(string $id, Reference $owner, MarkerTransition $transition, int $floor, int $sequence, string $createdAt): void
    {
        self::markers()->insert(DB::connection(StorageConnection::name()), new OwnerMarker($id, $owner, $transition, $floor, $sequence, $createdAt));
    }

    /**
     * A counter of the statements the storage connection runs from now on.
     *
     * @return object{count: int}
     */
    private function countStatements(): object
    {
        $counter = new class {
            /** @var int The statements run. */
            public int $count = 0;
        };

        Event::listen(QueryExecuted::class, static function () use ($counter): void {
            $counter->count++;
        });

        return $counter;
    }
}
