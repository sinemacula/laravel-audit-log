<?php

declare(strict_types = 1);

namespace Tests\Integration\Integrity;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityProgress;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\CheckpointWriter;
use SineMacula\Laravel\AuditLog\Integrity\SealEnvelope;
use SineMacula\Laravel\AuditLog\Integrity\Sealer;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\Concerns\InteractsWithReadWriteSplit;
use Tests\Concerns\SealsEntries;
use Tests\TestCase;

/**
 * Integration tests for sealing on each engine: chaining, exact keysets, late
 * commits, writer-only statements and digests from stored times.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Sealer::class)]
#[CoversClass(CheckpointWriter::class)]
final class SealerEnginesTest extends TestCase
{
    use InteractsWithReadWriteSplit, SealsEntries;

    /** @var string When each sealer runs. */
    private const string SEALED_AT = '2026-11-01 13:00:00';

    /** @var string A second connection to the test's database, for a writer whose transaction commits late. */
    private const string LATE_WRITER = 'late_writer';

    /** @var list<string> The shipped integrity migrations and the lifecycle journal's, whose head every seal commits to, which the split needs on both of its files. */
    private const array INTEGRITY_MIGRATIONS = [
        __DIR__ . '/../../../database/migrations/2026_11_02_000300_create_audit_log_checkpoints_table.php',
        __DIR__ . '/../../../database/migrations/2026_11_02_000400_create_audit_log_checkpoint_members_table.php',
        __DIR__ . '/../../../database/migrations/2026_11_02_000500_create_audit_log_integrity_state_table.php',
        __DIR__ . '/../../../database/migrations/2026_11_02_000700_create_audit_log_lifecycle_table.php',
    ];

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
     * Roll back the late writer's transaction, close its connection, and remove
     * the split, when a test made them.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        if (app(ConfigRepository::class)->has('database.connections.' . self::LATE_WRITER)) {
            $late = DB::connection(self::LATE_WRITER);

            while ($late->transactionLevel() > 0) {
                $late->rollBack();
            }

            DB::purge(self::LATE_WRITER);
        }

        $this->removeReadWriteSplit();

        parent::tearDown();
    }

    /**
     * Seals 1 to 3 chain by id and stored digest with no gap, every entry a
     * member once.
     *
     * @return void
     */
    public function testSealsAndChainsOnEachEngine(): void
    {
        app(ConfigRepository::class)->set('audit-log.integrity.seal.batch', 100);

        $ids = $this->storeEntries(250);

        self::assertSame(3, $this->sealer()->seal()->seals());

        $seals = $this->seals();

        self::assertSame([1, 2, 3], array_map(static fn (array $seal): int => (int) $seal['sequence'], $seals));
        self::assertNull($seals[0]['previous_id']);
        self::assertNull($seals[0]['previous_digest']);

        foreach ([1, 2] as $index) {
            self::assertSame($seals[$index - 1]['id'], $seals[$index]['previous_id'], "Seal {$index} does not name the seal before.");
            self::assertSame($seals[$index - 1]['seal_digest'], $seals[$index]['previous_digest'], "Seal {$index} does not chain onto the digest before.");
        }

        $members = DB::connection(StorageConnection::name())->table(IntegrityTables::membersTable())->orderBy('entry_id')->pluck('entry_id')->all();

        self::assertSame(self::sorted($ids), $members);
    }

    /**
     * Rows sharing one microsecond across batches are split exactly by id, each
     * sealed once.
     *
     * @return void
     */
    public function testTheKeysetIsExactAtEqualMicroseconds(): void
    {
        app(ConfigRepository::class)->set('audit-log.integrity.seal.batch', 100);

        $ids = [];

        for ($index = 0; $index < 150; $index++) {
            $ids[] = $this->storeEntryAt('2026-11-01 12:00:00.123456', sprintf('01932b4e-8a40-7000-8000-%012x', 1000 - $index));
        }

        $ids[] = $this->storeEntryAt('2026-11-01 12:00:00.123457', '01932b4e-8a40-7000-8000-000000000000');

        $result = $this->sealer()->seal();
        $seals  = $this->seals();
        $sorted = self::sorted(array_slice($ids, 0, 150));

        self::assertSame(2, $result->seals());
        self::assertSame(151, $result->entries());
        self::assertSame(array_slice($sorted, 0, 100), $this->membersOf((string) $seals[0]['id']));
        self::assertSame(self::sorted([...array_slice($sorted, 100), $ids[150]]), $this->membersOf((string) $seals[1]['id']));
    }

    /**
     * The id order is never a high-water mark: a later entry whose id sorts
     * before every sealed id is still sealed.
     *
     * @return void
     */
    public function testUuidOrderIsNeverAHighWaterMark(): void
    {
        $this->storeEntryAt('2026-11-01 12:00:00', '01932b4e-8a40-7000-8000-ffffffffffff');
        $this->sealer()->seal();

        $first = $this->storeEntryAt('2026-11-01 12:00:01', '00000000-0000-7000-8000-000000000001');

        self::assertSame(1, $this->sealer()->seal()->seals());
        self::assertSame([$first], $this->membersOf((string) $this->seals()[1]['id']));
    }

    /**
     * A row committed after a seal, though recorded before its latest member,
     * joins the next seal; on SQLite it commits once the seal has.
     *
     * @return void
     */
    public function testATransactionCommittingOutOfOrderJoinsALaterSeal(): void
    {
        $this->storeEntryAt('2026-11-01 12:00:00');
        $this->storeEntryAt('2026-11-01 12:10:00');

        $late = $this->lateWriter();

        $late?->beginTransaction();

        $id = $late === null ? null : $this->insertLateRow($late);

        $first = $this->sealer()->seal();

        $late?->commit();

        $id ??= $this->insertLateRow(null);

        self::assertSame(2, $first->entries());

        $second = $this->sealer()->seal();

        self::assertSame(1, $second->seals());
        self::assertSame([$id], $this->membersOf((string) $this->seals()[1]['id']));
    }

    /**
     * Sealing reads and writes the primary alone, so a lagging replica sees
     * none of it.
     *
     * @return void
     */
    public function testSealingReadsTheWriter(): void
    {
        $this->useReadWriteSplit();
        $this->migrateIntegrityOnTheSplit();

        $seeded = DB::connection(self::REPLICA_CONNECTION)->table(IntegrityTables::stateTable())->get()->all();
        $first  = $this->storeEntries(2);

        $this->sealer()->seal();

        $second = $this->storeEntries(1, '2026-11-01 12:30:00');
        $result = $this->sealer()->seal();

        $primary = DB::connection(self::PRIMARY_CONNECTION);
        $replica = DB::connection(self::REPLICA_CONNECTION);
        $seals   = $primary->table(IntegrityTables::checkpointsTable())->orderBy('sequence')->get()->all();

        self::assertSame(1, $result->seals());
        self::assertSame(2, $result->lastSequence());
        self::assertCount(2, $seals);
        self::assertSame($seals[0]->seal_digest, $seals[1]->previous_digest);
        $members = $primary->table(IntegrityTables::membersTable());

        self::assertSame(self::sorted($first), (clone $members)->where('checkpoint_id', $seals[0]->id)->orderBy('entry_id')->pluck('entry_id')->all());
        self::assertSame($second, (clone $members)->where('checkpoint_id', $seals[1]->id)->pluck('entry_id')->all());
        self::assertSame(1, $primary->table(IntegrityTables::stateTable())->where('name', IntegrityProgress::SEAL_LAST)->count());
        self::assertSame(0, $replica->table(IntegrityTables::checkpointsTable())->count());
        self::assertSame(0, $replica->table(IntegrityTables::membersTable())->count());
        self::assertEquals($seeded, $replica->table(IntegrityTables::stateTable())->get()->all());
        self::assertSame(0, $replica->table(EntrySettings::table())->count());
    }

    /**
     * A stored seal's fields, in the engine's time form, give back its inserted
     * digest, whole seconds and single fractional digits included.
     *
     * @return void
     */
    public function testTheStoredSealRoundTripsItsDigest(): void
    {
        $this->sealAt('2026-11-01 13:00:00.5');
        $this->storeEntryAt('2026-11-01 12:00:00');
        $this->storeEntryAt('2026-11-01 12:00:00.2');

        $inserted = $this->sealer()->seal();
        $stored   = $this->seals()[0];
        $seal     = SealEnvelope::fromRow($stored);

        self::assertSame(1, $inserted->seals());
        self::assertSame('2026-11-01T12:00:00.000000Z', $seal->firstRecordedAt);
        self::assertSame('2026-11-01T12:00:00.200000Z', $seal->lastRecordedAt);
        self::assertSame('2026-11-01T13:00:00.500000Z', $seal->sealedAt);
        self::assertSame($stored['seal_digest'], $seal->digest());
        self::assertTrue(app(SealSigner::class)->verifies($seal, (string) $stored['signature']));
        self::assertSame('2026-11-01T12:00:00.200000Z', StoredTime::fromStorage((string) $stored['last_recorded_at']));
    }

    /**
     * A second connection to the test's database, or `null` on SQLite, whose
     * one writer cannot hold a transaction open across a seal.
     *
     * @return ?\Illuminate\Database\Connection
     */
    private function lateWriter(): ?Connection
    {
        $config = app(ConfigRepository::class);
        $key    = 'database.connections.' . self::CONNECTION;

        if ($config->get($key . '.driver') === 'sqlite') {
            return null;
        }

        $config->set('database.connections.' . self::LATE_WRITER, $config->get($key));

        return DB::connection(self::LATE_WRITER);
    }

    /**
     * Insert a copy of the first entry under a new id, recorded before the
     * latest, through the late writer or else the package, and return its id.
     *
     * @param  ?\Illuminate\Database\Connection  $late
     * @return string
     */
    private function insertLateRow(?Connection $late): string
    {
        if ($late === null) {
            return $this->storeEntryAt('2026-11-01 12:05:00');
        }

        $row = (array) $late->table(EntrySettings::table())->orderBy('recorded_at')->first();
        $id  = '01932b4e-8a40-7000-8000-00000000abcd';

        $late->table(EntrySettings::table())->insert([...$row, 'id' => $id, 'recorded_at' => '2026-11-01 12:05:00.000000']);

        return $id;
    }

    /**
     * Run the shipped integrity migrations on the split's primary and replica,
     * leaving the split as the storage connection.
     *
     * @return void
     */
    private function migrateIntegrityOnTheSplit(): void
    {
        $config = app(ConfigRepository::class);

        foreach (self::INTEGRITY_MIGRATIONS as $path) {

            $migration = require $path;

            assert($migration instanceof Migration && method_exists($migration, 'up'));

            foreach ([self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION] as $connection) {
                $config->set('audit-log.storage.connection', $connection);
                $migration->up();
            }
        }

        $config->set('audit-log.storage.connection', self::SPLIT_CONNECTION);
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
