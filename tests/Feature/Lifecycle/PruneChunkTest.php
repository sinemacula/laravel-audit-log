<?php

declare(strict_types = 1);

namespace Tests\Feature\Lifecycle;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\RetentionPolicy;
use SineMacula\Laravel\AuditLog\Database\DeliveryTables;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\LifecycleTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\Enums\JournalKind;
use SineMacula\Laravel\AuditLog\Integrity\JournalRow;
use SineMacula\Laravel\AuditLog\Integrity\JournalSigner;
use SineMacula\Laravel\AuditLog\Integrity\PruneRecord;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Integrity\SealSettings;
use SineMacula\Laravel\AuditLog\Integrity\SealSigner;
use SineMacula\Laravel\AuditLog\Lifecycle\Authority;
use SineMacula\Laravel\AuditLog\Lifecycle\ConfiguredRetentionPolicy;
use SineMacula\Laravel\AuditLog\Lifecycle\Enums\HoldBasis;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldKeeper;
use SineMacula\Laravel\AuditLog\Lifecycle\HoldScope;
use SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay;
use SineMacula\Laravel\AuditLog\Lifecycle\MaintenanceTransaction;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneChunk;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneChunkOutcome;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneMismatchException;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneSeal;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneSeals;
use SineMacula\Laravel\AuditLog\Lifecycle\RetentionDecisions;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use Tests\Concerns\InteractsWithOutbox;
use Tests\Concerns\SealsEntries;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Feature tests for one prune chunk under the lifecycle lock, on whichever
 * engine the suite runs against: it deletes only the rows it read and verified
 * under the lock that are still eligible, unheld and delivered; an id already
 * gone is never covered; its record covers exactly the deleted positions; a
 * delete that mismatches rolls the chunk back; a hold committed before the
 * lock, an outbox row and a row no longer eligible each keep their entry; a
 * member of another seal deletes nothing; and every statement runs on the
 * maintenance connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PruneChunk::class)]
final class PruneChunkTest extends TestCase
{
    use InteractsWithOutbox, SealsEntries;

    /** @var string When every chunk runs. */
    private const string NOW = '2026-11-04 15:00:00';

    /** @var string When every entry is recorded. */
    private const string RECORDED_AT = '2026-11-01 12:00:00';

    /** @var string When every seal is made. */
    private const string SEALED_AT = '2026-11-01 13:00:00';

    /** @var string When an entry past its thirty days happened. */
    private const string OLD = '2026-09-01T10:00:00.000000Z';

    /** @var string When an entry within its thirty days happened. */
    private const string RECENT = '2026-11-01T10:00:00.000000Z';

    /** @var string The run every chunk belongs to. */
    private const string RUN = '01932b4e-c000-7000-8000-000000000001';

    /** @var string When every chunk's record says it pruned. */
    private const string PRUNED_AT = '2026-11-04T15:00:00.000000Z';

    /** @var string A maintenance connection of its own, to the worker's database. */
    private const string MAINTENANCE = 'audit_maintenance';

    /**
     * Stop the clock, keep every category thirty days, and bind the configured
     * policy.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(new CarbonImmutable(self::NOW, 'UTC'));

        app(ConfigRepository::class)->set('audit-log.retention.after_days', 30);
        app()->bind(RetentionPolicy::class, ConfiguredRetentionPolicy::class);

        $this->sealAt(self::SEALED_AT);
    }

    /**
     * Roll back any transaction left open and put the clock back.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $connection = $this->maintenance();

        while ($connection->transactionLevel() > 0) {
            $connection->rollBack();
        }

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * The chunk deletes only the rows it read under the lock that are eligible:
     * the lock is its first statement, every read follows it, the deletes name
     * exactly the eligible rows, and a planned row inside its cut-off is left.
     *
     * @return void
     */
    public function testItDeletesOnlyWhatItReadUnderTheLock(): void
    {
        $old    = [$this->seedEntry(self::OLD), $this->seedEntry(self::OLD)];
        $recent = $this->seedEntry(self::RECENT);

        $this->sealAll();

        $log     = $this->statements();
        $outcome = $this->runChunk([...$old, $recent]);

        $sorted = $old;

        usort($sorted, strcmp(...));

        self::assertSame($sorted, $outcome->deleted);
        self::assertSame(1, $outcome->ineligible);
        self::assertSame([$recent], $this->present([...$old, $recent]));
        $inside = array_values(array_filter($log->getArrayCopy(), static fn (array $entry): bool => $entry[2] > 0));

        self::assertSame('lock', $inside[0][0]);

        $deletes = array_values(array_filter($inside, static fn (array $entry): bool => $entry[0] === 'delete'));

        self::assertCount(3, $deletes);

        foreach ($deletes as $delete) {
            self::assertSame($sorted, $delete[1]);
        }
    }

    /**
     * An id whose entry is already gone is left alone and never covered: the
     * record sets the positions of the entries the chunk deleted alone.
     *
     * @return void
     */
    public function testAnIdAlreadyGoneIsNeverCovered(): void
    {
        $ids = [$this->seedEntry(self::OLD), $this->seedEntry(self::OLD), $this->seedEntry(self::OLD)];

        $this->sealAll();

        $seal = $this->loadSeal();
        $gone = $seal->memberIds[1];

        $this->maintenance()->table(EntrySettings::table())->where('id', $gone)->delete();

        $outcome = $this->runChunk($ids);

        self::assertSame([$seal->memberIds[0], $seal->memberIds[2]], $outcome->deleted);
        self::assertSame([0, 2], $this->records()[0]->positions());
    }

    /**
     * The record covers exactly the positions, in member order, of the entries
     * deleted, counts them, names the seal, its digest and its members, the run
     * as its operation and the time given, and verifies; the journal row names
     * the seal and the run.
     *
     * @return void
     */
    public function testTheRecordCoversExactlyTheDeletedPositions(): void
    {
        for ($index = 0; $index < 5; $index++) {
            $this->seedEntry(self::OLD);
        }

        $this->sealAll();

        $seal    = $this->loadSeal();
        $members = $seal->memberIds;

        $this->runChunk([$members[3], $members[1]]);

        $record = $this->records()[0];
        $row    = JournalRow::fromRow((array) $this->maintenance()->table(LifecycleTables::journalTable())->first(), true);

        self::assertSame([1, 3], $record->positions());
        self::assertSame([5, 2, $seal->envelope->id, $seal->digest, self::RUN, self::PRUNED_AT], [
            $record->memberCount,
            $record->prunedCount,
            $record->sealId,
            $record->sealDigest,
            $record->operationId,
            $record->prunedAt,
        ]);
        self::assertTrue(app(SealSigner::class)->verifiesPrune($record));
        self::assertSame([JournalKind::PRUNE, $seal->envelope->id, self::RUN, null], [$row->kind, $row->sealId, $row->operationId, $row->authorityType]);
        self::assertSame(self::RUN, $row->payloadMap()['run_id'] ?? null);
        self::assertSame([$members[0], $members[2], $members[4]], $this->present($members));
    }

    /**
     * A delete of entries that affects fewer rows than it names rolls the whole
     * chunk back: its other deletes and its journal row with it.
     *
     * @return void
     */
    public function testAnAffectedCountMismatchRollsBack(): void
    {
        $ids = [$this->seedEntry(self::OLD), $this->seedEntry(self::OLD), $this->seedEntry(self::OLD)];

        $this->sealAll();

        $this->deleteBeforeTheEntriesDelete($ids[0]);

        try {
            $this->runChunk($ids);

            self::fail('Expected the mismatch to be refused.');
        } catch (PruneMismatchException $exception) {
            self::assertSame('A prune chunk deleted 2 entries where it named 3; the chunk was rolled back.', $exception->getMessage());
        }

        self::assertCount(3, $this->present($ids));
        self::assertSame(0, $this->maintenance()->table(LifecycleTables::journalTable())->count());
    }

    /**
     * A hold committed after the replay was verified but before the chunk's
     * lock is seen: the chunk advances the replay under the lock, and the held
     * rows are kept and counted.
     *
     * @return void
     */
    public function testAHoldPlacedBeforeTheLockIsSeen(): void
    {
        $ids = [$this->seedEntry(self::OLD), $this->seedEntry(self::OLD)];

        $this->sealAll();

        $replay = $this->replay();

        $authority = new Authority(Reference::of('App\Models\User', '7'), 'case.review');

        app(HoldKeeper::class)->place(self::RUN, HoldScope::tenants(Reference::of('organisation', 'org_01')), $authority, HoldBasis::LEGAL_CLAIM, null);

        $outcome = $this->runChunk($ids, $replay);

        self::assertSame([[], 2, 1], [$outcome->deleted, $outcome->held, count($outcome->replay->holds())]);
        self::assertCount(2, $this->present($ids));
    }

    /**
     * Eligibility is decided from the verified row: a planned id whose row is
     * of a protected code, or whose time is inside its cut-off, is left and
     * counted, while the eligible rows beside it go.
     *
     * @return void
     */
    public function testEligibilityIsDecidedFromTheVerifiedRow(): void
    {
        $export   = $this->seedEntry(self::OLD, ['event' => 'audit_log.trail_exported', 'category' => 'audit']);
        $recent   = $this->seedEntry(self::RECENT);
        $eligible = $this->seedEntry(self::OLD);

        $this->sealAll();

        $outcome = $this->runChunk([$export, $recent, $eligible]);

        self::assertSame([$eligible], $outcome->deleted);
        self::assertSame([2, 0, 0], [$outcome->ineligible, $outcome->held, $outcome->pendingDelivery]);
        self::assertEqualsCanonicalizing([$export, $recent], $this->present([$export, $recent, $eligible]));
    }

    /**
     * An entry with an outbox row written before the chunk's lock is kept and
     * counted as pending, as is one with a receipt not yet delivered.
     *
     * @return void
     */
    public function testAnOutboxRowWrittenBeforeTheLockKeepsItsEntry(): void
    {
        $queued      = $this->seedEntry(self::OLD);
        $undelivered = $this->seedEntry(self::OLD);
        $eligible    = $this->seedEntry(self::OLD);

        $this->sealAll();
        $this->seedOutboxRow($queued, 'payload');

        $this->maintenance()->table(DeliveryTables::deliveriesTable())->insert([
            'entry_id'           => $undelivered,
            'destination'        => 'siem',
            'attempts'           => 3,
            'first_attempted_at' => '2026-11-01 12:00:01.000000',
            'delivered_at'       => null,
            'last_error_class'   => \RuntimeException::class,
        ]);

        $outcome = $this->runChunk([$queued, $undelivered, $eligible]);

        self::assertSame([$eligible], $outcome->deleted);
        self::assertSame(2, $outcome->pendingDelivery);
        self::assertEqualsCanonicalizing([$queued, $undelivered], $this->present([$queued, $undelivered, $eligible]));
    }

    /**
     * A planned id that is a member of another seal fails the chunk's check of
     * membership: nothing is deleted, nothing is journalled, and the seal is to
     * be skipped.
     *
     * @return void
     */
    public function testAMemberOfAnotherSealIsNeverDeleted(): void
    {
        $first = $this->seedEntry(self::OLD);

        $this->sealAll();

        $other = $this->seedEntry(self::OLD);

        $this->sealAll();

        $outcome = $this->runChunk([$first, $other]);

        self::assertTrue($outcome->sealFailed);
        self::assertSame([], $outcome->deleted);
        self::assertCount(2, $this->present([$first, $other]));
        self::assertSame(0, $this->maintenance()->table(LifecycleTables::journalTable())->count());
    }

    /**
     * A candidate whose row was changed after it was sealed fails verification,
     * and the chunk deletes nothing.
     *
     * @return void
     */
    public function testATamperedCandidateDeletesNothing(): void
    {
        $ids = [$this->seedEntry(self::OLD), $this->seedEntry(self::OLD)];

        $this->sealAll();

        $this->maintenance()->table(EntrySettings::table())->where('id', $ids[1])->update(['event' => 'invoice.forged']);

        $outcome = $this->runChunk($ids);

        self::assertTrue($outcome->sealFailed);
        self::assertCount(2, $this->present($ids));
    }

    /**
     * With a maintenance connection of its own, the lock, every read and every
     * delete of the chunk run on it, and the storage connection runs nothing.
     *
     * @return void
     */
    public function testTheDeletesRunOnTheMaintenanceConnection(): void
    {
        $ids = [$this->seedEntry(self::OLD), $this->seedEntry(self::OLD)];

        $this->sealAll();
        $this->sameDatabase();

        $replay      = $this->replay();
        $connections = [];

        DB::listen(static function (QueryExecuted $query) use (&$connections): void {
            $connections[] = $query->connectionName;
        });

        $outcome = $this->runChunk($ids, $replay);

        self::assertCount(2, $outcome->deleted);
        self::assertSame([self::MAINTENANCE], array_values(array_unique($connections)));
    }

    /**
     * Run a chunk of the ids of the first seal from the replay given, or one
     * verified now, in a lifecycle transaction, with the run's decisions.
     *
     * @param  list<string>  $ids
     * @param  ?\SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay  $replay
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\PruneChunkOutcome
     *
     * @throws \SineMacula\Laravel\AuditLog\Lifecycle\PruneMismatchException
     */
    private function runChunk(array $ids, ?JournalReplay $replay = null): PruneChunkOutcome
    {
        $replay ??= $this->replay();
        $seal      = $this->loadSeal();
        $decisions = new RetentionDecisions(app(RetentionPolicy::class), CarbonImmutable::now());

        return app(MaintenanceTransaction::class)->run(
            self::RUN,
            static fn (Connection $connection): PruneChunkOutcome => app(PruneChunk::class)->run($connection, $replay, $decisions, $seal, $ids, self::RUN, self::PRUNED_AT),
        );
    }

    /**
     * A replay of the whole journal, verified now.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\JournalReplay
     */
    private function replay(): JournalReplay
    {
        return JournalReplay::start(app(JournalSigner::class), app(SealSettings::class)->logId())->verify($this->maintenance());
    }

    /**
     * The first seal, authenticated.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\PruneSeal
     */
    private function loadSeal(): PruneSeal
    {
        $seal = app(PruneSeals::class)->load($this->maintenance(), 1);

        self::assertInstanceOf(PruneSeal::class, $seal);

        return $seal;
    }

    /**
     * Every prune record the journal holds, in order.
     *
     * @return list<\SineMacula\Laravel\AuditLog\Integrity\PruneRecord>
     */
    private function records(): array
    {
        $payloads = $this->maintenance()->table(LifecycleTables::journalTable())->where('kind', JournalKind::PRUNE->value)->orderBy('sequence')->pluck('payload')->all();

        return array_map(static function (mixed $payload): PruneRecord {
            self::assertIsString($payload);

            $decoded = json_decode($payload, true, 64, JSON_THROW_ON_ERROR);

            self::assertIsArray($decoded);
            self::assertIsArray($decoded['record'] ?? null);

            return PruneRecord::fromArray($decoded['record']);
        }, array_values($payloads));
    }

    /**
     * The ids among those given whose entries are still stored, sorted.
     *
     * @param  list<string>  $ids
     * @return list<string>
     */
    private function present(array $ids): array
    {
        $present = self::strings($this->maintenance()->table(EntrySettings::table())->whereIn('id', $ids)->pluck('id')->all());

        sort($present);

        return $present;
    }

    /**
     * Store a captured record with the fields given over its own, happening at
     * the instant given and recorded at the test's time, and return its id.
     *
     * @param  string  $occurredAt
     * @param  array<string, string>  $fields
     * @return string
     */
    private function seedEntry(string $occurredAt, array $fields = []): string
    {
        $record    = RecordFactory::withFields(['occurred_at' => $occurredAt, ...$fields]);
        $finalised = (new RecordFinaliser(FrozenClock::at(self::RECORDED_AT), app(RecordSigner::class)))->finalise($record);

        app(DatabaseAuditStore::class)->store($finalised);

        return $finalised->record->id;
    }

    /**
     * Delete the entry, through the chunk's own connection, as the chunk's last
     * delete of receipts runs, so its delete of entries affects one row fewer
     * than it names.
     *
     * @param  string  $id
     * @return void
     */
    private function deleteBeforeTheEntriesDelete(string $id): void
    {
        $done = false;

        DB::listen(static function (QueryExecuted $query) use ($id, &$done): void {
            if ($done || !str_starts_with($query->sql, 'delete') || !str_contains($query->sql, DeliveryTables::deliveriesTable())) {
                return;
            }

            $done = true;

            $query->connection->table(EntrySettings::table())->where('id', $id)->delete();
        });
    }

    /**
     * Log each statement from now as the lock, a delete or anything else, with
     * the ids it names and its connection's transaction level.
     *
     * @return \ArrayObject<int, array{0: string, 1: list<string>, 2: int}>
     */
    private function statements(): \ArrayObject
    {
        /** @var \ArrayObject<int, array{0: string, 1: list<string>, 2: int}> $log */
        $log = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($log): void {
            $kind = match (true) {
                str_starts_with($query->sql, 'update') && str_contains($query->sql, LifecycleTables::lockTable()) => 'lock',
                str_starts_with($query->sql, 'delete')                                                            => 'delete',
                default                                                                                           => 'other',
            };

            $ids = array_values(array_filter($query->bindings, is_string(...)));

            sort($ids);

            $log->append([$kind, $ids, $query->connection->transactionLevel()]);
        });

        return $log;
    }

    /**
     * Configure a second connection to the worker's database as the maintenance
     * connection: on SQLite it shares the in-memory database's connection.
     *
     * @return void
     */
    private function sameDatabase(): void
    {
        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . self::MAINTENANCE, $config->array('database.connections.' . self::CONNECTION));
        $config->set('audit-log.storage.maintenance_connection', self::MAINTENANCE);

        $root = DB::connection(self::CONNECTION);

        if ($root->getDriverName() !== 'sqlite') {
            return;
        }

        $same = DB::connection(self::MAINTENANCE);

        $same->setPdo($root->getPdo());
        $same->setReadPdo($root->getPdo());
    }

    /**
     * The maintenance connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function maintenance(): Connection
    {
        return DB::connection(StorageConnection::forMaintenance());
    }
}
