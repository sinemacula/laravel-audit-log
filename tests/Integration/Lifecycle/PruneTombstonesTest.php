<?php

declare(strict_types = 1);

namespace Tests\Integration\Lifecycle;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Contracts\PruneLedger;
use SineMacula\Laravel\AuditLog\Database\EntrySettings;
use SineMacula\Laravel\AuditLog\Database\IntegrityTables;
use SineMacula\Laravel\AuditLog\Database\StorageConnection;
use SineMacula\Laravel\AuditLog\Integrity\PruneBitmap;
use SineMacula\Laravel\AuditLog\Integrity\PruneRecord;
use SineMacula\Laravel\AuditLog\Lifecycle\PruneTombstones;
use Tests\Concerns\PrunesByHand;
use Tests\Concerns\SealsEntries;
use Tests\Fixtures\Integrity\InMemoryPruneLedger;
use Tests\TestCase;

/**
 * Integration tests for the tombstones of pruned records, on whichever engine
 * the suite runs against: a sealed member whose entry is gone and whose prune a
 * valid record covers is pruned; a present member, an id no seal holds, and an
 * absent member no valid record covers are not; ids are answered each once in
 * the order given, an id that is not a record id is never queried, and the ids
 * are read 500 to a statement on the storage connection's writer.
 *
 * Every test starts from one seal of three entries, sealed at a fixed instant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PruneTombstones::class)]
final class PruneTombstonesTest extends TestCase
{
    use PrunesByHand, SealsEntries;

    /** @var string When the entries are sealed: after every one was recorded. */
    private const string SEALED_AT = '2026-11-01 13:00:00';

    /** @var list<string> The sealed entries, in the order they were stored. */
    private array $sealed = [];

    /**
     * Store three entries and seal them.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->sealed = $this->storeEntries(3);

        $this->sealAt(self::SEALED_AT);

        self::assertSame(3, $this->sealAll()->entries());
    }

    /**
     * A member of a seal whose entry is gone, and whose prune a valid record of
     * the seal covers, is pruned.
     *
     * @return void
     */
    public function testASealedMemberAbsentFromTheEntriesIsPruned(): void
    {
        $this->pruneByHand($this->sealed[1]);

        self::assertTrue($this->tombstones()->isPruned($this->sealed[1]));
        self::assertSame([$this->sealed[1]], $this->tombstones()->prunedAmong($this->sealed));
    }

    /**
     * An absent member no valid record covers was removed by something other
     * than retention, and is never taken for pruned: with no record, with a
     * record of another member, or with a record whose signature fails.
     *
     * @return void
     */
    public function testAnAbsentMemberNoValidRecordCoversIsNot(): void
    {
        $this->deleteEntry($this->sealed[1]);

        self::assertFalse($this->tombstones()->isPruned($this->sealed[1]));

        $ledger = $this->pruneByHand($this->sealed[0]);

        self::assertSame([$this->sealed[0]], $this->tombstones()->prunedAmong($this->sealed));

        $this->deleteEntry($this->sealed[2]);

        $record = $ledger->recordsFor((string) $this->seals()[0]['id'])[0];
        $forged = PruneRecord::fromArray([...$record->toArray(), 'pruned' => PruneBitmap::encode([0, 1, 2], 3), 'pruned_count' => 3, 'signature' => $record->signature]);

        $fresh = new InMemoryPruneLedger;

        $fresh->add($forged);

        app()->instance(PruneLedger::class, $fresh);

        self::assertSame([], $this->tombstones()->prunedAmong($this->sealed));
    }

    /**
     * A member of a seal whose entry is still there is not pruned.
     *
     * @return void
     */
    public function testAPresentMemberIsNot(): void
    {
        self::assertFalse($this->tombstones()->isPruned($this->sealed[0]));
        self::assertSame([], $this->tombstones()->prunedAmong($this->sealed));
    }

    /**
     * An id no seal holds is never pruned, whether an entry holds it or not: a
     * record missing before it was sealed was never pruned.
     *
     * @return void
     */
    public function testAnUnsealedIdIsNot(): void
    {
        [$unsealed] = $this->storeEntries(1, '2026-11-01 13:30:00.000000');

        $never = Str::uuid7()->toString();

        self::assertFalse($this->tombstones()->isPruned($unsealed));
        self::assertFalse($this->tombstones()->isPruned($never));

        $this->deleteEntry($unsealed);

        self::assertFalse($this->tombstones()->isPruned($unsealed));
    }

    /**
     * The pruned ids are answered each once, in the order they were given,
     * however often and in whatever order they were asked.
     *
     * @return void
     */
    public function testThePrunedAreAnsweredOnceInTheOrderGiven(): void
    {
        $this->pruneByHand($this->sealed[0], $this->sealed[2]);

        [$first, $second, $third] = $this->sealed;

        self::assertSame([$third, $first], $this->tombstones()->prunedAmong([$third, $second, $first, $third, $first]));
    }

    /**
     * An id that is not a lower-case UUID is never a record's, so it is never
     * pruned and costs no statement: an upper-case form of a pruned id is not
     * that id, and a value PostgreSQL could not compare with a UUID is never
     * sent.
     *
     * @return void
     */
    public function testAnIdThatIsNoRecordIdIsNeverQueried(): void
    {
        $this->pruneByHand($this->sealed[0]);

        $hostile = $this->countStatements(fn (): array => $this->tombstones()->prunedAmong([strtoupper($this->sealed[0]), 'not-a-uuid', '']));
        $none    = $this->countStatements(fn (): array => $this->tombstones()->prunedAmong([]));

        self::assertSame([0, []], $hostile);
        self::assertSame([0, []], $none);
    }

    /**
     * Ids are read 500 to a statement, so 1,001 ids cost three, and a pruned id
     * in the last of them is still found, at the cost of its seal's row and
     * members, once.
     *
     * @return void
     */
    public function testFiveHundredIdsPerStatement(): void
    {
        $this->pruneByHand($this->sealed[2]);

        $ids   = array_map(static fn (): string => Str::uuid7()->toString(), range(1, PruneTombstones::CHUNK * 2));
        $ids[] = $this->sealed[2];

        self::assertSame(500, PruneTombstones::CHUNK);
        self::assertSame([5, [$this->sealed[2]]], $this->countStatements(fn (): array => $this->tombstones()->prunedAmong($ids)));
    }

    /**
     * The tombstones are read on the storage connection's writer, joining the
     * members to the entries, then the seal and its members, so a lagging
     * replica never reads a pruned entry as present.
     *
     * @return void
     */
    public function testItReadsTheStorageConnectionsWriter(): void
    {
        $this->pruneByHand($this->sealed[0]);

        $connection = DB::connection(StorageConnection::name());
        $reads      = [];

        $connection->listen(static function (QueryExecuted $query) use (&$reads): void {
            $reads[] = $query;
        });

        $connection->setReadPdo(static function (): never {
            throw new \LogicException('The reader is never asked.');
        });

        self::assertTrue($this->tombstones()->isPruned($this->sealed[0]));
        self::assertCount(3, $reads);
        self::assertStringContainsString(IntegrityTables::membersTable(), $reads[0]->sql);
        self::assertStringContainsString(EntrySettings::table(), $reads[0]->sql);
    }

    /**
     * The tombstones the container builds.
     *
     * @return \SineMacula\Laravel\AuditLog\Lifecycle\PruneTombstones
     */
    private function tombstones(): PruneTombstones
    {
        return app(PruneTombstones::class);
    }

    /**
     * Delete the entry outside retention, keeping its seal and its member, and
     * recording no prune of it.
     *
     * @param  string  $id
     * @return void
     */
    private function deleteEntry(string $id): void
    {
        self::assertSame(1, DB::connection(StorageConnection::name())->table(EntrySettings::table())->where('id', $id)->delete());
    }

    /**
     * The number of statements the storage connection runs while the work runs,
     * and the ids the work answers.
     *
     * @param  \Closure(): list<string>  $work
     * @return array{0: int, 1: list<string>}
     */
    private function countStatements(\Closure $work): array
    {
        $count = 0;

        DB::connection(StorageConnection::name())->listen(static function () use (&$count): void {
            $count++;
        });

        $ids = $work();

        return [$count, $ids];
    }
}
