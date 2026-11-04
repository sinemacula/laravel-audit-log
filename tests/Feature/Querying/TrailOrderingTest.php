<?php

declare(strict_types = 1);

namespace Tests\Feature\Querying;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\AuditLog\Access\ScopeCompiler;
use SineMacula\Laravel\AuditLog\Integrity\RecordSigner;
use SineMacula\Laravel\AuditLog\Querying\AuditTrail;
use SineMacula\Laravel\AuditLog\Querying\TrailEntry;
use SineMacula\Laravel\AuditLog\Querying\TrailPage;
use SineMacula\Laravel\AuditLog\Querying\TrailReader;
use SineMacula\Laravel\AuditLog\Records\RecordFinaliser;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\AuditLog\Stores\DatabaseAuditStore;
use SineMacula\Laravel\AuditLog\Support\StoredTime;
use Tests\Concerns\ReadsTheTrail;
use Tests\Fixtures\Records\RecordFactory;
use Tests\Fixtures\Support\FrozenClock;
use Tests\TestCase;

/**
 * Feature tests for the order the trail is read in, through the read API alone:
 * newest occurrence first, then the greatest id, so entries of one microsecond
 * keep a total order a cursor can split; entries a microsecond apart, across a
 * second included, ordered by their times; a walk of every page showing each
 * entry once and ending; and the order that of occurrence, not of recording.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuditTrail::class)]
#[CoversClass(TrailReader::class)]
#[CoversClass(ScopeCompiler::class)]
final class TrailOrderingTest extends TestCase
{
    use ReadsTheTrail;

    /** @var string The one instant the entries of a microsecond share. */
    private const string SHARED_AT = '2026-11-01T12:00:00.500000Z';

    /** @var list<string> Ids that sort in this order, seeded out of it. */
    private const array IDS = [
        '01932b4e-8a40-7000-8000-000000000001',
        '01932b4e-8a40-7000-8000-000000000002',
        '01932b4e-8a40-7000-8000-00000000000a',
        '01932b4e-8a40-7000-8000-0000000000a0',
        '01932b4e-8a40-7000-8000-000000000a00',
        '01932b4e-8a40-7000-8fff-000000000000',
        '01932b4e-8a40-7fff-8000-000000000000',
        'ffffffff-ffff-7fff-bfff-ffffffffffff',
    ];

    /**
     * Bind the read path and a policy that lets the viewer see every entry.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->bindReading();
        $this->allowEverything();
    }

    /**
     * Entries that occurred in the same microsecond are read greatest id first,
     * whatever order they were stored in, and a cursor between two of them
     * splits them exactly: every page of two holds the next two ids, and none
     * repeats or goes missing.
     *
     * @return void
     */
    public function testIdenticalMicrosecondsKeepATotalOrder(): void
    {
        foreach ([3, 7, 0, 5, 1, 6, 2, 4] as $index) {
            $this->seedEntry([], self::SHARED_AT, self::IDS[$index]);
        }

        $descending = array_reverse(self::IDS);

        self::assertSame($descending, self::idsOf($this->trail()->cursorPaginate(8)));
        self::assertSame(array_chunk($descending, 2), array_map(self::idsOf(...), $this->walk(2)));
    }

    /**
     * Entries a microsecond apart are ordered by their times, newest first,
     * whatever their ids: across a second, the later of two entries with the
     * smaller id comes first, and a cursor on one opens the other.
     *
     * @return void
     */
    public function testRowsAMicrosecondApartAreOrdered(): void
    {
        $this->seedEntry([], '2026-11-01T12:00:00.999999Z', self::IDS[7]);
        $this->seedEntry([], '2026-11-01T12:00:01.000000Z', self::IDS[0]);
        $this->seedEntry([], '2026-11-01T12:00:01.000001Z', self::IDS[1]);

        $pages = $this->walk(1);

        self::assertSame([[self::IDS[1]], [self::IDS[0]], [self::IDS[7]]], array_map(self::idsOf(...), $pages));
        self::assertSame(
            ['2026-11-01T12:00:01.000001Z', '2026-11-01T12:00:01.000000Z', '2026-11-01T12:00:00.999999Z'],
            array_map(static fn (TrailPage $page): string => StoredTime::format($page->entries[0]->occurredAt), $pages),
        );
    }

    /**
     * A walk from the first page by each page's cursor shows every entry once,
     * in order, entries of a shared microsecond among them, and ends on a page
     * with no cursor; the count agrees.
     *
     * @return void
     */
    public function testPagesWalkTheWholeTrailOnce(): void
    {
        $ids = $this->seedEntries(20);

        foreach (self::IDS as $id) {
            $ids[] = $this->seedEntry([], self::SHARED_AT, $id);
        }

        $pages = $this->walk(6);
        $shown = array_merge(...array_map(self::idsOf(...), $pages));

        self::assertCount(5, $pages);
        self::assertSame([...array_reverse(self::IDS), ...array_reverse(array_slice($ids, 0, 20))], $shown);
        self::assertNull($pages[4]->nextCursor);
        self::assertSame(count($ids), $this->trail()->count());
    }

    /**
     * The order is that of occurrence, not of recording: an entry that occurred
     * first but was recorded last, as a late delivery is, is read last.
     *
     * @return void
     */
    public function testTheOrderIsOccurrenceNotRecording(): void
    {
        $this->seedRecorded(self::IDS[0], '2026-11-01T12:00:00.000000Z', '2026-11-01T12:30:00.000000Z');
        $this->seedRecorded(self::IDS[1], '2026-11-01T12:00:02.000000Z', '2026-11-01T12:00:02.000000Z');
        $this->seedRecorded(self::IDS[2], '2026-11-01T12:00:01.000000Z', '2026-11-01T12:10:00.000000Z');

        $page = $this->trail()->cursorPaginate();

        self::assertSame([self::IDS[1], self::IDS[2], self::IDS[0]], self::idsOf($page));
        self::assertSame(
            ['2026-11-01T12:00:02.000000Z', '2026-11-01T12:10:00.000000Z', '2026-11-01T12:30:00.000000Z'],
            array_map(static fn (TrailEntry $entry): string => StoredTime::format($entry->recordedAt), $page->entries),
        );
    }

    /**
     * A walk of entries recorded in another order than they occurred pages by
     * occurrence too: each cursor carries the occurrence time of the last entry
     * shown, never its recording time, so an entry delivered late is neither
     * skipped nor repeated. Each later page's record names the occurrence
     * position it read after, under a scope of the entries' one tenant, which
     * is where a position is shown.
     *
     * @return void
     */
    public function testAWalkCarriesTheOccurrenceNotTheRecording(): void
    {
        $this->allowTenants(Reference::of('organisation', 'org_01'));

        $this->seedRecorded(self::IDS[0], '2026-11-01T12:00:00.000000Z', '2026-11-01T12:30:00.000000Z');
        $this->seedRecorded(self::IDS[1], '2026-11-01T12:00:02.000000Z', '2026-11-01T12:00:02.000000Z');
        $this->seedRecorded(self::IDS[2], '2026-11-01T12:00:01.000000Z', '2026-11-01T12:10:00.000000Z');

        $pages = $this->walk(1);

        self::assertSame([[self::IDS[1]], [self::IDS[2]], [self::IDS[0]]], array_map(self::idsOf(...), $pages));

        $positions = array_map(static fn (array $record): mixed => self::propertiesOf($record)['page'], $this->readRecords('audit_log.trail_read'));

        self::assertSameProperties([
            'first',
            ['occurred_at' => '2026-11-01T12:00:02.000000Z', 'id' => self::IDS[1]],
            ['occurred_at' => '2026-11-01T12:00:01.000000Z', 'id' => self::IDS[2]],
        ], $positions);
    }

    /**
     * Entries of a shared microsecond in different tenants keep their total
     * order inside a scope of both, and a walk across them under a tenant
     * filter shows only that tenant's, in order.
     *
     * @return void
     */
    public function testTheOrderHoldsUnderAFilter(): void
    {
        foreach (self::IDS as $index => $id) {
            $this->seedEntry(['tenant_id' => $index % 2 === 0 ? 'org_01' : 'org_02'], self::SHARED_AT, $id);
        }

        $pages = $this->walk(1, $this->trail()->forTenant(Reference::of('organisation', 'org_02')));

        self::assertSame([self::IDS[7], self::IDS[5], self::IDS[3], self::IDS[1]], array_merge(...array_map(self::idsOf(...), $pages)));
    }

    /**
     * The trail, in the `finance` category the seeded entries are in, read for
     * the viewer, so the records of the reads themselves are never among what
     * is read.
     *
     * @return \SineMacula\Laravel\AuditLog\Querying\AuditTrail
     */
    private function trail(): AuditTrail
    {
        return app(AuditTrail::class)->visibleTo($this->viewer())->inCategory('finance');
    }

    /**
     * Every page of the trail given, or of the trail, of the size given, from
     * the first by each page's cursor, in order.
     *
     * @param  int  $perPage
     * @param  ?\SineMacula\Laravel\AuditLog\Querying\AuditTrail  $trail
     * @return list<\SineMacula\Laravel\AuditLog\Querying\TrailPage>
     */
    private function walk(int $perPage, ?AuditTrail $trail = null): array
    {
        $trail ??= $this->trail();
        $pages = [$trail->cursorPaginate($perPage)];

        while (($cursor = end($pages)->nextCursor) !== null) {
            self::assertLessThan(100, count($pages), 'The walk never ended.');

            $pages[] = $trail->cursorPaginate($perPage, $cursor);
        }

        return $pages;
    }

    /**
     * Store a captured record under the id, occurring and recorded at the
     * instants given.
     *
     * @param  string  $id
     * @param  string  $occurredAt
     * @param  string  $recordedAt
     * @return void
     */
    private function seedRecorded(string $id, string $occurredAt, string $recordedAt): void
    {
        $record = RecordFactory::captured(id: $id, occurredAt: $occurredAt);

        app(DatabaseAuditStore::class)->store((new RecordFinaliser(FrozenClock::at($recordedAt), app(RecordSigner::class)))->finalise($record));
    }

    /**
     * The ids of the entries the page shows, in order.
     *
     * @param  \SineMacula\Laravel\AuditLog\Querying\TrailPage  $page
     * @return list<string>
     */
    private static function idsOf(TrailPage $page): array
    {
        return array_map(static fn (TrailEntry $entry): string => $entry->id, $page->entries);
    }
}
