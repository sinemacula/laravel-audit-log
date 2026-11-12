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
 * Feature tests for the order the trail is read in.
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
     * Entries of one microsecond keep a total order a cursor splits exactly.
     *
     * @return void
     */
    public function testIdenticalMicrosecondsKeepATotalOrder(): void
    {
        foreach ([3, 7, 0, 5, 1, 6, 2, 4] as $index) {
            $this->seedEntry([], self::SHARED_AT, self::IDS[$index]);
        }

        $descending = array_reverse(self::IDS);

        self::assertSame($descending, self::idsOf($this->financeTrail()->cursorPaginate(8)));
        self::assertSame(array_chunk($descending, 2), array_map(self::idsOf(...), $this->walk(2)));
    }

    /**
     * Entries a microsecond apart are ordered by time, newest first.
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
     * A walk of every page shows each entry once and ends with no cursor.
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
        self::assertSame(count($ids), $this->financeTrail()->count());
    }

    /**
     * The order is that of occurrence, not of recording.
     *
     * @return void
     */
    public function testTheOrderIsOccurrenceNotRecording(): void
    {
        $this->seedRecorded(self::IDS[0], '2026-11-01T12:00:00.000000Z', '2026-11-01T12:30:00.000000Z');
        $this->seedRecorded(self::IDS[1], '2026-11-01T12:00:02.000000Z', '2026-11-01T12:00:02.000000Z');
        $this->seedRecorded(self::IDS[2], '2026-11-01T12:00:01.000000Z', '2026-11-01T12:10:00.000000Z');

        $page = $this->financeTrail()->cursorPaginate();

        self::assertSame([self::IDS[1], self::IDS[2], self::IDS[0]], self::idsOf($page));
        self::assertSame(
            ['2026-11-01T12:00:02.000000Z', '2026-11-01T12:10:00.000000Z', '2026-11-01T12:30:00.000000Z'],
            array_map(static fn (TrailEntry $entry): string => StoredTime::format($entry->recordedAt), $page->entries),
        );
    }

    /**
     * A cursor carries occurrence time, so a late entry is never skipped.
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
     * The total order holds under a scope of two tenants and a tenant filter.
     *
     * @return void
     */
    public function testTheOrderHoldsUnderAFilter(): void
    {
        foreach (self::IDS as $index => $id) {
            $this->seedEntry(['tenant_id' => $index % 2 === 0 ? 'org_01' : 'org_02'], self::SHARED_AT, $id);
        }

        $pages = $this->walk(1, $this->financeTrail()->forTenant(Reference::of('organisation', 'org_02')));

        self::assertSame([self::IDS[7], self::IDS[5], self::IDS[3], self::IDS[1]], array_merge(...array_map(self::idsOf(...), $pages)));
    }

    /**
     * Every page of the trail given, or the default, from the first, in order.
     *
     * @param  int  $perPage
     * @param  ?\SineMacula\Laravel\AuditLog\Querying\AuditTrail  $trail
     * @return list<\SineMacula\Laravel\AuditLog\Querying\TrailPage>
     */
    private function walk(int $perPage, ?AuditTrail $trail = null): array
    {
        $trail ??= $this->financeTrail();
        $pages = [$trail->cursorPaginate($perPage)];

        while (($cursor = end($pages)->nextCursor) !== null) {
            self::assertLessThan(100, count($pages), 'The walk never ended.');

            $pages[] = $trail->cursorPaginate($perPage, $cursor);
        }

        return $pages;
    }

    /**
     * Store a captured record under the id, occurring and recorded as given.
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
}
